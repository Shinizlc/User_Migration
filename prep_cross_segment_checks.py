#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from shutil import which
import re
import tempfile

OK = "\x1b[32m✓\x1b[0m"
WARN = "\x1b[33m!\x1b[0m"
ERR = "\x1b[31m✗\x1b[0m"
CYN = "\x1b[36m"
NC = "\x1b[0m"

def say(msg): print(msg, flush=True)
def ok(msg):  say(f"{OK} {msg}")
def warn(msg):say(f"{WARN} {msg}")
def err(msg): say(f"{ERR} {msg}")

def ensure_dblink_exists(target_db, dblink_name, um_user, um_pass, env):
    """
    Проверяет наличие user_db_links.DB_LINK = dblink_name на TARGET под UMOVE.
    Если отсутствует — создаёт:
      CREATE DATABASE LINK <name> CONNECT TO UMOVE IDENTIFIED BY "<pass>" USING '<name>';
    Затем проверяет доступность через SELECT 1 FROM dual@<name>.
    """
    name_up = dblink_name.upper()
    check_sql = f"""
set head off pages 0 feed off
select count(*) from user_db_links where db_link = '{name_up}';
"""

    rc, out, logf = sqlplus_exec(f"{um_user}/{um_pass}@{target_db}", check_sql, env=env, tag=f"check_dblink_{name_up}")
    if rc != 0:
        err(f"Failed to check DB link {name_up} on TARGET. See log: {logf}")
        sys.exit(1)

    cnt = 0
    for line in (out or "").splitlines():
        s = line.strip()
        if s.isdigit():
            cnt = int(s)
            break

    if cnt == 0:
        say(f"{CYN}==> Creating DB link {name_up} on TARGET (UMOVE){NC}")
        # ВАЖНО: пароль экранируем двойными кавычками; предполагаем отсутствие двойных кавычек внутри.
        create_block = f"""
declare
  stmt varchar2(4000);
begin
  stmt := q'[CREATE DATABASE LINK {name_up}
              CONNECT TO {um_user} IDENTIFIED BY "{um_pass}"
              USING '{name_up}']';
  execute immediate stmt;
end;
/
"""
        rc2, out2, logf2 = sqlplus_exec(f"{um_user}/{um_pass}@{target_db}", create_block, env=env, tag=f"create_dblink_{name_up}")
        if rc2 != 0:
            err(f"Failed to create DB link {name_up} on TARGET. See log: {logf2}")
            sys.exit(1)
        ok(f"DB link {name_up} created on TARGET.")
    else:
        ok(f"DB link {name_up} already exists on TARGET.")

    # Быстрая проверка связности
    ping_sql = f"whenever sqlerror exit 1;\nselect 1 from dual@{name_up};\n"
    rc3, out3, logf3 = sqlplus_exec(f"{um_user}/{um_pass}@{target_db}", ping_sql, env=env, tag=f"ping_dblink_{name_up}")
    if rc3 != 0 or "1" not in (out3 or ""):
        err(f"DB link {name_up} exists but connectivity failed. See log: {logf3}")
        sys.exit(1)
    ok(f"DB link {name_up} is reachable.")


def patch_v_curr_sql(src_path: Path, active_dblink: str, src_podid: str) -> Path:
    """
    Патчит только первую активную строку select ... @adbXYZ в v_curr_source_scheduled_users.sql,
    чтобы она смотрела на АКТИВНЫЙ source dblink (и при желании — обновляет src_podid).
    Возвращает путь к временному пропатченному файлу.
    """
    text = src_path.read_text(encoding="utf-8")
    adb_active = active_dblink.lower()  # в файле dblink'и в нижнем регистре

    # Ограничим область замены до начала первого блок-комментария /*,
    # т.к. далее идут закомментированные UNION ALL, которые менять не надо.
    split_idx = text.find("/*")
    head = text if split_idx == -1 else text[:split_idx]
    tail = "" if split_idx == -1 else text[split_idx:]

    # 1) Обновим src_podid в первой активной строке select (если отличается)
    #    select '11' src_podid, ...
    head_new = re.sub(
        r"(select\s+')(\d+)('(\s+as)?\s*src_podid\b)",
        rf"\g<1>{src_podid}\3",
        head,
        count=1,
        flags=re.IGNORECASE
    )

    # 2) Заменим именно в ПЕРВОМ активном select оба @adbNNN (zadmin... и zportal...)
    #    ... from zadmin.scheduled_users@adb112 ... join zportal.users@adb112 ...
    #    Меняем только первые ДВЕ встречи @adb\d+ в head (до /*)
    def repl_first_two(match_iter, replacement):
        s = head_new
        cnt = 0
        for m in match_iter:
            if cnt >= 2:
                break
            s = s[:m.start()+cnt*(len(replacement)- (m.end()-m.start()))] + f"@{replacement}" + s[m.end()+cnt*(len(replacement)- (m.end()-m.start())):]
            cnt += 1
        return s

    # Поиск всех вхождений @adbNNN в head_new
    matches = list(re.finditer(r"@adb\d{3}", head_new, flags=re.IGNORECASE))
    if matches:
        # заменим только первые две (для zadmin и zportal в активной строке)
        head_new2 = head_new
        replaced = 0
        out = []
        last = 0
        for m in matches:
            if replaced < 2:
                out.append(head_new2[last:m.start()])
                out.append(f"@{adb_active}")
                last = m.end()
                replaced += 1
            else:
                break
        out.append(head_new2[last:])
        head_new = "".join(out)

    patched_text = head_new + tail

    # Сохраним во временный файл
    tmpdir = Path(tempfile.mkdtemp(prefix="umove_sql_"))
    patched_path = tmpdir / src_path.name
    patched_path.write_text(patched_text, encoding="utf-8")
    ok(f"Patched {src_path.name}: src_podid={src_podid}, dblink=@{adb_active} -> {patched_path}")
    return patched_path


def need_bin(name):
    if which(name) is None:
        err(f"Required binary '{name}' not found in PATH")
        sys.exit(1)

def run(cmd, input_text=None, env=None, logfile=None):
    """Run a command, optionally piping input_text, tee to logfile."""
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input_text else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    out, _ = proc.communicate(input=input_text)
    if logfile:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        logfile.write_text((logfile.read_text() if logfile.exists() else "") + out)
    return proc.returncode, out

def sqlplus_exec(connect_str, sql, env=None, logdir=Path("./logs"), tag="session"):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logf = logdir / f"{ts}_{tag}.log"
    rc, out = run(["sqlplus", "-s", connect_str], input_text=sql, env=env, logfile=logf)
    return rc, out, logf

def cfg_get(section, option, required=True, fallback=None):
    if cfg.has_option(section, option):
        return cfg.get(section, option).strip()
    if required:
        err(f"Config '{section}.{option}' is required")
        sys.exit(1)
    return fallback

def getenv_or_cfg(env_key, section, option, required=True):
    """
    Берём значение из переменной окружения ENV[env_key], если есть.
    Иначе — из config.ini (section.option).
    """
    v = os.environ.get(env_key)
    if v is not None and str(v).strip() != "":
        return str(v).strip()
    return cfg_get(section, option, required=required)

# === Active unit autodetect ===
def try_read_only_mode(tns_alias, um_user, um_pass, env):
    """Возвращает 0/1 (active/passive) или None при ошибке запроса."""
    rc, out, _ = sqlplus_exec(
        f"{um_user}/{um_pass}@{tns_alias}",
        "whenever oserror exit 1;\nwhenever sqlerror exit 1;\nset head off pages 0 feed off\nselect zportal.getbuzmeparameter('read_only_mode') from dual;\n",
        env=env, tag=f"{tns_alias}_romode"
    )
    if rc != 0:
        return None
    # ожидаем строку '0' или '1' в выводе
    out = (out or "").strip()
    for line in out.splitlines():
        s = line.strip()
        if s in ("0", "1"):
            return int(s)
    return None

def pick_active_from_list(aliases_csv, um_user, um_pass, env, role_expected=None):
    """
    Перебирает алиасы и возвращает кортеж:
      (active_alias, passive_aliases_list)
    role_expected: 'source'|'target' только для сообщений.
    """
    aliases = [a.strip() for a in (aliases_csv or "").split(",") if a.strip()]
    if not aliases:
        return None, []
    act, pas = None, []
    for a in aliases:
        mode = try_read_only_mode(a, um_user, um_pass, env)
        if mode is None:
            warn(f"Не удалось определить read_only_mode для {a} — пропускаю.")
            continue
        if mode == 0:  # active
            act = a
        else:
            pas.append(a)
    if not act:
        err(f"Не найден активный юнит среди: {', '.join(aliases)}"
            + (f" (роль: {role_expected})" if role_expected else ""))
        sys.exit(1)
    msg = f"Определён активный юнит ({role_expected or 'DB'}): {act}"
    if pas:
        msg += f"; пассивные: {', '.join(pas)}"
    ok(msg)
    return act, pas

# ---------- main ----------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} config.ini")
        sys.exit(1)

    cfg_path = Path(sys.argv[1])
    if not cfg_path.exists():
        err(f"Config file not found: {cfg_path}")
        sys.exit(1)

    cfg = configparser.ConfigParser()
    cfg.read(cfg_path)

    # Required tools
    need_bin("sqlplus")
    need_bin("awk")
    need_bin("sed")

    # Optional Oracle env
    env = os.environ.copy()
    if cfg.has_option("oracle_env", "tns_admin"):
        env["TNS_ADMIN"] = cfg.get("oracle_env", "tns_admin").strip()
    if cfg.has_option("oracle_env", "oracle_home"):
        env["ORACLE_HOME"] = cfg.get("oracle_env", "oracle_home").strip()
    if env.get("ORACLE_HOME"):
        binp = Path(env["ORACLE_HOME"]) / "bin"
        env["PATH"] = f"{binp}:{env['PATH']}"

    logs_dir = Path("./logs")
    logs_dir.mkdir(exist_ok=True)

    # Credentials
    UMOVE_USER = getenv_or_cfg("UMOVE_USER", "db", "umove_user")
    UMOVE_PASS = getenv_or_cfg("UMOVE_PASS", "db", "umove_pass")
    SYSTEM_PASS = getenv_or_cfg("SYSTEM_PASS", "db", "system_pass")

    if not UMOVE_PASS:
        err("UMOVE_PASS is empty: set environment variable or db.umove_pass in config.ini")
        sys.exit(1)
    if not SYSTEM_PASS:
        err("SYSTEM_PASS is empty: set environment variable or db.system_pass in config.ini")
        sys.exit(1)

    # === Active unit autodetect: читаем списки юнитов, иначе падаем на старые *_db_tns ===
    SOURCE_UNITS = cfg.get("db", "source_db_units", fallback="").strip()
    TARGET_UNITS = cfg.get("db", "target_db_units", fallback="").strip()

    if SOURCE_UNITS:
        say(f"{CYN}==> Определяю активный юнит для SOURCE из: {SOURCE_UNITS}{NC}")
        SOURCE_DB, source_passives = pick_active_from_list(SOURCE_UNITS, UMOVE_USER, UMOVE_PASS, env, "source")
    else:
        SOURCE_DB = cfg_get("db", "source_db_tns")

    if TARGET_UNITS:
        say(f"{CYN}==> Определяю активный юнит для TARGET из: {TARGET_UNITS}{NC}")
        TARGET_DB, target_passives = pick_active_from_list(TARGET_UNITS, UMOVE_USER, UMOVE_PASS, env, "target")
    else:
        TARGET_DB = cfg_get("db", "target_db_tns")

    # Links/params/sql paths
    ACTIVE_DBLINK = cfg_get("links", "active_src_dblink")
    PASSIVE_DBLINK = cfg_get("links", "passive_src_dblink")
    SRC_PODID = cfg_get("links", "src_podid")

    SQL_DIR = Path(cfg_get("paths", "sql_dir"))
    EXTDATA_BIN = Path(cfg_get("paths", "extdata_bin", required=False, fallback="./extdata/extdata"))

    # extdata check (инструкция: среда и проверка рантабельности) 
    # см. "Environment setup" и проверку коннектов/линков/параметров. :contentReference[oaicite:1]{index=1}
    say(f"{CYN}==> Checking extdata binary{NC}")
    if EXTDATA_BIN.exists() and os.access(EXTDATA_BIN, os.X_OK):
        rc, _ = run([str(EXTDATA_BIN), "-v"], env=env)
        if rc == 0:
            ok(f"extdata is runnable: {EXTDATA_BIN} -v")
        else:
            warn(f"extdata exists but '-v' failed (rc={rc}); main migration script also checks it.")
    else:
        warn(f"extdata not found or not executable at '{EXTDATA_BIN}'. Skipping this check.")

    # === Ensure DB links exist on TARGET (UMOVE) ===
    say(f"{CYN}==> Ensuring DB links exist on TARGET (UMOVE){NC}")
    ensure_dblink_exists(TARGET_DB, ACTIVE_DBLINK, UMOVE_USER, UMOVE_PASS, env)
    ensure_dblink_exists(TARGET_DB, PASSIVE_DBLINK, UMOVE_USER, UMOVE_PASS, env)

    say(f"{CYN}==> Checking sqlplus connectivity to SOURCE ({SOURCE_DB}){NC}")
    rc, out, logf = sqlplus_exec(
        f"{UMOVE_USER}/{UMOVE_PASS}@{SOURCE_DB}",
        "whenever oserror exit 1;\nwhenever sqlerror exit 1;\nselect 1 as ok from dual;\n",
        env=env, tag=f"{SOURCE_DB}_connect")
    if rc != 0 or "1" not in out:
        err(f"Cannot connect to SOURCE DB '{SOURCE_DB}'. See log: {logf}")
        sys.exit(1)
    ok(f"Connected to SOURCE {SOURCE_DB}")

    say(f"{CYN}==> Checking sqlplus connectivity to TARGET ({TARGET_DB}){NC}")
    rc, out, logf = sqlplus_exec(
        f"{UMOVE_USER}/{UMOVE_PASS}@{TARGET_DB}",
        "whenever oserror exit 1;\nwhenever sqlerror exit 1;\nselect 1 as ok from dual;\n",
        env=env, tag=f"{TARGET_DB}_connect")
    if rc != 0 or "1" not in out:
        err(f"Cannot connect to TARGET DB '{TARGET_DB}'. See log: {logf}")
        sys.exit(1)
    ok(f"Connected to TARGET {TARGET_DB}")

    # 2) Validate DB Links on TARGET (UMOVE schema) for active & passive source
    # Требование инструкции: проверить наличие и валидность двух DB links к активному/пассивному source. :contentReference[oaicite:3]{index=3}
    say(f"{CYN}==> Validating DB links on TARGET (user_db_links + v$instance via dblink){NC}")
    dblink_sql = f"""
set lines 200 pages 100
col db_link for a20
col host for a70
prompt -- user_db_links (ACTIVE)
select db_link, host from user_db_links where db_link = upper('{ACTIVE_DBLINK}');
prompt -- v$instance@ACTIVE
select instance_name from v$instance@{ACTIVE_DBLINK};
prompt -- user_db_links (PASSIVE)
select db_link, host from user_db_links where db_link = upper('{PASSIVE_DBLINK}');
prompt -- v$instance@PASSIVE
select instance_name from v$instance@{PASSIVE_DBLINK};
"""
    rc, out, logf = sqlplus_exec(f"{UMOVE_USER}/{UMOVE_PASS}@{TARGET_DB}", dblink_sql, env=env, tag="target_dblinks")
    if rc != 0:
        err(f"Failed to query/validate DB links on TARGET. See log: {logf}")
        sys.exit(1)
    if "INSTANCE_NAME" not in out:
        warn("He удалось увидеть INSTANCE_NAME из remote check — проверьте лог.")

    ok(f"DB links checked on TARGET ({ACTIVE_DBLINK} / {PASSIVE_DBLINK})")

    # 3) Cross-segment параметры на SOURCE и TARGET
    # Требование инструкции: проверить SEGMENTID и *_SERVICE_URL на обоих концах. :contentReference[oaicite:4]{index=4}
    q_params = """
set lines 200 pages 200
col param_name for a30
col param_value for a120
select param_name, param_value
  from zportal.buzme_parameters
 where param_name like '%\\_SERVICE\\_URL' escape '\\'
    or param_name = 'SEGMENTID'
 order by param_name;
"""
    say(f"{CYN}==> Reading cross-segment params on SOURCE ({SOURCE_DB}){NC}")
    rc, out, logf = sqlplus_exec(f"{UMOVE_USER}/{UMOVE_PASS}@{SOURCE_DB}", q_params, env=env, tag="source_params")
    if rc != 0:
        err(f"Failed to read zportal.buzme_parameters on SOURCE. See log: {logf}")
        sys.exit(1)

    say(f"{CYN}==> Reading cross-segment params on TARGET ({TARGET_DB}){NC}")
    rc, out, logf = sqlplus_exec(f"{UMOVE_USER}/{UMOVE_PASS}@{TARGET_DB}", q_params, env=env, tag="target_params")
    if rc != 0:
        err(f"Failed to read zportal.buzme_parameters on TARGET. See log: {logf}")
        sys.exit(1)
    ok("Cross-segment params queried on SOURCE and TARGET")

    # 4) Создание мониторинговых вьюх на TARGET (SYSTEM)
    # Требование инструкции: v_curr_source_scheduled_users.sql (define src_podid/dblink), v_um_current_status.sql, ready_2_migrate.sql. :contentReference[oaicite:5]{index=5}
    say(f"{CYN}==> Creating monitoring views on TARGET (SYSTEM){NC}")
    v1 = SQL_DIR / "v_curr_source_scheduled_users.sql"
    v2 = SQL_DIR / "v_um_current_status.sql"
    v3 = SQL_DIR / "ready_2_migrate.sql"
    for p in (v1, v2, v3):
        if not p.exists():
            err(f"Required SQL file not found: {p}")
            sys.exit(1)
    patched_v1 = patch_v_curr_sql(v1, ACTIVE_DBLINK, str(SRC_PODID))
    wrapper = f"""
define src_podid='{SRC_PODID}'
define dblink_name='{ACTIVE_DBLINK}'
@{patched_v1.as_posix()}
@{v2.as_posix()}
@{v3.as_posix()}
"""
    rc, out, logf = sqlplus_exec(
        f"system/{SYSTEM_PASS}@{TARGET_DB}",
        f"whenever oserror exit 1;\nwhenever sqlerror exit 1;\nset echo on feedback on\n{wrapper}",
        env=env, tag="create_monitoring_views"
    )
    if rc != 0:
        err(f"Failed to create monitoring views on TARGET. See log: {logf}")
        sys.exit(1)
    ok("Monitoring views created on TARGET")

    say("")
    ok("All pre-Preparation checks are DONE.")
    say("See logs in ./logs")

