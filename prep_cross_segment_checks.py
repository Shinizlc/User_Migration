#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from shutil import which
from typing import Optional

OK = "\x1b[32m✓\x1b[0m"
WARN = "\x1b[33m!\x1b[0m"
ERR = "\x1b[31m✗\x1b[0m"
CYN = "\x1b[36m"
NC = "\x1b[0m"

def say(msg): print(msg, flush=True)
def ok(msg):  say(f"{OK} {msg}")
def warn(msg):say(f"{WARN} {msg}")
def err(msg): say(f"{ERR} {msg}")

def need_bin(name):
    if which(name) is None:
        err(f"Required binary '{name}' not found in PATH"); sys.exit(1)

LOG_DIR = Path("./logs").resolve()
PROBE_TIMEOUT = 120  # сек. на короткие проверки (read_only_mode, ping, connect)

def run(cmd, input_text=None, env=None, cwd=None, logfile: Optional[Path]=None, timeout=None):
    """Запускает команду, отдаёт (rc, out). rc=124 при таймауте.
    encoding/errors заданы явно: вывод sqlplus с кириллицей (NLS_LANG) не должен ронять скрипт."""
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            stdin=None if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
        )
        rc, out = proc.returncode, proc.stdout or ""
    except subprocess.TimeoutExpired as e:
        out = e.output or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        out += f"\n*** TIMEOUT after {timeout}s: {' '.join(map(str, cmd))}\n"
        rc = 124
    if logfile:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(out)
    return rc, out

# ---------- sqlplus helpers ----------

def sqlplus_exec(user, password, alias, sql, env=None, logdir=None, tag="session", cwd=None, timeout=None):
    """
    Запуск sqlplus через /nolog + CONNECT из stdin:
      * пароль не попадает в командную строку (ps) и может содержать '@', '/' и т.п.;
      * -L: при неудачном логоне sqlplus не переспрашивает логин и не «съедает» SQL из stdin;
      * явный EXIT в конце.
    """
    logdir = logdir or LOG_DIR
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_tag = re.sub(r"[^\w.\-]", "_", tag)
    logf = logdir / f"{ts}_{safe_tag}.log"
    script = (
        "WHENEVER OSERROR EXIT 9\n"
        "WHENEVER SQLERROR EXIT 9\n"
        "SET DEFINE OFF\n"  # '&' в пароле не должен считаться подстановочной переменной
        f'CONNECT {user}/"{password}"@{alias}\n'
        "SET DEFINE ON\n"
        "WHENEVER OSERROR CONTINUE NONE\n"
        "WHENEVER SQLERROR CONTINUE NONE\n"
        f"{sql}\n"
        "EXIT\n"
    )
    rc, out = run(["sqlplus", "-s", "-L", "/nolog"], input_text=script, env=env, cwd=cwd,
                  logfile=logf, timeout=timeout)
    if rc == 0 and ("SP2-0640" in out or "SP2-0306" in out):  # Not connected / Invalid option
        rc = 9
    return rc, out, logf

# ---------- config helpers ----------

def cfg_get(cfg, section, option, required=True, fallback=None):
    if cfg.has_option(section, option):
        return cfg.get(section, option).strip()
    if required:
        err(f"Config '{section}.{option}' is required"); sys.exit(1)
    return fallback

def getenv_or_cfg(cfg, env_key, section, option, required=True):
    v = os.environ.get(env_key)
    if v is not None and str(v).strip() != "":
        return str(v).strip()
    return cfg_get(cfg, section, option, required=required)


def read_config(cfg_path: Path) -> configparser.ConfigParser:
    if not cfg_path.is_file():
        err(f"Config file not found: {cfg_path}"); sys.exit(1)
    cfg = configparser.ConfigParser()
    # config.ini содержит кириллицу — без явной кодировки падает при C/POSIX локали
    cfg.read(cfg_path, encoding="utf-8")
    return cfg

# ---------- active unit autodetect ----------

def try_read_only_mode(tns_alias, um_user, um_pass, env):
    rc, out, _ = sqlplus_exec(
        um_user, um_pass, tns_alias,
        "whenever sqlerror exit 1;\nset head off pages 0 feed off\n"
        "select zportal.getbuzmeparameter('read_only_mode') from dual;\n",
        env=env, tag=f"{tns_alias}_romode", timeout=PROBE_TIMEOUT
    )
    if rc != 0:
        return None
    for line in out.splitlines():
        s = line.strip()
        if s in ("0", "1"):
            return int(s)
    return None

def pick_active_from_list(aliases_csv, um_user, um_pass, env, role_expected=None):
    aliases = [a.strip() for a in (aliases_csv or "").split(",") if a.strip()]
    if not aliases:
        return None, []
    act, pas = [], []
    for a in aliases:
        mode = try_read_only_mode(a, um_user, um_pass, env)
        if mode is None:
            warn(f"Не удалось определить read_only_mode для {a} — пропускаю (см. ./logs/*_{a}_romode.log).")
            continue
        if mode == 0:
            act.append(a)
        else:
            pas.append(a)
    role = f" (роль: {role_expected})" if role_expected else ""
    if not act:
        err(f"Не найден активный юнит среди: {', '.join(aliases)}{role}"); sys.exit(1)
    if len(act) > 1:
        err(f"Несколько активных юнитов (read_only_mode = 0): {', '.join(act)}{role}"); sys.exit(1)
    ok(f"Определён активный юнит ({role_expected or 'DB'}): {act[0]}" + (f"; пассивные: {', '.join(pas)}" if pas else ""))
    return act[0], pas

def ensure_dblink_exists(target_db, dblink_name, um_user, um_pass, env):
    name_up = dblink_name.upper()
    check_sql = f"""
whenever sqlerror exit 1;
set head off pages 0 feed off
select count(*) from user_db_links where db_link = '{name_up}' or db_link like '{name_up}.%';
"""
    rc, out, logf = sqlplus_exec(um_user, um_pass, target_db, check_sql, env=env,
                                 tag=f"check_dblink_{name_up}", timeout=PROBE_TIMEOUT)
    if rc != 0:
        err(f"Failed to check DB link {name_up} on TARGET (see log {logf})"); sys.exit(1)

    cnt = None
    for line in out.splitlines():
        s = line.strip()
        if s.isdigit():
            cnt = int(s); break
    if cnt is None:
        err(f"Unexpected output while checking DB link {name_up} (see log {logf})"); sys.exit(1)

    if cnt == 0:
        say(f"{CYN}==> Creating DB link {name_up} on TARGET (UMOVE){NC}")
        create_block = f"""
whenever sqlerror exit 1;
set define off
BEGIN
  EXECUTE IMMEDIATE q'[CREATE DATABASE LINK {name_up} CONNECT TO {um_user} IDENTIFIED BY "{um_pass}" USING '{name_up}']';
END;
/
"""
        rc2, _, logf2 = sqlplus_exec(um_user, um_pass, target_db, create_block, env=env,
                                     tag=f"create_dblink_{name_up}", timeout=PROBE_TIMEOUT)
        if rc2 != 0:
            err(f"Failed to create DB link {name_up} on TARGET (see log {logf2})"); sys.exit(1)
        ok(f"DB link {name_up} created on TARGET.")
    else:
        ok(f"DB link {name_up} already exists on TARGET.")

    # ping
    ping_sql = f"whenever sqlerror exit 1;\nset head off pages 0 feed off\nselect 'PING_OK' from dual@{name_up};\n"
    rc3, out3, logf3 = sqlplus_exec(um_user, um_pass, target_db, ping_sql, env=env,
                                    tag=f"ping_dblink_{name_up}", timeout=PROBE_TIMEOUT)
    if rc3 != 0 or "PING_OK" not in out3:
        err(f"DB link {name_up} exists but connectivity failed (see log {logf3})"); sys.exit(1)
    ok(f"DB link {name_up} is reachable.")

# ---------- v_curr_source_scheduled_users.sql patch ----------

def _comment_mask(text: str) -> str:
    """
    Строка той же длины, где SQL-комментарии (/* ... */ и -- ...) заменены пробелами.
    Строковые литералы не трогаются (в них '--' и '/*' — не комментарии).
    Позиции совпадений в маске равны позициям в исходном тексте.
    """
    out = list(text)
    i, n, in_str = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    i += 2; continue
                in_str = False
            i += 1; continue
        if ch == "'":
            in_str = True; i += 1; continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
        elif text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
        else:
            i += 1; continue
        for k in range(i, j):
            if out[k] != "\n":
                out[k] = " "
        i = j
    return "".join(out)

def patch_v_curr_sql(src_path: Path, active_dblink: str, src_podid: str) -> Path:
    """
    Патчит первый активный (не закомментированный) select в v_curr_source_scheduled_users.sql:
      * src_podid в "select '<N>' src_podid";
      * первые две ссылки @adbNNN (zadmin.scheduled_users и zportal.users) -> активный source dblink.
    Раньше область поиска обрезалась по первому '/*' — если файл начинался с шапки-комментария,
    ничего не патчилось и вьюха молча смотрела на старый dblink.
    Возвращает путь к временному пропатченному файлу.
    """
    text = src_path.read_text(encoding="utf-8", errors="replace")
    masked = _comment_mask(text)
    adb_active = active_dblink.lower()  # в файле dblink'и в нижнем регистре

    repl = []  # (start, end, new_text)
    m = re.search(r"select\s+'(\d+)'(?:\s+as)?\s*src_podid\b", masked, flags=re.IGNORECASE)
    if m:
        repl.append((m.start(1), m.end(1), str(src_podid)))
    else:
        warn(f"{src_path.name}: не найдено \"select '<N>' src_podid\" — src_podid не пропатчен.")

    links = list(re.finditer(r"@adb\d+\b", masked, flags=re.IGNORECASE))
    if not links:
        err(f"{src_path.name}: не найдено ни одной активной ссылки @adbNNN — нечего патчить.")
        sys.exit(1)
    for lm in links[:2]:
        repl.append((lm.start(), lm.end(), f"@{adb_active}"))
    if len(links) > 2:
        warn(f"{src_path.name}: активных ссылок @adbNNN {len(links)}, пропатчены только первые две.")

    patched_text = text
    for s, e, new in sorted(repl, reverse=True):
        patched_text = patched_text[:s] + new + patched_text[e:]

    tmpdir = Path(tempfile.mkdtemp(prefix="umove_sql_"))
    patched_path = tmpdir / src_path.name
    patched_path.write_text(patched_text, encoding="utf-8")
    ok(f"Patched {src_path.name}: src_podid={src_podid}, dblink=@{adb_active} -> {patched_path}")
    return patched_path

# ---------- main ----------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} config.ini")
        sys.exit(1)

    cfg_path = Path(sys.argv[1]).resolve()
    cfg = read_config(cfg_path)

    # Required tools
    need_bin("sqlplus")

    # Optional Oracle env
    env = os.environ.copy()
    if cfg.has_option("oracle_env", "tns_admin"):
        env["TNS_ADMIN"] = cfg.get("oracle_env", "tns_admin").strip()
    if cfg.has_option("oracle_env", "oracle_home"):
        env["ORACLE_HOME"] = cfg.get("oracle_env", "oracle_home").strip()
    if env.get("ORACLE_HOME"):
        env["PATH"] = f"{Path(env['ORACLE_HOME']) / 'bin'}:{env.get('PATH', '')}"

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Credentials
    UMOVE_USER = getenv_or_cfg(cfg, "UMOVE_USER", "db", "umove_user")
    UMOVE_PASS = getenv_or_cfg(cfg, "UMOVE_PASS", "db", "umove_pass")
    SYSTEM_PASS = getenv_or_cfg(cfg, "SYSTEM_PASS", "db", "system_pass")

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
        SOURCE_DB, _ = pick_active_from_list(SOURCE_UNITS, UMOVE_USER, UMOVE_PASS, env, "source")
    else:
        SOURCE_DB = cfg_get(cfg, "db", "source_db_tns")

    if TARGET_UNITS:
        say(f"{CYN}==> Определяю активный юнит для TARGET из: {TARGET_UNITS}{NC}")
        TARGET_DB, _ = pick_active_from_list(TARGET_UNITS, UMOVE_USER, UMOVE_PASS, env, "target")
    else:
        TARGET_DB = cfg_get(cfg, "db", "target_db_tns")

    # Links/params/sql paths
    ACTIVE_DBLINK = cfg_get(cfg, "links", "active_src_dblink")
    PASSIVE_DBLINK = cfg_get(cfg, "links", "passive_src_dblink")
    SRC_PODID = cfg_get(cfg, "links", "src_podid")
    if not SRC_PODID.isdigit():
        err(f"links.src_podid must be a number, got '{SRC_PODID}'")
        sys.exit(1)

    SQL_DIR = Path(cfg_get(cfg, "paths", "sql_dir"))
    EXTDATA_BIN = Path(cfg_get(cfg, "paths", "extdata_bin", required=False, fallback="./extdata/extdata"))

    # extdata check
    say(f"{CYN}==> Checking extdata binary{NC}")
    if EXTDATA_BIN.is_file() and os.access(EXTDATA_BIN, os.X_OK):
        rc, _ = run([str(EXTDATA_BIN), "-v"], env=env, timeout=PROBE_TIMEOUT)
        if rc == 0:
            ok(f"extdata is runnable: {EXTDATA_BIN} -v")
        else:
            warn(f"extdata exists but '-v' failed (rc={rc}); main migration script also checks it.")
    else:
        warn(f"extdata not found or not executable at '{EXTDATA_BIN}'. Skipping this check.")

    # Connectivity first: без коннекта к TARGET нет смысла создавать DB links
    for role, alias in (("SOURCE", SOURCE_DB), ("TARGET", TARGET_DB)):
        say(f"{CYN}==> Checking sqlplus connectivity to {role} ({alias}){NC}")
        rc, out, logf = sqlplus_exec(
            UMOVE_USER, UMOVE_PASS, alias,
            "whenever sqlerror exit 1;\nset head off pages 0 feed off\nselect 'CONNECT_OK' from dual;\n",
            env=env, tag=f"{alias}_connect", timeout=PROBE_TIMEOUT)
        if rc != 0 or "CONNECT_OK" not in out:
            err(f"Cannot connect to {role} DB '{alias}'. See log: {logf}")
            sys.exit(1)
        ok(f"Connected to {role} {alias}")

    # === Ensure DB links exist on TARGET (UMOVE) ===
    say(f"{CYN}==> Ensuring DB links exist on TARGET (UMOVE){NC}")
    ensure_dblink_exists(TARGET_DB, ACTIVE_DBLINK, UMOVE_USER, UMOVE_PASS, env)
    ensure_dblink_exists(TARGET_DB, PASSIVE_DBLINK, UMOVE_USER, UMOVE_PASS, env)

    # Validate DB Links on TARGET (UMOVE schema) for active & passive source
    say(f"{CYN}==> Validating DB links on TARGET (user_db_links + v$instance via dblink){NC}")
    dblink_sql = f"""
set lines 200 pages 100
col db_link for a30
col host for a70
prompt -- user_db_links (ACTIVE)
select db_link, host from user_db_links where db_link = upper('{ACTIVE_DBLINK}') or db_link like upper('{ACTIVE_DBLINK}') || '.%';
prompt -- v$instance@ACTIVE
select instance_name from v$instance@{ACTIVE_DBLINK};
prompt -- user_db_links (PASSIVE)
select db_link, host from user_db_links where db_link = upper('{PASSIVE_DBLINK}') or db_link like upper('{PASSIVE_DBLINK}') || '.%';
prompt -- v$instance@PASSIVE
select instance_name from v$instance@{PASSIVE_DBLINK};
"""
    rc, out, logf = sqlplus_exec(UMOVE_USER, UMOVE_PASS, TARGET_DB, dblink_sql, env=env,
                                 tag="target_dblinks", timeout=PROBE_TIMEOUT)
    if rc != 0:
        err(f"Failed to query/validate DB links on TARGET. See log: {logf}")
        sys.exit(1)
    if out.upper().count("INSTANCE_NAME") < 2:
        warn(f"Не удалось увидеть INSTANCE_NAME через оба dblink — проверьте лог: {logf}")
    ok(f"DB links checked on TARGET ({ACTIVE_DBLINK} / {PASSIVE_DBLINK})")

    # Cross-segment параметры на SOURCE и TARGET (SEGMENTID и *_SERVICE_URL)
    q_params = r"""
whenever sqlerror exit 1;
set lines 200 pages 200
col param_name for a30
col param_value for a120
select param_name, param_value
  from zportal.buzme_parameters
 where param_name like '%\_SERVICE\_URL' escape '\'
    or param_name = 'SEGMENTID'
 order by param_name;
"""
    for role, alias, tag in (("SOURCE", SOURCE_DB, "source_params"), ("TARGET", TARGET_DB, "target_params")):
        say(f"{CYN}==> Reading cross-segment params on {role} ({alias}){NC}")
        rc, out, logf = sqlplus_exec(UMOVE_USER, UMOVE_PASS, alias, q_params, env=env, tag=tag,
                                     timeout=PROBE_TIMEOUT)
        if rc != 0:
            err(f"Failed to read zportal.buzme_parameters on {role}. See log: {logf}")
            sys.exit(1)
        say(out.rstrip())
    ok("Cross-segment params queried on SOURCE and TARGET")

    # Создание мониторинговых вьюх на TARGET (SYSTEM)
    say(f"{CYN}==> Creating monitoring views on TARGET (SYSTEM){NC}")
    v1 = SQL_DIR / "v_curr_source_scheduled_users.sql"
    v2 = SQL_DIR / "v_um_current_status.sql"
    v3 = SQL_DIR / "ready_2_migrate.sql"
    for p in (v1, v2, v3):
        if not p.is_file():
            err(f"Required SQL file not found: {p}")
            sys.exit(1)
    patched_v1 = patch_v_curr_sql(v1, ACTIVE_DBLINK, SRC_PODID)
    wrapper = f"""
whenever oserror exit 1;
whenever sqlerror exit 1;
set echo on feedback on
define src_podid='{SRC_PODID}'
define dblink_name='{ACTIVE_DBLINK}'
@{patched_v1.as_posix()}
@{v2.as_posix()}
@{v3.as_posix()}
"""
    # cwd=SQL_DIR — чтобы относительные @-вызовы внутри скриптов находили файлы
    rc, out, logf = sqlplus_exec("system", SYSTEM_PASS, TARGET_DB, wrapper, env=env,
                                 tag="create_monitoring_views", cwd=SQL_DIR)
    if rc != 0:
        err(f"Failed to create monitoring views on TARGET. See log: {logf}")
        sys.exit(1)
    ok("Monitoring views created on TARGET")

    say("")
    ok("All pre-Preparation checks are DONE.")
    say(f"See logs in {LOG_DIR}")

if __name__ == "__main__":
    main()
