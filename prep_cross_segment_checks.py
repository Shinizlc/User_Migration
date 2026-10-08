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
    # для DB links нужны все остальные юниты, в т.ч. недоступные сейчас
    return act[0], [a for a in aliases if a != act[0]]

# ---------- topology / paths: всё, что можно, вычисляется из config.ini ----------

def opt_cfg(cfg, section, option) -> Optional[str]:
    """Значение опции или None, если её нет или она пустая."""
    if cfg.has_option(section, option):
        v = cfg.get(section, option).strip()
        return v or None
    return None

def unit_to_dblink(alias: str) -> str:
    """PRO-ADB252 -> ADB252 (имя DB link и TNS-алиас source-юнита на стороне TARGET)."""
    m = re.search(r"ADB\d+", alias, flags=re.IGNORECASE)
    return (m.group(0) if m else alias.split("-")[-1]).upper()

def dblink_to_pod(name: str) -> Optional[int]:
    """ADB252 -> 25: номер POD = цифры без последней (последняя — номер юнита)."""
    m = re.fullmatch(r"ADB(\d+)\d", name or "", flags=re.IGNORECASE)
    return int(m.group(1)) if m else None

def opt_int(cfg, section, option) -> Optional[int]:
    v = opt_cfg(cfg, section, option)
    if v is None:
        return None
    if not v.isdigit():
        err(f"Config '{section}.{option}' must be a number, got '{v}'"); sys.exit(1)
    return int(v)

def resolve_topology(cfg, um_user, um_pass, env) -> dict:
    """
    Из [db] source_db_units / target_db_units определяет:
      source_db / target_db       — активные юниты (read_only_mode = 0);
      active_dblink               — DB link на активный source-юнит (PRO-ADB252 -> ADB252);
      passive_dblinks             — DB links на остальные source-юниты;
      source_pod / target_pod     — номера POD (ADB252 -> 25, ADB232 -> 23).
    Явные значения в config.ini ([links] active_src_dblink/passive_src_dblink/src_podid,
    [prep] source_pod_id/vsched_target_pod) необязательны и нужны только для переопределения
    или для старого режима source_db_tns/target_db_tns.
    """
    t = {}
    src_units = opt_cfg(cfg, "db", "source_db_units")
    tgt_units = opt_cfg(cfg, "db", "target_db_units")

    derived_active, derived_passive = None, []
    if src_units:
        say(f"{CYN}==> Определяю активный юнит для SOURCE из: {src_units}{NC}")
        t["source_db"], others = pick_active_from_list(src_units, um_user, um_pass, env, "source")
        derived_active = unit_to_dblink(t["source_db"])
        derived_passive = [unit_to_dblink(o) for o in others]
    else:
        t["source_db"] = cfg_get(cfg, "db", "source_db_tns")

    if tgt_units:
        say(f"{CYN}==> Определяю активный юнит для TARGET из: {tgt_units}{NC}")
        t["target_db"], _ = pick_active_from_list(tgt_units, um_user, um_pass, env, "target")
    else:
        t["target_db"] = cfg_get(cfg, "db", "target_db_tns")

    # --- DB links на source ---
    cfg_active = opt_cfg(cfg, "links", "active_src_dblink")
    if cfg_active and derived_active and cfg_active.upper() != derived_active:
        # жёстко заданный «активный» линк после переключения юнитов указывал бы на пассивный
        err(f"links.active_src_dblink = {cfg_active}, но активный source-юнит сейчас {t['source_db']} "
            f"({derived_active}). Удалите active_src_dblink из config.ini — он вычисляется автоматически.")
        sys.exit(1)
    t["active_dblink"] = (cfg_active or derived_active or "").upper()
    if not t["active_dblink"]:
        err("Не задан DB link на source: укажите [db] source_db_units или [links] active_src_dblink"); sys.exit(1)

    cfg_passive = opt_cfg(cfg, "links", "passive_src_dblink")
    t["passive_dblinks"] = [cfg_passive.upper()] if cfg_passive else derived_passive
    t["passive_dblinks"] = [p for p in t["passive_dblinks"] if p != t["active_dblink"]]
    if not t["passive_dblinks"]:
        warn("Пассивный source DB link не определён — проверяю только активный.")

    # --- POD id: берём из самих баз (zportal.getbuzmeparameter('PODID')) ---
    # 0.1_pre-copy_session_create.sql сравнивает scheduled_users.podid с PODID таргета,
    # а PODID источника — с тем, что вернёт DB link. Поэтому значения должны быть точными.
    pod_src_a = opt_int(cfg, "prep", "source_pod_id")
    pod_src_b = opt_int(cfg, "links", "src_podid")
    if pod_src_a is not None and pod_src_b is not None and pod_src_a != pod_src_b:
        err(f"prep.source_pod_id={pod_src_a} и links.src_podid={pod_src_b} различаются — оставьте одно."); sys.exit(1)
    t["source_pod"] = _check_pod(get_podid(t["source_db"], um_user, um_pass, env),
                                 pod_src_a if pod_src_a is not None else pod_src_b,
                                 dblink_to_pod(t["active_dblink"]), "source", "[prep] source_pod_id")
    t["target_pod"] = _check_pod(get_podid(t["target_db"], um_user, um_pass, env),
                                 opt_int(cfg, "prep", "vsched_target_pod"),
                                 dblink_to_pod(unit_to_dblink(t["target_db"])), "target", "[prep] vsched_target_pod")

    say(f"    SOURCE: {t['source_db']}  (POD {t['source_pod']}, dblink {t['active_dblink']}"
        + (f", passive {', '.join(t['passive_dblinks'])}" if t["passive_dblinks"] else "") + ")")
    say(f"    TARGET: {t['target_db']}  (POD {t['target_pod']})")
    return t

def get_podid(alias, um_user, um_pass, env) -> int:
    rc, out, logf = sqlplus_exec(
        um_user, um_pass, alias,
        "whenever sqlerror exit 1;\nset head off pages 0 feed off\n"
        "select 'PODID=' || zportal.getbuzmeparameter('PODID') from dual;\n",
        env=env, tag=f"{alias}_podid", timeout=PROBE_TIMEOUT)
    m = re.search(r"PODID=(\d+)", out)
    if rc != 0 or not m:
        err(f"Не удалось прочитать PODID на {alias} (see log {logf})"); sys.exit(1)
    return int(m.group(1))

def _check_pod(actual: int, explicit: Optional[int], by_name: Optional[int], role: str, cfg_key: str) -> int:
    if explicit is not None and explicit != actual:
        err(f"POD {role}: в config.ini {cfg_key} = {explicit}, а в базе PODID = {actual}. "
            f"Удалите {cfg_key} из config.ini — значение читается из базы."); sys.exit(1)
    if by_name is not None and by_name != actual:
        warn(f"POD {role}: по имени юнита получается {by_name}, в базе PODID = {actual} — использую {actual}.")
    return actual

def resolve_paths(cfg) -> dict:
    """Все каталоги по умолчанию строятся от [paths] release_root; каждый можно переопределить."""
    root = opt_cfg(cfg, "paths", "release_root")
    def path(option, default_rel):
        v = opt_cfg(cfg, "paths", option)
        if v:
            return Path(v).expanduser()
        if root is None:
            err(f"Задайте [paths] release_root (или {option})"); sys.exit(1)
        return Path(root).expanduser() / default_rel
    return {
        "sql_dir":         path("sql_dir", "tools/sql"),
        "precopy_sql_dir": path("precopy_sql_dir", "."),
        "work_dir":        path("work_dir", "."),
        "extdata_bin":     path("extdata_bin", "extdata/extdata"),
    }

def ensure_dblink_exists(target_db, dblink_name, um_user, um_pass, env, expected_pod: Optional[int] = None):
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

    if expected_pod is not None:
        # та же проверка, что делают 0.1/0.2: линк должен смотреть на нужный POD
        pod_sql = (f"whenever sqlerror exit 1;\nset head off pages 0 feed off\n"
                   f"select 'PODID=' || zportal.getbuzmeparameter@{name_up}('PODID') from dual;\n")
        rc4, out4, logf4 = sqlplus_exec(um_user, um_pass, target_db, pod_sql, env=env,
                                        tag=f"podid_dblink_{name_up}", timeout=PROBE_TIMEOUT)
        m = re.search(r"PODID=(\d+)", out4)
        if rc4 != 0 or not m:
            err(f"Cannot read PODID via DB link {name_up} (see log {logf4})"); sys.exit(1)
        if int(m.group(1)) != expected_pod:
            err(f"DB link {name_up} points to POD {m.group(1)}, expected POD {expected_pod}"); sys.exit(1)
        ok(f"DB link {name_up} points to POD {expected_pod}.")

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

    # SOURCE/TARGET, DB links и POD id — из списков юнитов
    topo = resolve_topology(cfg, UMOVE_USER, UMOVE_PASS, env)
    SOURCE_DB, TARGET_DB = topo["source_db"], topo["target_db"]
    ACTIVE_DBLINK = topo["active_dblink"]
    ALL_DBLINKS = [ACTIVE_DBLINK] + topo["passive_dblinks"]
    SRC_PODID = str(topo["source_pod"])

    paths = resolve_paths(cfg)
    SQL_DIR = paths["sql_dir"]
    EXTDATA_BIN = paths["extdata_bin"]

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
    for link in ALL_DBLINKS:
        ensure_dblink_exists(TARGET_DB, link, UMOVE_USER, UMOVE_PASS, env,
                             expected_pod=topo["source_pod"] if link == ACTIVE_DBLINK else None)

    # Validate DB Links on TARGET (UMOVE schema) for active & passive source
    say(f"{CYN}==> Validating DB links on TARGET (user_db_links + v$instance via dblink){NC}")
    dblink_sql = "set lines 200 pages 100\ncol db_link for a30\ncol host for a70\n" + "".join(
        f"""prompt -- user_db_links ({role} {link})
select db_link, host from user_db_links where db_link = '{link}' or db_link like '{link}.%';
prompt -- v$instance@{link}
select instance_name from v$instance@{link};
""" for role, link in [("ACTIVE", ACTIVE_DBLINK)] + [("PASSIVE", l) for l in topo["passive_dblinks"]])
    rc, out, logf = sqlplus_exec(UMOVE_USER, UMOVE_PASS, TARGET_DB, dblink_sql, env=env,
                                 tag="target_dblinks", timeout=PROBE_TIMEOUT)
    if rc != 0:
        err(f"Failed to query/validate DB links on TARGET. See log: {logf}")
        sys.exit(1)
    if out.upper().count("INSTANCE_NAME") < len(ALL_DBLINKS):
        warn(f"Не удалось увидеть INSTANCE_NAME через все dblink — проверьте лог: {logf}")
    ok(f"DB links checked on TARGET ({' / '.join(ALL_DBLINKS)})")

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
