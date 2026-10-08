#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import os
import re
import sys
from pathlib import Path
from shutil import which
from datetime import datetime
import subprocess
from typing import Optional, List

OK = "\x1b[32m✓\x1b[0m"; WARN = "\x1b[33m!\x1b[0m"; ERR = "\x1b[31m✗\x1b[0m"; CYN = "\x1b[36m"; NC = "\x1b[0m"

def say(m): print(m, flush=True)
def ok(m):  say(f"{OK} {m}")
def warn(m):say(f"{WARN} {m}")
def err(m): say(f"{ERR} {m}")

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

def resolve_path(p: str, base: Path) -> Path:
    """Относительный путь ищем от текущего каталога, затем от каталога config.ini."""
    path = Path(p).expanduser()
    if path.is_absolute() or path.exists():
        return path
    return base / path

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

    # --- POD id ---
    pod_src_a = opt_int(cfg, "prep", "source_pod_id")
    pod_src_b = opt_int(cfg, "links", "src_podid")
    if pod_src_a is not None and pod_src_b is not None and pod_src_a != pod_src_b:
        err(f"prep.source_pod_id={pod_src_a} и links.src_podid={pod_src_b} различаются — оставьте одно."); sys.exit(1)
    t["source_pod"] = _pod_with_override(pod_src_a if pod_src_a is not None else pod_src_b,
                                         dblink_to_pod(t["active_dblink"]), "source")
    t["target_pod"] = _pod_with_override(opt_int(cfg, "prep", "vsched_target_pod"),
                                         dblink_to_pod(unit_to_dblink(t["target_db"])), "target")

    say(f"    SOURCE: {t['source_db']}  (POD {t['source_pod']}, dblink {t['active_dblink']}"
        + (f", passive {', '.join(t['passive_dblinks'])}" if t["passive_dblinks"] else "") + ")")
    say(f"    TARGET: {t['target_db']}  (POD {t['target_pod']})")
    return t

def _pod_with_override(explicit: Optional[int], derived: Optional[int], role: str) -> Optional[int]:
    if explicit is not None:
        if derived is not None and derived != explicit:
            warn(f"POD {role}: в config.ini задан {explicit}, по имени юнита получается {derived} — использую {explicit}.")
        return explicit
    return derived

def require_pod(t: dict, key: str, cfg_hint: str) -> int:
    if t.get(key) is None:
        err(f"Не удалось определить {key} по имени юнита — задайте {cfg_hint} в config.ini"); sys.exit(1)
    return t[key]

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

# ---------- logic pieces ----------

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

# ----- idempotent INSERT into zadmin.vscheduled_users (method A) -----

def load_users_list(users_file: Path) -> List[int]:
    if not users_file.is_file():
        err(f"Users file not found: {users_file}"); sys.exit(1)
    # utf-8-sig: файл, сохранённый в Windows с BOM, иначе даёт int('﻿123') -> ValueError
    raw = users_file.read_text(encoding="utf-8-sig")
    ids, bad = [], []
    for t in re.split(r"[\s,;]+", raw.strip()):
        if not t:
            continue
        if t.isdigit():
            ids.append(int(t))
        else:
            bad.append(t)
    if bad:
        err(f"Non-numeric userid(s) in {users_file}: {', '.join(bad[:10])}{' ...' if len(bad) > 10 else ''}"); sys.exit(1)
    if not ids:
        err(f"Users file is empty: {users_file}"); sys.exit(1)
    uniq = list(dict.fromkeys(ids))
    if len(uniq) != len(ids):
        warn(f"Removed {len(ids) - len(uniq)} duplicate userid(s) from {users_file}")
    return uniq

def build_users_in_clause(ids: List[int], column="u.userid", chunk=1000) -> str:
    """Oracle не допускает более 1000 элементов в IN (...) — ORA-01795. Бьём на части через OR."""
    parts = []
    for i in range(0, len(ids), chunk):
        parts.append(f"{column} IN ({','.join(str(x) for x in ids[i:i + chunk])})")
    return "(" + "\n    OR ".join(parts) + ")"

def build_insert_sql_method_a(target_pod: int, vip_code: str, flags: dict, users_clause: str) -> str:
    vip_code_sql = vip_code.replace("'", "''")
    return f"""
INSERT INTO zadmin.vscheduled_users
  (userid, podid, status, vip_code,
   ext_migrate_mss, ext_migrate_lds, ext_migrate_hit, ext_migrate_mds, ext_migrate_rcv)
SELECT u.userid,
       {int(target_pod)},
       0,
       '{vip_code_sql}',
       {int(flags['mss'])}, {int(flags['lds'])}, {int(flags['hit'])}, {int(flags['mds'])}, {int(flags['rcv'])}
  FROM zportal.users u
 WHERE {users_clause}
   AND NOT EXISTS (SELECT 1 FROM zadmin.vscheduled_users vs
                    WHERE vs.userid = u.userid AND vs.vip_code = '{vip_code_sql}');
COMMIT;
"""

# ----- TMP helpers -----

def detect_tmp_argc(tmp_path: Path) -> int:
    """Return how many positional args (&1, &2) are referenced by tmp SQL."""
    try:
        txt = tmp_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return 0
    argc = 0
    if re.search(r'&\s*1\b', txt): argc = 1
    if re.search(r'&\s*2\b', txt): argc = 2
    return argc

def guess_transfer_no(files: List[Path]) -> Optional[str]:
    """
    Ищет TransferNo только в логах ТЕКУЩЕГО запуска 0.1 (раньше брались любые *.log
    в ./logs — при неудаче текущего запуска подхватывался номер из старого прогона).
    Берётся последнее по тексту совпадение: с 'set echo on' в начале лога лежит
    исходник скрипта (например, 'vTransferNo number := 0'), а реальное значение — ниже.
    """
    pats = [
        r'\bTransfer\s*No\b\s*[:=]\s*(\d+)',
        r'\bTRANSFERNO\b\s*[:=]\s*(\d+)',
        r'vTransferNo\s*number\s*:?\s*=\s*(\d+)',
    ]
    for p in files:
        if not p or not p.is_file():
            continue
        txt = p.read_text(encoding="utf-8", errors="ignore")
        best = None
        for rgx in pats:
            for m in re.finditer(rgx, txt, flags=re.IGNORECASE):
                if best is None or m.start() > best.start():
                    best = m
        if best and int(best.group(1)) > 0:
            return best.group(1)
    return None

# ---------- main ----------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} config.ini"); sys.exit(1)

    cfg_path = Path(sys.argv[1]).resolve()
    cfg = read_config(cfg_path)

    # tools
    need_bin("sqlplus")

    # env
    env = os.environ.copy()
    if cfg.has_option("oracle_env", "tns_admin"):
        env["TNS_ADMIN"] = cfg.get("oracle_env", "tns_admin").strip()
    if cfg.has_option("oracle_env", "oracle_home"):
        env["ORACLE_HOME"] = cfg.get("oracle_env", "oracle_home").strip()
    if env.get("ORACLE_HOME"):
        env["PATH"] = f"{Path(env['ORACLE_HOME']) / 'bin'}:{env.get('PATH', '')}"

    logs_dir = LOG_DIR; logs_dir.mkdir(parents=True, exist_ok=True)

    # creds (ENV first)
    UMOVE_USER = getenv_or_cfg(cfg, "UMOVE_USER", "db", "umove_user", required=True)
    UMOVE_PASS = getenv_or_cfg(cfg, "UMOVE_PASS", "db", "umove_pass", required=True)
    if not UMOVE_USER or not UMOVE_PASS:
        err("UMOVE creds are required (set UMOVE_USER/UMOVE_PASS or config)"); sys.exit(1)

    # SOURCE/TARGET, DB links и POD id — из списков юнитов
    topo = resolve_topology(cfg, UMOVE_USER, UMOVE_PASS, env)
    SOURCE_DB, TARGET_DB = topo["source_db"], topo["target_db"]
    ACTIVE_DBLINK = topo["active_dblink"]
    source_pod_id = require_pod(topo, "source_pod", "[prep] source_pod_id")
    target_pod    = require_pod(topo, "target_pod", "[prep] vsched_target_pod")

    paths = resolve_paths(cfg)
    PRECOPY_SQL_DIR = paths["precopy_sql_dir"].resolve()
    WORK_DIR        = paths["work_dir"].resolve()
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    brand_id = opt_int(cfg, "prep", "brand_id") or 0
    # ext_migrate_* по умолчанию 0 — в config.ini указываются только включённые
    flags = {k: opt_int(cfg, "prep", f"ext_migrate_{k}") or 0 for k in ("mss", "lds", "hit", "mds", "rcv")}
    vip_code = cfg_get(cfg, "prep", "vip_code_name")

    # 0) connectivity sanity (UMOVE to both)
    say(f"{CYN}==> Checking sqlplus connectivity (UMOVE) to SOURCE {SOURCE_DB} and TARGET {TARGET_DB}{NC}")
    for alias in (SOURCE_DB, TARGET_DB):
        rc, out, logf = sqlplus_exec(
            UMOVE_USER, UMOVE_PASS, alias,
            "whenever sqlerror exit 1;\nset head off pages 0 feed off\nselect 'CONNECT_OK' from dual;\n",
            env=env, tag=f"connect_{alias}", timeout=PROBE_TIMEOUT
        )
        if rc != 0 or "CONNECT_OK" not in out:
            err(f"Cannot connect as UMOVE to {alias} (see log {logf})"); sys.exit(1)
    ok("Connectivity OK")

    # 1) Ensure DB links on TARGET (UMOVE) and ping
    say(f"{CYN}==> Ensuring DB links exist on TARGET (UMOVE){NC}")
    for link in [ACTIVE_DBLINK] + topo["passive_dblinks"]:
        ensure_dblink_exists(TARGET_DB, link, UMOVE_USER, UMOVE_PASS, env)

    # 2) Populate ZADMIN.VSCHEDULED_USERS on SOURCE (method A) — idempotent
    say(f"{CYN}==> Populating ZADMIN.VSCHEDULED_USERS on SOURCE via method A (idempotent){NC}")
    users_file = cfg.get("prep", "users_file", fallback="").strip()
    if users_file:
        ids = load_users_list(resolve_path(users_file, cfg_path.parent))
        say(f"    users: {len(ids)}")
        users_where = build_users_in_clause(ids)
    else:
        users_where = cfg_get(cfg, "prep", "users_where", required=True)

    insert_sql = build_insert_sql_method_a(target_pod, vip_code, flags, users_where)
    rc, out, logf = sqlplus_exec(
        UMOVE_USER, UMOVE_PASS, SOURCE_DB,
        f"whenever sqlerror exit 1 rollback\nset echo on feedback on\n{insert_sql}",
        env=env, tag="insert_vscheduled_users"
    )
    if rc != 0:
        err(f"Failed to INSERT into zadmin.vscheduled_users (see log {logf})"); sys.exit(1)
    m = re.search(r"(\d+|no) rows? (created|inserted)", out, flags=re.IGNORECASE)
    ok(f"vscheduled_users populated (no duplicates added){': ' + m.group(0) if m else ''}")

    # 3) PreCopy session create on TARGET  (feeds answers for ACCEPT)
    say(f"{CYN}==> Running 0.1_pre-copy_session_create.sql on TARGET (UMOVE){NC}")
    pre_copy_path = PRECOPY_SQL_DIR / "0.1_pre-copy_session_create.sql"
    if not pre_copy_path.is_file():
        err(f"Script not found: {pre_copy_path}"); sys.exit(1)

    # Пути spool — абсолютные: sqlplus запускается с cwd=PRECOPY_SQL_DIR, и относительный
    # 'logs/...' писался в PRECOPY_SQL_DIR/logs (или не писался вовсе, если каталога нет).
    sess_call_log = logs_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_precopy_session_create_call.log"
    wrapper = f"""
spool {sess_call_log.as_posix()} append
whenever sqlerror exit 1
set echo on
prompt === 0.1_pre-copy_session_create.sql BEGIN ===
prompt CONNECT: {UMOVE_USER}@{TARGET_DB}
prompt (feeding answers to ACCEPT below)
@{pre_copy_path.as_posix()}
{source_pod_id}
{ACTIVE_DBLINK}
{brand_id}
prompt === 0.1_pre-copy_session_create.sql END ===
spool off
"""
    rc, out1, logf1 = sqlplus_exec(
        UMOVE_USER, UMOVE_PASS, TARGET_DB,
        wrapper,
        env=env, tag="precopy_session_create", cwd=PRECOPY_SQL_DIR
    )
    if rc != 0:
        err(f"PreCopy session create failed (see log {logf1})"); sys.exit(1)
    ok("PreCopy session created")

    # 4) PreCopyLogs: generate TMP then execute it (feeds answers for ACCEPT)
    say(f"{CYN}==> Running 0.2_pre-copylogs.sql (generate TMP) and executing TMP on TARGET{NC}")
    pre_logs_path = PRECOPY_SQL_DIR / "0.2_pre-copylogs.sql"
    if not pre_logs_path.is_file():
        err(f"Script not found: {pre_logs_path}"); sys.exit(1)

    # очистим старые TMP, чтобы не путать поиск
    for p in PRECOPY_SQL_DIR.glob("tmp_*.sql"):
        try:
            p.unlink()
        except OSError as e:
            warn(f"Cannot remove old {p}: {e}")
    gen_started = datetime.now().timestamp()

    logs_call = logs_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_precopylogs_gen_call.log"
    gen = f"""
spool {logs_call.as_posix()} append
whenever sqlerror exit 1
set echo on
prompt === 0.2_pre-copylogs.sql BEGIN ===
prompt CONNECT: {UMOVE_USER}@{TARGET_DB}
prompt (feeding answers to ACCEPT below)
@{pre_logs_path.as_posix()}
{source_pod_id}
{ACTIVE_DBLINK}
prompt === 0.2_pre-copylogs.sql END ===
spool off
"""
    rc, out2, logf2 = sqlplus_exec(
        UMOVE_USER, UMOVE_PASS, TARGET_DB,
        gen,
        env=env, tag="precopylogs_gen", cwd=PRECOPY_SQL_DIR
    )
    if rc != 0:
        err(f"0.2_pre-copylogs.sql failed (see log {logf2})"); sys.exit(1)

    # Поиск нового TMP в каталоге pre-copy: сначала по имени из вывода, затем — самый
    # свежий tmp_*.sql, созданный после запуска генератора.
    tmp_sql = None
    for m in re.finditer(r"tmp_[\w\-]+\.sql", out2, flags=re.IGNORECASE):
        cand = PRECOPY_SQL_DIR / m.group(0)
        if cand.is_file():
            tmp_sql = cand
    if tmp_sql is None:
        cands = sorted((p for p in PRECOPY_SQL_DIR.glob("tmp_*.sql") if p.stat().st_mtime >= gen_started - 1),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        if cands:
            tmp_sql = cands[0]
    if tmp_sql is None:
        err(f"TMP file not found after generator: expected {PRECOPY_SQL_DIR}/tmp_*.sql (see log {logf2})"); sys.exit(1)
    if tmp_sql.stat().st_size == 0:
        err(f"TMP file {tmp_sql} is empty (see log {logf2})"); sys.exit(1)

    # ---- autodetect & pass args to TMP (&1=TransferNo, &2=ACTIVE_DBLINK) ----
    argc = detect_tmp_argc(tmp_sql)
    args_str = ""
    transfer_no = guess_transfer_no([sess_call_log, logf1])
    if argc >= 1:
        if not transfer_no:
            err(f"Cannot detect TransferNo for TMP execution (&1). Check 0.1 logs: {logf1}"); sys.exit(1)
        args_str = f" {transfer_no}"
    if argc >= 2:
        args_str += f" {ACTIVE_DBLINK}"

    say(f"{CYN}==> Executing {tmp_sql.name} on TARGET (UMOVE){NC}")
    tmp_call_log = logs_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_precopylogs_exec_call.log"
    exec_sql = f"""
spool {tmp_call_log.as_posix()} append
whenever sqlerror exit 1
set echo on
prompt === EXEC TMP BEGIN ===
prompt CONNECT: {UMOVE_USER}@{TARGET_DB}
prompt TMP file : {tmp_sql.name}
prompt TMP args :{args_str or ' <none>'}
@{tmp_sql.as_posix()}{args_str}
prompt === EXEC TMP END ===
spool off
"""
    rc, out3, logf3 = sqlplus_exec(
        UMOVE_USER, UMOVE_PASS, TARGET_DB,
        exec_sql,
        env=env, tag="precopylogs_exec", cwd=PRECOPY_SQL_DIR
    )
    if rc != 0:
        err(f"TMP execution failed (see log {logf3})"); sys.exit(1)
    ok("PreCopyLogs done (TMP executed)")

    # (опц.) сохраним TransferNo для последующих шагов
    if transfer_no:
        (WORK_DIR / "transferno.txt").write_text(str(transfer_no))

    say("")
    ok("Preparation Steps completed.")

if __name__ == "__main__":
    main()
