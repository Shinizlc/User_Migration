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

def run(cmd, input_text=None, env=None, cwd=None, logfile: Optional[Path]=None):
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input_text else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        cwd=str(cwd) if cwd else None
    )
    out,_ = proc.communicate(input=input_text)
    if logfile:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        logfile.write_text((logfile.read_text() if logfile.exists() else "") + (out or ""))
    return proc.returncode, out

# ---------- sqlplus helpers ----------

def sqlplus_exec(connect_str, sql, env=None, logdir=Path("./logs"), tag="session", cwd=None):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logf = logdir / f"{ts}_{tag}.log"
    rc, out = run(["sqlplus", "-s", connect_str], input_text=sql, env=env, cwd=cwd, logfile=logf)
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

# ---------- active unit autodetect ----------

def try_read_only_mode(tns_alias, um_user, um_pass, env):
    rc, out, _ = sqlplus_exec(
        f"{um_user}/{um_pass}@{tns_alias}",
        "whenever oserror exit 1;\nwhenever sqlerror exit 1;\nset head off pages 0 feed off\n"
        "select zportal.getbuzmeparameter('read_only_mode') from dual;\n",
        env=env, tag=f"{tns_alias}_romode"
    )
    if rc != 0 or out is None:
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
    act, pas = None, []
    for a in aliases:
        mode = try_read_only_mode(a, um_user, um_pass, env)
        if mode is None:
            warn(f"Не удалось определить read_only_mode для {a} — пропускаю.")
            continue
        if mode == 0:
            act = a
        else:
            pas.append(a)
    if not act:
        err(f"Не найден активный юнит среди: {', '.join(aliases)}" + (f" (роль: {role_expected})" if role_expected else ""))
        sys.exit(1)
    ok(f"Определён активный юнит ({role_expected or 'DB'}): {act}" + (f"; пассивные: {', '.join(pas)}" if pas else ""))
    return act, pas

# ---------- logic pieces ----------

def ensure_dblink_exists(target_db, dblink_name, um_user, um_pass, env):
    name_up = dblink_name.upper()
    check_sql = f"""
set head off pages 0 feed off
select count(*) from user_db_links where db_link = '{name_up}';
"""
    rc, out, _ = sqlplus_exec(f"{um_user}/{um_pass}@{target_db}", check_sql, env=env, tag=f"check_dblink_{name_up}")
    if rc != 0:
        err(f"Failed to check DB link {name_up} on TARGET"); sys.exit(1)

    cnt = 0
    for line in (out or "").splitlines():
        s = line.strip()
        if s.isdigit():
            cnt = int(s); break

    if cnt == 0:
        say(f"{CYN}==> Creating DB link {name_up} on TARGET (UMOVE){NC}")
        create_block = f"""
DECLARE
  stmt VARCHAR2(4000);
BEGIN
  stmt := q'[CREATE DATABASE LINK {name_up}
              CONNECT TO {um_user} IDENTIFIED BY "{um_pass}"
              USING '{name_up}']';
  EXECUTE IMMEDIATE stmt;
END;
/
"""
        rc2, _, _ = sqlplus_exec(f"{um_user}/{um_pass}@{target_db}", create_block, env=env, tag=f"create_dblink_{name_up}")
        if rc2 != 0:
            err(f"Failed to create DB link {name_up} on TARGET"); sys.exit(1)
        ok(f"DB link {name_up} created on TARGET.")
    else:
        ok(f"DB link {name_up} already exists on TARGET.")

    # ping
    ping_sql = f"whenever sqlerror exit 1;\nselect 1 from dual@{name_up};\n"
    rc3, out3, _ = sqlplus_exec(f"{um_user}/{um_pass}@{target_db}", ping_sql, env=env, tag=f"ping_dblink_{name_up}")
    if rc3 != 0 or "1" not in (out3 or ""):
        err(f"DB link {name_up} exists but connectivity failed"); sys.exit(1)
    ok(f"DB link {name_up} is reachable.")

# ----- idempotent INSERT into zadmin.vscheduled_users (method A) -----

def load_users_list(users_file: Path) -> List[str]:
    if not users_file.exists():
        err(f"Users file not found: {users_file}"); sys.exit(1)
    raw = users_file.read_text(encoding='utf-8')
    tokens = re.split(r"[\s,]+", raw.strip())
    ids = [t for t in tokens if t]
    if not ids:
        err(f"Users file is empty: {users_file}"); sys.exit(1)
    return ids

def build_insert_sql_method_a(target_pod: int, vip_code: str, flags: dict, users_clause: str) -> str:
    return f"""
INSERT /*+ append */ INTO zadmin.vscheduled_users
  (userid, podid, status, vip_code,
   ext_migrate_mss, ext_migrate_lds, ext_migrate_hit, ext_migrate_mds, ext_migrate_rcv)
SELECT u.userid,
       {int(target_pod)},
       0,
       '{vip_code}',
       {int(flags['mss'])}, {int(flags['lds'])}, {int(flags['hit'])}, {int(flags['mds'])}, {int(flags['rcv'])}
  FROM zportal.users u
 WHERE {users_clause}
   AND NOT EXISTS (SELECT 1 FROM zadmin.vscheduled_users vs
                    WHERE vs.userid = u.userid AND vs.vip_code = '{vip_code}')
;
COMMIT;
"""

# ----- TMP helpers -----

def detect_tmp_argc(tmp_path: Path) -> int:
    """Return how many positional args (&1, &2) are referenced by tmp SQL."""
    try:
        txt = tmp_path.read_text(errors="ignore")
    except Exception:
        return 0
    argc = 0
    if re.search(r'&\s*1\b', txt): argc = 1
    if re.search(r'&\s*2\b', txt): argc = 2
    return argc

def guess_transfer_no(logs_dir: Path) -> Optional[str]:
    """Try to parse TransferNo from latest 0.1 logs."""
    pats = [
        r'\bTransfer\s*No\b[:=]\s*(\d+)',
        r'\bTRANSFERNO\b\s*[:=]\s*(\d+)',
        r'vTransferNo\s*number\s*:?\s*=\s*(\d+)',
    ]
    cands = sorted(list(logs_dir.glob("*precopy_session_create*.log")), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in cands:
        try:
            txt = p.read_text(errors="ignore")
        except Exception:
            continue
        for rgx in pats:
            m = re.search(rgx, txt, flags=re.IGNORECASE)
            if m:
                return m.group(1)
    return None

# ---------- main ----------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} config.ini"); sys.exit(1)

    cfg_path = Path(sys.argv[1])
    cfg = configparser.ConfigParser()
    cfg.read(cfg_path)

    # tools
    need_bin("sqlplus")

    # env
    env = os.environ.copy()
    if cfg.has_option("oracle_env", "tns_admin"):
        env["TNS_ADMIN"] = cfg.get("oracle_env", "tns_admin").strip()
    if cfg.has_option("oracle_env", "oracle_home"):
        env["ORACLE_HOME"] = cfg.get("oracle_env", "oracle_home").strip()
    if env.get("ORACLE_HOME"):
        env["PATH"] = f"{Path(env['ORACLE_HOME'])/ 'bin'}:{env['PATH']}"

    logs_dir = Path("./logs"); logs_dir.mkdir(exist_ok=True)

    # creds (ENV first)
    UMOVE_USER = getenv_or_cfg(cfg, "UMOVE_USER", "db", "umove_user", required=True)
    UMOVE_PASS = getenv_or_cfg(cfg, "UMOVE_PASS", "db", "umove_pass", required=True)
    if not UMOVE_USER or not UMOVE_PASS:
        err("UMOVE creds are required (set UMOVE_USER/UMOVE_PASS or config)"); sys.exit(1)

    # resolve SOURCE/TARGET TNS
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

    # links + paths + prep params
    ACTIVE_DBLINK  = cfg_get(cfg, "links", "active_src_dblink")
    PASSIVE_DBLINK = cfg_get(cfg, "links", "passive_src_dblink")

    SQL_DIR         = Path(cfg_get(cfg, "paths", "sql_dir"))
    PRECOPY_SQL_DIR = Path(cfg.get("paths", "precopy_sql_dir", fallback=str(SQL_DIR)))
    WORK_DIR        = Path(cfg.get("paths", "work_dir", fallback=".")).resolve()
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    target_pod    = int(cfg_get(cfg, "prep", "vsched_target_pod"))
    brand_id      = int(cfg.get("prep", "brand_id", fallback="0") or 0)
    source_pod_id = int(cfg_get(cfg, "prep", "source_pod_id"))
    vip_code      = cfg_get(cfg, "prep", "vip_code_name")
    flags = {
        "mss": int(cfg_get(cfg, "prep", "ext_migrate_mss")),
        "lds": int(cfg_get(cfg, "prep", "ext_migrate_lds")),
        "hit": int(cfg_get(cfg, "prep", "ext_migrate_hit")),
        "mds": int(cfg_get(cfg, "prep", "ext_migrate_mds")),
        "rcv": int(cfg_get(cfg, "prep", "ext_migrate_rcv")),
    }

    # 0) connectivity sanity (UMOVE to both)
    say(f"{CYN}==> Checking sqlplus connectivity (UMOVE) to SOURCE {SOURCE_DB} and TARGET {TARGET_DB}{NC}")
    for alias in (SOURCE_DB, TARGET_DB):
        rc, out, _ = sqlplus_exec(
            f"{UMOVE_USER}/{UMOVE_PASS}@{alias}",
            "whenever oserror exit 1;\nwhenever sqlerror exit 1;\nselect 1 from dual;\n",
            env=env, tag=f"connect_{alias}"
        )
        if rc != 0 or "1" not in (out or ""):
            err(f"Cannot connect as UMOVE to {alias}")
    ok("Connectivity OK")

    # 1) Ensure DB links on TARGET (UMOVE) and ping
    say(f"{CYN}==> Ensuring DB links exist on TARGET (UMOVE){NC}")
    ensure_dblink_exists(TARGET_DB, ACTIVE_DBLINK,  UMOVE_USER, UMOVE_PASS, env)
    ensure_dblink_exists(TARGET_DB, PASSIVE_DBLINK, UMOVE_USER, UMOVE_PASS, env)

    # 2) Populate ZADMIN.VSCHEDULED_USERS on SOURCE (method A) — idempotent
    say(f"{CYN}==> Populating ZADMIN.VSCHEDULED_USERS on SOURCE via method A (idempotent){NC}")
    users_file = cfg.get("prep", "users_file", fallback="").strip()
    if users_file:
        ids = load_users_list(Path(users_file))
        in_list = ",".join(str(int(x)) for x in ids)
        users_where = f"u.userid IN ({in_list})"
    else:
        users_where = cfg_get(cfg, "prep", "users_where", required=True)

    insert_sql = build_insert_sql_method_a(target_pod, vip_code, flags, users_where)
    rc, _, logf = sqlplus_exec(
        f"{UMOVE_USER}/{UMOVE_PASS}@{SOURCE_DB}",
        f"whenever sqlerror exit 1;\nset echo on\n{insert_sql}",
        env=env, tag="insert_vscheduled_users"
    )
    if rc != 0:
        err(f"Failed to INSERT into zadmin.vscheduled_users (see log {logf})"); sys.exit(1)
    ok("vscheduled_users populated (no duplicates added)")

    # 3) PreCopy session create on TARGET  (feeds answers for ACCEPT)
    say(f"{CYN}==> Running 0.1_pre-copy_session_create.sql on TARGET (UMOVE){NC}")
    pre_copy_path = PRECOPY_SQL_DIR / "0.1_pre-copy_session_create.sql"
    if not pre_copy_path.exists():
        err(f"Script not found: {pre_copy_path}"); sys.exit(1)

    sess_call_log = (logs_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_precopy_session_create_call.log")
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
        f"{UMOVE_USER}/{UMOVE_PASS}@{TARGET_DB}",
        wrapper,
        env=env, tag="precopy_session_create", cwd=PRECOPY_SQL_DIR
    )
    if rc != 0:
        err(f"PreCopy session create failed (see log {logf1})"); sys.exit(1)
    ok("PreCopy session created")

    # 4) PreCopyLogs: generate TMP then execute it (feeds answers for ACCEPT)
    say(f"{CYN}==> Running 0.2_pre-copylogs.sql (generate TMP) and executing TMP on TARGET{NC}")
    pre_logs_path = PRECOPY_SQL_DIR / "0.2_pre-copylogs.sql"
    if not pre_logs_path.exists():
        err(f"Script not found: {pre_logs_path}"); sys.exit(1)

    # очистим старые TMP, чтобы не путать поиск
    for p in PRECOPY_SQL_DIR.glob("tmp_*.sql"):
        try: p.unlink()
        except: pass

    logs_call = (logs_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_precopylogs_gen_call.log")
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
        f"{UMOVE_USER}/{UMOVE_PASS}@{TARGET_DB}",
        gen,
        env=env, tag="precopylogs_gen", cwd=PRECOPY_SQL_DIR
    )
    if rc != 0:
        err(f"0.2_pre-copylogs.sql failed (see log {logf2})"); sys.exit(1)

    # Поиск нового TMP в каталоге pre-copy
    tmp_sql = None
    m = re.search(r"tmp_([\w\-]+)\.sql", (out2 or ""), flags=re.IGNORECASE)
    if m:
        tmp_sql = PRECOPY_SQL_DIR / f"tmp_{m.group(1)}.sql"
    else:
        cands = sorted(PRECOPY_SQL_DIR.glob("tmp_*.sql"), key=lambda p: p.stat().st_mtime, reverse=True)
        if cands:
            tmp_sql = cands[0]
    if not tmp_sql or not tmp_sql.exists():
        err(f"TMP file not found after generator: expected {PRECOPY_SQL_DIR}/tmp_*.sql"); sys.exit(1)

    # ---- NEW: autodetect & pass args to TMP (&1=TransferNo, &2=ACTIVE_DBLINK) ----
    argc = detect_tmp_argc(tmp_sql)
    args_str = ""
    transfer_no = None
    if argc >= 1:
        transfer_no = guess_transfer_no(logs_dir)
        if not transfer_no:
            err("Cannot detect TransferNo for TMP execution (&1). Check 0.1 logs."); sys.exit(1)
        args_str = f" {transfer_no}"
    if argc >= 2:
        args_str += f" {ACTIVE_DBLINK}"

    say(f"{CYN}==> Executing {tmp_sql.name} on TARGET (UMOVE){NC}")
    tmp_call_log = (logs_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_precopylogs_exec_call.log")
    exec_sql = f"""
spool {tmp_call_log.as_posix()} append
whenever sqlerror exit 1
set echo on
prompt === EXEC TMP BEGIN ===
prompt CONNECT: {UMOVE_USER}@{TARGET_DB}
prompt TMP file : {tmp_sql.name}
prompt TMP args :{args_str or ' <none>'}
@{tmp_sql.name}{args_str}
prompt === EXEC TMP END ===
spool off
"""
    rc, out3, logf3 = sqlplus_exec(
        f"{UMOVE_USER}/{UMOVE_PASS}@{TARGET_DB}",
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

