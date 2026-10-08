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

# ---------- logic pieces ----------

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

# ----- TMP, который генерирует 0.2_pre-copylogs.sql -----
#
# 0.2 пишет tmp_<instance_name таргета>.sql вида:
#   spool ./logs/copylogs_<instance>.log append
#   alter session set time_zone = 'UTC'          <- без ';' (PROMPT срезает его)
#   ...
#   @2.0_copylogs.sql <transfer_no> <dblink>      <- по строке на каждую transfer-сессию
#   spool off
#   exit
# Сам TMP не исполняем: строки после 'alter session' без терминатора sqlplus может
# склеить в один SQL-буфер, и @2.0_copylogs не выполнится. Вместо этого берём из TMP
# пары (transfer_no, dblink) и запускаем 2.0_copylogs.sql для каждой сами.

COPYLOGS_LINE = re.compile(r"^\s*@@?\s*2\.0_copylogs\.sql\s+(\d+)\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)

def parse_tmp_transfers(tmp_path: Path) -> List[tuple]:
    txt = tmp_path.read_text(encoding="utf-8", errors="replace")
    return [(m.group(1), m.group(2)) for m in COPYLOGS_LINE.finditer(txt)]

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
    source_pod_id = topo["source_pod"]
    target_pod    = topo["target_pod"]

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
        ensure_dblink_exists(TARGET_DB, link, UMOVE_USER, UMOVE_PASS, env,
                             expected_pod=topo["source_pod"] if link == ACTIVE_DBLINK else None)

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

    # 0.1/0.2 спулят в относительный ./logs — относительно каталога релиза
    (PRECOPY_SQL_DIR / "logs").mkdir(exist_ok=True)

    # 3) PreCopy session create on TARGET.
    # 0.1 спрашивает 3 ACCEPT: SourcePODID, SourceDBLink, BRAND_ID; сам спулит в
    # ./logs/session_create.log и заканчивается EXIT. Номер transfer-сессии он не печатает,
    # только 'Total users processed: N'.
    say(f"{CYN}==> Running 0.1_pre-copy_session_create.sql on TARGET (UMOVE){NC}")
    pre_copy_path = PRECOPY_SQL_DIR / "0.1_pre-copy_session_create.sql"
    if not pre_copy_path.is_file():
        err(f"Script not found: {pre_copy_path}"); sys.exit(1)

    wrapper = f"""
whenever sqlerror exit 1
whenever oserror exit 1
@{pre_copy_path.as_posix()}
{source_pod_id}
{ACTIVE_DBLINK}
{brand_id}
"""
    rc, out1, logf1 = sqlplus_exec(
        UMOVE_USER, UMOVE_PASS, TARGET_DB,
        wrapper,
        env=env, tag="precopy_session_create", cwd=PRECOPY_SQL_DIR
    )
    if rc != 0:
        err(f"PreCopy session create failed (see log {logf1}, {PRECOPY_SQL_DIR}/logs/session_create.log)"); sys.exit(1)
    m = re.search(r"Total users processed:\s*(\d+)", out1)
    if not m:
        warn(f"0.1 не вывел 'Total users processed' — проверьте лог {logf1}")
    elif int(m.group(1)) == 0:
        warn("0.1: Total users processed: 0 — новых пользователей в transfer-сессии не добавлено "
             "(нет записей status=0 для этого POD в scheduled_users источника, они уже в активной "
             "transfer-сессии, отфильтрованы по brand_id или по userservices.parameter=462).")
    else:
        ok(f"PreCopy session created: {m.group(1)} user(s) processed")

    # 4) PreCopyLogs: 0.2 генерирует TMP со списком transfer-сессий, затем копируем логи по каждой.
    # 0.2 спрашивает 2 ACCEPT: SourcePODID, SourceDBLink.
    say(f"{CYN}==> Running 0.2_pre-copylogs.sql (generate TMP) on TARGET{NC}")
    pre_logs_path = PRECOPY_SQL_DIR / "0.2_pre-copylogs.sql"
    if not pre_logs_path.is_file():
        err(f"Script not found: {pre_logs_path}"); sys.exit(1)

    # очистим старые TMP (tmp_*.sql_bkp не трогаем), чтобы не взять результат прошлого запуска
    for p in PRECOPY_SQL_DIR.glob("tmp_*.sql"):
        try:
            p.unlink()
        except OSError as e:
            err(f"Cannot remove old {p}: {e}"); sys.exit(1)

    gen = f"""
whenever sqlerror exit 1
whenever oserror exit 1
@{pre_logs_path.as_posix()}
{source_pod_id}
{ACTIVE_DBLINK}
"""
    rc, out2, logf2 = sqlplus_exec(
        UMOVE_USER, UMOVE_PASS, TARGET_DB,
        gen,
        env=env, tag="precopylogs_gen", cwd=PRECOPY_SQL_DIR
    )
    if rc != 0:
        err(f"0.2_pre-copylogs.sql failed (see log {logf2})"); sys.exit(1)

    tmps = sorted(PRECOPY_SQL_DIR.glob("tmp_*.sql"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not tmps:
        err(f"TMP file not found after 0.2: expected {PRECOPY_SQL_DIR}/tmp_<instance>.sql (see log {logf2})"); sys.exit(1)
    tmp_sql = tmps[0]
    instance = tmp_sql.stem[len("tmp_"):]
    transfers = parse_tmp_transfers(tmp_sql)
    ok(f"{tmp_sql.name}: transfer-сессий для копирования логов: {len(transfers)}")

    if not transfers:
        warn("0.2 не нашёл transfer-сессий для копирования логов (status null/1/2, "
             "log_continue_dt пуст или старше вчерашнего дня) — копировать нечего.")

    for tno, link in transfers:
        if link.upper() != ACTIVE_DBLINK:
            warn(f"transfer {tno}: в TMP dblink {link}, ожидался {ACTIVE_DBLINK} — использую указанный в TMP.")
        say(f"{CYN}==> 2.0_copylogs.sql {tno} {link}{NC}")
        exec_sql = f"""
whenever sqlerror exit 1
whenever oserror exit 1
alter session set time_zone = 'UTC';
set serveroutput on size 1000000
spool ./logs/copylogs_{instance}.log append
@2.0_copylogs.sql {tno} {link}
spool off
"""
        rc, out3, logf3 = sqlplus_exec(
            UMOVE_USER, UMOVE_PASS, TARGET_DB,
            exec_sql,
            env=env, tag=f"copylogs_{tno}", cwd=PRECOPY_SQL_DIR
        )
        if rc != 0:
            err(f"2.0_copylogs.sql failed for transfer {tno} (see log {logf3}, "
                f"{PRECOPY_SQL_DIR}/logs/copylogs_{instance}.log)"); sys.exit(1)
        ok(f"copylogs done for transfer {tno}")

    # список transfer-сессий для последующих шагов
    (WORK_DIR / "transferno.txt").write_text("".join(f"{tno}\n" for tno, _ in transfers))

    say("")
    ok("Preparation Steps completed.")

if __name__ == "__main__":
    main()
