#!/usr/bin/env python3
"""Incremental pull of new QQ messages (read-only, one-shot).

Run it once per polling cycle from cron, a monitoring agent, or by
hand:

    python3 patrol_pull.py [--workdir DIR] [--user-uin NNN]

Pipeline (everything happens on COPIES inside the workdir; QQ's own
files are only ever read, never written, never opened with SQLite):

  1. Read-only copy nt_msg.db / group_msg_fts.db / group_info.db
     (each with -wal/-shm when present) into a per-run work dir.
  2. Decrypt with the stored key (<workdir>/key.json) using
     qq_crypto: WAL frames are applied with the salt-generation +
     commit-boundary filter (Linux QQ 3.2.34 pitfall: frame
     checksums match neither stock variant, so checksum gating
     must NOT be used), then PRAGMA integrity_check gates the
     result, with a main-DB-only fallback.
  3. If the stored key no longer verifies (QQ re-login changed
     it), recover the key from the running QQ process's memory with
     the memory-capped scanners (scan_key.py fast paths, then
     strong_scan.py full sweep) and retry once. Still failing ->
     status KEY_FAIL, exit code 3.
  4. Extract messages newer than <workdir>/watermark.json
     (per-source max (sendTime, msgId)); the watermark is
     initialised to the current maxima on first run so history is
     never dumped. The watermark is updated ONLY after the
     extraction output has been printed.
  5. Emit JSON lines on stdout: one status line, then one line per
     new message (group messages from group_msg_table, private
     messages from c2c_msg_table). Text comes from the FTS content
     table's flattened-text column (group_msg_fts."41701", joined
     on msgId 40001) when available, else from parsing the 40800
     protobuf of nt_msg directly. Non-text elements and @ targets
     always come from the 40800 parse.

Configuration (first match wins): CLI flags > environment
(QQ_READER_WORKDIR / QQ_READER_UIN / QQ_READER_QQ_HOME) >
<workdir>/config.json (see config.example.json) > defaults.
The workdir defaults to this script's directory.

Contains ZERO network functionality. Never writes outside the
workdir. The recovered key is never printed.
"""

import argparse
import base64
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import qq_crypto as qc  # noqa: E402

# --- configuration (defaults; configure() applies CLI/env/config) ---
WORKDIR = SCRIPT_DIR
KEY_PATH = os.path.join(WORKDIR, "key.json")
WM_PATH = os.path.join(WORKDIR, "watermark.json")
MAP_PATH = os.path.join(WORKDIR, "group_map.json")
IDENT_PATH = os.path.join(WORKDIR, "identity.json")
RUNS_DIR = os.path.join(WORKDIR, "runs")
QQ_HOME = os.path.expanduser("~/.config/QQ")
USER_UIN = None  # the account owner's QQ number (for @-me detection)
TZ = timezone(timedelta(hours=8))


def configure(workdir=None, config_path=None, user_uin=None,
              qq_home=None, tz_offset=None):
    global WORKDIR, KEY_PATH, WM_PATH, MAP_PATH, IDENT_PATH, RUNS_DIR
    global QQ_HOME, USER_UIN, TZ
    WORKDIR = (workdir or os.environ.get("QQ_READER_WORKDIR")
               or SCRIPT_DIR)
    cfg = {}
    cfg_path = config_path or os.path.join(WORKDIR, "config.json")
    if cfg_path and os.path.exists(cfg_path):
        try:
            with open(cfg_path) as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
    KEY_PATH = os.path.join(WORKDIR, "key.json")
    WM_PATH = os.path.join(WORKDIR, "watermark.json")
    MAP_PATH = os.path.join(WORKDIR, "group_map.json")
    IDENT_PATH = os.path.join(WORKDIR, "identity.json")
    RUNS_DIR = os.path.join(WORKDIR, "runs")
    uin = user_uin or os.environ.get("QQ_READER_UIN") \
        or cfg.get("user_uin")
    USER_UIN = int(uin) if uin else None
    QQ_HOME = (qq_home or os.environ.get("QQ_READER_QQ_HOME")
               or cfg.get("qq_home") or QQ_HOME)
    QQ_HOME = os.path.expanduser(QQ_HOME)
    off = tz_offset if tz_offset is not None \
        else cfg.get("tz_offset_hours", 8)
    TZ = timezone(timedelta(hours=float(off)))


EXIT_OK = 0
EXIT_KEY_FAIL = 3
EXIT_ERROR = 4

ETYPE_NAMES = {1: "text", 2: "image", 3: "file", 4: "voice",
               5: "video", 6: "face", 7: "reply", 8: "gray-tip",
               10: "ark-card", 16: "forward"}


def cst_str(ts):
    return datetime.fromtimestamp(ts, TZ).strftime("%Y-%m-%d %H:%M:%S")


def emit(obj):
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def atomic_write_json(path, obj, mode=0o600):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# ------------------------------------------------------------------
# protobuf element parsing (extended from parse_proof.py)
# ------------------------------------------------------------------

def read_varint(buf, i):
    shift = 0
    val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7


def iter_fields(buf):
    i = 0
    n = len(buf)
    while i < n:
        try:
            tag, i = read_varint(buf, i)
        except Exception:
            return
        field, wt = tag >> 3, tag & 7
        if field == 0:
            return
        try:
            if wt == 0:
                v, i = read_varint(buf, i)
                yield field, wt, v
            elif wt == 2:
                ln, i = read_varint(buf, i)
                v = buf[i:i + ln]
                if len(v) < ln:
                    return
                i += ln
                yield field, wt, v
            elif wt == 5:
                v = buf[i:i + 4]
                i += 4
                yield field, wt, v
            elif wt == 1:
                v = buf[i:i + 8]
                i += 8
                yield field, wt, v
            else:
                return
        except Exception:
            return


def parse_element(elem):
    """One ElementWire -> dict(type, text, at_uid)."""
    etype = None
    text = None
    at_uid = None
    for field, wt, v in iter_fields(elem):
        if field == 45002 and wt == 0:
            etype = v
        elif field == 45101 and wt == 2:
            text = v.decode("utf-8", errors="replace")
        elif field == 45105 and wt == 2:
            at_uid = v.decode("utf-8", errors="replace")
    return {"type": etype, "text": text, "at_uid": at_uid}


def parse_message(blob):
    """40800 blob -> list of element dicts (empty list if unparseable)."""
    if not blob:
        return []
    elems = []
    for field, wt, v in iter_fields(blob):
        if field == 40800 and wt == 2:
            elems.append(parse_element(v))
    return elems


# ------------------------------------------------------------------
# QQ process / data-dir helpers
# ------------------------------------------------------------------

def find_nt_db_dir():
    hits = sorted(glob.glob(os.path.join(QQ_HOME, "nt_qq_*", "nt_db")))
    return hits[0] if hits else None


def qq_pids():
    """All pids whose cmdline is a QQ binary; main pid = the one
    mapping wrapper.node (the NT kernel)."""
    any_qq = []
    main_pid = None
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read()
        except OSError:
            continue
        if b"/opt/QQ/qq" not in cmd:
            continue
        any_qq.append(int(pid))
        try:
            with open(f"/proc/{pid}/maps", "rb") as f:
                if b"wrapper.node" in f.read():
                    main_pid = int(pid)
        except OSError:
            pass
    return any_qq, main_pid


def copy_db_set(nt_db, dest_dir, names):
    copied = {}
    for name in names:
        for suffix in ("", "-wal", "-shm"):
            src = os.path.join(nt_db, name + suffix)
            if os.path.exists(src):
                dst = os.path.join(dest_dir, name + suffix)
                shutil.copyfile(src, dst)
                if suffix == "":
                    copied[name] = dst
    return copied


# ------------------------------------------------------------------
# decrypt helpers
# ------------------------------------------------------------------

class KeyFail(Exception):
    pass


def load_passphrase():
    with open(KEY_PATH) as f:
        mat = json.load(f)
    return base64.b64decode(mat["passphrase_b64"])


def decrypt_to_bytes(enc_path, wal_path, passphrase, apply_wal=True):
    """Decrypt one DB copy; returns plaintext bytes.
    Raises KeyFail if the passphrase does not verify on page 1."""
    stripped = qc.load_stripped(enc_path)
    algo = qc.detect_algo(stripped, passphrase)
    if not algo:
        raise KeyFail(f"key does not verify for {os.path.basename(enc_path)}")
    plain = bytearray(qc.decrypt_database(stripped, passphrase, algo))
    if apply_wal and wal_path and os.path.exists(wal_path) \
            and os.path.getsize(wal_path) > 0:
        with open(wal_path, "rb") as f:
            wal = f.read()
        frames, _info = qc.decrypt_wal_frames(
            wal, passphrase, algo, stripped[:qc.SALT_SIZE])
        for pgno, page in frames:
            need = pgno * qc.PAGE_SIZE
            if need > len(plain):
                plain.extend(b"\x00" * (need - len(plain)))
            plain[(pgno - 1) * qc.PAGE_SIZE: pgno * qc.PAGE_SIZE] = page
    return bytes(plain)


def integrity_ok(path):
    try:
        con = sqlite3.connect(f"file:{path}?immutable=1", uri=True)
        row = con.execute("PRAGMA integrity_check").fetchone()
        con.close()
        return bool(row) and row[0] == "ok"
    except Exception:
        return False


def decrypt_db_checked(enc_path, wal_path, passphrase, out_path):
    """Decrypt with WAL; if integrity_check fails, retry main-only.
    Returns True on success."""
    for apply_wal in (True, False):
        try:
            data = decrypt_to_bytes(enc_path, wal_path, passphrase,
                                    apply_wal=apply_wal)
        except KeyFail:
            raise
        with open(out_path, "wb") as f:
            f.write(data)
        if integrity_ok(out_path):
            return True
    return False


def recover_key(run_dir, main_pid):
    """Run the memory-capped scanners against the live QQ process.
    Returns True if a new verified key was saved to KEY_PATH."""
    settings = os.path.join(run_dir, "settings.db")
    msgdb = os.path.join(run_dir, "nt_msg.db")
    if not (os.path.exists(settings) and os.path.exists(msgdb) and main_pid):
        return False

    def run(cmd, timeout):
        try:
            r = subprocess.run(cmd, shell=True, timeout=timeout,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            return r.returncode == 0
        except Exception:
            return False

    base = ("ulimit -v 2097152; exec python3 "
            f"{os.path.join(SCRIPT_DIR, 'scan_key.py')} --pids {main_pid} "
            f"--settings {settings} --msgdb {msgdb} --out {KEY_PATH}")
    if run(f"bash -c '{base}'", timeout=300):
        return True
    base2 = ("ulimit -v 2097152; exec python3 "
             f"{os.path.join(SCRIPT_DIR, 'strong_scan.py')} --pid {main_pid} "
             f"--settings {settings} --msgdb {msgdb} --out {KEY_PATH}")
    return run(f"bash -c '{base2}'", timeout=1200)


# ------------------------------------------------------------------
# group map + identity
# ------------------------------------------------------------------

def refresh_group_map(info_plain_path, src_mtime):
    try:
        con = sqlite3.connect(f"file:{info_plain_path}?immutable=1",
                              uri=True)
        groups = {}
        for gid, name in con.execute(
                'SELECT "60001", "60007" FROM group_list'):
            if gid and name:
                groups[str(gid)] = name
        try:
            for gid, name in con.execute(
                    'SELECT "60001", "60007" FROM group_detail_info_ver1'):
                if gid and name and str(gid) not in groups:
                    groups[str(gid)] = name
        except Exception:
            pass
        con.close()
        atomic_write_json(MAP_PATH,
                          {"built_from_mtime": src_mtime, "groups": groups})
        return groups
    except Exception:
        return None


def load_group_map(info_plain_path, info_src_path):
    groups = {}
    built = None
    if os.path.exists(MAP_PATH):
        try:
            with open(MAP_PATH) as f:
                saved = json.load(f)
            groups = saved.get("groups", {})
            built = saved.get("built_from_mtime")
        except Exception:
            groups, built = {}, None
    try:
        mtime = int(os.path.getmtime(info_src_path))
    except OSError:
        mtime = None
    if info_plain_path and mtime is not None and mtime != built:
        fresh = refresh_group_map(info_plain_path, mtime)
        if fresh is not None:
            groups = fresh
    return groups


def load_identity(msg_con):
    ident = {"user_uin": USER_UIN, "user_uid": None}
    if os.path.exists(IDENT_PATH):
        try:
            with open(IDENT_PATH) as f:
                saved = json.load(f)
            if saved.get("user_uid"):
                saved.setdefault("user_uin", USER_UIN)
                return saved
            if saved.get("user_uin") and not ident["user_uin"]:
                ident["user_uin"] = saved["user_uin"]
        except Exception:
            pass
    if ident["user_uin"]:
        try:
            row = msg_con.execute(
                'SELECT DISTINCT "40020" FROM group_msg_table '
                'WHERE "40033" = ? LIMIT 1',
                (ident["user_uin"],)).fetchone()
            if row:
                ident["user_uid"] = row[0]
                atomic_write_json(IDENT_PATH, ident)
        except Exception:
            pass
    return ident


# ------------------------------------------------------------------
# extraction
# ------------------------------------------------------------------

def table_max(con, table):
    row = con.execute(
        f'SELECT "40050", "40001" FROM "{table}" '
        f'ORDER BY "40050" DESC, "40001" DESC LIMIT 1').fetchone()
    return [row[0], row[1]] if row else [0, 0]


def extract_new(con, table, wm):
    wm_ts, wm_mid = wm
    return con.execute(
        f'SELECT "40001", "40027", "40020", "40033", "40021", "40030", '
        f'"40050", "40800" FROM "{table}" '
        f'WHERE ("40050" > ? OR ("40050" = ? AND "40001" > ?)) '
        f'ORDER BY "40050" ASC, "40001" ASC',
        (wm_ts, wm_ts, wm_mid)).fetchall()


def build_message(source, row, fts_text, groups, user_uid):
    (msg_id, f40027, sender_uid, sender_uin, peer_uid, peer_uin,
     send_time, blob) = row
    elems = parse_message(blob)
    proto_parts = []
    at_uids = []
    nontext = []
    seen_types = set()
    for e in elems:
        et = e["type"]
        if et == 1 or (et is None and e["text"] is not None):
            if e["text"]:
                proto_parts.append(e["text"])
        else:
            if et is not None and et not in seen_types:
                seen_types.add(et)
                nontext.append({"type": et,
                                "name": ETYPE_NAMES.get(et, f"etype-{et}")})
        if e["at_uid"]:
            at_uids.append(e["at_uid"])
    proto_text = "".join(proto_parts)
    if fts_text:
        text, text_source = fts_text, "fts"
    elif proto_text:
        text, text_source = proto_text, "proto"
    else:
        text, text_source = "", "none"
    unparseable = (not elems) and not fts_text
    at_all = any(u == "0" for u in at_uids) or "@全体成员" in text
    msg = {
        "type": "message",
        "source": source,
        "msg_id": msg_id,
        "sender_uin": sender_uin,
        "sender_uid": sender_uid,
        "sender_is_self": bool(user_uid) and sender_uid == user_uid,
        "send_time": send_time,
        "send_time_cst": cst_str(send_time),
        "text": text,
        "text_source": text_source,
        "has_nontext": bool(nontext),
        "nontext_types": nontext,
        "at_uids": at_uids,
        "at_all": at_all,
        "at_me": bool(user_uid) and user_uid in at_uids,
        "unparseable": bool(unparseable),
    }
    if source == "group":
        msg["group_id"] = f40027
        msg["group_name"] = groups.get(str(f40027))
        msg["peer_uid"] = None
        msg["peer_uin"] = None
    else:
        msg["group_id"] = None
        msg["group_name"] = None
        msg["peer_uid"] = peer_uid
        msg["peer_uin"] = peer_uin
    return msg


# ------------------------------------------------------------------
# main
# ------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Incremental read-only pull of new QQ messages "
                    "as JSON lines.")
    ap.add_argument("--reinit", action="store_true",
                    help="re-initialise the watermark to the current "
                         "maxima (no history is emitted)")
    ap.add_argument("--workdir",
                    help="data dir for key.json / watermark.json / "
                         "group_map.json / identity.json / runs/ "
                         "(default: $QQ_READER_WORKDIR or the "
                         "script directory)")
    ap.add_argument("--config", help="path to config.json "
                                     "(default: <workdir>/config.json)")
    ap.add_argument("--user-uin", type=int,
                    help="your QQ number (enables @-me detection)")
    ap.add_argument("--qq-home",
                    help="QQ config home (default: ~/.config/QQ)")
    ap.add_argument("--tz-offset", type=float,
                    help="UTC offset in hours for send_time_cst "
                         "(default: 8)")
    args = ap.parse_args()
    configure(workdir=args.workdir, config_path=args.config,
              user_uin=args.user_uin, qq_home=args.qq_home,
              tz_offset=args.tz_offset)
    reinit = args.reinit
    run_id = time.strftime("%Y%m%d-%H%M%S")
    status = {"type": "status", "status": "OK", "run_id": run_id,
              "key_recovered": False}
    try:
        nt_db = find_nt_db_dir()
        if not nt_db:
            status.update(status="ERROR",
                          detail="nt_db dir not found")
            emit(status)
            return EXIT_ERROR
        any_qq, main_pid = qq_pids()
        status["qq_running"] = bool(any_qq)
        src_db = os.path.join(nt_db, "nt_msg.db")
        try:
            db_mtime = int(os.path.getmtime(src_db))
        except OSError:
            db_mtime = None
        status["db_mtime"] = db_mtime
        status["db_mtime_cst"] = cst_str(db_mtime) if db_mtime else None

        os.makedirs(RUNS_DIR, exist_ok=True)
        run_dir = os.path.join(RUNS_DIR, run_id)
        os.makedirs(run_dir, exist_ok=True)
        # prune older run dirs, keep the newest 2 (incl. current)
        runs = sorted(os.listdir(RUNS_DIR))
        for old in runs[:-2]:
            shutil.rmtree(os.path.join(RUNS_DIR, old), ignore_errors=True)

        copied = copy_db_set(
            nt_db, run_dir,
            ("nt_msg.db", "group_msg_fts.db", "group_info.db"))

        passphrase = load_passphrase()

        def decrypt_all():
            """Returns (ok, key_failed)."""
            try:
                ok = decrypt_db_checked(
                    copied["nt_msg.db"],
                    copied["nt_msg.db"] + "-wal", passphrase,
                    os.path.join(run_dir, "nt_msg.plain.db"))
                return ok, False
            except KeyFail:
                return False, True

        ok, key_failed = decrypt_all()
        if key_failed:
            # key may have rotated: copy settings.db and rescan memory
            copy_db_set(nt_db, run_dir, ("settings.db",))
            if recover_key(run_dir, main_pid):
                status["key_recovered"] = True
                passphrase = load_passphrase()
                ok, key_failed = decrypt_all()
            if not ok:
                status.update(status="KEY_FAIL",
                              detail="stored key invalid and memory "
                                     "rescan did not recover a key")
                emit(status)
                return EXIT_KEY_FAIL
        elif not ok:
            status.update(status="ERROR",
                          detail="decrypt integrity_check failed on "
                                 "both WAL and main-only attempts")
            emit(status)
            return EXIT_ERROR

        msg_plain = os.path.join(run_dir, "nt_msg.plain.db")

        # optional companions: failures here degrade, never abort
        fts_plain = None
        if "group_msg_fts.db" in copied:
            try:
                fp = os.path.join(run_dir, "group_msg_fts.plain.db")
                if decrypt_db_checked(
                        copied["group_msg_fts.db"],
                        copied["group_msg_fts.db"] + "-wal",
                        passphrase, fp):
                    fts_plain = fp
            except Exception:
                fts_plain = None
        info_plain = None
        if "group_info.db" in copied:
            try:
                ip = os.path.join(run_dir, "group_info.plain.db")
                if decrypt_db_checked(
                        copied["group_info.db"],
                        copied["group_info.db"] + "-wal",
                        passphrase, ip):
                    info_plain = ip
            except Exception:
                info_plain = None

        groups = load_group_map(info_plain,
                                os.path.join(nt_db, "group_info.db"))

        con = sqlite3.connect(f"file:{msg_plain}?immutable=1", uri=True)
        con.execute("PRAGMA query_only=ON")
        ident = load_identity(con)
        user_uid = ident.get("user_uid")

        wm = None
        if os.path.exists(WM_PATH) and not reinit:
            try:
                with open(WM_PATH) as f:
                    wm = json.load(f)
            except Exception:
                wm = None
        if wm is None:
            wm = {"group": table_max(con, "group_msg_table"),
                  "c2c": table_max(con, "c2c_msg_table")}
            atomic_write_json(WM_PATH, wm)
            status.update(status="INIT", new_messages=0, watermark=wm)
            emit(status)
            con.close()
            return EXIT_OK

        # FTS text lookup for group messages
        group_rows = extract_new(con, "group_msg_table", wm["group"])
        c2c_rows = extract_new(con, "c2c_msg_table", wm["c2c"])
        fts_map = {}
        if fts_plain and group_rows:
            try:
                fcon = sqlite3.connect(
                    f"file:{fts_plain}?immutable=1", uri=True)
                ids = [r[0] for r in group_rows]
                for i in range(0, len(ids), 500):
                    chunk = ids[i:i + 500]
                    q = ('SELECT "40001", "41701" FROM group_msg_fts '
                         'WHERE "40001" IN (%s)'
                         % ",".join("?" * len(chunk)))
                    for mid, txt in fcon.execute(q, chunk):
                        if txt:
                            fts_map[mid] = txt
                fcon.close()
            except Exception:
                fts_map = {}

        messages = []
        for row in group_rows:
            messages.append(build_message(
                "group", row, fts_map.get(row[0]), groups, user_uid))
        for row in c2c_rows:
            messages.append(build_message(
                "c2c", row, None, groups, user_uid))
        messages.sort(key=lambda m: (m["send_time"], m["msg_id"]))

        status["new_messages"] = len(messages)
        status["watermark_before"] = wm
        emit(status)
        for m in messages:
            emit(m)

        new_wm = {"group": list(wm["group"]), "c2c": list(wm["c2c"])}
        for src, rows in (("group", group_rows), ("c2c", c2c_rows)):
            for r in rows:
                cand = [r[6], r[0]]
                if tuple(cand) > tuple(new_wm[src]):
                    new_wm[src] = cand
        atomic_write_json(WM_PATH, new_wm)
        con.close()
        return EXIT_OK
    except Exception as e:  # noqa: BLE001 - report, never crash the caller
        status.update(status="ERROR", detail=f"{type(e).__name__}: {e}")
        try:
            emit(status)
        except Exception:
            print(json.dumps(status), flush=True)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
