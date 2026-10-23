#!/usr/bin/env python3
"""Mention search over ALL stored QQ messages (read-only).

Find every stored message that mentions you, using the same
validated decrypt path as patrol_pull.py on a FRESH copy inside
<workdir>/mention-search/. Does NOT run patrol_pull.py and never
touches <workdir>/watermark.json, so it is safe to run alongside
the incremental pull.

Buckets:
  A at_me        - 40800 @ element whose target uid == your uid
  B name_mention - text contains your name (config user_name),
                   not already in A
  C at_all       - @全体成员 (count + latest 10 in detail)
Messages sent by yourself are excluded from A and B.

Prerequisite: <workdir>/key.json must exist (run the key scanners
first), and identity.json / group_map.json are used when present
(patrol_pull.py creates them; without identity.json, @-me
detection is disabled and only bucket B/C by text are produced).

Optional sanity check: pass --expect-group, --expect-ts,
--expect-text and --expect-sender describing one message you KNOW
mentions you; the result reports whether it was found in bucket A.

Configuration: CLI flags > environment > <workdir>/config.json
(see config.example.json). Zero network code.
"""

import argparse
import glob
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import qq_crypto as qc  # noqa: E402

WORKDIR = SCRIPT_DIR
WORK = None
QQ_HOME = os.path.expanduser("~/.config/QQ")
USER_UIN = None
USER_NAME = None
TZ = timezone(timedelta(hours=8))


def configure(workdir=None, config_path=None, user_uin=None,
              user_name=None, qq_home=None, tz_offset=None):
    global WORKDIR, QQ_HOME, USER_UIN, USER_NAME, TZ
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
    uin = user_uin or os.environ.get("QQ_READER_UIN") \
        or cfg.get("user_uin")
    USER_UIN = int(uin) if uin else None
    USER_NAME = (user_name or os.environ.get("QQ_READER_NAME")
                 or cfg.get("user_name"))
    QQ_HOME = os.path.expanduser(
        qq_home or os.environ.get("QQ_READER_QQ_HOME")
        or cfg.get("qq_home") or QQ_HOME)
    off = tz_offset if tz_offset is not None \
        else cfg.get("tz_offset_hours", 8)
    TZ = timezone(timedelta(hours=float(off)))


# ---------- protobuf parsing (same as patrol_pull.py) ----------

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
    if not blob:
        return []
    elems = []
    for field, wt, v in iter_fields(blob):
        if field == 40800 and wt == 2:
            elems.append(parse_element(v))
    return elems


# ---------- decrypt (same validated path as patrol_pull.py) ----------

def load_passphrase():
    import base64
    with open(os.path.join(WORKDIR, "key.json")) as f:
        return base64.b64decode(json.load(f)["passphrase_b64"])


def decrypt_to_bytes(enc_path, wal_path, passphrase, apply_wal=True):
    stripped = qc.load_stripped(enc_path)
    algo = qc.detect_algo(stripped, passphrase)
    if not algo:
        raise RuntimeError(f"key does not verify for {enc_path}")
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


def decrypt_checked(enc_path, passphrase, out_path):
    for apply_wal in (True, False):
        data = decrypt_to_bytes(enc_path, enc_path + "-wal",
                                passphrase, apply_wal=apply_wal)
        with open(out_path, "wb") as f:
            f.write(data)
        if integrity_ok(out_path):
            return True
    return False


def cst_min(ts):
    return datetime.fromtimestamp(ts, TZ).strftime("%Y-%m-%d %H:%M")


def main():
    ap = argparse.ArgumentParser(
        description="Search all stored QQ messages for mentions "
                    "of you (read-only).")
    ap.add_argument("--workdir",
                    help="data dir holding key.json / identity.json "
                         "/ group_map.json (default: "
                         "$QQ_READER_WORKDIR or the script directory)")
    ap.add_argument("--outdir",
                    help="where copies/results go "
                         "(default: <workdir>/mention-search)")
    ap.add_argument("--config", help="path to config.json")
    ap.add_argument("--user-uin", type=int, help="your QQ number")
    ap.add_argument("--user-name",
                    help="your display name, for bucket B "
                         "(text mentions without a formal @)")
    ap.add_argument("--qq-home", help="QQ config home "
                                      "(default: ~/.config/QQ)")
    ap.add_argument("--tz-offset", type=float,
                    help="UTC offset in hours (default: 8)")
    ap.add_argument("--expect-group", type=int,
                    help="sanity check: group id of a message you "
                         "know mentions you")
    ap.add_argument("--expect-ts", type=int,
                    help="sanity check: its send time (unix seconds)")
    ap.add_argument("--expect-text",
                    help="sanity check: substring of its text")
    ap.add_argument("--expect-sender",
                    help="sanity check: its sender display name")
    args = ap.parse_args()
    configure(workdir=args.workdir, config_path=args.config,
              user_uin=args.user_uin, user_name=args.user_name,
              qq_home=args.qq_home, tz_offset=args.tz_offset)
    global WORK
    WORK = args.outdir or os.path.join(WORKDIR, "mention-search")

    nt_db_hits = sorted(glob.glob(os.path.join(QQ_HOME, "nt_qq_*",
                                               "nt_db")))
    if not nt_db_hits:
        print(json.dumps({"error": "nt_db dir not found"}))
        return 1
    nt_db = nt_db_hits[0]
    os.makedirs(WORK, exist_ok=True)
    copied = {}
    for name in ("nt_msg.db", "group_msg_fts.db", "group_info.db"):
        for suf in ("", "-wal", "-shm"):
            src = os.path.join(nt_db, name + suf)
            if os.path.exists(src):
                dst = os.path.join(WORK, name + suf)
                shutil.copyfile(src, dst)
                if suf == "":
                    copied[name] = dst
    pp = load_passphrase()
    msg_plain = os.path.join(WORK, "nt_msg.plain.db")
    if not decrypt_checked(copied["nt_msg.db"], pp, msg_plain):
        print(json.dumps({"error": "nt_msg decrypt failed"}))
        return 1
    fts_plain = os.path.join(WORK, "group_msg_fts.plain.db")
    fts_ok = False
    try:
        fts_ok = decrypt_checked(copied["group_msg_fts.db"], pp,
                                 fts_plain)
    except Exception:
        fts_ok = False
    info_plain = os.path.join(WORK, "group_info.plain.db")
    info_ok = False
    try:
        info_ok = decrypt_checked(copied["group_info.db"], pp,
                                  info_plain)
    except Exception:
        info_ok = False

    user_uid = None
    ident_path = os.path.join(WORKDIR, "identity.json")
    if os.path.exists(ident_path):
        try:
            with open(ident_path) as f:
                user_uid = json.load(f).get("user_uid")
        except Exception:
            user_uid = None
    groups = {}
    gpath = os.path.join(WORKDIR, "group_map.json")
    if os.path.exists(gpath):
        try:
            with open(gpath) as f:
                groups = json.load(f).get("groups", {})
        except Exception:
            groups = {}

    # fallback sender-name map from group_member3: (group, uid) -> card/nick
    member_names = {}
    if info_ok:
        try:
            icon = sqlite3.connect(f"file:{info_plain}?immutable=1",
                                   uri=True)
            for gid, uid, card, nick in icon.execute(
                    'SELECT "60001", "1000", "64003", "20002" '
                    'FROM group_member3'):
                nm = card or nick
                if uid and nm:
                    member_names[(str(gid), uid)] = nm
            icon.close()
        except Exception:
            member_names = {}

    con = sqlite3.connect(f"file:{msg_plain}?immutable=1", uri=True)
    con.execute("PRAGMA query_only=ON")

    fts_map = {}
    if fts_ok:
        try:
            fcon = sqlite3.connect(f"file:{fts_plain}?immutable=1",
                                   uri=True)
            for mid, txt in fcon.execute(
                    'SELECT "40001", "41701" FROM group_msg_fts'):
                if txt:
                    fts_map[mid] = txt
            fcon.close()
        except Exception:
            fts_map = {}

    def table_cols(table):
        return [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]

    def scan(table, source):
        cols = table_cols(table)
        has_card = "40090" in cols
        sel = ['"40001"', '"40027"', '"40020"', '"40033"', '"40021"',
               '"40030"', '"40050"', '"40800"']
        if has_card:
            sel.append('"40090"')
        rows = con.execute(
            f'SELECT {", ".join(sel)} FROM "{table}"').fetchall()
        out = []
        for r in rows:
            d = dict(zip(
                ["msg_id", "f40027", "sender_uid", "sender_uin",
                 "peer_uid", "peer_uin", "send_time", "blob"] +
                (["card"] if has_card else []), r))
            d["source"] = source
            out.append(d)
        return out

    all_rows = scan("group_msg_table", "group") + \
        scan("c2c_msg_table", "c2c")
    total = len(all_rows)
    times = [r["send_time"] for r in all_rows if r["send_time"]]
    span = [cst_min(min(times)), cst_min(max(times))] if times else None

    expect = None
    if None not in (args.expect_group, args.expect_ts,
                    args.expect_text, args.expect_sender):
        expect = {"group": args.expect_group, "ts": args.expect_ts,
                  "text": args.expect_text,
                  "sender": args.expect_sender}
    sanity = None  # None = not configured; else bool

    A, B, C_all = [], [], []
    for r in all_rows:
        elems = parse_message(r["blob"])
        at_uids = [e["at_uid"] for e in elems if e["at_uid"]]
        proto_text = "".join(
            e["text"] for e in elems
            if (e["type"] == 1 or (e["type"] is None
                                  and e["text"] is not None))
            and e["text"])
        if r["source"] == "group" and r["msg_id"] in fts_map:
            text = fts_map[r["msg_id"]]
        else:
            text = proto_text
        is_self = (r["sender_uin"] == USER_UIN
                   or (user_uid is not None
                       and r["sender_uid"] == user_uid))
        at_me = user_uid is not None and user_uid in at_uids
        at_all = any(u == "0" for u in at_uids) or "@全体成员" in text
        # sender display name: row card -> member map -> uin
        sname = r.get("card") or None
        if not sname and r["source"] == "group":
            sname = member_names.get((str(r["f40027"]), r["sender_uid"]))
        if not sname:
            sname = f"uin {r['sender_uin']}"
        if r["source"] == "group":
            where = groups.get(str(r["f40027"]),
                               f"群 {r['f40027']}")
        else:
            where = f"私聊 (peer uin {r['peer_uin']})"
        item = {"time": cst_min(r["send_time"]), "ts": r["send_time"],
                "where": where, "sender": sname,
                "sender_uin": r["sender_uin"], "text": text}
        if at_all:
            C_all.append(item)
        if is_self:
            continue
        if at_me:
            A.append(item)
            if expect and r["source"] == "group" \
                    and r["f40027"] == expect["group"] \
                    and r["send_time"] == expect["ts"]:
                sanity = (expect["text"] in text) \
                    and (sname == expect["sender"])
        elif USER_NAME and USER_NAME in text:
            B.append(item)

    A.sort(key=lambda x: (x["ts"],))
    B.sort(key=lambda x: (x["ts"],))
    C_all.sort(key=lambda x: (x["ts"],))
    C_latest = C_all[-10:]

    result = {
        "stats": {"total_rows_scanned": total,
                  "history_span": span,
                  "count_A_at_me": len(A),
                  "count_B_name_mention": len(B),
                  "count_C_at_all_total": len(C_all)},
        "sanity_check": sanity,
        "A_at_me": A,
        "B_name_mention": B,
        "C_at_all_latest10": C_latest,
    }
    with open(os.path.join(WORK, "mention_result.json"), "w") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    print(json.dumps(result, ensure_ascii=False))
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
