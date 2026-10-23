#!/usr/bin/env python3
"""Parser proof for the decrypted plaintext nt_msg.db copy.

Opens the plaintext DB READ-ONLY (immutable) and reports:
  * table list
  * row counts of group_msg_table / c2c_msg_table
  * the latest few group messages as (group, sender, time, text)

Text extraction: the 40800 column is a protobuf whose repeated field
40800 holds flat ElementWire items; an item is text when field 45002
(elementType) == 1, with the text in field 45101 and the @-target uid
in field 45105 when present. This parser implements a tolerant
wire-format walk (unknown fields skipped by wire type).
Zero network functionality. Prints only the small proof sample.
"""

import argparse
import sqlite3
import sys
import time


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
    """Yield (field_no, wire_type, value) tolerantly; stops on garbage."""
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


def element_text(elem: bytes):
    """Return (text, is_at) for one ElementWire blob, or (None, False)."""
    etype = None
    text = None
    at_uid = None
    for field, wt, v in iter_fields(elem):
        if field == 45002 and wt == 0:
            etype = v
        elif field == 45101 and wt == 2:
            try:
                text = v.decode("utf-8", errors="replace")
            except Exception:
                text = None
        elif field == 45105 and wt == 2:
            at_uid = v.decode("utf-8", errors="replace")
    if etype == 1 and text is not None:
        return text, at_uid
    if text is not None and etype in (None, 1):
        return text, at_uid
    return None, at_uid


def message_text(blob: bytes) -> str:
    if not blob:
        return ""
    parts = []
    for field, wt, v in iter_fields(blob):
        if field == 40800 and wt == 2:
            t, at_uid = element_text(v)
            if t:
                if at_uid:
                    parts.append(f"[@{at_uid}] {t}")
                else:
                    parts.append(t)
            else:
                parts.append("[non-text element]")
    return "".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="plaintext sqlite db")
    ap.add_argument("--latest", type=int, default=5)
    args = ap.parse_args()

    con = sqlite3.connect(f"file:{args.db}?immutable=1", uri=True)
    con.execute("PRAGMA query_only=ON")
    cur = con.cursor()
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    print(f"tables ({len(tables)}): {', '.join(tables[:40])}")
    for t in ("group_msg_table", "c2c_msg_table", "dataline_msg_table"):
        if t in tables:
            n = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            print(f"{t}: {n} rows")

    print("\n--- latest group messages ---")
    rows = cur.execute(
        'SELECT "40027", "40033", "40020", "40050", "40800" '
        'FROM group_msg_table ORDER BY "40050" DESC, "40001" DESC '
        'LIMIT ?', (args.latest,)).fetchall()
    for gid, sender_uin, sender_uid, ts, blob in rows:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        txt = message_text(blob)
        print(f"group={gid} sender_uin={sender_uin} sender_uid={sender_uid} "
              f"time={when} text={txt[:200]!r}")
    con.close()


if __name__ == "__main__":
    main()
