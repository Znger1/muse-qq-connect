#!/usr/bin/env python3
"""Decrypt a QQ NT DB copy into a plaintext SQLite file using the
passphrase recovered by scan_key.py.

The algorithm pair (page-HMAC x KDF-HMAC) is re-detected on the
target DB copy itself (cheap, page 1 only), then all pages are
decrypted and the decrypted WAL frames are applied in order.
Reads only lab copies; writes only the plaintext output in the lab.
Zero network functionality.
"""

import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qq_crypto as qc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--wal", default=None)
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.key) as f:
        mat = json.load(f)
    passphrase = base64.b64decode(mat["passphrase_b64"])

    stripped = qc.load_stripped(args.db)
    algo = qc.detect_algo(stripped, passphrase)
    if not algo:
        raise SystemExit("stored passphrase does NOT verify against this DB copy")
    print(f"algo detected for this db: {algo}")
    plain = bytearray(qc.decrypt_database(stripped, passphrase, algo))
    print(f"main db decrypted: {len(plain) // qc.PAGE_SIZE} pages")

    if args.wal and os.path.exists(args.wal) and os.path.getsize(args.wal) > 0:
        with open(args.wal, "rb") as f:
            wal = f.read()
        salt = stripped[:qc.SALT_SIZE]
        frames, info = qc.decrypt_wal_frames(wal, passphrase, algo, salt)
        for pgno, page in frames:
            need = pgno * qc.PAGE_SIZE
            if need > len(plain):
                plain.extend(b"\x00" * (need - len(plain)))
            plain[(pgno - 1) * qc.PAGE_SIZE: pgno * qc.PAGE_SIZE] = page
        print(f"wal frames applied: {len(frames)}; wal info: {info}")

    with open(args.out, "wb") as f:
        f.write(plain)
    print(f"plaintext written: {args.out} ({len(plain)} bytes)")


if __name__ == "__main__":
    main()
