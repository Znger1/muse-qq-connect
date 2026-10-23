#!/usr/bin/env python3
"""Read-only memory key scanner for the user's own QQ process. (v3)

Independent Python re-implementation of the algorithm published in
the open-source QQBackup/x_key_scanner project (src/scan.rs):

  * Anchor: the length-prefixed string "\\x09HMAC_SHA1" found in the
    SQLCipher codec's algorithm table. An occurrence at buffer offset
    p is an anchor iff (p - 1) is 16-byte aligned (region-relative).
  * A candidate key is a 16-byte, 16-aligned window of printable
    non-space ASCII (0x21..0x7E) containing at least one symbol byte.
  * Path A: nearest candidate within +/-0x200 of each anchor.
  * Path B (the Linux/Electron path): anchors cluster densely near
    the codec contexts; take the densest cluster (>= 4 anchors,
    gaps <= 0x4000), walk outward from its center up to 0x20000,
    collecting up to 256 distinct candidates.
  * Candidates are ranked (character-class count, occurrence count,
    bytes) and verified cryptographically against the settings.db
    copy's page 1 (see qq_crypto.detect_algo). First hit wins.
  * Strong mode (fallback): sweep all 16-aligned printable windows.

Memory is read via pread on /proc/<pid>/mem. No ptrace attach, no
debugger, no injection; the target is never paused or written to.
Contains ZERO network functionality. The recovered key is written
to a chmod-600 file; it is never printed or logged.
"""

import argparse
import base64
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qq_crypto as qc

ANCHOR = b"\x09HMAC_SHA1"
ALIGN = 16
KEY_LEN = 16
RADIUS = 0x200
MAX_REGION = 512 * 1024 * 1024
CLUSTER_GAP = 0x4000
MIN_CLUSTER_ANCHORS = 4
CLUSTER_MAX_OUT = 0x20000
CLUSTER_KEYS_PER = 256
STRONG_MAX_CANDIDATES = 200_000
PRINTABLE_RUN = re.compile(rb"[\x21-\x7e]{16,}")


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def is_alnum(b):
    return (0x30 <= b <= 0x39) or (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A)


def key_ok(win: bytes) -> bool:
    if len(win) != KEY_LEN:
        return False
    if not all(0x21 <= b <= 0x7E for b in win):
        return False
    return not all(is_alnum(b) for b in win)


def char_classes(win: bytes) -> int:
    has = [False, False, False, False]
    for b in win:
        if 0x30 <= b <= 0x39:
            has[0] = True
        elif 0x41 <= b <= 0x5A:
            has[1] = True
        elif 0x61 <= b <= 0x7A:
            has[2] = True
        else:
            has[3] = True
    return sum(has)


def parse_maps(pid):
    regions = []
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            parts = line.split()
            if "r" not in parts[1]:
                continue
            start, end = (int(x, 16) for x in parts[0].split("-"))
            regions.append((start, end))
    return regions


def read_region(fd, start, size):
    size = min(size, MAX_REGION)
    buf = bytearray()
    off = 0
    while off < size:
        try:
            chunk = os.pread(fd, min(32 * 1024 * 1024, size - off), start + off)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        off += len(chunk)
    return bytes(buf)


def find_anchor_slots(data: bytes):
    slots = []
    i = data.find(ANCHOR)
    while i != -1:
        if i >= 1 and (i - 1) % ALIGN == 0:
            slots.append(i - 1)
        i = data.find(ANCHOR, i + 1)
    return slots


def nearest_key(data: bytes, anchor: int):
    step = 0
    while step <= RADIUS:
        for off in ((anchor - step,) if step == 0 else (anchor - step, anchor + step)):
            if 0 <= off and off + KEY_LEN <= len(data):
                win = data[off:off + KEY_LEN]
                if key_ok(win):
                    return win
        step += ALIGN
    return None


def clusters_of(anchors):
    if not anchors:
        return []
    anchors = sorted(anchors)
    clusters = [[anchors[0]]]
    for a in anchors[1:]:
        if a - clusters[-1][-1] <= CLUSTER_GAP:
            clusters[-1].append(a)
        else:
            clusters.append([a])
    return [c for c in clusters if len(c) >= MIN_CLUSTER_ANCHORS]


def walk_collect(data: bytes, center: int, max_out: int, cap: int, out: list,
                 seen: set):
    step = 0
    while step <= max_out and len(out) < cap:
        offs = (center,) if step == 0 else (center - step, center + step)
        for off in offs:
            if 0 <= off and off + KEY_LEN <= len(data):
                win = data[off:off + KEY_LEN]
                if key_ok(win) and win not in seen:
                    seen.add(win)
                    out.append(win)
                    if len(out) >= cap:
                        return
        step += ALIGN


def harvest_region(data: bytes):
    """Faithful paths A+B, widened: every qualifying cluster is walked
    (not only the densest), every anchor contributes all key-shaped
    windows within +/-RADIUS, and every anchor is also walked out to
    CLUSTER_MAX_OUT. Verification is exact, so extra candidates only
    cost time."""
    slots = find_anchor_slots(data)
    cands = []
    seen = set()
    # Path A (nearest per anchor) + widened per-anchor sweep
    for s in slots:
        k = nearest_key(data, s)
        if k and k not in seen:
            seen.add(k)
            cands.append(k)
        tmp = []
        walk_collect(data, s, RADIUS, 512, tmp, set())
        for w in tmp:
            if w not in seen:
                seen.add(w)
                cands.append(w)
    # Path B: every dense cluster's center
    for cl in clusters_of(slots):
        center = ((cl[0] + cl[-1]) // 2) // ALIGN * ALIGN
        tmp = []
        walk_collect(data, center, CLUSTER_MAX_OUT, CLUSTER_KEYS_PER, tmp, set())
        for w in tmp:
            if w not in seen:
                seen.add(w)
                cands.append(w)
    # Path C: wide walk around every anchor
    for s in slots:
        tmp = []
        walk_collect(data, s, CLUSTER_MAX_OUT, CLUSTER_KEYS_PER, tmp, set())
        for w in tmp:
            if w not in seen:
                seen.add(w)
                cands.append(w)
    return slots, cands


def strong_region(data: bytes, seen: set):
    out = []
    for m in PRINTABLE_RUN.finditer(data):
        start = m.start()
        first = (start + ALIGN - 1) // ALIGN * ALIGN
        for off in range(first, m.end() - KEY_LEN + 1, ALIGN):
            win = data[off:off + KEY_LEN]
            if key_ok(win) and win not in seen:
                seen.add(win)
                out.append(win)
                if len(out) >= STRONG_MAX_CANDIDATES:
                    return out
    return out


def rank(cand_counts):
    return sorted(cand_counts.items(),
                  key=lambda kv: (-char_classes(kv[0]), -kv[1], kv[0]))


def save_key(path, passphrase: bytes, algo_settings, algo_msg):
    material = {"form": "passphrase16",
                "passphrase_b64": base64.b64encode(passphrase).decode(),
                "algo_settings": algo_settings,
                "algo_msg": algo_msg}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(material, f)
    os.chmod(path, 0o600)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pids", required=True)
    ap.add_argument("--settings", required=True, help="settings.db COPY")
    ap.add_argument("--msgdb", required=True, help="nt_msg.db COPY")
    ap.add_argument("--out", required=True)
    ap.add_argument("--strong", action="store_true")
    args = ap.parse_args()

    settings = qc.load_stripped(args.settings)
    msgdb = qc.load_stripped(args.msgdb)
    t0 = time.time()

    def verify(cand):
        algo = qc.detect_algo(settings, cand)
        if algo:
            algo_m = qc.detect_algo(msgdb, cand)
            return algo, algo_m
        return None

    for pid in [int(x) for x in args.pids.split(",") if x]:
        log(f"--- pid {pid} ---")
        try:
            fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        except OSError as e:
            log(f"cannot open mem: {e}")
            continue
        regions = parse_maps(pid)
        cand_counts = {}
        total_anchors = 0
        total_bytes = 0
        for (start, end) in regions:
            data = read_region(fd, start, end - start)
            total_bytes += len(data)
            slots, cands = harvest_region(data)
            total_anchors += len(slots)
            for c in cands:
                cand_counts[c] = cand_counts.get(c, 0) + 1
            del data  # never retain region buffers (server RAM is small)
        log(f"{len(regions)} regions, {total_bytes/1e6:.0f} MB read, "
            f"{total_anchors} anchors, {len(cand_counts)} unique candidates")
        ranked = rank(cand_counts)
        for i, (cand, _cnt) in enumerate(ranked):
            got = verify(cand)
            if got:
                algo_s, algo_m = got
                log(f"KEY VERIFIED in pid {pid}: candidate #{i + 1}/"
                    f"{len(ranked)}; settings algo={algo_s}; "
                    f"nt_msg algo={algo_m}; elapsed {time.time() - t0:.1f}s")
                save_key(args.out, cand, algo_s, algo_m)
                log(f"key saved to {args.out} (chmod 600)")
                os.close(fd)
                return 0
            if (i + 1) % 200 == 0:
                log(f"verified {i + 1}/{len(ranked)}, "
                    f"{time.time() - t0:.0f}s elapsed")
        log(f"pid {pid}: normal mode no hit")
        if args.strong:
            seen = set(cand_counts.keys())
            for ri, (rstart, rend) in enumerate(regions):
                data = read_region(fd, rstart, rend - rstart)
                batch = strong_region(data, seen)
                del data
                if not batch:
                    continue
                bc = {}
                for c in batch:
                    bc[c] = 1
                for j, (cand, _c) in enumerate(rank(bc)):
                    got = verify(cand)
                    if got:
                        algo_s, algo_m = got
                        log(f"KEY VERIFIED (strong) pid {pid} region {ri}: "
                            f"settings algo={algo_s}; nt_msg algo={algo_m}")
                        save_key(args.out, cand, algo_s, algo_m)
                        log(f"key saved to {args.out} (chmod 600)")
                        os.close(fd)
                        return 0
                log(f"strong region {ri}: {len(batch)} candidates, no hit")
        os.close(fd)

    log(f"FAIL: no verified key. elapsed={time.time() - t0:.1f}s")
    return 1


if __name__ == "__main__":
    sys.exit(main())
