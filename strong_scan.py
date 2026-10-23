#!/usr/bin/env python3
"""Strong-mode sweep: scan ALL readable memory of the QQ process for
key-shaped windows, in passes of decreasing strictness:

  pass 1: 16-aligned, printable, >= 1 symbol   (x_key_scanner Strong)
  pass 2: 8-aligned,  printable, >= 1 symbol
  pass 3: 4-aligned,  printable, >= 1 symbol   (V8 pointer-compressed
                                                strings are 4-aligned)
  pass 4: 4-aligned,  printable, any content   (all-alnum passphrase)

Candidates come from printable ASCII runs (>= 16 bytes); each pass
dedupes, ranks (character classes, occurrences) and verifies against
the settings.db copy page 1 via qq_crypto.detect_algo.

Reads /proc/<pid>/mem region by region, discarding each buffer.
No attach, no writes to the target, zero network functionality.
The key is never printed; it is saved to a chmod-600 JSON file.
"""

import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qq_crypto as qc
from scan_key import (key_ok, char_classes, read_region,
                      save_key, log)

RUN = re.compile(rb"[\x20-\x7e]{16,}")


def parse_maps_anon(pid):
    """Anonymous rw regions only: the V8 heap and codec structs live
    there; file-backed text (binaries, JS caches) is pure noise."""
    regions = []
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            parts = line.split()
            perms = parts[1]
            if not perms.startswith("rw"):
                continue
            path = parts[5] if len(parts) > 5 else ""
            if path and not path.startswith("["):
                continue
            start, end = (int(x, 16) for x in parts[0].split("-"))
            regions.append((start, end))
    return regions


def all_printable(win: bytes) -> bool:
    return all(0x21 <= b <= 0x7E for b in win)


def collect(fd, regions, alignment, need_symbol, seen):
    counts = {}
    total = 0
    for (start, end) in regions:
        data = read_region(fd, start, end - start)
        total += len(data)
        for m in RUN.finditer(data):
            s = m.start()
            first = (s + alignment - 1) // alignment * alignment
            for off in range(first, m.end() - 15, alignment):
                win = data[off:off + 16]
                if len(win) < 16:
                    continue
                if need_symbol:
                    if not key_ok(win):
                        continue
                elif not all_printable(win):
                    continue
                if win in seen:
                    continue
                counts[win] = counts.get(win, 0) + 1
        del data
    return counts, total


_SETTINGS = None
_MSGDB = None


def _pool_init(settings, msgdb):
    global _SETTINGS, _MSGDB
    _SETTINGS, _MSGDB = settings, msgdb


def _verify_one(cand):
    algo = qc.detect_algo(_SETTINGS, cand)
    if not algo:
        return None
    return cand, algo, qc.detect_algo(_MSGDB, cand)


def verify_ranked(ranked, settings, msgdb, t0, pi):
    """Parallel verification (2 workers); returns hit tuple or None."""
    import multiprocessing as mp
    cands = [c for c, _ in ranked]
    done = 0
    with mp.Pool(2, initializer=_pool_init, initargs=(settings, msgdb)) as pool:
        for hit in pool.imap_unordered(_verify_one, cands, chunksize=64):
            done += 1
            if hit:
                pool.terminate()
                return hit, done
            if done % 4000 == 0:
                log(f"pass {pi}: {done}/{len(cands)} verified, "
                    f"{time.time() - t0:.0f}s elapsed")
    return None, done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--settings", required=True)
    ap.add_argument("--msgdb", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    settings = qc.load_stripped(args.settings)
    msgdb = qc.load_stripped(args.msgdb)
    fd = os.open(f"/proc/{args.pid}/mem", os.O_RDONLY)
    regions = parse_maps_anon(args.pid)
    log(f"strong sweep on pid {args.pid}: {len(regions)} anon rw regions")
    t0 = time.time()
    seen = set()
    passes = [(16, True), (8, True), (4, True), (4, False)]
    for pi, (alignment, need_symbol) in enumerate(passes, 1):
        counts, total = collect(fd, regions, alignment, need_symbol, seen)
        seen.update(counts.keys())
        ranked = sorted(counts.items(),
                        key=lambda kv: (-char_classes(kv[0]), -kv[1], kv[0]))
        log(f"pass {pi} (align={alignment}, symbol={need_symbol}): "
            f"{len(ranked)} new candidates from {total/1e6:.0f} MB, "
            f"{time.time() - t0:.0f}s elapsed")
        hit, _done = verify_ranked(ranked, settings, msgdb, t0, pi)
        if hit:
            cand, algo, algo_m = hit
            log(f"KEY VERIFIED in pass {pi}: settings algo={algo}; "
                f"nt_msg algo={algo_m}; elapsed {time.time() - t0:.1f}s")
            save_key(args.out, cand, algo, algo_m)
            log(f"key saved to {args.out} (chmod 600)")
            os.close(fd)
            return 0
        log(f"pass {pi} done: no hit")
    os.close(fd)
    log(f"FAIL: strong sweep found no verified key. "
        f"elapsed={time.time() - t0:.1f}s")
    return 1


if __name__ == "__main__":
    sys.exit(main())
