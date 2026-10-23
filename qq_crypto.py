#!/usr/bin/env python3
"""QQ NT (SQLCipher) database verification + decryption primitives.

Implements the page-1 verification algorithm exactly as published in
the open-source QQBackup/x_key_scanner project (src/crypto/decrypt.rs),
which we re-implemented independently here:

  * The DB file has a 1024-byte QQ wrapper header; the SQLCipher
    stream follows. Page size 4096; salt = page1[0:16].
  * The key is a 16-byte passphrase. enc_key = PBKDF2-HMAC-<kdf>(
    passphrase, salt, 4000) -> 32 bytes. <kdf> in {sha1, sha256, sha512}.
  * Per-page reserve = ceil((16 + digest_size) / 16) * 16 where the
    digest is the page-HMAC algorithm in {none, sha1, sha256, sha512}
    (digest sizes 0/20/32/64 -> reserves 16/48/48/80).
  * data_end = 4096 - reserve; IV = page[data_end:data_end+16];
    stored MAC = page[data_end+16 : data_end+16+digest_size].
  * MAC key = PBKDF2-HMAC-<kdf>(enc_key, salt XOR 0x3a, 2) -> 32 bytes.
  * Page MAC = HMAC-<page>(mac_key, page[16:data_end] || IV || u32le(pgno)).
    NOTE: the MAC input starts at offset 16 -- the salt is NOT covered.
  * PageHmac "none" fallback: AES-decrypt page 1 and check the SQLite
    header invariants in the decrypted body.

This module contains ZERO network functionality and never writes to
any QQ file: it only reads a DB *copy* and writes a new plaintext file.
"""

import hashlib
import hmac as hmac_mod
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

QQ_HEADER_SIZE = 1024
PAGE_SIZE = 4096
SALT_SIZE = 16
KEY_SIZE = 32
KDF_ITER = 4000
FAST_ITER = 2
HMAC_MASK = 0x3A
SQLITE_MAGIC = b"SQLite format 3\x00"

DIGEST_SIZES = {None: 0, "sha1": 20, "sha256": 32, "sha512": 64}
PAGE_HMACS = ("sha1", "sha256", "sha512", None)
KDF_HASHES = ("sha1", "sha256", "sha512")


def pbkdf2(password: bytes, salt: bytes, iterations: int, hash_name: str,
           dklen: int = KEY_SIZE) -> bytes:
    return hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)


def reserve_for(page_hmac) -> int:
    d = DIGEST_SIZES[page_hmac]
    return ((16 + d + 15) // 16) * 16


def derive_enc_key(passphrase: bytes, salt: bytes, kdf_hash: str) -> bytes:
    return pbkdf2(passphrase, salt, KDF_ITER, kdf_hash)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def header_body_ok(pt_body: bytes) -> bool:
    """pt_body = decrypted page-1 bytes starting at file offset 16.
    Checks: page size (BE16) is 1 (64K sentinel) or a power of two
    >= 512, and payload fractions at body[5:8] are 64/32/32."""
    if len(pt_body) < 8:
        return False
    ps = int.from_bytes(pt_body[0:2], "big")
    if not (ps == 1 or (512 <= ps <= 65536 and ps & (ps - 1) == 0)):
        return False
    return pt_body[5:8] == bytes([64, 32, 32])


def _verify_with_enc(page1: bytes, enc_key: bytes, page_hmac,
                     kdf_hash: str, mac_start: int) -> bool:
    salt = page1[:SALT_SIZE]
    reserve = reserve_for(page_hmac)
    data_end = PAGE_SIZE - reserve
    iv = page1[data_end:data_end + 16]
    if page_hmac is None:
        pt = aes_cbc_decrypt(enc_key, iv, page1[16:data_end])
        return header_body_ok(pt)
    mac_salt = bytes(b ^ HMAC_MASK for b in salt)
    mac_key = pbkdf2(enc_key, mac_salt, FAST_ITER, kdf_hash)
    msg = page1[mac_start:data_end] + iv + struct.pack("<I", 1)
    calc = hmac_mod.new(mac_key, msg, getattr(hashlib, page_hmac)).digest()
    stored = page1[data_end + 16: data_end + 16 + DIGEST_SIZES[page_hmac]]
    return hmac_mod.compare_digest(calc, stored)


def verify_page1(page1: bytes, passphrase: bytes, page_hmac,
                 kdf_hash: str, mac_start: int = 16) -> bool:
    enc_key = derive_enc_key(passphrase, page1[:SALT_SIZE], kdf_hash)
    return _verify_with_enc(page1, enc_key, page_hmac, kdf_hash, mac_start)


def detect_algo(stripped: bytes, passphrase: bytes):
    """Try all (page-HMAC x KDF-HMAC) pairs on page 1. Primary MAC
    coverage starts at offset 16 (x_key_scanner / WCDB behaviour);
    offset 0 (upstream SQLCipher coverage incl. the salt) is tried
    as a variant. The 3 KDF derivations are computed once."""
    page1 = stripped[:PAGE_SIZE]
    salt = page1[:SALT_SIZE]
    enc_keys = {kh: derive_enc_key(passphrase, salt, kh) for kh in KDF_HASHES}
    for mac_start in (16, 0):
        for kh in KDF_HASHES:
            for ph in PAGE_HMACS:
                if _verify_with_enc(page1, enc_keys[kh], ph, kh, mac_start):
                    return {"page_hmac": ph, "kdf_hash": kh,
                            "mac_start": mac_start}
    return None


def _decrypt_page(page: bytes, pgno: int, enc_key: bytes, reserve: int) -> bytes:
    data_end = PAGE_SIZE - reserve
    iv = page[data_end:data_end + 16]
    if pgno == 1:
        pt = SQLITE_MAGIC + aes_cbc_decrypt(enc_key, iv, page[16:data_end])
    else:
        pt = aes_cbc_decrypt(enc_key, iv, page[:data_end])
    return pt + b"\x00" * reserve


def decrypt_database(stripped: bytes, passphrase: bytes, algo: dict) -> bytes:
    salt = stripped[:SALT_SIZE]
    enc_key = derive_enc_key(passphrase, salt, algo["kdf_hash"])
    reserve = reserve_for(algo["page_hmac"])
    n_pages = len(stripped) // PAGE_SIZE
    out = bytearray()
    for pgno in range(1, n_pages + 1):
        page = stripped[(pgno - 1) * PAGE_SIZE: pgno * PAGE_SIZE]
        out += _decrypt_page(page, pgno, enc_key, reserve)
    return bytes(out)


def _wal_checksum(data: bytes, s1: int, s2: int, big_endian: bool):
    """SQLite WAL cumulative checksum over 8-byte word pairs."""
    fmt = ">" if big_endian else "<"
    for i in range(0, len(data), 8):
        x, y = struct.unpack_from(fmt + "II", data, i)
        s1 = (s1 + x + s2) & 0xFFFFFFFF
        s2 = (s2 + y + s1) & 0xFFFFFFFF
    return s1, s2


def select_wal_frames(wal: bytes, decrypt_page=None):
    """Filter a WAL copy's frames: only frames of the header's salt
    generation, forming complete commit sequences. NOTE (measured on
    Linux QQ 3.2.34): this build's frame checksums follow neither the
    stock-encrypted nor the stock-plaintext WAL checksum variant --
    checksum gating rejects every frame -- so selection relies on
    salt-generation + commit-boundary filtering, and callers MUST
    run PRAGMA integrity_check on the result (falling back to the
    main DB alone if it is not ok). When decrypt_page is given, the
    decrypted page is what gets returned. Returns (applied, info)."""
    if len(wal) < 32:
        return [], {}
    magic = struct.unpack(">I", wal[0:4])[0]
    big_endian = (magic & 1) == 0  # 0x377f0682 -> big-endian checksums
    salt1, salt2 = struct.unpack(">II", wal[16:24])
    s1, s2 = struct.unpack(">II", wal[24:32])
    applied = []
    pending = []
    info = {"salt1": salt1, "salt2": salt2, "big_endian": big_endian,
            "frames_seen": 0, "frames_applied": 0, "commits": 0,
            "stopped": "end of file"}
    off = 32
    while off + 24 + PAGE_SIZE <= len(wal):
        fh = wal[off:off + 24]
        pgno, commit_size = struct.unpack(">II", fh[0:8])
        fs1, fs2 = struct.unpack(">II", fh[8:16])
        ck1, ck2 = struct.unpack(">II", fh[16:24])
        page = wal[off + 24: off + 24 + PAGE_SIZE]
        info["frames_seen"] += 1
        if (fs1, fs2) != (salt1, salt2):
            info["stopped"] = "salt generation changed"
            break
        use_page = decrypt_page(pgno, page) if decrypt_page else page
        pending.append((pgno, use_page))
        if commit_size:
            applied.extend(pending)
            pending = []
            info["commits"] += 1
            info["frames_applied"] = len(applied)
        off += 24 + PAGE_SIZE
    return applied, info


def decrypt_wal_frames(wal: bytes, passphrase: bytes, algo: dict,
                       salt: bytes):
    """Decrypt the valid frames of a SQLCipher WAL copy (header salt
    generation, commit-complete sequences only). Returns
    (frames, info): list of (pgno, plaintext_page) in order, plus
    diagnostics. Callers must integrity-check the merged result."""
    enc_key = derive_enc_key(passphrase, salt, algo["kdf_hash"])
    reserve = reserve_for(algo["page_hmac"])

    def _dec(pgno, stored):
        return _decrypt_page(stored, pgno, enc_key, reserve)

    frames, info = select_wal_frames(wal, decrypt_page=_dec)
    return frames, info


def load_stripped(path: str) -> bytes:
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:15] != b"SQLite header 3":
        raise ValueError("not a QQ NT db (missing custom header)")
    return raw[QQ_HEADER_SIZE:]
