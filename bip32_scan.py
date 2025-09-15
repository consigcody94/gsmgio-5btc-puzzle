#!/usr/bin/env python3
"""
BIP32 scanner for GSMG.IO puzzle

- Uses the 64-byte Phase 3.2 payload as BIP32 master (IL = master secret, IR = chain code)
- Derives children along a given base path and scans indices for a case-sensitive vanity prefix.

Usage examples:
  python bip32_scan.py --path m/1/4/1 --prefix 1gsm --limit 200000
  python bip32_scan.py --path "m/44'/0'/0'/0" --prefix 1gsm --limit 100000

The script prints the first hit (address + WIF) and exits with code 0.
If no hit is found within the limit, exits with code 1.
"""

import argparse
import hmac
import hashlib
import sys
from ecdsa import SECP256k1, SigningKey
import base58 as b58


ORDER = SECP256k1.order

# Master from phase3_final (decrypted with Phase 3.2 password)
IL_HEX = "d199916cf86003a78df106056cc1c3fe66986909a408e8b8e2eafebde96f6265"
CC_HEX = "b10bc764fc97d2ddaea075183026db779e0845c20cc8120d5841d50ce9c9bcce"


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def ser32(i: int) -> bytes:
    return i.to_bytes(4, 'big')


def ser256(p: int) -> bytes:
    return p.to_bytes(32, 'big')


def parse256(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def point(pk_int: int):
    sk = SigningKey.from_secret_exponent(pk_int, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    return x, y


def serP(pk_int: int) -> bytes:
    x, y = point(pk_int)
    return (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32, 'big')


def hash160(b: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()


def addr_from_k(k: int) -> str:
    vh = b'\x00' + hash160(serP(k))
    chk = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return b58.b58encode(vh + chk).decode()


def wif_from_k(k: int) -> str:
    payload = b'\x80' + ser256(k) + b'\x01'  # compressed mainnet
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58.b58encode(payload + chk).decode()


class Node:
    def __init__(self, depth: int, fp: bytes, childnum: int, k: int, c: bytes):
        self.depth = depth
        self.fp = fp
        self.childnum = childnum
        self.k = k
        self.c = c

    def child(self, i: int) -> "Node":
        if i >= 2 ** 31:
            data = b'\x00' + ser256(self.k) + ser32(i)
        else:
            data = serP(self.k) + ser32(i)
        I = hmac_sha512(self.c, data)
        IL, IR = I[:32], I[32:]
        ki = (parse256(IL) + self.k) % ORDER
        if ki == 0:
            raise ValueError('Child key invalid')
        fp = hash160(serP(self.k))[:4]
        return Node(self.depth + 1, fp, i, ki, IR)


def derive_from_path(root: Node, path: str) -> Node:
    cur = root
    if path == 'm':
        return cur
    for part in path.split('/')[1:]:
        if part.endswith("'"):
            i = int(part[:-1]) + 2 ** 31
        else:
            i = int(part)
        cur = cur.child(i)
    return cur


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--path', default='m/1/4/1', help='Base derivation path (default m/1/4/1)')
    ap.add_argument('--prefix', default='1gsm', help='Case-sensitive P2PKH vanity prefix (default 1gsm)')
    ap.add_argument('--start', type=int, default=0, help='Start index (default 0)')
    ap.add_argument('--limit', type=int, default=100000, help='Number of indices to scan (default 100k)')
    args = ap.parse_args()

    km = int(IL_HEX, 16)
    if not (1 <= km < ORDER):
        print('Master IL out of range', file=sys.stderr)
        sys.exit(2)
    root = Node(0, b"\x00\x00\x00\x00", 0, km, bytes.fromhex(CC_HEX))
    base = derive_from_path(root, args.path)

    end = args.start + args.limit
    for i in range(args.start, end):
        node = base.child(i)
        addr = addr_from_k(node.k)
        if addr.startswith(args.prefix):
            print('FOUND')
            print('path:', f"{args.path}/{i}")
            print('address:', addr)
            print('wif:', wif_from_k(node.k))
            return 0
        if (i - args.start) % 10000 == 0 and i != args.start:
            print(f'progress: {i - args.start} scanned...', file=sys.stderr)
    print('No match within range', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())

