#!/usr/bin/env python3
"""Relocation check for GOT-model relocations (relocatable objects). Ghidra put its GOT
in an artificial %got block, GNU ld (static link at Ghidra's section addresses) in its own .got,
so these sites are compared by what they compute in each image: the value in the GOT entry they
select, the address or thread-pointer offset they form, or (GOTPC) the GOT address. Every other
byte is compared directly.

  got_check.py <object.o> <ghidra.sum> <ghidra.mem> <ld-linked.elf | ->

The 8- and 16-bit data relocations (R_OR1K_8, R_OR1K_16, R_OR1K_16_PCREL, R_OR1K_8_PCREL) are
checked against S + A (- P) with the symbol addresses Ghidra assigned: GNU ld 2.43 and 2.45
cannot link them (bfd or1k_final_link_relocate asserts, comparing dst_mask with N_ONES of the
size in bytes instead of bits), so "-" skips the ld comparison.
"""
import struct
import sys
from collections import Counter

obj, gsum, gmem, lelf = sys.argv[1:5]


class Elf:
    """minimal ELF32 big-endian reader"""

    def __init__(self, path):
        d = self.d = open(path, "rb").read()
        shoff, = struct.unpack_from(">I", d, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(">HHH", d, 0x2e)
        self.sh = []
        for i in range(shnum):
            f = struct.unpack_from(">IIIIIIIIII", d, shoff + i * shentsize)
            self.sh.append(dict(name=f[0], type=f[1], flags=f[2], addr=f[3], off=f[4], size=f[5],
                                link=f[6], info=f[7]))
        so = self.sh[shstrndx]["off"]
        for h in self.sh:
            h["name"] = self.cstr(so, h["name"])

    def cstr(self, base, off):
        return self.d[base + off:self.d.index(b"\0", base + off)].decode()

    def symbols(self):
        h = next(x for x in self.sh if x["type"] == 2)
        so = self.sh[h["link"]]["off"]
        out = []
        for i in range(h["size"] // 16):
            name, value, size, info, other, shndx = struct.unpack_from(">IIIBBH", self.d, h["off"] + 16 * i)
            out.append(dict(name=self.cstr(so, name), value=value, shndx=shndx))
        return out


blocks, ext = {}, {}
for line in open(gsum):
    if line.startswith("blocks:"):
        for b in line.split()[1:]:
            n, a = b.rsplit("@", 1)
            blocks[n] = int(a, 16)
    if line.startswith("external symbols:"):
        for b in line.split()[2:]:
            n, a = b.rsplit("@", 1)
            ext[n] = int(a, 16)
G = {}
for line in open(gmem):
    a, b = line.split()
    G[int(a, 16)] = int(b, 16)
L = {}
got = {"ghidra": blocks.get("%got"), "ld": None}
if lelf != "-":
    lf = Elf(lelf)
    for h in lf.sh:
        if h["flags"] & 2 and h["type"] != 8:
            for i, x in enumerate(lf.d[h["off"]:h["off"] + h["size"]]):
                L[h["addr"] + i] = x
    got["ld"] = next((s["value"] for s in lf.symbols() if s["name"] == "_GLOBAL_OFFSET_TABLE_"), None)
img = {"ghidra": G, "ld": L}

def rd(m, a, n=4):
    return int.from_bytes(bytes(m[a + i] for i in range(n)), "big")

def lo(m, a):
    return rd(m, a) & 0xffff

def s16(v):
    return v - 0x10000 if v & 0x8000 else v

of = Elf(obj)
syms = of.symbols()
sites = []
for h in of.sh:
    if h["type"] != 4:                                   # SHT_RELA
        continue
    target = of.sh[h["info"]]["name"]
    if target not in blocks:
        continue
    for i in range(h["size"] // 12):
        off, info, add = struct.unpack_from(">IIi", of.d, h["off"] + 12 * i)
        t, si = info & 0xff, info >> 8
        sym = syms[si]
        sname = sym["name"] or of.sh[sym["shndx"]]["name"]
        if sym["shndx"] == 0:
            S = ext.get(sym["name"])
        elif sym["shndx"] < 0xff00:
            S = blocks.get(of.sh[sym["shndx"]]["name"], 0) + sym["value"]
        else:
            S = sym["value"]
        sites.append((t, blocks[target] + off, (sname, add), add, S))

NAMES = {12: "GOTPC_HI16", 13: "GOTPC_LO16", 14: "GOT16", 16: "GOTOFF_HI16", 17: "GOTOFF_LO16",
         22: "TLS_GD_HI16", 23: "TLS_GD_LO16", 28: "TLS_IE_HI16", 29: "TLS_IE_LO16",
         30: "TLS_LE_HI16", 31: "TLS_LE_LO16", 36: "GOTOFF_AHI16", 37: "TLS_IE_AHI16",
         38: "TLS_LE_AHI16", 40: "GOTOFF_SLO16", 41: "TLS_LE_SLO16", 54: "GOT_AHI16"}
ok, bad, msgs = Counter(), Counter(), []
def check(name, cond, what):
    (ok if cond else bad)[name] += 1
    if not cond and len(msgs) < 20:
        msgs.append(f"  {name}: {what}")

def fam(n):
    """relocation family: the name without its HI16/AHI16/LO16 part"""
    return n.rsplit("_", 1)[0]

skip = set()
his = {}
for t, P, key, add, S in sites:
    if t in NAMES:
        skip.update(range(P, P + 4))
        if NAMES[t].endswith("HI16"):
            his.setdefault((fam(NAMES[t]), key), []).append((t, P))

def value(which, t, P, key):
    """what the site (with its high-half partner) computes in one image"""
    m, g = img[which], got[which]
    n = NAMES[t]
    if n == "GOT16":
        return rd(m, g + s16(lo(m, P)))
    if n == "GOTPC_HI16":
        return (lo(m, P) << 16, g)
    if n == "GOTPC_LO16":
        return (lo(m, P), g)
    hi = his.get((fam(n), key))
    if not hi:
        return None
    ht, hp = hi[0]
    h = lo(m, hp)
    full = (h << 16) + s16(lo(m, P)) if NAMES[ht].endswith("AHI16") else (h << 16) | lo(m, P)
    if n.startswith("GOTOFF"):
        return (g + full) & 0xffffffff
    if n.startswith("TLS_GD"):
        return (rd(m, g + full), rd(m, g + full + 4))
    if n.startswith("TLS_IE"):
        return rd(m, g + full)
    if n.startswith("TLS_LE"):
        return full & 0xffffffff

for t, P, key, add, S in sites:
    n = NAMES.get(t)
    if n is None or (n.endswith("HI16") and n != "GOTPC_HI16"):
        continue
    if n.startswith("GOTPC"):
        # field = (GOT + A - P) high/low half, in each image with its own GOT
        for which in ("ghidra", "ld"):
            m, g = img[which], got[which]
            v = (g + add - P) & 0xffffffff
            want = (v >> 16) if n == "GOTPC_HI16" else (v & 0xffff)
            check(n, lo(m, P) == want, f"{which} {P:x}: {lo(m, P):x}, expect {want:x}")
        continue
    vg, vl = value("ghidra", t, P, key), value("ld", t, P, key)
    check(n, vg is not None and vg == vl, f"{P:x} {key}: ghidra {vg}, ld {vl}")

# 8- and 16-bit data relocations, by formula
SMALL = {2: ("R_OR1K_16", 2, False), 3: ("R_OR1K_8", 1, False), 10: ("R_OR1K_16_PCREL", 2, True),
         11: ("R_OR1K_8_PCREL", 1, True)}
for t, P, key, add, S in sites:
    if t in SMALL:
        n, size, pcrel = SMALL[t]
        skip.update(range(P, P + size))
        want = (S + add - (P if pcrel else 0)) & ((1 << (8 * size)) - 1)
        got_v = rd(G, P, size)
        check(n, got_v == want, f"{P:x}: {got_v:x}, expect {want:x}")

eh = blocks.get(".eh_frame")
if eh is not None:
    end = min([a for a in blocks.values() if a > eh] + [1 << 64])
    skip.update(a for a in G if eh <= a < end)
gb = blocks.get("%got")
n = nb = 0
for a, v in G.items():
    if a in skip or a not in L or (gb is not None and a >= gb):
        continue
    n += 1
    if L[a] != v:
        nb += 1
        if len(msgs) < 20:
            msgs.append(f"  byte {a:x}: ghidra {v:02x} ld {L[a]:02x}")
print("\n".join(msgs))
print(f"GOT sites: {dict(ok)} agree, {dict(bad)} differ; other bytes: {n} compared, {nb} differ")
sys.exit(1 if bad or nb else 0)
