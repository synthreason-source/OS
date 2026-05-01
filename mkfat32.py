#!/usr/bin/env python3
"""
mkfat32.py — Create a minimal FAT32 disk image with no external dependencies.
Usage: python3 mkfat32.py <output.img> [size_mb]
Default size: 128 MB.
"""
import struct, sys, os

def mkfat32(path, size_mb=128):
    SEC  = 512
    CLUS = 8          # sectors per cluster (4 KB clusters)
    RSVD = 32         # reserved sectors
    FATS = 2
    LABEL  = b'MYOS       '   # 11 bytes
    FSTYPE = b'FAT32   '      # 8 bytes

    total = (size_mb * 1024 * 1024) // SEC  # total sectors

    # Microsoft FAT32 FAT size formula (FAT spec §3.5)
    tmp1   = total - RSVD
    tmp2   = (256 * CLUS + FATS) // 2
    fat_sz = (tmp1 + tmp2 - 1) // tmp2      # sectors per FAT

    # ── Boot sector (BPB) ─────────────────────────────────────────────────────
    bpb = bytearray(SEC)
    bpb[0:3]  = bytes([0xEB, 0x58, 0x90])   # JMP SHORT + NOP
    bpb[3:11] = b'MSWIN4.1'
    struct.pack_into('<H', bpb, 11, SEC)     # bytes per sector
    bpb[13]   = CLUS                         # sectors per cluster
    struct.pack_into('<H', bpb, 14, RSVD)   # reserved sectors
    bpb[16]   = FATS                         # number of FATs
    struct.pack_into('<H', bpb, 17, 0)       # root entry count (0 = FAT32)
    struct.pack_into('<H', bpb, 19, 0)       # total16 (0 = use total32)
    bpb[21]   = 0xF8                         # media type = fixed disk
    struct.pack_into('<H', bpb, 22, 0)       # FAT size 16 (0 = FAT32)
    struct.pack_into('<H', bpb, 24, 32)      # sectors/track (geometry)
    struct.pack_into('<H', bpb, 26, 64)      # number of heads
    struct.pack_into('<I', bpb, 28, 0)       # hidden sectors
    struct.pack_into('<I', bpb, 32, total)   # total sectors 32
    struct.pack_into('<I', bpb, 36, fat_sz)  # FAT size 32
    struct.pack_into('<H', bpb, 40, 0)       # ext flags
    struct.pack_into('<H', bpb, 42, 0)       # FS version
    struct.pack_into('<I', bpb, 44, 2)       # root cluster = 2
    struct.pack_into('<H', bpb, 48, 1)       # FSInfo sector
    struct.pack_into('<H', bpb, 50, 6)       # backup boot sector
    bpb[64]   = 0x80                         # drive number
    bpb[66]   = 0x29                         # extended boot sig
    struct.pack_into('<I', bpb, 67, 0x12345678)  # volume serial
    bpb[71:82] = LABEL
    bpb[82:90] = FSTYPE
    bpb[510]  = 0x55                         # boot sector signature
    bpb[511]  = 0xAA

    # ── FSInfo (sector 1) ─────────────────────────────────────────────────────
    fsi = bytearray(SEC)
    struct.pack_into('<I', fsi,   0, 0x41615252)  # lead signature
    struct.pack_into('<I', fsi, 484, 0x61417272)  # structure signature
    struct.pack_into('<I', fsi, 488, 0xFFFFFFFF)  # free cluster count (unknown)
    struct.pack_into('<I', fsi, 492, 0xFFFFFFFF)  # next free cluster (unknown)
    fsi[510] = 0x55; fsi[511] = 0xAA

    # ── FAT (first three entries) ─────────────────────────────────────────────
    fat = bytearray(fat_sz * SEC)
    struct.pack_into('<I', fat,  0, 0x0FFFFFF8)   # FAT[0] = media descriptor
    struct.pack_into('<I', fat,  4, 0x0FFFFFFF)   # FAT[1] = reserved/EOC
    struct.pack_into('<I', fat,  8, 0x0FFFFFFF)   # FAT[2] = root dir EOC

    # ── Write image ───────────────────────────────────────────────────────────
    with open(path, 'wb') as f:
        f.write(bytes(total * SEC))   # zero-fill entire image

    with open(path, 'r+b') as f:
        f.seek(0 * SEC);           f.write(bpb)   # boot sector
        f.seek(1 * SEC);           f.write(fsi)   # FSInfo
        f.seek(6 * SEC);           f.write(bpb)   # backup boot sector
        f.seek(7 * SEC);           f.write(fsi)   # backup FSInfo
        f.seek(RSVD * SEC);        f.write(fat)   # FAT1
        f.seek((RSVD+fat_sz)*SEC); f.write(fat)   # FAT2
        # Root directory cluster (cluster 2) is already zeroed — empty dir

    print(f"FAT32 image: {path}  ({size_mb} MB, {fat_sz} FAT sectors, "
          f"{(total - RSVD - FATS*fat_sz)//CLUS} data clusters)")

if __name__ == '__main__':
    out  = sys.argv[1] if len(sys.argv) > 1 else 'disk.img'
    size = int(sys.argv[2]) if len(sys.argv) > 2 else 128
    mkfat32(out, size)
