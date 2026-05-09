#!/usr/bin/env python3
"""mkfat32.py — create a blank FAT32 disk image, no external tools needed.

Usage:
    python3 mkfat32.py <image_path> <size_megabytes>

Layout (per Microsoft FAT32 spec, simplified):
    LBA 0:           Boot sector (BPB)
    LBA 1:           FSInfo
    LBA 6:           Backup boot sector
    LBA 7:           Backup FSInfo
    LBA RSV..:       FAT1
    LBA RSV+FATSZ..: FAT2
    LBA DATA..:      Data area, root dir at cluster 2

This produces an image that the kernel's FAT32 driver and Linux's
`mtools` / `mount -o loop` can read, with an empty root directory.
"""
import os
import struct
import sys

SECTOR = 512
RESERVED_SECTORS = 32
NUM_FATS = 2
SECTORS_PER_CLUSTER = 8        # 4 KiB clusters
ROOT_CLUSTER = 2

def make_fat32(path: str, size_mb: int) -> None:
    total_sectors = (size_mb * 1024 * 1024) // SECTOR
    # FAT entries needed = clusters + 2 reserved entries
    # Each FAT entry is 4 bytes.
    # Iterate to a stable FAT size.
    fat_sectors = 1
    for _ in range(8):
        data_sectors = total_sectors - RESERVED_SECTORS - NUM_FATS * fat_sectors
        clusters = data_sectors // SECTORS_PER_CLUSTER
        needed_bytes = (clusters + 2) * 4
        new_fat_sectors = (needed_bytes + SECTOR - 1) // SECTOR
        if new_fat_sectors == fat_sectors:
            break
        fat_sectors = new_fat_sectors

    fat1_lba = RESERVED_SECTORS
    fat2_lba = fat1_lba + fat_sectors
    data_lba = fat2_lba + fat_sectors

    # ── Boot sector (BPB) ──
    bs = bytearray(SECTOR)
    bs[0:3]  = b'\xEB\x58\x90'               # JMP + NOP
    bs[3:11] = b'MSWIN4.1'                   # OEM
    struct.pack_into('<H', bs, 11, SECTOR)   # BytesPerSector
    bs[13]   = SECTORS_PER_CLUSTER
    struct.pack_into('<H', bs, 14, RESERVED_SECTORS)
    bs[16]   = NUM_FATS
    struct.pack_into('<H', bs, 17, 0)        # RootEntCnt (0 for FAT32)
    struct.pack_into('<H', bs, 19, 0)        # TotSec16
    bs[21]   = 0xF8                           # MediaType = fixed
    struct.pack_into('<H', bs, 22, 0)        # FATSz16 (0 for FAT32)
    struct.pack_into('<H', bs, 24, 63)       # SecPerTrk (placeholder)
    struct.pack_into('<H', bs, 26, 255)      # NumHeads (placeholder)
    struct.pack_into('<I', bs, 28, 0)        # HiddSec
    struct.pack_into('<I', bs, 32, total_sectors)
    struct.pack_into('<I', bs, 36, fat_sectors)  # FATSz32
    struct.pack_into('<H', bs, 40, 0)        # ExtFlags
    struct.pack_into('<H', bs, 42, 0)        # FSVer
    struct.pack_into('<I', bs, 44, ROOT_CLUSTER)
    struct.pack_into('<H', bs, 48, 1)        # FSInfo sector
    struct.pack_into('<H', bs, 50, 6)        # BkBootSec
    bs[64]   = 0x80                           # DrvNum
    bs[66]   = 0x29                           # BootSig
    struct.pack_into('<I', bs, 67, 0xDEADBEEF)  # VolID
    bs[71:82] = b'NO NAME    '
    bs[82:90] = b'FAT32   '
    bs[510]  = 0x55
    bs[511]  = 0xAA

    # ── FSInfo ──
    fs = bytearray(SECTOR)
    struct.pack_into('<I', fs, 0,   0x41615252)
    struct.pack_into('<I', fs, 484, 0x61417272)
    struct.pack_into('<I', fs, 488, 0xFFFFFFFF)  # FreeCount unknown
    struct.pack_into('<I', fs, 492, 3)            # NextFree hint
    struct.pack_into('<I', fs, 508, 0xAA550000)

    # ── FAT (one sector with reserved entries; rest is zero) ──
    fat0 = bytearray(SECTOR)
    struct.pack_into('<I', fat0, 0, 0x0FFFFFF8)  # entry 0
    struct.pack_into('<I', fat0, 4, 0x0FFFFFFF)  # entry 1
    struct.pack_into('<I', fat0, 8, 0x0FFFFFFF)  # entry 2 = root, EOC

    with open(path, 'wb') as f:
        # Boot sector + FSInfo
        f.write(bs)
        f.write(fs)
        # zeros up to backup boot sector (LBA 6)
        f.seek(6 * SECTOR)
        f.write(bs)                       # backup boot
        f.write(fs)                       # backup FSInfo
        # zeros up to FAT1
        f.seek(fat1_lba * SECTOR)
        f.write(fat0)
        # zeros up to FAT2
        f.seek(fat2_lba * SECTOR)
        f.write(fat0)
        # extend file to total size
        f.truncate(total_sectors * SECTOR)

    print(f"FAT32 image: {path}  ({size_mb} MiB, "
          f"FATsz={fat_sectors}, data_lba={data_lba})")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    make_fat32(sys.argv[1], int(sys.argv[2]))
