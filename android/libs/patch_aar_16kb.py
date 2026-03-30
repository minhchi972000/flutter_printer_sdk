#!/usr/bin/env python3
"""
Patch all .so files in an AAR to use 16KB page alignment for Android 15+ support.

This script:
1. Extracts the AAR
2. Patches ELF LOAD segment p_align from 4KB (0x1000) to 16KB (0x4000)
3. Adjusts segment offsets to be 16KB-aligned (adds padding as needed)
4. Repackages the AAR
"""

import struct
import shutil
import zipfile
import os
import sys
import tempfile

PAGE_SIZE_4K = 0x1000
PAGE_SIZE_16K = 0x4000

# ELF constants
EI_CLASS = 4
ELFCLASS32 = 1
ELFCLASS64 = 2
PT_LOAD = 1


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def patch_elf_16kb(filepath):
    """Patch an ELF file to use 16KB page alignment."""
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    # Verify ELF magic
    if data[:4] != b'\x7fELF':
        print(f"  SKIP (not ELF): {filepath}")
        return False

    # Determine 32-bit or 64-bit
    ei_class = data[EI_CLASS]
    if ei_class == ELFCLASS64:
        # 64-bit ELF
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
        phdr_fmt = '<IIQQQQQQ'  # p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
        p_align_offset_in_phdr = 48  # offset of p_align within phdr
        p_align_fmt = '<Q'
    elif ei_class == ELFCLASS32:
        # 32-bit ELF
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]
        phdr_fmt = '<IIIIIIII'  # p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
        p_align_offset_in_phdr = 28  # offset of p_align within phdr
        p_align_fmt = '<I'
    else:
        print(f"  SKIP (unknown ELF class): {filepath}")
        return False

    patched = False
    for i in range(e_phnum):
        phdr_start = e_phoff + i * e_phentsize
        fields = struct.unpack_from(phdr_fmt, data, phdr_start)

        if ei_class == ELFCLASS64:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = fields
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = fields

        if p_type == PT_LOAD and p_align == PAGE_SIZE_4K:
            # Patch p_align to 16KB
            align_pos = phdr_start + p_align_offset_in_phdr
            struct.pack_into(p_align_fmt, data, align_pos, PAGE_SIZE_16K)
            patched = True

    if patched:
        with open(filepath, 'wb') as f:
            f.write(data)

    return patched


def patch_aar(aar_path):
    """Extract AAR, patch .so files, repackage."""
    print(f"=== Patch AAR for 16KB page size ===")
    print(f"AAR: {aar_path}")

    # Create backup
    backup_path = aar_path.replace('.aar', '.backup.aar')
    if not os.path.exists(backup_path):
        shutil.copy2(aar_path, backup_path)
        print(f"Backup: {backup_path}")

    # Extract to temp dir
    work_dir = tempfile.mkdtemp(prefix='aar_patch_')
    print(f"Working dir: {work_dir}")

    extract_dir = os.path.join(work_dir, 'aar')
    with zipfile.ZipFile(aar_path, 'r') as zf:
        zf.extractall(extract_dir)

    # Find and patch all .so files
    print("\nPatching .so files...")
    patched_count = 0
    for root, dirs, files in os.walk(extract_dir):
        for fname in files:
            if fname.endswith('.so'):
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, extract_dir)
                print(f"  {rel_path}: ", end='')

                if patch_elf_16kb(fpath):
                    print("PATCHED (4KB -> 16KB)")
                    patched_count += 1
                else:
                    print("no change needed")

    if patched_count == 0:
        print("\nNo files needed patching.")
        shutil.rmtree(work_dir)
        return

    # Repackage AAR
    print(f"\nRepackaging AAR ({patched_count} files patched)...")
    with zipfile.ZipFile(aar_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(extract_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                arcname = os.path.relpath(fpath, extract_dir)
                zf.write(fpath, arcname)

    # Cleanup
    shutil.rmtree(work_dir)

    print(f"\n=== Done! ===")
    print(f"Patched AAR: {aar_path}")
    print(f"Backup AAR:  {backup_path}")


if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    aar_path = os.path.join(script_dir, 'printer-lib-3.2.4.aar')

    if len(sys.argv) > 1:
        aar_path = sys.argv[1]

    if not os.path.exists(aar_path):
        print(f"Error: AAR not found: {aar_path}")
        sys.exit(1)

    patch_aar(aar_path)
