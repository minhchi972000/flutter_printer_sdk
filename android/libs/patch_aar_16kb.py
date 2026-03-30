#!/usr/bin/env python3
"""
Patch all .so files in an AAR to use 16KB page alignment for Android 15+ support.

This script:
1. Extracts the AAR
2. Rebuilds ELF files so LOAD segments have 16KB-aligned offsets and p_align=0x4000
3. Repackages the AAR
"""

import struct
import shutil
import zipfile
import os
import sys
import tempfile
import copy

PAGE_SIZE_4K = 0x1000
PAGE_SIZE_16K = 0x4000

# ELF constants
EI_CLASS = 4
ELFCLASS32 = 1
ELFCLASS64 = 2
PT_LOAD = 1
PT_GNU_RELRO = 0x6474e552


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def patch_elf_16kb(filepath):
    """Rebuild an ELF file with 16KB-aligned LOAD segments."""
    with open(filepath, 'rb') as f:
        original = f.read()

    data = bytearray(original)

    # Verify ELF magic
    if data[:4] != b'\x7fELF':
        print(f"  SKIP (not ELF)")
        return False

    ei_class = data[EI_CLASS]
    is64 = ei_class == ELFCLASS64

    if is64:
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
        e_shoff_pos = 40
        e_shoff_fmt = '<Q'
    else:
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]
        e_shoff_pos = 32
        e_shoff_fmt = '<I'

    # Parse all program headers
    segments = []
    has_4k_load = False
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from('<IIQQQQQQ', data, off)
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                struct.unpack_from('<IIIIIIII', data, off)

        seg = {
            'index': i, 'phdr_off': off,
            'p_type': p_type, 'p_flags': p_flags,
            'p_offset': p_offset, 'p_vaddr': p_vaddr, 'p_paddr': p_paddr,
            'p_filesz': p_filesz, 'p_memsz': p_memsz, 'p_align': p_align,
        }
        segments.append(seg)

        if p_type == PT_LOAD and p_align <= PAGE_SIZE_4K:
            has_4k_load = True

    if not has_4k_load:
        print(f"  already 16KB aligned")
        return False

    # Build new ELF with properly aligned LOAD segments
    # Strategy: copy the file but insert padding before LOAD segments
    # so their file offsets are congruent with vaddr mod 16KB

    # Sort segments by original file offset for processing
    load_segments = [s for s in segments if s['p_type'] == PT_LOAD]
    load_segments.sort(key=lambda s: s['p_offset'])

    if not load_segments:
        return False

    # The first LOAD usually starts at offset 0, which is already aligned.
    # For subsequent LOADs, we need offset ≡ vaddr (mod 16KB)
    # We'll rebuild the file by copying chunks and inserting padding.

    new_data = bytearray()
    prev_end = 0  # tracks how far we've copied from original

    offset_adjustments = {}  # original_offset -> new_offset

    for seg in load_segments:
        orig_off = seg['p_offset']
        vaddr = seg['p_vaddr']

        # Copy everything before this segment
        new_data.extend(data[prev_end:orig_off])

        # Current position in new file
        cur_pos = len(new_data)

        # Required: new_offset ≡ vaddr (mod PAGE_SIZE_16K)
        required_mod = vaddr % PAGE_SIZE_16K
        cur_mod = cur_pos % PAGE_SIZE_16K

        if cur_mod <= required_mod:
            padding_needed = required_mod - cur_mod
        else:
            padding_needed = PAGE_SIZE_16K - cur_mod + required_mod

        # Insert padding
        if padding_needed > 0:
            new_data.extend(b'\x00' * padding_needed)

        new_offset = len(new_data)
        offset_adjustments[orig_off] = new_offset

        # Copy segment data
        seg_end = orig_off + seg['p_filesz']
        new_data.extend(data[orig_off:seg_end])
        prev_end = seg_end

    # Copy remaining data after last LOAD segment
    new_data.extend(data[prev_end:])

    # Calculate total shift for section headers
    total_shift = len(new_data) - len(data)

    # Update program headers in new_data
    # First, we need to find where the program headers are in the new data
    # Program headers are typically within the first LOAD segment
    # We need to update offsets for all segments

    for seg in segments:
        phdr_new_off = seg['phdr_off']

        # Adjust phdr_off if program headers shifted (they're in first LOAD which starts at 0)
        if load_segments[0]['p_offset'] == 0:
            # phdrs are in the first LOAD, offset 0 maps to 0, no shift
            phdr_new_off = seg['phdr_off']

        if seg['p_type'] == PT_LOAD:
            orig_off = seg['p_offset']
            new_off = offset_adjustments.get(orig_off, orig_off)
            new_align = PAGE_SIZE_16K

            if is64:
                # p_offset at phdr+8, p_align at phdr+48
                struct.pack_into('<Q', new_data, phdr_new_off + 8, new_off)
                struct.pack_into('<Q', new_data, phdr_new_off + 48, new_align)
            else:
                # p_offset at phdr+4, p_align at phdr+28
                struct.pack_into('<I', new_data, phdr_new_off + 4, new_off)
                struct.pack_into('<I', new_data, phdr_new_off + 28, new_align)

        elif seg['p_type'] == PT_GNU_RELRO:
            # RELRO usually overlaps with a LOAD segment, update its offset too
            orig_off = seg['p_offset']
            # Find which LOAD segment contains this offset
            for ls in load_segments:
                if ls['p_offset'] <= orig_off < ls['p_offset'] + ls['p_filesz']:
                    delta = offset_adjustments[ls['p_offset']] - ls['p_offset']
                    new_off = orig_off + delta
                    if is64:
                        struct.pack_into('<Q', new_data, phdr_new_off + 8, new_off)
                    else:
                        struct.pack_into('<I', new_data, phdr_new_off + 4, new_off)
                    break

        else:
            # For non-LOAD segments, adjust offset if it falls within a shifted region
            orig_off = seg['p_offset']
            for ls in load_segments:
                if ls['p_offset'] <= orig_off < ls['p_offset'] + ls['p_filesz']:
                    delta = offset_adjustments[ls['p_offset']] - ls['p_offset']
                    new_off = orig_off + delta
                    if is64:
                        struct.pack_into('<Q', new_data, phdr_new_off + 8, new_off)
                    else:
                        struct.pack_into('<I', new_data, phdr_new_off + 4, new_off)
                    break

    # Update section header table offset (e_shoff)
    if is64:
        old_shoff = struct.unpack_from('<Q', new_data, e_shoff_pos)[0]
    else:
        old_shoff = struct.unpack_from('<I', new_data, e_shoff_pos)[0]

    if old_shoff > 0:
        new_shoff = old_shoff + total_shift
        struct.pack_into(e_shoff_fmt, new_data, e_shoff_pos, new_shoff)

        # Update section header sh_offset fields
        if is64:
            e_shentsize = struct.unpack_from('<H', new_data, 58)[0]
            e_shnum = struct.unpack_from('<H', new_data, 60)[0]
        else:
            e_shentsize = struct.unpack_from('<H', new_data, 46)[0]
            e_shnum = struct.unpack_from('<H', new_data, 48)[0]

        for i in range(e_shnum):
            sh_start = new_shoff + i * e_shentsize
            if sh_start + e_shentsize > len(new_data):
                break

            if is64:
                sh_offset = struct.unpack_from('<Q', new_data, sh_start + 24)[0]
            else:
                sh_offset = struct.unpack_from('<I', new_data, sh_start + 16)[0]

            # Find if this section falls within a shifted LOAD segment
            for ls in load_segments:
                ls_end = ls['p_offset'] + ls['p_filesz']
                if ls['p_offset'] <= sh_offset < ls_end:
                    delta = offset_adjustments[ls['p_offset']] - ls['p_offset']
                    new_sh_offset = sh_offset + delta
                    if is64:
                        struct.pack_into('<Q', new_data, sh_start + 24, new_sh_offset)
                    else:
                        struct.pack_into('<I', new_data, sh_start + 16, new_sh_offset)
                    break
            else:
                # Section after all LOAD segments - shift by total
                if sh_offset >= load_segments[-1]['p_offset'] + load_segments[-1]['p_filesz']:
                    new_sh_offset = sh_offset + total_shift
                    if is64:
                        struct.pack_into('<Q', new_data, sh_start + 24, new_sh_offset)
                    else:
                        struct.pack_into('<I', new_data, sh_start + 16, new_sh_offset)

    with open(filepath, 'wb') as f:
        f.write(new_data)

    return True


def patch_aar(aar_path):
    """Extract AAR, patch .so files, repackage."""
    print(f"=== Patch AAR for 16KB page size ===")
    print(f"AAR: {aar_path}")

    # Create backup
    backup_path = aar_path.replace('.aar', '.backup.aar')
    if not os.path.exists(backup_path):
        shutil.copy2(aar_path, backup_path)
        print(f"Backup: {backup_path}")
    else:
        # Restore from backup to patch clean original
        shutil.copy2(backup_path, aar_path)
        print(f"Restored from backup: {backup_path}")

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

    # Verify
    print(f"\nVerifying patched .so files...")
    verify_dir = tempfile.mkdtemp(prefix='aar_verify_')
    with zipfile.ZipFile(aar_path, 'r') as zf:
        zf.extractall(verify_dir)
    for root, dirs, files in os.walk(verify_dir):
        for fname in files:
            if fname.endswith('.so'):
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, verify_dir)
                verify_elf_alignment(fpath, rel_path)
    shutil.rmtree(verify_dir)

    print(f"\n=== Done! ===")
    print(f"Patched AAR: {aar_path}")
    print(f"Backup AAR:  {backup_path}")


def verify_elf_alignment(filepath, label):
    """Verify LOAD segment alignment of an ELF file."""
    with open(filepath, 'rb') as f:
        data = f.read()

    if data[:4] != b'\x7fELF':
        return

    ei_class = data[4]
    is64 = ei_class == ELFCLASS64

    if is64:
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
    else:
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from('<IIQQQQQQ', data, off)
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                struct.unpack_from('<IIIIIIII', data, off)

        if p_type == PT_LOAD:
            aligned = (p_offset % PAGE_SIZE_16K) == (p_vaddr % PAGE_SIZE_16K)
            status = "OK" if (p_align >= PAGE_SIZE_16K and aligned) else "FAIL"
            print(f"  {label}: LOAD offset=0x{p_offset:x} vaddr=0x{p_vaddr:x} "
                  f"align=0x{p_align:x} offset_aligned={aligned} [{status}]")


if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    aar_path = os.path.join(script_dir, 'printer-lib-3.2.4.aar')

    if len(sys.argv) > 1:
        aar_path = sys.argv[1]

    if not os.path.exists(aar_path):
        print(f"Error: AAR not found: {aar_path}")
        sys.exit(1)

    patch_aar(aar_path)
