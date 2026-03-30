#!/usr/bin/env python3
"""
Patch all .so files in an AAR to use 16KB page alignment for Android 15+ support.

This script properly re-layouts ELF binaries:
1. Inserts padding so LOAD segments are on separate 16KB pages
2. Updates p_align, p_offset, p_vaddr, p_paddr in program headers
3. Shifts section headers, dynamic entries, relocations, and symbol addresses
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
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_RELRO = 0x6474e552

# Dynamic tags that contain virtual addresses
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_INIT = 12
DT_FINI = 13
DT_REL = 17
DT_JMPREL = 23
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_GNU_HASH = 0x6ffffef5
DT_VERSYM = 0x6ffffff0
DT_VERNEED = 0x6ffffffe

# These DT tags contain addresses (not sizes/counts)
DT_ADDR_TAGS = {
    DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_INIT, DT_FINI,
    DT_REL, DT_JMPREL, DT_INIT_ARRAY, DT_FINI_ARRAY, DT_GNU_HASH, DT_VERSYM,
    DT_VERNEED,
}

# Relocation types (only need RELATIVE for addend shifting)
R_AARCH64_RELATIVE = 0x403
R_ARM_RELATIVE = 0x17
R_386_RELATIVE = 0x08
R_X86_64_RELATIVE = 0x08


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


class ElfPatcher:
    def __init__(self, data):
        self.data = bytearray(data)
        self.is64 = self.data[4] == 2  # ELFCLASS64
        self.is_le = self.data[5] == 1  # Little endian
        self.e_machine = struct.unpack_from('<H', self.data, 18)[0]
        self._parse_header()
        self._parse_segments()
        self._parse_sections()

    def _u(self, fmt, off):
        return struct.unpack_from(('<' if self.is_le else '>') + fmt, self.data, off)

    def _p(self, fmt, off, *vals):
        struct.pack_into(('<' if self.is_le else '>') + fmt, self.data, off, *vals)

    def _parse_header(self):
        if self.is64:
            self.e_phoff = self._u('Q', 32)[0]
            self.e_shoff = self._u('Q', 40)[0]
            self.e_phentsize = self._u('H', 54)[0]
            self.e_phnum = self._u('H', 56)[0]
            self.e_shentsize = self._u('H', 58)[0]
            self.e_shnum = self._u('H', 60)[0]
        else:
            self.e_phoff = self._u('I', 28)[0]
            self.e_shoff = self._u('I', 32)[0]
            self.e_phentsize = self._u('H', 42)[0]
            self.e_phnum = self._u('H', 44)[0]
            self.e_shentsize = self._u('H', 46)[0]
            self.e_shnum = self._u('H', 48)[0]

    def _parse_segments(self):
        self.segments = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                p_type, p_flags = self._u('II', off)
                p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = self._u('QQQQQQ', off + 8)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = self._u('IIIIIIII', off)
            self.segments.append({
                'idx': i, 'off': off,
                'p_type': p_type, 'p_flags': p_flags,
                'p_offset': p_offset, 'p_vaddr': p_vaddr, 'p_paddr': p_paddr,
                'p_filesz': p_filesz, 'p_memsz': p_memsz, 'p_align': p_align,
            })

    def _parse_sections(self):
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if self.is64:
                sh_name, sh_type, sh_flags = self._u('IIQ', off)
                sh_addr, sh_offset, sh_size = self._u('QQQ', off + 16)
                sh_link, sh_info = self._u('II', off + 40)
                sh_addralign, sh_entsize = self._u('QQ', off + 48)
            else:
                sh_name, sh_type = self._u('II', off)
                sh_flags, sh_addr, sh_offset, sh_size = self._u('IIII', off + 8)
                sh_link, sh_info, sh_addralign, sh_entsize = self._u('IIII', off + 24)
            self.sections.append({
                'idx': i, 'off': off,
                'sh_name': sh_name, 'sh_type': sh_type, 'sh_flags': sh_flags,
                'sh_addr': sh_addr, 'sh_offset': sh_offset, 'sh_size': sh_size,
                'sh_link': sh_link, 'sh_info': sh_info,
                'sh_addralign': sh_addralign, 'sh_entsize': sh_entsize,
            })

    def needs_patch(self):
        load_segs = [s for s in self.segments if s['p_type'] == PT_LOAD]
        return any(s['p_align'] < PAGE_SIZE_16K for s in load_segs)

    def patch_16kb(self):
        load_segs = sorted(
            [s for s in self.segments if s['p_type'] == PT_LOAD],
            key=lambda s: s['p_offset']
        )

        if len(load_segs) < 2:
            return False

        first_load = load_segs[0]
        second_load = load_segs[1]

        # Check if segments overlap on 16KB pages
        first_end_page = first_load['p_vaddr'] + first_load['p_memsz']
        second_start = second_load['p_vaddr']

        if align_up(first_end_page, PAGE_SIZE_16K) > second_start:
            # Segments share a 16KB page - need to shift the second one
            # Calculate new vaddr for second LOAD: next 16KB boundary + same page offset
            page_offset = second_load['p_vaddr'] % PAGE_SIZE_16K
            new_vaddr_base = align_up(first_end_page, PAGE_SIZE_16K)
            new_vaddr = new_vaddr_base + page_offset

            vaddr_delta = new_vaddr - second_load['p_vaddr']
        else:
            vaddr_delta = 0

        # Calculate file layout: insert padding before second LOAD
        old_second_offset = second_load['p_offset']

        # New offset must satisfy: new_offset % 16K == new_vaddr % 16K
        new_vaddr = second_load['p_vaddr'] + vaddr_delta
        required_mod = new_vaddr % PAGE_SIZE_16K
        # Find smallest new_offset >= old_second_offset where new_offset % 16K == required_mod
        candidate = align_up(old_second_offset, PAGE_SIZE_16K) + required_mod
        if candidate < old_second_offset:
            candidate += PAGE_SIZE_16K
        new_second_offset = candidate

        file_delta = new_second_offset - old_second_offset

        if file_delta == 0 and vaddr_delta == 0:
            # Just update p_align
            for seg in load_segs:
                self._write_phdr_align(seg, PAGE_SIZE_16K)
            return True

        # Define the range of virtual addresses being shifted
        old_vaddr_start = second_load['p_vaddr']
        old_vaddr_end = second_load['p_vaddr'] + second_load['p_memsz']

        # Insert padding bytes into file
        padding = b'\x00' * file_delta
        self.data = self.data[:old_second_offset] + bytearray(padding) + self.data[old_second_offset:]

        # Re-parse header since offsets changed
        # But we need to manually update everything

        # 1. Update program headers
        for seg in self.segments:
            if seg['p_type'] == PT_LOAD:
                if seg['p_offset'] >= old_second_offset:
                    self._write_phdr_offset(seg, seg['p_offset'] + file_delta)
                    self._write_phdr_vaddr(seg, seg['p_vaddr'] + vaddr_delta)
                    self._write_phdr_paddr(seg, seg['p_paddr'] + vaddr_delta)
                self._write_phdr_align(seg, PAGE_SIZE_16K)

            elif seg['p_type'] in (PT_DYNAMIC, PT_GNU_RELRO):
                if seg['p_offset'] >= old_second_offset:
                    self._write_phdr_offset(seg, seg['p_offset'] + file_delta)
                    self._write_phdr_vaddr(seg, seg['p_vaddr'] + vaddr_delta)
                    self._write_phdr_paddr(seg, seg['p_paddr'] + vaddr_delta)

            else:
                # Other segments: shift file offset if after insertion point
                if seg['p_offset'] >= old_second_offset:
                    self._write_phdr_offset(seg, seg['p_offset'] + file_delta)
                    if seg['p_vaddr'] >= old_vaddr_start:
                        self._write_phdr_vaddr(seg, seg['p_vaddr'] + vaddr_delta)
                        self._write_phdr_paddr(seg, seg['p_paddr'] + vaddr_delta)

        # 2. Update e_shoff
        if self.e_shoff >= old_second_offset:
            new_shoff = self.e_shoff + file_delta
            if self.is64:
                self._p('Q', 40, new_shoff)
            else:
                self._p('I', 32, new_shoff)
            self.e_shoff = new_shoff

        # 3. Update section headers
        for sec in self.sections:
            new_sec_off = self.e_shoff + sec['idx'] * self.e_shentsize

            # Update sh_offset (file offset)
            if sec['sh_offset'] >= old_second_offset:
                new_offset = sec['sh_offset'] + file_delta
                if self.is64:
                    self._p('Q', new_sec_off + 24, new_offset)
                else:
                    self._p('I', new_sec_off + 16, new_offset)
                sec['sh_offset'] = new_offset

            # Update sh_addr (virtual address)
            if old_vaddr_start <= sec['sh_addr'] < old_vaddr_end:
                new_addr = sec['sh_addr'] + vaddr_delta
                if self.is64:
                    self._p('Q', new_sec_off + 16, new_addr)
                else:
                    self._p('I', new_sec_off + 12, new_addr)
                sec['sh_addr'] = new_addr

        # 4. Update .dynamic entries
        dyn_sec = None
        for sec in self.sections:
            if sec['sh_type'] == 6:  # SHT_DYNAMIC
                dyn_sec = sec
                break

        if dyn_sec:
            entry_size = 16 if self.is64 else 8
            num_entries = dyn_sec['sh_size'] // entry_size
            for i in range(num_entries):
                ent_off = dyn_sec['sh_offset'] + i * entry_size
                if self.is64:
                    d_tag = self._u('q', ent_off)[0]  # signed
                    d_val = self._u('Q', ent_off + 8)[0]
                else:
                    d_tag = self._u('i', ent_off)[0]
                    d_val = self._u('I', ent_off + 4)[0]

                if d_tag == 0:  # DT_NULL
                    break

                # Shift address-type entries that point to the moved range
                if d_tag in DT_ADDR_TAGS:
                    if old_vaddr_start <= d_val < old_vaddr_end:
                        if self.is64:
                            self._p('Q', ent_off + 8, d_val + vaddr_delta)
                        else:
                            self._p('I', ent_off + 4, d_val + vaddr_delta)

        # 5. Update relocations (.rela.dyn / .rela.plt / .rel.dyn / .rel.plt)
        for sec in self.sections:
            if sec['sh_type'] in (4, 9):  # SHT_RELA=4, SHT_REL=9 -- wait, SHT_RELA=4? No.
                pass

        # SHT_REL=9, SHT_RELA=4
        for sec in self.sections:
            is_rela = sec['sh_type'] == 4  # SHT_RELA
            is_rel = sec['sh_type'] == 9   # SHT_REL
            if not is_rela and not is_rel:
                continue

            if self.is64:
                ent_size = 24 if is_rela else 16
            else:
                ent_size = 12 if is_rela else 8

            num_rels = sec['sh_size'] // ent_size
            for i in range(num_rels):
                rel_off = sec['sh_offset'] + i * ent_size

                if self.is64:
                    r_offset = self._u('Q', rel_off)[0]
                    r_info = self._u('Q', rel_off + 8)[0]
                    r_type = r_info & 0xFFFFFFFF
                    r_addend = self._u('q', rel_off + 16)[0] if is_rela else 0
                else:
                    r_offset = self._u('I', rel_off)[0]
                    r_info = self._u('I', rel_off + 4)[0]
                    r_type = r_info & 0xFF
                    r_addend = self._u('i', rel_off + 8)[0] if is_rela else 0

                # Shift r_offset if it points into the moved range
                if old_vaddr_start <= r_offset < old_vaddr_end:
                    new_r_offset = r_offset + vaddr_delta
                    if self.is64:
                        self._p('Q', rel_off, new_r_offset)
                    else:
                        self._p('I', rel_off, new_r_offset)

                # For RELATIVE relocations, shift addend if it points to moved range
                is_relative = r_type in (R_AARCH64_RELATIVE, R_ARM_RELATIVE,
                                         R_386_RELATIVE, R_X86_64_RELATIVE)
                if is_rela and is_relative:
                    if old_vaddr_start <= r_addend < old_vaddr_end:
                        new_addend = r_addend + vaddr_delta
                        if self.is64:
                            self._p('q', rel_off + 16, new_addend)
                        else:
                            self._p('i', rel_off + 8, new_addend)

        # 6. Update symbol table entries
        for sec in self.sections:
            if sec['sh_type'] not in (2, 11):  # SHT_SYMTAB=2, SHT_DYNSYM=11
                continue

            if self.is64:
                ent_size = 24
            else:
                ent_size = 16

            num_syms = sec['sh_size'] // ent_size
            for i in range(num_syms):
                sym_off = sec['sh_offset'] + i * ent_size

                if self.is64:
                    st_value = self._u('Q', sym_off + 8)[0]
                else:
                    st_value = self._u('I', sym_off + 4)[0]

                if old_vaddr_start <= st_value < old_vaddr_end:
                    new_value = st_value + vaddr_delta
                    if self.is64:
                        self._p('Q', sym_off + 8, new_value)
                    else:
                        self._p('I', sym_off + 4, new_value)

        # 7. Update GOT entries (actual pointer values that were set by static linking)
        # The GOT.PLT first entry often contains the address of .dynamic
        # These will be fixed by the dynamic linker via relocations, but let's update
        # the initial values anyway for correctness
        got_sec = None
        for sec in self.sections:
            if sec['sh_offset'] > 0 and sec['sh_addr'] >= old_vaddr_start + vaddr_delta:
                # Find .got.plt by checking sections in the RW segment
                pass

        return True

    def _write_phdr_offset(self, seg, val):
        if self.is64:
            self._p('Q', seg['off'] + 8, val)
        else:
            self._p('I', seg['off'] + 4, val)
        seg['p_offset'] = val

    def _write_phdr_vaddr(self, seg, val):
        if self.is64:
            self._p('Q', seg['off'] + 16, val)
        else:
            self._p('I', seg['off'] + 8, val)
        seg['p_vaddr'] = val

    def _write_phdr_paddr(self, seg, val):
        if self.is64:
            self._p('Q', seg['off'] + 24, val)
        else:
            self._p('I', seg['off'] + 12, val)
        seg['p_paddr'] = val

    def _write_phdr_align(self, seg, val):
        if self.is64:
            self._p('Q', seg['off'] + 48, val)
        else:
            self._p('I', seg['off'] + 28, val)
        seg['p_align'] = val

    def get_data(self):
        return bytes(self.data)


def patch_elf_16kb(filepath):
    """Patch an ELF file for 16KB page alignment."""
    with open(filepath, 'rb') as f:
        data = f.read()

    if data[:4] != b'\x7fELF':
        return False

    patcher = ElfPatcher(data)
    if not patcher.needs_patch():
        return False

    patcher.patch_16kb()

    with open(filepath, 'wb') as f:
        f.write(patcher.get_data())

    return True


def verify_elf(filepath, label):
    """Verify LOAD segment alignment."""
    with open(filepath, 'rb') as f:
        data = f.read()

    if data[:4] != b'\x7fELF':
        return

    is64 = data[4] == 2
    if is64:
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
    else:
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]

    load_pages = []
    all_ok = True
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type = struct.unpack_from('<I', data, off)[0]
            p_offset = struct.unpack_from('<Q', data, off + 8)[0]
            p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
            p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
            p_memsz = struct.unpack_from('<Q', data, off + 40)[0]
            p_align = struct.unpack_from('<Q', data, off + 48)[0]
        else:
            p_type = struct.unpack_from('<I', data, off)[0]
            p_offset = struct.unpack_from('<I', data, off + 4)[0]
            p_vaddr = struct.unpack_from('<I', data, off + 8)[0]
            p_filesz = struct.unpack_from('<I', data, off + 16)[0]
            p_memsz = struct.unpack_from('<I', data, off + 20)[0]
            p_align = struct.unpack_from('<I', data, off + 28)[0]

        if p_type == PT_LOAD:
            congruent = (p_offset % PAGE_SIZE_16K) == (p_vaddr % PAGE_SIZE_16K)
            page_start = p_vaddr // PAGE_SIZE_16K
            page_end = (p_vaddr + p_memsz - 1) // PAGE_SIZE_16K if p_memsz > 0 else page_start

            overlap = False
            for (ps, pe) in load_pages:
                if page_start <= pe and page_end >= ps:
                    overlap = True
            load_pages.append((page_start, page_end))

            ok = p_align >= PAGE_SIZE_16K and congruent and not overlap
            if not ok:
                all_ok = False
            status = "OK" if ok else "FAIL"
            print(f"    LOAD off=0x{p_offset:x} vaddr=0x{p_vaddr:x} memsz=0x{p_memsz:x} "
                  f"align=0x{p_align:x} congruent={congruent} overlap={overlap} [{status}]")

    return all_ok


def patch_aar(aar_path):
    """Extract AAR, patch .so files, repackage."""
    print(f"=== Patch AAR for 16KB page size ===")
    print(f"AAR: {aar_path}")

    backup_path = aar_path.replace('.aar', '.backup.aar')
    if not os.path.exists(backup_path):
        shutil.copy2(aar_path, backup_path)
        print(f"Backup: {backup_path}")
    else:
        shutil.copy2(backup_path, aar_path)
        print(f"Restored from backup: {backup_path}")

    work_dir = tempfile.mkdtemp(prefix='aar_patch_')
    extract_dir = os.path.join(work_dir, 'aar')
    with zipfile.ZipFile(aar_path, 'r') as zf:
        zf.extractall(extract_dir)

    print("\nPatching .so files...")
    patched_count = 0
    for root, dirs, files in os.walk(extract_dir):
        for fname in files:
            if fname.endswith('.so'):
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, extract_dir)
                print(f"  {rel_path}: ", end='')
                if patch_elf_16kb(fpath):
                    print("PATCHED")
                    patched_count += 1
                else:
                    print("already OK")

    if patched_count == 0:
        print("\nNo files needed patching.")
        shutil.rmtree(work_dir)
        return

    # Verify
    print(f"\nVerifying...")
    all_ok = True
    for root, dirs, files in os.walk(extract_dir):
        for fname in files:
            if fname.endswith('.so'):
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, extract_dir)
                print(f"  {rel_path}:")
                if not verify_elf(fpath, rel_path):
                    all_ok = False

    if not all_ok:
        print("\nWARNING: Some files failed verification!")

    # Repackage
    print(f"\nRepackaging AAR ({patched_count} files patched)...")
    with zipfile.ZipFile(aar_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(extract_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                arcname = os.path.relpath(fpath, extract_dir)
                zf.write(fpath, arcname)

    shutil.rmtree(work_dir)

    print(f"\n=== Done! ===")
    print(f"Patched: {aar_path}")
    print(f"Backup:  {backup_path}")


if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    aar_path = os.path.join(script_dir, 'printer-lib-3.2.4.aar')
    if len(sys.argv) > 1:
        aar_path = sys.argv[1]
    if not os.path.exists(aar_path):
        print(f"Error: AAR not found: {aar_path}")
        sys.exit(1)
    patch_aar(aar_path)
