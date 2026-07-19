"""
Architecture configuration module for DynOP multi-arch support.
Provides unified abstraction for x86_64, ARM (armel), and MIPS (mipsel).
"""
from triton import ARCH
from keystone import (
    KS_ARCH_X86, KS_MODE_64,
    KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_LITTLE_ENDIAN,
    KS_ARCH_MIPS, KS_MODE_MIPS32,
)

# ============================================================
# Register definitions per architecture
# ============================================================

X86_64_GENERAL_PURPOSE = [
    "rax", "eax", "ax", "al",
    "rbx", "ebx", "bx", "bl",
    "rcx", "ecx", "cx", "cl",
    "rdx", "edx", "dx", "dl",
    "rsi", "esi", "si", "sil",
    "rdi", "edi", "di", "dil",
    "rbp", "ebp", "bp", "bpl",
    "rsp", "esp", "sp", "spl",
    "r8", "r8d", "r8w", "r8b",
    "r9", "r9d", "r9w", "r9b",
    "r10", "r10d", "r10w", "r10b",
    "r11", "r11d", "r11w", "r11b",
    "r12", "r12d", "r12w", "r12b",
    "r13", "r13d", "r13w", "r13b",
    "r14", "r14d", "r14w", "r14b",
    "r15", "r15d", "r15w", "r15b",
    "ah", "bh", "ch", "dh",
]

ARM_GENERAL_PURPOSE = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
]

MIPS_GENERAL_PURPOSE = [
    "$zero", "$at", "$v0", "$v1",
    "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
]

# Triton uses numeric register names for MIPS
MIPS_TRITON_REGS = [f"$r{i}" for i in range(32)] + ["$pc", "$hi", "$lo"]

# ============================================================
# Architecture config class
# ============================================================

class ArchConfig:
    """Encapsulates all architecture-specific parameters."""

    def __init__(self, arch_name):
        self.arch_name = arch_name.lower()
        if self.arch_name in ("x86_64", "amd64", "x86-64"):
            self._init_x86_64()
        elif self.arch_name in ("arm", "armel", "arm32"):
            self._init_arm()
        elif self.arch_name in ("mips", "mipsel", "mips32"):
            self._init_mips()
        else:
            raise ValueError(f"Unsupported architecture: {arch_name}")

    # ---- x86_64 ----
    def _init_x86_64(self):
        self.triton_arch = ARCH.X86_64
        self.triton_supported = True
        self.ks_arch = KS_ARCH_X86
        self.ks_mode = KS_MODE_64
        self.pwn_arch = "amd64"
        self.bits = 64
        self.ptr_size = 8  # bytes
        self.addr_mask = 0xffffffffffffffff
        self.sp_reg = "rsp"
        self.pc_reg = "rip"
        self.bp_reg = "rbp"
        self.lr_reg = None  # x86 uses stack-based return
        self.ret_inst = "ret"
        self.general_purpose = X86_64_GENERAL_PURPOSE
        self.regs_change_log_keys = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags"
        ]
        self.skip_regs = ['fs_base', 'gs_base']
        # syscall: execve
        self.execve_syscall_nr = 59
        self.execve_target_regs = lambda bss: [
            {'reg_name': 'rdi', 'reg_value': bss + 0x300},
            {'reg_name': 'rsi', 'reg_value': 0},
            {'reg_name': 'rdx', 'reg_value': 0},
            {'reg_name': 'rax', 'reg_value': 59},
        ]
        self.funcall4_target_regs = lambda bss: [
            {'reg_name': 'rdi', 'reg_value': bss + 0x300},
            {'reg_name': 'rsi', 'reg_value': 0x1000},
            {'reg_name': 'rdx', 'reg_value': 7},
            {'reg_name': 'rcx', 'reg_value': 10},
        ]
        self.gadget_tail_insts = ["ret", "retf"]
        self.control_flow_insts = ["call", "jmp"]
        self.pop_inst = "pop"
        self.push_inst = "push"
        self.leave_inst = "leave"
        self.virtual_mem_base = 0x8ffffff00000
        self.virtual_mem_size = 0x10000
        self.addr_format_width = 16  # hex digits for address formatting

    # ---- ARM (32-bit, little-endian) ----
    def _init_arm(self):
        self.triton_arch = ARCH.ARM32
        self.triton_supported = True
        self.ks_arch = KS_ARCH_ARM
        self.ks_mode = KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN
        self.pwn_arch = "arm"
        self.bits = 32
        self.ptr_size = 4  # bytes
        self.addr_mask = 0xffffffff
        self.sp_reg = "sp"
        self.pc_reg = "pc"
        self.bp_reg = "r11"  # frame pointer on ARM
        self.lr_reg = "lr"
        self.ret_inst = "pop {pc}"  # ARM uses pop {pc} or bx lr
        self.general_purpose = ARM_GENERAL_PURPOSE
        self.regs_change_log_keys = [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"
        ]
        self.skip_regs = []
        self.execve_syscall_nr = 11  # ARM Linux execve
        self.execve_target_regs = lambda bss: [
            {'reg_name': 'r0', 'reg_value': bss + 0x100},
            {'reg_name': 'r1', 'reg_value': 0},
            {'reg_name': 'r2', 'reg_value': 0},
            {'reg_name': 'r7', 'reg_value': 11},
        ]
        self.funcall4_target_regs = lambda bss: [
            {'reg_name': 'r0', 'reg_value': 0xfacefeed},
            {'reg_name': 'r1', 'reg_value': 0xdeadbeef},
            {'reg_name': 'r2', 'reg_value': 0x40},
            {'reg_name': 'r3', 'reg_value': 0x7b},
        ]
        self.gadget_tail_insts = ["pop {pc}", "bx lr"]
        self.control_flow_insts = ["bl", "blx", "bx", "b"]
        self.pop_inst = "pop"
        self.push_inst = "push"
        self.leave_inst = None  # ARM has no leave
        self.virtual_mem_base = 0x7fff0000
        self.virtual_mem_size = 0x10000
        self.addr_format_width = 8
        self.thumb_mode = False

    def set_thumb_mode(self, enabled):
        """Toggle Thumb mode for ARM. Adjusts Keystone mode accordingly."""
        if self.arch_name not in ('arm', 'armel', 'arm32'):
            return
        self.thumb_mode = enabled
        if enabled:
            self.ks_mode = KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN
        else:
            self.ks_mode = KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN

    # ---- MIPS (32-bit, little-endian) ----
    def _init_mips(self):
        # Triton does not support MIPS; set to None and handle in code
        self.triton_arch = None
        self.triton_supported = False
        self.ks_arch = KS_ARCH_MIPS
        self.ks_mode = KS_MODE_MIPS32 | KS_MODE_LITTLE_ENDIAN
        self.pwn_arch = "mips"
        self.bits = 32
        self.ptr_size = 4  # bytes
        self.addr_mask = 0xffffffff
        self.sp_reg = "$sp"
        self.pc_reg = "$pc"
        self.bp_reg = "$fp"
        self.lr_reg = "$ra"
        self.ret_inst = "jr $ra"
        self.general_purpose = MIPS_GENERAL_PURPOSE
        self.regs_change_log_keys = [
            "$zero", "$at", "$v0", "$v1",
            "$a0", "$a1", "$a2", "$a3",
            "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
            "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
            "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
        ]
        self.skip_regs = []
        self.execve_syscall_nr = 4011  # MIPS Linux execve
        self.execve_target_regs = lambda bss: [
            {'reg_name': '$a0', 'reg_value': bss + 0x100},
            {'reg_name': '$a1', 'reg_value': 0},
            {'reg_name': '$a2', 'reg_value': 0},
            {'reg_name': '$v0', 'reg_value': 4011},
        ]
        self.funcall4_target_regs = lambda bss: [
            {'reg_name': '$a0', 'reg_value': bss + 0x100},
            {'reg_name': '$a1', 'reg_value': 0x1000},
            {'reg_name': '$a2', 'reg_value': 7},
            {'reg_name': '$a3', 'reg_value': 10},
        ]
        self.gadget_tail_insts = ["jr $ra"]
        self.control_flow_insts = ["jal", "jalr", "jr", "j"]
        self.pop_inst = "lw"  # MIPS uses lw from stack
        self.push_inst = "sw"
        self.leave_inst = None
        self.virtual_mem_base = 0x7fff0000
        self.virtual_mem_size = 0x10000
        self.addr_format_width = 8

    # ---- Utility methods ----
    def p(self, value):
        """Pack a pointer-sized value."""
        from pwn import p32, p64
        if self.ptr_size == 8:
            return p64(value & self.addr_mask)
        else:
            return p32(value & self.addr_mask)

    def addr_hex(self, addr):
        """Format address as 0x-prefixed hex string with proper width."""
        return "0x" + hex(addr & self.addr_mask)[2:].zfill(self.addr_format_width)

    def is_gadget_tail(self, inst_str):
        """Check if instruction is a gadget tail (ret/pop{pc}/bx lr/jr $ra)."""
        inst_str = inst_str.strip()
        for tail in self.gadget_tail_insts:
            if tail in inst_str:
                return True
        return False

    def is_control_flow(self, inst_str):
        """Check if instruction is a control flow transfer."""
        op = inst_str.strip().split()[0]
        return op in self.control_flow_insts

    def get_cpusize(self):
        """Return Triton CPUSIZE for pointer."""
        from triton import CPUSIZE
        if self.ptr_size == 8:
            return CPUSIZE.QWORD
        else:
            return CPUSIZE.DWORD


# Global singleton (set by entry point)
_current_arch = None

def set_arch(arch_name):
    global _current_arch
    _current_arch = ArchConfig(arch_name)
    return _current_arch

def get_arch():
    global _current_arch
    if _current_arch is None:
        _current_arch = ArchConfig("x86_64")  # default
    return _current_arch
