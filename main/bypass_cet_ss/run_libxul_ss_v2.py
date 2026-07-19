#!/usr/bin/env python3
"""
Runner: CET-SS bypass for libxul_ss dataset.
Mode 1 (single): find COP chain that sets rdi = 0xdeadbeef
Mode 2 (multi):  find COP chain that sets rdi = 0xdeadbeef AND rsi = 0xcafebabe
"""
import sys, os, json, argparse, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tools
from bypass_cet_ss_v2 import solve_bypass_cet_ss, solve_bypass_cet_ss_multi, solve_bypass_cet_ss_sequential
from paths import CFI_DIR

DEFAULT_DATASET_DIR = str(CFI_DIR / 'libxul_ss')


def main():
    parser = argparse.ArgumentParser(description='Run CET-SS libxul demo (v2)')
    parser.add_argument('--dataset-dir', type=str, default=DEFAULT_DATASET_DIR)
    parser.add_argument('--gadget-file', type=str, default=None)
    parser.add_argument('--threads', type=int, default=8)
    args = parser.parse_args()

    dataset_dir = args.dataset_dir
    gadget_file = args.gadget_file or os.path.join(dataset_dir, 'gadget_cet_ss_focus.txt')
    cyclic_file = os.path.join(dataset_dir, 'cyclic_matches.json')

    t_load_start = time.time()
    gadgets = tools.load_gadget(gadget_file)
    gadgets_dict = tools.create_gadget_dict(gadgets)
    gadget_load_time = time.time() - t_load_start
    print(f"Loaded {len(gadgets_dict)} gadgets from {gadget_file}")
    print(f"[TIMING] Gadget Load Time: {gadget_load_time:.2f}s")

    regs_init = tools.parse_registers(dataset_dir)
    permission_table = tools.parse_memory_map(dataset_dir)
    print(f"Registers: rax={hex(regs_init['rax'])}, rsp={hex(regs_init['rsp'])}")
    print(f"Memory regions: {len(permission_table)}")

    with open(cyclic_file) as f:
        cyclic = json.load(f)
    controble_addr_base = int(cyclic[0]['start_addr'], 16)
    controble_length = cyclic[0]['length']
    offset_list = list(range(controble_length // 8))
    print(f"Controllable base: {hex(controble_addr_base)}, slots: {len(offset_list)}")

    controllable_reg = ['rax', 'rsp', 'rdi']

    print("\n" + "=" * 60)
    print("MODE 3: Call target  0xdeadbeef(0x400040, 0x1000, 7)")
    print("        rdi=0x400040, rsi=0x1000, rdx=7")
    print("=" * 60)
    target_regs_call = [
        {'reg_name': 'rdi', 'reg_value': 0x400040},
        {'reg_name': 'rsi', 'reg_value': 0x1000},
        {'reg_name': 'rdx', 'reg_value': 7},
    ]

    t_solve_start = time.time()
    results_call = solve_bypass_cet_ss_sequential(
        gadgets_dict, controllable_reg, target_regs_call, regs_init,
        controble_addr_base, offset_list, permission_table,
        num_threads=args.threads
    )
    solve_time = time.time() - t_solve_start

    if results_call:
        print(f"\nCALL-TARGET SUCCESS: {len(results_call)} solution(s) found")
    else:
        print("\nCALL-TARGET FAILED: no solution found")

    print(f"\n[TIMING] Gadget Load Time: {gadget_load_time:.2f}s")
    print(f"[TIMING] Solve Time: {solve_time:.2f}s")
    print(f"[TIMING] Total Time: {gadget_load_time + solve_time:.2f}s")


if __name__ == "__main__":
    main()
