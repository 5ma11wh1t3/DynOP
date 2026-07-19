#!/usr/bin/env python3
"""
Parallel benchmark runner for DynOP ARM/MIPS.
Uses multiprocessing Pool to run multiple binaries concurrently.

Usage:
    python3 run_parallel.py --arch arm --dataset benchmark_data/arm --target funcall4 --max_binaries 1000 --workers 32
"""
import argparse
import os
import sys
import time
import json
import multiprocessing
import multiprocessing.pool
from loguru import logger
from paths import ARM_DATASET_DIR, RESULT_DIR


class NoDaemonProcess(multiprocessing.Process):
    """Process subclass that is NOT daemonic, allowing it to spawn children."""
    @property
    def daemon(self):
        return False
    @daemon.setter
    def daemon(self, value):
        pass


class NoDaemonContext(type(multiprocessing.get_context())):
    Process = NoDaemonProcess


class NoDaemonPool(multiprocessing.pool.Pool):
    """Pool that uses non-daemon processes, so workers can spawn sub-processes."""
    def __init__(self, *args, **kwargs):
        kwargs['context'] = NoDaemonContext()
        super().__init__(*args, **kwargs)


def run_one_binary(task):
    """Run ROP chain generation on a single binary. Called in worker process."""
    binary_name, gadgets_file, ctx_dir, arch_name, target_type = task
    import arch_config
    import find_reg_gadget_chain
    import tools
    import solve_engine

    arch_config.set_arch(arch_name)
    ac = arch_config.get_arch()

    res_json = {"binary": binary_name, "arch": arch_name}
    start_time = time.time()

    try:
        # Load gadgets
        gadgets_data = tools.load_gadget(gadgets_file)
        if len(gadgets_data) == 0:
            return {"binary": binary_name, "status": "SKIP_NO_GADGETS", "All Time": 0}
        gadgets_dict = tools.create_gadget_dict(gadgets_data)

        if len(gadgets_dict) < 200:
            return {"binary": binary_name, "status": "SKIP_FEW_GADGETS",
                    "gadget_count": len(gadgets_dict), "All Time": 0}

        # Load context
        with open(os.path.join(ctx_dir, "cyclic_matches.json"), "r") as f:
            controllable_mem_data = json.load(f)
        controllable_mem_data = sorted(controllable_mem_data, key=lambda x: int(x['start_addr'], 16))
        controble_addr_base = int(controllable_mem_data[0]['start_addr'], 16)

        (permission_table, regs_init) = tools.get_map_regs(ctx_dir)
        controllable_regs = eval(open(os.path.join(ctx_dir, "controble_regs.txt"), 'r').read())

        # Find writable section for bss
        bss_address = 0
        for pt in permission_table:
            if 'w' in pt['permission'] and pt['start'] < controble_addr_base:
                bss_address = pt['start'] + 0x100
                break
        if bss_address == 0:
            bss_address = controble_addr_base - 0x100

        # Setup target registers
        if target_type == "execve":
            target_regs = ac.execve_target_regs(bss_address)
            if ac.bits == 64:
                target_mem_value = [{bss_address + 0x300: b"/bin/sh\x00"}]
            else:
                target_mem_value = [{bss_address + 0x100: b"/bin/sh\x00"}]
        else:
            target_regs = ac.funcall4_target_regs(bss_address)
            target_mem_value = []

        bss_address += 0x308 if ac.bits == 64 else 0x108

        # Setup stack pivot chain
        if ac.arch_name in ('arm', 'armel', 'arm32'):
            stack_pivot_chain = ['0x10000 -> pop {pc}']
        elif ac.arch_name in ('mips', 'mipsel', 'mips32'):
            stack_pivot_chain = ['0x10000 -> jr $ra']
        else:
            stack_pivot_chain = ['0x10000 -> ret']

        offset_list = [_ for _ in range(500)]
        sp_reg = ac.sp_reg
        if sp_reg in regs_init:
            sp_idx = (regs_init[sp_reg] - controble_addr_base) // ac.ptr_size
        else:
            sp_idx = 3
        offset_list = [x for x in offset_list if x >= 3]
        address_map = {sp_idx: "0xdeadbeef"}
        if sp_idx in offset_list:
            offset_list.remove(sp_idx)

        gadgets_info = solve_engine.GadgetsInfo(
            gadgets_file, regs_init, stack_pivot_chain, gadgets_dict,
            address_map, offset_list, controllable_mem_data, controble_addr_base,
            target_regs, target_mem_value, controllable_regs, permission_table, bss_address
        )

        res_json['gadget_count'] = len(gadgets_dict)
        res_json['Target Register'] = target_regs

        # Run ROP chain generation
        result = find_reg_gadget_chain.main(
            binary_name, binary_name, gadgets_info,
            mem_search_depth=1, reg_search_depth=2,
            res_json=res_json, valid_mem_reg_num=1,
            mem_reg_timeout=90, reg_timout=10*60,
            target_type=target_type
        )

        elapsed = time.time() - start_time
        res_json['All Time'] = elapsed

        if result:
            res_json['status'] = 'SUCCESS'
        else:
            res_json['status'] = 'FAIL'

    except Exception as e:
        elapsed = time.time() - start_time
        res_json['status'] = 'ERROR'
        res_json['error'] = str(e)
        res_json['All Time'] = elapsed

    return res_json


def main():
    parser = argparse.ArgumentParser(description="DynOP Parallel Benchmark Runner")
    parser.add_argument("--arch", required=True, choices=["x86_64", "arm", "armel", "mips", "mipsel"])
    parser.add_argument("--target", default="funcall4", choices=["execve", "funcall4"])
    parser.add_argument("--dataset", default=str(ARM_DATASET_DIR), type=str)
    parser.add_argument("--gadget_dir", type=str, default=None)
    parser.add_argument("--context_dir", type=str, default=None)
    parser.add_argument("--max_binaries", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--binary", type=str, default=None, help="Only run one binary name")
    parser.add_argument("--result-dir", type=str, default=str(RESULT_DIR))
    parser.add_argument("--skip_done", action="store_true", help="Skip binaries already in results.json")
    args = parser.parse_args()

    dataset_base = args.dataset
    gadget_dir = os.path.join(dataset_base, "gadgets") if args.gadget_dir is None else args.gadget_dir
    context_dir = os.path.join(dataset_base, "context_info") if args.context_dir is None else args.context_dir

    if not os.path.isdir(gadget_dir):
        print(f"Gadget directory not found: {gadget_dir}")
        return

    log_dir = os.path.join(args.result_dir, args.arch, args.target)
    os.makedirs(log_dir, exist_ok=True)

    # Load existing results if skip_done
    existing = {}
    results_file = f"{log_dir}/results.json"
    if args.skip_done and os.path.exists(results_file):
        with open(results_file) as f:
            existing = json.load(f)
        print(f"Loaded {len(existing)} existing results, skipping those")

    gadget_files = sorted([f for f in os.listdir(gadget_dir) if f.endswith('.txt')])
    total = min(len(gadget_files), args.max_binaries)

    # Build task list
    tasks = []
    skipped = 0
    for gf in gadget_files[:total]:
        binary_name = gf.replace('.txt', '')
        if args.binary and binary_name != args.binary:
            continue
        ctx_dir_path = os.path.join(context_dir, binary_name)
        if not os.path.isdir(ctx_dir_path):
            continue
        if binary_name in existing:
            skipped += 1
            continue
        gadgets_file = os.path.join(gadget_dir, gf)
        tasks.append((binary_name, gadgets_file, ctx_dir_path, args.arch, args.target))

    print(f"Architecture: {args.arch}")
    print(f"Target: {args.target}")
    print(f"Total binaries: {total}, tasks to run: {len(tasks)}, skipped (done): {skipped}")
    print(f"Workers: {args.workers}")
    print(f"Starting at {time.strftime('%Y-%m-%d %H:%M:%S')}")

    all_results = dict(existing)
    success = sum(1 for v in existing.values() if v.get('status') == 'SUCCESS')
    fail = sum(1 for v in existing.values() if v.get('status') in ('FAIL', 'ERROR'))
    done = 0
    start_all = time.time()

    with NoDaemonPool(processes=args.workers) as pool:
        for res_json in pool.imap_unordered(run_one_binary, tasks):
            done += 1
            bn = res_json.get('binary', '?')
            status = res_json.get('status', '?')
            elapsed = res_json.get('All Time', 0)

            if status == 'SUCCESS':
                success += 1
                print(f"[{done}/{len(tasks)}] {bn} SUCCESS ({elapsed:.1f}s) | Total: S={success} F={fail}")
            elif status in ('SKIP_FEW_GADGETS', 'SKIP_NO_GADGETS'):
                print(f"[{done}/{len(tasks)}] {bn} {status}")
            else:
                fail += 1
                print(f"[{done}/{len(tasks)}] {bn} {status} ({elapsed:.1f}s) | Total: S={success} F={fail}")

            all_results[bn] = res_json

            # Save every 20 completions
            if done % 20 == 0:
                with open(results_file, "w") as f:
                    json.dump(all_results, f, indent=2)

    total_time = time.time() - start_all
    print(f"\n{'='*60}")
    print(f"FINAL: Success={success} Fail={fail} Total={success+fail}")
    print(f"Total time: {total_time:.1f}s ({total_time/60:.1f}min)")
    print(f"{'='*60}")

    with open(results_file, "w") as f:
        json.dump(all_results, f, indent=2)


if __name__ == "__main__":
    main()
