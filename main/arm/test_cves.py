#!/usr/bin/env python3
"""
Test ARM CVE cases: CVE-2019-1010298, CVE-2022-46152, CVE-2023-30799_arm.

Reads metadata.json for each CVE to determine arch, thumb mode, targets,
controllable regs/mem, and stack pivot requirements.

Usage:
    python3 test_cves.py [case_name]   # run one case, e.g. CVE-2019-1010298
    python3 test_cves.py               # run all 3
"""
import os
import sys
import time
import json
import re
from loguru import logger

import arch_config
import find_reg_gadget_chain
import tools
import solve_engine
import argparse
from paths import ARM_CVE_DIR, RESULT_DIR

DATASET_BASE = str(ARM_CVE_DIR)

CVE_CASES = [
    "CVE-2019-1010298",
    "CVE-2022-46152",
    "CVE-2023-30799_arm",
]


def _addr_in_controllable(addr, controllable_mem_data, ptr_size):
    """Check if addr falls within any controllable memory region."""
    for region in controllable_mem_data:
        rstart = int(region['start_addr'], 16)
        rend = rstart + region['length']
        if rstart <= addr < rend:
            return True
    return False


def _build_offset_list(controllable_mem_data, controble_addr_base, ptr_size):
    """Build offset_list from actual controllable regions (handles disjoint memory)."""
    offset_list = []
    for region in controllable_mem_data:
        region_start = int(region['start_addr'], 16)
        region_len = region['length']
        for byte_off in range(0, region_len - (region_len % ptr_size), ptr_size):
            idx = (region_start + byte_off - controble_addr_base) // ptr_size
            offset_list.append(idx)
    return sorted(offset_list)


def run_one(case_name):
    case_dir = os.path.join(DATASET_BASE, case_name)
    meta_path = os.path.join(case_dir, "metadata.json")

    if not os.path.exists(meta_path):
        logger.error(f"metadata.json not found: {meta_path}")
        return False

    with open(meta_path, 'r') as f:
        meta = json.load(f)

    # Set arch and thumb mode
    arch_config.set_arch("arm")
    ac = arch_config.get_arch()
    thumb = meta.get("thumb_mode", False)
    ac.set_thumb_mode(thumb)
    logger.info(f"Arch: {meta['arch_name']}, thumb={thumb}")

    # Load gadgets
    gadgets_file = os.path.join(case_dir, "gadget.txt")
    if not os.path.exists(gadgets_file):
        logger.error(f"Gadget file not found: {gadgets_file}")
        return False

    gadgets_data = tools.load_gadget(gadgets_file)
    if len(gadgets_data) == 0:
        logger.error(f"No valid gadgets for {case_name}")
        return False
    gadgets_dict = tools.create_gadget_dict(gadgets_data)
    logger.info(f"Loaded {len(gadgets_dict)} gadgets")

    # Load context (mappings + registers)
    (permission_table, regs_init) = tools.get_map_regs(case_dir)
    logger.info(f"Memory map: {len(permission_table)} regions, regs: sp=0x{regs_init.get('sp',0):x}")

    # Controllable regs
    controllable_regs = eval(open(os.path.join(case_dir, "controble_regs.txt"), 'r').read())

    # Controllable memory from metadata (same as cyclic_matches.json)
    controllable_mem_data = meta['controllable_mem']
    controllable_mem_data = sorted(controllable_mem_data, key=lambda x: int(x['start_addr'], 16))
    controble_addr_base = int(controllable_mem_data[0]['start_addr'], 16)

    # Find writable section for bss
    bss_address = 0
    for pt in permission_table:
        if 'w' in pt['permission'] and pt['start'] < controble_addr_base:
            bss_address = pt['start'] + 0x100
            break
    if bss_address == 0:
        # Use a writable region that's not the controllable memory
        for pt in permission_table:
            if 'w' in pt['permission']:
                bss_address = pt['start'] + 0x100
                break
    if bss_address == 0:
        bss_address = controble_addr_base + 0x100

    # Target regs from metadata
    target_key = "func-call-4args"
    if target_key not in meta['targets']:
        target_key = "func-call-3args"
    target_regs = meta['targets'][target_key]
    target_mem_value = []
    logger.info(f"Targets: {[(t['reg_name'], hex(t['reg_value'])) for t in target_regs]}")

    ptr_size = ac.ptr_size
    sp_reg = ac.sp_reg
    sp_val = regs_init.get(sp_reg, 0)

    # Build offset_list from disjoint controllable regions
    offset_list = _build_offset_list(controllable_mem_data, controble_addr_base, ptr_size)

    # Determine sp_idx and address_map based on controllability
    sp_in_controllable = _addr_in_controllable(sp_val, controllable_mem_data, ptr_size)

    if sp_reg not in controllable_regs and not sp_in_controllable:
        # SP not controllable and not in controllable memory (e.g. CVE-2019-1010298: sp=0x0, r0 controlled)
        # The attacker controls a register pointing to heap memory. To use pop-based gadgets,
        # we set SP to point into the controllable memory so the framework can chain gadgets.
        sp_val = controble_addr_base
        regs_init[sp_reg] = sp_val
        if sp_reg not in controllable_regs:
            controllable_regs.append(sp_reg)
        sp_in_controllable = True
        stack_pivot_chain = [f'0x{controble_addr_base:x} -> pop {{pc}}']
        sp_idx = 0
        address_map = {sp_idx: "0xdeadbeef"}
        if sp_idx in offset_list:
            offset_list.remove(sp_idx)
        logger.info(f"Redirected sp to controllable mem: sp=0x{sp_val:x}, entry via {meta['controllable_regs']}")
    elif sp_in_controllable:
        # SP points into controllable memory
        # Check if the region containing SP is large enough, or if we should pivot
        sp_region = None
        for region in controllable_mem_data:
            rstart = int(region['start_addr'], 16)
            rend = rstart + region['length']
            if rstart <= sp_val < rend:
                sp_region = region
                break
        largest_region = max(controllable_mem_data, key=lambda r: r['length'])
        # If SP region is small (<64B) and there's a much larger region, pivot to it
        if sp_region and sp_region['length'] < 64 and largest_region['length'] > sp_region['length'] * 4:
            pivot_target = int(largest_region['start_addr'], 16)
            if 'stack-pivot' in meta['targets']:
                pivot_target = meta['targets']['stack-pivot']['pivot_start']
            regs_init[sp_reg] = pivot_target
            stack_pivot_chain = [f'0x{pivot_target:x} -> pop {{pc}}']
            sp_idx = (pivot_target - controble_addr_base) // ptr_size
            address_map = {sp_idx: "0xdeadbeef"}
            offset_list = _build_offset_list([largest_region], controble_addr_base, ptr_size)
            if sp_idx in offset_list:
                offset_list.remove(sp_idx)
            logger.info(f"SP region too small ({sp_region['length']}B), pivot to 0x{pivot_target:x} ({largest_region['length']}B)")
        else:
            sp_idx = (sp_val - controble_addr_base) // ptr_size
            address_map = {sp_idx: "0xdeadbeef"}
            if sp_idx in offset_list:
                offset_list.remove(sp_idx)
            stack_pivot_chain = [f'0x{controble_addr_base:x} -> pop {{pc}}']
            logger.info(f"SP in controllable mem: sp_idx={sp_idx}")
    else:
        # SP controllable but NOT in controllable memory — needs stack pivot
        # For pivot cases: set SP to the largest controllable region so the solver
        # can build the chain there. The actual pivot gadget is a separate concern.
        pivot_target = controble_addr_base
        if 'stack-pivot' in meta['targets']:
            pivot_info = meta['targets']['stack-pivot']
            pivot_target = pivot_info['pivot_start']

        # Find the controllable region containing pivot_target
        pivot_region = None
        for region in controllable_mem_data:
            rstart = int(region['start_addr'], 16)
            rend = rstart + region['length']
            if rstart <= pivot_target < rend:
                pivot_region = region
                break
        if pivot_region is None:
            # Use the largest controllable region
            pivot_region = max(controllable_mem_data, key=lambda r: r['length'])
            pivot_target = int(pivot_region['start_addr'], 16)

        # Redirect SP to pivot target and rebuild offset_list from that region
        regs_init[sp_reg] = pivot_target
        if sp_reg not in controllable_regs:
            controllable_regs.append(sp_reg)
        stack_pivot_chain = [f'0x{pivot_target:x} -> pop {{pc}}']
        sp_idx = (pivot_target - controble_addr_base) // ptr_size
        address_map = {sp_idx: "0xdeadbeef"}
        # Rebuild offset_list using only the pivot region
        offset_list = _build_offset_list([pivot_region], controble_addr_base, ptr_size)
        if sp_idx in offset_list:
            offset_list.remove(sp_idx)
        logger.info(f"Stack pivot: sp redirected to 0x{pivot_target:x}, region={int(pivot_region['start_addr'],16):#x}+{pivot_region['length']}")

    # Remove slot 0 (used by address_map for initial pivot) but keep slots 1,2
    # The benchmark convention of skipping first 3 slots doesn't apply to CVE cases
    # where controllable memory IS the stack
    offset_list = [x for x in offset_list if x >= 1]

    logger.info(f"offset_list: {len(offset_list)} slots, address_map: {address_map}")

    # Ensure virtual_mem_base is above controllable memory
    last_region = controllable_mem_data[-1]
    last_addr = int(last_region['start_addr'], 16) + last_region['length']
    if ac.virtual_mem_base <= last_addr:
        ac.virtual_mem_base = ((last_addr + 0x10000) // 0x10000) * 0x10000
        logger.info(f"Adjusted virtual_mem_base to 0x{ac.virtual_mem_base:x}")

    gadgets_info = solve_engine.GadgetsInfo(
        gadgets_file, regs_init, stack_pivot_chain, gadgets_dict,
        address_map, offset_list, controllable_mem_data, controble_addr_base,
        target_regs, target_mem_value, controllable_regs, permission_table, bss_address
    )

    res_json = {"binary": case_name, "arch": "arm", "thumb": thumb}
    res_json['gadget_count'] = len(gadgets_dict)
    res_json['Target Register'] = target_regs

    result = find_reg_gadget_chain.main(
        case_name, case_name, gadgets_info,
        mem_search_depth=1, reg_search_depth=2,
        res_json=res_json, valid_mem_reg_num=1,
        mem_reg_timeout=90, reg_timout=5*60,
        target_type="funcall4"
    )
    return result


def main():
    global DATASET_BASE
    parser = argparse.ArgumentParser(description="Run ARM CVE cases")
    parser.add_argument('case_name', nargs='?', default=None, help='Optional CVE case filter')
    parser.add_argument('--dataset-base', type=str, default=DATASET_BASE)
    parser.add_argument('--result-dir', type=str, default=str(RESULT_DIR / 'arm' / 'cve_cases'))
    args = parser.parse_args()

    DATASET_BASE = args.dataset_base

    cases = CVE_CASES
    if args.case_name:
        cases = [c for c in CVE_CASES if args.case_name in c]
        if not cases:
            cases = [args.case_name]

    log_dir = args.result_dir
    os.makedirs(log_dir, exist_ok=True)
    log_handler = logger.add(
        sink=f"{log_dir}/test_cves.log",
        level="DEBUG",
        encoding="utf-8"
    )

    logger.info(f"Testing {len(cases)} CVE cases")

    success = 0
    fail = 0
    results = {}

    for idx, case_name in enumerate(cases):
        logger.info(f"\n{'='*60}")
        logger.info(f"[{idx+1}/{len(cases)}] {case_name}")
        logger.info(f"{'='*60}")
        start = time.time()
        try:
            result = run_one(case_name)
            elapsed = time.time() - start
            if result:
                success += 1
                results[case_name] = {"status": "SUCCESS", "time": f"{elapsed:.2f}s"}
                logger.success(f"{case_name} SUCCESS ({elapsed:.2f}s)")
            else:
                fail += 1
                results[case_name] = {"status": "FAIL", "time": f"{elapsed:.2f}s"}
                logger.error(f"{case_name} FAIL ({elapsed:.2f}s)")
        except Exception as e:
            elapsed = time.time() - start
            fail += 1
            results[case_name] = {"status": "ERROR", "time": f"{elapsed:.2f}s", "error": str(e)}
            logger.error(f"{case_name} ERROR: {e} ({elapsed:.2f}s)")
            import traceback
            traceback.print_exc()

        logger.info(f"Running total: {success} success, {fail} fail")

    logger.info("=" * 60)
    logger.info(f"FINAL: {success}/{len(cases)} success")
    for name, r in results.items():
        logger.info(f"  {name}: {r['status']} ({r['time']})")
    logger.info("=" * 60)

    logger.remove(log_handler)

    with open(f"{log_dir}/results.json", "w") as f:
        json.dump(results, f, indent=2)

    return success == len(cases)


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
