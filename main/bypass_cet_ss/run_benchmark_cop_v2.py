#!/usr/bin/env python3
"""
Benchmark: CET-SS COP bypass across all benchmark binaries.
Target: 0xdeadbeef(0x400040, 0x1000, 7, 10)
Uses each binary's own registers/memory/cyclic, only swaps gadget file.
"""
import sys, os, json, time, argparse
import multiprocessing as mp
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tools
from bypass_cet_ss_v2 import solve_bypass_cet_ss_sequential, filter_no_ret_gadgets
from paths import BENCHMARK_CONTEXT_DIR, BENCHMARK_GADGET_DIR, RESULTS_DIR

BENCHMARK_INFO = str(BENCHMARK_CONTEXT_DIR)
BENCHMARK_GADGET = str(BENCHMARK_GADGET_DIR)

TARGET_REGS = [
    {'reg_name': 'rdi', 'reg_value': 0x400040},
    {'reg_name': 'rsi', 'reg_value': 0x1000},
    {'reg_name': 'rdx', 'reg_value': 7},
    {'reg_name': 'rcx', 'reg_value': 10},
]

TIMEOUT = 120  # seconds per binary


def format_target_regs(target_regs):
    return [f"{t['reg_name']}={hex(t['reg_value'])}" for t in target_regs]


def _solve_worker(gadgets_dict, controllable_reg, target_regs, regs_init,
                  controble_addr_base, offset_list, permission_table,
                  num_threads, result_queue):
    """Worker process for solving with timeout."""
    try:
        solve_out = solve_bypass_cet_ss_sequential(
            gadgets_dict, controllable_reg, target_regs, regs_init,
            controble_addr_base, offset_list, permission_table,
            num_threads=num_threads, return_metadata=True
        )
        results = solve_out["results"]
        solver_meta = solve_out["meta"]
        if results:
            result_queue.put({
                "status": "success",
                "chain_length": len(results[0]['gadget_chain']),
                "chain": list(results[0]['gadget_chain']),
                "memory_layout": {str(k): v for k, v in results[0]['address_map'].items()},
                "solvable_prefixes": solver_meta["solvable_prefixes"],
                "failed_prefixes": solver_meta["failed_prefixes"],
                "attempted_orderings": solver_meta["attempted_orderings"],
                "skipped_orderings": solver_meta["skipped_orderings"],
                "pruned_orderings": solver_meta["pruned_orderings"],
            })
        else:
            result_queue.put({
                "status": "fail",
                "solvable_prefixes": solver_meta["solvable_prefixes"],
                "failed_prefixes": solver_meta["failed_prefixes"],
                "attempted_orderings": solver_meta["attempted_orderings"],
                "skipped_orderings": solver_meta["skipped_orderings"],
                "pruned_orderings": solver_meta["pruned_orderings"],
            })
    except Exception as e:
        result_queue.put({"status": "error", "error": str(e)})


def run_one_binary(system, binary_name, gadget_file, info_dir, num_threads=2, timeout=TIMEOUT):
    """Run COP solver on a single binary with timeout. Returns result dict."""
    res = {
        "system": system,
        "binary": binary_name,
        "solvable_prefixes": [],
        "failed_prefixes": [],
        "attempted_orderings": 0,
        "skipped_orderings": 0,
        "pruned_orderings": [],
    }

    try:
        gadgets = tools.load_gadget(gadget_file)
        gadgets_dict = tools.create_gadget_dict(gadgets)
    except Exception as e:
        res["status"] = "error"
        res["error"] = f"load_gadget: {e}"
        return res

    no_ret_dict = filter_no_ret_gadgets(gadgets_dict)
    res["total_gadgets"] = len(gadgets_dict)
    res["no_ret_gadgets"] = len(no_ret_dict)

    if len(no_ret_dict) == 0:
        res["status"] = "no_gadgets"
        return res

    try:
        regs_init = tools.parse_registers(info_dir)
        permission_table = tools.parse_memory_map(info_dir)
        cyclic_file = os.path.join(info_dir, "cyclic_matches.json")
        with open(cyclic_file) as f:
            cyclic = json.load(f)
        controble_addr_base = int(cyclic[0]['start_addr'], 16)
        controble_length = cyclic[0]['length']
        offset_list = list(range(controble_length // 8))
    except Exception as e:
        res["status"] = "error"
        res["error"] = f"load_info: {e}"
        return res

    ctrl_reg_file = os.path.join(info_dir, "controble_regs.txt")
    try:
        with open(ctrl_reg_file) as f:
            controllable_reg = eval(f.read().strip())
    except Exception:
        controllable_reg = ['rsp']

    res["controllable_reg"] = controllable_reg
    res["controble_addr_base"] = hex(controble_addr_base)
    res["controble_slots"] = len(offset_list)

    start_time = time.time()
    result_queue = mp.Queue()
    proc = mp.Process(target=_solve_worker, args=(
        gadgets_dict, controllable_reg, TARGET_REGS, regs_init,
        controble_addr_base, offset_list, permission_table,
        num_threads, result_queue))
    proc.start()
    proc.join(timeout=timeout)

    elapsed = time.time() - start_time
    res["time"] = elapsed

    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
            proc.join()
        res["status"] = "timeout"
        return res

    if not result_queue.empty():
        sol = result_queue.get_nowait()
        res.update(sol)
    else:
        res["status"] = "error"
        res["error"] = "no result from worker"

    return res


BENCHMARK_SYSTEMS = [
    "centos-7.1810",
    "debian-10-cloud",
    "openbsd-62",
    "openbsd-64",
    "openbsd-65",
    "gcc_fzero",
    "openbsd-73",
]


def main():
    parser = argparse.ArgumentParser(description='COP benchmark across all binaries (v2)')
    parser.add_argument('--threads', type=int, default=8, help='Threads per solve (default 8)')
    parser.add_argument('--timeout', type=int, default=300, help='Timeout per binary in seconds (default 300)')
    parser.add_argument('--system', type=str, default=None, help='Only run specific system folder')
    parser.add_argument('--binary', type=str, default=None, help='Only run one binary name (without .bin)')
    parser.add_argument('--info-dir', type=str, default=BENCHMARK_INFO, help='Benchmark context directory root')
    parser.add_argument('--gadget-dir', type=str, default=BENCHMARK_GADGET, help='Benchmark gadget directory root')
    parser.add_argument('--output', type=str, default=str(RESULTS_DIR / 'cop_benchmark_v2'), help='Output directory')
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    log_file = os.path.join(args.output, "run.log")
    logger.add(sink=log_file, level="INFO", encoding="utf-8")

    if args.system:
        systems = [args.system]
    else:
        systems = BENCHMARK_SYSTEMS

    all_results = []
    total_success = 0
    total_fail = 0
    total_error = 0
    total_timeout = 0

    for system in systems:
        info_base = os.path.join(args.info_dir, system)
        gadget_base = os.path.join(args.gadget_dir, system)

        if not os.path.isdir(info_base) or not os.path.isdir(gadget_base):
            logger.warning(f"Skip {system}: missing info or gadget dir")
            continue

        binaries = [args.binary] if args.binary else sorted(os.listdir(info_base))
        logger.info(f"=== {system}: {len(binaries)} binaries ===")

        system_results = []
        sys_success = 0
        sys_fail = 0

        for binary_name in binaries:
            binary_info_dir = os.path.join(info_base, binary_name)
            if not os.path.isdir(binary_info_dir):
                continue

            gadget_file = os.path.join(gadget_base, f"{binary_name}.bin.txt")
            if not os.path.exists(gadget_file):
                gadget_file2 = os.path.join(gadget_base, f"{binary_name.upper()}.BIN.TXT")
                if os.path.exists(gadget_file2):
                    gadget_file = gadget_file2
                else:
                    logger.warning(f"  {system}/{binary_name}: gadget file not found")
                    system_results.append({
                        "system": system, "binary": binary_name,
                        "status": "error", "error": "gadget_file_not_found"
                    })
                    total_error += 1
                    continue

            logger.info(f"  {system}/{binary_name}")
            res = run_one_binary(system, binary_name, gadget_file, binary_info_dir,
                                 num_threads=args.threads, timeout=args.timeout)

            status = res["status"]
            if status == "success":
                sys_success += 1
                total_success += 1
                logger.success(f"    SUCCESS in {res['time']:.1f}s, chain={res['chain_length']} gadgets")
            elif status == "timeout":
                sys_fail += 1
                total_timeout += 1
                logger.warning(f"    TIMEOUT ({args.timeout}s)")
            elif status == "fail":
                sys_fail += 1
                total_fail += 1
                logger.error(f"    FAIL in {res.get('time', 0):.1f}s")
            elif status == "no_gadgets":
                sys_fail += 1
                total_fail += 1
                logger.warning(f"    NO call/jmp gadgets")
            else:
                total_error += 1
                logger.error(f"    ERROR: {res.get('error', '?')}")

            if res.get("solvable_prefixes"):
                logger.info(f"    Solvable prefixes: {', '.join(res['solvable_prefixes'])}")
            if res.get("skipped_orderings", 0):
                logger.info(f"    Pruned {res['skipped_orderings']} orderings via failed-prefix cache")

            system_results.append(res)

        logger.info(f"  {system} done: {sys_success}/{sys_success + sys_fail} success")
        all_results.extend(system_results)

        sys_out = os.path.join(args.output, f"{system}.json")
        with open(sys_out, 'w') as f:
            json.dump(system_results, f, indent=2)

    total_tested = total_success + total_fail + total_timeout
    summary = {
        "target": ", ".join(format_target_regs(TARGET_REGS)),
        "target_regs": format_target_regs(TARGET_REGS),
        "total_binaries": total_tested + total_error,
        "success": total_success,
        "fail": total_fail,
        "timeout": total_timeout,
        "error": total_error,
        "success_rate": f"{total_success / total_tested * 100:.1f}%" if total_tested > 0 else "N/A",
    }
    with open(os.path.join(args.output, "summary.json"), 'w') as f:
        json.dump(summary, f, indent=2)

    logger.info(f"\n{'=' * 60}")
    logger.info(f"TOTAL: {total_success} success / {total_fail} fail / {total_timeout} timeout / {total_error} error")
    logger.info(f"Success rate: {summary['success_rate']}")
    logger.info(f"Results saved to {args.output}/")


if __name__ == "__main__":
    main()
