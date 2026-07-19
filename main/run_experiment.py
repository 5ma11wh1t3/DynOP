#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path


MAIN_DIR = Path(__file__).resolve().parent


def add_opt(cmd, flag, value):
    if value is not None:
        cmd.extend([flag, str(value)])


def main():
    parser = argparse.ArgumentParser(description="Unified experiment entry for DynOP")
    parser.add_argument(
        "experiment",
        choices=[
            "dynop-cve",
            "dynop-benchmark",
            "dynop-real-pivot",
            "dynop-without-vcm",
            "cet-ss-benchmark",
            "cet-ss-demo",
            "cet-ibt-demo",
            "cet-ss-ibt-demo",
            "arm-benchmark",
            "arm-cve",
            "cet-none",
        ],
    )
    parser.add_argument("--target", default="funcall4")
    parser.add_argument("--case", default=None)
    parser.add_argument("--binary", default=None)
    parser.add_argument("--system", default=None)
    parser.add_argument("--arch", default="arm")
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--dataset-base", default=None)
    parser.add_argument("--benchmark-binary-dir", default=None)
    parser.add_argument("--benchmark-context-dir", default=None)
    parser.add_argument("--benchmark-gadget-dir", default=None)
    parser.add_argument("--cve-dataset-dir", default=None)
    parser.add_argument("--real-dataset-dir", default=None)
    parser.add_argument("--gadget-file", default=None)
    parser.add_argument("--cyclic-file", default=None)
    parser.add_argument("--binary-file", default=None)
    parser.add_argument("--gadget-dir", default=None)
    parser.add_argument("--context-dir", default=None)
    parser.add_argument("--info-dir", default=None)
    parser.add_argument("--output", default=None)
    parser.add_argument("--result-dir", default=None)
    parser.add_argument("--result-log", default=None)
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--max-binaries", type=int, default=None)
    parser.add_argument("--search-depth", type=int, default=None)
    parser.add_argument("--skip-done", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.experiment == "dynop-cve":
        script = MAIN_DIR / "base_x86" / "cve_log.py"
        cmd = [sys.executable, str(script), "--target", args.target]
        add_opt(cmd, "--case", args.case)
        add_opt(cmd, "--cve-dataset-dir", args.cve_dataset_dir)
        add_opt(cmd, "--result-dir", args.result_dir)
    elif args.experiment == "dynop-benchmark":
        script = MAIN_DIR / "base_x86" / "benchmark_log.py"
        cmd = [sys.executable, str(script), "--target", args.target]
        add_opt(cmd, "--system", args.system)
        add_opt(cmd, "--binary", args.binary)
        add_opt(cmd, "--benchmark-binary-dir", args.benchmark_binary_dir)
        add_opt(cmd, "--benchmark-context-dir", args.benchmark_context_dir)
        add_opt(cmd, "--benchmark-gadget-dir", args.benchmark_gadget_dir)
        add_opt(cmd, "--result-dir", args.result_dir)
    elif args.experiment == "dynop-real-pivot":
        script = MAIN_DIR / "base_x86" / "stack_pivot_vs_arc_real.py"
        cmd = [sys.executable, str(script)]
        add_opt(cmd, "--case", args.case)
        add_opt(cmd, "--binary", args.binary)
        add_opt(cmd, "--real-dataset-dir", args.real_dataset_dir)
        add_opt(cmd, "--result-log", args.result_log)
    elif args.experiment == "dynop-without-vcm":
        script = MAIN_DIR / "without_vcm" / "benchmark_log.py"
        cmd = [sys.executable, str(script), "--target", args.target]
        add_opt(cmd, "--system", args.system)
        add_opt(cmd, "--binary", args.binary)
        add_opt(cmd, "--benchmark-binary-dir", args.benchmark_binary_dir)
        add_opt(cmd, "--benchmark-context-dir", args.benchmark_context_dir)
        add_opt(cmd, "--benchmark-gadget-dir", args.benchmark_gadget_dir)
        add_opt(cmd, "--result-dir", args.result_dir)
    elif args.experiment == "cet-ss-benchmark":
        script = MAIN_DIR / "bypass_cet_ss" / "run_benchmark_cop_v2.py"
        cmd = [sys.executable, str(script)]
        add_opt(cmd, "--system", args.system)
        add_opt(cmd, "--binary", args.binary)
        add_opt(cmd, "--threads", args.threads)
        add_opt(cmd, "--timeout", args.timeout)
        add_opt(cmd, "--info-dir", args.info_dir)
        add_opt(cmd, "--gadget-dir", args.gadget_dir)
        add_opt(cmd, "--output", args.output)
    elif args.experiment == "cet-ss-demo":
        script = MAIN_DIR / "bypass_cet_ss" / "run_libxul_ss_v2.py"
        cmd = [sys.executable, str(script)]
        add_opt(cmd, "--dataset-dir", args.dataset)
        add_opt(cmd, "--gadget-file", args.gadget_file)
        add_opt(cmd, "--threads", args.threads)
    elif args.experiment == "cet-ibt-demo":
        script = MAIN_DIR / "bypass_cet_ibt" / "run_libxul_ibt.py"
        cmd = [sys.executable, str(script)]
        add_opt(cmd, "--dataset-dir", args.dataset)
        add_opt(cmd, "--gadget-file", args.gadget_file)
        add_opt(cmd, "--cyclic-file", args.cyclic_file)
        add_opt(cmd, "--binary-file", args.binary_file)
        add_opt(cmd, "--search-depth", args.search_depth)
        add_opt(cmd, "--timeout", args.timeout)
    elif args.experiment == "cet-ss-ibt-demo":
        script = MAIN_DIR / "bypass_cet_ss" / "run_libxul_ss_ibt_v2.py"
        cmd = [sys.executable, str(script)]
        add_opt(cmd, "--dataset-dir", args.dataset)
        add_opt(cmd, "--gadget-file", args.gadget_file)
        add_opt(cmd, "--threads", args.threads)
    elif args.experiment == "arm-benchmark":
        script = MAIN_DIR / "arm" / "run_parallel.py"
        cmd = [sys.executable, str(script), "--arch", args.arch, "--target", args.target]
        add_opt(cmd, "--dataset", args.dataset)
        add_opt(cmd, "--gadget_dir", args.gadget_dir)
        add_opt(cmd, "--context_dir", args.context_dir)
        add_opt(cmd, "--max_binaries", args.max_binaries)
        add_opt(cmd, "--workers", args.workers)
        add_opt(cmd, "--binary", args.binary)
        add_opt(cmd, "--result-dir", args.result_dir)
        if args.skip_done:
            cmd.append("--skip_done")
    elif args.experiment == "cet-none":
        script = MAIN_DIR / "base_x86" / "run_libxul_none.py"
        cmd = [sys.executable, str(script), "--target", args.target]
        add_opt(cmd, "--dataset-dir", args.dataset)
        add_opt(cmd, "--gadget-file", args.gadget_file)
        add_opt(cmd, "--reg-search-depth", args.search_depth)
        add_opt(cmd, "--reg-timeout", args.timeout)
        add_opt(cmd, "--result-dir", args.result_dir)
    else:
        script = MAIN_DIR / "arm" / "test_cves.py"
        cmd = [sys.executable, str(script)]
        if args.case is not None:
            cmd.append(args.case)
        add_opt(cmd, "--dataset-base", args.dataset_base)
        add_opt(cmd, "--result-dir", args.result_dir)

    if args.dry_run:
        print(" ".join(cmd))
        return

    raise_code = subprocess.run(cmd, cwd=str(MAIN_DIR.parent)).returncode
    raise SystemExit(raise_code)


if __name__ == "__main__":
    main()
