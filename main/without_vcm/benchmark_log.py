import os
from loguru import logger
import time
import find_reg_gadget_chain
import argparse
from paths import BENCHMARK_BINARY_DIR, BENCHMARK_CONTEXT_DIR, BENCHMARK_GADGET_DIR, WITHOUT_VCM_RESULT_DIR

def benchmark_test(
    fold_info,
    target_type="funcall4",
    benchmark_binary_dir=None,
    benchmark_context_dir=None,
    benchmark_gadget_dir=None,
    single_binary=None,
):
    benchmark_binary_dir = benchmark_binary_dir or str(BENCHMARK_BINARY_DIR)
    benchmark_context_dir = benchmark_context_dir or str(BENCHMARK_CONTEXT_DIR)
    benchmark_gadget_dir = benchmark_gadget_dir or str(BENCHMARK_GADGET_DIR)
    file_fold = fold_info['system']
    reg_search_depth = fold_info['reg_search_depth']
    mem_search_depth = fold_info['mem_search_depth']
    valid_mem_reg_num = fold_info['valid_mem_reg_num']
    mem_reg_timeout = fold_info['mem_reg_timeout']
    reg_timeout = fold_info['reg_timeout']
    binary_dir = os.path.join(benchmark_binary_dir, file_fold)
    binary_file_list = [f"{single_binary}.bin"] if single_binary else os.listdir(binary_dir)
    success = 0  # 72
    fail = 0
    if file_fold == "openbsd-65":
        success = 36
        fail = 24
    logger.info(f"Start Test {file_fold}")
    start = success + fail
    # input()
    for b_i in range(len(binary_file_list[start:])):
        b = binary_file_list[start:][b_i]
        if b.endswith(".bin"):
            logger.info(f"Start Test {b}")
            res_json = {"binary":f"{file_fold}/{b}"}
            res_json["size(KB)"] = os.path.getsize(os.path.join(binary_dir, b))//1024
            start_time = time.time()
            # try:
            if find_reg_gadget_chain.main(b[:-4], file_fold, mem_search_depth=mem_search_depth, reg_search_depth=reg_search_depth, res_json=res_json,valid_mem_reg_num=valid_mem_reg_num,mem_reg_timeout=mem_reg_timeout, reg_timout=reg_timeout, target_type=target_type, benchmark_binary_dir=benchmark_binary_dir, benchmark_context_dir=benchmark_context_dir, benchmark_gadget_dir=benchmark_gadget_dir):
                success += 1
                end_time = time.time()
                logger.success(f"{file_fold}/{b} Success!")
                res_json['All Time'] = end_time - start_time
                logger.success(f"All Time: {end_time - start_time}")
                logger.success(f"Success: {success} Fail: {fail}")
                logger.success(f"Res Json {res_json}")
            else:
                # logger.error(f"{file_fold}/{b} No Result!")
                # logger.error(f"{file_fold}/{b} Retry 1 Time")
                # start_time = time.time()
                # if find_reg_gadget_chain.main(b[:-4], file_fold, mem_search_depth=mem_search_depth, reg_search_depth=reg_search_depth, res_json=res_json,valid_mem_reg_num=valid_mem_reg_num,mem_reg_timeout=mem_reg_timeout, reg_timout=reg_timeout, target_type=target_type):
                #     success += 1
                #     end_time = time.time()
                #     logger.success(f"{file_fold}/{b} Success!")
                #     res_json['All Time'] = end_time - start_time
                #     logger.success(f"All Time: {end_time - start_time}")
                #     logger.success(f"Success: {success} Fail: {fail}")
                #     logger.success(f"Res Json {res_json}")
                # else:
                fail += 1
                logger.error(f"Success: {success} Fail: {fail}")
def test():
    logger.info("test")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run benchmark tests with specific target.')
    parser.add_argument('--target', type=str, default='funcall4', choices=['execve', 'funcall4'], help='Target type: execve or funcall4')
    parser.add_argument('--system', type=str, default=None, help='Only run one benchmark system')
    parser.add_argument('--binary', type=str, default=None, help='Only run one binary (without .bin suffix)')
    parser.add_argument('--benchmark-binary-dir', type=str, default=str(BENCHMARK_BINARY_DIR))
    parser.add_argument('--benchmark-context-dir', type=str, default=str(BENCHMARK_CONTEXT_DIR))
    parser.add_argument('--benchmark-gadget-dir', type=str, default=str(BENCHMARK_GADGET_DIR))
    parser.add_argument('--result-dir', type=str, default=str(WITHOUT_VCM_RESULT_DIR / "benchmark"))
    args = parser.parse_args()
    benchmark_fold = [
        {"system":"centos-7.1810", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":10*60},
        {"system":"debian-10-cloud", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":10*60},
        {"system":"openbsd-62", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":15*60},
        {"system":"openbsd-64", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":15*60},
        {"system":"openbsd-65", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":15*60},
        {"system":"gcc_fzero", "reg_search_depth":3, "mem_search_depth":3, "valid_mem_reg_num":2,"mem_reg_timeout":120,"reg_timeout":15*60},
        {"system":"openbsd-73", "reg_search_depth":3, "mem_search_depth":3, "valid_mem_reg_num":2,"mem_reg_timeout":120,"reg_timeout":15*60},
    ]
    if args.system:
        benchmark_fold = [fold for fold in benchmark_fold if fold["system"] == args.system]
        if not benchmark_fold:
            raise ValueError(f"Unknown system: {args.system}")
    for fold_info in benchmark_fold:
        log_dir = os.path.join(args.result_dir, args.target)
        os.makedirs(log_dir, exist_ok=True)
        log_handler = logger.add(
        sink=os.path.join(log_dir, f"{fold_info['system']}.log"),
        level="INFO",    # 关闭 DEBUG
        encoding="utf-8"
        )
        benchmark_test(
            fold_info,
            args.target,
            benchmark_binary_dir=args.benchmark_binary_dir,
            benchmark_context_dir=args.benchmark_context_dir,
            benchmark_gadget_dir=args.benchmark_gadget_dir,
            single_binary=args.binary,
        )
        logger.remove(log_handler)
