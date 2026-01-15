import os
from loguru import logger
import time
import find_reg_gadget_chain
import argparse

def benchmark_test(fold_info, target_type="funcall4"):
    file_fold = fold_info['system']
    reg_search_depth = fold_info['reg_search_depth']
    mem_search_depth = fold_info['mem_search_depth']
    valid_mem_reg_num = fold_info['valid_mem_reg_num']
    mem_reg_timeout = fold_info['mem_reg_timeout']
    reg_timeout = fold_info['reg_timeout']
    binary_file_list = os.listdir(f"/home/rop/my-rop/benchmark_experiment/rop-benchmark/binaries/x86/reallife/vuln/{file_fold}")
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
            res_json["size(KB)"] = os.path.getsize(f"/home/rop/my-rop/benchmark_experiment/rop-benchmark/binaries/x86/reallife/vuln/{file_fold}/{b}")//1024
            start_time = time.time()
            # try:
            if find_reg_gadget_chain.main(b[:-4], file_fold, mem_search_depth=mem_search_depth, reg_search_depth=reg_search_depth, res_json=res_json,valid_mem_reg_num=valid_mem_reg_num,mem_reg_timeout=mem_reg_timeout, reg_timout=reg_timeout, target_type=target_type):
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
    for fold_info in benchmark_fold:
        log_handler = logger.add(
        sink=f"../result/without_vcm/benchmark/{args.target}/{fold_info['system']}.log",  # 日志文件路径
        level="INFO",    # 关闭 DEBUG
        encoding="utf-8"
        )
        benchmark_test(fold_info, args.target)
        logger.remove(log_handler)