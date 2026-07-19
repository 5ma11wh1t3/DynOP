
import os
import sys
import json
import pandas as pd
import numpy as np
from tqdm import tqdm
from common_paths import DATASET_DIR, add_base_x86_to_syspath

# Add src to path to allow imports
add_base_x86_to_syspath()

try:
    import find_stack_pivot
    import find_reg_gadget_chain
except ImportError:
    print("Import Error")
    exit(1)

# Suppress loguru
from loguru import logger
logger.remove()
logger.add(sys.stderr, level="ERROR")

def analyze_cve(case_info):
    try:
        binary = case_info['binary']
        cve_case = case_info['cve']
        # Note: info_init_cve might require specific working directory or paths
        # The user snippet implies it works directly.
        
        gadgets_info = find_stack_pivot.info_init_cve(cve_case, binary)
        gadgets_dict = gadgets_info.gadgets_dict
        controllable_reg = gadgets_info.controllable_regs
        target_regs = [_['reg_name'] for _ in gadgets_info.target_regs]
        
        edges = find_reg_gadget_chain.get_edges(gadgets_dict, controllable_reg, target_regs)
        
        if edges is None:
            return None
            
        edges = find_reg_gadget_chain.sort_edges(gadgets_info, edges)
        
        if edges is None:
            return None
            
        return {
            "name": cve_case,
            "ag": len(gadgets_dict),
            "pg": len(edges)
        }
    except Exception as e:
        print(f"Error analyzing {case_info.get('cve', 'unknown')}: {e}")
        return None

def analyze_benchmark(fold_info):
    file_fold = fold_info['system']
    base_path = DATASET_DIR / "benchmark" / "benchmark_binary" / file_fold
    
    if not os.path.exists(base_path):
        return []

    binary_file_list = os.listdir(base_path)
    results = []
    
    # Using tqdm but printing to stderr to keep stdout clean for table? 
    # Or just suppress tqdm for cleaner output
    for i in tqdm(range(len(binary_file_list))):
        b = binary_file_list[i]
        if b.endswith(".bin"):
            try:
                gadgets_info = find_reg_gadget_chain.info_init(b[:-4], file_fold, target_type="execve")
                gadgets_dict = gadgets_info.gadgets_dict
                controllable_reg = gadgets_info.controllable_regs
                target_regs = [_['reg_name'] for _ in gadgets_info.target_regs]
                
                edges = find_reg_gadget_chain.get_edges(gadgets_dict, controllable_reg, target_regs)
                if edges is None: continue
                
                edges = find_reg_gadget_chain.sort_edges(gadgets_info, edges)
                if edges is None: continue
                
                results.append({
                    "name": f"{file_fold}/{b}",
                    "ag": len(gadgets_dict),
                    "pg": len(edges)
                })
            except Exception as e:
                pass
                
    return results

def print_row(target, ag, pg, rate):
    ag_s = f"{ag:,}" if isinstance(ag, (int, float)) else str(ag)
    pg_s = f"{pg:,}" if isinstance(pg, (int, float)) else str(pg)
    rate_s = f"{rate:.2f}%" if isinstance(rate, (int, float)) else str(rate)
    
    print(f"{target:<30} {ag_s:<15} {pg_s:<15} {rate_s:<10}")

def calculate_rate(ag, pg):
    if ag == 0: return 0.0
    return (ag - pg) / ag * 100

def main():
    # Case infos from user snippet
    case_infos = [
        {"binary":"libc.so.6","cve":"cve-2022-3974","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
        {"binary":"init","cve":"cve-2022-42475","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
        {"binary":"ffmpeg","cve":"cve-2016-10191","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
        {"binary":"init","cve":"cve-2023-25610","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
        {"binary":"init","cve":"cve-2024-21762","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
        {"binary":"login_mgr.cgi","cve":"Synacktiv_PR4100","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
        {"binary":"Serv-U.dll","cve":"cve-2021-35211","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
        {"binary":"init","cve":"cve-2024-23113","depth":0,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
        {"binary":"ffmpeg","cve":"cve-2016-10190","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
    ]

    benchmark_fold = [
        {"system":"centos-7.1810", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":10*60},
        {"system":"debian-10-cloud", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":10*60},
        {"system":"openbsd-62", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":15*60},
        {"system":"openbsd-64", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":15*60},
        {"system":"openbsd-65", "reg_search_depth":3, "mem_search_depth":1, "valid_mem_reg_num":1,"mem_reg_timeout":90,"reg_timeout":15*60},
        {"system":"gcc_fzero", "reg_search_depth":3, "mem_search_depth":3, "valid_mem_reg_num":2,"mem_reg_timeout":120,"reg_timeout":15*60},
        {"system":"openbsd-73", "reg_search_depth":3, "mem_search_depth":3, "valid_mem_reg_num":2,"mem_reg_timeout":120,"reg_timeout":15*60},
    ]

    print(f"{'Target':<30} {'AGs✦':<15} {'PGs':<15} {'Reduction Rate':<10}")
    
    rates = []
    results = []
    
    # Process CVEs
    for case in case_infos:
        res = analyze_cve(case)
        if res:
            rate = calculate_rate(res["ag"], res["pg"])
            rates.append(rate)
            # Display name cleanup (e.g. cve-2022-42475 to CVE-2022-42475)
            # The example shows nicely formatted CVEs.
            # I will just ensure "cve" -> "CVE"
            name = res["name"]
            if name.lower().startswith("cve"):
                name = name.upper().replace("CVE-", "CVE-") 
            # User example: "cve-2022-42475" -> "CVE-2022-42475"
            # "Synacktiv_PR4100" -> "Synacktiv_PR4100"
            # "ccb-2024-final-NFS-Heap" -> "ccb-2024-final-NFS-Heap"
            
            # Simple formatter
            if name.startswith("cve-"):
                name = "CVE-" + name[4:]
            
            print_row(name, res["ag"], res["pg"], rate)
            results.extend([{"ag":res["ag"], "pg":res["pg"]}])
            # print(res)
    # Process Benchmark
    bench_results = []
    # results = []
    for fold in benchmark_fold:
        bench_results.extend(analyze_benchmark(fold))
        # results.extend(analyze_benchmark(fold))
        
    if bench_results:
        total_ag = sum(r["ag"] for r in bench_results)
        total_pg = sum(r["pg"] for r in bench_results)
        count = len(bench_results)
        
        avg_ag = int(total_ag / count)
        avg_pg = int(total_pg / count)
        
        bench_rate = calculate_rate(avg_ag, avg_pg)
        rates.append(bench_rate)
        
        print_row("Benchmark (Avg.)✝", avg_ag, avg_pg, bench_rate)
        
    # Global Average
    if rates:
        global_avg_rate = np.mean(rates)
        print(f"{'Average':<30} {'–':<15} {'–':<15} {global_avg_rate:.2f}%")

if __name__ == "__main__":
    main()
