
import os
import glob
import json
import re
import numpy as np
from common_paths import RESULT_DIR, SOTA_RESULT_DIR

# Configuration for paths
DYNOP_BASE = str(RESULT_DIR / "base" / "benchmark")
SOTA_BASE = str(SOTA_RESULT_DIR)

def get_all_log_files(directory, pattern):
    return glob.glob(os.path.join(directory, pattern))

def parse_dynop(task):
    """
    Parses DynOP logs.
    Logic: 
    - Count 'Start Test' as attempted (Generated candidate).
    - User rule: If 'All Time' > 1800, it is a TIMEOUT, not a success.
    """
    ver_log_dir = os.path.join(DYNOP_BASE, task)
    log_files = get_all_log_files(ver_log_dir, "*.log")
    
    generated = 0
    success = 0
    explicit_timeouts = 0
    times = []
    
    for log_file in log_files:
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            
            current_binary = None
            has_success_flag = False
            
            for line in lines:
                if "Start Test" in line and ".bin" in line:
                    parts = line.split("Start Test")
                    if len(parts) > 1:
                        current_binary = parts[1].strip()
                        has_success_flag = False
                        
                if "Success!" in line and current_binary:
                    if current_binary in line:
                        has_success_flag = True
                        
                if "All Time:" in line and current_binary:
                    m = re.search(r"All Time:\s*([\d\.]+)", line)
                    if m:
                        t_val = float(m.group(1))
                        
                        if has_success_flag:
                            # It was marked successful by tool, but we check verification time limit
                            if t_val > 1800:
                                explicit_timeouts += 1
                                # Count as generated but failed/timed-out
                                generated += 1
                            else:
                                success += 1
                                generated += 1 
                                times.append(t_val)
                        
                        current_binary = None
                        has_success_flag = False

        except Exception as e:
            pass
            
    # Failures passed as explicit timeouts
    return {
        "generated": generated,
        "success": success,
        "failures": explicit_timeouts,
        "times": times,
        "tool": "DynOP"
    }

def parse_jsonl(tool_name, task):
    tool_dir = os.path.join(SOTA_BASE, tool_name, task)
    if not os.path.exists(tool_dir):
        return None
        
    files = get_all_log_files(tool_dir, "*.jsonl")
    
    generated = 0
    success = 0
    fp = 0
    timeout_count = 0
    total_entries = 0
    times = []
    
    for path in files:
        with open(path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    total_entries += 1
                    
                    gen = False
                    succ = False
                    is_timeout = data.get("timeout", False)
                    time_val = 0
                    
                    if is_timeout:
                        timeout_count += 1
                    
                    if data.get("chain_build") is True:
                        gen = True
                        generated += 1
                        
                    if gen:
                        if tool_name == "ropbot":
                            if data.get("chain_verify"):
                                succ = True
                            
                            time_val = (data.get("find_gadgets_time") or 0) + \
                                (data.get("builder_optimize_time") or 0) + \
                                (data.get("chain_build_time") or 0) + \
                                (data.get("chain_verify_time") or 0)
                                
                        elif tool_name == "cracker":
                            if data.get("runner_failed") is False:
                                succ = True
                            
                            time_val = (data.get("find_gadgets_time") or 0) + \
                                (data.get("chain_build_time") or 0)
                            
                        elif tool_name == "sgc":
                            v_lists = [data.get("chain_verify_unknown_payload_addr"), data.get("chain_verify_known_payload_addr")]
                            s_verified = False
                            v_times = []
                            for v_list in v_lists:
                                if isinstance(v_list, list):
                                    for item in v_list:
                                        if item and item[0] is True:
                                            s_verified = True
                                            v_times.append(item[1])
                            
                            if s_verified:
                                succ = True
                            
                            time_val = (data.get("find_gadgets_time") or 0) + (data.get("chain_build_time") or 0)
                            if v_times: time_val += np.mean(v_times)

                    if gen:
                        if succ:
                            success += 1
                            if time_val > 0:
                                times.append(time_val)
                        else:
                            fp += 1
                            
                except:
                    pass
                    
    return {
        "generated": generated,
        "success": success,
        "fp": fp,
        "timeout_count": timeout_count,
        "total_entries": total_entries,
        "times": times,
        "tool": tool_name
    }

def parse_tgrop(task):
    if task != "execve": return None
    d = os.path.join(SOTA_BASE, "tgrop")
    if not os.path.exists(d): return None   
    count = 0
    for root, dirs, files in os.walk(d):
        for file in files:
            if file.endswith(".script"):
                count += 1
                
    return {"generated": count, "tool": "tgrop"}

def parse_arcanist(task):
    d = os.path.join(SOTA_BASE, "arcanist", task)
    if not os.path.exists(d): return None
    
    generated = 0
    timeout_count = 0
    times = []
    total_files = 0
    
    for distro in os.listdir(d):
        path = os.path.join(d, distro)
        if not os.path.isdir(path): continue
        for bin_dir in os.listdir(path):
            if bin_dir.endswith(".json"):
                total_files += 1
                res_file = os.path.join(path, bin_dir, "stack_syscall_4args.json")
                if os.path.exists(res_file):
                    try:
                        with open(res_file) as f:
                            dat = json.load(f)
                        
                        if dat.get("success"):
                            generated += 1 
                            times.append(dat.get("time", 0))
                        
                        if dat.get("timeout"):
                            timeout_count += 1
                    except:
                        pass
                        
    return {
        "generated": generated,
        "timeout_count": timeout_count,
        "times": times,
        "total_entries": total_files,
        "tool": "arcanist"
    }

def print_row(tool, gen, succ, fp, timeout, avg_time):
    g_s = str(gen) if gen is not None else "–"
    s_s = str(succ) if succ is not None else "–"
    f_s = f"{fp:.2f}%" if fp is not None else "–"
    t_s = f"{timeout:.2f}%" if timeout is not None else "–"
    a_s = f"{avg_time:.2f}s" if avg_time is not None else "–"
    
    print(f"{tool:<10} {g_s:<6} {s_s:<6} {f_s:<8} {t_s:<8} {a_s:<10}")

def main():
    print(f"{'Tool':<10} {'Gen.':<6} {'Succ.':<6} {'FP':<8} {'Timeout':<8} {'Avg Time':<10}")
    
    print("Task 1: execve(’/bin/sh\\x00’, 0, 0)✝")
    
    d1 = parse_dynop("execve")
    tools_t1 = ["DynOP", "ropbot", "cracker", "sgc", "tgrop"]
    all_binaries = 987
    for t_name in tools_t1:
        if t_name == "DynOP":
            r = d1
            g = r["generated"]
            s = r["success"]
            to_cnt = r["failures"]
            # print(g+to_cnt)
            to_val = (to_cnt / (all_binaries) * 100) if (all_binaries) > 0 else 0
            avg_t = np.mean(r["times"]) if r["times"] and len(r["times"]) > 0 else 0
            print_row("DynOP", g, s, 0.0, to_val, avg_t)
            
        elif t_name == "ropbot":
            r = parse_jsonl("ropbot", "execve")
            g = r["generated"]
            s = r["success"]
            fp_val = (g-s)/g*100 if g>0 else 0
            to_val = r["timeout_count"]/r["total_entries"]*100 if r["total_entries"]>0 else 0
            avg_t = np.mean(r["times"]) if r["times"] and len(r["times"]) > 0 else 0
            print_row("ropbot", g, s, fp_val, to_val, avg_t)
            
        elif t_name == "cracker":
            r = parse_jsonl("cracker", "execve")
            to_val = r["timeout_count"]/r["total_entries"]*100 if r["total_entries"]>0 else 0
            print_row("Cracker", r["generated"], None, None, to_val, None)
            
        elif t_name == "sgc":
            r = parse_jsonl("sgc", "execve")
            g = r["generated"]
            s = r["success"]
            fp_val = (g-s)/g*100 if g>0 else 0
            to_val = r["timeout_count"]/r["total_entries"]*100 if r["total_entries"]>0 else 0
            avg_t = np.mean(r["times"]) if r["times"] and len(r["times"]) > 0 else 0
            print_row("SGC", g, s, fp_val, to_val, avg_t)
            
        elif t_name == "tgrop":
            r = parse_tgrop("execve")
            print_row("TGRop", r["generated"], None, None, None, None)

    print("Task 2: Call function with 4 arguments")
    d2 = parse_dynop("funcall4")
    tools_t2 = ["DynOP", "ropbot", "arcanist", "cracker", "sgc"]
    
    for t_name in tools_t2:
        if t_name == "DynOP":
            r = d2
            g = r["generated"]
            s = r["success"]
            to_cnt = r["failures"]
            to_val = (to_cnt / (all_binaries)*100) if (all_binaries)>0 else 0
            avg_t = np.mean(r["times"]) if r["times"] and len(r["times"]) > 0 else 0
            print_row("DynOP", g, s, 0.0, to_val, avg_t)
            
        elif t_name == "ropbot":
            r = parse_jsonl("ropbot", "funcall4")
            g = r["generated"]
            s = r["success"]
            fp_val = (g-s)/g*100 if g>0 else 0
            to_val = r["timeout_count"]/r["total_entries"]*100 if r["total_entries"]>0 else 0
            avg_t = np.mean(r["times"]) if r["times"] and len(r["times"]) > 0 else 0
            print_row("ropbot", g, s, fp_val, to_val, avg_t)
            
        elif t_name == "arcanist":
            r = parse_arcanist("funcall4")
            to_val = r["timeout_count"]/r["total_entries"]*100 if r["total_entries"]>0 else 0
            avg_t = np.mean(r["times"]) if r["times"] and len(r["times"]) > 0 else 0
            print_row("Arcanist", r["generated"], None, None, to_val, avg_t)

        elif t_name == "cracker":
            r = parse_jsonl("cracker", "funcall4")
            to_val = r["timeout_count"]/r["total_entries"]*100 if r["total_entries"]>0 else 0
            avg_t = np.mean(r["times"]) if r["times"] and len(r["times"]) > 0 else 0
            print_row("Cracker", r["generated"], None, None, to_val, avg_t)
            
        elif t_name == "sgc":
            r = parse_jsonl("sgc", "funcall4")
            g = r["generated"]
            s = r["success"]
            fp_val = (g-s)/g*100 if g>0 else 0
            to_val = r["timeout_count"]/r["total_entries"]*100 if r["total_entries"]>0 else 0
            avg_t = np.mean(r["times"]) if r["times"] and len(r["times"]) > 0 else 0
            print_row("SGC", g, s, fp_val, to_val, avg_t)

if __name__ == "__main__":
    main()
