import os
import glob
import re
from common_paths import RESULT_DIR

def parse_log(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

    # Use regex to find all matches
    sp_time_pattern = r"Find and Solve Pivot Gadget Chain Time : ([\d\.]+)"
    sp_count_pattern = r"Pivot Gadget Chain Found : (\d+)"
    reg_time_pattern = r"Register Time: ([\d\.]+)"

    sp_time_matches = re.findall(sp_time_pattern, content)
    sp_count_matches = re.findall(sp_count_pattern, content)
    reg_time_matches = re.findall(reg_time_pattern, content)

    if not sp_time_matches or not sp_count_matches or not reg_time_matches:
        # Check if we have at least SP info, possibly failed later? 
        # But requirement implies we need all for "F4" which is sum.
        # If Reg Time is missing, it implies F4 task wasn't fully successful or log incomplete.
        # For now, unless we find a complete set, we might consider it incomplete.
        # Let's align by index if they appear sequentially, but simple approach: take the LAST one.
        pass

    if sp_time_matches and sp_count_matches and reg_time_matches:
        # Assuming the logs are sequential and a full run produces all 3 in order.
        # We take the values from the last successful run.
        # However, we must be careful if a run failed halfway.
        # Let's assume the last occurrence of Reg Time corresponds to the last successful F4 run.
        # And the SP Time/Count immediately preceding it are the ones we want.
        
        # Actually simplest heuristic for these logs: Take the last match of each.
        # Usually checking the timestamps would be better but simple last match is likely sufficient given the log appended nature.
        
        sp_time = float(sp_time_matches[-1])
        sp_count = int(sp_count_matches[-1])
        reg_time = float(reg_time_matches[-1])
        
        return sp_time, sp_count, reg_time
    
    return None

def main():
    log_dir = str(RESULT_DIR / "base" / "cve" / "funcall4")
    log_files = glob.glob(os.path.join(log_dir, "*.log"))
    
    results = []

    print(f"{'Case':<30} {'SP (Time/Chain)':<25} {'F4 (Total Time)':<20}")
    print("-" * 75)

    for log_file in sorted(log_files):
        filename = os.path.basename(log_file)
        case_name = filename.replace(".log", "")
        
        data = parse_log(log_file)
        
        if data:
            sp_time, sp_count, reg_time = data
            total_time = sp_time + reg_time
            
            sp_str = f"{sp_time:.2f}/{sp_count}"
            f4_str = f"{total_time:.2f}"
            
            print(f"{case_name:<30} {sp_str:<25} {f4_str:<20}")
            results.append((case_name, sp_str, f4_str))
        else:
            print(f"{case_name:<30} {'N/A':<25} {'N/A':<20}")

if __name__ == "__main__":
    main()
