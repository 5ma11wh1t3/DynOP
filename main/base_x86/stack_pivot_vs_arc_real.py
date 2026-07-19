import find_stack_pivot
import tools
import solve_engine
import json
from pwn import *
import os
import time
import argparse
from paths import REAL_SOFTWARE_DIR, BASE_RESULT_DIR

def infoinit(case,binary, real_dataset_dir=None):
    global gadgets_info
    real_dataset_dir = real_dataset_dir or str(REAL_SOFTWARE_DIR)
    gadgets_file = os.path.join(real_dataset_dir, "real_binary", f"{binary}.txt")
    gadgets_data = tools.load_gadget(gadgets_file)
    gadgets_dict = tools.create_gadget_dict(gadgets_data)
    context_dir = os.path.join(real_dataset_dir, "context_info", case)
    controllable_mem_file_dir = os.path.join(context_dir, "cyclic_matches.json")
    with open(controllable_mem_file_dir, "r", encoding="utf-8") as file:
        controllable_mem_data = json.load(file)
    controllable_mem_data = sorted(controllable_mem_data, key=lambda x: int(x['start_addr'], 16))
    controble_addr_base = int(controllable_mem_data[0]['start_addr'],16)
    # print(f"controble_addr_base: {hex(controble_addr_base)}")
    (permission_table, regs_init) = tools.get_map_regs(context_dir)

    controllable_regs = eval(open(os.path.join(context_dir, "controble_regs.txt"),'r').read())
    binary_file = os.path.join(real_dataset_dir, "real_binary", binary)
    try:
        elf = ELF(binary_file,checksec=False)  # 加载目标二进制
        bss_address = elf.bss()  # 获取 .bss 段地址
        if permission_table[0]['start']>>32 > 0:
            bss_address = elf.bss()+permission_table[0]['start']
    except:
        for i in range(len(permission_table)):
            if 'rw' in permission_table[i]['permission'] and permission_table[i]['end'] < controble_addr_base:
                bss_address = permission_table[i]['start']
                break
    # target_regs = [{'reg_name':'rdi','reg_value':bss_address+0x300},{'reg_name':'rsi','reg_value':0},{'reg_name':'rdx','reg_value':0},{'reg_name':'rax','reg_value':59},{'reg_name':'rcx','reg_value':2}]
    target_regs = [{'reg_name':'rdi','reg_value':bss_address+0x300},{'reg_name':'rsi','reg_value':0x1000},{'reg_name':'rdx','reg_value':7},{'reg_name':'rcx','reg_value':10}]

    stack_pivot_chain = []
    
    offset_list = []
    s = 0
    for i in range(len(controllable_mem_data)):
        offset_list += [ _ + s for _ in range(int(controllable_mem_data[i]['length'])//8)]
        if i != len(controllable_mem_data) - 1:
            s = s + (int(controllable_mem_data[i+1]['start_addr'],16) - int(controllable_mem_data[i]['start_addr'],16))//8
    
    address_map = {}
    # target_mem_value = [{bss_address+0x300:b"/bin/sh\x00"}]
    target_mem_value = []
    bss_address += 0x308
    gadgets_info = solve_engine.GadgetsInfo(gadgets_file,regs_init,stack_pivot_chain,gadgets_dict,address_map,offset_list,controllable_mem_data,controble_addr_base,target_regs,target_mem_value,controllable_regs,permission_table,bss_address)

    return gadgets_info
def get_gadgets(binary, real_dataset_dir=None):
    real_dataset_dir = real_dataset_dir or str(REAL_SOFTWARE_DIR)
    binary_file = os.path.join(real_dataset_dir, "real_binary", binary)
    gadget_file = os.path.join(real_dataset_dir, "real_binary", f"{binary}.txt")
    os.system(f"ROPgadget --binary {binary_file} > {gadget_file}")

from loguru import logger

def main():
    parser = argparse.ArgumentParser(description="Run real-binary stack-pivot experiment")
    parser.add_argument('--case', type=str, default=None, help='Only run one register case')
    parser.add_argument('--binary', type=str, default=None, help='Only run one binary path like Nginx/nginx')
    parser.add_argument('--real-dataset-dir', type=str, default=str(REAL_SOFTWARE_DIR))
    parser.add_argument('--result-log', type=str, default=str(BASE_RESULT_DIR / "stack_pivot_vs_arc_real.log"))
    args = parser.parse_args()

    cases = [args.case] if args.case else ['rax','rdi','rsi','rdx']
    binaries = [args.binary] if args.binary else [
              "Nginx/nginx",
              "dnsmasq/dnsmasq",
              "Apache2/httpd",
              "OpenSSL/openssl",
              "libc/libc.so.6",
              "Fortigate/init",
              "ffmpeg/ffmpeg",
              "cisco/lina",
              "Firefox/libxul.so",
              "chrome/chrome"
            ]
    os.makedirs(os.path.dirname(args.result_log), exist_ok=True)
    log_handler = logger.add(
        sink=args.result_log,
        level="INFO",    # 关闭 DEBUG
        encoding="utf-8"
        )
    
    for binary in binaries:
        for case in cases:    
            logger.info(f"START {binary}-{case}")
            for n in range(5):
                if n == 4:
                    logger.error(f"{binary}-{case}-{0}")
                    break
                gadget_file = os.path.join(args.real_dataset_dir, "real_binary", f"{binary}.txt")
                if not os.path.exists(gadget_file):
                    print(f"[+] Generating gadgets for {binary}...")
                    get_gadgets(binary, args.real_dataset_dir)
                gadgets_info = infoinit(case,binary, args.real_dataset_dir)
                max_depth = n
                res_json = {}
                start_time = time.time()
                pivot_res = find_stack_pivot.main(case,gadgets_info,max_depth=max_depth,res_json=res_json,num_threads=64,mode=1)
                if len(pivot_res) == 0:
                    continue
                else:
                    for i in range(len(pivot_res)):
                        logger.success(f"{binary}-{case}-{n}")
                        logger.success(f"gadget chain length : {len(pivot_res[i]['gadget_chain'])} time : {pivot_res[i]['time']-start_time}")
                        logger.success(f"gadget chain : {pivot_res[i]['gadget_chain']}")
                    break

    logger.remove(log_handler)

if __name__ == "__main__":
    main()
