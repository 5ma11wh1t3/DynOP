from triton import TritonContext, ARCH, MemoryAccess, CPUSIZE, Instruction
from pwn import *
from itertools import product
context.arch = 'amd64'
import multiprocessing
from functools import partial
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
Ks = Ks(KS_ARCH_X86, KS_MODE_64)
def my_asm(gadget):
    return bytes(Ks.asm(gadget)[0])
def debug_log(s):
    print(f"debug log : {s}")
def get_reg(ctx, reg_name):
    for reg in ctx.getAllRegisters():
        if reg.getName() == reg_name :
            return reg
def init_reg(ctx, regs):
    # rs = ['rax','rbx','rcx','rdx','rdi','rsi','r8','r9','r10','r11','r12','r13','r14','r15','rbp','rsp']
    # for reg in ctx.getAllRegisters():
    #     if reg.getName() in rs :
    for reg, v in regs.items():
        if reg not in ['fs_base','gs_base']:
            ctx.setConcreteRegisterValue(get_reg(ctx, reg), v)
    return ctx
def table_check(addr, permission_table, mode):
    for i in range(len(permission_table)):
        # print(f"{hex(addr)} {hex(permission_table[i]['start'])} {hex(permission_table[i]['end'])} {addr > permission_table[i]['start'] and addr < permission_table[i]['end']}")
        if addr > permission_table[i]['start'] and addr < permission_table[i]['end']:
            if mode in permission_table[i]['permission']:
                return True
    return False

def read_write_check(instruction, permission_table):
    if instruction.isMemoryRead():
        a = instruction.getLoadAccess()
        readMemory = a[0][0].getAddress()
        if not table_check(readMemory, permission_table, 'r'):
            return False
    if instruction.isMemoryWrite():
        b = instruction.getStoreAccess()
        writeMemory = b[0][0].getAddress()
        if not table_check(writeMemory, permission_table, 'w'):
            return False
    return True
def symbol_solve_controble_reg_mem(regs, inst_idx, insts2, controble_addr_base, offset_list, permission_table,address_map,stack_mem={}):
    
    output_reg = extract_reg(insts2[inst_idx])[0]
    # input_reg = extract_reg(insts2[inst_idx])[1]
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    TARGET_VALUE = 0xDEADBEE1

    ctx = init_reg(ctx, regs)
    address_list = []
    for i in range(len(offset_list)):
        memory_access = MemoryAccess(controble_addr_base + 8 * offset_list[i], CPUSIZE.QWORD)
        address_list.append(controble_addr_base + 8 * offset_list[i])
        ctx.symbolizeMemory(memory_access, f"mem_{offset_list[i]}")
    for addr, values in address_map.items():
        ctx.setConcreteMemoryAreaValue(addr,p64(values['value']))
    for addr, values in stack_mem.items():
        ctx.setConcreteMemoryAreaValue(addr,p64(values['value']))
    address = 0x400000
    for i in range(inst_idx):
        instruction = Instruction(address, my_asm(insts2[i]))
        ctx.processing(instruction)
        address += len(my_asm(insts2[i]))
    instruction = Instruction(address, my_asm(insts2[inst_idx]))  #
    ctx.processing(instruction)
    rsp = ctx.getConcreteRegisterValue(get_reg(ctx,'rsp'))
    if rsp > controble_addr_base and rsp <= controble_addr_base+8*max(offset_list) and inst_idx != len(insts2)-1:
        return []
    output_reg_ast = ctx.getRegisterAst(get_reg(ctx, output_reg))
    output_reg_condition = output_reg_ast == TARGET_VALUE

    solution = ctx.getModel(output_reg_condition)
    res = []
    for s in solution:
        res.append(address_list[s])
    return res    

def extract_reg(target_string):
    registers = ["rax", "eax", "ax", "ah", "al","rbx", "ebx", "bx", "bh", "bl","rcx", "ecx", "cx", "ch", "cl","rdx", "edx", "dx", "dh", "dl","rsi", "esi", "si", "sil","rdi", "edi", "di", "dil","rbp", "ebp", "bp", "bpl","rsp", "esp", "sp", "spl","r8", "r8d", "r8w", "r8b","r9", "r9d", "r9w", "r9b","r10", "r10d", "r10w", "r10b","r11", "r11d", "r11w", "r11b","r12", "r12d", "r12w", "r12b","r13", "r13d", "r13w", "r13b","r14", "r14d", "r14w", "r14b","r15", "r15d", "r15w", "r15b"]
    registers_pattern = r'\b(' + '|'.join(registers) + r'|0x[0-9a-fA-F]+|\d+)\b'
    matches = re.findall(registers_pattern, target_string)
    if 'jmp' in target_string or 'call' in target_string:
        matches = ['rip']+matches
    if 'ret' == target_string:
        matches = ['rip','rsp']
    return matches

def taint_check(inst_idx, insts2, controble_addr_base, offset_list, regs, address_map, stack_mem={}):
    try:
        output_reg = extract_reg(insts2[inst_idx])[0]
        if "r" not in output_reg:
            return False
        # input_reg = extract_reg(insts2[inst_idx])[1]
        ctx = TritonContext()
        ctx.setArchitecture(ARCH.X86_64)

        for i in range(len(offset_list)):
            for j in range(8):
                ctx.taintMemory(controble_addr_base+offset_list[i]*8+j)
        for addr, values in address_map.items():
            ctx.setConcreteMemoryAreaValue(addr,p64(values['value']))
        for addr, values in stack_mem.items():
            ctx.setConcreteMemoryAreaValue(addr,p64(values['value']))
        ctx = init_reg(ctx,regs)
        address = 0x400000
        for k in range(inst_idx):
            instruction = Instruction(address, my_asm(insts2[k]))
            ctx.processing(instruction)
            address += len(my_asm(insts2[k]))
        instruction = Instruction(address, my_asm(insts2[inst_idx]))
        ctx.processing(instruction)

        if ctx.isRegisterTainted(get_reg(ctx, output_reg)):
            # print(f"{output_reg} 被污染")
            return True
        else:
            # print(f"{output_reg} 未被污染")
            return False
    except:
        return False
    
def init_mem(ctx, address_map):
    for memory_address, value in address_map.items():
        ctx.setConcreteMemoryValue(MemoryAccess(memory_address,value['length']), value['value'])
    return ctx

def update_regs(inst, address_map, regs, permission_table, stack_mem={}):
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx = init_reg(ctx, regs)
    ctx = init_mem(ctx, address_map)
    if len(stack_mem)!=0:
        ctx = init_mem(ctx, stack_mem)
    address = 0x400000
    jmp_inst = ['loopne','je','jne','ja','jna','jae','jnae','jb','jnb','jbe','jnbe','jg','jng','jge','jnge','jl','jnl','jle','jnle','jz','jnz','js','jns','jc','jnc','jo','jno','jp','jnp','jpe','jpo','jcxz','jecxz']
    try:
        for i in range(len(inst)):
            if inst[i].split(' ')[0] in jmp_inst:
                return None
            inst_list = inst[i].split(" ; ")
            for j in range(len(inst_list)):
                instruction = Instruction(address, my_asm(inst_list[j]))
                ctx.processing(instruction)
                address += len(my_asm(inst_list[j]))
                if not read_write_check(instruction, permission_table):
                    return None
    except:
        pass
    for reg,value in regs.items():
        regs[reg] = ctx.getConcreteRegisterValue(get_reg(ctx, reg))
    return regs

def solve_mem_gadget(regs_init,classify_res,controble_addr_base,offset_list_init, permission_table):
    res_f = {}
    for i in range(len(classify_res)):
        for a in product(*classify_res[i]):
            last_address = 0
            offset_list = offset_list_init.copy()
            regs = regs_init.copy()
            address_map = {}
            regs_new = {}
            count_i = 0
            for j in range(len(a)):
                if regs_new == None:
                    break
                demo2 = a[j]            
                inst_addr2 = demo2.split(' -> ')[0]
                insts2 = demo2.split(' -> ')[1].split(' ; ')
                if last_address != 0:
                    address_map[last_address] = {'value':int(inst_addr2,16),'length':8}
                    last_address = 0
                    count_i += 1
                for inst_idx in range(len(insts2)):
                    if taint_check(inst_idx, insts2, controble_addr_base, offset_list, regs,address_map):
                        res = symbol_solve_controble_reg_mem(regs, inst_idx, insts2, controble_addr_base, offset_list, permission_table,address_map)
                        if len(res) == 0:
                            continue
                        
                        address = res[0]
                        # print(hex(address))
                        offset_list.pop(offset_list.index((address-controble_addr_base)//8))
                        if 'ret' in insts2[inst_idx]:
                            address_map[address] = {'value':0xdeadbeef,'length':8}
                        elif 'jmp' in insts2[inst_idx] or 'call' in insts2[inst_idx]:
                            address_map[address] = {'value':0xdeadbeef,'length':8}
                            last_address = address
                        else:
                            address_map[address] = {'value':controble_addr_base+offset_list[0]*8,'length':8}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
                    else:
                        continue
                regs_new = update_regs(insts2, address_map, regs, permission_table)
                if regs_new == None:
                    break
                regs = regs_new
            if count_i != len(a)-1:
                continue
            if regs_new != None and len(address_map) != 0:
                if {'value':0xdeadbeef,'length':8} not in address_map.values():
                    continue
                # print(a)
                # open(f'../experiment/{case_name}/stack_piovt_res4.txt','a').write(str(a)+"\n")
                r = {}
                for addr, value in address_map.items():
                    r[(addr-controble_addr_base)//8] = f"{hex(value['value'])}"
                # print([r,offset_list])
                # open(f'../experiment/{case_name}/stack_piovt_res4.txt','a').write(str([r,offset_list])+"\n")
                # res_f.append([r,offset_list])
                res_f[a]=[r,offset_list]
    return res_f
def solve_mem_gadget_process(classify_res,regs_init,controble_addr_base,offset_list_init, permission_table, stack_mem={}):
    res_f = {}
    for i in range(len(classify_res)):
        for a in product(*classify_res[i]):
            last_address = 0
            offset_list = offset_list_init.copy()
            regs = regs_init.copy()
            address_map = {}
            regs_new = {}
            count_i = 0
            for j in range(len(a)):
                if regs_new == None:
                    break
                demo2 = a[j]            
                inst_addr2 = demo2.split(' -> ')[0]
                insts2 = demo2.split(' -> ')[1].split(' ; ')
                if last_address != 0:
                    address_map[last_address] = {'value':int(inst_addr2,16),'length':8}
                    last_address = 0
                    count_i += 1
                for inst_idx in range(len(insts2)):
                    if taint_check(inst_idx, insts2, controble_addr_base, offset_list, regs,address_map, stack_mem):
                        res = symbol_solve_controble_reg_mem(regs, inst_idx, insts2, controble_addr_base, offset_list, permission_table,address_map, stack_mem)
                        if len(res) == 0:
                            continue
                        address = res[0]
                        offset_list.pop(offset_list.index((address-controble_addr_base)//8))
                        if 'ret' in insts2[inst_idx]:
                            address_map[address] = {'value':0xdeadbeef,'length':8}
                        elif 'jmp' in insts2[inst_idx] or 'call' in insts2[inst_idx]:
                            address_map[address] = {'value':0xdeadbeef,'length':8}
                            last_address = address
                        else:
                            address_map[address] = {'value':controble_addr_base+offset_list[0]*8,'length':8}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
                    else:
                        continue
                regs_new = update_regs(insts2, address_map, regs, permission_table, stack_mem)
                if regs_new == None:
                    break
                regs = regs_new
            if count_i != len(a)-1:
                continue
            if regs_new != None and len(address_map) != 0:
                if {'value':0xdeadbeef,'length':8} not in address_map.values():
                    continue
                r = {}
                for addr, value in address_map.items():
                    r[(addr-controble_addr_base)//8] = f"{hex(value['value'])}"
                res_f[a]=[r,offset_list]
    return res_f

from loguru import logger

def solve_mem_gadget_process_func(regs_init,classify_res,controble_addr_base,offset_list_init, permission_table, num_threads, stack_mem):
    
    chunk_size = max(1, len(classify_res) // num_threads)
    chunks = [
        classify_res[i*chunk_size:i*chunk_size+chunk_size] 
        for i in range(num_threads)
    ]
    
    chunks[-1] = chunks[-1] + classify_res[chunk_size*num_threads:]

    # logger.debug("Start Solve")

    # s = solve_mem_gadget_process(classify_res,regs_init,controble_addr_base,offset_list_init, permission_table,stack_mem)

    solve_func = partial(solve_mem_gadget_process, regs_init=regs_init,controble_addr_base=controble_addr_base,offset_list_init=offset_list_init, permission_table=permission_table, stack_mem=stack_mem)
    dynaminc_params = [(_,) for _ in chunks]
    with multiprocessing.Pool(processes=num_threads) as pool:
        all_res_process = pool.starmap(solve_func, dynaminc_params)

    res = []
    for i in range(len(all_res_process)):
        for g, v in all_res_process[i].items():
            tmp = {}
            tmp['gadget_chain'] = g
            tmp['address_map'] = v[0]
            tmp['offset_list'] = v[1]
            res.append(tmp)
    # solve_mem_res = solve_mem_gadget(regs_init,classify_res,controble_addr_base,offset_list_init, permission_table)
    return res

if __name__ == '__main__':
    regs = {'rax': 3735928559, 'rbx': 93824992238128, 'rcx': 0, 'rdx': 40, 'rsi': 93824992237257, 'rdi': 0x55555555b8e0, 'rbp': 140737488347456, 'rsp': 140737488347432, 'r8': 10, 'r9': 0, 'r10': 140737353308864, 'r11': 0, 'r12': 93824992235824, 'r13': 140737488347776, 'r14': 0, 'r15': 0, 'rip': 3735928559, 'eflags': 66054, 'cs': 51, 'ss': 43, 'ds': 0, 'es': 0, 'fs': 0, 'gs': 0}
    classify_res = [[['0x0000000000151bb0 -> mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]'], ['0x000000000005b4d0 -> mov rsp, rdx ; ret']]]
    controble_addr_base = 0x55555555b310
    start = 0
    length = 0x400
    offset_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344]
    permission_table = [{'start': 93824992231424, 'end': 93824992235520, 'permission': 'r'}, {'start': 93824992235520, 'end': 93824992239616, 'permission': 'rx'}, {'start': 93824992239616, 'end': 93824992243712, 'permission': 'r'}, {'start': 93824992243712, 'end': 93824992247808, 'permission': 'r'}, {'start': 93824992247808, 'end': 93824992251904, 'permission': 'rw'}, {'start': 93824992251904, 'end': 93824992387072, 'permission': 'rw'}, {'start': 140737351610368, 'end': 140737351622656, 'permission': 'rw'}, {'start': 140737351622656, 'end': 140737351761920, 'permission': 'r'}, {'start': 140737351761920, 'end': 140737353302016, 'permission': 'rx'}, {'start': 140737353302016, 'end': 140737353621504, 'permission': 'r'}, {'start': 140737353621504, 'end': 140737353637888, 'permission': 'r'}, {'start': 140737353637888, 'end': 140737353646080, 'permission': 'rw'}, {'start': 140737353646080, 'end': 140737353662464, 'permission': 'rw'}, {'start': 140737353662464, 'end': 140737353670656, 'permission': 'r'}, {'start': 140737353670656, 'end': 140737353732096, 'permission': 'rx'}, {'start': 140737353732096, 'end': 140737353789440, 'permission': 'r'}, {'start': 140737353789440, 'end': 140737353793536, 'permission': ''}, {'start': 140737353793536, 'end': 140737353797632, 'permission': 'r'}, {'start': 140737353797632, 'end': 140737353801728, 'permission': 'rw'}, {'start': 140737353801728, 'end': 140737353809920, 'permission': 'rw'}, {'start': 140737353912320, 'end': 140737353928704, 'permission': 'r'}, {'start': 140737353928704, 'end': 140737353936896, 'permission': 'rx'}, {'start': 140737353936896, 'end': 140737353940992, 'permission': 'r'}, {'start': 140737353940992, 'end': 140737354084352, 'permission': 'rx'}, {'start': 140737354084352, 'end': 140737354117120, 'permission': 'r'}, {'start': 140737354121216, 'end': 140737354125312, 'permission': 'r'}, {'start': 140737354125312, 'end': 140737354129408, 'permission': 'rw'}, {'start': 140737354129408, 'end': 140737354133504, 'permission': 'rw'}, {'start': 140737488216064, 'end': 140737488351232, 'permission': 'rw'}, {'start': 18446744073699065856, 'end': 18446744073699069952, 'permission': 'x'}]
    print(solve_mem_gadget(regs,classify_res,controble_addr_base,offset_list, permission_table))





