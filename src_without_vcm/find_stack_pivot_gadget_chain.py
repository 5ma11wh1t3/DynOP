import re
from itertools import product
from triton import TritonContext, ARCH, MemoryAccess, CPUSIZE, Instruction
from pwn import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
Ks = Ks(KS_ARCH_X86, KS_MODE_64)
import multiprocessing
from functools import partial

def my_asm(gadget):
    return bytes(Ks.asm(gadget)[0])
context.arch = 'amd64'
def my_log(data,n):
    print("------------------------------------------------")
    for i in range(n):
        print(data[i])

# 过滤出结尾是jmp, call, ret的gadget
# syscall结尾的也过滤掉
def filler(data):
    # jmp_inst = ['loopne','je','jne','ja','jna','jae','jnae','jb','jnb','jbe','jnbe','jg','jng','jge','jnge','jl','jnl','jle','jnle','jz','jnz','js','jns','jc','jnc','jo','jno','jp','jnp','jpe','jpo','jcxz','jecxz','enter','fnsave']
    # for j in jmp_inst:
    #     if j in data:
    #         return False
    if "loop" in data or 'jrcxz' in data or 'notrack' in data:
        return False
    if "ret" == data.split(" ; ")[-1]:
        return True
    if "jmp" in data.split(" ; ")[-1] and "jmp 0x" not in data.split(" ; ")[-1]:
        return True
    if "call" in data.split(" ; ")[-1] and "call 0x" not in data.split(" ; ")[-1] and "syscall" not in data.split(" ; ")[-1]:
        return True
    return False
def load_gadget(gadgets_file):
    logger.debug("Load Gadget")
    # Read gadgets from file
    data = open(gadgets_file,'r').read()
    data = data.split('\n')
    gadgets = []
    for i in range(2,len(data)-3):
        gg = data[i].split(' : ')
        if filler(gg[1]):
            gadgets.append(gg)
    return gadgets

def parse_asm_line(line):
    # line = line.replace('retf','ret')
    # if 'ret ' in line:
    #     line = 'ret'
    # 定义指令集和操作模式
    operations = {
        'mov': ('dst', 'src'),
        'movzx': ('dst', 'src'),
        'movsx': ('dst', 'src'),
        'push': (None, 'src'),  # 特殊处理
        'pop': ('dst', None),    # 特殊处理
        
        'add': ('dst', 'src'),
        'sub': ('dst', 'src'),
        'mul': ('dst', 'src'),
        'imul': ('dst', 'src'),
        'div': ('dst', 'src'),
        'idiv': ('dst', 'src'),
        'inc': (None, 'src'),
        'dec': (None, 'src'),
        'neg': (None, 'src'),
        
        'and': ('dst', 'src'),
        'or': ('dst', 'src'),
        'xor': ('dst', 'src'),
        'not': (None, 'src'),
        'shl': ('dst', 'src'),
        'shr': ('dst', 'src'),
        'sal': ('dst', 'src'),
        'sar': ('dst', 'src'),
        
        'cmp': ('dst', 'src'),
        'test': ('dst', 'src'),
        'jmp': (None, 'src'),
        'je': (None, 'src'),
        'jne': (None, 'src'),
        'jg': (None, 'src'),
        'jl': (None, 'src'),
        'jge': (None, 'src'),
        'jle': (None, 'src'),
        'call': (None, 'src'),
        'ret': (None, None),
        'rep stosq': ('dst','src'),
        
        # 'leave': (None, None),
        'nop': (None, None),
        'lea': ('dst', 'src')
    }


    # 使用正则表达式提取指令和操作数
    if line == 'ret':
        return {
            "input": ["[rsp]"], 
            "operation": line, 
            "output": None, 
            "modified": ["rip"]
        }
    match = re.match(r"(\w+)\s+(.+)", line)
    if not match:
        return None
    
    operation = match.group(1).strip()
    operands = match.group(2).split(",")
    operands = [op.strip() for op in operands]

    if operation not in operations:
        return None

    # 获取指令的输入、输出操作数类型
    output_op, input_op = operations[operation]
    
    # 特殊处理 push 和 pop 指令
    if operation == 'push':
        return {
            "input": [operands[0]],
            "operation": operation, 
            "output": ["[rsp]"], 
            "modified": ["[rsp]"]
        }
    elif operation == 'pop':
        return {
            "input": ["[rsp]"], 
            "operation": operation, 
            "output": [operands[0]], 
            "modified": [operands[0]]
        }
    elif operation == 'cmp':
        return {
            "input": operands, 
            "operation": operation, 
            "output": None, 
            "modified": ["zf","sf","of"]
        }
    elif operation == 'test':
        return {
            "input": operands, 
            "operation": operation, 
            "output": None, 
            "modified": ["zf","sf"]
        }
    elif operation in ['jmp','je','jne','jg','jl','jge','jle','call','ret']:
        return {
            "input": operands, 
            "operation": operation, 
            "output": None, 
            "modified": ["rip"]
        }
    elif operation in ['inc','dec','neg','div','nop','idiv','mul','imul','not','bswap','clc','stc','cmc','hlt']:
        return {
            "input": operands[0], 
            "operation": operation, 
            "output": operands[0], 
            "modified": operands[0]
        }

    # 生成输入、输出、修改三元组
    # print(line)
    # print(operands)
    input_operands = [operands[1]]
    # print([operands[1]])
    output_operands = operands[0] if output_op == "dst" else None

    # 如果存在输出操作数，则将其视为被修改的寄存器或内存位置
    modified = output_operands

    # 确保所有三元组中的字段都有效
    return {"input": input_operands, "operation": operation, "output": output_operands, "modified": modified}
def sem(assembly_code):
    # 输出转换结果
    triplets = []
    for line in assembly_code:
        triplet = parse_asm_line(line)
        if triplet:
            triplets.append(triplet)

    # # 展示所有的三元组
    # for t in triplets=
    #     print(t=
    return triplets
def get_all_sematics(gadgets):
    logger.debug("Get All Sematics")
    sematics_list = {}
    for i in range(len(gadgets)):
        addr = gadgets[i][0]
        sematics = sem(gadgets[i][1].split(' ; '))
        # print(addr)
        # print(sematics)
        sematics_list[addr]=sematics
    return sematics_list

# [i_reg] -> o_reg
def v2r(lian, i_reg, o_reg):
    for i in range(len(lian)):
        if lian[i][0] != None and lian[i][1] != None:
            if i_reg in lian[i][0] and i_reg != lian[i][0] and o_reg == lian[i][1]:
                return True
    return False
# i_reg -> o_reg
def r2r(lian, i_reg, o_reg):
    for i in range(len(lian)):
        if lian[i][0] != None and lian[i][1] != None:
            if i_reg == lian[i][0] and o_reg == lian[i][1]:
                return True
    return False
# i_reg -> [o_reg]
def r2v(lian, i_reg, o_reg):
    for i in range(len(lian)):
        if lian[i][0] != None and lian[i][1] != None:
            if i_reg == lian[i][0] and o_reg in lian[i][1] and o_reg != lian[i][1]:
                return True
    return False
# [i_reg] -> [o_reg]
def v2v(lian, i_reg, o_reg):
    for i in range(len(lian)):
        if lian[i][0] != None and lian[i][1] != None:
            if i_reg in lian[i][0] and i_reg != lian[i][0] and o_reg in lian[i][1] and o_reg != lian[i][1]:
                return True
    return False
def i2r(lian, o_reg):
    for i in range(len(lian)):
        if lian[i][0] != None and lian[i][1] != None:
            try:
                if type(eval(lian[i][0])) == int and o_reg == lian[i][1]:
                    return True
            except:
                return False
    return False

def find(gadgets_dict,lians,controllable_reg,n,depth):
    global all_res
    if n > depth:
        return None
    else:
        regs = ['rax','rbx','rcx','rdx','rdi','rsi','r8','r9','r10','r11','r12','r13','r14','r15','rsp']
        tmp = []
        for addr, lian in lians.items():
            if len(lian) > 0:
                if n == 0 and controllable_reg not in lian[0][0]:
                    continue
                if (r2r(lian, controllable_reg, 'rsp') or v2r(lian, controllable_reg, 'rsp')) and (v2r(lian, 'rsp', 'rip') or v2r(lian, controllable_reg, 'rip')):
                    tmp.append(f"{addr} -> {gadgets_dict[addr]}")
                else:
                    for reg in regs:
                        if (((v2v(lian, controllable_reg, reg) or (r2v(lian, controllable_reg, reg))) and v2r(lian, reg, 'rsp')) or ((v2r(lian, controllable_reg, reg) or (r2r(lian, controllable_reg, reg))) and r2r(lian, reg, 'rsp'))) and (v2r(lian,controllable_reg,'rip') or r2r(lian,reg,'rip') or v2r(lian,reg,'rip')):
                            tmp.append(f"{addr} -> {gadgets_dict[addr]}")
                        else:
                            if (r2r(lian,controllable_reg,reg) or v2r(lian,controllable_reg,reg)) and (v2r(lian,controllable_reg,'rip') or r2r(lian,controllable_reg,'rip') or r2r(lian,reg,'rip') or v2r(lian,reg,'rip')):
                                res = [f"{addr} -> {gadgets_dict[addr]}"]
                                res1 = find(gadgets_dict,lians,reg,n+1,depth)
                                if res1 != None:
                                    res = [res] + res1
                                    if n == 0:
                                        all_res.append(res)
                                    else:
                                        return res
        if len(tmp) > 0: 
            return [tmp]
def find_thread(gadgets_dict,lians,controllable_reg,n,depth,lians_part,first_flag):
    global all_res
    if n > depth:
        return None
    else:
        if first_flag:
            lians_use = lians_part
            first_flag = False
        else:
            lians_use = lians
        regs = ['rax','rbx','rcx','rdx','rdi','rsi','r8','r9','r10','r11','r12','r13','r14','r15','rsp']
        tmp = []
        for addr, lian in lians_use.items():
            if len(lian) > 0:
                if n == 0 and controllable_reg not in lian[0][0]:
                    continue
                if (r2r(lian, controllable_reg, 'rsp') or v2r(lian, controllable_reg, 'rsp')) and (v2r(lian, 'rsp', 'rip') or v2r(lian, controllable_reg, 'rip')):
                    tmp.append(f"{addr} -> {gadgets_dict[addr]}")
                else:
                    for reg in regs:
                        if (((v2v(lian, controllable_reg, reg) or (r2v(lian, controllable_reg, reg))) and v2r(lian, reg, 'rsp')) or ((v2r(lian, controllable_reg, reg) or (r2r(lian, controllable_reg, reg))) and r2r(lian, reg, 'rsp'))) and (v2r(lian,controllable_reg,'rip') or r2r(lian,reg,'rip') or v2r(lian,reg,'rip')):
                            tmp.append(f"{addr} -> {gadgets_dict[addr]}")
                        else:
                            if (r2r(lian,controllable_reg,reg) or v2r(lian,controllable_reg,reg)) and (v2r(lian,controllable_reg,'rip') or r2r(lian,controllable_reg,'rip') or r2r(lian,reg,'rip') or v2r(lian,reg,'rip')):
                                res = [f"{addr} -> {gadgets_dict[addr]}"]
                                res1 = find_thread(gadgets_dict,lians,reg,n+1,depth,lians_part,first_flag)
                                if res1 != None:
                                    res = [res] + res1
                                    if n == 0:
                                        all_res.append(res)
                                    else:
                                        return res
        if len(tmp) > 0: 
            return [tmp]
def create_lians(sematics_list):
    logger.debug("Create Lians")
    # 单向
    lians = {}
    for addr, sema in sematics_list.items():
        edge = []
        for i in range(len(sema)):
            input = sema[i]['input']
            modified = sema[i]['modified']
            if type(modified) != list:
                modified = [modified]
            for j in range(len(input)):
                for k in range(len(modified)):
                    edge.append([input[j],modified[k]])    
        lians[addr] = edge
    return lians

def create_gadget_dict(gadgets):
    logger.debug("Create Gadget Dict")
    gadgets_dict = {}
    for i in range(len(gadgets)):
        gadgets_dict[gadgets[i][0]] = gadgets[i][1]
    return gadgets_dict

def find_thread_func(lians_part, gadgets_dict,lians,controllable_reg,n,depth,):
    global all_res
    all_res = []
    one_res = find_thread(gadgets_dict,lians,controllable_reg,n,depth,lians_part,True)

    if one_res!=None:
        for i in range(len(one_res[0])):
            all_res.append([[one_res[0][i]]])
    if len(all_res) == 0:
        return [one_res]
    return all_res

from loguru import logger

def stack_pivot_gadget_chain(gadgets_file,n = 0,depth = 1,controllable_reg = 'rdi', num_threads = 24):
    # logger.debug("Start find stack pivot gadget")
    logger.debug(f"Depth : {depth}")
    logger.debug(f"Controble Reg : {controllable_reg}")

    gadgets = load_gadget(gadgets_file)
    # print(gadgets)
    gadgets_dict = create_gadget_dict(gadgets)
    # print(gadgets_dict)
    sematics_list = get_all_sematics(gadgets)
    # print(sematics_list)
    lians = create_lians(sematics_list)

    flow_edges_list = list(lians.items())
    random.shuffle(flow_edges_list)  # 随机打乱

    # 计算每份的大小
    chunk_size = max(1, len(flow_edges_list) // num_threads)
    chunks = [
        dict(flow_edges_list[i*chunk_size:i*chunk_size+chunk_size])
        for i in range(num_threads)
    ]
    # print(lians)
    chunks[-1] = {**chunks[-1], **dict(flow_edges_list[chunk_size*num_threads:])}
    tmp = chunks[0]
    for i in range(len(chunks)-1):
        tmp = {**tmp, **chunks[i+1]}
    logger.debug("Start Find")

    find_func = partial(find_thread_func, gadgets_dict=gadgets_dict,lians=lians,controllable_reg=controllable_reg,n=n,depth=depth)
    dynaminc_params = [(_,) for _ in chunks]
    with multiprocessing.Pool(processes=num_threads) as pool:
        all_res_process = pool.starmap(find_func, dynaminc_params) 
    # print(all_res_process)
    res = []
    for i in range(len(all_res_process)):
        for j in range(len(all_res_process[i])):
            if all_res_process[i][j] == None:
                continue
            res.append(all_res_process[i][j])
    return res

def controble_reg_to_rip(mem_controllable_regs,lian):
    for r in mem_controllable_regs:
        if r2r(lian,r,'rip') or v2r(lian,r,'rip'):
            return True
def init_reg(ctx, regs):
    rs = ['rax','rbx','rcx','rdx','rdi','rsi','r8','r9','r10','r11','r12','r13','r14','r15','rbp','rsp']
    for reg in ctx.getAllRegisters():
        if reg.getName() in rs :
            ctx.setConcreteRegisterValue(reg, regs[reg.getName()])
    return ctx
def get_reg(ctx, reg_name):
    for reg in ctx.getAllRegisters():
        if reg.getName() == reg_name :
            return reg
def extract_reg(target_string):
    registers = ["rax", "eax", "ax", "ah", "al","rbx", "ebx", "bx", "bh", "bl","rcx", "ecx", "cx", "ch", "cl","rdx", "edx", "dx", "dh", "dl","rsi", "esi", "si", "sil","rdi", "edi", "di", "dil","rbp", "ebp", "bp", "bpl","rsp", "esp", "sp", "spl","r8", "r8d", "r8w", "r8b","r9", "r9d", "r9w", "r9b","r10", "r10d", "r10w", "r10b","r11", "r11d", "r11w", "r11b","r12", "r12d", "r12w", "r12b","r13", "r13d", "r13w", "r13b","r14", "r14d", "r14w", "r14b","r15", "r15d", "r15w", "r15b"]
    registers_pattern = r'\b(' + '|'.join(registers) + r'|0x[0-9a-fA-F]+|\d+)\b'
    matches = re.findall(registers_pattern, target_string)
    if 'jmp' in target_string or 'call' in target_string:
        matches = ['rip']+matches
    if 'ret' == target_string:
        matches = ['rip','rsp']
    return matches
    
if __name__ == "__main__":
    
    # gadgets_file = './gadget.txt'
    # gadgets_file = './llm/demo.txt'
    # gadgets_file = './gadget705.txt'
    # gadgets_file = '/home/rop/my-rop/src/705.txt'
    # gadgets_file = '../dataset/cve/ccb-2024-final-NFS-Heap/gadget.txt'
    gadgets_file = '../dataset/cve/cve-2022-42475/gadget.txt'
    n = 0
    depth = 1
    controllable_reg = 'rdx'
    all_res = stack_pivot_gadget_chain(gadgets_file,n,depth,controllable_reg)

    for i in range(len(all_res)):
        if all_res[i] == None:
            continue
        for a in product(*all_res[i]):
            for j in range(len(a)):
                print(a[j],end=" | ")
            print("\n",end='')
    print(all_res)