from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from triton import ARCH, TritonContext, MemoryAccess, CPUSIZE, Instruction
import os
import re
import itertools
def combine_multiple_arrays(*arrays):
    return list(itertools.product(*arrays))
def Analysis_reg(string):
    """
    {
        type: "value"/"mem_value"/"num", # 寄存器的值/寄存器指向的内存数据
        reg_name: str/[], # 字符串中的所有寄存器名
        bit:64/32/16/8, # 若type为寄存器的值，则填入寄存器的字节数;若type为mem_value，则填入写入内存的字节数
        expr:"", # 如果是表达式就将表达式提取出来
        }
    """
    general_purpose = ["rax", "eax", "ax", "al",
     "rbx", "ebx", "bx", "bl",
     "rcx", "ecx", "cx", "cl",
     "rdx", "edx", "dx", "dl",
     "rsi", "esi", "si", "sil",
     "rdi", "edi", "di", "dil",
     "rbp", "ebp", "bp", "bpl",
     "rsp", "esp", "sp", "spl",
     "r8", "r8d", "r8w", "r8b",
     "r9", "r9d", "r9w", "r9b",
     "r10", "r10d", "r10w", "r10b",
     "r11", "r11d", "r11w", "r11b",
     "r12", "r12d", "r12w", "r12b",
     "r13", "r13d", "r13w", "r13b",
     "r14", "r14d", "r14w", "r14b",
     "r15", "r15d", "r15w", "r15b","ah","bh","ch","dh",]
    beside_reg = ["ah","bh","ch","dh"]
    if string in general_purpose:
        type1 = "value"
        reg_name = general_purpose[general_purpose.index(string)//4*4]
        bit = 64 // (2**(general_purpose.index(string)%4))
        if string in beside_reg:
            reg_name = general_purpose[beside_reg.index(string)*4]
            bit = 8
        expr = ""
        return {"type":type1,"reg_name":reg_name,"bit":bit,"expr":expr}

    data_type = ['byte','word','dword','qword']
    if "[" in string:
        type1 = "mem_value"
        bit = 0
        for i in range(len(data_type)):
            if data_type[i] in string:
                bit = 8*(2**i)
        
        expr = string.split("[")[1].split("]")[0]
        if len(expr.split(" ")) != 1:
            reg_name = []
            for r in expr.split(" "):
                if r in general_purpose:
                    reg_name.append(r)
                    if bit == 0:
                        bit = 64 // (2**(general_purpose.index(r)%4))
        else:
            reg_name = [expr]
        if len(reg_name) == 1:
            reg_name = reg_name[0]
        return {"type":type1,"reg_name":reg_name,"bit":bit,"expr":expr}
    try:
        if type(eval(string)) == int:
            type1 = "num"
            return {"type":type1,"value":eval(string),"reg_name":"immediate_num"}
    except:
        return {"type":"no","reg_name":"no","bit":0,"expr":""}
def Analysis_op(op_str):
    op = op_str.split(" ")[0]
    if op == "mov" or op == "movsx" or op == "movsxd" or op == "movzx" or op == "movsb" or op == "movsw" or op == "movsd" or op == "movsq" or op == "movabs":
        dst = op_str[len(op)+1:op_str.index(", ")]
        src = op_str[op_str.index(", ")+2:]
        dst_reg = Analysis_reg(dst)
        src_reg = Analysis_reg(src)
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "push":
        src = op_str[len(op)+1:]
        src_reg = Analysis_reg(src)
        dst_reg = {"type":"mem_value","reg_name":"rsp","bit":64,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "pop":
        dst = op_str[len(op)+1:]
        dst_reg = Analysis_reg(dst)
        src_reg = {"type":"mem_value","reg_name":"rsp","bit":64,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op in ['inc','dec']:
        dst = op_str[len(op)+1:]
        dst_reg = Analysis_reg(dst)
        # src_reg = {"type":"mem_value","reg_name":"rsp","bit":64,"expr":""}
        return {"op":op,"src":dst_reg,"dst":dst_reg}
    elif op == "pusha":
        # print(f"TODO: {op}")
        pass
    elif op == "popa":
        # print(f"TODO: {op}")
        pass
    elif op == "pushad":
        # print(f"TODO: {op}")
        pass
    elif op == "popad":
        # print(f"TODO: {op}")
        pass
    elif op == "xchg":
        dst = op_str[len(op)+1:op_str.index(", ")]
        src = op_str[op_str.index(", ")+2:]
        dst_reg = Analysis_reg(dst)
        src_reg = Analysis_reg(src)
        return [{"op":op,"src":src_reg,"dst":dst_reg},{"op":op,"src":dst_reg,"dst":src_reg}]
    elif op == "lea":
        dst = op_str[len(op)+1:op_str.index(", ")]
        src = op_str[op_str.index(", ")+2:]
        dst_reg = Analysis_reg(dst)
        src_reg = Analysis_reg(src)
        src_reg["type"] = "value"
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "lahf":
        # dst_reg = {"type":"value","reg_name":"ah","bit":8,"expr":""}
        # src_reg = {"type":"value","reg_name":"rflags","bit":8,"expr":""}
        # return {"op":op,"src":src_reg,"dst":dst_reg}
        pass
    elif op == "sahf":
        # dst_reg = {"type":"value","reg_name":"rflags","bit":8,"expr":""}
        # src_reg = {"type":"value","reg_name":"ah","bit":8,"expr":""}
        # return {"op":op,"src":src_reg,"dst":dst_reg}
        pass
    elif op == "pushfq":
        dst_reg = {"type":"mem_value","reg_name":"rsp","bit":64,"expr":""}
        src_reg = {"type":"value","reg_name":"rflags","bit":64,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
        pass
    elif op == "popfq":
        dst_reg = {"type":"value","reg_name":"rflags","bit":64,"expr":""}
        src_reg = {"type":"mem_value","reg_name":"rsp","bit":64,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
        pass
    elif op == "pushd":
        # dst_reg = {"type":"mem_value","reg_name":"rsp","bit":64,"expr":""}
        # src_reg = {"type":"value","reg_name":"rflags","bit":32,"expr":""}
        # return {"op":op,"src":src_reg,"dst":dst_reg}
        pass
    elif op == "popd":
        # dst_reg = {"type":"value","reg_name":"rflags","bit":32,"expr":""}
        # src_reg = {"type":"mem_value","reg_name":"rsp","bit":64,"expr":""}
        # return {"op":op,"src":src_reg,"dst":dst_reg}
        pass
    elif op == "add" or op == "adc":
        dst = op_str[len(op)+1:op_str.index(", ")]
        src = op_str[op_str.index(", ")+2:]
        dst_reg = Analysis_reg(dst)
        src_reg = Analysis_reg(src)
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "and" or op == "or":
        dst = op_str[len(op)+1:op_str.index(", ")]
        src = op_str[op_str.index(", ")+2:]
        dst_reg = Analysis_reg(dst)
        if dst_reg['type'] == 'mem_value':
            src_reg = Analysis_reg(src)
            return {"op":op,"src":src_reg,"dst":dst_reg}
        else:
            pass
    elif op == "xor":
        dst = op_str[len(op)+1:op_str.index(", ")]
        src = op_str[op_str.index(", ")+2:]
        dst_reg = Analysis_reg(dst)
        src_reg = Analysis_reg(src)
        if dst == src:
            src_reg = {"type":"num","value":0,"reg_name":"immediate_num"}
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "sub" or op == "sbb":
        dst = op_str[len(op)+1:op_str.index(", ")]
        src = op_str[op_str.index(", ")+2:]
        dst_reg = Analysis_reg(dst)
        src_reg = Analysis_reg(src)
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "cmp" or op == "test":
        pass
        # dst = op_str[len(op)+1:op_str.index(", ")]
        # src = op_str[op_str.index(", ")+2:]
        # src_reg = {"type":"value","reg_name":"rflags","bit":64,"expr":""}
        # dst_reg = [dst,src]
        # return {"op":op,"src":dst_reg,"dst":dst_reg}
    elif op == "mul" or op == "div" or op == "idiv":
        src = op_str[len(op)+1:]
        src_reg = Analysis_reg(src)
        dst_reg1 = {"type":"value","reg_name":"rax","bit":64,"expr":""}
        dst_reg2 = {"type":"value","reg_name":"rdx","bit":64,"expr":""}
        return [{"op":op,"src":src_reg,"dst":dst_reg1},{"op":op,"src":src_reg,"dst":dst_reg2}]
    elif op == "imul":
        # if len(op_str.split(", ")) == 1:
        #     src = op_str[len(op)+1:]
        #     src_reg = Analysis_reg(src)
        #     dst_reg1 = {"type":"value","reg_name":"rax","bit":64,"expr":""}
        #     dst_reg2 = {"type":"value","reg_name":"rdx","bit":64,"expr":""}
        #     return [{"op":op,"src":src_reg,"dst":dst_reg1},{"op":op,"src":src_reg,"dst":dst_reg2}]
        # elif len(op_str.split(", ")) == 2:
        #     dst = op_str[len(op)+1:op_str.index(", ")]
        #     src = op_str[op_str.index(", ")+2:]
        #     dst_reg = Analysis_reg(dst)
        #     src_reg = Analysis_reg(src)
        #     return {"op":op,"src":src_reg,"dst":dst_reg}
        # elif len(op_str.split(", ")) == 3:
        #     dst = op_str[len(op)+1:op_str.index(", ")]
        #     src = op_str.split(", ")[1]
        #     dst_reg = Analysis_reg(dst)
        #     src_reg = Analysis_reg(src)
        #     return {"op":op,"src":src_reg,"dst":dst_reg}
        pass
    elif op == "not":
        src = op_str[len(op)+1:]
        src_reg = Analysis_reg(src)
        return {"op":op,"src":src_reg,"dst":src_reg}
    elif op == "cdq":
        src_reg = {"type":"value","reg_name":"rax","bit":32,"expr":""}
        dst_reg = {"type":"value","reg_name":"rdx","bit":32,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
        # pass
    elif op == "shl" or op == "sal" or op == "shr" or op == "sar":
        dst = op_str[len(op)+1:op_str.index(", ")]
        src = op_str.split(", ")[1]
        dst_reg = Analysis_reg(dst)
        src_reg = Analysis_reg(src)
        return {"op":op,"src":src_reg,"dst":dst_reg}
    # elif op == "rol" or op == "ror" or op == "rcl" or op == "rcr":
    #     pass
    elif op == "call" or op == "jmp":
        pass
        # src = op_str[len(op)+1:]
        # src_reg = Analysis_reg(src)
        # dst_reg = {"type":"value","reg_name":"rip","bit":64,"expr":""}
        # return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "ret" or op == "retf":
        pass
        # src_reg = {"type":"mem_value","reg_name":"rsp","bit":64,"expr":""}
        # dst_reg = {"type":"value","reg_name":"rip","bit":64,"expr":""}
        # return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "leave":
        src_reg = {"type":"value","reg_name":"rbp","bit":64,"expr":""}
        dst_reg = {"type":"value","reg_name":"rsp","bit":64,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op in ['rep','repe','repz','repne','repnz','repc','repnc','loop','loope','loopz','loopne','loopnz','jcxz','jecxz']:
        pass
        # if op_str.split(" ")[1] in ["ret","retf"]:
        #     src_reg = {"type":"mem_value","reg_name":"rsp","bit":64,"expr":""}
        #     dst_reg = {"type":"value","reg_name":"rip","bit":64,"expr":""}
        #     return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "stosb":
        src_reg = {"type":"value","reg_name":"rax","bit":8,"expr":""}
        dst_reg = {"type":"mem_value","reg_name":"rdi","bit":8,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "stosw":
        src_reg = {"type":"value","reg_name":"rax","bit":16,"expr":""}
        dst_reg = {"type":"mem_value","reg_name":"rdi","bit":16,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "stosd":
        src_reg = {"type":"value","reg_name":"rax","bit":32,"expr":""}
        dst_reg = {"type":"mem_value","reg_name":"rdi","bit":32,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
    elif op == "stosq":
        src_reg = {"type":"value","reg_name":"rax","bit":64,"expr":""}
        dst_reg = {"type":"mem_value","reg_name":"rdi","bit":64,"expr":""}
        return {"op":op,"src":src_reg,"dst":dst_reg}
    else:
        # print(f"TODO: {op}")
        pass
    return None
def Analysis_rip(gadget):
    gadget_list = gadget.split(" ; ")
    # push reg ; ret
    if 'ret' in gadget_list[-1]:
        push_idx = []
        for i in range(len(gadget_list)):
            if 'push' in gadget_list[i]:
                push_idx.append(i)
        pop_num = 0
        if len(push_idx) > 0:
            for j in range(push_idx[0],len(gadget_list)):
                if 'pop' in gadget_list[j]:
                    pop_num += 1
            if (len(push_idx)-pop_num) % 2 == 1:
                rip_reg = Analysis_op(gadget_list[push_idx[-1]])['src']['reg_name']
                return {"reg_name":rip_reg,'bit':64,"type":"value",'expr':""}
    rip_reg = Analysis_gadget(gadget)
    if rip_reg == False:
        return False
    elif len(rip_reg['hijack_reg']) == 0:
        return False
    else:
        rip_reg = rip_reg['hijack_reg'][0]
    return rip_reg
def Analysis_condition_jmp(gadget_str):
    condition_reg = []
    gadgets = gadget_str.split(" ; ")
    for i in range(len(gadgets)):
        op = gadgets[i]
        # 不循环 rcx=0 ['rep','repe','repz','repne','repnz','repc','repnc','loop','loope','loopz','loopne','loopnz','jcxz','jecxz']
        if op.split(" ")[0] in ['rep','repe','repz','repne','repnz','repc','repnc','loop','loope','loopz','loopne','loopnz','jcxz','jecxz']:
            condition_reg.append({'reg_name':"rcx",'bit':64})
        # 不跳转 test+跳转 cmp+跳转 ['je', 'js', 'jle', 'ja', 'jg', 'jbe', 'jne']
        # if op.split(" ")[0] in ['je', 'js', 'jle', 'ja', 'jg', 'jbe', 'jne']:
        #     condition_reg.append({'reg_name':"rcx",'bit':64})
        if i != len(gadgets)-1:
            if "test" in gadgets[i] or "cmp" in gadgets[i]:
                if len(gadgets[i+1].split(" "))==2 and "0x" == gadgets[i+1].split(" ")[1][:2]:
                    inst_length = len(gadgets[i].split(" ")[0])
                    dst = gadgets[i][inst_length+1:gadgets[i].index(", ")]
                    src = gadgets[i].split(", ")[1]
                    dst_reg = Analysis_reg(dst)
                    src_reg = Analysis_reg(src)
                    if dst_reg['type'] == "value":
                        condition_reg.append({"reg_name":dst_reg['reg_name'],'bit':dst_reg['bit']})
                    if src_reg['type'] == "value":
                        condition_reg.append({"reg_name":src_reg['reg_name'],'bit':src_reg['bit']})
    return condition_reg  
def Analysis_gadget(gadget_str):
    regs_change_log = {
    "rax":[],
    "rbx":[],
    "rcx":[],
    "rdx":[],
    "rsi":[],
    "rdi":[],
    "rbp":[],
    "rsp":[],
    "r8":[],
    "r9":[],
    "r10":[],
    "r11":[],
    "r12":[],
    "r13":[],
    "r14":[],
    "r15":[],
    "rflags":[]}
    can_change_regs = []
    hijack_reg = []
    valid_mem_reg = []
    condition_reg = Analysis_condition_jmp(gadget_str)

    gadgets = gadget_str.split(" ; ")
    op_res = []
    for i in range(len(gadgets)):
        op = gadgets[i]
        res = Analysis_op(op)
        if res != None:
            if type(res) != list:
                op_res.append(res)
            else:
                op_res = op_res + res
    # print(op_res)
    
    for i in range(len(op_res)):
        first_op_an = op_res[0]
        op_an = op_res[i]
        if i > 0 and op_an['dst']['reg_name'] == first_op_an['dst']['reg_name'] and op_an['dst']['reg_name']!='rsp':
            return False
        if op_an['dst']['type'] == "value":
            # for k in range(len(regs_change_log[first_op_an['dst']['reg_name']])):
                # if regs_change_log[op_an['dst']['reg_name']][k]['bit'] < first_op_an['dst']['bit']:
                    # return False
            tmp_op = op_an['dst']
            tmp_op['src_reg'] = op_an['src']['reg_name']
            tmp_op['src_type'] = op_an['src']['type']
            regs_change_log[op_an['dst']['reg_name']].append(tmp_op)
        if op_an['dst']['type'] == "mem_value":
            valid_mem_reg.append(op_an['dst'])
        if op_an['src']['type'] == "mem_value":
            valid_mem_reg.append(op_an['src'])

    for r, l in regs_change_log.items():
        if len(l) != 0:
            for i in range(len(l)):
                can_change_regs.append({'reg_name':l[i]['reg_name'],'bit':l[i]['bit'],'src_reg':l[i]['src_reg'],'src_reg_type':l[i]['src_type'],'type':l[i]['type']})
    
    # print(can_change_regs)
    
    last_inst = gadgets[-1]
    if "ret" in last_inst:
        # reg_name = 'rsp'
        # can_change_regs_name = [_['reg_name'] for _ in can_change_regs]
        # if 'rsp' in can_change_regs_name:
        #     reg_name_src = can_change_regs[can_change_regs_name.index('rsp')]
        #     if reg_name_src['src_reg'] != 'immediate_num':
        #         reg_name = reg_name_src['src_reg']
        # hijack_reg.append({"reg_name":reg_name,'bit':64,"type":"mem_value",'expr':"rsp"})
        hijack_reg.append({"reg_name":"rsp",'bit':64,"type":"mem_value",'expr':"rsp"})

    elif "call" in last_inst.split(" ") or "jmp" in last_inst.split(" "):
        inst_length = len(last_inst.split(" ")[0])
        reg_info = Analysis_reg(last_inst[inst_length+1:])
        rip_type = reg_info['type']
        # print(last_inst)
        # print(reg_info)
        reg_name = reg_info['reg_name']
        if len(reg_name) == 0:
            reg_name = ["no_reg"]
        if type(reg_name) == list:
            reg_name = reg_name[0]
        can_change_regs_name = [_['reg_name'] for _ in can_change_regs]
        if reg_name in can_change_regs_name:
            reg_name_src = can_change_regs[can_change_regs_name.index(reg_name)]
            if reg_name_src['type'] == 'value':
                can_change_regs.pop(can_change_regs_name.index(reg_name))
            reg_name = reg_name_src['src_reg']
            rip_type = reg_name_src['src_reg_type']
        hijack_reg.append({"reg_name":reg_name,'bit':64,'type':rip_type,'expr':reg_info['expr']})
    
    return {'can_change_regs':can_change_regs,'hijack_reg':hijack_reg,'valid_mem_reg':valid_mem_reg,'condition_reg':condition_reg}
def filler(gadgets):
    dele_op1 = ['xlatb', 'outsd', 'in', 'enter', 'out', 'loope', 'fld', 'hlt', 'endbr64', 'fisttp', 'loop', 'ud0', 'div', 'fdivr', 'fsubr', 'loopne', 'ficomp', 'fcomp', 'int1', 'insb', 'fimul', 'fucompi', 'lar', 'ficom', 'idiv', 'sldt', 'jrcxz', 'sgdt', 'fild', 'fidivr', 'fnsave', 'fldenv', 'fbld', 'fincstp', 'outsb', 'bnd', 'fxch', 'fdiv', 'fadd', 'faddp', 'fbstp', 'fcos', 'fdivrp', 'fiadd', 'fidiv', 'fistp', 'fisub', 'fmul', 'fnstcw', 'fnstenv', 'fsqrt', 'fst', 'fstp', 'fstpnce', 'fsub', 'fsubp', 'insd', 'psubsb', 'vandpd', 'vpsubsb', 'wrmsr', 'fcom', 'fnstsw', 'frstor', 'vshufpd', 'addps', 'addsd', 'cvtsi2sd', 'fucomi', 'bndldx', 'cvtpi2ps', 'fsubrp', 'fcmove', 'fcmovnb', 'fcmovu', 'fdivp', 'fist', 'fisubr', 'vminps', 'str', 'fsin', 'cvttps2pi', 'subps', 'cvttsd2si', 'subsd', 'vpsadbw', 'cmpps', 'fcmovb', 'fsincos', 'vpshufb', 'lgdt', 'fldz', 'fcmovne', 'fldcw', 'jecxz', 'fyl2xp1', 'pinsrw', 'ffreep', 'fcomi', 'fcompi', 'vpsubsw', 'fscale', 'fldpi', 'fcmovnbe', 'fcompp', 'fdecstp', 'fdisi8087_nop', 'ffree', 'mulps', 'fldl2e', 'fpatan', 'fprem1', 'frndint', 'fucom', 'fucomp', 'fucompp', 'psubusw', 'fxtract', 'lsl', 'maskmovq', 'vpaddsb', 'vmread', 'pmulhuw', 'psadbw', 'vpmaxub', 'sidt', 'vcmpps', 'vcvtsi2sd', 'vcvtsi2ss', 'vfixupimmpd', 'vmovapd', 'vpaddsw', 'xabort', 'xbegin', 'xsavec', 'cvtps2pd', 'vpmulhuw', 'paddsw', 'vucomisd', 'divss', 'cvtsi2ss', 'addss', 'crc32', 'cvtdq2ps', 'divps', 'fldl2t', 'fmulp', 'fyl2x', 'outsw', 'pushf', 'sqrtps', 'vcmppd', 'fcmovbe', 'ucomiss', 'vmulpd', 'btc', 'paddusw', 'punpcklbw', 'vmovhps', 'fld1', 'fcmovnu', 'rdpmc', 'vminsd', 'ud2', 'fnop', 'vhaddpd', 'vpsrld', 'comiss', 'rdmsr', 'vhsubpd', 'vpavgb', 'ucomisd', 'mulsd', 'maxsd', 'sqrtsd', 'divsd', 'cmpnltsd', 'minps', 'maxps', 'insw', 'cmpnltps', 'minsd', 'fptan', 'psubsw', 'vpaddusw', 'vaddps', 'ftst', 'cvtps2pi', 'femms', 'fabs', 'fchs', 'vrsqrtss', 'shufps', 'emms', 'bndstx', 'xend', 'xacquire', 'psubusb', 'rsqrtps', 'vandps', 'vmovlps', 'vaddsubpd', 'vpmaxud', 'cvttss2si', 'lcall', 'ltr', 'fsetpm', 'vmulss', 'mulss', 'paddsb', 'maxss', 'vmulps', 'subss', 'fxam', 'vaddss', 'fldln2', 'cldemote', 'vpackuswb', 'f2xm1', 'fnclex', 'fprem', 'lmsw', 'vpsrlq', 'vunpckhpd', 'vshufps', 'rcpps', 'rsm', 'ud1', 'vcvtss2sd', 'vhsubps', 'vmwrite', 'vorpd', 'vpminsd', 'vpsubusb', 'vsubpd', 'xrelease', 'vorps', 'sha1msg2', 'vsubps', 'cmpeqps', 'vsubsd', 'vpermilps', 'punpckldq', 'vfnmaddss', 'lldt', 'sysexit', 'vmaxpd', 'fninit', 'vxorpd', 'feni8087_nop', 'fldlg2', 'getsec', 'lgs', 'paddusb', 'punpcklwd', 'vaddsd', 'vmulsd', 'vpavgw', 'vpcmpestrm', 'vpsllq', 'vunpcklps', 'pcmpistri', 'pcmpestri', 'vpcmpistri', 'ljmp', 'pi2fd', 'rdrand', 'cvtpd2ps', 'sqrtss', 'cvtsd2si', 'vandnps', 'vpunpckhbw', 'vminpd', 'prefetchwt1', 'vandnpd', 'xtest', 'vmaskmovdqu', 'vpmuludq', 'vpinsrw', 'vcvtps2pd', 'vpshufhw', 'vaddpd', 'cmpltsd', 'cmpltps', 'vpblendw', 'vfnmadd213ps', 'vdivsd', 'vpaddusb', 'vpmaxsw', 'vpslld', 'lss', 'vmovshdup', 'swapgs', 'cmpeqpd', 'cmpeqsd', 'cmpeqss', 'vphsubw', 'pswapd', 'vfmaddsd', 'mulpd', 'vcmpltsd', 'vmaxsd', 'cvtsd2ss', 'vfmaddss', 'roundsd', 'roundss', 'vldmxcsr', 'vcmpgtsd', 'vfmsubsd', 'minss', 'vfmadd213sd', 'vfmadd213ss', 'vpsubusw', 'addpd', 'vcvttsd2si', 'vhaddps', 'cvtss2si', 'vzeroupper', 'vfnmaddsd', 'vminss', 'vcvtss2si', 'vcvtusi2ss', 'vdivps', 'vstmxcsr', 'xsaves', 'smsw', 'vunpckhps', 'vcmptruesd', 'vmovlpd', 'lfs', 'psignb', 'rdseed', 'vcmpeq_ospd', 'vcmpneqpd', 'comisd', 'vdivpd', 'vaddsubps', 'xrstor', 'vcvtsd2ss', 'vmaxps', 'vfmadd231ps', 'rdtscp', 'vcvtsd2si', 'cvtss2sd', 'vpaddq', 'vunpcklpd', 'vmovhpd', 'vpminsw', 'vsqrtsd', 'vcmpsd', 'vpmovsxbd', 'vfmaddsubps', 'vsubss', 'pi2fw', 'vpalignr', 'vmovddup', 'xgetbv', 'vmlaunch', 'vfnmsub231ss', 'vmcall', 'phaddw', 'vblendpd', 'vmovss', 'vmovdqu64', 'vpbroadcastd', 'vpbroadcastq', 'vpminud', 'vmovdqa64', 'rdpkru', 'wrpkru', 'vzeroall', 'aesdeclast', 'aesenclast', 'vinserti128', 'aesdec', 'aesenc', 'vaesenc', 'aesimc', 'vmovdqa32', 'vpclmulqdq', 'adox', 'vmovdqu32', 'vpermd', 'pclmulqdq', 'vpminsq', 'vbroadcasti128', 'vpxord', 'vporq', 'vpandq', 'vdivss', 'vcmptruepd', 'xsaveopt', 'vfmsubadd213pd', 'vcmpngtss', 'xcryptecb', 'xcryptcfb', 'xcryptofb', 'xstore', 'xsha1', 'xsha256', 'vfnmsub213pd', 'vcmpeqss', 'vcmple_oqss', 'vmresume', 'vcmpneqss', 'vcmpss', 'vfmsubadd231pd', 'vcmpeqpd', 'vcmpeqps', 'vcmpltss', 'enclv', 'kandnb', 'lidt', 'vcmpleps', 'vmptrld', 'vcmpnle_uqss', 'vcmpge_oqss', 'vcmpeq_uqss', 'vcmpfalsess', 'vcmpnge_uqss', 'vcmpeqsd', 'vcmptruess', 'vfnmsub213sd', 'vpermi2pd', 'vpcomnequb', 'clac', 'vfnmadd213pd', 'vcvtpd2ps', 'vextractps', 'vfnmadd132sd', 'vfmadd231sd', 'vfnmadd213sd', 'vfnmadd231sd', 'vfmadd132pd', 'vcomisd', 'vcomiss', 'vfmadd132sd', 'vcmplesd', 'vfmsub132sd', 'vucomiss', 'kandnw', 'kxorw', 'vpermilpd', 'vpmacsww', 'vmaskmovps', 'vpminsb', 'vcmptrue_ussd', 'vphaddd', 'vrcpss', 'vdppd', 'monitor', 'vgf2p8affineqb', 'vmovsldup', 'pmaddubsw', 'phsubw', 'subpd', 'shufpd', 'vpmulhrsw', 'kmovw', 'vcmpnleps', 'pfrcpit2', 'umonitor', 'vmaxss', 'vfmadd231ss', 'vmovhlps', 'vmovlhps', 'vaesdec', 'vcmpunord_ssd', 'vpmaskmovq', 'vlddqu', 'xrstors', 'vpxorq', 'kmovq', 'vaesenclast', 'vpternlogq', 'vpmacssww', 'wrssd', 'wrssq', 'mwaitx', 'kaddw', 'pconfig', 'vpermil2ps', 'vphaddw', 'vpmaxuw', 'vpsignb', 'vmptrst', 'vpmadcswd', 'vsqrtpd', 'pmulhrw', 'cvttps2dq', 'cvttpd2dq', 'cvtdq2pd', 'vcvtpd2dq', 'vmovupd', 'vpmaxsb', 'vpermpd', 'vdpps', 'vptestnmw', 'pabsw', 'vfnmadd213ss', 'vpblendd', 'vpinsrb', 'vpmaddubsw', 'vfmsubps', 'vfmaddsubpd', 'vcmpeq_uqps', 'vcmpltpd', 'vfmsubaddps', 'vcmpunordsd', 'vfmadd132ss', 'vsqrtss', 'pfcmpge', 'pfcmpgt', 'vphsubsw', 'encls', 'invlpga', 'vmfunc', 'xsave', 'stgi', 'mwait', 'invvpid', 'vmclear', 'vmxoff', 'xsetbv', 'phsubsw', 'vpsllvd', 'vfmaddps', 'invept', 'pavgusb', 'vfnmsubsd', 'vmxon', 'skinit', 'stac', 'blcfill', 'sha1nexte', 'cmpneqss', 'pfcmpeq', 'pfmin', 'vfnmaddps', 'pf2iw', 'phaddd', 'vblendps', 'vroundps', 'vpmacswd', 'vroundss', 'vpabsb', 'cvttpd2pi', 'cmpltss', 'vfnmadd132ss', 'vphsubd', 'vpackusdw', 'vfmadd213pd', 'phaddsw', 'psignw', 'sha256rnds2', 'vfnmsub231ps', 'invpcid', 'pfnacc', 'fxrstor64', 'vpmuldq', 'vaesdeclast', 'kaddb', 'monitorx', 'vrsqrtps', 'vpermps', 'vcmpngtpd', 'vcvttss2si', 'vphaddsw', 'vsqrtps', 'vpermi2ps', 'vmload', 'vpminuw', 'vfmsubss', 'vfmadd132ps', 'vfmsub231ps', 'vfnmsub132ss', 'cvtpd2pi', 'vcvttpd2dq', 'vpmulld', 'vcmple_oqps', 'cmpnltss', 'divpd', 'clzero', 'sqrtpd', 'pfmul', 'pfadd', 'cmpltpd', 'pfacc', 'vblendmps', 'pfmax', 'vpblendmb', 'vcmpneq_usss', 'vmovntpd', 'vfmaddsub132pd', 'clflushopt', 'vfmsub213ps', 'vpshuflw', 'kmovb', 'vmovntps', 'vfmaddsub213pd', 'vmrun', 'vpmovsxwq', 'vpmacsswd', 'vcvtps2ph', 'vcvtph2ps', 'cvtps2dq', 'movntdqa', 'vfmsubadd132pd', 'cvtpd2dq', 'vfmsub231sd', 'minpd', 'pfpnacc', 'vfnmadd231ps', 'vmovmskps', 'vfnmaddpd', 'vfnmsub231pd', 'vrcp14pd', 'vinsertf128', 'vcvtdq2pd', 'enclu', 'vcmpnltsd', 'cmpnltpd', 'maxpd', 'vfnmsubps', 'phsubd', 'rdsspq', 'rstorssp', 'saveprevssp', 'incsspq', 'vcmpeq_osss', 'vrcpps', 'vpabsw', 'vextractf128', 'vpperm', 'pmulhrsw', 'vphaddwq', 'pf2id', 'vpbroadcastw', 'vphadddq', 'vphadduwq', 'vpmacsdql', 'pmuldq', 'packusdw', 'pblendw', 'psignd', 'vpsignd', 'mpsadbw', 'vcvtps2dq', 'vperm2f128', 'addsubps', 'haddps', 'pfrcp', 'vcmpgt_oqpd', 'endbr32', 'vpdpbusd', 'vscalefpd', 'vpord', 'vpmacssdql', 'sha1rnds4', 'vmmcall', 'vpinsrq', 'vrangepd', 'vpandnq', 'vpmullq', 'vpmaskmovd', 'vcmptrue_uspd', 'maskmovdqu', 'clgi', 'cvtpi2pd', 'kxnorw', 'vcmpneq_oqpd', 'pext', 'vcvttps2dq']
    dele_op2 = ['pushf','qword ptr fs:[0x28]','iretd','iretq',"rol","ror","rcl","rcr","sysretq","sysret","notrack", 'scasb','scasw','scasw','scasd','scasq','cmpsb','cmpsw','cmpsd','cmpsq', "fs:"]
    gadgets = gadgets.split(" ; ")
    tail = gadgets[-1].split(" ")
    if len(gadgets) == 1 and gadgets[0]!='ret':
        return False
    if len(tail) == 2 and "0x" == tail[-1][:2]:
        return False
    for i in range(len(gadgets)):
        op = gadgets[i].split(" ")[0]
        if op in dele_op1:
            return False
        for j in dele_op2:
            if j in gadgets[i]:
                return False
    return True
def load_gadget(gadgets_file):
    data = open(gadgets_file,'r').read()
    data = data.split('\n')
    gadgets = []
    for i in range(2,len(data)-3):
        gg = data[i].split(' : ')
        if filler(gg[1]):
            gadgets.append(gg)
    return gadgets
def create_gadget_dict(gadgets):
    gadgets_dict = {}
    for i in range(len(gadgets)):
        gadgets[i][1] = gadgets[i][1].replace("call ptr","call qword ptr")
        gadgets[i][1] = gadgets[i][1].replace("jmp ptr","jmp qword ptr")

        gadgets_dict[gadgets[i][0]] = gadgets[i][1]
    return gadgets_dict
def my_asm(gadget):
    """将汇编指令转换为字节码"""
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    try:
        asm_res = bytes(ks.asm(gadget)[0])
    except:
        print(f"DEBUG {gadget}")
        op = gadget.split(" ")[0]
        x86_64_conditional_jump_instructions = [
    # 相等/不相等判断
    "je", "jz", "jne", "jnz",
    # 无符号数比较
    "ja", "jnbe", "jae", "jnb", "jb", "jnae", "jbe", "jna",
    # 有符号数比较
    "jg", "jnle", "jge", "jnl", "jl", "jnge", "jle", "jng",
    # 标志位直接判断
    "jp", "jpe", "jnp", "jpo", "jc", "jnc", "jo", "jno", "js", "jns", "jh", "jnh",
    # 计数器寄存器判断
    "jcxz", "jecxz", "jrcxz"
]
        if op in x86_64_conditional_jump_instructions:
            gadget = op + " 0xdeadbeef"
        asm_res = bytes(ks.asm(gadget)[0])
    return asm_res

def my_log(data, n):
    """打印日志信息"""
    print("------------------------------------------------")
    for i in range(n):
        print(data[i])

def controllable_mem_distributor(gadgets_info, address_map, now_gadget, mem_type):
    """内存分配器，对可控内存进行统一管理"""
    if mem_type == "rip_mem":
        (my_virtual_mem_start, my_virtual_mem_length) = gadgets_info.my_virtual_mem_info
        for mem_addr in range(my_virtual_mem_start, my_virtual_mem_start + my_virtual_mem_length, 8):
            if mem_addr not in gadgets_info.used_virtual_mem:
                return mem_addr

def addr_in_range(addr, mem_dict_list):
    """检查地址是否在指定内存范围内"""
    addr_n = eval(addr)
    for i in range(len(mem_dict_list)):
        start_addr = eval(mem_dict_list[i]['start_addr'])
        length = mem_dict_list[i]['length']
        if addr_n >= start_addr and addr_n <= start_addr + length:
            return True
    return False

def table_check(addr, permission_table, mode):
    """检查地址是否具有指定权限"""
    for i in range(len(permission_table)):
        if addr >= permission_table[i]['start'] and addr < permission_table[i]['end']:
            if mode in permission_table[i]['permission']:
                return True
    return False

def read_write_check(instruction, permission_table):
    """检查指令的内存读写权限"""
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

def my_max(gadgets_info, address_map):
    """获取地址映射中的最大索引（排除虚拟内存区域）"""
    my_virtual_mem_start = gadgets_info.my_virtual_mem_info[0]
    tmp = []
    for a, v in address_map.items():
        if a < (my_virtual_mem_start - gadgets_info.controble_addr_base) // 8:
            tmp.append(a)
    return max(tmp)

def check_asm(code):
    try:
        address = 0x100000
        ctx = TritonContext()
        ctx.setArchitecture(ARCH.X86_64)
        instruction = Instruction(address, my_asm(code))
        ctx.processing(instruction)
        rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
        if rip == 0:
            return False
        else:
            return True
    except:
        return False
def filer1():
    file_path = "/home/rop/my-rop/benchmark_experiment/benchmark_gadget_folders/"
    ff = os.listdir(file_path)
    operators = []
    dele_o = []

    for f0 in ff:
        file_path0 = os.path.join(file_path,f0)
        files = os.listdir(file_path0)
        
        for f in files:
            gadgets_file = os.path.join(file_path0,f)
            data = open(gadgets_file,'r').read()
            data = data.split('\n')
            
            for i in range(2,len(data)-3):
                gg = data[i].split(' : ')[1]
                asms = gg.split(" ; ")
                for j in range(len(asms)):
                    s = asms[j]
                    opera = s.split(" ")[0]
                    if opera not in operators and opera not in dele_o:
                        if j != len(asms)-1:
                            if check_asm(s):
                                operators.append(opera)
                            else:
                                dele_o.append(opera)
                        else:
                            operators.append(opera)
    print(operators)
    """
    ['adc', 'imul', 'and', 'iretd', 'jmp', 'add', 'or', 'cmp', 'cwde', 'call', 'je', 'xor', 'mov', 'sar', 'ret', 'lea', 'jae', 'movzx', 'sub', 'test', 'jle', 'shr', 'cmovne', 'sbb', 'stosd', 'jne', 'pop', 'nop', 'sete', 'retf', 'push', 'ror', 'popfq', 'jno', 'jbe', 'clc', 'not', 'cli', 'dec', 'sal', 'rol', 'repz', 'cmove', 'ja', 'jl', 'movsxd', 'syscall', 'shl', 'xchg', 'jg', 'int', 'sahf', 'cmova', 'movsx', 'pushfq', 'scasb', 'inc', 'wait', 'movsd', 'stc', 'js', 'movabs', 'cdq', 'cmpsd', 'movsb', 'jo', 'lahf', 'lodsd', 'rcl', 'cmpsb', 'lodsb', 'sti', 'movsq', 'setge', 'jb', 'repe', 'rep', 'cmovs', 'jns', 'leave', 'jge', 'std', 'stosb', 'lock', 'cdqe', 'cld', 'cmovg', 'setne', 'scasd', 'neg', 'rcr', 'repne', 'jnp', 'lodsq', 'jp', 'bswap', 'pcmpeqd', 'cmc', 'cmovns', 'cmpxchg', 'mul', 'movhps', 'pmullw', 'por', 'seta', 'setg', 'stosq', 'cmovb', 'wbinvd', 'sysret', 'setle', 'notrack', 'bsr', 'cmovl', 'cpuid', 'paddd', 'iretq', 'pcmpeqb', 'pcmpeqw', 'psubw', 'vpmulhw', 'ldmxcsr', 'stmxcsr', 'cmovle', 'punpckhbw', 'cmovbe', 'setl', 'rdtsc', 'vpandn', 'vxorps', 'bt', 'psubd', 'setb', 'cmovge', 'cqo', 'psrad', 'cmovo', 'vpaddd', 'vpacksswb', 'btr', 'setbe', 'cmovae', 'pmovmskb', 'packssdw', 'movlhps', 'cmovnp', 'cmovp', 'cmpsq', 'paddw', 'pandn', 'vpcmpeqb', 'vpslldq', 'vpsrlw', 'shld', 'movaps', 'movsw', 'stosw', 'paddb', 'paddq', 'psubq', 'xadd', 'scasq', 'scasw', 'vpor', 'setae', 'cmovno', 'popf', 'movups', 'unpcklps', 'seto', 'vpunpckhqdq', 'iret', 'sysenter', 'sets', 'psubb', 'clts', 'pand', 'lodsw', 'vpaddw', 'pause', 'movapd', 'vpaddb', 'psllq', 'punpckhdq', 'andpd', 'xorpd', 'xorps', 'movss', 'andps', 'movlps', 'pextrw', 'pmuludq', 'pslld', 'setnp', 'cbw', 'verw', 'invlpg', 'pcmpgtb', 'bsf', 'pcmpgtd', 'vpsubb', 'movq', 'packsswb', 'cmpsw', 'invd', 'psrlq', 'punpckhwd', 'verr', 'psllw', 'pavgb', 'pmaxub', 'shrd', 'pmaxsw', 'vpunpckhwd', 'psrld', 'unpckhps', 'fxrstor', 'setp', 'movd', 'pmaddwd', 'pminsw', 'psraw', 'setno', 'vpsrad', 'vpunpckldq', 'setns', 'vpmaddwd', 'movntq', 'vpsraw', 'pxor', 'vpmovmskb', 'vmovdqa', 'vpcmpeqq', 'movdqa', 'movdqu', 'prefetch', 'packuswb', 'vmovups', 'pmulhw', 'pavgw', 'andnps', 'psrlw', 'vpsubw', 'pcmpgtw', 'pminub', 'prefetchnta', 'prefetchw', 'pshufw', 'vpcmpeqd', 'vpunpcklbw', 'lddqu', 'movlpd', 'psrldq', 'palignr', 'movnti', 'sfence', 'ptest', 'vpsrldq', 'vmovdqu', 'vmovq', 'vpand', 'movntdq', 'tzcnt', 'vmovd', 'vpunpcklqdq', 'unpcklpd', 'vperm2i128', 'sysretq', 'orps', 'pshufb', 'orpd', 'movntps', 'popcnt', 'pshufd', 'vpminub', 'andnpd', 'cmpnlesd', 'cmpnleps', 'bts', 'vpcmpeqw', 'fxsave', 'vpcmpgtd', 'vpcmpgtb', 'vmovsd', 'movhpd', 'vpsubq', 'vpsllw', 'cwd', 'mfence', 'movmskps', 'vpsubd', 'vpunpcklwd', 'prefetcht1', 'vpxor', 'cmpleps', 'cmplesd', 'vpunpckhdq', 'vpmullw', 'vpackssdw', 'vpcmpgtw', 'movupd', 'movmskpd', 'movbe', 'pminud', 'vptest', 'vpbroadcastb', 'cmpnless', 'unpckhpd', 'punpcklqdq', 'mulx', 'adcx', 'pslldq', 'clflush', 'rorx', 'andn', 'movhlps', 'vpshufd', 'punpckhqdq', 'vextracti128', 'pextrd', 'cmpxchg8b', 'vpextrw', 'prefetcht0', 'shlx', 'shrx', 'vmovaps', 'sarx', 'cmpordps', 'cmpneqsd', 'pshuflw', 'cmpneqps', 'pshufhw', 'vpsignw', 'cmpunordps', 'movshdup', 'lfence', 'prefetcht2', 'cmpunordss', 'cmpunordsd', 'cmpless', 'cmplepd', 'cmpneqpd', 'cmpnlepd', 'pmaxud', 'movddup', 'cmpordss', 'cmpordsd', 'movdq2q', 'movq2dq', 'lzcnt', 'vpextrd', 'vmovntdq', 'vpermq', 'pmulld', 'pmaxuw', 'pminuw', 'movsldup', 'pminsd']
    """
    print(len(operators))

    print(dele_o)
    """
    ['xlatb', 'outsd', 'in', 'enter', 'out', 'loope', 'fld', 'hlt', 'endbr64', 'fisttp', 'loop', 'ud0', 'div', 'fdivr', 'fsubr', 'loopne', 'ficomp', 'fcomp', 'int1', 'insb', 'fimul', 'fucompi', 'lar', 'ficom', 'idiv', 'sldt', 'jrcxz', 'sgdt', 'fild', 'fidivr', 'fnsave', 'fldenv', 'fbld', 'fincstp', 'outsb', 'bnd', 'fxch', 'fdiv', 'fadd', 'faddp', 'fbstp', 'fcos', 'fdivrp', 'fiadd', 'fidiv', 'fistp', 'fisub', 'fmul', 'fnstcw', 'fnstenv', 'fsqrt', 'fst', 'fstp', 'fstpnce', 'fsub', 'fsubp', 'insd', 'psubsb', 'vandpd', 'vpsubsb', 'wrmsr', 'fcom', 'fnstsw', 'frstor', 'vshufpd', 'addps', 'addsd', 'cvtsi2sd', 'fucomi', 'bndldx', 'cvtpi2ps', 'fsubrp', 'fcmove', 'fcmovnb', 'fcmovu', 'fdivp', 'fist', 'fisubr', 'vminps', 'str', 'fsin', 'cvttps2pi', 'subps', 'cvttsd2si', 'subsd', 'vpsadbw', 'cmpps', 'fcmovb', 'fsincos', 'vpshufb', 'lgdt', 'fldz', 'fcmovne', 'fldcw', 'jecxz', 'fyl2xp1', 'pinsrw', 'ffreep', 'fcomi', 'fcompi', 'vpsubsw', 'fscale', 'fldpi', 'fcmovnbe', 'fcompp', 'fdecstp', 'fdisi8087_nop', 'ffree', 'mulps', 'fldl2e', 'fpatan', 'fprem1', 'frndint', 'fucom', 'fucomp', 'fucompp', 'psubusw', 'fxtract', 'lsl', 'maskmovq', 'vpaddsb', 'vmread', 'pmulhuw', 'psadbw', 'vpmaxub', 'sidt', 'vcmpps', 'vcvtsi2sd', 'vcvtsi2ss', 'vfixupimmpd', 'vmovapd', 'vpaddsw', 'xabort', 'xbegin', 'xsavec', 'cvtps2pd', 'vpmulhuw', 'paddsw', 'vucomisd', 'divss', 'cvtsi2ss', 'addss', 'crc32', 'cvtdq2ps', 'divps', 'fldl2t', 'fmulp', 'fyl2x', 'outsw', 'pushf', 'sqrtps', 'vcmppd', 'fcmovbe', 'ucomiss', 'vmulpd', 'btc', 'paddusw', 'punpcklbw', 'vmovhps', 'fld1', 'fcmovnu', 'rdpmc', 'vminsd', 'ud2', 'fnop', 'vhaddpd', 'vpsrld', 'comiss', 'rdmsr', 'vhsubpd', 'vpavgb', 'ucomisd', 'mulsd', 'maxsd', 'sqrtsd', 'divsd', 'cmpnltsd', 'minps', 'maxps', 'insw', 'cmpnltps', 'minsd', 'fptan', 'psubsw', 'vpaddusw', 'vaddps', 'ftst', 'cvtps2pi', 'femms', 'fabs', 'fchs', 'vrsqrtss', 'shufps', 'emms', 'bndstx', 'xend', 'xacquire', 'psubusb', 'rsqrtps', 'vandps', 'vmovlps', 'vaddsubpd', 'vpmaxud', 'cvttss2si', 'lcall', 'ltr', 'fsetpm', 'vmulss', 'mulss', 'paddsb', 'maxss', 'vmulps', 'subss', 'fxam', 'vaddss', 'fldln2', 'cldemote', 'vpackuswb', 'f2xm1', 'fnclex', 'fprem', 'lmsw', 'vpsrlq', 'vunpckhpd', 'vshufps', 'rcpps', 'rsm', 'ud1', 'vcvtss2sd', 'vhsubps', 'vmwrite', 'vorpd', 'vpminsd', 'vpsubusb', 'vsubpd', 'xrelease', 'vorps', 'sha1msg2', 'vsubps', 'cmpeqps', 'vsubsd', 'vpermilps', 'punpckldq', 'vfnmaddss', 'lldt', 'sysexit', 'vmaxpd', 'fninit', 'vxorpd', 'feni8087_nop', 'fldlg2', 'getsec', 'lgs', 'paddusb', 'punpcklwd', 'vaddsd', 'vmulsd', 'vpavgw', 'vpcmpestrm', 'vpsllq', 'vunpcklps', 'pcmpistri', 'pcmpestri', 'vpcmpistri', 'ljmp', 'pi2fd', 'rdrand', 'cvtpd2ps', 'sqrtss', 'cvtsd2si', 'vandnps', 'vpunpckhbw', 'vminpd', 'prefetchwt1', 'vandnpd', 'xtest', 'vmaskmovdqu', 'vpmuludq', 'vpinsrw', 'vcvtps2pd', 'vpshufhw', 'vaddpd', 'cmpltsd', 'cmpltps', 'vpblendw', 'vfnmadd213ps', 'vdivsd', 'vpaddusb', 'vpmaxsw', 'vpslld', 'lss', 'vmovshdup', 'swapgs', 'cmpeqpd', 'cmpeqsd', 'cmpeqss', 'vphsubw', 'pswapd', 'vfmaddsd', 'mulpd', 'vcmpltsd', 'vmaxsd', 'cvtsd2ss', 'vfmaddss', 'roundsd', 'roundss', 'vldmxcsr', 'vcmpgtsd', 'vfmsubsd', 'minss', 'vfmadd213sd', 'vfmadd213ss', 'vpsubusw', 'addpd', 'vcvttsd2si', 'vhaddps', 'cvtss2si', 'vzeroupper', 'vfnmaddsd', 'vminss', 'vcvtss2si', 'vcvtusi2ss', 'vdivps', 'vstmxcsr', 'xsaves', 'smsw', 'vunpckhps', 'vcmptruesd', 'vmovlpd', 'lfs', 'psignb', 'rdseed', 'vcmpeq_ospd', 'vcmpneqpd', 'comisd', 'vdivpd', 'vaddsubps', 'xrstor', 'vcvtsd2ss', 'vmaxps', 'vfmadd231ps', 'rdtscp', 'vcvtsd2si', 'cvtss2sd', 'vpaddq', 'vunpcklpd', 'vmovhpd', 'vpminsw', 'vsqrtsd', 'vcmpsd', 'vpmovsxbd', 'vfmaddsubps', 'vsubss', 'pi2fw', 'vpalignr', 'vmovddup', 'xgetbv', 'vmlaunch', 'vfnmsub231ss', 'vmcall', 'phaddw', 'vblendpd', 'vmovss', 'vmovdqu64', 'vpbroadcastd', 'vpbroadcastq', 'vpminud', 'vmovdqa64', 'rdpkru', 'wrpkru', 'vzeroall', 'aesdeclast', 'aesenclast', 'vinserti128', 'aesdec', 'aesenc', 'vaesenc', 'aesimc', 'vmovdqa32', 'vpclmulqdq', 'adox', 'vmovdqu32', 'vpermd', 'pclmulqdq', 'vpminsq', 'vbroadcasti128', 'vpxord', 'vporq', 'vpandq', 'vdivss', 'vcmptruepd', 'xsaveopt', 'vfmsubadd213pd', 'vcmpngtss', 'xcryptecb', 'xcryptcfb', 'xcryptofb', 'xstore', 'xsha1', 'xsha256', 'vfnmsub213pd', 'vcmpeqss', 'vcmple_oqss', 'vmresume', 'vcmpneqss', 'vcmpss', 'vfmsubadd231pd', 'vcmpeqpd', 'vcmpeqps', 'vcmpltss', 'enclv', 'kandnb', 'lidt', 'vcmpleps', 'vmptrld', 'vcmpnle_uqss', 'vcmpge_oqss', 'vcmpeq_uqss', 'vcmpfalsess', 'vcmpnge_uqss', 'vcmpeqsd', 'vcmptruess', 'vfnmsub213sd', 'vpermi2pd', 'vpcomnequb', 'clac', 'vfnmadd213pd', 'vcvtpd2ps', 'vextractps', 'vfnmadd132sd', 'vfmadd231sd', 'vfnmadd213sd', 'vfnmadd231sd', 'vfmadd132pd', 'vcomisd', 'vcomiss', 'vfmadd132sd', 'vcmplesd', 'vfmsub132sd', 'vucomiss', 'kandnw', 'kxorw', 'vpermilpd', 'vpmacsww', 'vmaskmovps', 'vpminsb', 'vcmptrue_ussd', 'vphaddd', 'vrcpss', 'vdppd', 'monitor', 'vgf2p8affineqb', 'vmovsldup', 'pmaddubsw', 'phsubw', 'subpd', 'shufpd', 'vpmulhrsw', 'kmovw', 'vcmpnleps', 'pfrcpit2', 'umonitor', 'vmaxss', 'vfmadd231ss', 'vmovhlps', 'vmovlhps', 'vaesdec', 'vcmpunord_ssd', 'vpmaskmovq', 'vlddqu', 'xrstors', 'vpxorq', 'kmovq', 'vaesenclast', 'vpternlogq', 'vpmacssww', 'wrssd', 'wrssq', 'mwaitx', 'kaddw', 'pconfig', 'vpermil2ps', 'vphaddw', 'vpmaxuw', 'vpsignb', 'vmptrst', 'vpmadcswd', 'vsqrtpd', 'pmulhrw', 'cvttps2dq', 'cvttpd2dq', 'cvtdq2pd', 'vcvtpd2dq', 'vmovupd', 'vpmaxsb', 'vpermpd', 'vdpps', 'vptestnmw', 'pabsw', 'vfnmadd213ss', 'vpblendd', 'vpinsrb', 'vpmaddubsw', 'vfmsubps', 'vfmaddsubpd', 'vcmpeq_uqps', 'vcmpltpd', 'vfmsubaddps', 'vcmpunordsd', 'vfmadd132ss', 'vsqrtss', 'pfcmpge', 'pfcmpgt', 'vphsubsw', 'encls', 'invlpga', 'vmfunc', 'xsave', 'stgi', 'mwait', 'invvpid', 'vmclear', 'vmxoff', 'xsetbv', 'phsubsw', 'vpsllvd', 'vfmaddps', 'invept', 'pavgusb', 'vfnmsubsd', 'vmxon', 'skinit', 'stac', 'blcfill', 'sha1nexte', 'cmpneqss', 'pfcmpeq', 'pfmin', 'vfnmaddps', 'pf2iw', 'phaddd', 'vblendps', 'vroundps', 'vpmacswd', 'vroundss', 'vpabsb', 'cvttpd2pi', 'cmpltss', 'vfnmadd132ss', 'vphsubd', 'vpackusdw', 'vfmadd213pd', 'phaddsw', 'psignw', 'sha256rnds2', 'vfnmsub231ps', 'invpcid', 'pfnacc', 'fxrstor64', 'vpmuldq', 'vaesdeclast', 'kaddb', 'monitorx', 'vrsqrtps', 'vpermps', 'vcmpngtpd', 'vcvttss2si', 'vphaddsw', 'vsqrtps', 'vpermi2ps', 'vmload', 'vpminuw', 'vfmsubss', 'vfmadd132ps', 'vfmsub231ps', 'vfnmsub132ss', 'cvtpd2pi', 'vcvttpd2dq', 'vpmulld', 'vcmple_oqps', 'cmpnltss', 'divpd', 'clzero', 'sqrtpd', 'pfmul', 'pfadd', 'cmpltpd', 'pfacc', 'vblendmps', 'pfmax', 'vpblendmb', 'vcmpneq_usss', 'vmovntpd', 'vfmaddsub132pd', 'clflushopt', 'vfmsub213ps', 'vpshuflw', 'kmovb', 'vmovntps', 'vfmaddsub213pd', 'vmrun', 'vpmovsxwq', 'vpmacsswd', 'vcvtps2ph', 'vcvtph2ps', 'cvtps2dq', 'movntdqa', 'vfmsubadd132pd', 'cvtpd2dq', 'vfmsub231sd', 'minpd', 'pfpnacc', 'vfnmadd231ps', 'vmovmskps', 'vfnmaddpd', 'vfnmsub231pd', 'vrcp14pd', 'vinsertf128', 'vcvtdq2pd', 'enclu', 'vcmpnltsd', 'cmpnltpd', 'maxpd', 'vfnmsubps', 'phsubd', 'rdsspq', 'rstorssp', 'saveprevssp', 'incsspq', 'vcmpeq_osss', 'vrcpps', 'vpabsw', 'vextractf128', 'vpperm', 'pmulhrsw', 'vphaddwq', 'pf2id', 'vpbroadcastw', 'vphadddq', 'vphadduwq', 'vpmacsdql', 'pmuldq', 'packusdw', 'pblendw', 'psignd', 'vpsignd', 'mpsadbw', 'vcvtps2dq', 'vperm2f128', 'addsubps', 'haddps', 'pfrcp', 'vcmpgt_oqpd', 'endbr32', 'vpdpbusd', 'vscalefpd', 'vpord', 'vpmacssdql', 'sha1rnds4', 'vmmcall', 'vpinsrq', 'vrangepd', 'vpandnq', 'vpmullq', 'vpmaskmovd', 'vcmptrue_uspd', 'maskmovdqu', 'clgi', 'cvtpi2pd', 'kxnorw', 'vcmpneq_oqpd', 'pext', 'vcvttps2dq']
    """
    print(len(dele_o))

def trans_to_list(data):
    tmp = []
    for i in data:
        if type(i) == list:
            for j in i:
                tmp.append(j)
        else:
            tmp.append(i)
    return tmp

def parse_memory_map(experiment_fold_dir):
    data = open(experiment_fold_dir+"/mappings.txt",'r').read()
    memory_map = []
    for line in data.splitlines()[2:]:
        # print(line)
        match = re.match(r'^\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+([rwx-]+)', line)
        if match:
            start = int(match.group(1), 16)
            end = int(match.group(2), 16)
            perms = match.group(3).replace("-", "")
            memory_map.append({
                "start": start,
                "end": end,
                "permission": perms
            })
    return memory_map

def parse_registers(experiment_fold_dir):
    data = open(experiment_fold_dir+"/registers.txt",'r').read()
    regs = {}
    for line in data.splitlines():
        parts = line.split()
        if len(parts) == 3 or parts[0] == 'eflags':
            register_name = parts[0]
            hex_value = parts[1]
            regs[register_name] = int(hex_value,16)
    return regs
def get_map_regs(experiment_fold_dir):
    memory_map = parse_memory_map(experiment_fold_dir)
    registers = parse_registers(experiment_fold_dir)
    return (memory_map,registers)

if __name__ == '__main__':
    gadget_str = 'pop rdx ; sbb byte ptr [rdi], cl ; ret'
    print(Analysis_gadget(gadget_str))
    pass