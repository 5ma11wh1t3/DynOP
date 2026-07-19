from keystone import Ks as KsClass, KS_MODE_ARM, KS_MODE_LITTLE_ENDIAN
from triton import ARCH, TritonContext, MemoryAccess, CPUSIZE, Instruction
import os
import re
import itertools
import arch_config

def combine_multiple_arrays(*arrays):
    return list(itertools.product(*arrays))

# ============================================================
# ARM register analysis
# ============================================================
ARM_REGS = ["r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","sp","lr","pc"]
ARM_REGS_ALIASES = {"fp":"r11", "ip":"r12", "sb":"r9", "sl":"r10", "r13":"sp", "r14":"lr", "r15":"pc"}

def Analysis_reg_arm(string):
    string = string.strip()
    s = ARM_REGS_ALIASES.get(string, string)
    if s in ARM_REGS:
        return {"type":"value","reg_name":s,"bit":32,"expr":""}
    # [reg, #offset] or [reg]
    if "[" in string:
        type1 = "mem_value"
        bit = 32
        expr = string.split("[")[1].split("]")[0].strip()
        parts = [p.strip().replace("#","") for p in expr.split(",")]
        reg_name = []
        for p in parts:
            p2 = ARM_REGS_ALIASES.get(p, p)
            if p2 in ARM_REGS:
                reg_name.append(p2)
        if len(reg_name) == 1:
            reg_name = reg_name[0]
        return {"type":type1,"reg_name":reg_name,"bit":bit,"expr":expr}
    # immediate
    try:
        val = string.replace("#","")
        if type(eval(val)) == int:
            return {"type":"num","value":eval(val),"reg_name":"immediate_num"}
    except:
        pass
    return {"type":"no","reg_name":"no","bit":0,"expr":""}

def Analysis_op_arm(op_str):
    op_str = op_str.strip()
    parts = op_str.split()
    op = parts[0].lower()
    # Handle conditional suffixes (e.g. moveq, addne)
    base_op = op
    for suffix in ['eq','ne','cs','hs','cc','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al']:
        if len(op) > len(suffix) and op.endswith(suffix) and op[:-len(suffix)] in ['mov','add','sub','ldr','str','pop','push','and','orr','eor','bic','mvn','cmp','tst','mul','lsl','lsr','asr','ror']:
            base_op = op[:-len(suffix)]
            break

    if base_op in ('mov','mvn','movw','movt'):
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        dst = operands[:operands.index(",")].strip()
        src = operands[operands.index(",")+1:].strip()
        return {"op":base_op,"src":Analysis_reg_arm(src),"dst":Analysis_reg_arm(dst)}
    elif base_op == 'ldr':
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        dst = operands[:operands.index(",")].strip()
        src = operands[operands.index(",")+1:].strip()
        return {"op":"ldr","src":Analysis_reg_arm(src),"dst":Analysis_reg_arm(dst)}
    elif base_op == 'str':
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        src = operands[:operands.index(",")].strip()
        dst = operands[operands.index(",")+1:].strip()
        return {"op":"str","src":Analysis_reg_arm(src),"dst":Analysis_reg_arm(dst)}
    elif base_op in ('add','sub','adc','sbc','rsb','rsc'):
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        if len(comma_parts) >= 2:
            dst = comma_parts[0]
            src = comma_parts[-1]
            return {"op":base_op,"src":Analysis_reg_arm(src),"dst":Analysis_reg_arm(dst)}
    elif base_op in ('and','orr','eor','bic'):
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        if len(comma_parts) >= 2:
            dst = comma_parts[0]
            src = comma_parts[-1]
            return {"op":base_op,"src":Analysis_reg_arm(src),"dst":Analysis_reg_arm(dst)}
    elif base_op == 'pop':
        # pop {r0, r1, ..., pc}
        reg_list_str = op_str[len(op):].strip().strip('{}')
        regs = [r.strip() for r in reg_list_str.split(",")]
        results = []
        for r in regs:
            r2 = ARM_REGS_ALIASES.get(r, r)
            dst_reg = Analysis_reg_arm(r2)
            src_reg = {"type":"mem_value","reg_name":"sp","bit":32,"expr":""}
            results.append({"op":"pop","src":src_reg,"dst":dst_reg})
        if len(results) == 1:
            return results[0]
        return results
    elif base_op == 'push':
        reg_list_str = op_str[len(op):].strip().strip('{}')
        regs = [r.strip() for r in reg_list_str.split(",")]
        results = []
        for r in regs:
            r2 = ARM_REGS_ALIASES.get(r, r)
            src_reg = Analysis_reg_arm(r2)
            dst_reg = {"type":"mem_value","reg_name":"sp","bit":32,"expr":""}
            results.append({"op":"push","src":src_reg,"dst":dst_reg})
        if len(results) == 1:
            return results[0]
        return results
    elif base_op in ('cmp','tst','cmn','teq'):
        return None
    elif base_op in ('b','bl','bx','blx'):
        return None
    elif base_op in ('lsl','lsr','asr','ror'):
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        dst = comma_parts[0]
        src = comma_parts[-1]
        return {"op":base_op,"src":Analysis_reg_arm(src),"dst":Analysis_reg_arm(dst)}
    elif base_op == 'mul':
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        dst = comma_parts[0]
        src = comma_parts[1]
        return {"op":"mul","src":Analysis_reg_arm(src),"dst":Analysis_reg_arm(dst)}
    elif base_op == 'nop':
        return None
    return None

def Analysis_gadget_arm(gadget_str):
    ac = arch_config.get_arch()
    regs_change_log = {r:[] for r in ac.regs_change_log_keys}
    can_change_regs = []
    hijack_reg = []
    valid_mem_reg = []
    condition_reg = []

    gadgets = gadget_str.split(" ; ")
    op_res = []
    for g in gadgets:
        res = Analysis_op_arm(g)
        if res is not None:
            if type(res) == list:
                op_res.extend(res)
            else:
                op_res.append(res)

    for i in range(len(op_res)):
        op_an = op_res[i]
        if op_an['dst']['type'] == "value" and op_an['dst']['reg_name'] in regs_change_log:
            tmp_op = op_an['dst'].copy()
            tmp_op['src_reg'] = op_an['src']['reg_name']
            tmp_op['src_type'] = op_an['src']['type']
            regs_change_log[op_an['dst']['reg_name']].append(tmp_op)
        if op_an['dst']['type'] == "mem_value":
            valid_mem_reg.append(op_an['dst'])
        if op_an['src']['type'] == "mem_value":
            valid_mem_reg.append(op_an['src'])

    for r, l in regs_change_log.items():
        for item in l:
            can_change_regs.append({
                'reg_name':item['reg_name'],'bit':item['bit'],
                'src_reg':item['src_reg'],'src_reg_type':item['src_type'],'type':item['type']
            })

    last_inst = gadgets[-1].strip()
    # pop {pc} or pop {..., pc}
    if 'pop' in last_inst and 'pc' in last_inst:
        hijack_reg.append({"reg_name":"sp",'bit':32,"type":"mem_value",'expr':"sp"})
    elif last_inst.startswith('bx'):
        reg = last_inst.split()[-1].strip()
        reg = ARM_REGS_ALIASES.get(reg, reg)
        hijack_reg.append({"reg_name":reg,'bit':32,"type":"value",'expr':""})
    elif last_inst.startswith('b ') or last_inst.startswith('bl ') or last_inst.startswith('blx '):
        reg = last_inst.split()[-1].strip()
        reg = ARM_REGS_ALIASES.get(reg, reg)
        if reg in ARM_REGS:
            hijack_reg.append({"reg_name":reg,'bit':32,"type":"value",'expr':""})

    return {'can_change_regs':can_change_regs,'hijack_reg':hijack_reg,'valid_mem_reg':valid_mem_reg,'condition_reg':condition_reg}

def Analysis_rip_arm(gadget):
    gadget_info = Analysis_gadget_arm(gadget)
    if not gadget_info or len(gadget_info['hijack_reg']) == 0:
        return False
    return gadget_info['hijack_reg'][0]

# ============================================================
# MIPS register analysis
# ============================================================
MIPS_REGS = [
    "$zero","$at","$v0","$v1","$a0","$a1","$a2","$a3",
    "$t0","$t1","$t2","$t3","$t4","$t5","$t6","$t7",
    "$s0","$s1","$s2","$s3","$s4","$s5","$s6","$s7",
    "$t8","$t9","$k0","$k1","$gp","$sp","$fp","$ra",
]

def Analysis_reg_mips(string):
    string = string.strip()
    if string in MIPS_REGS:
        return {"type":"value","reg_name":string,"bit":32,"expr":""}
    # offset($reg) memory access
    m = re.match(r'(-?\d+|0x[0-9a-fA-F]+)?\((\$\w+)\)', string)
    if m:
        offset = m.group(1) if m.group(1) else "0"
        reg = m.group(2)
        expr = f"{reg} + {offset}" if offset != "0" else reg
        return {"type":"mem_value","reg_name":reg,"bit":32,"expr":expr}
    # immediate
    try:
        val = int(string, 0)
        return {"type":"num","value":val,"reg_name":"immediate_num"}
    except:
        pass
    return {"type":"no","reg_name":"no","bit":0,"expr":""}

def Analysis_op_mips(op_str):
    op_str = op_str.strip()
    parts = op_str.split()
    if len(parts) == 0:
        return None
    op = parts[0].lower()

    if op in ('move',):
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        return {"op":"move","src":Analysis_reg_mips(comma_parts[1]),"dst":Analysis_reg_mips(comma_parts[0])}
    elif op in ('lw','lh','lb','lhu','lbu'):
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        return {"op":op,"src":Analysis_reg_mips(comma_parts[1]),"dst":Analysis_reg_mips(comma_parts[0])}
    elif op in ('sw','sh','sb'):
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        return {"op":op,"src":Analysis_reg_mips(comma_parts[0]),"dst":Analysis_reg_mips(comma_parts[1])}
    elif op in ('addiu','addi','addu','add','subu','sub','and','andi','or','ori','xor','xori','nor','sll','srl','sra','sllv','srlv','srav'):
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        dst = comma_parts[0]
        src = comma_parts[-1]
        return {"op":op,"src":Analysis_reg_mips(src),"dst":Analysis_reg_mips(dst)}
    elif op == 'li':
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        return {"op":"li","src":Analysis_reg_mips(comma_parts[1]),"dst":Analysis_reg_mips(comma_parts[0])}
    elif op == 'lui':
        operands = op_str[len(op):].strip()
        if "," not in operands:
            return None
        comma_parts = [p.strip() for p in operands.split(",")]
        return {"op":"lui","src":Analysis_reg_mips(comma_parts[1]),"dst":Analysis_reg_mips(comma_parts[0])}
    elif op in ('jr','jalr','j','jal','b','beq','bne','bgtz','blez','bgez','bltz'):
        return None  # control flow
    elif op == 'nop':
        return None
    return None

def Analysis_gadget_mips(gadget_str):
    ac = arch_config.get_arch()
    regs_change_log = {r:[] for r in ac.regs_change_log_keys}
    can_change_regs = []
    hijack_reg = []
    valid_mem_reg = []
    condition_reg = []

    gadgets = gadget_str.split(" ; ")
    op_res = []
    for g in gadgets:
        res = Analysis_op_mips(g)
        if res is not None:
            if type(res) == list:
                op_res.extend(res)
            else:
                op_res.append(res)

    for i in range(len(op_res)):
        op_an = op_res[i]
        if op_an['dst']['type'] == "value" and op_an['dst']['reg_name'] in regs_change_log:
            tmp_op = op_an['dst'].copy()
            tmp_op['src_reg'] = op_an['src']['reg_name']
            tmp_op['src_type'] = op_an['src']['type']
            regs_change_log[op_an['dst']['reg_name']].append(tmp_op)
        if op_an['dst']['type'] == "mem_value":
            valid_mem_reg.append(op_an['dst'])
        if op_an['src']['type'] == "mem_value":
            valid_mem_reg.append(op_an['src'])

    for r, l in regs_change_log.items():
        for item in l:
            can_change_regs.append({
                'reg_name':item['reg_name'],'bit':item['bit'],
                'src_reg':item['src_reg'],'src_reg_type':item['src_type'],'type':item['type']
            })

    last_inst = gadgets[-1].strip()
    if last_inst.startswith('jr') and '$ra' in last_inst:
        hijack_reg.append({"reg_name":"$sp",'bit':32,"type":"mem_value",'expr':"$sp"})
    elif last_inst.startswith('jr'):
        reg = last_inst.split()[-1].strip()
        hijack_reg.append({"reg_name":reg,'bit':32,"type":"value",'expr':""})
    elif last_inst.startswith('jalr'):
        reg = last_inst.split()[-1].strip()
        hijack_reg.append({"reg_name":reg,'bit':32,"type":"value",'expr':""})

    return {'can_change_regs':can_change_regs,'hijack_reg':hijack_reg,'valid_mem_reg':valid_mem_reg,'condition_reg':condition_reg}

def Analysis_rip_mips(gadget):
    gadget_info = Analysis_gadget_mips(gadget)
    if not gadget_info or len(gadget_info['hijack_reg']) == 0:
        return False
    return gadget_info['hijack_reg'][0]

# ============================================================
# Architecture-dispatching wrappers
# ============================================================
def Analysis_reg_dispatch(string):
    ac = arch_config.get_arch()
    if ac.arch_name in ('arm','armel','arm32'):
        return Analysis_reg_arm(string)
    elif ac.arch_name in ('mips','mipsel','mips32'):
        return Analysis_reg_mips(string)
    else:
        return Analysis_reg(string)

def Analysis_op_dispatch(op_str):
    ac = arch_config.get_arch()
    if ac.arch_name in ('arm','armel','arm32'):
        return Analysis_op_arm(op_str)
    elif ac.arch_name in ('mips','mipsel','mips32'):
        return Analysis_op_mips(op_str)
    else:
        return Analysis_op(op_str)

def Analysis_gadget_dispatch(gadget_str):
    ac = arch_config.get_arch()
    if ac.arch_name in ('arm','armel','arm32'):
        return Analysis_gadget_arm(gadget_str)
    elif ac.arch_name in ('mips','mipsel','mips32'):
        return Analysis_gadget_mips(gadget_str)
    else:
        return Analysis_gadget(gadget_str)

def Analysis_rip_dispatch(gadget):
    ac = arch_config.get_arch()
    if ac.arch_name in ('arm','armel','arm32'):
        return Analysis_rip_arm(gadget)
    elif ac.arch_name in ('mips','mipsel','mips32'):
        return Analysis_rip_mips(gadget)
    else:
        return Analysis_rip(gadget)

def Analysis_reg(string):
    """
    {
        type: "value"/"mem_value"/"num", # register value / memory data pointed to by the register
        reg_name: str/[], # all register names in the string
        bit:64/32/16/8, # if type is a register value, use the register byte width; if type is mem_value, use the number of bytes written to memory
        expr:"", # extract the expression if it is an expression
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
        # do not loop rcx=0 ['rep','repe','repz','repne','repnz','repc','repnc','loop','loope','loopz','loopne','loopnz','jcxz','jecxz']
        if op.split(" ")[0] in ['rep','repe','repz','repne','repnz','repc','repnc','loop','loope','loopz','loopne','loopnz','jcxz','jecxz']:
            condition_reg.append({'reg_name':"rcx",'bit':64})
        # do not jump test+jump cmp+jump ['je', 'js', 'jle', 'ja', 'jg', 'jbe', 'jne']
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
        if i > 0 and op_an['dst']['reg_name'] == first_op_an['dst']['reg_name'] and op_an['dst']['reg_name']!=arch_config.get_arch().sp_reg:
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

# ============================================================
# ARM/MIPS gadget filters
# ============================================================
def filler_arm(gadgets):
    """Filter ARM gadgets - keep those ending with pop {pc}, bx lr, or valid branch"""
    gadget_list = gadgets.split(" ; ")
    if len(gadget_list) == 0:
        return False
    last = gadget_list[-1].strip()
    # Must end with pop {pc}, bx lr, or branch to register
    if 'pop' in last and 'pc' in last:
        return True
    if last.startswith('bx') and 'lr' in last:
        return True
    if last.startswith('bx') or last.startswith('blx'):
        parts = last.split()
        if len(parts) == 2 and parts[1] in ARM_REGS:
            return True
    return False

def filler_mips(gadgets):
    """Filter MIPS gadgets - keep those containing jr $ra (with delay slot after it)"""
    gadget_list = gadgets.split(" ; ")
    if len(gadget_list) == 0:
        return False
    # MIPS has delay slots: jr $ra is typically second-to-last, with delay slot as last
    for i, inst in enumerate(gadget_list):
        inst = inst.strip()
        if inst == 'jr $ra':
            return True
    return False

def filler(gadgets):
    ac = arch_config.get_arch()
    if ac.arch_name in ('arm','armel','arm32'):
        return filler_arm(gadgets)
    elif ac.arch_name in ('mips','mipsel','mips32'):
        return filler_mips(gadgets)
    # x86_64 original logic below
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
    # Auto-detect format: if first line matches gadget pattern, no header/footer
    if data and re.match(r'^0x[0-9a-fA-F]+ : ', data[0]):
        start, end_skip = 0, 0
    else:
        start, end_skip = 2, 3
    gadgets = []
    for i in range(start, len(data) - end_skip):
        if ' : ' not in data[i]:
            continue
        gg = data[i].split(' : ')
        if len(gg) >= 2 and filler(gg[1]):
            gadgets.append(gg)
    return gadgets
def create_gadget_dict(gadgets):
    ac = arch_config.get_arch()
    gadgets_dict = {}
    for i in range(len(gadgets)):
        if ac.arch_name in ('x86_64','amd64','x86-64'):
            gadgets[i][1] = gadgets[i][1].replace("call ptr","call qword ptr")
            gadgets[i][1] = gadgets[i][1].replace("jmp ptr","jmp qword ptr")
        # Normalize address to match addr_format_width (e.g. 0x8b24 -> 0x00008b24)
        addr = gadgets[i][0].strip()
        if addr.startswith('0x') or addr.startswith('0X'):
            addr = "0x" + addr[2:].zfill(ac.addr_format_width)
        gadgets_dict[addr] = gadgets[i][1]
    return gadgets_dict

def my_asm_for_triton(gadget):
    """Assemble instruction for Triton processing. Always uses ARM mode (not Thumb)
    because Triton's Thumb support is limited. Semantics are identical."""
    ac = arch_config.get_arch()
    if ac.arch_name in ('arm', 'armel', 'arm32') and getattr(ac, 'thumb_mode', False):
        # Use ARM mode for Triton even when in Thumb mode
        ks = KsClass(ac.ks_arch, KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN)
        clean = re.sub(r'(\w+)\.w\b', r'\1', gadget)
        res = _ks_asm_safe(ks, clean)
        if res:
            return res
        # Try ARM fallback (strip conditions, etc.)
        res = _arm_asm_fallback(ks, clean)
        if res:
            return res
    # Fall back to normal my_asm
    return my_asm(gadget)

def _ks_asm_safe(ks, gadget):
    """Call ks.asm and handle None result (Keystone returns None for some deprecated ARM encodings)."""
    result = ks.asm(gadget)
    if result is None or result[0] is None:
        return None
    return bytes(result[0])

def _arm_asm_fallback(ks, gadget):
    """Try assembling ARM/Thumb instruction with fallbacks for Keystone quirks."""
    # Strip .w suffix (Thumb wide encoding hint) — Keystone doesn't need it
    clean = re.sub(r'(\w+)\.w\b', r'\1', gadget)
    if clean != gadget:
        res = _ks_asm_safe(ks, clean)
        if res:
            return res
    # Keystone Thumb can't assemble pop/ldm with lr+pc or sp in register list.
    # Remove sp and/or lr to get a valid encoding with correct byte size.
    if clean.strip().startswith('pop') or clean.strip().startswith('ldm'):
        stripped = clean
        for bad_reg in ['sp', 'lr']:
            if re.search(r'\b' + bad_reg + r'\b', stripped):
                stripped = re.sub(r',?\s*\b' + bad_reg + r'\b\s*,?', ',', stripped)
                stripped = stripped.replace('{,', '{').replace(',}', '}').replace(',,', ',')
        res = _ks_asm_safe(ks, stripped)
        if res:
            return res
    # Strip conditional suffix: e.g. addne -> add, movle -> mov
    # ARM condition codes appended to opcodes
    arm_conds = ['eq','ne','cs','hs','cc','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al']
    op = clean.split()[0]
    for cc in sorted(arm_conds, key=len, reverse=True):
        if op.endswith(cc) and len(op) > len(cc):
            base_op = op[:-len(cc)]
            if len(base_op) >= 2:  # valid mnemonic must be at least 2 chars
                new_gadget = base_op + clean[len(op):]
                res = _ks_asm_safe(ks, new_gadget)
                if res:
                    return res
                break
    return None

def my_asm(gadget):
    """Convert assembly instructions to bytecode, with multi-architecture support"""
    ac = arch_config.get_arch()
    ks = KsClass(ac.ks_arch, ac.ks_mode)
    try:
        asm_res = _ks_asm_safe(ks, gadget)
        if asm_res:
            return asm_res
        # Keystone returned None — try ARM fallback
        if ac.arch_name in ('arm','armel','arm32'):
            asm_res = _arm_asm_fallback(ks, gadget)
            if asm_res:
                return asm_res
        raise Exception(f"Keystone returned None for: {gadget}")
    except:
        if ac.arch_name in ('x86_64','amd64','x86-64'):
            op = gadget.split(" ")[0]
            x86_64_conditional_jump_instructions = [
                "je", "jz", "jne", "jnz",
                "ja", "jnbe", "jae", "jnb", "jb", "jnae", "jbe", "jna",
                "jg", "jnle", "jge", "jnl", "jl", "jnge", "jle", "jng",
                "jp", "jpe", "jnp", "jpo", "jc", "jnc", "jo", "jno", "js", "jns", "jh", "jnh",
                "jcxz", "jecxz", "jrcxz"
            ]
            if op in x86_64_conditional_jump_instructions:
                gadget = op + " 0xdeadbeef"
            asm_res = bytes(ks.asm(gadget)[0])
        elif ac.arch_name in ('arm','armel','arm32'):
            # ARM conditional branches
            arm_cond_branches = ['beq','bne','bcs','bhs','bcc','blo','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble']
            op = gadget.split()[0].lower()
            if op in arm_cond_branches:
                gadget = op + " #0x100"
            asm_res = _arm_asm_fallback(ks, gadget)
            if asm_res:
                return asm_res
            # Last resort: try direct assembly
            asm_res = _ks_asm_safe(ks, gadget)
            if asm_res:
                return asm_res
            raise Exception(f"Keystone cannot assemble ARM/Thumb: {gadget}")
        elif ac.arch_name in ('mips','mipsel','mips32'):
            op = gadget.split()[0].lower()
            mips_branches = ['beq','bne','bgtz','blez','bgez','bltz','beqz','bnez']
            if op in mips_branches:
                gadget = op + " $zero, $zero, 0x100" if op in ('beq','bne') else op + " $zero, 0x100"
            asm_res = bytes(ks.asm(gadget)[0])
        else:
            raise
    return asm_res

def my_log(data, n):
    """Print log messages"""
    print("------------------------------------------------")
    for i in range(n):
        print(data[i])

def controllable_mem_distributor(gadgets_info, address_map, now_gadget, mem_type):
    """Memory allocator for unified controllable-memory management, with multi-architecture support"""
    ac = arch_config.get_arch()
    ptr_size = ac.ptr_size
    if mem_type == "rip_mem":
        (my_virtual_mem_start, my_virtual_mem_length) = gadgets_info.my_virtual_mem_info
        for mem_addr in range(my_virtual_mem_start, my_virtual_mem_start + my_virtual_mem_length, ptr_size):
            if mem_addr not in gadgets_info.used_virtual_mem:
                return mem_addr
    elif mem_type == "valid_mem":
        valid_bss_addr = gadgets_info.bss_address
        return valid_bss_addr

def addr_in_range(addr, mem_dict_list):
    """Check whether an address is in the specified memory range"""
    addr_n = eval(addr)
    for i in range(len(mem_dict_list)):
        start_addr = eval(mem_dict_list[i]['start_addr'])
        length = mem_dict_list[i]['length']
        if addr_n >= start_addr and addr_n <= start_addr + length:
            return True
    return False

def table_check(addr, permission_table, mode):
    """Check whether an address has the specified permissions"""
    for i in range(len(permission_table)):
        if addr >= permission_table[i]['start'] and addr < permission_table[i]['end']:
            if mode in permission_table[i]['permission']:
                return True
    return False

def read_write_check(instruction, permission_table):
    """Check memory read/write permissions for an instruction"""
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
    """Get the maximum index in the address map, excluding virtual memory regions, with multi-architecture support"""
    ac = arch_config.get_arch()
    ptr_size = ac.ptr_size
    my_virtual_mem_start = gadgets_info.my_virtual_mem_info[0]
    tmp = []
    for a, v in address_map.items():
        if a < (my_virtual_mem_start - gadgets_info.controble_addr_base) // ptr_size:
            tmp.append(a)
    return max(tmp)

def check_asm(code):
    try:
        ac = arch_config.get_arch()
        if not ac.triton_supported:
            # Without Triton, just check if Keystone can assemble it
            try:
                my_asm(code)
                return True
            except:
                return False
        address = 0x100000
        ctx = TritonContext()
        ctx.setArchitecture(ac.triton_arch)
        instruction = Instruction(address, my_asm(code))
        ctx.processing(instruction)
        pc = ctx.getConcreteRegisterValue(get_reg_by_name(ctx, ac.pc_reg))
        if pc == 0:
            return False
        else:
            return True
    except:
        return False

def get_reg_by_name(ctx, reg_name):
    """Get a Triton register object by name"""
    _triton_reg_aliases = {
        'lr': 'r14',
        'fp': 'r11',
    }
    triton_name = _triton_reg_aliases.get(reg_name, reg_name)
    for reg in ctx.getAllRegisters():
        if reg.getName() == triton_name:
            return reg
        if reg.getName() == reg_name:
            return reg
    return None
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
    lines = data.splitlines()
    # Auto-detect: if first line matches map pattern, no header to skip
    if lines and re.match(r'^\s*0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+[rwx-]+', lines[0]):
        start_idx = 0
    else:
        start_idx = 2
    memory_map = []
    for line in lines[start_idx:]:
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
        if len(parts) >= 2:
            register_name = parts[0]
            hex_value = parts[1]
            try:
                regs[register_name] = int(hex_value, 16)
            except ValueError:
                continue
    return regs
def get_map_regs(experiment_fold_dir):
    memory_map = parse_memory_map(experiment_fold_dir)
    registers = parse_registers(experiment_fold_dir)
    return (memory_map,registers)

if __name__ == '__main__':
    gadget_str = 'pop rdx ; sbb byte ptr [rdi], cl ; ret'
    print(Analysis_gadget(gadget_str))
    pass