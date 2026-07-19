from solve_pivot_mem import solve_mem_gadget
from solve_no_ret_mem_v2 import (solve_no_ret_mem_process, solve_no_ret_mem_func,
                                  solve_no_ret_mem_func_multi, print_memory_layout,
                                  simulate_chain, verify_chain_multi)
from find_reg_gadget_chain import get_edges
from itertools import product as iter_product, permutations as iter_permutations
import tools


TRACKABLE_REGS = [
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
]

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


def _src_reg_in(src_reg, reg_list):
    """Check if src_reg (str or list of str) is 'in' reg_list.
    For a list, ALL registers must be in reg_list."""
    if isinstance(src_reg, list):
        return all(r in reg_list for r in src_reg)
    return src_reg in reg_list


def _src_reg_eq(src_reg, reg_name):
    """Check if src_reg equals reg_name. For a list, check if reg_name is in it."""
    if isinstance(src_reg, list):
        return reg_name in src_reg
    return src_reg == reg_name


def recompute_controllable_regs(regs, controble_addr_base, total_slots):
    """Rebuild the controllable-register set from the current register state."""
    controllable_regs = ['rsp']
    controllable_end = controble_addr_base + total_slots * 8

    for reg_name in TRACKABLE_REGS:
        reg_value = regs.get(reg_name, 0)
        if controble_addr_base <= reg_value < controllable_end:
            controllable_regs.append(reg_name)

    return controllable_regs
        
def coop_edges(gadgets_dict,controllable_reg,target_regs):
    edges = []
    while 1:
        controllable_reg2 = controllable_reg.copy()

        for addr, gadget_str in gadgets_dict.items():
            gadget_info = tools.Analysis_gadget(gadget_str)
            rip_info = tools.Analysis_rip(gadget_str)
            if gadget_info and rip_info:
                if len(gadget_info['can_change_regs'])!=0 and len(gadget_info['hijack_reg'])!=0 and mem_is_controllable(gadget_info,controllable_reg) and len(gadget_info['condition_reg'])==0:
                    if gadget_info['hijack_reg'][0]['reg_name'] in controllable_reg:
                        for i in range(len(gadget_info['can_change_regs'])):
                            if (_src_reg_in(gadget_info['can_change_regs'][i]['src_reg'], controllable_reg)):
                                if gadget_info['can_change_regs'][i]['bit'] >= 32 and _src_reg_in(gadget_info['can_change_regs'][i]['src_reg'], controllable_reg) and not _src_reg_eq(gadget_info['can_change_regs'][i]['src_reg'], gadget_info['can_change_regs'][i]['reg_name']) and gadget_info['can_change_regs'][i]['reg_name'] not in controllable_reg:
                                    src_label = gadget_info['can_change_regs'][i]['src_reg']
                                    if isinstance(src_label, list):
                                        if len(src_label) == 0:
                                            continue
                                        src_label = src_label[0]
                                    edges.append({'dst':gadget_info['can_change_regs'][i]['reg_name'],'src':src_label,'addr':addr,'rip':rip_info['reg_name']})
                                    if gadget_info['can_change_regs'][i]['bit'] >= 32 and gadget_info['can_change_regs'][i]['reg_name'] not in controllable_reg2:
                                        controllable_reg2.append(gadget_info['can_change_regs'][i]['reg_name'])
        if controllable_reg2 == controllable_reg:
            break
        controllable_reg = controllable_reg2

    for addr, gadget_str in gadgets_dict.items():
        gadget_info = tools.Analysis_gadget(gadget_str)
        rip_info = tools.Analysis_rip(gadget_str)
        if gadget_info and rip_info:
            if len(gadget_info['can_change_regs'])!=0 and len(gadget_info['hijack_reg'])!=0 and len(gadget_info['condition_reg'])==0:
                if gadget_info['hijack_reg'][0]['reg_name'] in controllable_reg2 or gadget_info['hijack_reg'][0]['reg_name'] in [_["reg_name"] for _ in gadget_info['can_change_regs']]:
                    for i in range(len(gadget_info['can_change_regs'])):
                        if gadget_info['can_change_regs'][i]['bit'] >= 32 and gadget_info['can_change_regs'][i]['src_reg_type'] in ["mem_value","num", "value"] and (_src_reg_in(gadget_info['can_change_regs'][i]['src_reg'], controllable_reg2) or gadget_info['can_change_regs'][i]['src_reg'] == "immediate_num") and gadget_info['can_change_regs'][i]['reg_name'] in target_regs:
                            can_change_regs_name = [_["reg_name"] for _ in gadget_info['can_change_regs']]
                            src_label = gadget_info['can_change_regs'][i]['src_reg']
                            if isinstance(src_label, list):
                                if len(src_label) == 0:
                                    continue
                                src_label = src_label[0]
                            if gadget_info['hijack_reg'][0]['reg_name'] in can_change_regs_name:
                                rip_reg = gadget_info['can_change_regs'][can_change_regs_name.index(gadget_info['hijack_reg'][0]['reg_name'])]['src_reg']
                                if isinstance(rip_reg, list):
                                    if len(rip_reg) == 0:
                                        continue
                                    rip_reg = rip_reg[0]
                                edges.append({'dst':gadget_info['can_change_regs'][i]['reg_name'],'src':src_label,'addr':addr,'rip':rip_reg})
                            else:
                                edges.append({'dst':gadget_info['can_change_regs'][i]['reg_name'],'src':src_label,'addr':addr,'rip':rip_info['reg_name']})
                            if gadget_info['can_change_regs'][i]['bit'] >= 32 and gadget_info['can_change_regs'][i]['reg_name'] not in controllable_reg2:
                                controllable_reg2.append(gadget_info['can_change_regs'][i]['reg_name'])
    deduped = []
    seen = set()
    for edge in edges:
        key = (edge['src'], edge['dst'], edge['addr'], edge.get('rip'))
        if key not in seen:
            seen.add(key)
            deduped.append(edge)
    return deduped

def find_data_flow_paths(edges, controllable_regs, target_regs):
    """
    Search for all paths from controllable registers to target registers given a list of data flow edges.
    
    Args:
        edges (list): List of edge dictionaries, e.g., [{'dst': 'rdx', 'src': 'rdi', ...}]
        controllable_regs (list): List of controllable register names, e.g., ['rdi']
        target_regs (list): List of target registers (str or dict with 'reg_name').

    Returns:
        list: A list of paths, where each path is a list of edge dictionaries.
    """
    # 1. Build adjacency list for efficient graph traversal
    # Graph maps start_node (src) -> list of edges
    adj = {}
    for edge in edges:
        src = edge['src']
        if src not in adj:
            adj[src] = []
        adj[src].append(edge)

    # Normalize target registers to a set of names for fast lookup
    target_set = set()
    for tr in target_regs:
        if isinstance(tr, dict):
            target_set.add(tr.get('reg_name'))
        else:
            target_set.add(tr)

    all_paths = []

    # 2. DFS function to find paths
    def dfs(current_reg, current_path, visited_regs):
        # If current register is a target, we found a path
        if current_reg in target_set:
            all_paths.append(list(current_path))
            # Note: We continue searching if we want paths *through* targets to other targets,
            # but usually reaching a target is a valid end. 
            # If we want to find *all* possible extensions, we shouldn't return here if we want to allow going deeper.
            # However, for typical gadget chaining, finding *a* path to the target is the goal.
            # If multiple targets are along the same path, current logic adds the prefix path.
            # Let's continue to explore to catch all possibilities.
        
        # Explore neighbors
        if current_reg in adj:
            for edge in adj[current_reg]:
                dst = edge['dst']
                # Avoid cycles
                if dst not in visited_regs:
                    visited_regs.add(dst)
                    current_path.append(edge)
                    dfs(dst, current_path, visited_regs)
                    current_path.pop()
                    visited_regs.remove(dst)

    # 3. Start search from each controllable register
    for start_reg in controllable_regs:
        visited = set([start_reg])
        dfs(start_reg, [], visited)

    deduped_paths = []
    seen = set()
    for path in all_paths:
        if len(path) == 0:
            continue
        key = tuple((edge['src'], edge['dst'], edge['addr'], edge.get('rip')) for edge in path)
        if key not in seen:
            seen.add(key)
            deduped_paths.append(path)

    return deduped_paths


def find_data_flow_paths_v2(edges, controllable_regs, target_regs,
                            max_depth=6, max_paths=2000):
    """
    Search for data-flow paths while allowing a register name to reappear later
    in the path. This preserves chains such as rdi -> rsi -> rdi that the
    original visited-register DFS incorrectly prunes.

    To avoid infinite recursion on cyclic graphs, v2 tracks used edges within
    the current path and applies explicit depth/path caps.
    """
    adj = {}
    for edge in edges:
        src = edge['src']
        if src not in adj:
            adj[src] = []
        adj[src].append(edge)

    for src in adj:
        adj[src] = sorted(
            adj[src],
            key=lambda e: (e['src'], e['dst'], e['addr'], str(e.get('rip')))
        )

    target_set = set()
    for tr in target_regs:
        if isinstance(tr, dict):
            target_set.add(tr.get('reg_name'))
        else:
            target_set.add(tr)

    all_paths = []
    seen_paths = set()

    def edge_key(edge):
        return (edge['src'], edge['dst'], edge['addr'], edge.get('rip'))

    def record_path(path):
        if len(path) == 0:
            return
        key = tuple(edge_key(edge) for edge in path)
        if key not in seen_paths:
            seen_paths.add(key)
            all_paths.append(list(path))

    def dfs(current_reg, current_path, used_edges):
        if len(all_paths) >= max_paths:
            return

        if current_reg in target_set and len(current_path) != 0:
            record_path(current_path)
            return

        if len(current_path) >= max_depth:
            return

        for edge in adj.get(current_reg, []):
            key = edge_key(edge)
            if key in used_edges:
                continue
            used_edges.add(key)
            current_path.append(edge)
            dfs(edge['dst'], current_path, used_edges)
            current_path.pop()
            used_edges.remove(key)
            if len(all_paths) >= max_paths:
                return

    for start_reg in controllable_regs:
        dfs(start_reg, [], set())
        if len(all_paths) >= max_paths:
            break

    return all_paths


def filter_no_ret_gadgets(gadgets_dict):
    """Filter gadgets to only keep call/jmp-ending (no ret) gadgets for COP chains."""
    filtered = {}
    for addr, inst in gadgets_dict.items():
        tail = inst.split(' ; ')[-1].strip()
        op = tail.split(' ')[0]
        if op in ('call', 'jmp') and 'qword ptr' in tail:
            filtered[addr] = inst
    return filtered


def find_bypass_cet_ss(gadgets_dict, controllable_reg, target_regs):
    """Find COP edges for CET-SS bypass (no-ret gadgets only)."""
    # Auto-filter to no-ret gadgets
    no_ret = filter_no_ret_gadgets(gadgets_dict)
    target_reg_names = []
    for t in target_regs:
        if isinstance(t, dict):
            target_reg_names.append(t['reg_name'])
        else:
            target_reg_names.append(t)
    edges = coop_edges(no_ret, controllable_reg, target_reg_names)
    return edges


def paths_to_classify_res(paths, gadgets_dict):
    """
    Convert data-flow paths (from find_data_flow_paths) into classify_res format
    that solve_no_ret_mem_v2 can consume.

    Each path is a list of edges: [{'dst','src','addr','rip'}, ...]
    Each edge corresponds to one gadget in the COP chain.
    classify_res format: [[['addr -> gadget_str'], ['addr -> gadget_str'], ...]]
    """
    classify_res = []
    for path in paths:
        chain_group = []
        for edge in path:
            addr = edge['addr']
            gadget_str = gadgets_dict[addr]
            chain_group.append([f"{addr} -> {gadget_str}"])
        classify_res.append(chain_group)
    return classify_res


def solve_bypass_cet_ss(gadgets_dict, controllable_reg, target_regs, regs_init,
                         controble_addr_base, offset_list, permission_table,
                         num_threads=4, stack_mem={}):
    """
    End-to-end CET-SS bypass: search COP chain + solve memory layout.

    Args:
        gadgets_dict: {addr_str: gadget_str}
        controllable_reg: list of initially controllable register names, e.g. ['rdi']
        target_regs: list of target dicts, e.g. [{'reg_name':'rax','reg_value':0xdeadbeef}]
        regs_init: initial register state dict
        controble_addr_base: base address of controllable memory
        offset_list: list of available memory slot offsets
        permission_table: memory permission table
        num_threads: parallel threads for solver
        stack_mem: optional stack memory

    Returns:
        list of solution dicts or empty list
    """
    print("=" * 60)
    print("CET-SS Bypass: Search COP Chain + Solve Memory Layout")
    print("=" * 60)

    # Step 1: Find data-flow edges (COP edges, no-ret only)
    edges = find_bypass_cet_ss(gadgets_dict, controllable_reg, target_regs)
    print(f"\n[Step 1] Found {len(edges)} COP edges")
    for e in edges:
        print(f"  {e['src']} -> {e['dst']} via {e['addr']} (dispatch: {e['rip']})")
        print(f"    {gadgets_dict[e['addr']]}")

    if len(edges) == 0:
        print("No COP edges found. Cannot build chain.")
        return []

    # Step 2: Find data-flow paths from controllable regs to target regs
    paths = find_data_flow_paths_v2(edges, controllable_reg, target_regs)
    print(f"\n[Step 2] Found {len(paths)} data-flow paths")
    for i, path in enumerate(paths):
        chain_str = " -> ".join([f"{e['src']}->{e['dst']}" for e in path])
        print(f"  Path {i+1}: {chain_str}")
        for edge in path:
            print(f"    {edge['addr']}: {gadgets_dict[edge['addr']]}")

    if len(paths) == 0:
        print("No data-flow paths found.")
        return []

    # Step 3: Convert paths to classify_res and solve memory layout
    classify_res = paths_to_classify_res(paths, gadgets_dict)
    print(f"\n[Step 3] Solving memory layout for {len(classify_res)} chain candidates...")

    all_results = []
    for t in target_regs:
        target_reg = t['reg_name']
        target_value = t['reg_value']
        print(f"\n  Target: {target_reg} = {hex(target_value)}")

        result = solve_no_ret_mem_func(
            regs_init, classify_res, controble_addr_base, offset_list,
            permission_table, gadgets_dict, target_reg, target_value,
            num_threads=num_threads, stack_mem=stack_mem, mode=1)

        if len(result) > 0:
            print(f"  FOUND {len(result)} solution(s)!")
            print_memory_layout(result, controble_addr_base, gadgets_dict)
            all_results.extend(result)
        else:
            print(f"  No solution for {target_reg}={hex(target_value)}")

    return all_results


def solve_bypass_cet_ss_multi(gadgets_dict, controllable_reg, target_regs, regs_init,
                               controble_addr_base, offset_list, permission_table,
                               num_threads=4, stack_mem={}, max_combinations=50000):
    """
    Multi-target CET-SS bypass: find a single COP chain that sets multiple registers
    simultaneously.

    Args:
        gadgets_dict: {addr_str: gadget_str}
        controllable_reg: list of initially controllable register names
        target_regs: list of target dicts, e.g. [{'reg_name':'rdi','reg_value':0xdeadbeef},
                                                  {'reg_name':'rsi','reg_value':0xcafebabe}]
        regs_init: initial register state dict
        controble_addr_base: base address of controllable memory
        offset_list: list of available memory slot offsets
        permission_table: memory permission table
        num_threads: parallel threads for solver
        stack_mem: optional stack memory
        max_combinations: cap on cartesian product of per-target paths

    Returns:
        list of solution dicts or empty list
    """
    print("=" * 60)
    print("CET-SS Multi-Target Bypass: Combined COP Chain")
    print("=" * 60)
    target_names = [t['reg_name'] for t in target_regs]
    print(f"Targets: {', '.join(t['reg_name'] + '=' + hex(t['reg_value']) for t in target_regs)}")

    # Step 1: Find COP edges (covers all target regs)
    edges = find_bypass_cet_ss(gadgets_dict, controllable_reg, target_regs)
    print(f"\n[Step 1] Found {len(edges)} COP edges")
    for e in edges:
        print(f"  {e['src']} -> {e['dst']} via {e['addr']} (dispatch: {e['rip']})")

    if len(edges) == 0:
        print("No COP edges found.")
        return []

    # Step 2: Find per-target data-flow paths
    per_target_paths = {}
    for t in target_regs:
        reg_name = t['reg_name']
        paths = find_data_flow_paths_v2(edges, controllable_reg, [reg_name])
        per_target_paths[reg_name] = paths
        print(f"\n[Step 2] {reg_name}: {len(paths)} data-flow path(s)")
        for i, path in enumerate(paths):
            chain_str = " -> ".join([f"{e['src']}->{e['dst']}" for e in path])
            print(f"  Path {i+1}: {chain_str}")

    # Check all targets have at least one path
    for t in target_regs:
        if len(per_target_paths[t['reg_name']]) == 0:
            print(f"\nNo data-flow path for {t['reg_name']}. Aborting.")
            return []

    # Step 3: Cartesian product of per-target paths -> combined chains
    # Try all permutations of target ordering since execution order matters:
    # a gadget that clobbers rdi must come BEFORE the rdi-setting gadget.
    # Sort each target's paths by length (shortest first).
    # Use round-robin across the smallest dimension to ensure all paths
    # in the rarest register get tried.
    n_targets = len(target_regs)
    target_perms = list(iter_permutations(range(n_targets)))
    print(f"\n[Step 3] Trying {len(target_perms)} target orderings")

    combined_chains = []
    seen_chain_keys = set()
    cap_per_perm = max(1, max_combinations // len(target_perms))

    for perm in target_perms:
        perm_names = [target_regs[i]['reg_name'] for i in perm]
        path_lists = [sorted(per_target_paths[target_regs[i]['reg_name']], key=len) for i in perm]
        total_combos = 1
        for pl in path_lists:
            total_combos *= len(pl)
        print(f"  Order {' -> '.join(perm_names)}: {' x '.join(str(len(pl)) for pl in path_lists)} = {total_combos} combos (cap {cap_per_perm})")

        # Find the dimension with fewest paths — enumerate ALL of those,
        # and for each, try a limited number of combinations from the other dims.
        # Sort other_dims so smallest comes LAST in iter_product (iterates fastest),
        # giving more diversity across the larger dimensions.
        dims = [len(pl) for pl in path_lists]
        min_dim = min(dims)
        min_dim_idx = dims.index(min_dim)
        other_dims = [i for i in range(len(dims)) if i != min_dim_idx]
        # Sort other_dims: largest first (slowest), smallest last (fastest)
        other_dims.sort(key=lambda i: dims[i], reverse=True)

        count = 0
        # Budget per entry in the smallest dimension
        budget_per_entry = max(1, cap_per_perm // max(1, min_dim))

        for small_idx in range(min_dim):
            if count >= cap_per_perm:
                break
            # Build the other path lists for iter_product
            other_lists = [path_lists[i] for i in other_dims]
            sub_count = 0
            for other_combo in iter_product(*other_lists):
                if sub_count >= budget_per_entry or count >= cap_per_perm:
                    break
                sub_count += 1
                count += 1

                # Reconstruct full combo
                combo = [None] * len(path_lists)
                combo[min_dim_idx] = path_lists[min_dim_idx][small_idx]
                for j, oi in enumerate(other_dims):
                    combo[oi] = other_combo[j]

                # Concatenate edges in permutation order, dedup by gadget address
                seen_addrs = set()
                merged_edges = []
                for path in combo:
                    for edge in path:
                        if edge['addr'] not in seen_addrs:
                            seen_addrs.add(edge['addr'])
                            merged_edges.append(edge)

                # Deduplicate identical combined chains (order-sensitive)
                chain_key = tuple(e['addr'] for e in merged_edges)
                if chain_key not in seen_chain_keys:
                    seen_chain_keys.add(chain_key)
                    combined_chains.append(merged_edges)

    print(f"  {len(combined_chains)} unique combined chain(s) total")

    # Step 4: Convert to classify_res and solve
    classify_res = []
    for chain_edges in combined_chains:
        chain_group = []
        for edge in chain_edges:
            addr = edge['addr']
            gadget_str = gadgets_dict[addr]
            chain_group.append([f"{addr} -> {gadget_str}"])
        classify_res.append(chain_group)

    print(f"\n[Step 4] Solving {len(classify_res)} combined chain candidates with multi-target solver...")

    result = solve_no_ret_mem_func_multi(
        regs_init, classify_res, controble_addr_base, offset_list,
        permission_table, gadgets_dict, target_regs,
        num_threads=num_threads, stack_mem=stack_mem, mode=1)

    if len(result) > 0:
        print(f"\nSUCCESS: {len(result)} multi-target solution(s) found!")
        print_memory_layout(result, controble_addr_base, gadgets_dict)
    else:
        print("\nNo multi-target solution found.")

    return result


def solve_bypass_cet_ss_sequential(gadgets_dict, controllable_reg, target_regs, regs_init,
                                    controble_addr_base, offset_list, permission_table,
                                    num_threads=4, stack_mem={}, max_paths_per_reg=500,
                                    return_metadata=False):
    """
    Sequential register-by-register CET-SS bypass.

    Strategy:
      1. Try all permutations of target register ordering.
      2. For each ordering, solve one register at a time:
         a. Find COP edges and data-flow paths for the current target reg
            using the CURRENT register/memory state.
         b. Solve the single-target chain.
         c. Simulate execution to get updated regs + memory state.
         d. Update offset_list (remove used offsets).
         e. Move to the next register.
      3. Starting from the second solved register, immediately concatenate the
         current prefix and verify all solved targets together.
      4. Map virtual memory back to real at the very end.

    Returns:
        list of solution dicts or empty list
        When return_metadata=True, returns {"results": ..., "meta": ...}
    """
    from solve_no_ret_mem_v2 import (solve_no_ret_mem_func, simulate_chain,
                                      verify_chain_multi, print_memory_layout,
                                      get_dispatch_offsets)

    print("=" * 60)
    print("CET-SS Sequential Bypass: Register-by-Register")
    print("=" * 60)
    print(f"Targets: {', '.join(t['reg_name'] + '=' + hex(t['reg_value']) for t in target_regs)}")

    n_targets = len(target_regs)
    target_perms = list(iter_permutations(range(n_targets)))
    print(f"Trying {len(target_perms)} register orderings\n")

    solver_meta = {
        'total_orderings': len(target_perms),
        'attempted_orderings': 0,
        'skipped_orderings': 0,
        'solvable_prefixes': [],
        'failed_prefixes': [],
        'pruned_orderings': [],
    }
    solvable_prefix_seen = set()
    failed_prefix_map = {}

    def prefix_to_str(prefix):
        return '-'.join(prefix)

    def finalize_result(results, status):
        solver_meta['final_status'] = status
        if results:
            for res in results:
                res['solver_meta'] = solver_meta
        if return_metadata:
            return {'results': results, 'meta': solver_meta}
        return results

    def record_failed_prefix(prefix, reason):
        if prefix in failed_prefix_map:
            return
        failed_prefix_map[prefix] = reason
        solver_meta['failed_prefixes'].append({
            'prefix': list(prefix),
            'prefix_str': prefix_to_str(prefix),
            'reason': reason,
        })
        print(f"    Marked failed prefix: {' -> '.join(prefix)} ({reason})")

    def record_solved_prefix(prefix):
        if prefix in solvable_prefix_seen:
            return
        solvable_prefix_seen.add(prefix)
        solver_meta['solvable_prefixes'].append(prefix_to_str(prefix))
        print(f"    Recorded solvable prefix: {' -> '.join(prefix)}")

    def build_combined_chain_and_map():
        full_chain = []
        for chain_tuple in all_gadget_chains:
            full_chain.extend(chain_tuple)

        merged_map = {}
        for result_map in all_result_maps:
            merged_map.update(result_map)

        return tuple(full_chain), merged_map

    def verify_current_prefix(prefix_targets, prefix_names):
        full_chain, merged_map = build_combined_chain_and_map()

        print(f"\n  Verifying current prefix: {' -> '.join(prefix_names)}")
        print(f"  Combined chain length: {len(full_chain)} gadgets")
        print(f"  Dispatch offsets (locked): {sorted(all_dispatch_offsets)}")
        for step_i, result_map in enumerate(all_result_maps):
            print(f"  Step {step_i+1} result_map: {dict(sorted(result_map.items()))}")
        print(f"  Merged map: {dict(sorted(merged_map.items()))}")

        ok = verify_chain_multi(regs_init, full_chain, controble_addr_base,
                                merged_map, permission_table, prefix_targets)
        if ok:
            print(f"  VERIFIED prefix: {' -> '.join(prefix_names)}")
            return True, full_chain, merged_map

        print(f"  Verification FAILED for prefix: {' -> '.join(prefix_names)}")
        record_failed_prefix(prefix_names, 'verification_failed')

        new_regs2, _ = simulate_chain(regs_init, full_chain, controble_addr_base,
                                       merged_map, permission_table)
        if new_regs2:
            for target in prefix_targets:
                actual = new_regs2.get(target['reg_name'], 0)
                expected = target['reg_value'] & 0xffffffffffffffff
                status = 'OK' if actual == expected else 'MISMATCH'
                print(f"    {target['reg_name']}: expected={hex(expected)} actual={hex(actual)} {status}")

        return False, full_chain, merged_map

    for perm_idx, perm in enumerate(target_perms):
        perm_targets = [target_regs[i] for i in perm]
        perm_names = tuple(t['reg_name'] for t in perm_targets)

        blocked_prefix = None
        for prefix_len in range(1, len(perm_names) + 1):
            candidate_prefix = perm_names[:prefix_len]
            if candidate_prefix in failed_prefix_map:
                blocked_prefix = candidate_prefix
                break

        if blocked_prefix is not None:
            blocked_by = prefix_to_str(blocked_prefix)
            print(f"--- Ordering {perm_idx+1}/{len(target_perms)}: {' -> '.join(perm_names)} ---")
            print(f"    Skipping ordering due to failed prefix: {blocked_by}")
            solver_meta['skipped_orderings'] += 1
            solver_meta['pruned_orderings'].append({
                'ordering': list(perm_names),
                'ordering_str': prefix_to_str(perm_names),
                'blocked_by': list(blocked_prefix),
                'blocked_by_str': blocked_by,
                'reason': failed_prefix_map[blocked_prefix],
            })
            continue

        solver_meta['attempted_orderings'] += 1
        print(f"--- Ordering {perm_idx+1}/{len(target_perms)}: {' -> '.join(perm_names)} ---")

        # State that evolves as we solve each register
        cur_regs = dict(regs_init)
        cur_offset_list = list(offset_list)
        cur_controllable_reg = list(controllable_reg)
        all_gadget_chains = []   # list of gadget string tuples
        all_result_maps = []     # list of {offset: hex_value} dicts
        all_dispatch_offsets = set()  # dispatch offsets that must be preserved
        success = True

        for step, target in enumerate(perm_targets):
            reg_name = target['reg_name']
            reg_value = target['reg_value']
            print(f"\n  [Step {step+1}] Solving {reg_name} = {hex(reg_value)}")

            # Find edges using current state
            edges = find_bypass_cet_ss(gadgets_dict, cur_controllable_reg, [target])
            if len(edges) == 0:
                print(f"    No COP edges for {reg_name}. Trying next ordering.")
                record_failed_prefix(perm_names[:step+1], 'no_cop_edges')
                success = False
                break

            # Find data-flow paths
            paths = find_data_flow_paths_v2(
                edges, cur_controllable_reg, [reg_name],
                max_paths=max_paths_per_reg)
            paths = sorted(paths, key=len)[:max_paths_per_reg]
            print(f"    Found {len(paths)} path(s) (capped at {max_paths_per_reg})")
            # print(paths)
            # for i in range(len(paths)):
                # for j in range(len(paths[i])):
                    # print(gadgets_dict[paths[i][j]['addr']])
                # print("_________________________________________")


            if len(paths) == 0:
                print(f"    No paths for {reg_name}. Trying next ordering.")
                record_failed_prefix(perm_names[:step+1], 'no_data_flow_paths')
                success = False
                break

            # Convert to classify_res
            classify_res = paths_to_classify_res(paths, gadgets_dict)

            # Solve each target independently from the current register state.
            # Memory conflicts are handled at merge time instead of constraining
            # the per-step solver with earlier concrete slots.
            result = solve_no_ret_mem_func(
                cur_regs, classify_res, controble_addr_base, cur_offset_list,
                permission_table, gadgets_dict, reg_name, reg_value,
                num_threads=num_threads, stack_mem=stack_mem, mode=1)

            if len(result) == 0:
                print(f"    No solution for {reg_name}. Trying next ordering.")
                record_failed_prefix(perm_names[:step+1], 'no_memory_solution')
                success = False
                break

            sol = result[0]
            chain_tuple = sol['gadget_chain']
            result_map = sol['address_map']
            print(f"    SOLVED {reg_name}! Chain length: {len(chain_tuple)}")
            for g in chain_tuple:
                print(f"      {g}")

            # Simulate execution to get updated state
            cur_regs_before = dict(cur_regs)  # save for get_dispatch_offsets
            new_regs, used_offsets = simulate_chain(
                cur_regs, chain_tuple, controble_addr_base,
                result_map, permission_table)

            if new_regs is None:
                print(f"    Simulation failed for {reg_name}. Trying next ordering.")
                record_failed_prefix(perm_names[:step+1], 'simulation_failed')
                success = False
                break

            # Update state
            all_gadget_chains.append(chain_tuple)
            all_result_maps.append(result_map)
            cur_regs = new_regs
            # Only remove DISPATCH offsets (pointers to next gadgets) from available list.
            # Data offsets (values read by gadget body) can be overwritten by later chains.
            dispatch_offs = get_dispatch_offsets(
                chain_tuple, cur_regs_before, controble_addr_base, cur_offset_list)
            if dispatch_offs is None:
                dispatch_offs = used_offsets  # fallback: treat all as locked
            all_dispatch_offsets.update(dispatch_offs)
            for off in dispatch_offs:
                if off in cur_offset_list:
                    cur_offset_list.remove(off)
            # Recompute controllable regs from the simulated post-chain state so
            # stale sources such as rdi=0x400040 do not remain marked controllable.
            cur_controllable_reg = recompute_controllable_regs(
                cur_regs, controble_addr_base, len(offset_list))

            print(f"    Updated state: rsp={hex(cur_regs['rsp'])}, "
                  f"remaining offsets: {len(cur_offset_list)}")

            prefix_names = perm_names[:step+1]
            prefix_targets = perm_targets[:step+1]
            should_verify_prefix = (step > 0) or (len(perm_targets) == 1)

            if should_verify_prefix:
                ok, full_chain, merged_map = verify_current_prefix(
                    prefix_targets, prefix_names)
                if not ok:
                    success = False
                    break
                record_solved_prefix(prefix_names)
                if step == len(perm_targets) - 1:
                    result_list = [{
                        'gadget_chain': full_chain,
                        'address_map': merged_map,
                        'offset_list': cur_offset_list,
                    }]
                    print_memory_layout(result_list, controble_addr_base, gadgets_dict)
                    return finalize_result(result_list, 'success')
            elif step == 0:
                record_solved_prefix(prefix_names)

        if not success:
            continue

    print("\nAll orderings exhausted. No solution found.")
    return finalize_result([], 'fail')


if __name__ == '__main__':
    gadgets_dict = {
        '0x00000000039a6440' : 'push rbp ; mov rbp, rsp ; push rbx ; push rax ; mov rbx, rdi ; mov rdi, rsi ; call qword ptr [rbx + 0x98]',
        '0x0000000000151bb0': 'push rbp ; mov rbp, rsp ; mov rsi, qword ptr [rdi + 0x20] ; mov rdi, qword ptr [rdi + 0x28] ; mov rax, qword ptr [rdi] ; call qword ptr [rax + 0x18]',
        '0x0000000003969c30': 'push rbp ; mov rbp, rsp ; mov rdx, rsi ; mov rax, qword ptr [rdi] ; mov esi, 6 ; call qword ptr [rax + 0xb0]'
        # '0x0000000000050000': 'mov rsi, qword ptr [rdi + 8] ; mov rdx, rdi ; jmp qword ptr [rsi]',
        # '0x0000000000050010': 'mov rcx, rdx ; call qword ptr [rcx + 0x30]',
        # '0x0000000000050050': 'mov rax, qword ptr [rcx] ; jmp qword ptr [rsi + 0x10]'
    }

    controble_addr_base = 0x55555555b310
    controllable_reg = ['rdi', 'rax']
    target_regs = [{'reg_name': 'rdx', 'reg_value': 0xdeadbeef}]

    # Initial state: only rdi controllable, pointing to controllable memory
    regs_init = {
        'rax': controble_addr_base, 'rbx': 0, 'rcx': 0, 'rdx': 0,
        'rsi': 0, 'rdi': controble_addr_base,
        'rbp': 0x7fff80010000, 'rsp': 0x7fff80010000,
        'r8': 0, 'r9': 0, 'r10': 0, 'r11': 0,
        'r12': 0, 'r13': 0, 'r14': 0, 'r15': 0,
        'rip': 0, 'eflags': 0x202,
        'cs': 51, 'ss': 43, 'ds': 0, 'es': 0, 'fs': 0, 'gs': 0
    }

    offset_list = list(range(256))

    permission_table = [
        {'start': controble_addr_base, 'end': controble_addr_base + 0x10000, 'permission': 'rw'},
        {'start': 0x7fff80000000, 'end': 0x7fff80020000, 'permission': 'rw'},
    ]

    results = solve_bypass_cet_ss(
        gadgets_dict, controllable_reg, target_regs, regs_init,
        controble_addr_base, offset_list, permission_table, num_threads=4)
