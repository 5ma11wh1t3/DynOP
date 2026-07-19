import time
import sys
import argparse
import json
import multiprocessing
from multiprocessing import Queue
from multiprocessing.synchronize import Barrier, Event
import threading
from threading import Thread
import psutil
import queue

import random
from arcanist.synthesizer.memory_layout import MemoryLayout
from arcanist.synthesizer.state import State
from arcanist.synthesizer.state_builder import OnlyUsedRegisterStateBuilder
from arcanist.synthesizer.synthesis import Assumptions, IncrementalSynthesizer, SimpleAssumptionFunction, SimpleSpecificationFunction, Specifications, SynthesizedChain
from arcanist.synthesizer.tainted_types.bitvec import TaintedBitvec
from arcanist.synthesizer.tainted_types.bool import TaintedBool
from pysmt.shortcuts import Solver, BV
from typing import Any, Dict, List, Callable
from timeit import default_timer as timer

from pysmt import fnode
from pysmt.shortcuts import And

from arcanist.synthesizer.gadget import GadgetBase, GadgetLibrary, JSONGadget

import logging
logging.basicConfig(level=logging.NOTSET,
                    format="[%(levelname)s] (%(name)s) %(message)s")
LOGGER = logging.getLogger('arcanist-benchmark')


# def random_gadgets(gadgets: List[JSONGadget], size: int, proportion_mem_store: float) -> List[JSONGadget]:
#     # l = list(filter(
#     #     lambda g: g.assembly_str.startswith('pop {r4, r5, pc}') or g.assembly_str.startswith('pop.w {r3, r4, r5, r6, r7, r8, sb, pc}') or 'mov sp' in g.assembly_str, gadgets))
#     # for g in l:
#     #     LOGGER.info(f"{g.assembly_str}")
#     #     LOGGER.info(g.formula.to_smtlib())
#     # return l
#     with_mem_stores = list(
#         # and g.formula.to_smtlib().count('store') <= 16
#         filter(lambda g: g.has_store_operation, gadgets))
#     without_mem_stores = list(filter(
#         lambda g: not g.has_store_operation, gadgets))
#     with_count = min(len(with_mem_stores), int(size * proportion_mem_store))
#     without_count = size - with_count
#     return random.sample(population=without_mem_stores, k=without_count) + random.sample(population=with_mem_stores, k=with_count)

def _get_rare_gadgets(gadgets: List[dict]) -> List[dict]:
    rare_patterns = ["xchg rsp", "xchg esp",
                     "mov rsp", "mov esp", "mov sp", "movs sp"]

    def _is_rare(gadget: dict) -> bool:
        asm: str = gadget['assembly']
        return any(map(lambda pattern: pattern in asm, rare_patterns))
    return list(filter(_is_rare, gadgets))


def random_gadgets_json(gadgets: List[dict], size: int, proportion_mem_store: float, balance_jop_rop: bool, force_rare_gadgets: bool) -> List[dict]:
    selected_gadgets = []
    if force_rare_gadgets:
        rare_gadgets = _get_rare_gadgets(gadgets)
        num = min(len(rare_gadgets), size)
        selected_gadgets += rare_gadgets[:num]
        size -= num

    if balance_jop_rop:
        def is_jop(g: dict) -> bool:
            last_inst = g['assembly'].split(";")[-2]
            return last_inst.startswith(" call") or last_inst.startswith(" jmp") or last_inst.startswith(" blx") or last_inst.startswith(" bx")
        jop_gadgets = list(filter(is_jop, gadgets))
        rop_gadgets = list(filter(lambda g: not is_jop(g), gadgets))
        with_mem_stores_jop = list(
            filter(lambda g: g['has_store_operation'], jop_gadgets))
        without_mem_stores_jop = list(
            filter(lambda g: not g['has_store_operation'], jop_gadgets))
        with_mem_stores_rop = list(
            filter(lambda g: g['has_store_operation'], rop_gadgets))
        without_mem_stores_rop = list(
            filter(lambda g: not g['has_store_operation'], rop_gadgets))

        jop_count = min(size // 2, len(jop_gadgets))
        rop_count = min(size - jop_count, len(rop_gadgets))
        with_jop_count = min(len(with_mem_stores_jop),
                             int(jop_count * proportion_mem_store))
        without_jop_count = min(
            jop_count - with_jop_count, len(without_mem_stores_jop))
        with_rop_count = min(len(with_mem_stores_rop),
                             int(rop_count * proportion_mem_store))
        without_rop_count = min(
            rop_count - with_rop_count, len(with_mem_stores_rop))

        selected_gadgets += random.sample(population=without_mem_stores_jop, k=without_jop_count) + random.sample(population=with_mem_stores_jop, k=with_jop_count) + \
            random.sample(population=without_mem_stores_rop, k=without_rop_count) + \
            random.sample(population=with_mem_stores_rop, k=with_rop_count)
    else:
        with_mem_stores = list(
            filter(lambda g: g['has_store_operation'], gadgets))
        without_mem_stores = list(filter(
            lambda g: not g['has_store_operation'], gadgets))
        with_count = min(len(with_mem_stores), int(
            size * proportion_mem_store))
        without_count = size - with_count
        selected_gadgets += random.sample(population=without_mem_stores, k=without_count) + \
            random.sample(population=with_mem_stores, k=with_count)

    return selected_gadgets


def get_synthesis_function(args: Any) -> None:
    if args.strategy == 'incremental':
        return incremental_solving
    elif args.strategy == 'one-shot':
        return one_shot_solving

    raise ValueError(f"unknown strategy {args.strategy}")


def initialize_worker(init_barrier: Barrier, seed_queue: Queue, mem_store_proportion_queue: Queue, args: Any, mem_layout: MemoryLayout, assumptions: Assumptions, specifications: Specifications) -> None:
    seed = seed_queue.get()
    random.seed(seed)

    LOGGER.info("Loading gadgets...")
    with open(args.gadgets, "r") as f:
        # library = GadgetLibrary.from_json_str(f.read())
        library_json = json.loads(f.read())
    # LOGGER.info(f"Loaded {len(library.gadgets)} gadgets")

    mem_store_proportion = mem_store_proportion_queue.get()
    LOGGER.info(
        f"Selecting {args.library_size} gadgets with {mem_store_proportion*100}% of memory stores...")
    # gadgets = random_gadgets(
    #     library.gadgets, args.library_size, mem_store_proportion)

    gadgets_json = random_gadgets_json(
        library_json['gadgets'], args.library_size, mem_store_proportion, args.balance_rop_jop_gadgets, args.force_rare_gadgets)

    library_json['gadgets'] = gadgets_json
    library = GadgetLibrary.from_json_dict(library_json)

    LOGGER.info(f"Loaded {len(library.gadgets)} gadgets")

    init_barrier.wait()

    return (args, library.arch_info, library.gadgets, mem_store_proportion, mem_layout, assumptions, specifications)


def one_shot_solving() -> Any:
    raise NotImplementedError


def incremental_solving(idx: int, result_queue: Queue, start_event: Event, **kwargs) -> None:
    args, arch_info, gadgets, mem_store_proportion, mem_layout, assumptions, specifications = initialize_worker(
        **kwargs)
    start_event.wait()

    solver_options = {}
    # if mem_store_proportion > 0:
    #     solver_options['fun-store-lambdas'] = 1
    #     solver_options['beta-reduce'] = 1
    solver = Solver(logic='QF_AUFBV*', name='btor',
                    solver_options=solver_options)
    synthesizer = IncrementalSynthesizer(
        solver, arch_info, gadgets, OnlyUsedRegisterStateBuilder)

    try:
        chain = synthesizer.synthesize(
            args.max_length, mem_layout, assumptions, specifications)
    except Exception as e:
        LOGGER.warning(e)
        chain = None

    result_queue.put((idx, timer(), chain))
    return


def make_memory_layout(args: Any) -> MemoryLayout:
    mem_layout = MemoryLayout()
    if args.goal.startswith("optee"):
        mem_layout.add_region(0x8F700000, 0x8F700FFF, readable=True,
                              writable=False, name="shared-mem-pivot-buffer")
        mem_layout.add_region(
            0x8db5eac8, 0x8db5eaff, readable=True, writable=False, name="thread-stack-ro")
    elif args.goal.startswith("stack"):
        mem_layout.add_region(0x7ffffffde000, 0x7ffffffde07f,
                              readable=True, writable=False, name="stack-ro")
        mem_layout.add_region(0x7ffffffde080, 0x7fffffffefff,
                              readable=True, writable=True, name="stack-rw")
        if 'stack-pivot' in args.goal:
            mem_layout.add_region(0x7ffffff40000, 0x7ffffff4007F,
                                  readable=True, writable=False, name="pivot-buffer")
    elif args.goal.startswith("heap"):
        mem_layout.add_region(0x7ffffffde080, 0x7fffffffefff,
                              readable=True, writable=True, name="stack-rw")
        mem_layout.add_region(0x7ffffff80000, 0x7ffffff801ff,
                              readable=True, writable=False, name="heap-ro")

    return mem_layout


def make_goal_assumptions(args: Any) -> Assumptions:
    is_stack_goal = args.goal.startswith("stack")
    is_heap_goal = not is_stack_goal
    valid_stack_region = 0x7ffffffde180
    controlled_buffer = 0x7ffffffde000 if is_stack_goal else 0x7ffffff80000
    controlled_size = 0x80 if is_stack_goal else 0x200

    is_pivot_goal = 'stack-pivot' in args.goal
    pivot_buffer = 0x7ffffff40000
    pivot_buffer_size = 0x80

    def is_in_controlled_buffer(val: fnode.FNode) -> fnode.FNode:
        in_controlled_buffer = And(
            [val >= controlled_buffer, val < controlled_buffer+controlled_size])
        return in_controlled_buffer

    def _assumptions(input_state: State) -> fnode.FNode:
        memory = input_state.memory.clone_untainted().taint_range(
            controlled_buffer, controlled_size)

        # only use this pivot buffer for stack goal
        # in heap goal pivot buffer is the controlled buffer
        if is_pivot_goal and is_stack_goal:
            # say that the pivot buffer is controlled
            memory = memory.taint_range(pivot_buffer, pivot_buffer_size)

        memory_assertions = input_state.memory.Equals(memory)
        assertions = [memory_assertions]
        for regname, reg in input_state.registers.items():
            if regname == 'rip':
                assertions.append(reg.taint)
            elif (is_heap_goal and regname == 'rsp'):
                # put stack in a valid region to ensure validity of 'call' instruction (push to stack)
                assertions.append(reg.Equals(
                    TaintedBitvec.from_int(valid_stack_region, reg.bv_width)))
            elif (is_heap_goal and regname == 'rbp'):
                # put rbp in a valid region to ensure validity of rbp-based memory loads
                assertions.append(reg.Equals(
                    TaintedBitvec.from_int(valid_stack_region + 8, reg.bv_width)))
            elif (is_heap_goal and regname == args.reg):
                assertions.append(is_in_controlled_buffer(reg.value))
                assertions.append(reg.taint)
            elif (is_stack_goal and regname == 'rsp'):
                assertions.append(reg.Equals(
                    TaintedBitvec.from_int(controlled_buffer, reg.bv_width)))
            else:
                assertions.append(reg.Equals(
                    TaintedBitvec.new_zero_untainted(reg.bv_width)))

        for flag in input_state.flags.values():
            assertions.append(flag.Equals(TaintedBool.new_false_untainted()))

        assumptions = And(assertions)
        return assumptions

    return SimpleAssumptionFunction(_assumptions)


def make_optee_cve_assumptions(args: Any) -> Assumptions:
    def _assumptions(input_state: State) -> fnode.FNode:
        assertions = []
        # consider these uncontrolled because their values are too constrained
        # a0 = TaintedBitvec.with_name("a0", 32)
        # a1 = TaintedBitvec.with_name("a1", 32)
        # a2 = TaintedBitvec.with_name("a2", 32)

        a3 = TaintedBitvec.with_name("a3", 32)
        assertions.append(a3.taint)
        a4 = TaintedBitvec.with_name("a4", 32)
        assertions.append(a4.taint)
        a5 = TaintedBitvec.with_name("a5", 32)
        assertions.append(a5.taint)
        a6 = TaintedBitvec.with_name("a6", 32)
        assertions.append(a6.taint)
        a7 = TaintedBitvec.with_name("a7", 32)
        assertions.append(a7.taint)

        memory = input_state.memory.clone_untainted()
        # taint the pivot buffer (shared memory)
        memory = memory.taint_range(0x8F700000, 0x20)
        # give constraints on thread stack layout (controlled vs uncontrolled, args layout)
        memory = memory \
            .write_at(BV(0x8db5eac8, 32), a3) \
            .write_at(BV(0x8db5eacc, 32), a4) \
            .write_at(BV(0x8db5ead0, 32), a5) \
            .write_at(BV(0x8db5eae4, 32), a3) \
            .write_at(BV(0x8db5eae8, 32), a4) \
            .write_at(BV(0x8db5eaec, 32), a5) \
            .write_at(BV(0x8db5eaf0, 32), a6) \
            .write_at(BV(0x8db5eaf4, 32), a7)

        memory_assertions = input_state.memory.Equals(memory)
        assertions.append(memory_assertions)

        for regname, reg in input_state.registers.items():
            # overwritten pc using arb decrement
            if regname == "pc":
                assertions.append(reg.taint)
                assertions.append(reg.value < 0x8DB028CF)
            elif regname == "sp":
                assertions.append(reg.taint)
                assertions.append(reg.value.Equals(0x8db5eac8))
            else:
                assertions.append(reg.Equals(
                    TaintedBitvec.new_zero_untainted(reg.bv_width)))

        for flag in input_state.flags.values():
            assertions.append(flag.Equals(TaintedBool.new_false_untainted()))

        assumptions = And(assertions)
        return assumptions

    return SimpleAssumptionFunction(_assumptions)


assumption_makers: Dict[str, Callable[[Any], Assumptions]] = {
    "stack-func-call-3args": make_goal_assumptions,
    "stack-func-call-4args": make_goal_assumptions,
    "stack-syscall-4args": make_goal_assumptions,
    "stack-stack-pivot": make_goal_assumptions,
    "heap-func-call-3args": make_goal_assumptions,
    "heap-stack-pivot": make_goal_assumptions,
    "optee-cve-pivot": make_optee_cve_assumptions,
    "optee-cve-func-call3": make_optee_cve_assumptions,
    "optee-cve-func-call4": make_optee_cve_assumptions,
}


def make_assumptions(args: Any) -> Assumptions:
    return assumption_makers[args.goal](args)


def make_func_call_3args_specs(args: Any) -> Specifications:
    def _specifications(_: State, output_state: State) -> Specifications:
        rsi = output_state.registers['rsi']
        rdi = output_state.registers['rdi']
        rdx = output_state.registers['rdx']
        rip = output_state.registers['rip']
        rsi_is_arb = rsi.Equals(TaintedBitvec.from_int(0xBAD, rsi.bv_width))
        rdi_is_arb = rdi.Equals(TaintedBitvec.from_int(0xC0DE, rdi.bv_width))
        rdx_is_arb = rdx.Equals(TaintedBitvec.from_int(0x0, rdx.bv_width))
        rip_is_arb = rip.Equals(
            TaintedBitvec.from_int(0xDEADCAFE, rip.bv_width))
        assertions = And([rsi_is_arb, rdi_is_arb, rdx_is_arb, rip_is_arb])
        return assertions
    return SimpleSpecificationFunction(_specifications)


def make_func_call_4args_specs(args: Any) -> Specifications:
    def _specifications(_: State, output_state: State) -> Specifications:
        rsi = output_state.registers['rsi']
        rdi = output_state.registers['rdi']
        rdx = output_state.registers['rdx']
        rcx = output_state.registers['rcx']
        rip = output_state.registers['rip']
        rsi_is_arb = rsi.Equals(TaintedBitvec.from_int(0xBAD, rsi.bv_width))
        rdi_is_arb = rdi.Equals(TaintedBitvec.from_int(0xC0DE, rdi.bv_width))
        rdx_is_arb = rdx.Equals(TaintedBitvec.from_int(0x0, rdx.bv_width))
        rcx_is_arb = rcx.Equals(TaintedBitvec.from_int(0xFF, rcx.bv_width))
        rip_is_arb = rip.Equals(
            TaintedBitvec.from_int(0xDEADCAFE, rip.bv_width))
        assertions = And(
            [rsi_is_arb, rdi_is_arb, rdx_is_arb, rcx_is_arb, rip_is_arb])
        return assertions
    return SimpleSpecificationFunction(_specifications)


def make_syscall_4args_specs(args: Any) -> Specifications:
    def _specifications(_: State, output_state: State) -> Specifications:
        rax = output_state.registers['rax']
        rsi = output_state.registers['rsi']
        rdi = output_state.registers['rdi']
        rdx = output_state.registers['rdx']
        rcx = output_state.registers['rcx']
        rip = output_state.registers['rip']
        rax_is_arb = rax.Equals(TaintedBitvec.from_int(0x42, rax.bv_width))
        rsi_is_arb = rsi.Equals(TaintedBitvec.from_int(0xBAD, rsi.bv_width))
        rdi_is_arb = rdi.Equals(TaintedBitvec.from_int(0xC0DE, rdi.bv_width))
        rdx_is_arb = rdx.Equals(TaintedBitvec.from_int(0x0, rdx.bv_width))
        rcx_is_arb = rcx.Equals(TaintedBitvec.from_int(0xFF, rcx.bv_width))
        rip_is_arb = rip.Equals(
            TaintedBitvec.from_int(0xDEADCAFE, rip.bv_width))
        assertions = And(
            [rax_is_arb, rsi_is_arb, rdi_is_arb, rdx_is_arb, rcx_is_arb, rip_is_arb])
        return assertions
    return SimpleSpecificationFunction(_specifications)


def make_stack_pivot_specs(args: Any) -> Specifications:
    is_stack_goal = args.goal.startswith("stack")

    def is_in_pivot_buffer(reg: TaintedBitvec):
        # in stack scenario use the 'pivot-buffer'
        # in heap scenario use the controlled heap buffer as pivot buffer
        pivot_buffer = 0x7ffffff40000 if is_stack_goal else 0x7ffffff80000
        pivot_buffer_size = 0x80 if is_stack_goal else 0x200
        return And([reg.taint, reg.value >= pivot_buffer, reg.value < pivot_buffer+pivot_buffer_size])

    def _specifications(_: State, output_state: State) -> Specifications:
        rsp = output_state.registers['rsp']
        rip = output_state.registers['rip']
        rsp_points_in_pivot_buffer = is_in_pivot_buffer(rsp)
        rip_is_arb = rip.Equals(
            TaintedBitvec.from_int(0xDEADCAFE, rip.bv_width))
        assertions = And(
            [rsp_points_in_pivot_buffer, rip_is_arb])
        return assertions
    return SimpleSpecificationFunction(_specifications)


def make_optee_cve_pivot_specs(args: Any) -> Specifications:
    def _specifications(_: State, output_state: State) -> Specifications:
        sp = output_state.registers['sp']
        pc = output_state.registers['pc']
        sp_points_in_pivot_buffer = And(
            [sp.taint, sp.value >= 0x8F700000, sp.value < 0x8F700100])
        pc_is_arb = pc.Equals(
            TaintedBitvec.from_int(0xDEADCAFE, pc.bv_width))
        assertions = And(
            [sp_points_in_pivot_buffer, pc_is_arb])
        return assertions
    return SimpleSpecificationFunction(_specifications)


def make_optee_cve_func_call3_specs(args: Any) -> Specifications:
    def _specifications(_: State, output_state: State) -> Specifications:
        r0 = output_state.registers['r0']
        r1 = output_state.registers['r1']
        r2 = output_state.registers['r2']
        pc = output_state.registers['pc']
        r0_is_arb = r0.Equals(TaintedBitvec.from_int(0xDEADC0DE, r0.bv_width))
        r1_is_arb = r1.Equals(TaintedBitvec.from_int(0xC0DE0BAD, r1.bv_width))
        r2_is_arb = r2.Equals(TaintedBitvec.from_int(0x0DADDEAD, r2.bv_width))
        pc_is_arb = pc.Equals(
            TaintedBitvec.from_int(0xDEADCAFE, pc.bv_width))
        assertions = And(
            [r0_is_arb, r1_is_arb, r2_is_arb, pc_is_arb])
        return assertions
    return SimpleSpecificationFunction(_specifications)


def make_optee_cve_func_call4_specs(args: Any) -> Specifications:
    def _specifications(_: State, output_state: State) -> Specifications:
        r0 = output_state.registers['r0']
        r1 = output_state.registers['r1']
        r2 = output_state.registers['r2']
        r3 = output_state.registers['r3']
        pc = output_state.registers['pc']
        r0_is_arb = r0.Equals(TaintedBitvec.from_int(0xDEADC0DE, r0.bv_width))
        r1_is_arb = r1.Equals(TaintedBitvec.from_int(0xC0DE0BAD, r1.bv_width))
        r2_is_arb = r2.Equals(TaintedBitvec.from_int(0x0DADDEAD, r2.bv_width))
        r3_is_arb = r3.Equals(TaintedBitvec.from_int(0xBABADADA, r3.bv_width))
        pc_is_arb = pc.Equals(
            TaintedBitvec.from_int(0xDEADCAFE, pc.bv_width))
        assertions = And(
            [r0_is_arb, r1_is_arb, r2_is_arb, r3_is_arb, pc_is_arb])
        return assertions
    return SimpleSpecificationFunction(_specifications)


specification_makers: Dict[str, Callable[[Any], Assumptions]] = {
    "stack-func-call-3args": make_func_call_3args_specs,
    "stack-func-call-4args": make_func_call_4args_specs,
    "stack-syscall-4args": make_syscall_4args_specs,
    "stack-stack-pivot": make_stack_pivot_specs,
    "heap-func-call-3args": make_func_call_3args_specs,
    "heap-stack-pivot": make_stack_pivot_specs,
    "optee-cve-pivot": make_optee_cve_pivot_specs,
    "optee-cve-func-call3": make_optee_cve_func_call3_specs,
    "optee-cve-func-call4": make_optee_cve_func_call4_specs,
}


def make_specifications(args: Any) -> Specifications:
    return specification_makers[args.goal](args)


def memory_profiler(processes: List[multiprocessing.Process], memusages: List[int], stop_event: threading.Event) -> None:
    procs = list(map(lambda p: psutil.Process(p.pid), processes))
    while not stop_event.is_set():
        for i in range(len(procs)):
            p = procs[i]
            try:
                memusages[i] = max(p.memory_info().vms, memusages[i])
            except Exception as _:
                continue
        time.sleep(0.01)


def benchmark(args: Any):
    mem_layout = make_memory_layout(args)
    assumptions = make_assumptions(args)
    specifications = make_specifications(args)

    random.seed(args.seed)
    seed_queue = Queue()
    for _ in range(args.jobs):
        seed_queue.put(random.getrandbits(64))

    mem_store_proportion_queue = Queue()
    with_mem_store_count = int(args.jobs*args.jobs_with_mem_stores)
    with_high_mem_store_count = with_mem_store_count//2
    with_low_mem_store_count = with_mem_store_count - with_high_mem_store_count
    without_mem_store_count = args.jobs - with_mem_store_count
    for _ in range(without_mem_store_count):
        mem_store_proportion_queue.put(0.00)
    for _ in range(with_low_mem_store_count):
        mem_store_proportion_queue.put(args.low_mem_store_ratio)
    for _ in range(with_high_mem_store_count):
        mem_store_proportion_queue.put(args.high_mem_store_ratio)

    init_barrier = multiprocessing.Barrier(args.jobs + 1)
    start_event = multiprocessing.Event()
    result_queue = multiprocessing.Queue()
    synthesis_fn = get_synthesis_function(args)

    synthesis_args = {'result_queue': result_queue, 'start_event': start_event, 'init_barrier': init_barrier,
                      'seed_queue': seed_queue, 'mem_store_proportion_queue': mem_store_proportion_queue, 'args': args, 'mem_layout': mem_layout, 'assumptions': assumptions, 'specifications': specifications}
    processes = [multiprocessing.Process(
        target=synthesis_fn, args=(i,), kwargs=synthesis_args, daemon=True) for i in range(args.jobs)]

    mem_usages = [0]*len(processes)
    stop_profile_event = threading.Event()
    mem_profile_thread = Thread(target=memory_profiler, args=(
        processes, mem_usages, stop_profile_event))
    mem_profile_thread.start()

    for p in processes:
        p.start()

    init_barrier.wait()
    start = timer()
    deadline = start + args.timeout
    start_event.set()

    chain: SynthesizedChain | None = None
    timed_out = False

    while chain is None and any(map(lambda p: p.is_alive(), processes)):
        remaining = deadline - timer()
        if remaining <= 0:
            LOGGER.warning("Timed out...")
            timed_out = True
            time_taken = args.timeout
            break
        try:
            # FIXME: seems like 'get' with timeout ends up not working for whatever reason
            # when a log of values are put in the queue simultaneously, 'get' with timeout fails
            # to get the values...
            idx, timestamp, chain = result_queue.get_nowait()
            time.sleep(1)
        except queue.Empty:
            continue
        processes[idx].terminate()
        time_taken = timestamp - start

    for p in processes:
        p.kill()

    stop_profile_event.set()
    mem_profile_thread.join()

    if chain is not None:
        LOGGER.info(f"Successfully found chain in {time_taken}s")
        for g in chain.chain:
            LOGGER.info(g.assembly_str)
    else:
        LOGGER.warning("Unable to find chain...")

    if args.output:
        log_results = dict()
        log_results["time"] = time_taken
        log_results["timeout"] = timed_out
        log_results["success"] = chain is not None
        log_results["max_length"] = args.max_length
        log_results["library_size"] = args.library_size
        log_results["synthesis_per_length"] = args.jobs
        log_results["jobs"] = args.jobs
        log_results["memory_peaks"] = mem_usages
        if chain is not None:
            log_results["chain_length"] = len(chain.chain)
            log_results["raw"] = list(
                map(lambda g: g.assembly_str, chain.chain))
        with open(args.output, 'w') as f:
            json.dump(log_results, f)

    sys.exit()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark ARCANIST performance and ability to find chains for specific goals")

    parser.add_argument("gadgets", help="Path to the JSON gadget library")
    parser.add_argument(
        "max_length", help="Max length of synthesized chain", type=int)
    parser.add_argument(
        "library_size", help="Size of gadget libraries provided to the solver", type=int)

    parser.add_argument("--strategy", help="Solving strategy",
                        choices=['one-shot', 'incremental'], default='incremental')

    parser.add_argument(
        "--seed", help="Seed for random library sampling", default=1337, type=int)

    parser.add_argument(
        "--timeout", help="Timeout limit in seconds", default=3600, type=int)
    parser.add_argument(
        "--jobs", help="Number of processes", type=int, default=1)
    parser.add_argument(
        "--jobs_with_mem_stores", help="Proportion of syntheses given gadgets that include memory store operations", type=float, default=0.25
    )

    parser.add_argument(
        "--low_mem_store_ratio", help="The proportion of gadgets with memory stores operation in 'low mem store proportion' mode", type=float, default=0.05
    )

    parser.add_argument(
        "--high_mem_store_ratio", help="The proportion of gadgets with memory stores operation in 'high mem store proportion' mode", type=float, default=0.10
    )

    parser.add_argument(
        "--balance-rop-jop-gadgets", help="Gadget sampling heuristics that balance the number of 'ROP' and 'JOP' gadgets", action='store_true', default=False
    )

    parser.add_argument(
        "--force-rare-gadgets", help="Gadget sampling heuristics that forces the inclusion of rare gadgets", action='store_true', default=False
    )

    parser.add_argument(
        "--output", help="Output results to JSON file", type=str)

    goal_parsers = parser.add_subparsers(
        dest="goal", help="Which goal to achieve")
    goal_parsers.add_parser(
        "stack-func-call-3args", help="Function call with 3 arguments (stack controlled)"
    )
    goal_parsers.add_parser(
        "stack-func-call-4args", help="Function call with 4 arguments (stack controlled)"
    )
    goal_parsers.add_parser(
        "stack-syscall-4args", help="System call with 4 arguments (stack controlled)"
    )
    goal_parsers.add_parser(
        "stack-stack-pivot", help="Stack pivot (stack controlled)")
    heap_func_call_parser = goal_parsers.add_parser(
        "heap-func-call-3args", help="Function call with 3 arguments (heap controlled)")
    heap_func_call_parser.add_argument(
        "--reg", help="Register pointing to controlled area (default: rsi)", default="rsi")
    heap_pivot_parser = goal_parsers.add_parser(
        "heap-stack-pivot", help="Stack pivot (heap controlled)")
    heap_pivot_parser.add_argument(
        "--reg", help="Register pointing to controlled area (default: rsi)", default="rsi")
    goal_parsers.add_parser(
        "optee-cve-pivot", help="OPTEE CVE (pivot)")
    goal_parsers.add_parser(
        "optee-cve-func-call3", help="OPTEE CVE (func call 3 args)")
    goal_parsers.add_parser(
        "optee-cve-func-call4", help="OPTEE CVE (func call 4 args)")
    # set_regs_parser.add_argument(
    #     "reg", type=str, help="Register to set"
    # )

    args = parser.parse_args()
    benchmark(args)


if __name__ == '__main__':
    main()
