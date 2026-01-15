import gdb
from pwn import cyclic
import json
import re
import os

def scan_memory_for_cyclic(start, end, pattern):
    memory = gdb.execute(f"x/{end - start}xb {start}", to_string=True)
    memory_byte = [line.split(':')[1] for line in memory.splitlines() if ":" in line]
    for m in range(len(memory_byte)):
        memory_byte[m] = bytes(eval("[" + memory_byte[m].replace("\t",",")[1:] + "]"))
    memory_bytes = b"".join(memory_byte)
    matches = []
    offset = 0
    while(offset < len(pattern)-8+1):
        index = memory_bytes.find(pattern[offset:offset+8])
        if index == -1:
            offset += 1
        else:
            match_length = 8
            while(memory_bytes[index:index+match_length+1] == pattern[offset:offset+match_length+1]):
                match_length += 1
            matches.append({"start_addr":hex(start+index),"length":match_length,"data":pattern[offset:offset+match_length].hex()})
            offset += match_length
    return matches

def decimal_to_bytes(number: int, length=None, byteorder='little', signed=False):
    if not isinstance(number, int):
        raise ValueError("Input must be an integer")

    if length is None:
        length = (number.bit_length() + 7) // 8 or 1

    return number.to_bytes(length, byteorder=byteorder, signed=signed)

def check_reg_data_controble(cyclic_pattern):
    regs = ['rax','rbx','rcx','rdx','rdi','rsi','r8','r9','r10','r11','r12','r13','r14','r15','rsp']
    controble_addrs = []
    controble_regs = []
    for reg in regs:
        try:
            addr_value = gdb.execute(f"x/1gx ${reg}", to_string=True)
            addr,value = addr_value.split()[0][:-1],decimal_to_bytes(int(addr_value.split()[-1],16))
            if value in cyclic_pattern:
                controble_addrs.append(int(addr,16)&0xffffffffffff0000)
                controble_regs.append(reg)
            
        except gdb.MemoryError:
            continue
    return (list(set(controble_addrs)),controble_regs)

def remove_ansi_colors(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

class SegvHandler(gdb.Command):
    def __init__(self, path):
        super(SegvHandler, self).__init__("handle_segv", gdb.COMMAND_OBSCURE)
        self.path = path 

    def invoke(self, arg, from_tty):
        print("\n[+] SIGSEGV caught! Displaying memory mappings:\n")
        
        mappings = gdb.execute("vmmap", to_string=True)
        mappings = remove_ansi_colors(mappings)

        registers = gdb.execute("info registers", to_string=True)

        print(os.path.join(self.path, 'mappings.txt'))
        open(os.path.join(self.path, 'mappings.txt'), 'w').write(mappings)
        open(os.path.join(self.path, 'registers.txt'), 'w').write(registers)

        cyclic_pattern = cyclic(0x10000)
        (controble_addrs, controble_regs) = check_reg_data_controble(cyclic_pattern)

        open(os.path.join(self.path, 'controble_regs.txt'), 'w').write(str(controble_regs))

        results = []
        for line in mappings.splitlines():
            parts = line.split()
            if len(parts) < 2 or not parts[0].startswith("0x") or 'rw' not in parts[2]:
                continue 
            
            start, end = int(parts[0], 16), int(parts[1], 16)
            for controble_addr in controble_addrs:
                if start <= controble_addr < end:
                    print(f"Scanning memory from {hex(controble_addr)} to {hex(end)}...")
                    try:
                        matches = scan_memory_for_cyclic(controble_addr, end, cyclic_pattern)
                        results.extend(matches)
                    except gdb.MemoryError:
                        print(f"Cannot access memory region: {hex(start)}-{hex(end)}")

        with open(os.path.join(self.path, "cyclic_matches.json"), "w") as f:
            json.dump(results, f, indent=4)

def main():
    path = '/home/angr/angrop/my-rop/benchmark_experiment/tmp'
    SegvHandler(path)
    gdb.execute("target remote 127.0.0.1:1234")
    gdb.execute("c")
    gdb.execute('''
    set logging on
    catch signal SIGSEGV
    commands 1
        handle_segv
        quit
    end
    continue
    ''')
    
main()