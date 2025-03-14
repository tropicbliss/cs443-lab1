import angr
import claripy
import sys
from collections import defaultdict

def find_puts_calls(proj):
    puts_addresses = []
    print("[*] Generating CFG to find 'puts' calls...")
    cfg = proj.analyses.CFGFast()
    puts_function = None
    for addr, func in cfg.functions.items():
        if func.name == 'puts':
            puts_function = func
            print(f"[+] Found 'puts' function at 0x{addr:x}")
            break
    if not puts_function:
        print("[-] Could not find 'puts' function in the binary")
        return puts_addresses
    print("[*] Finding all calls to 'puts'...")
    puts_callers = defaultdict(list)
    for func_addr, func in cfg.functions.items():
        if func.name == 'puts':
            continue
        for block in func.blocks:
            try:
                last_instr = block.capstone.insns[-1]
                if last_instr.mnemonic == 'call':
                    call_target = last_instr.operands[0].imm
                    if call_target == puts_function.addr:
                        puts_callers[func.name].append(last_instr.address)
                        puts_addresses.append(last_instr.address)
                        print(f"[+] Found 'puts' call at 0x{last_instr.address:x} in function {func.name}")
            except:
                continue
    if puts_addresses:
        print(f"[+] Found {len(puts_addresses)} 'puts' calls in the binary")
    else:
        print("[-] No 'puts' calls found")
    return puts_addresses

def extract_puts_strings(proj, puts_addresses):
    string_args = {}
    for addr in puts_addresses:
        state = proj.factory.blank_state(addr=addr)
        try:
            rdi_value = state.regs.rdi
            string_data = state.memory.load(rdi_value, 100)
            concrete_string = state.solver.eval(string_data, cast_to=bytes)
            null_term_idx = concrete_string.find(b'\x00')
            if null_term_idx != -1:
                concrete_string = concrete_string[:null_term_idx]
            string_args[addr] = concrete_string
            print(f"[+] String at 0x{addr:x}: {concrete_string}")
        except:
            string_args[addr] = None
            print(f"[-] Could not determine string for puts call at 0x{addr:x}")
    return string_args

class MyScanf(angr.SimProcedure):
    def run(self, fmt, ptr):
        user_input = claripy.BVS('user_input', 32)
        self.state.add_constraints(user_input >= 0, user_input < 100000)
        self.state.memory.store(ptr, user_input, endness=self.state.arch.memory_endness)
        self.state.globals['user_input'] = user_input
        return 1

def solve_for_inputs(proj, puts_addresses):
    results = {}
    proj.hook_symbol('scanf', MyScanf())
    
    for target_addr in puts_addresses:
        print(f"\n[*] Solving for input to reach 'puts' call at 0x{target_addr:x}")
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        print("[*] Starting symbolic execution...")
        simgr.explore(find=target_addr)
        if simgr.found:
            found_state = simgr.found[0]
            if 'user_input' in found_state.globals:
                user_input = found_state.globals['user_input']
                solution = found_state.solver.eval(user_input)
                print(f"[+] Found solution to reach 'puts' at 0x{target_addr:x}:")
                print(f"    Input (decimal): {solution}")
                print(f"    Input (hex): 0x{solution:x}")
                if solution == 0xc8e:
                    print(f"[+] This matches the expected password (0xc8e/3214)!")
                results[target_addr] = solution
            else:
                print(f"[-] Could not find user input in state globals")
        else:
            print(f"[-] Could not find a path to 'puts' at 0x{target_addr:x}")
    
    return results

def exec(binary_path):
    print(f"[*] Loading binary: {binary_path}")
    proj = angr.Project(binary_path, auto_load_libs=False)
    puts_addresses = find_puts_calls(proj)
    if not puts_addresses:
        print("No 'puts' calls found. Exiting.")
        return
    strings = extract_puts_strings(proj, puts_addresses)
    results = solve_for_inputs(proj, puts_addresses)
    print("\n[*] Summary of results:")
    for addr, input_value in results.items():
        string = strings.get(addr, "Unknown")
        print(f"  - To reach 'puts' at 0x{addr:x} (string: {string}), input: {input_value} (0x{input_value:x})")