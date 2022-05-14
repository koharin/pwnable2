#!/usr/bin/python 
import angr,sys

p = angr.Project('./08_angr_constraints')

state = p.factory.blank_state(
        addr=0x804863c,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)

# symbolic bitvector
buffer = state.solver.BVS('buffer', 8*16)

# set buffer value
password_addr = 0x804A040
state.memory.store(password_addr, buffer)

# create simulation managers
simgr = p.factory.simgr(state)

# find state before check_equals()
simgr.explore(find=0x08048683)

if simgr.found:
    solution_state = simgr.found[0]
    print('solution state:', end=' ')
    print(solution_state)

    # get buffer value
    constrained_addr = 0x804A040
    constrained_size = 16
    constrained_bitvector = solution_state.memory.load(constrained_addr, constrained_size)

    # constrain system to find an input that make constrained_bitvector equal desired value
    constrained_desired_value = "OSIWHBXIFOQVSBZB".encode()

    # test whether constrained_bitvector == desired value 
    solution_state.add_constraints(constrained_bitvector == constrained_desired_value)

    solution = solution_state.solver.eval(buffer, cast_to=bytes).decode()

    print('solution:', end=' ')
    print(solution)
else:
    raise Exception('could not find the solution.')
