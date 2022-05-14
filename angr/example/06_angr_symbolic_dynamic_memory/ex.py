#!/usr/bin/python 
import angr, sys

# create angr project
p = angr.Project('./06_angr_symbolic_dynamic_memory')

# set start state
state = p.factory.blank_state(
        addr=0x080486AF,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)

# create bitvectors
input0 = state.solver.BVS('input0', 8*8)
input1 = state.solver.BVS('input1', 8*8)

# fake heap address 
fake_heap_addr0 = 0x5160000
fake_heap_addr1 = 0x5160008

# set buffer0, buffer1 to fake heap address
state.memory.store(0x0A2DEF74, fake_heap_addr0, endness=p.arch.memory_endness, size=4)
state.memory.store(0x0A2DEF7C, fake_heap_addr1, endness=p.arch.memory_endness, size=4)

# store fake heap space with input0, input1
state.memory.store(fake_heap_addr0, input0)
state.memory.store(fake_heap_addr1, input1)

# create simulation managers
simgr = p.factory.simgr(state)

# explore possible path to find solution 
simgr.explore(find=lambda s: 'Good'.encode() in s.posix.dumps(sys.stdout.fileno()), avoid=lambda s: 'Try'.encode() in s.posix.dumps(sys.stdout.fileno()))

# if found stash is not empty
if simgr.found:
    solution_state = simgr.found[0]
    
    print('solution state:', end=' ')
    print(solution_state)

    solution0 = solution_state.solver.eval(input0, cast_to=bytes).decode()
    solution1 = solution_state.solver.eval(input1, cast_to=bytes).decode()

    print("%s %s" % (solution0, solution1))
else:
    raise Exception('could no find the solution')
