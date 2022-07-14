#!/usr/bin/python 
import angr,sys

# create angr Project
p = angr.Project('./05_angr_symbolic_memory')

# set start state
state = p.factory.blank_state(
        addr=0x08048618,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)

# set bitvectors
input0 = state.solver.BVS('input0', 8*8)
input1 = state.solver.BVS('input1', 8*8)
input2 = state.solver.BVS('input2', 8*8)
input3 = state.solver.BVS('input3', 8*8)

# set global variables with bitvectors
state.memory.store(0x0AB232C0, input0)
state.memory.store(0x0AB232C8, input1)
state.memory.store(0x0AB232D0, input2)
state.memory.store(0x0AB232D8, input3)

# create simulation managers
simgr = p.factory.simgr(state)

# search possible path to find solution
simgr.explore(find=lambda s: 'Good'.encode() in s.posix.dumps(sys.stdout.fileno()), avoid=lambda s: 'Try'.encode() in s.posix.dumps(sys.stdout.fileno()))

if simgr.found:
    solution_state = simgr.found[0]
    print('solution state:', end=' ')

    solution0 = solution_state.solver.eval(input0, cast_to=bytes).decode()
    solution1 = solution_state.solver.eval(input1, cast_to=bytes).decode()
    solution2 = solution_state.solver.eval(input2, cast_to=bytes).decode()
    solution3 = solution_state.solver.eval(input3, cast_to=bytes).decode()

    print("%s %s %s %s" % (solution0, solution1, solution2, solution3))
else:
    raise Exception('could not find the solution')
