#!/usr/bin/python 
import angr, sys

# create angr project
p = angr.Project('./03_angr_symbolic_registers')

# specify start address where symbolic execution engine should begin
state = p.factory.blank_state(
        addr=0x80488C7, 
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)

# create symbolic bitvectors
SIZE=32
input0 = state.solver.BVS('input0', SIZE)
input1 = state.solver.BVS('input1', SIZE)
input2 = state.solver.BVS('input2', SIZE)

# set register to a symbolic value
state.regs.eax = input0 
state.regs.ebx = input1
state.regs.edx = input2

simgr = p.factory.simgr(state)

find_condition=lambda s: 'Good'.encode() in s.posix.dumps(sys.stdout.fileno())
avoid_condition=lambda s: 'Try'.encode() in s.posix.dumps(sys.stdout.fileno())
# find possible path with given address
simgr.explore(find=find_condition, avoid=avoid_condition)

if simgr.found:
    solution_state = simgr.found[0]
    print('solution state:', end=' ')
    print(solution_state)

    # pass eval the bitvector that we want to solve
    solution0 = solution_state.solver.eval(input0)
    solution1 = solution_state.solver.eval(input1)
    solution2 = solution_state.solver.eval(input2)

    print("%x %x %x" % (solution0, solution1, solution2))
else:
    raise Exception('could not find the solution')
