#!/usr/bin/python 
import angr, sys

# create angr project
p = angr.Project('./04_angr_symbolic_stack')

# set start state
state = p.factory.blank_state(
        addr=0x080486AE,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

# create bitvectors
input0 = state.solver.BVS('input0', 32)
input1 = state.solver.BVS('input1', 32)

# mov ebp, esp (set ebp to esp register value)
state.regs.ebp = state.regs.esp

# allocate padding by decreasing esp before push bitvectors
padding = 8
state.regs.esp -= padding

# push bitvectors to stack
state.stack_push(input0)
state.stack_push(input1)

# create simulation manager
simgr = p.factory.simgr(state)

# search possible path with given address
simgr.explore(find=lambda s: 'Good'.encode() in s.posix.dumps(sys.stdout.fileno()), avoid=lambda s: 'Try'.encode() in s.posix.dumps(sys.stdout.fileno()))

if simgr.found:
    solution_state = simgr.found[0]
    print('solution state:', end=' ')
    print(solution_state)

    solution0 = solution_state.solver.eval(input0)
    solution1 = solution_state.solver.eval(input1)

    print("%u %u" % (solution0, solution1))
else:
    raise Exception('could not find solution')

