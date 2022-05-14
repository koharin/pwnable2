#!/usr/bin/python 
import angr, sys

# create angr project
p = angr.Project('./07_angr_symbolic_file')

# set start state
state = p.factory.blank_state(
        addr=0x080488BF,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)

# file content (64 bytes)
password = state.solver.BVS('password', 64)

# symbolic file copying it's content to symbolic input(buffers global variable)
filename = 'FOQVSBZB.txt'
password_file = angr.storage.SimFile(filename, content=password)

# add symbolic file(password_file) to filesystem
state.fs.insert(filename, password_file)

# create simluation manager
simgr = p.factory.simgr(state)

# search possible path for solution
simgr.explore(find=lambda s: 'Good'.encode() in s.posix.dumps(sys.stdout.fileno()), avoid=lambda s: 'Try'.encode() in s.posix.dumps(sys.stdout.fileno()))

# if found stash is not empty
if simgr.found:
    print('solution state:', end=' ')
    print(simgr.found[0])
    
    solution = simgr.found[0].solver.eval(password, cast_to=bytes).decode()
    
    print('solution: ', end=' ')
    print(solution)
else:
    raise Exception('could not find the solution.')
