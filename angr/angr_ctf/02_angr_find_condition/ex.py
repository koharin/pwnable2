#!/usr/bin/python 
import angr 
import sys

# create angr project
project = angr.Project('./02_angr_find_condition')

# set starting state from main()
state = project.factory.entry_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

# create simulation manager initializing with starting state
simgr = project.factory.simgr(state)

# dump whatever printed out by the binary into string and find path include good in string
# avoid path including Try
simgr.explore(find=lambda s: b'Good' in s.posix.dumps(sys.stdout.fileno()), avoid=lambda s: b'Try' in s.posix.dumps(sys.stdout.fileno()))

# if found stash is not empty, print found address, decoded solution
if simgr.found:
    print('find address:', end= ' ')
    print(simgr.found[0])
    print('solution:', end=' ')
    print(simgr.found[0].posix.dumps(0).decode())

else:
    raise Exception('error: could not find solution')
