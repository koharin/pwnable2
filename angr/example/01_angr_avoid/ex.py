#!/usr/bin/python 
import angr

'''
AVOID=0x08048609
FIND=0x080485f7 
'''
FIND=0x080485f4
AVOID=0x8048606

# create angr project
project = angr.Project('./01_angr_avoid', auto_load_libs=False)

# set starting state to main()
initial_state = project.factory.entry_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

# create simulation manager initializing starting state
simgr = project.factory.simgr(initial_state)

# explore possible path while avoiding given address 
#simgr.explore(find=MAYBE_GOOD, avoid=AVOID)
simgr.explore(find=FIND, avoid=AVOID)

if simgr.found:
    print(simgr.found[0].posix.dumps(0))
else:
    raise Exception('could not find the solution')
