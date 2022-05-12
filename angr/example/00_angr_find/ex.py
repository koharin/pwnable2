#!/usr/bin/python 
import angr

# address to find
FIND = 0x804868C

# create angr project
project = angr.Project('./00_angr_find', auto_load_libs=False)

# tell angr where to start executing (main() or somewhere)
# add options to indicate angr to start from main()
state = project.factory.entry_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

# create a simulation manager and initialize it with starting state

#simgr = project.factory.simulation_manager(state)
simgr = project.factory.simgr(state)

# explore possible path while executing binary
simgr.explore(find=FIND)

if simgr.found:
    # if address found, state saved in found stash. if failed it is empty
    print(simgr.found[0])

    # print the string that angr wrote to stdin to find solution
    print(simgr.found[0].posix.dumps(0))
else:
    raise Exception('Could no find the solution')
