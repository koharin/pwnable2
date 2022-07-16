#!/usr/bin/python 
import angr

# load binary
proj = angr.Project('./r200', auto_load_libs=False)

# initial state
state = proj.factory.entry_state()

simgr = proj.factory.simulation_manager(state)

simgr.use_technique(angr.exploration_techniques.ManualMergepoint(0x4007FD))
simgr.use_technique(angr.exploration_techniques.Explorer(find=0x400936, avoid=(0x40085D, 0x400882)))

simgr.run()

print(simgr.found[0].posix.dumps(0))

