#!/usr/bin/python 
import angr

# load binary
p = angr.Project('r100', auto_load_libs=False)

# get state from entrypoint
state = p.factory.entry_state()

# use simulation manager
simgr = p.factory.simgr(state)

# search path
simgr.explore(find=lambda s:b'Nice' in s.posix.dumps(1))
print(simgr.found)
print(simgr.found[0].posix.dumps(0))
print(simgr.found[0].posix.dumps(1))
