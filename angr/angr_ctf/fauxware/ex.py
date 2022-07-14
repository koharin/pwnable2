#!/usr/bin/python
import angr
 
# load binary into angr project
project = angr.Project('fauxware', auto_load_libs=False)

# program state in entrypoint
state = project.factory.entry_state()

# Create Simulation Manager
simgr = project.factory.simgr(state)

# step until nothing left to step
simgr.run()
print(simgr)
print(simgr.deadended)
'''
# classify authenticated state
simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome' in s.posix.dumps(1))
print(simgr.authenticated)
'''
for i in range(len(simgr.deadended)):
    str = simgr.deadended[i].posix.dumps(1)
    if b'Welcome' in str:
        print(simgr.deadended[i], end=' ')
        print(str)
'''
simgr.run(until=lambda sm:len(sm.active) > 1)
print(simgr)
for i in range(len(simgr.active)):
    if b'SOSNEAKY' in simgr.active[i].posix.dumps(0):
        print(simgr.active[i].posix.dumps(0))
'''
