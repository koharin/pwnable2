#!/usr/bin/python 
import angr

START=0x400B30
FIND=0x403A3B
AVOID=[0x403A7E + i*60 for i in range(100)]
BUF_LEN=100

def char(state, c):
    return state.solver.And(c <= '~', c >= ' ')

p = angr.Project('./FUck_binary', auto_load_libs=False)

# set initial state
state = p.factory.blank_state(addr=START)

# set initial flag
flag = state.solver.BVS('flag', BUF_LEN*8)

# add constraint to stdin
for c in flag.chop(8):
    state.solver.add(char(state, c))

# create simulation manager
sm = p.factory.simulation_manager(state)

# create state
sm.use_technique(angr.exploration_techniques.Explorer(find=FIND, avoid=AVOID))

# run Explorer
sm.run()

# get solution
flag_input = sm.one_found.posix.dumps(0)
print(repr(flag_input))
