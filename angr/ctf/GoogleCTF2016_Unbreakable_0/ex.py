#!/usr/bin/python 
import angr

# load binary
p = angr.Project('./unbreakable-enterprise-product-activation', auto_load_libs=False)

# max length from strncpy is 0x43
input_size = 0x43

# initialize argv1
state = p.factory.entry_state()
argv1 = state.solver.BVS('argv1', 8*input_size)

# initial state with argument input
state = p.factory.entry_state(args=[p.filename, argv1])

# default is 60 symbolic bytes. so increase size
state.libc.symbolic_bytes = input_size + 1

# argv1 start with CTF{
state.add_constraints(argv1.chop(8)[0]=='C') 
state.add_constraints(argv1.chop(8)[1]=='T') 
state.add_constraints(argv1.chop(8)[2]=='F') 
state.add_constraints(argv1.chop(8)[3]=='{') 

simgr = p.factory.simgr(state)

# 0x400830: success message path, 0x400850: failure path
simgr.explore(find=0x400830, avoid=0x400850)

print(simgr.found[0].solver.eval(argv1, cast_to=bytes))
