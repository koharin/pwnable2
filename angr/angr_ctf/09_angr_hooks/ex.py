#!/usr/bin/python3 

import angr

proj = angr.Project('./09_angr_hooks', auto_load_lib=False)
state = proj.factory.entry_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

# hook the address of check_equals_* function is called
check_equals_call_address = 0x080486CA

# hook function
instruction_to_skip_length=5

@project.hook(check_equals_call_address, length=instruction_to_skip_length)
def skip_check_equals(state):
    # address where user input is stored
    user_input_stored_address = 0x804A034 
    user_input_stored_length = 
