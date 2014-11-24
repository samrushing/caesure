# -*- Mode: Python -*-

from scan_utxo import gen_utxo
from caesure.script import parse_script, pprint_script, ScriptError, OPCODES, PUSH_OP
from caesure._script import ScriptError

def is_p2sh (s):
    return (
        len(s) == 3
        and s[0] == (2, OPCODES.OP_HASH160)
        and s[2] == (2, OPCODES.OP_EQUAL)
        and s[1][0] == 0
        and s[1][2] == PUSH_OP
        and len(s[1][1]) == 20
    )

for txname, index, amt, script in gen_utxo():
    try:
        script = parse_script (script)
        if is_p2sh (script):
            print pprint_script (script)
    except ScriptError:
        # there are quite a few broken outpoint scripts in the utxo set.
        pass
        
    
