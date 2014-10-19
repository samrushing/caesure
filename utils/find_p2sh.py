# -*- Mode: Python -*-

from scan_utxo import gen_utxo
from caesure.script import parse_script, pprint_script, ScriptError, OPCODES
from caesure._script import ScriptError

def is_p2sh (s):
    return (
        len(s) == 3
        and s[0] == (2, OPCODES.OP_HASH160)
        and s[2] == (2, OPCODES.OP_EQUAL)
        and s[1][0] == 0
        and len(s[1][1]) == 20
    )

for txname, outputs in gen_utxo():
    for (index, amt, script) in outputs:
        try:
            script = parse_script (script)
            if is_p2sh (script):
                print pprint_script (script)
        except ScriptError:
            # there are quite a few broken outpoint scripts in the utxo set.
            pass
        
    
