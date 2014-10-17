# -*- Mode: Python -*-

from scan_utxo import gen_utxo
from caesure.script import parse_script, pprint_script, ScriptError
from caesure._script import ScriptError

for txname, outputs in gen_utxo():
    for (index, amt, script) in outputs:
        try:
            script = parse_script (script)
            if len(script) == 3:
                print pprint_script (script)
        except ScriptError:
            print 'bogus', txname.encode("hex")
        
    
