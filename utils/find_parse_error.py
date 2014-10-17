# -*- Mode: Python -*-

from scan_utxo import gen_utxo
from caesure.script import parse_script, pprint_script, ScriptError
from caesure._script import ScriptError
from caesure.bitcoin import bcrepr

def frob (name):
    return name[::-1].encode ('hex')

n = 0
for txname, outputs in gen_utxo():
    for (index, amt, script) in outputs:
        try:
            script = parse_script (script)
        except ScriptError:
            print frob(txname), index, bcrepr (amt), script.encode ('hex'), repr(script)
        n += 1
print 'scanned %d scripts' % (n,)
