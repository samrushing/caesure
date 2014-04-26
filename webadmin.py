# -*- Mode: Python -*-

import re
import sys
import time
import zlib
import coro

from urllib import splitquery
from urlparse import parse_qs
from cgi import escape
from caesure._script import parse_script
from caesure.script import pprint_script

favicon = (
    'AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAAAAAAAAAAAAAAAAA'
    'AAAAAAD///8A////AP///wD9/f0A2uXsKbTN3FVFqeHlQqfe6mqhva1bsuLKj8Pfhu/v7w////8A'
    '////AP///wD///8A////AP///wD8/f0AabXfuTat7v1lrs26V7Hc0G242LSBxN2cSqvd4E2s3d2K'
    'wNKNv9LYR/z8/AH///8A////AP///wDv8/YSk7zSfkir3uJpt9i5ldToh5XU6IeV1OiHldToh5XU'
    '6IeV1OiHldToh5TU54esydNh+vr6A////wD///8AYLPgxUKo3uqV1OiHldToh5XU6IeV1OiHldTo'
    'h5XU6IeV1OiHldToh5XU6IeV1OiHlNTnh7jP1k////8A/Pz8ATSg2vpqtdW1kM3gipLQ44mV1OiH'
    'ldToh5TU54eQzeCKlNTnh5XU6IeV1OiHjcjbjYa/0ZKSzd+G5unqGY7E4ohqsc+0PVdfzQQFBvoE'
    'Bgb6OFFY0JXU6IeGwNKSAAAA/5DN4IqV1OiHWX+KtQUGBvoJDQ73UXN+vbjR2VI5pOD2WrLcyz1X'
    'X81FYmvHea29mwIDA/2U1OeHhsDSkgAAAP+QzeCKjsvdjAUGB/pql6WqlNPnh4O7zJScx9R1Xq3Y'
    'xXnA26Q9V1/NGiYp6Sc3PN4rPkTbldToh4bA0pIAAAD/kM3ginquvpsCAwP9lNPmh5XU6IeV1OiH'
    'j8LShmGs1cB9wtygPVdfzSw+RNs7VFvPLD9F25XU6IeGwNKSAAAA/5DN4IqDu8yUAAAA/YjC1JGV'
    '1OiHldToh4/D04ZGquHjUK7c2T1XX80kNDjgLkNJ2SU0OeBlkZ6tOFBX0AAAAP87VV3OapinqCU1'
    'OeAlNTrgTG14wFl/iracx9R1rdHlYlut08holaOqSmpzwk9xfL2BucmWbZupp0pqc8JKanPCSmpz'
    'wnKhsaOLx9mOTG12wUJfZ8l8sMCbuNLZU////wBFn9DiXbHYxpXU6IeV1OiHldToh5XU6IeV1OiH'
    'ldToh5XU6IeV1OiHldToh5XU6IeV1OiHk83ghuTn6Rr///8Ah8Likzat7v2GxdqUldToh5XU6IeV'
    '1OiHldToh5XU6IeV1OiHldToh5XU6IeV1OiHlNTnh7fO1lD///8A////AP39/QGtydhdSKHO3lmx'
    '2s2PzeKNldToh5XU6IeV1OiHldToh5XU6IeV1OiHlNTnh6rJ02P6+voD////AP///wD///8A////'
    'AJXH4382quv8VanQzl+028dgtNvEisnekFux2spIq97je7jPnr3R10r6+voD////AP///wD///8A'
    '////AP///wD///8A7/HxD7/P10dSruDVPqbg7mSdu7NKrOHecrrirejr7Rf///8A////AP///wD/'
    '//8A/B8AAOAPAADgBwAAgAMAAIABAAAAAQAAAAEAAAAAAAAAAAAAAAEAAIABAACAAQAAgAMAAOAH'
    'AADwDwAA/B8AAA=='
    ).decode ('base64')

from __main__ import *

# all this CSS magic is stolen from looking at the output from pident.artefact2.com
css = """
<style type="text/css">
body { font-family: monospace; }
table > tbody > tr:nth-child(odd) {
	background-color:#f0f0f0;
}
table > tbody > tr:nth-child(even) {
	background-color:#e0e0e0;
}
table { width:100%; }
tr.inrow { border:1px green; }
tr.plus > td { background-color:#80ff80; }
tr.minus > td { background-color:#ff8080; }
a.alert { color:#ff0000; }
</style>
"""

def shorten (s, w=20):
    if len(s) > w:
        return s[:w] + '&hellip;'
    else:
        return s

def shorthex (s):
    return shorten (hexify (s))

def is_normal_tx (s):
    return len(s) == 5 and s[0] == 'OP_DUP' and s[1] == 'OP_HASH160' and s[-2] == 'OP_EQUALVERIFY' and s[-1] == 'OP_CHECKSIG'

def is_pubkey_tx (s):
    return len(s) == 2 and s[1] == 'OP_CHECKSIG'

def is_p2sh_tx (s):
    return len(s) == 3 and s[0] == 'OP_HASH160' and s[2] == 'OP_EQUAL' and len(s[1]) == 42

class handler:

    def __init__ (self):
        self.pending_send = []

    def match (self, request):
        return request.path.startswith ('/admin/')

    safe_cmd = re.compile ('[a-z]+')

    def handle_request (self, request):
        parts = request.path.split ('/')[2:] # ignore ['', 'admin']
        subcmd = parts[0]
        if not subcmd:
            subcmd = 'status'
        method_name = 'cmd_%s' % (subcmd,)
        if self.safe_cmd.match (subcmd) and hasattr (self, method_name):
            request['content-type'] = 'text/html'
            request.set_deflate()
            method = getattr (self, method_name)
            request.push (
                '\r\n'.join ([
                        '<html><head>',
                        css,
                        '</head><body>',
                        '<h1>caesure admin</h1>',
                        ])
                )
            self.menu (request)
            try:
                method (request, parts)
            except SystemExit:
                raise
            except:
                request.push ('<h1>something went wrong</h1>')
                request.push ('<pre>%r</pre>' % (coro.compact_traceback(),))
            request.push ('<hr>')
            self.menu (request)
            request.push ('</body></html>')
            request.done()
        else:
            request.error (400)

    def menu (self, request):
        request.push (
            '&nbsp;&nbsp;<a href="/admin/reload">reload</a>'
            '&nbsp;&nbsp;<a href="/admin/status">status</a>'
            '&nbsp;&nbsp;<a href="/admin/block/">blocks</a>'
            '&nbsp;&nbsp;<a href="/admin/send/">send</a>'
            '&nbsp;&nbsp;<a href="/admin/connect/">connect</a>'
            '&nbsp;&nbsp;<a href="/admin/shutdown/">shutdown</a>'
            )

    def cmd_status (self, request, parts):
        db = the_block_db
        RP = request.push
        RP ('<h3>last block</h3>')
        RP ('hash[es]: %s' % (escape (repr (db.num_block[db.last_block]))))
        RP ('<br>num: %d' % (db.last_block,))
        RP ('<h3>connections</h3>')
        RP ('<table><thead><tr><th>packets</th><th>address</th><tr></thead>')
        for conn in the_connection_list:
            try:
                addr, port = conn.getpeername()
                RP ('<tr><td>%d</td><td>%s:%d</td></tr>' % (conn.packet_count, addr, port))
            except:
                RP ('<br>dead connection</br>')
        RP ('</table><hr>')

    def dump_block (self, request, b, num, name):
        RP = request.push
        RP ('\r\n'.join ([
            '<br>block: %d' % (num,),
            '<br>version: %d' % (b.version,),
            '<br>name: %s' % (name,),
            '<br>prev: %s' % (b.prev_block,),
            '<br>merk: %s' % (hexify (b.merkle_root),),
            '<br>time: %s (%s)' % (b.timestamp, time.ctime (b.timestamp)),
            '<br>bits: %s' % (b.bits,),
            '<br>nonce: %s' % (b.nonce,),
            '<br><a href="http://blockexplorer.com/b/%d">block explorer</a>' % (num,),
            '<br><a href="http://blockchain.info/block/%s">blockchain.info</a>' % (name,),
        ]))
        #RP ('<pre>%d transactions\r\n' % len(b.transactions))
        RP ('<table><thead><tr><th>num</th><th>ID</th><th>inputs</th><th>outputs</th></tr></thead>')
        for i in range (len (b.transactions)):
            self.dump_tx (request, b.transactions[i], i)
        RP ('</table>')
        #RP ('</pre>')
        
    def cmd_block (self, request, parts):
        db = the_block_db
        RP = request.push
        if len(parts) == 2 and len (parts[1]):
            name = parts[1]
            if len(name) < 64 and db.num_block.has_key (int (name)):
                name = list(db.num_block[int(name)])[0]
        else:
            name = list(db.num_block[db.last_block])[0]
        if db.has_key (name):
            b = db[name]
            num = db.block_num[name]
            RP ('<br>&nbsp;&nbsp;<a href="/admin/block/%s">First Block</a>' % (genesis_block_hash,))
            RP ('&nbsp;&nbsp;<a href="/admin/block/">Last Block</a><br>')
            if name != genesis_block_hash:
                RP ('&nbsp;&nbsp;<a href="/admin/block/%s">Prev Block</a>' % (db.prev[name],))
            else:
                RP ('&nbsp;&nbsp;Prev Block<br>')
            if db.next.has_key (name):
                names = list (db.next[name])
                if len(names) > 1:
                    longer, length = longest (names)
                    for i in range (len (names)):
                        if names[i] != longer:
                            descrip = "Next Block (Orphan Chain)"
                            aclass = ' class="alert" '
                        else:
                            descrip = "Next Block"
                            aclass = ''
                        RP ('&nbsp;&nbsp;<a href="/admin/block/%s" %s>%s</a>' % (names[i], aclass, descrip,))
                else:
                    RP ('&nbsp;&nbsp;<a href="/admin/block/%s">Next Block</a>' % (names[0],))
                RP ('<br>')
            else:
                RP ('&nbsp;&nbsp;Next Block<br>')
            self.dump_block (request, b, num, name)

    def dump_tx (self, request, tx, tx_num):
        RP = request.push
        RP ('<tr><td>%s</td><td>%s</td>\r\n' % (tx_num, shorthex (dhash (tx.raw))))
        RP ('<td><table>')
        for i in range (len (tx.inputs)):
            (outpoint, index), script, sequence = tx.inputs[i]
            RP ('<tr><td>%3d</td><td>%s:%d</td><td>%s</td></tr>' % (
                    i,
                    shorthex (outpoint),
                    index,
                    shorthex (script),
                ))
        RP ('</table></td><td><table>')
        for i in range (len (tx.outputs)):
            value, pk_script = tx.outputs[i]
            script = parse_script (pk_script)
            parsed = pprint_script (script)
            if is_normal_tx (parsed):
                h = script[2][1]
                k = key_to_address (h)
            elif is_pubkey_tx (parsed):
                pk = script[0][1]
                k = 'pk:' + key_to_address (rhash (pk))
            elif is_p2sh_tx (parsed):
                h = script[1][1]
                k = 'p2sh:' + key_to_address (h, 5)
            else:
                k = parsed
            RP ('<tr><td>%s</td><td>%s</td></tr>' % (bcrepr (value), k))
        # lock time seems to always be zero
        #RP ('</table></td><td>%s</td></tr>' % tx.lock_time,)
        RP ('</table></td></tr>')

    def cmd_reload (self, request, parts):
        new_hand = reload (sys.modules['webadmin'])
        hl = sys.modules['__main__'].h.handlers
        for i in range (len (hl)):
            if hl[i] is self:
                del hl[i]
                h0 = new_hand.handler()
                # copy over any pending send txs
                h0.pending_send = self.pending_send
                hl.append (h0)
                break
        request.push ('<h3>[reloaded]</h3>')
        self.cmd_status (request, parts)

    def match_form (self, qparts, names):
        if len(qparts) != len(names):
            return False
        else:
            for name in names:
                if not qparts.has_key (name):
                    return False
        return True

    def cmd_connect (self, request, parts):
        RP = request.push
        if request.query:
            qparts = parse_qs (request.query[1:])
            if self.match_form (qparts, ['host']):
                global bc
                ## if bc:
                ##     bc.close()
                bc = connection (qparts['host'][0])
        RP ('<form>'
            'IP Address: <input type="text" name="host" value="127.0.0.1"/><br/>'
            '<input type="submit" value="Connect"/></form>')

    def cmd_shutdown (self, request, parts):
        request.push ('<h3>Shutting down...</h3>')
        request.done()
        coro.sleep_relative (1)
        coro.set_exit()

def chain_gen (name):
    db = the_block_db
    while 1:
        if db.next.has_key (name):
            names = db.next[name]
            if len(names) > 1:
                for x in longest (names):
                    yield 1
            else:
                name = list(names)[0]
                yield 1
        else:
            break

def longest (names):
    gens = [ (name, chain_gen (name)) for name in list (names) ]
    ng = len (gens)
    left = ng
    n = 0
    while left > 1:
        for i in range (ng):
            if gens[i]:
                name, gen = gens[i]
                try:
                    gen.next()
                except StopIteration:
                    gens[i] = None
                    left -= 1
        n += 1
    [(name, _)] = [x for x in gens if x is not None]
    return name, n

