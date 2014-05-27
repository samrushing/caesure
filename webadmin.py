# -*- Mode: Python -*-

import re
import sys
import time
import zlib
import coro
import bitcoin

from urllib import splitquery
from urlparse import parse_qs
from cgi import escape
from caesure._script import parse_script
from caesure.script import pprint_script, OPCODES
from caesure.proto import hexify, Name, name_from_hex
from bitcoin import key_to_address, rhash

from html_help import *

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

css = """
<style type="text/css">
body { font-family: monospace; }
tr:nth-child(odd) {
  background-color:#f0f0f0;
}
tr:nth-child(even) {
  background-color:#e0e0e0;
}
.ellipsis {
  text-overflow: ellipsis;
  overflow: hidden;
  width:20em;
  display:block;
}
</style>
"""

def shorten (s, w=20):
    if len(s) > w:
        return wrap1 ('span', s, klass="ellipsis")
    else:
        return s

def shorthex (s):
    return shorten (hexify (s))

def is_push (x):
    return x[0] == 0

def is_cond (x):
    return x[0] == 1

def is_op (x, code):
    return x[0] == 2 and x[1] == code

def is_check (x):
    return x[0] == 3

def is_checksig (x):
    return x[0] == 3 and x[1] == OPCODES.OP_CHECKSIG

def is_checkmultisig (x):
    return x[0] == 3 and x[1] == OPCODES.OP_CHECKMULTISIG

def is_normal_tx (s):
    if (len(s) == 5
            and s[0] == (2, OPCODES.OP_DUP)
            and s[1] == (2, OPCODES.OP_HASH160)
            and s[-2] == (2, OPCODES.OP_EQUALVERIFY)
            and is_check (s[-1])):
        return 'normal', key_to_address (s[2][1])
    else:
        return None

def is_pubkey_tx (s):
    if len(s) == 2 and is_check (s[1]):
        return 'pubkey', key_to_address (rhash (s[0][1]))
    else:
        return None

def is_p2sh_tx (s):
    if (len(s) == 3
            and s[0] == (2, OPCODES.OP_HASH160)
            and s[2] == (2, OPCODES.OP_EQUAL)
            and s[1][0] == 0
            and len(s[1][1]) == 20):
        return 'p2sh', key_to_address (s[1][1], 5)

OP_NUMS = {}
for i in range (0x51, 0x61):
    OP_NUMS[i] = i - 0x50

def is_multi_tx (s):
    # OP_3 pubkey0 pubkey1 pubkey2 OP_3 OP_CHECKMULTISIG
    if is_checkmultisig (s[-1]):
        n0 = OP_NUMS.get (s[0][1], None)
        n1 = OP_NUMS.get (s[-2][1], None)
        if n0 is None or n1 is None:
            return None
        elif n1 == (len(s) - 3):
            for i in range (1, 1 + n1):
                if not s[i][0] == 0:
                    return None
            val = '%d/%d:%s' % (
                n0,
                n1,
                '\n'.join ([key_to_address (rhash (s[i][1])) for i in range (1, 1 + n1)])
            )
            return 'multi', val
        else:
            return None

def get_output_addr (pk_script):
    if len(pk_script) > 500:
        return 'big', ''
    try:
        script = parse_script (pk_script)
        probe = is_normal_tx (script)
        if not probe:
            probe = is_pubkey_tx (script)
            if not probe:
                probe = is_p2sh_tx (script)
                if not probe:
                    probe = is_multi_tx (script)
        if probe:
            return probe
        else:
            return 'other', repr (pprint_script (script))
    except:
        return 'bad', pk_script.encode ('hex')

def describe_iscript (p):
    if len(p) == 2 and p[0][0] == 0 and p[1][0] == 0:
        # PUSH PUSH
        pubkey = p[1][1]
        if pubkey[0] in ('\x02', '\x03', '\x04'):
            return 'sig ' + key_to_address (rhash (pubkey))
        else:
            return shorthex (pubkey)
    elif p[0] == (0, '') and all ([x[0] == 0 for x in p[1:]]):
        # p2sh redeem
        sigs = p[1:-1]
        redeem = parse_script (p[-1][1])
        _, val = is_multi_tx (redeem)
        return 'p2sh (%d sigs):%s' % (len(sigs), val)
    elif len(p) == 1 and p[0][0] == 0:
        return 'sig'
    else:
        return repr (pprint_script (p))

class handler:

    def __init__ (self):
        self.pending_send = []

    def match (self, request):
        return request.path.startswith ('/admin/')

    safe_cmd = re.compile ('[a-z]+')

    def handle_request (self, request):
        parts = request.path.split ('/')[2:]
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
        RP ('<table><thead><tr><th>#</th><th>packets</th><th>address</th><th>version</th></tr></thead>')
        i = 1
        for addr, conn in the_connection_map.iteritems():
            ip, port = conn.other_addr
            if conn.other_version is not None:
                v = conn.other_version.sub_version_num
            else:
                v = 'N/A'
            RP ('<tr><td>%d</td><td>%d</td><td>%s:%d</td><td>%s</td></tr>' % (i, conn.packet_count, ip, port, v))
            i += 1
        RP ('</table><hr>')

    def dump_block (self, request, b, num, name):
        RP = request.push
        RP ('\r\n'.join ([
            '<br>block: %d' % (num,),
            '<br>version: %d' % (b.version,),
            '<br>name: %064x' % (name,),
            '<br>prev: %064x' % (b.prev_block,),
            '<br>merk: %064x' % (b.merkle_root,),
            '<br>time: %s (%s)' % (b.timestamp, time.ctime (b.timestamp)),
            '<br>bits: %s' % (b.bits,),
            '<br>nonce: %s' % (b.nonce,),
            '<br>txns: %d' % (len(b.transactions),),
            '<br><a href="http://blockexplorer.com/b/%d" rel="noreferrer">block explorer</a>' % (num,),
            '<br><a href="http://blockchain.info/block/%064x" rel="noreferrer">blockchain.info</a>' % (name,),
        ]))
        #RP ('<pre>%d transactions\r\n' % len(b.transactions))
        RP ('<table style="width:100%"><thead><tr><th>num</th><th>ID</th><th>inputs</th><th>outputs</th></tr></thead>')
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
                name = name_from_hex (name)
        else:
            name = list(db.num_block[db.last_block])[0]
        if db.has_key (name):
            b = db[name]
            num = db.block_num[name]
            RP ('<br>&nbsp;&nbsp;<a href="/admin/block/%064x">First Block</a>' % (bitcoin.genesis_block_hash,))
            RP ('&nbsp;&nbsp;<a href="/admin/block/">Last Block</a><br>')
            if name != bitcoin.genesis_block_hash:
                RP ('&nbsp;&nbsp;<a href="/admin/block/%064x">Prev Block</a>' % (db.prev[name],))
            else:
                RP ('&nbsp;&nbsp;Prev Block<br>')
            if db.num_block.has_key (num + 1):
                names = list (db.num_block[num + 1])
                if len(names) > 1:
                    longer, length = longest (names)
                    for i in range (len (names)):
                        if names[i] != longer:
                            descrip = "Next Block (Orphan Chain)"
                            aclass = ' class="alert" '
                        else:
                            descrip = "Next Block"
                            aclass = ''
                        RP ('&nbsp;&nbsp;<a href="/admin/block/%064x" %s>%s</a>' % (names[i], aclass, descrip,))
                else:
                    RP ('&nbsp;&nbsp;<a href="/admin/block/%064x">Next Block</a>' % (names[0],))
                RP ('<br>')
            else:
                RP ('&nbsp;&nbsp;Next Block<br>')
            self.dump_block (request, b, num, name)

    def dump_tx (self, request, tx, tx_num):
        RP = request.push
        RP ('<tr><td>%s</td><td>%s</td>\n' % (tx_num, shorten (Name (dhash (tx.raw)).hex())))
        RP ('<td><table>')
        for i in range (len (tx.inputs)):
            (outpoint, index), script, sequence = tx.inputs[i]
            if tx_num == 0:
                script = shorthex (script)
            else:
                script = describe_iscript (parse_script (script))
            RP ('<tr><td>%s</td><td>%d</td><td>%s</td></tr>' % (
                shorten (outpoint.hex()),
                index,
                script
            ))
        RP ('</table></td><td><table>')
        for i in range (len (tx.outputs)):
            value, pk_script = tx.outputs[i]
            kind, addr = get_output_addr (pk_script)
            if kind == 'normal':
                kind = ''
            else:
                kind = kind + ':'
            k = '%s%s' % (kind, addr)
            RP ('<tr><td>%d</td><td>%s</td><td>%s</td></tr>' % (i, bitcoin.bcrepr (value), k))
        # lock time seems to always be zero
        #RP ('</table></td><td>%s</td></tr>' % tx.lock_time,)
        RP ('</table></td></tr>')

    def cmd_reload (self, request, parts):
        new_hand = reload (sys.modules['webadmin'])
        from __main__ import h
        hl = h.handlers
        for i in range (len (h.handlers)):
            if isinstance (hl[i], coro.http.handlers.auth_handler) and hl[i].handler is self:
                h0 = new_hand.handler()
                hl[i].handler = h0
                break
            elif hl[i] is self:
                hl[i] = h0
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
