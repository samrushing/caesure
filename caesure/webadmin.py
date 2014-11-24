# -*- Mode: Python -*-

import re
import sys
import time
import zlib
import coro

from urllib import splitquery
from urlparse import parse_qs
from cgi import escape
from caesure._script import parse_script, ScriptError
from caesure.script import pprint_script, OPCODES, PUSH_OP
from caesure.proto import hexify, Name, name_from_hex
from caesure.bitcoin import *

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
"""

class OutputBuffer:
    def __init__ (self, request):
        self.request = request
        self.data = []
        self.size = 0
    def push (self, *items):
        self.data.extend (items)
        self.size += sum (len (x) for x in items)
        if self.size > 8000:
            self.flush()
    def flush (self):
        data, self.data = self.data, []
        self.request.push (''.join (data))
        self.size = 0

def shorten (s, w=20):
    if len(s) > w:
        return SPAN (s, klass="ellipsis")
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

def is_multi_tx (s):
    # OP_3 pubkey0 pubkey1 pubkey2 OP_3 OP_CHECKMULTISIG
    if is_checkmultisig (s[-1]):
        n0 = unrender_int (s[0][1])
        n1 = unrender_int (s[-2][1])
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
            return key_to_address (rhash (pubkey))
        else:
            return shorthex (pubkey)
    elif p[0] == (0, '', PUSH_OP) and all ([x[0] == 0 for x in p[1:]]):
        # p2sh redeem
        sigs = p[1:-1]
        try:
            redeem = parse_script (p[-1][1])
            probe = is_multi_tx (redeem)
            if probe is not None:
                _, val = probe
            else:
                val = repr(probe)
            return 'p2sh (%d sigs):%s' % (len(sigs), val)
        except ScriptError:
            return 'bad p2sh'
    elif len(p) == 1 and p[0][0] == 0:
        return 'sig'
    else:
        return repr (pprint_script (p))

class handler:

    def __init__ (self, global_state):
        self.pending_send = []
        self.G = global_state

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
            OB = OutputBuffer (request)
            PUSH = OB.push
            PUSH (
                elem0 ('html'),
                HEAD (STYLE (css, type='text/css')),
                elem0 ('body'),
                H1 ('caesure admin'),
                elem0 ('hr'),
            )
            self.menu (PUSH)
            try:
                method (request, PUSH, parts)
            except SystemExit:
                raise
            except:
                request.push ('<h1>something went wrong</h1>')
                request.push ('<pre>%r</pre>' % (coro.compact_traceback(),))
            PUSH (elem0 ('hr'))
            self.menu (PUSH)
            PUSH (elems1 ('body', 'html'))
            OB.flush()
            request.done()
        else:
            request.error (400)

    def menu (self, PUSH):
        space = '&nbsp;'
        space2 = space * 2
        PUSH (
            space2 + A ('reload', href="/admin/reload"),
            space2 + A ('status', href="/admin/status"),
            space2 + A ('connections', href="/admin/connections"),            
            space2 + A ('blocks', href="/admin/block"),
            space2 + A ('pool', href="/admin/pool"),
            space2 + A ('ledger', href="/admin/ledger"),
            space2 + A ('connect', href="/admin/connect"),
            space2 + A ('shutdown', href="/admin/shutdown"),
        )

    def cmd_status (self, request, PUSH, parts):
        r = self.G.recent_blocks
        oldest = r.root
        leaves = [(lx.height, lx) for lx in r.leaves]
        leaves.sort()
        leaves.reverse()
        PUSH (H2 ('status'))
        if self.G.hoover.running:
            PUSH (H3 ('synchronizing block chain'))
            bh = self.G.hoover
            PUSH (autotable ([
                ('in_flight.avail', bh.in_flight_sem.avail),
                ('|ready|', len(bh.ready)),
                ('target', bh.target),
                ('|queue|', len(bh.queue)),
                ('remaining', bh.remaining),
                ])
            )
        else:
            PUSH (H3 ('synchronized'))
        PUSH (H2 ('blockchain tips'))
        for height, lx in leaves:
            b = self.G.block_db[lx.block_name]
            PUSH (autotable ([
                ('height', height),
                ('version', b.version),
                ('name', '%064x' % (b.name,)),
                ('prev', '%064x' % (b.prev_block,)),
                ('merk', '%064x' % (b.merkle_root,)),
                ('time', '%s (%s)' % (b.timestamp, time.ctime (b.timestamp))),
                ('bits', b.bits),
                ('nonce', b.nonce),
                ('txns', len(b.transactions)),
            ]))
            PUSH (elemz ('br'))
        PUSH (H2 ('connections'))
        PUSH (autotable ([
            ('in_conn_sem.avail', G.in_conn_sem.avail),
            ('out_conn_sem.avail', G.out_conn_sem.avail),
            ('|connections|', len(G.connection_map)),
            ])
        )

    def cmd_connections (self, request, PUSH, parts):
        PUSH (
            H3 ('connections'),
            elem0 ('table'),
            thead ('#', 'packets', 'address', 'port', 'height', 'services', 'relay', 'direction', 'protocol', 'version', 'name'),
        )
        i = 1
        items = self.G.connection_map.items()
        items.sort (lambda (ak,av),(bk,bv): cmp (av.direction, bv.direction))
        for addr, conn in items:
            ip, port = conn.other_addr
            if conn.other_version is not None:
                p = conn.other_version.version
                v = conn.other_version.sub_version_num
                h = conn.other_version.start_height
                s = conn.other_version.services
                r = int(conn.other_version.relay)
            else:
                p = 0
                v = 'N/A'
                h = 0
                s = 0
                r = 0
            PUSH (trow (i, conn.packet_count, ip, port, h, s, r, conn.direction, p, v, conn.other_name))
            i += 1
        PUSH (elem1 ('table'))

    def dump_block (self, PUSH, b, num, name):
        PUSH (
            autotable ([
                ('block', num),
                ('version', b.version),
                ('name', '%064x' % (b.name,)),
                ('prev', '%064x' % (b.prev_block,)),
                ('merk', '%064x' % (b.merkle_root,)),
                ('time', '%s (%s)' % (b.timestamp, time.ctime (b.timestamp))),
                ('bits', '%08x' % (b.bits,)),
                ('nonce', b.nonce),
                ('txns', len(b.transactions)),
                ('size', len(b.raw)),
            ]),
            elem0 ('br'), A ('block explorer', href="http://blockexplorer.com/block/%064x" % (b.name)),
            elem0 ('br'), A ('blockchain.info', href="http://blockchain.info/block/%064x" % (b.name)),
        )
        PUSH (elem0 ('table'), thead ('num', 'name', 'inputs', 'outputs'))
        for i in range (len (b.transactions)):
            self.dump_tx (PUSH, b.transactions[i], i)
        PUSH (elem1 ('table'))

    def cmd_block (self, request, PUSH, parts):
        db = self.G.block_db
        space2 = ent ('nbsp') * 2
        if len(parts) == 2 and len (parts[1]):
            name = parts[1]
            if len(name) < 64 and re.match ('^[0-9]+$', name) and db.num_block.has_key (int (name)):
                names = list (db.num_block[int(name)])
                name, length = longest (names)
            else:
                name = name_from_hex (name)
        else:
            name = list(db.num_block[db.last_block])[0]
        if db.has_key (name):
            b = db[name]
            num = db.block_num[name]
            PUSH (
                elem0 ('br'),
                space2,
                A ('First Block', href='/admin/block/%064x' % (genesis_block_hash,)),
                space2,
                A ('Last Block', href='/admin/block/'),
                elem0 ('br'),
            )
            if name != genesis_block_hash:
                PUSH (space2, A ('Prev Block', href='/admin/block/%064x' % (db.prev[name],)))
            else:
                PUSH (space2, 'Prev Block', elemz ('br'))
            names = db.next (name)
            if len(names) > 1:
                longer, length = longest (names)
                for i in range (len (names)):
                    if names[i] != longer:
                        descrip = "Next Block (Orphan Chain)"
                        aclass = 'alert'
                    else:
                        descrip = "Next Block"
                        aclass = ''
                    PUSH (space2 + A (descrip, href='/admin/block/%064x' % (names[i],), klass=aclass))
            elif len(names) == 1:
                PUSH (space2 + A ('Next Block', href='/admin/block/%064x' % (names[0],)))
            else:
                PUSH (space2, 'Next Block', elemz ('br'))
            PUSH (elemz ('br'))
            self.dump_block (PUSH, b, num, name)

    def dump_tx (self, PUSH, tx, tx_num):
        PUSH (
            elem0 ('tr'),
            TD (tx_num),
            TD (shorten (Name (dhash (tx.raw)).hex())),
            elem0 ('td'),
            elem0 ('table'),
        )
        for i in range (len (tx.inputs)):
            (outpoint, index), script, sequence = tx.inputs[i]
            if tx_num == 0:
                script = shorthex (script)
            else:
                script = describe_iscript (parse_script (script))
            PUSH (trow (shorten (outpoint.hex()), index, script))
        PUSH (elems1 ('table', 'td'))
        PUSH (elem0 ('td'), elem0 ('table'))
        for i in range (len (tx.outputs)):
            value, pk_script = tx.outputs[i]
            kind, addr = get_output_addr (pk_script)
            if kind == 'normal':
                kind = ''
            else:
                kind = kind + ':'
            k = '%s%s' % (kind, addr)
            PUSH (trow (i, bcrepr (value), k))
        #RP ('</table></td><td>%s</td></tr>' % tx.lock_time,)
        PUSH (elems1 ('table', 'td', 'tr'))

    def cmd_pool (self, request, PUSH, parts):
        PUSH (
            H3 ('transaction pool'),
            elem0 ('table'),
        )
        txns = self.G.txn_pool.pool.values()
        i = 0
        for tx in txns:
            self.dump_tx (PUSH, tx, i)
            i += 1
        PUSH (elem1 ('table'))

    def cmd_reload (self, request, PUSH, parts):
        new_hand = reload (sys.modules['caesure.webadmin'])
        h = self.G.http_server
        hl = h.handlers
        h0 = new_hand.handler (self.G)
        for i in range (len (h.handlers)):
            if isinstance (hl[i], coro.http.handlers.auth_handler) and hl[i].handler is self:
                hl[i].handler = h0
                break
            elif hl[i] is self:
                hl[i] = h0
                break
        request.push ('<h3>[reloaded]</h3>')
        G.webadmin_handler = h0
        self.cmd_status (request, PUSH, parts)

    def match_form (self, qparts, names):
        if len(qparts) != len(names):
            return False
        else:
            for name in names:
                if not qparts.has_key (name):
                    return False
        return True

    def cmd_connect (self, request, PUSH, parts):
        from caesure.server import Connection, get_my_addr
        if request.query:
            qparts = parse_qs (request.query[1:])
            if self.match_form (qparts, ['host']):
                host = qparts['host'][0]
                parts = host.split (':')
                if len(parts) == 2:
                    port = int (parts[1])
                else:
                    port = 8333
                he_addr = (qparts['host'][0], port)
                me_addr = get_my_addr (he_addr)
                bc = Connection (me_addr, he_addr)
        PUSH (H3 ('[note: IPV4 only as of yet]'))
        PUSH (
            elem0 ('form'),
            'IP Address: ',
            elemz ('input', type="text", name="host", value="127.0.0.1:8333"),
            elemz ('input', type="submit", value="Connect"),
        )

    def cmd_ledger (self, request, PUSH, parts):
        r = self.G.recent_blocks
        oldest = r.root
        leaves = r.leaves
        leaves = [(lx.height, lx) for lx in leaves]
        leaves.sort()
        leaves.reverse()
        PUSH (H2 ('ledger leaves'))

        def ledger_table (lx):
            return autotable ([
                ('height', lx.height),
                ('name', hex(lx.block_name)),
                ('total', bcrepr (lx.total + lx.lost)),
                ('live', bcrepr (lx.total)),
                ('lost', bcrepr (lx.lost)),
                ('fees', bcrepr (lx.fees)),
                ('|utxo|', len(lx.outpoints)),
            ])

        for height, lx in leaves:
            PUSH (ledger_table (lx))
            PUSH (elemz ('br'))
        PUSH (H2 ('trailing ledger (at horizon)'))
        PUSH (ledger_table (oldest))
        db = G.block_db
        values = r.blocks.values()
        values.sort (lambda a,b: cmp (b.height, a.height))
        PUSH (H2 ('RecentBlocks.blocks'))
        PUSH (elem0 ('table', style="width:auto"))
        PUSH (thead ('height', 'name', 'prev'))
        r = []
        for lx in values:
            row = [lx.height, hex(lx.block_name), hex(db.prev[lx.block_name])]
            r.append (wrapn ('tr', [wrap ('td', x) for x in row]))
        PUSH (''.join (r))
        PUSH (elem1 ('table'))

    def cmd_shutdown (self, request, PUSH, parts):
        request.push (H3 ('Shutting down...'))
        request.done()
        coro.sleep_relative (1)
        coro.set_exit()


def chain_gen (name):
    from __main__ import G
    db = G.block_db
    while 1:
        names = db.next (name)
        if len(names) > 1:
            for x in longest (names):
                yield 1
        elif len(names) == 1:
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
