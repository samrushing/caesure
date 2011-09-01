# -*- Mode: Python -*-

import re
import sys
import time
import zlib

from urllib import splitquery
from urlparse import parse_qs
from cgi import escape

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
</style>
"""

def shorten (s, w=20):
    if len(s) > w:
        return s[:w] + '&hellip;'
    else:
        return s

def shorthex (s):
    return shorten (hexify (s))

class handler:

    def __init__ (self):
        self.pending_send = []

    def match (self, request):
        path, params, query, fragment = request.split_uri()
        if path == '/favicon.ico':
            return True
        else:
            return path.startswith ('/admin/')

    safe_cmd = re.compile ('[a-z]+')

    def handle_request (self, request):
        path, params, query, fragment = request.split_uri()
        if path == '/favicon.ico':
            request['Content-Type'] = 'image/x-icon'
            request.push (favicon)
            request.done()
        else:
            parts = path.split ('/')[2:] # ignore ['', 'admin']
            subcmd = parts[0]
            if not subcmd:
                subcmd = 'status'
            method_name = 'cmd_%s' % (subcmd,)
            if self.safe_cmd.match (subcmd) and hasattr (self, method_name):
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
                    request.push ('<pre>%r</pre>' % (asyncore.compact_traceback(),))
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
            '&nbsp;&nbsp;<a href="/admin/wallet/">wallet</a>'
            '&nbsp;&nbsp;<a href="/admin/send/">send</a>'
            '&nbsp;&nbsp;<a href="/admin/connect/">connect</a>'
            '&nbsp;&nbsp;<a href="/admin/shutdown/">shutdown</a>'
            )

    def cmd_status (self, request, parts):
        db = the_block_db
        w = the_wallet
        RP = request.push
        RP ('<h3>last block</h3>')
        RP ('hash: %s' % (db.last_block,))
        RP ('<br>num: %d' % (db.block_num[db.last_block],))
        if len (db.embargo):
            RP ('<hr>%d blocks in embargo:' % (len(db.embargo),))
            for name in db.embargo.keys():
                RP ('<br>%s' % name)
            RP ('<hr>')
        RP ('<h3>connections</h3>')
        RP ('<table><thead><tr><th>packets</th><th>address</th><tr></thead>')
        for conn in the_connection_list:
            try:
                addr, port = conn.getpeername()
                RP ('<tr><td>%d</td><td>%s:%d</td></tr>' % (conn.packet_count, addr, port))
            except:
                RP ('<br>dead connection</br>')
        RP ('</table><hr>')
        RP ('<h3>wallet</h3>')
        if w is None:
            RP ('No Wallet')
        else:
            RP ('total btc: %s' % (bcrepr (w.total_btc),))

    def dump_block (self, request, b, num):
        RP = request.push
        RP ('\r\n'.join ([
                    '<br>block: %d' % (num,),
                    '<br>prev_block: %s' % (b.prev_block,),
                    '<br>merkle_root: %s' % (hexify (b.merkle_root),),
                    '<br>timestamp: %s (%s)' % (b.timestamp, time.ctime (b.timestamp)),
                    '<br>bits: %s' % (b.bits,),
                    '<br>nonce: %s' % (b.nonce,),
                    '<br><a href="http://blockexplorer.com/b/%d">block explorer</a>' % (num,),
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
        if len(parts) == 2:
            if parts[1] == 'embargo':
                if len(db.embargo):
                    for name, block in db.embargo.iteritems():
                        RP ('<hr>%s' % (name,))
                        self.dump_block (request, block, db.last_block_index + 1)
                else:
                    RP ('<h3>no blocks in embargo</h3>')
                return
            elif len(parts[1]):
                try:
                    num = int (parts[1])
                except ValueError:
                    num = db.last_block_index
            else:
                num = db.last_block_index
        else:
            num = db.last_block_index
        if db.num_block.has_key (num):
            b = db[db.num_block[num]]
            last_num = db.block_num[db.last_block]
            RP ('<br>&nbsp;&nbsp;<a href="/admin/block/0">First Block</a>')
            RP ('&nbsp;&nbsp;<a href="/admin/block/">Last Block</a><br>')
            RP ('&nbsp;&nbsp;<a href="/admin/block/embargo">Embargo</a>')
            if num > 0:
                RP ('&nbsp;&nbsp;<a href="/admin/block/%d">Prev Block</a>' % (num-1,))
            else:
                RP ('&nbsp;&nbsp;Prev Block<br>')
            if num < db.block_num[db.last_block]:
                RP ('&nbsp;&nbsp;<a href="/admin/block/%d">Next Block</a><br>' % (num+1,))
            else:
                RP ('&nbsp;&nbsp;Next Block<br>')
            self.dump_block (request, b, num)

    def dump_tx (self, request, tx, tx_num):
        RP = request.push
        RP ('<tr><td>%s</td><td>%s</td>\r\n' % (tx_num, shorthex (dhash (tx.render()))))
        RP ('<td><table>')
        for i in range (len (tx.inputs)):
            (outpoint, index), script, sequence = tx.inputs[i]
            tr_class = ''
            if the_wallet and the_wallet.outpoints.has_key ((outpoint, index)):
                tr_class = ' class="minus"'
            else:
                col0, col1 = '', ''
            RP ('<tr%s><td>%3d</td><td>%s:%d</td><td>%s</td><td>%s</td></tr>' % (
                    tr_class,
                    i,
                    shorthex (outpoint),
                    index,
                    shorthex (script),
                    sequence)
                )
        RP ('</table></td><td><table>')
        for i in range (len (tx.outputs)):
            value, pk_script = tx.outputs[i]
            kind, data = parse_oscript (pk_script)
            col0, col1 = '', ''
            tr_class = ''
            if kind == 'address':
                addr = data
                if the_wallet and the_wallet.addrs.has_key (addr):
                    tr_class = ' class="plus"'
                # too noisy, simplify
                kind = ''
            elif kind == 'pubkey':
                addr = key_to_address (rhash (data))
            else:
                addr = hexify (pk_script)
            RP ('<tr%s><td>%s</td><td>%s %s</td></tr>' % (tr_class, bcrepr (value), kind, addr))
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

    def cmd_wallet (self, request, parts):
        RP = request.push
        w = the_wallet
        if not w:
            RP ('<h3>no wallet</h3>')
        else:
            if parts == ['wallet', 'newkey']:
                nk = w.new_key()
                RP ('<p>New Key: %s</p>' % (nk,))
            else:
                addrs = w.value.keys()
                addrs.sort()
                sum = 0
                RP ('<p>%d addrs total</p>' % (len(addrs),))
                for addr in addrs:
                    RP ('<dl>')
                    if len(w.value[addr]):
                        RP ('<dt>addr: %s</dt>' % (addr,))
                        for (outpoint, index), value in w.value[addr].iteritems():
                            RP ('<dd>%s %s:%d</dd>' % (bcrepr (value), outpoint.encode ('hex'), index))
                            sum += value
                    RP ('</dl>')
                RP ('<br>total: %s' % (bcrepr(sum),))
                RP ('<br>unused keys:')
                for addr in addrs:
                    if not len(w.value[addr]):
                        RP ('<br>%s' % (addr,))
                RP ('<p><a href="/admin/wallet/newkey">Make a New Key</a></p>')

    def match_form (self, qparts, names):
        if len(qparts) != len(names):
            return False
        else:
            for name in names:
                if not qparts.has_key (name):
                    return False
        return True

    def cmd_connect (self, request, parts):
        path, params, query, fragment = request.split_uri()
        RP = request.push
        if query:
            qparts = parse_qs (query[1:])
            if self.match_form (qparts, ['host']):
                global bc
                if bc:
                    bc.close()
                bc = connection (qparts['host'][0])
        RP ('<form>'
            'IP Address: <input type="text" name="host" value="127.0.0.1"/><br/>'
            '<input type="submit" value="Connect"/></form>')

    def cmd_send (self, request, parts):
        path, params, query, fragment = request.split_uri()
        RP = request.push
        w = the_wallet
        if not w:
            RP ('<h3>no wallet</h3>')
            return
        if query:
            qparts = parse_qs (query[1:])
            if self.match_form (qparts, ['amount', 'addr', 'fee']):
                btc = float_to_btc (float (qparts['amount'][0]))
                fee = float_to_btc (float (qparts['fee'][0]))
                addr = qparts['addr'][0]
                try:
                    _ = address_to_key (addr) # verify it's a real address
                except:
                    RP ('<br><h3>Bad Address: %r</h3>' % escape (addr),)
                else:
                    tx = w.build_send_request (btc, addr, fee)
                    RP ('<br>send tx:<br><pre>')
                    self.dump_tx (request, tx, 0)
                    self.pending_send.append (tx)
                    RP ('</pre>')
            elif self.match_form (qparts, ['cancel', 'index']):
                index = int (qparts['index'][0])
                del self.pending_send[index]
                RP ('<h3>deleted tx #%d</h3>' % (index,))
            elif self.match_form (qparts, ['confirm', 'index']):
                index = int (qparts['index'][0])
                tx = self.pending_send[index]
                RP ('<h3>sent tx #%d</h3>' % (index,))
                # send it
                bc.push (make_packet ('tx', tx.render()))
                # forget about it
                del self.pending_send[index]
            else:
                RP ('???')
        RP ('<form>'
            'Amount to Send: <input type="text" name="amount" /><br/>'
            'To Address: <input type="text" name="addr" /><br/>'
            'Fee: <input type="text" name="fee" value="0.0005"><br/>'
            '<input type="submit" value="Send"/></form>'
            '<p>Clicking "Send" will queue up the send request, where it can be examined and either confirmed or cancelled</p>'
            '<p>Note: as currently designed, the bitcoin network may not forward transactions without fees, which could result in bitcoins being "stuck".  Sending tiny amounts (less than 0.01) requires a fee.  This includes the amount left in "change"!</p>'
            )
        if not self.pending_send:
            RP ('<h3>no pending send requests</h3>')
        else:
            RP ('<h3>pending send requests</h3>')
            for i in range (len (self.pending_send)):
                RP ('<hr>#%d: <br>' % (i,))
                RP ('<pre>')
                self.dump_tx (request, self.pending_send[i], i)
                RP ('</pre>')
                RP ('<form><input type="hidden" name="index" value="%d">'
                    '<input type="submit" name="confirm" value="confirm"/>'
                    '<input type="submit" name="cancel" value="cancel"/>'
                    '</form>' % (i,))

    def cmd_shutdown (self, request, parts):
        request.push ('<h3>Shutting down...</h3>')
        if the_wallet:
            the_wallet.write_value_cache()
        import os
        os._exit (os.EX_OK)
