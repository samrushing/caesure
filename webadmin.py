# -*- Mode: Python -*-

import re
import sys
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
                            '<html><head></head>'
                            '<body>'
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
        RP ('<h3>connection</h3>')
        RP (escape (repr (bc)))
        try:
            RP ('<br>here: %s' % (bc.getsockname(),))
            RP ('<br>there: %s' % (bc.getpeername(),))
        except:
            RP ('<br>no connection</br>')
        RP ('<h3>wallet</h3>')
        if w is None:
            RP ('No Wallet')
        else:
            RP ('total btc: %s' % (bcrepr (w.total_btc),))

    def dump_block (self, request, b):
        RP = request.push
        RP ('\r\n'.join ([
                    '<br>prev_block: %s' % (hexify (b.prev_block),),
                    '<br>merkle_root: %s' % (hexify (b.merkle_root),),
                    '<br>timestamp: %s' % (b.timestamp,),
                    '<br>bits: %s' % (b.bits,),
                    '<br>nonce: %s' % (b.nonce,),
                    ]))
        RP ('<pre>%d transactions\r\n' % len(b.transactions))
        for tx in b.transactions:
            self.dump_tx (request, tx)
        RP ('</pre>')
        
    def cmd_block (self, request, parts):
        db = the_block_db
        RP = request.push
        if len(parts) == 2:
            if parts[1] == 'embargo':
                if len(db.embargo):
                    for name, block in db.embargo.iteritems():
                        RP ('<hr>%s' % (name,))
                        self.dump_block (request, unpack_block (block))
                else:
                    RP ('<h3>no blocks in embargo</h3>')
                return
            elif len(parts[1]):
                num = int (parts[1])
            else:
                num = 0
        else:
            num = 0
        if db.num_block.has_key (num):
            b = db[db.num_block[num]]
            last_num = db.block_num[db.last_block]
            RP ('<br>&nbsp;&nbsp;<a href="/admin/block/0">First Block</a>')
            RP ('&nbsp;&nbsp;<a href="/admin/block/%d">Last Block</a><br>' % last_num,)
            RP ('&nbsp;&nbsp;<a href="/admin/block/embargo">Embargo</a>')
            if num > 0:
                RP ('&nbsp;&nbsp;<a href="/admin/block/%d">Prev Block</a>' % (num-1,))
            if num < db.block_num[db.last_block]:
                RP ('&nbsp;&nbsp;<a href="/admin/block/%d">Next Block</a><br>' % (num+1,))
            self.dump_block (request, b)

    def dump_tx (self, request, tx):
        RP = request.push
        RP ('tx: %s\r\n' % (hexify (dhash (tx.render()))))
        RP ('inputs: %d\r\n' % (len(tx.inputs)))
        for i in range (len (tx.inputs)):
            (outpoint, index), script, sequence = tx.inputs[i]
            RP ('%3d %s:%d %s %d\r\n' % (i, hexify(outpoint), index, hexify (script), sequence))
        RP ('%d outputs\n' % (len(tx.outputs)))
        for i in range (len (tx.outputs)):
            value, pk_script = tx.outputs[i]
            addr = parse_oscript (pk_script)
            if not addr:
                addr = hexify (pk_script)
            RP ('%3d %s %s\n' % (i, bcrepr (value), addr))
        RP ('lock_time: %s\n' % tx.lock_time)

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
                    self.dump_tx (request, tx)
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
                self.dump_tx (request, self.pending_send[i])
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
