# -*- Mode: Python -*-

import re
import sys
import zlib

bling=0

from urllib import splitquery
from cgi import escape

favicon = ('00000100010010100000010018006803000016000000280000001000000020000000010018000000000000030000120b0000120b000000000000000000009292'
           '929292929292929293939394938e8d8d8c898a8e8d8d908f908e8c8d8e8c8d919191939493929292929292929292000000000000000000000000000000010101'
           '16262221322d1a2e29142520010101000000000000000000000000000000303030404040100000010101273835455e59557167506a6048635a4a645949645940'
           '594f1a25220000004040403030301010100000000101013c524d49645b536c62597367546e6150675d4e675c4c6559506c5e5170611b26220000001010100000'
           '00003030324845546e655d776c536e654760564862593a554d3e584d60736a5771684c6a5d4a645a0101010000000000001a2a284f6a62627b6e4e6962486760'
           '59726a4d685f567267687b7074847a59756a49635c5371642b3832000000105040314b47677d7359736b5a78705e79735f78704e6b62415a525b73686b827853'
           '6f634e665d516b6141574d30505001010147615c5e756b4b67625d7c7556756f49696334524c344f4b516c61536d6250695f49665a48645b4a675d161e1c181f'
           '1f617a745b716848676059736c546f663b575048645e46645d61756c748278647c746682784c695f4e695f252c290101015a7770556d65516f69647d7638534d'
           '334e484b655e526d664a6358728273768b82506c635772644d685f1c21201000003d55514461594f69633f5d5636514c415c55516e683957514a665a798d8275'
           '8e8464847c6481754e6961101514000000232d2c4d70693a544e3b5750405e5857746c516d6757736b617c715a756b59766f5f7b7357756a40524e0000001010'
           '10000000586b685c7d7638514b49645e74938c6080776a877e6f887f7b9486809b8f617d73596f681216150000001010100000000101016b7e7a688980405e56'
           '53706a79979077968e8ca79e8ca49b6e8b84495d58161817000000101010000000001010000000010101303937566b654e6660506863647d775f78725e716c23'
           '2d2b5060600000001010100000000000000000001010101020200000000101011214140101012226250101010000000000001010101010100000000000000000'
           '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
           ).decode ('hex_codec')

from __main__ import *

class handler:

    def __init__ (self):
        pass

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
            )

    def cmd_status (self, request, parts):
        db = the_block_db
        w = the_wallet
        RP = request.push
        RP ('<h3>last block</h3>')
        RP ('<dl><dt>hash:</dt><dd>%s</dd>' % (db.last_block,))
        RP ('<dl><dt>num:</dt><dd>%d</dd>' % (db.block_num[db.last_block],))
        RP ('</dl>')
        RP ('<h3>connection</h3>')
        RP (escape (repr (bc)))
        RP ('<h3>wallet</h3>')
        if w is None:
            RP ('None')
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
                        RP ('<dd>%s %s:%d</dd>' % (bcrepr (value), outpoint.encode ('hex_codec'), index))
                        sum += value
                RP ('</dl>')
            RP ('<br>total: %s' % (bcrepr(sum),))

    def cmd_block (self, request, parts):
        db = the_block_db
        RP = request.push
        if len(parts) == 2 and len(parts[1]):
            num = int (parts[1])
        else:
            num = 0
        if db.num_block.has_key (num):
            b = db[db.num_block[num]]
            last_num = db.block_num[db.last_block]
            RP ('&nbsp;&nbsp;<a href="/admin/block/0">First Block</a>')
            RP ('&nbsp;&nbsp;<a href="/admin/block/%d">Last Block</a><br>' % last_num,)
            if num > 0:
                RP ('&nbsp;&nbsp;<a href="/admin/block/%d">Prev Block</a>' % (num-1,))
            if num < db.block_num[db.last_block]:
                RP ('&nbsp;&nbsp;<a href="/admin/block/%d">Next Block</a><br>' % (num+1,))
            RP ('\r\n'.join ([
                        '<br>prev_block: %s' % (hexify (b.prev_block),),
                        '<br>merkle_root: %s' % (hexify (b.merkle_root),),
                        '<br>timestamp: %s' % (b.timestamp,),
                        '<br>bits: %s' % (b.bits,),
                        '<br>nonce: %s' % (b.nonce,),
                        ]))
            RP ('<pre>%d transactions\r\n' % len(b.transactions))
            for tx in b.transactions:
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
            RP ('</pre>')

    def cmd_reload (self, request, parts):
        new_hand = reload (sys.modules['webadmin'])
        new_hand.handler()
        hl = sys.modules['__main__'].h.handlers
        for i in range (len (hl)):
            if hl[i] is self:
                del hl[i]
                hl.append (new_hand.handler())
                break
