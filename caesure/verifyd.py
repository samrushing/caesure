# -*- Mode: Python; indent-tabs-mode: nil -*-

import argparse
import os
import coro
import struct
from caesure.bitcoin import TX
from coro.asn1.python import encode, decode

W = coro.write_stderr

def serve (G):
    path = os.path.join (G.args.base, G.args.file)
    s = coro.sock (coro.AF.UNIX, coro.SOCK.STREAM)
    try:
        os.unlink (path)
    except OSError:
        pass
    s.bind (path)
    s.listen (100)
    try:
        while 1:
            conn, addr = s.accept()
            if coro.fork() == 0:
                coro.spawn (go, G, conn)
                return
            else:
                conn.close()
        s.close()
    finally:
        coro.set_exit()

def go (G, s):
    try:
        while 1:
            # what are the per-txn size limits?
            pktlen = s.recv_exact (4)
            if not pktlen:
                break
            else:
                pktlen, = struct.unpack ('>I', pktlen)
                packet = s.recv_exact (pktlen)
                data, size = decode (packet)
                assert size == pktlen
                [block_timestamp, raw_tx, lock_scripts] = data
                tx = TX()
                tx.unpack (raw_tx)
                result = True
                for i in range (len (tx.inputs)):
                    lock_script = lock_scripts[i]
                    try:
                        tx.verify (i, lock_script, block_timestamp)
                    except SystemError:
                        result = False
                pkt = encode (result)
                s.writev ([struct.pack ('>I', len(pkt)), pkt])
    except EOFError:
        pass
    coro.set_exit()
        
class GlobalState:
    pass

G = GlobalState()

p = argparse.ArgumentParser()
p.add_argument ('-b', '--base', help='data directory', default='/usr/local/caesure', metavar='PATH')
p.add_argument ('-f', '--file', help='server socket filename', default='verifyd.sock', metavar='PATH')
args = G.args = p.parse_args()
coro.spawn (serve, G)
coro.event_loop()
