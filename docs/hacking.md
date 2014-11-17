# -*- Mode: rst -*-

This file: notes for hackers, or anyone that wants to understand how
the system works.  As of now a bit thin, but I plan to fill it out
more time permitting.


Block Chain Database
====================

All blocks (orphans/forks/main-chain) are stored in an append-only
file.  Each block is preceded by an 8-byte header containing the size
of the block.

At startup, caesure will either create or load and update a checkpoint
of 'metadata.bin', containing a map of block-name to position on disk.

Other processes (see the 'txmap' directory) can open this file in
read-only mode with no impact on the running server.

The Ledger
==========

The in-memory ledger ("UTXO" == "unspent transaction outputs") uses a
'persistent' (in the functional sense) data structure that allows it
to keep multiple versions of the ledger - one for each of the last 20
blocks or so.  This also means there's no need for reorganization
during fork races.  Another important advantage - as long as you have
a pointer to a valid utxo map, you can keep it in memory.  It will not
be impacted by incoming blocks or transactions... this means you can
take your time checkpointing it to disk, or sharing it via the
network.

The Server
==========

Caesure is built using "Shrapnel", a high-performance user-threading
concurrency package originally from IronPort Systems.  It can easily
juggle thousands of connections, using different protocols,
etc... Just some highlights relevant to caesure: it supports
HTTP/HTTPS/Websockets/SPDY and includes a fast ASN1 codec.

One major goal of Caesure is to get a higher branching factor for a
well-connected site.  It should easily be able to handle hundreds of
open connections, if not thousands.

ECDSA
=====

There are three different ECDSA signature-verification
implementations.  The original uses the OpenSSL support built into
shrapnel.  Much faster is sipa's (Pieter Wuille) libsecp256k1.  A
final option uses the Crypto++ library from Wei Dai.  Unfortunately
the latter can no longer be used because of the SIGHASH
non-error-error-return bug (or rather, maybe it can be used again some
day when that bug is left behind).

OpenSSL
=======

One of my goals is to remove the need to use OpenSSL at all (I
consider it a serious security risk)... the only remaining obstacle to
this is Python's hashlib module, where the ripemd160 hash comes from.
It should be an easy matter to make a Cython implementation or wrapper
for this hash function.

Safety
======

By being written mostly in Python, many of the problems plaguing
unsafe languages do not apply to Caesure.  However, a non-trivial
amount of Caesure's code is written in Cython, which is as unsafe as C
or C++.  Therefore extra care needs to be taken with the code written
in Cython.  Currently, the packet codec and script parser/unparser are
the only such parts.  I may eventually push more of the scripting
engine into Cython, but only if necessary.  [note that with verifyd.py
on my Mac Pro I can get verification rates above 2500/sec, so this is
unlikely to be an issue soon.]


Minimalism
==========

Please take note of the size and complexity of the code.  After
correctness, I consider size to be one of the most important measures
of the quality of code.  Make it as simple as possible (no simpler).
All other things being equal, the shorter and more readable code is
better.  Pull requests that double the size of a module for a 1%
speedup are unlikely to be accepted.

And please don't bring up PEP 8. 8^)

TXMAP
=====

Caesure itself doesn't need quick access to every transaction by
name.  But many applications do... e.g. block-chain browsers.  The
txmap directory contains a start on this.  It uses leveldb to maintain
an index of all transactions (not just utxo), and could form the basis
of a nice, fast blockchain browser.
