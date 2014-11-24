# -*- Mode: Python -*-

# used to store global state throughout a caesure application.

from caesure.bitcoin import *

# fill in more defaults.
class GlobalState:
    # XXX put everything for switching to testnet here.
    MAGIC = MAGIC
    genesis_block_hash = genesis_block_hash
    BITCOIN_PORT = BITCOIN_PORT

