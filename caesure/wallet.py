# -*- Mode: Python -*-

# unused - temporary holding spot for the wallet code taken out of
#   caesure.  eventually I'll discover whatever sort of official rpc
#   calls exist to make it possible to have/use light clients and
#   implement whatever side of that I need.

# wallet file format: (<8 bytes of size> <private-key>)+
class wallet:

    # self.keys  : public_key -> private_key
    # self.addrs : addr -> public_key
    # self.value : addr -> { outpoint : value, ... }

    def __init__ (self, path):
        self.path = path
        self.keys = {}
        self.addrs = {}
        self.outpoints = {}
        # these will load from the cache
        self.last_block = 0
        self.total_btc = 0
        self.value = {}
        #
        try:
            file = open (path, 'rb')
        except IOError:
            file = open (path, 'wb')
            file.close()
            file = open (path, 'rb')
        while 1:
            size = file.read (8)
            if not size:
                break
            else:
                size, = struct.unpack ('<Q', size)
                key = file.read (size)
                public_key = key[-65:] # XXX
                self.keys[public_key] = key
                pub0 = rhash (public_key)
                addr = key_to_address (pub0)
                self.addrs[addr] = public_key
                self.value[addr] = {} # overriden by cache if present
        # try to load value from the cache.
        self.load_value_cache()

    def load_value_cache (self):
        db = the_block_db
        cache_path = self.path + '.cache'
        try:
            file = open (cache_path, 'rb')
        except IOError:
            pass
        else:
            self.last_block, self.total_btc, self.value = pickle.load (file)
            file.close()
        db_last = db.last_block
        if not len(self.keys):
            print 'no keys in wallet'
            self.last_block = db_last
            self.write_value_cache()
        elif db_last < self.last_block:
            print 'the wallet is ahead of the block chain.  Disabling wallet for now.'
            global the_wallet
            the_wallet = None
        elif self.last_block < db_last:
            print 'scanning %d blocks from %d-%d' % (db_last - self.last_block, self.last_block, db_last)
            self.scan_block_chain (self.last_block)
            self.last_block = db_last
            # update the cache
            self.write_value_cache()
        else:
            print 'wallet cache is caught up with the block chain'
        # update the outpoint map
        for addr, outpoints in self.value.iteritems():
            for outpoint, value in outpoints.iteritems():
                self.outpoints[outpoint] = value
        print 'total btc in wallet:', bcrepr (self.total_btc)

    def write_value_cache (self):
        cache_path = self.path + '.cache'
        file = open (cache_path, 'wb')
        self.last_block = the_block_db.last_block
        pickle.dump ((self.last_block, self.total_btc, self.value), file)
        file.close()

    def new_key (self):
        k = KEY()
        k.generate()
        key = k.get_privkey()
        size = struct.pack ('<Q', len(key))
        file = open (self.path, 'ab')
        file.write (size)
        file.write (key)
        file.close()
        pubkey = k.get_pubkey()
        addr = key_to_address (rhash (pubkey))
        self.addrs[addr] = pubkey
        self.keys[pubkey] = key
        self.value[addr] = {}
        self.write_value_cache()
        return addr

    def check_tx (self, tx):
        dirty = False
        # did we send money somewhere?
        for outpoint, iscript, sequence in tx.inputs:
            if outpoint == NULL_OUTPOINT:
                # we don't generate coins
                continue
            sig, pubkey = parse_iscript (iscript)
            if sig and pubkey:
                addr = key_to_address (rhash (pubkey))
                if self.addrs.has_key (addr):
                    if not self.value[addr].has_key (outpoint):
                        raise KeyError ("input for send tx missing?")
                    else:
                        value = self.value[addr][outpoint]
                        self.value[addr][outpoint] = 0
                        self.outpoints[outpoint] = 0
                        self.total_btc -= value
                        dirty = True
                    print 'SEND: %s %s' % (bcrepr (value), addr,)
                    #import pdb; pdb.set_trace()
        # did we receive any moneys?
        i = 0
        rtotal = 0
        index = 0
        for value, oscript in tx.outputs:
            kind, addr = parse_oscript (oscript)
            if kind == 'address' and self.addrs.has_key (addr):
                hash = tx.get_hash()
                outpoint = hash, index
                if self.value[addr].has_key (outpoint):
                    raise KeyError ("outpoint already present?")
                else:
                    self.value[addr][outpoint] = value
                    self.outpoints[outpoint] += value
                    self.total_btc += value
                    dirty = True
                print 'RECV: %s %s' % (bcrepr (value), addr)
                rtotal += 1
            index += 1
            i += 1
        if dirty:
            self.write_value_cache()
        return rtotal

    def dump_value (self):
        addrs = self.value.keys()
        addrs.sort()
        sum = 0
        for addr in addrs:
            if len(self.value[addr]):
                print 'addr: %s' % (addr,)
                for (outpoint, index), value in self.value[addr].iteritems():
                    print '  %s %s:%d' % (bcrepr (value), outpoint.encode ('hex'), index)
                    sum += value
        print 'total: %s' % (bcrepr(sum),)

    def scan_block_chain (self, start):
        # scan the whole chain for any TX related to this wallet
        db = the_block_db
        blocks = db.num_block.keys()
        blocks.sort()
        total = 0
        for num in blocks:
            if num >= start:
                names = db.num_block[num]
                for name in names:
                    b = db[name]
                    for tx in b.transactions:
                        try:
                            n = self.check_tx (tx)
                            if len(names) > 1:
                                print 'warning: competing blocks involved in transaction!'
                            total += n
                        except:
                            print '*** bad tx'
                            tx.dump()
        print 'found %d txs' % (total,)

    def new_block (self, block):
        # only scan blocks if we have keys
        if len (self.addrs):
            for tx in block.transactions:
                self.check_tx (tx)

    def __getitem__ (self, addr):
        pubkey = self.addrs[addr]
        key = self.keys[pubkey]
        k = KEY()
        k.set_privkey (key)
        return k
    
    def build_send_request (self, value, dest_addr, fee=0):
        # first, make sure we have enough money.
        total = value + fee
        if total > self.total_btc:
            raise ValueError ("not enough funds")
        elif value <= 0:
            raise ValueError ("zero or negative value?")
        elif value < 1000000 and fee < 50000:
            # any output less than one cent needs a fee.
            raise ValueError ("fee too low")
        else:
            # now, assemble the total
            sum = 0
            inputs = []
            for addr, outpoints in self.value.iteritems():
                for outpoint, v0 in outpoints.iteritems():
                    if v0:
                        sum += v0
                        inputs.append ((outpoint, v0, addr))
                        if sum >= total:
                            break
                if sum >= total:
                    break
            # assemble the outputs
            outputs = [(value, dest_addr)]
            if sum > total:
                # we need a place to dump the change
                change_addr = self.get_change_addr()
                outputs.append ((sum - total, change_addr))
            inputs0 = []
            keys = []
            for outpoint, v0, addr in inputs:
                pubkey = self.addrs[addr]
                keys.append (self[addr])
                iscript = make_iscript ('bogus-sig', pubkey)
                inputs0.append ((outpoint, iscript, 4294967295))
            outputs0 = []
            for val0, addr0 in outputs:
                outputs0.append ((val0, make_oscript (addr0)))
            lock_time = 0
            tx = TX (inputs0, outputs0, lock_time)
            for i in range (len (inputs0)):
                tx.sign (keys[i], i)
            return tx

    def get_change_addr (self):
        # look for an empty key
        for addr, outpoints in self.value.iteritems():
            empty = True
            for outpoint, v0 in outpoints.iteritems():
                if v0 != 0:
                    empty = False
                    break
            if empty:
                # found one
                return addr
        return self.new_key()

