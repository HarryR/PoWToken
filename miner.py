from __future__ import print_function
import math
import os
from collections import defaultdict
from base64 import b64decode
from binascii import unhexlify, hexlify
from ethereum import utils
import bitcoin as b


def difficulty(data):
    bitcount = 0
    for X in [ord(X) for X in data]:
        if X:
            bits = bin(X)[2:]
            bitcount += len(bits) - len(bits.rstrip('0'))
            break
        bitcount += 8
    return bitcount


class PoWToken(object):
    @property
    def owner(self):
        return None

    @property
    def value(self):
        raise NotImplementedError()

    @property
    def difficulty(self):
        return difficulty(self.value)

    def spend(self, owner):
        raise NotImplementedError()


class HashPowToken(PoWToken):
    __slots__ = ('_owner', '_nonce')

    HASH_FN = None

    def __init__(self, owner, nonce):
        assert isinstance(owner, (str, bytes))
        assert len(owner) == 20
        self._owner = owner
        assert isinstance(nonce, (str, bytes))
        assert len(nonce) == 32
        self._nonce = nonce

    @property
    def value(self):
        return self.hash(self._owner + self._nonce)

    @classmethod
    def mine(cls, owner, min_value=1):
        assert isinstance(owner, (str, bytes))
        assert len(owner) == 20
        nonce = os.urandom(32)
        while True:
            proof = cls.hash(owner + nonce)
            if 2**difficulty(proof) >= min_value:
                return cls(owner, nonce)
            nonce = proof

    def spend(self, owner=None):
        if owner is not None and owner != self._owner:
            raise ValueError()
        return "\"0x%s\"" % (hexlify(self._nonce),)


class SHA256PowToken(HashPowToken):
    @classmethod
    def hash(cls, data):
        return b.bin_sha256(data)


class SHA3PowToken(HashPowToken):
    @classmethod
    def hash(cls, data):
        return utils.sha3(data)


class ECPoWToken(PoWToken):
    __slots__ = ('_pubkey', '_seckey')

    def __init__(self, pubkey, seckey):
        assert isinstance(pubkey, (str, bytes))
        assert len(pubkey) == 20
        self._pubkey = pubkey

        assert isinstance(seckey, (str, bytes))
        assert len(seckey) == 32
        self._seckey = seckey

    @property
    def value(self):
        return utils.sha3(self._pubkey)

    @classmethod
    def mine(cls, min_value=1):
        seckey = os.urandom(32)
        while True:
            seckey = utils.sha3(seckey)
            pubkey = utils.sha3(b.privtopub(seckey)[1:])[12:]
            value = 2 ** difficulty(utils.sha3(pubkey))
            if value >= min_value:
                return cls(pubkey, seckey)

    def spend(self, owner):
        assert isinstance(owner, (str, bytes))
        assert len(owner) == 20
        # Sign it, so it can be accepted by an address
        messageHash = utils.sha3(owner + self._pubkey)
        V, R, S = b.ecdsa_raw_sign(messageHash, self._seckey)
        recoveredPublicKey = b.ecdsa_raw_recover(messageHash, (V, R, S))
        assert b.pubtoaddr(recoveredPublicKey) == b.privtoaddr(self._seckey)

        # Correctly encoded
        return ", ".join([
            "\"0x%s\"" % (hexlify(self._pubkey),),
            "%d" % (V,),
            "\"0x%064X\"" % (R,),
            "\"0x%064X\"" % (S,),
            ])


my_address = unhexlify("ca35b7d915458ef540ade6068dfe2f44e8fa733c")

coin = ECPoWToken.mine(2**5)
print('EC:', coin.spend(my_address))

coin = SHA256PowToken.mine(my_address, 2**5)
print('SHA256:', coin.spend())

coin = SHA3PowToken.mine(my_address, 2**5)
print('SHA3:', coin.spend())
