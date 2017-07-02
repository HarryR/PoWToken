# Proof of Work Token (ALPHA)

These ethereum smart-contracts allow you to mine a cryptographic proof of work using different algorithms, then submit the result in return for tokens with a value representative of their difficulty.

The tokens are ERC20 and ERC223 compatible and can be traded openly on all compatible exchanges, different algorithms require differing amounts of effort to produce tokens of the same difficulty, the current implementations are:

 * SHA3 (Ethereum)
 * SHA256
 * Elliptic Curve (secp256k1)

The difficulty calculation uses the number of leading `0` bits of a hash as the `1 in 2^N` chance of finding it with any input:

```python
def difficulty(data):
    bitcount = 0
    for X in [ord(X) for X in data]:
        if X:
            bits = bin(X)[2:]
            bitcount += len(bits) - len(bits.rstrip('0'))
            break
        bitcount += 8
    return bitcount
```

For example, a proof of work with difficulty 8 is at least twice as hard to find as one with difficulty 7.

## Reference Implementation

This repository provides the reference implementations and the authoritative smart-contract source code.

### Hash based Proof of Work

Hashing a random 32 byte value and the owners public key represents the difficulty/value of this type of coin, it can only be spent by the `owner`.

```
nonce = random_bytes(32)
proof = hash(owner + nonce)
value = pow(2, difficulty(proof))
```

Two variants are available: `SHA256` and `SHA3`.

The interface for registering a hash based proof of work token is:

```
function mine( bytes32 nonce );
```

### Key-Pair based Proof of Work

Hashing the public key of a random key pair represents the difficulty/value of this type of coin. It can be mined and traded offline as long as you hold the private key but there is no way other than trust to prevent a double-spend, the private key holder must sign the new owner's public key to convert it into Ethereum PoW Tokens.

```
seckey, pubkey = random_keypair()
proof = hash(pubkey)
value = pow(2, difficulty(proof))
authority = sign(seckey, hash(owner + pubkey))
```

The Ethereum implementation uses `secp256k1` and `sha3`.

The interface for registering a key-pair based proof of work token is:

```
function mine (address pubkey, uint8 v, bytes32 r, bytes32 s)
```

## Security Audit

This software is written by a security auditor, feel free to submit a GitHub Issue, or hack it and reap the rewards (if you can): PoC or GTFO.
