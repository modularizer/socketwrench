import os

class X25519:
    P = 2**255 - 19
    A24 = 121665
    # get the endianess of the system
    endianess = 'little'


    # Helper functions for finite field arithmetic
    @classmethod
    def add(cls, a, b):
        return (a + b) % cls.P

    @classmethod
    def sub(cls, a, b):
        return (a - b) % cls.P

    @classmethod
    def mul(cls, a, b):
        return (a * b) % cls.P

    @classmethod
    def inv(cls, x):
        return pow(x, cls.P - 2, cls.P)


class X25519PublicKey(bytes):

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "X25519PublicKey":
        if len(data) != 32:
            raise ValueError("Public key must be 32 bytes long")
        return cls(data)

    def public_bytes(self) -> bytes:
        return self


class X25519PrivateKey(bytes, X25519):
    def __new__(cls, private_key: bytes):
        if len(private_key) != 32:
            raise ValueError("Private key must be 32 bytes long")
        return super().__new__(cls, private_key)

    def __init__(self, private_key: bytes):
        super().__init__()
        self.public_key_obj = self._derive_public_key()

    @classmethod
    def generate(cls) -> "X25519PrivateKey":
        private_key = os.urandom(32)
        # Clamp the private key
        private_key = bytearray(private_key)
        private_key[0] &= 248
        private_key[31] &= 127
        private_key[31] |= 64
        return cls(bytes(private_key))

    def _derive_public_key(self) -> X25519PublicKey:
        # Implement scalar multiplication on Curve25519
        base_point = (9).to_bytes(32, self.endianess)
        public_key = self._scalar_mult(self, base_point)
        return X25519PublicKey(public_key)

    def public_key(self) -> X25519PublicKey:
        return self.public_key_obj

    def exchange(self, peer_public_key: X25519PublicKey) -> bytes:
        if len(peer_public_key) != 32:
            raise ValueError("Peer public key must be 32 bytes long")
        shared_secret = self._scalar_mult(self, peer_public_key)
        return shared_secret

    # Correct implementation of scalar multiplication
    def _scalar_mult(self, scalar, point):
        x1 = int.from_bytes(point, 'little')
        x2, z2 = 1, 0
        x3, z3 = x1, 1
        swap = 0

        for i in reversed(range(256)):
            bit = (scalar[i // 8] >> (i % 8)) & 1
            swap ^= bit
            x2, x3 = self._cswap(swap, x2, x3)
            z2, z3 = self._cswap(swap, z2, z3)
            swap = bit

            a = self.add(x2, z2)
            aa = self.mul(a, a)
            b = self.sub(x2, z2)
            bb = self.mul(b, b)
            e = self.sub(aa, bb)
            c = self.add(x3, z3)
            d = self.sub(x3, z3)
            da = self.mul(d, a)
            cb = self.mul(c, b)
            x3 = self.mul(self.add(da, cb), self.add(da, cb))
            z3 = self.mul(x1, self.mul(self.sub(da, cb), self.sub(da, cb)))
            x2 = self.mul(aa, bb)
            z2 = self.mul(e, self.add(aa, self.mul(self.A24, e)))

        x2, x3 = self._cswap(swap, x2, x3)
        z2, z3 = self._cswap(swap, z2, z3)
        result = self.mul(x2, self.inv(z2))
        return result.to_bytes(32, 'little')

    def _cswap(self, swap, x2, x3):
        dummy = swap * (x2 ^ x3)
        x2 ^= dummy
        x3 ^= dummy
        return x2, x3


class X25519KeyPair:
    def __init__(self):
        self.private_key, self.public_key = self.generate()

    def generate(self):
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key

    def shared_secret(self, peer_public_key: bytes) -> bytes:
        peer_key = X25519PublicKey.from_public_bytes(peer_public_key)
        return self.private_key.exchange(peer_key)

    def __iter__(self):
        return iter([self.private_key, self.public_key])

    def __len__(self):
        return 2

    def __getitem__(self, index):
        if index == 0:
            return self.private_key
        elif index == 1:
            return self.public_key
        else:
            raise IndexError("Index out of range")

    def __repr__(self):
        return f"X25519KeyPair(private_key={self.private_key}, public_key={self.public_key})"

if __name__ == '__main__':
    key_pair1 = X25519KeyPair()
    key_pair2 = X25519KeyPair()

    print(f"Key Pair 1: {key_pair1}")
    print(f"Key Pair 2: {key_pair2}")

    secret1 = key_pair1.shared_secret(key_pair2.public_key)
    secret2 = key_pair2.shared_secret(key_pair1.public_key)

    print(f"Secret 1: {secret1}")
    print(f"Secret 2: {secret2}")

    assert secret1 == secret2, "Shared secrets do not match!"
