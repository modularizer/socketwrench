class X25519Kyber768KeyPair:
    def __init__(self):
        self.x25519 = X25519KeyPair()
        self.kyber768 = Kyber768KeyPair()

    def generate(self):
        self.x25519.generate()
        self.kyber768.generate()

    def public_key(self) -> bytes:
        return self.x25519.public_key() + self.kyber768.public_key()

    def private_key(self) -> bytes:
        return self.x25519.private_key() + self.kyber768.private_key()

    def shared_secret(self, peer_public_key: bytes) -> bytes:
        x25519_peer_public_key = peer_public_key[:32]
        kyber768_peer_public_key = peer_public_key[32:]
        x25519_shared_secret = self.x25519.shared_secret(x25519_peer_public_key)
        kyber768_shared_secret = self.kyber768.shared_secret(kyber768_peer_public_key)
        return x25519_shared_secret + kyber768_shared_secret
