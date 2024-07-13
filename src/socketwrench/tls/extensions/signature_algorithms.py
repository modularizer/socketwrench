from enum import Enum


class SignatureAlgorithm(Enum):
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601
    ECDSA_SHA256 = 0x0403
    ECDSA_SHA384 = 0x0503
    ECDSA_SHA512 = 0x0603
    RSA_PSS_SHA256 = 0x0804
    RSA_PSS_SHA384 = 0x0805
    RSA_PSS_SHA512 = 0x0806
    ED25519 = 0x0807
    ED448 = 0x0808
    RSA_PKCS1_SHA1 = 0x0201
    ECDSA_SHA1 = 0x0203
    RSA_PSS_SHA1 = 0x0802
    DSA_SHA1 = 0x0202

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"{self.name} ({hex(self.value)})"

    def __int__(self):
        return self.value


class SignatureAlgorithms(list):
    @classmethod
    def parse(cls, data: bytes) -> list:
        if len(data) < 2:
            raise ValueError("Invalid SignatureAlgorithms extension data")

        length = int.from_bytes(data[:2], 'big')
        algorithms = [SignatureAlgorithm(int.from_bytes(data[i:i + 2], 'big')) for i in range(2, 2 + length, 2)]
        return cls(algorithms)
