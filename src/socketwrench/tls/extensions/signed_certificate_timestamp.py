

class SignedCertificateTimestamp:
    @classmethod
    def parse(cls, data: bytes) -> bytes:
        return data