class ClientCertificateURL(str):
    number = 2

    @classmethod
    def parse(cls, data: bytes) -> str:
        return cls(data.decode())

    @property
    def data(self) -> bytes:
        return self.encode()

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()