class ClientCertificateURL(str):
    @classmethod
    def parse(cls, data: bytes) -> str:
        return cls(data.decode())