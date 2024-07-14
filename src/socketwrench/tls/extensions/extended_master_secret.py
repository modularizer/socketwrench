

class ExtendedMasterSecret(bytes):
    @classmethod
    def parse(cls, data: bytes) -> bytes:
        return data