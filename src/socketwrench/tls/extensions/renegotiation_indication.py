class RenegotiationIndication(bytes):
    number = 65281
    @classmethod
    def parse(cls, data: bytes) -> bytes:
        length = data[0]
        renegotiated_connection = data[1:length+1]
        return cls(renegotiated_connection)

    @property
    def data(self) -> bytes:
        return len(self).to_bytes(1, "big") + self

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()