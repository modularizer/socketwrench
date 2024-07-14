class Padding(int):
    number = 21

    @classmethod
    def parse(cls, data: bytes) -> dict:
        # The padding extension doesn't have specific content, just a length field.
        return cls(len(data))

    @property
    def data(self) -> bytes:
        return b'\x00' * self

    def to_bytes(self, length, byteorder, *, signed = False) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()