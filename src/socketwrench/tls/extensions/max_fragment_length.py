class MaxFragmentLength(int):
    number = 1

    @classmethod
    def parse(cls, data: bytes) -> int:
        if len(data) != 1 or data[0] not in {1, 2, 3, 4}:
            raise ValueError("Invalid MaxFragmentLength extension data")
        return cls(data[0])

    @property
    def data(self) -> bytes:
        return self.to_bytes(1, "big")

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()