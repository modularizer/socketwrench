class MaxFragmentLength(int):
    @classmethod
    def parse(cls, data: bytes) -> int:
        if len(data) != 1 or data[0] not in {1, 2, 3, 4}:
            raise ValueError("Invalid MaxFragmentLength extension data")
        return cls(data[0])