from enum import IntEnum


class ECPointFormat(IntEnum):
    UNCOMPRESSED = 0
    ANSIX962_COMPRESSED_PRIME = 1
    ANSIX962_COMPRESSED_CHAR2 = 2
    # 3-255 are reserved for future use


class UnrecognizedECPointFormat(int):
    pass

class ECPointFormats(list):
    number = 11

    @classmethod
    def parse(cls, data: bytes) -> list:
        length = data[0]
        data = data[1:]
        if len(data) != length:
            raise ValueError("Invalid ECPointFormats extension data: incorrect length")
        formats = []
        for byte in data:
            if byte == 0:
                formats.append(ECPointFormat.UNCOMPRESSED)
            elif byte == 1:
                formats.append(ECPointFormat.ANSIX962_COMPRESSED_PRIME)
            elif byte == 2:
                formats.append(ECPointFormat.ANSIX962_COMPRESSED_CHAR2)
            else:
                formats.append(UnrecognizedECPointFormat(byte))
        return cls(formats)

    @property
    def data(self) -> bytes:
        data = b''
        for format in self:
            if isinstance(format, UnrecognizedECPointFormat):
                data += format
            else:
                data += format.to_bytes(1, "big")
        return len(data).to_bytes(1, "big") + data

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()