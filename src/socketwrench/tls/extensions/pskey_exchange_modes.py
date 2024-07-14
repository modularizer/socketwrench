from enum import Enum, IntEnum


class PSKKeyExchangeMode(IntEnum):
    PSK_KE = 0
    PSK_DHE_KE = 1

    def __str__(self):
        return self.value


class UnrecognizedPSKKeyExchangeMode(str):
    pass


class PSKKeyExchangeModes(list):
    number = 45

    @classmethod
    def parse(cls, data: bytes) -> list:
        if len(data) < 1:
            raise ValueError("Invalid PSKKeyExchangeModes extension data")

        length = data[0]
        offset = 1
        modes = []
        while offset < 1 + length:
            mode = data[offset]
            try:
                mode = PSKKeyExchangeMode(mode)
            except ValueError:
                mode = UnrecognizedPSKKeyExchangeMode(mode)
            modes.append(mode)
            offset += 1
        return modes

    @property
    def data(self) -> bytes:
        data = b''
        for mode in self:
            if isinstance(mode, UnrecognizedPSKKeyExchangeMode):
                data += mode
            else:
                data += mode.to_bytes(1, "big")
        return

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()