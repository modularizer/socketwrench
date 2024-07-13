from enum import Enum


class PSKKeyExchangeMode(Enum):
    PSK_DHE_KE = "psk_dhe_ke"
    PSK_KE = "psk_ke"

    def __str__(self):
        return self.value


class UnrecognizedPSKKeyExchangeMode(str):
    pass


class PSKKeyExchangeModes(list):
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