from enum import Enum


class TLSVersion(Enum):
    TLS_1_3 = (3, 4)
    TLS_1_2 = (3, 3)
    TLS_1_1 = (3, 2)
    TLS_1_0 = (3, 1)
    SSL_3_0 = (3, 0)

    def __str__(self):
        return f"TLS/{self.value[0]}.{self.value[1]}"

    @classmethod
    def from_bytes(cls, data: bytes) -> "TLSVersion":
        if len(data) != 2:
            raise ValueError("Invalid SupportedVersion data")
        major, minor = data
        if major == 3:
            if minor == 4:
                return cls.TLS_1_3
            if minor == 3:
                return cls.TLS_1_2
            if minor == 2:
                return cls.TLS_1_1
            if minor == 1:
                return cls.TLS_1_0
            if minor == 0:
                return cls.SSL_3_0
        raise ValueError("Invalid SupportedVersion data")

    def to_bytes(self) -> bytes:
        return bytes(self.value)

    def __bytes__(self):
        return self.to_bytes()

    def __float__(self):
        return float(self.value[0] + self.value[1] / 10)

