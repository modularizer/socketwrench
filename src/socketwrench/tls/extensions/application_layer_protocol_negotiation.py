from enum import Enum


class ApplicationLayerProtocol(Enum):
    H2 = "h2"
    HTTP1_1 = "http/1.1"

    def __str__(self):
        return self.value

class UnrecognizedApplicationLayerProtocol(str):
    pass


class ApplicationLayerProtocolNegotiation(list):
    number = 16
    @classmethod
    def parse(cls, data: bytes) -> list:
        if len(data) < 2:
            raise ValueError("Invalid ALPN extension data")

        length = int.from_bytes(data[:2], 'big')
        offset = 2
        protocols = []
        while offset < 2 + length:
            protocol_length = data[offset]
            protocol = data[offset + 1:offset + 1 + protocol_length].decode()
            try:
                protocol = ApplicationLayerProtocol(protocol)
            except ValueError:
                protocol = UnrecognizedApplicationLayerProtocol(protocol)
            protocols.append(protocol)
            offset += 1 + protocol_length
        return protocols

    @property
    def data(self) -> bytes:
        data = b''
        for protocol in self:
            if isinstance(protocol, UnrecognizedApplicationLayerProtocol):
                data += len(protocol).to_bytes(1, "big") + protocol.encode()
            else:
                data += len(protocol.value).to_bytes(1, "big") + protocol.value.encode()
        return len(data).to_bytes(2, "big") + data

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()