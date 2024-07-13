from enum import Enum


class ApplicationLayerProtocol(Enum):
    H2 = "h2"
    HTTP1_1 = "http/1.1"

    def __str__(self):
        return self.value

class UnrecognizedApplicationLayerProtocol(str):
    pass


class ApplicationLayerProtocolNegotiation(list):
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