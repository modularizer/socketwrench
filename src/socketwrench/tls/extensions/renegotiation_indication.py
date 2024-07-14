class RenegotiationIndication(bytes):
    @classmethod
    def parse(cls, data: bytes) -> bytes:
        length = data[0]
        renegotiated_connection = data[1:length+1]
        return cls(renegotiated_connection)