class ApplicationLayerProtocolSettings(bytes):
    number = 17513
    @classmethod
    def parse(cls, data: bytes) -> bytes:
        offset = 0

        # Read Settings Length
        if len(data) < offset + 2:
            raise ValueError("Invalid ApplicationLayerProtocolSettings extension data: insufficient data for settings length")
        settings_length = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2

        # Read Settings
        if len(data) < offset + settings_length:
            raise ValueError("Invalid ApplicationLayerProtocolSettings extension data: insufficient data for settings")
        settings_data = data[offset:offset + settings_length]


        return cls(settings_data)

    @property
    def data(self) -> bytes:
        return len(self).to_bytes(2, "big") + self

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()
