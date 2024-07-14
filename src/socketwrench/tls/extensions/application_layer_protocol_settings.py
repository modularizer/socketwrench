class ApplicationLayerProtocolSettings(bytes):
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
