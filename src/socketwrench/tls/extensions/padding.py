class Padding(dict):
    @classmethod
    def parse(cls, data: bytes) -> dict:
        # The padding extension doesn't have specific content, just a length field.
        return cls({"padding_length": len(data), "padding_bytes": data})