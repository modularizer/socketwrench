from socketwrench.tls.versions import TLSVersion


class UnrecognizedTLSVersion(bytes):
    pass


class SupportedVersions(list):
    number = 43

    @classmethod
    def parse(cls, data: bytes) -> list:
        if len(data) < 1:
            raise ValueError("Invalid SupportedVersions extension data")

        length = data[0]
        offset = 1
        versions = []
        while offset < 1 + length:
            version = data[offset:offset + 2]
            try:
                version = TLSVersion.from_bytes(version)
            except ValueError:
                version = UnrecognizedTLSVersion(version)
            versions.append(version)
            offset += 2
        return versions

    @property
    def data(self) -> bytes:
        data = b''
        for version in self:
            if isinstance(version, UnrecognizedTLSVersion):
                data += version
            else:
                data += version.to_bytes()
        return data

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()
