from socketwrench.tls.versions import TLSVersion


class UnrecognizedTLSVersion(bytes):
    pass


class SupportedVersions(list):
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
