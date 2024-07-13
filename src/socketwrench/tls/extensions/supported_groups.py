from enum import Enum


class SupportedGroup(Enum):
    SECP256R1 = 23       # NIST P-256
    SECP384R1 = 24       # NIST P-384
    SECP521R1 = 25       # NIST P-521
    X25519 = 29          # Curve25519
    X448 = 30            # Curve448
    FFDHE2048 = 256      # ffdhe2048
    FFDHE3072 = 257      # ffdhe3072
    FFDHE4096 = 258      # ffdhe4096
    FFDHE6144 = 259      # ffdhe6144
    FFDHE8192 = 260      # ffdhe8192
    X25519Kyber768Draft00 = 25497

    # Add other named groups as defined in RFC 8446 and other relevant specifications
    # These values are reserved and not assigned by IANA
    GREASE_1 = 2570      # 0x0a0a
    GREASE_2 = 6682      # 0x1a1a
    GREASE_3 = 10794     # 0x2a2a
    GREASE_4 = 14906     # 0x3a3a
    GREASE_5 = 19018     # 0x4a4a
    GREASE_6 = 23130     # 0x5a5a
    GREASE_7 = 27242     # 0x6a6a
    GREASE_8 = 31354     # 0x7a7a
    GREASE_9 = 35466     # 0x8a8a
    GREASE_10 = 39578    # 0x9a9a
    GREASE_11 = 43690    # 0xaaaa
    GREASE_12 = 47802    # 0xbaba
    GREASE_13 = 51914    # 0xcaca
    GREASE_14 = 56026    # 0xdada
    GREASE_15 = 60138    # 0xeaea
    GREASE_16 = 64250    # 0xfafa


class UnrecognizedSupportedGroup(int):
    pass


class SupportedGroups(list):
    @classmethod
    def parse(cls, data: bytes) -> list:
        if len(data) < 2:
            raise ValueError("Invalid SupportedGroups extension data")

        length = int.from_bytes(data[:2], 'big')
        groups = []
        for i in range(2, 2 + length, 2):
            x = int.from_bytes(data[i:i + 2], 'big')
            try:
                v = SupportedGroup(x)
            except ValueError:
                v = UnrecognizedSupportedGroup(x)
            groups.append(v)
        return cls(groups)
