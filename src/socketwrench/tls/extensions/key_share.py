from socketwrench.tls.extensions.supported_groups import SupportedGroup, UnrecognizedSupportedGroup


class KeyShare(list):
    number = 51

    @classmethod
    def parse(cls, data: bytes) -> list:
        full_length = int.from_bytes(data[:2], 'big')
        data = data[2:]
        if len(data) != full_length:
            raise ValueError("Invalid KeyShare extension data: incorrect length")
        key_shares = []
        offset = 0

        while offset < len(data):
            if len(data) < offset + 4:
                raise ValueError("Invalid KeyShare extension data: insufficient data for named group and length")

            # Extract the named group (2 bytes)
            named_group = int.from_bytes(data[offset:offset + 2], 'big')

            # Extract the key exchange length (2 bytes)
            key_exchange_length = int.from_bytes(data[offset + 2:offset + 4], 'big')

            if len(data) < (offset + 4 + key_exchange_length):
                raise ValueError("Invalid KeyShare extension data: insufficient data for key exchange")

            # Extract the key exchange data
            key_exchange = data[offset + 4:offset + 4 + key_exchange_length]

            try:
                named_group = SupportedGroup(named_group)
            except ValueError:
                named_group = UnrecognizedSupportedGroup(named_group)

            # Append the parsed key share entry to the list
            key_shares.append({
                "named_group": named_group,
                "key_exchange": key_exchange
            })

            # Move to the next key share entry
            offset += 4 + key_exchange_length

        return cls(key_shares)

    @property
    def data(self) -> bytes:
        data = b''
        for key_share in self:
            named_group = key_share["named_group"]
            if isinstance(named_group, UnrecognizedSupportedGroup):
                data += named_group
            else:
                data += named_group.to_bytes(2, "big")
            key_exchange = key_share["key_exchange"]
            key_exchange_length = len(key_exchange).to_bytes(2, "big")
            data += key_exchange_length + key_exchange
        return len(data).to_bytes(2, "big") + data

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()


# Example usage
# extension_data = (
#     b'\x00\x1d\x00\x20\x04\x87\xd2\xac\x05\x6b\xd2\x1a\x92\x23\x0d\xb8\x20\x8c\xd3\xb9'
#     b'\x25\x67\xd1\x6b\xd3\x4e\xa1\x72\x26\x71\x1e\xcf\x2b\x92\xe7\x11\x00\x1d\x00\x20'
#     b'\x04\xed\xfa\xfa\x00\x01\x00c\x99\x04\xc0\xe8\x27\x4e\x3b\xa7\x75\x4b\x92\xb0'
# )
# parsed_key_shares = KeyShare.parse(extension_data)
# print("Parsed Key Share Extension:", parsed_key_shares)
