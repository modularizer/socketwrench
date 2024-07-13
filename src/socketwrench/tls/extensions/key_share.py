class KeyShare(list):
    @classmethod
    def parse(cls, data: bytes) -> list:
        key_shares = []
        offset = 0
        print(data)
        print(f"{len(data)}, {offset=}")
        while offset < len(data):
            if len(data) < offset + 4:
                raise ValueError("Invalid KeyShare extension data: insufficient data for named group and length")

            # Extract the named group (2 bytes)
            named_group = int.from_bytes(data[offset:offset + 2], 'big')

            # Extract the key exchange length (2 bytes)
            key_exchange_length = int.from_bytes(data[offset + 2:offset + 4], 'big')

            print(f"{named_group=}, {key_exchange_length=}")

            if len(data) < (offset + 4 + key_exchange_length):
                raise ValueError("Invalid KeyShare extension data: insufficient data for key exchange")

            # Extract the key exchange data
            key_exchange = data[offset + 4:offset + 4 + key_exchange_length]

            # Append the parsed key share entry to the list
            key_shares.append({
                "named_group": named_group,
                "key_exchange": key_exchange
            })
            print(key_shares[-1])

            # Move to the next key share entry
            offset += 4 + key_exchange_length

        return cls(key_shares)