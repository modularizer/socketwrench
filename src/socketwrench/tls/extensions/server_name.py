class ServerName(str):
    number = 0

    @classmethod
    def parse(cls, data: bytes) -> str:
        if len(data) < 5:
            raise ValueError("Invalid ServerName extension data")

        name_type = data[2]
        if name_type != 0:  # 0 is the HostName type
            raise ValueError("Unknown name type")

        server_name_length = int.from_bytes(data[3:5], 'big')
        if len(data[5:]) != server_name_length:
            raise ValueError("Invalid ServerName length")

        server_name = data[5:5 + server_name_length].decode()
        return cls(server_name)

    @property
    def data(self) -> bytes:
        return b'\x00' + len(self).to_bytes(2, "big") + self.encode()

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()