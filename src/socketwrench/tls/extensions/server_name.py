class ServerName(str):
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