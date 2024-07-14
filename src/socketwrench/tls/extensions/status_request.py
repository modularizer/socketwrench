from enum import IntEnum


class StatusType(IntEnum):
    OCSP = 0
    RESERVED = 1
    OCSP_MULTI = 2

class UnrecognizedStatusType(int):
    pass


class StatusRequest(dict):
    number = 5

    @classmethod
    def parse(cls, data: bytes) -> dict:
        if len(data) < 5:
            raise ValueError("Invalid StatusRequest extension data")

        status_type = data[0]
        try:
            status_type = StatusType(status_type)
        except ValueError:
            status_type = UnrecognizedStatusType(status_type)
        responder_id_list_length = int.from_bytes(data[1:3], 'big')
        extensions_length = int.from_bytes(data[3 + responder_id_list_length:5 + responder_id_list_length], 'big')

        responder_ids_data = data[3:3 + responder_id_list_length]
        # convert responder_id_list to a list of responder_id
        offset = 0
        responder_ids = []
        while offset < len(responder_ids_data):
            responder_id_length = int.from_bytes(responder_ids_data[offset:offset + 2], 'big')
            responder_id = responder_ids_data[offset + 2:offset + 2 + responder_id_length]
            # convert to int
            responder_id = int.from_bytes(responder_id, "big")
            responder_ids.append(responder_id)
            offset += 2 + responder_id_length

        extensions = data[5 + responder_id_list_length:5 + responder_id_list_length + extensions_length]
        extensions = cls.parse_extensions(extensions)

        return cls({
            "status_type": status_type,
            "responder_ids": responder_ids,
            "extensions": extensions
        })

    @staticmethod
    def parse_extensions(data: bytes) -> list:
        extensions = []
        offset = 0
        while offset < len(data):
            if len(data) < offset + 4:
                raise ValueError("Invalid extension data: insufficient data for extension header")

            ext_type = int.from_bytes(data[offset:offset + 2], 'big')
            ext_length = int.from_bytes(data[offset + 2:offset + 4], 'big')
            ext_data = data[offset + 4:offset + 4 + ext_length]

            if len(ext_data) != ext_length:
                raise ValueError("Invalid extension data: extension length mismatch")

            extensions.append({
                "extension_type": ext_type,
                "extension_length": ext_length,
                "extension_data": ext_data
            })
            offset += 4 + ext_length

        return extensions

    @property
    def data(self) -> bytes:
        data = b''
        data += bytes(self["status_type"])
        responder_ids = b''
        for responder_id in self["responder_ids"]:
            responder_id = responder_id.to_bytes(2, "big")
            responder_ids += responder_id
        data += len(responder_ids).to_bytes(2, "big") + responder_ids
        extensions = b''
        for extension in self["extensions"]:
            ext_type = extension["extension_type"].to_bytes(2, "big")
            ext_length = extension["extension_length"].to_bytes(2, "big")
            ext_data = extension["extension_data"]
            extensions += ext_type + ext_length + ext_data
        data += len(extensions).to_bytes(2, "big") + extensions
        return data

    def to_bytes(self) -> bytes:
        # convert number to two bytes, and length to two bytes
        n = self.number.to_bytes(2, "big")
        l = len(self.data).to_bytes(2, "big")
        return n + l + self.data

    def __bytes__(self):
        return self.to_bytes()