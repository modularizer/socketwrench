class StatusRequest(dict):
    @classmethod
    def parse(cls, data: bytes) -> dict:
        if len(data) < 5:
            raise ValueError("Invalid StatusRequest extension data")

        status_type = data[0]
        responder_id_list_length = int.from_bytes(data[1:3], 'big')
        extensions_length = int.from_bytes(data[3 + responder_id_list_length:5 + responder_id_list_length], 'big')

        responder_id_list = data[3:3 + responder_id_list_length]
        extensions = data[5 + responder_id_list_length:5 + responder_id_list_length + extensions_length]

        return cls({
            "status_type": status_type,
            "responder_id_list": responder_id_list,
            "extensions": extensions
        })