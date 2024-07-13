from typing import Literal, Optional, Dict, Any, TypedDict

from socketwrench.tls.cipher_suites import CipherSuite, UnrecognizedCipherSuite

from socketwrench.tls.extensions import ExtensionType, UnrecognizedExtensionType


class ParsedClientHello(TypedDict):
    message: bytes
    tls_version: float
    record_length: int
    client_hello_length: int
    client_hello_data: bytes
    client_version: float
    random: bytes
    session_id: bytes
    cipher_suites: list[CipherSuite | UnrecognizedCipherSuite]
    extensions: dict[ExtensionType | UnrecognizedExtensionType, bytes]


class ClientHello:
    message: bytes
    tls_version: float
    record_length: int
    client_hello_length: int
    client_hello_data: bytes
    client_version: float
    random: bytes
    session_id: bytes
    cipher_suites: list[CipherSuite | UnrecognizedCipherSuite]
    extensions: dict[ExtensionType | UnrecognizedExtensionType, bytes]

    def __init__(self, data: bytes | ParsedClientHello):
        if isinstance(data, bytes):
            valid, parsed_client_hello = self.is_client_hello(data)
            if not valid:
                raise RuntimeError("Invalid ClientHello")
        else:
            parsed_client_hello = data
        self.message = message
        self.__dict__.update(parsed_client_hello)

    def __getitem__(self, item):
        return getattr(self, item)

    @classmethod
    def is_client_hello(cls, message: bytes) -> tuple[Literal[True, "partial", False], ParsedClientHello]:
        n = len(message)
        parsed_info = {
            "message": bytes
        }

        if not (message and isinstance(message, bytes)):
            return False, parsed_info

        # First byte is 0x16 (Handshake record type)
        if not message.startswith(b'\x16'):
            return False, parsed_info

        if n < 3:
            return "partial", parsed_info

        # Read TLS version (bytes 1-2)
        v = message[1:3]
        if v == b'\x03\x01':
            tls_version = 1.0
        elif v == b'\x03\x02':
            tls_version = 1.1
        elif v == b'\x03\x03':
            tls_version = 1.2
        elif v == b'\x03\x04':
            tls_version = 1.3
        else:
            return False, parsed_info

        parsed_info["tls_version"] = tls_version

        if n < 5:
            return "partial", parsed_info

        # Read length of the record (bytes 3-5)
        record_length = int.from_bytes(message[3:5], 'big')
        parsed_info["record_length"] = record_length

        if n < (5 + record_length):
            return "partial", parsed_info

        # Read Handshake message type (byte 5, should be 0x01 for ClientHello)
        if message[5] != 0x01:
            return False, parsed_info

        if n < 9:
            return "partial", parsed_info

        # Read length of the ClientHello (bytes 6-9)
        client_hello_length = int.from_bytes(message[6:9], 'big')
        parsed_info["client_hello_length"] = client_hello_length

        if n < (9 + client_hello_length):
            return "partial", parsed_info

        # Extract ClientHello data
        client_hello_data = message[9:9 + client_hello_length]
        parsed_info["client_hello_data"] = client_hello_data

        # Read client_version (2 bytes)
        if len(client_hello_data) < 2:
            return "partial", parsed_info
        client_version_bytes = client_hello_data[:2]
        if client_version_bytes == b'\x03\x01':
            client_version = 1.0
        elif client_version_bytes == b'\x03\x02':
            client_version = 1.1
        elif client_version_bytes == b'\x03\x03':
            client_version = 1.2
        elif client_version_bytes == b'\x03\x04':
            client_version = 1.3
        else:
            return False, parsed_info

        parsed_info["client_version"] = client_version

        # Read random (32 bytes)
        if len(client_hello_data) < 34:
            return "partial", parsed_info
        random = client_hello_data[2:34]
        parsed_info["random"] = random

        # Read session_id
        session_id_length = client_hello_data[34]
        if len(client_hello_data) < 35 + session_id_length:
            return "partial", parsed_info
        session_id = client_hello_data[35:35 + session_id_length]
        parsed_info["session_id"] = session_id

        # Read cipher_suites
        offset = 35 + session_id_length
        if len(client_hello_data) < offset + 2:
            return "partial", parsed_info
        cipher_suites_length = int.from_bytes(client_hello_data[offset:offset + 2], 'big')
        if len(client_hello_data) < offset + 2 + cipher_suites_length:
            return "partial", parsed_info
        cipher_suites_bytes = client_hello_data[offset + 2:offset + 2 + cipher_suites_length]
        # print(cipher_suites_bytes)
        # now parse the cipher suites into a list of CipherSuite enums
        cipher_suites = []
        for i in range(0, len(cipher_suites_bytes), 2):
            cipher_suite_bytes = cipher_suites_bytes[i:i + 2]
            # convert to an int
            x = int.from_bytes(cipher_suite_bytes, 'big')
            try:
                cipher_suite = CipherSuite(x)
            except ValueError:
                cipher_suite = UnrecognizedCipherSuite(cipher_suite_bytes)
            cipher_suites.append(cipher_suite)

        parsed_info["cipher_suites"] = cipher_suites

        # Read compression_methods
        offset += 2 + cipher_suites_length
        if len(client_hello_data) < offset + 1:
            return "partial", parsed_info
        compression_methods_length = client_hello_data[offset]
        if len(client_hello_data) < offset + 1 + compression_methods_length:
            return "partial", parsed_info
        compression_methods = client_hello_data[offset + 1:offset + 1 + compression_methods_length]
        if compression_methods != b'\x00':
            # only null compression method is supported
            return False, parsed_info

        # Read extensions
        offset += 1 + compression_methods_length
        if len(client_hello_data) > offset:
            if len(client_hello_data) < offset + 2:
                return "partial", parsed_info
            extensions_length = int.from_bytes(client_hello_data[offset:offset + 2], 'big')
            if len(client_hello_data) < offset + 2 + extensions_length:
                return "partial", parsed_info

        extensions = {}
        extension_bytes = client_hello_data[offset + 2:offset + 2 + extensions_length]
        while extension_bytes:
            extension_type = int.from_bytes(extension_bytes[:2], 'big')
            extension_data_length = int.from_bytes(extension_bytes[2:4], 'big')
            try:
                t = ExtensionType(extension_type)
            except ValueError:
                t = UnrecognizedExtensionType(extension_bytes[:2])
            # print(f"Extension ({t}) length: {extension_data_length}")
            extension_data = extension_bytes[4:4 + extension_data_length]
            extensions[t] = extension_data
            extension_bytes = extension_bytes[4 + extension_data_length:]
        parsed_info["extensions"] = extensions
        return True, parsed_info


