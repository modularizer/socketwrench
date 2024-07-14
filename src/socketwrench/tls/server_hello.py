import os
import struct

from socketwrench.tls.client_hello import ClientHello
from socketwrench.tls.versions import TLSVersion


class ServerHello:
    def __init__(self, client_hello: ClientHello):
        self.client_hello = client_hello
        self.version = TLSVersion.TLS_1_2
        self.random = os.urandom(32)
        self.session_id = client_hello['session_id']
        self.cipher_suite = self.select_cipher_suite(client_hello['cipher_suites'])
        self.compression_method = b'\x00'  # Null compression
        self.extensions = self.build_extensions(client_hello['extensions'])

    def select_cipher_suite(self, client_cipher_suites):
        # Select a cipher suite supported by the server
        server_supported_suites = [b'\x00\x2F', b'\x00\x35']  # Example: TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA
        for suite in client_cipher_suites:
            if suite in server_supported_suites:
                return suite
        raise ValueError("No supported cipher suite found")

    def build_extensions(self, client_extensions):
        # Build server extensions based on client's extensions and server capabilities
        extensions = b''
        # Example: Server might include Supported Groups extension if client proposed it
        if b'\x00\x0A' in client_extensions:
            supported_groups = b'\x00\x0A\x00\x04\x00\x02\x00\x1D'  # Example extension: Supported Groups
            extensions += supported_groups
        return extensions

    def to_bytes(self):
        # Construct the ServerHello message
        handshake_message = (
            b'\x02' +  # Handshake Type: ServerHello
            struct.pack('!I', len(self.version + self.random + self.session_id + self.cipher_suite + self.compression_method + self.extensions))[1:] +
            self.version +
            self.random +
            struct.pack('B', len(self.session_id)) + self.session_id +
            self.cipher_suite +
            self.compression_method +
            struct.pack('!H', len(self.extensions)) + self.extensions
        )

        record_layer = (
            b'\x16' +  # Content Type: Handshake
            self.version +
            struct.pack('!H', len(handshake_message)) +
            handshake_message
        )

        return record_layer

# Example ClientHello data (simplified)
client_hello = {
    'session_id': b'\x01\x02\x03\x04',
    'cipher_suites': [b'\x00\x2F', b'\x00\x35', b'\x00\x0A'],
    'extensions': {b'\x00\x0A': b'\x00\x02\x00\x1D'}  # Example extensions
}

server_hello = ServerHello(client_hello)
server_hello_bytes = server_hello.to_bytes()

print(server_hello_bytes)
