import os
import struct

from socketwrench.tls.cipher_suites.algorithms.aes_gcm import AES128GCM_SHA256
from socketwrench.tls.cipher_suites.cipher_suites import CipherSuite
from socketwrench.tls.client_hello import ClientHello
from socketwrench.tls.extensions.extension_types import Extensions
from socketwrench.tls.extensions.key_share import KeyShare
from socketwrench.tls.extensions.supported_versions import SupportedVersions
from socketwrench.tls.versions import TLSVersion


class ServerHello:
    supported_cipher_suites = {
        CipherSuite.TLS_AES_128_GCM_SHA256: AES128GCM_SHA256

    }

    def __init__(self, client_hello: ClientHello):
        self.client_hello = client_hello
        self.version = TLSVersion.TLS_1_3
        self.random = os.urandom(32)
        self.session_id = client_hello['session_id']
        self.cipher_suite = self.select_cipher_suite(client_hello['cipher_suites'])
        self.compression_method = b'\x00'  # Null compression
        self.extensions = self.build_extensions(client_hello['extensions'])

    def select_cipher_suite(self, client_cipher_suites):
        # Select a cipher suite supported by the server
        for suite in client_cipher_suites:
            if suite in self.supported_cipher_suites:
                return suite
        raise ValueError("No supported cipher suite found")

    def build_extensions(self, client_extensions):
        extensions = Extensions({
            "SupportedVersions": SupportedVersions([self.version]),
            "ServerName": client_extensions.get('ServerName', b''),

        })
        # Build server extensions based on client's extensions and server capabilities
        # extensions = b''
        #
        # # for extension_type, value in client_extensions.items():
        # #     if extension_type == b'\x00\x0A':
        return extensions.to_bytes()

    def to_bytes(self):
        # Construct the ServerHello message
        handshake_message = (
            b'\x02' +  # Handshake Type: ServerHello
            struct.pack('!I', len(self.version.to_bytes() + self.random + self.session_id + self.cipher_suite + self.compression_method + self.extensions))[1:] +
            self.version.to_bytes() +
            self.random +
            struct.pack('B', len(self.session_id)) + self.session_id +
            self.cipher_suite +
            self.compression_method +
            struct.pack('!H', len(self.extensions)) + self.extensions
        )

        record_layer = (
            b'\x16' +  # Content Type: Handshake
            self.version.to_bytes() +
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
