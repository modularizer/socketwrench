from enum import IntEnum

from socketwrench.tls.extensions.application_layer_protocol_negotiation import ApplicationLayerProtocolNegotiation
from socketwrench.tls.extensions.client_certificate_url import ClientCertificateURL
from socketwrench.tls.extensions.key_share import KeyShare
from socketwrench.tls.extensions.max_fragment_length import MaxFragmentLength
from socketwrench.tls.extensions.pskey_exchange_modes import PSKKeyExchangeModes
from socketwrench.tls.extensions.server_name import ServerName
from socketwrench.tls.extensions.signature_algorithms import SignatureAlgorithms
from socketwrench.tls.extensions.status_request import StatusRequest
from socketwrench.tls.extensions.supported_groups import SupportedGroups
from socketwrench.tls.extensions.supported_versions import SupportedVersions
from socketwrench.tls.extensions.extended_master_secret import ExtendedMasterSecret
from socketwrench.tls.extensions.signed_certificate_timestamp import SignedCertificateTimestamp
from socketwrench.tls.extensions.padding import Padding
from socketwrench.tls.extensions.application_layer_protocol_settings import ApplicationLayerProtocolSettings
from socketwrench.tls.extensions.renegotiation_indication import RenegotiationIndication
from socketwrench.tls.extensions.compress_certificate import CompressCertificate
from socketwrench.tls.extensions.ec_point_formats import ECPointFormats


class ExtensionType(IntEnum):
    UnrecognizedExtensionType = -1
    ServerName = 0
    MaxFragmentLength = 1
    ClientCertificateURL = 2
    TrustedCAKeys = 3
    TruncatedHMAC = 4
    StatusRequest = 5
    UserMapping = 6
    ClientAuthz = 7
    ServerAuthz = 8
    CertType = 9
    SupportedGroups = 10
    ECPointFormats = 11
    SRP = 12
    SignatureAlgorithms = 13
    UseSRTP = 14
    Heartbeat = 15
    ApplicationLayerProtocolNegotiation = 16
    StatusRequestV2 = 17
    SignedCertificateTimestamp = 18
    ClientCertificateType = 19
    ServerCertificateType = 20
    Padding = 21
    EncryptThenMAC = 22
    ExtendedMasterSecret = 23
    TokenBinding = 24
    CachedInfo = 25
    CompressCertificate = 27
    SessionTicket = 35
    PreSharedKey = 41
    EarlyData = 42
    SupportedVersions = 43
    Cookie = 44
    PSKKeyExchangeModes = 45
    CertificateAuthorities = 47
    OIDFilters = 48
    PostHandshakeAuth = 49
    SignatureAlgorithmsCert = 50
    KeyShare = 51
    TransparencyInfo = 52
    ConnectionId = 53
    ApplicationLayerProtocolSettings = 17513
    Padding_2 = 65037
    RenegotiationIndication = 65281


class UnrecognizedExtension:
    def __init__(self, extension_type: int, data: bytes):
        self.extension_type = extension_type
        self.data = data


class ExtensionTypes:
    ServerName = ServerName
    MaxFragmentLength = MaxFragmentLength
    ClientCertificateURL = ClientCertificateURL
    StatusRequest = StatusRequest
    SupportedGroups = SupportedGroups
    SignatureAlgorithms = SignatureAlgorithms
    KeyShare = KeyShare
    ECPointFormats = ECPointFormats
    ApplicationLayerProtocolNegotiation = ApplicationLayerProtocolNegotiation
    PSKKeyExchangeModes = PSKKeyExchangeModes
    SupportedVersions = SupportedVersions
    UnrecognizedExtensionType = UnrecognizedExtension
    ExtendedMasterSecret = ExtendedMasterSecret
    SignedCertificateTimestamp = SignedCertificateTimestamp
    Padding = Padding
    Padding_2 = Padding
    ApplicationLayerProtocolSettings = ApplicationLayerProtocolSettings
    RenegotiationIndication = RenegotiationIndication
    CompressCertificate = CompressCertificate


def parse_extension(extension_type: int, data: bytes):
    try:
        t = ExtensionType(extension_type)
        et = getattr(ExtensionTypes, t.name, None)
        if et is None:
            return t.name, data
        value = et.parse(data)
        return t.name, value
    except ValueError:
        return extension_type.to_bytes(2, "big"), data

class Extensions(dict):
    @classmethod
    def parse(cls, data: bytes) -> dict:
        extensions = {}
        offset = 0
        while offset < len(data):
            extension_type = int.from_bytes(data[offset:offset + 2], 'big')
            offset += 2
            extension_length = int.from_bytes(data[offset:offset + 2], 'big')
            offset += 2
            extension_data = data[offset:offset + extension_length]
            offset += extension_length
            extension_name, extension_value = parse_extension(extension_type, extension_data)
            extensions[extension_name] = extension_value
        return cls(extensions)

    def _parse_key(self, key):
        if isinstance(key, ExtensionType):
            return key.name
        return key

    def __getattr__(self, item):
        item = self._parse_key(item)
        return self.get(item)

    def __getitem__(self, item):
        item = self._parse_key(item)
        return self.get(item)

    def __contains__(self, item):
        item = self._parse_key(item)
        return item in self.keys()

    def get(self, key, default=None):
        key = self._parse_key(key)
        return super().get(key, default)




class UnrecognizedExtensionType(bytes):
    pass







