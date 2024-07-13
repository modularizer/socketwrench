from enum import IntEnum


class ExtensionType(IntEnum):
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

class UnrecognizedExtensionType(bytes):
    pass

