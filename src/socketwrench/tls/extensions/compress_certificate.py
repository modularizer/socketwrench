from enum import Enum


class CompressionAlgorithms(Enum):
    RESERVED = 0
    ZLIB = 1
    BROTLI = 2
    ZSTD = 3

    def __str__(self):
        return self.name


class ExperimentalCompressionAlgorithm(int):
    pass

class UnrecognizedCompressionAlgorithm(int):
    pass




class CompressCertificate(list):
    @classmethod
    def parse(cls, data: bytes) -> list:
        algorithms = []
        offset = 0
        while offset < len(data):
            algorithm_id = int.from_bytes(data[offset:offset + 2], 'big')
            if 0 <= algorithm_id <= 3:
                algorithm = CompressionAlgorithms(algorithm_id)
            elif 16384 <= algorithm_id <= 65535:
                algorithm = ExperimentalCompressionAlgorithm(algorithm_id)
            else:
                algorithm = UnrecognizedCompressionAlgorithm(algorithm_id)
            algorithms.append(algorithm)
            offset += 2
        return cls(algorithms)