from socketwrench.tls.cipher_suites.algorithms.aes import AES_128, AES, AES_256
from socketwrench.tls.cipher_suites.algorithms.sha256 import SHA256


class _AES_GCM(AES):
    def __init__(self, key: bytes):
        self.key = key
        self.round_keys = self.parse_key_to_round_keys(key)

    def ghash(self, H: bytes, A: bytes, C: bytes) -> bytes:
        block_size = 16
        A_len = len(A) * 8
        C_len = len(C) * 8

        # Pad A and C to block size (16 bytes)
        A_padded = A + b'\x00' * ((block_size - len(A) % block_size) % block_size)
        C_padded = C + b'\x00' * ((block_size - len(C) % block_size) % block_size)

        # Concatenate A, C, and lengths
        S = A_padded + C_padded + A_len.to_bytes(8, 'big') + C_len.to_bytes(8, 'big')

        # Initialize the result (X) to zero
        X = b'\x00' * block_size

        # Process each block
        for i in range(0, len(S), block_size):
            X = self.gf_mult(X, H)
            X = bytes(a ^ b for a, b in zip(X, S[i:i + block_size]))

        return X

    def gf_mult(self, X: bytes, Y: bytes) -> bytes:
        R = 0xe1000000000000000000000000000000  # Polynomial for Galois field (2^128)
        X = int.from_bytes(X, 'big')
        Y = int.from_bytes(Y, 'big')
        Z = 0

        for i in range(128):
            if (X >> (127 - i)) & 1:
                Z ^= Y
            if Y & 1:
                Y = (Y >> 1) ^ R
            else:
                Y >>= 1

        return Z.to_bytes(16, 'big')

    def encrypt(self, plaintext: bytes, aad: bytes, nonce: bytes) -> tuple[bytes, bytes]:
        # Ensure nonce is of correct size (12 bytes is standard for GCM)
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes long")

        # Step 1: Create the initial counter value
        counter = int.from_bytes(nonce + b'\x00\x00\x00\x01', 'big')  # Nonce || 0x00000001

        # Step 2: Encrypt the plaintext
        ciphertext = self._encrypt_counter_mode(plaintext, counter)

        # Step 3: Compute the authentication tag
        tag = self._compute_gcm_tag(aad, ciphertext, nonce)

        return ciphertext, tag

    def compute_hash_subkey(self) -> bytes:
        return self.encrypt_block(b'\x00' * 16, self.key)

    def _encrypt_counter_mode(self, plaintext: bytes, counter: int) -> bytes:
        block_size = 16
        encrypted = bytearray()
        for i in range(0, len(plaintext), block_size):
            counter_block = counter.to_bytes(block_size, 'big')
            encrypted_block = self.encrypt_block(counter_block, self.key)
            block = plaintext[i:i + block_size]
            encrypted_block = bytes(a ^ b for a, b in zip(block, encrypted_block[:len(block)]))
            encrypted.extend(encrypted_block)
            counter += 1
        return bytes(encrypted)

    def _compute_gcm_tag(self, aad: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
        H = self.compute_hash_subkey()
        ghash_result = self.ghash(H, aad, ciphertext)
        return ghash_result

    def gcm_encrypt(self, plaintext: bytes, aad: bytes, iv: bytes) -> tuple[bytes, bytes]:
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes long")

        # Generate the counter block
        counter = int.from_bytes(iv + b'\x00\x00\x00\x01', 'big')

        # Encrypt the plaintext using counter mode
        ciphertext = self._encrypt_counter_mode(plaintext, counter)

        # Compute the authentication tag
        tag = self._compute_gcm_tag(aad, ciphertext, iv)

        return ciphertext, tag

    def decrypt(self, ciphertext: bytes, aad: bytes, nonce: bytes, tag: bytes) -> bytes:
        # Ensure nonce is of correct size (12 bytes is standard for GCM)
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes long")

        # Step 1: Compute and verify the authentication tag
        computed_tag = self._compute_gcm_tag(aad, ciphertext, nonce)
        if computed_tag != tag:
            raise ValueError("Invalid authentication tag")

        # Step 2: Create the initial counter value
        counter = int.from_bytes(nonce + b'\x00\x00\x00\x01', 'big')  # Nonce || 0x00000001

        # Step 3: Decrypt the ciphertext
        plaintext = self._encrypt_counter_mode(ciphertext, counter)  # Counter mode decryption is the same as encryption

        return plaintext

    def gcm_decrypt(self, ciphertext: bytes, aad: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Decrypt ciphertext with AES-128-GCM.
        """
        # Ensure IV is of correct size (12 bytes is standard for GCM)
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes long")

        # Step 1: Compute and verify the authentication tag
        computed_tag = self._compute_gcm_tag(aad, ciphertext, iv)
        if computed_tag != tag:
            raise ValueError("Invalid authentication tag")

        # Step 2: Create the initial counter value
        counter = int.from_bytes(iv + b'\x00\x00\x00\x01', 'big')  # IV || 0x00000001

        # Step 3: Decrypt the ciphertext
        plaintext = self._encrypt_counter_mode(ciphertext, counter)  # Counter mode decryption is the same as encryption

        return plaintext


class AES_128_GCM(AES_128, _AES_GCM):
    pass


class AES_256_GCM(AES_256, _AES_GCM):
    pass


class AESGCMCipherSuite_SHA256:
    AESGCM: type[_AES_GCM]

    def __init__(self, key: bytes):
        self.aes_gcm = self.AESGCM(key)
        self.hash_function = SHA256.hexdigest

    def encrypt(self, plaintext: bytes, aad: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
        ciphertext, tag = self.aes_gcm.encrypt(plaintext, aad, nonce)
        return ciphertext, tag, self.hash_function(plaintext)

    def decrypt(self, ciphertext: bytes, aad: bytes, nonce: bytes, tag: bytes, hash_value: bytes) -> bytes:
        plaintext = self.aes_gcm.decrypt(ciphertext, aad, nonce, tag)
        if self.hash_function(plaintext) != hash_value:
            raise ValueError("Hash mismatch, data integrity compromised")
        return plaintext


class AES128GCM_SHA256(AESGCMCipherSuite_SHA256):
    AESGCM = AES_128_GCM


class AES256GCM_SHA256(AESGCMCipherSuite_SHA256):
    AESGCM = AES_256_GCM

