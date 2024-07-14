class AES:
    min_key_length: int = 16
    N: int
    ROUNDS: int
    Rcon: list[int]
    Sbox: list[int]
    InvSbox: list[int]

    @staticmethod
    def bytes_to_state(bytes_block):
        """Convert a 16-byte block into a 4x4 state matrix."""
        assert len(bytes_block) == 16, "Input must be a 16-byte block."
        return [list(bytes_block[i:i + 4]) for i in range(0, 16, 4)]

    @staticmethod
    def state_to_bytes(state):
        """Convert a 4x4 state matrix back into a 16-byte block."""
        return bytes(sum(state, []))

    @classmethod
    def key_expansion(cls, key: bytes) -> list[bytes]:
        """
        Expands the AES key into an array of key schedule words (4-byte each) for each round of AES.

        Parameters:
        key (bytes): The original AES key (must be 16 bytes for AES-128).

        Returns:
        list[bytes]: The expanded key schedule as a list of 4-byte words.

        Raises:
        ValueError: If the input key is not 16 bytes long.

        """
        if len(key) != cls.min_key_length:
            raise ValueError("Key length must be 16 bytes for AES-128.")

        key_schedule = [key[i:i + 4] for i in range(0, 16, 4)]
        for i in range(cls.N, cls.N * (cls.ROUNDS + 1)):
            temp = key_schedule[i - 1]
            if i % cls.N == 0:
                temp = cls.sub_word(cls.rot_word(temp))
                temp = bytes([temp[0] ^ cls.Rcon[(i // cls.N) - 1]] + list(temp[1:]))
            key_schedule.append(bytes(a ^ b for a, b in zip(key_schedule[i - cls.N], temp)))
        return key_schedule

    @classmethod
    def sub_word(cls, word: bytes) -> bytes:
        """
        Apply S-box substitution to a 4-byte word.

        Parameters:
        word (bytes): The 4-byte word to be substituted.

        Returns:
        bytes: The substituted 4-byte word.
        """
        return bytes(cls.Sbox[b] for b in word)

    @staticmethod
    def rot_word(word: bytes) -> bytes:
        """
        Perform a cyclic permutation (rotation) on a 4-byte word.

        Parameters:
        word (bytes): The 4-byte word to be rotated.

        Returns:
        bytes: The rotated 4-byte word.
        """
        return word[1:] + word[:1]

    @classmethod
    def sub_bytes(cls, state: list[list[int]]) -> list[list[int]]:
        """
        Perform the SubBytes step in AES, replacing each byte in the state with its corresponding value from the S-box.

        Parameters:
        state (list[list[int]]): The current state matrix.

        Returns:
        list[list[int]]: The state matrix after SubBytes transformation.
        """
        for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] = cls.Sbox[state[i][j]]
        return state

    @staticmethod
    def shift_rows(state: list[list[int]]) -> list[list[int]]:
        """
        Perform the ShiftRows step in AES, cyclically shifting the rows of the state matrix to the left.

        Parameters:
        state (list[list[int]]): The current state matrix.

        Returns:
        list[list[int]]: The state matrix after ShiftRows transformation.
        """
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state

    @classmethod
    def mix_columns(cls, state: list[list[int]]) -> list[list[int]]:
        for i in range(4):
            s0 = state[i][0]
            s1 = state[i][1]
            s2 = state[i][2]
            s3 = state[i][3]
            state[i][0] = cls.xtime(s0) ^ cls.xtime(s1) ^ s1 ^ s2 ^ s3
            state[i][1] = s0 ^ cls.xtime(s1) ^ cls.xtime(s2) ^ s2 ^ s3
            state[i][2] = s0 ^ s1 ^ cls.xtime(s2) ^ cls.xtime(s3) ^ s3
            state[i][3] = cls.xtime(s0) ^ s0 ^ s1 ^ s2 ^ cls.xtime(s3)
        return state

    @staticmethod
    def xtime(a):
        return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)

    @staticmethod
    def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
        """
        Perform the AddRoundKey step in AES, XORing each byte of the state with the corresponding byte of the round key.

        Parameters:
        state (list[list[int]]): The current state matrix.
        round_key (list[list[int]]): The round key matrix for the current round.

        Returns:
        list[list[int]]: The state matrix after AddRoundKey transformation.
        """
        for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] ^= round_key[i][j]
        return state

    @classmethod
    def parse_key_to_round_keys(cls, key: bytes) -> list[list[list[int]]]:
        round_keys = cls.key_expansion(key)
        # Convert each 16-byte round key to a 4x4 state matrix
        return [cls.bytes_to_state(b''.join(round_keys[i:i + 4])) for i in range(0, len(round_keys), 4)]

    @classmethod
    def encrypt_block(cls, plaintext_block: bytes, key: bytes) -> bytes:
        # Convert the plaintext block and key to the required format
        state = cls.bytes_to_state(plaintext_block)
        round_keys = cls.parse_key_to_round_keys(key)

        # Initial AddRoundKey step
        state = cls.add_round_key(state, round_keys[0])

        # Perform the main rounds
        for round in range(1, cls.ROUNDS):
            state = cls.sub_bytes(state)
            state = cls.shift_rows(state)
            state = cls.mix_columns(state)
            state = cls.add_round_key(state, round_keys[round])

        # Perform the final round (without MixColumns)
        state = cls.sub_bytes(state)
        state = cls.shift_rows(state)
        state = cls.add_round_key(state, round_keys[cls.ROUNDS])

        # Convert the state back to bytes
        return cls.state_to_bytes(state)

    @classmethod
    def inv_sub_bytes(cls, state: list[list[int]]) -> list[list[int]]:
        for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] = cls.InvSbox[state[i][j]]
        return state

    @staticmethod
    def inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        return state

    @classmethod
    def inv_mix_columns(cls, state: list[list[int]]) -> list[list[int]]:
        for i in range(4):
            t = state[i][:]
            state[i][0] = cls.mul(0x0e, t[0]) ^ cls.mul(0x0b, t[1]) ^ cls.mul(0x0d, t[2]) ^ cls.mul(0x09, t[3])
            state[i][1] = cls.mul(0x09, t[0]) ^ cls.mul(0x0e, t[1]) ^ cls.mul(0x0b, t[2]) ^ cls.mul(0x0d, t[3])
            state[i][2] = cls.mul(0x0d, t[0]) ^ cls.mul(0x09, t[1]) ^ cls.mul(0x0e, t[2]) ^ cls.mul(0x0b, t[3])
            state[i][3] = cls.mul(0x0b, t[0]) ^ cls.mul(0x0d, t[1]) ^ cls.mul(0x09, t[2]) ^ cls.mul(0x0e, t[3])
        return state

    @staticmethod
    def mul(a, b):
        """ Perform multiplication in GF(2^8) """
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            high_bit_set = a & 0x80
            a <<= 1
            if high_bit_set:
                a ^= 0x1b
            b >>= 1
        return p & 0xff

    @classmethod
    def decrypt_block(cls, ciphertext_block: bytes, key: bytes) -> bytes:
        # Convert the ciphertext block and key to the required format
        state = cls.bytes_to_state(ciphertext_block)
        round_keys = cls.parse_key_to_round_keys(key)

        # Initial AddRoundKey step
        state = cls.add_round_key(state, round_keys[cls.ROUNDS])

        # Perform the main rounds
        for round in range(cls.ROUNDS - 1, 0, -1):
            state = cls.inv_shift_rows(state)
            state = cls.inv_sub_bytes(state)
            state = cls.add_round_key(state, round_keys[round])
            state = cls.inv_mix_columns(state)

        # Perform the final round (without inv_mix_columns)
        state = cls.inv_shift_rows(state)
        state = cls.inv_sub_bytes(state)
        state = cls.add_round_key(state, round_keys[0])

        return cls.state_to_bytes(state)

    @classmethod
    def check(cls, plaintext: bytes, key: bytes, verbose: bool = False) -> bool:
        if verbose:
            print(f"Plaintext: {plaintext}")
            print(f"Key: {key}")
        ciphertext = cls.encrypt_block(plaintext, key)
        if verbose:
            print(f"Ciphertext: {ciphertext}")
        decrypted = cls.decrypt_block(ciphertext, key)
        if verbose:
            print(f"Decrypted: {decrypted}")
        matches = decrypted == plaintext
        if verbose:
            print(f"Match: {matches}")
        if not matches:
            raise RuntimeError("AES encryption/decryption failed.")
        return matches


class AES_128(AES):
    min_key_length = 16  # Minimum key length for AES-128
    N = 4  # Number of 4-byte words in the key (AES-128 has 16 bytes key)
    ROUNDS = 10  # Number of rounds for AES-128
    Rcon = [
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36
    ]
    """Rcon is the round constant for key expansion"""

    Sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    InvSbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]


