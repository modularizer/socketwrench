class ToolBin(object):
    @staticmethod
    def chunk(s, size=4, mode='raise', padding='0'):
        """chunk a string
        :param s: (str) message to chunk
        :param size: (int) number of characters per chunk
        :param mode: (str) mode for handling remainder
            'pre_pad' will pad beginning of first chunk
            'post_pad' will pad end of last_chunk
            'raise' will raise an exception if length of s is not divisible by size
        :param padding: (str) string to pad with, must be '' or single character
        :return chunks: (list) list of strings of length {size} (unless padding in ['', None] start or end may be short)
        """
        remainder = len(s) % size
        if remainder:
            if mode not in ['pre_pad', 'post_pad', 'raise']:
                raise Exception("mode must be 'pre_pad', 'post_pad', or 'raise'")
            if mode == 'raise':
                raise Exception(f"cannot chunk string of length {len(s)} into chunks of {size}")
            if 'post' in mode:
                s = ''.join(v for v in reversed(s))
            if 'pad' in mode:
                if padding is None:
                    padding = ''
                if not isinstance(padding, str) or len(padding) > 1:
                    raise Exception("padding must be string of length 0 or 1")
                s = padding * remainder + s
        chunks = [s[n * size:(n + 1) * size] for n in range(len(s) // size)]
        if 'post' in mode:
            chunks = [''.join(v for v in reversed(w)) for w in reversed(chunks)]
        return chunks

    @staticmethod
    def ascii_to_bin(message, separator=' '):
        """convert an ascii str to a binary str
        :param message: (str) ascii str, e.g. 'hello'
        :param separator: (str) string separating chunks of bits, e.g. ' '
        :return bs: (str) binary str, e.g. '01101000 01100101 01101100 01101100 01101111'
        """
        if isinstance(message, str):
            return separator.join('{0:08b}'.format(ord(letter), 'b') for letter in message)
        if isinstance(message, bytes):
            return separator.join('{0:08b}'.format(letter, 'b') for letter in message)

    @classmethod
    def hex_to_bin(cls, hs, separator=' '):
        """convert a hex string to a binary string
        :param hs: (str) hex str e.g. '68656c6c6f'
        :param separator: (str) string to separate chunks of bits, e.g. ' '
        :return bs: (str) binary str, e.g. '01101000 01100101 01101100 01101100 01101111'
        """
        hs = hs.replace(' ', '')
        bs = bin(int(hs, 16))[2:].zfill(len(hs) * 4)
        return separator.join(cls.chunk(bs, 8))

    @classmethod
    def bin_to_hex(cls, bs, separator=' '):
        """convert a binary string to a hex string
        :param bs: (str) binary str, e.g. '01101000 01100101 01101100 01101100 01101111'
        :param separator: (str) string seperating letters, e.g. ' '
        :return hs: (str) hex str, e.g. '68656c6c6f'
        """
        bs = bs.replace(separator, '')
        return ''.join([hex(int(chunk, 2))[2:] for chunk in cls.chunk(bs, 4)])

    @staticmethod
    def int_to_bin(i, word_size=8):
        """convert int to binary string of set size
        :param i: (int), e.g. 12
        :param word_size: (int) number of bits, e.g. 8
        :return bs: (str) binary str, e.g. '00001100'
        """
        return bin(i)[2:].zfill(word_size)

    @staticmethod
    def fractional_root(radicand, index=2):
        """get a hex code value representing the first 32 bits of the fractional part of the square root of a number
        first32_hex = hex(int(((radicand**(1/index)) % 1)*(1<<32)))
        :param radicand: (int | float) number to take root of
        :param index: (int | float) index of the root, default 2 for square root
        :return: first32: (int) 32 bit number
        """
        radical = radicand ** (1 / index)
        fractional_part = radical % 1
        first32 = int(float(fractional_part) * (1 << 32))
        return first32


class SHA256(ToolBin):
    """https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf"""
    # ______________________________________ Pre-Processed Constants ___________________________________________________
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
              107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
              227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311]
    """list of first 64 prime numbers"""

    H0 = [ToolBin.fractional_root(prime, 2) for prime in primes[:8]]
    """list of 8 hash values created from the square root of the first 8 prime numbers"""

    K = [ToolBin.fractional_root(prime, 3) for prime in primes[:64]]
    """list of 64 round constants created from the cubed root of the first 64 prime numbers"""

    # _____________________________________ Pre-Process Message ________________________________________________________
    @classmethod
    def _pre_process(cls, original_message, chunk_size=512, word_size=32):
        """convert a message into a list of lists of binary strings
        :param original_message: (str) ascii string
        :param chunk_size: (int) number of bits per chunk of binary encoded original message
        :param word_size: (int) number of bits per word of chunk
        :return chunk_of_words: (list) list of lists of words (integers)"""
        original_message_bin_str = cls.ascii_to_bin(original_message, separator='')
        l = len(original_message_bin_str)
        padding_needed = chunk_size - ((1 + l + 64) % chunk_size)
        padding_needed = 0 if padding_needed == chunk_size else padding_needed
        processed = original_message_bin_str + '1' + padding_needed * '0' + cls.int_to_bin(l, 64)

        chunks = cls.chunk(processed, chunk_size)
        chunks_of_words = [cls.chunk(chunk, word_size) for chunk in chunks]
        chunks_of_words = [[int(bs, 2) for bs in chunk] for chunk in chunks_of_words]
        return chunks_of_words

    # _______________________________________ Basic Operations _________________________________________________________
    @staticmethod
    def _rotr(x, n, word_size):
        """circular bitshift right"""
        return (x >> n) | (x << (word_size - n))

    @classmethod
    def _mod_sum(cls, *words, word_size):
        """"""
        if len(words) == 1:
            return words[0] % (2 ** word_size)

        if len(words) == 2:
            return (words[0] + words[1]) % (2 ** word_size)

        return cls._mod_sum(words[0], cls._mod_sum(*words[1:], word_size=word_size), word_size=word_size)

    # __________________________________________ Primary Operations ____________________________________________________
    @staticmethod
    def _choose(x, y, z):
        """Ch(x, y, z) = (x & y) ^ (~x & z)
        bitwise x == y or x != z
        """
        return (x & y) ^ (~x & z)

    @staticmethod
    def _majority(x, y, z):
        """Maj(x, y, z) = (x & y) ^ (x & z) ^ ( y & z)"""
        return (x & y) ^ (x & z) ^ (y & z)

    @classmethod
    def _sigma_0(cls, x, word_size):
        rotr = lambda _x, n: cls._rotr(_x, n, word_size=word_size)
        return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) % (2 ** word_size)

    @classmethod
    def _sigma_1(cls, x, word_size):
        rotr = lambda _x, n: cls._rotr(_x, n, word_size=word_size)
        return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) % (2 ** word_size)

    @classmethod
    def _gamma_0(cls, x, word_size):
        rotr = lambda _x, n: cls._rotr(_x, n, word_size=word_size)
        return (rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)) % (2 ** word_size)

    @classmethod
    def _gamma_1(cls, x, word_size):
        rotr = lambda _x, n: cls._rotr(_x, n, word_size=word_size)
        return (rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)) % (2 ** word_size)

    # ______________________________________ Computation _______________________________________________________________
    @classmethod
    def _compute_digest(cls, chunks_of_words, word_size):
        """takes in chunks of words and outputs a 256bit number"""
        H = [cls.H0]
        for i, chunk_of_words in enumerate(chunks_of_words):
            a, b, c, d, e, f, g, h = H[-1]
            """eight working variables"""

            words = chunk_of_words
            """store modified words to use recursively in loop"""

            for t in range(64):
                # in iterations 0-15, use a word from input message to hash
                if t > 15:
                    # in iterations 16-63, use previous words to make new words to then hash
                    words.append(
                        cls._mod_sum(
                            cls._gamma_1(words[t - 2], word_size=word_size),
                            words[t - 7],
                            cls._gamma_0(words[t - 15], word_size=word_size),
                            words[t - 16], word_size=word_size
                        )
                    )
                word = words[t]

                t1 = cls._mod_sum(h,
                                  cls._sigma_1(e, word_size=word_size),
                                  cls._choose(e, f, g),
                                  cls.K[t],
                                  word,
                                  word_size=word_size)
                """temporary word one"""

                t2 = cls._mod_sum(cls._sigma_0(a, word_size=word_size),
                                  cls._majority(a, b, c), word_size=word_size)
                """temporary word two"""

                # update working variables
                h, g, f = g, f, e
                e = cls._mod_sum(d, t1, word_size=word_size)
                d, c, b = c, b, a
                a = cls._mod_sum(t1, t2, word_size=word_size)

            # save new hashed words
            H.append([
                cls._mod_sum(v, H[-1][i], word_size=word_size) for i, v in enumerate([a,b,c,d,e,f,g,h])
            ])
        # combined final set of hashed words into one word output
        digest_256_bin_str = ''.join(cls.int_to_bin(word, word_size=word_size) for word in H[-1])
        digest_256 = int(digest_256_bin_str, 2)
        return digest_256

    # _____________________________________ Post-Process Output ________________________________________________________
    @classmethod
    def _post_process_hexdigest(cls, digest, digest_size):
        bs = cls.int_to_bin(digest, digest_size)
        digest_hex = cls.bin_to_hex(bs)
        return ' '.join(cls.chunk(digest_hex, 8))

    @classmethod
    def hexdigest(cls, original_message, _word_size=32, _digest_size=256):
        chunks_of_words = cls._pre_process(original_message, word_size=_word_size)
        digest_256 = cls._compute_digest(chunks_of_words, word_size=_word_size)
        digest_hex = cls._post_process_hexdigest(digest_256, digest_size=_digest_size)
        return digest_hex

    tests = {
        '': 'e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855',
        'abc': 'ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad',
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq': '248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1',
        'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu': 'cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1',
        'a' * 1000000: 'cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0'
    }

    @classmethod
    def check(cls, message, sig):
        return cls(message) == sig

    @classmethod
    def test(cls):
        return all(cls.check(k, v) for k, v in cls.tests.items())

    def __init__(self, message):
        self.digest_hex = self.hexdigest(message)

    def __repr__(self):
        return self.digest_hex

    def __int__(self):
        return int(self.digest_hex.replace(" ", ""), 16)

    def __hex__(self):
        return hex(int(self.digest_hex.replace(" ", ""), 16))

    def bin_str(self):
        return self.hex_to_bin(self.digest_hex)

    def __eq__(self, other):
        if isinstance(other, str):
            return str(self) == other
        if isinstance(other, int):
            return int(self) == other
        if isinstance(other, type(self)):
            return self.digest_hex == other.digest_hex

    def __getattr__(self, item):
        return self.digest_hex.__getattr__(item)

    def to_chars(self, chars, separator='', chunk_size=1):
        n = len(chars)
        i = int(self)
        inds = []
        while i:
            inds.append(i % n)
            i //= n
        s = [chars[ind] for ind in reversed(inds)]
        s_chunks = self.chunk(s, chunk_size)
        return separator.join(''.join(chunk) for chunk in s_chunks)

    def to_charset(self, charset='hex', separator='', chunk_size=1):
        charsets = {
            'hex': '0123456789abcdef',
            'az': 'abcdefghijklmnopqrstuvwxyz',
            'AZ': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '09': '0123456789',
            'aZ': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'az9': 'abcdefghijklmnopqrstuvwxyz',
            'AZ9': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            'aZ9': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
        }
        if charset in charsets:
            charset = charsets[charset]
        return self.to_chars(charset, separator, chunk_size)

    @classmethod
    def large_salted_hash(cls, message, min_bits=2048, salt='SALT'):
        """generate a hash from a long string combined with some salt"""
        n = min_bits // 256 + 1 * ((min_bits % 256) != 0)
        hashes = [cls(message + f"{salt}{i}") for i in range(n)]
        bin_str = "".join(h.bin_str() for h in hashes).replace(" ", "")
        i = int(bin_str, 2)
        return i


if __name__ == "__main__":
    SHA256.test()
    s = SHA256("testing123")