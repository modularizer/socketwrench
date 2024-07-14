class _RSATools(object):
    @staticmethod
    def gcd(e, r):
        """greatest common denominator"""
        while r != 0:
            e, r = r, e % r
        return e

    @classmethod
    def eea(cls, a, b):
        """extended euclidean algorithm"""
        if a % b == 0:
            return b, 0, 1
        else:
            gcd, s, t = cls.eea(b, a % b)
            s = s - ((a // b) * t)
            return gcd, t, s

    @classmethod
    def mod_inv(cls, a, b):
        gcd, s, _ = cls.eea(a, b)
        if gcd != 1:
            raise Exception(f"a={a}, b={b}")
        else:
            return s % b

    @staticmethod
    def rebase(i, new_base=10, old_base=10):
        if isinstance(i, (list, tuple)) or old_base != 10:
            i = sum([v * (old_base ** (len(i) - ind - 1)) for ind, v in enumerate(i)])
        if new_base == 10:
            return i
        inds = []
        while i:
            inds.append(i % new_base)
            i //= new_base
        value_list = reversed(inds)
        return value_list


class _RSAGen(_RSATools):
    @staticmethod
    def totient(p, q):
        return (p - 1) * (q - 1)

    @classmethod
    def invalid_e(cls, e, phi):
        if e <= 0:
            return "e must be > 0"
        if e >= phi:
            return "e must be < phi"
        f = cls.gcd(e, phi)
        if f != 1:
            print(f, e, phi)
            return "e must be co-prime to phi"
        return False

    @classmethod
    def check_e(cls, e, phi):
        e = cls.invalid_e(e, phi)
        if e:
            raise Exception(f"Invalid e: {e}")
        return True

    @classmethod
    def generate_public_key(cls, p, q, e):
        n = p * q
        """product of primes"""

        phi = cls.totient(p, q)
        """totient"""

        cls.check_e(e, phi)
        return n, e

    @classmethod
    def generate_private_key(cls, p, q, e):
        n = p * q
        phi = cls.totient(p, q)
        cls.check_e(e, phi)
        d = cls.mod_inv(e, phi)
        return d, n


class _RSAPublic(_RSAGen):
    def __init__(self, p, q, e):
        self.public_key = self.generate_public_key(p, q, e)

    @staticmethod
    def _encrypt_block(p_block, public_key):
        n, e = public_key
        return pow(p_block + 2, e, n)

    @classmethod
    def _encrypt(cls, p: bytes, public_key, unencrypted_block_size=800) -> bytes:
        p_int = int.from_bytes(p, 'big')
        if p_int >= (1 << unencrypted_block_size):
            print("rebasing")
            p_chunks = cls.rebase(p_int, 1 << unencrypted_block_size)
        else:
            p_chunks = [p_int]
        c_chunks = [cls._encrypt_block(v, public_key) for v in p_chunks]
        # Convert each chunk to bytes and concatenate
        max_chunk_length = (public_key[0].bit_length() + 7) // 8
        c_bytes = b''.join(chunk.to_bytes(max_chunk_length, 'big') for chunk in c_chunks)
        return c_bytes

    def encrypt(self, p: bytes) -> bytes:
        return self._encrypt(p, self.public_key)

    def __call__(self, *args, **kwargs):
        return self.encrypt(*args, **kwargs)


class _RSAPrivate(_RSAPublic):
    def __init__(self, p, q=None, e=65537):
        super().__init__(p, q, e)
        self._private_key = self.generate_private_key(p, q, e)

    @staticmethod
    def _decrypt_block(c_block, private_key):
        d, n = private_key
        return pow(int(c_block), d, n) - 2

    @classmethod
    def _decrypt(cls, c: bytes, private_key,
                 unencrypted_block_size=800):
        c_chunks = [c[i:i + unencrypted_block_size] for i in range(0, len(c), unencrypted_block_size)]
        p_chunks = [cls._decrypt_block(int.from_bytes(v, "big"), private_key) for v in c_chunks]
        p_int = cls.rebase(p_chunks, 10, 1 << unencrypted_block_size)
        return p_int.to_bytes((p_int.bit_length() + 7) // 8, 'big')

    def decrypt(self, c: bytes) -> bytes:
        return self._decrypt(c, self._private_key)

    def check(self, message):
        print(f'checking: {message}')
        r = self.encrypt(message)
        print(f'encrypted: {r}')
        m = self.decrypt(r)
        print(f'decrypted: {m}')
        return m == message


class RSA(_RSAPrivate):
    pass


if __name__ == "__main__":
    p = 796158404950237945787196764633550801236724792940237837217179
    q = 1517812095106123640180711070925933522879203927512681025034651
    r = RSA(p, q)
    r.check(b"testing the encryption")