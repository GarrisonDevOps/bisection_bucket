    def publickey(self):
        """:meta private:"""
        return self.public_key()

    # Methods defined in PyCryptodome that we don't support anymore
    def sign(self, M, K):
        """:meta private:"""
        raise NotImplementedError("Use module Cryptodome.Signature.pkcs1_15 instead")

    def verify(self, M, signature):
        """:meta private:"""
        raise NotImplementedError("Use module Cryptodome.Signature.pkcs1_15 instead")

    def encrypt(self, plaintext, K):
        """:meta private:"""
        raise NotImplementedError("Use module Cryptodome.Cipher.PKCS1_OAEP instead")

    def decrypt(self, ciphertext):
        """:meta private:"""
        raise NotImplementedError("Use module Cryptodome.Cipher.PKCS1_OAEP instead")

    def blind(self, M, B):
        """:meta private:"""
        raise NotImplementedError

    def unblind(self, M, B):
        """:meta private:"""
        raise NotImplementedError

    def size(self):
        """:meta private:"""
        raise NotImplementedError


def generate(bits, randfunc=None, e=65537):
    """Create a new RSA key pair.

    The algorithm closely follows NIST `FIPS 186-4`_ in its
    sections B.3.1 and B.3.3. The modulus is the product of
    two non-strong probable primes.
    Each prime passes a suitable number of Miller-Rabin tests
    with random bases and a single Lucas test.

    Args:
      bits (integer):
        Key length, or size (in bits) of the RSA modulus.
        It must be at least 1024, but **2048 is recommended.**
        The FIPS standard only defines 1024, 2048 and 3072.
    Keyword Args:
      randfunc (callable):
        Function that returns random bytes.
        The default is :func:`Cryptodome.Random.get_random_bytes`.
      e (integer):
        Public RSA exponent. It must be an odd positive integer.
        It is typically a small number with very few ones in its
        binary representation.
        The FIPS standard requires the public exponent to be
        at least 65537 (the default).

    Returns: an RSA key object (:class:`RsaKey`, with private key).

    .. _FIPS 186-4: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    if bits < 1024:
        raise ValueError("RSA modulus length must be >= 1024")
    if e % 2 == 0 or e < 3:
        raise ValueError("RSA public exponent must be a positive, odd integer larger than 2.")

    if randfunc is None:
        randfunc = Random.get_random_bytes

    d = n = Integer(1)
    e = Integer(e)

    while n.size_in_bits() != bits and d < (1 << (bits // 2)):
        # Generate the prime factors of n: p and q.
        # By construciton, their product is always
        # 2^{bits-1} < p*q < 2^bits.
        size_q = bits // 2
        size_p = bits - size_q

        min_p = min_q = (Integer(1) << (2 * size_q - 1)).sqrt()
        if size_q != size_p:
            min_p = (Integer(1) << (2 * size_p - 1)).sqrt()

        def filter_p(candidate):
            return candidate > min_p and (candidate - 1).gcd(e) == 1

        p = generate_probable_prime(exact_bits=size_p,
                                    randfunc=randfunc,
                                    prime_filter=filter_p)

        min_distance = Integer(1) << (bits // 2 - 100)

        def filter_q(candidate):
            return (candidate > min_q and
                    (candidate - 1).gcd(e) == 1 and
                    abs(candidate - p) > min_distance)

        q = generate_probable_prime(exact_bits=size_q,
                                    randfunc=randfunc,
                                    prime_filter=filter_q)

        n = p * q
        lcm = (p - 1).lcm(q - 1)
        d = e.inverse(lcm)

    if p > q:
        p, q = q, p

    u = p.inverse(q)

    return RsaKey(n=n, e=e, d=d, p=p, q=q, u=u)


def construct(rsa_components, consistency_check=True):
    r"""Construct an RSA key from a tuple of valid RSA components.

    The modulus **n** must be the product of two primes.
    The public exponent **e** must be odd and larger than 1.

    In case of a private key, the following equations must apply:

    .. math::

        \begin{align}
        p*q &= n \\
        e*d &\equiv 1 ( \text{mod lcm} [(p-1)(q-1)]) \\
        p*u &\equiv 1 ( \text{mod } q)
        \end{align}

    Args:
        rsa_components (tuple):
            A tuple of integers, with at least 2 and no
            more than 6 items. The items come in the following order:

            1. RSA modulus *n*.
            2. Public exponent *e*.
            3. Private exponent *d*.
               Only required if the key is private.
            4. First factor of *n* (*p*).
               Optional, but the other factor *q* must also be present.
            5. Second factor of *n* (*q*). Optional.
            6. CRT coefficient *q*, that is :math:`p^{-1} \text{mod }q`. Optional.

    Keyword Args:
        consistency_check (boolean):
            If ``True``, the library will verify that the provided components
            fulfil the main RSA properties.

    Raises:
        ValueError: when the key being imported fails the most basic RSA validity checks.

    Returns: An RSA key object (:class:`RsaKey`).
    """

    class InputComps(object):
        pass

    input_comps = InputComps()
    for (comp, value) in zip(('n', 'e', 'd', 'p', 'q', 'u'), rsa_components):
        setattr(input_comps, comp, Integer(value))

    n = input_comps.n
    e = input_comps.e
    if not hasattr(input_comps, 'd'):
        key = RsaKey(n=n, e=e)
    else:
        d = input_comps.d
        if hasattr(input_comps, 'q'):
            p = input_comps.p
            q = input_comps.q
        else:
            # Compute factors p and q from the private exponent d.
            # We assume that n has no more than two factors.
            # See 8.2.2(i) in Handbook of Applied Cryptography.
            ktot = d * e - 1
            # The quantity d*e-1 is a multiple of phi(n), even,
            # and can be represented as t*2^s.
            t = ktot
            while t % 2 == 0:
                t //= 2
            # Cycle through all multiplicative inverses in Zn.
            # The algorithm is non-deterministic, but there is a 50% chance
            # any candidate a leads to successful factoring.
            # See "Digitalized Signatures and Public Key Functions as Intractable
            # as Factorization", M. Rabin, 1979
            spotted = False
            a = Integer(2)
            while not spotted and a < 100:
                k = Integer(t)
                # Cycle through all values a^{t*2^i}=a^k
                while k < ktot:
                    cand = pow(a, k, n)
                    # Check if a^k is a non-trivial root of unity (mod n)
                    if cand != 1 and cand != (n - 1) and pow(cand, 2, n) == 1:
                        # We have found a number such that (cand-1)(cand+1)=0 (mod n).
                        # Either of the terms divides n.
                        p = Integer(n).gcd(cand + 1)
                        spotted = True
                        break
                    k *= 2
                # This value was not any good... let's try another!
                a += 2
            if not spotted:
                raise ValueError("Unable to compute factors p and q from exponent d.")
            # Found !
            assert ((n % p) == 0)
            q = n // p

        if hasattr(input_comps, 'u'):
            u = input_comps.u
        else:
            u = p.inverse(q)

        # Build key object
        key = RsaKey(n=n, e=e, d=d, p=p, q=q, u=u)

    # Verify consistency of the key
    if consistency_check:

        # Modulus and public exponent must be coprime
        if e <= 1 or e >= n:
            raise ValueError("Invalid RSA public exponent")
        if Integer(n).gcd(e) != 1:
            raise ValueError("RSA public exponent is not coprime to modulus")

        # For RSA, modulus must be odd
        if not n & 1:
            raise ValueError("RSA modulus is not odd")

        if key.has_private():
            # Modulus and private exponent must be coprime
            if d <= 1 or d >= n:
                raise ValueError("Invalid RSA private exponent")
            if Integer(n).gcd(d) != 1:
                raise ValueError("RSA private exponent is not coprime to modulus")
            # Modulus must be product of 2 primes
            if p * q != n:
                raise ValueError("RSA factors do not match modulus")
            if test_probable_prime(p) == COMPOSITE:
                raise ValueError("RSA factor p is composite")
            if test_probable_prime(q) == COMPOSITE:
                raise ValueError("RSA factor q is composite")
            # See Carmichael theorem
            phi = (p - 1) * (q - 1)
            lcm = phi // (p - 1).gcd(q - 1)
            if (e * d % int(lcm)) != 1:
                raise ValueError("Invalid RSA condition")
            if hasattr(key, 'u'):
                # CRT coefficient
                if u <= 1 or u >= q:
                    raise ValueError("Invalid RSA component u")
                if (p * u % q) != 1:
                    raise ValueError("Invalid RSA component u with p")

    return key


def _import_pkcs1_private(encoded, *kwargs):
    # RSAPrivateKey ::= SEQUENCE {
    #           version Version,
    #           modulus INTEGER, -- n
    #           publicExponent INTEGER, -- e
    #           privateExponent INTEGER, -- d
    #           prime1 INTEGER, -- p
    #           prime2 INTEGER, -- q
    #           exponent1 INTEGER, -- d mod (p-1)
    #           exponent2 INTEGER, -- d mod (q-1)
    #           coefficient INTEGER -- (inverse of q) mod p
    # }
    #
    # Version ::= INTEGER
    der = DerSequence().decode(encoded, nr_elements=9, only_ints_expected=True)
    if der[0] != 0:
        raise ValueError("No PKCS#1 encoding of an RSA private key")
    return construct(der[1:6] + [Integer(der[4]).inverse(der[5])])


def _import_pkcs1_public(encoded, *kwargs):
    # RSAPublicKey ::= SEQUENCE {
    #           modulus INTEGER, -- n
    #           publicExponent INTEGER -- e
    # }
    der = DerSequence().decode(encoded, nr_elements=2, only_ints_expected=True)
    return construct(der)


def _import_subjectPublicKeyInfo(encoded, *kwargs):

    oids = (oid, "1.2.840.113549.1.1.10")

    algoid, encoded_key, params = _expand_subject_public_key_info(encoded)
    if algoid not in oids or params is not None:
        raise ValueError("No RSA subjectPublicKeyInfo")
    return _import_pkcs1_public(encoded_key)


def _import_x509_cert(encoded, *kwargs):

    sp_info = _extract_subject_public_key_info(encoded)
    return _import_subjectPublicKeyInfo(sp_info)


def _import_pkcs8(encoded, passphrase):
    from Cryptodome.IO import PKCS8

    oids = (oid, "1.2.840.113549.1.1.10")

    k = PKCS8.unwrap(encoded, passphrase)
    if k[0] not in oids:
        raise ValueError("No PKCS#8 encoded RSA key")
    return _import_keyDER(k[1], passphrase)


def _import_keyDER(extern_key, passphrase):
    """Import an RSA key (public or private half), encoded in DER form."""

    decodings = (_import_pkcs1_private,
                 _import_pkcs1_public,
                 _import_subjectPublicKeyInfo,
                 _import_x509_cert,
                 _import_pkcs8)

    for decoding in decodings:
        try:
            return decoding(extern_key, passphrase)
        except ValueError:
            pass

    raise ValueError("RSA key format is not supported")


def _import_openssh_private_rsa(data, password):

    from ._openssh import (import_openssh_private_generic,
                           read_bytes, read_string, check_padding)

    ssh_name, decrypted = import_openssh_private_generic(data, password)

    if ssh_name != "ssh-rsa":
        raise ValueError("This SSH key is not RSA")

    n, decrypted = read_bytes(decrypted)
    e, decrypted = read_bytes(decrypted)
    d, decrypted = read_bytes(decrypted)
    iqmp, decrypted = read_bytes(decrypted)
    p, decrypted = read_bytes(decrypted)
    q, decrypted = read_bytes(decrypted)

    _, padded = read_string(decrypted)  # Comment
    check_padding(padded)

    build = [Integer.from_bytes(x) for x in (n, e, d, q, p, iqmp)]
    return construct(build)


def import_key(extern_key, passphrase=None):
    """Import an RSA key (public or private).

    Args:
      extern_key (string or byte string):
        The RSA key to import.

        The following formats are supported for an RSA **public key**:

        - X.509 certificate (binary or PEM format)
        - X.509 ``subjectPublicKeyInfo`` DER SEQUENCE (binary or PEM
          encoding)
        - `PKCS#1`_ ``RSAPublicKey`` DER SEQUENCE (binary or PEM encoding)
        - An OpenSSH line (e.g. the content of ``~/.ssh/id_ecdsa``, ASCII)

        The following formats are supported for an RSA **private key**:

        - PKCS#1 ``RSAPrivateKey`` DER SEQUENCE (binary or PEM encoding)
        - `PKCS#8`_ ``PrivateKeyInfo`` or ``EncryptedPrivateKeyInfo``
          DER SEQUENCE (binary or PEM encoding)
        - OpenSSH (text format, introduced in `OpenSSH 6.5`_)

        For details about the PEM encoding, see `RFC1421`_/`RFC1423`_.

      passphrase (string or byte string):
        For private keys only, the pass phrase that encrypts the key.

    Returns: An RSA key object (:class:`RsaKey`).

    Raises:
      ValueError/IndexError/TypeError:
        When the given key cannot be parsed (possibly because the pass
        phrase is wrong).

    .. _RFC1421: http://www.ietf.org/rfc/rfc1421.txt
    .. _RFC1423: http://www.ietf.org/rfc/rfc1423.txt
    .. _`PKCS#1`: http://www.ietf.org/rfc/rfc3447.txt
    .. _`PKCS#8`: http://www.ietf.org/rfc/rfc5208.txt
    .. _`OpenSSH 6.5`: https://flak.tedunangst.com/post/new-openssh-key-format-and-bcrypt-pbkdf
    """

    from Cryptodome.IO import PEM

    extern_key = tobytes(extern_key)
    if passphrase is not None:
        passphrase = tobytes(passphrase)

    if extern_key.startswith(b'-----BEGIN OPENSSH PRIVATE KEY'):
        text_encoded = tostr(extern_key)
        openssh_encoded, marker, enc_flag = PEM.decode(text_encoded, passphrase)
        result = _import_openssh_private_rsa(openssh_encoded, passphrase)
        return result

    if extern_key.startswith(b'-----'):
        # This is probably a PEM encoded key.
        (der, marker, enc_flag) = PEM.decode(tostr(extern_key), passphrase)
        if enc_flag:
            passphrase = None
        return _import_keyDER(der, passphrase)

    if extern_key.startswith(b'ssh-rsa '):
        # This is probably an OpenSSH key
        keystring = binascii.a2b_base64(extern_key.split(b' ')[1])
        keyparts = []
        while len(keystring) > 4:
            length = struct.unpack(">I", keystring[:4])[0]
            keyparts.append(keystring[4:4 + length])
            keystring = keystring[4 + length:]
        e = Integer.from_bytes(keyparts[1])
        n = Integer.from_bytes(keyparts[2])
        return construct([n, e])

    if len(extern_key) > 0 and bord(extern_key[0]) == 0x30:
        # This is probably a DER encoded key
        return _import_keyDER(extern_key, passphrase)

    raise ValueError("RSA key format is not supported")


# Backward compatibility
importKey = import_key

#: `Object ID`_ for the RSA encryption algorithm. This OID often indicates
#: a generic RSA key, even when such key will be actually used for digital
#: signatures.
#:
#: .. note:
#:    An RSA key meant for PSS padding has a dedicated Object ID ``1.2.840.113549.1.1.10``
#:
#: .. _`Object ID`: http://www.alvestrand.no/objectid/1.2.840.113549.1.1.1.html
oid = "1.2.840.113549.1.1.1"
