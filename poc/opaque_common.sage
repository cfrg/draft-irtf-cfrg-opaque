#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import hmac
import hashlib
import struct

if sys.version_info[0] == 3:
    xrange = range
    def _as_bytes(x): return x if isinstance(x, bytes) else bytes(x, "utf-8")
    def _strxor(str1, str2): return bytes(
        s1 ^ s2 for (s1, s2) in zip(str1, str2))
else:
    def _as_bytes(x): return x
    def _strxor(str1, str2): return ''.join(chr(ord(s1) ^ ord(s2))
                                            for (s1, s2) in zip(str1, str2))

def random_bytes(n):
    return os.urandom(n)

def xor(a, b):
    assert len(a) == len(b)
    c = bytearray(a)
    for i, v in enumerate(b):
        c[i] = c[i] ^^ v  # bitwise XOR
    return bytes(c)

def hkdf_extract(config, salt, ikm):
    return hmac.digest(salt, ikm, config.hash_alg)

def hkdf_expand(config, prk, info, L):
    # https://tools.ietf.org/html/rfc5869
    # N = ceil(L/HashLen)
    # T = T(1) | T(2) | T(3) | ... | T(N)
    # OKM = first L octets of T
    hash_length = config.hash_alg().digest_size
    N = ceil(L / hash_length)
    Ts = [bytes(bytearray([]))]
    for i in range(N):
        Ts.append(hmac.digest(
            prk, Ts[i] + info + int(i+1).to_bytes(1, 'big'), config.hash_alg))

    def concat(a, b):
        return a + b
    T = reduce(concat, map(lambda c: c, Ts))
    return T[0:L]

def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    if isinstance(octet_string, bytes):
        return "" + "".join("{:02x}".format(c) for c in octet_string)
    assert isinstance(octet_string, bytearray)
    return ''.join(format(x, '02x') for x in octet_string)


# HKDF-Expand-Label(Secret, Label, Context, Length) =
#   HKDF-Expand(Secret, HkdfLabel, Length)
#
# struct {
#    uint16 length = Length;
#    opaque label<8..255> = "OPAQUE " + Label;
#    opaque context<0..255> = Context;
# } HkdfLabel;
def hkdf_expand_label(config, secret, label, context, length):
    def build_label(length, label, context):
        return I2OSP(length, 2) + encode_vector_len(_as_bytes("OPAQUE ") + label, 1) + encode_vector_len(context, 1)
    hkdf_label = build_label(length, label, context)
    print(to_hex(hkdf_label))
    return hkdf_expand(config, secret, hkdf_label, length)

# Derive-Secret(Secret, Label, Transcript) =
#     HKDF-Expand-Label(Secret, Label, Hash(Transcript), Nh)
def derive_secret(config, secret, label, transcript):
    transcript_hash = config.hash_alg(transcript).digest()
    return hkdf_expand_label(config, secret, label, transcript_hash, config.hash_alg().digest_size)

# defined in RFC 3447, section 4.1
def I2OSP(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in reversed(xrange(0, length)):
        ret[idx] = val_ & 0xff
        val_ = val_ >> 8
    ret = struct.pack("=" + "B" * length, *ret)
    assert OS2IP(ret, True) == val
    return ret

# defined in RFC 3447, section 4.2
def OS2IP(octets, skip_assert=False):
    ret = 0
    for octet in struct.unpack("=" + "B" * len(octets), octets):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP(ret, len(octets))
    return ret

# little-endian version of I2OSP
def I2OSP_le(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in range(0, length):
        ret[idx] = val_ & 0xff
        val_ = val_ >> 8
    ret = struct.pack("=" + "B" * length, *ret)
    assert OS2IP_le(ret, True) == val
    return ret

# little-endian version of OS2IP
def OS2IP_le(octets, skip_assert=False):
    ret = 0
    for octet in reversed(struct.unpack("=" + "B" * len(octets), octets)):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP_le(ret, len(octets))
    return ret

def encode_vector_len(data, L):
    return len(data).to_bytes(L, 'big') + data

def decode_vector_len(data_bytes, L):
    if len(data_bytes) < L:
        raise Exception("Insufficient length")
    data_len = int.from_bytes(data_bytes[0:L], 'big')
    if len(data_bytes) < L+data_len:
        raise Exception("Insufficient length")
    return data_bytes[L:L+data_len], L+data_len

def encode_vector(data):
    return encode_vector_len(data, 2)

def decode_vector(data_bytes):
    return decode_vector_len(data_bytes, 2)
