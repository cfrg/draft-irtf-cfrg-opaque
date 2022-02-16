#!/usr/bin/sage
# vim: syntax=python

import sys
import random
import hashlib
import struct

try:
    from sagelib.test_drng import TestDRNG
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

# defined in RFC 3447, section 4.1
def I2OSP(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in reversed(range(0, length)):
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

class OPAQUEDRNG(TestDRNG):
    def __init__(self, seed):
        TestDRNG.__init__(self, seed)

    def random_bytes(self, n):
        random.seed(self.seed)
        output = I2OSP(random.randrange(2**(8*n)), n)
        val = random.randint(0, 2^32)
        self.seed = int.from_bytes(hashlib.sha256(int(val % 2^32).to_bytes(4, 'big')).digest(), 'big')
        return output