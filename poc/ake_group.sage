import sys
import hashlib 

########## Definitions from RFC 7748 ##################
from sagelib.rfc7748 import *
from sagelib.groups import *
from sagelib.string_utils import *

try:
    from sagelib.opaque_common import curve25519_clamp
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)


class GroupCurve25519(Group):
    def __init__(self):
        Group.__init__(self, "curve25519")

    def generator(self):
        return IntegerToByteArray(9)

    def serialize(self, element):
        # Curve25519 points are bytes
        return element

    def deserialize(self, encoded):
        # Curve25519 points are bytes
        return encoded

    def serialize_scalar(self, scalar):
        # Curve25519 scalars are represented as bytes
        return scalar

    def element_byte_length(self):
        return 32

    def scalar_byte_length(self):
        return 32

    def random_scalar(self, rng):
        return curve25519_clamp(rng.random_bytes(32))

    def scalar_mult(self, x, y):
        return X25519(x, y)

    def __str__(self):
        return self.name

if __name__ == "__main__":
    # From RFC7748: https://www.rfc-editor.org/rfc/rfc7748#section-6.1
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    A = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    G = GroupCurve25519()
    A_exp = G.scalar_mult(a, G.generator())
    assert(A_exp == A)