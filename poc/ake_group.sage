import sys
import hashlib 

########## Definitions from RFC 7748 ##################
from sagelib.rfc7748 import *
from sagelib.groups import *
from sagelib.string_utils import *

class H_SHA512:
    def __init__(self):
        self.b_in_bytes = 64
        self.bmax_in_bytes = 64
        self.s_in_bytes = 128
        self.name = "SHA-512"
        
    def hash(self,input_str, l = 64):
        m = hashlib.sha512(input_str)
        digest = m.digest()
        if len(digest) < l:
            raise ValueError("Output length of Hash primitive (%i bytes) not long enough. %i bytes were requested." % (len(digest), l))
        return digest[0:l]

class G_Montgomery:
    def decodeLittleEndian(self, b):
        bits = self.field_size_bits
        num_bytes = floor((bits+7)/8)
        return sum([b[i] << 8*i for i in range(num_bytes)])

    def decodeUCoordinate(self, u):        
        u_list = [b for b in u]
        # Ignore any unused bits.
        if self.field_size_bits % 8:
            u_list[-1] &= (1<<(self.field_size_bits%8))-1
        return self.decodeLittleEndian(u_list)

    def encodeUCoordinate(self,u):
        u = u % self.q
        return IntegerToByteArray(u,self.field_size_bytes)
    
class G_X25519(G_Montgomery):
    def __init__(self):
        self.q = 2^255 - 19
        self.A = 486662
        
    def scalar_mult(self,scalar,point):
        return X25519(scalar,point)

    def scalar_mult_vfy(self,scalar,point):
        return X25519(scalar,point)


class GroupX25519(Group):
    def __init__(self):
        Group.__init__(self, "x25519")
        self.G = G_X25519()

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
        return os.urandom(32)

    def scalar_mult(self, x, y):
        return self.G.scalar_mult(x, y)

    def __str__(self):
        return self.name

if __name__ == "__main__":
    # From RFC7748: https://www.rfc-editor.org/rfc/rfc7748#section-6.1
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    A = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    G = GroupX25519()
    A_exp = G.scalar_mult(a, G.generator())
    assert(A_exp == A)