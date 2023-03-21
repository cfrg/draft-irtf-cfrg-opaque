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

    
class H_SHA384:
    def __init__(self):
        self.b_in_bytes = 48
        self.bmax_in_bytes = 48
        self.s_in_bytes = 128
        self.name = "SHA-384"
        
    def hash(self,input_str, l = 48):
        m = hashlib.sha384(input_str)
        digest = m.digest()
        if len(digest) < l:
            raise ValueError("Output length of Hash primitive (%i bytes) not long enough. %i bytes were requested." % (len(digest), l))
        return digest[0:l]

    
class H_SHA256:
    def __init__(self):
        self.b_in_bytes = 32
        self.bmax_in_bytes = 32
        self.s_in_bytes = 64
        self.name = "SHA-256"
        
    def hash(self,input_str, l = 32):
        m = hashlib.sha256(input_str)
        digest = m.digest()
        if len(digest) < l:
            raise ValueError("Output length of Hash primitive (%i bytes) not long enough. %i bytes were requested." % (len(digest), l))

        return digest[0:l]

class H_SHAKE256:
    def __init__(self):
        self.b_in_bytes = 64
        self.bmax_in_bytes = 2^128
        self.s_in_bytes = 136
        self.name = "SHAKE-256"
        
    def hash(self,input_str, l = 64):
        m = hashlib.shake_256(input_str)
        digest = m.digest(l) # Note: hashlib.shake_256 seems to be buggy in some Sage environments :-(
        return digest

class G_Montgomery:
    """Here we have common definitions for the X448 and X25519"""
    def sample_scalar(self, deterministic_scalar_for_test_vectors = "False"):
        if deterministic_scalar_for_test_vectors == "False":
            return random_bytes(self.field_size_bytes)
        else:
            H = H_SHA512()
            value = H.hash(deterministic_scalar_for_test_vectors)
            return value[0:self.field_size_bytes]

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

    def output_markdown_description_for_decodeUCoordinate(self, file = sys.stdout):
    	print ("""

## Decoding and Encoding functions according to RFC7748

~~~
   def decodeLittleEndian(b, bits):
       return sum([b[i] << 8*i for i in range((bits+7)/8)])

   def decodeUCoordinate(u, bits):
       u_list = [ord(b) for b in u]
       # Ignore any unused bits.
       if bits % 8:
           u_list[-1] &= (1<<(bits%8))-1
       return decodeLittleEndian(u_list, bits)

   def encodeUCoordinate(u, bits):
       return ''.join([chr((u >> 8*i) & 0xff)
                       for i in range((bits+7)/8)])
~~~

"""             , file = file);


    def output_markdown_description_for_elligator2(self,file = sys.stdout):
    	print (
"""
## Elligator 2 reference implementation
The Elligator 2 map requires a non-square field element Z which shall be calculated
as follows.

~~~
    def find_z_ell2(F):
        # Find nonsquare for Elligator2
        # Argument: F, a field object, e.g., F = GF(2^255 - 19)
        ctr = F.gen()
        while True:
            for Z_cand in (F(ctr), F(-ctr)):
                # Z must be a non-square in F.
                if is_square(Z_cand):
                    continue
                return Z_cand
            ctr += 1
~~~

The values of the non-square Z only depend on the curve. The algorithm above
results in a value of Z = 2 for Curve25519 and Z=-1 for Ed448.

The following code maps a field element r to an encoded field element which
is a valid u-coordinate of a Montgomery curve with curve parameter A.

~~~
    def elligator2(r, q, A, field_size_bits):
        # Inputs: field element r, field order q,
        #         curve parameter A and field size in bits
        Fq = GF(q); A = Fq(A); B = Fq(1);

        # get non-square z as specified in the hash2curve draft.
        z = Fq(find_z_ell2(Fq))
        powerForLegendreSymbol = floor((q-1)/2)

        v = - A / (1 + z * r^2)
        epsilon = (v^3 + A * v^2 + B * v)^powerForLegendreSymbol
        x = epsilon * v - (1 - epsilon) * A/2
        return encodeUCoordinate(Integer(x), field_size_bits)
~~~

"""         , file = file);
    	
    def encodeUCoordinate(self,u):
        u = u % self.q
        return IntegerToByteArray(u,self.field_size_bytes)
    
    def find_z_ell2(self,F):
        """ Argument: F, a field object, e.g., F = GF(2^255 - 19) """
        ctr = F.gen()
        while True:
            for Z_cand in (F(ctr), F(-ctr)):
                # Z must be a non-square in F.
                if is_square(Z_cand):
                    continue
                return Z_cand
            ctr += 1
        
    def elligator2(self,r):
        q = self.q
        Fq = GF(q)
        A = Fq(self.A)
        B = Fq(1)
    
        # calculate the appropriate non-square as specified in the hash2curve draft.
        u = Fq(self.find_z_ell2(Fq))
        powerForChi = floor((q-1)/2)
    
        v = - A / (1 + u * r^2)
        epsilon = (v^3 + A * v^2 + B * v)^powerForChi
        x = epsilon * v - (1 - epsilon) * A/2
        return self.encodeUCoordinate(Integer(x))

    def calculate_generator(self, H, PRS, CI, sid, print_test_vector_info = False, file = sys.stdout):
        (gen_string, len_zpad) = generator_string(self.DSI, PRS, CI, sid, H.s_in_bytes)
        string_hash = H.hash(gen_string, self.field_size_bytes)
        u = self.decodeUCoordinate(string_hash)
        result = self.elligator2(u)
        if print_test_vector_info:
            print ("\n###  Test vectors for calculate\\_generator with group "+self.name+"\n",file=file)
            print ("~~~", file=file)

            print ("  Inputs", file=file)
            print ("    H   =", H.name, "with input block size", H.s_in_bytes, "bytes.", file=file)
            print ("    PRS =", PRS, "; ZPAD length:", len_zpad,"; DSI =", self.DSI, file=file)
            print ("    CI =", CI, file=file)
            print ("    CI =", ByteArrayToLEPrintString(CI), file=file)
            print ("    sid =", ByteArrayToLEPrintString(sid), file=file)
            print ("  Outputs",file=file)
            tv_output_byte_array(gen_string, test_vector_name = "generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes)", 
                                 line_prefix = "    ", max_len = 60, file=file)
            tv_output_byte_array(string_hash, test_vector_name = "hash generator string", 
                                 line_prefix = "    ", max_len = 60, file=file)
            tv_output_byte_array(IntegerToByteArray(u,self.field_size_bytes), test_vector_name = "decoded field element of %i bits" % self.field_size_bits, 
                                 line_prefix = "    ", max_len = 60, file=file)
            tv_output_byte_array(result, test_vector_name = "generator g", 
                                 line_prefix = "    ", max_len = 60, file=file)
            print ("~~~", file=file)
        return result

    
class G_X25519(G_Montgomery):
    def __init__(self):
        self.I = zero_bytes(32)
        self.field_size_bytes = 32
        self.field_size_bits = 255
        self.name = "X25519" # group name
        self.encoding_of_scalar = "little endian"
        
        # curve definitions
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