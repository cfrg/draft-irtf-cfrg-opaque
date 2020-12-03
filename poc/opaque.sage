#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import hmac
import hashlib
import struct

try:
    from sagelib.oprf import SetupBaseServer, SetupBaseClient, Evaluation, KeyGen
    from sagelib.oprf import oprf_ciphersuites, ciphersuite_ristretto255_sha512
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x
    _strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )

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

def random_bytes(n):
    return os.urandom(n)

def xor(a, b):
    assert len(a) == len(b)
    c = bytearray(a)
    for i, v in enumerate(b):
        c[i] = c[i] ^^ v # bitwise XOR
    return bytes(c)

OPAQUE_NONCE_LENGTH = 32

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
        Ts.append(hmac.digest(prk, Ts[i] + info + int(i+1).to_bytes(1, 'big'), config.hash_alg))

    def concat(a, b):
        return a + b
    T = reduce(concat, map(lambda c : c, Ts))
    return T[0:L]

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
        return int(length).to_bytes(2, 'big') + encode_vector_len(_as_bytes("OPAQUE ") + label, 1) + encode_vector_len(context, 1)
    hkdf_label = build_label(length, label, context)
    return hkdf_expand(config, secret, hkdf_label, length)

# Derive-Secret(Secret, Label, Transcript) =
#     HKDF-Expand-Label(Secret, Label, Hash(Transcript), Nh)
def derive_secret(config, secret, label, transcript):
    transcript_hash = config.hash_alg(transcript).digest()
    return hkdf_expand_label(config, secret, label, transcript_hash, config.hash_alg().digest_size)

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

# struct {
#   opaque nonce[32];
#   opaque ct<1..2^16-1>;
#   opaque auth_data<0..2^16-1>;
# } InnerEnvelope;
def deserialize_inner_envelope(data):
    if len(data) < 34:
        raise Exception("Insufficient bytes")
    nonce = data[0:32]
    ct, ct_offset = decode_vector(data[32:])
    auth_data, auth_offset = decode_vector(data[32+ct_offset:])

    return InnerEnvelope(nonce, ct, auth_data), 32+ct_offset+auth_offset

class InnerEnvelope(object):
    def __init__(self, nonce, ct, auth_data):
        assert(len(nonce) == 32)
        self.nonce = nonce
        self.ct = ct
        self.auth_data = auth_data

    def serialize(self):
        return self.nonce + encode_vector(self.ct) + encode_vector(self.auth_data)

# struct {
#   InnerEnvelope contents;
#   opaque auth_tag[Nh];
# } Envelope;
def deserialize_envelope(config, data):
    contents, offset = deserialize_inner_envelope(data)
    Nh = config.hash_alg().digest_size
    if offset + Nh > len(data):
        raise Exception("Insufficient bytes")
    auth_tag = data[offset:offset+Nh]
    return Envelope(contents, auth_tag), offset+Nh

class Envelope(object):
    def __init__(self, contents, auth_tag):
        self.contents = contents
        self.auth_tag = auth_tag

    def serialize(self):
        return self.contents.serialize() + self.auth_tag

# enum {
#   skU(1),
#   pkU(2),
#   pkS(3),
#   idU(4),
#   idS(5),
#   (255)
# } CredentialType;
#
# struct {
#   CredentialType type;
#   CredentialData data<0..2^16-1>;
# } CredentialExtension;
credential_skU = int(1)
credential_pkU = int(2)
credential_pkS = int(3)
credential_idU = int(4)
credential_idS = int(5)

def deserialize_credential_list(data):
    if len(data) < 1:
        raise Exception("Insufficient bytes")
    length = int.from_bytes(data[0:1], "big")
    types = [int(c) for c in data[1:1+length]]
    return types, 1+length

def serialize_credential_list(credential_types):
    length = len(credential_types)
    if length > 255:
        raise Exception("Input list length is too long")
    data = I2OSP(length, 1)
    for credential_type in credential_types:
        data = data + I2OSP(credential_type, 1)
    return data

def deserialize_credential_extension(data):
    if len(data) < 3:
        raise Exception("Insufficient bytes")

    credential_type = int.from_bytes(data[0:1], "big")
    data_length = int.from_bytes(data[1:3], "big")

    if 3+data_length > len(data):
        raise Exception("Insufficient bytes")

    return CredentialExtension(credential_type, data[3:3+data_length]), 3+data_length

class CredentialExtension(object):
    def __init__(self, credential_type, data):
        self.credential_type = credential_type
        self.data = data

    def serialize(self):
        body = encode_vector(self.data)
        return self.credential_type.to_bytes(1, 'big') + body

def deserialize_extensions(data):
    if len(data) < 2:
        raise Exception("Insufficient bytes")
    total_length = int.from_bytes(data[0:2], "big")
    exts = []
    offset = 2 # Skip over the length
    while offset < 2+total_length:
        ext, ext_length = deserialize_credential_extension(data[offset:])
        offset += ext_length
        exts.append(ext)

    if offset != 2+total_length:
        raise Exception("Invalid encoding, got %d, expected %d" % (offset, 2+total_length))
    return exts, offset

def serialize_extensions(exts):
    def concat(a, b):
        return a + b
    serialized = reduce(concat, map(lambda c : c.serialize(), exts))
    return len(serialized).to_bytes(2, 'big') + serialized

# struct {
#   CredentialExtension secret_credentials<1..2^16-1>;
#   CredentialExtension cleartext_credentials<0..2^16-1>;
# } Credentials;
def deserialize_credentials(data):
    if len(data) < 4:
        raise Exception("Insufficient bytes")

    secret_creds, secret_offset = deserialize_extensions(data)
    cleartext_creds, cleartext_offset = deserialize_extensions(data[secret_offset:])
    return Credentials(secret_creds, cleartext_creds), secret_offset+cleartext_offset

class Credentials(object):
    def __init__(self, secret_credentials, cleartext_credentials):
        self.secret_credentials = secret_credentials
        self.cleartext_credentials = cleartext_credentials

    def serialize(self):
        secret_creds = serialize_extensions(self.secret_credentials)
        cleartext_creds = serialize_extensions(self.cleartext_credentials)
        return secret_creds + cleartext_creds

class ProtocolMessage(object):
    def __init__(self):
        pass

    def serialize(self):
        raise Exception("Not implemented")

    def __eq__(self, other):
        if isinstance(other, ProtocolMessage):
            serialized = self.serialize()
            other_serialized = other.serialize()
            return serialized == other_serialized
        return False

# struct {
#     opaque data<1..2^16-1>;
# } RegistrationRequest;
def deserialize_registration_request(config, msg_bytes):
    data, offset = decode_vector(msg_bytes)
    return RegistrationRequest(data)

class RegistrationRequest(ProtocolMessage):
    def __init__(self, data):
        ProtocolMessage.__init__(self)
        self.data = data

    def serialize(self):
        return encode_vector(self.data)

# struct {
#     opaque data<0..2^16-1>;
#     opaque pkS<0..2^16-1>;
#     CredentialType secret_types<1..255>;
#     CredentialType cleartext_types<0..255>;
# } RegistrationResponse;
def deserialize_registration_response(config, msg_bytes):
    offset = 0

    data, data_offset = decode_vector(msg_bytes[offset:])
    offset += data_offset

    pkS, pkS_offset = decode_vector(msg_bytes[offset:])
    offset += pkS_offset

    secret_types, secret_types_offset = deserialize_credential_list(msg_bytes[offset:])
    offset += secret_types_offset

    cleartext_types, cleartext_types_offset = deserialize_credential_list(msg_bytes[offset:])
    offset += cleartext_types_offset

    return RegistrationResponse(data, pkS, secret_types, cleartext_types)

class RegistrationResponse(ProtocolMessage):
    def __init__(self, data, pkS, secret_list, cleartext_list):
        ProtocolMessage.__init__(self)
        self.data = data
        self.pkS = pkS
        self.secret_list = secret_list
        self.cleartext_list = cleartext_list

    def serialize(self):
        return encode_vector(self.data) + encode_vector(self.pkS) + serialize_credential_list(self.secret_list) + \
            serialize_credential_list(self.cleartext_list)

# struct {
#     Envelope envelope;
#     opaque pkU<0..2^16-1>;
# } RegistrationUpload;
def deserialize_registration_upload(config, msg_bytes):
    offset = 0

    envU, envU_offset = deserialize_envelope(config, msg_bytes[offset:])
    offset += envU_offset

    pkU, pkU_offset = decode_vector(msg_bytes[offset:])
    offset += pkU_offset

    return RegistrationUpload(envU, pkU)

class RegistrationUpload(ProtocolMessage):
    def __init__(self, envU, pkU):
        ProtocolMessage.__init__(self)
        self.envU = envU
        self.pkU = pkU

    def serialize(self):
        return self.envU.serialize() + encode_vector(self.pkU)

# struct {
#     opaque data<1..2^16-1>;
# } CredentialRequest;
def deserialize_credential_request(config, msg_bytes):
    data, offset = decode_vector(msg_bytes)
    return CredentialRequest(data)

class CredentialRequest(ProtocolMessage):
    def __init__(self, data):
        ProtocolMessage.__init__(self)
        self.data = data

    def serialize(self):
        return encode_vector(self.data)

# struct {
#     opaque data<1..2^16-1>;
#     Envelope envelope;
# } CredentialResponse;
def deserialize_credential_response(config, msg_bytes):
    offset = 0

    data, data_offset = decode_vector(msg_bytes[offset:])
    offset += data_offset

    envU, envU_offset = deserialize_envelope(config, msg_bytes[offset:])
    offset += envU_offset

    return CredentialResponse(data, envU)

class CredentialResponse(ProtocolMessage):
    def __init__(self, data, envU):
        ProtocolMessage.__init__(self)
        self.data = data
        self.envU = envU

    def serialize(self):
        return encode_vector(self.data) + self.envU.serialize()

'''
===================  OPAQUE registration flow ====================

 Client (idU, pwdU, skU, pkU)                 Server (skS, pkS)
  -----------------------------------------------------------------
   request, blind = CreateRegistrationRequest(idU, pwdU)

                                   request
                              ----------------->

            (response, kU) = CreateRegistrationResponse(request, pkS)

                                   response
                              <-----------------

 record = FinalizeRequest(idU, pwdU, skU, blind, request, response)

                                    record
                              ------------------>

                                             StoreUserRecord(record)
'''

def create_registration_request(config, pwdU):
    oprf_context = SetupBaseClient(config.oprf_suite)

    blind, blinded_element = oprf_context.blind(pwdU)
    request = RegistrationRequest(blinded_element)

    return request, blind

def create_registration_response(config, request, pkS, secret_list, cleartext_list):
    kU, pkU = KeyGen(config.oprf_suite)
    oprf_context = SetupBaseServer(config.oprf_suite, kU)

    data, _ = oprf_context.evaluate(request.data)
    response = RegistrationResponse(data, pkS, secret_list, cleartext_list)

    return response, kU

def derive_secrets(config, pwdU, response, blind, nonce, Npt):
    oprf_context = SetupBaseClient(config.oprf_suite)
    N = oprf_context.unblind(blind, response.data, None, None) # TODO(caw): https://github.com/cfrg/draft-irtf-cfrg-opaque/issues/68
    y = oprf_context.finalize(pwdU, N, _as_bytes("OPAQUE00"))
    y_harden = config.harden(y, params=[100000])
    rwdU = hkdf_extract(config, _as_bytes("rwdU"), y_harden)

    Nh = config.hash_alg().digest_size

    pseudorandom_pad = hkdf_expand(config, rwdU, nonce + _as_bytes("Pad"), Npt)
    auth_key = hkdf_expand(config, rwdU, nonce + _as_bytes("AuthKey"), Nh)
    export_key = hkdf_expand(config, rwdU, nonce + _as_bytes("ExportKey"), Nh)

    return rwdU, pseudorandom_pad, auth_key, export_key

def finalize_request(config, idU, pwdU, skU, pkU, blind, request, response, kU):
    secret_credentials = []
    for credential_type in response.secret_list:
        if credential_type == credential_skU:
            secret_credentials.append(CredentialExtension(credential_skU, skU))
        else:
            # TODO(caw): implement other extensions here
            pass
    cleartext_credentials = []
    for credential_type in response.cleartext_list:
        if credential_type == credential_idU:
            cleartext_credentials.append(CredentialExtension(credential_idU, idU))
        else:
            # TODO(caw): implement other extensions here
            pass

    pt = serialize_extensions(secret_credentials)
    auth_data = serialize_extensions(cleartext_credentials)

    nonce = random_bytes(OPAQUE_NONCE_LENGTH)
    rwdU, pseudorandom_pad, auth_key, export_key = derive_secrets(config, pwdU, response, blind, nonce, len(pt))
    ct = xor(pt, pseudorandom_pad)

    contents = InnerEnvelope(nonce, ct, auth_data)
    serialized_contents = contents.serialize()
    auth_tag = hmac.digest(auth_key, serialized_contents, config.hash_alg)

    envU = Envelope(contents, auth_tag)
    upload = RegistrationUpload(envU, pkU)

    return upload, export_key

'''
========================= OPAQUE authentication flow ========================

 Client (idU, pwdU)                           Server (skS, pkS)
  -----------------------------------------------------------------
   request, blind = CreateCredentialRequest(idU, pwdU)

                                   request
                              ----------------->

         (response, pkU) = CreateCredentialResponse(request, pkS)

                                   response
                              <-----------------

  creds, export_key = RecoverCredentials(pwdU, blind, request, response)

                               (AKE with creds)
                              <================>
'''

def create_credential_request(config, pwdU):
    oprf_context = SetupBaseClient(config.oprf_suite)
    blind, blinded_element = oprf_context.blind(pwdU)

    request = CredentialRequest(blinded_element)

    return request, blind

def create_credential_response(config, request, pkS, kU, record):
    envU, pkU = record.envU, record.pkU

    oprf_context = SetupBaseServer(config.oprf_suite, kU)

    data, _ = oprf_context.evaluate(request.data)

    response = CredentialResponse(data, envU)

    return response, pkU

def recover_credentials(config, pwdU, blind, request, response):
    contents = response.envU.contents
    serialized_contents = contents.serialize()
    nonce = contents.nonce
    ct = contents.ct
    auth_data = contents.auth_data

    rwdU, pseudorandom_pad, auth_key, export_key = derive_secrets(config, pwdU, response, blind, nonce, len(ct))
    expected_tag = hmac.digest(auth_key, serialized_contents, config.hash_alg)

    if expected_tag != response.envU.auth_tag:
        raise Exception("Invalid tag")

    pt = xor(ct, pseudorandom_pad)
    secret_credentials, _ = deserialize_extensions(pt)
    cleartext_credentials, _ = deserialize_extensions(auth_data)
    creds = Credentials(secret_credentials, cleartext_credentials)

    return creds, export_key, rwdU, pseudorandom_pad, auth_key

class Configuration(object):
    def __init__(self, oprf_suite, hash_alg, harden):
        self.oprf_suite = oprf_suite
        self.hash_alg = hash_alg
        self.harden = harden

scrypt_harden = lambda y, params : hashlib.scrypt(y, "", b'salt', params[0], params[1], params[2])
pbkdf_harden = lambda y, params : hashlib.pbkdf2_hmac('sha256', y, b'salt', params[0])
default_opaque_configuration = Configuration(oprf_ciphersuites[ciphersuite_ristretto255_sha512], hashlib.sha512, pbkdf_harden)
