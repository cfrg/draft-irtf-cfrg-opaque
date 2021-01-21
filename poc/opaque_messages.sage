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
    from sagelib.opaque_common import derive_secret, hkdf_expand_label, hkdf_expand, hkdf_extract, random_bytes, xor, I2OSP, OS2IP, encode_vector, encode_vector_len, decode_vector, decode_vector_len
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    def _as_bytes(x): return x if isinstance(x, bytes) else bytes(x, "utf-8")
    def _strxor(str1, str2): return bytes(
        s1 ^ s2 for (s1, s2) in zip(str1, str2))
else:
    def _as_bytes(x): return x
    def _strxor(str1, str2): return ''.join(chr(ord(s1) ^ ord(s2))
                                            for (s1, s2) in zip(str1, str2))

# struct {
#    opaque skU<1..2^16-1>; 
# } SecretCredentials;
# 
# struct {
#    opaque pkS<1..2^16-1>;
# } CleartextCredentials;
#
# struct {
#   SecretCredentials secret_credentials;
#   CleartextCredentials cleartext_credentials;
# } Credentials;

envelope_mode_base = 0x00
envelope_mode_custom_identifier = 0x01

def deserialize_secret_credentials(data):
    skU, offset = decode_vector(data)
    return SecretCredentials(skU), offset

class SecretCredentials(object):
    def __init__(self, skU):
        self.skU = skU

    def serialize(self):
        return encode_vector(self.skU)

class CleartextCredentials(object):
    def __init__(self, pkS, mode = envelope_mode_base):
        self.pkS = pkS
        self.mode = mode

    def serialize(self):
        return encode_vector(self.pkS)

class CustomCleartextCredentials(CleartextCredentials):
    def __init__(self, pkS, idU, idS):
        CleartextCredentials.__init__(self, pkS, envelope_mode_custom_identifier)
        self.idU = idU
        self.idS = idS

    def serialize(self):
        return encode_vector(self.pkS) + encode_vector(self.idU) + encode_vector(self.idS)

class Credentials(object):
    def __init__(self, skU, pkU):
        self.mode = envelope_mode_base
        self.skU = skU
        self.pkU = pkU

class CustomCredentials(Credentials):
    def __init__(self, skU, pkU, idU, idS):
        Credentials.__init__(self, skU, pkU)
        self.mode = envelope_mode_custom_identifier
        self.idU = idU
        self.idS = idS

# struct {
#   InnerEnvelopeMode mode;
#   opaque nonce[32];
#   opaque ct<1..2^16-1>;
# } InnerEnvelope;
def deserialize_inner_envelope(data):
    if len(data) < 35:
        raise Exception("Insufficient bytes")
    mode = OS2IP(data[0:1])
    nonce = data[1:33]
    ct, ct_offset = decode_vector(data[33:])
    return InnerEnvelope(mode, nonce, ct), 33+ct_offset

class InnerEnvelope(object):
    def __init__(self, mode, nonce, ct):
        assert(len(nonce) == 32)
        self.mode = mode
        self.nonce = nonce
        self.ct = ct

    def serialize(self):
        return I2OSP(self.mode, 1) + self.nonce + encode_vector(self.ct)

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

    def __eq__(self, other):
        if isinstance(other, Envelope):
            serialized = self.serialize()
            other_serialized = other.serialize()
            return serialized == other_serialized
        return False

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
#     SerializedElement data;
# } RegistrationRequest;
def deserialize_registration_request(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    if len(msg_bytes) < length:
        raise Exception("Invalid message")
    return RegistrationRequest(msg_bytes[0:length])

class RegistrationRequest(ProtocolMessage):
    def __init__(self, data):
        ProtocolMessage.__init__(self)
        self.data = data

    def serialize(self):
        return self.data

# struct {
#     SerializedElement data;
#     opaque pkS<1..2^16-1>;
# } RegistrationResponse;
def deserialize_registration_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]
    pkS, _ = decode_vector(msg_bytes[length:])

    return RegistrationResponse(data, pkS)

class RegistrationResponse(ProtocolMessage):
    def __init__(self, data, pkS):
        ProtocolMessage.__init__(self)
        self.data = data
        self.pkS = pkS

    def serialize(self):
        return self.data + encode_vector(self.pkS)

# struct {
#     opaque pkU<1..2^16-1>;
#     Envelope envU;
# } RegistrationUpload;
def deserialize_registration_upload(config, msg_bytes):
    offset = 0

    pkU, pkU_offset = decode_vector(msg_bytes[offset:])
    offset += pkU_offset

    envU, _ = deserialize_envelope(config, msg_bytes[offset:])

    return RegistrationUpload(envU, pkU)

class RegistrationUpload(ProtocolMessage):
    def __init__(self, envU, pkU):
        ProtocolMessage.__init__(self)
        self.envU = envU
        self.pkU = pkU

    def serialize(self):
        return encode_vector(self.pkU) + self.envU.serialize()

# struct {
#     SerializedElement data;
# } CredentialRequest;
def deserialize_credential_request(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    if len(msg_bytes) < length:
        raise Exception("Invalid message")
    return CredentialRequest(msg_bytes[0:length]), length

class CredentialRequest(ProtocolMessage):
    def __init__(self, data):
        ProtocolMessage.__init__(self)
        self.data = data

    def serialize(self):
        return self.data

# struct {
#     SerializedElement data;
#     opaque pkS<1..2^16-1>;
#     Envelope envelope;
# } CredentialResponse;
def deserialize_credential_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]

    pkS, pkS_length = decode_vector(msg_bytes[length:])
    offset = length + pkS_length

    envU, length = deserialize_envelope(config, msg_bytes[offset:])
    offset = offset + length

    return CredentialResponse(data, pkS, envU), offset

class CredentialResponse(ProtocolMessage):
    def __init__(self, data, pkS, envU):
        ProtocolMessage.__init__(self)
        self.data = data
        self.pkS = pkS
        self.envU = envU

    def serialize(self):
        return self.data + encode_vector(self.pkS) + self.envU.serialize()
