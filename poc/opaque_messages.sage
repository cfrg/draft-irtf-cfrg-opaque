#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import hmac
import hashlib
import struct

try:
    from sagelib.opaque_common import I2OSP, OS2IP, encode_vector, encode_vector_len, decode_vector, decode_vector_len
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

# enum {
#   internal(1),
#   external(2),
#   (255)
# } EnvelopeMode;
envelope_mode_internal = 0x01
envelope_mode_external = 0x02

# struct {
#    opaque client_private_key[Nsk];
# } SecretCredentials;
# 
# struct {
#    opaque server_public_key[Npk];
# } CleartextCredentials;
#
# struct {
#   SecretCredentials secret_credentials;
#   CleartextCredentials cleartext_credentials;
# } Credentials;

def deserialize_secret_credentials(data):
    return SecretCredentials(data), len(data)

class SecretCredentials(object):
    def __init__(self, skU):
        self.skU = skU

    def serialize(self):
        return self.skU

class CleartextCredentials(object):
    def __init__(self, pkS, idU, idS):
        self.pkS = pkS
        self.idU = idU
        self.idS = idS

    def serialize(self):
        return self.pkS + encode_vector(self.idU) + encode_vector(self.idS)

class Credentials(object):
    def __init__(self, skU, pkU, idU = None, idS = None):
        self.skU = skU
        self.pkU = pkU
        self.idU = idU
        self.idS = idS

# struct {
#   select (EnvelopeMode) {
#     case internal:
#       // empty in internal mode
#     case external:
#       opaque encrypted_creds[Nsk];  
#   }
# } InnerEnvelope;
def deserialize_inner_envelope(config, data):
    if config.mode == envelope_mode_internal:
        return InnerEnvelope(), 0
    elif len(data) >= config.Nsk:
        return InnerEnvelope(data[0:config.Nsk]), config.Nsk

class InnerEnvelope(object):
    def __init__(self, encrypted_creds = None):
        self.encrypted_creds = encrypted_creds

    def serialize(self):
        if self.encrypted_creds == None:
            return bytes([])
        else:
            return self.encrypted_creds

# struct {
#   opaque nonce[Nn];
#   InnerEnvelope inner_env;
#   opaque auth_tag[Nm];
# } Envelope;
def deserialize_envelope(config, data):

    # TODO(caw): put Nm in the config
    inner_length = 0
    if config.mode == envelope_mode_external:
        inner_length = config.Nsk
    Nm = config.hash().digest_size
    if len(data) != 32 + inner_length + Nm:
         raise Exception("Invalid envelope length")

    nonce = data[:32]
    inner_env, offset = deserialize_inner_envelope(config, data[32:])
    auth_tag = data[32+offset:]

    return Envelope(nonce, inner_env, auth_tag), 32+offset+Nm

    # contents, offset = deserialize_inner_envelope(config, data)
    # Nh = config.hash().digest_size
    # if offset + Nh > len(data):
    #     raise Exception("Insufficient bytes")
    # auth_tag = data[offset:offset+Nh]
    # return Envelope(contents, auth_tag), offset+Nh

class Envelope(object):
    def __init__(self, nonce, inner_env, auth_tag):
        self.nonce = nonce
        self.inner_env = inner_env
        self.auth_tag = auth_tag

    def serialize(self):
        return self.nonce + self.inner_env.serialize() + self.auth_tag

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
#     opaque pkS[Npk];
# } RegistrationResponse;
def deserialize_registration_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]
    pkS = msg_bytes[length:]
    if len(pkS) != config.Npk:
        raise Exception("Invalid message: %d %d" % (len(pkS), config.Npk))

    return RegistrationResponse(data, pkS)

class RegistrationResponse(ProtocolMessage):
    def __init__(self, data, pkS):
        ProtocolMessage.__init__(self)
        self.data = data
        self.pkS = pkS

    def serialize(self):
        return self.data + self.pkS

# struct {
#     opaque pkU[Npk];
#     opaque masking_key[Nh];
#     Envelope envU;
# } RegistrationUpload;
def deserialize_registration_upload(config, msg_bytes):
    if len(msg_bytes) < config.Npk:
        raise Exception("Invalid message")
    pkU = msg_bytes[:config.Npk]

    Nh = config.hash().digest_size
    masking_key = msg_bytes[config.Npk:config.Npk+Nh]

    envU, _ = deserialize_envelope(config, msg_bytes[config.Npk+Nh:])

    return RegistrationUpload(pkU, masking_key, envU)

class RegistrationUpload(ProtocolMessage):
    def __init__(self, pkU, masking_key, envU):
        ProtocolMessage.__init__(self)
        self.pkU = pkU
        self.masking_key = masking_key
        self.envU = envU

    def serialize(self):
        return self.pkU + self.masking_key + self.envU.serialize()

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
#     opaque masking_nonce[32];
#     opaque masked_response[Npk + Ne];
# } CredentialResponse;
def deserialize_credential_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]
    masking_nonce = msg_bytes[length:length+32]

    Nm = config.hash().digest_size
    Npk = config.Npk
    Ne = Nm + 32
    if config.mode == envelope_mode_external:
        Ne = Ne + config.Nsk
    masked_response = msg_bytes[length+32:length+32+Npk+Ne]
    return CredentialResponse(data, masking_nonce, masked_response), length+32+Npk+Ne

class CredentialResponse(ProtocolMessage):
    def __init__(self, data, masking_nonce, masked_response):
        ProtocolMessage.__init__(self)
        self.data = data
        self.masking_nonce = masking_nonce
        self.masked_response = masked_response

    def serialize(self):
        return self.data + self.masking_nonce + self.masked_response
