#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import hmac
import hashlib
import struct

from collections import namedtuple

try:
    from sagelib.oprf import SetupBaseServer, SetupBaseClient, Evaluation
    from sagelib.oprf import ciphersuite_p256_hkdf_sha512_sswu_ro, Ciphersuite, GroupP256
    from sagelib import ristretto255
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x
    _strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )

## TODO(caw): move these to common.sage

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

OPAQUE_NONCE_LENGTH = 32

def random_bytes(n):
    return os.urandom(n)

def xor(a, b):
    assert len(a) == len(b)
    c = bytearray(a)
    for i, v in enumerate(b):
        c[i] = c[i] ^^ v # bitwise XOR
    return bytes(c)

def harden(y, params):
    # TODO(caw): no-op as of now until we figure out parameters:
    # https://github.com/cfrg/draft-irtf-cfrg-opaque/issues/69
    return y

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

# enum {
#     registration_request(1),
#     registration_response(2),
#     registration_upload(3),
#     credential_request(4),
#     credential_response(5),
#     (255)
# } ProtocolMessageType;
opaque_message_registration_request = 1
opaque_message_registration_response = 2
opaque_message_registration_upload = 3
opaque_message_credential_request = 4
opaque_message_credential_response = 5

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

def deserialize_message(config, msg_data):
    if len(msg_data) < 4:
        raise Exception("Insufficient bytes")
    msg_type = int.from_bytes(msg_data[0:1], "big")
    msg_length = int.from_bytes(msg_data[1:4], "big")
    if 4+msg_length < len(msg_data):
        raise Exception("Insufficient bytes")

    if msg_type == opaque_message_registration_request:
        return deserialize_registration_request(config, msg_data[4:4+msg_length]), 4+msg_length
    elif msg_type == opaque_message_registration_response:
        return deserialize_registration_response(config, msg_data[4:4+msg_length]), 4+msg_length
    elif msg_type == opaque_message_registration_upload:
        return deserialize_registration_upload(config, msg_data[4:4+msg_length]), 4+msg_length
    elif msg_type == opaque_message_credential_request:
        return deserialize_credential_request(config, msg_data[4:4+msg_length]), 4+msg_length
    elif msg_type == opaque_message_credential_response:
        return deserialize_credential_response(config, msg_data[4:4+msg_length]), 4+msg_length
    else:
        raise Exception("Invalid message type:", msg_type)

class ProtocolMessage(object):
    def __init__(self, msg_type):
        self.msg_type = msg_type

    def serialize_message(self):
        body = self.serialize()
        return int(self.msg_type).to_bytes(1, 'big') + len(body).to_bytes(3, 'big') + body

    def __eq__(self, other):
        if isinstance(other, ProtocolMessage):
            serialized = self.serialize_message()
            other_serialized = other.serialize_message()
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
        ProtocolMessage.__init__(self, opaque_message_registration_request)
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
        ProtocolMessage.__init__(self, opaque_message_registration_response)
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
        ProtocolMessage.__init__(self, opaque_message_registration_upload)
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
        ProtocolMessage.__init__(self, opaque_message_credential_request)
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
        ProtocolMessage.__init__(self, opaque_message_credential_response)
        self.data = data
        self.envU = envU

    def serialize(self):
        return encode_vector(self.data) + self.envU.serialize()

class RequestMetadata(object):
    def __init__(self, data_blind):
        self.data_blind = data_blind

    def serialize(self):
        return encode_vector(self.data_blind)

'''
===================  OPAQUE registration flow ====================

 Client (idU, pwdU, skU, pkU)                 Server (skS, pkS)
  -----------------------------------------------------------------
   request, metadata = CreateRegistrationRequest(idU, pwdU)

                                   request
                              ----------------->

            (response, kU) = CreateRegistrationResponse(request, pkS)

                                   response
                              <-----------------

 record = FinalizeRequest(idU, pwdU, skU, metadata, request, response)

                                    record
                              ------------------>

                                             StoreUserRecord(record)
'''

def create_registration_request(config, pwdU):
    oprf_context = SetupBaseClient(config.oprf_suite)

    r, M, _ = oprf_context.blind(pwdU)
    data = oprf_context.suite.group.serialize(M)
    blind = oprf_context.suite.group.serialize_scalar(r)

    request = RegistrationRequest(data)
    request_metadata = RequestMetadata(blind)

    return request, request_metadata

def create_registration_response(config, request, pkS, secret_list, cleartext_list):
    oprf_context = SetupBaseServer(config.oprf_suite)
    kU = oprf_context.skS

    M = oprf_context.suite.group.deserialize(request.data)
    Z_eval = oprf_context.evaluate(M)
    data = oprf_context.suite.group.serialize(Z_eval.evaluated_element)

    response = RegistrationResponse(data, pkS, secret_list, cleartext_list)

    return response, kU

def derive_secrets(config, pwdU, response, metadata, nonce, Npt):
    oprf_context = SetupBaseClient(config.oprf_suite)
    Z = oprf_context.suite.group.deserialize(response.data)
    r = oprf_context.suite.group.deserialize_scalar(metadata.data_blind)
    N = oprf_context.unblind(Evaluation(Z, None), r, None) # TODO(caw): https://github.com/cfrg/draft-irtf-cfrg-opaque/issues/68
    y = oprf_context.finalize(pwdU, N, _as_bytes("OPAQUE00"))
    y_harden = config.harden(y, params=None)
    rwdU = hkdf_extract(config, _as_bytes("rwdU"), y_harden)

    Nh = config.hash_alg().digest_size

    pseudorandom_pad = hkdf_expand(config, rwdU, nonce + _as_bytes("Pad"), Npt)
    auth_key = hkdf_expand(config, rwdU, nonce + _as_bytes("AuthKey"), Nh)
    export_key = hkdf_expand(config, rwdU, nonce + _as_bytes("ExportKey"), Nh)

    return pseudorandom_pad, auth_key, export_key

def finalize_request(config, idU, pwdU, skU, pkU, metadata, request, response, kU):
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
    pseudorandom_pad, auth_key, export_key = derive_secrets(config, pwdU, response, metadata, nonce, len(pt))
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
   request, metadata = CreateCredentialRequest(idU, pwdU)

                                   request
                              ----------------->

         (response, pkU) = CreateCredentialResponse(request, pkS)

                                   response
                              <-----------------

  creds, export_key = RecoverCredentials(pwdU, metadata, request, response)

                               (AKE with creds)
                              <================>
'''

def create_credential_request(config, pwdU):
    oprf_context = SetupBaseClient(config.oprf_suite)
    r, M, _ = oprf_context.blind(pwdU)
    data = oprf_context.suite.group.serialize(M)
    blind = oprf_context.suite.group.serialize_scalar(r)

    request = CredentialRequest(data)
    request_metadata = RequestMetadata(blind)

    return request, request_metadata

def create_credential_response(config, request, pkS, kU, record):
    envU, pkU = record.envU, record.pkU

    oprf_context = SetupBaseServer(config.oprf_suite)
    oprf_context.skS = kU

    M = oprf_context.suite.group.deserialize(request.data)
    Z_eval = oprf_context.evaluate(M) # kU * M
    data = oprf_context.suite.group.serialize(Z_eval.evaluated_element)

    response = CredentialResponse(data, envU)

    return response, pkU

def recover_credentials(config, pwdU, metadata, request, response):
    contents = response.envU.contents
    serialized_contents = contents.serialize()
    nonce = contents.nonce
    ct = contents.ct
    auth_data = contents.auth_data

    pseudorandom_pad, auth_key, export_key = derive_secrets(config, pwdU, response, metadata, nonce, len(ct))
    expected_tag = hmac.digest(auth_key, serialized_contents, config.hash_alg)

    if expected_tag != response.envU.auth_tag:
        raise Exception("Invalid tag")

    pt = xor(ct, pseudorandom_pad)
    secret_credentials, _ = deserialize_extensions(pt)
    cleartext_credentials, _ = deserialize_extensions(auth_data)
    creds = Credentials(secret_credentials, cleartext_credentials)

    return creds, export_key





####

class Configuration(object):
    def __init__(self, oprf_suite, hash_alg, harden):
        self.oprf_suite = oprf_suite
        self.hash_alg = hash_alg
        self.harden = harden



# # TODO(caw): update this to ristretto255
default_oprf_ciphersuite = Ciphersuite("OPRF-P256-HKDF-SHA512-SSWU-RO", ciphersuite_p256_hkdf_sha512_sswu_ro, GroupP256(), hashlib.sha512)
default_opaque_configuration = Configuration(default_oprf_ciphersuite, hashlib.sha512, harden)

'''
Docs: https://docs.google.com/document/d/1Gl97UFfydWFZyGVnDV1rcxqBVtyHbuIr400zEkAIQ88/edit#

Length of group element: LG
Length of keys: LK
Length of secret credential types: LSCT
Length of cleartext credentials types: LCCT
'''

class KeyExchange(object):
    def __init__(self):
        pass

    def generate_ke1(self, l1):
        raise Exception("Not implemented")

    def generate_ke2(self, l1, l2, ke1, pkU, skS, pkS):
        raise Exception("Not implemented")

    def generate_ke3(self, l2, ke2, ke1_state, pkS, skU, pkU):
        raise Exception("Not implemented")

class KeyExchangeMessage(object):
    def __init__(self, components):
        self.components = components

    def serialize(self):
        def concat(a, b):
            return a + b
        T = reduce(concat, map(lambda c : c, self.components))

TripleDHComponents = namedtuple("TripleDHComponents", "pk1 sk1 pk2 sk2 pk3 sk3")

class TripleDH(KeyExchange):
    def __init__(self, config):
        KeyExchange.__init__(self)
        self.config = config

    def derive_3dh_keys(self, dh_components, client_nonce, server_nonce, pkU, pkS):
        dh1 = ristretto255._edw_mul(dh_components.sk1, dh_components.pk1)
        dh2 = ristretto255._edw_mul(dh_components.sk2, dh_components.pk2)
        dh3 = ristretto255._edw_mul(dh_components.sk3, dh_components.pk3)

        dh1_encoded = ristretto255.ENCODE(*dh1)
        dh2_encoded = ristretto255.ENCODE(*dh2)
        dh3_encoded = ristretto255.ENCODE(*dh3)
        ikm = dh1_encoded + dh2_encoded + dh3_encoded

        # info = "3DH keys" || I2OSP(len(nonceU), 2) || nonceU
        #           || I2OSP(len(nonceS), 2) || nonceS
        #           || I2OSP(len(idU), 2) || idU
        #           || I2OSP(len(idS), 2) || idS
        empty_vector = encode_vector_len(bytes([]), 2)
        info = _as_bytes("3DH keys") + encode_vector_len(client_nonce, 2) + encode_vector_len(server_nonce, 2) \
            + empty_vector + empty_vector # idU and idS are empty

        output_size = self.config.hash_alg().digest_size
        prk = hkdf_extract(self.config, bytes([]), ikm)
        handshake_secret = derive_secret(self.config, prk, _as_bytes("handshake secret"), info)
        session_key = derive_secret(self.config, prk, _as_bytes("handshake secret"), info)

        # Km2 = HKDF-Expand-Label(handshake_secret, "client mac", "", Hash.length)
        # Km3 = HKDF-Expand-Label(handshake_secret, "server mac", "", Hash.length)
        # Ke2 = HKDF-Expand-Label(handshake_secret, "client enc", "", key_length)
        # Ke3 = HKDF-Expand-Label(handshake_secret, "server enc", "", key_length)
        # TODO(caw): need to parameterize these values accordingly
        # TODO(caw): move these constant labels to actual constants
        empty_info = bytes([])
        km2 = hkdf_expand_label(self.config, handshake_secret, _as_bytes("client mac"), empty_info, 32)
        km3 = hkdf_expand_label(self.config, handshake_secret, _as_bytes("server mac"), empty_info, 32)
        ke2 = hkdf_expand_label(self.config, handshake_secret, _as_bytes("server mac"), empty_info, 16)
        ke3 = hkdf_expand_label(self.config, handshake_secret, _as_bytes("server mac"), empty_info, 16)

        return km2, km3, ke2, ke3, session_key

    def generate_ke1(self, l1):
        client_nonce = random_bytes(32)
        (eskU, epkU) = ristretto255.keygen()
        ke1 = TripleDHMessageInit(client_nonce, ristretto255.ENCODE(*epkU))

        hasher = hashlib.sha256()
        hasher.update(l1)
        hasher.update(client_nonce)
        hasher.update(ristretto255.ENCODE(*epkU))

        return (client_nonce, eskU, epkU, hasher), KeyExchangeMessage([l1, ke1])

    def generate_ke2(self, l1, l2, ke1, pkU, skS, pkS):
        server_nonce = random_bytes(32)
        (eskS, epkS) = ristretto255.keygen()
        client_nonce = ke1.components[1].client_nonce
        epkU = ristretto255.DECODE(ke1.components[1].epkU)

        # K3dh = epkU^eskS || epkU^skS || pkU^eskS
        dh_components = TripleDHComponents(epkU, eskS, epkU, skS, pkU, eskS)
        km2, km3, _, _, session_key = self.derive_3dh_keys(dh_components, client_nonce, server_nonce, pkU, pkS)

        # transcript2 includes the concatenation of the values:
        # credential_request, nonceU, info1, idU, epkU, credential_response, nonceS, info2, epkS, Einfo2;¶
        hasher = hashlib.sha256()
        hasher.update(l1)
        hasher.update(client_nonce)
        hasher.update(ristretto255.ENCODE(*epkU))
        hasher.update(l2)
        hasher.update(server_nonce)
        hasher.update(ristretto255.ENCODE(*epkS))
        transcript_hash = hasher.digest()

        mac = hmac.digest(km2, transcript_hash, hashlib.sha256)
        ke2 = TripleDHMessageRespond(server_nonce, ristretto255.ENCODE(*epkS), mac)

        return (hasher, km3, session_key), KeyExchangeMessage([l2, ke2])

    def generate_ke3(self, l2, ke2, ke1_state, pkS, skU, pkU):
        server_nonce = ke2.components[1].server_nonce
        epkS = ristretto255.DECODE(ke2.components[1].epkS)
        (client_nonce, eskU, epkU, hasher) = ke1_state

        # K3dh = epkS^eskU || pkS^eskU || epkS^skU
        dh_components = TripleDHComponents(epkS, eskU, pkS, eskU, epkS, skU)
        km2, km3, _, _, session_key = self.derive_3dh_keys(dh_components, client_nonce, server_nonce, pkU, pkS)

        hasher.update(l2)
        hasher.update(server_nonce)
        hasher.update(ristretto255.ENCODE(*epkS))
        transcript_hash = hasher.digest()

        server_mac = hmac.digest(km2, transcript_hash, hashlib.sha256)
        assert server_mac == ke2.components[1].mac

        # transcript3 includes the concatenation of all elements in transcript2 followed by info3, Einfo3
        # TODO(caw): include info3 and Einfo3
        transcript_hash = hasher.digest()

        client_mac = hmac.digest(km3, transcript_hash, hashlib.sha256)
        ke3 = TripleDHMessageFinish(client_mac)

        return session_key, KeyExchangeMessage([ke3])

    def finish(self, ke3, ke2_state):
        (hasher, km3, session_key) = ke2_state

        # transcript3 includes the concatenation of all elements in transcript2 followed by info3, Einfo3
        # TODO(caw): include info3 and Einfo3
        transcript_hash = hasher.digest()

        client_mac = hmac.digest(km3, transcript_hash, hashlib.sha256)
        assert client_mac == ke3.components[0].mac

        return session_key

# struct {
#      opaque client_nonce[32];
#      opaque epkU[LK];
#  } KE1M;
def deserialize_tripleDH_init(data):
    pass

class TripleDHMessageInit(object):
    def __init__(self, client_nonce, epkU):
        self.client_nonce = client_nonce
        self.epkU = epkU

    def serialize(self):
        pass

# struct {
#      opaque server_nonce[32];
#      opaque epkS[LK];
#      opaque mac[LH];
#  } KE2M;
def deserialize_tripleDH_respond(data):
    pass

class TripleDHMessageRespond(object):
    def __init__(self, server_nonce, epkS, mac):
        self.server_nonce = server_nonce
        self.epkS = epkS
        self.mac = mac

    def serialize(self):
        pass

# struct {
#      opaque mac[LH];
#  } KE3M;
def deserialize_tripleDH_finish(data):
    pass

class TripleDHMessageFinish(object):
    def __init__(self, mac):
        self.mac = mac

    def serialize(self):
        pass