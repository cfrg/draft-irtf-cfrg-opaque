#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json

import hmac
import hashlib

try:
    from sagelib.oprf import Evaluation
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x
    _strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )

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

def hkdf_extract(salt, ikm):
    return hmac.digest(salt, ikm, hashlib.sha256)

def hkdf_expand(prk, info, L):
    # https://tools.ietf.org/html/rfc5869
    # N = ceil(L/HashLen)
    # T = T(1) | T(2) | T(3) | ... | T(N)
    # OKM = first L octets of T
    hash_length = 32
    N = ceil(L / hash_length)
    Ts = [bytes(bytearray([]))]
    for i in range(N):
        Ts.append(hmac.digest(prk, Ts[i] + info + int(i+1).to_bytes(1, 'big'), hashlib.sha256))

    def concat(a, b):
        return a + b
    T = reduce(concat, map(lambda c : c, Ts))
    return T[0:L]

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

def encode_vector(data):
    return len(data).to_bytes(2, 'big') + data

def decode_vector(data_bytes):
    if len(data_bytes) < 2:
        raise Exception("Insufficient length")
    data_len = int.from_bytes(data_bytes[0:2], 'big')
    if len(data_bytes) < 2+data_len:
        raise Exception("Insufficient length")
    return data_bytes[2:2+data_len], 2+data_len

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
def deserialize_envelope(data):
    contents, offset = deserialize_inner_envelope(data)
    if offset+32 > len(data):
        raise Exception("Insufficient bytes")
    auth_tag = data[offset:offset+32]
    return Envelope(contents, auth_tag), offset+32

class Envelope(object):
    def __init__(self, contents, auth_tag):
        assert(len(auth_tag) == 32)
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

def deserialize_message(msg_data):
    if len(data) < 4:
        raise Exception("Insufficient bytes")
    msg_type = int.from_bytes(data[0:1], "big")
    msg_length = int.from_bytes(data[1:4], "big")
    if 4+msg_length < len(data):
        raise Exception("Insufficient bytes")

    if msg_type == opaque_message_registration_request:
        return deserialize_registration_request(data[4:4+msg_length]), 4+msg_length

def deserialize_registration_request(msg_bytes):
    username, offset = decode_vector(msg_bytes)
    data, offset = decode_vector(msg_bytes[offset:])
    return RegistrationRequest(username, data)

def serialize_message(msg):
    body = self.serialize_body()
    return msg.msg_type.to_bytes(1, 'big') + len(body).to_bytes(3, 'big') + body

class ProtocolMessage(object):
    def __init__(self, msg_type):
        self.msg_type = msg_type

# TODO(caw): make clear what are the types of each thing
class RegistrationRequest(ProtocolMessage):
    def __init__(self, idU, data):
        ProtocolMessage.__init__(self, opaque_message_registration_request)
        self.idU = idU
        self.data = data

    def serialize(self):
        return encode_vector(self.idU) + encode_vector(self.data)

class CredentialRequest(ProtocolMessage):
    def __init__(self, idU, data):
        ProtocolMessage.__init__(self, opaque_message_credential_request)
        self.idU = idU
        self.data = data

    def serialize(self):
        return encode_vector(self.idU) + encode_vector(self.data)

class RegistrationResponse(ProtocolMessage):
    def __init__(self, data, pkS, secret_list, cleartext_list):
        ProtocolMessage.__init__(self, opaque_message_registration_request)
        self.data = data
        self.pkS = pkS
        self.secret_list = secret_list
        self.cleartext_list = cleartext_list

    def serialize(self):
        raise Exception("Not implemented")

class CredentialResponse(ProtocolMessage):
    def __init__(self, data, envU, pkS):
        ProtocolMessage.__init__(self, opaque_message_credential_request)
        self.data = data
        self.envU = envU
        self.pkS = pkS

    def serialize(self):
        raise Exception("Not implemented")

class RegistrationUpload(ProtocolMessage):
    def __init__(self, envU, pkU):
        ProtocolMessage.__init__(self, opaque_message_registration_upload)
        self.envU = envU
        self.pkU = pkU

    def serialize(self):
        raise Exception("Not implemented")

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

def create_registration_request(oprf_context, idU, pwdU):
    r, M, _ = oprf_context.blind(pwdU)
    data = oprf_context.suite.group.serialize(M)
    blind = oprf_context.suite.group.serialize_scalar(r)

    request = RegistrationRequest(idU, data)
    request_metadata = RequestMetadata(blind)

    # TODO(caw): should we expose metadata as a struct as output here?
    # (probably not, since it's an implementation detail)
    return request, request_metadata

def create_registration_response(oprf_context, request, pkS, secret_list, cleartext_list):
    kU = oprf_context.skS

    M = oprf_context.suite.group.deserialize(request.data)
    Z_eval = oprf_context.evaluate(M)
    data = oprf_context.suite.group.serialize(Z_eval.evaluated_element)

    response = RegistrationResponse(data, pkS, secret_list, cleartext_list)

    return response, kU

def derive_secrets(oprf_context, pwdU, response, metadata, nonce, Npt, Nh):
    Z = oprf_context.suite.group.deserialize(response.data)
    r = oprf_context.suite.group.deserialize_scalar(metadata.data_blind)
    N = oprf_context.unblind(Evaluation(Z, None), r, None) # TODO(caw): https://github.com/cfrg/draft-irtf-cfrg-opaque/issues/68
    y = oprf_context.finalize(pwdU, N, _as_bytes("OPAQUE00"))
    y_harden = harden(y, params=None) # TODO(caw): figure out how to specify and pass in Harden params
    rwdU = hkdf_extract(_as_bytes("rwdU"), y_harden)

    pseudorandom_pad = hkdf_expand(rwdU, nonce + _as_bytes("Pad"), Npt)
    auth_key = hkdf_expand(rwdU, nonce + _as_bytes("AuthKey"), Nh)
    export_key = hkdf_expand(rwdU, nonce + _as_bytes("ExportKey"), Nh)

    return pseudorandom_pad, auth_key, export_key

def finalize_request(oprf_context, idU, pwdU, skU, pkU, metadata, request, response, kU):
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
    pseudorandom_pad, auth_key, export_key = derive_secrets(oprf_context, pwdU, response, metadata, nonce, len(pt), 32)
    ct = xor(pt, pseudorandom_pad)

    contents = InnerEnvelope(nonce, ct, auth_data)
    serialized_contents = contents.serialize()
    auth_tag = hmac.digest(auth_key, serialized_contents, hashlib.sha256)

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

def create_credential_request(oprf_context, idU, pwdU, kU):
    r, M, _ = oprf_context.blind(pwdU)
    data = oprf_context.suite.group.serialize(M)
    blind = oprf_context.suite.group.serialize_scalar(r)

    request = CredentialRequest(idU, data)
    request_metadata = RequestMetadata(blind)

    return request, request_metadata

def create_credential_response(oprf_context, request, pkS, lookupFunction):
    kU, envU, pkU = lookupFunction(request.idU)
    oprf_context.skS = kU

    M = oprf_context.suite.group.deserialize(request.data)
    Z_eval = oprf_context.evaluate(M) # kU * M
    data = oprf_context.suite.group.serialize(Z_eval.evaluated_element)

    response = CredentialResponse(data, envU, pkS)

    return response, pkU

def recover_credentials(oprf_context, pwdU, metadata, request, response):
    contents = response.envU.contents
    serialized_contents = contents.serialize()
    nonce = contents.nonce
    ct = contents.ct
    auth_data = contents.auth_data

    pseudorandom_pad, auth_key, export_key = derive_secrets(oprf_context, pwdU, response, metadata, nonce, len(ct), 32)
    expected_tag = hmac.digest(auth_key, serialized_contents, hashlib.sha256)

    if expected_tag != response.envU.auth_tag:
        raise Exception("Invalid tag")

    pt = xor(ct, pseudorandom_pad)
    secret_credentials, _ = deserialize_extensions(pt)
    cleartext_credentials, _ = deserialize_extensions(auth_data)
    creds = Credentials(secret_credentials, cleartext_credentials)

    return creds, export_key
