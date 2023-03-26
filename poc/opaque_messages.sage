#!/usr/bin/sage
# vim: syntax=python

import sys

try:
    from sagelib.opaque_common import encode_vector, OPAQUE_NONCE_LENGTH
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

# struct {
#   uint8 server_public_key[Npk];
#   uint8 server_identity<1..2^16-1>;
#   uint8 client_identity<1..2^16-1>;
# } CleartextCredentials;
class CleartextCredentials(object):
    def __init__(self, server_public_key, client_identity, server_identity):
        self.server_public_key = server_public_key
        self.client_identity = client_identity
        self.server_identity = server_identity

    def serialize(self):
        return self.server_public_key + encode_vector(self.server_identity) + encode_vector(self.client_identity)

class Credentials(object):
    def __init__(self, client_private_key, client_public_key, client_identity = None, server_identity = None):
        self.client_private_key = client_private_key
        self.client_public_key = client_public_key
        self.client_identity = client_identity
        self.server_identity = server_identity

# struct {
#   opaque nonce[Nn];
#   opaque auth_tag[Nm];
# } Envelope;
def deserialize_envelope(config, data):

    # TODO(caw): put Nm in the config
    Nm = config.hash().digest_size
    if len(data) != OPAQUE_NONCE_LENGTH + Nm:
         raise Exception("Invalid envelope length")

    nonce = data[:OPAQUE_NONCE_LENGTH]
    auth_tag = data[OPAQUE_NONCE_LENGTH:]

    return Envelope(nonce, auth_tag), OPAQUE_NONCE_LENGTH+Nm

class Envelope(object):
    def __init__(self, nonce, auth_tag):
        self.nonce = nonce
        self.auth_tag = auth_tag

    def serialize(self):
        return self.nonce + self.auth_tag

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
#     opaque blinded_message[Noe];
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
#     opaque evaluated_message[Noe];
#     opaque server_public_key[Npk];
# } RegistrationResponse;
def deserialize_registration_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]
    server_public_key = msg_bytes[length:]
    if len(server_public_key) != config.Npk:
        raise Exception("Invalid message: %d %d" % (len(server_public_key), config.Npk))

    return RegistrationResponse(data, server_public_key)

class RegistrationResponse(ProtocolMessage):
    def __init__(self, data, server_public_key):
        ProtocolMessage.__init__(self)
        self.data = data
        self.server_public_key = server_public_key

    def serialize(self):
        return self.data + self.server_public_key

# struct {
#     opaque client_public_key[Npk];
#     opaque masking_key[Nh];
#     Envelope envU;
# } RegistrationUpload;
def deserialize_registration_upload(config, msg_bytes):
    if len(msg_bytes) < config.Npk:
        raise Exception("Invalid message")
    client_public_key = msg_bytes[:config.Npk]

    Nh = config.hash().digest_size
    masking_key = msg_bytes[config.Npk:config.Npk+Nh]

    envU, _ = deserialize_envelope(config, msg_bytes[config.Npk+Nh:])

    return RegistrationUpload(client_public_key, masking_key, envU)

class RegistrationUpload(ProtocolMessage):
    def __init__(self, client_public_key, masking_key, envU):
        ProtocolMessage.__init__(self)
        self.client_public_key = client_public_key
        self.masking_key = masking_key
        self.envU = envU

    def serialize(self):
        return self.client_public_key + self.masking_key + self.envU.serialize()

# struct {
#     opaque blinded_message[Noe];
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
#     opaque evaluated_message[Noe];
#     opaque masking_nonce[32];
#     opaque masked_response[Npk + Ne];
# } CredentialResponse;
def deserialize_credential_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]
    masking_nonce = msg_bytes[length:length+OPAQUE_NONCE_LENGTH]

    Nm = config.hash().digest_size
    Npk = config.Npk
    Ne = Nm + OPAQUE_NONCE_LENGTH
    masked_response = msg_bytes[length+OPAQUE_NONCE_LENGTH:length+OPAQUE_NONCE_LENGTH+Npk+Ne]
    return CredentialResponse(data, masking_nonce, masked_response), length+OPAQUE_NONCE_LENGTH+Npk+Ne

class CredentialResponse(ProtocolMessage):
    def __init__(self, data, masking_nonce, masked_response):
        ProtocolMessage.__init__(self)
        self.data = data
        self.masking_nonce = masking_nonce
        self.masked_response = masked_response

    def serialize(self):
        return self.data + self.masking_nonce + self.masked_response
