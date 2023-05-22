#!/usr/bin/sage
# vim: syntax=python

import sys
import hmac
from hash import scrypt

try:
    from sagelib.oprf import SetupOPRFClient, SetupOPRFServer, DeriveKeyPair, MODE_OPRF
    from sagelib.opaque_messages import RegistrationRequest, RegistrationResponse, RegistrationUpload, CredentialRequest, CredentialResponse, CleartextCredentials, Envelope, deserialize_envelope
    from sagelib.opaque_common import curve25519_clamp, xor, OS2IP, OS2IP_le, _as_bytes, OPAQUE_NONCE_LENGTH
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

OPAQUE_SEED_LENGTH = 32

class OPAQUECore(object):
    def __init__(self, config, rng):
        self.config = config
        self.rng = rng

    def derive_randomized_password(self, password, response, blind):
        oprf_context = SetupOPRFClient(self.config.oprf_suite.identifier)
        oprf_output = oprf_context.finalize(password, blind, self.config.oprf_suite.group.deserialize(response.data), None, None, None)
        stretched_oprf_output = self.config.ksf.stretch(oprf_output)
        return self.config.kdf.extract(_as_bytes(""), oprf_output + stretched_oprf_output)

    def derive_masking_key(self, randomized_password):
        Nh = self.config.hash().digest_size
        masking_key = self.config.kdf.expand(randomized_password, _as_bytes("MaskingKey"), Nh)
        return masking_key

    def create_registration_request(self, password):
        oprf_context = SetupOPRFClient(self.config.oprf_suite.identifier)
        blind, blinded_element = oprf_context.blind(password, self.rng)
        blinded_message = self.config.oprf_suite.group.serialize(blinded_element)
        request = RegistrationRequest(blinded_message)
        return request, blind

    def create_registration_response(self, request, server_public_key, oprf_seed, credential_identifier):
        ikm = self.config.kdf.expand(oprf_seed, credential_identifier + _as_bytes("OprfKey"), OPAQUE_SEED_LENGTH)
        (kU, _) = DeriveKeyPair(MODE_OPRF, self.config.oprf_suite.identifier, ikm, _as_bytes("OPAQUE-DeriveKeyPair"))
        oprf_context = SetupOPRFServer(self.config.oprf_suite.identifier, kU)

        blinded_element = self.config.oprf_suite.group.deserialize(request.data)
        evaluated_element, _, _ = oprf_context.blind_evaluate(blinded_element, None, self.rng)
        evaluated_message = self.config.oprf_suite.group.serialize(evaluated_element)

        response = RegistrationResponse(evaluated_message, server_public_key)
        return response, kU

    def recover_public_key(self, private_key):
        sk = OS2IP(private_key)
        if "ristretto" in self.config.group.name or "decaf" in self.config.group.name:
            sk = OS2IP_le(private_key)
        pk = self.config.group.scalar_mult(sk, self.config.group.generator())
        return self.config.group.serialize(pk)

    def derive_dh_group_key_pair(self, seed):
        sk, pk = DeriveKeyPair(MODE_OPRF, self.config.oprf_suite.identifier, seed, _as_bytes("OPAQUE-DeriveDiffieHellmanKeyPair"))
        return sk, self.config.group.serialize(pk)

    def derive_diffie_hellman_key_pair(self, seed):
        if self.config.group.name == "curve25519":
            clamped_seed = curve25519_clamp(seed)
            return clamped_seed, self.config.group.serialize(self.config.group.scalar_mult(clamped_seed, self.config.group.generator()))
        else:
            return self.derive_dh_group_key_pair(seed)

    def create_cleartext_credentials(self, server_public_key_bytes, client_public_key_bytes, server_identity, client_identity):
        if server_identity == None:
            server_identity = server_public_key_bytes
        if client_identity == None:
            client_identity = client_public_key_bytes
        return CleartextCredentials(server_public_key_bytes, client_identity, server_identity)

    def create_envelope(self, randomized_password, encoded_server_public_key, client_identity, server_identity):
        envelope_nonce = self.rng.random_bytes(OPAQUE_NONCE_LENGTH)
        Nh = self.config.hash().digest_size
        auth_key = self.config.kdf.expand(randomized_password, envelope_nonce + _as_bytes("AuthKey"), Nh)
        export_key = self.config.kdf.expand(randomized_password, envelope_nonce + _as_bytes("ExportKey"), Nh)
        masking_key = self.derive_masking_key(randomized_password)

        seed = self.config.kdf.expand(randomized_password, envelope_nonce + _as_bytes("PrivateKey"), OPAQUE_SEED_LENGTH)
        (_, client_public_key_bytes) = self.derive_diffie_hellman_key_pair(seed)

        cleartext_credentials = self.create_cleartext_credentials(encoded_server_public_key, client_public_key_bytes, server_identity, client_identity)
        auth_tag = self.config.mac.mac(auth_key, envelope_nonce + cleartext_credentials.serialize())
        envelope = Envelope(envelope_nonce, auth_tag)

        self.auth_key = auth_key
        self.envelope_nonce = envelope.nonce

        return envelope, client_public_key_bytes, masking_key, export_key

    def finalize_request(self, password, blind, response, client_identity=None, server_identity=None):
        randomized_password = self.derive_randomized_password(password, response, blind)
        envelope, client_public_key, masking_key, export_key = self.create_envelope(randomized_password, response.server_public_key, client_identity, server_identity)
        record = RegistrationUpload(client_public_key, masking_key, envelope)

        self.registration_rwdU = randomized_password
        self.masking_key = masking_key

        return record, export_key

    def create_credential_request(self, password):
        oprf_context = SetupOPRFClient(self.config.oprf_suite.identifier)
        blind, blinded_element = oprf_context.blind(password, self.rng)
        request = CredentialRequest(self.config.oprf_suite.group.serialize(blinded_element))
        return request, blind

    def create_credential_response(self, request, server_public_key, oprf_seed, envU, credential_identifier, masking_key):
        ikm = self.config.kdf.expand(oprf_seed, credential_identifier + _as_bytes("OprfKey"), OPAQUE_SEED_LENGTH)
        (kU, _) = DeriveKeyPair(MODE_OPRF, self.config.oprf_suite.identifier, ikm, _as_bytes("OPAQUE-DeriveKeyPair"))

        oprf_context = SetupOPRFServer(self.config.oprf_suite.identifier, kU)
        Z, _, _ = oprf_context.blind_evaluate(self.config.oprf_suite.group.deserialize(request.data), None, self.rng)

        masking_nonce = self.rng.random_bytes(OPAQUE_NONCE_LENGTH)
        Npk = self.config.Npk
        Ne = self.config.Nm + OPAQUE_NONCE_LENGTH
        credential_response_pad = self.config.kdf.expand(masking_key, masking_nonce + _as_bytes("CredentialResponsePad"), Npk + Ne)
        masked_response = xor(credential_response_pad, server_public_key + envU.serialize())

        self.masking_nonce = masking_nonce

        response = CredentialResponse(self.config.oprf_suite.group.serialize(Z), masking_nonce, masked_response)
        return response

    def recover_keys(self, randomized_password, envelope_nonce):
        seed = self.config.kdf.expand(randomized_password, envelope_nonce + _as_bytes("PrivateKey"), OPAQUE_SEED_LENGTH)
        (client_private_key, client_public_key_bytes) = self.derive_diffie_hellman_key_pair(seed)
        sk_bytes = self.config.group.serialize_scalar(client_private_key)
        return sk_bytes, client_public_key_bytes

    def recover_envelope(self, randomized_password, server_public_key, client_identity, server_identity, envelope):
        Nh = self.config.hash().digest_size
        auth_key = self.config.kdf.expand(randomized_password, envelope.nonce + _as_bytes("AuthKey"), Nh)
        export_key = self.config.kdf.expand(randomized_password, envelope.nonce + _as_bytes("ExportKey"), Nh)

        self.credential_auth_key = auth_key
        self.credential_export_key = export_key
        
        client_private_key, client_public_key = self.recover_keys(randomized_password, envelope.nonce)
        cleartext_credentials = self.create_cleartext_credentials(server_public_key, client_public_key, server_identity, client_identity)
        expected_tag = self.config.mac.mac(auth_key, envelope.nonce + cleartext_credentials.serialize())
        if expected_tag != envelope.auth_tag:
            raise Exception("Invalid tag")

        return client_private_key, cleartext_credentials, export_key

    def recover_credentials(self, password, blind, response, client_identity = None, server_identity = None):
        randomized_password = self.derive_randomized_password(password, response, blind)
        masking_key = self.derive_masking_key(randomized_password)
        Npk = self.config.Npk
        Ne = self.config.Nm + OPAQUE_NONCE_LENGTH
        credential_response_pad = self.config.kdf.expand(masking_key, response.masking_nonce + _as_bytes("CredentialResponsePad"), Npk + Ne)

        data = xor(credential_response_pad, response.masked_response)
        server_public_key = data[0:Npk]
        envelope, _ = deserialize_envelope(self.config, data[Npk:])

        self.credential_randomized_password = randomized_password
        self.credential_decryption_pad = credential_response_pad
        self.credential_masking_key = masking_key

        client_private_key, cleartext_credentials, export_key = self.recover_envelope(randomized_password, server_public_key, client_identity, server_identity, envelope)

        return client_private_key, cleartext_credentials, export_key

class KeyStretchingFunction(object):
    def __init__(self, name, stretch):
        self.name = name
        self.stretch = stretch

def identity_stretch(pwd):
    return pwd

class KDF(object):
    def __init__(self, name):
        self.name = name
    
    def extract(self, salt, ikm):
        raise Exception("Not implemented")

    def expand(self, prk, info, L):
        raise Exception("Not implemented")

class HKDF(KDF):
    def __init__(self, fast_hash):
        KDF.__init__(self, "HKDF-" + fast_hash().name.upper())
        self.hash = fast_hash

    def extract(self, salt, ikm):
        return hmac.digest(salt, ikm, self.hash)

    def expand(self, prk, info, L):
        # https://tools.ietf.org/html/rfc5869
        # N = ceil(L/HashLen)
        # T = T(1) | T(2) | T(3) | ... | T(N)
        # OKM = first L octets of T
        hash_length = self.hash().digest_size
        N = ceil(L / hash_length)
        Ts = [bytes(bytearray([]))]
        for i in range(N):
            Ts.append(hmac.digest(
                prk, Ts[i] + info + int(i+1).to_bytes(1, 'big'), self.hash))

        def concat(a, b):
            return a + b
        T = reduce(concat, map(lambda c: c, Ts))
        return T[0:L]

class MAC(object):
    def __init__(self, name):
        self.name = name
    
    def mac(self, key, input):
        raise Exception("Not implemented")

class HMAC(MAC):
    def __init__(self, fast_hash):
        MAC.__init__(self, "HMAC-" + fast_hash().name.upper())
        self.hash = fast_hash

    def output_size(self):
        return self.hash().digest_size

    def mac(self, key, input):
        return hmac.digest(key, input, self.hash)

