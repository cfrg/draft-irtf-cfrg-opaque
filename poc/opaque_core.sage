#!/usr/bin/sage
# vim: syntax=python

import sys
import hmac
from hash import scrypt

try:
    from sagelib.oprf import SetupOPRFClient, SetupOPRFServer, DeriveKeyPair, MODE_OPRF
    from sagelib.opaque_messages import RegistrationRequest, RegistrationResponse, RegistrationUpload, CredentialRequest, CredentialResponse, CleartextCredentials, Envelope, deserialize_envelope
    from sagelib.opaque_common import xor, OS2IP, OS2IP_le, _as_bytes, OPAQUE_NONCE_LENGTH
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

OPAQUE_SEED_LENGTH = 32

class OPAQUECore(object):
    def __init__(self, config, rng):
        self.config = config
        self.rng = rng

    def derive_random_pwd(self, pwdU, response, blind):
        oprf_context = SetupOPRFClient(self.config.oprf_suite)
        oprf_output = oprf_context.finalize(pwdU, blind, self.config.oprf_suite.group.deserialize(response.data), None, None, None)
        stretched_oprf_output = self.config.ksf.stretch(oprf_output)
        return self.config.kdf.extract(_as_bytes(""), oprf_output + stretched_oprf_output)

    def derive_masking_key(self, random_pwd):
        Nh = self.config.hash().digest_size
        masking_key = self.config.kdf.expand(random_pwd, _as_bytes("MaskingKey"), Nh)
        return masking_key

    def create_registration_request(self, pwdU):
        oprf_context = SetupOPRFClient(self.config.oprf_suite)
        blind, blinded_element = oprf_context.blind(pwdU, self.rng)
        blinded_message = self.config.oprf_suite.group.serialize(blinded_element)
        request = RegistrationRequest(blinded_message)
        return request, blind

    def create_registration_response(self, request, pkS, oprf_seed, credential_identifier):
        ikm = self.config.kdf.expand(oprf_seed, credential_identifier + _as_bytes("OprfKey"), OPAQUE_SEED_LENGTH)
        (kU, _) = DeriveKeyPair(MODE_OPRF, self.config.oprf_suite, ikm, _as_bytes("OPAQUE-DeriveKeyPair"))
        oprf_context = SetupOPRFServer(self.config.oprf_suite, kU)

        blinded_element = self.config.oprf_suite.group.deserialize(request.data)
        evaluated_element, _, _ = oprf_context.evaluate(blinded_element, None, self.rng)
        evaluated_message = self.config.oprf_suite.group.serialize(evaluated_element)

        response = RegistrationResponse(evaluated_message, pkS)
        return response, kU

    def recover_public_key(self, private_key):
        sk = OS2IP(private_key)
        if "ristretto" in self.config.group.name or "decaf" in self.config.group.name:
            sk = OS2IP_le(private_key)
        pk = sk * self.config.group.generator()
        return self.config.group.serialize(pk)

    def derive_group_key_pair(self, seed):
        return DeriveKeyPair(MODE_OPRF, self.config.oprf_suite, seed, _as_bytes("OPAQUE-DeriveAuthKeyPair"))

    def create_cleartext_credentials(self, server_public_key, client_public_key, server_identity, client_identity):
        if server_identity == None:
            server_identity = server_public_key
        if client_identity == None:
            client_identity = client_public_key
        return CleartextCredentials(server_public_key, client_identity, server_identity)

    def create_envelope(self, random_pwd, server_public_key, idU, idS):
        envelope_nonce = self.rng.random_bytes(OPAQUE_NONCE_LENGTH)
        Nh = self.config.hash().digest_size
        auth_key = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("AuthKey"), Nh)
        export_key = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("ExportKey"), Nh)
        masking_key = self.derive_masking_key(random_pwd)

        seed = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("PrivateKey"), OPAQUE_SEED_LENGTH)
        (_, client_public_key) = self.derive_group_key_pair(seed)
        pk_bytes = self.config.group.serialize(client_public_key)
        client_public_key = self.config.group.serialize(client_public_key)

        cleartext_creds = self.create_cleartext_credentials(server_public_key, client_public_key, idS, idU)
        auth_tag = self.config.mac.mac(auth_key, envelope_nonce + cleartext_creds.serialize())
        envelope = Envelope(envelope_nonce, auth_tag)

        self.auth_key = auth_key
        self.envelope_nonce = envelope.nonce

        return envelope, client_public_key, masking_key, export_key

    def finalize_request(self, pwdU, blind, response, idU=None, idS=None):
        random_pwd = self.derive_random_pwd(pwdU, response, blind)
        envelope, client_public_key, masking_key, export_key = self.create_envelope(random_pwd, response.pkS, idU, idS)
        record = RegistrationUpload(client_public_key, masking_key, envelope)

        self.registration_rwdU = random_pwd
        self.masking_key = masking_key

        return record, export_key

    def create_credential_request(self, pwdU):
        oprf_context = SetupOPRFClient(self.config.oprf_suite)
        blind, blinded_element = oprf_context.blind(pwdU, self.rng)
        request = CredentialRequest(self.config.oprf_suite.group.serialize(blinded_element))
        return request, blind

    def create_credential_response(self, request, pkS, oprf_seed, envU, credential_identifier, masking_key):
        ikm = self.config.kdf.expand(oprf_seed, credential_identifier + _as_bytes("OprfKey"), OPAQUE_SEED_LENGTH)
        (kU, _) = DeriveKeyPair(MODE_OPRF, self.config.oprf_suite, ikm, _as_bytes("OPAQUE-DeriveKeyPair"))

        oprf_context = SetupOPRFServer(self.config.oprf_suite, kU)
        Z, _, _ = oprf_context.evaluate(self.config.oprf_suite.group.deserialize(request.data), None, self.rng)

        masking_nonce = self.rng.random_bytes(OPAQUE_NONCE_LENGTH)
        Npk = self.config.Npk
        Ne = self.config.Nm + OPAQUE_NONCE_LENGTH
        credential_response_pad = self.config.kdf.expand(masking_key, masking_nonce + _as_bytes("CredentialResponsePad"), Npk + Ne)
        masked_response = xor(credential_response_pad, pkS + envU.serialize())

        self.masking_nonce = masking_nonce

        response = CredentialResponse(self.config.oprf_suite.group.serialize(Z), masking_nonce, masked_response)
        return response

    def recover_keys(self, random_pwd, envelope_nonce):
        seed = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("PrivateKey"), OPAQUE_SEED_LENGTH)
        (client_private_key, client_public_key) = self.derive_group_key_pair(seed)
        sk_bytes = self.config.group.serialize_scalar(client_private_key)
        pk_bytes = self.config.group.serialize(client_public_key)
        return sk_bytes, pk_bytes

    def recover_envelope(self, random_pwd, server_public_key, client_identity, server_identity, envelope):
        Nh = self.config.hash().digest_size
        auth_key = self.config.kdf.expand(random_pwd, envelope.nonce + _as_bytes("AuthKey"), Nh)
        export_key = self.config.kdf.expand(random_pwd, envelope.nonce + _as_bytes("ExportKey"), Nh)

        self.credential_auth_key = auth_key
        self.credential_export_key = export_key
        
        client_private_key, client_public_key = self.recover_keys(random_pwd, envelope.nonce)
        cleartext_creds = self.create_cleartext_credentials(server_public_key, client_public_key, server_identity, client_identity)
        expected_tag = self.config.mac.mac(auth_key, envelope.nonce + cleartext_creds.serialize())
        if expected_tag != envelope.auth_tag:
            raise Exception("Invalid tag")

        return client_private_key, export_key

    def recover_credentials(self, pwdU, blind, response, idU = None, idS = None):
        random_pwd = self.derive_random_pwd(pwdU, response, blind)
        masking_key = self.derive_masking_key(random_pwd)
        Npk = self.config.Npk
        Ne = self.config.Nm + OPAQUE_NONCE_LENGTH
        credential_response_pad = self.config.kdf.expand(masking_key, response.masking_nonce + _as_bytes("CredentialResponsePad"), Npk + Ne)

        data = xor(credential_response_pad, response.masked_response)
        server_public_key = data[0:Npk]
        envelope, _ = deserialize_envelope(self.config, data[Npk:])

        self.credential_rwd = random_pwd
        self.credential_decryption_pad = credential_response_pad
        self.credential_masking_key = masking_key

        skU, export_key = self.recover_envelope(random_pwd, server_public_key, idU, idS, envelope)

        return skU, server_public_key, export_key

class KeyStretchingFunction(object):
    def __init__(self, name, stretch):
        self.name = name
        self.stretch = stretch

def scrypt_stretch(pwd):
    return scrypt(pwd, b'', 32768, 8, 1, 64)

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

def scrypt_stretch(pwd):
    return scrypt(pwd, b'', 32768, 8, 1, 64)

def identity_stretch(pwd):
    return pwd
