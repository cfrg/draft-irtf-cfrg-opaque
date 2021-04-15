#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import hmac
import hashlib
import struct
from hash import scrypt

try:
    from sagelib.oprf import SetupBaseServer, SetupBaseClient, Evaluation, DeriveKeyPair
    from sagelib.opaque_messages import RegistrationRequest, RegistrationResponse, RegistrationUpload, CredentialRequest, CredentialResponse, Credentials, SecretCredentials, CleartextCredentials, Envelope, InnerEnvelope, envelope_mode_internal, envelope_mode_external, deserialize_secret_credentials, deserialize_envelope
    from sagelib.opaque_common import derive_secret, hkdf_expand_label, hkdf_expand, hkdf_extract, random_bytes, xor, I2OSP, OS2IP, OS2IP_le, encode_vector, encode_vector_len, decode_vector, decode_vector_len, _as_bytes
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

OPAQUE_NONCE_LENGTH = 32

class OPAQUECore(object):
    def __init__(self, config):
        self.config = config

    def derive_random_pwd(self, pwdU, response, blind):
        oprf_context = SetupBaseClient(self.config.oprf_suite)
        y = oprf_context.finalize(pwdU, blind, response.data, None, None)
        y_harden = self.config.mhf.harden(y)
        return self.config.kdf.extract(_as_bytes(""), y_harden)

    def derive_masking_key(self, random_pwd):
        Nh = self.config.hash().digest_size
        masking_key = self.config.kdf.expand(random_pwd, _as_bytes("MaskingKey"), Nh)
        return masking_key

    def derive_keys(self, random_pwd, nonce, Npt):
        Nh = self.config.hash().digest_size
        pseudorandom_pad = self.config.kdf.expand(random_pwd, nonce + _as_bytes("Pad"), Npt)
        auth_key = self.config.kdf.expand(random_pwd, nonce + _as_bytes("AuthKey"), Nh)
        export_key = self.config.kdf.expand(random_pwd, nonce + _as_bytes("ExportKey"), Nh)
        return pseudorandom_pad, auth_key, export_key

    def derive_secrets(self, pwdU, response, blind, nonce, Npt):
        random_pwd = self.derive_random_pwd(pwdU, response, blind)
        masking_key = self.derive_masking_key(random_pwd)
        pseudorandom_pad, auth_key, export_key = self.derive_keys(random_pwd, nonce, Npt)

        return random_pwd, pseudorandom_pad, auth_key, export_key, masking_key

    def create_registration_request(self, pwdU):
        oprf_context = SetupBaseClient(self.config.oprf_suite)
        blind, blinded_element = oprf_context.blind(pwdU)
        request = RegistrationRequest(blinded_element)
        return request, blind

    def create_registration_response(self, request, pkS, oprf_seed, credential_identifier):
        Nok = self.config.oprf_suite.group.scalar_byte_length()
        ikm = self.config.kdf.expand(oprf_seed, credential_identifier + _as_bytes("OprfKey"), Nok)
        (kU, _) = DeriveKeyPair(self.config.oprf_suite, ikm)

        oprf_context = SetupBaseServer(self.config.oprf_suite, kU)
        data, _, _ = oprf_context.evaluate(request.data)
        response = RegistrationResponse(data, pkS)
        return response, kU

    def recover_public_key(self, private_key):
        sk = OS2IP(private_key)
        if "ristretto" in self.config.group.name or "decaf" in self.config.group.name:
            sk = OS2IP_le(private_key)
        pk = sk * self.config.group.generator()
        return self.config.group.serialize(pk)

    def derive_group_key_pair(self, seed):
        skS = self.config.group.hash_to_scalar(seed, dst=_as_bytes("OPAQUE-HashToScalar"))
        pkS = skS * self.config.group.generator()
        return (skS, pkS)

    def build_inner_envelope(self, random_pwd, envelope_nonce, client_private_key):
        if self.config.mode == envelope_mode_internal:
            Nsk = self.config.Nsk
            seed = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("PrivateKey"), Nsk)
            (_, client_public_key) = self.derive_group_key_pair(seed)
            pk_bytes = self.config.group.serialize(client_public_key)
            return (InnerEnvelope(), self.config.group.serialize(client_public_key))
        if self.config.mode == envelope_mode_external:
            pseudorandom_pad = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("Pad"), len(client_private_key))
            encrypted_creds = xor(client_private_key, pseudorandom_pad)
            client_public_key = self.recover_public_key(client_private_key)
            return (InnerEnvelope(encrypted_creds), client_public_key)
        raise Exception("Unsupported mode")

    def create_cleartext_credentials(self, server_public_key, client_public_key, server_identity, client_identity):
        if server_identity == None:
            server_identity = server_public_key
        if client_identity == None:
            client_identity = client_public_key
        return CleartextCredentials(server_public_key, client_identity, server_identity)

    def create_envelope(self, creds, random_pwd, server_public_key):
        envelope_nonce = random_bytes(OPAQUE_NONCE_LENGTH)
        Nh = self.config.hash().digest_size
        auth_key = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("AuthKey"), Nh)
        export_key = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("ExportKey"), Nh)
        masking_key = self.derive_masking_key(random_pwd)

        inner_env, client_public_key = self.build_inner_envelope(random_pwd, envelope_nonce, creds.skU)
        cleartext_creds = self.create_cleartext_credentials(server_public_key, client_public_key, creds.idS, creds.idU)
        auth_tag = self.config.mac.mac(auth_key, I2OSP(self.config.mode, 1) + envelope_nonce + inner_env.serialize() + cleartext_creds.serialize())
        envelope = Envelope(self.config.mode, envelope_nonce, auth_tag, inner_env)

        self.auth_key = auth_key
        self.envelope_nonce = envelope.nonce

        return envelope, client_public_key, masking_key, export_key

    def finalize_request(self, creds, pwdU, blind, response):
        random_pwd = self.derive_random_pwd(pwdU, response, blind)
        envelope, client_public_key, masking_key, export_key = self.create_envelope(creds, random_pwd, response.pkS)
        record = RegistrationUpload(client_public_key, masking_key, envelope)

        self.registration_rwdU = random_pwd
        self.masking_key = masking_key

        return record, export_key

    def create_credential_request(self, pwdU):
        oprf_context = SetupBaseClient(self.config.oprf_suite)
        blind, blinded_element = oprf_context.blind(pwdU)
        request = CredentialRequest(blinded_element)
        return request, blind

    def create_credential_response(self, request, pkS, oprf_seed, envU, credential_identifier, masking_key):
        Nok = self.config.oprf_suite.group.scalar_byte_length()
        ikm = self.config.kdf.expand(oprf_seed, credential_identifier + _as_bytes("OprfKey"), Nok)
        (kU, _) = DeriveKeyPair(self.config.oprf_suite, ikm)

        oprf_context = SetupBaseServer(self.config.oprf_suite, kU)
        Z, _, _ = oprf_context.evaluate(request.data)

        masking_nonce = random_bytes(OPAQUE_NONCE_LENGTH)
        Nh = self.config.hash().digest_size
        Npk = self.config.Npk
        Ne = Nh + 33
        if self.config.mode == envelope_mode_external:
            Ne = Ne + self.config.Nsk
        credential_response_pad = self.config.kdf.expand(masking_key, masking_nonce + _as_bytes("CredentialResponsePad"), Npk + Ne)
        masked_response = xor(credential_response_pad, pkS + envU.serialize())

        self.masking_nonce = masking_nonce

        response = CredentialResponse(Z, masking_nonce, masked_response)
        return response

    def recover_keys(self, random_pwd, envelope_nonce, inner_env):
        if self.config.mode == envelope_mode_internal:
            Nsk = self.config.Nsk
            seed = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("PrivateKey"), Nsk)
            (client_private_key, client_public_key) = self.derive_group_key_pair(seed)
            secret_creds = SecretCredentials(self.config.group.serialize_scalar(client_private_key))
            pk_bytes = self.config.group.serialize(client_public_key)
            return secret_creds, self.config.group.serialize(client_public_key)
        elif self.config.mode == envelope_mode_external:
            encrypted_creds = inner_env.encrypted_creds
            pseudorandom_pad = self.config.kdf.expand(random_pwd, envelope_nonce + _as_bytes("Pad"), len(encrypted_creds))
            serialized_creds = xor(encrypted_creds, pseudorandom_pad)
            client_public_key = self.recover_public_key(serialized_creds)
            secret_creds = SecretCredentials(serialized_creds)
            return secret_creds, client_public_key
        raise Exception("Unsupported mode")

    def recover_envelope(self, random_pwd, server_public_key, client_identity, server_identity, envelope):
        Nh = self.config.hash().digest_size
        auth_key = self.config.kdf.expand(random_pwd, envelope.nonce + _as_bytes("AuthKey"), Nh)
        export_key = self.config.kdf.expand(random_pwd, envelope.nonce + _as_bytes("ExportKey"), Nh)
        
        secret_creds, client_public_key = self.recover_keys(random_pwd, envelope.nonce, envelope.inner_env)
        cleartext_creds = self.create_cleartext_credentials(server_public_key, client_public_key, server_identity, client_identity)
        expected_tag = self.config.mac.mac(auth_key, I2OSP(self.config.mode, 1) + envelope.nonce + envelope.inner_env.serialize() + cleartext_creds.serialize())
        if expected_tag != envelope.auth_tag:
            raise Exception("Invalid tag")

        self.credential_auth_key = auth_key
        self.credential_export_key = export_key

        return secret_creds, export_key

    def recover_credentials(self, pwdU, blind, response, idU = None, idS = None):
        random_pwd = self.derive_random_pwd(pwdU, response, blind)
        masking_key = self.derive_masking_key(random_pwd)
        Nh = self.config.hash().digest_size
        Npk = self.config.Npk
        Ne = Nh + 33
        if self.config.mode == envelope_mode_external:
            Ne = Ne + self.config.Nsk
        credential_response_pad = self.config.kdf.expand(masking_key, response.masking_nonce + _as_bytes("CredentialResponsePad"), Npk + Ne)

        data = xor(credential_response_pad, response.masked_response)
        server_public_key = data[0:Npk]
        envelope, _ = deserialize_envelope(self.config, data[Npk:])

        secret_creds, export_key = self.recover_envelope(random_pwd, server_public_key, idU, idS, envelope)

        self.credential_prk = random_pwd
        self.credential_decryption_pad = credential_response_pad
        self.credential_masking_key = masking_key

        return secret_creds.skU, server_public_key, export_key

class MHF(object):
    def __init__(self, name, harden):
        self.name = name
        self.harden = harden

def scrypt_harden(pwd):
    return scrypt(pwd, b'', 32768, 8, 1, 64)

def identity_harden(pwd):
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

def scrypt_harden(pwd):
    return scrypt(pwd, b'', 32768, 8, 1, 64)

def identity_harden(pwd):
    return pwd
