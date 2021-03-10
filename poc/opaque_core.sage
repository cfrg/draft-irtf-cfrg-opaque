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
    from sagelib.oprf import SetupBaseServer, SetupBaseClient, Evaluation, GenerateKeyPair
    from sagelib.opaque_messages import RegistrationRequest, RegistrationResponse, RegistrationUpload, CredentialRequest, CredentialResponse, Credentials, SecretCredentials, CleartextCredentials, CustomCleartextCredentials, Envelope, InnerEnvelope, envelope_mode_base, envelope_mode_custom_identifier, deserialize_secret_credentials
    from sagelib.opaque_common import derive_secret, hkdf_expand_label, hkdf_expand, hkdf_extract, random_bytes, xor, I2OSP, OS2IP, encode_vector, encode_vector_len, decode_vector, decode_vector_len, _as_bytes
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

OPAQUE_NONCE_LENGTH = 32

class OPAQUECore(object):
    def __init__(self, config):
        self.config = config

    def derive_secrets(self, pwdU, response, blind, nonce, Npt):
        oprf_context = SetupBaseClient(self.config.oprf_suite)
        y = oprf_context.finalize(pwdU, blind, response.data, None, None)
        y_harden = self.config.mhf.harden(y)
        rwdU = self.config.kdf.extract(nonce, y_harden)

        Nh = self.config.hash().digest_size
        pseudorandom_pad = self.config.kdf.expand(rwdU, _as_bytes("Pad"), Npt)
        auth_key = self.config.kdf.expand(rwdU, _as_bytes("AuthKey"), Nh)
        export_key = self.config.kdf.expand(rwdU, _as_bytes("ExportKey"), Nh)

        return rwdU, pseudorandom_pad, auth_key, export_key

    def create_registration_request(self, pwdU):
        oprf_context = SetupBaseClient(self.config.oprf_suite)
        blind, blinded_element = oprf_context.blind(pwdU)
        request = RegistrationRequest(blinded_element)
        return request, blind

    def create_registration_response(self, request, pkS):
        kU, _ = GenerateKeyPair(self.config.oprf_suite)
        oprf_context = SetupBaseServer(self.config.oprf_suite, kU)
        data, _, _ = oprf_context.evaluate(request.data)
        response = RegistrationResponse(data, pkS)
        return response, kU

    def finalize_request(self, creds, pwdU, blind, response):
        secret_creds = SecretCredentials(creds.skU)
        cleartext_creds = CleartextCredentials(response.pkS)
        if self.config.mode == envelope_mode_custom_identifier:
            cleartext_creds = CustomCleartextCredentials(response.pkS, creds.idU, creds.idS)

        pt = secret_creds.serialize()
        auth_data = cleartext_creds.serialize()

        nonce = random_bytes(OPAQUE_NONCE_LENGTH)
        rwdU, pseudorandom_pad, auth_key, export_key = self.derive_secrets(pwdU, response, blind, nonce, len(pt))
        ct = xor(pt, pseudorandom_pad)

        contents = InnerEnvelope(self.config.mode, nonce, ct)
        serialized_contents = contents.serialize()
        auth_tag = self.config.mac.mac(auth_key, serialized_contents + auth_data)

        envU = Envelope(contents, auth_tag)
        record = RegistrationUpload(envU, creds.pkU)

        self.registration_rwdU = rwdU
        self.envelope_nonce = nonce
        self.auth_key = auth_key
        self.pseudorandom_pad = pseudorandom_pad

        return record, export_key

    def create_credential_request(self, pwdU):
        oprf_context = SetupBaseClient(self.config.oprf_suite)
        blind, blinded_element = oprf_context.blind(pwdU)
        request = CredentialRequest(blinded_element)
        return request, blind

    def create_credential_response(self, request, pkS, kU, envU):
        oprf_context = SetupBaseServer(self.config.oprf_suite, kU)
        data, _, _ = oprf_context.evaluate(request.data)
        response = CredentialResponse(data, pkS, envU)
        return response

    def recover_credentials(self, pwdU, blind, response, idU = None, idS = None):
        contents = response.envU.contents
        serialized_contents = contents.serialize()
        nonce = contents.nonce
        ct = contents.ct

        cleartext_creds = CleartextCredentials(response.pkS)
        if contents.mode == envelope_mode_custom_identifier:
            cleartext_creds = CustomCleartextCredentials(response.pkS, idU, idS)
        auth_data = cleartext_creds.serialize()

        rwdU, pseudorandom_pad, auth_key, export_key = self.derive_secrets(pwdU, response, blind, nonce, len(ct))
        expected_tag = self.config.mac.mac(auth_key, serialized_contents + auth_data)

        if expected_tag != response.envU.auth_tag:
            raise Exception("Invalid tag")

        pt = xor(ct, pseudorandom_pad)
        secret_credentials, _ = deserialize_secret_credentials(pt)

        self.credential_rwdU = rwdU
        self.credential_decryption_pad = pseudorandom_pad
        self.credential_auth_key = auth_key

        return secret_credentials.skU, response.pkS, export_key

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

    def mac(self, key, input):
        return hmac.digest(key, input, self.hash)

def scrypt_harden(pwd):
    return scrypt(pwd, b'', 32768, 8, 1, 64)

def identity_harden(pwd):
    return pwd
