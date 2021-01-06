#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib

try:
    from sagelib.opaque import default_opaque_configuration
    from sagelib.opaque import deserialize_registration_request, deserialize_registration_response, deserialize_registration_upload, deserialize_credential_request, deserialize_credential_response
    from sagelib.opaque import encode_vector, decode_vector, random_bytes, _as_bytes
    from sagelib.opaque import create_registration_request, create_registration_response, finalize_request, \
        create_credential_request, create_credential_response, recover_credentials
    from sagelib.opaque import InnerEnvelope, deserialize_inner_envelope, envelope_mode_base, envelope_mode_custom_identifier, \
        Envelope, deserialize_envelope
    from sagelib.opaque import Credentials, SecretCredentials, CleartextCredentials, CustomCleartextCredentials
    from sagelib import ristretto255
    from sagelib.opaque import I2OSP, OS2IP
    from sagelib.opaque_ake import TripleDH
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)


def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, bytes)
    return "0x" + "".join("{:02x}".format(c) for c in octet_string)


def test_vector_serialization():
    data = "hello".encode('utf-8')
    encoded_data = encode_vector(data)
    assert len(encoded_data) == len(data) + 2
    recovered_data, length = decode_vector(encoded_data)
    assert data == recovered_data


def create_inner_envelope():
    nonce = random_bytes(32)
    ct = "ct".encode('utf-8')
    return InnerEnvelope(envelope_mode_base, nonce, ct)


def test_inner_envelope_serialization():
    inner_envelope = create_inner_envelope()
    serialized_inner = inner_envelope.serialize()
    recovered_inner, offset = deserialize_inner_envelope(serialized_inner)

    assert offset == len(serialized_inner)
    assert recovered_inner.mode == inner_envelope.mode
    assert recovered_inner.nonce == inner_envelope.nonce
    assert recovered_inner.ct == inner_envelope.ct


def test_envelope_serialization():
    inner_envelope = create_inner_envelope()
    auth_tag = random_bytes(
        default_opaque_configuration.hash_alg().digest_size)
    envelope = Envelope(inner_envelope, auth_tag)
    serialized_envelope = envelope.serialize()
    recovered_envelope, offset = deserialize_envelope(
        default_opaque_configuration, serialized_envelope)

    assert offset == len(serialized_envelope)
    assert recovered_envelope.contents.nonce == envelope.contents.nonce
    assert recovered_envelope.auth_tag == envelope.auth_tag


def test_core_protocol():
    idU = _as_bytes("alice")
    pwdU = _as_bytes("opaquerulez")
    badPwdU = _as_bytes("iloveopaque")
    skU = _as_bytes("skU")
    pkU = _as_bytes("pkU")
    pkS = _as_bytes("pkS")

    # Create the OPRF context
    config = default_opaque_configuration

    # Run the registration flow to register credentials
    request, metadata = create_registration_request(config, pwdU)
    serialized_request = request.serialize()
    deserialized_request = deserialize_registration_request(
        config, serialized_request)
    assert request == deserialized_request

    response, kU = create_registration_response(
        config, request, pkS)
    serialized_response = response.serialize()
    deserialized_response = deserialize_registration_response(
        config, serialized_response)
    assert response == deserialized_response

    secret_creds = SecretCredentials(skU)
    cleartext_creds = CleartextCredentials(response.pkS)
    creds = Credentials(secret_creds, cleartext_creds, pkU)

    envU, export_key = finalize_request(
        config, creds, pwdU, metadata, response)
    serialized_envU = envU.serialize()
    deserialized_envU, envU_len = deserialize_envelope(config, serialized_envU)
    assert envU_len == len(serialized_envU)
    assert envU == deserialized_envU

    # Run the authentication flow to recover credentials
    cred_request, cred_metadata = create_credential_request(config, pwdU)
    serialized_request = cred_request.serialize()
    deserialized_request = deserialize_credential_request(
        config, serialized_request)
    assert cred_request == deserialized_request

    cred_response = create_credential_response(
        config, cred_request, kU, envU)
    serialized_response = cred_response.serialize()
    deserialized_response = deserialize_credential_response(
        config, serialized_response)
    assert cred_response == deserialized_response

    recovered_creds, recovered_export_key, rwdU, pseudorandom_pad, auth_key = recover_credentials(
        config, cleartext_creds, pwdU, cred_metadata, cred_response)

    # Check that recovered credentials match the registered credentials
    assert export_key == recovered_export_key
    assert recovered_creds.secret_credentials.skU == skU
    assert recovered_creds.cleartext_credentials.pkS == pkS

    # Run with different credentials and expect failure
    cred_request, cred_metadata = create_credential_request(config, badPwdU)
    cred_response = create_credential_response(
        config, cred_request, kU, envU)
    try:
        recovered_creds, recovered_export_key, rwdU, pseudorandom_pad, auth_key = recover_credentials(
            config, cleartext_creds, badPwdU, cred_metadata, cred_response)
        assert False
    except:
        # We expect the MAC authentication tag to fail, so should get here
        pass


def test_3DH():
    idU = _as_bytes("alice")
    pwdU = _as_bytes("opaquerulez")
    badPwdU = _as_bytes("iloveopaque")

    (skU, pkU) = ristretto255.keygen()
    (skS, pkS) = ristretto255.keygen()

    skU_bytes = I2OSP(skU, 32)
    pkU_bytes = ristretto255.ENCODE(*pkU)
    skS_bytes = I2OSP(skS, 32)
    pkS_bytes = ristretto255.ENCODE(*pkS)

    # Create the OPRF context
    config = default_opaque_configuration

    secret_creds = SecretCredentials(skU_bytes)
    cleartext_creds = CleartextCredentials(pkS_bytes)
    creds = Credentials(secret_creds, cleartext_creds, pkU_bytes)

    # Run the registration flow to register credentials
    request, metadata = create_registration_request(config, pwdU)
    response, kU = create_registration_response(
        config, request, pkS_bytes)
    envU, export_key = finalize_request(
        config, creds, pwdU, metadata, response)

    # Now run the authentication flow
    kex = TripleDH(config)

    request, metadata = create_credential_request(config, pwdU)
    ke1_state, ke1 = kex.generate_ke1(request.serialize())

    response = create_credential_response(
        config, request, kU, envU)
    ke2_state, ke2 = kex.generate_ke2(
        request.serialize(), response.serialize(), ke1, pkU, skS, pkS)
    client_session_key, ke3 = kex.generate_ke3(
        response.serialize(), ke2, ke1_state, pkS, skU, pkU)
    server_session_key = kex.finish(ke3, ke2_state)

    assert client_session_key == server_session_key


class Protocol(object):
    def __init__(self):
        self.inputs = [
            {
                "idU": _as_bytes("alice"),
                "pwdU": _as_bytes("opaquerulez"),
                "skU": _as_bytes("skU"),
                "pkU": _as_bytes("pkU"),
                "pkS": _as_bytes("pkS"),
            }
        ]

    def run_vector(self, vector):
        raise Exception("Not implemented")

    def run(self, config):
        vectors = []
        for x in self.inputs:
            idU = x["idU"]
            pwdU = x["pwdU"]
            skU = x["skU"]
            pkU = x["pkU"]
            pkS = x["pkS"]

            secret_creds = SecretCredentials(skU)
            cleartext_creds = CleartextCredentials(pkS)
            creds = Credentials(secret_creds, cleartext_creds, pkU)

            # Run the registration flow to register credentials
            request, reg_metadata = create_registration_request(config, pwdU)
            serialized_reg_request = request.serialize()
            deserialized_request = deserialize_registration_request(
                config, serialized_reg_request)
            assert request == deserialized_request

            response, kU = create_registration_response(config, request, pkS)
            serialized_reg_response = response.serialize()
            deserialized_response = deserialize_registration_response(
                config, serialized_reg_response)
            assert response == deserialized_response

            record, export_key = finalize_request(
                config, idU, pwdU, skU, pkU, reg_metadata, request, response, kU)
            serialized_record = record.serialize()
            deserialized_record = deserialize_registration_upload(
                config, serialized_record)
            assert record == deserialized_record

            # Run the authentication flow to recover credentials
            cred_request, cred_metadata = create_credential_request(
                config, pwdU)
            serialized_cred_request = cred_request.serialize()
            deserialized_request = deserialize_credential_request(
                config, serialized_cred_request)
            assert cred_request == deserialized_request

            cred_response, recovered_pkU = create_credential_response(
                config, cred_request, kU, record)
            serialized_cred_response = cred_response.serialize()
            deserialized_response = deserialize_credential_response(
                config, serialized_cred_response)
            assert cred_response == deserialized_response

            creds, recovered_export_key, rwdU, pseudorandom_pad, auth_key = recover_credentials(
                config, pwdU, cred_metadata, cred_response)

            # Check that recovered credentials match the registered credentials
            assert recovered_pkU == pkU
            assert export_key == recovered_export_key
            assert creds.secret_credentials[0].data == skU
            assert creds.cleartext_credentials[0].data == idU

            vector = {}

            # Protocol inputs
            vector["idU"] = to_hex(idU)
            vector["pwdU"] = to_hex(pwdU)
            vector["skU"] = to_hex(skU)
            vector["pkU"] = to_hex(pkU)
            vector["pkS"] = to_hex(pkS)

            # Protocol messages
            vector["RegistrationRequest"] = to_hex(serialized_reg_request)
            # vector["RegistrationRequestMetadata"] = to_hex(reg_metadata.serialize())
            vector["RegistrationResponse"] = to_hex(serialized_reg_response)
            vector["RegistrationUpload"] = to_hex(serialized_record)
            vector["CredentialRequest"] = to_hex(serialized_cred_request)
            # vector["CredentialRequestMetadata"] = to_hex(cred_metadata.serialize())
            vector["CredentialResponse"] = to_hex(serialized_cred_response)

            # Intermediate computations
            vector["kU"] = to_hex(config.oprf_suite.group.serialize_scalar(kU))
            vector["envU"] = to_hex(record.envU.serialize())
            vector["rwdU"] = to_hex(rwdU)
            vector["pseudorandom_pad"] = to_hex(pseudorandom_pad)
            vector["auth_key"] = to_hex(auth_key)

            # Protocol outputs
            vector["export_key"] = to_hex(export_key)

            vectors.append(vector)

        return vectors


def main(path="vectors"):
    test_vector_serialization()
    test_inner_envelope_serialization()
    test_envelope_serialization()
    test_core_protocol()
    test_3DH()

    # runner = Protocol()
    # vectors = runner.run(default_opaque_configuration)

    # with open(path + "/allVectors.json", 'wt') as f:
    #     json.dump(vectors, f, sort_keys=True, indent=2)
    #     f.write("\n")


if __name__ == "__main__":
    main()
