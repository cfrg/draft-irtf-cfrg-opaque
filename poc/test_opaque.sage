#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib

try:
    from sagelib.oprf import SetupBaseServer, SetupBaseClient, SetupVerifiableServer, SetupVerifiableClient, oprf_ciphersuites, _as_bytes, Evaluation
    from sagelib.oprf import ciphersuite_p256_hkdf_sha512_sswu_ro, Ciphersuite, GroupP256
    from sagelib.opaque import encode_vector, decode_vector, random_bytes, _as_bytes
    from sagelib.opaque import serialize_credential_list, deserialize_credential_list
    from sagelib.opaque import serialize_extensions, deserialize_extensions
    from sagelib.opaque import deserialize_message
    from sagelib.opaque import create_registration_request, create_registration_response, finalize_request, \
        create_credential_request, create_credential_response, recover_credentials
    from sagelib.opaque import CredentialExtension, deserialize_credential_extension, \
        Credentials, deserialize_credentials, \
        credential_idU, credential_skU, credential_pkS, \
        InnerEnvelope, deserialize_inner_envelope, \
        Envelope, deserialize_envelope
    from sagelib.opaque import TripleDH
    from sagelib import ristretto255
    from sagelib.opaque import I2OSP, OS2IP
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

def test_credential_list_serialization():
    types = [credential_pkS, credential_idU]

    encoded_types = serialize_credential_list(types)
    assert len(encoded_types) == len(types) + 1

    decoded_types, offset = deserialize_credential_list(encoded_types)
    assert offset == len(types) + 1
    assert decoded_types == types

def test_credential_extension_serialization():
    test_idU = b'\x01\x02\x03\x04'
    ext_idU = CredentialExtension(credential_idU, test_idU)

    serialized_idU = ext_idU.serialize()
    expected_serialized_idU = b'\x04\x00\x04\x01\x02\x03\x04'
    assert serialized_idU == expected_serialized_idU

    recovered_idU, offset = deserialize_credential_extension(serialized_idU)
    assert ext_idU.credential_type == recovered_idU.credential_type
    assert ext_idU.data == recovered_idU.data

def test_credential_serialization():
    test_pkS = b'\x01\x02\x03\x04'
    ext_pkS = CredentialExtension(credential_pkS, test_pkS)

    test_skU = b'\x05\x06\x07\x08\x09\x0a'
    ext_skU = CredentialExtension(credential_skU, test_skU)

    creds = Credentials(secret_credentials = [ext_skU], cleartext_credentials = [ext_pkS])

    serialized_creds = creds.serialize()
    expected_serialized_creds = b'\x00\x09\x01\x00\x06\x05\x06\x07\x08\x09\x0a\x00\x07\x03\x00\x04\x01\x02\x03\x04'
    assert serialized_creds == expected_serialized_creds

    recovered_creds, offset = deserialize_credentials(serialized_creds)
    assert len(recovered_creds.secret_credentials) == 1
    assert len(recovered_creds.cleartext_credentials) == 1

    ext_vector = [ext_pkS, ext_skU]
    serialized_ext_vector = serialize_extensions(ext_vector)
    recovered_ext_vector, vector_len = deserialize_extensions(serialized_ext_vector)
    assert len(recovered_ext_vector) == 2
    assert recovered_ext_vector[0].credential_type == ext_vector[0].credential_type
    assert recovered_ext_vector[0].data == ext_vector[0].data
    assert recovered_ext_vector[1].credential_type == ext_vector[1].credential_type
    assert recovered_ext_vector[1].data == ext_vector[1].data

def create_inner_envelope():
    nonce = random_bytes(32)
    ct = "ct".encode('utf-8')
    auth_data = "ct".encode('utf-8')
    return InnerEnvelope(nonce, ct, auth_data)

def test_inner_envelope_serialization():
    inner_envelope = create_inner_envelope()
    serialized_inner = inner_envelope.serialize()
    recovered_inner, offset = deserialize_inner_envelope(serialized_inner)

    assert offset == len(serialized_inner)
    assert recovered_inner.nonce == inner_envelope.nonce
    assert recovered_inner.ct == inner_envelope.ct
    assert recovered_inner.auth_data == inner_envelope.auth_data

def test_envelope_serialization():
    inner_envelope = create_inner_envelope()
    auth_tag = random_bytes(32)
    envelope = Envelope(inner_envelope, auth_tag)
    serialized_envelope = envelope.serialize()
    recovered_envelope, offset = deserialize_envelope(serialized_envelope)

    assert offset == len(serialized_envelope)
    assert recovered_envelope.contents.nonce == envelope.contents.nonce
    assert recovered_envelope.auth_tag == envelope.auth_tag

def test_registration_authentication_flow():
    idU = _as_bytes("alice")
    pwdU = _as_bytes("opaquerulez")
    badPwdU = _as_bytes("iloveopaque")
    skU = _as_bytes("skU")
    pkU = _as_bytes("pkU")
    pkS = _as_bytes("pkS")

    # Create the OPRF context
    suite = Ciphersuite("OPRF-P256-HKDF-SHA512-SSWU-RO", ciphersuite_p256_hkdf_sha512_sswu_ro, GroupP256(), hashlib.sha512)

    # TODO(caw): work out a better way to implement different configurations or profiles
    secret_list = [credential_skU]
    cleartext_list = [credential_idU]

    # Run the registration flow to register credentials
    client_context = SetupBaseClient(suite)
    server_context = SetupBaseServer(suite)

    request, metadata = create_registration_request(client_context, pwdU)
    serialized_request = request.serialize_message()
    deserialized_request, _ = deserialize_message(serialized_request)
    assert request == deserialized_request

    response, kU = create_registration_response(server_context, request, pkS, secret_list, cleartext_list)
    serialized_response = response.serialize_message()
    deserialized_response, _ = deserialize_message(serialized_response)
    assert response == deserialized_response

    record, export_key = finalize_request(client_context, idU, pwdU, skU, pkU, metadata, request, response, kU)
    serialized_record = record.serialize_message()
    deserialized_record, _ = deserialize_message(serialized_record)
    assert record == deserialized_record

    # Run the authentication flow to recover credentials
    client_context = SetupBaseClient(suite)
    server_context = SetupBaseServer(suite)

    cred_request, cred_metadata = create_credential_request(client_context, pwdU)
    serialized_request = cred_request.serialize_message()
    deserialized_request, _ = deserialize_message(serialized_request)
    assert cred_request == deserialized_request

    cred_response, recovered_pkU = create_credential_response(server_context, cred_request, pkS, kU, record)
    serialized_response = cred_response.serialize_message()
    deserialized_response, _ = deserialize_message(serialized_response)
    assert cred_response == deserialized_response

    creds, recovered_export_key = recover_credentials(client_context, pwdU, cred_metadata, cred_request, cred_response)

    # Check that recovered credentials match the registered credentials
    assert recovered_pkU == pkU
    assert export_key == recovered_export_key
    assert len(creds.secret_credentials) == len(secret_list)
    assert creds.secret_credentials[0].data == skU
    assert len(creds.cleartext_credentials) == len(cleartext_list)
    assert creds.cleartext_credentials[0].data == idU

    # Run with different credentials and expect failure
    client_context = SetupBaseClient(suite)
    server_context = SetupBaseServer(suite)
    cred_request, cred_metadata = create_credential_request(client_context, badPwdU)
    cred_response, recovered_pkU = create_credential_response(server_context, cred_request, pkS, kU, record)
    try:
        creds, recovered_export_key = recover_credentials(client_context, badPwdU, cred_metadata, cred_request, cred_response)
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
    suite = Ciphersuite("OPRF-P256-HKDF-SHA512-SSWU-RO", ciphersuite_p256_hkdf_sha512_sswu_ro, GroupP256(), hashlib.sha512)

    secret_list = [credential_skU]
    cleartext_list = [credential_idU]

    # Run the registration flow to register credentials
    client_context = SetupBaseClient(suite)
    server_context = SetupBaseServer(suite)
    request, metadata = create_registration_request(client_context, pwdU)
    response, kU = create_registration_response(server_context, request, pkS_bytes, secret_list, cleartext_list)
    record, export_key = finalize_request(client_context, idU, pwdU, skU_bytes, pkU_bytes, metadata, request, response, kU)

    # Now run the authentication flow
    kex = TripleDH()

    request, metadata = create_credential_request(client_context, pwdU)
    ke1_state, ke1 = kex.generate_ke1(request.serialize())

    response, recovered_pkU = create_credential_response(server_context, request, pkS_bytes, kU, record)
    ke2_state, ke2 = kex.generate_ke2(request.serialize(), response.serialize(), ke1, pkU, skS, pkS)
    client_session_key, ke3 = kex.generate_ke3(response.serialize(), ke2, ke1_state, pkS, skU, pkU)
    server_session_key = kex.finish(ke3, ke2_state)

def main(path="vectors"):
    test_vector_serialization()
    test_credential_list_serialization()
    test_credential_extension_serialization()
    test_credential_serialization()
    test_inner_envelope_serialization()
    test_envelope_serialization()
    test_registration_authentication_flow()
    test_3DH()

    # with open(path + "/allVectors.json", 'wt') as f:
    #     json.dump(vectors, f, sort_keys=True, indent=2)
    #     f.write("\n")

if __name__ == "__main__":
    main()
