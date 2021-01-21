#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib

try:
    from sagelib.opaque import default_opaque_configuration, OPAQUECore
    from sagelib.opaque_messages import deserialize_registration_request, deserialize_registration_response, deserialize_registration_upload, deserialize_credential_request, deserialize_credential_response
    from sagelib.opaque_messages import InnerEnvelope, deserialize_inner_envelope, envelope_mode_base, envelope_mode_custom_identifier, \
        Envelope, deserialize_envelope
    from sagelib.opaque_messages import Credentials, SecretCredentials, CleartextCredentials, CustomCleartextCredentials
    from sagelib.opaque_common import I2OSP, OS2IP, encode_vector, encode_vector_len, decode_vector, decode_vector_len, _as_bytes, random_bytes
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def test_vector_serialization():
    data = _as_bytes("hello")
    encoded_data = encode_vector(data)
    assert len(encoded_data) == len(data) + 2
    recovered_data, length = decode_vector(encoded_data)
    assert data == recovered_data
    assert length == len(encoded_data)

def create_inner_envelope():
    nonce = random_bytes(32)
    ct = _as_bytes("ct")
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

def test_core_protocol_serialization():
    pwdU = _as_bytes("CorrectHorseBatteryStaple")
    skU = _as_bytes("skU")
    pkU = _as_bytes("pkU")
    pkS = _as_bytes("pkS")

    config = default_opaque_configuration   
    core = OPAQUECore(config)
    creds = Credentials(skU, pkU)

    # Run the registration flow to register credentials
    request, metadata = core.create_registration_request(pwdU)
    serialized_request = request.serialize()
    deserialized_request = deserialize_registration_request(
        config, serialized_request)
    assert request == deserialized_request

    response, kU = core.create_registration_response(request, pkS)
    serialized_response = response.serialize()
    deserialized_response = deserialize_registration_response(
        config, serialized_response)
    assert response == deserialized_response

    record, export_key = core.finalize_request(creds, pwdU, metadata, response)
    serialized_envU = record.envU.serialize()
    deserialized_envU, envU_len = deserialize_envelope(config, serialized_envU)
    assert envU_len == len(serialized_envU)
    assert record.envU == deserialized_envU

    # Run the authentication flow to recover credentials
    cred_request, cred_metadata = core.create_credential_request(pwdU)
    serialized_request = cred_request.serialize()
    deserialized_request, length = deserialize_credential_request(
        config, serialized_request)
    assert cred_request == deserialized_request
    assert length == len(serialized_request)

    cred_response = core.create_credential_response(cred_request, pkS, kU, record.envU)
    serialized_response = cred_response.serialize()
    deserialized_response, length = deserialize_credential_response(
        config, serialized_response)
    assert cred_response == deserialized_response
    assert length == len(serialized_response)

    recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(pwdU, cred_metadata, cred_response)

    # Check that recovered credentials match the registered credentials
    assert export_key == recovered_export_key
    assert recovered_skU == skU
    assert recovered_pkS == pkS

def main(path="vectors"):
    test_vector_serialization()
    test_inner_envelope_serialization()
    test_envelope_serialization()
    test_core_protocol_serialization()

if __name__ == "__main__":
    main()
