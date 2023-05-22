#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib
from collections import namedtuple

try:
    from sagelib.oprf import oprf_ciphersuites, ciphersuite_ristretto255_sha512, ciphersuite_p256_sha256
    from sagelib.opaque_core import OPAQUECore, HKDF, HMAC, KeyStretchingFunction, identity_stretch
    from sagelib.opaque_messages import RegistrationUpload, Envelope, deserialize_envelope, deserialize_registration_request, deserialize_registration_response, \
            deserialize_credential_request, deserialize_credential_response
    from sagelib.groups import GroupRistretto255, GroupP256
    from sagelib.ake_group import GroupCurve25519
    from sagelib.opaque_common import curve25519_clamp, zero_bytes, _as_bytes, to_hex, OPAQUE_NONCE_LENGTH
    from sagelib.opaque_ake import OPAQUE3DH, Configuration
    from sagelib.opaque_drng import OPAQUEDRNG
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

default_opaque_configuration = Configuration(
    oprf_ciphersuites[ciphersuite_ristretto255_sha512], 
    HKDF(hashlib.sha512),
    HMAC(hashlib.sha512),
    hashlib.sha512, 
    KeyStretchingFunction("Identity", identity_stretch),
    GroupRistretto255(),
    _as_bytes("OPAQUE-POC"),
)

def test_core_protocol_serialization():
    client_identity = _as_bytes("Username")
    password = _as_bytes("CorrectHorseBatteryStaple")
    rng = OPAQUEDRNG("test_core_protocol_serialization".encode('utf-8'))

    config = default_opaque_configuration 
    group = config.group
    server_private_key = group.random_scalar(rng)
    server_public_key = group.scalar_mult(server_private_key, group.generator())
    server_public_key_enc = group.serialize(server_public_key)
    oprf_seed = rng.random_bytes(config.hash().digest_size)

    core = OPAQUECore(config, rng)

    # Run the registration flow to register credentials
    request, metadata = core.create_registration_request(password)
    serialized_request = request.serialize()
    deserialized_request = deserialize_registration_request(
        config, serialized_request)
    assert request == deserialized_request

    response, kU = core.create_registration_response(request, server_public_key_enc, oprf_seed, client_identity)
    serialized_response = response.serialize()
    deserialized_response = deserialize_registration_response(
        config, serialized_response)
    assert response == deserialized_response

    record, export_key = core.finalize_request(password, metadata, response)
    serialized_envU = record.envU.serialize()
    deserialized_envU, envU_len = deserialize_envelope(config, serialized_envU)
    assert envU_len == len(serialized_envU)
    assert record.envU == deserialized_envU

    # Run the authentication flow to recover credentials
    cred_request, cred_metadata = core.create_credential_request(password)
    serialized_request = cred_request.serialize()
    deserialized_request, length = deserialize_credential_request(
        config, serialized_request)
    assert cred_request == deserialized_request
    assert length == len(serialized_request)

    cred_response = core.create_credential_response(cred_request, server_public_key_enc, oprf_seed, record.envU, client_identity, record.masking_key)
    serialized_response = cred_response.serialize()
    deserialized_response, length = deserialize_credential_response(
        config, serialized_response)
    assert cred_response == deserialized_response
    assert length == len(serialized_response)

    _, _, recovered_export_key = core.recover_credentials(password, cred_metadata, cred_response)

    # Check that recovered credentials match the registered credentials
    assert export_key == recovered_export_key

def test_registration_and_authentication():
    client_identity = _as_bytes("Username")
    password = _as_bytes("opaquerulez")
    badPwdU = _as_bytes("iloveopaque")
    rng = OPAQUEDRNG("test_registration_and_authentication".encode('utf-8'))

    config = default_opaque_configuration 
    group = config.group
    server_private_key = group.random_scalar(rng)
    server_public_key = group.scalar_mult(server_private_key, group.generator())
    server_public_key_enc = group.serialize(server_public_key)
    oprf_seed = rng.random_bytes(config.hash().digest_size)

    core = OPAQUECore(config, rng)

    request, metadata = core.create_registration_request(password)
    response, kU = core.create_registration_response(request, server_public_key_enc, oprf_seed, client_identity)
    record, export_key = core.finalize_request(password, metadata, response)

    cred_request, cred_metadata = core.create_credential_request(password)
    cred_response = core.create_credential_response(cred_request, server_public_key_enc, oprf_seed, record.envU, client_identity, record.masking_key)
    _, _, recovered_export_key = core.recover_credentials(password, cred_metadata, cred_response)

    assert export_key == recovered_export_key

    cred_request, cred_metadata = core.create_credential_request(badPwdU)
    cred_response = core.create_credential_response(cred_request, server_public_key_enc, oprf_seed, record.envU, client_identity, record.masking_key)
    try:
        _, _, recovered_export_key = core.recover_credentials(badPwdU, cred_metadata, cred_response)
        assert False
    except:
        # We expect the MAC authentication tag to fail, so should get here
        pass

# Checks that a the scalar value represented by vector[key] has indeed been clamped
def assert_entry_clamped(vector, key):
    if key not in vector:
        # No need to do the check if the key doesn't exist
        return

    hex_scalar = vector[key]
    scalar = _as_bytes(bytes.fromhex(hex_scalar))
    assert scalar == curve25519_clamp(scalar)

TestVectorParams = namedtuple("TestVectorParams", "is_fake client_identity credential_identifier server_identity password context oprf fast_hash ksf group")

def run_test_vector(params, seed):
    is_fake = params.is_fake
    client_identity = params.client_identity
    credential_identifier = params.credential_identifier
    server_identity = params.server_identity
    password = params.password
    context = params.context
    oprf = params.oprf
    fast_hash = params.fast_hash
    ksf = params.ksf
    group = params.group
    core_rng = OPAQUEDRNG(_as_bytes("run_test_vector") + seed)

    server_private_key = group.random_scalar(core_rng)
    server_public_key = group.scalar_mult(server_private_key, group.generator())
    server_private_key_bytes = group.serialize_scalar(server_private_key)
    server_public_key_bytes = group.serialize(server_public_key)
    oprf_seed = core_rng.random_bytes(fast_hash().digest_size)

    kdf = HKDF(fast_hash)
    mac = HMAC(fast_hash)
    config = Configuration(oprf, kdf, mac, fast_hash, ksf, group, context)
    core = OPAQUECore(config, core_rng)

    if not is_fake:
        reg_request, metadata = core.create_registration_request(password)
        reg_response, kU = core.create_registration_response(reg_request, server_public_key_bytes, oprf_seed, credential_identifier)
        record, export_key = core.finalize_request(password, metadata, reg_response, client_identity, server_identity)
        client_public_key_bytes = record.client_public_key
        client_public_key = group.deserialize(client_public_key_bytes)
    else:
        fake_client_private_key = group.random_scalar(core_rng)
        fake_client_public_key = group.scalar_mult(fake_client_private_key, group.generator())
        fake_client_private_key_bytes = group.serialize_scalar(fake_client_private_key)
        fake_client_public_key_bytes = group.serialize(fake_client_public_key)

        fake_masking_key = core_rng.random_bytes(config.Nh)
        fake_envU = Envelope(zero_bytes(OPAQUE_NONCE_LENGTH), zero_bytes(config.Nm))
        record = RegistrationUpload(fake_client_public_key_bytes, fake_masking_key, fake_envU)

    client_kex = OPAQUE3DH(config, OPAQUEDRNG(_as_bytes("client") + seed))
    server_kex = OPAQUE3DH(config, OPAQUEDRNG(_as_bytes("server") + seed))

    ke1 = client_kex.generate_ke1(password)
    ke2 = server_kex.generate_ke2(ke1, oprf_seed, credential_identifier, record.envU, record.masking_key, server_identity, server_private_key, server_public_key_bytes, client_identity, fake_client_public_key_bytes if is_fake else client_public_key_bytes)
    if is_fake:
        try:
            ke3 = client_kex.generate_ke3(ke2, client_identity, server_identity)
            assert False
        except:
            # Expected since the MAC was generated using garbage
            pass
    else:
        ke3 = client_kex.generate_ke3(ke2, client_identity, server_identity)
        server_session_key = server_kex.auth_server_finish(ke3)
        assert server_session_key == client_kex.session_key

    inputs = {}
    intermediates = {}
    outputs = {}

    # Protocol inputs
    if not is_fake:
        if client_identity:
            inputs["client_identity"] = to_hex(client_identity)
        if server_identity:
            inputs["server_identity"] = to_hex(server_identity)
        inputs["oprf_seed"] = to_hex(oprf_seed)
        inputs["credential_identifier"] = to_hex(credential_identifier)
        inputs["password"] = to_hex(password)
        inputs["server_private_key"] = to_hex(server_private_key_bytes)
        inputs["server_public_key"] = to_hex(server_public_key_bytes)
        inputs["client_nonce"] = to_hex(client_kex.client_nonce)
        inputs["server_nonce"] = to_hex(server_kex.server_nonce)
        inputs["client_keyshare_seed"] = to_hex(client_kex.client_keyshare_seed)
        inputs["server_keyshare_seed"] = to_hex(server_kex.server_keyshare_seed)
        inputs["envelope_nonce"] = to_hex(core.envelope_nonce)
        inputs["masking_nonce"] = to_hex(server_kex.masking_nonce)
        inputs["blind_registration"] = to_hex(config.oprf_suite.group.serialize_scalar(metadata))
        inputs["blind_login"] = to_hex(config.oprf_suite.group.serialize_scalar(client_kex.cred_metadata))

        # Intermediate computations
        intermediates["client_public_key"] = to_hex(client_public_key_bytes)
        intermediates["oprf_key"] = to_hex(config.oprf_suite.group.serialize_scalar(kU))
        intermediates["envelope"] = to_hex(record.envU.serialize())
        intermediates["randomized_password"] = to_hex(client_kex.core.credential_randomized_password)
        intermediates["masking_key"] = to_hex(client_kex.core.credential_masking_key)
        intermediates["auth_key"] = to_hex(client_kex.core.credential_auth_key)
        intermediates["server_mac_key"] = to_hex(client_kex.server_mac_key)
        intermediates["client_mac_key"] = to_hex(client_kex.client_mac_key)
        intermediates["handshake_secret"] = to_hex(client_kex.handshake_secret)

        # Protocol outputs
        outputs["registration_request"] = to_hex(reg_request.serialize())
        outputs["registration_response"] = to_hex(reg_response.serialize())
        outputs["registration_upload"] = to_hex(record.serialize())
        outputs["KE1"] = to_hex(ke1)
        outputs["KE2"] = to_hex(ke2)
        outputs["KE3"] = to_hex(ke3)
        outputs["session_key"] = to_hex(server_session_key)
        outputs["export_key"] = to_hex(export_key)
    else:
        # client_public_key, server_public_key, ke1, record.envU, record.masking_key, server_identity, server_private_key, server_public_key, client_identity, client_public_key
        if client_identity:
            inputs["client_identity"] = to_hex(client_identity)
        if server_identity:
            inputs["server_identity"] = to_hex(server_identity)
        inputs["oprf_seed"] = to_hex(oprf_seed)
        inputs["credential_identifier"] = to_hex(credential_identifier)
        inputs["client_private_key"] = to_hex(fake_client_private_key_bytes)
        inputs["client_public_key"] = to_hex(fake_client_public_key_bytes)
        inputs["server_private_key"] = to_hex(server_private_key_bytes)
        inputs["server_public_key"] = to_hex(server_public_key_bytes)
        inputs["server_nonce"] = to_hex(server_kex.server_nonce)
        inputs["client_keyshare_seed"] = to_hex(client_kex.client_keyshare_seed)
        inputs["server_keyshare_seed"] = to_hex(server_kex.server_keyshare_seed)
        inputs["masking_key"] = to_hex(fake_masking_key)
        inputs["masking_nonce"] = to_hex(server_kex.masking_nonce)
        inputs["KE1"] = to_hex(ke1)

        # Protocol outputs
        outputs["KE2"] = to_hex(ke2)

    vector = {}
    vector["config"] = client_kex.json()
    vector["config"]["Fake"] = str(is_fake)
    vector["inputs"] = inputs
    vector["intermediates"] = intermediates
    vector["outputs"] = outputs
    
    return vector

def test_3DH():
    client_identity = _as_bytes("alice")
    credential_identifier = _as_bytes("1234")
    server_identity = _as_bytes("bob")
    password = _as_bytes("CorrectHorseBatteryStaple")
    context = _as_bytes("OPAQUE-POC")

    # Configurations specified here:
    # https://cfrg.github.io/draft-irtf-cfrg-opaque/draft-irtf-cfrg-opaque.html#name-configurations
    configs = [
        (oprf_ciphersuites[ciphersuite_ristretto255_sha512], hashlib.sha512, KeyStretchingFunction("Identity", identity_stretch), GroupRistretto255()),
        (oprf_ciphersuites[ciphersuite_ristretto255_sha512], hashlib.sha512, KeyStretchingFunction("Identity", identity_stretch), GroupCurve25519()),
        (oprf_ciphersuites[ciphersuite_p256_sha256], hashlib.sha256, KeyStretchingFunction("Identity", identity_stretch), GroupP256()),
    ]

    vectors = []
    for (oprf, fast_hash, ksf, group) in configs:
        for (client_identity, server_identity) in [(None, None), (client_identity, server_identity)]:
            params = TestVectorParams(False, client_identity, credential_identifier, server_identity, password, context, oprf, fast_hash, ksf, group)
            vector = run_test_vector(params, _as_bytes("real test vector seed"))
            vectors.append(vector)

    for (oprf, fast_hash, ksf, group) in configs:
        fake_params = TestVectorParams(True, client_identity, credential_identifier, server_identity, password, context, oprf, fast_hash, ksf, group)
        vector = run_test_vector(fake_params, _as_bytes("fake test vector seed"))
        vectors.append(vector)

    # Ensure that curve25519 private keys are all clamped
    for vector in vectors:
        if vector["config"]["Group"] == "curve25519":
            assert_entry_clamped(vector["inputs"], "client_private_key")
            assert_entry_clamped(vector["inputs"], "server_private_key")
            assert_entry_clamped(vector["inputs"], "client_private_keyshare")
            assert_entry_clamped(vector["inputs"], "server_private_keyshare")

    return json.dumps(vectors, sort_keys=True, indent=2)

def main(path="vectors"):
    test_core_protocol_serialization()
    test_registration_and_authentication()

    formatted_vectors = test_3DH()
    with open(os.path.join(path, "vectors.json"), "w") as fh:
        fh.write(formatted_vectors)

if __name__ == "__main__":
    main()
