#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib
from collections import namedtuple

try:
    from sagelib.oprf import oprf_ciphersuites, ciphersuite_ristretto255_sha512, ciphersuite_decaf448_shake256, ciphersuite_p256_sha256, ciphersuite_p384_sha384, ciphersuite_p521_sha512
    from sagelib.opaque_core import OPAQUECore, HKDF, HMAC, MHF, identity_harden
    from sagelib.opaque_messages import RegistrationUpload, Envelope, deserialize_envelope, deserialize_registration_request, deserialize_registration_response, deserialize_registration_upload, \
            deserialize_credential_request, deserialize_credential_response
    from sagelib.groups import GroupRistretto255, GroupDecaf448, GroupP256, GroupP384, GroupP521
    from sagelib.opaque_common import I2OSP, OS2IP, I2OSP_le, OS2IP_le, random_bytes, zero_bytes, _as_bytes, encode_vector, encode_vector_len, decode_vector, decode_vector_len, to_hex, OPAQUE_NONCE_LENGTH
    from sagelib.opaque_ake import OPAQUE3DH, Configuration
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

default_opaque_configuration = Configuration(
    oprf_ciphersuites[ciphersuite_ristretto255_sha512], 
    HKDF(hashlib.sha512),
    HMAC(hashlib.sha512),
    hashlib.sha512, 
    MHF("Identity", identity_harden),
    GroupRistretto255(),
    _as_bytes("OPAQUE-POC"),
)

def test_core_protocol_serialization():
    idU = _as_bytes("Username")
    pwdU = _as_bytes("CorrectHorseBatteryStaple")

    config = default_opaque_configuration 
    group = config.group
    skS, pkS = group.key_gen()
    skS_enc = group.serialize_scalar(skS)
    pkS_enc = group.serialize(pkS)
    oprf_seed = random_bytes(config.hash().digest_size)

    core = OPAQUECore(config)

    # Run the registration flow to register credentials
    request, metadata = core.create_registration_request(pwdU)
    serialized_request = request.serialize()
    deserialized_request = deserialize_registration_request(
        config, serialized_request)
    assert request == deserialized_request

    response, kU = core.create_registration_response(request, pkS_enc, oprf_seed, idU, _as_bytes(""))
    serialized_response = response.serialize()
    deserialized_response = deserialize_registration_response(
        config, serialized_response)
    assert response == deserialized_response

    record, export_key = core.finalize_request(pwdU, metadata, response, _as_bytes(""))
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

    cred_response = core.create_credential_response(cred_request, pkS_enc, oprf_seed, record.envU, idU, record.masking_key, _as_bytes(""))
    serialized_response = cred_response.serialize()
    deserialized_response, length = deserialize_credential_response(
        config, serialized_response)
    assert cred_response == deserialized_response
    assert length == len(serialized_response)

    recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(pwdU, cred_metadata, cred_response, _as_bytes(""))

    # Check that recovered credentials match the registered credentials
    assert export_key == recovered_export_key

def test_registration_and_authentication():
    idU = _as_bytes("Username")
    pwdU = _as_bytes("opaquerulez")
    badPwdU = _as_bytes("iloveopaque")

    config = default_opaque_configuration 
    group = config.group
    skS, pkS = group.key_gen()
    skS_enc = group.serialize_scalar(skS)
    pkS_enc = group.serialize(pkS)
    oprf_seed = random_bytes(config.oprf_suite.group.scalar_byte_length())

    core = OPAQUECore(config)

    request, metadata = core.create_registration_request(pwdU)
    response, kU = core.create_registration_response(request, pkS_enc, oprf_seed, idU, _as_bytes(""))
    record, export_key = core.finalize_request(pwdU, metadata, response, _as_bytes(""))

    cred_request, cred_metadata = core.create_credential_request(pwdU)
    cred_response = core.create_credential_response(cred_request, pkS_enc, oprf_seed, record.envU, idU, record.masking_key, _as_bytes(""))
    recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(pwdU, cred_metadata, cred_response, _as_bytes(""))

    assert export_key == recovered_export_key

    cred_request, cred_metadata = core.create_credential_request(badPwdU)
    cred_response = core.create_credential_response(cred_request, pkS_enc, oprf_seed, record.envU, idU, record.masking_key, _as_bytes(""))
    try:
        recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(badPwdU, cred_metadata, cred_response, _as_bytes(""))
        assert False
    except:
        # We expect the MAC authentication tag to fail, so should get here
        pass

TestVectorParams = namedtuple("TestVectorParams", "is_fake idU credential_identifier idS pwdU context oprf fast_hash mhf group")

def run_test_vector(params):
    is_fake = params.is_fake
    idU = params.idU
    info = _as_bytes("")
    credential_identifier = params.credential_identifier
    idS = params.idS
    pwdU = params.pwdU
    context = params.context
    oprf = params.oprf
    fast_hash = params.fast_hash
    mhf = params.mhf
    group = params.group

    (skS, pkS) = group.key_gen()
    skS_bytes = group.serialize_scalar(skS)
    pkS_bytes = group.serialize(pkS)
    oprf_seed = random_bytes(fast_hash().digest_size)

    kdf = HKDF(fast_hash)
    mac = HMAC(fast_hash)
    config = Configuration(oprf, kdf, mac, fast_hash, mhf, group, context)
    core = OPAQUECore(config)

    if not is_fake:
        reg_request, metadata = core.create_registration_request(pwdU)
        reg_response, kU = core.create_registration_response(reg_request, pkS_bytes, oprf_seed, credential_identifier, info)
        record, export_key = core.finalize_request(pwdU, metadata, reg_response, info, idU, idS)
        pkU_enc = record.pkU
        pkU = group.deserialize(pkU_enc)
        pkU_bytes = pkU_enc
    else:
        (fake_skU, fake_pkU) = group.key_gen()
        fake_skU_bytes = group.serialize_scalar(fake_skU)
        fake_pkU_bytes = group.serialize(fake_pkU)

        fake_masking_key = random_bytes(config.Nh)
        fake_envU = Envelope(zero_bytes(OPAQUE_NONCE_LENGTH), zero_bytes(config.Nm))
        record = RegistrationUpload(fake_pkU_bytes, fake_masking_key, fake_envU)

    client_kex = OPAQUE3DH(config)
    server_kex = OPAQUE3DH(config)

    ke1 = client_kex.generate_ke1(pwdU, idU, fake_pkU if is_fake else pkU, idS, pkS)
    ke2 = server_kex.generate_ke2(ke1, oprf_seed, credential_identifier, record.envU, record.masking_key, idS, skS, pkS, idU, fake_pkU if is_fake else pkU)
    if is_fake:
        try:
            ke3 = client_kex.generate_ke3(ke2)
            assert False
        except:
            # Expected since the MAC was generated using garbage
            pass
    else:
        ke3 = client_kex.generate_ke3(ke2)
        server_session_key = server_kex.finish(ke3)
        assert server_session_key == client_kex.session_key

    inputs = {}
    intermediates = {}
    outputs = {}

    # Protocol inputs
    if not is_fake:
        if idU:
            inputs["client_identity"] = to_hex(idU)
        if idS:
            inputs["server_identity"] = to_hex(idS)
        inputs["oprf_seed"] = to_hex(oprf_seed)
        inputs["credential_identifier"] = to_hex(credential_identifier)
        inputs["password"] = to_hex(pwdU)
        inputs["server_private_key"] = to_hex(skS_bytes)
        inputs["server_public_key"] = to_hex(pkS_bytes)
        inputs["client_nonce"] = to_hex(client_kex.nonceU)
        inputs["server_nonce"] = to_hex(server_kex.nonceS)
        inputs["client_private_keyshare"] = to_hex(group.serialize_scalar(client_kex.eskU))
        inputs["client_keyshare"] = to_hex(group.serialize(client_kex.epkU))
        inputs["server_private_keyshare"] = to_hex(group.serialize_scalar(server_kex.eskS))
        inputs["server_keyshare"] = to_hex(group.serialize(server_kex.epkS))
        inputs["envelope_nonce"] = to_hex(core.envelope_nonce)
        inputs["masking_nonce"] = to_hex(server_kex.masking_nonce)
        inputs["blind_registration"] = to_hex(config.oprf_suite.group.serialize_scalar(metadata))
        inputs["blind_login"] = to_hex(config.oprf_suite.group.serialize_scalar(client_kex.cred_metadata))

        # Intermediate computations
        intermediates["client_public_key"] = to_hex(pkU_bytes)
        intermediates["oprf_key"] = to_hex(config.oprf_suite.group.serialize_scalar(kU))
        intermediates["envelope"] = to_hex(record.envU.serialize())
        intermediates["randomized_pwd"] = to_hex(client_kex.core.credential_rwd)
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
        # pkU, pkS, ke1, record.envU, record.masking_key, idS, skS, pkS, idU, pkU
        if idU:
            inputs["client_identity"] = to_hex(idU)
        if idS:
            inputs["server_identity"] = to_hex(idS)
        inputs["oprf_seed"] = to_hex(oprf_seed)
        inputs["credential_identifier"] = to_hex(credential_identifier)
        inputs["client_private_key"] = to_hex(fake_skU_bytes)
        inputs["client_public_key"] = to_hex(fake_pkU_bytes)
        inputs["server_private_key"] = to_hex(skS_bytes)
        inputs["server_public_key"] = to_hex(pkS_bytes)
        inputs["server_nonce"] = to_hex(server_kex.nonceS)
        inputs["server_private_keyshare"] = to_hex(group.serialize_scalar(server_kex.eskS))
        inputs["server_keyshare"] = to_hex(group.serialize(server_kex.epkS))
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
    idU = _as_bytes("alice")
    credential_identifier = _as_bytes("1234")
    idS = _as_bytes("bob")
    pwdU = _as_bytes("CorrectHorseBatteryStaple")
    context = _as_bytes("OPAQUE-POC")

    # Configurations specified here:
    # https://cfrg.github.io/draft-irtf-cfrg-opaque/draft-irtf-cfrg-opaque.html#name-configurations
    configs = [
        (oprf_ciphersuites[ciphersuite_ristretto255_sha512], hashlib.sha512, MHF("Identity", identity_harden), GroupRistretto255()),
        (oprf_ciphersuites[ciphersuite_p256_sha256], hashlib.sha256, MHF("Identity", identity_harden), GroupP256()),
    ]

    vectors = []
    for (oprf, fast_hash, mhf, group) in configs:
        for (idU, idS) in [(None, None), (idU, idS)]:
            params = TestVectorParams(False, idU, credential_identifier, idS, pwdU, context, oprf, fast_hash, mhf, group)
            vector = run_test_vector(params)
            vectors.append(vector)

    for (oprf, fast_hash, mhf, group) in configs:
        fake_params = TestVectorParams(True, idU, credential_identifier, idS, pwdU, context, oprf, fast_hash, mhf, group)
        vector = run_test_vector(fake_params)
        vectors.append(vector)

    return json.dumps(vectors, sort_keys=True, indent=2)

def main(path="vectors"):
    test_core_protocol_serialization()
    test_registration_and_authentication()

    formatted_vectors = test_3DH()
    with open(os.path.join(path, "vectors.json"), "w") as fh:
        fh.write(formatted_vectors)

if __name__ == "__main__":
    main()
