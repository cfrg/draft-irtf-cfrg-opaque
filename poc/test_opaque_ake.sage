#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib
try:
    from sagelib.oprf import oprf_ciphersuites, ciphersuite_ristretto255_sha512, ciphersuite_decaf448_sha512, ciphersuite_p256_sha256, ciphersuite_p384_sha512, ciphersuite_p521_sha512
    from sagelib.opaque_core import OPAQUECore, HKDF, HMAC, MHF, identity_harden
    from sagelib.opaque_messages import InnerEnvelope, deserialize_inner_envelope, envelope_mode_base, envelope_mode_custom_identifier, \
        Envelope, deserialize_envelope, deserialize_registration_request, deserialize_registration_response, deserialize_registration_upload, \
            deserialize_credential_request, deserialize_credential_response, \
            Credentials, SecretCredentials, CleartextCredentials, CustomCleartextCredentials
    from sagelib.groups import GroupRistretto255, GroupDecaf448, GroupP256, GroupP384, GroupP521
    from sagelib.opaque_common import I2OSP, OS2IP, I2OSP_le, OS2IP_le, random_bytes, _as_bytes, encode_vector, encode_vector_len, decode_vector, decode_vector_len, to_hex
    from sagelib.opaque_ake import OPAQUE3DH, Configuration
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

default_opaque_configuration = Configuration(
    envelope_mode_base, 
    oprf_ciphersuites[ciphersuite_ristretto255_sha512], 
    HKDF(hashlib.sha512),
    HMAC(hashlib.sha512),
    hashlib.sha512, 
    MHF("Identity", identity_harden),
    GroupRistretto255(),
)

def test_vector_serialization():
    data = _as_bytes("hello")
    encoded_data = encode_vector(data)
    assert len(encoded_data) == len(data) + 2
    recovered_data, length = decode_vector(encoded_data)
    assert data == recovered_data
    assert length == len(encoded_data)

def create_inner_envelope():
    nonce = random_bytes(32)
    config = default_opaque_configuration
    ct = os.urandom(config.Nsk)
    return InnerEnvelope(envelope_mode_base, nonce, ct)

def test_inner_envelope_serialization():
    inner_envelope = create_inner_envelope()
    serialized_inner = inner_envelope.serialize()
    recovered_inner, offset = deserialize_inner_envelope(default_opaque_configuration, serialized_inner)

    assert offset == len(serialized_inner)
    assert recovered_inner.mode == inner_envelope.mode
    assert recovered_inner.nonce == inner_envelope.nonce
    assert recovered_inner.ct == inner_envelope.ct

def test_envelope_serialization():
    inner_envelope = create_inner_envelope()
    auth_tag = random_bytes(
        default_opaque_configuration.hash().digest_size)
    envelope = Envelope(inner_envelope, auth_tag)
    serialized_envelope = envelope.serialize()
    recovered_envelope, offset = deserialize_envelope(
        default_opaque_configuration, serialized_envelope)

    assert offset == len(serialized_envelope)
    assert recovered_envelope.contents.nonce == envelope.contents.nonce
    assert recovered_envelope.auth_tag == envelope.auth_tag

def test_core_protocol_serialization():
    pwdU = _as_bytes("CorrectHorseBatteryStaple")

    config = default_opaque_configuration 
    group = config.group
    skU, pkU = group.key_gen()
    skU_enc = group.serialize_scalar(skU)
    pkU_enc = group.serialize(pkU)
    skS, pkS = group.key_gen()
    skS_enc = group.serialize_scalar(skS)
    pkS_enc = group.serialize(pkS)

    core = OPAQUECore(config)
    creds = Credentials(skU_enc, pkU_enc)

    # Run the registration flow to register credentials
    request, metadata = core.create_registration_request(pwdU)
    serialized_request = request.serialize()
    deserialized_request = deserialize_registration_request(
        config, serialized_request)
    assert request == deserialized_request

    response, kU = core.create_registration_response(request, pkS_enc)
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

    cred_response = core.create_credential_response(cred_request, pkS_enc, kU, record.envU)
    serialized_response = cred_response.serialize()
    deserialized_response, length = deserialize_credential_response(
        config, serialized_response)
    assert cred_response == deserialized_response
    assert length == len(serialized_response)

    recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(pwdU, cred_metadata, cred_response)

    # Check that recovered credentials match the registered credentials
    assert export_key == recovered_export_key
    assert recovered_skU == skU_enc
    assert recovered_pkS == pkS_enc

def test_registration_and_authentication():
    pwdU = _as_bytes("opaquerulez")
    badPwdU = _as_bytes("iloveopaque")
    
    config = default_opaque_configuration 
    group = config.group
    skU, pkU = group.key_gen()
    skU_enc = group.serialize_scalar(skU)
    pkU_enc = group.serialize(pkU)
    skS, pkS = group.key_gen()
    skS_enc = group.serialize_scalar(skS)
    pkS_enc = group.serialize(pkS)
  
    core = OPAQUECore(config)
    creds = Credentials(skU_enc, pkU_enc)

    request, metadata = core.create_registration_request(pwdU)
    response, kU = core.create_registration_response(request, pkS_enc)
    record, export_key = core.finalize_request(creds, pwdU, metadata, response)
    
    cred_request, cred_metadata = core.create_credential_request(pwdU)
    cred_response = core.create_credential_response(cred_request, pkS_enc, kU, record.envU)
    recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(pwdU, cred_metadata, cred_response)

    assert export_key == recovered_export_key
    assert recovered_skU == skU_enc
    assert recovered_pkS == pkS_enc

    cred_request, cred_metadata = core.create_credential_request(badPwdU)
    cred_response = core.create_credential_response(cred_request, pkS_enc, kU, record.envU)
    try:
        recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(badPwdU, cred_metadata, cred_response)
        assert False
    except:
        # We expect the MAC authentication tag to fail, so should get here
        pass

def test_3DH():
    idU = _as_bytes("alice")
    idS = _as_bytes("bob")
    pwdU = _as_bytes("CorrectHorseBatteryStaple")
    info1 = _as_bytes("hello bob")
    info2 = _as_bytes("greetings alice")

    # Configurations specified here:
    # https://cfrg.github.io/draft-irtf-cfrg-opaque/draft-irtf-cfrg-opaque.html#name-configurations
    configs = [
        (oprf_ciphersuites[ciphersuite_ristretto255_sha512], hashlib.sha512, MHF("Identity", identity_harden), GroupRistretto255()),
        (oprf_ciphersuites[ciphersuite_decaf448_sha512], hashlib.sha512, MHF("Identity", identity_harden), GroupDecaf448()),
        (oprf_ciphersuites[ciphersuite_p256_sha256], hashlib.sha256, MHF("Identity", identity_harden), GroupP256()),
        (oprf_ciphersuites[ciphersuite_p384_sha512], hashlib.sha512, MHF("Identity", identity_harden), GroupP384()),
        (oprf_ciphersuites[ciphersuite_p521_sha512], hashlib.sha512, MHF("Identity", identity_harden), GroupP521()),
    ]

    vectors = []
    for mode in [envelope_mode_base, envelope_mode_custom_identifier]:
        for (oprf, fast_hash, mhf, group) in configs:
            (skU, pkU) = group.key_gen()
            (skS, pkS) = group.key_gen()
            skU_bytes = group.serialize_scalar(skU)
            pkU_bytes = group.serialize(pkU)
            skS_bytes = group.serialize_scalar(skS)
            pkS_bytes = group.serialize(pkS)

            idU = pkU_bytes
            idS = pkS_bytes

            kdf = HKDF(fast_hash)
            mac = HMAC(fast_hash)
            config = Configuration(mode, oprf, kdf, mac, fast_hash, mhf, group)

            creds = Credentials(skU_bytes, pkU_bytes, idU, idS)
            core = OPAQUECore(config)

            reg_request, metadata = core.create_registration_request(pwdU)
            reg_response, kU = core.create_registration_response(reg_request, pkS_bytes)
            record, export_key = core.finalize_request(creds, pwdU, metadata, reg_response)

            client_kex = OPAQUE3DH(config)
            server_kex = OPAQUE3DH(config)

            ke1 = client_kex.generate_ke1(pwdU, info1, idU, skU, pkU, idS, pkS)
            ke2 = server_kex.generate_ke2(ke1, kU, record.envU, info2, idS, skS, pkS, idU, pkU)
            ke3 = client_kex.generate_ke3(ke2)
            server_session_key = server_kex.finish(ke3)

            assert server_session_key == client_kex.session_key

            inputs = {}
            intermediates = {}
            outputs = {}

            # Protocol inputs
            if config.mode == envelope_mode_custom_identifier:
                inputs["client_identity"] = to_hex(idU)
                inputs["server_identity"] = to_hex(idS)
            inputs["password"] = to_hex(pwdU)
            inputs["client_private_key"] = to_hex(skU_bytes)
            inputs["client_public_key"] = to_hex(pkU_bytes)
            inputs["server_private_key"] = to_hex(skS_bytes)
            inputs["server_public_key"] = to_hex(pkS_bytes)
            inputs["client_info"] = to_hex(info1)
            inputs["server_info"] = to_hex(info2)
            inputs["client_nonce"] = to_hex(client_kex.nonceU)
            inputs["server_nonce"] = to_hex(server_kex.nonceS)
            inputs["client_private_keyshare"] = to_hex(group.serialize_scalar(client_kex.eskU))
            inputs["client_keyshare"] = to_hex(group.serialize(client_kex.epkU))
            inputs["server_private_keyshare"] = to_hex(group.serialize_scalar(server_kex.eskS))
            inputs["server_keyshare"] = to_hex(group.serialize(server_kex.epkS))
            inputs["envelope_nonce"] = to_hex(core.envelope_nonce)
            inputs["blind_registration"] = to_hex(config.oprf_suite.group.serialize_scalar(metadata))
            inputs["blind_login"] = to_hex(config.oprf_suite.group.serialize_scalar(client_kex.cred_metadata))
            inputs["oprf_key"] = to_hex(config.oprf_suite.group.serialize_scalar(kU))

            # Intermediate computations
            intermediates["envelope"] = to_hex(record.envU.serialize())
            intermediates["prk"] = to_hex(core.registration_rwdU)
            intermediates["pseudorandom_pad"] = to_hex(core.pseudorandom_pad)
            intermediates["auth_key"] = to_hex(core.auth_key)
            intermediates["server_mac_key"] = to_hex(client_kex.server_mac_key)
            intermediates["client_mac_key"] = to_hex(client_kex.client_mac_key)
            intermediates["handshake_encrypt_key"] = to_hex(client_kex.handshake_encrypt_key)
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

            vector = {}
            vector["config"] = client_kex.json()
            vector["inputs"] = inputs
            vector["intermediates"] = intermediates
            vector["outputs"] = outputs
            vectors.append(vector)

    return json.dumps(vectors, sort_keys=True, indent=2)

def main(path="vectors"):
    test_vector_serialization()
    test_inner_envelope_serialization()
    test_envelope_serialization()
    test_core_protocol_serialization()
    test_registration_and_authentication()

    formatted_vectors = test_3DH()
    with open(os.path.join(path, "vectors.json"), "w") as fh:
        fh.write(formatted_vectors)

if __name__ == "__main__":
    main()