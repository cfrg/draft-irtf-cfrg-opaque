#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib
try:
    from sagelib.oprf import oprf_ciphersuites, ciphersuite_ristretto255_sha512, ciphersuite_decaf448_sha512, ciphersuite_p256_sha256, ciphersuite_p384_sha512, ciphersuite_p521_sha512
    from sagelib.opaque_core import OPAQUECore, HKDF, HMAC, MHF, identity_harden
    from sagelib.opaque_messages import InnerEnvelope, deserialize_inner_envelope, envelope_mode_internal, envelope_mode_external, \
        Envelope, deserialize_envelope, deserialize_registration_request, deserialize_registration_response, deserialize_registration_upload, \
            deserialize_credential_request, deserialize_credential_response, \
            Credentials, SecretCredentials, CleartextCredentials
    from sagelib.groups import GroupRistretto255, GroupDecaf448, GroupP256, GroupP384, GroupP521
    from sagelib.opaque_common import I2OSP, OS2IP, I2OSP_le, OS2IP_le, random_bytes, _as_bytes, encode_vector, encode_vector_len, decode_vector, decode_vector_len, to_hex
    from sagelib.opaque_ake import OPAQUE3DH, Configuration
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

default_opaque_configuration = Configuration(
    envelope_mode_internal, 
    oprf_ciphersuites[ciphersuite_ristretto255_sha512], 
    HKDF(hashlib.sha512),
    HMAC(hashlib.sha512),
    hashlib.sha512, 
    MHF("Identity", identity_harden),
    GroupRistretto255(),
)

def test_core_protocol_serialization():
    idU = _as_bytes("Username")
    pwdU = _as_bytes("CorrectHorseBatteryStaple")

    config = default_opaque_configuration 
    group = config.group
    skU, pkU = group.key_gen()
    skU_enc = group.serialize_scalar(skU)
    pkU_enc = group.serialize(pkU)
    skS, pkS = group.key_gen()
    skS_enc = group.serialize_scalar(skS)
    pkS_enc = group.serialize(pkS)
    oprf_seed = random_bytes(config.hash().digest_size)

    core = OPAQUECore(config)
    creds = Credentials(skU_enc, pkU_enc)

    # Run the registration flow to register credentials
    request, metadata = core.create_registration_request(pwdU)
    serialized_request = request.serialize()
    deserialized_request = deserialize_registration_request(
        config, serialized_request)
    assert request == deserialized_request

    response, kU = core.create_registration_response(request, pkS_enc, oprf_seed, idU)
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

    cred_response = core.create_credential_response(cred_request, pkS_enc, oprf_seed, record.envU, idU, record.masking_key)
    serialized_response = cred_response.serialize()
    deserialized_response, length = deserialize_credential_response(
        config, serialized_response)
    assert cred_response == deserialized_response
    assert length == len(serialized_response)

    recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(pwdU, cred_metadata, cred_response)

    # Check that recovered credentials match the registered credentials
    assert export_key == recovered_export_key
    if config.mode == envelope_mode_external:
        assert recovered_skU == skU_enc
        assert recovered_pkS == pkS_enc

def test_registration_and_authentication():
    idU = _as_bytes("Username")
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
    oprf_seed = random_bytes(config.oprf_suite.group.scalar_byte_length())
  
    core = OPAQUECore(config)
    creds = Credentials(skU_enc, pkU_enc)

    request, metadata = core.create_registration_request(pwdU)
    response, kU = core.create_registration_response(request, pkS_enc, oprf_seed, idU)
    record, export_key = core.finalize_request(creds, pwdU, metadata, response)
    
    cred_request, cred_metadata = core.create_credential_request(pwdU)
    cred_response = core.create_credential_response(cred_request, pkS_enc, oprf_seed, record.envU, idU, record.masking_key)
    recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(pwdU, cred_metadata, cred_response)

    assert export_key == recovered_export_key
    if config.mode == envelope_mode_external:
        assert recovered_skU == skU_enc
        assert recovered_pkS == pkS_enc

    cred_request, cred_metadata = core.create_credential_request(badPwdU)
    cred_response = core.create_credential_response(cred_request, pkS_enc, oprf_seed, record.envU, idU, record.masking_key)
    try:
        recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(badPwdU, cred_metadata, cred_response)
        assert False
    except:
        # We expect the MAC authentication tag to fail, so should get here
        pass

def test_3DH():
    idU = _as_bytes("alice")
    credential_identifier = _as_bytes("1234")
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
    for mode in [envelope_mode_internal, envelope_mode_external]:
        for (oprf, fast_hash, mhf, group) in configs:
            for (idU, idS) in [(None, None), (idU, None), (None, idS), (idU, idS)]:
                (skU, pkU) = group.key_gen()
                (skS, pkS) = group.key_gen()
                skU_bytes = group.serialize_scalar(skU)
                pkU_bytes = group.serialize(pkU)
                skS_bytes = group.serialize_scalar(skS)
                pkS_bytes = group.serialize(pkS)
                oprf_seed = random_bytes(fast_hash().digest_size)

                kdf = HKDF(fast_hash)
                mac = HMAC(fast_hash)
                config = Configuration(mode, oprf, kdf, mac, fast_hash, mhf, group)

                creds = Credentials(skU_bytes, pkU_bytes, idU, idS)
                core = OPAQUECore(config)

                reg_request, metadata = core.create_registration_request(pwdU)
                reg_response, kU = core.create_registration_response(reg_request, pkS_bytes, oprf_seed, credential_identifier)
                record, export_key = core.finalize_request(creds, pwdU, metadata, reg_response)

                # TODO(caw): do something else with this
                pkU_enc = record.pkU
                pkU = group.deserialize(pkU_enc)
                pkU_bytes = pkU_enc

                client_kex = OPAQUE3DH(config)
                server_kex = OPAQUE3DH(config)

                ke1 = client_kex.generate_ke1(pwdU, info1, idU, pkU, idS, pkS)
                ke2 = server_kex.generate_ke2(ke1, oprf_seed, credential_identifier, record.envU, record.masking_key, info2, idS, skS, pkS, idU, pkU)
                ke3 = client_kex.generate_ke3(ke2)
                server_session_key = server_kex.finish(ke3)

                assert server_session_key == client_kex.session_key

                inputs = {}
                intermediates = {}
                outputs = {}

                # Protocol inputs
                if idU:
                    inputs["client_identity"] = to_hex(idU)
                if idS:
                    inputs["server_identity"] = to_hex(idS)
                inputs["oprf_seed"] = to_hex(oprf_seed)
                inputs["credential_identifier"] = to_hex(credential_identifier)
                inputs["password"] = to_hex(pwdU)
                if mode == envelope_mode_external:
                    inputs["client_private_key"] = to_hex(skU_bytes)
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
                inputs["masking_nonce"] = to_hex(server_kex.core.masking_nonce)
                inputs["blind_registration"] = to_hex(config.oprf_suite.group.serialize_scalar(metadata))
                inputs["blind_login"] = to_hex(config.oprf_suite.group.serialize_scalar(client_kex.cred_metadata))
                inputs["oprf_key"] = to_hex(config.oprf_suite.group.serialize_scalar(kU))

                # Intermediate computations
                intermediates["client_public_key"] = to_hex(pkU_bytes)
                intermediates["envelope"] = to_hex(record.envU.serialize())
                intermediates["random_pwd"] = to_hex(core.registration_rwdU)
                intermediates["masking_key"] = to_hex(core.masking_key)
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
    test_core_protocol_serialization()
    test_registration_and_authentication()

    formatted_vectors = test_3DH()
    with open(os.path.join(path, "vectors.json"), "w") as fh:
        fh.write(formatted_vectors)

if __name__ == "__main__":
    main()