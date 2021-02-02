#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib

try:
    from sagelib.opaque import default_opaque_configuration_base, default_opaque_configuration_custom, OPAQUECore 
    from sagelib.opaque_common import encode_vector, decode_vector, random_bytes, _as_bytes
    from sagelib.opaque_messages import InnerEnvelope, deserialize_inner_envelope, envelope_mode_base, envelope_mode_custom_identifier, \
        Envelope, deserialize_envelope, deserialize_registration_request, deserialize_registration_response, deserialize_registration_upload, \
            deserialize_credential_request, deserialize_credential_response
    from sagelib.opaque_messages import Credentials, SecretCredentials, CleartextCredentials, CustomCleartextCredentials
    from sagelib import ristretto255
    from sagelib.opaque_common import I2OSP, OS2IP, I2OSP_le, OS2IP_le, encode_vector, encode_vector_len, decode_vector, decode_vector_len, to_hex
    from sagelib.opaque_ake import OPAQUE3DH
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def test_3DH():
    idU = _as_bytes("alice")
    idS = _as_bytes("bob")
    pwdU = _as_bytes("CorrectHorseBatteryStaple")
    info1 = _as_bytes("hello bob")
    info2 = _as_bytes("greetings alice")

    (skU, pkU) = ristretto255.keygen()
    (skS, pkS) = ristretto255.keygen()
    skU_bytes = I2OSP_le(skU, 32)
    pkU_bytes = ristretto255.ENCODE(*pkU)
    skS_bytes = I2OSP_le(skS, 32)
    pkS_bytes = ristretto255.ENCODE(*pkS)

    idU = pkU_bytes
    idS = pkS_bytes

    vectors = []
    for config in [default_opaque_configuration_base, default_opaque_configuration_custom]:
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
        inputs["client_identity"] = to_hex(idU)
        inputs["server_identity"] = to_hex(idS)
        inputs["password"] = to_hex(pwdU)
        inputs["client_private_key"] = to_hex(skU_bytes)
        inputs["client_public_key"] = to_hex(pkU_bytes)
        inputs["server_private_key"] = to_hex(skS_bytes)
        inputs["server_public_key"] = to_hex(pkS_bytes)

        # Protocol messages
        intermediates["registration_request"] = to_hex(reg_request.serialize())
        intermediates["blind_registration"] = to_hex(config.oprf_suite.group.serialize_scalar(metadata))
        intermediates["registration_response"] = to_hex(reg_response.serialize())
        intermediates["registration_upload"] = to_hex(record.serialize())
        intermediates["blind_login"] = to_hex(config.oprf_suite.group.serialize_scalar(client_kex.cred_metadata))
        intermediates["KE1"] = to_hex(ke1)
        intermediates["KE2"] = to_hex(ke2)
        intermediates["KE3"] = to_hex(ke3)

        intermediates["client_info"] = to_hex(info1)
        intermediates["server_info"] = to_hex(info2)
        intermediates["client_nonce"] = to_hex(client_kex.nonceU)
        intermediates["server_nonce"] = to_hex(server_kex.nonceS)
        intermediates["client_private_keyshare"] = to_hex(I2OSP_le(client_kex.eskU, 32))
        intermediates["client_keyshare"] = to_hex(ristretto255.ENCODE(*client_kex.epkU))
        intermediates["server_private_keyshare"] = to_hex(I2OSP_le(server_kex.eskS, 32))
        intermediates["server_keyshare"] = to_hex(ristretto255.ENCODE(*server_kex.epkS))

        # Intermediate computations
        intermediates["kU"] = to_hex(config.oprf_suite.group.serialize_scalar(kU))
        intermediates["envelope_nonce"] = to_hex(core.envelope_nonce)
        intermediates["envelope"] = to_hex(record.envU.serialize())
        intermediates["prk"] = to_hex(core.registration_rwdU)
        intermediates["pseudorandom_pad"] = to_hex(core.pseudorandom_pad)
        intermediates["auth_key"] = to_hex(core.auth_key)
        intermediates["server_mac_key"] = to_hex(client_kex.server_mac_key)
        intermediates["client_mac_key"] = to_hex(client_kex.client_mac_key)
        intermediates["handshake_encrypt_key"] = to_hex(client_kex.handshake_encrypt_key)
        intermediates["handshake_secret"] = to_hex(client_kex.handshake_secret)

        # Protocol outputs
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
    formatted_vectors = test_3DH()
    with open(os.path.join(path, "vectors.json"), "w") as fh:
        fh.write(formatted_vectors)

if __name__ == "__main__":
    main()