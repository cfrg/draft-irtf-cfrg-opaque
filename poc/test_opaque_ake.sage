#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib

try:
    from sagelib.opaque import default_opaque_configuration, OPAQUECore 
    from sagelib.opaque_common import encode_vector, decode_vector, random_bytes, _as_bytes
    from sagelib.opaque_messages import InnerEnvelope, deserialize_inner_envelope, envelope_mode_base, envelope_mode_custom_identifier, \
        Envelope, deserialize_envelope, deserialize_registration_request, deserialize_registration_response, deserialize_registration_upload, \
            deserialize_credential_request, deserialize_credential_response
    from sagelib.opaque_messages import Credentials, SecretCredentials, CleartextCredentials, CustomCleartextCredentials
    from sagelib import ristretto255
    from sagelib.opaque_common import I2OSP, OS2IP, I2OSP_le, OS2IP_le, encode_vector, encode_vector_len, decode_vector, decode_vector_len
    from sagelib.opaque_ake import OPAQUE3DH
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    if isinstance(octet_string, bytes):
        return "" + "".join("{:02x}".format(c) for c in octet_string)
    assert isinstance(octet_string, bytearray)
    return ''.join(format(x, '02x') for x in octet_string)

def test_3dh():
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

    config = default_opaque_configuration
    creds = Credentials(skU_bytes, pkU_bytes)
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

    vector = {}

    # Protocol inputs
    vector["client_identifier"] = to_hex(idU)
    vector["server_identifier"] = to_hex(idS)
    vector["password"] = to_hex(pwdU)
    vector["client_s_sk"] = to_hex(skU_bytes)
    vector["client_s_pk"] = to_hex(pkU_bytes)
    vector["server_s_sk"] = to_hex(skS_bytes)
    vector["server_s_pk"] = to_hex(pkS_bytes)

    # Protocol messages
    vector["registration_request"] = to_hex(reg_request.serialize())
    vector["blinding_factor_registration"] = to_hex(config.oprf_suite.group.serialize_scalar(metadata))
    vector["registration_response"] = to_hex(reg_response.serialize())
    vector["registration_upload"] = to_hex(record.serialize())
    vector["blinding_factor_login"] = to_hex(config.oprf_suite.group.serialize_scalar(client_kex.cred_metadata))
    vector["credential_request"] = to_hex(ke1)
    vector["credential_response"] = to_hex(ke2)
    vector["credential_finalization"] = to_hex(ke3)

    vector["info1"] = to_hex(info1)
    vector["info2"] = to_hex(info2)
    vector["client_nonce"] = to_hex(client_kex.nonceU)
    vector["server_nonce"] = to_hex(server_kex.nonceS)
    vector["client_e_sk"] = to_hex(I2OSP_le(client_kex.eskU, 32))
    vector["client_e_pk"] = to_hex(ristretto255.ENCODE(*client_kex.epkU))
    vector["server_e_sk"] = to_hex(I2OSP_le(server_kex.eskS, 32))
    vector["server_e_pk"] = to_hex(ristretto255.ENCODE(*server_kex.epkS))
    vector["shared_secret"] = to_hex(server_session_key)

    # Intermediate computations
    vector["oprf_key"] = to_hex(config.oprf_suite.group.serialize_scalar(kU))
    vector["envelope_nonce"] = to_hex(core.envelope_nonce)
    vector["envU"] = to_hex(record.envU.serialize())
    vector["rwdU"] = to_hex(core.registration_rwdU)
    vector["pseudorandom_pad"] = to_hex(core.pseudorandom_pad)
    vector["auth_key"] = to_hex(core.auth_key)
    vector["km2"] = to_hex(client_kex.km2)
    vector["km3"] = to_hex(client_kex.km3)
    vector["ke2"] = to_hex(client_kex.ke2)
    vector["handshake_secret"] = to_hex(client_kex.handshake_secret)

    # Protocol outputs
    vector["export_key"] = to_hex(export_key)

    print(json.dumps(vector, sort_keys=True, indent=2))

def main(path="vectors"):
    test_3dh()

if __name__ == "__main__":
    main()