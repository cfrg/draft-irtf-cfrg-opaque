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


# class Protocol(object):
#     def __init__(self):
#         self.inputs = [
#             {
#                 "idU": _as_bytes("alice"),
#                 "idS": _as_bytes("bob"),
#                 "pwdU": _as_bytes("CorrectHorseBatteryStaple"),
#                 "info1": _as_bytes("hello bob"),
#                 "info2": _as_bytes("greetings alice"),
#             }
#         ]

#     def run_vector(self, vector):
#         raise Exception("Not implemented")

#     def run(self, config):
#         vectors = []
#         for x in self.inputs:
#             # idU = x["idU"]
#             # idS = x["idS"]
#             pwdU = x["pwdU"]
#             info1 = x["info1"]
#             info2 = x["info1"]

#             # TODO(caw): call this from the configuration?
#             (skU, pkU) = ristretto255.keygen()
#             (skS, pkS) = ristretto255.keygen()
#             skU_bytes = I2OSP_le(skU, 32)
#             pkU_bytes = ristretto255.ENCODE(*pkU)
#             skS_bytes = I2OSP_le(skS, 32)
#             pkS_bytes = ristretto255.ENCODE(*pkS)

#             idU = pkU_bytes
#             idS = pkS_bytes

#             creds = Credentials(skU_bytes, pkU_bytes)

#             # Run the registration flow to register credentials
#             request, reg_metadata = create_registration_request(config, pwdU)
#             response, kU = create_registration_response(config, request, pkS_bytes)
#             record, export_key, nonce = finalize_request(config, creds, pwdU, reg_metadata, response)

#             kex = TripleDH(config)

#             # Run the authentication flow to recover credentials
#             cred_request, cred_metadata = create_credential_request(
#                 config, pwdU)
#             serialized_cred_request = cred_request.serialize()
#             # deserialized_request = deserialize_credential_request(
#             #     config, serialized_cred_request)
#             # assert cred_request == deserialized_request

#             ke1_state, ke1, ke1_serialized = kex.generate_ke1(serialized_cred_request, info1)
#             (client_nonce, eskU, epkU, hasher) = ke1_state
#             epkU_bytes = ristretto255.ENCODE(*epkU)

#             cred_response = create_credential_response(
#                 config, cred_request, pkS_bytes, kU, record.envU)
#             serialized_cred_response = cred_response.serialize()
#             # deserialized_response = deserialize_credential_response(
#             #     config, serialized_cred_response)
#             # assert cred_response == deserialized_response

#             ke2_state, ke2, ke2_serialized = kex.generate_ke2(serialized_cred_request, serialized_cred_response, ke1, info2, idU, pkU, idS, skS, pkS)
#             (server_nonce, hasher, km3, eskS, epkS, session_key) = ke2_state
#             epkS_bytes = ristretto255.ENCODE(*epkS)

#             recovered_skU_bytes, recovered_pkS_bytes, recovered_export_key, rwdU, pseudorandom_pad, auth_key = recover_credentials(
#                 config, pwdU, cred_metadata, cred_response)

#             recovered_skU = OS2IP(recovered_skU_bytes)
#             recovered_pkS = ristretto255.DECODE(recovered_pkS_bytes)

#             client_session_key, ke3, ke3_serialized = kex.generate_ke3(serialized_cred_response, ke2, ke1_state, idS, recovered_pkS, idU, recovered_skU, pkU)
            
#             server_session_key = kex.finish(ke3, ke2_state)

#             # Check that recovered credentials match the registered credentials
#             assert export_key == recovered_export_key
#             assert recovered_skU_bytes == skU_bytes
#             assert recovered_pkS_bytes == pkS_bytes
#             assert client_session_key == server_session_key

#             vector = {}

#             # Protocol inputs
#             vector["idU"] = to_hex(idU)
#             vector["idS"] = to_hex(idS)
#             vector["pwdU"] = to_hex(pwdU)
#             vector["skU"] = to_hex(skU_bytes)
#             vector["pkU"] = to_hex(pkU_bytes)
#             vector["skS"] = to_hex(skS_bytes)
#             vector["pkS"] = to_hex(pkS_bytes)

#             # Protocol messages
#             vector["RegistrationRequest"] = to_hex(serialized_reg_request)
#             vector["RegistrationRequestBlind"] = to_hex(config.oprf_suite.group.serialize_scalar(reg_metadata))
#             vector["RegistrationResponse"] = to_hex(serialized_reg_response)
#             vector["RegistrationUpload"] = to_hex(serialized_record)
#             vector["CredentialRequest"] = to_hex(serialized_cred_request)
#             vector["CredentialRequestBlind"] = to_hex(config.oprf_suite.group.serialize_scalar(cred_metadata))
#             vector["CredentialResponse"] = to_hex(serialized_cred_response)
#             vector["KE1"] = to_hex(ke1_serialized)
#             vector["KE2"] = to_hex(ke2_serialized)
#             vector["KE3"] = to_hex(ke3_serialized)

#             vector["info1"] = to_hex(info1)
#             vector["info2"] = to_hex(info2)
#             vector["client_nonce"] = to_hex(client_nonce)
#             vector["server_nonce"] = to_hex(server_nonce)
#             vector["epkU"] = to_hex(epkU_bytes)
#             vector["epkS"] = to_hex(epkS_bytes)
#             vector["shared_secret"] = to_hex(server_session_key)

#             # Intermediate computations
#             vector["kU"] = to_hex(config.oprf_suite.group.serialize_scalar(kU))
#             vector["envU_nonce"] = to_hex(nonce)
#             vector["envU"] = to_hex(record.envU.serialize())
#             vector["rwdU"] = to_hex(rwdU)
#             vector["pseudorandom_pad"] = to_hex(pseudorandom_pad)
#             vector["auth_key"] = to_hex(auth_key)

#             # Protocol outputs
#             vector["export_key"] = to_hex(export_key)

#             vectors.append(vector)

#         return vectors

# TODO(caw): instantiate and test out the new core, and work on minimizing the API!!
def test_3dh_new():
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
    # vector["CredentialRequest"] = to_hex(serialized_cred_request)
    # vector["CredentialRequestBlind"] = to_hex(config.oprf_suite.group.serialize_scalar(cred_metadata))
    # vector["CredentialResponse"] = to_hex(serialized_cred_response)
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
    (skU, pkU) = ristretto255.keygen()
    (skS, pkS) = ristretto255.keygen()

    skU_bytes = to_hex(I2OSP_le(skU, 32))
    pkU_bytes = to_hex(ristretto255.ENCODE(*pkU))
    skS_bytes = to_hex(I2OSP_le(skS, 32))
    pkS_bytes = to_hex(ristretto255.ENCODE(*pkS))

    print("skU,", skU_bytes)
    print("pkU,", pkU_bytes)
    print("skS,", skS_bytes)
    print("pkS,", pkS_bytes)

    # runner = Protocol()
    # vectors = runner.run(default_opaque_configuration)
    # with open(path + "/allVectors.json", 'wt') as f:
    #     json.dump(vectors, f, sort_keys=True, indent=2)
    #     f.write("\n")

    test_3dh_new()

if __name__ == "__main__":
    main()