#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib

try:
    from sagelib.opaque import default_opaque_configuration, OPAQUECore
    from sagelib.opaque_common import encode_vector, decode_vector, random_bytes, _as_bytes
    from sagelib.opaque_messages import deserialize_registration_request, deserialize_registration_response, deserialize_registration_upload, deserialize_credential_request, deserialize_credential_response
    from sagelib.opaque_messages import InnerEnvelope, deserialize_inner_envelope, envelope_mode_base, envelope_mode_custom_identifier, \
        Envelope, deserialize_envelope
    from sagelib.opaque_messages import Credentials, SecretCredentials, CleartextCredentials, CustomCleartextCredentials
    from sagelib import ristretto255
    from sagelib.opaque_common import I2OSP, OS2IP, encode_vector, encode_vector_len, decode_vector, decode_vector_len
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def test_registration_and_authentication():
    pwdU = _as_bytes("opaquerulez")
    badPwdU = _as_bytes("iloveopaque")
    skU = _as_bytes("skU")
    pkU = _as_bytes("pkU")
    pkS = _as_bytes("pkS")

    config = default_opaque_configuration    
    core = OPAQUECore(config)
    creds = Credentials(skU, pkU)

    request, metadata = core.create_registration_request(pwdU)
    response, kU = core.create_registration_response(request, pkS)
    record, export_key = core.finalize_request(creds, pwdU, metadata, response)
    
    cred_request, cred_metadata = core.create_credential_request(pwdU)
    cred_response = core.create_credential_response(cred_request, pkS, kU, record.envU)
    recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(pwdU, cred_metadata, cred_response)

    assert export_key == recovered_export_key
    assert recovered_skU == skU
    assert recovered_pkS == pkS

    cred_request, cred_metadata = core.create_credential_request(badPwdU)
    cred_response = core.create_credential_response(cred_request, pkS, kU, record.envU)
    try:
        recovered_skU, recovered_pkS, recovered_export_key = core.recover_credentials(badPwdU, cred_metadata, cred_response)
        assert False
    except:
        # We expect the MAC authentication tag to fail, so should get here
        pass

def main(path="vectors"):
    test_registration_and_authentication()

if __name__ == "__main__":
    main()
