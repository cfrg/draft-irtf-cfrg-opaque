#!/usr/bin/python3
# vim: syntax=python

import sys
import json

config_keys = [
    "OPRF",
    "Hash",
    "MHF",
    "KDF",
    "MAC",
    "Name",
    "EnvelopeMode",
    "Group",
    "Nh",
    "Npk",
    "Nsk",
    "Nm",
    "Nx",
    "Nok",
]

input_keys = [
    "client_identity",
    "server_identity",
    "oprf_seed",
    "credential_identifier",
    "password",
    "envelope_nonce",
    "masking_nonce",
    "client_private_key",
    "client_public_key",
    "server_private_key",
    "server_public_key",
    "client_info",
    "server_info",
    "server_nonce",
    "client_nonce",
    "server_keyshare",
    "client_keyshare",
    "server_private_keyshare",
    "client_private_keyshare",
    "blind_registration",
    "blind_login",
    "oprf_key",
]

intermediate_keys = [
    "client_public_key",
    "auth_key",
    "random_pwd",
    "pseudorandom_pad",
    "envelope",
    "handshake_secret",
    "handshake_encrypt_key",
    "server_mac_key",
    "client_mac_key",
]

output_keys = [
    "registration_request",
    "registration_response",
    "registration_upload",
    "KE1",
    "KE2",
    "KE3",
    "export_key",
    "session_key",
]

def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    if isinstance(octet_string, bytes):
        return "" + "".join("{:02x}".format(c) for c in octet_string)
    assert isinstance(octet_string, bytearray)
    return ''.join(format(x, '02x') for x in octet_string)

def wrap_print(arg, *args):
    line_length = 69
    string = arg + " " + " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            print(hunk)

def format_vector_name(vector):
    return "OPAQUE-" + vector["config"]["Name"]

def print_vector_config(vector):
    for key in config_keys:
        for config_key in vector["config"]:
            if key == config_key:
                wrap_print(key + ":", vector["config"][key])

def print_vector_inputs(vector):
    for key in input_keys:
        for input_key in vector["inputs"]:
            if key == input_key:
                wrap_print(key + ":", vector["inputs"][key])

def print_vector_intermediates(vector):
    for key in intermediate_keys:
        for int_key in vector["intermediates"]:
            if key == int_key:
                wrap_print(key + ":", vector["intermediates"][key])

def print_vector_outputs(vector):
    for key in output_keys:
        for output_key in vector["outputs"]:
            if key == output_key:
                wrap_print(key + ":", vector["outputs"][key])

def format_vector(vector, i):
    print("\n### Configuration\n")
    print("~~~")
    print_vector_config(vector)
    print("~~~")
    print("\n### Input Values\n")
    print("~~~")
    print_vector_inputs(vector)
    print("~~~")
    print("\n### Intermediate Values\n")
    print("~~~")
    print_vector_intermediates(vector)
    print("~~~")
    print("\n### Output Values\n")
    print("~~~")
    print_vector_outputs(vector)
    print("~~~")
    print("")

with open(sys.argv[1], "r") as fh:
    vectors = json.loads(fh.read())
    for i, vector in enumerate(vectors):
        print("## " + format_vector_name(vector) + " Test Vector " + str(i+1))
        format_vector(vector, i)
