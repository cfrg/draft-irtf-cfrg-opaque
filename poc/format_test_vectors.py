#!/usr/bin/python3
# vim: syntax=python

import sys
import json

config_keys = [
    "OPRF",
    "Hash",
    "KSF",
    "KDF",
    "MAC",
    "Group",
    "Context",
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
    "server_private_key",
    "server_public_key",
    "server_nonce",
    "client_nonce",
    "server_keyshare",
    "client_keyshare",
    "server_private_keyshare",
    "client_private_keyshare",
    "blind_registration",
    "blind_login",
]

intermediate_keys = [
    "client_public_key",
    "auth_key",
    "randomized_pwd",
    "pseudorandom_pad",
    "envelope",
    "handshake_secret",
    "server_mac_key",
    "client_mac_key",
    "oprf_key",
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

### Fake Vector Keys

fake_input_keys = [
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
    "server_nonce",
    "client_nonce",
    "server_keyshare",
    "client_keyshare",
    "server_private_keyshare",
    "client_private_keyshare",
    "blind_registration",
    "blind_login",
    "masking_key",
    "KE1",
]

fake_output_keys = [
    "KE2",
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

def print_vector_inputs(arr, vector):
    for key in arr:
        for input_key in vector["inputs"]:
            if key == input_key:
                wrap_print(key + ":", vector["inputs"][key])

def print_vector_intermediates(arr, vector):
    for key in arr:
        for int_key in vector["intermediates"]:
            if key == int_key:
                wrap_print(key + ":", vector["intermediates"][key])

def print_vector_outputs(arr, vector):
    for key in arr:
        for output_key in vector["outputs"]:
            if key == output_key:
                wrap_print(key + ":", vector["outputs"][key])

def format_vector(vector, i):
    print("\n#### Configuration\n")
    print("~~~")
    print_vector_config(vector)
    print("~~~")
    print("\n#### Input Values\n")
    print("~~~")
    print_vector_inputs(input_keys, vector)
    print("~~~")
    print("\n#### Intermediate Values\n")
    print("~~~")
    print_vector_intermediates(intermediate_keys, vector)
    print("~~~")
    print("\n#### Output Values\n")
    print("~~~")
    print_vector_outputs(output_keys, vector)
    print("~~~")
    print("")

def format_fake_vector(vector, i):
    print("\n#### Configuration\n")
    print("~~~")
    print_vector_config(vector)
    print("~~~")
    print("\n#### Input Values\n")
    print("~~~")
    print_vector_inputs(fake_input_keys, vector)
    print("~~~")
    print("\n#### Output Values\n")
    print("~~~")
    print_vector_outputs(fake_output_keys, vector)
    print("~~~")
    print("")

with open(sys.argv[1], "r") as fh:
    vectors = json.loads(fh.read())
    real_vectors = []
    fake_vectors = []
    for i, vector in enumerate(vectors):
        if vector["config"]["Fake"] == "True":
            fake_vectors.append(vector)
        else:
            real_vectors.append(vector)
    print("## Real Test Vectors {#real-vectors}\n")
    for i, vector in enumerate(real_vectors):
        print("### " + format_vector_name(vector) + " Real Test Vector " + str(i+1))
        format_vector(vector, i)

    print("## Fake Test Vectors {#fake-vectors}\n")
    for i, vector in enumerate(fake_vectors):
        print("### " + format_vector_name(vector) + " Fake Test Vector " + str(i+1))
        format_fake_vector(vector, i)
