#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import hmac
import hashlib
import struct

from collections import namedtuple

try:
    from sagelib.opaque_common import derive_secret, hkdf_expand_label, hkdf_expand, hkdf_extract, I2OSP, OS2IP_le, random_bytes, xor, encode_vector, encode_vector_len, decode_vector, decode_vector_len, to_hex
    from sagelib.opaque import OPAQUECore
    from sagelib.opaque_messages import deserialize_credential_request, deserialize_credential_response, envelope_mode_base, envelope_mode_custom_identifier
    from sagelib import ristretto255
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x
    _strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )

class KeyExchange(object):
    def __init__(self):
        pass

    def json(self):
        raise Exception("Not implemented")

    def generate_ke1(self, l1):
        raise Exception("Not implemented")

    def generate_ke2(self, l1, l2, ke1, pkU, skS, pkS):
        raise Exception("Not implemented")

    def generate_ke3(self, l2, handshake_encrypt_key, ke1_state, pkS, skU, pkU):
        raise Exception("Not implemented")

TripleDHComponents = namedtuple("TripleDHComponents", "pk1 sk1 pk2 sk2 pk3 sk3")

class OPAQUE3DH(KeyExchange):
    def __init__(self, config):
        self.config = config
        self.core = OPAQUECore(config)

    def json(self):
        return {
            "Name": "3DH",
            "Group": self.config.oprf_suite.group.name,
            "EnvelopeMode": to_hex(I2OSP(self.config.mode, 1)),
            "OPRF": to_hex(I2OSP(self.config.oprf_suite.identifier, 2)),
            "Hash": self.config.hash().name.upper(),
            "SlowHash": self.config.slow_hash.name,
        }

    def derive_3dh_keys(self, dh_components, client_nonce, server_nonce, idU, pkU, idS, pkS):
        dh1 = ristretto255._edw_mul(dh_components.sk1, dh_components.pk1)
        dh2 = ristretto255._edw_mul(dh_components.sk2, dh_components.pk2)
        dh3 = ristretto255._edw_mul(dh_components.sk3, dh_components.pk3)

        dh1_encoded = ristretto255.ENCODE(*dh1)
        dh2_encoded = ristretto255.ENCODE(*dh2)
        dh3_encoded = ristretto255.ENCODE(*dh3)
        ikm = dh1_encoded + dh2_encoded + dh3_encoded

        # info = "3DH keys" || I2OSP(len(nonceU), 2) || nonceU
        #           || I2OSP(len(nonceS), 2) || nonceS
        #           || I2OSP(len(idU), 2) || idU
        #           || I2OSP(len(idS), 2) || idS
        info = _as_bytes("3DH keys") \
            + encode_vector_len(client_nonce, 2) + encode_vector_len(server_nonce, 2) \
            + encode_vector_len(idU, 2) + encode_vector_len(idS, 2)

        prk = hkdf_extract(self.config, bytes([]), ikm)
        handshake_secret = derive_secret(self.config, prk, _as_bytes("handshake secret"), info)
        session_key = derive_secret(self.config, prk, _as_bytes("session secret"), info)

        # client_mac_key = HKDF-Expand-Label(handshake_secret, "client mac", "", Hash.length)
        # server_mac_key = HKDF-Expand-Label(handshake_secret, "server mac", "", Hash.length)
        # handshake_encrypt_key = HKDF-Expand-Label(handshake_secret, "handshake enc", "", key_length)
        Nh = self.config.hash().digest_size
        empty_info = bytes([])
        server_mac_key = hkdf_expand_label(self.config, handshake_secret, _as_bytes("server mac"), empty_info, Nh)
        client_mac_key = hkdf_expand_label(self.config, handshake_secret, _as_bytes("client mac"), empty_info, Nh)
        handshake_encrypt_key = hkdf_expand_label(self.config, handshake_secret, _as_bytes("handshake enc"), empty_info, Nh)

        return server_mac_key, client_mac_key, handshake_encrypt_key, session_key, handshake_secret

    def generate_ke1(self, pwdU, info1, idU, skU, pkU, idS, pkS):
        cred_request, cred_metadata = self.core.create_credential_request(pwdU)
        serialized_request = cred_request.serialize()

        nonceU = random_bytes(32)
        (eskU, epkU) = ristretto255.keygen()
        ke1 = TripleDHMessageInit(nonceU, info1, ristretto255.ENCODE(*epkU))

        # transcript1 includes the concatenation of the values:
        # cred_request, nonceU, info1, epkU
        transcript1 = serialized_request + nonceU + encode_vector(info1) + ristretto255.ENCODE(*epkU)

        self.cred_request = cred_request
        self.cred_metadata = cred_metadata
        self.idU = idU
        self.idS = idS
        self.pwdU = pwdU
        self.pkS = pkS
        self.eskU = eskU
        self.epkU = epkU
        self.nonceU = nonceU
        self.cred_metadata = cred_metadata
        self.transcript1 = transcript1
        self.pkU = pkU

        return serialized_request + ke1.serialize()

    def generate_ke2(self, msg, kU, envU, info2, idS, skS, pkS, idU, pkU):
        cred_request, offset = deserialize_credential_request(self.config, msg)
        serialized_request = cred_request.serialize()
        ke1 = deserialize_tripleDH_init(self.config, msg[offset:])

        pkS_bytes = ristretto255.ENCODE(*pkS)
        cred_response = self.core.create_credential_response(cred_request, pkS_bytes, kU, envU)
        serialized_response = cred_response.serialize()

        nonceS = random_bytes(32)
        (eskS, epkS) = ristretto255.keygen()
        nonceU = ke1.nonceU
        info1 = ke1.info1
        epkU = ristretto255.DECODE(ke1.epkU)

        # K3dh = epkU^eskS || epkU^skS || pkU^eskS
        dh_components = TripleDHComponents(epkU, eskS, epkU, skS, pkU, eskS)
        server_mac_key, client_mac_key, handshake_encrypt_key, session_key, handshake_secret = self.derive_3dh_keys(dh_components, nonceU, nonceS, idU, pkU, idS, pkS)

        # Encrypt e_info2
        pad = hkdf_expand(self.config, handshake_encrypt_key, _as_bytes("encryption pad"), len(info2))
        e_info2 = xor(pad, info2)

        # transcript2 includes the concatenation of the values:
        # credential_request, nonceU, info1, epkU, credential_response, nonceS, epkS, Einfo2;
        transcript2 = serialized_request + nonceU + encode_vector(info1) + ke1.epkU + serialized_response + nonceS + ristretto255.ENCODE(*epkS) + encode_vector(e_info2)
        server_mac = hmac.digest(server_mac_key, transcript2, hashlib.sha512)
        ke2 = TripleDHMessageRespond(nonceS, ristretto255.ENCODE(*epkS), e_info2, server_mac)

        # transcript3 is transcript2 + server_mac
        transcript3 = transcript2 + server_mac

        self.nonceS = nonceS
        self.transcript3 = transcript3
        self.eskS = eskS
        self.epkS = epkS
        self.server_mac_key = server_mac_key
        self.handshake_encrypt_key = handshake_encrypt_key
        self.client_mac_key = client_mac_key
        self.session_key = session_key
        self.server_mac = server_mac
        self.handshake_secret = handshake_secret

        return serialized_response + ke2.serialize()

    def generate_ke3(self, msg):
        cred_response, offset = deserialize_credential_response(self.config, msg)
        serialized_response = cred_response.serialize()
        handshake_encrypt_key = deserialize_tripleDH_respond(self.config, msg[offset:])

        skU_bytes, pkS_bytes, export_key = self.core.recover_credentials(self.pwdU, self.cred_metadata, cred_response, self.idU, self.idS)
        skU = OS2IP_le(skU_bytes)
        pkS = ristretto255.DECODE(pkS_bytes)

        idU = self.idU
        idS = self.idS
        pkU = self.pkU
        pkS = self.pkS
        eskU = self.eskU
        nonceU = self.nonceU
        nonceS = handshake_encrypt_key.nonceS
        epkS = ristretto255.DECODE(handshake_encrypt_key.epkS)
        e_info2 = handshake_encrypt_key.e_info2
        mac = handshake_encrypt_key.mac

        # K3dh = epkS^eskU || pkS^eskU || epkS^skU
        dh_components = TripleDHComponents(epkS, eskU, pkS, eskU, epkS, skU)
        server_mac_key, client_mac_key, handshake_encrypt_key, session_key, handshake_secret = self.derive_3dh_keys(dh_components, nonceU, nonceS, idU, pkU, idS, pkS)

        # transcript2 = transcript, plus ke2 components
        transcript2 = self.transcript1 + serialized_response + nonceS + ristretto255.ENCODE(*epkS) + encode_vector(e_info2)
        server_mac = hmac.digest(server_mac_key, transcript2, hashlib.sha512)
        assert server_mac == mac

        # transcript3 = transcript2, plus server_mac
        transcript3 = transcript2 + server_mac

        # TODO(caw): decrypt e_info2 and pass it to the application

        self.session_key = session_key
        self.server_mac_key = server_mac_key
        self.handshake_encrypt_key = handshake_encrypt_key
        self.client_mac_key = client_mac_key
        self.handshake_secret = handshake_secret

        client_mac = hmac.digest(client_mac_key, transcript3, self.config.hash)
        ke3 = TripleDHMessageFinish(client_mac)

        return ke3.serialize()

    def finish(self, msg):
        ke3 = deserialize_tripleDH_finish(self.config, msg)
        client_mac_key = self.client_mac_key
        client_mac = hmac.digest(client_mac_key, self.transcript3, self.config.hash)
        assert client_mac == ke3.mac

        return self.session_key

# struct {
#      opaque nonceU[32];
#      opaque info<0..2^16-1>;
#      opaque epkU[LK];
#  } KE1M;
def deserialize_tripleDH_init(config, data):
    nonceU = data[0:32]
    info, offset = decode_vector(data[32:])
    epkU_bytes = data[32+offset:]
    length = config.oprf_suite.group.element_byte_length()
    if len(epkU_bytes) != length:
        raise Exception("Invalid epkU length")
    return TripleDHMessageInit(nonceU, info, epkU_bytes)

class TripleDHMessageInit(object):
    def __init__(self, nonceU, info1, epkU):
        self.nonceU = nonceU
        self.info1 = info1
        self.epkU = epkU

    def serialize(self):
        return self.nonceU + encode_vector(self.info1) + self.epkU

# struct {
#      opaque nonceS[32];
#      opaque epkS[LK];
#      opaque e_info2<0..2^16-1>;
#      opaque mac[LH];
#  } KE2M;
def deserialize_tripleDH_respond(config, data):
    length = config.oprf_suite.group.element_byte_length()
    nonceS = data[0:32]
    epkS = data[32:32+length]
    e_info2, offset = decode_vector(data[32+length:])
    mac = data[32+length+offset:]
    if len(mac) != config.hash().digest_size:
        raise Exception("Invalid MAC length")
    return TripleDHMessageRespond(nonceS, epkS, e_info2, mac)

class TripleDHMessageRespond(object):
    def __init__(self, nonceS, epkS, e_info2, mac):
        self.nonceS = nonceS
        self.epkS = epkS
        self.e_info2 = e_info2
        self.mac = mac

    def serialize(self):
        return self.nonceS + self.epkS + encode_vector(self.e_info2) + self.mac

# struct {
#      opaque mac[LH];
#  } KE3M;
def deserialize_tripleDH_finish(config, data):
    if len(data) != config.hash().digest_size:
        raise Exception("Invalid MAC length")
    return TripleDHMessageFinish(data)

class TripleDHMessageFinish(object):
    def __init__(self, mac):
        self.mac = mac

    def serialize(self):
        return self.mac