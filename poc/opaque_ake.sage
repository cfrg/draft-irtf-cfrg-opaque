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
    from sagelib.opaque_common import derive_secret, hkdf_expand_label, hkdf_expand, hkdf_extract, I2OSP, OS2IP, OS2IP_le, random_bytes, xor, encode_vector, encode_vector_len, decode_vector, decode_vector_len, to_hex, OPAQUE_NONCE_LENGTH
    from sagelib.opaque_core import OPAQUECore
    from sagelib.opaque_messages import deserialize_credential_request, deserialize_credential_response, Envelope
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x
    _strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )

class Configuration(object):
    def __init__(self, oprf_suite, kdf, mac, hash, mhf, group, context):
        self.oprf_suite = oprf_suite
        self.kdf = kdf
        self.mac = mac
        self.hash = hash
        self.mhf = mhf
        self.group = group
        self.context = context
        self.Npk = group.element_byte_length()
        self.Nsk = group.scalar_byte_length()
        self.Nm = mac.output_size()
        self.Nx = hash().digest_size
        self.Nok = oprf_suite.group.scalar_byte_length()
        self.Nh = hash().digest_size
        self.Nn = OPAQUE_NONCE_LENGTH
        self.Ne = self.Nn + self.Nm

class KeyExchange(object):
    def __init__(self):
        pass

    def json(self):
        raise Exception("Not implemented")

    def generate_ke1(self, l1):
        raise Exception("Not implemented")

    def generate_ke2(self, l1, l2, ke1, pkU, skS, pkS):
        raise Exception("Not implemented")

    def generate_ke3(self, l2, ake2, ke1_state, pkS, skU, pkU):
        raise Exception("Not implemented")

TripleDHComponents = namedtuple("TripleDHComponents", "pk1 sk1 pk2 sk2 pk3 sk3")

class OPAQUE3DH(KeyExchange):
    def __init__(self, config):
        self.config = config
        self.core = OPAQUECore(config)

    def json(self):
        return {
            "Name": "3DH",
            "Group": self.config.group.name,
            "OPRF": to_hex(I2OSP(self.config.oprf_suite.identifier, 2)),
            "KDF": self.config.kdf.name,
            "MAC": self.config.mac.name,
            "Hash": self.config.hash().name.upper(),
            "MHF": self.config.mhf.name,
            "Context": to_hex(self.config.context),
            "Nh": str(self.config.Nh),
            "Npk": str(self.config.Npk),
            "Nsk": str(self.config.Nsk),
            "Nm": str(self.config.Nm),
            "Nx": str(self.config.Nx),
            "Nok": str(self.config.Nok),
        }

    def derive_3dh_keys(self, dh_components, info):
        dh1 = dh_components.sk1 * dh_components.pk1
        dh2 = dh_components.sk2 * dh_components.pk2
        dh3 = dh_components.sk3 * dh_components.pk3

        dh1_encoded = self.config.group.serialize(dh1)
        dh2_encoded = self.config.group.serialize(dh2)
        dh3_encoded = self.config.group.serialize(dh3)
        ikm = dh1_encoded + dh2_encoded + dh3_encoded

        prk = hkdf_extract(self.config, bytes([]), ikm)
        handshake_secret = derive_secret(self.config, prk, _as_bytes("HandshakeSecret"), info)
        session_key = derive_secret(self.config, prk, _as_bytes("SessionKey"), info)

        # client_mac_key = HKDF-Expand-Label(handshake_secret, "ClientMAC", "", Hash.length)
        # server_mac_key = HKDF-Expand-Label(handshake_secret, "ServerMAC", "", Hash.length)
        # handshake_encrypt_key = HKDF-Expand-Label(handshake_secret, "HandshakeKey", "", key_length)
        Nh = self.config.hash().digest_size
        empty_info = bytes([])
        server_mac_key = hkdf_expand_label(self.config, handshake_secret, _as_bytes("ServerMAC"), empty_info, Nh)
        client_mac_key = hkdf_expand_label(self.config, handshake_secret, _as_bytes("ClientMAC"), empty_info, Nh)

        return server_mac_key, client_mac_key, session_key, handshake_secret

    def generate_ke1(self, pwdU, idU, pkU, idS, pkS):
        cred_request, cred_metadata = self.core.create_credential_request(pwdU)
        serialized_request = cred_request.serialize()

        nonceU = random_bytes(OPAQUE_NONCE_LENGTH)
        (eskU, epkU) = self.config.group.key_gen()
        ke1 = TripleDHMessageInit(nonceU, self.config.group.serialize(epkU))

        # transcript1 includes the concatenation of the values:
        # cred_request, nonceU, epkU
        hasher = self.config.hash()
        hasher.update(_as_bytes("RFCXXXX"))
        hasher.update(encode_vector(self.config.context))
        if idU:
            hasher.update(encode_vector_len(idU, 2))
        else:
            hasher.update(encode_vector_len(self.config.group.serialize(pkU), 2))
        hasher.update(serialized_request)
        hasher.update(nonceU)
        hasher.update(self.config.group.serialize(epkU))

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
        self.hasher = hasher
        self.pkU = pkU

        return serialized_request + ke1.serialize()

    def generate_ke2(self, msg, oprf_seed, credential_identifier, envU, masking_key, idS, skS, pkS, idU, pkU):
        cred_request, offset = deserialize_credential_request(self.config, msg)
        serialized_request = cred_request.serialize()
        ke1 = deserialize_tripleDH_init(self.config, msg[offset:])

        pkS_bytes = self.config.group.serialize(pkS)
        info = _as_bytes("")
        cred_response = self.core.create_credential_response(cred_request, pkS_bytes, oprf_seed, envU, credential_identifier, masking_key, info)
        serialized_response = cred_response.serialize()

        nonceS = random_bytes(OPAQUE_NONCE_LENGTH)
        (eskS, epkS) = self.config.group.key_gen()
        nonceU = ke1.nonceU
        epkU = self.config.group.deserialize(ke1.epkU)

        hasher = self.config.hash()
        hasher.update(_as_bytes("RFCXXXX"))
        hasher.update(encode_vector(self.config.context))
        if idU:
            hasher.update(encode_vector_len(idU, 2))
        else:
            hasher.update(encode_vector_len(self.config.group.serialize(pkU), 2))
        hasher.update(serialized_request)
        hasher.update(nonceU)
        hasher.update(self.config.group.serialize(epkU))
        if idS:
            hasher.update(encode_vector_len(idS, 2))
        else:
            hasher.update(encode_vector_len(self.config.group.serialize(pkS), 2))
        hasher.update(serialized_response)
        hasher.update(nonceS)
        hasher.update(self.config.group.serialize(epkS))

        # K3dh = epkU^eskS || epkU^skS || pkU^eskS
        dh_components = TripleDHComponents(epkU, eskS, epkU, skS, pkU, eskS)
        server_mac_key, client_mac_key, session_key, handshake_secret = self.derive_3dh_keys(dh_components, hasher.digest())
        transcript_hash = hasher.digest()

        mac = hmac.digest(server_mac_key, transcript_hash, self.config.hash)
        ake2 = TripleDHMessageRespond(nonceS, self.config.group.serialize(epkS), mac)

        self.nonceS = nonceS
        self.hasher = hasher
        self.eskS = eskS
        self.epkS = epkS
        self.server_mac_key = server_mac_key
        self.ake2 = ake2
        self.client_mac_key = client_mac_key
        self.session_key = session_key
        self.server_mac = mac
        self.handshake_secret = handshake_secret
        self.masking_nonce = cred_response.masking_nonce

        return serialized_response + ake2.serialize()

    def generate_ke3(self, msg):
        cred_response, offset = deserialize_credential_response(self.config, msg)
        serialized_response = cred_response.serialize()
        ake2 = deserialize_tripleDH_respond(self.config, msg[offset:])
        info = _as_bytes("")
        skU_bytes, pkS_bytes, export_key = self.core.recover_credentials(self.pwdU, self.cred_metadata, cred_response, info, self.idU, self.idS)
        skU = OS2IP(skU_bytes)
        if "ristretto" in self.config.group.name or "decaf" in self.config.group.name:
            skU = OS2IP_le(skU_bytes)
        pkS = self.config.group.deserialize(pkS_bytes)
        
        idS = self.idS
        pkS = self.pkS
        eskU = self.eskU
        nonceS = ake2.nonceS
        epkS = self.config.group.deserialize(ake2.epkS)
        mac = ake2.mac

        hasher = self.hasher
        if idS:
            hasher.update(encode_vector_len(idS, 2))
        else:
            hasher.update(encode_vector_len(self.config.group.serialize(pkS), 2))
        hasher.update(serialized_response)
        hasher.update(nonceS)
        hasher.update(self.config.group.serialize(epkS))

        # K3dh = epkS^eskU || pkS^eskU || epkS^skU
        dh_components = TripleDHComponents(epkS, eskU, pkS, eskU, epkS, skU)
        server_mac_key, client_mac_key, session_key, handshake_secret = self.derive_3dh_keys(dh_components, hasher.digest())

        transcript_hash = hasher.digest()

        server_mac = hmac.digest(server_mac_key, transcript_hash, self.config.hash)
        assert server_mac == mac

        self.session_key = session_key
        self.server_mac_key = server_mac_key
        self.client_mac_key = client_mac_key
        self.handshake_secret = handshake_secret
        self.export_key = export_key

        # transcript3 == transcript2, plus server_mac
        hasher.update(server_mac)
        transcript_hash = hasher.digest()

        client_mac = hmac.digest(client_mac_key, transcript_hash, self.config.hash)
        ke3 = TripleDHMessageFinish(client_mac)

        return ke3.serialize()

    def finish(self, msg):
        ke3 = deserialize_tripleDH_finish(self.config, msg)
        
        client_mac_key = self.client_mac_key
        self.hasher.update(self.server_mac)
        transcript_hash = self.hasher.digest()

        client_mac = hmac.digest(client_mac_key, transcript_hash, self.config.hash)
        assert client_mac == ke3.mac

        return self.session_key

# struct {
#      opaque nonceU[32];
#      opaque epkU[LK];
#  } KE1M;
def deserialize_tripleDH_init(config, data):
    nonceU = data[0:OPAQUE_NONCE_LENGTH]
    epkU_bytes = data[OPAQUE_NONCE_LENGTH:]
    length = config.oprf_suite.group.element_byte_length()
    if len(epkU_bytes) != length:
        raise Exception("Invalid epkU length: %d %d" % (len(epkU_bytes), length))
    return TripleDHMessageInit(nonceU, epkU_bytes)

class TripleDHMessageInit(object):
    def __init__(self, nonceU, epkU):
        self.nonceU = nonceU
        self.epkU = epkU

    def serialize(self):
        return self.nonceU + self.epkU

# struct {
#      opaque nonceS[32];
#      opaque epkS[LK];
#      opaque mac[LH];
#  } KE2M;
def deserialize_tripleDH_respond(config, data):
    length = config.oprf_suite.group.element_byte_length()
    nonceS = data[0:OPAQUE_NONCE_LENGTH]
    epkS = data[OPAQUE_NONCE_LENGTH:OPAQUE_NONCE_LENGTH+length]
    mac = data[OPAQUE_NONCE_LENGTH+length:]
    if len(mac) != config.hash().digest_size:
        raise Exception("Invalid MAC length: %d %d" % (len(mac), config.hash().digest_size))
    return TripleDHMessageRespond(nonceS, epkS, mac)

class TripleDHMessageRespond(object):
    def __init__(self, nonceS, epkS, mac):
        self.nonceS = nonceS
        self.epkS = epkS
        self.mac = mac

    def serialize(self):
        return self.nonceS + self.epkS + self.mac

# struct {
#      opaque mac[LH];
#  } KE3M;
def deserialize_tripleDH_finish(config, data):
    if len(data) != config.hash().digest_size:
        raise Exception("Invalid MAC length: %d %d" % (len(data), config.hash().digest_size))
    return TripleDHMessageFinish(data)

class TripleDHMessageFinish(object):
    def __init__(self, mac):
        self.mac = mac

    def serialize(self):
        return self.mac
