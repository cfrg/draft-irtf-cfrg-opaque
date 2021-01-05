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
    from sagelib.opaque import encode_vector_len, derive_secret, hkdf_extract, hkdf_expand_label, I2OSP
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

def random_bytes(n):
    return os.urandom(n)

class KeyExchange(object):
    def __init__(self):
        pass

    def generate_ke1(self, l1):
        raise Exception("Not implemented")

    def generate_ke2(self, l1, l2, ke1, pkU, skS, pkS):
        raise Exception("Not implemented")

    def generate_ke3(self, l2, ke2, ke1_state, pkS, skU, pkU):
        raise Exception("Not implemented")

class KeyExchangeMessage(object):
    def __init__(self, message_type, components):
        self.message_type = message_type
        self.components = components

    def serialize(self):
        def concat(a, b):
            return a + b
        return I2OSP(self.message_type, 1) + reduce(concat, map(lambda c : c, self.components))

TripleDHComponents = namedtuple("TripleDHComponents", "pk1 sk1 pk2 sk2 pk3 sk3")

class TripleDH(KeyExchange):
    def __init__(self, config):
        KeyExchange.__init__(self)
        self.config = config

    def derive_3dh_keys(self, dh_components, client_nonce, server_nonce, pkU, pkS):
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
        empty_vector = encode_vector_len(bytes([]), 2)
        info = _as_bytes("3DH keys") + encode_vector_len(client_nonce, 2) + encode_vector_len(server_nonce, 2) \
            + empty_vector + empty_vector # idU and idS are empty

        output_size = self.config.hash_alg().digest_size
        prk = hkdf_extract(self.config, bytes([]), ikm)
        handshake_secret = derive_secret(self.config, prk, _as_bytes("handshake secret"), info)
        session_key = derive_secret(self.config, prk, _as_bytes("handshake secret"), info)

        # Km2 = HKDF-Expand-Label(handshake_secret, "client mac", "", Hash.length)
        # Km3 = HKDF-Expand-Label(handshake_secret, "server mac", "", Hash.length)
        # Ke2 = HKDF-Expand-Label(handshake_secret, "client enc", "", key_length)
        # Ke3 = HKDF-Expand-Label(handshake_secret, "server enc", "", key_length)
        # TODO(caw): move these constant labels to actual constants
        Nh = self.config.hash_alg().digest_size
        Nk = 16
        empty_info = bytes([])
        km2 = hkdf_expand_label(self.config, handshake_secret, _as_bytes("client mac"), empty_info, Nh)
        km3 = hkdf_expand_label(self.config, handshake_secret, _as_bytes("server mac"), empty_info, Nh)
        ke2 = hkdf_expand_label(self.config, handshake_secret, _as_bytes("server mac"), empty_info, Nk)
        ke3 = hkdf_expand_label(self.config, handshake_secret, _as_bytes("server mac"), empty_info, Nk)

        return km2, km3, ke2, ke3, session_key

    def generate_ke1(self, l1):
        client_nonce = random_bytes(32)
        (eskU, epkU) = ristretto255.keygen()
        ke1 = TripleDHMessageInit(client_nonce, ristretto255.ENCODE(*epkU))

        hasher = hashlib.sha256()
        hasher.update(l1)
        hasher.update(client_nonce)
        hasher.update(ristretto255.ENCODE(*epkU))

        return (client_nonce, eskU, epkU, hasher), KeyExchangeMessage(0x04, [l1, ke1])

    def generate_ke2(self, l1, l2, ke1, pkU, skS, pkS):
        server_nonce = random_bytes(32)
        (eskS, epkS) = ristretto255.keygen()
        client_nonce = ke1.components[1].client_nonce
        epkU = ristretto255.DECODE(ke1.components[1].epkU)

        # K3dh = epkU^eskS || epkU^skS || pkU^eskS
        dh_components = TripleDHComponents(epkU, eskS, epkU, skS, pkU, eskS)
        km2, km3, _, _, session_key = self.derive_3dh_keys(dh_components, client_nonce, server_nonce, pkU, pkS)

        # transcript2 includes the concatenation of the values:
        # credential_request, nonceU, info1, idU, epkU, credential_response, nonceS, info2, epkS, Einfo2;¶
        hasher = hashlib.sha256()
        hasher.update(l1)
        hasher.update(client_nonce)
        hasher.update(ristretto255.ENCODE(*epkU))
        hasher.update(l2)
        hasher.update(server_nonce)
        hasher.update(ristretto255.ENCODE(*epkS))
        transcript_hash = hasher.digest()

        mac = hmac.digest(km2, transcript_hash, hashlib.sha256)
        ke2 = TripleDHMessageRespond(server_nonce, ristretto255.ENCODE(*epkS), mac)

        return (hasher, km3, session_key), KeyExchangeMessage(0x05, [l2, ke2])

    def generate_ke3(self, l2, ke2, ke1_state, pkS, skU, pkU):
        server_nonce = ke2.components[1].server_nonce
        epkS = ristretto255.DECODE(ke2.components[1].epkS)
        (client_nonce, eskU, epkU, hasher) = ke1_state

        # K3dh = epkS^eskU || pkS^eskU || epkS^skU
        dh_components = TripleDHComponents(epkS, eskU, pkS, eskU, epkS, skU)
        km2, km3, _, _, session_key = self.derive_3dh_keys(dh_components, client_nonce, server_nonce, pkU, pkS)

        hasher.update(l2)
        hasher.update(server_nonce)
        hasher.update(ristretto255.ENCODE(*epkS))
        transcript_hash = hasher.digest()

        server_mac = hmac.digest(km2, transcript_hash, hashlib.sha256)
        assert server_mac == ke2.components[1].mac

        # transcript3 includes the concatenation of all elements in transcript2 followed by info3, Einfo3
        # TODO(caw): include info3 and Einfo3
        transcript_hash = hasher.digest()

        client_mac = hmac.digest(km3, transcript_hash, hashlib.sha256)
        ke3 = TripleDHMessageFinish(client_mac)

        return session_key, KeyExchangeMessage(0x06, [ke3])

    def finish(self, ke3, ke2_state):
        (hasher, km3, session_key) = ke2_state

        # transcript3 includes the concatenation of all elements in transcript2 followed by info3, Einfo3
        # TODO(caw): include info3 and Einfo3
        transcript_hash = hasher.digest()

        client_mac = hmac.digest(km3, transcript_hash, hashlib.sha256)
        assert client_mac == ke3.components[0].mac

        return session_key

# struct {
#      opaque client_nonce[32];
#      opaque epkU[LK];
#  } KE1M;
def deserialize_tripleDH_init(data):
    pass

class TripleDHMessageInit(object):
    def __init__(self, client_nonce, epkU):
        self.client_nonce = client_nonce
        self.epkU = epkU

    def serialize(self):
        pass

# struct {
#      opaque server_nonce[32];
#      opaque epkS[LK];
#      opaque mac[LH];
#  } KE2M;
def deserialize_tripleDH_respond(data):
    pass

class TripleDHMessageRespond(object):
    def __init__(self, server_nonce, epkS, mac):
        self.server_nonce = server_nonce
        self.epkS = epkS
        self.mac = mac

    def serialize(self):
        pass

# struct {
#      opaque mac[LH];
#  } KE3M;
def deserialize_tripleDH_finish(data):
    pass

class TripleDHMessageFinish(object):
    def __init__(self, mac):
        self.mac = mac

    def serialize(self):
        pass