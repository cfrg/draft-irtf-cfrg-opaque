#!/usr/bin/sage
# vim: syntax=python

import sys
import hmac

from collections import namedtuple

try:
    from sagelib.opaque_common import derive_secret, hkdf_expand_label, hkdf_extract, I2OSP, OS2IP, OS2IP_le, encode_vector, encode_vector_len, to_hex, OPAQUE_NONCE_LENGTH
    from sagelib.opaque_core import OPAQUECore
    from sagelib.opaque_messages import deserialize_credential_request, deserialize_credential_response
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

_as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

class Configuration(object):
    def __init__(self, oprf_suite, kdf, mac, hash, ksf, group, context):
        self.oprf_suite = oprf_suite
        self.kdf = kdf
        self.mac = mac
        self.hash = hash
        self.ksf = ksf
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

    def generate_ke2(self, l1, l2, ke1, client_public_key, server_private_key, server_public_key):
        raise Exception("Not implemented")

    def generate_ke3(self, l2, ake2, ke1_state, server_public_key, client_private_key, client_public_key):
        raise Exception("Not implemented")

TripleDHComponents = namedtuple("TripleDHComponents", "pk1 sk1 pk2 sk2 pk3 sk3")

class OPAQUE3DH(KeyExchange):
    def __init__(self, config, rng):
        self.config = config
        self.core = OPAQUECore(config, rng)
        self.rng = rng

    def json(self):
        return {
            "Name": "3DH",
            "Group": self.config.group.name,
            "OPRF": self.config.oprf_suite.identifier,
            "KDF": self.config.kdf.name,
            "MAC": self.config.mac.name,
            "Hash": self.config.hash().name.upper(),
            "KSF": self.config.ksf.name,
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

    def auth_client_start(self):
            self.client_nonce = self.rng.random_bytes(OPAQUE_NONCE_LENGTH)
            self.eskU = ZZ(self.config.group.random_scalar(self.rng))
            self.epkU_bytes = self.config.group.serialize(self.eskU * self.config.group.generator())

            return TripleDHMessageInit(self.client_nonce, self.epkU_bytes)

    def generate_ke1(self, pwdU):
        cred_request, cred_metadata = self.core.create_credential_request(pwdU)
        serialized_request = cred_request.serialize()

        nonceU = self.rng.random_bytes(OPAQUE_NONCE_LENGTH)
        eskU = ZZ(self.config.group.random_scalar(self.rng))
        epkU = eskU * self.config.group.generator()
        ke1 = TripleDHMessageInit(nonceU, self.config.group.serialize(epkU))

    def generate_ke1(self, password):
        cred_request, cred_metadata = self.core.create_credential_request(password)
        self.serialized_request = cred_request.serialize()
        self.cred_metadata = cred_metadata
        self.password = password

        ke1 = self.auth_client_start()

        return self.serialized_request + ke1.serialize()

    def transcript_hasher(self, serialized_request, serialized_response , client_identity, client_public_key, client_nonce, epkU_bytes, server_identity, server_public_key_bytes, server_nonce, epkS_bytes):
        hasher = self.config.hash()
        hasher.update(_as_bytes("RFCXXXX")) # RFCXXXX
        hasher.update(encode_vector(self.config.context)) # context
        if client_identity: # client identity
            hasher.update(encode_vector_len(client_identity, 2))
        else:
            hasher.update(encode_vector_len(self.config.group.serialize(client_public_key), 2))
        hasher.update(serialized_request)          # ke1: cred request
        hasher.update(client_nonce)                            # ke1: client nonce
        hasher.update(epkU_bytes) # ke1: client keyshare
        if server_identity: # server identity
            hasher.update(encode_vector_len(server_identity, 2))
        else:
            hasher.update(encode_vector_len(server_public_key_bytes, 2))
        hasher.update(serialized_response)              # ke2: cred response
        hasher.update(server_nonce)                            # ke2: server nonce
        hasher.update(epkS_bytes) # ke2: server keyshare

        self.hasher = hasher

        return hasher.digest()

    def auth_server_respond(self, cred_request, cred_response, ke1, server_identity, server_public_key_bytes, server_private_key, client_identity, client_public_key):
        self.server_nonce = self.rng.random_bytes(OPAQUE_NONCE_LENGTH)
        self.eskS = ZZ(self.config.group.random_scalar(self.rng))
        self.epkS = self.eskS * self.config.group.generator()
        epkS_bytes = self.config.group.serialize(self.epkS)
        epkU = self.config.group.deserialize(ke1.epkU)

        transcript_hash = self.transcript_hasher(cred_request.serialize(), cred_response.serialize(), client_identity, client_public_key, ke1.client_nonce, ke1.epkU, server_identity, server_public_key_bytes, self.server_nonce, epkS_bytes)

        # K3dh = epkU^eskS || epkU^skS || pkU^eskS
        dh_components = TripleDHComponents(epkU, self.eskS, epkU, server_private_key, client_public_key, self.eskS)
        server_mac_key, client_mac_key, session_key, handshake_secret = self.derive_3dh_keys(dh_components, self.hasher.digest())

        mac = hmac.digest(server_mac_key, transcript_hash, self.config.hash)
        ake2 = TripleDHMessageRespond(self.server_nonce, epkS_bytes, mac)

        self.server_mac_key = server_mac_key
        self.ake2 = ake2
        self.client_mac_key = client_mac_key
        self.session_key = session_key
        self.server_mac = mac
        self.handshake_secret = handshake_secret

        return ake2

    def generate_ke2(self, msg, oprf_seed, credential_identifier, envU, masking_key, server_identity, server_private_key, server_public_key, client_identity, client_public_key):
        cred_request, offset = deserialize_credential_request(self.config, msg)
        ke1 = deserialize_tripleDH_init(self.config, msg[offset:])

        server_public_key_bytes = self.config.group.serialize(server_public_key)
        cred_response = self.core.create_credential_response(cred_request, server_public_key_bytes, oprf_seed, envU, credential_identifier, masking_key)
        serialized_response = cred_response.serialize()
        self.masking_nonce = cred_response.masking_nonce

        ake2 = self.auth_server_respond(cred_request, cred_response, ke1, server_identity, server_public_key_bytes, server_private_key, client_identity, client_public_key)

        return serialized_response + ake2.serialize()

    def auth_client_finalize(self, cred_response, ake2, client_identity, client_private_key, client_public_key, server_identity, server_public_key, server_public_key_bytes):
            transcript_hash = self.transcript_hasher(self.serialized_request, cred_response.serialize(), client_identity, client_public_key, self.client_nonce, self.epkU_bytes, server_identity, server_public_key_bytes, ake2.server_nonce, ake2.epkS)

            # K3dh = epkS^eskU || pkS^eskU || epkS^skU
            epkS = self.config.group.deserialize(ake2.epkS)
            dh_components = TripleDHComponents(epkS, self.eskU, server_public_key, self.eskU, epkS, client_private_key)
            server_mac_key, client_mac_key, session_key, handshake_secret = self.derive_3dh_keys(dh_components, self.hasher.digest())

            server_mac = hmac.digest(server_mac_key, transcript_hash, self.config.hash)
            assert server_mac == ake2.mac

            self.session_key = session_key
            self.server_mac_key = server_mac_key
            self.client_mac_key = client_mac_key
            self.handshake_secret = handshake_secret

            # transcript3 == transcript2, plus server_mac
            self.hasher.update(server_mac)
            transcript_hash = self.hasher.digest()

            client_mac = hmac.digest(client_mac_key, transcript_hash, self.config.hash)

            return TripleDHMessageFinish(client_mac)

        def generate_ke3(self, msg, client_identity, client_public_key, server_identity):
            cred_response, offset = deserialize_credential_response(self.config, msg)
            ake2 = deserialize_tripleDH_respond(self.config, msg[offset:])
            client_private_key_bytes, server_public_key_bytes, export_key = self.core.recover_credentials(self.password, self.cred_metadata, cred_response, client_identity, server_identity)
            client_private_key = OS2IP(client_private_key_bytes)
            if "ristretto" in self.config.group.name or "decaf" in self.config.group.name:
                client_private_key = OS2IP_le(client_private_key_bytes)
            server_public_key = self.config.group.deserialize(server_public_key_bytes)

            self.export_key = export_key

            ke3 = self.auth_client_finalize(cred_response, ake2, client_identity, client_private_key, client_public_key, server_identity, server_public_key, server_public_key_bytes)

            return ke3.serialize()

        def auth_server_finish(self, msg):
            ke3 = deserialize_tripleDH_finish(self.config, msg)

            client_mac_key = self.client_mac_key
            self.hasher.update(self.server_mac)
            transcript_hash = self.hasher.digest()

            client_mac = hmac.digest(client_mac_key, transcript_hash, self.config.hash)
            assert client_mac == ke3.mac

            return self.session_key

# struct {
#      opaque client_nonce[32];
#      opaque epkU[LK];
#  } KE1M;
def deserialize_tripleDH_init(config, data):
    client_nonce = data[0:OPAQUE_NONCE_LENGTH]
    epkU_bytes = data[OPAQUE_NONCE_LENGTH:]
    length = config.oprf_suite.group.element_byte_length()
    if len(epkU_bytes) != length:
        raise Exception("Invalid epkU length: %d %d" % (len(epkU_bytes), length))
    return TripleDHMessageInit(client_nonce, epkU_bytes)

class TripleDHMessageInit(object):
    def __init__(self, client_nonce, epkU):
        self.client_nonce = client_nonce
        self.epkU = epkU

    def serialize(self):
        return self.client_nonce + self.epkU

# struct {
#      opaque server_nonce[32];
#      opaque epkS[LK];
#      opaque mac[LH];
#  } KE2M;
def deserialize_tripleDH_respond(config, data):
    length = config.oprf_suite.group.element_byte_length()
    server_nonce = data[0:OPAQUE_NONCE_LENGTH]
    epkS = data[OPAQUE_NONCE_LENGTH:OPAQUE_NONCE_LENGTH+length]
    mac = data[OPAQUE_NONCE_LENGTH+length:]
    if len(mac) != config.hash().digest_size:
        raise Exception("Invalid MAC length: %d %d" % (len(mac), config.hash().digest_size))
    return TripleDHMessageRespond(server_nonce, epkS, mac)

class TripleDHMessageRespond(object):
    def __init__(self, server_nonce, epkS, mac):
        self.server_nonce = server_nonce
        self.epkS = epkS
        self.mac = mac

    def serialize(self):
        return self.server_nonce + self.epkS + self.mac

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
