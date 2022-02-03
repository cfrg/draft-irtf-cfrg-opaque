---
title: The OPAQUE Asymmetric PAKE Protocol
abbrev: OPAQUE
docname: draft-irtf-cfrg-opaque-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: D. Bourdrez
    name: Daniel Bourdrez
    email: d@bytema.re
 -
    ins: H. Krawczyk
    name: Hugo Krawczyk
    organization: Algorand Foundation
    email: hugokraw@gmail.com
 -
    ins: K. Lewi
    name: Kevin Lewi
    organization: Novi Research
    email: lewi.kevin.k@gmail.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    organization: Cloudflare, Inc.
    email: caw@heapingbits.net

informative:

  Boyen09:
    title: "HPAKE: Password Authentication Secure against Cross-Site User Impersonation"
    author:
      -
        ins: X. Boyen
        name: Xavier Boyen

    seriesinfo: Cryptology and Network Security (CANS)
    date: 2009

  BG04:
    title: The static Diffie-Hellman problem
    author:
      -
        ins: D. Brown
        name: Daniel R. L. Brown
      -
        ins: R. Galant
        name: Robert P. Galant

    seriesinfo: http://eprint.iacr.org/2004/306
    date: 2004

  Canetti01:
    title: "Universally composable security: A new paradigm for cryptographic
protocols"
    author:
      -
        ins: R. Canetti
        name: Ran Canetti

    seriesinfo: IEEE Symposium on Foundations of Computer Science (FOCS)
    date: 2001

  Cheon06:
    title: Security analysis of the strong Diffie-Hellman problem
    author:
      -
        ins: J. H. Cheon
        name: Jung Hee Cheon

    seriesinfo: Euroctypt 2006
    date: 2006

  FK00:
    title: Server-assisted generation of a strong secret from a password
    author:
      -
        ins: W. Ford
        name: Warwick Ford
      -
        ins: B. S. Kaliski, Jr
        name: Burton S. Kaliski, Jr

    seriesinfo: WETICE
    date: 2000

  FIPS202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    date: Aug, 2015
    author:
      -
        org: National Institute of Standards and Technology (NIST)

  GMR06:
    title: "A method for making password-based key exchange resilient to server compromise"
    author:
      -
        ins: C. Gentry
        name: Craig Gentry
      -
        ins: P. MacKenzie
        name: Phil MacKenzie
      -
        ins: Z, Ramzan
        name: Zulfikar Ramzan

    seriesinfo: CRYPTO
    date: 2006

  AuCPace:
    title: "AuCPace: Efficient verifier-based PAKE protocol tailored for the IIoT"
    author:
      -
        ins: B. Haase
        name: Bjorn Haase
      -
        ins: B. Labrique
        name: Benoit Labrique

    seriesinfo: http://eprint.iacr.org/2018/286
    date: 2018

  keyagreement: DOI.10.6028/NIST.SP.800-56Ar3

  OPAQUE:
    title: "OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks"
    # see the quotes above? Needed because of the embedded colon.
    author:
      -
        ins: S. Jarecki
        name: Stanislaw Jarecki
      -
        ins: H. Krawczyk
        name: Hugo Krawczyk
      -
        ins: J. Xu
        name: Jiayu Xu
    seriesinfo: Eurocrypt
    date: 2018

  JKKX16:
    title: "Highly-efficient and composable password-protected secret sharing (or: how to protect your bitcoin wallet online)"
    # see the quotes above? Needed because of the embedded colon.
    author:
      -
        ins: S. Jarecki
        name: Stanislaw Jarecki
      -
        ins: A. Kiayias
        name: Aggelos Kiayias
      -
        ins: H. Krawczyk
        name: Hugo Krawczyk
      -
        ins: J. Xu
        name: Jiayu Xu
    seriesinfo: IEEE European Symposium on Security and Privacy
    date: 2016

  LGR20:
    title: Partitioning Oracle Attacks
    target: https://eprint.iacr.org/2020/1491.pdf
    author:
      -
        ins: J. Len
        name: Julia Len
      -
        ins: P. Grubbs
        name: Paul Grubbs
      -
        ins: T. Ristenpart
        name: Thomas Ristenpart
  HMQV:
    title: "HMQV: A high-performance secure Diffie-Hellman protocol"
    author:
      -
        ins: H. Krawczyk
        name: Hugo Krawczyk

    seriesinfo: CRYPTO
    date: 2005

  SPAKE2plus:
    title: "Security Analysis of SPAKE2+"
    author:
      -
        ins: V. Shoup
        name: Victor Shoup

    seriesinfo: http://eprint.iacr.org/2020/313
    date: 2020

  SIGNAL:
    title: "Simplifying OTR deniability"
    seriesinfo: https://signal.org/blog/simplifying-otr-deniability
    date: 2016

  WhatsAppE2E:
    title: Security of End-to-End Encrypted Backups
    target: https://scontent.whatsapp.net/v/t39.8562-34/241394876_546674233234181_8907137889500301879_n.pdf/WhatsApp_Security_Encrypted_Backups_Whitepaper.pdf?ccb=1-5&_nc_sid=2fbf2a&_nc_ohc=Y3PFzd-3LG4AX9AdA8_&_nc_ht=scontent.whatsapp.net&oh=01_AVwwbFhPNWAn-u9VV4wqetjL2T9rX2pDmXwlk0aus4YrKA&oe=620029BC
    authors:
      -
        ins: WhatsApp
        name: WhatsApp

  RFC2945:
  RFC5869:
  RFC8125:
  RFC8446:

--- abstract

This document describes the OPAQUE protocol, a secure asymmetric
password-authenticated key exchange (aPAKE) that supports mutual
authentication in a client-server setting without reliance on PKI and
with security against pre-computation attacks upon server compromise.
In addition, the protocol provides forward secrecy and the ability to
hide the password from the server, even during password registration.
This document specifies the core OPAQUE protocol and one instantiation
based on 3DH.

--- middle

# Introduction {#intro}

Password authentication is ubiquitous in many applications. In a common
implementation, a client authenticates to a server by sending its client
ID and password to the server over a secure connection. This makes
the password vulnerable to server mishandling, including accidentally
logging the password or storing it in plaintext in a database. Server
compromise resulting in access to these plaintext passwords is not an
uncommon security incident, even among security-conscious organizations.
Moreover, plaintext password authentication over secure channels such as
TLS is also vulnerable to cases where TLS may fail, including PKI
attacks, certificate mishandling, termination outside the security
perimeter, visibility to TLS-terminating intermediaries, and more.

Asymmetric (or Augmented) Password Authenticated Key Exchange (aPAKE)
protocols are designed to provide password authentication and
mutually authenticated key exchange in a client-server setting without
relying on PKI (except during client registration) and without
disclosing passwords to servers or other entities other than the client
machine. A secure aPAKE should provide the best possible security for a
password protocol. Indeed, some attacks are inevitable, such as
online impersonation attempts with guessed client passwords and offline
dictionary attacks upon the compromise of a server and leakage of its
credential file. In the latter case, the attacker learns a mapping of
a client's password under a one-way function and uses such a mapping to
validate potential guesses for the password. Crucially important is
for the password protocol to use an unpredictable one-way mapping.
Otherwise, the attacker can pre-compute a deterministic list of mapped
passwords leading to almost instantaneous leakage of passwords upon
server compromise.

This document describes OPAQUE, a PKI-free secure aPAKE that is secure
against pre-computation attacks. OPAQUE provides forward secrecy with
respect to password leakage while also hiding the password from the
server, even during password registration. OPAQUE allows applications
to increase the difficulty of offline dictionary attacks via iterated
hashing or other key stretching schemes. OPAQUE is also extensible, allowing
clients to safely store and retrieve arbitrary application data on servers
using only their password.

OPAQUE is defined and proven as the composition of three functionalities:
an oblivious pseudorandom function (OPRF), a key recovery mechanism,
and an authenticated key exchange (AKE) protocol. It can be seen
as a "compiler" for transforming any suitable AKE protocol into a secure
aPAKE protocol. (See {{security-considerations}} for requirements of the
OPRF and AKE protocols.) This document specifies one OPAQUE instantiation
based on 3DH {{SIGNAL}}. Other instantiations are possible, as discussed in
{{alternate-akes}}, but their details are out of scope for this document.
In general, the modularity of OPAQUE's design makes it easy to integrate
with additional AKE protocols, e.g., TLS or HMQV, and with future ones such
as those based on post-quantum techniques.

OPAQUE consists of two stages: registration and authenticated key exchange.
In the first stage, a client registers its password with the server and stores
information used to recover authentication credentials on the server. Recovering these
credentials can only be done with knowledge of the client password. In the second
stage, a client uses its password to recover those credentials and subsequently
uses them as input to an AKE protocol.

The name OPAQUE is a homonym of O-PAKE where O is for Oblivious. The name
OPAKE was taken.

This draft complies with the requirements for PAKE protocols set forth in
{{RFC8125}}.

## Requirements Notation

{::boilerplate bcp14}

## Notation {#notation}

The following functions are used throughout this document:

- I2OSP and OS2IP: Convert a byte string to and from a non-negative integer as
  described in Section 4 of {{?RFC8017}}. Note that these functions operate on
  byte strings in big-endian byte order.
- concat(x0, ..., xN): Concatenate byte strings. For example,
  `concat(0x01, 0x0203, 0x040506) = 0x010203040506`.
- random(n): Generate a cryptographically secure pseudorandom byte string of length `n` bytes.
- xor(a,b): Apply XOR to byte strings. For example, `xor(0xF0F0, 0x1234) = 0xE2C4`.
  It is an error to call this function with arguments of unequal length.
- ct_equal(a, b): Return `true` if `a` is equal to `b`, and false otherwise.
  The implementation of this function must be constant-time in the length of `a`
  and `b`, which are assumed to be of equal length, irrespective of the values `a`
  or `b`.

Except if said otherwise, random choices in this specification refer to
drawing with uniform distribution from a given set (i.e., "random" is short
for "uniformly random"). Random choices can be replaced with fresh outputs from
a cryptographically strong pseudorandom generator, according to the requirements
in {{!RFC4086}}, or pseudorandom function. For convenience, we define `nil` as a
lack of value.

All protocol messages and structures defined in this document use the syntax from
{{?RFC8446, Section 3}}.

# Cryptographic Dependencies {#dependencies}

OPAQUE depends on the following cryptographic protocols and primitives:

- Oblivious Pseudorandom Function (OPRF); {{deps-oprf}}
- Key Derivation Function (KDF); {{deps-symmetric}}
- Message Authenticate Code (MAC); {{deps-symmetric}}
- Cryptographic Hash Function; {{deps-hash}}
- Memory-Hard Function (MHF); {{deps-hash}}
- Key Recovery Mechanism; {{deps-keyrec}}
- Authenticated Key Exchange (AKE) protocol; {{deps-ake}}

This section describes these protocols and primitives in more detail. Unless said
otherwise, all random nonces and key derivation seeds used in these dependencies and
the rest of the OPAQUE protocol are of length `Nn` and `Nseed` bytes, respectively,
where `Nn` = `Nseed` = 32.

## Oblivious Pseudorandom Function {#deps-oprf}

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol between client and
server for computing a PRF such that the client learns the PRF output and neither party learns
the input of the other. This specification uses the the OPRF defined in {{!I-D.irtf-cfrg-voprf}},
Version -08, with the following API and parameters:

- Blind(x): Convert input `x` into an element of the OPRF group, randomize it
  by some scalar `r`, producing `M`, and output (`r`, `M`).
- Evaluate(k, M, info): Evaluate input element `M` using private key `k` and
  public input (or metadata) `info`, yielding output element `Z`.
- Finalize(x, r, Z, info): Finalize the OPRF evaluation using input `x`,
  random scalar `r`, evaluation output `Z`, and public input (or metadata)
  `info`, yielding output `y`.
- DeriveKeyPair(seed): Derive a private and public key pair deterministically
  from a seed.
- Noe: The size of a serialized OPRF group element.
- Nok: The size of an OPRF private key.

The public input `info` is currently set to nil.

Note that we only need the base mode variant (as opposed to the verifiable mode
variant) of the OPRF described in {{I-D.irtf-cfrg-voprf}}. The implementation of
DeriveKeyPair based on {{I-D.irtf-cfrg-voprf}} is below:

~~~
DeriveKeyPair

Input:
- seed, pseudo-random byte sequence used as a seed.

Output:
- private_key, a private key.
- public_key, the associated public key.

def DeriveKeyPair(seed):
  private_key = HashToScalar(seed, dst="OPAQUE-DeriveKeyPair")
  public_key = ScalarBaseMult(private_key)
  return (private_key, public_key)
~~~

HashToScalar(msg, dst) is as specified in {{I-D.irtf-cfrg-voprf, Section 2.1}}.

## Key Derivation Function and Message Authentication Code {#deps-symmetric}

A Key Derivation Function (KDF) is a function that takes some source of initial
keying material and uses it to derive one or more cryptographically strong keys.
This specification uses a KDF with the following API and parameters:

- Extract(salt, ikm): Extract a pseudorandom key of fixed length `Nx` bytes from
  input keying material `ikm` and an optional byte string `salt`.
- Expand(prk, info, L): Expand a pseudorandom key `prk` using optional string `info`
  into `L` bytes of output keying material.
- Nx: The output size of the `Extract()` function in bytes.

This specification also makes use of a collision resistant Message Authentication Code
(MAC) with the following API and parameters:

- MAC(key, msg): Compute a message authentication code over input `msg` with key
  `key`, producing a fixed-length output of `Nm` bytes.
- Nm: The output size of the `MAC()` function in bytes.

## Hash Functions {#deps-hash}

This specification makes use of a collision-resistant hash function with the following
API and parameters:

- Hash(msg): Apply a cryptographic hash function to input `msg`, producing a
  fixed-length digest of size `Nh` bytes.
- Nh: The output size of the `Hash()` function in bytes.

A Memory Hard Function (MHF) is a slow and expensive cryptographic hash function
with the following API:

- Stretch(msg, params): Apply a key stretching function with parameters
  `params` to stretch the input `msg` and harden it against offline
  dictionary attacks. This function also needs to satisfy collision resistance.

## Key Recovery Method {#deps-keyrec}

OPAQUE relies on a key recovery mechanism for storing authentication
material on the server and recovering it on the client. This material
is encapsulated in an envelope, whose structure, encoding,
and size must be specified by the key recovery mechanism. The size of
the envelope is denoted `Ne` and may vary between mechanisms.

The key recovery storage mechanism takes as input a private seed and outputs
an envelope. The retrieval process takes as input a private seed and envelope
and outputs authentication material. The signatures for these functionalities
are as follows:

- Store(private_seed): build and return an `Envelope` structure and the client's
public key.
- Recover(private_seed, envelope): recover and return the authentication
material for the AKE from the Envelope. This function raises an error if the
private seed cannot be used for recovering authentication material from the
input envelope.

The key recovery mechanism MUST return an error when trying to recover
authentication material from an envelope with a private seed that was not used
in producing the envelope.

Moreover, it MUST be compatible with the chosen AKE. For example, the key
recovery mechanism specified in {{key-recovery}} directly recovers a private key
from a seed, and the cryptographic primitive in the AKE must therefore support
such a possibility.

If applications implement {{preventing-client-enumeration}}, they MUST use the
same mechanism throughout their lifecycle in order to avoid activity leaks due
to switching.

## Authenticated Key Exchange (AKE) Protocol {#deps-ake}

OPAQUE additionally depends on a three-message Authenticated Key Exchange (AKE)
protocol which satisfies the forward secrecy and KCI properties discussed in
{{security-considerations}}.

The AKE must define three messages `AuthInit`, `AuthResponse` and `AuthFinish`
and provide the following functions for the client:

- Start(): Initiate the AKE by producing message `AuthInit`.
- ClientFinish(client_identity, client_private_key,
server_identity, server_public_key, `AuthInit`): upon receipt of the server's
response `AuthResponse`, complete the protocol for the client, produce
`AuthFinish`.

The AKE protocol must provide the following functions for the server:

- Response(server_identity, server_private_key, client_identity,
client_public_key, `AuthInit`): upon receipt of a client's request `AuthInit`,
engage in the AKE.
- ServerFinish(`AuthFinish`): upon receipt of a client's final AKE message
`AuthFinish`, complete the protocol for the server.

Both ClientFinish and ServerFinish return an error if authentication failed.
In this case, clients and servers MUST NOT use any outputs from the protocol,
such as `session_key` or `export_key` (defined below).

Prior to the execution of these functions, both the client and the server MUST
agree on a configuration; see {{configurations}} for details.

This specification defines one particular AKE based on 3DH;
see {{ake-protocol}}. 3DH assumes a prime-order group as described in
{{I-D.irtf-cfrg-voprf, Section 2.1}}.

# Protocol Overview {#protocol-overview}

OPAQUE consists of two stages: registration and authenticated key exchange.
In the first stage, a client registers its password with the server and stores
its credential file on the server. In the second stage the client recovers its
authentication material and uses it to perform a mutually authenticated key
exchange.

## Setup

Previously to both stages, the client and server agree on a configuration, which
fully specifies the cryptographic algorithm dependencies necessary to run the
protocol; see {{configurations}} for details.
The client chooses its password, and the server chooses its own pair
of keys (server_private_key and server_public_key) for the
AKE, and chooses a seed (oprf_seed) of Nh bytes for the OPRF.
The server can use the same pair of keys with multiple
clients and can opt to use multiple seeds (so long as they are kept consistent for
each client).

## Registration

Registration is the only part in OPAQUE that requires a server-authenticated
and confidential channel, either physical, out-of-band, PKI-based, etc.

The client inputs its credentials, which includes its password and user
identifier, and the server inputs its parameters, which includes its private key
and other information.

The client output of this stage is a single value `export_key` that the client
may use for application-specific purposes, e.g., to encrypt additional
information for storage on the server. The server does not have access to this
`export_key`.

The server output of this stage is a record corresponding to the client's
registration that it stores in a credential file alongside other client
registrations as needed.

The registration flow is shown below:

~~~
    creds                                   parameters
      |                                         |
      v                                         v
    Client                                    Server
    ------------------------------------------------
                registration request
             ------------------------->
                registration response
             <-------------------------
                      record
             ------------------------->
   ------------------------------------------------
      |                                         |
      v                                         v
  export_key                                 record
~~~

These messages are named `RegistrationRequest`, `RegistrationResponse`, and
`Record`, respectively. Their contents and wire format are defined in
{{registration-messages}}.

## Online Authentication

In this second stage, a client obtains credentials previously registered
with the server, recovers private key material using the password, and
subsequently uses them as input to the AKE protocol. As in the registration
phase, the client inputs its credentials, including its password and user
identifier, and the server inputs its parameters and the credential file record
corresponding to the client. The client outputs two values, an `export_key`
(matching that from registration) and a `session_key`, the latter of which
is the primary AKE output. The server outputs a single value `session_key`
that matches that of the client. Upon completion, clients and servers can
use these values as needed.

The authenticated key exchange flow is shown below:

~~~
    creds                             (parameters, record)
      |                                         |
      v                                         v
    Client                                    Server
    ------------------------------------------------
                   AKE message 1
             ------------------------->
                   AKE message 2
             <-------------------------
                   AKE message 3
             ------------------------->
   ------------------------------------------------
      |                                         |
      v                                         v
(export_key, session_key)                  session_key
~~~

These messages are named `KE1`, `KE2`, and `KE3`, respectively. They carry the
messages of the concurrent execution of the key recovery process (OPRF) and the
authenticated key exchange (AKE):

- `KE1` is composed of the `CredentialRequest` and `AuthInit` messages
- `KE2` is composed of the `CredentialResponse` and `AuthResponse` messages
- `KE3` represents the `AuthFinish` message

The `CredentialRequest` and `CredentialResponse` message contents and wire
format are specified in {{cred-retrieval}}, and those of `AuthInit`,
`AuthResponse` and `AuthFinish` are specified in {{ake-messages}}.

The rest of this document describes the details of these stages in detail.
{{client-material}} describes how client credential information is
generated, encoded, stored on the server on registration, and recovered on
login. {{offline-phase}} describes the first registration stage of the protocol,
and {{online-phase}} describes the second authentication stage of the protocol.
{{configurations}} describes how to instantiate OPAQUE using different
cryptographic dependencies and parameters.

# Client Credential Storage and Key Recovery {#client-material}

OPAQUE makes use of a structure called `Envelope` to manage client credentials.
The client creates its `Envelope` on registration and sends it to the server for
storage. On every login, the server sends this `Envelope` to the client so it can
recover its key material for use in the AKE.

Future variants of OPAQUE may use different key recovery mechanisms. See {{key-recovery}} for details.

Applications may pin key material to identities if desired. If no identity is given
for a party, its value MUST default to its public key. The following types of
application credential information are considered:

- client_private_key: The encoded client private key for the AKE protocol.
- client_public_key: The encoded client public key for the AKE protocol.
- server_public_key: The encoded server public key for the AKE protocol.
- client_identity: The client identity. This is an application-specific value,
  e.g., an e-mail address or an account name. If not specified, it defaults
  to the client's public key.
- server_identity: The server identity. This is typically a domain name, e.g., example.com.
  If not specified, it defaults to the server's public key. See {{identities}} for
  information about this identity.

These credential values are used in the `CleartextCredentials` structure as follows:

~~~
struct {
  uint8 server_public_key[Npk];
  uint8 server_identity<1..2^16-1>;
  uint8 client_identity<1..2^16-1>;
} CleartextCredentials;
~~~

The function CreateCleartextCredentials constructs a `CleartextCredentials` structure given
application credential information.

~~~
CreateCleartextCredentials

Input:
- server_public_key, The encoded server public key for the AKE protocol.
- client_public_key, The encoded client public key for the AKE protocol.
- server_identity, The optional encoded server identity.
- client_identity, The optional encoded client identity.

Output:
- cleartext_credentials, a CleartextCredentials structure

def CreateCleartextCredentials(server_public_key, client_public_key,
                               server_identity, client_identity):
  # Set identities as public keys if no application-layer identity is provided
  if server_identity == nil
    server_identity = server_public_key
  if client_identity == nil
    client_identity = client_public_key

  Create CleartextCredentials cleartext_credentials with
    (server_public_key, server_identity, client_identity)
  return cleartext_credentials
~~~

## Key Recovery {#key-recovery}

This specification defines a key recovery mechanism that uses the stretched OPRF
output as a seed to directly derive the private and public key using the
`DeriveAuthKeyPair()` function defined in {{key-creation}}.

### Envelope Structure {#envelope-structure}

The key recovery mechanism defines its `Envelope` as follows:

~~~
struct {
  uint8 nonce[Nn];
  uint8 auth_tag[Nm];
} Envelope;
~~~

nonce: A unique nonce of length `Nn` used to protect this Envelope.

auth_tag: Authentication tag protecting the contents of the envelope, covering
the envelope nonce, and `CleartextCredentials`.

### Envelope Creation {#envelope-creation}

Clients create an `Envelope` at registration with the function `Store` defined
below.

~~~
Store

Input:
- randomized_pwd, randomized password.
- server_public_key, The encoded server public key for
  the AKE protocol.
- server_identity, The optional encoded server identity.
- client_identity, The optional encoded client identity.

Output:
- envelope, the client's `Envelope` structure.
- client_public_key, the client's AKE public key.
- masking_key, an encryption key used by the server with the sole purpose
  of defending against client enumeration attacks.
- export_key, an additional client key.

def Store(randomized_pwd, server_public_key, server_identity, client_identity):
  envelope_nonce = random(Nn)
  masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
  auth_key = Expand(randomized_pwd, concat(envelope_nonce, "AuthKey"), Nh)
  export_key = Expand(randomized_pwd, concat(envelope_nonce, "ExportKey"), Nh)
  seed = Expand(randomized_pwd, concat(envelope_nonce, "PrivateKey"), Nseed)
  (_, client_public_key) = DeriveAuthKeyPair(seed)

  cleartext_creds =
    CreateCleartextCredentials(server_public_key, client_public_key,
                               server_identity, client_identity)
  auth_tag = MAC(auth_key, concat(envelope_nonce, cleartext_creds))

  Create Envelope envelope with (envelope_nonce, auth_tag)
  return (envelope, client_public_key, masking_key, export_key)
~~~

### Envelope Recovery {#envelope-recovery}

Clients recover their `Envelope` during login with the `Recover` function
defined below.

~~~
Recover

Input:
- randomized_pwd, randomized password.
- server_public_key, The encoded server public key for the AKE protocol.
- envelope, the client's `Envelope` structure.
- server_identity, The optional encoded server identity.
- client_identity, The optional encoded client identity.

Output:
- client_private_key, The encoded client private key for the AKE protocol.
- export_key, an additional client key.

Exceptions:
- KeyRecoveryError, when the key fails to be recovered

def Recover(randomized_pwd, server_public_key, envelope,
            server_identity, client_identity):
  auth_key = Expand(randomized_pwd, concat(envelope.nonce, "AuthKey"), Nh)
  export_key = Expand(randomized_pwd, concat(envelope.nonce, "ExportKey", Nh)
  seed = Expand(randomized_pwd, concat(envelope.nonce, "PrivateKey"), Nseed)
  (client_private_key, client_public_key) = DeriveAuthKeyPair(seed)

  cleartext_creds = CreateCleartextCredentials(server_public_key,
                      client_public_key, server_identity, client_identity)
  expected_tag = MAC(auth_key, concat(envelope.nonce, cleartext_creds))

  if !ct_equal(envelope.auth_tag, expected_tag)
    raise KeyRecoveryError

  return (client_private_key, export_key)
~~~

# Offline Registration {#offline-phase}

The registration process proceeds as follows. The client inputs
the following values:

- password: client password.
- creds: client credentials, as described in {{client-material}}.

The server inputs the following values:

- server_private_key: server private key for the AKE protocol.
- server_public_key: server public key for the AKE protocol.
- credential_identifier: unique identifier for the client's
  credential, generated by the server.
- oprf_seed: seed used to derive per-client OPRF keys.

The registration protocol then runs as shown below:

~~~
  Client                                         Server
 ------------------------------------------------------
 (request, blind) = CreateRegistrationRequest(password)

                        request
              ------------------------->

 response = CreateRegistrationResponse(request,
                                       server_public_key,
                                       credential_identifier,
                                       oprf_seed)

                        response
              <-------------------------

 (record, export_key) = FinalizeRequest(response,
                                        server_identity,
                                        client_identity)

                        record
              ------------------------->
~~~

{{registration-functions}} describes details of the functions and the
corresponding parameters referenced above.

Both client and server MUST validate the other party's public key before use.
See {{validation}} for more details. Upon completion, the server stores
the client's credentials for later use. Moreover, the client MAY use the output
`export_key` for further application-specific purposes; see {{export-key-usage}}.

## Registration Messages {#registration-messages}

~~~
struct {
  uint8 data[Noe];
} RegistrationRequest;
~~~

data
: A serialized OPRF group element.

~~~
struct {
  uint8 data[Noe];
  uint8 server_public_key[Npk];
} RegistrationResponse;
~~~

data
: A serialized OPRF group element.

server_public_key
: The server's encoded public key that will be used for the online authenticated key exchange stage.

~~~
struct {
  uint8 client_public_key[Npk];
  uint8 masking_key[Nh];
  Envelope envelope;
} RegistrationRecord;
~~~

client_public_key
: The client's encoded public key, corresponding to the private key `client_private_key`.

masking_key
: An encryption key used by the server to preserve confidentiality of the envelope during login
  to defend against client enumeration attacks.

envelope
: The client's `Envelope` structure.

## Registration Functions {#registration-functions}

### CreateRegistrationRequest

~~~
CreateRegistrationRequest

Input:
- password, an opaque byte string containing the client's password.

Output:
- request, a RegistrationRequest structure.
- blind, an OPRF scalar value.

def CreateRegistrationRequest(password):
  (blind, M) = Blind(password)
  Create RegistrationRequest request with M
  return (request, blind)
~~~

### CreateRegistrationResponse {#create-reg-response}

~~~
CreateRegistrationResponse

Input:
- request, a RegistrationRequest structure.
- server_public_key, the server's public key.
- credential_identifier, an identifier that uniquely represents the credential.
- oprf_seed, the seed of Nh bytes used by the server to generate an oprf_key.

Output:
- response, a RegistrationResponse structure.

def CreateRegistrationResponse(request, server_public_key,
                               credential_identifier, oprf_seed):
  seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nseed)
  (oprf_key, _) = DeriveKeyPair(seed)
  Z = Evaluate(oprf_key, request.data, nil)
  Create RegistrationResponse response with (Z, server_public_key)
  return response
~~~

### FinalizeRequest {#finalize-request}

To create the user record used for further authentication, the client executes
the following function.

~~~
FinalizeRequest

Input:
- password, an opaque byte string containing the client's password.
- blind, an OPRF scalar value.
- response, a RegistrationResponse structure.
- server_identity, the optional encoded server identity.
- client_identity, the optional encoded client identity.

Output:
- record, a RegistrationRecord structure.
- export_key, an additional client key.

def FinalizeRequest(password, blind, response, server_identity, client_identity):
  oprf_output = Finalize(password, blind, response.data, nil)
  stretched_oprf_output = Stretch(oprf_output, params)
  randomized_pwd = Extract("", concat(oprf_output, stretched_oprf_output))
  (envelope, client_public_key, masking_key, export_key) =
    Store(randomized_pwd, response.server_public_key,
          server_identity, client_identity)
  Create RegistrationUpload record with (client_public_key, masking_key, envelope)
  return (record, export_key)
~~~

See {{online-phase}} for details about the output export_key usage.

Upon completion of this function, the client MUST send `record` to the server.

## Finalize Registration {#finalize-registration}

The server stores the `record` object as the credential file for each client
along with the associated `credential_identifier` and `client_identity` (if
different). Note that the values `oprf_seed` and `server_private_key` from the
server's setup phase must also be persisted. The `oprf_seed` value SHOULD be used
for all clients; see {{preventing-client-enumeration}}. The `server_private_key`
may be unique for each client.

# Online Authenticated Key Exchange {#online-phase}

The generic outline of OPAQUE with a 3-message AKE protocol includes three messages
ke1, ke2, and ke3, where ke1 and ke2 include key exchange shares, e.g., DH values, sent
by the client and server, respectively, and ke3 provides explicit client authentication and
full forward security (without it, forward secrecy is only achieved against eavesdroppers,
which is insufficient for OPAQUE security).

This section describes the online authenticated key exchange protocol flow,
message encoding, and helper functions. This stage is composed of a concurrent
OPRF and key exchange flow. The key exchange protocol is authenticated using the
client and server credentials established during registration; see {{offline-phase}}.
In the end, the client proves its knowledge of the password, and both client and
server agree on (1) a mutually authenticated shared secret key and (2) any optional
application information exchange during the handshake.

In this stage, the client inputs the following values:

- password: client password.
- client_identity: client identity, as described in {{client-material}}.

The server inputs the following values:

- server_private_key: server private for the AKE protocol.
- server_public_key: server public for the AKE protocol.
- server_identity: server identity, as described in {{client-material}}.
- record: RegistrationUpload corresponding to the client's registration.
- credential_identifier: an identifier that uniquely represents the credential.
- oprf_seed: seed used to derive per-client OPRF keys.

The client receives two outputs: a session secret and an export key. The export
key is only available to the client, and may be used for additional
application-specific purposes, as outlined in {{export-key-usage}}. The output
`export_key` MUST NOT be used in any way before the protocol completes
successfully. See {{alternate-key-recovery}} for more details about this
requirement. The server receives a single output: a session secret matching the
client's.

The protocol runs as shown below:

~~~
  Client                                         Server
 ------------------------------------------------------
  ke1 = ClientInit(password)

                         ke1
              ------------------------->

  ke2 = ServerInit(server_identity, server_private_key,
                    server_public_key, record,
                    credential_identifier, oprf_seed, ke1)

                         ke2
              <-------------------------

    (ke3,
    session_key,
    export_key) = ClientFinish(client_identity, password,
                              server_identity, ke2)

                         ke3
              ------------------------->

                       session_key = ServerFinish(ke3)
~~~

Both client and server may use implicit internal state objects to keep necessary
material for the OPRF and AKE, `client_state` and `server_state`, respectively.

The client state may have the following named fields:

- password, the input password; and
- blind, the random blinding scalar returned by `Blind()`, of length Nok; and
- client_ake_state, the client's AKE state if necessary.

The server state may have the following fields:

- server_ake_state, the server's AKE state if necessary.

The rest of this section describes these authenticated key exchange messages
and their parameters in more detail. {{cred-retrieval}} discusses internal
functions used for retrieving client credentials, and {{ake-protocol}} discusses
how these functions are used to execute the authenticated key exchange protocol.

## Client Authentication Functions {#opaque-client}

~~~
ClientInit

State:
- state, a ClientState structure.

Input:
- password, an opaque byte string containing the client's password.

Output:
- ke1, a KE1 message structure.

def ClientInit(password):
  request, blind = CreateCredentialRequest(password)
  state.blind = blind
  ake_1 = Start(request)
  Output KE1(request, ake_1)
~~~

~~~
ClientFinish

State:
- state, a ClientState structure

Input:
- client_identity, the optional encoded client identity, which is set
  to client_public_key if not specified.
- server_identity, the optional encoded server identity, which is set
  to server_public_key if not specified.
- ke2, a KE2 message structure.

Output:
- ke3, a KE3 message structure.
- session_key, the session's shared secret.
- export_key, an additional client key.

def ClientFinish(client_identity, server_identity, ke2):
  (client_private_key, server_public_key, export_key) =
    RecoverCredentials(state.password, state.blind, ke2.CredentialResponse,
                       server_identity, client_identity)
  (ke3, session_key) =
    ClientFinalize(client_identity, client_private_key, server_identity,
                    server_public_key, ke2)
  return (ke3, session_key)
~~~

## Server Authentication Functions {#opaque-server}

~~~
ServerInit

Input:
- server_identity, the optional encoded server identity, which is set to
  server_public_key if nil.
- server_private_key, the server's private key.
- server_public_key, the server's public key.
- record, the client's RegistrationRecord structure.
- credential_identifier, an identifier that uniquely represents the credential.
- oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key.
- ke1, a KE1 message structure.
- client_identity, the encoded client identity.

Output:
- ke2, a KE2 structure.

def ServerInit(server_identity, server_private_key, server_public_key,
               record, credential_identifier, oprf_seed, ke1, client_identity):
  response = CreateCredentialResponse(ke1.request, server_public_key, record,
    credential_identifier, oprf_seed)
  ake_2 = Response(server_identity, server_private_key,
    client_identity, record.client_public_key, ke1, response)
  return KE2(response, ake_2)
~~~

Since the OPRF is a two-message protocol, KE3 has no element of the OPRF. We can
therefore call the AKE's `ServerFinish()` directly. The `ServerFinish()` function
MUST take KE3 as input and MUST verify the client authentication material it contains
before the `session_key` value can be used. This verification is paramount in order to
ensure forward secrecy against active attackers.

This function MUST NOT return the `session_key` value if the client authentication
material is invalid, and may instead return an appropriate error message.

## Credential Retrieval {#cred-retrieval}

### Credential Retrieval Messages

~~~
struct {
  uint8 data[Noe];
} CredentialRequest;
~~~

data
: A serialized OPRF group element.

~~~
struct {
  uint8 data[Noe];
  uint8 masking_nonce[Nn];
  uint8 masked_response[Npk + Ne];
} CredentialResponse;
~~~

data
: A serialized OPRF group element.

masking_nonce
: A nonce used for the confidentiality of the masked_response field.

masked_response
: An encrypted form of the server's public key and the client's `Envelope`
structure.

### Credential Retrieval Functions

#### CreateCredentialRequest {#create-credential-request}

~~~
CreateCredentialRequest

Input:
- password, an opaque byte string containing the client's password.

Output:
- request, a CredentialRequest structure.
- blind, an OPRF scalar value.

def CreateCredentialRequest(password):
  (blind, M) = Blind(password)
  Create CredentialRequest request with M
  return (request, blind)
~~~

#### CreateCredentialResponse {#create-credential-response}

There are two scenarios to handle for the construction of a CredentialResponse
object: either the record for the client exists (corresponding to a properly
registered client), or it was never created (corresponding to a client that has
yet to register).

In the case of an existing record with the corresponding identifier
`credential_identifier`, the server invokes the following function to
produce a CredentialResponse:

~~~
CreateCredentialResponse

Input:
- request, a CredentialRequest structure.
- server_public_key, the public key of the server.
- record, an instance of RegistrationRecord which is the server's
  output from registration.
- credential_identifier, an identifier that uniquely represents the credential.
- oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key.

Output:
- response, a CredentialResponse structure.

def CreateCredentialResponse(request, server_public_key, record,
                             credential_identifier, oprf_seed):
  seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
  (oprf_key, _) = DeriveKeyPair(seed)
  Z = Evaluate(oprf_key, request.data, nil)
  masking_nonce = random(Nn)
  credential_response_pad = Expand(record.masking_key,
                                   concat(masking_nonce, "CredentialResponsePad"),
                                   Npk + Ne)
  masked_response = xor(credential_response_pad,
                        concat(server_public_key, record.envelope))
  Create CredentialResponse response with (Z, masking_nonce, masked_response)

  return response
~~~

In the case of a record that does not exist and if client enumeration prevention is desired,
the server MUST respond to the credential request to fake the existence of the record.
The server SHOULD invoke the CreateCredentialResponse function with a fake client record
argument that is configured so that:

- record.client_public_key is set to a randomly generated public key of length Npk
- record.masking_key is set to a random byte string of length Nh
- record.envelope is set to the byte string consisting only of zeros of length Ne

It is RECOMMENDED that a fake client record is created once (e.g. as the first user record
of the application) and stored alongside legitimate client records. This allows servers to locate
the record in time comparable to that of a legitimate client record.

Note that the responses output by either scenario are indistinguishable to an adversary
that is unable to guess the registered password for the client corresponding to credential_identifier.

#### RecoverCredentials {#recover-credentials}

~~~
RecoverCredentials

Input:
- password, an opaque byte string containing the client's password.
- blind, an OPRF scalar value.
- response, a CredentialResponse structure.
- server_identity, The optional encoded server identity.
- client_identity, The encoded client identity.

Output:
- client_private_key, the client's private key for the AKE protocol.
- server_public_key, the public key of the server.
- export_key, an additional client key.

def RecoverCredentials(password, blind, response,
                       server_identity, client_identity):
  oprf_output = Finalize(password, blind, response.data, nil)
  stretched_oprf_output = Stretch(oprf_output, params)
  randomized_pwd = Extract("", concat(oprf_output, stretched_oprf_output))
  masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
  credential_response_pad = Expand(masking_key,
                                   concat(response.masking_nonce, "CredentialResponsePad"),
                                   Npk + Ne)
  concat(server_public_key, envelope) = xor(credential_response_pad,
                                              response.masked_response)
  (client_private_key, export_key) =
    Recover(randomized_pwd, server_public_key, envelope,
            server_identity, client_identity)

  return (client_private_key, server_public_key, export_key)
~~~

## AKE Protocol {#ake-protocol}

This section describes the authenticated key exchange protocol for OPAQUE using
3DH, a 3-message AKE which satisfies the forward secrecy and KCI properties
discussed in {{security-considerations}}.

The AKE client state `client_ake_state` mentioned in {{online-phase}} has the
following named fields:

- client_secret, an opaque byte string of length Nsk; and
- ke1, a value of type KE1.

The server state `server_ake_state` mentioned in {{online-phase}} has the
following fields:

- expected_client_mac, an opaque byte string of length Nm; and
- session_key, an opaque byte string of length Nx.

{{ake-client}} and {{ake-server}} specify the inner workings of client and
server functions, respectively.

### AKE Messages {#ake-messages}

~~~
struct {
  uint8 client_nonce[Nn];
  uint8 client_keyshare[Npk];
} AuthInit;
~~~

client_nonce : A fresh randomly generated nonce of length Nn.

client_keyshare : Client ephemeral key share of fixed size Npk.

~~~
struct {
  uint8 server_nonce[Nn];
  uint8 server_keyshare[Npk];
  uint8 server_mac[Nm];
} AuthResponse;
~~~

server_nonce : A fresh randomly generated nonce of length Nn.

server_keyshare : Server ephemeral key share of fixed size Npk, where Npk
depends on the corresponding prime order group.

server_mac : An authentication tag computed over the handshake transcript
computed using Km2, defined below.

~~~
struct {
  uint8 client_mac[Nm];
} AuthFinish;
~~~

client_mac : An authentication tag computed over the handshake transcript
computed using Km2, defined below.

### Key Creation {#key-creation}

We assume the following functions to exist for all candidate groups in this
setting:

- RecoverPublicKey(private_key): Recover the public key related to the input
  `private_key`.
- DeriveAuthKeyPair(seed): Derive a private and public authentication key pair
  deterministically from the input `seed`.
- GenerateAuthKeyPair(): Return a randomly generated private and public key
  pair. This can be implemented by generating a random private key `sk`, then
  computing `pk = RecoverPublicKey(sk)`.
- SerializeElement(element): A member function of the underlying group that
  maps `element` to a unique byte array, mirrored from the definition of the
  similarly-named function of the OPRF group described in
  {{I-D.irtf-cfrg-voprf}}.

The implementation of DeriveAuthKeyPair is as follows:

~~~
DeriveAuthKeyPair

Input:
- seed, pseudo-random byte sequence used as a seed.

Output:
- private_key, a private key.
- public_key, the associated public key.

def DeriveAuthKeyPair(seed):
  private_key = HashToScalar(seed, dst="OPAQUE-DeriveAuthKeyPair")
  public_key = ScalarBaseMult(private_key)
  Output (private_key, public_key)
~~~

HashToScalar(msg, dst) is as specified in {{I-D.irtf-cfrg-voprf, Section 2.1}}.

### Key Schedule Functions

#### Transcript Functions {#transcript-functions}

The OPAQUE-3DH key derivation procedures make use of the functions below,
re-purposed from TLS 1.3 {{?RFC8446}}.

~~~
Expand-Label(Secret, Label, Context, Length) =
    Expand(Secret, CustomLabel, Length)
~~~

Where CustomLabel is specified as:

~~~
struct {
  uint16 length = Length;
  opaque label<8..255> = "OPAQUE-" + Label;
  uint8 context<0..255> = Context;
} CustomLabel;

Derive-Secret(Secret, Label, Transcript-Hash) =
    Expand-Label(Secret, Label, Transcript-Hash, Nx)
~~~

Note that the Label parameter is not a NULL-terminated string.

OPAQUE-3DH can optionally include shared `context` information in the
transcript, such as configuration parameters or application-specific info, e.g.
"appXYZ-v1.2.3".

The OPAQUE-3DH key schedule requires a preamble, which is computed as follows.

~~~
Preamble

Parameters:
- context, optional shared context information.

Input:
- client_identity, the optional encoded client identity, which is set
  to client_public_key if not specified.
- ke1, a KE1 message structure.
- server_identity, the optional encoded server identity, which is set
  to server_public_key if not specified.
- ke2, a KE2 message structure.

Output:
- preamble, the protocol transcript with identities and messages.

def Preamble(client_identity, ke1, server_identity, ke2):
  preamble = concat("RFCXXXX",
                     I2OSP(len(context), 2), context,
                     I2OSP(len(client_identity), 2), client_identity,
                     ke1,
                     I2OSP(len(server_identity), 2), server_identity,
                     ke2.credential_response,
                     ke2.AuthResponse.server_nonce, ke2.AuthResponse.server_keyshare)
  return preamble
~~~

#### Shared Secret Derivation

The OPAQUE-3DH shared secret derived during the key exchange protocol is
computed using the following functions.

~~~
TripleDHIKM

Input:
- skx, scalar to be multiplied with their corresponding pkx.
- pkx, element to be multiplied with their corresponding skx.

Output:
- ikm, input key material.

def TripleDHIKM(sk1, pk1, sk2, pk2, sk3, pk3):
  dh1 = SerializeElement(sk1 * pk1)
  dh2 = SerializeElement(sk2 * pk2)
  dh3 = SerializeElement(sk3 * pk3)
  return concat(dh1, dh2, dh3)
~~~

~~~
DeriveKeys

Input:
- ikm, input key material.
- preamble, the protocol transcript with identities and messages.

Output:
- Km2, a MAC authentication key.
- Km3, a MAC authentication key.
- session_key, the shared session secret.

def DeriveKeys(ikm, preamble):
  prk = Extract("", ikm)
  handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
  session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
  Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
  Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
  return (Km2, Km3, session_key)
~~~

### 3DH Client Functions {#ake-client}

~~~
Start

Parameters:
- Nn, the nonce length.

State:
- state, a ClientState structure.

Input:
- credential_request, a CredentialRequest structure.

Output:
- ke1, a KE1 structure.

def Start(credential_request):
  client_nonce = random(Nn)
  (client_secret, client_keyshare) = GenerateAuthKeyPair()
  Create KE1 ke1 with (credential_request, client_nonce, client_keyshare)
  Populate state with ClientState(client_secret, ke1)
  return (ke1, client_secret)
~~~

~~~
ClientFinalize

State:
- state, a ClientState structure.

Input:
- client_identity, the optional encoded client identity, which is
  set to client_public_key if not specified.
- client_private_key, the client's private key.
- server_identity, the optional encoded server identity, which is
  set to server_public_key if not specified.
- server_public_key, the server's public key.
- ke2, a KE2 message structure.

Output:
- ke3, a KE3 structure.
- session_key, the shared session secret.

Exceptions:
- HandshakeError, when the handshake fails

def ClientFinalize(client_identity, client_private_key, server_identity,
                   server_public_key, ke2):
  ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare,
    state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
  preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
  Km2, Km3, session_key = DeriveKeys(ikm, preamble)
  expected_server_mac = MAC(Km2, Hash(preamble))
  if !ct_equal(ke2.server_mac, expected_server_mac),
    raise HandshakeError
  client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac))
  Create KE3 ke3 with client_mac
  return (ke3, session_key)
~~~

### 3DH Server Functions {#ake-server}

~~~
Response

Parameters:
- Nn, the nonce length.

State:
- state, a ServerState structure.

Input:
- server_identity, the optional encoded server identity, which is set to
  server_public_key if not specified.
- server_private_key, the server's private key.
- client_identity, the optional encoded client identity, which is set to
  client_public_key if not specified.
- client_public_key, the client's public key.
- ke1, a KE1 message structure.

Output:
- ke2, a KE2 structure.

def Response(server_identity, server_private_key, client_identity,
             client_public_key, ke1, credential_response):
  server_nonce = random(Nn)
  (server_private_keyshare, server_keyshare) = GenerateAuthKeyPair()
  Create inner_ke2 ike2 with (ke1.credential_response, server_nonce, server_keyshare)
  preamble = Preamble(client_identity, ke1, server_identity, ike2)
  ikm = TripleDHIKM(server_private_keyshare, ke1.client_keyshare,
                    server_private_key, ke1.client_keyshare,
                    server_private_keyshare, client_public_key)
  Km2, Km3, session_key = DeriveKeys(ikm, preamble)
  server_mac = MAC(Km2, Hash(preamble))
  expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
  Populate state with ServerState(expected_client_mac, session_key)
  Create KE2 ke2 with (ike2, server_mac)
  return ke2
~~~

~~~
ServerFinish

State:
- state, a ServerState structure.

Input:
- ke3, a KE3 structure.

Output:
- session_key, the shared session secret if and only if KE3 is valid.

Exceptions:
- HandshakeError, when the handshake fails

def ServerFinish(ke3):
  if !ct_equal(ke3.client_mac, state.expected_client_mac):
    raise HandshakeError
  return state.session_key
~~~

# Configurations {#configurations}

An OPAQUE-3DH configuration is a tuple (OPRF, KDF, MAC, Hash, MHF, Group, Context)
such that the following conditions are met:

- The OPRF protocol uses the "base mode" variant of {{I-D.irtf-cfrg-voprf}} and implements
  the interface in {{dependencies}}. Examples include OPRF(ristretto255, SHA-512) and
  OPRF(P-256, SHA-256).
- The KDF, MAC, and Hash functions implement the interfaces in {{dependencies}}.
  Examples include HKDF {{RFC5869}} for the KDF, HMAC {{!RFC2104}} for the MAC,
  and SHA-256 and SHA-512 for the Hash functions. If an extensible output function
  such as SHAKE128 {{FIPS202}} is used then the output length `Nh` MUST be chosen
  to align with the target security level of the OPAQUE configuration. For example,
  if the target security parameter for the configuration is 128-bits, then `Nh` SHOULD be at least 32 bytes.
- The MHF has fixed parameters, chosen by the application, and implements the
  interface in {{dependencies}}. Examples include Argon2 {{?ARGON2=RFC9106}},
  scrypt {{?SCRYPT=RFC7914}}, and PBKDF2 {{?PBKDF2=RFC2898}} with fixed parameter choices.
- The Group mode identifies the group used in the OPAQUE-3DH AKE. This SHOULD
  match that of the OPRF. For example, if the OPRF is OPRF(ristretto255, SHA-512),
  then Group SHOULD be ristretto255.

Context is the shared parameter used to construct the preamble in {{transcript-functions}}.
This parameter SHOULD include any application-specific configuration information or
parameters that are needed to prevent cross-protocol or downgrade attacks.

Absent an application-specific profile, the following configurations are RECOMMENDED:

- OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512, Scrypt(32768,8,1), internal, ristretto255
- OPRF(P-256, SHA-256), HKDF-SHA-256, HMAC-SHA-256, SHA-256, Scrypt(32768,8,1), internal, P-256

Future configurations may specify different combinations of dependent algorithms,
with the following considerations:

1. The size of AKE public and private keys -- `Npk` and `Nsk`, respectively -- must adhere
to the output length limitations of the KDF Expand function. If HKDF is used, this means
Npk, Nsk <= 255 * Nx, where Nx is the output size of the underlying hash function.
See {{RFC5869}} for details.
2. The output size of the Hash function SHOULD be long enough to produce a key for
MAC of suitable length. For example, if MAC is HMAC-SHA256, then `Nh` could be
32 bytes.

# Application Considerations {#app-considerations}

Beyond choosing an appropriate configuration, there are several parameters which
applications can use to control OPAQUE:

- Credential identifier: As described in {{offline-phase}}, this is a unique
  handle to the client's credential being stored. In applications where there are alternate
  client identities that accompany an account, such as a username or email address, this
  identifier can be set to those alternate values. For simplicity, applications may choose
  to set `credential_identifier` to be equal to `client_identity`. Applications
  MUST NOT use the same credential identifier for multiple clients.
- Context information: As described in {{configurations}}, applications may include
  a shared context string that is authenticated as part of the handshake. This parameter
  SHOULD include any configuration information or parameters that are needed to prevent
  cross-protocol or downgrade attacks. This context information is not sent over the
  wire in any key exchange messages. However, applications may choose to send it alongside
  key exchange messages if needed for their use case.
- Client and server identities: As described in {{client-material}}, clients
  and servers are identified with their public keys by default. However, applications
  may choose alternate identities that are pinned to these public keys. For example,
  servers may use a domain name instead of a public key as their identifier. Absent
  alternate notions of an identity, applications SHOULD set these identities to nil
  and rely solely on public key information.
- Enumeration prevention: As described in {{create-credential-response}}, if servers
  receive a credential request for a non-existent client, they SHOULD respond with a
  "fake" response in order to prevent active client enumeration attacks. Servers that
  implement this mitigation SHOULD use the same configuration information (such as
  the oprf_seed) for all clients; see {{preventing-client-enumeration}}. In settings
  where this attack is not a concern, servers may choose to not support this functionality.

# Implementation Considerations {#implementation-considerations}

Implementations of OPAQUE should consider addressing the following:

- Clearing secrets out of memory: All private key material and intermediate values,
including the outputs of the key exchange phase, should not be retained in memory after
deallocation.
- Constant-time operations: All operations, particularly the cryptographic and group
arithmetic operations, should be constant-time and independent of the bits of any secrets.
This includes any conditional branching during the creation of the credential response,
to support implementations which provide mitigations against client enumeration attacks.
- Deserialization checks: When parsing messages that have crossed trust boundaries (e.g.
a network wire), implementations should properly handle all error conditions covered in
{{I-D.irtf-cfrg-voprf}} and abort accordingly.
- Additional client-side entropy: OPAQUE supports the ability to incorporate the
client identity alongside the password to be input to the OPRF. This provides additional
client-side entropy which can supplement the entropy that should be introduced by the
server during an honest execution of the protocol. This also provides domain separation
between different clients that might otherwise share the same password.
- Server-authenticated channels: Note that online guessing attacks
(against any Asymmetric PAKE) can be done from both the client side and the server side.
In particular, a malicious server can attempt to simulate honest responses in order to
learn the client's password. This means that additional checks should be considered in
a production deployment of OPAQUE: for instance, ensuring that there is a
server-authenticated channel over which OPAQUE registration and login is run.

# Security Considerations {#security-considerations}

OPAQUE is defined as the composition of two functionalities: an OPRF and
an AKE protocol. It can be seen as a "compiler" for transforming any AKE
protocol (with KCI security and forward secrecy; see below)
into a secure aPAKE protocol. In OPAQUE, the client stores a secret private key at the
server during password registration and retrieves this key each time
it needs to authenticate to the server. The OPRF security properties
ensure that only the correct password can unlock the private key
while at the same time avoiding potential offline guessing attacks.
This general composability property provides great flexibility and
enables a variety of OPAQUE instantiations, from optimized
performance to integration with existing authenticated key exchange
protocols such as TLS.

## Notable Design Differences

[[RFC EDITOR: Please delete this section before publication.]]

The specification as written here differs from the original cryptographic design in {{OPAQUE}}.
The following list enumerates important differences:

- Clients construct envelope contents without revealing the password to the
  server, as described in {{offline-phase}}, whereas the servers construct
  envelopes in {{OPAQUE}}. This change adds to the security of the protocol.
  {{OPAQUE}} considered the case where the envelope was constructed by the
  server for reasons of compatibility with previous UC modeling. An upcoming
  paper analyzes the registration phase as specified in this document. This
  change was made to support registration flows where the client chooses the
  password and wishes to keep it secret from the server, and it is compatible
  with the variant in {{OPAQUE}} that was originally analyzed.
- Envelopes do not contain encrypted credentials. Instead, envelopes contain
  information used to derive client private key material for the AKE. This
  variant is also analyzed in the new paper referred to in the previous item.
  This change improves the assumption behind the protocol by getting rid of
  equivocability and random key robustness for the encryption function. The
  latter property is only required for authentication and achieved by a
  collision-resistant MAC. This change was made for two reasons. First, it
  reduces the number of bytes stored in envelopes, which is an helpful
  improvement for large applications of OPAQUE with many registered users.
  Second, it removes the need for client applications to generate authentication
  keys. Instead, this responsibility is handled by OPAQUE, thereby simplifying
  the client interface to the protocol.
- Envelopes are masked with a per-user masking key as a way of preventing
  client enumeration attacks. See {{preventing-client-enumeration}} for more
  details. This extension does not add to the security of OPAQUE as an aPAKE
  but only used to provide a defense against enumeration attacks. In the
  analysis, this key can be simulated as a (pseudo) random key. This change
  was made to support real-world use cases where client or user enumeration
  is a security (or privacy) threat.
- Per-user OPRF keys are derived from a client identity and cross-user seed
  as a mitigation against client enumeration attacks. See
  {{preventing-client-enumeration}} for more details. The analysis of OPAQUE
  assumes OPRF keys of different users are independently random or
  pseudorandom. Deriving these keys via a single PRF (i.e., with a single
  cross-user key) applied to users' identities satisfies this assumption.
  This change was made to support real-world use cases where client or user
  enumeration is a security (or privacy) threat.
- The protocol outputs an export key for the client in addition to shared
  session key that can be used for application-specific purposes. This key
  is a pseudorandom value independent of other values in the protocol and
  have no influence in the security analysis (it can be simulated with a
  random output). This change was made to support more application use cases
  for OPAQUE, such as use of OPAQUE for end-to-end encrypted backups;
  see {{WhatsAppE2E}}.
- The protocol admits optional application-layer client and server identities.
  In the absence of these identities, client and server are authenticated
  against their public keys. Binding authentication to identities is part
  of the AKE part of OPAQUE. The type of identities and their semantics
  are application dependent and independent of the protocol analysis. This
  change was made to simplify client and server interfaces to the protocol
  by removing the need to specify an additional identity alongside public
  authentication keys when not needed.
- The protocol admits application-specific context information configured
  out-of-band in the AKE transcript. This allows domain separation between
  different application uses of OPAQUE. This is a mechanism for the AKE
  component and is best practice as for domain separation between different
  applications of the protocol. This change was made to allow different
  applications to use OPAQUE without risk of cross-protocol attacks.
- Servers use a separate identifier for computing OPRF evaluations and
  indexing into the password file storage, called the credential_identifier.
  This allows clients to change their application-layer identity
  (client_identity) without inducing server-side changes, e.g., by changing
  an email address associated with a given account. This mechanism is part
  of the derivation of OPRF keys via a single OPRF. As long as the derivation
  of different OPRF keys from a single OPRF have different PRF inputs, the
  protocol is secure. The choice of such inputs is up to the application.

## Security Analysis

Jarecki et al. {{OPAQUE}} proved the security of OPAQUE
in a strong aPAKE model that ensures security against pre-computation attacks
and is formulated in the Universal Composability (UC) framework {{Canetti01}}
under the random oracle model. This assumes security of the OPRF
function and the underlying key exchange protocol. In turn, the
security of the OPRF protocol from {{I-D.irtf-cfrg-voprf}} is proven
in the random oracle model under the One-More Diffie-Hellman assumption {{JKKX16}}.

OPAQUE's design builds on a line of work initiated in the seminal
paper of Ford and Kaliski {{FK00}} and is based on the HPAKE protocol
of Xavier Boyen {{Boyen09}} and the (1,1)-PPSS protocol from Jarecki
et al. {{JKKX16}}. None of these papers considered security against
pre-computation attacks or presented a proof of aPAKE security
(not even in a weak model).

The KCI property required from AKE protocols for use with OPAQUE
states that knowledge of a party's private key does not allow an attacker
to impersonate others to that party. This is an important security
property achieved by most public-key based AKE protocols, including
protocols that use signatures or public key encryption for
authentication. It is also a property of many implicitly
authenticated protocols, e.g., HMQV, but not all of them. We also note that
key exchange protocols based on shared keys do not satisfy the KCI
requirement, hence they are not considered in the OPAQUE setting.
We note that KCI is needed to ensure a crucial property of OPAQUE: even upon
compromise of the server, the attacker cannot impersonate the client to the
server without first running an exhaustive dictionary attack.
Another essential requirement from AKE protocols for use in OPAQUE is to
provide forward secrecy (against active attackers).

## Related Protocols

Despite the existence of multiple designs for (PKI-free) aPAKE protocols,
none of these protocols are secure against pre-computation attacks.
This includes protocols that have recent analyses in the UC model such
as AuCPace {{AuCPace}} and SPAKE2+ {{SPAKE2plus}}. In particular, none
of these protocols can use the standard technique against pre-computation
that combines secret random values ("salt") into the one-way password mappings.
Either these protocols do not use a salt at all or, if they do, they
transmit the salt from server to client in the clear, hence losing the
secrecy of the salt and its defense against pre-computation.

We note that as shown in {{OPAQUE}}, these protocols, and any aPAKE
in the model from {{GMR06}}, can be converted into an aPAKE secure against
pre-computation attacks at the expense of an additional OPRF execution.

Beyond AuCPace and SPAKE2+, the most widely deployed PKI-free aPAKE is SRP {{?RFC2945}},
which is vulnerable to pre-computation attacks, lacks proof of security, and is
less efficient than OPAQUE. Moreover, SRP requires a ring as it mixes addition and
multiplication operations, and thus does not work over standard elliptic curves.
OPAQUE is therefore a suitable replacement for applications that use SRP.

## Identities {#identities}

AKE protocols generate keys that need to be uniquely and verifiably bound to a pair
of identities. In the case of OPAQUE, those identities correspond to client_identity and server_identity.
Thus, it is essential for the parties to agree on such identities, including an
agreed bit representation of these identities as needed.

Applications may have different policies about how and when identities are
determined. A natural approach is to tie client_identity to the identity the server uses
to fetch envelope (hence determined during password registration) and to tie server_identity
to the server identity used by the client to initiate an offline password
registration or online authenticated key exchange session. server_identity and client_identity can also
be part of the envelope or be tied to the parties' public keys. In principle, identities
may change across different sessions as long as there is a policy that
can establish if the identity is acceptable or not to the peer. However, we note
that the public keys of both the server and the client must always be those defined
at the time of password registration.

The client identity (client_identity) and server identity (server_identity) are
optional parameters that are left to the application to designate as aliases for
the client and server. If the application layer does not supply values for these
parameters, then they will be omitted from the creation of the envelope
during the registration stage. Furthermore, they will be substituted with
client_identity = client_public_key and server_identity = server_public_key during
the authenticated key exchange stage.

The advantage to supplying a custom client_identity and server_identity (instead of simply relying
on a fallback to client_public_key and server_public_key) is that the client can then ensure that any
mappings between client_identity and client_public_key (and server_identity and server_public_key)
are protected by the authentication from the envelope. Then, the client can verify that the
client_identity and server_identity contained in its envelope match the client_identity
and server_identity supplied by the server.

However, if this extra layer of verification is unnecessary for the application, then simply
leaving client_identity and server_identity unspecified (and using client_public_key and
server_public_key instead) is acceptable.

## Export Key Usage {#export-key-usage}

The export key can be used (separately from the OPAQUE protocol) to provide
confidentiality and integrity to other data which only the client should be
able to process. For instance, if the server is expected to maintain any
client-side secrets which require a password to access, then this export key
can be used to encrypt these secrets so that they remain hidden from the
server.

## Static Diffie-Hellman Oracles

While one can expect the practical security of the OPRF function (namely,
the hardness of computing the function without knowing the key) to be in the
order of computing discrete logarithms or solving Diffie-Hellman, Brown and
Gallant {{BG04}} and Cheon {{Cheon06}} show an attack that slightly improves
on generic attacks. For typical curves, the attack requires an infeasible
number of calls to the OPRF or results in insignificant security loss;
see {{I-D.irtf-cfrg-voprf}} for more information. For OPAQUE, these attacks
are particularly impractical as they translate into an infeasible number of
failed authentication attempts directed at individual users.

## Input Validation {#validation}

Both client and server MUST validate the other party's public key(s) used
for the execution of OPAQUE. This includes the keys shared during the
offline registration phase, as well as any keys shared during the online
key agreement phase. The validation procedure varies depending on the
type of key. For example, for OPAQUE instantiations
using 3DH with P-256, P-384, or P-521 as the underlying group, validation
is as specified in Section 5.6.2.3.4 of {{keyagreement}}. This includes
checking that the coordinates are in the correct range, that the point
is on the curve, and that the point is not the point at infinity.
Additionally, validation MUST ensure the Diffie-Hellman shared secret is
not the point at infinity.

## OPRF Key Stretching

Applying a key streching function to the output of the OPRF greatly increases the cost of an offline
attack upon the compromise of the credential file at the server. Applications
SHOULD select parameters that balance cost and complexity. Note that in
OPAQUE, the key stretching function is executed by the client, as opposed to
the server. This means that applications must consider a tradeoff between the
performance of the protocol on clients (specifically low-end devices) and
protection against offline attacks after a server compromise.

## Client Enumeration {#preventing-client-enumeration}

Client enumeration refers to attacks where the attacker tries to learn
extra information about the behavior of clients that have registered with
the server. There are two types of attacks we consider:

1) An attacker tries to learn whether a given client identity is registered
with a server, and
2) An attacker tries to learn whether a given client identity has recently
completed registration, re-registered (e.g. after a password change), or
changed its identity.

OPAQUE prevents these attacks during the authentication flow. The first is
prevented by requiring servers to act with unregistered client identities in a
way that is indistinguishable from its behavior with existing registered clients.
Servers do this for an unregistered client by simulating a fake
CredentialResponse as specified in {{create-credential-response}}.
Implementations must also take care to avoid side-channel leakage (e.g., timing
attacks) from helping differentiate these operations from a regular server
response. Note that this may introduce possible abuse vectors since the
server's cost of generating a CredentialResponse is less than that of the
client's cost of generating a CredentialRequest. Server implementations
may choose to forego the construction of a simulated credential response
message for an unregistered client if these client enumeration attacks can
be mitigated through other application-specific means or are otherwise not
applicable for their threat model.

Preventing the second type of attack requires the server to supply a
credential_identifier value for a given client identity, consistently between
the registration response and credential response; see {{create-reg-response}}
and {{create-credential-response}}. Note that credential_identifier can be set
to client_identity for simplicity.

In the event of a server compromise that results in a re-registration of
credentials for all compromised clients, the oprf_seed value MUST be resampled,
resulting in a change in the oprf_key value for each client. Although this
change can be detected by an adversary, it is only leaked upon password rotation
after the exposure of the credential files, and equally affects all registered
clients.

Finally, applications must use the same key recovery mechanism when using this
prevention throughout their lifecycle. The envelope size may vary between
mechanisms, so a switch could then be detected.

OPAQUE does not prevent either type of attack during the registration flow.
Servers necessarily react differently during the registration flow between
registered and unregistered clients. This allows an attacker to use the server's
response during registration as an oracle for whether a given client identity is
registered. Applications should mitigate against this type of attack by rate
limiting or otherwise restricting the registration flow.

## Password Salt and Storage Implications

In OPAQUE, the OPRF key acts as the secret salt value that ensures the infeasibility
of pre-computation attacks. No extra salt value is needed. Also, clients never
disclose their passwords to the server, even during registration. Note that a corrupted
server can run an exhaustive offline dictionary attack to validate guesses for the client's
password; this is inevitable in any aPAKE protocol. (OPAQUE enables defense against such
offline dictionary attacks by distributing the server so that an offline attack is only
possible if all - or a minimal number of - servers are compromised {{OPAQUE}}.) Furthermore,
if the server does not sample this OPRF key with sufficiently high entropy, or if it is not
kept hidden from an adversary, then any derivatives from the client's password may also be
susceptible to an offline dictionary attack to recover the original password.

Some applications may require learning the client's password for enforcing password
rules. Doing so invalidates this important security property of OPAQUE and is
NOT RECOMMENDED. Applications should move such checks to the client. Note that
limited checks at the server are possible to implement, e.g., detecting repeated
passwords.

## AKE Private Key Storage

Server implementations of OPAQUE do not need access to the raw AKE private key. They only require
the ability to compute shared secrets as specified in {{key-schedule-functions}}. Thus, applications
may store the server AKE private key in a Hardware Security Module (HSM) or
similar. Upon compromise of the OPRF seed and client envelopes, this would prevent an
attacker from using this data to mount a server spoofing attack. Supporting implementations
need to consider allowing separate AKE and OPRF algorithms in cases where the HSM is
incompatible with the OPRF algorithm.

# IANA Considerations

This document makes no IANA requests.

--- back

# Acknowledgments

The OPAQUE protocol and its analysis is joint work of the author with Stanislaw
Jarecki and Jiayu Xu. We are indebted to the OPAQUE reviewers during CFRG's
aPAKE selection process, particularly Julia Hesse and Bjorn Tackmann.
This draft has benefited from comments by multiple people. Special thanks
to Richard Barnes, Dan Brown, Eric Crockett, Paul Grubbs, Fredrik Kuivinen,
Payman Mohassel, Jason Resch, Greg Rubin, and Nick Sullivan.

# Alternate Key Recovery Mechanisms {#alternate-key-recovery}

Client authentication material can be stored and retrieved using different key
recovery mechanisms, provided these mechanisms adhere to the requirements
specified in {{deps-keyrec}}. Any key recovery mechanism that encrypts data
in the envelope MUST use an authenticated encryption scheme with random
key-robustness (or key-committing). Deviating from the key-robustness
requirement may open the protocol to attacks, e.g., {{LGR20}}.
This specification enforces this property by using a MAC over the envelope
contents.

We remark that export_key for authentication or encryption requires
no special properties from the authentication or encryption schemes
as long as export_key is used only after authentication material is successfully
recovered, i.e., after the MAC in RecoverCredentials passes verification.

# Alternate AKE Instantiations {#alternate-akes}

It is possible to instantiate OPAQUE with other AKEs, such as HMQV {{HMQV}} and SIGMA-I.
HMQV is similar to 3DH but varies in its key schedule. SIGMA-I uses digital signatures
rather than static DH keys for authentication. Specification of these instantiations is
left to future documents. A sketch of how these instantiations might change is included
in the next subsection for posterity.

OPAQUE may also be instantiated with any post-quantum (PQ) AKE protocol that has the message
flow above and security properties (KCI resistance and forward secrecy) outlined
in {{security-considerations}}. Note that such an instantiation is not quantum-safe unless
the OPRF is quantum-safe. However, an OPAQUE instantiation where the AKE is quantum-safe,
but the OPRF is not, would still ensure the confidentiality of application data encrypted
under session_key (or a key derived from it) with a quantum-safe encryption function.

## HMQV Instantiation Sketch

An HMQV instantiation would work similar to OPAQUE-3DH, differing primarily in the key
schedule {{HMQV}}. First, the key schedule `preamble` value would use a different constant prefix
-- "HMQV" instead of "3DH" -- as shown below.

~~~
preamble = concat("HMQV",
                  I2OSP(len(client_identity), 2), client_identity,
                  KE1,
                  I2OSP(len(server_identity), 2), server_identity,
                  KE2.credential_response,
                  KE2.AuthResponse.server_nonce, KE2.AuthResponse.server_keyshare)
~~~

Second, the IKM derivation would change. Assuming HMQV is instantiated with a cyclic
group of prime order p with bit length L, clients would compute `IKM` as follows:

~~~
u' = (eskU + u \* skU) mod p
IKM = (epkS \* pkS^s)^u'
~~~

Likewise, servers would compute `IKM` as follows:

~~~
s' = (eskS + s \* skS) mod p
IKM = (epkU \* pkU^u)^s'
~~~

In both cases, `u` would be computed as follows:

~~~
hashInput = concat(I2OSP(len(epkU), 2), epkU,
                   I2OSP(len(info), 2), info,
                   I2OSP(len("client"), 2), "client")
u = Hash(hashInput) mod L
~~~

Likewise, `s` would be computed as follows:

~~~
hashInput = concat(I2OSP(len(epkS), 2), epkS,
                   I2OSP(len(info), 2), info,
                   I2OSP(len("server"), 2), "server")
s = Hash(hashInput) mod L
~~~

Hash is the same hash function used in the main OPAQUE protocol for key derivation.
Its output length (in bits) must be at least L.

## SIGMA-I Instantiation Sketch

A SIGMA-I instantiation differs more drastically from OPAQUE-3DH since authentication
uses digital signatures instead of Diffie Hellman. In particular, both KE2 and KE3
would carry a digital signature, computed using the server and client private keys
established during registration, respectively, as well as a MAC, where the MAC is
computed as in OPAQUE-3DH.

The key schedule would also change. Specifically, the key schedule `preamble` value would
use a different constant prefix -- "SIGMA-I" instead of "3DH" -- and the `IKM` computation
would use only the ephemeral key shares exchanged between client and server.

# Test Vectors

This section contains real and fake test vectors for the OPAQUE-3DH specification.
Each real test vector in {{real-vectors}} specifies the configuration information,
protocol inputs, intermediate values computed during registration and authentication,
and protocol outputs.

Similarly, each fake test vector in {{fake-vectors}} specifies
the configuration information, protocol inputs, and protocol
outputs computed during authentication of an unknown or unregistered user. Note that `masking_key`, `client_private_key`, and
`client_public_key` are used as additional inputs as described in
{{create-credential-response}}. `client_public_key` is used as the fake record's public key, and
`masking_key` for the fake record's masking key parameter.

All values are encoded in hexadecimal strings. The configuration information
includes the (OPRF, Hash, MHF, EnvelopeMode, Group) tuple, where the Group
matches that which is used in the OPRF. These test vectors were generated using
draft-09 of {{I-D.irtf-cfrg-voprf}}.

## Real Test Vectors {#real-vectors}

### OPAQUE-3DH Real Test Vector 1

#### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Group: ristretto255
Context: 4f50415155452d504f43
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

#### Input Values

~~~
oprf_seed: 776860514a411287a923210b7b55d600438172a371b8f14b7a1059cdad
c414c409064a22cf9e970b0ffc6f1fc6fdd539c4676775252f3240ae7ccb8ad4c401d
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d323fef4ead34cde967798f2e9784f69d233b1a6da7add58b2c95
a57bc213aca
masking_nonce: 521432344d52c17cc8ca390f9823c266b2b65fe9088a623e83ce5d
b56b66fd9a
server_private_key: 8965a1e4330d030997f517dbc52937d17dc9aa213c9038f84
fe8c5bfa772c60a
server_public_key: b078d8e20de67ae43a6fb7ace867096a648ae5cf62857e10b3
ccc28ac9b6cc7c
server_nonce: 62e17ecc3cdc9f918dbacacdd111f91ff04d765299320300d44aaf3
68a5704e7
client_nonce: 18b5420ec2386513929cede49a06199dea238cf3d05672f48cdd496
0726d1403
server_keyshare: b04e962a2139901078ac4c9f240e08572f31114338db80a48528
47c59d7aaa72
client_keyshare: 1a7ae48eac1f61a481d6cbb3256ea9852b6f2858f9d351c5c9e9
d9839a0b333c
server_private_keyshare: 6d3c110a936fbe18553328590016fbfbc0ea0c409ec7
2b7960696576d456860c
client_private_keyshare: 27d4e3a4d1b9c493f7c94bea0bb4f9d688c1e0407c08
bc88defd87624aaa4301
blind_registration: d89b55ad74923299ff6d2c1b795c23c6915f1ee97d6e44525
b0d206a4afb830d
blind_login: 874afedb28cf6a6b0f7083a11c34f95439c5cb4469bfed4fbf424635
8d15c20a
~~~

#### Intermediate Values

~~~
client_public_key: 84dea2d490db499c31a11589d5be55f453808c3dca222f3955
cd30b1d10d9d77
auth_key: 6c75222156348bc1335303ac528b52eceed7782aaaf7e311f39f85fe82b
435765cc9ce29a5a7daebc72d8497b19f0578e50a57ac55a67e66e93cd608ba378712
randomized_pwd: b823e057ef7680a5598a9a65f79e9d91f394068e36ab169e81e09
b7a226def105c7b6c2f89d8ed48beb2810445182b801dbb86861c9d4dd48423dee718
0d1217
envelope: d323fef4ead34cde967798f2e9784f69d233b1a6da7add58b2c95a57bc2
13aca4cd6aa51f41960607c1953ebfc80905798b8d7f35520bf52dee514beaf6da372
9e113b5c51eb80a2dabebb0514837a9cf36d161a98907d92d99203f01c2023df
handshake_secret: 81ff6c12eccd6a0c56040b53ead889040a849d8b85e22fc9c42
5e1605c26f34369d0c6bbaa4ffcfc94e37e473bb1eafec86dd8ccef99bce20ba2cb0f
b7bb4d5e
server_mac_key: 60108ae181e39fa7279726342f51c6b3f28c55cc8e7f9029f74da
ed3e5709a27b216138722a58d5eee0a042448f3446e883f8707113a8eb0d4b81d93f7
dced2f
client_mac_key: c760e4548d6a8965952d25a59c1d0539bc977507ef483eaaae31d
7faf52642aaa9f1e7f1099539ab93b414d3d27f12e53fe57093a5e3623add5991e91a
685b71
oprf_key: f9417edca8c2c821a4be92556fcd34d6e394d23f8756f9ed753cb663b74
78505
~~~

#### Output Values

~~~
registration_request: 34353245449074b76eb17f124b5837da7496b2c6748d288
dee41d6269d0a995e
registration_response: c8daa1c8cc762beedff046e18e7dfc2ef9e06efa9d60d0
e3bca3566036d95969b078d8e20de67ae43a6fb7ace867096a648ae5cf62857e10b3c
cc28ac9b6cc7c
registration_upload: 84dea2d490db499c31a11589d5be55f453808c3dca222f39
55cd30b1d10d9d772d6ac3dd0b0a631d2b353843388fcd9b4ed9de96d167544cff294
8fc37e4dac6878655cccff0c2aaf0e75b05124cd00284e6f170cf5e7851fff1139267
839d40d323fef4ead34cde967798f2e9784f69d233b1a6da7add58b2c95a57bc213ac
a4cd6aa51f41960607c1953ebfc80905798b8d7f35520bf52dee514beaf6da3729e11
3b5c51eb80a2dabebb0514837a9cf36d161a98907d92d99203f01c2023df
KE1: 4c1e02cf6b07ec1881adde0e04746648de2a87becca32f44fe1b6c5ff1cba779
18b5420ec2386513929cede49a06199dea238cf3d05672f48cdd4960726d14031a7ae
48eac1f61a481d6cbb3256ea9852b6f2858f9d351c5c9e9d9839a0b333c
KE2: fca0773e6754c2d066090597aa35cfcb42863c92c681a2340b97f45eb576c03f
521432344d52c17cc8ca390f9823c266b2b65fe9088a623e83ce5db56b66fd9a082ad
e883cd25425f50ca4ecd50f2c1c5e2aee952baaf16e583c01717e4542406718135aa5
f64517cbdf19a5dab88a567a8c6dd7dc4361331ab8787392363168ed2c628b8da7565
4bb011396975b3c03861ba845b60b93723781c620862ee05bba1132c6cc94f82b8305
8b334b6849a4f694b5bed135e50a6be0799d5642456c62e17ecc3cdc9f918dbacacdd
111f91ff04d765299320300d44aaf368a5704e7b04e962a2139901078ac4c9f240e08
572f31114338db80a4852847c59d7aaa72537c87d23f5d47e7e44e674d9b86f1dc075
63ac7a7161ad0d923e71a3438522415edcac81f3d8f4a734d35ea31ff71db1d438f0a
2c167e4029a7a46166357644
KE3: c346f1a0e44e56a45de3e4ec2f96192b994a415bec3015ea4ca20a2c2cfb2548
a728181ee454eedf5657d87fb8c21f3360055dac9f2157f970d7b90042bce6ab
export_key: 67c31f34585ce75e7ee191e07890e0553c723a0025e2d6663453343c7
2a987f98c8ee6885f35d3480f44a6f4de15ecbb4ebbf21a1ab5665c0a26cfc3711eb0
1c
session_key: 8275f3509e434fbb20df1f44d90c38761e348ec154b2aa40949ea2b4
d83861c754d4e7185922548053073e49d4c7494f819c414305eacd5969a12ca45d2b4
602
~~~

### OPAQUE-3DH Real Test Vector 2

#### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Group: ristretto255
Context: 4f50415155452d504f43
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e6085d8
c1187a72b3027e5b8ba25cd329d936e301e81907aa4bcaef549aa173689e18ac61f1e
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853
b5def228c85
masking_nonce: 6b2e9019503d8495c6d04efaee8370c45fa1dfad70201edd140cec
8ed6c73b5f
server_private_key: 0fc45ec0edb2fcc794f98501b16139771720a0713a2750b9e
528adfd46acd50a
server_public_key: 561f67c72c59ec3b02803932603103014946039dfb9b23216c
9cea76dcd2a533
server_nonce: 0d0d88f0936c712d3e901b42cb792f3657240ce5296dd5633e73335
31009c11e
client_nonce: 87ef09986545b295e8f5bbbaa7ad3dce15eb299eb2a5b34875ff421
b1d63d7a2
server_keyshare: 560895c14306f5f33e9c23766c0120ed9f745c4cc809a1f4a416
665b3282f061
client_keyshare: 40c7c67ee30fa68cbed3dba0d276ec22933e6916eb682eda7b48
953a62164f16
server_private_keyshare: 1e6fe817b87b2f8f50b5a0760acc81ef9818727289e8
1b6ffef83972184f520a
client_private_keyshare: 49a64f98e619251074345b023f19931b1652c993559a
8c2165c0bf774262b70a
blind_registration: 03b52f066898929f4aca48014b2b97365205ce691ee3444b0
a7cecec3c7efb01
blind_login: c7743c394e85e3f81ce383ddf78791d163b457fbec78c58c57a82a58
d5beea05
~~~

#### Intermediate Values

~~~
client_public_key: 6cac8290091af3ca2a8011ac13e748e42971398d831d6d0a4b
c22d1c59a52208
auth_key: af9337d6ea193edaa8a0978a055f9a0267e09e60b34756d0316ce257620
5eae18c9837373fc732c4a5ca263ecd872e6f5418d0c70c4abca4342ee2ff38196b0b
randomized_pwd: 7f077c60ee0e1de3dc99bd46f8e7fb789b42ce0661e273e9fb1ce
e60544b13e5febe08e3f9c915c277b5027425a835648b061a7fd800a171335d61c93e
afe207
envelope: 30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def2
28c85e92dc6e5fd0bb88b8ae24be705280bc9fb49c898d07f139e28cc89a4aef2bd0c
5afa963418f9d852d64c9edf964da075945d97ce06b80c6c810cc189b808085c
handshake_secret: d8c37b70645af5b8686e8a9687304efffb1fa535ed221b13fa1
34d2db8c267e24b4c617c5bb081f00791722b80b59b1799c04d12519b69c30fbf1a8c
c7957838
server_mac_key: 423cde5008793bc8489244180c0fd371c4fb8fe6d008e56dd1d2e
f00d97d2f01dda54fffcb5714e18f3abca705ce1766c497d52eed64043ceda4497dbf
6ea366
client_mac_key: 9d29bfeba7090176cd3a83440c06850cc3755e694e8185faa4d9b
9af6c6e5bec97d982072bcb9357276f79a75f2a00ef0f48b94b41a33a654b5ea7c816
5ca44f
oprf_key: ffe51c0a23e3043f276f07179e0ec023d93b3f4422162a5e56ae6c12e44
67d02
~~~

#### Output Values

~~~
registration_request: facacbb0b0768ec4e22629ca2f37f9b29c178f67a4f4019
3d517f81416789068
registration_response: 20caf9c214afaefe36aa033c13ef75c43ddb621319b97c
fa7731a0d38faed002561f67c72c59ec3b02803932603103014946039dfb9b23216c9
cea76dcd2a533
registration_upload: 6cac8290091af3ca2a8011ac13e748e42971398d831d6d0a
4bc22d1c59a52208ec8da1312c1ad615de9989954eef40667b0980093535996345a06
616708e166989144f336413f591f56fe8cbd35cbbd591559d40e2e7af5ef8104727e3
39f0df30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def228c8
5e92dc6e5fd0bb88b8ae24be705280bc9fb49c898d07f139e28cc89a4aef2bd0c5afa
963418f9d852d64c9edf964da075945d97ce06b80c6c810cc189b808085c
KE1: 2088e02ac314f323aebbea61ed5c998f3fee856957e573b6574b93cf98de8108
87ef09986545b295e8f5bbbaa7ad3dce15eb299eb2a5b34875ff421b1d63d7a240c7c
67ee30fa68cbed3dba0d276ec22933e6916eb682eda7b48953a62164f16
KE2: 70f2560d7a39766768490e262d1c0337d18ef3ab3a7c3ca6af09b2b1a7f34c54
6b2e9019503d8495c6d04efaee8370c45fa1dfad70201edd140cec8ed6c73b5f437ae
af35569931449c87118bbc62b5ef80c6b7b70f175a46804094dd60b8111ba846a95ad
16503a6e063e8bd561bd90e12558d56846e7591da70e5bf4b14621c9b4c50f13a71f1
94dba753408d26a36b607dbc2e4ac93325290f0b069ee34b52972ba1761f117049126
7a4cd6ec25724810199efb5625e5a5516ec5f31370490d0d88f0936c712d3e901b42c
b792f3657240ce5296dd5633e7333531009c11e560895c14306f5f33e9c23766c0120
ed9f745c4cc809a1f4a416665b3282f061a5873e2d1fcf8491104e82050a29ddae599
a4559d60f094cdee1c1ec844af6410a08d137027a13cffea253fa62447516adc9e72a
669b126f31b535f780c90139
KE3: a0d3e46d15f3549b01a8cec458f67aeb6deab71f42b49dedd8a394d91e161927
ef0d52c2c9ab23d36cdfc7e174819b084166c3c90a96a76fc544356953e7aeca
export_key: 1909884ffe1899e670b894791db9d3a48a70a6fca8031109fd5fc82f9
ba43df9c8efd2db392fc36ab239e8c9f78db4ed96a6f031e30d675ca285f7d84812c9
c5
session_key: 8fdac33cc719274c16824c785c46e2a8b641b15fe0cbb395f1613a33
e67fad0aed99a26760775c69eb3b4524f805f00808af7c6421a8e83677f42e4f280f7
e67
~~~

### OPAQUE-3DH Real Test Vector 3

#### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

#### Input Values

~~~
oprf_seed: 4d77dab871872dba848bdf20ed725f0fa3b58e7d8f3eab2a0aace261f6
1193c7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4a0f9f1984ff1f2a310fe428d9de5819bf63b3942dbe09f991ca0
cf545e33a8f
masking_nonce: 344022969d17d9cf4c88b7a9eec4c36bf64de079abb6dc7a1d4643
9446498f95
server_private_key: 4c3ad31f016b68085d25f85613f5838cd7c6b1697f27bb5e8
018e88ecfc53892
server_public_key: 03845043cc460779d3d868894fd28dcf4a0814e6fdd7b87769
e6d4ba4c477df6e7
server_nonce: 69259e0708bdfab794f689eec14c7deb7edde68c81645156cf278f2
1161e3aaa
client_nonce: e206269fe3eabd2b6e928b97b901c4819a3e89f48f9a72f09280e20
3ef27d9ef
server_keyshare: 02d7f81fa9773faf00efa7021a476abbfa77740267e841b5e55c
f809944d436a93
client_keyshare: 03753c309e7c68be892012552680ae399bb786cd2fc1ef92e928
b285adec7296cb
server_private_keyshare: 0d0518d56d002be476bd06c756aee97ba2912bab9b6a
62cddf7d5e3209a2859f
client_private_keyshare: 8525ce421747e59131ae68b478bfc59f5ef534d4e009
2e8ef1bfe338aaa4b65d
blind_registration: a17ab9c688c0bd231ec85e55de90b7d0b16385659d1b4a269
7a53276c728ebf5
blind_login: 0d1d189bb3c02a66ef9a72d48cca6c1f9afc1fedea22567b0868140b
48212366
~~~

#### Intermediate Values

~~~
client_public_key: 032c44882b558a6638f170d1d1808862ed2f9161927135871d
d1521c9dbd8b342d
auth_key: b8031ce3646df15e03a22aa6bdde52b623190438a00b96ceacadbe646ce
aaa40
randomized_pwd: 8d29441ad85676f44554479a9fec22e850fd110826b34be017b77
fd72bb675b3
envelope: 4a0f9f1984ff1f2a310fe428d9de5819bf63b3942dbe09f991ca0cf545e
33a8f0990eef6097a8ddfd4d704c0fb19b181bff4b93c9219693be715045d30cfef69
handshake_secret: 526a07308b37f5b6486f6494c31c0bf22f09439583e985c79c8
0bfe20dff827b
server_mac_key: 19b54a3e048bfd73f104070d91fecf23352795a5998cb03a47066
3326673c46d
client_mac_key: 24882a153ae0678804d79606b3a01dd10b85373df9b8d58fbe3b2
72d0f8ddb54
oprf_key: 173909c7099b97c14e149aff13f2810a5145081fce81925202f7f6f80c8
7d1d9
~~~

#### Output Values

~~~
registration_request: 03282f9e0421bf75d92335b924c4e8acea6299323e02299
a999b818482a3b69be9
registration_response: 0243cdfb0b60cfe1435e03643bec83b3579a40c10e6352
aa6f056cc4749f73765c03845043cc460779d3d868894fd28dcf4a0814e6fdd7b8776
9e6d4ba4c477df6e7
registration_upload: 032c44882b558a6638f170d1d1808862ed2f916192713587
1dd1521c9dbd8b342dde96555cb878e7e4dc22cba87a607119a45ef4228e6ff0da09f
85342ff8749614a0f9f1984ff1f2a310fe428d9de5819bf63b3942dbe09f991ca0cf5
45e33a8f0990eef6097a8ddfd4d704c0fb19b181bff4b93c9219693be715045d30cfe
f69
KE1: 0337f1c7b981c4488967bf2808ff63a7e0fe194f09c2b72f98c4122a60fdb8de
f4e206269fe3eabd2b6e928b97b901c4819a3e89f48f9a72f09280e203ef27d9ef037
53c309e7c68be892012552680ae399bb786cd2fc1ef92e928b285adec7296cb
KE2: 03e15aaf8ce6c8badc8737e88ed59f471ab08b1f9b5d5dd877ae445c41381171
56344022969d17d9cf4c88b7a9eec4c36bf64de079abb6dc7a1d46439446498f95688
5d9a6758fc50faaf3c7e1472be27ee8cdfcdabe99164c2779e35e3c804526fe25a2ee
83a8b185f1823ad7a8ba4a6109b95e63334aa8facc0455e3a748b196fd5ffbb90fff0
10b67d3a5f591453d310444fa4949ab4e871b1bd11c28b3fab72d69259e0708bdfab7
94f689eec14c7deb7edde68c81645156cf278f21161e3aaa02d7f81fa9773faf00efa
7021a476abbfa77740267e841b5e55cf809944d436a935978b1d6c5c5e523d93098ca
aa5793d5aae9f5f13379cca6f63a6402e471a060
KE3: 1d5998a358fcfc8b4719e3b8175058d21eaf6c6ba828d1e89e4a119eaf57802c
export_key: 48d3fc682273c005be26a59fb3e7f0bc4557f24e8fc71bb17b87de32c
04aa2d7
session_key: 3011f590f59b9539b29981abb66f477a8dbc1d8f02f379d785c3da32
5972ebcd
~~~

### OPAQUE-3DH Real Test Vector 4

#### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 1f4b263b2b18c85bc0154de4711c04899739c0620dc94323d026011ac6
def373
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0051724f14d71ff13ba5add017512cce702800f4272cdae1976cb
fbdfd6ba61d
masking_nonce: 6f768fd0979f8dc006ca297e7954ebf0e81a893021ee24acc35e1a
3f4b5e0366
server_private_key: 8cc6b69daac7a90de8837d49708e76310767cbe4af18594df
cd436216c265831
server_public_key: 029022b70aac38a4b838dc694744e10ae6ece18414b5e5e5b2
94d1ee4ba2e1b592
server_nonce: 3179547a4489c8718048ba107066398cfe2f8b5b2c0cdd8afa9fcaf
662e5f231
client_nonce: c42416787f78b5321bad1c8b6ad879e348e15bd698ee70b2c51d3e8
9d9c08b00
server_keyshare: 0260f1b9fe339983392e915678594d4ef64b35184832a3ea9361
2ee738afe19431
client_keyshare: 0396372f51d9440c44c8ddb84f45bb13280d19a7a289d16ff01f
6813ba0e18ddca
server_private_keyshare: 2c3542a08837b6c0709160251cbebe0d55e4423554c4
5da7a8952367cf336eb7
client_private_keyshare: 939993624b8a7c3b024164f8935dbe56fc7fc92082eb
d907ef6e6a63f214dc05
blind_registration: 34760c02e2a29e6b9c9e71ee3143a236fab39949655880d88
538d3efb0b85e9d
blind_login: a3cd7e6f042429c7c9e946f5351292fa08f4e99e395c30a95b268f2a
077aa6fc
~~~

#### Intermediate Values

~~~
client_public_key: 02d9ff4d5e5d414f75cca3fb9e71fb83dea6eaf1d281417a2c
77f777e07d924aff
auth_key: fc53819ad42e71e6c17b7507397650acf1c399cab1c616a3e63bf8cf684
c2e2f
randomized_pwd: 3a663c1f7fd73b8feb09863d6941e1f00e02308e21f2ce932246d
b53a329690f
envelope: 0051724f14d71ff13ba5add017512cce702800f4272cdae1976cbfbdfd6
ba61d0ee9ad5982907791f19ea1e1f04108c787399772ff5c197311c53e258f72ae03
handshake_secret: 90cc61aa797d3dcfb96dee30b0c720c024971a47b6ffa5d62bb
bf11c9e011b15
server_mac_key: 0571759363dc9dab4b2b410040653694d75a2c63401aa77bcd371
98ba646296c
client_mac_key: ad4c39997df613cd9506e65b2b402e2ba2e864710b86c7c3e09ab
b5e82ff9222
oprf_key: 4a8cfd04212a68b62b1853d6869b734e62ad38a7fd4e14a20a505502d1c
45054
~~~

#### Output Values

~~~
registration_request: 022c10067956d68ef7bcda9f087e20b0c9f64db7d92b11b
35bb6ad7da84bdf2d94
registration_response: 0385142a349ddef7f35842e6def0f413fceea4c09a20f6
f239101701f191c1a2ed029022b70aac38a4b838dc694744e10ae6ece18414b5e5e5b
294d1ee4ba2e1b592
registration_upload: 02d9ff4d5e5d414f75cca3fb9e71fb83dea6eaf1d281417a
2c77f777e07d924affd78311649d3758e0a3cf6e550c7628481385af520897f75862b
2a8ce82d1ed3c0051724f14d71ff13ba5add017512cce702800f4272cdae1976cbfbd
fd6ba61d0ee9ad5982907791f19ea1e1f04108c787399772ff5c197311c53e258f72a
e03
KE1: 02404ed848dc2f1546573a10d9118b0cee33f495eb7407a1eaf9861c4621d7b4
afc42416787f78b5321bad1c8b6ad879e348e15bd698ee70b2c51d3e89d9c08b00039
6372f51d9440c44c8ddb84f45bb13280d19a7a289d16ff01f6813ba0e18ddca
KE2: 02ad1b8dd39670a911d3d6ce4f2deb2c4d81b166cabe12885badfe7f20eebb69
686f768fd0979f8dc006ca297e7954ebf0e81a893021ee24acc35e1a3f4b5e03668a6
891a733009bc350074f6dcd067be7b117e6d229dea8cdd5a5282a0dcd8a2e25b268a5
aa7fd68204c0d3ccb4623ea3bafec0706ff6dcd62de5f1207a08888b265645da84384
940a4007081ef1d0f4f1f386e11878f6cf9e580237d02543b07163179547a4489c871
8048ba107066398cfe2f8b5b2c0cdd8afa9fcaf662e5f2310260f1b9fe339983392e9
15678594d4ef64b35184832a3ea93612ee738afe19431d7c98c1cc1dc382ad37643e1
0ff6f0ccc70a816a9426d386946e82256b5127d3
KE3: 5a2f3a2e80d594f4448b35205f20bb30c0bf404f97cc06c665e681d1f6c2e96c
export_key: cdc99ba5372729e4bf57e818eb4c20cbdcebe1f79aff49443b0cca594
0dcf447
session_key: 582987ea4c533e16b6903cc676b0e816b953c70295cdb9ee1083db91
5359284e
~~~

## Fake Test Vectors {#fake-vectors}

### OPAQUE-3DH Fake Test Vector 1

#### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Group: ristretto255
Context: 4f50415155452d504f43
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: ac0a0a2cf96eef565811811c94384ca183c8e6f639ab29b5d2a81ef430
5df9a67cb33db5ba8082e4f4bfb830e8e3f525b0ddcb70469b34224758d725ce53ac7
6
credential_identifier: 31323334
masking_nonce: e0d04374ad9a276620c681abfca7bdb432e63509e5ec96ed2ec554
2f6fc7db23
client_private_key: 5791eacfa2980bc0807bd327239b53f4370eb21d5b306257a
82104eaaab43f01
client_public_key: 846c28da13144e5908f1db4c8ba2c848ac34ae6b9a8855dcdb
08d5ecfb000d73
server_private_key: 3e80e5bedb45574e5fc16313c3bf46a8c80d4e012ffb4101f
df1dc9abe44430a
server_public_key: dae2f1e0cd79b733131d499fb9e77efe0f235d73c1f920bdc5
816259ad3a7429
server_nonce: a91c9485d74c9010185f462ce1eec52f588a8e392f36915849b6bfc
b6bd5b904
server_keyshare: f29cc7cbbc76091a0774bcae7239a9c8980982ebee7537635767
41240d5a3621
server_private_keyshare: 786fab66d8bd2070dbb71f82f81e1a3c8ce277df30ab
5f46a3c88d79d177300c
masking_key: 41723264b8bb2700cdd47e339d95404519f2fb3da58c93d84cbb4d51
de6757a31919382ba65c10e80cbb7f50a43e32782b08f8bee3ffaba39407660179105
ac5
KE1: 90681ccd8e4f538dc41b94742c27767df28db72b4b7e24b8ca99ddc07837b412
86e2b0916361fb6a69f9a097e3ef2f83f8fd5f95cc79432eabf3e01f0020bac6f033c
6fc3d6ca62913f0f98f612d9208a7b595f487c17b4aa2a4481942bebd09
~~~

#### Output Values

~~~
KE2: 0456d364a2ef8b2daf6c81c325cecdcc6f0a6d1444673f0e30fd30a8a05be71e
e0d04374ad9a276620c681abfca7bdb432e63509e5ec96ed2ec5542f6fc7db2337d59
904539bac9f84d61da7a9072096249e25306311b81065aded1e5ba651a02b273b4bfd
9e468a56b2d5cebd1a38bfc0a550601979e808842391a8c1f93cf27723d663ce06266
e0f27ec38d3b824d66fa7c43d68d7cd6c8cfe2775748887d24cdf1b07f04a33d51e7f
56b53156545a35e4becd8822e875a1441857332c77e5a91c9485d74c9010185f462ce
1eec52f588a8e392f36915849b6bfcb6bd5b904f29cc7cbbc76091a0774bcae7239a9
c8980982ebee753763576741240d5a3621be7d6db4aec4a0262dca383ec6d86d7b5f1
0e7a49c04c7a6254b989a3c492752f0cf2a0ef71465636de1fdab8d22c74030d0ac28
ec0a52845d33679906c3db7a
~~~

### OPAQUE-3DH Fake Test Vector 2

#### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 00e9ecfe6745415fe147f60270fc68fd0990c1fd9b34b9187adfc0b6e4
85f8fc
credential_identifier: 31323334
masking_nonce: 3292ebc7c8a8c933f0fc98006c14e59960a4d2f9fab11e9bf5247f
7c1c9d9a61
client_private_key: 18a92b2afbfccea5d80d337f07defe40d92673a52f3844058
f5d949aa9b03d49
client_public_key: 023e521c666df06223849ab2ff4e65ee9b037227dfb9d0f0ad
7a729e32cf3bc12c
server_private_key: 6ab6fea7ba0438613acde5a926bf796e5e24e879ebb50b60b
2569a3cefa27913
server_public_key: 03aa203944898f1423bc64190c32c283d85d0832e498ede685
40164526b091a47a
server_nonce: 466cfb980f9a2604c25d83d1a98a38717e97bfde3b1dd8eb8d3346c
a21d8a643
server_keyshare: 0277f390bba2952e8bc676c54663f09d3e7f2c7bf92c40ee46ce
374bc8e1c24738
server_private_keyshare: 7ebc43be4717550e6140dc5156c2f4d56bcb3cb24401
b182ad275c32713d314b
masking_key: d13299f10df28595d761c8b636815f62dad9d7ed319efefe641bb4c3
d1cc83a6
KE1: 034f10dba94f1dc855ff3c67f63251d759753630c6b1e5331ac7a6b416322f6d
52ee14b2d747cd0d76b9e5e27d7077eec3be075d20ac4e145572a45beeeb6066b902d
2696034d752cbac6c0e47adc9fbac916a19534516c5a25246bd9ce0dead5600
~~~

#### Output Values

~~~
KE2: 033a2ec2199f6865b70a3ce538a3093d94387882d1275c4a216a7b4d3734065c
943292ebc7c8a8c933f0fc98006c14e59960a4d2f9fab11e9bf5247f7c1c9d9a61ed6
43d6e5b97fc9de6cfbfee003a29ad5ba7f2ae8a68e53f0ae08d54f4ea6948673bfdbd
215a31a90769ffe74825497231b31f04994c2275d4e5c34db6f5f74c6296b7b95716d
8b6e86729b057e63e88eadd107f2c04abe3417df6aaa64df6531c466cfb980f9a2604
c25d83d1a98a38717e97bfde3b1dd8eb8d3346ca21d8a6430277f390bba2952e8bc67
6c54663f09d3e7f2c7bf92c40ee46ce374bc8e1c2473882a3c99b36c8dcf11b5956eb
ed89b3401e0fe7f61a7581dace64a4fdf53ea8f4
~~~
