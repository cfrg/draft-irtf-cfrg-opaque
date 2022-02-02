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
the input of the other. This specification depends on the prime-order OPRF construction specified
in {{!OPRF=I-D.irtf-cfrg-voprf}}, draft version -09, using the OPRF mode (0x00) from {{OPRF, Section 3.1}}.

The following OPRF client APIs are used:

- Blind(x): Create and output (`r`, `M`), consisting of a blinded representation of
  input `x`, denoted `M`, along with a value to revert the this blinding process,
  denoted `r`.
- Finalize(x, r, Z): Finalize the OPRF evaluation using input `x`,
  random inverter `r`, and evaluation output `Z`, yielding output `y`.

Moreover, the following OPRF server APIs:

- Evaluate(k, M): Evaluate input element `M` using input key `k`, yielding output
  element `Z`. This is equivalent to the Evaluate function described in {{OPRF, Section 3.3.1}},
  where `k` is the private key parameter.
- DeriveKeyPair(seed, info): Derive a private and public key pair deterministically
  from a seed, as described in {{OPRF, Section 3.2}}. In this specification,
  the info parameter to DeriveKeyPair is set to "OPAQUE-DeriveKeyPair".

Finally, this specification makes use of the following shared APIs and parameters:

- SerializeElement(element): Map input `element` to a fixed-length byte array `buf`.
- DeserializeElement(buf): Attempt to map input byte array `buf` to an OPRF group element.
  This function can raise a DeserializeError upon failure; see {{OPRF, Section 2.1}}
  for more details.
- Noe: The size of a serialized OPRF group element output from SerializeElement.
- Nok: The size of an OPRF private key as output from DeriveKeyPair.

This specification uses the OPRF mode (0x00) from {{OPRF, Section 3.1}}.

## Key Derivation Function and Message Authentication Code {#deps-symmetric}

A Key Derivation Function (KDF) is a function that takes some source of initial
keying material and uses it to derive one or more cryptographically strong keys.
This specification uses a KDF with the following API and parameters:

- Extract(salt, ikm): Extract a pseudorandom key of fixed length `Nx` bytes from
  input keying material `ikm` and an optional byte string `salt`.
- Expand(prk, info, L): Expand a pseudorandom key `prk` using optional string `info`
  into `L` bytes of output keying material.
- Nx: The output size of the `Extract()` function in bytes.

This specification also makes use of a Message Authentication Code (MAC) with
the following API and parameters:

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
{{OPRF, Section 2.1}}.

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
  uint8 blinded_message[Noe];
} RegistrationRequest;
~~~

data
: A serialized OPRF group element.

~~~
struct {
  uint8 evaluated_message[Noe];
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
  (blind, blinded_element) = Blind(password)
  blinded_message = SerializeElement(blinded_element)
  Create RegistrationRequest request with blinded_message
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

Exceptions:
- DeserializeError, when OPRF element deserialization fails.

def CreateRegistrationResponse(request, server_public_key,
                               credential_identifier, oprf_seed):
  seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nseed)
  (oprf_key, _) = DeriveKeyPair(seed, "OPAQUE")

  blinded_element = DeserializeElement(request.blinded_message)
  evaluated_element = Evaluate(oprf_key, blinded_element)
  evaluated_message = SerializeElement(evaluated_element)

  Create RegistrationResponse response with (evaluated_message, server_public_key)
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

Exceptions:
- DeserializeError, when OPRF element deserialization fails.

def FinalizeRequest(password, blind, response, server_identity, client_identity):
  evaluated_element = DeserializeElement(response.evaluated_message)
  oprf_output = Finalize(password, blind, evaluated_element, nil)

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
- blind, the random blinding inverter returned by `Blind()`; and
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
  uint8 blinded_message[Noe];
} CredentialRequest;
~~~

data
: A serialized OPRF group element.

~~~
struct {
  uint8 evaluated_message[Noe];
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
  (blind, blinded_element) = Blind(password)
  blinded_message = SerializeElement(blinded_element)
  Create CredentialRequest request with blinded_message
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

Exceptions:
- DeserializeError, when OPRF element deserialization fails.

def CreateCredentialResponse(request, server_public_key, record,
                             credential_identifier, oprf_seed):
  seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
  (oprf_key, _) = DeriveKeyPair(seed, "OPAQUE")

  blinded_element = DeserializeElement(request.blinded_message)
  evaluated_element = Evaluate(oprf_key, blinded_element)
  evaluated_message = SerializeElement(evaluated_element)

  masking_nonce = random(Nn)
  credential_response_pad = Expand(record.masking_key,
                                   concat(masking_nonce, "CredentialResponsePad"),
                                   Npk + Ne)
  masked_response = xor(credential_response_pad,
                        concat(server_public_key, record.envelope))
  Create CredentialResponse response with (evaluated_message, masking_nonce, masked_response)

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

Exceptions:
- DeserializeError, when OPRF element deserialization fails.

def RecoverCredentials(password, blind, response,
                       server_identity, client_identity):
  evaluated_elemenet = DeserializeElement(response.evaluated_message)

  oprf_output = Finalize(password, blind, evaluated_elemenet, nil)
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
  deterministically from the input `seed`. This function is implemented as
  DeriveKeyPair(seed, "OPAQUE-DeriveAuthKeyPair"), where DeriveKeyPair is
  as specified in {{OPRF, Section 3.2}}.
- GenerateAuthKeyPair(): Return a randomly generated private and public key
  pair. This can be implemented by generating a random private key `sk`, then
  computing `pk = RecoverPublicKey(sk)`.
- SerializeElement(element): A member function of the underlying group that
  maps `element` to a unique byte array, mirrored from the definition of the
  similarly-named function of the OPRF group described in
  {{OPRF, Section 2.1}}.

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

- The OPRF protocol uses the "base mode" variant of {{OPRF}} and implements
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
{{OPRF}} and abort accordingly.
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

- Clients construct envelope contents without revealing the password to the server, as described in {{offline-phase}}, whereas the servers construct envelopes in {{OPAQUE}}. This change adds to the security of the protocol. {{OPAQUE}} considered the case where the envelope was constructed by the server for reasons of compatibility with previous UC modeling. An upcoming paper analyzes the registration phase as specified in this document.
- Envelopes do not contain encrypted credentials. Instead, envelopes contain information used to derive client private key material for the AKE. This variant is also analyzed in the new paper referred to in the previous item. This change improves the assumption behind the protocol by getting rid of equivocability and random key robustness for the encryption function. The latter property is only required for authentication and achieved by a MAC.
- Envelopes are masked with a per-user masking key as a way of preventing client enumeration attacks. See {{preventing-client-enumeration}} for more details. This extension does not add to the security of OPAQUE as an aPAKE but only used to provide a defense against enumeration attacks. In the analysis, this key can be simulated as a (pseudo) random key.
- Per-user OPRF keys are derived from a client identity and cross-user seed as a mitigation against client enumeration attacks. See {{preventing-client-enumeration}} for more details. The analysis of OPAQUE assumes OPRF keys of different users are independently random or pseudorandom. Deriving these keys via a single PRF (i.e., with a single cross-user key) applied to users' identities satisfies this assumption.
- The protocol outputs an export key for the client in addition to shared session key that can be used for application-specific purposes. This key is a pseudorandom value independent of other values in the protocol and have no influence in the security analysis (it can be simulated with a random output).
- The protocol admits optional application-layer client and server identities. In the absence of these identities, client and server are authenticated against their public keys. Binding authentication to identities is part of the AKE part of OPAQUE. The type of identities and their semantics are application dependent and independent of the protocol analysis.
- The protocol admits application-specific context information configured out-of-band in the AKE transcript. This allows domain separation between different application uses of OPAQUE. This is a mechanism for the AKE component and is best practice as for domain separation between different applications of the protocol.
- Servers use a separate identifier for computing OPRF evaluations and indexing into the password file storage, called the credential_identifier. This allows clients to change their application-layer identity (client_identity) without inducing server-side changes, e.g., by changing an email address associated with a given account. This mechanism is part of the derivation of OPRF keys via a single OPRF. As long as the derivation of different OPRF keys from a single OPRF have different PRF inputs, the protocol is secure. The choice of such inputs is up to the application.

## Security Analysis

Jarecki et al. {{OPAQUE}} proved the security of OPAQUE
in a strong aPAKE model that ensures security against pre-computation attacks
and is formulated in the Universal Composability (UC) framework {{Canetti01}}
under the random oracle model. This assumes security of the OPRF
function and the underlying key exchange protocol. In turn, the
security of the OPRF protocol from {{OPRF}} is proven
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
see {{OPRF}} for more information. For OPAQUE, these attacks
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
includes the (OPRF, Hash, MHF, KDF, MAC, Group, Context) tuple, where the Group
matches that which is used in the OPRF. These test vectors were generated using
draft-09 of {{OPRF}}.

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
client_public_key: c44d957470058d59c3190dee73c81353127bae04d22ce5956e
39961f7b68d921
auth_key: 09535c6f998ecbcdf3fb30cedd00e2723af14b066b0e1188fde8ae15e0e
a4d621e41efd3b0d0db7d9a09e79d1d815051d6bd7a54fb32df7d65fcb5e121afcac9
randomized_pwd: 4a54bd150ae70a76c624dcb306538e163a0d90caecede93fcc881
4c5d234aac974900e64a70002461ff7d7eb2a3c137cc28952217f206d3ba2ffadbc73
7dfb0b
envelope: d323fef4ead34cde967798f2e9784f69d233b1a6da7add58b2c95a57bc2
13acabb3b24440da1af73c88ef44ec3361034c980749c5335e010c69c0519412c667e
44bbccbebc4a2775c055542c50aed0aea4136c1af351a0ba256ff0c0589d7665
handshake_secret: ddcf3684026df6d2ed8130422d7ede1578726e9269d9519863a
48e1fe10d942d0d6743cd8d27bf58ed8271abc2c76e459fb4019d98fac8a6a46b30f5
a8da5012
server_mac_key: 1b5ecef534985b44bee7f5eba146246db3d4daabb70f876c4ffa4
a5ce4580eba256165c8f1bce132a37d74bc38c71cdaaa16a3a91b6714112263b0c515
1f6b9b
client_mac_key: ca3209b30314c087f10dcfbd8bb30de4dcf7d05aed8e0899eaf5a
be43a726a2d7d66f15d6cbd91219619ded59c19d9d3267a9d29912f226409bcd34b0e
733469
oprf_key: 34775e3a1a06cc11df4d388034b0a8353b48c060ca096c67f8f7a620f23
79009
~~~

#### Output Values

~~~
registration_request: 34353245449074b76eb17f124b5837da7496b2c6748d288
dee41d6269d0a995e
registration_response: b0d335cb7cdb9bcff550c1dd7386fb48ba6252f2f05888
85052259eac46fcf21b078d8e20de67ae43a6fb7ace867096a648ae5cf62857e10b3c
cc28ac9b6cc7c
registration_upload: c44d957470058d59c3190dee73c81353127bae04d22ce595
6e39961f7b68d9214ae58e08d7aa374e9195bc3f71ddb19e0f70033d993e826d99766
5f0d32601a1dbff6ade1ec17d9e5e7efab3f68d9ee54346fe45705de72de85f0d497c
6dce8ad323fef4ead34cde967798f2e9784f69d233b1a6da7add58b2c95a57bc213ac
abb3b24440da1af73c88ef44ec3361034c980749c5335e010c69c0519412c667e44bb
ccbebc4a2775c055542c50aed0aea4136c1af351a0ba256ff0c0589d7665
KE1: 4c1e02cf6b07ec1881adde0e04746648de2a87becca32f44fe1b6c5ff1cba779
18b5420ec2386513929cede49a06199dea238cf3d05672f48cdd4960726d14031a7ae
48eac1f61a481d6cbb3256ea9852b6f2858f9d351c5c9e9d9839a0b333c
KE2: a2d577931fd0c9a53e0f647f1240bb1e98b223fe39c23a0f2e22bf7364ff9618
521432344d52c17cc8ca390f9823c266b2b65fe9088a623e83ce5db56b66fd9aa3c28
376ad267563ac71ae63f471a74e305a9103c373cd91912ee02e57ffa0f9b1aa73ed57
ce53d76122d9bc10aaa43fc391ea4ba0bb95bcccb419ce437f9774e8cb72568d1fe90
8b0076d650bfae3ded635b0ff58187a985129550ad393896c2229ded1a710cb02a106
094f29df242707aedc565081b756fc2bf92e6c0a29f462e17ecc3cdc9f918dbacacdd
111f91ff04d765299320300d44aaf368a5704e7b04e962a2139901078ac4c9f240e08
572f31114338db80a4852847c59d7aaa72f1c02fee54fa73fc5edf0d42edaf14d2c45
caeff7a2124eb488c6500a6011b3a2e1d6381b92167b82e5bb96be0e6e5f4b8185a8f
6d81287e49622cbde2fff5e3
KE3: f03640e482505d5f4874fd37bd70b38bc0f3eb360fb356ac1807f2f3aba78f6e
eb965b80d66a84a63be9730e8bf7e9cf6158d20ba8661bd83e86e6cc060cda15
export_key: bf567e23104ec91693ae0d04f034115b9f8dfb06217dd9b22a5ea1706
fadfde7a39d03cba9dcfb4f1722cb0f28ecae4d19cf765992248cc121a34418de40db
26
session_key: e0253805477d12eac29e6c05b51a453ac4fdfd975a5f8688a2026e18
71fb1773f25277d2dc83446c53bde7f027e65ad5321df04f63fff300f377a046f2995
5ea
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
client_public_key: 54e72d9dac4d9a53574436cd1d43d302cc0c3f097b887cfd02
4857c228cd444e
auth_key: 22f2706beb43a6172176d3717696524ca180e6ba24c9dd9fc556ca09304
076452d2f4753b5298af94629e49e8adb9836ab05d64bdf44b88c6262f69945fceb3c
randomized_pwd: c337b34490af7af6a5d15519903da4dee275169866e21a6a549ad
c21776eecab3ff19c1e6dfc5d76870a3a39b6d1b72bcfca0906837f087c55ec46ad80
861350
envelope: 30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def2
28c851513822e03878dd26c24616021530d2ccfc3ffb39ad984c547d7b836842e1cfb
65032d5279f1c523d6d3b05c94a63775d06b740d385a2015b5a7097cda3963a7
handshake_secret: f32f5870a1d6e0d776e062cb0447912a26d96043cd3fa73cae2
d9425348c1dac8f5d8e7429e933f9cc7c7498c544878124da2384e635a83289bf856a
c12ed57c
server_mac_key: 57ebf95c7905a1a790db461c5cf73f6e8583513db7df5e292798b
b7c232a2beb639bf93f29303faf3b00ac33d269aa6757fd3d4be53761c1d92447c981
c7566a
client_mac_key: 76a6a2ee8c514a50fdd1bb34eaa1195f3437c874bc22cd819d71b
d0f86db0604e47e58797e25d1fe252e101733df846b6bbc1d8ab76cce4b60331648d1
87c1b4
oprf_key: 406b9847a5f848eb1f7fd11639178d77e6d218390ee3459c73b62909eb8
07909
~~~

#### Output Values

~~~
registration_request: facacbb0b0768ec4e22629ca2f37f9b29c178f67a4f4019
3d517f81416789068
registration_response: c26c857c0568950d35af89266ce6ed10d6b37e054bf6da
7ce0812f6057bfdc69561f67c72c59ec3b02803932603103014946039dfb9b23216c9
cea76dcd2a533
registration_upload: 54e72d9dac4d9a53574436cd1d43d302cc0c3f097b887cfd
024857c228cd444e76c288d1f470297ad1a69eaff93805602813d1ea8b8e69f52e396
dcea03e092229ce2409dd017749eaf5315a933cf4af0514b3e993876b8d30b2429679
8f1e0630635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def228c8
51513822e03878dd26c24616021530d2ccfc3ffb39ad984c547d7b836842e1cfb6503
2d5279f1c523d6d3b05c94a63775d06b740d385a2015b5a7097cda3963a7
KE1: 2088e02ac314f323aebbea61ed5c998f3fee856957e573b6574b93cf98de8108
87ef09986545b295e8f5bbbaa7ad3dce15eb299eb2a5b34875ff421b1d63d7a240c7c
67ee30fa68cbed3dba0d276ec22933e6916eb682eda7b48953a62164f16
KE2: 2ecdd280fa5b991b2c5ac259f2a4d095b0b7da66afbfe3545c2b62530dafa028
6b2e9019503d8495c6d04efaee8370c45fa1dfad70201edd140cec8ed6c73b5f8027b
cc70557a3652051cd76ca900dd233b500ef7fd2f49f5b49b7e71a3c5c98bfde64f1bf
ceb77cd0128df90be6d7cf4a349a16fbcfe864a2ce5ac3ca6dcd840cd920ea58bfac4
03ffcdde3f87aa686835d2bede398b7943bc2b41cd00010d2889af2097d01ec2ff20e
146a94bf7f0fe598c626b8b62a76386122d4b84d0a0a0d0d88f0936c712d3e901b42c
b792f3657240ce5296dd5633e7333531009c11e560895c14306f5f33e9c23766c0120
ed9f745c4cc809a1f4a416665b3282f06104458e9d05e8db02c0f4f6446d88f67993e
598142913aa0dd5e66f0ccad3638422c13e6ebe8f332c1fda36eb0dfd292343e035cb
85eaf56eb38cb8159feb1a44
KE3: 00f041b477940a05abd723abbb57af21a1e15859e99ddb46765bddafe5e189dc
566ac94bcb37fda4890d95060fc32ebfba8a10ea464811fa16754a9aca6bde16
export_key: 2c71af1848f92c46f35976ce5a812d60a6ec86cf29c4152c83667e329
d8fe0a11a49f8cb67185059bbd352949b77b6810e6435a98805c324c713a0b9b8e555
01
session_key: 9b4b72ca4dac89b13054fef04f790c756f761554f7a95cbd52399b72
c5ec931f71ea1e72bae403145055f7921e45dbf1bf8e65d9e289c8a1a856cdbe74cc6
958
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
client_public_key: 0207cc04cd0eb402c6c0ff709b37c7ff7518305268bec1ac57
340ff81cc24afe1c
auth_key: 992856f90d2afbc319aea1fae2b7ea3f769862e347a33930f00e366da3a
14e73
randomized_pwd: 3d65d6f82a100a5d2063e2b671c85aca39c6101d184015b6a20c5
a885089adb8
envelope: 4a0f9f1984ff1f2a310fe428d9de5819bf63b3942dbe09f991ca0cf545e
33a8ff97a50a042f27a7b0ee41ef49d89a9299c79aceb7663707c552cab5b6018df51
handshake_secret: 174f0c8df43db239f28784e6d9ebe86cfc4719b612c655e1a89
9512b1899173c
server_mac_key: 163fedfbfc7320d757a87bc98cb545e46223a3372e53c26b88852
2301074a76a
client_mac_key: 065f54fcc7a36c08c252930c2f1cdb94e4bf87526be92aa535e0d
f2e3f203e3f
oprf_key: 195babb7cef7b670c35866e4d8159dc1f9a36143c98884c23a4ccc55d01
4cc8d
~~~

#### Output Values

~~~
registration_request: 03282f9e0421bf75d92335b924c4e8acea6299323e02299
a999b818482a3b69be9
registration_response: 02b4a4e06a96a7e4e260a57192a50deae8a30b139e762d
2ef8e57866f0b153d74503845043cc460779d3d868894fd28dcf4a0814e6fdd7b8776
9e6d4ba4c477df6e7
registration_upload: 0207cc04cd0eb402c6c0ff709b37c7ff7518305268bec1ac
57340ff81cc24afe1c257debde1ce06f34605ad72ece788e28dcc7ab4ff8b1f4b4597
242231c84875c4a0f9f1984ff1f2a310fe428d9de5819bf63b3942dbe09f991ca0cf5
45e33a8ff97a50a042f27a7b0ee41ef49d89a9299c79aceb7663707c552cab5b6018d
f51
KE1: 0337f1c7b981c4488967bf2808ff63a7e0fe194f09c2b72f98c4122a60fdb8de
f4e206269fe3eabd2b6e928b97b901c4819a3e89f48f9a72f09280e203ef27d9ef037
53c309e7c68be892012552680ae399bb786cd2fc1ef92e928b285adec7296cb
KE2: 026087d7ec64ede8ec2bd7995136081e8aa588b8531f90ef658a3c9646769711
e0344022969d17d9cf4c88b7a9eec4c36bf64de079abb6dc7a1d46439446498f9593e
7f989d7cbdd5f6fa924f4e465c9763141322fd9b619d53a1989ea1cacc99de7814d78
9e519100bb93784261a5ac8f129a4f9567dfd1d891bd9e1176e06d59e0d10067639cd
5d8502c50b52f9b4721f767c76a8ed6cdc3625ea2837513d3300869259e0708bdfab7
94f689eec14c7deb7edde68c81645156cf278f21161e3aaa02d7f81fa9773faf00efa
7021a476abbfa77740267e841b5e55cf809944d436a9385922d8143558061635181f2
bed0b8ac0fc3d7a0848fd40f49a1f5369c8e67dd
KE3: 133d06b1488819a05d211f8a55c591e55cb010a5471d607b1f648dfa3162cb54
export_key: 62828b967aa3472fdf5f10409992386ceb1dcf6d8ea922e40c4df6f55
c3fd1e1
session_key: 7a8665a719a3c8be6b83c573e1b793fe784e67602b72c1e03ac8e1f4
6e92396f
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
client_public_key: 03a78c29820e932ad07dd81c22d57626cbf7a43781763626bc
5bdd985dd2f1979d
auth_key: 5f271fe14cd9102cc40cc591eab4af55ca1c497941b076aa8d3dd4a70ef
ee235
randomized_pwd: f1929054028412506056e8d7dcdd4cf5e1291362400055e5309bd
dd18b79e65f
envelope: 0051724f14d71ff13ba5add017512cce702800f4272cdae1976cbfbdfd6
ba61d9d2e83d2c44132bf25a19b1611524feb85e95cb7a43ca83e91f6edec2285265c
handshake_secret: 35d4f3fde3e184db3bbb1582b13b93d0bd5468787c6c9ff1243
a91de9c9de268
server_mac_key: 61476e0274ed6672236fd83022c1fbee5a5a74c8a9b6a2dfe9577
4795daf2f9e
client_mac_key: 5245c765a0e4b4c1ce0ffbdc994f0a5a9789a5a4bef7fa9ed8341
6f346f045e6
oprf_key: ca2e88042a4afc13f185cb14337ec1ffc644cf7bd0d9b8b162170de61e8
cd2f6
~~~

#### Output Values

~~~
registration_request: 022c10067956d68ef7bcda9f087e20b0c9f64db7d92b11b
35bb6ad7da84bdf2d94
registration_response: 025a26a48fde22a8e546e94b6e5fb8df4322ca70b2f13b
c9f5348d41684ba07af1029022b70aac38a4b838dc694744e10ae6ece18414b5e5e5b
294d1ee4ba2e1b592
registration_upload: 03a78c29820e932ad07dd81c22d57626cbf7a43781763626
bc5bdd985dd2f1979d78b02ea64b7b51b0dd29d5b57c06db624d9fdd00ca77e04ca9a
a7a0acab7c1230051724f14d71ff13ba5add017512cce702800f4272cdae1976cbfbd
fd6ba61d9d2e83d2c44132bf25a19b1611524feb85e95cb7a43ca83e91f6edec22852
65c
KE1: 02404ed848dc2f1546573a10d9118b0cee33f495eb7407a1eaf9861c4621d7b4
afc42416787f78b5321bad1c8b6ad879e348e15bd698ee70b2c51d3e89d9c08b00039
6372f51d9440c44c8ddb84f45bb13280d19a7a289d16ff01f6813ba0e18ddca
KE2: 0363338cf72e021d366a5875e97fc542f16e12753b4bb258c1b66a8cc06126ef
ea6f768fd0979f8dc006ca297e7954ebf0e81a893021ee24acc35e1a3f4b5e036667a
33723ffe167c893fb3a7341f2f5317306904ded609208775b313c19004d172880265d
b75876739d8babc98a821429d1710736c95b74071e23d17873ab7b88b8da0cfda22fa
24bc00700c2ddbcc783ab75a1c724a5b27c0e3a91f52fab5a11843179547a4489c871
8048ba107066398cfe2f8b5b2c0cdd8afa9fcaf662e5f2310260f1b9fe339983392e9
15678594d4ef64b35184832a3ea93612ee738afe194315cb503594dd29063319c7b9a
9dbfe5c2ded202209c88d44950908a68a6b74006
KE3: 8e8e2f59118204912c7244c6444097c4c3f8e9333bad948043ca18c10bb54c34
export_key: 9a7f2522e1225348e9ae128e9e97717b767cc590a150239dd4f0a5314
0b8321f
session_key: 05f4032709067e8f3ff4ec823a701840446c9e321b3ac2c2bee3168e
8e8fba36
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
KE2: de83f36c5b681e1802e1968aaeca8856e80da47e1b03ad5c8d37d3acf5685a0b
e0d04374ad9a276620c681abfca7bdb432e63509e5ec96ed2ec5542f6fc7db2337d59
904539bac9f84d61da7a9072096249e25306311b81065aded1e5ba651a02b273b4bfd
9e468a56b2d5cebd1a38bfc0a550601979e808842391a8c1f93cf27723d663ce06266
e0f27ec38d3b824d66fa7c43d68d7cd6c8cfe2775748887d24cdf1b07f04a33d51e7f
56b53156545a35e4becd8822e875a1441857332c77e5a91c9485d74c9010185f462ce
1eec52f588a8e392f36915849b6bfcb6bd5b904f29cc7cbbc76091a0774bcae7239a9
c8980982ebee753763576741240d5a36215187c85a53e629b693136208713864e0116
6580d67142b3493c9851affe755b292594c0af5ea573125c821c1a1fbfdbf17afd9d6
7ea424f59c7c329455d03f3f
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
KE2: 0347c54d4df029f57c21bb2d6c9bdafd662d7948e74d028e99ceffa6934051ab
0f3292ebc7c8a8c933f0fc98006c14e59960a4d2f9fab11e9bf5247f7c1c9d9a61ed6
43d6e5b97fc9de6cfbfee003a29ad5ba7f2ae8a68e53f0ae08d54f4ea6948673bfdbd
215a31a90769ffe74825497231b31f04994c2275d4e5c34db6f5f74c6296b7b95716d
8b6e86729b057e63e88eadd107f2c04abe3417df6aaa64df6531c466cfb980f9a2604
c25d83d1a98a38717e97bfde3b1dd8eb8d3346ca21d8a6430277f390bba2952e8bc67
6c54663f09d3e7f2c7bf92c40ee46ce374bc8e1c247383efc90154f5d264d3fb8b255
d1862600168c77cf64f796bdbec5d5b8832912a8
~~~
