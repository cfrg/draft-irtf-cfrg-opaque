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
    ins: H. Krawczyk
    name: Hugo Krawczyk
    organization: Algorand Foundation
    email: hugokraw@gmail.com
 -
    ins: D. Bourdrez
    name: Daniel Bourdrez
    email: dan@bytema.re
 -
    ins: K. Lewi
    name: Kevin Lewi
    organization: Novi Research
    email: lewi.kevin.k@gmail.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    organization: Cloudflare
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
    title: "Signal recommended cryptographic algorithms"
    seriesinfo: https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms
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
uncommon security incident, even among security-conscious companies.
Moreover, plaintext password authentication over secure channels like
TLS is also vulnerable to cases where TLS may fail, including PKI
attacks, certificate mishandling, termination outside the security
perimeter, visibility to middleboxes, and more.

Asymmetric (or Augmented) Password Authenticated Key Exchange (aPAKE)
protocols are designed to provide password authentication and
mutually authenticated key exchange in a client-server setting without
relying on PKI (except during client/password registration) and without
disclosing passwords to servers or other entities other than the client
machine. A secure aPAKE should provide the best possible security for a password
protocol. Namely, it should only be open to inevitable attacks, such as
online impersonation attempts with guessed client passwords and offline
dictionary attacks upon the compromise of a server and leakage of its
password file. In the latter case, the attacker learns a mapping of
a client's password under a one-way function and uses such a mapping to
validate potential guesses for the password. Crucially important is
for the password protocol to use an unpredictable one-way mapping.
Otherwise, the attacker can pre-compute a deterministic list of mapped
passwords leading to almost instantaneous leakage of passwords upon
server compromise.

Despite the existence of multiple designs for
(PKI-free) aPAKE protocols, none of these protocols are secure against
pre-computation attacks. In particular, none of these protocols can
use the standard technique against pre-computation that combines
_secret_ random values ("salt") into the one-way password mappings.
Either these protocols do not use a salt at all or, if they do, they
transmit the salt from server to client in the clear, hence losing the
secrecy of the salt and its defense against pre-computation. Furthermore,
transmitting the salt may require additional protocol messages.

This document describes OPAQUE, a PKI-free secure aPAKE that is secure
against pre-computation attacks. OPAQUE provides forward secrecy (essential
for protecting past communications in case of password leakage) and the
ability to hide the password from the server, even during password
registration. Furthermore, OPAQUE enjoys good performance and an array
of additional features including the ability to increase
the difficulty of offline dictionary attacks via iterated hashing
or other hardening schemes, and offloading these operations to the
client (that also helps against online guessing attacks); extensibility of
the protocol to support storage and retrieval of client secrets solely
based on a password; being amenable to a multi-server distributed
implementation where offline dictionary attacks are not possible without
breaking into a threshold of servers (such a distributed solution requires
no change or awareness on the client-side relative to a single-server implementation).

OPAQUE is defined and proven as the composition of two functionalities:
an oblivious pseudorandom function (OPRF) and an authenticated key
exchange (AKE) protocol. It can be seen
as a "compiler" for transforming any suitable AKE protocol into a secure
aPAKE protocol. (See {{security-considerations}} for requirements of the
OPRF and AKE protocols.) This document specifies one OPAQUE instantiation
based on 3DH {{SIGNAL}}. Other instantiations are possible, as discussed in
{{alternate-akes}}, but their details are out of scope for this document.
In general, the modularity of OPAQUE's design makes it easy to integrate
with additional AKE protocols, e.g., TLS, and with future ones such as those
based on post-quantum techniques.

OPAQUE consists of two stages: registration and authenticated key exchange.
In the first stage, a client registers its password with the server and stores
its encrypted credentials on the server. In the second stage, a client obtains
those credentials, recovers them using the client's password, and subsequently
uses them as input to an AKE protocol.

Currently, the most widely deployed PKI-free aPAKE is SRP {{?RFC2945}}, which is
vulnerable to pre-computation attacks, lacks proof of security, and is less efficient
relative to OPAQUE. Moreover, SRP requires a ring as it mixes addition and
multiplication operations, and thus does not work over plain elliptic curves.
OPAQUE is therefore a suitable replacement for applications that use SRP.

This draft complies with the requirements for PAKE protocols set forth in
{{RFC8125}}.

## Requirements Notation

{::boilerplate bcp14}

## Notation

The following functions are used throughout this document:

- I2OSP and OS2IP: Convert a byte string to and from a non-negative integer as
  described in Section 4 of {{?RFC8017}}. Note that these functions operate on
  byte strings in big-endian byte order.
- concat(x0, ..., xN): Concatenate byte strings. For example,
  `concat(0x01, 0x0203, 0x040506) = 0x010203040506`.
- random(n): Generate a cryptographically secure pseudorandom byte string of length `n` bytes.
- xor(a,b): Apply XOR to byte strings. For example, `xor(0xF0F0, 0x1234) = 0xE2C4`.
  It is an error to call this function with two arguments of unequal length.
- ct_equal(a, b): Return `true` if `a` is equal to `b`, and false otherwise.
  This function is constant-time in the length of `a` and `b`, which are assumed
  to be of equal length, irrespective of the values `a` or `b`.

Except if said otherwise, random choices in this specification refer to
drawing with uniform distribution from a given set (i.e., "random" is short
for "uniformly random"). Random choices can be replaced with fresh outputs from
a cryptographically strong pseudorandom generator, according to the requirements
in {{!RFC4086}}, or pseudorandom function. For convenience, we define `nil` as a
lack of value.

The name OPAQUE is a homonym of O-PAKE where O is for Oblivious. The name
OPAKE was taken.

# Cryptographic Dependencies {#dependencies}

OPAQUE relies on the following cryptographic protocols and primitives:

- Oblivious Pseudorandom Function (OPRF, {{!I-D.irtf-cfrg-voprf}}, version -06):
  - Blind(x): Convert input `x` into an element of the OPRF group, randomize it
    by some scalar `r`, producing `M`, and output (`r`, `M`).
  - Evaluate(k, M): Evaluate input element `M` using private key `k`, yielding
    output element `Z`.
  - Finalize(x, r, Z): Finalize the OPRF evaluation using input `x`,
    random scalar `r`, and evaluation output `Z`, yielding output `y`.
  - DeriveKeyPair(seed): Derive a private and public key pair deterministically
    from a seed.
  - Noe: The size of a serialized OPRF group element.
  - Nok: The size of an OPRF private key.

Note that we only need the base mode variant (as opposed to the verifiable mode
variant) of the OPRF described in {{I-D.irtf-cfrg-voprf}}.

- Key Derivation Function (KDF):
  - Extract(salt, ikm): Extract a pseudorandom key of fixed length `Nx` bytes from
    input keying material `ikm` and an optional byte string `salt`.
  - Expand(prk, info, L): Expand a pseudorandom key `prk` using optional string `info`
    into `L` bytes of output keying material.
  - Nx: The output size of the `Extract()` function in bytes.

- Message Authentication Code (MAC):
  - MAC(key, msg): Compute a message authentication code over input `msg` with key
    `key`, producing a fixed-length output of `Nm` bytes.
  - Nm: The output size of the `MAC()` function in bytes.

- Hash Function:
  - Hash(msg): Apply a cryptographic hash function to input `msg`, producing a
    fixed-length digest of size `Nh` bytes.
  - Nh: The output size of the `Hash()` function in bytes.

- Memory Hard Function (MHF):
  - Harden(msg, params): Repeatedly apply a memory-hard function with parameters
    `params` to strengthen the input `msg` against offline dictionary attacks.
    This function also needs to satisfy collision resistance.

OPAQUE additionally depends on an Authenticated Key Exchange (AKE) protocol.
This specification defines one particular AKE based on 3DH; see {{ake-protocol}}.
We let `Npk` and `Nsk` denote the size of public and private keys, respectively,
used in the AKE. The AKE protocol must provide the following functions:

- RecoverPublicKey(private_key): Recover the public key related to the input `private_key`.
- DeriveAuthKeyPair(seed): Derive a private and public authentication key pair
  deterministically from the input `seed`.
- GenerateKeyPair(): Return a randomly generated private and public key pair. This can be
  implemented by generating a random private key `sk`, then computing `pk = RecoverPublicKey(sk)`.

Finally, all random nonces used in this protocol are of length `Nn` = 32 bytes.

# Protocol Overview {#protocol-overview}

OPAQUE consists of two stages: registration and authenticated key exchange.
In the first stage, a client registers its password with the server and stores
its encrypted credentials on the server. The client inputs its credentials,
which includes its password and user identifier, and the server inputs its
parameters, which includes its private key and other information. The client
output of this stage is a single value `export_key` that the client may use
for application-specific purposes, e.g., to encrypt additional information
to the server. The server output of this stage is a record corresponding to
the client's registration that it stores in a password file alongside other
client registrations as needed.

Registration is the only part in OPAQUE that requires an authenticated and
confidential channel, either physical, out-of-band, PKI-based, etc.

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

In the second stage, a client obtains credentials previously registered
with the server, recovers private key material using the password, and
subsequently uses them as input to an AKE protocol. As in the registration
phase, the client inputs its credentials, including its password and user
identifier, and the server inputs its parameters and password file record
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

The rest of this document describes the details of these stages in detail.
{{client-credential-storage}} describes how client credential information is
generated, encoded, encrypted, and stored on the server. {{offline-phase}} describes the
first registration stage of the protocol, and {{online-phase}} describes the
second authentication stage of the protocol. {{configurations}} describes how
to instantiate OPAQUE using different cryptographic dependencies and parameters.

# Client Credential Storage {#client-credential-storage}

OPAQUE makes use of a structure `Envelope` to manage client credentials.
This envelope holds information about its format and content for the client to
obtain its authentication material.

OPAQUE allows applications to either provide custom client private and public keys
for authentication, or to generate them internally. Each public and private key
value is encoded as a byte string, specific to the AKE protocol in which OPAQUE
is instantiated. These two options are defined as the `internal` and `external`
modes, respectively. See {{envelope-modes}} for their specifications.

Applications may pin key material to identities if desired. If no identity is given
for a party, its value MUST default to its public key. The following types of
application credential information are considered:

- client_private_key: The encoded client private key for the AKE protocol.
- client_public_key: The encoded client public key for the AKE protocol.
- server_public_key: The encoded server public key for the AKE protocol.
- client_identity: The client identity. This is an application-specific value,
  e.g., an e-mail address or normal account name. If not specified, it defaults
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
CreateCleartextCredentials(server_public_key, client_public_key,
                           server_identity, client_identity)

Input:
- server_public_key, The encoded server public key for the AKE protocol.
- client_public_key, The encoded client public key for the AKE protocol.
- server_identity, The optional encoded server identity.
- client_identity, The optional encoded client identity.

Output:
- cleartext_credentials, a CleartextCredentials structure

Steps:
1. if server_identity == nil
2.    server_identity = server_public_key
3. if client_identity == nil
4.    client_identity = client_public_key
5. Create CleartextCredentials cleartext_credentials
   with (server_public_key, server_identity, client_identity)
6. Output cleartext_credentials
~~~

During protocol execution, the identity values can be stored in an
implementation-specific `Credentials` object with names matching the
values.

~~~
struct {
  uint8 server_identity;
  uint8 client_identity;
} Credentials;
~~~

## Envelope Structure {#envelope-structure}

A client `Envelope` is constructed based on the `EnvelopeMode`, consisting
of an `InnerEnvelope` entry whose structure is determined by the mode. Future
modes MAY introduce alternate `InnerEnvelope` contents. `Envelope` is
defined as follows:

~~~
struct {
  uint8 nonce[Nn];
  InnerEnvelope inner_env;
  uint8 auth_tag[Nm];
} Envelope;
~~~

nonce: A unique nonce of length `Nn` used to protect this Envelope.

auth_tag: Authentication tag protecting the contents of the envelope, covering the envelope nonce,
`InnerEnvelope`, and `CleartextCredentials`.

inner_env: A mode dependent `InnerEnvelope` structure. See {{envelope-modes}} for its specifications.

The size of the serialized envelope is denoted `Ne` and varies based on the mode.
The exact value for `Ne` is specified in {{internal-mode}} and {{external-mode}}.

## Envelope Creation and Recovery {#envelope-creation-recovery}

Clients create an `Envelope` at registration with the function `CreateEnvelope` defined below.

For the `internal` mode, implementations can choose to leave out the `client_private_key`
parameter, as it is not used. For the `external` mode, implementations are free to
additionally provide `client_public_key` to this function. With this, the public key does
not need to be recovered by `BuildInnerEnvelope()` and that function should be adapted
accordingly.

~~~
CreateEnvelope(randomized_pwd, server_public_key, client_private_key,
               server_identity, client_identity)

Parameter:
- mode, the EnvelopeMode mode

Input:
- randomized_pwd, randomized password.
- server_public_key, The encoded server public key for
  the AKE protocol.
- client_private_key, The encoded client private key for
  the AKE protocol. This is nil in the internal key mode.
- server_identity, The optional encoded server identity.
- client_identity, The optional encoded client identity.

Output:
- envelope, the client's `Envelope` structure.
- client_public_key, the client's AKE public key.
- masking_key, a key used by the server to encrypt the
  envelope during login.
- export_key, an additional client key.

Steps:
1. envelope_nonce = random(Nn)
2. auth_key = Expand(randomized_pwd, concat(envelope_nonce, "AuthKey"), Nh)
3. export_key = Expand(randomized_pwd, concat(envelope_nonce, "ExportKey"), Nh)
4. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
5. inner_env, client_public_key = BuildInnerEnvelope(randomized_pwd, envelope_nonce, client_private_key)
6. cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
7. auth_tag = MAC(auth_key, concat(envelope_nonce, inner_env, cleartext_creds))
8. Create Envelope envelope with (envelope_nonce, inner_env, auth_tag)
9. Output (envelope, client_public_key, masking_key, export_key)
~~~

Clients recover their `Envelope` during authentication with the `RecoverEnvelope`
function defined below.

~~~
RecoverEnvelope(randomized_pwd, server_public_key, creds, envelope)

Input:
- randomized_pwd, randomized password.
- server_public_key, The encoded server public key for the AKE protocol.
- creds, a Credentials structure.
- envelope, the client's `Envelope` structure.

Output:
- client_private_key, The encoded client private key for the AKE protocol
- export_key, an additional client key

Steps:
1. auth_key = Expand(randomized_pwd, concat(envelope.nonce, "AuthKey"), Nh)
2. export_key = Expand(randomized_pwd, concat(envelope.nonce, "ExportKey", Nh)
3. (client_private_key, client_public_key) =
    RecoverKeys(randomized_pwd, envelope.nonce, envelope.inner_env)
4. cleartext_creds = CreateCleartextCredentials(server_public_key,
                      client_public_key, creds.server_identity,
                      creds.client_identity)
5. expected_tag = MAC(auth_key, concat(envelope.nonce, inner_env, cleartext_creds))
6. If !ct_equal(envelope.auth_tag, expected_tag),
     raise MacError
7. Output (client_private_key, export_key)
~~~

## Envelope Modes {#envelope-modes}

The `EnvelopeMode` specifies the structure and encoding of the
corresponding `InnerEnvelope`. This document specifies the values
of the two aforementioned modes:

~~~
enum {
  internal(1),
  external(2),
  (255)
} EnvelopeMode;
~~~

Each `EnvelopeMode` defines its own `InnerEnvelope` structure and must implement
the following interface:

- `inner_env, client_public_key = BuildInnerEnvelope(randomized_pwd, nonce, client_private_key)`:
  Build and return the mode's `InnerEnvelope` structure and the client's public key.
- `client_private_key, client_public_key = RecoverKeys(randomized_pwd, nonce, inner_env)`:
  Recover and return the client's private and public keys for the AKE protocol.

The implementations of this interface for both `internal` and `external` modes
are in {{internal-mode}} and {{external-mode}}, respectively.

The size of the envelope may vary between modes. If applications implement
{{preventing-client-enumeration}}, they MUST use the same envelope mode throughout
their lifecycle in order to avoid activity leaks due to mode switching.

### Internal mode {#internal-mode}

In this mode, the client's private and public keys are deterministically derived
from the OPRF output.

With the internal key mode the `EnvelopeMode` value MUST be `internal` and the
`InnerEnvelope` is empty, and the size `Ne` of the serialized `Envelope` is `Nn + Nm`.

To generate the private key OPAQUE-3DH implements `DeriveAuthKeyPair(seed)` as follows:

~~~
DeriveAuthKeyPair(seed)

Input:
- seed, pseudo-random byte sequence used as a seed.

Output:
- private_key, a private key
- public_key, the associated public key

Steps:
1. private_key = HashToScalar(seed, dst="OPAQUE-HashToScalar")
2. public_key = private_key * G
3. Output (private_key, public_key)
~~~

HashToScalar(msg, dst) is as specified in {{I-D.irtf-cfrg-voprf}},
except that the `dst` parameter is "OPAQUE-HashToScalar".

~~~
BuildInnerEnvelope(randomized_pwd, nonce, client_private_key)

Input:
- randomized_pwd, randomized password.
- nonce, a unique nonce of length `Nn`.
- client_private_key, empty value. Not used in this function,
  it only serves to comply with the API.

Output:
- inner_env, nil value (serves to comply with the API).
- client_public_key, the client's AKE public key.

Steps:
1. seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nsk)
2. _, client_public_key = DeriveAuthKeyPair(seed)
3. Output (nil, client_public_key)
~~~

Note that implementations are free to leave out the `client_private_key`
parameter, as it is not used.

~~~
RecoverKeys(randomized_pwd, nonce, inner_env)

Input:
- randomized_pwd, randomized password.
- nonce, a unique nonce of length `Nn`.
- inner_env, an InnerEnvelope structure. Not used in this
  function, it only serves to comply with the API.

Output:
- client_private_key, The encoded client private key for the AKE protocol
- client_public_key, The encoded client public key for the AKE protocol

Steps:
1. seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nsk)
2. client_private_key, client_public_key = DeriveAuthKeyPair(seed)
4. Output (client_private_key, client_public_key)
~~~

Note that implementations are free to leave out the `inner_env` parameter,
as it is not used.

### External mode {#external-mode}

This mode allows applications to import or generate keys for the client. This
specification only imports the client's private key and internally recovers the
corresponding public key. Implementations are free to import both, in which case
the functions `FinalizeRequest()`, `CreateEnvelope()`, and `BuildInnerEnvelope()`
must be adapted accordingly.

With the external key mode the `EnvelopeMode` value MUST be `external`, and the
size `Ne` of the serialized `Envelope` is `Nn + Nm + Nsk`.

An encryption key is generated from the hardened OPRF output and used to encrypt
the client's private key, which is then stored encrypted in the `InnerEnvelope`.
On key recovery, the client's public key is recovered using the private key.

~~~
struct {
  uint8 encrypted_creds[Nsk];
} InnerEnvelope;
~~~

encrypted_creds : Encrypted client_private_key. Authentication of this field is
ensured with the `auth_tag` field in the envelope that covers this `InnerEnvelope`.

If the implementation provides the `client_public_key`, then `BuildInnerEnvelope()`
can skip the `RecoverPublicKey()` call.

~~~
BuildInnerEnvelope(randomized_pwd, nonce, client_private_key)

Input:
- randomized_pwd, randomized password.
- nonce, a unique nonce of length `Nn`.
- client_private_key, the encoded client private key for the AKE protocol.

Output:
- inner_env, an InnerEnvelope structure.
- client_public_key, The encoded client public key for the AKE protocol.

Steps:
1. pseudorandom_pad = Expand(randomized_pwd, concat(nonce, "Pad"), len(client_private_key))
2. encrypted_creds = xor(client_private_key, pseudorandom_pad)
3. Create InnerEnvelope inner_env with encrypted_creds
4. client_public_key = RecoverPublicKey(client_private_key)
5. Output (inner_env, client_public_key)
~~~

~~~
RecoverKeys(randomized_pwd, nonce, inner_env)

Input:
- randomized_pwd, randomized password.
- nonce, a unique nonce of length `Nn`.
- inner_env, an InnerEnvelope structure.

Output:
- client_private_key, the encoded client private key for the AKE protocol.
- client_public_key, the client's AKE public key.

Steps:
1. encrypted_creds = inner_env.encrypted_creds
2. pseudorandom_pad = Expand(randomized_pwd, concat(nonce, "Pad"), len(encrypted_creds))
3. client_private_key = xor(encrypted_creds, pseudorandom_pad)
4. client_public_key = RecoverPublicKey(client_private_key)
5. Output (client_private_key, client_public_key)
~~~

# Offline Registration {#offline-phase}

This section describes the registration flow, message encoding, and helper functions.
In a setup phase, the client chooses its password, and the server chooses its own pair
of private-public AKE keys (server_private_key, server_public_key) for use with the
AKE, along with a Nh-byte oprf_seed. The server can use the same pair of keys with multiple
clients and can opt to use multiple seeds (so long as they are kept consistent for
each client). These steps can happen offline, i.e., before the registration phase.

If using `external` mode, the client provides a key pair
(client_private_key, client_public_key)
for an AKE protocol which is suitable for use with OPAQUE; See {{online-phase}}.
The private-public keys (client_private_key, client_public_key) may be randomly
generated (using a cryptographically secure pseudorandom number generator) for the
account or provided by the calling client. Clients MUST NOT use the same key pair
(client_private_key, client_public_key) for two different accounts.

Once complete, the registration process proceeds as follows. The client inputs
the following values:

- password: client password.
- creds: client credentials, as described in {{client-credential-storage}}.

The server inputs the following values:

- server_private_key: server private key for the AKE protocol.
- server_public_key: server public key for the AKE protocol.
- credential_identifier: client credential identifier.
- oprf_seed: seed used to derive per-client OPRF keys.

The registration protocol then runs as shown below:

~~~
  Client                                         Server
 ------------------------------------------------------
 (request, blind) = CreateRegistrationRequest(password)

                        request
              ------------------------->

(response, oprf_key) = CreateRegistrationResponse(request,
                          server_public_key,
                          credential_identifier,
                          oprf_seed)

                        response
              <-------------------------

 (record, export_key) = FinalizeRequest(client_private_key,
                                        password,
                                        creds,
                                        blind,
                                        response)

                        record
              ------------------------->
~~~

{{registration-functions}} describes details of the functions and the
corresponding parameters referenced above.

Both client and server MUST validate the other party's public key before use.
See {{validation}} for more details. Upon completion, the server stores
the client's credentials for later use. Moreover, the client MAY use the output
`export_key` for further application-specific purposes; see {{export-key-usage}}.

### Registration Messages

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
} RegistrationUpload;
~~~

client_public_key
: The client's encoded public key, corresponding to the private key `client_private_key`.

masking_key
: A key used by the server to preserve confidentiality of the envelope during login.

envelope
: The client's `Envelope` structure.

### Registration Functions {#registration-functions}

#### CreateRegistrationRequest

~~~
CreateRegistrationRequest(password)

Input:
- password, an opaque byte string containing the client's password.

Output:
- request, a RegistrationRequest structure.
- blind, an OPRF scalar value.

Steps:
1. (blind, M) = Blind(password)
2. Create RegistrationRequest request with M
3. Output (request, blind)
~~~

#### CreateRegistrationResponse {#create-reg-response}

~~~
CreateRegistrationResponse(request, server_public_key, credential_identifier, oprf_seed)

Input:
- request, a RegistrationRequest structure.
- server_public_key, the server's public key.
- credential_identifier, an identifier that uniquely represents the credential being
  registered.
- oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key.

Output:
- response, a RegistrationResponse structure.
- oprf_key, the per-client OPRF key known only to the server.

Steps:
1. ikm = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
2. (oprf_key, _) = DeriveKeyPair(ikm)
3. Z = Evaluate(oprf_key, request.data)
4. Create RegistrationResponse response with (Z, server_public_key)
5. Output (response, oprf_key)
~~~

#### FinalizeRequest {#finalize-request}

To create the user record used for further authentication, the client executes
the following function. In the internal key mode, the `client_private_key` is nil.

Depending on the mode, implementations are free to leave out the `client_private_key`
parameter (`internal` mode), or to additionally include `client_public_key`
(`external` mode). See {{envelope-creation-recovery}} for more details.

~~~
FinalizeRequest(client_private_key, password, creds, blind, response)

Input:
- client_private_key, the client's private key. In internal mode, this is nil.
- password, an opaque byte string containing the client's password.
- creds, a Credentials structure.
- blind, the OPRF scalar value used for blinding.
- response, a RegistrationResponse structure.

Output:
- record, a RegistrationUpload structure.
- export_key, an additional client key.

Steps:
1. y = Finalize(password, blind, response.data)
2. randomized_pwd = Extract("", Harden(y, params))
3. (envelope, client_public_key, masking_key, export_key) =
    CreateEnvelope(randomized_pwd, response.server_public_key, client_private_key,
                   creds.server_identity, creds.client_identity)
4. Create RegistrationUpload record with (client_public_key, masking_key, envelope)
5. Output (record, export_key)
~~~

See {{online-phase}} for details about the output export_key usage.

Upon completion of this function, the client MUST send `record` to the server.

#### Finalize Registration {#finalize-registration}

The server stores the `record` object as the credential file for each client
along with the associated `credential_identifier` and `client_identity` (if
different). Note that the values `oprf_seed` and `server_private_key` from the
server's setup phase must also be persisted.

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
server agree on a mutually authenticated shared secret key.

In this stage, the client inputs the following values:

- password: client password.
- client_identity: client identity, as described in {{client-credential-storage}}.
- client_info: optional, application-specific information to send to the server
  during the handshake.

The server inputs the following values:

- server_private_key: server private for the AKE protocol.
- server_public_key: server public for the AKE protocol.
- server_identity: server identity, as described in {{client-credential-storage}}.
- record: RegistrationUpload corresponding to the client's registration.
- credential_identifier: client credential identifier.
- oprf_seed: seed used to derive per-client OPRF keys.
- server_info: optional, application-specific information to send to the client
  during the handshake.

The client receives two outputs: a session secret and an export key. The export key
is only available to the client, and may be used for additional application-specific
purposes, as outlined in {{export-key-usage}}. The output `export_key` MUST NOT be
used in any way before the protocol completes successfully. See {{envelope-encryption}}
for more details about this requirement. The server receives a single output: a session
secret matching that of the client's.

The protocol runs as shown below:

~~~
  Client                                         Server
 ------------------------------------------------------
  ke1 = ClientInit(client_identity, password, client_info)

                         ke1
              ------------------------->

  ke2 = ServerInit(server_identity, server_private_key,
                    server_public_key, record,
                    credential_identifier, oprf_seed, ke1)

                         ke2
              <-------------------------

    (ke3,
    server_info,
    session_key,
    export_key) = ClientFinish(password, client_identity,
                              server_identity, ke2)

                         ke3
              ------------------------->

                       session_key = ServerFinish(ke3)
~~~

The rest of this section describes these authenticated key exchange messages
and their parameters in more detail. {{cred-retrieval}} discusses internal
functions used for retrieving client credentials, and {{ake-protocol}} discusses
how these functions are used to execute the authenticated key exchange protocol.

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
: A nonce used for the confidentiality of the masked_response field

masked_response
: An encrypted form of the server's public key and the client's `Envelope` structure

### Credential Retrieval Functions

#### CreateCredentialRequest {#create-credential-request}

~~~
CreateCredentialRequest(password)

Input:
- password, an opaque byte string containing the client's password.

Output:
- request, a CredentialRequest structure.
- blind, an OPRF scalar value.

Steps:
1. (blind, M) = Blind(password)
2. Create CredentialRequest request with M
3. Output (request, blind)
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
CreateCredentialResponse(request, server_public_key, record,
                         credential_identifier, oprf_seed)

Input:
- request, a CredentialRequest structure.
- server_public_key, the public key of the server.
- record, an instance of RegistrationUpload which is the server's
  output from registration.
- credential_identifier, an identifier that uniquely represents the credential
  being registered.
- oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key.

Output:
- response, a CredentialResponse structure.

Steps:
1. ikm = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
2. (oprf_key, _) = DeriveKeyPair(ikm)
3. Z = Evaluate(oprf_key, request.data)
4. masking_nonce = random(32)
5. credential_response_pad = Expand(record.masking_key,
     concat(masking_nonce, "CredentialResponsePad"), Npk + Ne)
6. masked_response = xor(credential_response_pad,
                         concat(server_public_key, record.envelope))
7. Create CredentialResponse response with (Z, masking_nonce, masked_response)
8. Output response
~~~

In the case of a record that does not exist, the server invokes the
CreateCredentialResponse function where the record argument is configured so that:

- record.masking_key is set to a random byte string of length Nh, and
- record.envelope is set to the byte string consisting only of zeros, of length Ne

Note that the responses output by either scenario are indistinguishable to an adversary
that is unable to guess the registered password for the client corresponding to credential_identifier.

#### RecoverCredentials {#recover-credentials}

~~~
RecoverCredentials(password, blind, response, creds)

Input:
- password, an opaque byte string containing the client's password.
- blind, an OPRF scalar value.
- response, a CredentialResponse structure.
- creds, a Credentials structure.

Output:
- client_private_key, the client's private key for the AKE protocol.
- server_public_key, the public key of the server.
- export_key, an additional client key.

Steps:
1. y = Finalize(password, blind, response.data)
2. randomized_pwd = Extract("", Harden(y, params))
3. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
4. credential_response_pad = Expand(masking_key,
     concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
5. concat(server_public_key, envelope) = xor(credential_response_pad,
                                              response.masked_response)
6. (client_private_key, export_key) =
    RecoverEnvelope(randomized_pwd, server_public_key, creds, envelope)
7. Output (client_private_key, response.server_public_key, export_key)
~~~

## AKE Protocol {#ake-protocol}

This section describes the authenticated key exchange protocol for OPAQUE using 3DH,
a 3-message AKE which satisfies the forward secrecy and KCI properties discussed in
{{security-considerations}}. The protocol consists of three messages sent between
client and server, each computed using the following application APIs:

- ke1 = ClientInit(client_identity, password, client_info)
- ke2, client_info = ServerInit(server_identity, server_private_key, server_public_key, record, credential_identifier, oprf_seed, ke1)
- ke3, server_info, session_key, export_key = ClientFinish(password, client_identity, server_identity, ke2)
- session_key = ServerFinish(ke3)

Outputs `ke1`, `ke2`, and `ke3` are the three protocol messages sent between client
and server. Outputs `client_info` and `server_info` correspond to the optional
information exchanged between client and server during the key exchange protocol.
And finally, `session_key` and `export_key` are outputs to be consumed by applications.
Applications can use `session_key` to derive additional keying material as needed.

Both ClientFinish and ServerFinish return an error if authentication failed. In this case,
clients and servers MUST NOT use any outputs from the protocol, such as `session_key` or
`export_key`. ClientInit and ServerInit both implicitly return internal state objects
`client_state` and `server_state`, respectively, with the following named fields:

~~~
struct {
  uint8 blind[Nok];
  uint8 client_secret[Nsk];
  KE1 ke1;
} ClientState;

struct {
  uint8 expected_client_mac[Nm];
  uint8 session_key[Nx];
} ServerState;
~~~

{{opaque-client}} and {{opaque-server}} specify the inner working of these functions
and their parameters for clients and servers, respectively.

Prior to the execution of these functions, both the client and the server MUST agree
on a configuration; see {{configurations}} for details.

### Protocol Messages

~~~
struct {
  CredentialRequest request;
  uint8 client_nonce[Nn];
  uint8 client_info<0..2^16-1>;
  uint8 client_keyshare[Npk];
} KE1;
~~~

request
: A `CredentialRequest` generated according to {{create-credential-request}}.

client_nonce
: A fresh randomly generated nonce of length `Nn`.

client_info
: Optional application-specific information to exchange during the protocol.

client_keyshare
: Client ephemeral key share of fixed size Npk, where Npk depends on the corresponding
prime order group.

~~~
struct {
  struct {
    CredentialResponse response;
    uint8 server_nonce[Nn];
    uint8 server_keyshare[Npk];
  } inner_ke2;
  uint8 enc_server_info<0..2^16-1>;
  uint8 server_mac[Nm];
} KE2;
~~~

response
: A `CredentialResponse` generated according to {{create-credential-response}}.

server_nonce
: A fresh randomly generated nonce of length `Nn`.

server_keyshare
: Server ephemeral key share of fixed size Npk, where Npk depends on the corresponding
prime order group.

enc_server_info
: Optional application-specific information to exchange during the protocol encrypted
under key Ke2, defined below.

server_mac
: An authentication tag computed over the handshake transcript computed using Km2,
defined below.

~~~
struct {
  uint8 client_mac[Nm];
} KE3;
~~~

client_mac
: An authentication tag computed over the handshake transcript computed using
Km2, defined below.

### Key Schedule Functions

#### Transcript Functions

The OPAQUE-3DH key derivation procedures make use of the functions below, re-purposed
from TLS 1.3 {{?RFC8446}}.

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

The OPAQUE-3DH key schedule requires a preamble, which is computed as follows.

~~~
Preamble(client_identity, ke1, server_identity, inner_ke2)

Input:
- client_identity, the optional encoded client identity, which is set
  to client_public_key if not specified.
- ke1, a KE1 message structure.
- server_identity, the optional encoded server identity, which is set
  to server_public_key if not specified.
- inner_ke2, an inner_ke2 structure as defined in KE2.

Output:
- preamble, the protocol transcript with identities and messages.

Steps:
1. preamble = concat("3DH",
                     I2OSP(len(client_identity), 2), client_identity,
                     ke1,
                     I2OSP(len(server_identity), 2), server_identity,
                     inner_ke2)
2. Output preamble
~~~

#### Shared Secret Derivation

The OPAQUE-3DH shared secret derived during the key exchange protocol is computed
using the following function.

~~~
TripleDHIKM(sk1, pk1, sk2, pk2, sk3, pk3)

Input:
- skx, scalar to be multiplied with their corresponding pkx.
- pkx, element to be multiplied with their corresponding skx.

Output:
- ikm, input key material.

Steps:
1. dh1 = sk1 * pk1
2. dh2 = sk2 * pk2
3. dh3 = sk3 * pk3
4. Output concat(dh1, dh2, dh3)
~~~

Using this shared secret, further keys used for encryption and authentication are
computed using the following function.

~~~
DeriveKeys(ikm, preamble)

Input:
- ikm, input key material.
- preamble, the transcript as defined by Preamble().

Output:
- Km2, a MAC authentication key.
- Km3, a MAC authentication key.
- handshake_encrypt_key, an encryption key for `enc_server_info`.
- session_key, the shared session secret.

Steps:
1. prk = Extract("", ikm)
2. handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
3. session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
4. Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
5. Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
6. handshake_encrypt_key = Derive-Secret(handshake_secret, "HandshakeKey", "")
7. Output (Km2, Km3, handshake_encrypt_key, session_key)
~~~

### External Client API {#opaque-client}

~~~
ClientInit(client_identity, password, client_info)

State:
- state, a ClientState structure.

Input:
- client_identity, the optional encoded client identity, which is nil
  if not specified.
- password, an opaque byte string containing the client's password.
- client_info, the optional client_info sent unencrypted to the server,
  only authenticated with client_mac in KE3.

Output:
- ke1, a KE1 message structure.
- blind, the OPRF blinding scalar.
- client_secret, the client's Diffie-Hellman secret share for the session.

Steps:
1. request, blind = CreateCredentialRequest(password)
2. state.blind = blind
3. ke1 = Start(request, client_info)
4. Output ke1
~~~

~~~
ClientFinish(password, client_identity, server_identity, ke1, ke2)

State:
- state, a ClientState structure

Input:
- password, an opaque byte string containing the client's password.
- client_identity, the optional encoded client identity, which is set
  to client_public_key if not specified.
- server_identity, the optional encoded server identity, which is set
  to server_public_key if not specified.
- ke1, a KE1 message structure.
- ke2, a KE2 message structure.

Output:
- ke3, a KE3 message structure.
- server_info, optional application-specific information sent encrypted
  and authenticated to the client.
- session_key, the session's shared secret.

Steps:
1. Create Credentials creds with (client_identity, server_identity)
2. (client_private_key, server_public_key, export_key) =
    RecoverCredentials(password, state.blind, ke2.CredentialResponse)
3. (ke3, server_info, session_key) =
    ClientFinalize(client_identity, client_private_key, server_identity,
                    server_public_key, ke1, ke2)
4. Output (ke3, server_info, session_key)
~~~

#### Internal Client Functions {#client-internal}

~~~
Start(credential_request, client_info)

Parameters:
- Nn, the nonce length.

State:
- state, a ClientState structure.

Input:
- credential_request, a CredentialRequest structure.
- client_info, the optional client_info sent unencrypted to the server,
  only authenticated with client_mac in KE3.

Output:
- ke1, a KE1 structure.

Steps:
1. client_nonce = random(Nn)
2. client_secret, client_keyshare = GenerateKeyPair()
3. Create KE1 ke1 with (credential_request, client_nonce,
                        client_info, client_keyshare)
4. state.client_secret = client_secret
5. Output (ke1, client_secret)
~~~

~~~
ClientFinalize(client_identity, client_private_key, server_identity,
               server_public_key, ke1, ke2)

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
- server_info, optional application-specific information sent
  encrypted and authenticated to the client.
- session_key, the shared session secret.

Steps:
1. ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare,
    state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
2. preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
3. Km2, Km3, handshake_encrypt_key, session_key = DeriveKeys(ikm, preamble)
4. expected_server_mac = MAC(Km2, Hash(concat(preamble, ke2.enc_server_info))
5. If !ct_equal(ke2.server_mac, expected_server_mac),
     raise MacError
6. client_mac = MAC(Km3, Hash(concat(preamble, ke2.enc_server_info, expected_server_mac))
7. pad = Expand(handshake_encrypt_key, "EncryptionPad", len(ke2.enc_server_info))
8. server_info = xor(pad, enc_server_info)
9. Create KE3 ke3 with client_mac
10. Output (ke3, server_info, session_key)
~~~

### External Server API {#opaque-server}

~~~
ServerInit(server_identity, server_private_key, server_public_key,
           record, credential_identifier, oprf_seed, ke1)

Input:
- server_identity, the optional encoded server identity, which is set to
  server_public_key if nil.
- server_private_key, the server's private key.
- server_public_key, the server's public key.
- server_info, the optional server info sent unencrypted to the client.
- record, the client's RegistrationUpload structure.
- credential_identifier, an identifier that uniquely represents the credential
  being registered.
- oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key.
- ke1, a KE1 message structure.

Output:
- ke2, a KE2 structure.
- client_info, the optional client_info sent unencrypted to the server, only
  authenticated with client_mac in KE3.

Steps:
1. response = CreateCredentialResponse(ke1.request, server_public_key, record,
    credential_identifier, oprf_seed)
2. (ke2, client_info) = Response(server_identity, server_private_key,
    client_identity, record.client_public_key, server_info, ke1, response)
3. Output (ke2, client_info)
~~~

~~~
ServerFinish(ke3)

State:
- state, a ServerState structure.

Input:
- ke3, a KE3 structure.

Output:
- session_key, the shared session secret if, and only if, KE3 is valid, nil otherwise.

Steps:
1. if ct_equal(ke3.client_mac, state.expected_client_mac):
2.    Output state.session_key
3. Output nil
~~~

#### Internal Server Functions {#server-internal}

~~~
Response(server_identity, server_private_key, client_identity,
         client_public_key, server_info, ke1, credential_response)

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
- server_info, optional application-specific information sent encrypted and
  authenticated to the client.
- ke1, a KE1 message structure.
- credential_response, a CredentialResponse structure.

Output:
- ke2, A KE2 structure.
- client_info, the optional client_info sent unencrypted to the server,
  only authenticated with client_mac in KE3.

Steps:
1. server_nonce = random(Nn)
2. server_secret, server_keyshare = GenerateKeyPair()
3. Create inner_ke2 ike2 with (credential_response, server_nonce, server_keyshare)
4. preamble = Preamble(client_identity, ke1, server_identity, ike2)
5. ikm = TripleDHIKM(server_secret, ke1.client_keyshare, server_private_key, ke1.client_keyshare, server_secret, client_public_key)
6. Km2, Km3, handshake_encrypt_key, session_key = DeriveKeys(ikm, preamble)
7. pad = Expand(handshake_encrypt_key, "EncryptionPad", len(server_info))
8. enc_server_info = xor(pad, server_info)
9. server_mac = MAC(Km2, Hash(concat(preamble, enc_server_info))
10. expected_client_mac = MAC(Km3, Hash(concat(preamble, enc_server_info, server_mac))
11. Populate state with ServerState(expected_client_mac, session_key)
11. Create KE2 ke2 with (ike2, enc_server_info, server_mac)
12. Output (ke2, ke1.client_info)
~~~

# Configurations {#configurations}

An OPAQUE-3DH configuration is a tuple (OPRF, KDF, MAC, Hash, MHF, EnvelopeMode, Group)
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
  interface in {{dependencies}}. Examples include Argon2 {{?I-D.irtf-cfrg-argon2}},
  scrypt {{?RFC7914}}, and PBKDF2 {{?RFC2898}} with fixed parameter choices.
- EnvelopeMode value is as defined in {{client-credential-storage}}, and is one of
  `internal` or `external`.
- The Group mode identifies the group used in the OPAQUE-3DH AKE. This SHOULD
  match that of the OPRF. For example, if the OPRF is OPRF(ristretto255, SHA-512),
  then Group SHOULD be ristretto255.

Absent an application-specific profile, the following configurations are RECOMMENDED:

- OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512, Scrypt(32768,8,1), internal, ristretto255
- OPRF(P-256, SHA-256), HKDF-SHA-256, HMAC-SHA-256, SHA-256, Scrypt(32768,8,1), internal, P-256

Future configurations may specify different combinations of dependent algorithms,
with the following considerations:

1. The size of AKE public and private keys -- `Npk` and `Nsk`, respectively -- must adhere
to the output length limitations of the KDF Expand function. If HKDF is used, this means
Npk, Nsk <= 255 * Nx, where Nx is the output size of the underlying hash function.
See {{RFC5869}} for details.
1. The output size of the Hash function SHOULD be long enough to produce a key for
MAC of suitable length. For example, if MAC is HMAC-SHA256, then `Nh` could be the
32 bytes.

# Security Considerations {#security-considerations}

OPAQUE is defined and proven as the composition of two
functionalities: an OPRF and an AKE protocol.
It can be seen as a "compiler" for transforming any AKE
protocol (with KCI security and forward secrecy - see below)
into a secure aPAKE protocol. In OPAQUE, the client stores a secret private key at the
server during password registration and retrieves this key each time
it needs to authenticate to the server. The OPRF security properties
ensure that only the correct password can unlock the private key
while at the same time avoiding potential offline guessing attacks.
This general composability property provides great flexibility and
enables a variety of OPAQUE instantiations, from optimized
performance to integration with TLS. The latter aspect is of prime
importance as the use of OPAQUE with TLS constitutes a major security
improvement relative to the standard password-over-TLS practice.
At the same time, the combination with TLS builds OPAQUE as a fully functional
secure communications protocol and can help provide privacy to
account information sent by the client to the server prior to authentication.

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

## Related Analysis

Jarecki et al. {{OPAQUE}} proved the security of OPAQUE
in a strong aPAKE model that ensures security against pre-computation attacks
and is formulated in the Universal Composability (UC) framework {{Canetti01}}
under the random oracle model. This assumes security of the OPRF
function and the underlying key exchange protocol. In turn, the
security of the OPRF protocol from {{I-D.irtf-cfrg-voprf}} is proven
in the random oracle model under the One-More Diffie-Hellman assumption {{JKKX16}}.

Very few aPAKE protocols have been proven formally, and those proven were analyzed
in a weak security model that allows for pre-computation attacks (e.g.,
{{GMR06}}). This is not just a formal issue: these protocols are
actually vulnerable to such attacks. This includes protocols that have recent
analyses in the UC model such as AuCPace {{AuCPace}} and SPAKE2+ {{SPAKE2plus}}.
We note that as shown in {{OPAQUE}}, these protocols, and any aPAKE
in the model from {{GMR06}}, can be converted into an aPAKE secure against
pre-computation attacks at the expense of an additional OPRF execution.

OPAQUE's design builds on a line of work initiated in the seminal
paper of Ford and Kaliski {{FK00}} and is based on the HPAKE protocol
of Xavier Boyen {{Boyen09}} and the (1,1)-PPSS protocol from Jarecki
et al. {{JKKX16}}. None of these papers considered security against
pre-computation attacks or presented a proof of aPAKE security
(not even in a weak model).

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
be part of the envelope or be tied to the parties' public keys. In principle, identities may change across different sessions as long as there is a policy that
can establish if the identity is acceptable or not to the peer. However, we note
that the public keys of both the server and the client must always be those defined
at the time of password registration.

The client identity (client_identity) and server identity (server_identity) are
optional parameters that are left to the application to designate as monikers for the client
and server. If the application layer does not supply values for these
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

## Envelope Encryption {#envelope-encryption}

The analysis of OPAQUE from {{OPAQUE}} requires the authenticated encryption scheme
used to produce the envelope in the external mode to have a special property called random key-robustness
(or key-committing). This specification enforces this property by utilizing
encrypt-then-MAC in the construction of the envelope. There is no option to use another
authenticated encryption scheme with this specification. (Deviating from the
key-robustness requirement may open the protocol to attacks, e.g., {{LGR20}}.)
We remark that export_key for authentication or encryption requires no special
properties from the authentication or encryption schemes as long as export_key
is used only after the envelope is validated, i.e., after the MAC in RecoverCredentials
passes verification.

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

## OPRF Hardening

Hardening the output of the OPRF greatly increases the cost of an offline
attack upon the compromise of the password file at the server. Applications
SHOULD select parameters that balance cost and complexity.

## Preventing Client Enumeration {#preventing-client-enumeration}

Client enumeration refers to attacks where the attacker tries to learn
extra information about the behavior of clients that have registered with
the server. There are two types of attacks we consider:
1) An attacker tries to learn whether a given client identity is registered
with a server, and
2) An attacker tries to learn whether a given client identity has recently
completed registration, or has re-registered (e.g. after a password change).

Preventing the first type of attack requires the server to act with
unregistered client identities in a way that is indistinguishable from its
behavior with existing registered clients. This is achieved in
{{create-credential-response}} for an unregistered client by simulating a
CredentialResponse for unregistered clients through the sampling of a
random masking_key value and relying on the semantic security provided by
the XOR-based pad over the envelope.

Implementations must employ care to avoid side-channel leakage (e.g.,
timing attacks) from helping differentiate these operations from a regular
server response.

Preventing the second type of attack requires the server to supply a
credential_identifier value for a given client identity, consistently between the
{{create-reg-response}} and {{create-credential-response}} steps.
Note that credential_identifier can be set to client_identity, for simplicity.

In the event of a server compromise that results in a re-registration of
credentials for all compromised clients, the oprf_seed value must be resampled,
resulting in a change in the oprf_key value for each client. Although this
change can be detected by an adversary, it is only leaked upon password rotation
after the exposure of the credential files.

Applications must use the same envelope mode when using this prevention
throughout their lifecycle. The envelope size varies from one to another,
and a switch in envelope mode could then be detected.

Finally, note that server implementations may choose to forego the construction
of a simulated credential response message for an unregistered client if these client
enumeration attacks can be mitigated through other application-specific means.

## Password Salt and Storage Implications

In OPAQUE, the OPRF key acts as the secret salt value that ensures the infeasibility
of pre-computation attacks. No extra salt value is needed. Also, clients never
disclose their passwords to the server, even during registration. Note that a corrupted
server can run an exhaustive offline dictionary attack to validate guesses for the client's
password; this is inevitable in any aPAKE protocol. (OPAQUE enables defense against such
offline dictionary attacks by distributing the server so that an offline attack is only
possible if all - or a minimal number of - servers are compromised {{OPAQUE}}.)

Some applications may require learning the client's password for enforcing password
rules. Doing so invalidates this important security property of OPAQUE and is
NOT RECOMMENDED. Applications should move such checks to the client. Note that
limited checks at the server are possible to implement, e.g., detecting repeated
passwords.

# IANA Considerations

This document makes no IANA requests.

--- back

# Acknowledgments

The OPAQUE protocol and its analysis is joint work of the author with Stas
Jarecki and Jiayu Xu. We are indebted to the OPAQUE reviewers during CFRG's
aPAKE selection process, particularly Julia Hesse and Bjorn Tackmann.
This draft has benefited from comments by multiple people. Special thanks
to Richard Barnes, Dan Brown, Eric Crockett, Paul Grubbs, Fredrik Kuivinen,
Payman Mohassel, Jason Resch, Greg Rubin, and Nick Sullivan.

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
                  KE2.inner_ke2)
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

This section contains test vectors for the OPAQUE-3DH specification. Each test
vector specifies the configuration information, protocol inputs, intermediate
values computed during registration and authentication, and protocol outputs.
All values are encoded in hexadecimal strings. The configuration information
includes the (OPRF, Hash, MHF, EnvelopeMode, Group) tuple, where the Group
matches that which is used in the OPRF. These test vectors were generated using
draft-06 of {{I-D.irtf-cfrg-voprf}}.

## OPAQUE-3DH Test Vector 1

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
oprf_seed: 7c16d1ec100aa62589ab11d89278f746d80aa123cf3ffafe0686814a4c
62573fe714a44e016a93470964c09e6b260f8574380deba0b04246512f1885a5727f8
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ae4d1d2e52ca9067502964fb4e5eb4f4c64757bf3b699c579a760
312c86301ea
masking_nonce: dd480a597c8a7053fa9189c41950bab52f33b9f52efca96b5e1b5e
221554d993
server_private_key: 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a
9706137886dce08
server_public_key: 4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b
78624cbd10b371
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ccce80d99a21fa1cdcbd276f469f47921c079db97584bd5c7cdd9d7
d9abebee7
client_nonce: d4b95117d25f32b52f363be901b53095effc5340969ebfbfab7d20c
731485687
server_keyshare: ca372e52516d51c19763ad5eb1a5b60dafb68c264dcf6bcc692f
667a71c5a617
client_keyshare: 4c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
server_private_keyshare: 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6c
a5b914b335512fe70508
client_private_keyshare: 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc
1e9213a043b743b95800
blind_registration: 8bcb0b70dac18de24eef12e737d6b28724d3e37774e0b092f
9f70b255defaf04
blind_login: f3a0829898a89239dce29ccc98ec8b449a34b255ba1e6f944829d18e
0d589b0f
oprf_key: c15eacfb16da4b0e9761231701b7dbd42c00f2f768831cba82133bda779
a4c0d
~~~

### Intermediate Values

~~~
client_public_key: a4d473ab102b06c6c0c4908437d9186ef62d60f592609eafb8
9a8450e69fff51
auth_key: abe4ed20b06a9b6e552bf02f30f681618289b335fda5f6627f1f3ef315d
63725e5cb8b52d17ca54b88c5b7d472fb5973a5f53e6990356350608e20effa616ab3
randomized_pwd: 7f841ca7e57d0a715c75647ce7099f209456282d69c2b6391a98d
f1c1d0adcaf1dccc37d778419946ca367aa79712cf85541679a574d78218a00b48f94
e0bf99
envelope: ae4d1d2e52ca9067502964fb4e5eb4f4c64757bf3b699c579a760312c86
301ea18b6fbd43b46747b84b16bc82c37cd57bb45e51d5970d233f4bc408e4e5af252
1b7601cfbe3897fd337bc9a6ff85a39c121ddd53948db2c137f0c096304bcee2
handshake_secret: 96b4956971637ab428be25208ff9448b91443aad347b55c3d2c
83d5a1db86a3ded0401faaa47000b3112ae4bea51906a54209e4064e74cbea6899cdf
cef6e6e5
handshake_encrypt_key: 4375e9f85fd0f4234acf15c14d8d71ba690d311e7dce9c
841b9c477e5d1fd2201abf64c2cee9846142f53b1d1b773dd29283e13b3b3f9718ab4
c0b404600af6c
server_mac_key: ddf8ee1b79ee721c61575b1a07a9659809f54c9a115b32e9f1231
db85f473defd5a3059d1df4a035a3e070cdfa400d03ee04bdde3e6048045743f5a4ed
d50813
client_mac_key: c3fa63ae04bbfac917d62eee8cc7102e07ae78d442fc967aa7515
52ec50b706455d9232f81bcd6dbc6a79dfa0c645f6495defa410ad26d8c442e111664
740380
~~~

### Output Values

~~~
registration_request: 24bbcabb15452642f709cb8567eff38f4cda6044aca3356
87a62b8453d849c18
registration_response: 4ad7080e8c0a1b6c25b613c7a7c7f038e9185895ff4f16
24252fce384d7c88494c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b7
8624cbd10b371
registration_upload: a4d473ab102b06c6c0c4908437d9186ef62d60f592609eaf
b89a8450e69fff51a1f68e5a03b5d945b64344e3c595b682b49ec144b2a7eb8bf246e
c553197e9bcbef149245f48cbeeae8898a868df3384e54ce99ab77b69d6cebd3b889d
e2dd96ae4d1d2e52ca9067502964fb4e5eb4f4c64757bf3b699c579a760312c86301e
a18b6fbd43b46747b84b16bc82c37cd57bb45e51d5970d233f4bc408e4e5af2521b76
01cfbe3897fd337bc9a6ff85a39c121ddd53948db2c137f0c096304bcee2
KE1: 0e8eeeb2ca0dbf5f690cfe0b76783d7667245f399b874a989f168fdd3e572663
d4b95117d25f32b52f363be901b53095effc5340969ebfbfab7d20c73148568700096
8656c6c6f20626f624c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
KE2: 084add8b95846e455b421eafff4c0626e846da1edf81bdfa015039a798a08b40
dd480a597c8a7053fa9189c41950bab52f33b9f52efca96b5e1b5e221554d993650b6
e353e554f9360b851a7c47da0a51d67b31df1a5e8203bc10ea0eb18a368ae19d33ea0
1951fe45316bc62a19853005acbf0f045389871e60070b355cb7b149b169e16aa6c1f
18ce2178cc4535cf42ef63644b998d3d98606007d6f7481c7b802311dca4f2dc04abc
bc82e692e94e074ab35b030584f826069bfa677cc2f2ccce80d99a21fa1cdcbd276f4
69f47921c079db97584bd5c7cdd9d7d9abebee7ca372e52516d51c19763ad5eb1a5b6
0dafb68c264dcf6bcc692f667a71c5a617000feac6ccb9bd159dfd7a0804224a7a01d
9581b6e4166bc4262a1e4c16e97e085c80d291731258ec541be9a1c68012b46ced7f4
ab12b49739870b4643acd9bff5fc7dd5ff2655dee2bd1291a1dccf36dc
KE3: 49e0c785d8cd9805179d52fb420c45aa74eb8cfa4a3bf1781be9b182448b5deb
48a232742e1c78bd361407e0e15f065612821b3c45f993b3758a408051e85a95
export_key: ff68ecc8c48408e44f803c1367b491c10c3359dc2bb30aba2f7e51938
918961d6a4a1879b8c7501c30bd5fae85b8925471910de4855ef1fd9dbd41bb47e9c6
c6
session_key: 96e256d482d1e0e7dad5f9231075fbdff8b2054c9ab78ad6bb4812a6
1c5a51b03ef81dac52799371328b0495dd45181be9ed0d26dd6fb244a2618e01e7ba0
9cd
~~~

## OPAQUE-3DH Test Vector 2

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 0ffdbc9874c751fc1a43ba11dda08ebcaeb7f999780804aff975df52c1
be7c11f7c665892b52c2e47bac3f2ed57ec9e6eb5ff09d385a374f3224d3f4838b740
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0e51a98cf5748f021086da6a40c707f54a077831cc91a9bcf1804
103343a9282
masking_nonce: 8bd5a108e6a05affde823439a17a97f9c07b2c2a58f18a3cef371e
e85b75a73c
server_private_key: de2e98f422bf7b99be19f7da7cac62f1599d35a225ec63401
49a0aaff3102003
server_public_key: a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e7874
92b98265a5e651
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 578e04e4205af9ae3b9fafa46d850767224a8887a85f474ebee6627
ad0869a0e
client_nonce: b339b7a02983d128cd8a01545c6f4c5e1de982a65abf0e1115f641b
a9fd58725
server_keyshare: 80d9b21c255bf04113a6d339fff579c68475e516c0c98f625a90
f6532a310f13
client_keyshare: 746987c9ba92c3636d92fa7afc0379009ed54a7fb2db3cf7e4c4
07d4ed2c6e35
server_private_keyshare: 0bb106c0e1aac79e92dd2d051e90efe4e2e093bc1e82
b80e8cce6afa4f519802
client_private_keyshare: e79a642b20f4c9118febffaf6b6a31471fe7794aa77c
ed123f07e56cb8cf7c01
blind_registration: c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a74432f
685b2b6a4b42a0c
blind_login: 614bb578f29cc677ea9e7aea3e4839413997e020f9377b63c1358415
2d81b40d
oprf_key: 1ea6ba49377190dac9adae5ec6471577c1d82253db9986d7a593c2c316a
e0500
~~~

### Intermediate Values

~~~
client_public_key: 28839665f903b654da8cbc1d8aef2528ab2c58794271a88949
cabe9e959b9723
auth_key: a30c05fc95db9f75f4db7533c5adb2a768b685a5668fb1a4892f604b357
54ad87653792f318784210157cbddcf25ee4519ca319066592c900a0bd9901e74619e
randomized_pwd: 0984cc7624ed91e0bfef2a45a88e7c62b79f10a6d1c04c47e054e
93c3409b807cf7ac22f5bb5c7d59881d1ed7c8d36229b7dc817df6714fe847ff27be8
a4e8d3
envelope: 0e51a98cf5748f021086da6a40c707f54a077831cc91a9bcf1804103343
a9282fed1ed5d8977be01ec5a15f558dac5b5e98a55830efb98fca2fef2b022539369
d6c74aabea49d77a56f3afb271837cd03e58d99bcd0fa08aca825b746ea86ccf
handshake_secret: ebc6d9468be0be65d84e3e41b3391b8a789a5bf6aa5adfa00f4
485d2569234200371a31dd3c96ce9ed257e791ee50c6b9955aaffe79e16009dbeb796
c639ad39
handshake_encrypt_key: 3d6a8dbee1df4dc5063191867e71c73d00a51b5fce5916
393d7f8a861f4f4135e2ee35211422d00b45a2ec800a21886d5a26de6db3f26e1bdf6
0f66675536169
server_mac_key: 9c1cd7167526b3d78f865b81559190c3f375c247880e357acb8a9
28728d2aab53e7dca4c6b0549c807c90c2965b1b5f59db2effea2672084f226cef417
fe6dbf
client_mac_key: 78a98350f0be222f6ffcc552c7d88bf7e108366dcb09e4f911fb9
c5cdb852dcf4c4342cf8d20e4ccff108fd29a922be5cc0b3c2289b23ea35993f4f7e6
4fdaf1
~~~

### Output Values

~~~
registration_request: fa8c0e0144f7b9cd1de1bfcf78104f94d63c0f90398c9df
ceee06ab5593ec500
registration_response: 4050a6e95fdb81b47bfcda99524460e791a9b3e2960829
1ac5f0cca020d31260a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e78749
2b98265a5e651
registration_upload: 28839665f903b654da8cbc1d8aef2528ab2c58794271a889
49cabe9e959b9723a62c7e51b5118d184c057979a334c8f338e44bbfb5364668ec2f3
1a4e54fa85408fa903d054c3092ac3994df118ab99cea5842ba13968717379eefe646
7df3610e51a98cf5748f021086da6a40c707f54a077831cc91a9bcf1804103343a928
2fed1ed5d8977be01ec5a15f558dac5b5e98a55830efb98fca2fef2b022539369d6c7
4aabea49d77a56f3afb271837cd03e58d99bcd0fa08aca825b746ea86ccf
KE1: dedef709c5faf24970b4fa77480a2c640dc8c6b7a53ae78a2dbf3fc75134a250
b339b7a02983d128cd8a01545c6f4c5e1de982a65abf0e1115f641ba9fd5872500096
8656c6c6f20626f62746987c9ba92c3636d92fa7afc0379009ed54a7fb2db3cf7e4c4
07d4ed2c6e35
KE2: 985b8739594ed8a1cb4e03d74c4e630e8bebc0575f657f53b3e7ebf24317b927
8bd5a108e6a05affde823439a17a97f9c07b2c2a58f18a3cef371ee85b75a73ca6a60
3e6e934f7783a0b249cd6b3039b344bd01fdbb90210e516957512fb51842e287b812d
fe74e93e86d39c49adb3bdc79e7d02c8d8a50b08c0dea9f2521f2d8bd180fff926804
d4dd364a0418f39c75c09959da811bbe12ad2fa3ec122a2151fd7b48a92cf1f582c1c
64408331c30f626a8cc05b16a6392ff72705ae20610a578e04e4205af9ae3b9fafa46
d850767224a8887a85f474ebee6627ad0869a0e80d9b21c255bf04113a6d339fff579
c68475e516c0c98f625a90f6532a310f13000ffc9c8e0bad2571c695aa85bf421d968
23e88c7cbd31e84fe468867cc286b0247c8abd0e87c5e8271100cd8af9082f055fb90
66aa3e2babb0ad80f14d2921225d2fa401f37245fec3d2735592bce641
KE3: 659ab46fe55da07b754d6024fc9c8c0a214cfcde32daf69b8245a1255fee8bad
bbab800f55631dd721c6221b8c405476bbf3e543ee173a48e51da58ade1250af
export_key: d2e30fe6be5bdf769fae2f29458a8a810beb22294131f113c70b61f17
3bf6ec6273c03fdc16d0dd810c16746fc5aaaa317de6f5641dd15190699a86e717004
73
session_key: 35c10904d5f497361f1f936b63e9436b485922860a4e4ca515b3d2c2
bda4ddefa8392d2b8dffe48b20ea1534cf9ea149d97b963d663aa545dad8ae997d2ae
ea4
~~~

## OPAQUE-3DH Test Vector 3

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 8e0aaf4dfe21787fdb07badc15661ee8fd9b6f74987f80adaacf81cd01
bee833ffc46094e3178c8e8c4c675e9689e2d980e9a8faba64be082d472a7b40b978d
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cb2ef5b3afed25cb6332e74ce40d3b8fb8aff0f3a029fec560adb
ba41a907b97
masking_nonce: dd58cdd24ac0ac8083a305994a73948a5bd1e8e786507e8cdccb10
4de7c479f0
server_private_key: be81db28eb1e147561c478a3f84cbf77037f010272fd51abc
ff08ac9537e750b
server_public_key: 5ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3
f459678b0e0d25
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 4c34797dec207e283260fa80e61ae932519e83028fa96f0ca4f73ef
c94417bb8
client_nonce: 4953f4d7e2b908aabe90d35c139afcd340357aed9ff30231e6d5514
6a5d796f2
server_keyshare: a6d76012999541f1ec0c014ec1606f2bd2a517e51f731d595469
51d9699e1739
client_keyshare: 2e8a05799d3c524ede0482f39e047df99d9a53dc2dc30e8947eb
5da98b8c4354
server_private_keyshare: 14a08c384d74f6dcaed32bb9448c02865efb17a32b82
c7f06a9586c6e72e4b06
client_private_keyshare: 01229ee057507c3e53534ad9db9f6df6ce515d1b8017
923b65cada1973524d0c
blind_registration: 27fa7b2a6d920c76cf03fb57bdeacc2ec39330fd6e7f9e5db
dfcb571e271a60f
blind_login: a4e7b12d5b712efcac9ba734d54c2b24bff0ef6310404b5c05d60d7c
8451bd0c
oprf_key: 183899a56b7a5980a3adaf7a7bf55a8c516dad4a94ac232aa53815a982e
9490f
~~~

### Intermediate Values

~~~
client_public_key: c28fd47d9b71f4e427904c3f20f6148e9d7ac42acf3463f427
8aeaf8a267af5f
auth_key: 2c31e524e4f5fb42e49afb9ec8dc63a717a89f2fb97bb566c2cff5f62e3
dd0ecef8fcbd23c06b66b1b03ddf807ddcb1b55fb77e860173dfee2dad6bf6f364380
randomized_pwd: 319579dc9218ceb2a1d0c48b39b3ada23bf78e4c7d48adcebed83
88ab4856dea3c806855fdde3eb66fcfdf58c3caa03c1d8f53670ef3d8c0e2617bc231
c0d22b
envelope: cb2ef5b3afed25cb6332e74ce40d3b8fb8aff0f3a029fec560adbba41a9
07b971f770afa8fb6ac2dfae400dbe2a4c2c470c3eab8d40094f8bb867e3a1016952e
3117f8abfb252e8e684266b183d6094b126b3ea446ea3af9c7efa31297dcf0b2
handshake_secret: c8f6fb5083c8f165b4f5358ff0c3f190cab6aceaecd98b01df0
f384018885b12a90e9d81925eab8c1ec75dcacf3a41921ac7d4bc8a52caeb2ab9d4c2
ba7e5e90
handshake_encrypt_key: fb6dfcff6e7c608dcd4e959b568ac4834a8487a1b91729
ae36b387b2f5cef09bd94360355ae8b93c5d4cde6294ea04799e6856bb38bf707020d
45f1f7af7abae
server_mac_key: 77b59b5c77b4433da90e8afcfc8cc5eaac139c072dfad8ecd6631
fdea7816da11b4a6a9788eb01b6889cd56769461373644178fd82ddf34013a163f18d
361080
client_mac_key: eba19966d1d66893a77e77c493bdaaac2b162912f7c5350d8122f
0db2dd66c5a66e07571648e396839b29ff62ad2ff65788a50139381265c8de0128eaa
431e30
~~~

### Output Values

~~~
registration_request: fa39a478c220a89929613f9e65c9a4617da96b62509c42b
39d7e3606ed2e8031
registration_response: a0ffcffeb69e885c3983ae1ee7181ae6926b1daaa254b9
20ea8ea3207e6a5f325ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3f
459678b0e0d25
registration_upload: c28fd47d9b71f4e427904c3f20f6148e9d7ac42acf3463f4
278aeaf8a267af5fadd651f79e277bac65b6ab94837502dcd550a4fd9760dd7732e7c
6ddafb55912eb004a364cccfc159826136fb15d0b3db10cc7270c705ef45854565b72
43c988cb2ef5b3afed25cb6332e74ce40d3b8fb8aff0f3a029fec560adbba41a907b9
71f770afa8fb6ac2dfae400dbe2a4c2c470c3eab8d40094f8bb867e3a1016952e3117
f8abfb252e8e684266b183d6094b126b3ea446ea3af9c7efa31297dcf0b2
KE1: 96f9f35ebc0ca71607fd2cfcd465e285eeeabdec61151b39b2b4fb735538aa0c
4953f4d7e2b908aabe90d35c139afcd340357aed9ff30231e6d55146a5d796f200096
8656c6c6f20626f622e8a05799d3c524ede0482f39e047df99d9a53dc2dc30e8947eb
5da98b8c4354
KE2: bed95c2e47175634a3b845cf3fc40bb4ddd9ef8e8a1b815bdded3500d898a45c
dd58cdd24ac0ac8083a305994a73948a5bd1e8e786507e8cdccb104de7c479f0dd94c
8de23d83c7a29f934d4056bf905d2d284e9dfcf163110ccb516fe33bc27aa769e5788
6b45f3c486ff738a05194fccd044a0e1bcba7d3e029ee61d2aacc6be7f1e0b5590fb6
eaeb4758ad48ec455b09bbf3c9a6079c619d96e78a493e058fddbae195a62efea6786
a33f49f55645ebfdebca7ff97d348453a0547035206d4c34797dec207e283260fa80e
61ae932519e83028fa96f0ca4f73efc94417bb8a6d76012999541f1ec0c014ec1606f
2bd2a517e51f731d59546951d9699e1739000fa10f6bacd674e7bb72acf76ea2902b1
fcd7dde605e1b76b24caf4a912c73f3ffb26850099f51659307589034b5be92f71e20
18ab6df824eb9b3e691b69c4e4fc3f20112e61d2adf43a21bc6aa1424e
KE3: 66c1ecc6a6028f188fbd563b1e594fd6fa9752518bdcf26dacc42144dd3a695d
320d098da9f94f9117b470bb8074c0e1df0c9d6fa4bb7de1ff18c3e7edb1e16e
export_key: 29d05720560fa0d96af22fbef7cc6b5189e3d90bd5c58df93456c0851
76368662a92aa8767b1d9d20f854138f886e68007d6ffab1cf0bce39d1bad1e9120a6
73
session_key: 0a71a28002cf637dcc0cdbcb83c804ba5b3e9939f53ca932179d0285
91531059c5666c0fc23411bfed4128b66dbee4d267c17f6a5ec8c5e9efc911602eefa
86e
~~~

## OPAQUE-3DH Test Vector 4

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 389e8c2b070e95e0c5f183cddee8bff604cde897c7d4796614f322f070
ec05799f58aea870c5bd8d78a6a638dc5bd5b4cbc532345ebf6b1a847f85d8a535227
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: f3e01f0691b1bd96dd76b1ac0e3b162c01dead2d5a460996db61c
7cb6e06f054
masking_nonce: e98bd401befe1c3656af0335023eb4d39623d7709475baf2f97b61
96d500b0c3
server_private_key: d49399dc3bc1022938dfb0e79db523d4e4e41f494c3898eac
652bf95f6efa108
server_public_key: fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce50
017dc037001c63
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 06e1342e124cec21e81844c070baffad06ae9639ba7644f312e87eb
90b1e60cd
client_nonce: 3d92d44306392e9c01483550614cbfc9f9c166883845d4c17dd5859
952dc72ca
server_keyshare: 6a398e50c4e395ee52ef332d6c2c0a77187e2e0b3564617eb66d
2878c41e6c47
client_keyshare: 14b434e33a39d7d9fd6dbe3638925edd7a0344a312a22971754b
d075d8347342
server_private_keyshare: 5f4a55d2e8474fe0ec811b4cca7c0e51a886c4343d83
c4e5228b8739b3e37700
client_private_keyshare: 2928684a1796b559988623c12413cf511d13cb07ecb6
d54be4962fe2b1bd6f08
blind_registration: 89ae863bc6f3e8b59bbd1354548220e81cd0ffb6f9e4ec217
3870ae6107f8d03
blind_login: 07e41ecdb9ef83429e58098b8f30a6b49d414ad5e6073d177a1f0b69
cf537f05
oprf_key: cc5626bba30643d91feb3ea84169e1e317d5a5cc58f338333d3e15e0784
04b0e
~~~

### Intermediate Values

~~~
client_public_key: f02fc825a4bbbaa93194c8d8e3bef57bf7f7217ff526f89524
be78cf88326f36
auth_key: 77e1e98f362558d7f03c8f82211e1a3b3344c9d91fc3b84172da615173b
4223191030e408a36d42cee24f84033b8d85f1211dda7ced47ad4e2a891ec3ae818c8
randomized_pwd: a5f101b43f06680a15a28f8451919eebd962a257b438ae49a98bd
7e458da1b5901d2ddaff50b264bf5f218df074fc2bbabb8a64b32e8aae4a477085606
489f9d
envelope: f3e01f0691b1bd96dd76b1ac0e3b162c01dead2d5a460996db61c7cb6e0
6f05479c0f198d63c785cd4be603103d77d62b033aef7d7ac70c28441dc3ece8ffcab
182460d77693a2cc20c52284f046541631f1ba14b023436d11bce8c421c661ed
handshake_secret: ff94d02a713a89c44b47d837ec8e083859bb562d7476674a57e
d14d0f81fd0463695b3386147625204204aff8f854acea3a06c14d99d6c0e7b5931b0
973deaa9
handshake_encrypt_key: 3669bfbffc3884a9e9753d8bd8e00336adfdde00c15176
47e7b0a6b1ce6fd1a6df9a37f476ceb0ab1ced5dffb9acdf0aaf1a14a8ac0ee067f83
b50a2480c97cf
server_mac_key: 7fe6cf6ab68cb965216dbe58fe5169e906ee3d465e812c80d5020
c7ff922ff2b236a21460f0ac8f09ea2493c4fc555323b33e8f81cf40baa66823c4ab0
85b236
client_mac_key: e399874544be8a581c92aee5dcc3651f04467435baffe5a98192a
92e9d8b8125d692319462aa5b57605b5459d81531bd26d69599d15d18a0a897cd781f
fe3113
~~~

### Output Values

~~~
registration_request: 307ff12c023cb5ce33a04efd497252442fa899505732b4c
322b02d1e7a655f21
registration_response: 7adb55bef90bd68f344e20e78a70d6ee7142b7d99caf9d
21861befcec8124874fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce500
17dc037001c63
registration_upload: f02fc825a4bbbaa93194c8d8e3bef57bf7f7217ff526f895
24be78cf88326f36d2a15a304bcb3a6e184b14d0ff5db92788d01d922e406d6d9e888
c1728fd1e20d43d3aecf9c5d2bb5796f8383522d2563370fe18caa392aa4850ce5060
0d3af3f3e01f0691b1bd96dd76b1ac0e3b162c01dead2d5a460996db61c7cb6e06f05
479c0f198d63c785cd4be603103d77d62b033aef7d7ac70c28441dc3ece8ffcab1824
60d77693a2cc20c52284f046541631f1ba14b023436d11bce8c421c661ed
KE1: e6fb9b013986abe5f6e9586a0110395a97ad695dde622d58470adb0a0cdcb37e
3d92d44306392e9c01483550614cbfc9f9c166883845d4c17dd5859952dc72ca00096
8656c6c6f20626f6214b434e33a39d7d9fd6dbe3638925edd7a0344a312a22971754b
d075d8347342
KE2: f056ba65d12e66794253220c6025157a66540ba67a154c78aa2c4d1829cf2f0e
e98bd401befe1c3656af0335023eb4d39623d7709475baf2f97b6196d500b0c364f51
cb7aedd768ff45793dc630031914dcf80bc0983dbe690698c4ee8e9566b19c362eb89
323184a4e4a4ab2c94b97ad08c0a112d9676950855c01097759194cc6c801122d1876
24f0fe7e8704a94efafad7197106fbe07faafe9e2e111b828c6ffd076e755e0bb1c57
1b1f79fc837260d7f65c376d852e3b69ad13b8c335bf06e1342e124cec21e81844c07
0baffad06ae9639ba7644f312e87eb90b1e60cd6a398e50c4e395ee52ef332d6c2c0a
77187e2e0b3564617eb66d2878c41e6c47000ffe003e3a4f069652e7b4df4d93dd7fd
d9f3c04b3f231e8e7df85424eaa6f3ab3cf62ca99b902d60ef66ffdf03ceb9c46b945
29edfbfde5128016fc18be803c6c65f8c687f96e40c7fd3dd9f74db4e5
KE3: de85e7818163d60a00ed1f11e7223be2a3ebb6d1894c60a7676ee6403a7326aa
827e327a41b8137a05a9705ab289744fa80ee177d33b289ba945da5db158a9a4
export_key: 8a7280e120dba669c07f39567e338fa0f56d20d5a4c0269469f345b45
b1d690400caf29bd3ac1b4083fb866eb63845416cefce6c00ac8f2dfe8047f2e2255f
35
session_key: 986c130fa4208a6a231272fad57f7cff370c893941e21affb7f1b773
9158081a50b9c040d7b665a74d55412e7a4c45d81fdb6d86f4f4bc58a4979c2f68625
b77
~~~

## OPAQUE-3DH Test Vector 5

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
Nm: 64
Nx: 64
Nok: 56
~~~

### Input Values

~~~
oprf_seed: 077906f7255b7391b91483968461626e9547b82a445cd6a9127d433ac4
f2037fea083ddab4782c8643dcbadf45ed25e4d6070414f9676cb9777efdab0dfcb61
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b27e906182129a354335ef733e8f211e7f77c6ec70b1a05e45d2b
145ce938ef8
masking_nonce: 6c91ef10f0a12c9775dc03cef0d9f0aea07f22afa5d3b55802d7a4
9fa7c84049
server_private_key: 4b642526ef9910289315b71f7a977f7b265e46a6aea42c40b
78bd2f1281617519f3f790c8d0f42eacce68456c259202c352f233ae2dc6506
server_public_key: 7a9e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa
3e421385fd2194903385345e6ac39e2a9911b6e624b0928051af9a6834ce57
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: dcd4a5a60406b4812c25a48e68f6756d20ae8f7feeaee936820ae80
6e922a21c
client_nonce: e3392b2a02ac5be57a05df55afd9b3e79f13f9f7c91bcbf85ebe2ec
3bf1600f8
server_keyshare: b0fd650f0efdf4cec17e85b9cca2fa7ac7f1ff76ca94ed07e8ac
65afd6304ef8102bf24376fc5b064edb55fe02027d7fef41d05db3652db0
client_keyshare: de9bfa627cb161dd7098c8a582f5fb3a38641e8df3d6e7c40dff
ec1adff5f0d148716cf15cd11a04b80b11cc12a1056493b23ee23267704c
server_private_keyshare: b4c67a79b035b9887260399acc5f7083245d8adc40b8
f39f14cd8bd4ade8abbb95166afdc9e922203abe7a8539854c64b943b0b49bc7c611
client_private_keyshare: 2e28ff4c5f89353d25d6b5a8720734ed34a4a70f8e63
2de4046e64cee0b47cfcd9173c7ceb0d373234e06b81b5a3b316aec93a8212ba2c31
blind_registration: 26abc79daa9fcc06f6d3acf12df82de919be4937f28f531b1
4ac96b844320e7a66810c2d9391cbb877348301ab59a3a91b4a2129198aa12b
blind_login: 5ea7839f2ac8cf1c5fa92703d4cff61ba2e896e126d371f6380ca417
57f6458b93b049e1b0d73ab5b8d914b08dff3e52e62ea889638dac21
oprf_key: 92d00609c97ae75e88e82690a1c8a7e63ed83508c7c8a451765d3b1bd4f
b5b9c400ec86559bf673debc80bce7d31c8640234f1620e360834
~~~

### Intermediate Values

~~~
client_public_key: 8eb67a9bf7cfcb736810c1827bd7c2923c06581a9836c77f02
1c0277e86172632307ca773b9c5a287636cde4a322a946e7abff65cd83a142
auth_key: 0ff33a4c0f8c42d74d7cebb13aab9507ce81e1ecda761242c10ebd242a7
7bd8be9d46f56588f224491e88356c148645f35917db91629adb9ca0e6623df2006f8
randomized_pwd: 4605dbf72bd606e0f456d2e8b26cec1e8761c3d151a89041ca8ce
6a5d27436da25251a3a252d8782afab349acdece1e1fe72a6a141fac69e51e7248193
d2a352
envelope: b27e906182129a354335ef733e8f211e7f77c6ec70b1a05e45d2b145ce9
38ef81637506a2dc0f1bbd7a13cc90b776730280d7fafc62b1d529036a505cc0203fc
3b788ac59d4b9287ffcbe63354ab6f4ced1df3e87a3cdf23a3cdae83e5aa920b
handshake_secret: 7b69558cab8f3397c1a918b7f052696dafb5a7d28b9bf536352
f7fe73db49e2a662b629c2c834a1d0f4f0d0234255fb496dfbd84eafce9f308a34632
91802d80
handshake_encrypt_key: aa50678d3d271521e0ad9980696e46cbfa07b907499420
f85f5df4d1d58324400f7e681b8829d4de42b77833eb9ca4345531bed741a8e6cfb39
b26623794536c
server_mac_key: 5f9a74f5c943cd04f6669ef047bf4c01d4d3ccec986cf1061fb84
f45ab9c722d922c48bd5844b45e3f00ee09cc78d8e41ae4ce3d9f6a9751d5dd446905
fe27b8
client_mac_key: d2d47efa98ff716de9b2d91756776fb984ee1ee5c1be8bdd5b9fb
8de99625a2ad6a2caf206d00e71ac54d6dcca2ed141e59f7b94ee892713723ce7613e
d2b381
~~~

### Output Values

~~~
registration_request: a2c1e08d638fa00bdd13a4a2ec5a3e2d9f31c7c4784188d
441b6a709f47e2196911ce68a8add9ee7dd6e488cd1a00b0301766dd02af2aa3c
registration_response: 0cee15027c49c8a67a1c6e46196f5ab710239ff1c54cec
77b68bb68e9afa4997de355c35c03d4e9905651d563c2989d06d6ef4a0631d32f87a9
e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa3e421385fd219490338534
5e6ac39e2a9911b6e624b0928051af9a6834ce57
registration_upload: 8eb67a9bf7cfcb736810c1827bd7c2923c06581a9836c77f
021c0277e86172632307ca773b9c5a287636cde4a322a946e7abff65cd83a142095ff
ef79ad465fb047386358d4d68e5ae6a42ac03cad226b27fa0a5404e4a867cfda8969e
da8899440360d50783a66eeebd5bb777bae55b5760372367233124b27e906182129a3
54335ef733e8f211e7f77c6ec70b1a05e45d2b145ce938ef81637506a2dc0f1bbd7a1
3cc90b776730280d7fafc62b1d529036a505cc0203fc3b788ac59d4b9287ffcbe6335
4ab6f4ced1df3e87a3cdf23a3cdae83e5aa920b
KE1: 08d74cf75888a3c22b52d9ba2070f43e699a1439c8a312178e1605bbe7479731
9ab7898faf4f2c33d19679a257bca53e27a7c295b50b0d87e3392b2a02ac5be57a05d
f55afd9b3e79f13f9f7c91bcbf85ebe2ec3bf1600f8000968656c6c6f20626f62de9b
fa627cb161dd7098c8a582f5fb3a38641e8df3d6e7c40dffec1adff5f0d148716cf15
cd11a04b80b11cc12a1056493b23ee23267704c
KE2: 5e43757ee70502f4a7dfd8192d025587f75ad6b05f7a2dbc5286fc2368567a80
e30fc73f5b57fa21973a388b13a4978738dbdb40b04a955a6c91ef10f0a12c9775dc0
3cef0d9f0aea07f22afa5d3b55802d7a49fa7c840492f928e6582dc855eec7683bbac
2e51306942fc6000b4fc5a70d389e999993fc9946f293ae1f438e3abdd3c3d25b4fcf
6d8958eba9198a2c055f148de74f1c034e244f53f418286b067249cdb9dcf5d2017fe
12b79f1ae23fe5be88b4c43a7f47708492f45c6afd58766c8f1026bbfbe9365e7f3bc
981ae774d1646f694af8a5d9bb3efc6933df2500d78196ce5d74cb31824aeb9fc8881
cfdcd4a5a60406b4812c25a48e68f6756d20ae8f7feeaee936820ae806e922a21cb0f
d650f0efdf4cec17e85b9cca2fa7ac7f1ff76ca94ed07e8ac65afd6304ef8102bf243
76fc5b064edb55fe02027d7fef41d05db3652db0000f5d1ab7b954489e21815dceb9f
3e1df67f1fa5a460c4a91e93db5614a03c48da57f4cdccfb3c55bbe9d163b7c3bf709
4621b24e1f529e7237e3685c0b7fdbac2d291055e50a46e33738a64c4c4b549b
KE3: bb3204c71f1ad6e6f16807f5c44cb01fcdc662cebc0e0699f97d230c2b78e570
f85e5f4cd8d3d4c9c2f5045de5eab044965d7aa532d5233e29beebea09cb79e3
export_key: 09d1ab28781693795471eeee2d4c06a579ac59a5b80b552a0a8e1bcbf
90db6a788a8cec93dfd62d65759053ca48aa87fc0e781ad60d8f97e93d0e4e1845ec9
60
session_key: 1dee607190ed3ca16f6374a5d8bf97aa89453b47b3b64cd6cf796a6f
705e3c75dba0c5f192cd91a5a9591da949b2922854f8be73c9cf8b6c88c71960d8b90
b61
~~~

## OPAQUE-3DH Test Vector 6

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
Nm: 64
Nx: 64
Nok: 56
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: ce664d61ce8e6fad5fa2b6ce395ba0e396e9cc7fae28cd5b9167811010
06dd8260770815df83cd01d5744e07e4cf7b88e61e3393ae9b709019ef660abb23bb1
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d435848ca1554f0e7bad7d1577a5cca9d620a83f4ef8939a21b03
a906c3dfe22
masking_nonce: f3dbff9d25947c274222060eb0cafa2c9f81a60b5dcb2dcb793ced
c0d3ddfce1
server_private_key: f0a17b7f6b056dfcfbee5bd7db70a99bbabf1ebe98b192e93
cedceb9c0164e95b891bd8bc81721b8ea31835d6f9687a36c94592a6d591e3d
server_public_key: 741b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230
316ebd2b419ae2f0fbb21e308c1dfa0d745b702c2b375227b601859da5eb92
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 0964b779670cbfd504d4cce8ea37f2707b727b7236532cbcaab548f
529bb0a3f
client_nonce: f98b5fc700740f05c5bb0d67545cb11f979a3531e73d1be85eeb87d
bf111fc24
server_keyshare: 5cc2a00d1b42d14ac07e05dca2dbc20661a4f30909137bc3274a
25c3fb4310fc9c61d76fc6576c8ed1c9816719433acc81722a2a5e23357b
client_keyshare: ee784169a2abed53764292f2e7385c5dd99ee21d09a4df244057
06a59abb6d91f3ed3dd8c6649807d11cb59ddfa23fad081ddda04ea49075
server_private_keyshare: 619befc22cca054c042da7b2eab01c59f99bc955df62
2548e247f7ef180732909ff3c5f87ff8c786d85b3c276550d64df70618a81e14d339
client_private_keyshare: ca6f309f131e21373228a44b09d4c00da9a6bbaf9a5e
54a1687c07f327833643112a8a5a2f1bd6a011fa82f705f20cf788d6b6741b158e26
blind_registration: 2de1be6961f0700496e71df806ebd5322aa0926b2f8f1d3fa
1fea402f3c90b04601274050a3c6f467387c2f48878823949820d4fad44da19
blind_login: ab0cb69c311b71343843ea041bae30e2bde41b548b8fbd8b77ceb623
25f25986ce21cef85c92e3399433661eeeb9c1150a9cc64c3fb53001
oprf_key: ca2e2837fdbac208e3d1fca1a8f435f1d1137ce4893e85cb906eb434c0a
5ddda5297295cc4d82e18bb5506988d208f06d9ec424a3f01f337
~~~

### Intermediate Values

~~~
client_public_key: 186e80b2bf794cebbf9b8eaae4ab30f7f97ff8b4608f6015e6
09965ba5ca9a013efe4a33e6d74b0d5792eb953444d3c3412931954c5593d0
auth_key: 8ec795aa74327f4319213b9d24abbf50a127e7ebd7fae62e308012cc3ab
656bfca09be67727abe99677cee9e7efc353ea3bf8be6efa3bdedd50d39e0c1ec0eb7
randomized_pwd: b8222790bec472e0ac35dfec8c20985ae0fa78cd35b6441441d20
336dc8dc2c59197fb1024a4e7eb347ae1b8b85c9f6641a970705a0695e0d0854f010b
b36cb9
envelope: d435848ca1554f0e7bad7d1577a5cca9d620a83f4ef8939a21b03a906c3
dfe2285ef3427a3828910f19b8eaa71e5f96fef52bcf42d6da50cad3c57e46bafd765
a8b5c43ae8c22e9191ac80d5de8fd03ef31f0b83a72fda6900b67768e6282efd
handshake_secret: 175b48cadac266e0538eac4f95afd534cfded63fbaaa44954d6
d817a772aed0d744eb0c47d52fcb0862aae4187f37c92e3f267e46aefd941e6348d24
d41a6430
handshake_encrypt_key: 5abd7661e053e40cb906aaeb35ab0d6d0e8b66c395f408
072374bb6b8507f14f938083705ac3d269eafe8fd3dec25f501c9a715cdef507d3daf
9ec29c597961b
server_mac_key: ad4070a2766f2e6f8bbc73409c500ece84dad628ecc38d10fbeac
e6be33c07d4af4c2b9ebb587e6590fb37f912a13b141af696da2f58ed09630d75b5bd
d57390
client_mac_key: aacc0bc86be130005d89727327c1a507b82efec7a92cf3a935643
94cd81de9e9928c839c0b16cd1c8ce46629bc1f81ebf54b0fabc857fb8a1467d05303
a78b4a
~~~

### Output Values

~~~
registration_request: 66660fc08075380d7c2d4728ed1a7b550647e8231d6d29e
60d3d1fa8fa3132c8dc445fa9c94de42e5f12e29de958e5daea84eba6a6410042
registration_response: ea812c4f71859e56aec9c59058f1b9bcd15a4ca107080b
78376a2f1adb637ace37eada25d433ab915aefa0abcaa823e4373c819a276bdfc7741
b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230316ebd2b419ae2f0fbb21e
308c1dfa0d745b702c2b375227b601859da5eb92
registration_upload: 186e80b2bf794cebbf9b8eaae4ab30f7f97ff8b4608f6015
e609965ba5ca9a013efe4a33e6d74b0d5792eb953444d3c3412931954c5593d0391e3
a388ab9a83d94abc9bd7b08565fcea19b1a50e49891e1e818a114a4a8af1557c447c6
c7c3cb9d92c02753351c485bc00eb655bcb7fd4a4b66d70b42bcd0d435848ca1554f0
e7bad7d1577a5cca9d620a83f4ef8939a21b03a906c3dfe2285ef3427a3828910f19b
8eaa71e5f96fef52bcf42d6da50cad3c57e46bafd765a8b5c43ae8c22e9191ac80d5d
e8fd03ef31f0b83a72fda6900b67768e6282efd
KE1: 1c83acd948f714989a2276ef0c3bb16d5b637942e6d642da9826fbcba741291f
0b093b8c94888ff0ab621f90344f5b8b72159e2eb80651c1f98b5fc700740f05c5bb0
d67545cb11f979a3531e73d1be85eeb87dbf111fc24000968656c6c6f20626f62ee78
4169a2abed53764292f2e7385c5dd99ee21d09a4df24405706a59abb6d91f3ed3dd8c
6649807d11cb59ddfa23fad081ddda04ea49075
KE2: 284678bf91c8cbe62aa3ee0bab908ab4f738d1b9019f90586efdfca95163b25d
ef3da3957ce9dc6764b1461c9ef1039918760f7bc31a44d8f3dbff9d25947c2742220
60eb0cafa2c9f81a60b5dcb2dcb793cedc0d3ddfce1100452e645f51a5f8ee104cb84
6f1ba962b900f5d28f63bbef21a60bf3bcb02131e83daceee0fe89a67b9ce703b2e8b
abc581c8d4df72b4ce6c59688a3d60e2e58a2daaca302abcf6d32a8669f25c7e3032d
bfae3be2cd1a0690dd8ef83abd179da490fb6f6dd623f1041f175aca82fb2fbae30c9
8f19eb9dfb1de9a4d661a7461721d4525624d800758afe20c7ab6d9c03d5c6f6f144a
4c0964b779670cbfd504d4cce8ea37f2707b727b7236532cbcaab548f529bb0a3f5cc
2a00d1b42d14ac07e05dca2dbc20661a4f30909137bc3274a25c3fb4310fc9c61d76f
c6576c8ed1c9816719433acc81722a2a5e23357b000f843a4f5a9016bf4629f4dd77e
140462e90e037f7278315f286665552928db406e3f5f4c6494204c9e39b48cbbe0b8e
8d32c6f2c80afc18dfd50c7567041faddfa8789ebcb4473d0c4280dde2b51f7c
KE3: 0e0e13e7da56e241bcf7e72bce9d82aabac647d5827350920d73caa0c173291e
a9677bac1116c91b8c53abbd5b14aee07403e8e2bf16b76aefcad28aa4b6ae77
export_key: 2d76cb8eb36d6b52ca5548f18973bb3f4e16227dc4f402de3d8e7ed86
f675fd69e83d11080af9f5cbd1307b27324673010b72b6ac05bf33481d6693bfdb8f5
55
session_key: 25aebd6c39af42d10704abcf085d3a13a4cb6f13cbd444476cb3fabb
8a34dbdb7b7c8f4003e1901db34d7fa020cae3a313c42d3919a3a23ae2b4e4dedec4e
14a
~~~

## OPAQUE-3DH Test Vector 7

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
Nm: 64
Nx: 64
Nok: 56
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: bb646e39ddb426383f5030be0d7cd7d81b47c2b31878a610b0c0283780
9b62af192ac8b166e11cdc57f8af5941688b00e59a7a90625a06d81c178738530341e
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 21f858c4575df153350ac12e48f10978fec8a180c7efcb6f51ca4
b80d44b0f54
masking_nonce: 61666249fe4ad8c10356c935a1320d656e9c8c248201d0ff1509c7
70df7420a4
server_private_key: 8cd37bf60927fafeca73ed8093538a994b1a8bd463666faa0
68e5ff9e00d588446b7d6cdc09ae8df069b30987a2cdd39286e0481e87ae227
server_public_key: 684e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04
ef823fc5c55e19163c714071efcab7ec06ccce8e6b9eba74ca92444be54f3c
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 354f3898c203edbe31f0db10c9df8d90f2001757caefdfe8dbe37d8
bb5d120de
client_nonce: 0a60dcb6a59b88bcdbbe96bde209eed4df105a09a01a08ee0100f15
c919426a1
server_keyshare: 80f64e52526682c9d332c4cb517bb261e21b86bc7199223b962c
3d2906f90bbf3252a02bf2889a01d0cfcd6390b8567854107e38abb21033
client_keyshare: d0cecdcb40e68a8f2a3c472d1fb7f0d96ce9effb7b71281a588d
f2ca0666ce00126e14b9a28bbe73ada49d059f7794e5da6be7e7bf0eee12
server_private_keyshare: 906707dee9b2e3ebd9842b0442e25d08ba2548c6a44c
0d7bf4ee396a0e4a3f023b35698aaa93a2be8bb632747671b3edeaedff0784da7e2d
client_private_keyshare: da23a46519065977331abaa1e3c0d86545162d96e9ad
ba538bf67207633a956ea71fbd02ea2dbfe7e195dbd26ea562c6f2406fe1f7c4593e
blind_registration: 4f0db672264527a8115f176c53709a4f94d1cca39c557ee10
3479baef585ba8017f7659cdd0b804c0938525199d88853b52ccfc7604bc233
blind_login: 39ba35e36db24404602da8a616e7ad8f72142cdb97a5689edb98ed34
24fa5c8584423c6b047121fc36fcec934c8ad24a98c86d0078b8f534
oprf_key: e1d2159815c27712d61236cd201e0de254e948c13a1f43d6a2c2a458b68
717912d9164a3f79d4655e11b9941f56ca4971987f280d176fa00
~~~

### Intermediate Values

~~~
client_public_key: c43abbc2fc929a784c3f764da5bbadb92be69d79eac950d110
9ae855c5e73a47fc6762ab8ea780d01ec30c093a70e30f00e889cbb1cb944b
auth_key: 1fc18c2785eeca0340a5a67e0380b491455481e821268ea474c9f9d3133
56423ff828e4ad258935def799ffafb8505e8f2ecf4f37d57e9af3c60e133db752f6c
randomized_pwd: 82c33b5df1031b36735360e7c03d829ee6a80fde9ef4f15ac586b
3bcc1539618839e94d80bbef9775bd99f17e820439b66a3b384041b871899b357fa6d
e35981
envelope: 21f858c4575df153350ac12e48f10978fec8a180c7efcb6f51ca4b80d44
b0f5410f4a8a1a814066a13d8746935490f50dd1b355c988bbbc2d9d34f0dc99310e8
5efa3668018b80d563933aeeda4801051bb57c260285f5042e2c1ba6a7f3d605
handshake_secret: 8c1c07962eaaf949ccec104351ba7cb5bea04d1916990e1adad
7bbe567bd62f52534a4f0d0bae31cb5f2147b5a135122fb87cc08a5af99827a494104
3674f44b
handshake_encrypt_key: 37684cc6a9fc72d474b3487d7a3b24aaa3d26a930cd4f4
a9bfe60d68438c4b36480453714a53d0bd5f13ed5e115009f2b737cb9c7f9459fccd2
316d1e5e38899
server_mac_key: 99c77d4cf69293572bfcad517dd1fd6aa71ff3897ad3ff8d0ed90
d2b46733f3d58e2eea3ff4de324979d020bfd365e6d1e4302b48f4e36f790f6a50496
bcafc4
client_mac_key: 11cf030cdf5f45ec4eb0bf6a62ea481f231e30c8c76d5c3383d83
f0bea47b8b0ce4419960b8a354bbcb0bb4e73993c660268a609cf477d50711c0f4408
61c2d9
~~~

### Output Values

~~~
registration_request: 8a8f12abe7f223895549fd121f9d6124424273b7524e033
f610261caf6ff83eb92d848318e7574c06ccee189b8b447b0fd26a348942d787c
registration_response: ccfc0bff52203f5f15da05ea4aef0590df0167de51d39b
472543c4abbb21da219c38c11182d66c1e2a28bbd6faba830419cddb69417f2474684
e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04ef823fc5c55e19163c7140
71efcab7ec06ccce8e6b9eba74ca92444be54f3c
registration_upload: c43abbc2fc929a784c3f764da5bbadb92be69d79eac950d1
109ae855c5e73a47fc6762ab8ea780d01ec30c093a70e30f00e889cbb1cb944b11aef
d6ec42306c84501e6cbfb4e7e11efc54dfa2202422a0aab6b1cc29a05215d5dfbeeb7
41cacd654c54cbbb9643442d279e8612b9de4f89d8d961806f547521f858c4575df15
3350ac12e48f10978fec8a180c7efcb6f51ca4b80d44b0f5410f4a8a1a814066a13d8
746935490f50dd1b355c988bbbc2d9d34f0dc99310e85efa3668018b80d563933aeed
a4801051bb57c260285f5042e2c1ba6a7f3d605
KE1: 442b8d7585abe08bbb6b03b3d73c7f5d81cba60845258a4174e7b8d25a6d7238
8ec7814b7f0a0559fff29ac97c329f2c7b0844c3adb1c6ba0a60dcb6a59b88bcdbbe9
6bde209eed4df105a09a01a08ee0100f15c919426a1000968656c6c6f20626f62d0ce
cdcb40e68a8f2a3c472d1fb7f0d96ce9effb7b71281a588df2ca0666ce00126e14b9a
28bbe73ada49d059f7794e5da6be7e7bf0eee12
KE2: 8a63ae784c8af59cd2dd193d11de4f36fd26e3ce0f74e751110e3eec331fa940
4f5ad32d9a67be88737ef441b393bca26045955affd6484c61666249fe4ad8c10356c
935a1320d656e9c8c248201d0ff1509c770df7420a4d2740f4e1ebaf4c805b9256672
fc33d391a1f78f34ff4882e904ab84a6ac073f210be384f62c203e5ddb9b8781b55f3
19f7bc1f6be7c5b34445643503ce562c5a6734f4e4d8131b1335fbe59ae2463a5125a
ca78d8d9957e7a73e00c1557f765def34dbdc4a15b786a897f3cdf6a7f312820addb5
7fa41b25cdc4f0368355f3797f3f18a8a6ed8c4fd0808014d6db777779d9f5afe6a3d
0a354f3898c203edbe31f0db10c9df8d90f2001757caefdfe8dbe37d8bb5d120de80f
64e52526682c9d332c4cb517bb261e21b86bc7199223b962c3d2906f90bbf3252a02b
f2889a01d0cfcd6390b8567854107e38abb21033000fd52c2008c3a618c8e9c6786dc
86c517d60af9188c103668709f4bbc47297ad16d05ace1a8e6e89b0b623e9a4df42de
f99316d7d48e03c33efdc71227bea6e62eb69f0fc617a5975a5ffa9181b55da8
KE3: 68384cab4a57e4f1ec93ebf8bff07b176999def6c4ea12daff73bc3c257946f2
042c4340c956dc0ff901c345ab6f999cf67ad53687e4dc1de91987a5bf0f4e48
export_key: 58c3a7a78c35b71bad6779f4cae5784bce53d51d711ff14aa6f4183f6
ec5b3cc5a8210df6c24194ef848ece3e48e5aa917226cecc14111efa46c66b6d5743b
4f
session_key: 3d5c60fe73b69266f46c7a4a241a25c0e5296af9c94dc88b84e1141d
434cfbf85dde4013dbe8e8e5b70de24f1d166dfd10fc0b1e833cf59dff592ed279209
426
~~~

## OPAQUE-3DH Test Vector 8

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
Nm: 64
Nx: 64
Nok: 56
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 5369e7ba363cc0ffd9f5435b87d13da37c69e70dd753d883a4581328a0
b1211b63870f94d19c970849e3f832d79a13cb8f17b3f699e0d44824c42ea9ed6673c
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d70af1a254350f45be31d80eff65fd804988d535c163e90687b9f
bdc5b49ab57
masking_nonce: c1eeacfb99f49efaae5dfd166cea7fb9952bda134f57f1104daf9b
d2d288c584
server_private_key: 0fb0bff035e9b9cbae6cfca36aa4827ccbac66177b64fabef
a67263087c0cb4e0d9cf547979e753c22548e3174abb5ac630d97dcd4af9830
server_public_key: 8071f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444b
a7ffe82aab916bc5ca6a11fd5fe1479e553040a8b724b6305c3f4289f3f39a
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 40744099d9bad5836511cb1bd87730fad25cf96124a2a41a2efa8f9
a1af37fa2
client_nonce: 2d829f911233762b8429f4145c63e362568b1e40c6477cb709baa40
3c42893ad
server_keyshare: d410d142e679aee86adbe57da4801741034120c59fa942ef44c1
9ffcf4a4d65200d5e17e7d287220037ab038ee08f96c9dee6db68f02cf18
client_keyshare: f2a67ee95170c51833a88419529748e55dd13e23ffed8fefdc1d
2b7c939b6371630031299800b01a99f83129aa986369e4a188220d056f0b
server_private_keyshare: 2903816a392680424bf4d98a04bda8934e23b94f5279
08fb98aedb6906e3ad31ab455e2718f4bab54e74adf302faf75cac75b1ea07dda807
client_private_keyshare: 6c148fe1102c81c00f1c5d3bd8a90198b5acfd60fd83
0fada243e5edc9bb4d6a1c0e88ea960201be2765b54f75a40efa86f066e6d5680131
blind_registration: efd50ea4c9248eb1f1e96143a8a41c1a1ee2cfebb2f07ff75
5a6d9fcf090696cd8b70a6ef67bd77ed5d38cf293669c6073cb4da3add7972f
blind_login: 7e134fa5223d965deb53441a7ab139fd35c83736b6eb89aae524dc5a
9fe6e16af18a4d33b1c9953fc1a7219dd6f81eac8b915a75e5fa3505
oprf_key: 7846997289e365bb95b8da4364b67ca6b9c2e6c5b1fcd4f624a37008820
12e38f1a67c7a622311de77a087c91abbc2ee65062c19236ee138
~~~

### Intermediate Values

~~~
client_public_key: cc9ce87a51859068deec37fd6f7a6375c3874b466b44df61a2
24da792d495935e815c3025091ab758fcfb6732db61a28abbe7c9c25a59f7c
auth_key: 200fd5916a6a5c4e76faa882f3e478c3abf4673e1181b758f14ef945372
0da57e9185418e7365b54b607d8530c5830a27576545b79f2bf3119298d170fdc53f7
randomized_pwd: 042f827c3c676da51206b07471f5d65926a932ccc5aa602bfc312
71b2c0653d3fe40b8bb8ad74ea78bc08c226961b306397c51b3606f9bc84a5b6ede0e
f7cbe6
envelope: d70af1a254350f45be31d80eff65fd804988d535c163e90687b9fbdc5b4
9ab57020fcc9ce588e385c92cfb2d2caf5bf1532863b1b5dc77c8cecc0bdf705c6e69
c81febaaa364b5f69c57fc7716c17e7bcb44eb5a6ca42dfc3007c7ba49ef7184
handshake_secret: 2e7155c6b2f7ddda06ba72c4d9f0067246696ef855c952d9fa2
970fb162580bbbdaa546032a18de61b999c63a618ba6a885524c83df4b42d373fe460
9425c5a0
handshake_encrypt_key: ec57354e4588c741ca4bd0ae40b13dbeca873edd6b2548
36f8e07bcb76c9e653c145aaa97cae30bc25d6a771d7b910d76c088d67e18fc1bd55f
694022ccd1673
server_mac_key: 65febfac5cf04540ccd0c1e99115b8ac71d7bce95224cf338f8b9
1d1305367c5ffea21ce576756bbf3c6f7cf80e89001c61d2b6b9b5c511fd1fea415cc
94197e
client_mac_key: ac27e4daf2316d958f475a65c07330b1259612f5fda6a02de3795
6aa931d9fba1ab1e9c1c6894cd98d7af31a76dcad19cc105836c00704685ab27595b6
c53c9d
~~~

### Output Values

~~~
registration_request: e499c1ea1a644df877a01f23ddc5dccbf3add4407605f67
dcc55f29c2ccec5daf9bc231dd62aa61cf2c9fdeaf59b3ed7a8f33af59ba20914
registration_response: 02d0a9b5d262d560b9839258ee696c78497c6f23624289
07d817439f72fe619496fa87b8c0427d600e8030851276e3df50be027bc86a45d3807
1f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444ba7ffe82aab916bc5ca6a11
fd5fe1479e553040a8b724b6305c3f4289f3f39a
registration_upload: cc9ce87a51859068deec37fd6f7a6375c3874b466b44df61
a224da792d495935e815c3025091ab758fcfb6732db61a28abbe7c9c25a59f7c3649c
55344cde7130181ab36e9dad95ad627a00c85f81fecd6cb07a34f2d3801818bb6944c
df6737b6072a3d422ea2806629f28dddf8069d28c83827e2c5825bd70af1a254350f4
5be31d80eff65fd804988d535c163e90687b9fbdc5b49ab57020fcc9ce588e385c92c
fb2d2caf5bf1532863b1b5dc77c8cecc0bdf705c6e69c81febaaa364b5f69c57fc771
6c17e7bcb44eb5a6ca42dfc3007c7ba49ef7184
KE1: 501e3dc8509cecfa36efadeba5efd0e4f66988ff9575c821b0128af06a2f5ebb
d77362f2a9e63b5a76cf5a636bad31b7a86f6c6803a2c9952d829f911233762b8429f
4145c63e362568b1e40c6477cb709baa403c42893ad000968656c6c6f20626f62f2a6
7ee95170c51833a88419529748e55dd13e23ffed8fefdc1d2b7c939b6371630031299
800b01a99f83129aa986369e4a188220d056f0b
KE2: 8e344a24535edcb94f862bdda3d5281e5821a7697d8169280df3a1b7f599aa27
472c381b67a594a6eadad3c48ac03cce1d0b67e946f826c7c1eeacfb99f49efaae5df
d166cea7fb9952bda134f57f1104daf9bd2d288c584aab53685e458f2b3359ff7d317
06874edccde0d1fc5809244ed2ef42a9bfec732d0b0e910788fd8cb400feade5de6ff
16a8c01bbe9433529b3c33a4b3b69b9dfb067b85e6f956380cf29d1e37cda3395ff8c
a3715a13a3ae5d2e49f97821ef4e94cbf79cfe6627ae47bdde41d47fb28a2f81d9933
9d4bf69b202c3bc899af72f494c156127dac299c9e6b345f3ce867000a7ad6043a86a
d640744099d9bad5836511cb1bd87730fad25cf96124a2a41a2efa8f9a1af37fa2d41
0d142e679aee86adbe57da4801741034120c59fa942ef44c19ffcf4a4d65200d5e17e
7d287220037ab038ee08f96c9dee6db68f02cf18000f81562d32804f41b3314561920
c91fe27dde4271020d3a9d78365ed865128f0b715289b8a656741830a596a65682dd3
86b7e18c55d009e493021aa4c98148fcdfd76b600523534e164b976c204ac1e5
KE3: 6d21e161839d0529b5031b3eab2856f6106acf53d476c10f889eee8c566446a5
ec9278a8b0b5cb3e9fb18065f2a17e7e94d1d5c9a854b6c06d2bd9d54a14facd
export_key: ece89a05e8d0a5cd7052e8e59b219ff4f553825450b0115b8ca377383
26b6ec6bac04c30359607d5b6442836de2ea6f3d7b4ee2bd166dbc14476cf42cad255
5c
session_key: 26e3855833c5392729901f112b2c62f280c3e6a1548dafd4b9812e1b
6aea12906ce31c29fe27accb044dac14941d7a376c6be668439bb6fe5fdf3f9548033
231
~~~

## OPAQUE-3DH Test Vector 9

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 01
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
oprf_seed: 222de1044eb3a2b1e0365c8f7d20cac72b212820f4212bfabbc7180eac
5e1f14
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 65f0dc5ad3ce0b549202d5dd3867cc35670e6164cd3bf8a56f358
32c276ce5eb
masking_nonce: 33ef31702b4b5adaf29b22cff288bfce7e363506046bb1da00857b
ae9a12fbc1
server_private_key: b3c9b3d78588213957ea3a5dfd0f1fe3cda63dff3137c9597
47ec1d27852fce5
server_public_key: 02e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398c
7100af2939f672bf
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: d355c4bb8ea252e88a22e03fb7f77f56e709a2a5409bf522c250467
a4c1739f9
client_nonce: fd9f7f07919823537dd02a3eeb22f400c97b5583d8cf9f64a9b2311
b905af4c0
server_keyshare: 03651207f3887f92cfec56edd9b9df0047c1d6b7bfc55b3650a9
579d44f435b092
client_keyshare: 03285470567bccdd3755aa8d00261e1ce65aa120e15571cc9772
789a361b4cafaf
server_private_keyshare: f5685928c72d9dab8ddfe45de734ce0d4ff5823d2e40
c4fcf880e9a8272b46ef
client_private_keyshare: a593b1095e7d38ba6ff37c42b3c4859761247a74d0c6
2c98ddff1365bb9b82b3
blind_registration: f9e066cf04a050c4fd762bff10c1b9bd5d37afc6f3644f854
5b9a09a6d7a3074
blind_login: 79e775b7220c673c782e351691bea8206a6b6856c044df390ab56839
64fc7aac
oprf_key: 33d82b5c6d96b0e2eee646aee10193f83c8420211e07fae25095eb6f4df
369e6
~~~

### Intermediate Values

~~~
client_public_key: 025d19e7faf171e0a39d8f3b872f53e98017d6c49a708da2e1
26b78c1a7169d4cf
auth_key: 46ca67ab022b506c42b8be86baa0e19d1462762d182b1f8cc6f040ec253
a0409
randomized_pwd: e7b1a04736150f90afb666cdc04e868e86c100ee9ab2379d74e12
66030f45c22
envelope: 65f0dc5ad3ce0b549202d5dd3867cc35670e6164cd3bf8a56f35832c276
ce5eba93f34e6f73e5795912086ba07f113f0e14d7731850db1c2b38d3e46e8778c58
handshake_secret: 0d4bdf9a5dc37cfdf90f47c9e0bfa8f6b2bbafb5043b237de65
2a266f84cf27a
handshake_encrypt_key: 5fc60179a58f729c5fe9716ee2864dbb0a73cbb5733dfc
da4816349501b84fb1
server_mac_key: 253e6b00cfc920d8f7e491fc293ab7fb325ec4f5894033e51a9c3
1b5942e1959
client_mac_key: 506688d52612857c8e7dbc8150c73e3830abc0a4d2746f50f0e4a
3f5942f83e1
~~~

### Output Values

~~~
registration_request: 03761c2597a039a535c3180bd3fb6ea9830baa50376dafa
6e98bb41be2aaae0e91
registration_response: 022c78531bce7284214b2a693c217dcdf4ca53ba4ca0fd
8679def7698b3b89be0502e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398
c7100af2939f672bf
registration_upload: 025d19e7faf171e0a39d8f3b872f53e98017d6c49a708da2
e126b78c1a7169d4cf8b3218ffb32c3c4e40542f9b81e5ad8472d4371bb9914165b77
5b94247c5eba165f0dc5ad3ce0b549202d5dd3867cc35670e6164cd3bf8a56f35832c
276ce5eba93f34e6f73e5795912086ba07f113f0e14d7731850db1c2b38d3e46e8778
c58
KE1: 021922b40d051877d0f03ccf2831eede9b328e22c8b173d5f28091af0b92421f
54fd9f7f07919823537dd02a3eeb22f400c97b5583d8cf9f64a9b2311b905af4c0000
968656c6c6f20626f6203285470567bccdd3755aa8d00261e1ce65aa120e15571cc97
72789a361b4cafaf
KE2: 03c5dec0723bf62419a4572b9651b2000ed362b5e35266850468b7bc647530b6
6e33ef31702b4b5adaf29b22cff288bfce7e363506046bb1da00857bae9a12fbc14fa
b54da44a07cff69e135f22cc5430f03b4757cdea284978709b2ea6b6fb4bc860daf24
d4fa24017d629a717cac436a74d389f9cfd00c7c4cfe1697de2b0158ba0ebb10e3beb
621b9045ce0a4e2ce63b937058732ac0261c23237adb4357cbc38d355c4bb8ea252e8
8a22e03fb7f77f56e709a2a5409bf522c250467a4c1739f903651207f3887f92cfec5
6edd9b9df0047c1d6b7bfc55b3650a9579d44f435b092000ffa88ce75b0eb1e6bf8ca
567aab76baed74be60749d008e3102ca12d7f8aec5e94e1e24e6a39ba808459e75df1
b1c71
KE3: 6b9e3bfa986cc8f17a47024275d4c86421e928e5f9aae9b65235555e2c529462
export_key: b15b8482f93486c6c611bfb425983b920e497595515d4aba60c36c98f
d085585
session_key: eded1d0fc7840adbef00e47868707b13b01fa50e7d143b2d694ff428
67769ad9
~~~

## OPAQUE-3DH Test Vector 10

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 01
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 411231f4c1e2a61b4295bbc556c82b3200a5011eb95da458bc975074f8
c40f0c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 7e28c4858849aba47c0f3a8788e263eb2992076d6e13ae1c31c95
bb425cf520e
masking_nonce: d07690a0ea1027783695e907cf1977e9ccc7d9ae0ea3922417fe6c
a99b1ea4fc
server_private_key: 2bc92534ac475d6a3649f3e9cdf20a7e882066be571714f5d
b073555bc1bfebf
server_public_key: 0206964a921521c993120098916f5000b21104a59f22ff90ea
4452ca976a671554
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b954553c8c79d924a1c591f783ba1bd5d4815f54893e96f58bc469e
be87758d6
client_nonce: 93dca0cec3925e275d0c790c25d6456b7f36d6f9bdecd6cf678263a
c002d1296
server_keyshare: 036d85072a9cda8438f67dd81042861349f697c06ad4efb068dc
eb58c98986409c
client_keyshare: 031e7dcb77fdba4b7e7b1625e43dae84733b28eaf2b4fbd7df14
1b1ee353748b44
server_private_keyshare: 196708f773cf65852bda777210337d8b3b88754b881a
a5fd937ec7932e725ac5
client_private_keyshare: 3a07cb3ea0e90b40e0501e6bdc3c97510cdd9475ad6d
9e630235ff21b634bc66
blind_registration: ef54a703503046d8272eaea47cfa963b696f07af04cbc6545
ca16de56540574f
blind_login: 0bf837aaa273530dc66aa53bb9adb4f0ed499871eb81ae8c1af769a5
6d4fc42b
oprf_key: 179b24e76ebd4e1be0e108bf006aa77232f2aebd2e64ec6e5fc15e6bbb1
0bd72
~~~

### Intermediate Values

~~~
client_public_key: 03bb0ea77280040f08a1387541588a15626616bd6d5fbc5f86
5e336dc4239e073a
auth_key: 1b46cf0d5e965018b3daf72888b446d2af2000555b725061975c91ac7ed
930bd
randomized_pwd: cb2410d0b7d2c3868892a7ce491de10deba5ad3c51ce50cf38c35
83ca2a61575
envelope: 7e28c4858849aba47c0f3a8788e263eb2992076d6e13ae1c31c95bb425c
f520efdb6d71170c02d62b42d4836c6e86111d001f3b8ee7a04800f964398928962fe
handshake_secret: a23bff26bc68422cfe2f77d67d91d9966fc86f5c26202d1d4f3
0f6a2acca190f
handshake_encrypt_key: c009b1a9f339868db545503890b28d73a97c51c3562846
7f8d87b9254d80fae7
server_mac_key: c482b5aa511c35013987032ae5fe6621d4b71bb98adbc17e1a8ea
32417047d52
client_mac_key: 4bdcf02f9f2b4bba2a2001b95c46bd776a027764f9fa0bc479eb9
9a320ace697
~~~

### Output Values

~~~
registration_request: 02cd04a4a3c6b37f6013d848e1c63c204c4593377e9a14c
68e95097b615d29c129
registration_response: 037087c8ee3db58c82f02bf4685572e3e48b9639417722
64f5436febc9d2e566a00206964a921521c993120098916f5000b21104a59f22ff90e
a4452ca976a671554
registration_upload: 03bb0ea77280040f08a1387541588a15626616bd6d5fbc5f
865e336dc4239e073aebc552c85f3af13f76e12831012f33d891481a03556d64f51ac
6e4d5216a957e7e28c4858849aba47c0f3a8788e263eb2992076d6e13ae1c31c95bb4
25cf520efdb6d71170c02d62b42d4836c6e86111d001f3b8ee7a04800f96439892896
2fe
KE1: 02e747d027881e63565ce0a611dae6da50c2a8b349010a52f5c936169be1e0f9
3693dca0cec3925e275d0c790c25d6456b7f36d6f9bdecd6cf678263ac002d1296000
968656c6c6f20626f62031e7dcb77fdba4b7e7b1625e43dae84733b28eaf2b4fbd7df
141b1ee353748b44
KE2: 023e69bd9f6ac2a9247a45cd6ece02734b01f4f097277cef4b651d292b92958a
f0d07690a0ea1027783695e907cf1977e9ccc7d9ae0ea3922417fe6ca99b1ea4fc21b
f6b965eb775c1ae1621d56b3b2a909524d755f09dfb5abfba139c38d03a06d7fbacdb
9362415cb82e80a426b2243c861a99ab96c375d638778555ae59497e3982f4a4f5f31
8ebd25b9135a613fdfb9c78b12a9fac85ab50502cb750e2e6f162b954553c8c79d924
a1c591f783ba1bd5d4815f54893e96f58bc469ebe87758d6036d85072a9cda8438f67
dd81042861349f697c06ad4efb068dceb58c98986409c000fbd84aa78e5bd91d5c371
3a82701f84eaf16cc8b383370374ad7ae365a2a5c4cbb5f807cedfb89f72a484b151e
d86c3
KE3: 148aec24c974679b8f2b22545fe6b438919cfe17d5c01477506bd838af4e0070
export_key: ce386730106337ff5442cefb268e042f4018a254efec5afa042f6e317
84ff18d
session_key: fb4663e7bf2c24bf84f39559f0fbc1a5461dc2eef52eb458cdbbb391
95fd806b
~~~

## OPAQUE-3DH Test Vector 11

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 01
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 7ff9f5a010a39202ec8583b1af1667e39a790c8eeae3c8850cf1b22593
4b1bb7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4b2ac56569cac13e4c94b3c5a661297b9507bce9cb4d61b988e79
cf66e7376d8
masking_nonce: 1c289200b0c01921d4367f7f5d6efdf313597a494e4652eed4fddb
640030ecc9
server_private_key: b0b4f35c14eb2477c52e1ffe177f193a485cccf5018abbf87
5b8e81c5ade0df0
server_public_key: 02e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e5
59ae18b6bf7bb5b2
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 2348f61d807548ef1e7b35a914f52bfb9c2fdd799ac0f75333a17cf
266cc48f8
client_nonce: 95d6caca3088960f7e014beacaf854cf3c1f81ed707bcbd7cda660b
43f2cb8fa
server_keyshare: 0222d4232635f4ee3706759740d7a0d8fb6a4068f2fbd34be7cf
065f9989b637cd
client_keyshare: 026ab0dc783fb12c9427dd0bcb4d95f5b5212f092406dd581bd3
37c73468953226
server_private_keyshare: 9fc1965033654f34b06b578fe36ef23a5b9872ade82b
9261cc447670debcf784
client_private_keyshare: 18add682f6055089b0a2484abc37f110b36f4c2a140b
7a3c53dd8efb6171d3bc
blind_registration: b0d53a6f8da29c3cf4f8695135d645424c747bec642bc9137
5ff142da4687427
blind_login: 4d73591be8483a1a38e40c13a04b0f2180dda3c36e3d43c3a8f12715
8d010945
oprf_key: bfcb3351d8cac1374c48d88262115a8ce447116f8d9659af4927e8ba473
b3860
~~~

### Intermediate Values

~~~
client_public_key: 029ef859264f5bce3ce76ef33cea426c0868cb6cefdd40cc97
40530e4e2b8eb9ec
auth_key: 794a4b51879f176d7535dc173209697e58adc5ba355071dec1c010c1a30
88267
randomized_pwd: 1d7413e513aae8db0fc7ecff608c5a8ee36ade8e19c03245d7848
886eb9e2f3e
envelope: 4b2ac56569cac13e4c94b3c5a661297b9507bce9cb4d61b988e79cf66e7
376d8e8764cec8c7f0352bab2e22a52784068274a3d9bf6e867fb1174dad9fda451be
handshake_secret: 9fd8f0f8e2faa0f5b09bb04b6b414b4d3a85bb7ce85e53ebcbc
44c9b0ffffbe4
handshake_encrypt_key: 0ad54a7aa1eba3c373884458aa42025bb707801dae3abb
f8369a286aeddf0cd3
server_mac_key: a3c1a5b0dca01277cfd2357ad2102cbbe29620066c3c9bb9da6f3
c71044605c5
client_mac_key: 49deecc8c3abbd5974f12864c2145204866385bd8a74f642df192
1999dd6935b
~~~

### Output Values

~~~
registration_request: 026aa49819f2c29b9543cefa0850db7fd36352c6ad8f47b
631b5b621266b670f7b
registration_response: 03895ca32517359a907fc25fb7b60e63f0ae40422c4438
bc41129ffea836e306ec02e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e
559ae18b6bf7bb5b2
registration_upload: 029ef859264f5bce3ce76ef33cea426c0868cb6cefdd40cc
9740530e4e2b8eb9ec93cf8a8e4931fda8a52ddf2713542e8959cf8ee995f42333a12
b36020697975d4b2ac56569cac13e4c94b3c5a661297b9507bce9cb4d61b988e79cf6
6e7376d8e8764cec8c7f0352bab2e22a52784068274a3d9bf6e867fb1174dad9fda45
1be
KE1: 0223c6f12f3c763bdfea59c13d8f1e055b02277625aa06cb3d839e03a60268d7
c195d6caca3088960f7e014beacaf854cf3c1f81ed707bcbd7cda660b43f2cb8fa000
968656c6c6f20626f62026ab0dc783fb12c9427dd0bcb4d95f5b5212f092406dd581b
d337c73468953226
KE2: 03d7c51c4c0911f7767034c5fa8e7de860e32ea2f5fd5bbb41dcdbe752cdfe38
d21c289200b0c01921d4367f7f5d6efdf313597a494e4652eed4fddb640030ecc98ef
d62c96d1fa8326a148a19faf7e32eb023b0eba83cd72d5edc0d92a759c431784a5183
ae68962edb95ab18e1f920c8363cc3a47b60ac873e3b745df1ab0f4a100c8817b7a2f
569b9ba67b1f10a38c440bf178eb7129a8743f32071d4bfcbcb962348f61d807548ef
1e7b35a914f52bfb9c2fdd799ac0f75333a17cf266cc48f80222d4232635f4ee37067
59740d7a0d8fb6a4068f2fbd34be7cf065f9989b637cd000fee4f603aa29b2064b11b
07ac6deac7a32a58b59efe45afb77b097af2ec1942d2ffdcb44da599ef82cc5beed29
6be38
KE3: a271bf176d064d979545657cd8f6f53b3efbaa37aea6cd45782749f7c4744844
export_key: ce86f17a7720b70dcd4947c727dc48f549ca76bcae48837a6aff2ac88
65bb07d
session_key: 315b45cc16fb96a1697decfaf732df3d5b539b9d67465a61eeab7f0e
06004702
~~~

## OPAQUE-3DH Test Vector 12

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 01
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 7b79e836d42b66345781840b42a9475350106dd58ed1f2d9670e7b3430
052729
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 972d1d19b3f76c5a53e1de821dc64cec826f716136c9397a7fd11
3bd04e6819c
masking_nonce: 5a5ff17381f05c594745598e064751cfa87ef81ff8a3a05965a4c6
e700f2b060
server_private_key: f7493200a8a605644334de4987fb60d9aaec15b54fc65ef1e
10520556b439390
server_public_key: 021ab46fc27c946b526793af1134d77102e4f9579df6904360
4d75a3e087187a9f
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: f7877b506a288dfd45503bd89a48458aafc0971d3e8cddc4b54ab58
e23ebc079
client_nonce: 8ab09b516c0696e39295549d80b482aab2178688195ad806c922c66
26e98cf75
server_keyshare: 029ad3943fb8e838ed49e4d64e5f0b84e120f175f30115009f18
f009f7e35081b9
client_keyshare: 033b64a07786c37f90b1abc757bf074c18326773bc296ec69f38
c111e4274a4071
server_private_keyshare: 629de5cfea56c0532dd8254a5a6e7fcc9e51e20a1cf4
f254335ca57ce603ae7d
client_private_keyshare: f03fc00b7a2d495298d84c8c83b686b67e82569cb56d
97e9c20e59311bac3a51
blind_registration: 9572d3a8a106f875023c9722b2de94efaa02c8e46a9e48f3e
2ee00241f9a75f4
blind_login: 735d573abb787b251879b77de4df554c91e25e117919a9db2af19b32
ce0d501d
oprf_key: 3265323242d130d8ba66357c22520711b50ddebaf76449ad006a7c0e3e8
175ae
~~~

### Intermediate Values

~~~
client_public_key: 02e1b4141e364cf9ec579ad9ddff3ad17de4ed8d3b03d884a3
7ba0d3afec5b45c7
auth_key: d2fc33d0eaaba07cfca12b836586821ce7ebbd676271ba85cfd87d46914
4d8d8
randomized_pwd: a808d107c852b2670e12235fa548e71304ae6b75479871f805e1c
165921d23cb
envelope: 972d1d19b3f76c5a53e1de821dc64cec826f716136c9397a7fd113bd04e
6819cee0781091b47d746f894ada27e2eda06ec56bedb2983407791d377f889321cd3
handshake_secret: 8f1f714cd4cc8db5eef700834df215cd65eb6a0fddb37b787db
23f76be56d710
handshake_encrypt_key: 6c45f6bcdef803c17bd82ef4b55f6b1f4e6d1c54f32af4
b43703607b5ed378d3
server_mac_key: a94bf39005d55b243d4b28a905cb950c0d9d98333dbb70cbe193e
13717985e92
client_mac_key: 7bed59107c599b2db2c0b8dc5beb9932c0335cc7dff01d53e78d5
5d162a0349d
~~~

### Output Values

~~~
registration_request: 03a120f6f2a0b858f546d1e2b60f810ad0ed8511ef0791d
c26d8413fe13b0181fe
registration_response: 0236fceabfe2a4930814ca9a332ce07e68f2adc3716027
0451a702ac23512cfa1d021ab46fc27c946b526793af1134d77102e4f9579df690436
04d75a3e087187a9f
registration_upload: 02e1b4141e364cf9ec579ad9ddff3ad17de4ed8d3b03d884
a37ba0d3afec5b45c721afeee74ac33d7723f75646579845bfbf12bfbdc50fe96d95d
60fab8cc547df972d1d19b3f76c5a53e1de821dc64cec826f716136c9397a7fd113bd
04e6819cee0781091b47d746f894ada27e2eda06ec56bedb2983407791d377f889321
cd3
KE1: 03edd5c0afa7257bbaeacab64837430929df9b36bc2784e47577e071a7abd9f2
ef8ab09b516c0696e39295549d80b482aab2178688195ad806c922c6626e98cf75000
968656c6c6f20626f62033b64a07786c37f90b1abc757bf074c18326773bc296ec69f
38c111e4274a4071
KE2: 0239e4df8488c462d1c224682a9d281f457308b93dd20c3f75c27b9f2b9c2500
a35a5ff17381f05c594745598e064751cfa87ef81ff8a3a05965a4c6e700f2b0600dc
b0032c499f548c5c6d390e905d62e3de1e178162d2fcdcce28e342b9d37582fe5d99c
7894a64f74399525ccd83a4895ca3781e29df46a410b42a725fe4dab9e9c90342c5a6
7da914e89eb8194ac782511e937ce15aae294acf0f8db74408dd2f7877b506a288dfd
45503bd89a48458aafc0971d3e8cddc4b54ab58e23ebc079029ad3943fb8e838ed49e
4d64e5f0b84e120f175f30115009f18f009f7e35081b9000fee6e8c5e47d907f747ff
767394f8c8df4db2838bc5b92955d6038470a2069a6974b8909a6a956d1aea3563627
cde2f
KE3: d0abcf6e885a567fa3ca78cd8ad21baee81efa2111c31266b63681453102196c
export_key: a20bb894d3f92d728b18611e87219a5e10b65d46140d20c87337db9e1
5b3c258
session_key: 102c4211b41b0277245548e6b5640af480f0d7307264aa574067b4ce
aa6d2496
~~~

## OPAQUE-3DH Test Vector 13

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
Nm: 64
Nx: 64
Nok: 48
~~~

### Input Values

~~~
oprf_seed: 13800aba98225fd13ea9ede334af6f7b3a9c21e03aeb93a18a14b39684
a6889d2f79d4e8dc5feba7c45fd0e8c9150edb4d15f7814a4b06f99d8226f7c3e1384
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4a8a6e468f5d68d5b3fa677d48a3bec161f2c89322a873ea92662
3243af2ea2c
masking_nonce: 42c2f63d5b5278536247f6ae675807d8bddcaaede623ced8a96cec
b9844d7d79
server_private_key: 6b61028c0ce57aa6729d935ef02e2dd607cb7efcf4ae3bbac
5ec43774e65a9980f648a5af772f5e7337fbeefbee276ca
server_public_key: 023713c6af0a60612224a7ec8f87af0a8bf8586a42104a617a
b725ce73dc9fdb7aacbd21405bd0f7f6738504492c98b3e3
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 326453281b10997aa161dc84f134178efe6570781421afd7919aaee
7c4e2b2d2
client_nonce: 322435bbe19729913346a5e4afc400479667a0228c1c6e8e4f5444f
d598b31f2
server_keyshare: 03196d22794e67e69232db19e4032d2f2daa09828c4ef71e5a4f
296a0edecaa5bf564c97a7e8c96a4977975a44eed2b37c
client_keyshare: 037e9c1e7bbf41bff8ca6fabb630db2db73a92e57c6260f39d40
24c619f8b4f2807473ec0f715d83e88ad62b88ff3828f2
server_private_keyshare: c7a86f11c143a291e349b70b34e67b38fe9dc6f90b47
375087d72e891df74070810500dfd391282c15d87bacdc9867a5
client_private_keyshare: be210603388cbcabb8cb630aa1ad04d73e349009a438
ce248380bd4b7e6758211fe9692922fb61f00f1a39bc735cefce
blind_registration: cfa46891dfa664a785675b2c95bbc2412ceae9d69a1860383
45f8ff704bc925f6818500615a825a9a6b5646a4e4f11b2
blind_login: ebd2fec41edafcba833ccaac567c14d2fa01f55b33a2fbbb37118f2f
5603b1298346e02cbdf55c95ef9b1aadda5ef281
oprf_key: f655c17978ae61bed13d01a1116fa75011a9e6191d46fc960606663dcf8
dae07ceee252875e658bb1d1c5b841d362062
~~~

### Intermediate Values

~~~
client_public_key: 035de411e2fb5577953f30f87c4d9d3917523f45b566224508
cef53aa0945cb6a7ccce4dab6b7c7328d11d667efc6cfd0e
auth_key: 9cee8f606fda00485838192d7e31fb2eae77f8304d7654af477cf23c78c
0fc5d9338274e67f9f06c8c97c3fb844986e99b11742a31d7c2513234a6ec8740290b
randomized_pwd: 09be717bcbaec4e06df0b406fc9a05f079c3f77497ccad88fcc2b
aa34a2349f8d0079ad5e28128e8a0ed8243b31232720beb178baff69e828ba88cee2f
c15cac
envelope: 4a8a6e468f5d68d5b3fa677d48a3bec161f2c89322a873ea926623243af
2ea2c6eb6c5b7f4fc402d2172d66fb490ef71a552934051511da40766f4ce4aa847d4
3c3c3ea55b117a1a5c48ddc55970ef3b64de1fe35e305b68ad636cf15dc4aaa8
handshake_secret: b18a5d52f7cd9bcbf618154ffd440bc7279dd5bb2ad4cfa8518
f00cc55a3208c05921899b07c08a7e7380f842bf330ec5fc916e1849f8a144750bf04
9056310f
handshake_encrypt_key: a4c41abe175bf6d9258a3dceb3f2210b5519ccaaafcf33
7b0ba50b2ce841513326bfdcfdd8b3bcaaf6449a8de0919c31b72315285fc8a88a16f
41aa3d44974ff
server_mac_key: cc2f7f60b051b72fabd39537c4dd60682dedcdb36cd04d291c948
00e94707d2bf85e4ace90a8c61a2894bd9bc65aee19d61ce144c2c873d6ca73e098fb
8fbacd
client_mac_key: 027bcba9c75a1152c2a7c915f544c43f2be877d5608d8a1a676e7
301489c64eaf36271c404b70da768cb51ff642449cfbb2e51754619b0d70cb83a2332
31bffa
~~~

### Output Values

~~~
registration_request: 032a1ed9cba49c4f38f62e77ca295b8dd95d4d928aeb7ec
db24e28d927909e4624e4ef5df6b729071abb6e557b809d5ae8
registration_response: 03c1da8bd060abc6e688aac947e3f849c0b4440e9ee9de
f90ba7ad7f79c5a32627ebdf1d02c9768c8ab55a5638ef8033fc023713c6af0a60612
224a7ec8f87af0a8bf8586a42104a617ab725ce73dc9fdb7aacbd21405bd0f7f67385
04492c98b3e3
registration_upload: 035de411e2fb5577953f30f87c4d9d3917523f45b5662245
08cef53aa0945cb6a7ccce4dab6b7c7328d11d667efc6cfd0efcf452f9e40c4d9df2c
441d4a65aa2b6c73c12eeb0abc32d87cd5655b57c5c019997da030219eb51cf4468c4
92d0953aaaeb43f634cbb0ed5100cf95a2a2a75c4a8a6e468f5d68d5b3fa677d48a3b
ec161f2c89322a873ea926623243af2ea2c6eb6c5b7f4fc402d2172d66fb490ef71a5
52934051511da40766f4ce4aa847d43c3c3ea55b117a1a5c48ddc55970ef3b64de1fe
35e305b68ad636cf15dc4aaa8
KE1: 036bb3b9d78c508490de49427658685d8a74bdb5acb7ca4fcfb6fa5488911b86
8e746c08a1260d828fc5fa7e4232a2e58f322435bbe19729913346a5e4afc40047966
7a0228c1c6e8e4f5444fd598b31f2000968656c6c6f20626f62037e9c1e7bbf41bff8
ca6fabb630db2db73a92e57c6260f39d4024c619f8b4f2807473ec0f715d83e88ad62
b88ff3828f2
KE2: 035e2060062e1fa5cbabafe394331fe40e84a7ee61ba0f00db18551adf53a3c3
80803b5d296e64a4ec298cead57dfa4d8a42c2f63d5b5278536247f6ae675807d8bdd
caaede623ced8a96cecb9844d7d79a960a3b4f660a8b0df50469ee450e36b648a3913
d6f3ebb7bf1981a9edd6a425f13242e1bf5a529f7f472e776f8ef2dccf7af9c9785cf
c23a20a17d75615d019399ce4b78a1a8b88353fc6aac945377f4f87e705a39c0ac017
d5226dcb15b118dd3c84b53c935dc648555e3ca33be2122633ea59d8f3d1374e63cdc
df1217b8614bde3396183aba4d93f412f153c293018326453281b10997aa161dc84f1
34178efe6570781421afd7919aaee7c4e2b2d203196d22794e67e69232db19e4032d2
f2daa09828c4ef71e5a4f296a0edecaa5bf564c97a7e8c96a4977975a44eed2b37c00
0f473d1a939f630099a3272f271913ec909f1300f12da57d3d6ae33e0d587b2d16a5a
21200c2860321523950d6e59831c8056310e3a73b0bd9c49716310a69e3d2d043d646
96b3ebf52ab66e13a81e31
KE3: c9a4a4461e249f13a553edac3b86cb73c6944b15161a2f0d069eef5de7ffe73b
388d5497963b1f70a3158075e06e97db6c715be0f04d93980f63918170681408
export_key: 57baa1225a9bc0e5f97d9ac053fff44d488eac46326b99b385afa7471
3a6e0c57b0e1d83705db58aea52d169a7d782f3a3601dfbdd8709db37d8164c52cfa8
94
session_key: ce5fbf3d3645c21626073bd55802311a8ae168cf79a4826a7a55d543
c7ac170bb56a005a686b7643305d1c575f41e0e1ee4c35b888a9aec84f821082c188c
dd3
~~~

## OPAQUE-3DH Test Vector 14

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
Nm: 64
Nx: 64
Nok: 48
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 2fa53469eadd73b1fa9887554db81fcc1dd326a364ddf58330f8174958
875763130077aee6e744624c72c29668535d30250d89a20cbc9e2654b08314da9245c
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 9a1242e14caeb650b6db37478131f194c58aff77ae769388699ec
c81f99b8820
masking_nonce: 1904aefee8a91aa363df4a775d4834c553c8ecbdef6c173403f066
8ac96a0bfa
server_private_key: f5acc7b0dbee75bcd8bb50363ec640038177f06904f2476ad
5274e2f9d258659e80b0fbd20e4761b22298eba98ae9dc5
server_public_key: 03ca37ed36b0b311e3241e6e96f49a44edaa971419d91fcabf
fbca0184afabd92827344da8379abfa84480d9ba3f9e4a99
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: c5fe35951cf3cf6b68e388bed557b8ec848eb49ef719deaf56273b2
4190d8485
client_nonce: 30cf008c4abd83de383f29da8820d2868d106c347de88d5b7057c0a
c79a1884a
server_keyshare: 037b55471c1bb3a246d0030fda68aa80a79786fa060c0b56e7bc
7d0000886e3d661be0afcaa0cf69519eb528a11af48a9c
client_keyshare: 021323ffcdb6e9971cb3d0516ac4f70f48c50ce81c897b4c3459
ab5aa664a410e20012f6a3eefc00044991282868648a0f
server_private_keyshare: 181c9f03d5b5e51b3a90cc9da17604b2e59a93759eb0
985d2259c20e3783be009527adf47f8fb5b1437cba7731c34ac8
client_private_keyshare: 0bc6ab1b8c14ff4110afc54c9598d5f1544830f9d667
b683234c68ef3db95227fe3ebdfd963d03070055fef107bfeb3d
blind_registration: 92e4dc9cd7f7aebfb1d3d2b8c7fa7904503aef20c694a01d3
e1154fe98e7232be9eaec5789a012a559367b1f99654ddf
blind_login: 79c86b934061f894227b23a69eb0b53f168a4a2230ef6a7d703ac4cd
5b5e0fe438b3000884019316267eae9b424f8126
oprf_key: f375a6dd502549e0dd8c67060b1b3610a6c01fb78a2d4fc2555ef78f494
23393b7aa166a4d47b5526db558e6a818a93d
~~~

### Intermediate Values

~~~
client_public_key: 027fd481529fe30db35dbebb7bce46564920f5cd18221c7a31
265ff3ea9af5896f685cfa39d100dd9ddde1fdf0139b6f77
auth_key: c8873508331f03fa55a3157e3405b6358bc42270387a181b38a2f8faa8c
ebb95eaa0f07af9589a1f6dbf5d5e1bc835a84dbc1b120dd647dcabbc2ef9f3fb1808
randomized_pwd: 08afd475c652f52c25433db458d79792f1205e22e23b2127ec992
bb10e4acf9d3b583128e59241fb64918756bfcb43c7189df8f5348303e0fde437bc7a
8d9e3d
envelope: 9a1242e14caeb650b6db37478131f194c58aff77ae769388699ecc81f99
b88206ec6539fd339dab28daf5dcc962b240bed4776952de1a622d5dbb33e314f142a
4c7903cafbe5d3464c78552655e153bb3ff274e6a80a7c0560d2ad7bf243e682
handshake_secret: b562b476cbef308f37efa9fe4e9baef70b0435e3cb7ffdf940e
4e72881902999b3e62c76a573a44044bfe28ac82a77767df31cff79a35508df967061
d7b9c5a9
handshake_encrypt_key: 8e52d760aa23442270a6c880ea165e2b4d07eb15cfbcd1
07d27c9d2573fdc918e598397527895faa1565935cadea27ca415321019a3e6dd9555
6ccbbe08012d9
server_mac_key: bafd8cbd704a553c4859ba9cad35d024d8a14c35e9d1c26512995
bb47aac4147cbb9a927607e0dc4c1abe03265991ee982918b2a3a6b4a6bf9c9dfb75e
e992e2
client_mac_key: 18dae5081243b3ae9f8ff3a400a413e0e33a4fc83e68174bf8aa6
b4e6b30881c38738d9bc3ce35db6caaef4fceb70d3af255c6120900c8dd21d1fe04c9
fdc016
~~~

### Output Values

~~~
registration_request: 03c11a1b33c831ff085bea647c06bb354083adeaf4e7c25
d4ef17e90a25e590b275d412a48b83c064f75a6fd383e4730a1
registration_response: 032e2e2d79c4de3f578cf146419357b40c766356636712
310c3e787b768a90ad21500cb17a5715cc17e55b287a1ec4574703ca37ed36b0b311e
3241e6e96f49a44edaa971419d91fcabffbca0184afabd92827344da8379abfa84480
d9ba3f9e4a99
registration_upload: 027fd481529fe30db35dbebb7bce46564920f5cd18221c7a
31265ff3ea9af5896f685cfa39d100dd9ddde1fdf0139b6f77cff2cc696df1a036600
41b9c521a0ce6290e098168ffc27730118cf5ef4300ec692158ede08cfed5d64e4703
f2c375b7483cf210f5d3149d4b06e2721398dc349a1242e14caeb650b6db37478131f
194c58aff77ae769388699ecc81f99b88206ec6539fd339dab28daf5dcc962b240bed
4776952de1a622d5dbb33e314f142a4c7903cafbe5d3464c78552655e153bb3ff274e
6a80a7c0560d2ad7bf243e682
KE1: 03569da14f7d483ae405bdbd365b7bc7cd11968aa5c105d6fdf21d83cbc77050
7be9fb3aea6709f4a37e940900bccb4ca830cf008c4abd83de383f29da8820d2868d1
06c347de88d5b7057c0ac79a1884a000968656c6c6f20626f62021323ffcdb6e9971c
b3d0516ac4f70f48c50ce81c897b4c3459ab5aa664a410e20012f6a3eefc000449912
82868648a0f
KE2: 03c7b550c1f4a2ffdbce37b8c3048d6684972d3e145af0af6b4d9042c2c95a73
cc43c1b0d21e79e52096fd92936eea28351904aefee8a91aa363df4a775d4834c553c
8ecbdef6c173403f0668ac96a0bfa6fe644beeb3cc4b900ca849a68c6fe3cf0d2aa8d
7e994bb8dcd63455dd800f51fdaf741c489488ca6032ac215f83300c939b3ebec5294
8afb1db24771b2ebbbea5ae284140757302a75262fec7047687fec7ea92e622d3c561
546b9ef1627a0016a60a7a840da5834bac6c958a2637fdd0fdf658e1e9d8959730b27
8e897222982490739efacabe818b3e8c6e071d68928c5fe35951cf3cf6b68e388bed5
57b8ec848eb49ef719deaf56273b24190d8485037b55471c1bb3a246d0030fda68aa8
0a79786fa060c0b56e7bc7d0000886e3d661be0afcaa0cf69519eb528a11af48a9c00
0f075806cae72c6f1c14f022f7091dcc285c043a001c7a91300aac71bfec828623eb7
090d6daf98a2073a5194c0f4a2ea670de39b0e671dfdac3127141c0ebb02d771f7ed8
195d017ef635711a941a89
KE3: 0b23e8b3d9aec014f7b408bb096887fd163ed983d35e24dd0674566418679aca
55ca0346271b01ee5e5ee080a643b239b7c89402d406c86a25a99920aed79168
export_key: f7c4b9ce1da6bad2cd801d0896fcb9e2336214833174b405371886866
0de96f0641ebb441334c1330a4fd9ed07864436b7468efb38409d60499764b7736bc2
ba
session_key: 660a911162675dddfe9d309bbf3169c7a4e52fc900a7eaf12cbd4001
1c93f1a3015e1323ee772a82ef32b5b67eb57ab3f894ddc655ebed71639f643190ebe
067
~~~

## OPAQUE-3DH Test Vector 15

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
Nm: 64
Nx: 64
Nok: 48
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: fc75fe0ccf7b66bead3c7df4578fdf22f1a5e412fdfb02240e98c23931
7e142e4555a81532c2c38bb2a359bff297e4eb371cb2c70e5d9f4baf6f4422a62c664
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 611ffe4346ea4da5e6211dff6595c9a7180e89790a92ed156605f
633ca69fc17
masking_nonce: edea8ae70db1b219cdfa2e7a2f19490cee9f1bbba684d05e8ac7a3
e5c54ff287
server_private_key: 8099b50c7ed9444176251781b6a8575de7491bec330164821
b9b2a108e3ef8964622075015ac9ea0f8380dcce04b4c71
server_public_key: 03aa179347ce8e27d2122b8c2c43315635e5489dfe1a50ab77
186e4710cc489638b097b3302b550da04f5d76adfa826688
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 2d069de96e1151da43e0148ef707ab89f8d9f771d4e43a88e1fe08c
aa45865cd
client_nonce: 222efa759f00e0ab036835e37ab6ad3563188bce0dcbc42f39e5958
9c8419d24
server_keyshare: 03ed7dcbc8318a00c1f42c2b75682d0beb532636c2e03c524bb5
bf5af735812003bdc0d076ca0dc9aa7ea97273c7088f78
client_keyshare: 038d4077ad0d00842d0d621527f8225c405f80049752378a4e11
1b3dcd52857d35f464202f22a17d717d5a3be3455a93f9
server_private_keyshare: 3311ce41098e662e559a0599ff077b4ebcbe7f73e9fc
1bc25fff3fc5fd6c8bc664e27822fdece106def4a69460e97774
client_private_keyshare: 47a314fbbe5035803d3aa65819e81997c4d89909e25c
e20d0bbbe0ad45a97be4680b39889979a8b4b432245062838a00
blind_registration: 2df429f90cf65d49d89d9289512729491e70dbcfef197f2df
475d05175e75fb25791f11a8f5484eb790492839c0c38ea
blind_login: 2d90c0799597e99c926ae54b2fce5ca13daa8cabbd4da53324fbd205
54f2c56460442edb7d6ee76b64ab68d0a8f5b1cb
oprf_key: c65f2080ce0134064252d414e5e13252a34f0e8b25da287edfc20175034
0ac3bbbdf5729aae5d6c788c38113d16c842d
~~~

### Intermediate Values

~~~
client_public_key: 03bad5466cf47b6ac4dc17d4ba64de8a1ac31d1c8a314b0509
c89e4e7738c93f2e12fae8aa7332f9f6c009576b29fa3959
auth_key: 2f3e95329ae7a2ff94f93d7442e54e522f2a4aa967d1ed9dfe0a2ede638
cfaf0a76d0e095b9d16a590f7ff16938d18bafec5ddaa769065e092f8cedad4356f5a
randomized_pwd: 7e379dbebbb4baca152835f5212dfb0d581fe4d4c45762c4c8503
1859123a6c1a0ed2349e991825167f7d51290d444f050c56c4e5b5c33ef9b64a479f6
6cc1fd
envelope: 611ffe4346ea4da5e6211dff6595c9a7180e89790a92ed156605f633ca6
9fc171c92b31b1184420dd2dfd9746c0778e0e290d944930a4348b0d496efd418dc3a
511955a202a9ec5195a49a0f43e480dbcac29ae734636aaa450d2921af5d3bd2
handshake_secret: a0f8d3b354c1911d782d0c8aa8bf154adf3dc513fb54767cb91
0f85c481c0ebacc67db9de9ce13c79a132ad24efc6bb4bd09b05edb6c364e9740756f
b260fb32
handshake_encrypt_key: 73210a2c777df797e2f76bcb0d8caab8387fbce88c6620
f6b8aa3d1e2e46a8eb4b30970421c3b74e92b7002a0ec2d21894378aef76fa7abbbab
1e84481c37b27
server_mac_key: a40f5da4b2e8b6c3ae0d0f388fbf75c9cd541f163c8f28a17b1e6
38abd3f7cb91bd46fe787e2cccd7b7811d7e3f6664fcddb7a5f58a43deaadb9d4bc02
a8d345
client_mac_key: 86675536bc72d43f1deb1b829ebae685e3f7caf576b93eeea84b2
8ce81a729ab4d67a875049ba18b7f80c4d67a91378309d887d214aa083111bcc10c25
be4f96
~~~

### Output Values

~~~
registration_request: 0399b76973449a299bd2ad6be1ca983c8a1eccc7e05a36c
a120a30a8807d96bd4b98d076ddbd99e36adfd30b0886fe42f9
registration_response: 03a899022ac8527f0c325fc8efdf2204d09c2f49992356
5c083fea154155350707b32f7e995d74ca71e6a3b7fdf85bfef003aa179347ce8e27d
2122b8c2c43315635e5489dfe1a50ab77186e4710cc489638b097b3302b550da04f5d
76adfa826688
registration_upload: 03bad5466cf47b6ac4dc17d4ba64de8a1ac31d1c8a314b05
09c89e4e7738c93f2e12fae8aa7332f9f6c009576b29fa39597531c4c89226673b215
0ebe2393123efaf27c211f74342ce066e1248256036f6aa69cbfaae7d2c2434a5453c
fc3566d5ca6aec0ee75d264a009894c05aa96c7d611ffe4346ea4da5e6211dff6595c
9a7180e89790a92ed156605f633ca69fc171c92b31b1184420dd2dfd9746c0778e0e2
90d944930a4348b0d496efd418dc3a511955a202a9ec5195a49a0f43e480dbcac29ae
734636aaa450d2921af5d3bd2
KE1: 03bb6ba53426efb2307df620440d09e1b503d3d2135dd0c845b59f135ab39bb3
00aad505641fdbc2725c31d221feb82d9a222efa759f00e0ab036835e37ab6ad35631
88bce0dcbc42f39e59589c8419d24000968656c6c6f20626f62038d4077ad0d00842d
0d621527f8225c405f80049752378a4e111b3dcd52857d35f464202f22a17d717d5a3
be3455a93f9
KE2: 020e9f886684004eddf958ee21389e9935e4d127e336e24fd1208f0d94944410
6db5a01f31dc322b67e6a640e8ace9206cedea8ae70db1b219cdfa2e7a2f19490cee9
f1bbba684d05e8ac7a3e5c54ff287a782199b1bce66b423d1920c4dd74be003ab175e
94766cbf0d5f909c9c39318b69b7d3def1d25091d4ac84906f5e6a52bf32158bd1f81
0b5ac56cea398d8b385dabfb51de1df1bc23116aa7824e2f17d8a1723abfdd468843e
3ef972d27db78fc56b79ba0c7b30ca5bbc3cf1feed3d160347b47d705145a2a0f61cb
e0ae3d12ab4b5327b8eacff5b9040daf3674a9e6e482d069de96e1151da43e0148ef7
07ab89f8d9f771d4e43a88e1fe08caa45865cd03ed7dcbc8318a00c1f42c2b75682d0
beb532636c2e03c524bb5bf5af735812003bdc0d076ca0dc9aa7ea97273c7088f7800
0f52a1e35aa6b9ce5b2af65860ab82a57aa94bf37ee0bd7ac7e97655d29fca42cf032
c975f84f2f4cee58cea51b0b0e3d92856894b5e8008efe058d31776d76411c1bae7fc
ec7ecbe924dc292e2fe009
KE3: a9a0310debd4c69755563868a7b88cf6558c787410beaac22ab8ef535ac2e3a6
10a51d1ba42a0f37b2c034d82cc2a84b7d5ad20e00504aecdd4a83ca91509141
export_key: df4875f440f3fc915fc1f6f66c167dfe368dfac89942b352db7bac0e6
e1029c96607d5b4ef9e391d24d6b2bd7da12cf16cf88b47de29c07bdf31fc14f2dcc4
0b
session_key: c53bef385e9015d2fe40cc4c02d1cce7133f9fb8cda3d399c8f7d252
1c0cad5067ce2a7785c0923dfcaa85eed8f1e6f63bdca67976697830a3d26204e4866
025
~~~

## OPAQUE-3DH Test Vector 16

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
Nm: 64
Nx: 64
Nok: 48
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 2bdfd31fa072994aa6978c8dde8c5841326dc8b4a732cc70fe08a86535
a8e2941feab21cd6ddf3fb88c7d76f00df95f2c0e47ff21bd70820cd0f66459d66f29
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 32d93989aeb49cae6efa3963bc9f55d727779dd2f72c0974acf04
333392a92d3
masking_nonce: 17cc538cdb5aa6e30dcc560737523284e78004ad5be2133e99c8cd
bb3010773d
server_private_key: c6c4dfa3a822d8f670e5aa46e733baaec9f93d5e14ad9ab99
dfcbcb2ad157a8aef1f3fec3f24bbc392c9755271e8792c
server_public_key: 028cde89b6908e81425fa8a597e3103021475346a146b1f1dd
ab47f09c76ed3b78a251cf390bdc086924bebd471063abec
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 3e21d9300486633273041ef5f2a160c1a73b98addc5482c6a96c108
f84d34d57
client_nonce: a3d77a82779471cf9b98f8b7dcb5212a1f2edc9ecf6f8e8946bec9d
68ba6bffb
server_keyshare: 030d570f50898367457561b3a5c707852633b4f9404cc45b4058
f52f5da1ebf67cb737bfe5c272bfeb65efe6bf7255116f
client_keyshare: 0246ba00038cfa5105659e8c250d10618a2c7f9d09d174663bc5
689e4778f7054534d9a4200a447510023af3ad3c61ece7
server_private_keyshare: 8075bbd3ebb3097a0f9bdfb7430fa3490ab6c2790e3a
d33faeef2365ebf9c1edbdb24825e5735614aaf644f03458a1f4
client_private_keyshare: 0c90229f8068bec0ae930eef110e98ea1cbc6d849b4c
9ca5b7a970d0320ba5f4f95f5cd4f501d71f00c654c50fddc636
blind_registration: a1bde3dbb840b3924c5ceba5bdb181a51679ed98960e4cee2
7f330d5d3dccebf40596dc7e8b057938841423f8b336f13
blind_login: 6f1aa3fb05702631e213b4bbbe8fe5176fff25526ed5b1772ba61649
52c3c2da8017fdf337f81f5cbd0ec805923a3360
oprf_key: 2f87ba23ed2b08e13fda5423b7fa525e4d51a7e3d334a4747409e6876fd
3e41960ef475d75108fbb9964c34bd8c81302
~~~

### Intermediate Values

~~~
client_public_key: 03520d07d74259e58087a91bb199dd2434393202c882f969a9
cf4a725265c0d75c3747fc1be62b018001c0b27577efc201
auth_key: 3fdc19a161ad6919b37ddb1653014cd96fd1deb98e277330727829d9045
7ff08f816e685af01399144ccbb26f54c007ced38fb19a0be1d22f6865cc1ec0fbbd2
randomized_pwd: 0c1222bf0d77b3b103f6b40f84a83f2d78afba7e401c5747ad41f
4c850a5b61202c0acabb684b1fa56dd77cf435f917c561446030b9b241e0b6831bf0d
e27909
envelope: 32d93989aeb49cae6efa3963bc9f55d727779dd2f72c0974acf04333392
a92d30b3cd05893b9312195f056aca4648f6728ea8f6a699107a02be0919ae296d0f8
5d2c504a3aff8827d4ae66cc686da46545ae18d8ddf70ca3967dce24c22a76f7
handshake_secret: d322173215751da05fa700355e019fb006fcfc91c55a07d1402
aa359b9da0a8033a20f65cfa583cb89f6d6887d1ace1600a3b1508535980e1d361bff
4f1ab4ec
handshake_encrypt_key: 2a3b4627aa6bac7cc689ed6ba935e8dbb94f950fef73de
8fc68865ba1fa828e47a1fa0f227fa4db8a4d88e41c6e02aa7ed0ee5a40c66d6ac331
a8288340f8ee1
server_mac_key: d51679240895a92d8c9043a376e0f6fb8342040bb19316ad4fba7
e1255c33f8cae47ae5afa6499170860d07934077890d1e1bc3bd221f5b8aeb86d3866
59d2a9
client_mac_key: 720ead3623c388df8ec008fe90b5a2c4487fb2945c87558d671eb
1b0a5b391b37825e3c7c577aab365631c377647833730bc1801d804be60eede6da818
942f10
~~~

### Output Values

~~~
registration_request: 03f8569ce50a023ad6518281322157e79e1207a96bb9214
95ccde8cf48eaf27895245a7b8f4b3b5c43ba54963a19cc488e
registration_response: 03eb9df563b7315fcd8894fc37bf1476e968100040df1f
51367923f19a683157fd5223e0953b9471c4bacf90204c1da47b028cde89b6908e814
25fa8a597e3103021475346a146b1f1ddab47f09c76ed3b78a251cf390bdc086924be
bd471063abec
registration_upload: 03520d07d74259e58087a91bb199dd2434393202c882f969
a9cf4a725265c0d75c3747fc1be62b018001c0b27577efc20106e6f8dfc764d4aa2b6
654de97281e7ce747e5c98edb159028d68be2af2df21fb4a66721d5d5492ca72052b6
baedce841446a783ff71c5ce47d35103e3e209c932d93989aeb49cae6efa3963bc9f5
5d727779dd2f72c0974acf04333392a92d30b3cd05893b9312195f056aca4648f6728
ea8f6a699107a02be0919ae296d0f85d2c504a3aff8827d4ae66cc686da46545ae18d
8ddf70ca3967dce24c22a76f7
KE1: 0255b2107d1a2192eb54c25c98bb7a95e581d7d23a38e1fceac9f8ce99f568a4
fad6c9bbc5abe4ff08f8b22e31bdfd6971a3d77a82779471cf9b98f8b7dcb5212a1f2
edc9ecf6f8e8946bec9d68ba6bffb000968656c6c6f20626f620246ba00038cfa5105
659e8c250d10618a2c7f9d09d174663bc5689e4778f7054534d9a4200a447510023af
3ad3c61ece7
KE2: 030e286b95d83b077e53625276ad321ad65f5228ed34a14b54f41e26449a4385
d3a1267cf0bdb2d4ac262b08c07d123ad717cc538cdb5aa6e30dcc560737523284e78
004ad5be2133e99c8cdbb3010773d0881c3a5b9974d7b2c9dc8de2c2c4771961ae920
1903da36d7a4194782b61b5cfbd43328172c32612e8f0679998d92231b88c381011a7
dcabbc46d8f0db34675091028b13c9fdc0dc3fd6d0ec34689c2d1692208668ae2c655
10112e0b4f5197ecbe0bab9efc748610f185d660a748cf09664b0ac1ca99270bad2a2
0ca2dbf8ba711350db0fe6c526459facc3452fb1f233e21d9300486633273041ef5f2
a160c1a73b98addc5482c6a96c108f84d34d57030d570f50898367457561b3a5c7078
52633b4f9404cc45b4058f52f5da1ebf67cb737bfe5c272bfeb65efe6bf7255116f00
0f509b8349bbd798853b4bd3411ed1510754ef45a3a98746b80b1b03c143d3f68c7e2
41ce16d8c8c361e97d4d4972fba0a5f77765440f896084775695ff96ed009d02e3b51
f8c5bafd0ccc97e8be12ac
KE3: 52bc1ef46ae8e519aa1b2f069c51513ca9413736612764b2234b0bce1ba368c4
ccd273b1140279c17f01c004f3c8f80dde7784b8a37f8b8ce3b0db89bb2aab03
export_key: 590ba54db51fcecd99b7736c972e54f0ef1c6e648837bd625552bc3ec
bdbb06b7a82f32357719db9ff93c8b972144b681aee6b8dd6b2bc8a1a3787142fcfae
2b
session_key: a3170d57e3dd49183ecfd8805b781bb64647abb5c68119da02bb1a1a
d0c05742caf908e70d317bd10fb336eb4809c12ee9fc5f7c903f05e6829ae41d6e7fe
af8
~~~

## OPAQUE-3DH Test Vector 17

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
Nm: 64
Nx: 64
Nok: 66
~~~

### Input Values

~~~
oprf_seed: a2f0732043d4e8dc0909314ba2681df5eeed5a0c30b599c257b88037fe
2c6f8ba1e038930e003c2563d265c49c56d4d82a155d6b81e82cc46210869a68fa4d8
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 8576a0c7c81f7a7575dbbabe910d8abd35258409dd4fedb8dacbe
0fbe1f99d8c
masking_nonce: b9d3084eeafa7d20d841bdc80289111ec8aab7b1bdaa8f670051b1
04db229e88
server_private_key: 00648b7498e2122a7a6033b6261a1696a772404fce4089c8f
e443c9749d5cc3851c9b2766e9d2dc8026da0b90d9398e669221297e75bfdea0b8c6b
f74fcb24894335
server_public_key: 0200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 30af4fa64192a5338aeeeb43345b014348afd6f4cb7e2a103057dfb
ac8cfb834
client_nonce: 1e3b093abca6b82059f2e0ba5ffafd8b54ebc7215eea7a556461d65
0a3c41199
server_keyshare: 02016c63c8e2b3feac6366e3dcf752a8c2a287c1fb4d648aedba
86aa0ee07d2b1133d3282584d7c66357bfcab76526f184f7ff9af506f9eec01645b99
b6918bdda600c
client_keyshare: 030187b0369b07402c41744c664239d0f9fad568f0ea5c13e4e4
d80c770fda054cca7fdebd3f91a803a3efe7353969e388623c224a86cc32575ef8cd5
e0cdc3c467343
server_private_keyshare: 00746f74e77a62905a6d3e4b0b10600a7cbb4293a187
ad3fc8c91caec3bd7699591b10d6da93877a470e128f38030627dffcbbf1f576b3867
7841fc47af778f9d85b
client_private_keyshare: 01939388ddf4607e295e64cea6f4f95078b7e30ca85c
4154cee4afed8403406502ed2f79ae56e032dcd5436254daeb0620f584755b22ff954
eb79ac24c8778dcf34f
blind_registration: 01c14aba77e5e37d5ab1389e09b80a34cfa96e2d294e9f04f
b076cffe7d179d692a05b0c2210b6c008c1062c1e54514ef654eefc0519dd1867571c
9d518e305fdf47
blind_login: 01448da2c02dab317d5175d73a1ff9d62286602e87d57a53a1c70f44
466b3861be4f8ef48c2bb1aec2e478e341c467fd4a2638aeca63ed6c4bc48d008bca3
f36f044
oprf_key: 01fcaac74a26d002c492c586fc16dcc83f0bb8dee9b991ab8adf9da3b9d
0551e28f64f2d39e244ae8da38949f0bd3b8828e0bf824c1101394bee7bc83a732837
acef
~~~

### Intermediate Values

~~~
client_public_key: 02015d849771c3ae0ea3af9f2462c822b605be212e05e83c3f
7d6e65551945636147da2b14e09c596ca154526b09ca9ce7b51b63185e016cf2aecc8
6d3800359151daf
auth_key: 5fe6261467d324fe32b627478eca4b266a30d67d8b982e10c311c928ab8
c394ef17958502bbb650cd39035b18b393df1efd6037f98216caf96db3860dbb739b8
randomized_pwd: c1ebdbd0b7737dc8f747261671d106ed8a9ba8751198741e34147
91ddc11abe2900f8d3630454162e169228155670aca7960069900e9bf6fcca43a028a
5f9eb2
envelope: 8576a0c7c81f7a7575dbbabe910d8abd35258409dd4fedb8dacbe0fbe1f
99d8c089d602d3349adc7ef4fdf1ce7654d946ae6bf23f0a53a72e7836c07de92af79
e9e6aa5353a0f10b3f8314a88aaaa98695396dc5bd045a68d7647adf50dc2c77
handshake_secret: ac52ad048c93b646ed484dd29ddc35530ce69327a928a4ba134
11b9f222ca132443bd9174160ff72c65fe2555b507672510109ad718ef9d207468a34
534181a1
handshake_encrypt_key: 003b51400c880b90baa64a92347eb97f645f4e5f8fe986
fcb9e7f7810bec3d9be597f5467a388eb9df415b56272a36a59c67cf84cf16627c701
a0c1e5bdc2b2c
server_mac_key: 998ba809cc34d7934f25c8f3c4b16917918577045b6ef805d76ea
bb5d06d451c03185c5b0ee50d537310ffea3748d9c0eb18efdd119b6a56849dea5733
457ca0
client_mac_key: 559874ed898f25cb67b94c84b1355c5e5fbe58b903a3c9f1b3a22
22aa4a2dd92951be7848ea64cf8e94e4ce4d2e43f44f7fb5b96c3f0110a10c6f88ed2
37d172
~~~

### Output Values

~~~
registration_request: 03019f508a03d6d883f28a0afa477eac4dfad2ae9052a82
ef5736b24eab85dfc40309c5d205bb94b9a6697ac7b97b9b63e057f163905ec396db8
fe250544bd94e90c13
registration_response: 02004e15d16f075d2de7e2ee6e203d5f4b4f2c176a1592
2d47bd5f8d2a7e94515ff328ea4f74331a293e1252d8ab4c04a778eed1234f6596baf
84afaf2b9fd43eb953a0200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
registration_upload: 02015d849771c3ae0ea3af9f2462c822b605be212e05e83c
3f7d6e65551945636147da2b14e09c596ca154526b09ca9ce7b51b63185e016cf2aec
c86d3800359151daf832629d42f82e752f1a8b4014218402b034e6e26c239c33329eb
0258a42721688d990208a793a05f1d99e4f2116f11e06fb1af650ecf057f8cfaa5d68
9b1a8ec8576a0c7c81f7a7575dbbabe910d8abd35258409dd4fedb8dacbe0fbe1f99d
8c089d602d3349adc7ef4fdf1ce7654d946ae6bf23f0a53a72e7836c07de92af79e9e
6aa5353a0f10b3f8314a88aaaa98695396dc5bd045a68d7647adf50dc2c77
KE1: 0200001c8b7065b1f65b9e87150b85b32e6a13738dfcfe40a947a3868b0504a9
c0b8f2d2f8261af3c4507f583ac24caee8981b3c2e7c6a81192d383aec9fb93e64203
51e3b093abca6b82059f2e0ba5ffafd8b54ebc7215eea7a556461d650a3c411990009
68656c6c6f20626f62030187b0369b07402c41744c664239d0f9fad568f0ea5c13e4e
4d80c770fda054cca7fdebd3f91a803a3efe7353969e388623c224a86cc32575ef8cd
5e0cdc3c467343
KE2: 030035f08ea3de22b0376ff3721ba6d46701a9b5e5687d1ceb47e9f533d7f8a1
f60904eaf5125803327480d25a7107e9d895258b38c2462d102a8fdd56cb323854ca6
8b9d3084eeafa7d20d841bdc80289111ec8aab7b1bdaa8f670051b104db229e884e02
0fd59f017168a8c4ef61aef2b7510cc38b11ae0cf323d13ea9953f0340f9200206d0f
27fc6e7c1346dfeac1059b1bbed15d472783259fb867acd0ea79b58bc09f04ab5275f
6a476ed42a9205422848cc46dbf6962dc0ad425bc00739d542c540807023946ad4fad
a727dd19813d1bfe7c9f30e97530827c1ef18c0057e062744e9263362f3649371bd1a
548382cc0a6afb69009021eda3a9254acb3bf680153c7730af4fa64192a5338aeeeb4
3345b014348afd6f4cb7e2a103057dfbac8cfb83402016c63c8e2b3feac6366e3dcf7
52a8c2a287c1fb4d648aedba86aa0ee07d2b1133d3282584d7c66357bfcab76526f18
4f7ff9af506f9eec01645b99b6918bdda600c000f8daa20d5162eea9d681b87661762
cd4f9ec59a54bcd56c8b3438642bed1c23b6c1fd39f267f9b905ecb2cab7a48cc1d5e
64d909c589cb7fca0c8cd5298deb4577dfed8797209246caaa3443ffabec9
KE3: e578e0b651f5124e89664cfdf7343c40c9bcc055705b9101c39ff2d4426242a7
3b30dadbb8684aa58d5c37c89afc1cdb81444e270c4f23b2dc60e48002751d9c
export_key: fc013ef1b0425bee62b845c76823a5a38c361d0f9147266d2e58a6570
c8e27b13faee7bf59920ab94fc5d53d358d935b3f67be6e239a322792a18f4046de82
08
session_key: 444b5612450eca7cd77a214b6d0690ce8188f70468e4c28f3fca8e94
ccfa31e9ba3fedb9db0547185bdcdf95dd930d1edb08bfe632a8bce831372f8c4b52d
b35
~~~

## OPAQUE-3DH Test Vector 18

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
Nm: 64
Nx: 64
Nok: 66
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: cbf99f721bb05bbb38c3dff97984ba8cde188b3827bbd814cd7a42af6e
65a3b12067920609dc601239a238e23f40d75e1aaa3a509edf8c7cd2baa7f5c1f95e9
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 71dc777337eef4e8ac3cac80a4180f926f029f2cb820b1a176b95
a945a44d784
masking_nonce: 73180d73a4c972db77ce27294dee5a2f9ab174d5409ada18b37fc8
a7f051ff9e
server_private_key: 01e58f3492c6da02dd7387bd1dc40065b23155fcc16e56ed3
586c3c2d80245859235d872c5266668cd562a2bd7f34654235b1b9961485ae246256d
f3935910d36507
server_public_key: 03000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 982aad1d4df60e1ec7598ad90ee10d986d8ddd8986c4ef3b009b535
6a21f4375
client_nonce: 11034c017067f1258bc7720a174b559d38c2864d089c0cadca46134
598ce4ded
server_keyshare: 03015da5c9a33d3168383837d8d2ae4d00f39a8a631cd126b4dc
1b01f06c32ac86ce29440df0e45650879f65ad94a3d752f265254f7d5861046cc0165
67f9e36b873d0
client_keyshare: 0301bcdfcaabb52a829a450fdeb63bf90b8c98c6b2717164f48e
27d4c737058feb556f81fe39aed7846313ff6a6fb9c4bf1d81083974f2babdb080048
cc67e12f8ce2e
server_private_keyshare: 012dd5f057d34f77f82886ba9c12bf99b4c79e232e68
82168463a7d53d03090c1da44b4cb34efcf9e45a0e4f9ee14e00bab7a7ca19b6616b9
ea190d4a2db57bc6590
client_private_keyshare: 01b52f1d5c1c022ce72f0b4dc3405e239f2f85026764
82559ee5e4ba79c390c4033405e3f792bc49daa905c694707e7e0191104b34d68c7cc
81c2e392da60b838eae
blind_registration: 01ec57a21c1fc56bf3514635ac7fb8618f72cebff14ed87eb
abccec2627d4006b698d9ba57f6e207c989448d39fe0431e60c9a9a4110596d5a16fa
6cdf3f66467525
blind_login: 01e8d9b4f7c7beb31e37008156656c19382a56cc79b9aeeed48a6f9a
8fb57640c3bff88d3ab3cc52ef969f02beaba2c6e32c2f37baaf4ee9c691833dc081e
2a0fb70
oprf_key: 010c6e84907f48ee9ef1a2b06b0f62032fc716c2e6c253928e5d4f02d58
a15c7afe0ac4f35762ee53f04aa6477700f68832492781160eb1c6968c4ff7ff01aae
752a
~~~

### Intermediate Values

~~~
client_public_key: 02014e85db957b2e39c82d7ff67fd42f2f4689a1e999cadbf7
8606279d1ac5f593efb9e8ed8d4b5bb7fe80e3b5324a8cebcddc26319d7cbe05796dc
4a0e7b9d13ff933
auth_key: 3b430d33aa3d6b97fec63500eeec4f57a3783dce1a6e2bbafbcbfc60561
520ff806ad075983ba2b36263028683a5c5d4f5ec667ed8473db0d4cec1c389da097f
randomized_pwd: a668c0639403d64a159f5657184c80027dd0738ce65b612b2398c
1e5f6390ae76a352763020e3f0189cebe0df03702c7835416598eb8b2df2d2eae2120
aef217
envelope: 71dc777337eef4e8ac3cac80a4180f926f029f2cb820b1a176b95a945a4
4d7846e31ef250b103d54bfcfb85b7a61587f8b3eada628c18ede52c1003d22a17cb9
ddc1ffb448e9adaf0bbcbab7c19302465dd2f1abd5b60e4938adbea4a13aa25c
handshake_secret: fe9cf741d612210e48960231217e76d09312390c69529b781e0
2b7054d1114866f10adb3f1cfa3dfbdc25a8b4c737b0207d45479b2d635316ebf251d
f33b324c
handshake_encrypt_key: 926c324f94e5840c6356b5b298fc788081135bff19b27e
1ea75bf788ef1970d43a8c1d9a82917ae534a54aac91645eb383339512d1f3ac77587
983e6190476ac
server_mac_key: e18734ad27c3f60c703600c29ad2d8242e9caf0f90f55e10aef7d
a53e4a8ab5be905e31c15349e8b2dc40270af02957e4625bc8c01dbd7f1bfe60832df
9e6d28
client_mac_key: 1d3b2348afb25f8ec33fd07b992eeac8fa434a9dd5f7b091887a0
005cd46656ea9768551e5906c91a2122507e37421a11382c3f6fdee74dbe0d11492eb
6d8b8f
~~~

### Output Values

~~~
registration_request: 0200bce08f110a6634cd66b75c0721208df3d8c392f86f2
feb9c20fb62c9a30df00b37caba143386c7880a96301814e425ba9df870cfbf19724e
b58411604b3a618f29
registration_response: 03004f08faa49284110ada3a43007ed1f3d7766748509a
5bb2d6317c14320a406eec518882ee4ea2863d1631c3b06b83f9d81ec1620759537ca
7f4170bc13a453bf50903000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
registration_upload: 02014e85db957b2e39c82d7ff67fd42f2f4689a1e999cadb
f78606279d1ac5f593efb9e8ed8d4b5bb7fe80e3b5324a8cebcddc26319d7cbe05796
dc4a0e7b9d13ff93389cdbf2bb199008e95e5ba25a49fdbadf09cf8ae13356bccf65e
85f689f73ba6bc37ee4375ff52e9dcdc73d14779468063e85981f41be04c8cdfbcec2
4040ef971dc777337eef4e8ac3cac80a4180f926f029f2cb820b1a176b95a945a44d7
846e31ef250b103d54bfcfb85b7a61587f8b3eada628c18ede52c1003d22a17cb9ddc
1ffb448e9adaf0bbcbab7c19302465dd2f1abd5b60e4938adbea4a13aa25c
KE1: 0201e2974af3a0c9a479cf1589e9c7db8f3e04723123436453ec427f75974423
4a57a91a724879c5cfe93ed919501d567a6fad6ff5763647c351ad6dd925f39cdb04d
d11034c017067f1258bc7720a174b559d38c2864d089c0cadca46134598ce4ded0009
68656c6c6f20626f620301bcdfcaabb52a829a450fdeb63bf90b8c98c6b2717164f48
e27d4c737058feb556f81fe39aed7846313ff6a6fb9c4bf1d81083974f2babdb08004
8cc67e12f8ce2e
KE2: 0301c05496686104a7b82a151351b988f5ed4295ae73b0f8e47a32099806cdb7
9709b862abed66719debce0cf92fad9da0cbd045ce097fc5e27f947380dc513f5277d
273180d73a4c972db77ce27294dee5a2f9ab174d5409ada18b37fc8a7f051ff9ece11
3424e9770c02c879e86c1c243ed9aa1e3345b2e6a85e4ac5b886839cb9297853f364a
a9c5bcc43f74f66665312dc74e7678366a34ca81aaf1030cc5f7b9b59ab1ecc9bc5a6
5e8f811fbcdf2796503f3838b7f788db8e11197d053e61a99010e8c495c3f14e4e4ed
9a153edc659dcff3c79946dc9371d4ea0cb88ed660785d3bd3fcb5477960dc3e12450
c6ce106afe8776cbfce9a09b5b4dc53257d16cf27f0f93982aad1d4df60e1ec7598ad
90ee10d986d8ddd8986c4ef3b009b5356a21f437503015da5c9a33d3168383837d8d2
ae4d00f39a8a631cd126b4dc1b01f06c32ac86ce29440df0e45650879f65ad94a3d75
2f265254f7d5861046cc016567f9e36b873d0000fff16bf58565186eacb93d146efac
63c093a7ab3b1f889f07ac032d6bcc0a284f9c52f980b98f9eff2f95631a109c0d145
dcd083c0422104cc927de843096461705556ff43d100664be619a495657c5
KE3: 74edc4d75d6bf38331d73e3de41b83c1a89fedf90a5f9c4e47dbfc604945909d
1979805a6fe2d38e2b533f47891c36004bdd591d5086dff115f0f980f50bd68e
export_key: 1289e218d166d73784be0e138cb47769577dc9b923d6a6171e0bff476
74215b7493eac47496e2cacc8a1a6cc307591cf6f90717105e54f6e86d9cc67ca8f0f
1e
session_key: a7835cc873095ac6909749c62293ed99c6014bf79a60f316e789e0d0
e30d3a7a53ee90a0037b9c00c9e30db3c25ca61eaabf7db18a0695068ff3a31e4bd07
83b
~~~

## OPAQUE-3DH Test Vector 19

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
Nm: 64
Nx: 64
Nok: 66
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: b090a604a7d3281747950c012686f1be5ee87b8486e729e69c50ead57a
9d5b6ae3ec6ee58cd097ff5e3c30a2f99e304a3f7597fef8738a29714a9fc07c7189e
e
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a814e5fe5234bc21018efd4f7e4c04313fd9e0b620d8c88de9538
2520e5c9861
masking_nonce: 258e8c4868e5d2db2aa035494fa4ac772de24d8c01c01e53bf888d
a6074fa211
server_private_key: 00deb3fb5eef3871cfaef0953ac3482c88f2bb4849b6ac355
3c3609aa005b2cb37316964371a39548566c5e4e4dfbfbe5faca38a62651e9a519143
d04ac366bd3097
server_public_key: 0200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: d1ce234ade6c2215d7b13028d26549da6057d3f693defb346eb32e1
524617da0
client_nonce: db7b40b96e0627332f446bb00d6ab8dae8aabfc0e9efc44aa07de3c
bd5a1bec9
server_keyshare: 0300f8b6a63f05a1a6f6e3c856d512860d5700cb3ad37bc1dbf4
ecfc4c77c3aab7bb6576f70be7b460143e577d02409524ef5fd5e82a85fec43cc2d66
adc312fb27a1c
client_keyshare: 02018f831d92dd0355becccd11cc3904ddae5edc18d6e357ae43
a7dc3459335316f842771994b3b411da7ad3c8911c806b322a9fad184e8b5586926be
76313b87f3d9d
server_private_keyshare: 015f117db2282bb2d11b833ca36711f28643a2fb2afe
4c3ac0692c402f2878e409eb94d01340491d9b1845c2c7c6c3512c359de4a62f9d890
1797659b3e5d47f317d
client_private_keyshare: 00e3562e44a2df91376353e89693d62c238e11ce26bf
e7eebd8e88410aad6046327ef267fd05717803c45c647f4a003b4ff428c9a21288025
cee0279eaec16e0fb7c
blind_registration: 00d7057ba6488a9f8f33b362f9ea293381eb5aa20a58124e6
db14076aa4f7aae03e79e1345b87735b977981b0b53d33a2545b6f301e66a98d04212
7462fc69c7e5d9
blind_login: 0029bd129200e0656181aba1c2e7d839ec26e9579970c1d4ba1db609
28b9ac043a5b622404c46dbe17dd4304b9566fc77d5c202e5ed9689829d4d0a746d77
66ca057
oprf_key: 0012bf9958039dbbd0037e3c565a4e3f91a018e6132e1941b9a5b023d6b
38b68912e01ff86a6c62c85ea91f303c4a23f63744569768a22d2086712f9f764587a
53fe
~~~

### Intermediate Values

~~~
client_public_key: 0201797183ce928876fcf43b6d249e0e12aca4e99eefc4aec5
6cfdf1467a1d93e49ae362964c0ad76aa50f71f4fb7ba9cf353a8906e0dca73e66d54
c793c6d9bd1ecdb
auth_key: fe067f7dc8bb1099dae60a5491359209a2453c7d03d7526700f2f4bf72e
965ead28a6e3bce76a5fca6e5351b17a54e6c930130d275446a214032fae8e82b114d
randomized_pwd: 1f041980cd3e486eea2564bc313c3be962d176805443abed26165
9f3e0a123bb7fd7f78625da9738b8a29409e506e3e7087183edcde88126a19771b2cf
c474a3
envelope: a814e5fe5234bc21018efd4f7e4c04313fd9e0b620d8c88de95382520e5
c98617550e08881bb945bd9354eafbb54906e6aead43ac002fabd7b89edee010c5491
6ba4e740808728d79bbd9b94c5864d21de0d3a654a7762e81b11266c7833c722
handshake_secret: 9db3e37f927129b5a5eb507d78f9bb93308aca1027a6dd00ac7
f0fed446161b472274badf054298401e917170d3452c9abc0d14b6bfc5b48353e964e
ce3b807d
handshake_encrypt_key: c6abdfc9be8bc8a059731e655700f3c732e6bd886d42b6
bb334277eef4e11b75585aa5b9abb5d93e24d15aef4783e077210580b66266eeb018e
17c9c0687cd88
server_mac_key: 7e924ee23fc473733159d1eb3977c286df21b1f6c775281c660e9
50b6891aa0b8fa682eccdda1613ba3fe4b69da5f46a1444d029ac63efd656fccd9cdd
1c8dd0
client_mac_key: 8d5ed81e71bf7748bbb97bda3ead9617e637a7d3379d055289234
9e1f7715da9501fca1cf79b8976b7d261faea1c081233ff5cfaca74ca0802469171eb
cec53e
~~~

### Output Values

~~~
registration_request: 0301fca4ee81d22c8e8cab4cd5e1724bae3cede81109f61
7910beaee9771549cf0090692d4342f0045a99a0707e09e38838e611a3f19c81bba90
12ad6c67ba55f40b1a
registration_response: 020017dc64d3918b41dc2c9c8e07a4608cf1a619036e9a
6d389ecb73f859f20fbbde3fdb70fbd799c58adb2f73a81a6d020930aa6ab04390c2e
2214fd151b7b97ab9ad0200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
registration_upload: 0201797183ce928876fcf43b6d249e0e12aca4e99eefc4ae
c56cfdf1467a1d93e49ae362964c0ad76aa50f71f4fb7ba9cf353a8906e0dca73e66d
54c793c6d9bd1ecdb7c8c1f1e587b532c918e27d9816554da9772e57ccd3a3f3bc2db
335be1bd687bfa050f53267d6bc780b0c61a4ee5190d426bdcf0176b4ba3c7eb064b8
46f4563a814e5fe5234bc21018efd4f7e4c04313fd9e0b620d8c88de95382520e5c98
617550e08881bb945bd9354eafbb54906e6aead43ac002fabd7b89edee010c54916ba
4e740808728d79bbd9b94c5864d21de0d3a654a7762e81b11266c7833c722
KE1: 020197ca02b425dfcae9aafd4608362a1dedd8998e6cf906191b4d888db30de6
dbbd22fb3a1bf310cc09f781d9c6fa0bf1f1e9a79c09eaf0df596801cb9a1030f9d2c
fdb7b40b96e0627332f446bb00d6ab8dae8aabfc0e9efc44aa07de3cbd5a1bec90009
68656c6c6f20626f6202018f831d92dd0355becccd11cc3904ddae5edc18d6e357ae4
3a7dc3459335316f842771994b3b411da7ad3c8911c806b322a9fad184e8b5586926b
e76313b87f3d9d
KE2: 0200b6d24d300bcd70adacb93da7b564d129d1e61a5435efe37af3bf03494ea3
55113e3ea3d73650d53cb869bb523f7b229792cc17a106229c76679bb833cfd32ccec
b258e8c4868e5d2db2aa035494fa4ac772de24d8c01c01e53bf888da6074fa211ee36
345d93da3ee2a6126d7ec76d3e810bf43d20c37b269c5ac7fc070c5eb16260ea98f56
27b6af42483a20f9fc898dc90efbf5b2efd558077c592621516e26f337303485ffbc8
cece4aaf04449d977b89dd6b8b7d24d1acf7079b5194ef4c7547c704112425fe1a6e7
23ef87d83f816f1f2cfbbf8757fe8bebfeb0f9f3509b2a99fb428ff1fb5ad260a5010
c99e703c3d723a3523768dbc8ede6140c5af6c2202fa3ed1ce234ade6c2215d7b1302
8d26549da6057d3f693defb346eb32e1524617da00300f8b6a63f05a1a6f6e3c856d5
12860d5700cb3ad37bc1dbf4ecfc4c77c3aab7bb6576f70be7b460143e577d0240952
4ef5fd5e82a85fec43cc2d66adc312fb27a1c000f053f575e011f389f77025472cb98
f154d99d1fafa6865cffc96b84d512133d02e67c0f9dcb6ee2d392ae8bffad4085e3c
215e732f7d4f8eb45a4ca9eeca722d53a48e0ca821dc817e326f6ad06137a
KE3: 2106053b5b0fb08ea0b5a075a8a6b7060605a5749b0fa6ad04987870a2344ffd
42394f6a4825bd194f8ff6004eb32bc5add5a4c9f9cab726407172ebb9090bb3
export_key: 83805ffecd205e9669763235d7772070834ce6527210d4a76ca6f6c1d
ea714cd08f53f25cd718b67542ca1ef0a8ed4c5565fd911d67b9d773b585ba3f447b1
74
session_key: 3fb67694db6985a49624a205ededeadefa45bfa1e0fb643eafcf641a
ed1ce3c13d2a73a42aab02daae5ecd7cd45995d613bb3e1a2808c03831002ecc142cb
520
~~~

## OPAQUE-3DH Test Vector 20

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 01
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
Nm: 64
Nx: 64
Nok: 66
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: a2c0c702a75378f6771ed1087cb27dd9f0869df8fa1ce77e253f226568
89bcead33b86d6c18261116288d4473eefce9bf39bed15fdb12e534aa4d2dbe10fb85
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: dea8622b286f46198d18d6d98fed732d86bd910b3e2fc59f5ca02
4ae99be3c70
masking_nonce: 7ee13d13ee90a7b858d8b5656de79de860eb333bf12a568c32ae4c
dea4333dc1
server_private_key: 012bc7471bdb9fa3e113b809a86dcc379b782052bce3fc9f9
62d373217b0c266b1e0932c7a0727030de9ce81d360d97fa94f7ca377aa6969e1748c
9f8b0a3f230c50
server_public_key: 0200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 54e5ebe024150039f4ad50d12b5e966ac60420eac4177642d482938
f9100f0fe
client_nonce: 104152a7d95e6b9fe3c397ba45cf5079086abc6d9ed12fd12b79019
9d10e0d4b
server_keyshare: 030121f7821162fbe027849ad750dab6227d5633a7148e1b0910
7d200d7fe63219f09a4e96ba8cb734b5b20941196edb471863e1785c22e950e3ee34c
85aecc454fafb
client_keyshare: 0301125c341b183c9ed98ad735039a5aeb7a9c99c6a90eb2dbd5
a02ffa442393c1de1a7f11ef5a7395a3881525c7fb8674d74d842f0cbece5069f98e2
528ec903ba7e4
server_private_keyshare: 00ec758fbb7a807a0b725c417256e9bad495f760d4bf
6aea0b7d2a2fe0f1660e30464e5955387c712d35d62960b00d071f63e3560802ba48d
4da12e2cd081925d11e
client_private_keyshare: 0007c0fe9f79f95d3324731ad78ad2d84b9d2ca47765
5b1a09af067a58b841237e3264ebc5f2375483e3a71937f93e63620bd2c12c9b86f54
5fa4ce86844ad1e41d2
blind_registration: 0154817095006ebb66fdf789c9d0321035076dbcee1fa1a41
ea6de59cdace06668d5a3932570c74fb7a9fb779e38ccdb9b80f53bd3009d7e86289c
d1b792e0abe00c
blind_login: 016520486cf32cccea61ffe9fa97730d95ecfe264267499aba78d966
19996d938cbf6dd303a0093c7b426b1c63f7d78884489fbcee764bcd720068da3134a
af107a3
oprf_key: 0100703932da18a28a76013efe6fcf9c388c2c680a0df18f187b31a13fd
32c2d1c1a4131b2b85fad42e87208f5b930740dc534a81face4573e9a9edf05d235a1
26a2
~~~

### Intermediate Values

~~~
client_public_key: 0300eee979cc9628959506bb943bce5fc1901b8f1b2c0259f6
0a7e5f5d01af5a43706ca3f799290b4ce1abd23a32c7260b0f75606f3add4e768c611
3a570cb7ad0db30
auth_key: 4597f5622807e5c3b2fd6a9ad5dc487eb9d240af3f025083760352b263b
061161ea10dad253455dc75c4bbc8ab5e6bec06d205ebcedb841175f9b7552a4980df
randomized_pwd: 198335ac6be7ab8ac7ba3a5160bbac64c69f4e348fc14190d58d6
2ebe002b325d5c33f92bc03953a711d59c200de2b6b43a22562a3be6422f8dc2da891
956f17
envelope: dea8622b286f46198d18d6d98fed732d86bd910b3e2fc59f5ca024ae99b
e3c7093bdc73cbca4195fbf98d0b2f773ae1b8cb885c9c61a28cd87c1c8b128b22f35
241aa767c9b73508ebcdf18e3a03c4de549911b973651590454e3c1e22e01d95
handshake_secret: 79f29aef1ae37d0d217f78cc19a2a2aab0b70242bef27069cb0
6353df37148ba54f469dd345f3f154be0c4ddeca3ea3edf619e0e2b213cbecc24e252
1afbd13d
handshake_encrypt_key: 532c242245e697d23a9759fd26546ee70803d9991a72f0
2e3c343d66d956964bbc8149da1d8a3c9e0ef279a0af8d20bed0c9c72ec3767bdc853
b4f0e21eb6711
server_mac_key: 868fad12525bfc183c4b3065a5cd9f99ab477821406cfc6eadbab
e7990fd7a7bc5da8227a9f7d95fa9d59f931f09dcb2d3298a50942d863f305d017343
89bf28
client_mac_key: 645e4e9726ddb31d819d9655fc67e55347f57ea51ad4db4ee11af
c5bb6b69b1ffc48b50fb30f495a345088a317973f9236eb580e7b4dbb49512d64cd0b
51d529
~~~

### Output Values

~~~
registration_request: 020178d37274cd1fa2512ca1d238613727201561218673a
d3fb6a391cf6dbe028dd8d953f0e36516eec3c69ab0293b19769074c4b16ca36d06ca
2765543e694fd8a2f5
registration_response: 0300571f1324c87ef36cfc5be06f0dbfccc3c6d324d4bd
2142df09e840f703bccb12308c9a761ec230f6a2510d31c86d61c0493523cd053559b
6f85bbfc9f95b06f1b10200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
registration_upload: 0300eee979cc9628959506bb943bce5fc1901b8f1b2c0259
f60a7e5f5d01af5a43706ca3f799290b4ce1abd23a32c7260b0f75606f3add4e768c6
113a570cb7ad0db304d11e0950c55aa0894620fde4ca4200ad3259ec633e862327ad8
4452ff996950c96ccb00ab9d5960f9f97cc208dfb3c43cfeb5b1ad2b245e9710db845
74fcfdddea8622b286f46198d18d6d98fed732d86bd910b3e2fc59f5ca024ae99be3c
7093bdc73cbca4195fbf98d0b2f773ae1b8cb885c9c61a28cd87c1c8b128b22f35241
aa767c9b73508ebcdf18e3a03c4de549911b973651590454e3c1e22e01d95
KE1: 030041daee06de56612bc011e3fc1b5b1c5eb334b6cc0cd587b5c6fd9f94271f
dade91de48e730d2499eefc313038c54e3ff0326da0afd4f5defd0e4f88eb9fe6dde4
f104152a7d95e6b9fe3c397ba45cf5079086abc6d9ed12fd12b790199d10e0d4b0009
68656c6c6f20626f620301125c341b183c9ed98ad735039a5aeb7a9c99c6a90eb2dbd
5a02ffa442393c1de1a7f11ef5a7395a3881525c7fb8674d74d842f0cbece5069f98e
2528ec903ba7e4
KE2: 0300f01dd603426fa47f34041bc81fc2c74aad672fb6229b5fbe1ca3ae5d6f03
2ecc470fc55ef79944e5b7de9eac051a37692174c809a5801cc2707492e962226ff04
57ee13d13ee90a7b858d8b5656de79de860eb333bf12a568c32ae4cdea4333dc1b43a
3d351df1a5df73d47603a78174f6aa19a52b054c4d3a3fa1a267eaa7b6320418c241c
084ea1aa5296fbfc238b1d38a602f82f44acf4a0e3cbd9c5976ee3734ddc0b4da5692
604145332dcdad50f8690d70007422e6b31a177ed2258d2e61f0846719ad1bd34e649
4b2db478b1b2920e3c22ec9884e99b990c7cf3fa62003eb013956745518e690659006
b7e028d98e6412db0974741738adf0a07d676bf90dd10254e5ebe024150039f4ad50d
12b5e966ac60420eac4177642d482938f9100f0fe030121f7821162fbe027849ad750
dab6227d5633a7148e1b09107d200d7fe63219f09a4e96ba8cb734b5b20941196edb4
71863e1785c22e950e3ee34c85aecc454fafb000f2288bed259d4c04f46bd66125ed6
a2df8d051d6e3c1c325a1fb9da4db176043e949bc6cc5fbbcc0eebfc712555cdca285
8cf492fab1d17745078b53bfd412f4944bf68535b8b499d29f334b9a2d92f
KE3: 913e4e963b9d6adecbc64b5d997963042f647e4f2169fa099532eaa7d2b701b6
f13333498a95078084dc28d21985fba00cb44a72ad67f0a4f8ade46e2c328bae
export_key: 90945205c08c63899a16b2e9932c9d56992ea97e463093251823d21ec
286ae60913e18d6cee485af823f252a405bf3cff0da58fffeb60f01c9ee56d337deb3
12
session_key: a1376439646b9b273e8780891406c692a930fe660540a40235ff6991
01339e8fe530072ca7e23bfb98d48de57fa0b08bc826afd60622c94d794348115f697
839
~~~

## OPAQUE-3DH Test Vector 21

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
oprf_seed: 953eb80562c4a252c8896399588db86af14f9587d082ec2f3e06d4621a
8c940984cd0ab83a2d396404e181076a005dc929d1fc18066a3b1a62226228d2fd47a
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 22efea550c5ce8ee58c2b5c0d8a62c247fefb259bacc92efa68c7
2374da302df
masking_nonce: 479e8543c72cffa59bdb524bd242c3440a32781caa3bd834e0dce4
d2df34debf
client_private_key: 2d8cc16606d110ecf2ba00464406a0975452b63a3f27ce575
921f91146543b0a
server_private_key: 5a673fae0015e31ccb70006aa21ae18853489bcfd11c0b796
0a3b37fc3654402
server_public_key: 0c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd
9d2f936a37f14e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 7476222fa83425d3b2259e3c44a665751dc2aa54e381a8a210505ce
56cf137a2
client_nonce: 062762c1650bc61c27c22782c1b09ac2018928721bd9de0765c776e
09f8e62dd
server_keyshare: 34be8693c06fc0168040b3321043f40ad79648211e6604f883bd
f23abb045813
client_keyshare: 9698728bd0febdc164c410a6738962b955c08a36b25c89058c38
d4575592c12d
server_private_keyshare: 23c1313bcad4f689a23bc623bbd8f160301def2c2245
b5d6977e67dcc2048a03
client_private_keyshare: 7429e9b8592ba3e7d20b3bbee1bf0a0247c5f9c357b5
a7f029ebb222c4ad4a0b
blind_registration: a60f751ce4fd2b8f4412cedce7bf9e19ee5800a95743d557a
44caa494840ec06
blind_login: 9e21bcfcc4c82070b5e27de6b540da38c9ba48d7840912dd2f860fad
cc40d50d
oprf_key: 31305d34c37c0902677f3cc5995660266a08ecd7d11fb0e9bcf2270a30b
df307
~~~

### Intermediate Values

~~~
client_public_key: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c79
787e2df91e2371
auth_key: e67f53d70097411ea5d25af74989768ed6d50777ef05c54ff3dfd15e5ea
f96d3a9dfa75964a097b0787c9eeba5ad38669cf24573836c8ea5d42f167166508a92
randomized_pwd: a183bffb2d02e389de37e9bceabae59fe58d3a878c216f82c47d8
74ffcc5cb63ee7344f1f777a9b98ca87307dc670791605e58f864ba214593e07a2ddd
f3ed0e
envelope: 22efea550c5ce8ee58c2b5c0d8a62c247fefb259bacc92efa68c72374da
302df289b2a501579e986301b0acbbb2a27d370842890219b362956c892c8b6fd2c80
7c2229b8db3aa5789910d28806128b49a93ecae34e6bef5b380e74bed86d5be99bd69
149836d71924f05cc50d433ac93aeae849d50c5f4bc630cee6d5943e1dc
handshake_secret: 68c7f99ebb56d8061f7972bfe0dab36493b84b40a939d2949ad
d8ca11a57b34c6846d0c65e859cd5b08d0fe12adfd930afac48e0a054dac6ff995a37
140abc75
handshake_encrypt_key: 66fdebbde7462f9d2c3563ad6f015d618f0f033df391d1
8c260eae2ff3aa761f92885d83280855bd2b1098800355163d42a2094960d96ade7d5
e17441dbe8368
server_mac_key: 57b6d878cfbd58312060b7408cd5479b78b955f97064ef196c976
051d5c3d6a672b8dab5ad0b2cf875816eebc2b3f5b1eedff3d848ae339778e63ef91d
1bd8ae
client_mac_key: a91f18e43c459c4b3d3c5ec48f45a9f8d86b6eb41f7e9649ffda4
132094b5cdaf7eb7e9f25a794f71c4e9aeb3c34c98deb7d027cd24e8548c601acdf40
056696
~~~

### Output Values

~~~
registration_request: ac2882512f36bc4d5914964e782418271371fa9bd16878a
5fb6c3b6d29c54422
registration_response: ca4a3e5868d8dfbc625c7950d900a20cd8856fa9dc7213
40eec6b4fedc63a5670c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd9
d2f936a37f14e
registration_upload: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c
79787e2df91e2371b016784d117cb3b97e4414fbeee94b6e1a4410b70fea7fad280f6
30bbfddcc581637e8351b006fbf04f56561ce68327cc844e35077063a8a09e8cceee7
0b5ab922efea550c5ce8ee58c2b5c0d8a62c247fefb259bacc92efa68c72374da302d
f289b2a501579e986301b0acbbb2a27d370842890219b362956c892c8b6fd2c807c22
29b8db3aa5789910d28806128b49a93ecae34e6bef5b380e74bed86d5be99bd691498
36d71924f05cc50d433ac93aeae849d50c5f4bc630cee6d5943e1dc
KE1: ecb46e5c31b4044876ccb2a689efc82231d2995561841156db449c71637d145f
062762c1650bc61c27c22782c1b09ac2018928721bd9de0765c776e09f8e62dd00096
8656c6c6f20626f629698728bd0febdc164c410a6738962b955c08a36b25c89058c38
d4575592c12d
KE2: 2ec103925f086229f5d9c975fb39e9cb0f19854e51f9b413f80e682f868d973a
479e8543c72cffa59bdb524bd242c3440a32781caa3bd834e0dce4d2df34debf56bb1
8fb92639b503d662744626f911a3583a9fdd21127fd21748b4fc5c8030c41361dbe2b
a0e32fdd0841a209047bb8873fba1d109bba2d757d357388f875ef3466f3aa4b029a2
1635a5f9e68a668d19f09b2f4ec70753aa7ba1aa620fb52730a1ec4d54efae9448304
c75c984042801c21436c6362298a58e1a06f05b0542009c81782ef947b51fc7849dee
4ba755b5e370ae25b7077e0543546c4b2ee8e5b7476222fa83425d3b2259e3c44a665
751dc2aa54e381a8a210505ce56cf137a234be8693c06fc0168040b3321043f40ad79
648211e6604f883bdf23abb045813000f688324213fdfab8fccff85ae23222d2ea602
43ac209971ccb7c5af08364773a59c789a6877354af62bb882c7be993cd8b9da89619
600eefab870f40666db1fd562a937360b565d625aa70c5647df16
KE3: 8a13ee354343c6ff379ee7480eef34556002df293869ebf23866e82cd60ae306
c8221164cb6abe54a64d49d3fde1ed6294f76fb0e30903725fdd69f5e63f5ad5
export_key: ada3fd8cc1a9b3cde08ddd7b2c5cbf468b6b51b182f7a6912e12d0338
7bf93104e4e1c919dec660703270a6a2d566f7a605c3311edd5097a7a328c33baaa9a
c2
session_key: 701b8efd0fd9df983d3d39fd8ead85e95b5ee465748ee911c9b8f16e
1dad529fb46d07398831ed33ca0354a30af138ba14ce9ab799c6968b17ad637a09d18
15b
~~~

## OPAQUE-3DH Test Vector 22

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 5ab0bb73be6c353dc1f8e8bdc5e9ed9fee98106940df35fd5bced89570
f105dab968256cfd0141a9da054559a453c94ecdfc79622ec4942040bb11488c2812b
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d7ad320966dfe48874bb962eb8b1efc258456ab764d7814e92c64
fd965be39ed
masking_nonce: 4b54a15ba427f3354b1890f6fab4c9d0fd1e5749f3808b8be07440
b3117e885e
client_private_key: 10b3066e47db372d6cd714fd308d056c349df63a477498b28
ad3f0e75ba47b0e
server_private_key: b69bfaa8582bc1d07933c6354dace6674e72fb420b9c40cef
3a5fed717de1d03
server_public_key: 928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9
f4389fecd57073
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b4109f26b436a2e40e589c4edd384559311f588db48c7b354ab850f
9ba069008
client_nonce: 529b15c72d4f19fe38e4aa1121f4ab142c2e46f73ff5f3a15d216be
e59e0fb15
server_keyshare: 5ef3502cc40e7ba5006845c131b661ba6ebd0e6994b6f526e3b7
cc108635912f
client_keyshare: 84a786fae7664759a8bae0cbe9065cd80b70cbf600efc695654c
93e356735c66
server_private_keyshare: d44dd3ee61cda55a67f2bf180b4cbb2b549f6bfddb1a
0e17ddb1936b678ff70b
client_private_keyshare: e5b9002b44f14abc8e2bc5bbca09fe6bad94dc3a7f89
be6787674b64ee609d00
blind_registration: cc1ed755daf519e81c8a3ac073a357709d1c5946654b83476
9933c09c92cf805
blind_login: df67b103f15ba97ad4d7977a3a0779cf03b60362c2245bb1d2dc6093
49be3f09
oprf_key: 59d61982f48e931494a78cbf83fc325fb1df4e1cf04b8dc7d638e17feaa
4cd0e
~~~

### Intermediate Values

~~~
client_public_key: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae5b
a927c3c6a9af07
auth_key: 0c8b9ef74972229b2eb8c2524a7da4451b5daa9bfa18928ba972faf1cbb
ddcd7352fec57d316f6b93e3854e933b11671199f19b905cc0732884368d6b094c9e5
randomized_pwd: 2bcb002d2e5f1f34ceb4dfa99401d6f6cba8dea1cd287339c9e91
011c4802188ca619f7149b4786d7480a27b7f503ea80698ecc5614bcfbfb60f016fed
0cf752
envelope: d7ad320966dfe48874bb962eb8b1efc258456ab764d7814e92c64fd965b
e39ed32f315c302c80c25ad8020575ab3a5464ccfa5164d0c765f83e9bf60a3dee00a
5ea20604733282d854ae0364637fa5b8867425cc22e31f0dc552220e2582caef91a06
a06db1a62911ec0b55f7cfb3f765f34e94c78ae621f417597786f4c766c
handshake_secret: 3d855c2cc58aa1ed982f595652136d3973d3a9da5f91b7097a6
e5815c346d74fcbf8e5619cf6f2fb56327c7c00e02db6a73c96eb24a28ab5266946a6
6b12113a
handshake_encrypt_key: 4978aa4ea99bcf2f3d9bdbb577322a72e4347141c536f5
5e52c0910f07871ae9e3e7c4e9c50542f6f5fe0deb4a71fbd35a3089ffd49adccd9be
4650f14859c4e
server_mac_key: 68a86f0774244188d9508fac801e968926e01e4eb97e445e64036
77041839a003c3d122560ec33176520f12340f713eb3534996e05e9a3eaf40ebe7fc7
06a914
client_mac_key: 178a01c97d9a7aa67a21c3f0006d8ffef6289720d5c7e15f0a711
27f184dc32c7ef45be96f7bae75356e177919a68e78945e349d08784ab475f80095b6
b494f6
~~~

### Output Values

~~~
registration_request: 34fb6ba29e60511d9ce2d2a644a58b8b34af6516cc54f20
f7ff605e8134c1213
registration_response: 12b14ed747acc293ac00e8480dc953b3f9516d6947002b
3e6b0db6c8c3698d79928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9f
4389fecd57073
registration_upload: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae
5ba927c3c6a9af07983a2e0e4d1bdab25059b7ff55eee087f4ee41a53b396db0fdda0
b6975e33f4e323063245dff77e370fc7dea2479896c6ba03be021994921b3f2ae8e98
e6a632d7ad320966dfe48874bb962eb8b1efc258456ab764d7814e92c64fd965be39e
d32f315c302c80c25ad8020575ab3a5464ccfa5164d0c765f83e9bf60a3dee00a5ea2
0604733282d854ae0364637fa5b8867425cc22e31f0dc552220e2582caef91a06a06d
b1a62911ec0b55f7cfb3f765f34e94c78ae621f417597786f4c766c
KE1: 9e642c6da6a475f89078708431aaa4e04d96097f7778b0de577bf4d08496ae5d
529b15c72d4f19fe38e4aa1121f4ab142c2e46f73ff5f3a15d216bee59e0fb1500096
8656c6c6f20626f6284a786fae7664759a8bae0cbe9065cd80b70cbf600efc695654c
93e356735c66
KE2: 40fb1dc1c9c8d7771e993ab1047c8ca9407e579c8d2873c1bf3ed8a41ab8b34c
4b54a15ba427f3354b1890f6fab4c9d0fd1e5749f3808b8be07440b3117e885e36ed9
11f1fb812ebb18a05e3b9af3fa13c50ac2bafafedcf2af9907b101527c9d2458cd916
6a6206ed89fca49a09e1ebfb4d30a08bc453a35add6f33c666d26c3a6d8e116efb01d
3ca3ac6fdd966d4fad04bb5ba71e873d70b20a02aa44ccc9809a03d93a7ed60df6943
227781f8b55267da68d3a616747b35c89a4f453d96eeef6f392931bca03904dc4c601
b15538ce41ab7417f9dae024c7f8c1d2d86f145b4109f26b436a2e40e589c4edd3845
59311f588db48c7b354ab850f9ba0690085ef3502cc40e7ba5006845c131b661ba6eb
d0e6994b6f526e3b7cc108635912f000fbc69fa5154e7e449537c2607a5fd3d493bbb
783d5f1543604beed103e8cda5e60fe5cb4cd90ea10a75f359fb7cf9f3f6225741fd1
24bd89f4e5da45267ca3a826038b6b99b282c5d9100ece5e9114a
KE3: e0897053f8a12731d6bec0a3d5b0634ee6e24f17db7fc1bcf3c09804e8e092fb
8963fa96de1dedea5243cb613b037caf3e96045439118a1dc620c7ec7ce6b877
export_key: f393b134080b770c9b7e2fcf4088c9cc3af90db172a8f0164196e4916
fe57621f021a8ffcdddff8c6976c01183d515441f043d9be76b3fa019015a30620f75
4b
session_key: 6a2f7dcfa0421336e71b98a6657e719aee366b7a32a9af35bec2aa15
a3c06fe57fd78b6d364c671cd05115566528f999650239d2370b5c3dd9db3670b72a9
167
~~~

## OPAQUE-3DH Test Vector 23

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: cdff706f61d92313589724d7726bd05f55f9d2b15ff0e1dcaa146e9af6
09f8e65eb747399d0778bd4fbb6b2889b6df683292a633038918154fe5d3e242719b7
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4beeb15f5ccf589b9f8b39a185bc3e4985f1708293c22973caf32
74a9b319080
masking_nonce: 1d70046fc629cfc5252109848b60ad5fc1083539e6cfd463cafde9
4fb60d48c1
client_private_key: fee07a49ab54150e525557deebd0a14a8ea81876fdbbf94da
f03d5a2e3cc8306
server_private_key: ad52e51fb993d6053fd960279d81b6111a367246256f87159
8aaa2367eb1770d
server_public_key: c26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d
9d5eda7943266e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: cb1ed5ebd4350d9cf2a4fc5d97ccc81ce0848f55417a04436fe54cf
a7b5d7943
client_nonce: 8a9560c4662fdf073d51d16012230b8bfe14a00e6bedb521ddcaa1f
4acd7c09b
server_keyshare: 16041ea53924cafd460331043cb3ec0c7f17d6c246499b9c6381
18a606071e61
client_keyshare: c2b0aee89ec05d28e6f9638d2e056f7cb4bfb8b4d032239d3e4a
7960d7479e7c
server_private_keyshare: 3593a6a9750f5d3573fd491ecddfa8bcd41036d3f822
b056878005902dfc4802
client_private_keyshare: 2a9fe9a4a28d0f41ac665d22d08577d7a546054f9c10
ad092180b669e8183605
blind_registration: 29fe2a69e6a588f230704cdb406004f763c86c685ca52b07c
eebf891bd86510c
blind_login: ad0703869a0fe935af28eda1b2c2ee62bc6b73edaf4d12d4580e9b1b
9b4cad07
oprf_key: 87fa0a7a2c834f8dd5edc65d0c536336488a129cfc6769b2858878028bd
6ba0b
~~~

### Intermediate Values

~~~
client_public_key: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f21f
51945a636d180d
auth_key: f8ff8b1baa2bac17972484bf9129e2830db7102d2cbd58d1948092812e7
95f9e295f2c6aefeb8787177118c62aea1ab27e6f4ed752fe948c89c8c5a1a098acf1
randomized_pwd: 6af83b726bbcfe7fb95c046ef79c59c19b325165080b8d504b1b5
92195ee18fba07bda135c9e477aafe359b496ba6e495b0853d2328f903296daacf61f
6bb232
envelope: 4beeb15f5ccf589b9f8b39a185bc3e4985f1708293c22973caf3274a9b3
1908075b1d83f75d5f179eddc74341d61769c701279fb2054416cdb7a4170f256eafb
c0903a6da7151bb35c327435c51105ddc59be90299b9e6fc535d9a9c843f4def24a03
cd6d2ee7de7fcf59ff034b0634abfb8c1d35cf5947c4f4f8c4cefd340f0
handshake_secret: 5360a504f2653c67d76a34da3358882d8374df39002a589a883
86cfd250eb0dec22adfdc2ab55ee5ac9d56df5f6eddd49f06e6302f94bc3f89300c15
c71a48a3
handshake_encrypt_key: 221451330aea49dc3fea2a5c1848b696b2fa57c0599e73
13e590d81fbeac967dff8b4e2e4667218ac9b039322c794779ca25879d2650222d3a2
0b74cfc231ace
server_mac_key: 97d7c19fc7a7215889e03a292476e252a75ea5b93857eebc36ddf
feb81aab633d4f06a9d0efdaba5ecd03edf85a00bcda4a0d712a223e66584e7aeb7ff
343350
client_mac_key: 6a55854a1a4807fd3aab699385e988ae0801edc7e67df5b673534
26f5f548e85333fbad29c11e7524c6b0340a52f8efe0785694f759e71c4374aa1a22e
782e32
~~~

### Output Values

~~~
registration_request: b02294ae456aa0e055e49a09a3a4cd7176d9b34778a4dd9
493eaace4883c0016
registration_response: b4e607d62a90a0a8496f73aa4e16a34eeff616b0c28d1f
d1d17b6fb877ca760fc26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d9
d5eda7943266e
registration_upload: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f2
1f51945a636d180d797a8fc5e5de0846dbab3f580a33e15365264f13da63dc0221e65
3ff32d0b56eb4164874c063ad64120c0b8a18062c996dcd21b7a2c8fd40dc08aca7a2
0b3ac64beeb15f5ccf589b9f8b39a185bc3e4985f1708293c22973caf3274a9b31908
075b1d83f75d5f179eddc74341d61769c701279fb2054416cdb7a4170f256eafbc090
3a6da7151bb35c327435c51105ddc59be90299b9e6fc535d9a9c843f4def24a03cd6d
2ee7de7fcf59ff034b0634abfb8c1d35cf5947c4f4f8c4cefd340f0
KE1: 7405ec93c531676eb9437f46cf3c3dbe9346fa83dda34a37da03d693a90e9f7e
8a9560c4662fdf073d51d16012230b8bfe14a00e6bedb521ddcaa1f4acd7c09b00096
8656c6c6f20626f62c2b0aee89ec05d28e6f9638d2e056f7cb4bfb8b4d032239d3e4a
7960d7479e7c
KE2: 7cbdfc98edb75bfa3d9636771e5c9dbf9168b69966262d80f290950a682a8909
1d70046fc629cfc5252109848b60ad5fc1083539e6cfd463cafde94fb60d48c1a1fdf
a8a4ecbf187a365734a283a26b697bf4214aedd1c8e723e921eea5b7e7a00a234ef19
bd9686f339739be234214baefb713cb69e3c13abd57738cb67b70c4a25b2601ed7dab
3e6b3665a7623e1ceeda030c3f148bc99d966b990e878dad9a0d59e258f6c0d73fd00
b2b8410fac749da23652247892ef7912f1e5a879590c997ca97a3ba6aefabf89ee749
e46b6a8426a4ac46e118afdc6229a3e2d7bb1e4cb1ed5ebd4350d9cf2a4fc5d97ccc8
1ce0848f55417a04436fe54cfa7b5d794316041ea53924cafd460331043cb3ec0c7f1
7d6c246499b9c638118a606071e61000f5f992cf6370573bf9a3d02dab6b13d6cf1fd
022417ac3dfe7ff855876b234813917dd3a92b823e19051f7fb93bb62ac9b2b83596d
0a362adb53bd40e0bb66a5cae9d0f112988269d3f8fd500396b35
KE3: e27202e021ea59a325bbe704085f357db251fd7527a9ac396dbc53371eeee3c4
e4990c23f0d920f03a16e064b6a3006e1c0335fc5670da49a3e96322366484ac
export_key: b9df96a941b985e6ee63d271fb6625136a70839aa4823ff94eb48a3c2
a0535da46ce89ed91230c434e16118da578eed2ee1ffebefdf87f17531b0477170c2d
ba
session_key: 587dfda5fae9a29132a81fc3a77cb9a2909993a99c7699bb96a14a84
094e7312c49e37f03ccaa6662b0a54e9496ebab9a7ef0db20a6aa716a1d3dd8ff34b9
f94
~~~

## OPAQUE-3DH Test Vector 24

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 857bf1908e1bd5a995004390be61b2b97a7b30ac36ebb8dc2071f69e7d
31517c455fa3a0b20372cd34cdab9b095bd9b37d3273fe448f8b3fa4bdd0a83de5971
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cdcf4a19a19ad7d40bad8804be0267fc4c82831c7374a4d8091a5
5b896fa1715
masking_nonce: 3a674793181723ee2f13807844cef144ceab2021a615301ab7e13c
41db9f1dbb
client_private_key: 75da35392023fcbfaa87fcf458b0344248870cd73a38e3fcc
d00a994e1a09e0e
server_private_key: a7f4d763822fcc14bb91a7b36b0a6d30f1ae8c3ca1c36505a
02610dbec29260f
server_public_key: 9023317b443158b83d4f4b49674209ad390595bd29758f5e86
b1fb217190e964
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 3d428d82363a0b92bd63fdf234271c884adb897fe7d9ea47e5e7935
781dc9999
client_nonce: 99653c99fa82f8232d14584e49201af116e9e14678cea3bcf2b6e18
b0c850c7c
server_keyshare: 58a6c4fdb4b3da03df2e5b1f6ce1549402e209712e5bf9d31efb
db82c00eef5c
client_keyshare: 2c8ffcf1bbc02dab15df7834ebdf85841395f07c8e7317285ba8
574b6eee3910
server_private_keyshare: 67cd6d248d654a4f7b687e0c7eb2a02bf83796d422d0
857bc80b26e57574af08
client_private_keyshare: eb3b4ed65a30dd1ac8bd653f707b4cfa3e6b2698b2af
5cb5237235104958d109
blind_registration: 7910645dea4be0d8f6e45f39d3db7bc33d1573d18032ac63b
63afc6c3170cd04
blind_login: ed642fdcc98bbe29b7b93769cd75686cce64941bdfd686956b1a60ac
9f7d3a04
oprf_key: 54b0c41d68c4a7a978acc7dcdffc3908beaf97d4000ac53b2e3e5507caa
1840f
~~~

### Intermediate Values

~~~
client_public_key: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def633
28bec3a4f21146
auth_key: 321da064406e79cf9963cdedf484a8b0c3812da356303080133ec0bcd1e
30d64f168325292c0c661154cac0733231c792d5d14dfd31e37dcd1b503d65a393af7
randomized_pwd: a61188761cd72985376a9b988cbb1696df046158d49e6874afb2b
8a3c5baa95d447c081ee0ce711d39d7550cc16e49d289d662af1211ec4fea507ee9b5
4fe66e
envelope: cdcf4a19a19ad7d40bad8804be0267fc4c82831c7374a4d8091a55b896f
a1715a7f71de44b67b178b02ba465f6d090eab194b53d2e84b049298e0d4cdbf10840
f6d234e5dfcb7ef83ee879d9afd93f2be74eb4d7195cacb0819b18e7f55a2e37065b2
f47e672372cdec7c83de33e54e06dbe7837fb90c2853c2ca2ed59487e5e
handshake_secret: e1cba61a067d33368bd1e26a7c3bc4cffdd916a38affe4a7349
008881063985955ef1ef19a25b31f18637f353fde61aa5c39a10914346341e0f02304
773aad60
handshake_encrypt_key: d3d98cafecadb46b4d508b599a36084e2590c1db39a676
731e5c545944dad35e496b1acd3aa30f6c98fe4f6d030bd805e9475fed5c37ff58387
fa5cc682212cb
server_mac_key: aa94da7ac4668b921db447c2c74460d7e80f4b85ff620e772a0f6
ac3f7db3d44f6a3f4f105c534ae61b33394f7ac4c1eda1e79dd4644d8f0ad9010328d
142e97
client_mac_key: 07a6d9a46f5f1b84096615f84c9e9542178dcac1f8ff12f12ff64
c3e269f6d2f5897220cc8eac0c299b874380d295e80caf91627ca233681cc9df9f481
68f4ad
~~~

### Output Values

~~~
registration_request: 6a525dc9419e2d0261fbcd6033f9d500503a27027a48d91
27ca1209e01690d29
registration_response: 06ad8201e34d8e1eea1de904c484fc493df7b6ce11ac09
d490ab7305b539b9789023317b443158b83d4f4b49674209ad390595bd29758f5e86b
1fb217190e964
registration_upload: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def6
3328bec3a4f211467a0eefbd8a4b69df36d9a29d4e8393f49fd1dc32f64af2d7f7fa2
ab81f3023c80e3b1d847258efe8cdc1ae0aaa975256f0624a79caf9d1cc2b9fd4058a
9e03a5cdcf4a19a19ad7d40bad8804be0267fc4c82831c7374a4d8091a55b896fa171
5a7f71de44b67b178b02ba465f6d090eab194b53d2e84b049298e0d4cdbf10840f6d2
34e5dfcb7ef83ee879d9afd93f2be74eb4d7195cacb0819b18e7f55a2e37065b2f47e
672372cdec7c83de33e54e06dbe7837fb90c2853c2ca2ed59487e5e
KE1: d6a8af82258885688aada828f32e04463c3739c7da0e63c5246711520dc16e37
99653c99fa82f8232d14584e49201af116e9e14678cea3bcf2b6e18b0c850c7c00096
8656c6c6f20626f622c8ffcf1bbc02dab15df7834ebdf85841395f07c8e7317285ba8
574b6eee3910
KE2: 14ec99860a47e2ef0ee0a896bd65234669149b67dd23c32e595ad895d1028c57
3a674793181723ee2f13807844cef144ceab2021a615301ab7e13c41db9f1dbb04b8f
1067ecad6b35eb7f0538671dbdcf3171876dc4a5120bbe65fbba8830ea8d4f342ef60
e07c0e7441bb80744fe68717225306e47557592903a94453ea32cd3a1f8e74d59456d
8d7eb2bb2d0d3540f30b6273e73684b82bfe8f59e990a197299ac8ee84f0e01a7deb7
c7c5cb65db6ae5a9b955a6d39352a34eb26bc6e239dfa35dcee20ca03e58962ce66a1
6ca522e518c530f56b1e2a1786d39d0c1afbbb13d428d82363a0b92bd63fdf234271c
884adb897fe7d9ea47e5e7935781dc999958a6c4fdb4b3da03df2e5b1f6ce1549402e
209712e5bf9d31efbdb82c00eef5c000f1e14d47ff11c4dd61751e4b521af2fde2903
5df0e8f2616676342a152bd17781886b2c9c1844b1016cab6810f5de1b09321ed728e
79955d08f9e6b40215cc4e52d05d4d5d0e7021973a163d540d033
KE3: 01fbabd1475c7c254fcfc01a167241a414ca01e368671f650dc82598c38774f6
b7ee8674318f995d13d50c79bb0ab4b681deaf4402d4b3c459154660abf9ed3f
export_key: bc324fcf39c2076ae28bd99b695dbfdec525a413c5644ef66ea331716
e407979591473722bbc11e3ba15b604017df611b082ce980cfcff2f220c814cb5f591
42
session_key: a0d263d5e1f4aa6abb16929f20490f91e193322c25946521b78a8097
cfcfa6f5be61db2e48b77a22cc50243c88e1063451f96415ab32f6440b72aca514f86
4da
~~~

## OPAQUE-3DH Test Vector 25

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
Nm: 64
Nx: 64
Nok: 56
~~~

### Input Values

~~~
oprf_seed: 2d8f83b63ef32c9adfe9f9c430b1cac00f49ba284bc52f0c9f1f7c38b7
1001dacd1bddd63cfe8967fd13c55bbdf25e8b6cc087ee23a38f7485b2eeed2648eff
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cca755b1341937e284043a2c88bf3d69b2761077d84981a37d555
01d5a514873
masking_nonce: dae2cd69425f7a341e2a51f5177e565fef6c3fecd2864b2b228239
b82c5aca36
client_private_key: f4ff0c84bacb98d40ef1b543bdec5009b450e4fea1c8aeefa
6022540fde3cac20b940bc918b0a16389fe160a1e6ae09a48d235acaa1d3735
server_private_key: a762ac7f6fc2f643032abc43fbb2ad4e6e012f48d106d10ed
ddb5b69d9e36d59b08eaa6830c6bfe473f50ccfb5c033b97885214dfe740e35
server_public_key: fcbb8bbe6f857883e38783acf58dcd6de556530055a2353c4e
584320e0916d28b8278212bd6405864ae84a5cd2508f09ea1185f82c9ba518
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 483fd0e4b908c66c202500357e2491f1462af3776667129d118bca4
61790b288
client_nonce: 7fa76459168d148209a19f65ae653e294bcb559b1f535116594d3f1
9a566a92a
server_keyshare: 5898c178da53ad329a001103a6f2b4ec6e0966c665fff16d88b8
7a83aa267c2be161d1a36a39b7b184828166f721b83ee15fe4753b05755e
client_keyshare: d25b52b3af68ebda6905d0db5d964660ec9ec81066ef7955559a
a302e012006b1ce049556666231483f56af9dcd1c27fdbafb4d954060091
server_private_keyshare: be35304a0559db2bb6c9e25206ba0fc53b33226b8024
79acd16c975c6cf2dd688fc9a0dad8b6ec9dbc18b90c704a53626c5baf9094cd0c3b
client_private_keyshare: d4bce964deba5ebdfa17b366504278e82626cfed3d19
06ad0e990e08c94faa134d3842d167394a1ae296300bcc9818b8373f191382ae5124
blind_registration: 83a353c6d832a563b5706dbdfdb9f3e711ee26a9c31b896d0
da0433f4f6eb32221c3c90388e170f8ed58afce06edf6625440f4e552502839
blind_login: 31c8ad493e51f27fff7955175d8b2606fa4f81f8d116d2a9e8e49578
715881238aa712a6fea64bbe268869aa0e6c166754e0b3cc45f4fe0b
oprf_key: 113e070de69c20f96dd6565cc617a736807b518cf49b312a04e1dcd49ad
ab8176f895732193028cac0367c25bc486a79ce5777dd09a36514
~~~

### Intermediate Values

~~~
client_public_key: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9fb6
86b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aa
auth_key: d6c51857cdf177529419946ab6fe5a08f50ebdeef0d88ccee5f05862946
e397bdc326c39ed86eca82d2cb13b5b4642a4efa50fd97a65946f32a48f82d8b8594c
randomized_pwd: 43ca8e9fc4658fff4275bcf84450b6f2787458d4ee53c387aba45
70d8e84c91c5117b3ba93669f1431d3ef9d8a57a1269faef765c593be33ea66e7ff94
ad3369
envelope: cca755b1341937e284043a2c88bf3d69b2761077d84981a37d55501d5a5
14873659eb13e14fc7ef6a77136d1eb63bda85baf00c336515630d48c4d037304d7bf
38f7b95d4f5a124f475c018645b17448b3ae776f0c5f86bc2232a074f9dd90e7d394e
c83ecbbe64da8359a745e9768705ece4714205acb8b86597f4e8d6a0f089287adfaca
bc5270ff8fb62d22f6418ccfe81d18ffbeef19
handshake_secret: 7176e3d5471625f5fe5ea2bd17ec5dc4b6e00467448e72ddee4
9b8edd6ff11f36e7e6aa7f976c157426c0ecb192f4d1503a8efd1211434573f0168b1
779ebfde
handshake_encrypt_key: 812f5c30fd8d09d895a8099192e8f822422b5bc5518610
ec3f33e5e49f042d54ad88ca0324d8acefca3559a1030f53d5ed1c4f62d4484583b4d
4713b3b75c8db
server_mac_key: fa2d39fd3d030276683ee3de4adb4934d4bd6551a824446a49620
42ec036a469c71fb81ac5be2e981070e74653b6606c1885f78328519637b8b63da249
05ee78
client_mac_key: 6e76c94f60b8e7609be2be03a624bed130a82acdd84341764b4cd
04f7ef02ec751d39b4c63886759f6e0d8c6b198319eed12c3b08f549b96e6bd472041
4274bb
~~~

### Output Values

~~~
registration_request: 56eba0e757af33e634107f2da32fbe987af1d37bfec1918
a2d42ed2f6b3714bdc1dd190ed6dc6da310536bb748cad363e76ad2fb1b05f1c3
registration_response: 5261c7f2f21aaf3ba2c3897f3a44dcc2beabea6f4abb5f
10a64c401d1481e309d14c54affffb9116e903c4ec36551752fdb0206748fadd96fcb
b8bbe6f857883e38783acf58dcd6de556530055a2353c4e584320e0916d28b8278212
bd6405864ae84a5cd2508f09ea1185f82c9ba518
registration_upload: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9f
b686b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aa7d742
6306a4962a57d06cd6be47a7c8f795437e86a50dc71f0c9035b543ae436d13f9c67f1
ee9157ebe46d28372869439c8d0b48ab26c0692b2e7ff66fd0e29acca755b1341937e
284043a2c88bf3d69b2761077d84981a37d55501d5a514873659eb13e14fc7ef6a771
36d1eb63bda85baf00c336515630d48c4d037304d7bf38f7b95d4f5a124f475c01864
5b17448b3ae776f0c5f86bc2232a074f9dd90e7d394ec83ecbbe64da8359a745e9768
705ece4714205acb8b86597f4e8d6a0f089287adfacabc5270ff8fb62d22f6418ccfe
81d18ffbeef19
KE1: 16ecbe71c272b0b9cce77059395154ae766c95a7f10ad0e699aa0c773877225b
a13e0a8ace5007c53ce3631c7e7cee782a6c44cad6832e0a7fa76459168d148209a19
f65ae653e294bcb559b1f535116594d3f19a566a92a000968656c6c6f20626f62d25b
52b3af68ebda6905d0db5d964660ec9ec81066ef7955559aa302e012006b1ce049556
666231483f56af9dcd1c27fdbafb4d954060091
KE2: d672a158bd9178546c287befff0c4789ece9a84071a98f9146ce5449b5a19c2a
7160862145916b3e56627abcde87d163964edd7727907353dae2cd69425f7a341e2a5
1f5177e565fef6c3fecd2864b2b228239b82c5aca36d0824c4440d1d7f15e0d722c07
24f97041a5b88b9f30a7263f49bc562227561b3847efbadaea5a286d7d24d112dde27
83772e7c697fa472addadbdb9d833d76053086be08e3a27df16724c7c365f0a8d0eb3
1833e7b5988a4dd14f8768eb2da6605eacb7ba01b913afc33081453945f36e74ff12b
f599e1013f1e08ad4acb65845599fff72629a418a51b1f89cf96c81f44228b44bcf55
7c42b9239e84e2ba2e425c80fe4c713a8ed5195aca8c43d3aa203271c9e7b01eff85f
2beb8a70c0b4baec22e95712ea0a03707073b91fa60b7483fd0e4b908c66c20250035
7e2491f1462af3776667129d118bca461790b2885898c178da53ad329a001103a6f2b
4ec6e0966c665fff16d88b87a83aa267c2be161d1a36a39b7b184828166f721b83ee1
5fe4753b05755e000f9fa4f4dbfdbe9b2f15c28fba6c0bdb0fad3c99de5035d0f9af0
59311aab2a69975ea5c0925db497649349bd356c7a4f41c4d0d3aebbf92aba3522e83
ebadf9bf3220de92f5ecb10ff439a35519bfb5
KE3: 9b61f2bf14953304f7a52a3e40c089aa0b9723abe6f10f8df4d1d97d0197c30b
e7cde1b5d2871046d8b5d72b63dba1ebe926319b8cb256256db5b4a202fbd63e
export_key: e9db9e65c49aeca60415f412f3511040e0f0debc8114d6752c0172b1c
a0a5f420c61a8a46aed0fdec06757a7d1ecca05de761ec676046a0e6d192ed038715c
7b
session_key: 1e296c1baac73f1df293b131f351d58fffe6fbd622e5f37ae002dc48
2829775cc721a6d3db4df8cb032fcc4e0d954f9065b0964c5ab6eea58a98b430b8b83
172
~~~

## OPAQUE-3DH Test Vector 26

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
Nm: 64
Nx: 64
Nok: 56
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 408b58278566cf765109018e203e2e6e6a8f255698c1bdeebb14bc22e1
c2a1cde4ace22c8300adc036177c2dd26d2fda16c5f78b6de5b72898fa377be3a5bca
0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 10241f737e77bcc1ed216c9a367950a7ef43678f9ee29b309544d
f34298d472c
masking_nonce: b2ea57c79da7ced6dfda2dc6c6c0402cd96b329f7fcd183bf9d1d7
e5a716d42a
client_private_key: 4f4b1b91c6a9c0dab6a8ad279201e00d358aed1a0ba88c458
589796b05ac19101d1119df1070dbd0911ca74b4634a51b9b1b093b74e1873c
server_private_key: 6ab03a76f031abde2e7d1f987c101064757d6133445217316
02876c29cc7d2652a7329cb8513ddcebb66b178194206a61256f5e14e70d23f
server_public_key: 2ef8f9560867402d20f9c34942bb26e63d2cc667851473334c
6cdf1f89ec0ea218e3ce0f73f9f1fd303f140bff958f80b7d4dd22a150a0aa
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 2aa2944a2fac12229bb22b6b63389635f6102d71fbf95b4a8a6cbf7
8e6b2814d
client_nonce: a7d04cb60ee0f6ea96a3dc44160f7db4b22d2652c4461577685d5f8
0450a0aea
server_keyshare: 32751cb95f97035f22d498ed57a8af0d2495075aace642f15244
2da8485211d6a551142d9bc6771619ecf80ca8b4def396f706ce555e2896
client_keyshare: d87899f024ee66ed5b8718f9966f2f34dde445da12078789f1e6
208028cbc9b7ac7cff5ae937856aa01321310e1858f0e3b89492e9e49f42
server_private_keyshare: ee1fee6fc5ad0f317b2639067b1ef7796b5caa6e94d7
9390dd16061e4dc69508c2913424b3a6b84133223db6c51c01b054e8dcd2f32e6724
client_private_keyshare: 071e199a022ce8c6cb0005eb1e2fd4703582c35881f2
64ce05ec18365cea6b66423035e531a19194e5934618e546215460f66eed7d0b6f0b
blind_registration: 0db98607cff12cd2badef2406e0491ecd3d6bb96a4335ee7f
0c504e5cbe48ef5daa3a2b717e4009bfc8c60f6a0ad5e73607538ee51807c3a
blind_login: 24ff7adb77a75a1f02efa6633339b91ae4a42dd0b52fb5f997673263
f7f5af9ed39730c2d1a09d12123d1bee3f550acb33790d70b0123815
oprf_key: 3d1e92b4ddb6bee3cf32ba6c0b16addc525da38f13266939d8961fc3cdd
1437673e1be929c75d3679b22a9145205d2c1719bb44a7983832e
~~~

### Intermediate Values

~~~
client_public_key: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec2a
f04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f357
auth_key: 3bde34bb68300e7843d79c1bfc63e5cae9fff249b00557348442d81c59b
ccdf5f13db9e59da32f6b25a4fcc76dca3e90021fc1553614b71cd1982d33dd95c07b
randomized_pwd: 351cad5b1f66d74e7f6beb7ef2e02234ef37775800b0ac91de427
af72ec6cf5a0c2920099005247e1cb7c77ed91cd094d3bf6a97e99201f1f1c58b2241
0623ac
envelope: 10241f737e77bcc1ed216c9a367950a7ef43678f9ee29b309544df34298
d472c8e46164d8929ae397121cff467322b1dd47bdd5f714f1dc5c04ae8230a274a36
eb9574040d6baf198c5599c69c346f8e12c1fd4a2e558365d23260f6ba5c75901fc9f
34c675288fc52648f964c4270c7936a0bed5e36df70184c187af486f5f2a3c0ebea06
38dc5dc2a7567cda68ee2654f7691c03ce3011
handshake_secret: 727af8282b3f529691b3914a6735286c1abd31415a1276abfbd
734e77a6bf6aceae95c4661b6cc0f1bf7c918e841154ff7ea7153e4f47639b8e581c2
4ec02c65
handshake_encrypt_key: 9891ad2af01d57842cfc10f959d1e1a3592f1b86529f44
1411c8fc9451e90e6b379085645e6a01f93f63106b116e10788c244f57c28a0f75b09
4d4c34e80cd16
server_mac_key: 6c3c56402e8ab595f1c72bb2c01813205f302c6b557773c7a233f
1c7c02dd7257fefcbc0feff679df81c11ec0c63b866b20cddd0beaef7a8ea627d5725
16f036
client_mac_key: c4e85273ca8aa64e109b4cb05089c16bcab3d9b11ef1225464e2a
5585f7d60911675649025b3a54292ae64b00c0407ee5cbc9c2bca3a642f87ac6cdc16
feceb2
~~~

### Output Values

~~~
registration_request: d287a62ca4d452ff3b5e2d800121dbb5785bb383db9bdb0
c541f8e643443dfe2ddb1162b8b7c758893fde1131a84ae57935e7b60b14058c1
registration_response: 6cd7ab8b0bdc800c66c217d22ef729c08465e5df1a6b5c
c01c0cfe5d9d7b4adc6e40dc1013b8b8f8094b386530e673a179735e0cedee0d1e2ef
8f9560867402d20f9c34942bb26e63d2cc667851473334c6cdf1f89ec0ea218e3ce0f
73f9f1fd303f140bff958f80b7d4dd22a150a0aa
registration_upload: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec
2af04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f357c1549
7051bcca080dd4a5566430fa8850bac4abf66fc2df50c6dba2f29c9ad9bc3616ff533
a202e553070f3f4dd45e53931ed02c151cecbbdcfbf66277acd1a710241f737e77bcc
1ed216c9a367950a7ef43678f9ee29b309544df34298d472c8e46164d8929ae397121
cff467322b1dd47bdd5f714f1dc5c04ae8230a274a36eb9574040d6baf198c5599c69
c346f8e12c1fd4a2e558365d23260f6ba5c75901fc9f34c675288fc52648f964c4270
c7936a0bed5e36df70184c187af486f5f2a3c0ebea0638dc5dc2a7567cda68ee2654f
7691c03ce3011
KE1: e4420dd6be305be0776f14c1140f0b36ca304c007827a8c5b4910c5432dd4caa
6214b4077d4a99e6d6dd7f756bb3531bd010eec2253afd1ba7d04cb60ee0f6ea96a3d
c44160f7db4b22d2652c4461577685d5f80450a0aea000968656c6c6f20626f62d878
99f024ee66ed5b8718f9966f2f34dde445da12078789f1e6208028cbc9b7ac7cff5ae
937856aa01321310e1858f0e3b89492e9e49f42
KE2: 564606d70bd3fa461bee6e06ae9412f4c49b505ed6559cbc9d17c02072931636
2975c2e2fd560f68032c93ac7ea5357c892b32ea0dcc6050b2ea57c79da7ced6dfda2
dc6c6c0402cd96b329f7fcd183bf9d1d7e5a716d42a81d354f006c5e4d63eb73de41d
39abf0c44b9891362030c679bdca90e2f2467681509c612d390a5fa831e9db97b9226
b6f0468c142c3ea47d0e86da34855965e257d610666aaf29cefabd4f0067c624abc3b
9990c6bf06c874579f9dd0717c1c52cafa52b108a301a7f1e727e252d1a6295eb3635
feab6b65374441f28dd2ee501b0fed3ea88ec7dbed28ba544fc94977b5f1754f7ed92
7409f3e0e0f44a9f40ace2e37e4865d3ae9085befadbb8a30d0ee3307d90328776b26
c3c95861fd5d9c961820f84617d430d04f5e9f94e27082aa2944a2fac12229bb22b6b
63389635f6102d71fbf95b4a8a6cbf78e6b2814d32751cb95f97035f22d498ed57a8a
f0d2495075aace642f152442da8485211d6a551142d9bc6771619ecf80ca8b4def396
f706ce555e2896000f96681a27592a697a734b1a00b338429d06d94788d9f450de709
1a4f3c7f3bee1f0bb8e62aa8cb2d34a1ec009da7e61ba8de473c06b33e09e16565fa7
2be1f642bef88dfabca88b21b095f165eb6c01
KE3: 3a978eb658c077997e8544b1cf52dfaf2b152956db661139afbc34e05fe8cc15
be7f1dd6544789e3452275f40de05653f98e86122f74253e22c7768de653a3ee
export_key: 12d1b25d6990128ffdc8cbf21832b96d55bc64be7ab2cc967d0c04814
835d23e4b183319d369cd3955f992126fb3b8d130a2f65cf2ac9ca0750f0acac1031f
e8
session_key: f5ca4e7189e76679957f386672f82aac0cd8972402817600ef2d578d
79c38156a80f9e7443c63439c3674242b54b28e829780f729463e20dc6fe9f21d423d
53c
~~~

## OPAQUE-3DH Test Vector 27

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
Nm: 64
Nx: 64
Nok: 56
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 256d4027516b703d2dfa1ded7a8c46870c7236091776781e8927dee64b
6675a65292295706a43c1848e82eb6825692b2528bc7ca6dbed9e7c29c02dcc2ada74
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ce9053d023afa73f0b28c64e4322207a28921ec1ae96b9ee0bad8
f87187a0ad4
masking_nonce: eec732470af6e228628f3ae80e3e90c64c51f83a41cc42d2f2c73c
7f81a9131b
client_private_key: 80b8326dd0c2b506b88b0b4025c0db89bb624a8b94861078d
88f88515adfc5374ba9326bc531c7ec458fa14a482339ce7854b1c044ba083b
server_private_key: 5315b843996e1c8dab628f7848b29fd8d4368a414eaaa9110
da1cc53752548548f132674a235f9ee105780d4ece5e1a760c147f744bb450d
server_public_key: bcd8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93
c99e1e9dc14db5c9c26b09e1980f7f5b45774012be6234ac5a8953ff69ef28
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 075e1b74c7eeb1dffa6ba8f304340956b3aa3bf6d2a43e5ebd616b5
9cd439d6b
client_nonce: cec96d9c640c98d9aca9792007035c7e9daf29343ea0b9ebb7d73e8
f210b2584
server_keyshare: 3ab8469c97f3394c729de0b4f980ac06ea6a90dd077f924aac42
10ce65521a90aa1ed82f46ad5cd948d1d96a179409a020f8a01cc86cb7b2
client_keyshare: 6e0974f24da70adf24d24b5e267c80f6335a5cba9442a5658cdb
76b3a2bc569d39ec6fedc1a162f4e6c6a460b0978684aa5f30b3304cf04c
server_private_keyshare: 3aa67989ec3df11a5dc574b914e150f5abd7cccc551c
0aa34e6667a1636de9926e6bc4a4bdc21ba549ae8b93b848051abd4dd80242f57d1d
client_private_keyshare: 03d97c90df43947879a326b5b22372e3cb561aaee6d5
8bab4f4a884a8f62a58ab60476b6d0c460e7dd6726866ff416874521249aaaaaa70e
blind_registration: 5a58b6378e03f24937ae6ebb685ba39f43d99b2f6fdbe00a8
c754c0d6d7ed824d2b5c8afca5b1cdbf7c3248fd9f16400508eecb6b7894a12
blind_login: dfbc42d70013abe2cb8ebcf6de5b275aa83525d606424339cb500346
6051f19cedbf00b0f680b7435bb165c340da077f8acc37c0a2594119
oprf_key: 96ef1f565460533723a129c4fd59e70192471cb1591f5a18a06954b9236
ff89543ebe7582493cf9fd7254eeacc5cfacba0a10c00660d252a
~~~

### Intermediate Values

~~~
client_public_key: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e5f
4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948ef
auth_key: de033180dde10c04d68198d94217bdc178ec07adac74e5a7a1a33a808c8
44f5e13136ee12e46cfc76ddb739b75189f485b202b05ff921ae170230fe226447986
randomized_pwd: 03d2fcd5b13cf0d6877bcad567de4e6036a1a51ac7006c2a496ce
538985100c8a190a240d59e69a0582918b578f51fab18c19842d796aa4668e1a6bc66
ea4e9c
envelope: ce9053d023afa73f0b28c64e4322207a28921ec1ae96b9ee0bad8f87187
a0ad47da721931582ed0eef7eca8b1eae0ce21244afcb7c2d324849df09e314cae97c
d449a9c67d2c8266c4083d004e7d572a481bb10dd9614b0d95c56ea5b687882b18135
8565c5f27dbd0d1bfc27b1d34d6a529ef9c16e58e947610ceb09471b768b1542eeb85
78aaa37e9b93e2c37ec21e531088a36297fcaa
handshake_secret: 66f51cefa898ae9486ccdf092f5ad47eaadfd6db2f76e3adfab
9407ea37b44448b7036f0b1b1e268fa823b8244b7780e3be115e004e9d931c9c0d033
67d9abf5
handshake_encrypt_key: 4c54e8d80bfb35bd90c365aa360bdfc985b56f1e8bdb84
a61df27b1470f7a5b5e887da6c151c9e8cef1064be46444aafc6f799ad53ae726f30d
619620067eae4
server_mac_key: 18d7bc4872a86d2ea01caf299fb7e5d9c4e587ad374d57debf119
85f0914c4730776e6894522c5df770a2267faafd7442388b4784dfee5b9c2a9ecfc78
c3d08b
client_mac_key: e9a6bfdcbc5943bfe9d7cf0642e103c096eaaed1f6c4216cd0a6c
e3f47a32b0b98cd02dd9ad589b2cf2bb2d3febc0ae66501ba6ceded570efa769b0e03
1c38a1
~~~

### Output Values

~~~
registration_request: cc1b854bfac5f36d7f09d18975d26bd031490a8810722e5
e84d13320bc6cc1ad88f2faefeeb84ac706985e2784da104dcfa376ea200241d6
registration_response: e04b3c954f1d6d709a83bff990215ec498fb9c7935bcc1
d340e7ac899ecbde26fd98cac559fa0183baed54d1185e32132b68c672d80ab6dbbcd
8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93c99e1e9dc14db5c9c26b09
e1980f7f5b45774012be6234ac5a8953ff69ef28
registration_upload: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e
5f4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948ef3ca0f
22b76379fccff1ed10ba860afee6db14441177b8ccf0d1f08e4bfd7e691704f8e973b
3c0c56479677dfb7004325e75ace6b7f0699baf642947a4aec1fb0ce9053d023afa73
f0b28c64e4322207a28921ec1ae96b9ee0bad8f87187a0ad47da721931582ed0eef7e
ca8b1eae0ce21244afcb7c2d324849df09e314cae97cd449a9c67d2c8266c4083d004
e7d572a481bb10dd9614b0d95c56ea5b687882b181358565c5f27dbd0d1bfc27b1d34
d6a529ef9c16e58e947610ceb09471b768b1542eeb8578aaa37e9b93e2c37ec21e531
088a36297fcaa
KE1: 8447080996dd1f729709b137aa45b6a6e68651f7f5794ec80d7aabca6f171226
e8c5ac7aadfe6b9ace4bc355d7b891907d50282031c15d9fcec96d9c640c98d9aca97
92007035c7e9daf29343ea0b9ebb7d73e8f210b2584000968656c6c6f20626f626e09
74f24da70adf24d24b5e267c80f6335a5cba9442a5658cdb76b3a2bc569d39ec6fedc
1a162f4e6c6a460b0978684aa5f30b3304cf04c
KE2: 7a4ca243be6375b2f474a8d1a15bf6811ce899e22562942c3501f6bebcdbdfac
4654b2ea096da25687958252fea11562d31ce1983ba50e8beec732470af6e228628f3
ae80e3e90c64c51f83a41cc42d2f2c73c7f81a9131b6072d400f79d38df5ee84c74e4
a6261049d4d9683edb7c5899a62d61060369ced1858f37a662981a6052c886e6aada7
6110b5a65d19aaf793c4428e096e31ab7f1dc89985e0a375fac698c9a6f1252618426
1fbaf37fb056f1448ae1c7aa751184bd2f0b8a0e784cdd93890ab06c6efda58ee8646
85d61af752c6cb42d738c03b7c9a27388a40dd9d6fe5b287d05c1e35a05593ff7bb10
b2b730d692e3e47974a5a5f001c31fb7e22a3b4e4ac3606e8a4c9542bce8738baeb4b
bc69c2e8c4cc41ee4f34325fd053ab5140775fe6793ed075e1b74c7eeb1dffa6ba8f3
04340956b3aa3bf6d2a43e5ebd616b59cd439d6b3ab8469c97f3394c729de0b4f980a
c06ea6a90dd077f924aac4210ce65521a90aa1ed82f46ad5cd948d1d96a179409a020
f8a01cc86cb7b2000f450aed233507678afed7293a894422dde5c7174b91cbc297d89
85315579b3cef14b155bb28e313ce6e2f07f6e5318096c98a0a9dd7ab9ce747c09381
4a2f9181d3d28ffd4c1bd814266024c25b7709
KE3: cbd323005e96f5a89734c1ef409359e117c8acf3a1d7e6c136ddc423d40998e0
ad7307913d2b83bca249c91c6da75a72572a96f669153ca57f4b5562d3bb5b7c
export_key: 93270b252a4b1e08488be7e3ae9594e0b8fe9192a540c73402b16233d
01ed59867ce4c3e8d579966c2c2c20a7d64939aac3b63ccaf71de487262d129d5f674
0b
session_key: 0435267dec4eaeefaf46b4524b7ace609d26f803bf22a35d2e3d9788
4af225c41ced72f826cf1c7e9ead18f9e21553d28b54653381354d6a64d3d36f8e254
ccc
~~~

## OPAQUE-3DH Test Vector 28

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
Nm: 64
Nx: 64
Nok: 56
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: b4d286e6e3f6225fa137f4686d0f34ad52eae2a96fc35e8cb1f6da569c
5d8a87b2e25e3347b5b0baa692d9f4e08e40f423a524638dfd264856245e1154f07cc
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a186e2babdfdca646623f073cec9d6d1e8d64e66b99cc4fd14ff9
3fa41654317
masking_nonce: 67fa0025edb3233e4ad7c3c620d5941addcbdef0b8203effafd77e
0006dcb38e
client_private_key: 771370125ea54cd3f86666bcf4155379dc1e0d5e6a8fbaa4c
0e0a570b44a311701b936a442f340c21a65638fe11c0e7b3bd1c3528e632d19
server_private_key: 7d455931c4f4efa18d5731a27e8ddbe8eac8be6eae6175f91
137a8cffccfcd6cb52345e2bf2ad8995f69ba5a19ffa1afe3cba5f538b0e629
server_public_key: 9cc2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8
e42262e63634ec59d0431f3878051eca9888bb45c17a68359bb55071e6f6e7
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 9c759396ff32036ca0f46e4f94dfb1420e0a372e533fc26ebf06954
e502ec0ef
client_nonce: 5850a05d1746b701f3ae10f0f992c2bee512b396f4d1f4ac4a071f5
4dcc150a9
server_keyshare: b886b2c735272aa37e700b602edcdfcf53f73ae463d94139dfd0
e173feda40f8ec315c59dabf8b7db0a77cf9c3e5b3528688b01849fd3523
client_keyshare: b8de36842175636d346164767aa834a4bd1a0abe805678ced434
06c4a09ce40145f03cd1d620d6b3932243017098851f7003f34a849e6c46
server_private_keyshare: 3ed756eed880d3de7c18dccba6b3cf4e50a1e6b4afdf
c46bc0aba90513085e532370a16b0e93d9805376f144775a662ef08423826eb76436
client_private_keyshare: 567e1a4dd379827702cbf43273917f368325b5ff3e29
353d5c0f1fab7fc092bcb7dfa7aa7596b1d670da83d996a9990af5ba44b0d7b5f630
blind_registration: 1b121a9a0c3105a83ea792da07521422552c83edaf183ee32
959f966fa8956b647b7c5d00ae7e1b60633bfccd44243649644143e6177763d
blind_login: b38d2f5fc9a95095a10bc711cf190e7749518aff1f7207b6ba2daef2
162a03cfcae4ba482b466a135440f1a813185f7dc14e970097e66335
oprf_key: 47d4e7986915d99639c87166202023361ed0079370a237be49af7387ba0
1130addbdff507ad0d46c644d9976b1007bec3358083db036c33f
~~~

### Intermediate Values

~~~
client_public_key: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0c4
0dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc61844549
auth_key: 3ea9ebf52a60b3a129e79263dc9be81a8dde6edfeed0307b76910284dbe
9ece059e5d9bda8bf13c101ae8d6c003039559943dcdfb5b5d18f1f5c195aca519b00
randomized_pwd: a5313a9b69388094685dd8b977a37ce88f3940b3d5fbacefd8c8f
fc7bf5a57f3198a6f71b7d77d731dd2c265d020d256e0684962e0a1a9ba7485abb953
bbd2f8
envelope: a186e2babdfdca646623f073cec9d6d1e8d64e66b99cc4fd14ff93fa416
5431744575c4f68efbc2d4610872a498baee8d8f8165c20090e1d7d28e79775605792
4c93a6a1edfcd504f5da77bb58fdbd63f1e84e2e6a1b4f5ca9ff55bf33fa5fe11ba66
5f8f0479f788dbb47ec236c7731913a7958d554cd9f8a955350c627ffb5c21a9a9c07
375b0fcb20cc120e7fd02e092692470fa8dab4
handshake_secret: 969906025c4b246bc804d1ee495cda9907da66c708ba1b03298
a4f1d58ce8da905bba4d75e512d4dbd104d58a915207439ba8e4960dba1eed409fe5c
0e734b6f
handshake_encrypt_key: ea333818b24fe6d6b0f136bef8981db80f2d6bc679223f
b986de8bdd4573a8e1aa0d2af9a9de01eeb4022cc11e6e13ded4d78609c007b092445
8ed30b216b5cf
server_mac_key: 7f159bf11622720b3c0af3a831828ab43bd27be6ca2459536bb29
2a014bd69f5cea21ac64995976acb96e7d4f66943fb33082da10a426e3c2a01b0cab1
870455
client_mac_key: 67773fecc9c4984aade4d537d1a645268cf5236afd82c9bc0bf0f
b384cb03a69cd350f926aef4e10b00c649ca01c30b42c31bc6eac8fe30fe8568fac63
341bd7
~~~

### Output Values

~~~
registration_request: 88c032a418dfb1e1cd1a3324ba5992452f93c66edbec9c3
65e92c1ea793cf76c05ae910ae194ca9c51e885d3c2bcba7d76989d0d824ace6e
registration_response: ce808e991bdac9a449cf4357ed54879d5b7d0d3df64e04
8a1ffe074dbaf6365c8cf096923240bf9df5889749603ad0acc18c111d5666e8319cc
2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8e42262e63634ec59d0431f
3878051eca9888bb45c17a68359bb55071e6f6e7
registration_upload: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0
c40dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc6184454953d62
aef94f33c58f8f1bf792fa721c30cd74a8936609f0a5f096709d86dc155701a724133
c17b61b968503f7166e4920a5eeb40e11288ff8a247951ee149806a186e2babdfdca6
46623f073cec9d6d1e8d64e66b99cc4fd14ff93fa4165431744575c4f68efbc2d4610
872a498baee8d8f8165c20090e1d7d28e797756057924c93a6a1edfcd504f5da77bb5
8fdbd63f1e84e2e6a1b4f5ca9ff55bf33fa5fe11ba665f8f0479f788dbb47ec236c77
31913a7958d554cd9f8a955350c627ffb5c21a9a9c07375b0fcb20cc120e7fd02e092
692470fa8dab4
KE1: b4f7627e7bdcfa7d9112301dd0081a3f51cf7e8853eb48a16c9078aeb0dd99b1
6e691ec45b6dacb2dc05b62f0e09c124c94b1b5390a68abf5850a05d1746b701f3ae1
0f0f992c2bee512b396f4d1f4ac4a071f54dcc150a9000968656c6c6f20626f62b8de
36842175636d346164767aa834a4bd1a0abe805678ced43406c4a09ce40145f03cd1d
620d6b3932243017098851f7003f34a849e6c46
KE2: 2edc7ca204555431a8ac43aba0d4edf5894595ed38786df7b685c426d95d4bb0
0bc9d867c48723b75f9cbb23e31274b549f5ebea8448a21267fa0025edb3233e4ad7c
3c620d5941addcbdef0b8203effafd77e0006dcb38e76498ed9375714df930d7715d7
5b27cede703f9e07e18a1ae08f35ace7e0f530e2cb38e8501d8ef37320ec646b3769d
6ba622d5252e8a08f6da52c8ef0e27766bd0041f46412b8704fcbbe0c1f84fe1fcbb7
81a463887d181b548f53c5adccc1bf3c249846facc22d3fc855725c49d2f103daa17f
21b092885ec78580792fd8ffb545cb26bcea0987853c19a04aa43d511a1dea0e588ac
2999f1d7fcdb513b7ca39c65ea5561555ba9605c987b8fd82ea83df14d09a0000aff0
61112ef8a360a4918d1df4a3da734967cee64b8302ced9c759396ff32036ca0f46e4f
94dfb1420e0a372e533fc26ebf06954e502ec0efb886b2c735272aa37e700b602edcd
fcf53f73ae463d94139dfd0e173feda40f8ec315c59dabf8b7db0a77cf9c3e5b35286
88b01849fd3523000ff6c5c1545b52e898a91178d9689a6ee6fc59bd10034889a8f47
ceee0b3cf2c04687446e48df78ddeef3e85ff812ee522e60849a1764c39d3dd7bc274
0f7b0c476e8c60532e5df9c6628b65f4e42116
KE3: ec135e1c78f31bcacbf8ebb446bc9959be5f0133e5d5d19822c3d77d58ed226c
a074503dd96e6b0a7bbff00914a599bf10e726c7972c8c37ee03c131120a1f74
export_key: d5623f7b35d664df8435cbd73a6d651bb96109fac75b673a7bff53728
13e41bf91d430cb0215ffcc72fbe47027632465094cfebe01e4a8a6ab424689540c0d
57
session_key: 990b91912884bd34b13093596066df5f371b13088e3349f99e4b6a77
9313bc9319c658b8f923abcd3650ae7b048f783847706377d68e54bf784c1c9aa885c
35c
~~~

## OPAQUE-3DH Test Vector 29

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 02
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
oprf_seed: ca3dcc6f809ebbdec499a453e64168cc772eec040ce22cba6286e0bda6
edd27a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 817da7eb95c282c39e6716521f9f2dcf1908cb3cb60082e99d1e2
65009d9275f
masking_nonce: 1b9fdbc44c3491e52d5abab23fba7a97c6589898152f0babee3e36
d2e415a671
client_private_key: 5b1a8d0d1f59318d1a325244e784530a56f15f95cd7594b41
1ea8f7ac77652db
server_private_key: 40e02b1164d21f51b8022acbceb26069ac5ad37af70212b20
1e18725cb41a5e7
server_public_key: 02c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1b
f7dafca0807eb046
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 6520475f364bcda5edc971af216bfd1c3cbff6f22077018a212a518
9254ac886
client_nonce: a543212613ca62b7c9e35677951e46fda946f782d75122ca19b2db0
ea23cc35b
server_keyshare: 02c5583ec9a10dfa32344fe8000007904dacd5e6be9eef27b0f9
4b50605b017126
client_keyshare: 02496d129c40fe6d255d57f6d92af5c0cf0ba277e8a0e7b67a61
df2dccd9b02c5f
server_private_keyshare: b1d0433877efe00464be6b896d06f05ca36e9fd8d6e0
2ff17435e6a4f4bbecd5
client_private_keyshare: ddd367c02e495b689d91a556eba0702d16e92e891a87
04d094e67d684ab53321
blind_registration: 6418ab119b59a01aa2a2d0fc7658c372a2ca039410fb968eb
ed2ba1d2991d9dc
blind_login: 74b8f4b1411f14fe35c4f40e826c546bd9cabd9e4ef380108359988d
4ec5165a
oprf_key: 275c9ec4ecf98cc541bdd9572d43f316d1d799bc11c281f377d56030060
fcf62
~~~

### Intermediate Values

~~~
client_public_key: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430b5
2d36b1ccc475cc8d
auth_key: c64828f188bb72f48c655a7f9d428d524baf80ea24bdce20a1f43a64bba
a692c
randomized_pwd: ae2e16dff4c105ef4319edd0b8d89fd0cd8666895843b530712fc
958b9b649be
envelope: 817da7eb95c282c39e6716521f9f2dcf1908cb3cb60082e99d1e265009d
9275f38c11ca420422ac49aa2815d5ed221280430ad4e972171a614bdd899a3e4831d
428bba482f9d7d78a07fba0d271432b7971acd4cc8a0d898c4cc4b07044e4c6f
handshake_secret: c59958e430578214b37c9ee29de08f682c676d00115e36108e8
c8f7c376f56b8
handshake_encrypt_key: 8b4722b266a742dd6627f2bb9777c0192b7ba18c1bf701
dcc6b2d7003aeaee0f
server_mac_key: 3e440be6032e1d22644678c2215c3cebe6e574733ce1a74b1582d
f4cdab62a83
client_mac_key: ec3b8660322fffd7bda47211aae564e24602f7c3936e609cc42bc
dceb1ac2fb6
~~~

### Output Values

~~~
registration_request: 039ae9435af572249db38975b192f1beeac30ed093c4d9f
40bb5236d3521035ab9
registration_response: 03c9cd90478b17e18e1098c8ebbc9642a7b1c576241476
563108391e39b1ba982202c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1
bf7dafca0807eb046
registration_upload: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430
b52d36b1ccc475cc8d7993e8446626bb099af7800aaf9dc9cd6d0e92982bed8633365
c36d78b2e8963817da7eb95c282c39e6716521f9f2dcf1908cb3cb60082e99d1e2650
09d9275f38c11ca420422ac49aa2815d5ed221280430ad4e972171a614bdd899a3e48
31d428bba482f9d7d78a07fba0d271432b7971acd4cc8a0d898c4cc4b07044e4c6f
KE1: 03f86d270a693da19f82b655d8ffe6a26ac2b79ef779de92012d7fad3e15a7d1
5da543212613ca62b7c9e35677951e46fda946f782d75122ca19b2db0ea23cc35b000
968656c6c6f20626f6202496d129c40fe6d255d57f6d92af5c0cf0ba277e8a0e7b67a
61df2dccd9b02c5f
KE2: 0311fb6fdb33bfeda7c01479d378ac90e2362efd1c8d69406be3243c65fbf3c6
e01b9fdbc44c3491e52d5abab23fba7a97c6589898152f0babee3e36d2e415a671804
99afbb55a152d5e8deeb5f19bf5106849ea4eebe5783b45613755e6d4eba236f4e847
6b6387a219e5a7642b7b7b93cc806898098fec251c8a4fec922edc5770b18da58f9cb
e4882389d47cea2165674122d5d1f77f2a9b5fd4bfea427832985e23a269c402960b0
5dcdbbd970ccc0e488ca59f12c5d71aaa4d4b719a931d4c76520475f364bcda5edc97
1af216bfd1c3cbff6f22077018a212a5189254ac88602c5583ec9a10dfa32344fe800
0007904dacd5e6be9eef27b0f94b50605b017126000f478605d9f8e07d5fa988c5373
7c9fcab0085b6d9e84ba237caf3370257cca26175d7cefa2e18f0186a9aa3460a1b6f
KE3: 6c39dc33096cda62c23c60d6e03c29ffda2062400299a2f2a52c7df4c5deba68
export_key: dac545de97f7d8a27dc9062bf42b3b6c02c3cd7a7fdb08251736c5aeb
59a1a36
session_key: b59169165e64e5c00474dcb2b3aea2922a4fe06aa6418fb020309037
5e48bea5
~~~

## OPAQUE-3DH Test Vector 30

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 02
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: dca8ac4c4c4d080a4b441cbde52ac9159398f983e91c0ff1ead4922f81
3665c1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: be560b984659185632de94b35bf6f59ffda8f0601c72f1e4e5e41
d22ec81ff60
masking_nonce: c8c9df3983aa76316a8a491436e41036a00244ce40b29c7035f8f9
aeaead3f2a
client_private_key: 03be3245a3830887fbce88f3eccc26f1639b91aa8f043ae61
75d146de19bef1d
server_private_key: 6a62ab611cc2ea77a7fcb3565850ac22c6d3a18b19541fce8
3b070cfa802882c
server_public_key: 02e1249c0906886b33b0ae59c981001448f2541fb718a158c4
b4f37d391e813fed
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 862a717c0bb5285de381a7d49ba23557dcdf2f408f7b75f032c4226
1d555a077
client_nonce: f0c231edf5b97f8c6886c26a5f60147c7fcdac76fc29f6562eebc97
af4d5d45a
server_keyshare: 02178e9554d669786c2e9349f1e178eb84961a7f8073d9ecbc5c
f52bc2fef7791f
client_keyshare: 026ec987d3b7ea3ef8cfdca092b9d6994d134e933a5fb7892953
35d5f6956399b6
server_private_keyshare: 9269aa286624945b3ff399dafe30f3edd53adf2184d6
8c94007a2ad0ba0472d5
client_private_keyshare: b93132abc198000cabf47020290b885f6bdef29aea8a
6169bf50dca978827f64
blind_registration: b93db502618c7ed6facd1b2d033bf401d74b2c8b13b2da213
802025522072622
blind_login: d30953abfe724ce286487ba13f12ffa86adb64f66c99f58a465d8cd3
16a5d496
oprf_key: 8f811da0d5810756052762d6061215c3e13e8abe75f2dba291e830d9dcf
a2cd6
~~~

### Intermediate Values

~~~
client_public_key: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a264e
65baa2434709f808
auth_key: 2a21ddfc9f9ef354ede473b1841c61b56091faeb0d56867ede7d40fa9a7
ffbb5
randomized_pwd: bf91e6be126cc5d5386accf3ee28be9faacac99a7c715e3d01cc2
6978fd4039e
envelope: be560b984659185632de94b35bf6f59ffda8f0601c72f1e4e5e41d22ec8
1ff60f9c21a88bb8070c7a4870bfd36773b64a6e77162c60873e2304cdc6ba8286a47
14ebcaef275654e13d38a167a91d7cf89a037b20d5c18235b9f3faad55a4f6b5
handshake_secret: 5e940bebc34e2fe2ab3e4fcac683c594f3691cea77f1aa02522
d476507136535
handshake_encrypt_key: 9b0c4f4fb660f6dd8ad268278673fced3f8452f25b9201
79824aef0166b5b6ae
server_mac_key: e380b3517496df4fc34cecf13282cbc8cb673aa8b8d9f8d77a010
742146e6fe5
client_mac_key: f36ef042a728b8564553293cc778c42b34525e07578cfdecceaea
e2af71e821b
~~~

### Output Values

~~~
registration_request: 037a055d502f2a882c021fda1ec2fe8e5d8cd0d2a913e5a
03b1e27e0fd06308275
registration_response: 03c37a7ddb6f23c6af97247bba7bebc62a71ad1bf1e2cf
6fad1bd816732070c4c702e1249c0906886b33b0ae59c981001448f2541fb718a158c
4b4f37d391e813fed
registration_upload: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a26
4e65baa2434709f80811b7eb6d15140bacbb18c954bfa176f9819e105802ed2eb3441
ef6484a935df8be560b984659185632de94b35bf6f59ffda8f0601c72f1e4e5e41d22
ec81ff60f9c21a88bb8070c7a4870bfd36773b64a6e77162c60873e2304cdc6ba8286
a4714ebcaef275654e13d38a167a91d7cf89a037b20d5c18235b9f3faad55a4f6b5
KE1: 02e532d2687a979f0a75112437e1f4c6d5411c555b2330a8d6c45c7c7c657aeb
b9f0c231edf5b97f8c6886c26a5f60147c7fcdac76fc29f6562eebc97af4d5d45a000
968656c6c6f20626f62026ec987d3b7ea3ef8cfdca092b9d6994d134e933a5fb78929
5335d5f6956399b6
KE2: 03895f049933a11baec47a6240ef25d45a150be742c46a1fafcecb1d286aec5a
0dc8c9df3983aa76316a8a491436e41036a00244ce40b29c7035f8f9aeaead3f2a77c
2f90b224115f60a13f2d5a71ae1b4ea6add852c818bb94a02f4a7417632c5cd0f0c41
e87601e077898b5e2b25c6d2336d9f2b58384a225b8993dea499d5c8156d14011d6cf
f78c26f103d8b8dbabbc7b587e702b358d5a20c30ce127925e9b08e7b4d3acc9a1c13
d8fe07bb3619a0be799307c6b463bb6b2a764f5db62e59ba862a717c0bb5285de381a
7d49ba23557dcdf2f408f7b75f032c42261d555a07702178e9554d669786c2e9349f1
e178eb84961a7f8073d9ecbc5cf52bc2fef7791f000fa8ef70781cd05b0711e77278c
87e4267a355b70cfa90ccf69210474178db4ac8c3b0d445cb73f00ec05114700a1c54
KE3: eb9233923ea58877b958553e860fec7721f367ffd1b6a37d01ab7454ff1d806c
export_key: e54b8d82f23782f4bbf7fa4f63cb4fb84096a7de28ece53f5bf40da50
5697a40
session_key: b2af2995c6c177963a066c23b26ef750710a0344b8de57564070f7f1
b57c6de5
~~~

## OPAQUE-3DH Test Vector 31

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 02
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 7f7b085a6dd65b2336cf2152c3ad9b17d4220a0ff2fe6d63ee20335837
df3329
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: be37b298e8c5c46aa08e6fc6d816ad4b36b97a2db7b670c1ccb4e
bcadad20477
masking_nonce: 73ff4d5ed3f2d1662316a9dbb7f1fbc5de9df5fa10d767e94e267b
e4b7e74f01
client_private_key: eb7d0ea4bf06b78e3ed83cb2d3feb9683cece55d800eb5196
e9304e50ac61518
server_private_key: b4cd2e42c0bbef01350751994440026574a20f677965ad056
1acb622a32651dc
server_public_key: 025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a2
5b74538d149fc226
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 5d87ade9bd39d623e7507cef77f5e0261a0dcc5f69431a0f61cd68b
7122f0290
client_nonce: e565ffa2b4aaa7dedf48a20dc758dbc5a8a3989757d3ded74daef4a
6f986448b
server_keyshare: 03981bb9a42c6f60750d2c9098ec0e64d52dc1ef0b4d02a20b2a
e9ce40b425a389
client_keyshare: 02736055b3c97c36bc8e7bfe53ae65bc38c5be6b46adf3d48681
df7bcfeb96770a
server_private_keyshare: cd95a821cc128dfb687ff3f9e730721712454f271dbb
f2f76022ae85ae56b481
client_private_keyshare: 27a18769e08a1cfb22e03d2d98e62ef8ab50db505d5e
28afc93cc3c289c5646c
blind_registration: e1891039c8ca2bb5a8591dfa6e02d8bf4bb7eb3e3861cbe29
cd03197fd5f6733
blind_login: 9ed684a129b5e704cdd2a770bcc863c9f1f44d7e3e90c233aae441c7
cb8da45d
oprf_key: cfa04176753d0b38555dde5205b8dcbadb069510b61ae5819430fbedd93
b372a
~~~

### Intermediate Values

~~~
client_public_key: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b00
3b652dc03e8b5304
auth_key: 5654fc11468d38a1a963c8f51fa4bd0f082be96a76aa750ddf97646c787
6a5f6
randomized_pwd: 19c0377846322b2147dc14ac0014036e102b8458238f117bf5612
41a4cdf352f
envelope: be37b298e8c5c46aa08e6fc6d816ad4b36b97a2db7b670c1ccb4ebcadad
20477eccda5b0bc3320bec5db504ec64b2bdaa22f7e83a668d894c2e72e816a734bc4
500cd039810a832de1bc2a769c0ef5d3cb06fa49e5818751571b42e176607508
handshake_secret: 9e01e6b408544997779441b7e42f31dd45ee38edb08d55b2f5b
4cd5ef0790548
handshake_encrypt_key: 110ddb279a11da46fefa06a565abc650230ce9883e1964
7463c92d057d11731a
server_mac_key: 52e714943f9b85c110fb523542d5a1e63516b63dd4acfdfbb36be
2075fa3107b
client_mac_key: e8ad048b660269216d7ab6a65ee1061a8fdee4097a7567571d4b0
2e8d5c1773a
~~~

### Output Values

~~~
registration_request: 029ead8cb71d9f802fc71737e16f75eda7843e5b961c9ef
0bdf8da0cb97a6364db
registration_response: 024d8f3cda5f4dc58936784c6b5377bea3c819c72b12ca
3d90d59acb74fe183009025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a
25b74538d149fc226
registration_upload: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b
003b652dc03e8b530443424bef487a5b3f29fe001d5e172f14b4320537aa10a63005e
201e98e6ea239be37b298e8c5c46aa08e6fc6d816ad4b36b97a2db7b670c1ccb4ebca
dad20477eccda5b0bc3320bec5db504ec64b2bdaa22f7e83a668d894c2e72e816a734
bc4500cd039810a832de1bc2a769c0ef5d3cb06fa49e5818751571b42e176607508
KE1: 03fbe22a5b37f7345b2370c51a5290091f5af7b21cea757ca017b2a32279b543
f6e565ffa2b4aaa7dedf48a20dc758dbc5a8a3989757d3ded74daef4a6f986448b000
968656c6c6f20626f6202736055b3c97c36bc8e7bfe53ae65bc38c5be6b46adf3d486
81df7bcfeb96770a
KE2: 0399d8305f2ce775a6cf3f97a83aa67b2b1e1fe01866f324eb27263bb46dc0f9
fb73ff4d5ed3f2d1662316a9dbb7f1fbc5de9df5fa10d767e94e267be4b7e74f014ff
39c134da493d71343eb35013108546f149432808fad33aec65629d2d9ce4d6b288ec1
6b3fbf51de7c4a049786d270050e3925e0504efd91ea52f7bead0814ad20402679bca
eaf43e488ab9af1545cacca3578a79c1e9404e7401f42085dfbf11fa18c9265c54b3b
928dbd7167000a5c6bc1338d8c96c3e6e6289c812c50520f5d87ade9bd39d623e7507
cef77f5e0261a0dcc5f69431a0f61cd68b7122f029003981bb9a42c6f60750d2c9098
ec0e64d52dc1ef0b4d02a20b2ae9ce40b425a389000feeb52595f8b5ad3920c1d59ce
375a1a2a944d0ca4b28328547d65a23e9603d540813aa9b61bfbf3bd22e7a9ae1e8ea
KE3: 7055a1786c3c39a920bc77558911719a2feeee4270fe38ebba22d8f09910f90b
export_key: 2b79ac3f3ee4e6f097f7e589075575856af3a1b203ccc51b418e5cd4a
07dc912
session_key: b26257f43cc2012162126a2640e03e79de4be7cae81542622a1c7e10
e7d11721
~~~

## OPAQUE-3DH Test Vector 32

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 02
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 480a89408820aafa632df740b00cd8b002ac00086bc9211fdab8bfa95d
2ad5fd
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 471701d52712c910049f9daf2852017e785ce123d9562769ea055
496ac41c997
masking_nonce: b3fb4943667c6106d10803ead63c46128dc9f1737b61f3de206f07
45f949f999
client_private_key: 02c14f564a29a05e39d4b9382c20686e41faa8407f03f5d2b
2b111efcb64be89
server_private_key: 759ebff988d2878fc2ac6619807ac6625d0ba08ab0d6c5a67
e15fdbd8e329839
server_public_key: 0249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c5
e37937a9187772af
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 4eed2237b8fc1f9aea48e112847cdc4a3d9867b0c523bbec033adb9
68e5ac898
client_nonce: fe61b550c07d1f74f56c99d9f5e7e74d0ca6eeeadd324d1f0076696
f9e66a47e
server_keyshare: 03a05823236f8f28bd60569e51b83712e6371b7006059bb85422
16c9b9ec73ae8a
client_keyshare: 03eeb46969c8d3c0ff2160547e2ab719958b7e8686ca4d9b12f6
04883194bb90a1
server_private_keyshare: 3fe67cd510f555773e65e85deab5aa1a8b54deb7605a
6dcdbbd0fa19154ba659
client_private_keyshare: b61c995dc5041f841785ac17ee8510cf3adc1db17814
2267fb32cb31f5faa46f
blind_registration: 3edf1af7e06163a5711bdb94b2df8e91003824a359d0902c1
4ceae7aff5a3ced
blind_login: e10bb5610ececbde9ff768f649d22bfb588782c804b553e33fec1789
41510c4f
oprf_key: 263ecc204db759f8518b2cb2e026c43bf51d563906856b80c889a32cefa
a84b7
~~~

### Intermediate Values

~~~
client_public_key: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f89a
da3ab1d4b3f89098
auth_key: 3e1cd2f71ccd7343633b94ac259e1b3d8fea684d9e0570c88e41f809d16
2755b
randomized_pwd: 25a1b355f6bafd8f26c8739e81df14cfc466d9961c765779de48a
dce7ad0f12c
envelope: 471701d52712c910049f9daf2852017e785ce123d9562769ea055496ac4
1c99793e65765a55bc0903531ed834e7c44744871638e818d7d770fd099a4e3c78d4d
5a4119040126166f137ff8b788ac56bf24b7aa706c8e458b609954651dce60c9
handshake_secret: 356020eff008cc7346cd9d6640e52ea2c88da63b2afaebd9541
d78380ef4fb27
handshake_encrypt_key: 02d2724f9d9d6dd75b3f73915a79ef3c67d9c9a719aac9
28797b63a2d30623b5
server_mac_key: 657ef04028a61b854c7a2964215c160d0ecbde0788934073d7c80
15b30d84b82
client_mac_key: c477f239d12bf21a0cd23599f4bc6f7dd047442f11352f2f0f10e
a0823530752
~~~

### Output Values

~~~
registration_request: 024ff8b8c3636b93127c0c5350c4d2e64b47c78837d6edd
ece7dd67a260bde8085
registration_response: 02b553b15de8c06a8a37dbd2c8a5f7887e6fbc566adc65
b9c5bfd928b4ba84e07c0249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c
5e37937a9187772af
registration_upload: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f8
9ada3ab1d4b3f8909805ec1d8daa73f13643575a6cd8eccf0e2fd83f24b8427308add
4b947d56c37ef471701d52712c910049f9daf2852017e785ce123d9562769ea055496
ac41c99793e65765a55bc0903531ed834e7c44744871638e818d7d770fd099a4e3c78
d4d5a4119040126166f137ff8b788ac56bf24b7aa706c8e458b609954651dce60c9
KE1: 027694e256efc51327333fba8ab1927b511c4152f93ddb0771370995407b4b25
fefe61b550c07d1f74f56c99d9f5e7e74d0ca6eeeadd324d1f0076696f9e66a47e000
968656c6c6f20626f6203eeb46969c8d3c0ff2160547e2ab719958b7e8686ca4d9b12
f604883194bb90a1
KE2: 03bf099eaf5dd6d79aefafe7d5d78e8861ef676bc0e2338161503dcd6f83cd7e
8bb3fb4943667c6106d10803ead63c46128dc9f1737b61f3de206f0745f949f9990c1
e77e6164e1e9d051f44973c41dfbc7ec25570cdd988cf5242abcb263cf555687ee9cd
a65e3e32c5cbbaab8c67b1af9d8f6bf0b0b171906d07f451dee32f6127b3e0a396435
25508e40a4dc2121982bedf331788180846513497a09e982cd26b789b1e12b17ddfd8
91cd50a304a948ff5bd0cf206072bbc95c4191aa5bb417134eed2237b8fc1f9aea48e
112847cdc4a3d9867b0c523bbec033adb968e5ac89803a05823236f8f28bd60569e51
b83712e6371b7006059bb8542216c9b9ec73ae8a000faf8083bd50717813bae4ccb51
bdcf6eb9e28b09e0cdc739d4761cbb643707b3d5ca413584252967410d53fa21cca53
KE3: 2d7fd750fc7c745519ccda0a16739dcca6c0b7840249e842c1e88ee4725cc232
export_key: fae999d5e1e9a1a4da3441f2350af64ac65d2c8d4eb478ff9d0d6e370
ca1464f
session_key: a927afa80f591e67c8682b085f569cae857f9aef025c6c5fb8528a05
cf474ebe
~~~

## OPAQUE-3DH Test Vector 33

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
Nm: 64
Nx: 64
Nok: 48
~~~

### Input Values

~~~
oprf_seed: beb10ac3b42697e6051e52a53d35efe2fc47ec41b073d12ce14498ca16
2e51894adb660e8986bd7d688e5954e23024a6ea4cfcd7e29a289026df92c9cfcb3dd
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 3eeab156aeafbfe321af3f9b0cc37599a4dae19e4efa1dd237b60
3a156e7f989
masking_nonce: e2d42a43bd2b6116c1a01bbf3b0f402b21b74215854da1ec99ddd9
3fddd67bd2
client_private_key: a052da1e7263802eb5ea90bc30ebd07510b7997e0563f04cd
b0173a862ea1adfe5ebc2d261008f3dfe97647b8ae9d6d8
server_private_key: 32a099b199f3eae54592db460c87aa23e9dc4f969294ee264
5b5184d63c0e7f19fcbfb025d7dd9e32e4906883081c997
server_public_key: 02094306eaa9c62c5a873fee4afdf81c91a91556be8286e7c8
f5fadc077f810adb6bb760faf2e46f85cb0b7649ebdfc524
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 293a21b2cd156f63b878ae387145e13dd2cc825a3ae7afb90b00529
bb48e54a1
client_nonce: d74391b27c45ed6d7474a131b4647492fbfa7aadf7a2c3ceec4b73b
7f790f159
server_keyshare: 0218bb6548593c38236dd6991a1c556a5cfa81be6c235891e5a0
0cf4eef1bb3ab6d653e03abcfe1634908971d19b9959f7
client_keyshare: 03f58c4669321d580f98b4b166fbccd6da300ef7c4f0fe19d557
6d3debceb23e50b5405ac264c31691e4517154d993fbe1
server_private_keyshare: ea4680672ef4148df846b9ad206a7dbe9494ec584139
b85ec522c8e1524572ce5fc608d150037efb2f7a8940d9e7535f
client_private_keyshare: 9f48d31a5dbdef09d8fbef92e6ead8f67fc2d6b4a976
38ead320a94d15f2cf3d3f2dd9c2f64d068f4a2a6aace580d391
blind_registration: 1cb9b5ceeaff77653d67f2a897fa9364f72142c751dc724db
566bc1edc57dca409d1c2c7f5247c62530ba0d92b779aeb
blind_login: b1cd2d3b0027787f8d37c70cf5cfac66388fc090290dd4a2ef28559b
88a3654fd3ad4d159273ad92f8c9b0f154e87dd7
oprf_key: 46d4111433f6dff59e4416c66c62a1b660c0417df102c47562cbeed2fc8
e02bc0fff80d6e9731bccb2f65c16bbbf5a42
~~~

### Intermediate Values

~~~
client_public_key: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132f2
2abd78a05172adde74d97f453b902fb2c454718c91fe403e
auth_key: f5bae69be60e9fd74d576bcdba6b2decfdeeef3449e6e6e1e3a0a4ea7be
cea2510a24f44c83cac8b95d233da18540d8c6b4c485d6809ff7a088be9bc41cb58dd
randomized_pwd: 7a3de06fc6a8760d7b191e8c7276dc30c8759df3d3e6d62608f55
a4c3136e5386e8aea6988faa18afc5eb2f8a9983887045a421df22b7f5bd25ea2c11f
347584
envelope: 3eeab156aeafbfe321af3f9b0cc37599a4dae19e4efa1dd237b603a156e
7f989c022b97d98026dc42e5cd49846b0232d8bb3f47446e7545670149b07ad7711da
9f23dad096b382ccd88f28b9baa8a8a8e8bea6db90ab9eed81fa9f54f8027b17951b1
227dba04410074cf6de71b600f00828b43056652037c78a8248a678356dfaa984fddf
99c3b021fda54808820518
handshake_secret: adf7938f9464d6cdf6e40d67a0d3c67a875d491d693db48a843
60fa5c7a20a5b5621f3a60381222cc85661e6c800d8d37cebdff6e5b74fccc07e8b2e
ef8d127a
handshake_encrypt_key: 2f06fc9f4cd70407dd6f1bb2f1c0789872d00622c154bb
329a49e269459ebe6603029a18a386ce72a809717953a8410f4b484b6e02a7d5352b7
3ba6f1cf461e4
server_mac_key: 870c5a716263c7e815eb4ad1ac30b2301e173090f89f8bb54dac5
9ffda4c487d5aa85e036469452635a4c6e0f677f6f36108256575b518912d2b9eafc4
1255ae
client_mac_key: 235dd0d8f601f4ba6251cc97858300a0af80eb6b9f2281b8a5212
2a0220a3c687e909ec8384e16ac950d6ba7b72d6bba3686152ff6d5277c7a5a05ff6e
5b6f45
~~~

### Output Values

~~~
registration_request: 032b5a44024063a5644913f145e01c5b787a77804a5ec25
588320d5ecea9d524c1f9321b9ae76a6bc168b1f99e7305b9ec
registration_response: 023980ddfefbc0d729af050999b1996e41c0a54816ff1a
1b0b2823ead24de0a07a893cb8e62685a7173ac52caf85c821f802094306eaa9c62c5
a873fee4afdf81c91a91556be8286e7c8f5fadc077f810adb6bb760faf2e46f85cb0b
7649ebdfc524
registration_upload: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132
f22abd78a05172adde74d97f453b902fb2c454718c91fe403e0c46eb0f213ce4eb3b7
3fdccf63cc47d6c93ca5a854f3c57f3b49142bc793638f49dacdf1bbf127abec2c0fa
286b741192a7dc8a55f156c44da36fe41a25faf93eeab156aeafbfe321af3f9b0cc37
599a4dae19e4efa1dd237b603a156e7f989c022b97d98026dc42e5cd49846b0232d8b
b3f47446e7545670149b07ad7711da9f23dad096b382ccd88f28b9baa8a8a8e8bea6d
b90ab9eed81fa9f54f8027b17951b1227dba04410074cf6de71b600f00828b4305665
2037c78a8248a678356dfaa984fddf99c3b021fda54808820518
KE1: 03cc36ccf48d3e8018af55ce86c309bf23f2789bac1bc8f6b4163fc107fbbc47
b92184dbba18bc9b984f29c7730463fba9d74391b27c45ed6d7474a131b4647492fbf
a7aadf7a2c3ceec4b73b7f790f159000968656c6c6f20626f6203f58c4669321d580f
98b4b166fbccd6da300ef7c4f0fe19d5576d3debceb23e50b5405ac264c31691e4517
154d993fbe1
KE2: 02e611c63390d2dcb729d941be385aa6a7000aec51db33ce8a374dea4847e0a5
c70f36b133acfd628ccc68d019712a574ce2d42a43bd2b6116c1a01bbf3b0f402b21b
74215854da1ec99ddd93fddd67bd239da742d19ea722e5a99996cc70165bfc012d816
bd51365c464bed0f7342a980b3f529be5aba66e682b376dc991e62f957c59e817c09f
e0fbb54c9f7c31b675cf5b651441095e489480131eea0fe539b13435b1390633d57ef
297a70ee3a9efc6602f55943669548231bcc7380176af93faa4636ec4b8d7be54448b
91d50a1b45d8778b62880ae15f74f69a915ae9a43154e22169893241556319e4e8cbd
801f4f386539ec6d9cb519aef5dc19cf793922c093a879d021a4aa863bc494d38b6ad
1293a21b2cd156f63b878ae387145e13dd2cc825a3ae7afb90b00529bb48e54a10218
bb6548593c38236dd6991a1c556a5cfa81be6c235891e5a00cf4eef1bb3ab6d653e03
abcfe1634908971d19b9959f7000fc2caa91e5b33c2d942fb34f9b537f80a66be5426
911c3457f51862cc247877e684ab8558d5569126753cbd79e109bb0277a511e1810c5
f3d43039c77a5c0e57cd3d900eb3ef6b3a8ed718e5a1312e9
KE3: afedae80de7270f58f14ce58b30de7ea476888e016ff0ebeb777e3d71778c362
2b94c0398dc126025fa2500880415fba262cda14be92ce2f019af97561bd9098
export_key: 78ccfdae5b3a53da59acca3948632f8a0fabe6e078ec0949bd1735f48
e12147bffdac90a5c2136b0dbdeda8b223fc83401a40b1df2011f2aa58ffdea39c765
e1
session_key: 2f77adc009cefd0a839bd9fdbe00dfcb63124ac774cbbd7fdc4c788e
c34f2de60ac0e5e99136ee9acb79360673d6eb9a74d85debff6cc1f09afa4f25669b1
fea
~~~

## OPAQUE-3DH Test Vector 34

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
Nm: 64
Nx: 64
Nok: 48
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 640f999af3686324f919a5b1dce195a1bdca03f6ec65647c5beea478fc
ccf7a94d6217e8575dd70d97904a2e2592468ff70aad1a796f2161a9513d0c35455e1
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 3d3a7e297878e15a21bbd0a04e9af8923fbaad2ae66244ba153c6
5c16bd52d19
masking_nonce: e37668d36ca5e43465081d1269c3263d5df4caf14e67dd032fb837
28c3691cf8
client_private_key: 194f9a720f11c3f0f1613cef116e218267201ce0aa4f4f55b
68c5393aaa4101699ae3b0dfa984cb954913dea02087eab
server_private_key: d650dcda20f27d7bf4673d820cbf71e498ec903e4b3959af8
52f6d9edfa68f06f4d7ff89d5897912df4f9c633a6d925b
server_public_key: 030278df9fe8759989883c2ef9047b2449abcdbe9f508aad83
f227836ddda86b3dfe0aea33995cd76243a4319800bf8ff7
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 815012d1a13337bebc5c63adb386376cc81351657d969edfe09e4d2
048c72c45
client_nonce: 12057fc0f4e3e52951458bc3a0b37d95a5ea0b5832712b169588eb8
f29eabf73
server_keyshare: 03ba3e99f4c2f39463fe214e7607ca3e9b1f6112d565d80bbdb3
88f52437ec89f0da6b80279e10382bacc7cdab25a3a830
client_keyshare: 02313f18385e0f0c3c88f3e60178a6727c9023e1044973eeb676
b9a17a398424b1074d5e35246fc25be83028853dc22f1d
server_private_keyshare: 418e3a79ede03e259ed68dcdfc20e12ba1dee7f0f3f1
ca2fc4be708da7456b2d769111ae0ddc0a45eb159eb5dd3bf78d
client_private_keyshare: 4de164be05c824711f0208bc191f1871f41f874af27b
36b15b94b87abdb6bcfbb35769429178d602612cef394d6477f2
blind_registration: f69c6179ddb976b981abec905a0bdb649e99e5441bc707cfe
3c966a87b253bb94ee1be97f8d0e0f99e4862e483b7e00b
blind_login: b71e35cbe26e4ab93794edaa2ea66295456005572a7096070f6b551f
0032de9749f7c6675eec2432a64c88d99c56fe1f
oprf_key: 17dd112310250b970793add4f66b282f6cfe897ef2b23c3ea329e211c00
457358cdff5666d771243f6cf840de47579d3
~~~

### Intermediate Values

~~~
client_public_key: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1b0
a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff59
auth_key: 6125a9980f29e44cf4f11f8768f7b0a5d6ac48df20744706b74160224bc
23aba90d5caeb2ad370af373dc19828671e72ee1d73df636712255fbfa2f6979c4e69
randomized_pwd: d7abfb75209139cf2dcbf8f0e286ba6e8539e9213b21548cbef7c
7bd23d351299fac735657da8388fd3769946591b5ac6c60ef1cb06e168ae647358db3
d55a8d
envelope: 3d3a7e297878e15a21bbd0a04e9af8923fbaad2ae66244ba153c65c16bd
52d19f1b8c0c2819090ee52c8a27c2d95c8a39ea62a8f2a1c31f2f7b41390cc93c33b
a44b16247d69c96080089d9ddb15dbbb3d77b7e64f4fcd5c906b2ecb03b7dd2aaf6b5
e7e62507de037aae56f02b0baf69d2676bb6ae6e3cbd10ea7f2648c2ba826d999c618
2e77c15c59cf6461d37099
handshake_secret: 866d1c8338e9e512f12936ab6936a69e6701faa45e62ff6a9e6
76133d4eed5062631068eae2e8ac24e1e5011df5fa02800719be864a66635a2986024
a09a8d86
handshake_encrypt_key: 177d3304ea30e45e0ae9c23805ed3ec253a734c06fc26a
8e4769aebc0fafb813fc15743c7b1eca07fbc67094649b51c1478371cfa5b514a1f2e
b96a5270338b0
server_mac_key: d81ccff3ee63aa7e0c4338daf3d26287f434da478fd374988332f
8a7ee9d93a57caaa7a8348b1fb5bd9c281af7758e903c43686c23a4de05d9022aff05
ce7f5f
client_mac_key: d00c50bf828bf23a3f0e8b95849d5bb52f5be0a7937f076d2f6b1
e315c2d18ec856a079157f5bc286d9a06ab1f00fa8a9e44212e0763dc9ce1e0efd439
f4879c
~~~

### Output Values

~~~
registration_request: 02bc8b8b2d8b96ba8f527f59dc0054349f0fbf4c7cda280
480d643909db6a8dbd4bcb455cc374050d8cce29147fab0a020
registration_response: 0221657ecbc73b1307b23125dc470f66ed99526833c17f
39520fae6202a8e951a54334e19cf0514ede5fb784606039b3d8030278df9fe875998
9883c2ef9047b2449abcdbe9f508aad83f227836ddda86b3dfe0aea33995cd76243a4
319800bf8ff7
registration_upload: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1
b0a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff590593860a6e70bf7c24f
842f664a51f866234f71a973ee8a5e50079d0ea1ddf46c043f53ca1b2908b3e1914c3
a55427ba44b09256680d97bdb37745d2b4462bf33d3a7e297878e15a21bbd0a04e9af
8923fbaad2ae66244ba153c65c16bd52d19f1b8c0c2819090ee52c8a27c2d95c8a39e
a62a8f2a1c31f2f7b41390cc93c33ba44b16247d69c96080089d9ddb15dbbb3d77b7e
64f4fcd5c906b2ecb03b7dd2aaf6b5e7e62507de037aae56f02b0baf69d2676bb6ae6
e3cbd10ea7f2648c2ba826d999c6182e77c15c59cf6461d37099
KE1: 0258fdc4ba750f504274ff4644f2f43a75759b77adb1817c8686340bb28059b2
af91d82801b94bbcb8326cc2e046a4df5112057fc0f4e3e52951458bc3a0b37d95a5e
a0b5832712b169588eb8f29eabf73000968656c6c6f20626f6202313f18385e0f0c3c
88f3e60178a6727c9023e1044973eeb676b9a17a398424b1074d5e35246fc25be8302
8853dc22f1d
KE2: 036abecaa6e3d83acbc1fab89ea644b295e27db1483c252179ec6d7262c0df04
bf25da68b0cec348229734bebe50a136a9e37668d36ca5e43465081d1269c3263d5df
4caf14e67dd032fb83728c3691cf8c7d320d57547bac4a459e419072afb91e6b5d892
e2af83d49e89df18e54503d1ec3e08daefbffbca02816e16829b54bcbb9aabc9a9553
8f338c6f7f786ee846e09a5bbfb65533febab20a97cc3bb59632619bc24cee27bb3b9
0cc424367b7cc823c1483b32f7b9f504ae2a976934100c9b8b7aeb86794eaf8653b86
57e41580229ea1bbc8d4be53fe7d5b14939049dc34e31f4986433677a4f10ea332286
96b1225b4f3f411b383e73f5913f140a89d53bbc9a6e9ba820136ec6a71e47d5f350b
2815012d1a13337bebc5c63adb386376cc81351657d969edfe09e4d2048c72c4503ba
3e99f4c2f39463fe214e7607ca3e9b1f6112d565d80bbdb388f52437ec89f0da6b802
79e10382bacc7cdab25a3a830000f693f933fdebd5562530fe0ddb9f3fa7689b8d8ba
bdbef59ea4be0950e1cdcd595101aed70aa60619caaa5c16bde228bdf7ab089ae40d1
3313c99fcc667de70d5627151a7d13a5dc8009aec669d858b
KE3: 5ee0b226dea45969a341bf68b5db2efa281e3af87a093fc33e3725a1e0f08929
a0ebe4d1504ffcfad9e4435bb5f1b66b0cc3dfacd094630239fd4d9283c09e1d
export_key: 60056150c995824db0ee2d19ce26c539e905732a63d4303ab0f2a6d59
1f1eb223300142eb6dd9e03ab895b96b92451e4e3a1da0f588c10ffbc6a516deb6956
0a
session_key: 9af68830e6f83d7817d1d163a3b4e0345f1399273495596c309cfee4
b2e6924365f6a611e01c1761299a35e0c99cffb298bd5b056a4b5bc027847765e8748
c9f
~~~

## OPAQUE-3DH Test Vector 35

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
Nm: 64
Nx: 64
Nok: 48
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 8e252ab570f6b5c498ea83ee732c8dfb1862300010b6f78e5ce27c8b26
f122c6240c0fcc25fd6f82899bb72605a60c047c44a22b75ef4aaff304f407eab3bf5
9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e1652155f9d7fb49b4075645a89c1c9986562a3f5598c3181fbf8
7686f5a2e62
masking_nonce: 14a2164d3310b595689981b58a47cdd52a8a7e5b6c5f7ea5327925
046488a2c6
client_private_key: fd62874455ee10870acb5cd728e1e21943e18c3afc1fc668e
18c48250da37feea7768de6574b8b152dc64790a0fbd8ef
server_private_key: 9364031f78d6cfc1aec5bed89c718d3c8ff87115ed1526fde
d4495afe150eeeabc6195e48de31f2a5b24f798faea51fb
server_public_key: 03b73b7125c1d9517a42d63bf21b0c3eeed2b4f76005f72478
de3440dda2a2a580ef58077c145719505764689842231b65
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 5aeb5b6767569fa0b0f2e9f532d950d57e93504daa86e7eb98c9914
e11f84511
client_nonce: 3c17162106541a7fa8a078a71dec020fb9f5c3c7c55eba13590023b
477a3461d
server_keyshare: 02bb887f84a3158bd1a95c26114059d1064a69dd87c8813ad1ab
19b0cff29b48d0e945af14537ac16d8f4160bb027fdeae
client_keyshare: 03f07983f1b0b62e778918e7b15aa899a5c5c9fce3af75c5a424
e114f3c9bc539cb3b290c4c4705829c21e2185ab3eefcf
server_private_keyshare: ca2d8735a3913f363a1f95b46cd40278b59de5c08b9e
b5a845eb4a9d49d86edf2505a0b18bf6a4a8cd933a140349496d
client_private_keyshare: 4ae162607c624388974273d4e1e77d96184bb50a0e39
a863c7c69376f4571ba904d7c7db930f11f0789361e5e7db3327
blind_registration: 43ecbe67abd4b7d730867cbd85f758e9921a8614816cbeb5c
d80d0aaefbd98c6e6b26643af7d92581e62be316ad49bc3
blind_login: 087dcfc60cb02473a6148e636c3e87edb4da112f01b7bb4ac4e13e81
c6a757191c9256cc0c7282d7b27fb62a60b63756
oprf_key: ccc3b06e0951d90ca1a650e46adff561370e3f0c63d30f166b4876daa95
2a69d0fd6b9f6224a36d0742b434ee446634a
~~~

### Intermediate Values

~~~
client_public_key: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab18
f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef0
auth_key: 7a5ff225b2fa269726c3cb32bf7e90a5a5c6768e494108914a9d576c0c4
b990a798f56b93453f5e675a479f7f1a91aa0f6dac7d913dadf05a87be39616d011ea
randomized_pwd: 7191b7c8468b2f999d5a4dd05624f7a863059f281412c34fa0e78
73ca64c8b57bf0bb928b0feb767dc0cc2a4f8e15413bb863d714ffd118166a1fe4407
1ac9f6
envelope: e1652155f9d7fb49b4075645a89c1c9986562a3f5598c3181fbf87686f5
a2e622d9cdced2931217a953fe4c55ea97ebf09b511684241f2f70c3f865a597b7239
1e71d3c7720a0ddc5afd082f00a4a1fda91712c5f359f225d40258b354bc8cce9a601
1ae404a182515ae143ce297865f57ad42599c35cd45271ab6aefba5784abcebfe03cc
c37859aeee8230f60c483c
handshake_secret: c93dbd78345272018cb1dd8ee664b1d000643450391df67591e
02a26ffdf5bd2ebf2c6a8aa29a2a1fbb8bee0b147197a46e2e4fc7e3da406c465ab1d
7aad6168
handshake_encrypt_key: b688efc53cfdf84a512fa517c65d9683ac35603fc152df
6fc23edb9bde091ef22e8dd55696c783700ac683dc15574bcafdbc290357b54efccbc
01b5b98eb7750
server_mac_key: 5d5b968068d5602b64120c9e8f20b24e1ab0417784a713102d26c
c08c51741f6b9bf71b8d70fa03bdbdfd1c73b349061e0c902cae424c07a91eb9cbacf
dd20fd
client_mac_key: 59b2567c186ef41c86892ce7b91a88b43253771bf930bf63342e8
b14386c7a38aa688b5862034695db9a3465da0636816bd4f3242434ac8674d7e548d9
5e54b6
~~~

### Output Values

~~~
registration_request: 03e0ffa19f9860931638c2a6a3fbcd8e0ec673cd39615a9
d80959edda6fc8d269bfc206586f1a10b46a895f8f17e730174
registration_response: 039397ace4ba63ee72514740cfc5d5009813c4ec52cd8d
7e1f8fe502606aa07aa36c1694b4fbc11ec74b15aec94b611b2903b73b7125c1d9517
a42d63bf21b0c3eeed2b4f76005f72478de3440dda2a2a580ef58077c145719505764
689842231b65
registration_upload: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab
18f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef0b46168c87b26ff18533
1659cc779b95a102b2c1c97a7a15047b4707cde0bf9a6a7246cb311e87502be15ba26
bb98f94243d523e2013f5d98b0a3bd8277510f35e1652155f9d7fb49b4075645a89c1
c9986562a3f5598c3181fbf87686f5a2e622d9cdced2931217a953fe4c55ea97ebf09
b511684241f2f70c3f865a597b72391e71d3c7720a0ddc5afd082f00a4a1fda91712c
5f359f225d40258b354bc8cce9a6011ae404a182515ae143ce297865f57ad42599c35
cd45271ab6aefba5784abcebfe03ccc37859aeee8230f60c483c
KE1: 027b40080d3b93d00403d4e7ce1944644d57cce6241c69181216ba7323afc9c6
2054300441470c06aff071717754a2fd603c17162106541a7fa8a078a71dec020fb9f
5c3c7c55eba13590023b477a3461d000968656c6c6f20626f6203f07983f1b0b62e77
8918e7b15aa899a5c5c9fce3af75c5a424e114f3c9bc539cb3b290c4c4705829c21e2
185ab3eefcf
KE2: 029dab1f20e6a59e6234f17c1f2eed472fd81c30578cafee7f0ab2060b86e392
a9309dd72b902392d70416bdf61f53952414a2164d3310b595689981b58a47cdd52a8
a7e5b6c5f7ea5327925046488a2c6f9881e2b928048679dec8e164f50c9cd6b975377
d1cb9b4f82c39de1cdc5143b41daf6c77f1a7afdb1bfc71ba1e71100ca3ff05f09062
ece5f8b529ceeb30629e8e38cfb92d3bc1edba5c457d2a3e8d145fd72f343173bb8f1
072113edb9f514dfb570969a7bf7b8afb827dbb750ee8d9bfd947e8c12ced4e0a37c5
59f76037a346e6d42d840dd46c204021e48f8eaa51f3e62c16c32e5bb23c9092366e3
f9472ea527d3c86edeae5b8920655c52f4bef5dd3b05ed9e78a9208504cfaecec68b5
a5aeb5b6767569fa0b0f2e9f532d950d57e93504daa86e7eb98c9914e11f8451102bb
887f84a3158bd1a95c26114059d1064a69dd87c8813ad1ab19b0cff29b48d0e945af1
4537ac16d8f4160bb027fdeae000fa1a1ced50f1157c5b6a5acd3fc1a57bb2bcc270b
abb06d28bb271e2224586bf00e9834b288aaea492804c47cbb536cb591709693074a4
dcaec37b2142f3e72bb567d57f811243e07266526a5240836
KE3: c0d6c30d020c3bca62a96d102c9d3779725c2b17020fc9299fac2ec288bb8a53
d2abf77b8b69d288a7f4f37e39de4b578ec9668f5aca2c8d58f565519eeee219
export_key: 110362dde3383750324ff0cfd36b278d01a047141ffeef775ea085a87
644c14b0add828919cf8441629f90d00b3a6ed8f21303b9519f8550b919b8d1ed603b
43
session_key: be4ea315cb6a384b1c454e3d471401fbacb2972546b3608e3bb5b4d3
dc71750bc48b09b996e7a2f9cc68641a1f63fb596ecd4267fde40b5d9e917ad891ef3
465
~~~

## OPAQUE-3DH Test Vector 36

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
Nm: 64
Nx: 64
Nok: 48
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: cdf705a27cad39d13fb419c1357dd1a03dc528b2838fd1221194d65955
4c5e54adfce25be5c79f1a47ba8c991fe72ab43178385b069180dd6f58f644cca5cc8
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: f25e66ee00f3c599aa38144edc4ef9eb3fcae001ea928d9f37426
310b3336e88
masking_nonce: 01041eb8344ea0a627a97dee712e364c08ad4d8dc6562524dad344
509e2520a1
client_private_key: 4bbeadefc59f6beea6a2a9557781f5e37bb6ad6f76e66c82f
37070b975ef988bee3486703e469e30348af71c1050d94a
server_private_key: 8e510d60a068ab453634d9f74837185ea0d5483ac4f1dfd38
2792f1299390d98ffcd4e956fc02fe35df273276b75bd2e
server_public_key: 028beb3ce19f449deb6aa31eb19c661d4c4ba0fd08b4cc1e91
416b0c5b5ae74de003a76d68ac4f59b64b954717c4d843ba
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 372979bdfee525d1b0534f6377e9d1f17adcceb0b8430c1463d0e7f
297d187ff
client_nonce: 7b9317e5b3bff2aeaffbc337d0872f3e28780cee6f1d99f191d9170
56afdb2c5
server_keyshare: 036357745dab9026251b2bfb2ccd847536219da8e475cd1f2dc4
842206a8452c720e3ee24c0abe77452903c64985b76a27
client_keyshare: 02a39a8a45c68e977db2ff70778f0d34c28f7cf430ca1045d4c4
8e6e749429f0f10b226c26cb0ab71bf2445f6b9ccb81cb
server_private_keyshare: efbb63d13c3b79c8b75df372608ee07c6b51dce7c4aa
f335e9d9c353cd09807924175d0014cc8055da3bb705ad8f3e4a
client_private_keyshare: d7c5782b343f60ed63eb22730d7c8a2d3e9786b30da2
f907359ff2db863e2796c0866f3257aca9fc06a029fb3921c93d
blind_registration: da4e681eeb61cbcb455e0f0c71af34cda3415ec62af58fea7
52ae033f75706f6b00936445c37439ea821d4b515d8f9aa
blind_login: 701a9cfae365aded9dc31c1bf34648023fdb53b284f0101d6612f750
6b1471b67bd1a8eb1183844268c128bb84aec1fb
oprf_key: f2ba0f4b7a9294318dbc2587ba44688d0bad3c7a56901c8f839e7c15fb5
e0170cb0ca01946f79a2a818c4956e277638a
~~~

### Intermediate Values

~~~
client_public_key: 024954440156358f8db7a32b042020404c7918cfd0003699aa
1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce906040
auth_key: 7507cead2b6d76ae3cb7f9b996329b43609fda2d0cd9bfb6b5eb8be695b
5c39a8b78d4d4ac6195253bbd5db5104bac78a02520080b737f325d37dc91883fd625
randomized_pwd: 22b18716fc52fe4cd68300851779be88ee4cad287627cbf688530
38e2c441146201b2c9d16a8138efde88c5aef70524dac433d6bb367e99875a3d84ebb
5cf451
envelope: f25e66ee00f3c599aa38144edc4ef9eb3fcae001ea928d9f37426310b33
36e88acfa8ce7d0a9a42fcf021e43b12ada8788ce532074d3e93c5970e0138607dfe0
2135b1f825d9876f90d3c5381326e9dd2cd88dd456b5e162ec4a55ed1b9e4d7926710
2f4e24beb39868b1c3b3444451971c7c04a17b668a2a7d2930d7f9c1ff8f37ae58938
de7281ea1c5b6de2fa032b
handshake_secret: 9ae241dd2e9a22abc2353f5642792c858dca178101a5812eefe
be79d3c449b7e0a99bd1f793ef355d60a2f6192a1eb37f18236ff91b43162753718ed
9ddb6128
handshake_encrypt_key: e0c2ef835367b056a8f698a39f79b363f4f43fac371199
76244fecf47cc9143f227d656798d7bbb03b062a38116902877e90d69029a871451b3
a04a12492a5a4
server_mac_key: 8671eb3b156eae0ab2858dda5bebae296b32d5a5db5b0ee7f5b98
9d6e37e354202cd6b85ad65a8f6c2ff8e7fef0ae999fdae8e2e858461cd930bff1e67
cc5f8f
client_mac_key: 7b46531121397cd3104b08356019ffa4f4982fe2c40d5d025845c
877bc763bc111471931f1a6d0a87f83a3afa6e449d17c4a4b63dfa164fa34e6cd4e68
23eb43
~~~

### Output Values

~~~
registration_request: 03a2e55f8d839d6b162d179f9b4f886337188f731db9ffe
0ac206b54096e6a9a8f30785c33d207ece91c4fb97530fd491d
registration_response: 0337b5fa736ebc11eee695b3170d795ee7e7a880f9b4d6
926f5398188c15c8abe811a72c745e7ea31664564b83d277b0b2028beb3ce19f449de
b6aa31eb19c661d4c4ba0fd08b4cc1e91416b0c5b5ae74de003a76d68ac4f59b64b95
4717c4d843ba
registration_upload: 024954440156358f8db7a32b042020404c7918cfd0003699
aa1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce90604000d376a8a86206ec69f
11f6156104f0c388271ebb6e288c3237e79547be0c81b697c63acd30baf0bd0e2c36f
14230cee83ebcbf1128f74619add17e123d1e822f25e66ee00f3c599aa38144edc4ef
9eb3fcae001ea928d9f37426310b3336e88acfa8ce7d0a9a42fcf021e43b12ada8788
ce532074d3e93c5970e0138607dfe02135b1f825d9876f90d3c5381326e9dd2cd88dd
456b5e162ec4a55ed1b9e4d79267102f4e24beb39868b1c3b3444451971c7c04a17b6
68a2a7d2930d7f9c1ff8f37ae58938de7281ea1c5b6de2fa032b
KE1: 031b4f459c984d8a56589785181e03b93108602ccb92ef3e247651d9a9e72d36
0a93afc86dd79490fa621685779408ba327b9317e5b3bff2aeaffbc337d0872f3e287
80cee6f1d99f191d917056afdb2c5000968656c6c6f20626f6202a39a8a45c68e977d
b2ff70778f0d34c28f7cf430ca1045d4c48e6e749429f0f10b226c26cb0ab71bf2445
f6b9ccb81cb
KE2: 03378f329bf4531c7448e2b3bca2c2beacaa2967b8dac6332bb96b9bd80c843d
1e34c88f7927bfc21750c7367d0bd39f4a01041eb8344ea0a627a97dee712e364c08a
d4d8dc6562524dad344509e2520a13f41f07c3a6f2c51b6ba614ac8a2e79eb142a8c7
dd1d8930b7325e43fbf0e1001d13841f3a223456cb8b634b0eb24bc1ab8b636efa5df
bf029b98f213593b770d80a26ff4034e300b35a5d61079bb180dde5cfb5aac3fdec59
9d5b7263388a478ac0300767c7e15e6efa6c32559f9c96fb815d87c86192055b76da1
01aeee332683bb404b44e64042586b843fde1140919d0f448b0f776d6132761a0d106
2aeeae8862933f95991d3b81819235017832d306b3fb94ed5a36146321b26ee4ef40a
c372979bdfee525d1b0534f6377e9d1f17adcceb0b8430c1463d0e7f297d187ff0363
57745dab9026251b2bfb2ccd847536219da8e475cd1f2dc4842206a8452c720e3ee24
c0abe77452903c64985b76a27000fe2f83feb675429bfff4f855ee99f043e67752fcd
6c87d1b5f194baa75be19ecb868576ff8dde0cf70f3a72e77b0f134ab881167f8ad8f
040b08cfb1ddbd3a08f88fca6fbf404a78b1727484154417b
KE3: 26aa67e26763bea08dd41ca4bbd5a380eeed2c460b16fee171582e9e5a173608
75f40626a15f4043a9c254268714f453da6a70e1fb620bbb24b9de1fb6b6845b
export_key: dd200510aef3a243f4428aa5cabe380d27a8b8dd20a88c3292534a51b
a06c6af5d9de9d43b54396ca9ad9c563bcb3ac0487ca302a59d4ee339de3d45b436e9
65
session_key: 60f3b8b89b5a6c3040053b3b43a7d41ca015596af8a635f9b83b56ec
81b4fb82698ee28a07256edde2cbb6a4877c0079f572809165a09810cdd3aad1f728c
7c0
~~~

## OPAQUE-3DH Test Vector 37

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
Nm: 64
Nx: 64
Nok: 66
~~~

### Input Values

~~~
oprf_seed: 66273da68a367439446a81c9102dc59538e18853d39fca38096d8f1f2e
0dea70a894a0146efcf6df476cd0847ccbd0af4efa8e1713c61c7536318321cfb94ec
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0262a7e6fd5d77b0b04c5ef1ed302c4bab0b4818e9b3fefcc6886
ee6dcb35923
masking_nonce: ce3f6fdd39eec1869f23eda9f9c16229d4ae07618d47b48d6b7fe0
205c8f292a
client_private_key: 01e4eb0ddc00ee9c2e21a17727dd82145f8d42ce298b1b66f
34284b8c5f884619f8ff53ea8f950ef4306d01fe5610b278f19d0acc0e752f86eb4b5
3eb5acffbd5e7c
server_private_key: 0180674b4b34953199004d4c6ab21b6667721b3ce89a5f440
f7f2b6ff1e3748041e66ebdcb789e3bbe63ce391c04598cab4ee6b5ea710911272f2a
8ff2de75057d81
server_public_key: 03018fc6a77bc4127886d67871c03462740fc4d6fe66dc2226
365e994f8392a0b4c43cd6e67ce90ad594cb63c146011dc56b213bd42ef677cb6a5f0
1d0bd9944a9161a
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 74256da53ee823c1cf83f3ce4bdadf2e5785766a62a1b301bccdf50
1c79dda23
client_nonce: 62ae28bb5390b267e4663d10960997362214446de4f323ff806b365
3a1b6dd1a
server_keyshare: 0301ff9a97a3a4733b144d38330209bcea5a6401eb4e08e0697a
c4dcb8369e20d76d32c34b619c424d643dc47bd680c0ef665404643d2961ad051a792
0c318ecd948f0
client_keyshare: 030080bf524d28ba64b134c0bd0c860c8b1f976e55d94eb35d42
aa0cae1935a185c9f7c517875877aac4aa4e909dd5f25cc6ccfe125d031dcfe024597
af1f7bfb5ed89
server_private_keyshare: 01963f6398d6481485f24f7ca088d1bb75216f8de622
9572036ef4b8eec58c7856203ad458e0422acb38d481a4231e1507ee52958825e18ca
ee20f50b2ac1d4e9719
client_private_keyshare: 00e0d68f7382c7400deea8c1ebff0e76870bc490f1ba
271a357887901a9c3be411b68d57be69b7b9c27b352ae86d42a5cfdbbf15984b35a67
33ede918146c06e2a0f
blind_registration: 000de48e5ce653decb9dacdec7bc0aea97cc85749b792cc26
1c551bf7e26c34d252d034137c4fa435e4ee55bb53a5ce21384293834fc48a93c97e4
31b60d5f22aab2
blind_login: 00933d069bf9f5ac0439cb60de65fbe75c0096db58b875f19390d61c
1e3a6d240c943f951b5b3fd7eedb2b9861f5cd3642ad0fa46b92b65fa5e3fe2999e32
cd1822e
oprf_key: 009a077112d891176b71738e4a577fff40c9ccf217daa81ffab5dccb171
652a6b354699f7a004ded89e1eb011d86cbda59d424ba20823680daa9a8b10629f7a5
c182
~~~

### Intermediate Values

~~~
client_public_key: 0201d6bd681715e3d330475e72471c1218aa718d96be735325
1c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf1831f
811d49d120a8d45
auth_key: 1092eb1d54fd516d81d887a37bd0e00df4c6f588b95848141748a49ec9f
85ae3a1b74671d585986771fa5aca0bc9860d9b8290dfd747343812de66a00dfc180b
randomized_pwd: ff857dd0c19fb58de8eaea7ed405ac104d5dfcf89257c60c57075
58c820cad77c54b50bab383d7477c8c2a1abe171105f67c1e795d97d6f217855979df
6100b3
envelope: 0262a7e6fd5d77b0b04c5ef1ed302c4bab0b4818e9b3fefcc6886ee6dcb
35923b74db084f802cbea5fa213c4a03eb660bb35ab03b7c0f8902b25e66c23b85335
2de5f38981bbd80a6347e4e4b231846c1515c9a1605139a129f37a1007d1b4309e4b7
b718d194f035908f1307f8c2c9619437ef672c9bc01f3cd9e4335bfb67e5f973ddcaa
a7881f4a5dce93f854940099b133b223b7acad9a64987529bafe3ed698
handshake_secret: b77e928c3376e7ce958062997c7c4ce1415adc6b15e9a3a7141
58e69f72e521d3002a937841834e78122dfac526674e11bb16d2acbca9fa1f665c23a
61c4f013
handshake_encrypt_key: c41bbb3c0bfb65e53aecce4b206d19706fbf440cd877e1
6e6aa6c5d11ed11cd8c19ab457a13118029053eb3423b634a8ed818614db7245d065c
696a95cd1808a
server_mac_key: d1840c0cf16e7b246890d123a51614f53a49f64bef55f915459c0
d937987f4cf9888b4cd6f4dbd9ab92ed443aa2c5a27d513488338813e488d77a7a334
832fcd
client_mac_key: e76dbcd14d22cc30ec2ff91c4a272abe3c90d9afb66c086caa696
7fe351452660f48c8fda7ce4b46daffc71dfbafc0e75b1209e50897543a7acd0a1222
62d37a
~~~

### Output Values

~~~
registration_request: 02015d0cf2aa22e0448949416bb4b3c246429439d4cee47
a52b3b9874aaf727dbde7f34b5112e91e97e1d98c9cb0fb58e015721456160aadd16a
d4f9a9ef2fa3d0ad8e
registration_response: 02019b6376e69e60d1da3d7aca82faaf34bec65c155ad7
cd232007f118bb83178ef81fdda7ee2c85f14c1a24bf786362db41cf019d2a1ed4dbc
1b64c273388d9eb45c103018fc6a77bc4127886d67871c03462740fc4d6fe66dc2226
365e994f8392a0b4c43cd6e67ce90ad594cb63c146011dc56b213bd42ef677cb6a5f0
1d0bd9944a9161a
registration_upload: 0201d6bd681715e3d330475e72471c1218aa718d96be7353
251c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf183
1f811d49d120a8d4550f57da81a52148659beadc46eb4a7e742d53a1aadab386929a9
c5168ab982a8108f7c316bea8a3bc9b919770b17934f0a3ffc6e503b9b95898f5862e
d9be3ab0262a7e6fd5d77b0b04c5ef1ed302c4bab0b4818e9b3fefcc6886ee6dcb359
23b74db084f802cbea5fa213c4a03eb660bb35ab03b7c0f8902b25e66c23b853352de
5f38981bbd80a6347e4e4b231846c1515c9a1605139a129f37a1007d1b4309e4b7b71
8d194f035908f1307f8c2c9619437ef672c9bc01f3cd9e4335bfb67e5f973ddcaaa78
81f4a5dce93f854940099b133b223b7acad9a64987529bafe3ed698
KE1: 0200c3bce8c2c7da1856b486576082a136f031304eeba82c3e582d920469621b
9657d018aabad67dd15d32492f0155ec944d11593c079c64c5d19088a72cddb12baaa
462ae28bb5390b267e4663d10960997362214446de4f323ff806b3653a1b6dd1a0009
68656c6c6f20626f62030080bf524d28ba64b134c0bd0c860c8b1f976e55d94eb35d4
2aa0cae1935a185c9f7c517875877aac4aa4e909dd5f25cc6ccfe125d031dcfe02459
7af1f7bfb5ed89
KE2: 03001268a7de1c5203c0dc088b56fd06119acb2edb79ff5539bde0fe4a057a5c
53e20d71eec6973f996583aa9c4f3f4c5c0e136145c9c84f2f5db934f6c4bfc32ea49
ace3f6fdd39eec1869f23eda9f9c16229d4ae07618d47b48d6b7fe0205c8f292aab7e
96d72577ccd82bfbeb1051127cce8f6dd6d6ab49bda83effc19a614c2b9304447c78a
88597c3d25ab201331e348fc130689cd8f3830132bc99f16300e8a012b70f159fa065
6c18b5677e508caeca6900cd827beb7e533be71b8ea42d9b42dcb68c470f0418b88d8
3c1cef9dc4e2a4fdebae420dfe6f1491a378b07476f22dc79d02a2661f2927f3c7e10
77e6f138ea164e5ab5759393dc193b918b43aa01b2a2c9ca463a986cc869b572950ff
f36740a723ed2630e154c49a306c1d0e94377d41773dea8ec8d849f8ec16cf5757277
58306250f4bfeed1cd92500e50c08ad5a6844d0374256da53ee823c1cf83f3ce4bdad
f2e5785766a62a1b301bccdf501c79dda230301ff9a97a3a4733b144d38330209bcea
5a6401eb4e08e0697ac4dcb8369e20d76d32c34b619c424d643dc47bd680c0ef66540
4643d2961ad051a7920c318ecd948f0000f14a99b8e58944d0f7cdf6392bf6d69642b
515f3559d4f2d5eb523ceaf9289b43ee67d96edfb99a24412b5e150aa51e017509d22
d2f90226b58f3daf3c9ab0aaad9ded6e4a1a2055edc11ef0939a501
KE3: df34eb9095fc7d4e6fd067a9b8a885675b07d5c1d061ead5fa0978e7cd60c1af
665a1205a29a4d167d33759e45d7d561bcb67d3bfb60572f861f70f26e7c3f79
export_key: db55c71638fd194a740842ea1902313bb11225a6c90c15dc1474622fe
97d9e36cdb35673bb5b9b3f51f71db369bb20f9d492e6d4ee6806990058c40fe4cb20
51
session_key: 713e0b4accd1a906d4d81521e279eb2cd908feacc29beec58eb9c9c6
baf487b0b6f8dc5681aca449435e9686ae25678990a0c2652471dadc0c0570b6a2de5
7e1
~~~

## OPAQUE-3DH Test Vector 38

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
Nm: 64
Nx: 64
Nok: 66
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: e118ca0800d385798e78f2830f95008dadd82a04cf98cc970e40f509e3
efe6f58283b13638643fc0b81d865b5d6a8b00f1c6f2c58ceb340229a79deee88ef6c
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: f7103f1060ae779631da2a2ca29f7876b823836a3551f29480588
0396baabd6e
masking_nonce: 78970b409b43b2dd60c174fd9acc783cc73d62be52f5252165f597
689fca9daa
client_private_key: 01dbf86c586f691ca14b9ab40d70a9e5c73c0b8c027fb639c
9affddf316a4f24a457b33e0273c41c71c5ca880a54ed88d6eb7176277593cbb29d44
bb9daf835f3133
server_private_key: 015d65d73dfd2c51951ac649bb19095f1d02a822b02e5a86b
ae37e79a3ac7d05f1d1a02f58c3cc57af7318bd8c3aef01e27f343d5f8aa5197e80d7
2ed5ceacb845a9
server_public_key: 0200e85b446310593c25258991eeb8da130df718df2efeee93
29b6d6c7a3906749464ffb90f8e43122192f8e77b9f04f708aa5f9ecca9cbeab701f4
9929d82395d9928
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 5f3134280d4b9b4b2bb8132f57ad1eb53c2b7b558e2de883f3b4b92
c1744bdac
client_nonce: c92ec3f315ee9acf4c8224b97991aef4bc413f0e63e3a18980a0380
123fa1241
server_keyshare: 0300ffcefd89e8ee736b4e6149934a1040b8691ba4bc58b160d8
c526e73cb99d7c45ce09264ae268a5afd07c1a3db59c5feb9203ecffc694a41b1138d
eb9a11d6fecbd
client_keyshare: 03001f619d901664fc0a4916b616bf340eafded4dec3c9af08a7
d89f9442bf41048a8824f22d5ce906558f99250ba96a112c5ccf2ff02e062cf9158df
bd1abc4a48e92
server_private_keyshare: 0114c08e5500caa1ef91b2c4c242d628edc59e6b9f42
a97767c678c27ead0f9fc3bc1a20f078365ae8e7c313e612cd9f648be2bd0084e1416
a7c8277fb5c7c832749
client_private_keyshare: 00166500743a98b5bb899e595d818845bd0d927fe4f1
e28d0b87d7ac285fc0e432dd1a20ede64a560bce514ccf868c41a759b6d24d47856bf
ae0cd231ee605249991
blind_registration: 000b01864a7e1e45075a976e1d797dc58bbb07ff85aa36e8f
c57f1dbe4de36c40141c93b2bb304e7718ebcd7bd9978981955e4d6b6addb9cc52a45
04ca40584d5ec0
blind_login: 01d230b755d2262f548f495004d64322b827dcd30baa2d3960769310
cb55be07bbe2b70eb67bc27a11714cc90e5296b68e7e316be4c1d9b09393deb3e724c
349b971
oprf_key: 00cda4e8e3a42a1a3d1fd6e8742bc2b3ac008970a238dd5b464349a1d35
07bf006e95578ecfd411cbf68b547a15517570795515a23c3ed0846d227b329bd4e29
f02e
~~~

### Intermediate Values

~~~
client_public_key: 0301347c5fb96ce61b57ab45d42005522f77483664bd260ec7
f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a8290
cee86e55fe23462
auth_key: 8ce329e79dd2e249507917ed33cea41f99b79939889f16fc9b98dc891a6
e9b331c111bef6b1532642f4871839dcaf0ac1574854e4f3eeb0adc20a7a21f7c3ab3
randomized_pwd: 2827e964b768a1c12bdd09b7369c220613bf82f9fa224c37a4912
19e29aaf3cfe912ab0b4de925ea3bcd3562d4d0f19966a89a0442c571b867f3d960f7
b74508
envelope: f7103f1060ae779631da2a2ca29f7876b823836a3551f294805880396ba
abd6e95dfb01c73ef18e272ee824814cb5a029c4dbbbcabb9afff9ee2d600f8202e0e
43ef0a98c36c3d3acd9545ac06523819641c8134135708d8bebe63fc2996040115351
1824d8819532b65268b1ad954afa1ff546f9e914258dedee38aae971d31acd8828125
646b74a0a01d524a19defb11c1679c2506ab3e922528aa004467815fc7
handshake_secret: bafd0fd64f9b41de2f660a7f48faf0af91293169ea1f68f782f
6d29c1487d3ea5d24e19b79ccf95c4c6cb7b0a77d9b6fff80cd7aeffd7b03e8af2f89
dc02783f
handshake_encrypt_key: b173d0b996d68bca28bdeb03dc5ef4cb3ab3462ee6023a
8e4aad0bca6f38a7e7d4d82832da13d9eaec316320f92204f8fa65f7ff934f4265498
540a209c9dd49
server_mac_key: de912aa4a249015304eb26a0e50bb9a4d464e43cb86e8e787e9ec
a370a980abb8b4158c27edbcdb5ec82b4039518604dedc842e04cd8d2628efce51fa7
0b5f5e
client_mac_key: 0150d70801143bee3c7e3f452fd1b69c60eeb6351cfd2996c7806
0a26361c6efacfb4989331b443e1f4030daf5a6352cf9dddbc582c4359cdbf4c3387d
1bff9a
~~~

### Output Values

~~~
registration_request: 0200572541736c54fb88d0f50d1080d98cc390cec131e56
c5e3d038122c6655d23defe37f0946f3d3b5dcf73545a6df6277e20f9b377591bd443
034fdf53d008028969
registration_response: 020075a39ff76f444258cbb875db3ee78db1bdb809885f
f7675d40b608820a9446483a596fe7e9368e0c031fbe47a2a05d687637adb2effefd2
4ccb13648414553e4310200e85b446310593c25258991eeb8da130df718df2efeee93
29b6d6c7a3906749464ffb90f8e43122192f8e77b9f04f708aa5f9ecca9cbeab701f4
9929d82395d9928
registration_upload: 0301347c5fb96ce61b57ab45d42005522f77483664bd260e
c7f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a82
90cee86e55fe23462aa44090453c6efc9691b184a31fd890f8e564f14a27db513609f
2b81f15c2479a29caf2498a3415022ddb6649f82e4c08a2e96642a808dd08c4ca6ea9
cc9ac61f7103f1060ae779631da2a2ca29f7876b823836a3551f294805880396baabd
6e95dfb01c73ef18e272ee824814cb5a029c4dbbbcabb9afff9ee2d600f8202e0e43e
f0a98c36c3d3acd9545ac06523819641c8134135708d8bebe63fc2996040115351182
4d8819532b65268b1ad954afa1ff546f9e914258dedee38aae971d31acd8828125646
b74a0a01d524a19defb11c1679c2506ab3e922528aa004467815fc7
KE1: 0201147f07392ddb5ab846130ce65a4c16d1eb26735fec1de7716b2c8bc935ad
1c65ebc30a6449adb8504b41fe61b9634a1ac3e429e03db700e6e6f852469e8e83bec
4c92ec3f315ee9acf4c8224b97991aef4bc413f0e63e3a18980a0380123fa12410009
68656c6c6f20626f6203001f619d901664fc0a4916b616bf340eafded4dec3c9af08a
7d89f9442bf41048a8824f22d5ce906558f99250ba96a112c5ccf2ff02e062cf9158d
fbd1abc4a48e92
KE2: 0200a8894e451ac2fcaf5504adce52cb1e6a4d302f105df23878c3b897e5b0b8
ac0f4a4978288dbe6ee92efe0d87b1d5bd2249873fa48c4f79eff423632223bbe025f
278970b409b43b2dd60c174fd9acc783cc73d62be52f5252165f597689fca9daa8a12
b244e728a2dd390529b7e8ec312f77f671ee88f932cfb9a1a9dbd425b5070afbb72b9
e9f0ddd97d4102853ac935a684591b3733cc37ec5b21aeff9c9a0b66a8bae4334d602
91a06755b44c794d5de4dde803f5782c991b42679007a4b5a9dd02ac65b1fe2b33794
641a7deaea6b605caecae7c1a65050b73825aeba2ce9d1a4085e603ec5bb240574143
87d274492cacf3e47af05fe7ddab84dc64dac6ca9cfb4d8da216d6bdb887b24500676
ec53d171232360c17ff81407d6c7ac48f2768c8ca4b5a5ec36c09e5ed18b31124c000
404d3981952ffee21a76ee798e34805ebe9315175f3134280d4b9b4b2bb8132f57ad1
eb53c2b7b558e2de883f3b4b92c1744bdac0300ffcefd89e8ee736b4e6149934a1040
b8691ba4bc58b160d8c526e73cb99d7c45ce09264ae268a5afd07c1a3db59c5feb920
3ecffc694a41b1138deb9a11d6fecbd000f2433ed6462cf9384da1fb0a6a988cd14a2
0830bceb61ddbc37e1ff3ca50d69ee1bc5d769e0cf69aa30665587f74e985b304f5c9
d6440c31cacc81c9cdb077d56c35c4b38c5b07151ab79e1c9cfa59c
KE3: 20d38ebbc756b7ec1b6cd5ba62a9717fb04119a42c54ccf0a4ed86e831c5ff62
f4a2c7aca9d9b1d87d1c191dfec74efb61602c4011959dd04aa23c83f0265858
export_key: 2a0e9c9083941677c7147e86af79ef365cb23579d7719b1fe336ac750
cd0a059ce946a6091978f326eb7ed57fadfab69db86e228232697486c2f7c9b65db87
fc
session_key: 8951727a6a070813459bfc2f9820e955e02a5315524d6d228a2dc28e
8a9b66b1a9dec50f48a499979194f1522c3a0dd505e9c85b6e16bddb533722f9f49a9
3bf
~~~

## OPAQUE-3DH Test Vector 39

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
Nm: 64
Nx: 64
Nok: 66
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: e4033259ef1ace9df3f85dce94677e67ada095af242eb4801840e4399c
544f6b1220fba7db31caf6664b5156ce39bc7c0e416f5cb725454fc7417779a6b13d7
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b40d2f90448536e7fd0cca3823f6c686d328a5be128de587d483c
682eeb327c3
masking_nonce: fdc5df65f9471bc9e684e36cc2a77b845de2f61917dbc0bd944b23
ac501fb242
client_private_key: 01aa0739d3c390e0df1d6a83419001361e6494e0958c6268e
9a64bc44109b2f8e1784d38719b913380fff07f6d1fe601f5560987bb2828a484cf42
b97e93965448d3
server_private_key: 00ac7137ef41e45bd9f1cf40ea91380647ac28462ad98e22b
5326fc0adc6757c67e0fdfb9fb3141a5595e168f85adb13e86ecbd0e8af169868d1c9
4aeadca2d95be0
server_public_key: 0201a6573b69f46bf93cb3f18e2510c753f689097b7b96059c
3ca8f8e45c66a03b694fd8618c9a52c4104ca42186438849e73613cb25fbd4ecc16c5
a65f95345686984
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: fce0d7665ebb10c9620d750061f7e4696d172dc739650c7e723e893
236389b30
client_nonce: 0dd58467372e1363bed48bf972bffdee3a2f2b4b323c83feeb59f3f
ca09f40a6
server_keyshare: 030029562d54d53c7c51651334989bcc95b45a1a07484448ef72
bab708b55322b49a43736afc60bf85fc05d3c1d8b60a0b55a83e37befa115e9625e00
f35c1eeae27ba
client_keyshare: 0201e2f40c1d877219e9512862469e31da268ab014fdce9cb3f9
ed6b27fc01fe6d9b1ec37c6cee76131139ccc3eee0a35438250e9ecaff6cf223ad9fa
469dfaaa0f0a5
server_private_keyshare: 00dcc0dafbe3cd1ab45d51d228ce608b3ce3ef8f0c54
3bb26ae91e9fce8497136b9a3da744973ce025f709315e46f49890bddf7724692f218
f46c3fd03990c335ac3
client_private_keyshare: 001f5307985d5b5248e235cc8e3bc1b489790ce1cc4f
0ee46f4b2ae5dc4e19cfd401632a4120949cbe776376d560a74cc6d59307ef8bc37fc
596bf6c0c180dfb80dd
blind_registration: 00f4bdd1521b23adce41b680898d5524610afc314961ae68f
1d3716f62c76cfb98a8beffaa25acf7c637fb43a96971009630887739963dacff0be2
8625faf6333a25
blind_login: 00291beead7120bd93250d96aa3a7e5945f5b2e1f8955e6ae5645915
40c8f92ad668d4ab1ac65eace7d1f74d34335b389d3e6ea3da84a830cd902bf1bd8fd
5879b10
oprf_key: 01fadcdfb7d893cccb13deb7c952a27830e311579087068d2de4a0647d6
ff05a409b5a087972ff5190b49f76a61d50423cde30793662bd1501825dcf5788ac75
bb46
~~~

### Intermediate Values

~~~
client_public_key: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4ca
15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1e7
ee4c024556f0808
auth_key: c44d010187fa2c73f57726c22a6e71da26b1d1791cc2c13a51af85b71ef
4899e1c3d203ccfc19f8c8e7765656da2fe8fdae7992385261a28b5474280940d3d75
randomized_pwd: bd58368f9f84ea07f5f6daee041b86dfb8291966fb6a9db24b1de
1bdcc49c40e4e284bb4916b539fb07d5519a63375dfb43993ced83bfaf433d71f678f
ee835a
envelope: b40d2f90448536e7fd0cca3823f6c686d328a5be128de587d483c682eeb
327c378591c399e877d4798e6ea62aa8eecc63fa2b8dc7f558babb0f9b20287eb1053
93c4a980d7bce12249b02b22ef562090db01f5f67b4a5dd85165920abe5516c5b6cc8
b3f757c6220b145a5bec199a16187851c19d8c5d891ffa8a30610163bc2e3da696958
add3b6a5db827e0e1d9bc038829e64a8fa474b6cfb3bf2d9f5d0d40d36
handshake_secret: 1a98dd20a434d72b1b84b4de5e447498ceaa739a46c2f18a030
151d3a7637c83b6a4b09ce09aca7ff8d7155746f4bca2d269525f775c915e8b894e00
8777bc99
handshake_encrypt_key: dfeb781312fa8068c623181aba7260a5e62f08ee7f51c9
680d98ae411bb05b7d759cdc6c847a696f4e169c5ad4fff8704af2aac0f2987d399c8
ad78e40ee1c93
server_mac_key: 2367b97b2b1de79e2eff9bdaad70e8782a8fcce9b0c43873dc614
d9ef2c90b7bfa96d33015906a53ddb13120de0d6386bd309c6eb230c4ad501f120e7b
3401d9
client_mac_key: 1c97a97fe1d28750ec8f848a94531c88361d9fb263190aa1649c3
e37d0d268011f3c58da3e387d4f3c068720d9c4dd6973c54026f2cac5ff7767f1610c
d1a261
~~~

### Output Values

~~~
registration_request: 02000c53a2fa3c1dd1ed747b297b82020f316ee5b38d5ad
d8bfa68d9c6eb9b22ac651badd5d5751e7371cae832503f66442cdc156414f4a5ba0c
2db08b33530cde8dec
registration_response: 0201b5220da8916269548ac1de516fe90b9b6560afbeee
8d940fac786ad9ce565915750665e57181ecfa062c5255b84a62c89241f2a7d2725a1
f02e2dcd0f582eb24c70201a6573b69f46bf93cb3f18e2510c753f689097b7b96059c
3ca8f8e45c66a03b694fd8618c9a52c4104ca42186438849e73613cb25fbd4ecc16c5
a65f95345686984
registration_upload: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4
ca15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1
e7ee4c024556f080806c8834822aa404c713f8f559b2057ab9400fb7c3c011af054f2
65c84a9c128b3b459f21d8c6dc6f877f3b5c93c485760efdfcc0f25ac9faa43dedc58
c44a603b40d2f90448536e7fd0cca3823f6c686d328a5be128de587d483c682eeb327
c378591c399e877d4798e6ea62aa8eecc63fa2b8dc7f558babb0f9b20287eb105393c
4a980d7bce12249b02b22ef562090db01f5f67b4a5dd85165920abe5516c5b6cc8b3f
757c6220b145a5bec199a16187851c19d8c5d891ffa8a30610163bc2e3da696958add
3b6a5db827e0e1d9bc038829e64a8fa474b6cfb3bf2d9f5d0d40d36
KE1: 03014f2799259882d01af61644db264602a3486a32f6b510aecb336456ce58af
6cdf6f5630ab4e3e7081f1e99b1688558f0a1bf15da34b7c0252f1036d916928a0f33
20dd58467372e1363bed48bf972bffdee3a2f2b4b323c83feeb59f3fca09f40a60009
68656c6c6f20626f620201e2f40c1d877219e9512862469e31da268ab014fdce9cb3f
9ed6b27fc01fe6d9b1ec37c6cee76131139ccc3eee0a35438250e9ecaff6cf223ad9f
a469dfaaa0f0a5
KE2: 0301aec61ca3ce7c9d7adbbb2e30371de2e6216477739f50aa09de3d239d45dc
37f906f34422aa0b845ed70802f3b5be77d4b3f4512ffe4eb8e99be207831666fbff3
4fdc5df65f9471bc9e684e36cc2a77b845de2f61917dbc0bd944b23ac501fb242da36
0e3bc5a3a2babe9871d3e90c5f57b3baf46e6a215444cc0a586026e45239768467aed
7f90c8dc8562ecfd1e6ce5fadb937ad944229e1523de20e3d4ebd6a74c48eb28148e0
71d77981b0a4671fda7768ba136a34b70fcf267f1c403f8484a74234022c2218d9a20
95a653ae88f4ebce7066d8944c71c0b6f670bc2e41bd7d1e846ddfd890f614574aabd
24dbf8cdf8fe83b37c4dfff041fd42118b6aa2fed7aae3418f0a6399dcd1ff130453c
ba9daf76468c6a77746a3847cbb5b6f9528feb92be06e4b7928460ce1d418924b5197
f2c409b936482b2daabb151f93dbb78d696cd56cfce0d7665ebb10c9620d750061f7e
4696d172dc739650c7e723e893236389b30030029562d54d53c7c51651334989bcc95
b45a1a07484448ef72bab708b55322b49a43736afc60bf85fc05d3c1d8b60a0b55a83
e37befa115e9625e00f35c1eeae27ba000f8fa2e9a2692290d48e6acaab14d5e266b0
b8dca0ba048f22443bb89a80a91c6e8213f6cdb430f0685dbb84571f05a0dc3d1a4c9
75b0d0145cdaaae50d31b665bcea1bd2783d3a4866ec441313a6cdb
KE3: 58e6876a60b74ee229f2b85f91038c6adee4c0cc0029115a4bfad6b5ac6e1a96
b977e1eb51f5ccb4cad0f9f80508c93bb6376ebb3c84b1736cd7c89eb1675c70
export_key: 296647dba41d525309e59855880d41250f3e2bc78fdea25cd169522bf
0f3f06fb96f729880a5c648f1118d5084b70776a231bd9cca8fcc823f8fba7cf140c5
9e
session_key: 29f5c0aa51eb65d9ab09bb3bc4b72330ae56da16b8df4dcbcd653eca
48e3af5e7e619c182f4f230e360790b79750441ed0aceb653c6471f48bc28bd60eb35
e84
~~~

## OPAQUE-3DH Test Vector 40

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
Nm: 64
Nx: 64
Nok: 66
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: fbf260b2fefb6b873f200a672a8cad12238939b8d8d9a0f5ac3968b607
a5b61c7c31e3385c64ee91e2923fa816cc8b9f71cd19bc8c03f0a0c1472703b15241e
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 148680a2ed9221cce00118e45854b7a7bdf7a7413fef7901fda93
30f23b74537
masking_nonce: 10e071046caa5653285f2d6157a395159b3b397d24faf2795d4a39
2809efd933
client_private_key: 008fb26f2c88d274661db787733c175d7034e4da200a4ebb0
1c9589fd7a0d54771e479fce2a99af6a64f80e4106dcef77a750147dcf14217936a74
679455ddadece4
server_private_key: 00b78f376d4dee066fa82592ffb702498326c37dadf63135c
ca8df4d8e19f5dc6e830163ea683e19a507b15a66ed74b1ce6ebbd902a5c74a51eeaa
2ec2bfc113d4fc
server_public_key: 0200f944f464cfcbdfe94b720c0a59487456cca17580dd1982
4532d540642aa4017edec0b9308bf4f4fc00611115a145c1374680847e4815f6c8dd7
febdecef64998dc
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 12d249aed7235d544e9dcca2a84c170a4ee3f06b2476e3a277bdc2d
b6656b3fc
client_nonce: 95e8256fb398e5b9b108c80976b3d52ab0e1daf76b1c4c3b60cc7b5
6ca02c567
server_keyshare: 0300ed0fdc747de2ff4797c4b18da821ae9ec83376c51d00a51b
2d1701e5689e8dd720cca6fdd1a548b5b3ad34015006ce4f7548be73295e07f15f8b0
c60331cb65160
client_keyshare: 0300c566f59e65c950d86356e925ce1f87b3d4a7a9b2e556ecef
17041679c76f8afd8f7b1e9fb82549886fdedf29e4e86564475b0c2c200a9c7a4e089
e846932e07d36
server_private_keyshare: 000edecf9fb5e59078188296e515e4ca73bbe621fba3
5f6c96d3864ea0bd2e0456d416426fae1344e0fc3b40fedaf785bf4d7c8b08424b6a3
4a2a343d0a0f288f4d4
client_private_keyshare: 01f63ed931f59a0368288ac23921775322360ce0c6d6
96e76eb046a5b04a05c1a16272e0b8c22ee595320c808337e5804daf7a463c23f1f40
7b77dca84824b4657fc
blind_registration: 002a6e47e6eb00445978d7a0f5e876189839fce07fa4c3f5e
e73f71b7054c673a45711b4be7a89fee03569a6a058f9dda2294315a167fa19af3279
769bdb191cfc70
blind_login: 011646fd1eb67204c84e2be0273c76e96a29d0f20428bcb157922105
599e83b939f76446fb738af8d38a00fae287d39a8d7234b7b8a704076e51cfacd73bb
24554bc
oprf_key: 01296ee14ded1e15d1475342ec5ca999d6b06da34d21c032e983c8798f3
83713e826d20a87579166b896fa22835171d491010aa0ae233cb8364a37fbc67fcd76
a7e7
~~~

### Intermediate Values

~~~
client_public_key: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fef6
f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea03
e0379fb9127abe5
auth_key: 06fdbb3eac5a64969d5b9d706d42f5bf4974e8cb384045cbf1635d4c38e
b4d40ab510794bfb080ace09afc515b607c655a98a9d574e3540d236eb11e2a33ae5a
randomized_pwd: ab42f356f88a289e39db5ad0c3000f61e218377a38eb5bdd7e5c3
4a49515af35139fd03bf7766b388658d3f97013e682e8b03312cb132e1b6ad38b9de5
f2c541
envelope: 148680a2ed9221cce00118e45854b7a7bdf7a7413fef7901fda9330f23b
7453701def71a3293a7da19c084e4d8c2455ec701a6e4dc3a7306c4167fdd647596bf
dc5c6c55c65f3580211522c87bd1e637eac225a3724d720bb9fe5a672070c1044a8f8
1fc9747a6236b83782a0cbced17fc42f1f1341998bedae5c3514f719c42025bc652a3
e33565f3d0ea4f85d432b8699d45cd6feea8c991d0839f064be2829213
handshake_secret: 45ffe957a00d84c425c78bcc80913316da6f6e5b203ebef3153
69aa437aa6d69ff4c6ef75d2b3b44015eee8bd4e9f5fb372a9acedb1a137a0230c169
1d72897f
handshake_encrypt_key: 575eb190b6c33011ed4f2d3712be61557b8cef58f76d55
4d10a18c541a240b419b0eb71283463708d26c34e768f8de56b2f00dc2894c4b723c5
d0afedb23369a
server_mac_key: 1c11f159aef9b208ffcbaf9e94954bad25c4db5d53023dfdbe1e5
c190a6cc7678bd2d439e1ff473925eb53f4ebc1409561bda0ff1dd9d464753574685c
9ae768
client_mac_key: ac527810534c51e15db0ea3b5523a4bcdddedb25822235d48d6b2
fd603d3e24ea439b8a35e6498282737e4c343c62ae7f4c76caa2d6fdc23b8b3e74b72
f33780
~~~

### Output Values

~~~
registration_request: 0201d22759697d1d91f6b1812d14acfee093886e889d913
cdffc78de009924d3d80a7aa9384149f163fd706498375c34402df2ccd8c1283cd250
477ce032c9e7c78ef8
registration_response: 030056fb0c3756244faf6dd675c12f4b60ffe048b95fa3
b01e7eefc55cee0bd563984101048808fa2549626efc2de0b1bfba47219946c4bdd6f
1a76d2ef795c10877250200f944f464cfcbdfe94b720c0a59487456cca17580dd1982
4532d540642aa4017edec0b9308bf4f4fc00611115a145c1374680847e4815f6c8dd7
febdecef64998dc
registration_upload: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fe
f6f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea
03e0379fb9127abe5b236c94348d63a9b4f6d7a0c29d141cb2f370e58fd49ef257ec0
0f85e3626224e8c473c05ffb7737dd3d8177be3a478ffef34e9c898c141dbbdd1ac93
0fb6287148680a2ed9221cce00118e45854b7a7bdf7a7413fef7901fda9330f23b745
3701def71a3293a7da19c084e4d8c2455ec701a6e4dc3a7306c4167fdd647596bfdc5
c6c55c65f3580211522c87bd1e637eac225a3724d720bb9fe5a672070c1044a8f81fc
9747a6236b83782a0cbced17fc42f1f1341998bedae5c3514f719c42025bc652a3e33
565f3d0ea4f85d432b8699d45cd6feea8c991d0839f064be2829213
KE1: 02002c6e65b998d160fbbde62484f39c2678bda170db547005889379b570e83e
4f6aa45200a183dc5cbf014bc7f94f28064bae53132dfb3a0736bf7b806b1091ce541
895e8256fb398e5b9b108c80976b3d52ab0e1daf76b1c4c3b60cc7b56ca02c5670009
68656c6c6f20626f620300c566f59e65c950d86356e925ce1f87b3d4a7a9b2e556ece
f17041679c76f8afd8f7b1e9fb82549886fdedf29e4e86564475b0c2c200a9c7a4e08
9e846932e07d36
KE2: 0201357df114b1c70a0fc8bd2959be6f8665c8d678d9bec2adeb659f6b0dc13d
362d923d1dc12abf35950aa6394a35b6b098d6ce00f19fdfe74130eeaaa05a94a03bd
c10e071046caa5653285f2d6157a395159b3b397d24faf2795d4a392809efd9338172
75c06ae88cfc284404d0a1e2fbd980a3fc279422cc02900e736924bd0e92ad10a041f
5e7fb4ed14ad05835884b15ccce805d6cb1d98c205e728c75c0340c91b10fe0b6f4a3
e6ed72da929e19e01b2dd954205389fd8785cf68bf1f8a1b7bdd21c1880aef17e6aac
821d1cf935d241fbbafab51c70895a8632c90524340e10b353fe8d6a59e30f55b476b
7c999c6a3db8dfca675da4a9406b4bf203025cfbee27d48724595c417419afb70ff17
d5545728ec4db9b94ca06f76cf1b8a00a14d128c6ee8c4f14c8ed7165e10a784ae3ea
4f4133c43fe605f930ad908f7ad1302a9866285e12d249aed7235d544e9dcca2a84c1
70a4ee3f06b2476e3a277bdc2db6656b3fc0300ed0fdc747de2ff4797c4b18da821ae
9ec83376c51d00a51b2d1701e5689e8dd720cca6fdd1a548b5b3ad34015006ce4f754
8be73295e07f15f8b0c60331cb65160000fa617cd8614963cc4a93daa6f9f39af7de5
c14264be441bccb88f4a8ecf0bc02e6a00cc865fe075ef0a26e5bd30ecfc33e0e54f7
4e5f321a064d00936b7dcb794e1b9e9beea94724085999472211d15
KE3: b8d4c9fec7e500686d441a87e104f95d70b444a605100736d0159a2ed24ea759
75320d73dc63c0e14fa20b68567f922a20f99f0215d40a467d95f5967971e4ab
export_key: 0c54bc0aaa31c4537fa2bad1b952405c388ea0af4aee0f19b314f0cac
b24fcd51a9ac25cef1aa54ebe08cb7e460e48e26ed78045b82df4763a2e4cdea4a252
8c
session_key: c529e3877be75151e9fd18f1dee4e1bcb27f81b7277e06a5ded2296f
7d0fc8ca13b8f23116e34a2ab83f644a5c9ce94b74d574667f679463d51a9db41200e
0a9
~~~
