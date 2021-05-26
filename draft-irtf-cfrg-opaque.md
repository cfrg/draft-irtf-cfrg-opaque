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
credential file. In the latter case, the attacker learns a mapping of
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
the client's registration that it stores in a credential file alongside other
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
RecoverEnvelope(randomized_pwd, server_public_key, envelope,
                server_identity, client_identity)

Input:
- randomized_pwd, randomized password.
- server_public_key, The encoded server public key for the AKE protocol.
- envelope, the client's `Envelope` structure.
- server_identity, The optional encoded server identity.
- client_identity, The optional encoded client identity.

Output:
- client_private_key, The encoded client private key for the AKE protocol
- export_key, an additional client key

Steps:
1. auth_key = Expand(randomized_pwd, concat(envelope.nonce, "AuthKey"), Nh)
2. export_key = Expand(randomized_pwd, concat(envelope.nonce, "ExportKey", Nh)
3. (client_private_key, client_public_key) =
    RecoverKeys(randomized_pwd, envelope.nonce, envelope.inner_env)
4. cleartext_creds = CreateCleartextCredentials(server_public_key,
                      client_public_key, server_identity, client_identity)
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

### Internal Mode {#internal-mode}

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

### External Mode {#external-mode}

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
                                        blind,
                                        response,
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
FinalizeRequest(client_private_key, password, blind, response,
                server_identity, client_identity)

Input:
- client_private_key, the client's private key. In internal mode, this is nil.
- password, an opaque byte string containing the client's password.
- blind, the OPRF scalar value used for blinding.
- response, a RegistrationResponse structure.
- server_identity, the optional encoded server identity.
- client_identity, the optional encoded client identity.

Output:
- record, a RegistrationUpload structure.
- export_key, an additional client key.

Steps:
1. y = Finalize(password, blind, response.data)
2. randomized_pwd = Extract("", Harden(y, params))
3. (envelope, client_public_key, masking_key, export_key) =
    CreateEnvelope(randomized_pwd, response.server_public_key, client_private_key,
                   server_identity, client_identity)
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
server agree on (1) a mutually authenticated shared secret key and (2) any optional
application information exchange during the handshake.

In this stage, the client inputs the following values:

- password: client password.
- client_identity: client identity, as described in {{client-credential-storage}}.

The server inputs the following values:

- server_private_key: server private for the AKE protocol.
- server_public_key: server public for the AKE protocol.
- server_identity: server identity, as described in {{client-credential-storage}}.
- record: RegistrationUpload corresponding to the client's registration.
- credential_identifier: client credential identifier.
- oprf_seed: seed used to derive per-client OPRF keys.

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
  ke1 = ClientInit(client_identity, password)

                         ke1
              ------------------------->

  ke2 = ServerInit(server_identity, server_private_key,
                    server_public_key, record,
                    credential_identifier, oprf_seed, ke1)

                         ke2
              <-------------------------

    (ke3,
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

In the case of a record that does not exist, the server SHOULD invoke the
CreateCredentialResponse function where the record argument is configured so that:

- record.masking_key is set to a random byte string of length Nh, and
- record.envelope is set to the byte string consisting only of zeros, of length Ne

Note that the responses output by either scenario are indistinguishable to an adversary
that is unable to guess the registered password for the client corresponding to credential_identifier.

#### RecoverCredentials {#recover-credentials}

~~~
RecoverCredentials(password, blind, response,
                   server_identity, client_identity)

Input:
- password, an opaque byte string containing the client's password.
- blind, an OPRF scalar value.
- response, a CredentialResponse structure.
- server_identity, The optional encoded server identity.
- client_identity, The optional encoded client identity.

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
    RecoverEnvelope(randomized_pwd, server_public_key, envelope,
                    server_identity, client_identity)
7. Output (client_private_key, response.server_public_key, export_key)
~~~

## AKE Protocol {#ake-protocol}

This section describes the authenticated key exchange protocol for OPAQUE using 3DH,
a 3-message AKE which satisfies the forward secrecy and KCI properties discussed in
{{security-considerations}}. The protocol consists of three messages sent between
client and server, each computed using the following application APIs:

- ke1 = ClientInit(client_identity, password)
- ke2 = ServerInit(server_identity, server_private_key, server_public_key, record, credential_identifier, oprf_seed, ke1)
- ke3, session_key, export_key = ClientFinish(password, client_identity, server_identity, ke2)
- session_key = ServerFinish(ke3)

Outputs `ke1`, `ke2`, and `ke3` are the three protocol messages sent between client
and server. `session_key` and `export_key` are outputs to be consumed by applications.
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
  uint8 client_keyshare[Npk];
} KE1;
~~~

request
: A `CredentialRequest` generated according to {{create-credential-request}}.

client_nonce
: A fresh randomly generated nonce of length `Nn`.

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

#### Transcript Functions {#transcript-functions}

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

OPAQUE-3DH can optionally include shared `context` information in the transcript,
such as configuration parameters or application-specific info, e.g. "appXYZ-v1.2.3".

The OPAQUE-3DH key schedule requires a preamble, which is computed as follows.

~~~
Preamble(client_identity, ke1, server_identity, inner_ke2)

Parameters:
- context, optional shared context information.

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
1. preamble = concat("RFCXXXX",
                     I2OSP(len(context), 2), context,
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
- session_key, the shared session secret.

Steps:
1. prk = Extract("", ikm)
2. handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
3. session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
4. Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
5. Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
6. Output (Km2, Km3, session_key)
~~~

### External Client API {#opaque-client}

~~~
ClientInit(client_identity, password)

State:
- state, a ClientState structure.

Input:
- client_identity, the optional encoded client identity, which is nil
  if not specified.
- password, an opaque byte string containing the client's password.

Output:
- ke1, a KE1 message structure.
- blind, the OPRF blinding scalar.
- client_secret, the client's Diffie-Hellman secret share for the session.

Steps:
1. request, blind = CreateCredentialRequest(password)
2. state.blind = blind
3. ke1 = Start(request)
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
- session_key, the session's shared secret.

Steps:
1. (client_private_key, server_public_key, export_key) =
    RecoverCredentials(password, state.blind, ke2.CredentialResponse,
                       server_identity, client_identity)
2. (ke3, session_key) =
    ClientFinalize(client_identity, client_private_key, server_identity,
                    server_public_key, ke1, ke2)
3. Output (ke3, session_key)
~~~

#### Internal Client Functions {#client-internal}

~~~
Start(credential_request)

Parameters:
- Nn, the nonce length.

State:
- state, a ClientState structure.

Input:
- credential_request, a CredentialRequest structure.

Output:
- ke1, a KE1 structure.

Steps:
1. client_nonce = random(Nn)
2. client_secret, client_keyshare = GenerateKeyPair()
3. Create KE1 ke1 with (credential_request, client_nonce, client_keyshare)
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
- session_key, the shared session secret.

Steps:
1. ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare,
    state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
2. preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
3. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
4. expected_server_mac = MAC(Km2, Hash(preamble))
5. If !ct_equal(ke2.server_mac, expected_server_mac),
     raise MacError
6. client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac))
7. Create KE3 ke3 with client_mac
8. Output (ke3, session_key)
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
- record, the client's RegistrationUpload structure.
- credential_identifier, an identifier that uniquely represents the credential
  being registered.
- oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key.
- ke1, a KE1 message structure.

Output:
- ke2, a KE2 structure.

Steps:
1. response = CreateCredentialResponse(ke1.request, server_public_key, record,
    credential_identifier, oprf_seed)
2. ke2 = Response(server_identity, server_private_key,
    client_identity, record.client_public_key, ke1, response)
3. Output ke2
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
         client_public_key, ke1, credential_response)

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
- credential_response, a CredentialResponse structure.

Output:
- ke2, A KE2 structure.

Steps:
1. server_nonce = random(Nn)
2. server_secret, server_keyshare = GenerateKeyPair()
3. Create inner_ke2 ike2 with (credential_response, server_nonce, server_keyshare)
4. preamble = Preamble(client_identity, ke1, server_identity, ike2)
5. ikm = TripleDHIKM(server_secret, ke1.client_keyshare, server_private_key, ke1.client_keyshare, server_secret, client_public_key)
6. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
7. server_mac = MAC(Km2, Hash(preamble))
8. expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
9. Populate state with ServerState(expected_client_mac, session_key)
10. Create KE2 ke2 with (ike2, server_mac)
11. Output ke2
~~~

# Configurations {#configurations}

An OPAQUE-3DH configuration is a tuple (OPRF, KDF, MAC, Hash, MHF, EnvelopeMode, Group, Context)
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
1. The output size of the Hash function SHOULD be long enough to produce a key for
MAC of suitable length. For example, if MAC is HMAC-SHA256, then `Nh` could be the
32 bytes.

# Application Considerations {#app-considerations}

Beyond choosing an appropriate configuration, there are several parameters which
applications can use to control OPAQUE:

- Client credential identifier: As described in {{offline-phase}}, this is a unique
  handle to the client credential being stored. In applications where there are alternate
  client identifiers that accompany an account, such as a username or email address, this
  identifier can be set to those alternate values. Applications SHOULD set the credential
  identifier to the client identifier. Applications MUST NOT use the same credential
  identifier for multiple clients.
- Context information: As described in {{configurations}}, applications may include
  a shared context string that is authenticated as part of the handshake. This parameter
  SHOULD include any configuration information or parameters that are needed to prevent
  cross-protocol or downgrade attacks. This context information is not sent over the
  wire in any key exchange messages. However, applications may choose to send it alongside
  key exchange messages if needed for their use case.
- Client and server identifier: As described in {{client-credential-storage}}, clients
  and servers are identified with their public keys by default. However, applications
  may choose alternate identifiers that are pinned to these public keys. For example,
  servers may use a domain name instead of a public key as their identifier. Absent
  alternate notions of an identity, applications SHOULD set these identifiers to nil
  and rely solely on public key information.
- Enumeration prevention: As described in {{create-credential-response}}, if servers
  receive a credential request for a non-existent client, they SHOULD respond with a
  "fake" response in order to prevent active client enumeration attacks. Servers that
  implement this mitigation SHOULD use the same configuration information (such as
  the oprf_seed) for all clients; see {{preventing-client-enumeration}}. In settings
  where this attack is not a concern, servers may choose to not support this functionality.

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
attack upon the compromise of the credential file at the server. Applications
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
Context: 4f50415155452d504f43
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
oprf_seed: 5c4f99877d253be5817b4b03f37b6da680b0d5671d1ec5351fa61c5d82
eab28b9de4c4e170f27e433ba377c71c49aa62ad26391ee1cac17011d8a7e9406657c
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd
539c4676775
masking_nonce: 54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab
86ff39ed7f
server_private_key: 16eb9dc74a3df2033cd738bf2cfb7a3670c569d7749f284b2
b241cb237e7d10f
server_public_key: 18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d
402f672bcc0933
server_nonce: f9c5ec75a8cd571370add249e99cb8a8c43f6ef05610ac6e354642b
f4fedbf69
client_nonce: 804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f
2e9784f69
server_keyshare: 6e77d4749eb304c4d74be9457c597546bc22aed699225499910f
c913b3e90712
client_keyshare: f67926bd036c5dc4971816b9376e9f64737f361ef8269c18f69f
1ab555e96d4a
server_private_keyshare: f8e3e31543dd6fc86833296726773d51158291ab9afd
666bb55dce83474c1101
client_private_keyshare: 4230d62ea740b13e178185fc517cf2c313e6908c4cd9
fb42154870ff3490c608
blind_registration: c62937d17dc9aa213c9038f84fe8c5bf3d953356db01c4d48
acb7cae48e6a504
blind_login: b5f458822ea11c900ad776e38e29d7be361f75b4d79b55ad74923299
bf8d6503
oprf_key: 23d431bab39aea4d2737ac391a50076300210730971788e3a6a8c29ad3c
5930e
~~~

### Intermediate Values

~~~
client_public_key: f692d6b738b4e240d5f59d534371363b47817c00c7058d4a33
439911e66c3c27
auth_key: 27972f9b1cf2ce524d50a7afa40a2ee6957904e2bef29976bdbda452a84
fcf01023f3ddd8182e64ea5287f99765dd39b83fa89fe189db227212a144134684783
randomized_pwd: 750ef06299c2fb102242fd84e59613616338f83e69c09c1dc3f91
c57ac0642876ccbe785e94aa094262efdc6aed08b3faff7c1bddfa14c434c5a908ad6
c5f9d5
envelope: 71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c46
76775455739db882585a7c8b3e9ae7955da7135900d85ab832aa83a34b3ce481efc9e
43d4c2276220c8bcb9d27b5a827a5a2d655700321f3b32d21f578c21316195d8
handshake_secret: 02fb23a668b7138b029c95d21f1e0eec9e10377be933bdbf3e5
33ea39073d3ce9d1ef16b55a8a8464f3bf6a991cc645d14c1fa3d9d6cfe36c6c0dcc2
691d7109
server_mac_key: e75ce46beeebd26f22540d7988de9809a69cf34fec6c050750708
e91232297fdbb51e875cd37167d5ce661ebccf0004dbbf96311daf64ddec7faae04c4
8bbd89
client_mac_key: 4bce132daa031fff2a6e5ac29287c4641e3b9dc2560394b8c73f3
b748f1e51e577b932a960b236981217b33bee220b0bce2696638cfb7791f427ade292
d60f55
~~~

### Output Values

~~~
registration_request: 80576bce33c6ce89f9e1a06d8595cd9d09d9aef46b20dad
d57a845dc50e7c074
registration_response: 1a80fdb4f4eb1985587b5b95661d2cff1ef2493cdcdd88
b5699f39048f0d6c2618d5035fd0a9c1d6412226df037125901a43f4dff660c0549d4
02f672bcc0933
registration_upload: f692d6b738b4e240d5f59d534371363b47817c00c7058d4a
33439911e66c3c2795014d8fc0c710bd763c981c5b9329c95e149c6717af91bad2cec
daf87f2c3c9c11914cb6d44aaee5679e3e61e1b65241fda74902cca908a065495c0b2
8b799e71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c467677
5455739db882585a7c8b3e9ae7955da7135900d85ab832aa83a34b3ce481efc9e43d4
c2276220c8bcb9d27b5a827a5a2d655700321f3b32d21f578c21316195d8
KE1: 60d71c9f5d2a14568807b869e2c251a8e5f7ad8951cd8386c7e32c0634b26b16
804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69f6792
6bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a
KE2: 78a428204f552d3532bad040c961324edb22c738d98f1dd770d65caba0bd8966
54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7fbcbbb
84a18810b8eb1dc898d9af686f5901a21d0768720b325279fde4931ee52f0d4a0d0d9
cd1cd7c424d4622b1588ba554cd9241352a59ef52bbe85e0f865021404b115ba954f5
540cf2d811a6566a93876cac1239b1f75f39b070250af5a84a819e08b13e9e437a80f
c25cc130f8475dde43efe6d900c664e9bac300298bb0f9c5ec75a8cd571370add249e
99cb8a8c43f6ef05610ac6e354642bf4fedbf696e77d4749eb304c4d74be9457c5975
46bc22aed699225499910fc913b3e907120485942e3e077f71c1dd2d87053b39f0d31
bfe5d5f90df0e85ad9ce771e4f4d1ab697a10a02002cd73916051b887da9554465d58
68811fd8b22b8f457ed5a4b0
KE3: b4f8aece9fb4f6b7b5ffe1c98747a91f4ec7bf5481fe5719ba4baad668e3fd4e
8aba4fa227bd4c688ed9e17f6c6d28ab5e5617a883207d80979dc4797ca89304
export_key: 045f61f4baa0a945c2e85dfb7a85fe4df8a49e6c31344920e863c286b
c8a17fe25fc16c84836335b4b5ecc9743c5d3a221101ab004aa99ce65026b6953ad6c
c0
session_key: 91187690e5ea0da3110a1dd7d5ffd7c4c3111950c587d9fcf3b9f34b
f73b86dbeafed42a05024fa875a32415c6143d20c39cd732eb0e31db5e60ea3fb2551
cf7
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
Context: 4f50415155452d504f43
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
oprf_seed: db5c1c16e264b8933d5da56439e7cfed23ab7287b474fe3cdcd58df089
a365a426ea849258d9f4bc13573601f2e727c90ecc19d448cf3145a662e0065f157ba
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf
2747829b2d2
masking_nonce: 30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b
5def228c85
server_private_key: eeb2fcc794f98501b16139771720a0713a2750b9e528adfd3
662ad56a7e19b04
server_public_key: 8aa90cb321a38759fc253c444f317782962ca18d33101eab2c
8cda04405a181f
server_nonce: 3fa57f7ef652185f89114109f5a61cc8c9216fdd7398246bb7a0c20
e2fbca2d8
client_nonce: a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e608
5d8c1187a
server_keyshare: ae070cdffe5bb4b1c373e71be8e7d8f356ee5de37881533f1039
7bcd84d35445
client_keyshare: 642e7eecf19b804a62817486663d6c6c239396f709b663a4350c
da67d025687a
server_private_keyshare: 0974010a8528b813f5b33ae0d791df88516c8839c152
b030697637878b2d8b0a
client_private_keyshare: 03b52f066898929f4aca48014b2b97365205ce691ee3
444b0a7cecec3c7efb01
blind_registration: a66ffb41ccf1194a8d7dda900f8b6b0652e4c7fac4610066f
e0489a804d3bb05
blind_login: e6f161ac189e6873a19a54efca4baa0719e801e336d929d35ca28b5b
4f60560e
oprf_key: 1e0550d2dbb9ce5dd9bdbb5f808afbb724c573dc03306dcfc7217796465
ce607
~~~

### Intermediate Values

~~~
client_public_key: ba6cb41f1870e9db7e858440a664e6559d01fdbfb638bbf7e1
c9004f20d5db71
auth_key: 5142ae6f6bd80686039656fd7a03cdd7e39cc6e869aa637220d4b5fb64f
afee2f284a1581fff95ad3a5261b413c5e5b91115f78a3c35486fa56023c300d1726b
randomized_pwd: cea240b632b9c1d704034920cc3dc3c664ed8cd82cf5c0339af76
4d6350d2ee9ba1f675ce8df7b6cf8692d1efb158bafa3c2695ac03a2d92346c19810c
1a698b
envelope: d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf274782
9b2d26e18240c0cbad3b4cdbd7d9d86512f87e43fac39e3785a17504aaa8508f81e3c
1517b150259be478720935e175b1e34bbe625d0828a62ca9983f9a27aed27f5e
handshake_secret: 7925c12d7bf3050e62fe5c8caaece3c85737754c5df79bc59a6
0fa87929ab1f4a4730f903b87be8b7d89ded8ec97aaec97bc8e7d53a555fd4ad74c4f
33b9bc83
server_mac_key: 27d6036335c5654132fb08cc81d95b3067ef7fe795f017531231a
e3fa03cd3ab72f1f5e81473318f9c01f990263d885dfce4b6ac8630fdc8ee8abc6a36
7c2339
client_mac_key: ebb3693bac6310075a89922c7a40599d14d03d9104b7a331106e8
a578a32a4944751f9d3c230a6690a5747137388a86159cf587969d13dadc0a3830218
dfbca5
~~~

### Output Values

~~~
registration_request: f841cbb85844967568c7405f3831a58c4f5f37ccddb0baa
4972ea912c960ae66
registration_response: 0256257cc6e2b04444edc076b9ad44d8b31593e050bea8
06485707a818f8a93f8aa90cb321a38759fc253c444f317782962ca18d33101eab2c8
cda04405a181f
registration_upload: ba6cb41f1870e9db7e858440a664e6559d01fdbfb638bbf7
e1c9004f20d5db71146e42585d25fa19913876edce4b5ee99b638eb37b1d8a8a76607
efaa12299e828641ba4fbf1c46fc2c3776e0a0c9791f88a15b9ddfb5495d63ce92d8f
58823bd0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf2747829b2d
26e18240c0cbad3b4cdbd7d9d86512f87e43fac39e3785a17504aaa8508f81e3c1517
b150259be478720935e175b1e34bbe625d0828a62ca9983f9a27aed27f5e
KE1: 14cc586d982b6db9846c78e0b3c543591e95fbf2fc877fa0e5eff89897dd3050
a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e6085d8c1187a642e7
eecf19b804a62817486663d6c6c239396f709b663a4350cda67d025687a
KE2: 8ab71c17547f376ae787741c367142790087090cdde6327dabb2581197bffa59
30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def228c85dd973
a1ac59244f674da4a1c057961886661bd29e0c1346f0fcf75bf1c78d4781815c2f9f6
f2f9fe0e370b256f6e82fb2e14c7ffc374d42caf26abf13dca169a6faafd5cff8baa9
717090bc1fc5e1ba56acb93492d1a8b789f33ff29b6004c4be9a755ff590d7d00d6e8
893e7e54e639aebf69d18f2182a9bb0f2e1c27c81ba73fa57f7ef652185f89114109f
5a61cc8c9216fdd7398246bb7a0c20e2fbca2d8ae070cdffe5bb4b1c373e71be8e7d8
f356ee5de37881533f10397bcd84d35445401c619d464ab3a134c71da4d9874f2f736
189b8bbb659c28f8db25a58b9f089272132e3091efa87d6b07d10321ba464047be011
3e91514aba299fd1553bcebb
KE3: c4a0d5b8148f3ac0f8611b38de38bda085d4eb00d561397ae59676f36dc705be
1c939e7bfdd7301103af5eb164bdfb70298aab889bd2ac797e419a82bfb442e6
export_key: 6b50ae4dba956930c0465b4a26c3cee58e05afcab623c1c254ae34acc
38babf954530a53475672ff46a1cf7fd53ef9e808f85b08793d021bb5c6d2a1bb9204
f6
session_key: c9bc2b7e2237f6fbeccd92dc6ec6d51faeb886492f8d23f21743a967
597025215df02a4afb75349acbafeef9dfd4f19e6d38da8bea4912f7b691b70849b0d
78e
~~~

## OPAQUE-3DH Test Vector 3

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 01
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
oprf_seed: 77bfc065218c9a5593c952161b93193f025b3474102519e6984fa64831
0dd1bf
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1
acacc4a8319
masking_nonce: cb792f3657240ce5296dd5633e7333531009c11ee6ab46b6111f15
6d96a160b2
server_private_key: 87ef09986545b295e8f5bbbaa7ad3dce15eb299eb2a5b3487
5ff421b1d63d7a3
server_public_key: 025b95a6add1f2f3d038811b5ad3494bed73b1e2500d8dadec
592d88406e25c2f2
server_nonce: 8018e88ecfc53891529278c47239f8fe6f1be88972721898ef81cc0
a76a0b550
client_nonce: 967fcded96ed46986e60fcbdf985232639f537377ca3fcf07ad4899
56b2e9019
server_keyshare: 0242bc29993976185dacf6be815cbfa923aac80fad8b7f020c9d
4f18e0b6867a17
client_keyshare: 03358b4eae039953116889466bfddeb40168e39ed83809fd5f0d
5f2de9c5234398
server_private_keyshare: b1c0063e442238bdd89cd62b4c3ad31f016b68085d25
f85613f5838cd7c6b16a
client_private_keyshare: 10256ab078bc1edbaf79bee4cd28dd9db89179dcc921
9bc8f388b533f5439099
blind_registration: d50e29b581d716c3c05c4a0d6110b510cb5c9959bee817fde
b1eabd7ccd74fee
blind_login: 503d8495c6d04efaee8370c45fa1dfad70201edd140cec8ed6c73b5f
cd15c478
oprf_key: 5bce459c307cd013dcbb295e303e2749b815d37a416f7db3859fbead356
ac139
~~~

### Intermediate Values

~~~
client_public_key: 02caf666b8ea63c9dee4498ac77a86a6d5efdda6777a2c8aa1
e726c32ba5d11a0d
auth_key: 0ec95438e7599b62959412890330ff6ec661aa69ab7141c6a4840456a20
57937
randomized_pwd: c85f1ce0ef374213a4f1fe2e319678ce0460da54dfa3188c65df4
bc99dae2148
envelope: 2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1acacc4
a8319d5cc24503cb4225d199a02097ffc5643f63fa40166009ca97c95f9eb95c1b4fc
handshake_secret: e82b11ecc2a63347a714bd7f92ab6607631843787312e60e7f5
9abc37f795845
server_mac_key: bef218a8076f646ad9ac954d4e191280bb5a58460668affe0c13a
6786b48d103
client_mac_key: 89a406c125cf1b2f57e235339e7c58a00435a66154e1982253065
6da15ea5e48
~~~

### Output Values

~~~
registration_request: 0246c44aa3759178508aac8d3271100baf0746fd691bb17
c21817077066fab9151
registration_response: 02bf62610c4e4bf8a467db2fc62d3c9d190d618c46e770
633e9f34383921e677b5025b95a6add1f2f3d038811b5ad3494bed73b1e2500d8dade
c592d88406e25c2f2
registration_upload: 02caf666b8ea63c9dee4498ac77a86a6d5efdda6777a2c8a
a1e726c32ba5d11a0da2600aba1f132fbf26a127553288f56b4fb27f5fb2cdf7baba3
61d68432e3fc02527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1aca
cc4a8319d5cc24503cb4225d199a02097ffc5643f63fa40166009ca97c95f9eb95c1b
4fc
KE1: 02f5143a70a787c7e15b0e7323ecdbaa87426c5be9083311eb0d2f92c72e6a21
22967fcded96ed46986e60fcbdf985232639f537377ca3fcf07ad489956b2e9019033
58b4eae039953116889466bfddeb40168e39ed83809fd5f0d5f2de9c5234398
KE2: 03e032d55ee42d2dd306797774293184d350298a82aea114dac4d160afe52d86
85cb792f3657240ce5296dd5633e7333531009c11ee6ab46b6111f156d96a160b2f6b
3c2d7f7d86f046e533768bf3cf38279a3620d64a93fbccf79ad5f7b64068eeeef1044
e92430bde145dd3e606cd6204f36cc19abf28554e4131425b2d6a0631e3746c22543c
0a5b1cf04e4cf9ef68c955ed313dc5de1f7aadf3c4c16660f3af18018e88ecfc53891
529278c47239f8fe6f1be88972721898ef81cc0a76a0b5500242bc29993976185dacf
6be815cbfa923aac80fad8b7f020c9d4f18e0b6867a1767de0b161ca0ef9378ff95be
ed9233ee8e635e59a841af94c7f01ca50ffe0d3e
KE3: f712a40f7b3edda40e511026b5a2b3d7047c5156609f46f44f77ebc1dd478253
export_key: e4c76d8c7d499c8baffd127fd2dafb1f2c3cdf254da8f7db3b856137b
26c7c89
session_key: 66e4e1c6013e2027c7913c2a4d762ab82a0f1b1715e9b780ff44c21e
e89ecce6
~~~

## OPAQUE-3DH Test Vector 4

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 01
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
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
oprf_seed: 482123652ea37c7e4a0f9f1984ff1f2a310fe428d9de5819bf63b3942d
be09f9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b
842e4426e42
masking_nonce: 5947586f69259e0708bdfab794f689eec14c7deb7edde68c816451
56cf278f21
server_private_key: c728ebf47b1c65594d77dab871872dba848bdf20ed725f0fa
3b58e7d8f3eab2b
server_public_key: 029a2c6097fbbcf3457fe3ff7d4ef8e89dab585a67dfed0905
c9f104d909138bae
server_nonce: 581ac468101aee528cc6b69daac7a90de8837d49708e76310767cbe
4af18594d
client_nonce: 46498f95ec7986f0602019b3fbb646db87a2fdbc12176d4f7ab74fa
5fadace60
server_keyshare: 022aa8746ab4329d591296652d44f6dfb04470103311bacd7ad5
1060ef5abac41b
client_keyshare: 02a9f857ad3eabe09047049e8b8cee72feea2acb7fc487777c0b
22d3add6a0e0c0
server_private_keyshare: 48a5baa24274d5acc5e007a44f2147549ac8dd675564
2638f1029631944beed4
client_private_keyshare: 161e3aaa50f50e33344022969d17d9cf4c88b7a9eec4
c36bf64de079abb6dc7b
blind_registration: 9280e203ef27d9ef0d1d189bb3c02a66ef9a72d48cca6c1f9
afc1fedea22567c
blind_login: 4308682dc1bdab92ff91bb1a5fc5bc084223fe4369beddca3f1640a6
645455ad
oprf_key: e5e9bdc66fb1fb8235ba6e2da193f43aa2ea30098257f1600585af2fd54
6e675
~~~

### Intermediate Values

~~~
client_public_key: 0258ee1175fab0690496dc51d46f2af29a662e639cdc59ab0d
b3795d5babf5ca8a
auth_key: 9b6331eeb6a6cef0979fd1555e066ba65f4f0dfd616373464614f765623
d3ab8
randomized_pwd: 88b647589c767b5621f412c2386185de0cdf64450752bc72f0449
c85ac7fa854
envelope: 75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842e44
26e420cc2c9c4f3d7b47c403951e688a266fb9cb62acc8aef79447379f136e41a442f
handshake_secret: 795f7aec5aeb31936ecd799b6cbdc88c6e907cc755fa3df9a61
e25dfb0e81022
server_mac_key: 7417c7daf044f762475911c7737288f94cab148afc5e28d51faf1
dcac753b315
client_mac_key: 1f5ac945caed1a6a27740bdd0278c2a57e692aefc6bb4db2e729f
65427712a13
~~~

### Output Values

~~~
registration_request: 033619c0aae68a60d889b7638593997a03edf68b3533516
b80a0f94d71fe387e66
registration_response: 038a30497a1020abe1f9fa91f131564cb8ccefb14507c0
99032c488fd515504b2f029a2c6097fbbcf3457fe3ff7d4ef8e89dab585a67dfed090
5c9f104d909138bae
registration_upload: 0258ee1175fab0690496dc51d46f2af29a662e639cdc59ab
0db3795d5babf5ca8aa4be5844b9d94456527f6ed141156920de4dc0f3a7d6540a576
73e72bce2f3ea75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842
e4426e420cc2c9c4f3d7b47c403951e688a266fb9cb62acc8aef79447379f136e41a4
42f
KE1: 036a18d16c663642f1adf6f2d56877ebf829f6536584eddf7ef398708934141d
0946498f95ec7986f0602019b3fbb646db87a2fdbc12176d4f7ab74fa5fadace6002a
9f857ad3eabe09047049e8b8cee72feea2acb7fc487777c0b22d3add6a0e0c0
KE2: 02059aa4bd27d22a75b00694cf340eaea154115e09ba22f7136f041e0c706191
f15947586f69259e0708bdfab794f689eec14c7deb7edde68c81645156cf278f219c7
aa01228faf14b7d74a756dda95d2ae756bd25fa08c998be78f9cd66fcf37600fce483
d1f45afddb02a76acf4ca02b6eaeb7d82d29e13c12fa3c5d0aaa88abc51ed36bddd7a
8182cb7e78c23bd24c1bd787886238791b409fe427c400e4bcbda581ac468101aee52
8cc6b69daac7a90de8837d49708e76310767cbe4af18594d022aa8746ab4329d59129
6652d44f6dfb04470103311bacd7ad51060ef5abac41b65bac77eee78d92f29714fe6
b3c04f645764f6a489e94072d02fd800b39cb079
KE3: 0a4bafe11d15fd0b4a0399edc5a8c0a0bc2850892122ea62ec30faf224274168
export_key: beda84a559bfe6a1d47ff2ea77bd40e0308595c455f3b6a0f345ebc2b
13c4103
session_key: 3978639fe09e27481b40b73dc115222c0dd8a69a7f7407ef4c5f854c
557046a9
~~~

## OPAQUE-3DH Test Vector 5

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: ristretto255
Context: 4f50415155452d504f43
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

### Input Values

~~~
oprf_seed: 98ee70b2c51d3e89d9c08b00889a1fa8f3947a48dac9ad994e946f408a
2c31250ee34f9d04a7d85661bab11c67048ecfb7a68c657a3df87cff3d09c6af9912a
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 13e74aa6263b562b9764bfbcbbe54081383f3057c26fead2a8b3d
5910e25fd29
masking_nonce: 8837b6c0709160251cbebe0d55e4423554c45da7a8952367cf336e
b623379e80
client_private_key: 74f3dec61a0126d02343c90d62c0399789041c71e44d15c05
bc8182bc764e903
server_private_key: 030c7634ae24b9c6d4e2c07176719e7a246850b8e019f1c71
a23af6bdb847b0b
server_public_key: 1ac449e9cdd633788069cca1aaea36ea359d7c2d493b254e5f
fe8d64212dcc59
server_nonce: ff26a6386c0a4077f512138e2203f247d56cbe900310cd43b4a55e4
c54231cc6
client_nonce: 077adba76f768fd0979f8dc006ca297e7954ebf0e81a893021ee24a
cc35e1a3f
server_keyshare: 046a0fce623dc08f253b239bfc96850e7ed02dc87f3e29830ccd
128aaa365840
client_keyshare: f27ab6cb55389234dd3f045713b6fc7c1f3de0e84140ee8b07be
e138ba587d79
server_private_keyshare: 26d7584722349b4670cbddb025f5e3e830b8bff4e482
80bab53db37c34bf0b06
client_private_keyshare: 32f2e562f6ca9ffa8add0c2c5b8b2ffe8c39667010ba
488071c889448f2a2f06
blind_registration: 21c97ffc56be5d93f86441023b7c8a4b629399933b3f845f5
852e8c716a60408
blind_login: f3fbfd52953b95ae7567d2590ecd8b0defe05a0321ec8230137157c1
6cc06b09
oprf_key: 606df815763ed4fd56e96e0133fd2142e7f732a0703c6538c44d2778107
a9a01
~~~

### Intermediate Values

~~~
client_public_key: cef8fa52ed24697b25418aa4703deb80a1e8f2caca405e2aaf
6758718ac7e33f
auth_key: ec096f794fa4eaa46e80d8021416f28eba830da7630912a4b1f34738cce
96c9c3ecdcbaa2599eeb653a39e37c0398190d82c3729c4d829edc3c13f3b54656d98
randomized_pwd: 5ceecc5644e55fd22c568bade729b6b9314164e01c3f2f1646314
d095a9abf8ae6ace00fec9c851657f01c333ef4eea5ad4594187ec919c4036ef61d36
a442c9
envelope: 13e74aa6263b562b9764bfbcbbe54081383f3057c26fead2a8b3d5910e2
5fd294017af6acff57ecca4e6f9d519901fe0eb1f9a37ba78c01d59da1726e91b2328
64b089c1423e3e70e5656b3e77fde8f8e394dd83fd5d3c6341790c1e00c5bef948d5a
561e833c4d0a74281c7333dcbe5f06db023b9a60da6da32492128565c45
handshake_secret: b4e41f5055c8b298144f4d5cd73f7075657d6570062cc0d7930
82dbd105174f9f04d5b26cd4eddb498b4e90129487c7661509d539a130c4e0418fe0d
c2d2c0f0
server_mac_key: 8bcee1c29a47651dadb623978a4efb44058ea660615f8bea4b751
9727b96931b75e176a2aa6c7e653adafcf4fd415348b92dcf0421de52772880d5ecc5
d85a33
client_mac_key: 21b665d6b15dbb9682be949a8f34a048bb0e7ef9dca0258417f8f
ad934047a09a22ccc4ad675fd8ddc8f375b0259b658e00c81fc03d84cc03c6e03c5b2
043c54
~~~

### Output Values

~~~
registration_request: b43f5246573e51d9407cc1e337f6cb9823aebc34d4d9546
8604c479dc097004f
registration_response: 649e5facca021247b31ba76a577e3b73cd372c1bd2abdb
332c1c7b0f2742f1151ac449e9cdd633788069cca1aaea36ea359d7c2d493b254e5ff
e8d64212dcc59
registration_upload: cef8fa52ed24697b25418aa4703deb80a1e8f2caca405e2a
af6758718ac7e33f11518ef42b8821faff7cf52985e7bc1010cee906229b645688335
6f724a98bb13ae3bedf731a26fba8c473af44821acec8596d786df41345f8d8ee150e
0a5a3e13e74aa6263b562b9764bfbcbbe54081383f3057c26fead2a8b3d5910e25fd2
94017af6acff57ecca4e6f9d519901fe0eb1f9a37ba78c01d59da1726e91b232864b0
89c1423e3e70e5656b3e77fde8f8e394dd83fd5d3c6341790c1e00c5bef948d5a561e
833c4d0a74281c7333dcbe5f06db023b9a60da6da32492128565c45
KE1: eec2a6633a86b4412d2510ab021109c252fee0f6bafa8a9d2f6324db070b946b
077adba76f768fd0979f8dc006ca297e7954ebf0e81a893021ee24acc35e1a3ff27ab
6cb55389234dd3f045713b6fc7c1f3de0e84140ee8b07bee138ba587d79
KE2: 387f48e60e4fcbba1c86320608dd00a0d4caf8bf6f9671ec38e08378df97507b
8837b6c0709160251cbebe0d55e4423554c45da7a8952367cf336eb623379e8098a42
606a531940b2cccbf26bd2fa56f5cb4a21fe98ed482b3c999d972c0b7fcc8217b035b
f0a7d7e71c544270321a19ebc68e8e71a9657f043447e193957f86e8d0f1929a2c58b
1e1a34dd0e40f624c772328ffc6ac33fc1d4e30f5707a61447e1e7421a66e63532ade
320af83fd10de94268887bc6cfc3fbfbcfaada81c980ad46ef85b593a52d9d8bb386b
a054577116fbe0321cb1fe06d01d5747e1d5df9ff26a6386c0a4077f512138e2203f2
47d56cbe900310cd43b4a55e4c54231cc6046a0fce623dc08f253b239bfc96850e7ed
02dc87f3e29830ccd128aaa3658400a3cce171a6d9447d19e1fc382df2bcacaf0eeb6
098d2895bffe8f8d3b97283de319d19a31e64f4c69d5da9c009468476a9fab05e5ba7
ce45c8c46cae7ed4f56
KE3: 85ecbbe014dd0216d1404d506040fcdd03c967b24d7618812b2e686972bf81aa
a96fe77bf7b7a0fdec6b84a22cb77756b90eeccaed40107e9b641a53c065e769
export_key: f147adfdd224e197d4b7d50b346457c112c11c97fa0c11385599a3bd4
e764338245c8b5130e6f615758ae2962509acb61a980dec8ed25b2257043b79bdb6af
ba
session_key: 1b90ffcd6aca7dd7276b851cbbd28d5d849e56ad0825a909753b8d50
10b487d6d2e56f0674d74c493a28f2caf2aaf023579a3288049ffb1ca72b5a1aabfbc
1b6
~~~

## OPAQUE-3DH Test Vector 6

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
EnvelopeMode: 02
Group: ristretto255
Context: 4f50415155452d504f43
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
oprf_seed: 41723264b8bb2700cdd47e339d95404519f2fb3da58c93d84cbb4d51de
6757a31919382ba65c10e80cbb7f50a43e32782b08f8bee3ffaba39407660179105ac
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 86e2b0916361fb6a69f9a097e3ef2f83f8fd5f95cc79432eabf3e
01f0020bac6
masking_nonce: f551feeed04ea7967c2d6c8847b6ca8bc09eced6848f0a73208e71
e3f1b688e6
client_private_key: f51ea8d2b529ab39f6e6c883a14c38941c81115856ef6ef92
c0a0aacf1449e05
server_private_key: 5791eacfa2980bc0807bd327239b53f4370eb21d5b306257a
82104eaaab43f01
server_public_key: 846c28da13144e5908f1db4c8ba2c848ac34ae6b9a8855dcdb
08d5ecfb000d73
server_nonce: f35483b457e208972f1cbffbb70249fa31064a8883002d3b8024a02
3b4feac41
client_nonce: e0d04374ad9a276620c681abfca7bdb432e63509e5ec96ed2ec5542
f6fc7db23
server_keyshare: d856f10de218fc035faad7dddd3f3f01e2f27ff589ebbe605fa8
e4659652fa52
client_keyshare: 1c48ce65e44088bb7f7503f7ad7f3a050177b727e9b490aac3d4
e639be06e157
server_private_keyshare: 381fbcf62f24a60451e6ca6a9b8cffdacb40f507334b
4384173539b287a94e0d
client_private_keyshare: d7b1baf64ffc214733c46987fd2a0e91bb1f30f8ac55
70d636293675879c6900
blind_registration: a8fe808852933dec78a535ad1cd3a6e64b82b5302a5a99f16
66c3cce1c4f2408
blind_login: ec58b546968ed476e1a55a9dff9c80cc9c56cc9021a662d5cb7d5d37
109b760b
oprf_key: 174df334e2cde01a6fbd987ac279799c068d4e465427a5d1eff0a863fb1
ac005
~~~

### Intermediate Values

~~~
client_public_key: 262321548e1fbb06525167181fb3ca34409410120c7feb4144
26b4176f519264
auth_key: 168e6fa2cfd61440f03afe029498bed77751b3fab80c3b3d248248fa44f
9da8e69cf6d89b12f8ae6072f49deaf300921f35cb6539d83887dc376f9a7b41f3bde
randomized_pwd: a7df98e0f6b7f0d0d69c81bacc59b575cca85669aeb31a8f00693
ed03e8c04b577a69a9c6c414564da632bc433a4964f4ec1267d78a2b0788f25da152d
e88a94
envelope: 86e2b0916361fb6a69f9a097e3ef2f83f8fd5f95cc79432eabf3e01f002
0bac628561ede51dbcd029be43807303bd2c7fe0a7acdd0491eed4196d170c832d240
63992e571a1a491b8ba0a99c5291648ce3047c26c62b9ba1d75055088b10029a5e46d
29d79f85a6e2d6d28eaebf10236ea9e9296270f54bb3667e935c0e006d5
handshake_secret: 9804e84ed42d8755823661bb35bb18bea4b74cb7b55e50a62e6
53f7aaad8d32ea837b2f03c3a3bbb40cc139b28625590227ccecd35da37b4dff7abe1
7275147b
server_mac_key: 1e33b3829eec666586e0ebc4e48aaf0b4d9e7d18eb36e18bc9742
a89bb084e483f974155efcd8b243cfe6431b549ff44268668f962e80653cd49cc5ffa
7c4394
client_mac_key: ae2f19f91640bf582545e29e52f3ce8f1677e01457c8c626404ab
5c9b4358b2eda4bc819bfe80f2274ac3cb4b4f65a39b88914a063e838c33c168173f6
e5ea58
~~~

### Output Values

~~~
registration_request: 2079dfe5df4e57dc4a26f9e87e9a10cc9bbfe9f3e75723e
697f1e1d311e1c217
registration_response: e674b472a20961a93063e0d6cbcba46e22c6b90934d731
b3a104452a0788d13d846c28da13144e5908f1db4c8ba2c848ac34ae6b9a8855dcdb0
8d5ecfb000d73
registration_upload: 262321548e1fbb06525167181fb3ca34409410120c7feb41
4426b4176f519264ac65179ca59f395afdb45d5e69666095835c6758219a3bcbb3665
de79af7783f6b544fb95a75af9a19e7c073cdb5721a766ed043437af42e43cc74299c
dde20d86e2b0916361fb6a69f9a097e3ef2f83f8fd5f95cc79432eabf3e01f0020bac
628561ede51dbcd029be43807303bd2c7fe0a7acdd0491eed4196d170c832d2406399
2e571a1a491b8ba0a99c5291648ce3047c26c62b9ba1d75055088b10029a5e46d29d7
9f85a6e2d6d28eaebf10236ea9e9296270f54bb3667e935c0e006d5
KE1: 30ac2903834a284959cbf70561d9c9419f66ce0bbcad345584d8708c4c3cb87c
e0d04374ad9a276620c681abfca7bdb432e63509e5ec96ed2ec5542f6fc7db231c48c
e65e44088bb7f7503f7ad7f3a050177b727e9b490aac3d4e639be06e157
KE2: 8c761e41102564e2015ae978b5759424ffdcdbdda3782a9171ef0fb6ec5dca21
f551feeed04ea7967c2d6c8847b6ca8bc09eced6848f0a73208e71e3f1b688e6867ab
18f59b29ffa64c845147a80f8f75b44e2764775401eaee4615531c655bd476567b24f
5cfd146faf22d8d82d86349b0ad2abdcfb0a6297d75391bd38d30710c26995b036add
646ee8ee10d545495b81347d49d15a3e193c7388285c9ed92287720afae68ec18b245
f33f475fa81baaa8a32de94cffa29b2728fa93dc5721af51c872d88e15e0cbad40264
4593feecb612406e69a5a075c2b2e85e0039ac9f35483b457e208972f1cbffbb70249
fa31064a8883002d3b8024a023b4feac41d856f10de218fc035faad7dddd3f3f01e2f
27ff589ebbe605fa8e4659652fa5280e044783fea165ee28120436026775fc6041224
a0012448d1e535ac4bcf28179a201820998760f7fa6c8ee4b5622c9a260c89b91b367
340c45c1767aa87a02d
KE3: 8da2b77f5bd61568b875e7bb35d1983981799a4cf587e4ece474fe3f5048c4e2
390b22c489712bcb85bb77e3e69e774be8977311e37ad18f0c2b8bc0dea9b89e
export_key: f4a80f94c840b17518aed57508d030bd0a034cc1e9dd64aa20242774d
3a3f5dbc2de6a715f322749183a048453ebe267ec8eb7c0198641f45322e7f9035bc1
4d
session_key: 043f40c7d6fa0961e40738c8b8bcfe72a844669b4aecfeca2c4f0ab6
9ebae08866652e3afaf8968ce7cea29725cb2caea3b40ec072e6afbbb0a08202b9d16
de6
~~~

## OPAQUE-3DH Test Vector 7

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 02
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

### Input Values

~~~
oprf_seed: 26bf796e5e24e879ebb50b60b2569a3cefa279126183be8b798dc8a346
5fab30
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d761c8b636815f62dad9d7ed319efefe641bb4c3d1cc83a6a6600
bbadfe603ad
masking_nonce: 65ebd00e208f7a1c679eb9edc4b8943b0ffbe09577ecdb625726cb
333292ebc7
client_private_key: 185f462ce1eec52f588a8e392f36915849b6bfcb6bd5b904c
095be332181a28b
server_private_key: df77e28c3c1a1ef8821fb7db7020bdd866ab6f771482b58ca
91c9485d74c9011
server_public_key: 03d264f0e386387704da3d82a32883d2045326b32296ed1028
12dd3ed6d26f3b8b
server_nonce: 6819cd5cca28ea3ed382a155205669141c9bcbdca0a2c66ad0adc66
f43e4e82c
client_nonce: b9e5e27d7077eec3be075d20ac4e145572a45beeeb6066b9533421c
2cd4fee72
server_keyshare: 02e47a5f856e1ad51f3c0e9e34b620c2f7e2d4b70c59db7c1d0a
3a108322242baa
client_keyshare: 02778a3a12ae78faf76c59723a0b72ee134ac3977d297ce65d59
b41a12a385975d
server_private_keyshare: c25d83d1a98a38717e97bfde3b1dd8eb8d3346ca21d8
a6439465aea2b4b54c1e
client_private_keyshare: cc99d1ec838306ac17f68550b99cea1bc58b89723c0d
fada6c3dcb53ee14b2d8
blind_registration: e147f60270fc68fd0990c1fd9b34b9187adfc0b6e485f8fc6
ab6fea7ba043862
blind_login: 417fe2da072d4eccf379adfb08f7f8ec28aadd14a78b68466e51a251
d13299f2
oprf_key: eb8e7898b5f1d9af9fdbb68ad4ea14e9912c7a26195e86f85830c45b7d9
a2c58
~~~

### Intermediate Values

~~~
client_public_key: 026be6ae76a078ed03bada87b595104050b65951dbd2f4160b
7fe0153494e9dc9b
auth_key: 1792340644a8a5dd06b1e9e1e9feb039de1d2abff1dc1cc55895b15658b
a9f1a
randomized_pwd: c9b0ed265dc68ec56bff2805380bf7d32a2616e00247e576b41ce
302635ea703
envelope: d761c8b636815f62dad9d7ed319efefe641bb4c3d1cc83a6a6600bbadfe
603ad77bdb47bd2171ea6741727762e539532004a6771ee282e68ba1818150fe06d42
ccdc7e16e6a1341e76dba04f259a674904d04369b6dce73e6be3000cc6b0e6ee
handshake_secret: 4b8404af87c500e6168c4e124fe65c73e4ed690749fbbe60c9e
04ea40f115891
server_mac_key: 2b9a10366f931384ecf351deea83e51c18a057548d7cceacc0039
c560c699988
client_mac_key: 34d182fd055784c76dfb44606d0043eeff7a25407576d0c553e20
a97c58d4a43
~~~

### Output Values

~~~
registration_request: 029f166cdf0f56c8b1e40328800a44d43a40c04ac04b5e1
098281d668738cfa456
registration_response: 035dfd3788066782eff1c6b5212125d83543f338ea3e1a
fbe413178af011b10b5103d264f0e386387704da3d82a32883d2045326b32296ed102
812dd3ed6d26f3b8b
registration_upload: 026be6ae76a078ed03bada87b595104050b65951dbd2f416
0b7fe0153494e9dc9b0f8b266886832d3ef6fe777dfdb3049161b3895466318bf0438
e2d3cf6da8308d761c8b636815f62dad9d7ed319efefe641bb4c3d1cc83a6a6600bba
dfe603ad77bdb47bd2171ea6741727762e539532004a6771ee282e68ba1818150fe06
d42ccdc7e16e6a1341e76dba04f259a674904d04369b6dce73e6be3000cc6b0e6ee
KE1: 02e57991edfd0d7e2fee31d88f5f1ab389b7d7879bfe9fc380a6615cdd732c2f
9bb9e5e27d7077eec3be075d20ac4e145572a45beeeb6066b9533421c2cd4fee72027
78a3a12ae78faf76c59723a0b72ee134ac3977d297ce65d59b41a12a385975d
KE2: 029e08635dfe781f73af303136699e27509eebdb2505f6993450a6324b60b95b
6765ebd00e208f7a1c679eb9edc4b8943b0ffbe09577ecdb625726cb333292ebc7668
578bd702501179d5542ac6bd36f9b2dad11193681fde5a0af509dc9acf83f011bdf07
30aca8859630aeb14cc04aa09e86ec153d27b8f014aa8edbe01afde27e03bd839bee6
a3ce765684c4ac5a34a864d289f07a7f8ad397adabf59cce27621f50164b78b0d8791
700b7ec997c86dfdceb38568591db6b48eeb070ab7c378766819cd5cca28ea3ed382a
155205669141c9bcbdca0a2c66ad0adc66f43e4e82c02e47a5f856e1ad51f3c0e9e34
b620c2f7e2d4b70c59db7c1d0a3a108322242baae9d525e656a7a3b2796e9b4c8ca34
11ebc6578d2f1a1c340e9fb1a2dc20b0f99
KE3: 3fb42462fb7bda5265d39839118f3fd83352d0583cc31c6893659df5f6c08380
export_key: d5c4cdd4184af45fe06771a2d103c35a6e625d6f47ed38a1606557fff
0e68dfb
session_key: 8dafa5bc24c6f8316f5adda8620331518f5f7ef9b6cbeca030a2a663
6d7403cf
~~~

## OPAQUE-3DH Test Vector 8

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 02
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
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
oprf_seed: 14aa8d5a418b130dafb6513ad917000c83c70199f3202b928f355704e3
a25dc7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 6244563994473ca960143fe2de622464f00e607813de02e1784fa
9f7d6e3b7bc
masking_nonce: c68c15bf920702323ae20c552cdaefac7e1d665da7cc705485b75a
3514b967a3
client_private_key: 56c2f4d56bcb3cb24401b182ad275c32713d314a14cd58a64
66cfb980f9a2605
server_private_key: f1a945c34e824e9063e6f2ac4fc8a48af35e4c417ebc43be4
717550e6140dc52
server_public_key: 03512bae40ee42c0fce71f447611b39f2e91d68437f75fc1f1
71e80ae8a09d30ce
server_nonce: dc4ff822a5e5865d2f9e86117a7480a8a64a166e1cb724f59c39f93
a802f7f70
client_nonce: af0023091cb7e3e9c8581d8ca2837e78cd88fb76287d235b919bc75
7a0a70ab8
server_keyshare: 03ba9d8ad954f80f5ee6053c6c51f70a7ef7a65cc9f73c6e809d
0eac701f412acb
client_keyshare: 02ef46b931a4b8a017235597c595090dac6f059f599a00f46e08
c62fc266e28d04
server_private_keyshare: 1af9e9958dbf9198484561119bff18efc1f931f08888
9520195d6a0e47b7ce91
client_private_keyshare: f3f58965653b1dcdbf269eabb52782056318551fd0f9
48617aac77ab942f2817
blind_registration: 677e95d5335dbbd7d468a4bc0750ce4672a5b3e9098e8263f
37dea986a921e99
blind_login: e304d794b21e52c661090c25af0e432e6bdcc891568226adab56bf02
dd0ea391
oprf_key: e2f616cf2e16b6b731bf9b5ab9fd75dbb5c30ef7443465d4662e144c342
fe74e
~~~

### Intermediate Values

~~~
client_public_key: 030833fa0933e79ed8dafa9cf3d537eec06987fb1c064d74f4
d45a480de9a179c9
auth_key: 76f10720c0ed60bb08d9c0d34e9ace15f27bbceda5ac7562495ff00cf7b
d7f57
randomized_pwd: a9fad21233431757ffc27f2b86538d7137834147144d9aee99fdc
7510ad5caa2
envelope: 6244563994473ca960143fe2de622464f00e607813de02e1784fa9f7d6e
3b7bc168b8289d9fb356cf773e5bff34b907bb58f5a4fd60a40877097bb6d72343a30
68d69abc263b9b20dfb9006fda428511949459d57470eb76903aee9dd06a8464
handshake_secret: 4988e81855e82e047cb633f4b7749e96c308cf27eeefd5804a5
e3ced37c62b49
server_mac_key: 1a6bdc07970adcf6098d05acdee53929902579fbc8ec7a5e0ef7f
1eae5cd8e53
client_mac_key: 9ed05257c961118165d9e279ed31aee488a004b39da3c162a5e76
65c043221cd
~~~

### Output Values

~~~
registration_request: 02d0b88d26d0c1e339ac89d46af6a1a550ca5516809fad6
721526bc456c5e04c73
registration_response: 0332a6c93b45b41c4f73ee7261fb5fdb22c9a32b1490af
7a910b98b2dff6a4d9ad03512bae40ee42c0fce71f447611b39f2e91d68437f75fc1f
171e80ae8a09d30ce
registration_upload: 030833fa0933e79ed8dafa9cf3d537eec06987fb1c064d74
f4d45a480de9a179c9dcc1c99a1b1eecb38d8e1a9013be3ac6b6500db38c3033e2975
a87e8e3e879bb6244563994473ca960143fe2de622464f00e607813de02e1784fa9f7
d6e3b7bc168b8289d9fb356cf773e5bff34b907bb58f5a4fd60a40877097bb6d72343
a3068d69abc263b9b20dfb9006fda428511949459d57470eb76903aee9dd06a8464
KE1: 03d59aae90b1a1835b9543a3ffdc93d0a859c5a052a77544f31ce0fd348726cd
95af0023091cb7e3e9c8581d8ca2837e78cd88fb76287d235b919bc757a0a70ab802e
f46b931a4b8a017235597c595090dac6f059f599a00f46e08c62fc266e28d04
KE2: 036a2007acdda2855e6eeb0824060aa63ca09762bf7935f90d47de52ef879155
e8c68c15bf920702323ae20c552cdaefac7e1d665da7cc705485b75a3514b967a3c3b
e7776cefef435897384bd01d7a7548bb009ee50bb14d12d3d5d090e7a3cbb545a193a
6c3a18fb08cdefb10446101d25e639a2081842b4b6c24c01268abf760f9d13cf41d67
2ec43217971e90f3b40e5db80b0bb07875eb3164f5acf635aee5518f717c3d5e1a45f
134be9ca15ba0da1fde0feeba39a81344a7fed85722bbdeedc4ff822a5e5865d2f9e8
6117a7480a8a64a166e1cb724f59c39f93a802f7f7003ba9d8ad954f80f5ee6053c6c
51f70a7ef7a65cc9f73c6e809d0eac701f412acbb9fc7f79ef97282a48168c84462a0
e39f1db318670eaa49c6374c5f2965d2d04
KE3: 017a137a71391c63709d9047a3c2526259b74e671b92b168ab1d65fc26dd2101
export_key: d06b749af4739bfbf4422aba432cdb607c54a769b9d5543e9107d477f
0594b1c
session_key: 41f5201e8e537b961cea8ff9dbf1d30bcc02833eee233af99d5eeddc
448a526f
~~~

