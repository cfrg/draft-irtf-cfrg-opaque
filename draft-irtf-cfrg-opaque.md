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
hashing or other hardening schemes. OPAQUE is also extensible, allowing
clients to safely store and retrieve arbitrary application data on servers
using only their password.

OPAQUE is defined and proven as the composition of two functionalities:
an oblivious pseudorandom function (OPRF) and an authenticated key
exchange (AKE) protocol. It can be seen
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

The name OPAQUE is a homonym of O-PAKE where O is for Oblivious. The name
OPAKE was taken.

# Cryptographic Dependencies {#dependencies}

OPAQUE depends on the following cryptographic protocols and primitives:

- Oblivious Pseudorandom Function (OPRF); {{deps-oprf}}
- Key Derivation Function (KDF); {{deps-symmetric}}
- Message Authenticate Code (MAC); {{deps-symmetric}}
- Cryptographic Hash Function; {{deps-hash}}
- Memory-Hard Function (MHF); {{deps-hash}}
- Authenticated Key Exchange (AKE) protocol; {{deps-ake}}

This section describes these protocols and primitives in more detail. Unless said
otherwise, all random nonces used in these dependencies and the rest of the OPAQUE
protocol are of length `Nn` = 32 bytes.

## Oblivious Pseudorandom Function {#deps-oprf}

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol between client and
server for computing a PRF such that the client learns the PRF output and neither party learns
the input of the other. This specification uses the the OPRF defined in {{!I-D.irtf-cfrg-voprf}},
Version -07, with the following API and parameters:

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
variant) of the OPRF described in {{I-D.irtf-cfrg-voprf}}. The implementation of
DeriveKeyPair based on {{I-D.irtf-cfrg-voprf}} is below:

~~~
DeriveKeyPair(seed)

Input:
- seed, pseudo-random byte sequence used as a seed.

Output:
- private_key, a private key.
- public_key, the associated public key.

Steps:
1. private_key = HashToScalar(seed, dst="OPAQUE-DeriveKeyPair")
2. public_key = ScalarBaseMult(private_key)
3. Output (private_key, public_key)
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

- Harden(msg, params): Repeatedly apply a memory-hard function with parameters
  `params` to strengthen the input `msg` against offline dictionary attacks.
  This function also needs to satisfy collision resistance.

## Authenticated Key Exchange (AKE) Protocol {#deps-ake}

OPAQUE additionally depends on a mutually Authenticated Key Exchange (AKE) protocol.
This specification defines one particular AKE based on 3DH; see {{ake-protocol}}.
3DH assumes a prime-order group as described in {{I-D.irtf-cfrg-voprf, Section 2.1}}.
We let `Npk` and `Nsk` denote the size of public and private keys, respectively,
used in the AKE. The AKE protocol must provide the following functions:

- RecoverPublicKey(private_key): Recover the public key related to the input `private_key`.
- SerializePublicKey(public_key): Serialize a public key to a byte string of length Npk.
- GenerateAuthKeyPair(): Return a randomly generated private and public key pair. This can be
  implemented by generating a random private key `sk`, then computing `pk = RecoverPublicKey(sk)`.
- DeriveAuthKeyPair(seed): Derive a private and public authentication key pair
  deterministically from the input `seed`.

For the AKE sspecified in this document, the implementation of DeriveAuthKeyPair
is as follows:

~~~
DeriveAuthKeyPair(seed)

Input:
- seed, pseudo-random byte sequence used as a seed.

Output:
- private_key, a private key.
- public_key, the associated public key.

Steps:
1. private_key = HashToScalar(seed, dst="OPAQUE-DeriveAuthKeyPair")
2. public_key = ScalarBaseMult(private_key)
3. Output (private_key, public_key)
~~~

HashToScalar(msg, dst) is as specified in {{I-D.irtf-cfrg-voprf, Section 2.1}}.

# Protocol Overview {#protocol-overview}

OPAQUE consists of two stages: registration and authenticated key exchange.
In the first stage, a client registers its password with the server and stores
its credential file on the server. The client inputs its credentials,
which includes its password and user identifier, and the server inputs its
parameters, which includes its private key and other information.

The client output of this stage is a single value `export_key` that the client
may use for application-specific purposes, e.g., to encrypt additional
information for storage on the server. The server does not have access to this
`export_key`.

The server output of this stage is a record corresponding to the client's
registration that it stores in a credential file alongside other client
registrations as needed.

Registration is the only part in OPAQUE that requires a server-authenticated
and confidential channel, either physical, out-of-band, PKI-based, etc.

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

The rest of this document describes the details of these stages in detail.
{{client-credential-storage}} describes how client credential information is
generated, encoded, encrypted, and stored on the server. {{offline-phase}} describes the
first registration stage of the protocol, and {{online-phase}} describes the
second authentication stage of the protocol. {{configurations}} describes how
to instantiate OPAQUE using different cryptographic dependencies and parameters.

# Client Credential Storage {#client-credential-storage}

OPAQUE makes use of a structure `Envelope` to manage client credentials.
Clients uses this envelope to recover private keys used for authentication.

OPAQUE allows applications to either provide custom client private and public keys
for authentication, or to generate them internally. Each public and private key
value is encoded or serialized as a byte string, specific to the AKE protocol in
which OPAQUE is instantiated. These two options are defined as the `external` and
`internal` modes, respectively. See {{envelope-modes}} for their specifications.

The internal mode is RECOMMENDED. Applications can use the external mode if there
are additional requirements for how private keys are generated, e.g., in the case
of compliance, or if applications have pre-existing private keys they wish to
register for use with OPAQUE.

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

inner_env: A mode dependent `InnerEnvelope` structure. See {{envelope-modes}} for its specifications.

auth_tag: Authentication tag protecting the contents of the envelope, covering the envelope nonce,
`InnerEnvelope`, and `CleartextCredentials`.

The size of the serialized InnerEnvelope is denoted `Ne` and varies based on the mode.
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
function defined below. The `RecoverKeys` implementation is defined in the
following sections.

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
- client_private_key, The encoded client private key for the AKE protocol.
- export_key, an additional client key.

Exceptions:
- EnvelopeRecoveryError, when the envelope fails to be recovered

Steps:
1. auth_key = Expand(randomized_pwd, concat(envelope.nonce, "AuthKey"), Nh)
2. export_key = Expand(randomized_pwd, concat(envelope.nonce, "ExportKey", Nh)
3. (client_private_key, client_public_key) =
    RecoverKeys(randomized_pwd, envelope.nonce, envelope.inner_env)
4. cleartext_creds = CreateCleartextCredentials(server_public_key,
                      client_public_key, server_identity, client_identity)
5. expected_tag = MAC(auth_key, concat(envelope.nonce, inner_env, cleartext_creds))
6. If !ct_equal(envelope.auth_tag, expected_tag),
     raise EnvelopeRecoveryError
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

The implementations of this interface for `internal` and `external` modes
are in {{internal-mode}} and {{external-mode}}, respectively.

The size of the envelope may vary between modes. If applications implement
{{preventing-client-enumeration}}, they MUST use the same envelope mode throughout
their lifecycle in order to avoid activity leaks due to mode switching.

### Internal Mode {#internal-mode}

In this mode, the client's private and public keys are deterministically derived
from the OPRF output.

With the internal key mode the `EnvelopeMode` value MUST be `internal` and the
`InnerEnvelope` is empty, and the size `Ne` of the serialized `Envelope` is `Nn + Nm`.

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
- client_private_key, The encoded client private key for the AKE protocol.
- client_public_key, The encoded client public key for the AKE protocol.

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
1. pseudorandom_pad = Expand(randomized_pwd, concat(nonce, "Pad"), Nsk)
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

 response = CreateRegistrationResponse(request,
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
} RegistrationRecord;
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
- credential_identifier, an identifier that uniquely represents the credential.
- oprf_seed, the seed of Nh bytes used by the server to generate an oprf_key.

Output:
- response, a RegistrationResponse structure.

Steps:
1. seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
2. (oprf_key, _) = DeriveKeyPair(seed)
3. Z = Evaluate(oprf_key, request.data)
4. Create RegistrationResponse response with (Z, server_public_key)
5. Output response
~~~

#### FinalizeRequest {#finalize-request}

To create the user record used for further authentication, the client executes
the following function. In the internal key mode, the `client_private_key` is nil.
See {{envelope-creation-recovery}} for more details.

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
- record, a RegistrationRecord structure.
- export_key, an additional client key.

Steps:
1. y = Finalize(password, blind, response.data)
2. randomized_pwd = Extract("", Harden(y, params))
3. (envelope, client_public_key, masking_key, export_key) =
    CreateEnvelope(randomized_pwd, response.server_public_key, client_private_key,
                   server_identity, client_identity)
4. Create RegistrationRecord record with (client_public_key, masking_key, envelope)
5. Output (record, export_key)
~~~

See {{online-phase}} for details about the output export_key usage.

Upon completion of this function, the client MUST send `record` to the server.

#### Finalize Registration {#finalize-registration}

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
- client_identity: client identity, as described in {{client-credential-storage}}.

The server inputs the following values:

- server_private_key: server private for the AKE protocol.
- server_public_key: server public for the AKE protocol.
- server_identity: server identity, as described in {{client-credential-storage}}.
- record: RegistrationRecord corresponding to the client's registration.
- credential_identifier: client credential identifier.
- oprf_seed: seed used to derive per-client OPRF keys.

The client receives two outputs: a session secret and an export key. The export key
is only available to the client, and may be used for additional application-specific
purposes, as outlined in {{export-key-usage}}. The output `export_key` MUST NOT be
used in any way before the protocol completes successfully. See {{envelope-encryption}}
for more details about this requirement. The server receives a single output: a session
secret matching the client's.

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
: A nonce used for the confidentiality of the masked_response field.

masked_response
: An encrypted form of the server's public key and the client's `Envelope` structure.

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
- record, an instance of RegistrationRecord which is the server's
  output from registration.
- credential_identifier, an identifier that uniquely represents the credential
  being registered.
- oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key.

Output:
- response, a CredentialResponse structure.

Steps:
1. seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
2. (oprf_key, _) = DeriveKeyPair(seed)
3. Z = Evaluate(oprf_key, request.data)
4. masking_nonce = random(Nn)
5. credential_response_pad = Expand(record.masking_key,
     concat(masking_nonce, "CredentialResponsePad"), Npk + Ne)
6. masked_response = xor(credential_response_pad,
                         concat(server_public_key, record.envelope))
7. Create CredentialResponse response with (Z, masking_nonce, masked_response)
8. Output response
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
7. Output (client_private_key, server_public_key, export_key)
~~~

## AKE Protocol {#ake-protocol}

This section describes the authenticated key exchange protocol for OPAQUE using 3DH,
a 3-message AKE which satisfies the forward secrecy and KCI properties discussed in
{{security-considerations}}. The protocol consists of three messages sent between
client and server, each computed using the following application APIs:

- ke1 = ClientInit(password)
- ke2 = ServerInit(server_identity, server_private_key, server_public_key, record, credential_identifier, oprf_seed, ke1)
- ke3, session_key, export_key = ClientFinish(password, client_identity, server_identity, ke2)
- session_key = ServerFinish(ke3)

Outputs `ke1`, `ke2`, and `ke3` are the three protocol messages sent between client
and server. `session_key` and `export_key` are outputs to be consumed by applications.
Applications can use `session_key` to derive additional keying material as needed.
Applications can use `export_key` for further application-specific purposes;
see {{export-key-usage}}.

Both ClientFinish and ServerFinish return an error if authentication failed. In this case,
clients and servers MUST NOT use any outputs from the protocol, such as `session_key` or
`export_key`. ClientInit and ServerInit both implicitly return internal state objects
`client_state` and `server_state`, respectively. The client state has the following
named fields:

- blind, an opaque byte string of length Nok;
- client_sescret, an opaque byte string of length Nsk; and
- ke1, a value of type KE1.

The server state has the following fields:

- expected_client_mac, an opaque byte string of length Nm; and
- session_key, an opaque byte string of length Nx.

{{opaque-client}} and {{opaque-server}} specify the inner workings of client and
server functions, respectively.s

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
: Client ephemeral key share of fixed size Npk.

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
1. dh1 = SerializePublicKey(sk1 * pk1)
2. dh2 = SerializePublicKey(sk2 * pk2)
3. dh3 = SerializePublicKey(sk3 * pk3)
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
ClientInit(password)

State:
- state, a ClientState structure.

Input:
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
ClientFinish(client_identity, password, server_identity, ke1, ke2)

State:
- state, a ClientState structure

Input:
- client_identity, the optional encoded client identity, which is set
  to client_public_key if not specified.
- password, an opaque byte string containing the client's password.
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
2. client_secret, client_keyshare = GenerateAuthKeyPair()
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

Exceptions:
- HandshakeError, when the handshake fails

Steps:
1. ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare,
    state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
2. preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
3. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
4. expected_server_mac = MAC(Km2, Hash(preamble))
5. If !ct_equal(ke2.server_mac, expected_server_mac),
     raise HandshakeError
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
- record, the client's RegistrationRecord structure.
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
- session_key, the shared session secret if and only if KE3 is valid.

Exceptions:
- HandshakeError, when the handshake fails

Steps:
1. if !ct_equal(ke3.client_mac, state.expected_client_mac):
2.    raise HandshakeError
3. Output state.session_key
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
2. server_secret, server_keyshare = GenerateAuthKeyPair()
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
MAC of suitable length. For example, if MAC is HMAC-SHA256, then `Nh` could be
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

sWe note that as shown in {{OPAQUE}}, these protocols, and any aPAKE
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

Finally, applications must use the same envelope mode when using this prevention
throughout their lifecycle. The envelope size varies between modes, so a switch
in mode could then be detected.

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
draft-06 of {{I-D.irtf-cfrg-voprf}}.

## Real Test Vectors {#real-vectors}

### OPAQUE-3DH Real Test Vector 1

#### Configuration

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

#### Input Values

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
~~~

#### Intermediate Values

~~~
client_public_key: 2046d15924599adbcb7c03abe00350e9dde62267037eb0d2a9
59a17b2210eb0f
auth_key: 0ee186ac3a0fe0ec45d36c7cc9786934918a58d6a1abce6842a2b7bd0ec
1c0626e64d887622e8937e987bfbe042f904728966e121b01c739c8dbe66beb6241eb
randomized_pwd: 22f5e31fbbbf4649f77ebfc92a2ef555fc30a09edc903123d978d
e3ca356b85ce2120b0d2735bd772011ecb573e614cd7b1aeeb86ca0ac6b8732c33cdf
7a6816
envelope: 71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c46
767759f0fe7ab535b75ff4a01887e30a733091b05cc6ace0fd49309fe3758f57f4d01
71b270e309d14e59413849c3ed672e076d97d71ceace93dcade9f26712461611
handshake_secret: 036b0351f1b041d4e2eb6f4104833e3d13db721b9e9ec85d797
daf354e8e13ce55ceb3756b9a781439e15015712ce9bc0d66caddb5d5d19c4aa6d03b
fd075301
server_mac_key: 95592913b88470536b3dc7ecb514a17fbb1916e3efa8e64d55639
7acbc5ed37f654bf860bfa8ae106f73ef9df92f303715bf29c7dc67d49598d8d6640c
4c7ce3
client_mac_key: bbb5ee19ec9d491094878dd4a458a776557be3d79d078f40bb294
01f74b80eb8102c65e2cc203c79740bc0e5bb71a138a9efda58f35a486da1835abe63
38838b
oprf_key: 3f76113135e6ca7e51ac5bb3e8774eb84709ad36b8907ec8f7bc3537828
71906
~~~

#### Output Values

~~~
registration_request: 76cc85628d5ac0e01de4ede72479d607490e7f58b94578d
b7a0606d74bc58b03
registration_response: 865f3305ff73be7388313e7a74b5fc277a165ff2895f92
60391057b84c7bc72718d5035fd0a9c1d6412226df037125901a43f4dff660c0549d4
02f672bcc0933
registration_upload: 2046d15924599adbcb7c03abe00350e9dde62267037eb0d2
a959a17b2210eb0fdc3b0057603d1c23df7e6f239984604c4b0dfa111528ab0ba3c7f
6ab1ceb11d10aa85433f63bbf30b9b0ae8951653bcd3beb12aa61cf942e6e5b442282
0d810871b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c467677
59f0fe7ab535b75ff4a01887e30a733091b05cc6ace0fd49309fe3758f57f4d0171b2
70e309d14e59413849c3ed672e076d97d71ceace93dcade9f26712461611
KE1: e47c1c5e5eed1910a1cbb6420c5edf26ea3c099aaaedcb03599fc311a724d84f
804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69f6792
6bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a
KE2: 9692d473e0bde7a1fbb6d2c0e4001ccc58902102857d0e67e5fa44f4b902b17f
54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7f7b11e
e2cb784efa8e6cbbb9cc6b52b16290e3906235d71b773534c3da1575a00708219fa81
05b3d2a1292d58d6ea6b0e464c752df6f957a9e34a66de7e5d44dbdf958070f8a97fa
374af5dd0febfaf9003095e610278b5ba10de7a16816365d2df80cfd566e6f9ea4a93
968992e9b153fe4196e4c1f5144643eb240575aba49bf9c5ec75a8cd571370add249e
99cb8a8c43f6ef05610ac6e354642bf4fedbf696e77d4749eb304c4d74be9457c5975
46bc22aed699225499910fc913b3e90712b085f3437e22abbf37e997f507589944fbc
ccb0128441680382a3eec27d1a80bb154296a1f00e10e984dfa7434a7c7db09284261
12bd54a0063fff8584da1261
KE3: faac852789872a58c40e406c301655a55806b117c61c5070364561ecdc5f0951
8c745ca87a13ca20b41116957066aa040a69786b247e811fb92cbc85d8b3d9bb
export_key: 47d742be256471ec7a7b0ebc022d6ca016b022a7dcbdd41fa1b6dbfcd
6f88285aee60db87e7c5e5aff87b55904b07137b3d85648bb62d70a18954dd1c66cdd
c2
session_key: 01905d1312467beaca17c20e64c50c91ca6e756067adebbc38a89efd
9c1305f8eff3c641062755ba156749ea4ac7d9e9a6187791c40adc13473538b470b20
a67
~~~

### OPAQUE-3DH Real Test Vector 2

#### Configuration

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

#### Input Values

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
~~~

#### Intermediate Values

~~~
client_public_key: 64b38be7d1b6cb0e7c50644acb8b326f67167eb164899b1867
970ab770628643
auth_key: 494f1326c65c057e301f15e619b9e3de553c77132987828ba20026062da
a1f18d516ac2e37b1dfc296e21137623856fb3ccba48cc511f143110944848764dfb7
randomized_pwd: a4853e726d14efb03c35686ee2bc67665d02bdccb0c4c02523bf4
e1398e78b1094195a082b5ebb1b62ac75d06711643e9990c2be0071a42bc21a2b766b
787eac
envelope: d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf274782
9b2d21a6d25b3a1b8a541f47fc4bbe5783c2cc61c77ed389280a05ed2ef8c2c2d03fe
2066bd22ea959c7bb14b5259ee136e86f4d956fbaa2af2f6a326785f21262909
handshake_secret: 39ec65469f2bbabfa47bdf29f5d3c2f655009cc9ffffa423688
6b6b0c25cf0e7f677bc2a4f2454ffaa916b1abf3d53c8a76df2b8ec32cd6a579daf09
e9606088
server_mac_key: d47c287732202807e20f9309201019fd167aeadb41d6cc28dc7a3
eb05dd385a9fa2d1737e8719e89ecd3cc1db0bf53dc084bd8a5ab4586d1927679d11e
c42d69
client_mac_key: e2ff0e615fb1283856e8d68d284245c5e3790272fc83db97f784e
6f90d2c54a0123459c1d5f75c904ee191c5d535dcbbb1df6c1a900f32d3458dfc30dc
518f93
oprf_key: 531b0c7b0a3f90060c28d3d96ef5fecf56e25b8e4bf71c14bc770804c3f
b4507
~~~

#### Output Values

~~~
registration_request: ec2927a03ced1220168b6d5a54f0372f813ced8ad3673d5
1dee92d2cbfee500c
registration_response: f6e244e131f8cd14bc37a856a933c91128b2498c06540d
2dba3a197ed7d8bd778aa90cb321a38759fc253c444f317782962ca18d33101eab2c8
cda04405a181f
registration_upload: 64b38be7d1b6cb0e7c50644acb8b326f67167eb164899b18
67970ab7706286439fabb8544108ec64de2b992935dd5fd9a98441412ccf724bf4853
c28749d9fd33fb1824b964f616a7fce654e05bb15133bd4a69441dcbfe6a02b8a546e
1b32dbd0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf2747829b2d
21a6d25b3a1b8a541f47fc4bbe5783c2cc61c77ed389280a05ed2ef8c2c2d03fe2066
bd22ea959c7bb14b5259ee136e86f4d956fbaa2af2f6a326785f21262909
KE1: d0a498e621d3ff7a011b37166a63ef40fe268f93c7d75a467eea42a98c0a490d
a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e6085d8c1187a642e7
eecf19b804a62817486663d6c6c239396f709b663a4350cda67d025687a
KE2: e6d0c01cdc14f7bfdb38effbd63394f6304b47c2dc26fd510ecdbf471486b972
30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def228c8563625
e7cfa2857bdc95991bfccc09b69ed53fd5f173389f4d8786b261b6dfd2fc7c18968dd
1be8cdb52b1ca691d8d27ad655e6c78a6ef67c2ad43899259b060706f7d4f4946f97b
d283c009a736227e9c1913b394d0d88419c6463970c0c2887bd5890eac805e8657903
f7f8887f5eab9e700414af99bbabe3b6594418e2a3723fa57f7ef652185f89114109f
5a61cc8c9216fdd7398246bb7a0c20e2fbca2d8ae070cdffe5bb4b1c373e71be8e7d8
f356ee5de37881533f10397bcd84d354456350043199df4e4d9b338cbc2314a9f67e5
9f4334595f5ae18954bfcc2815ba19a0682403d2f1a62bd050851a038a3c0fb5a8179
6f627dbae98c7e1e4a9a46ff
KE3: 328b7fdd7d94b63093184409b850c7af99a24dd2a4e14dc9c758ed4c7ada94a6
5a81d394b881e00d99dc6e71cf7acba03d8235f6e681b802b9a48be03f23991f
export_key: 7f2e5b749ec5f6ab34663655184f3653275aafd5db070b6aac6afd80a
78309a8ec0f97a2f2cfcc7a971983a914ead081a8a642b65d298c579d3526d2219381
8d
session_key: 70d8c538c371757e5e63d522a5f5e1329d7024f73fa854f5899733e3
d2b5afa800e6db4727aec02ca58cee310c7e8f8193f7cdb5a667fe32247711a3c72ca
06a
~~~

### OPAQUE-3DH Real Test Vector 3

#### Configuration

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

#### Input Values

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
~~~

#### Intermediate Values

~~~
client_public_key: 0234cb18fb529a1cd33b4cf6b9330e4a429d8b8fbe8b2c43a0
d130713a190b3eb7
auth_key: 570a8105a7d86679b4c9d009edc9627af6b17e8b2d2f0d50cbd13ea8a00
82cd7
randomized_pwd: 04f1615bc400765f22f7af1277a0814b5665ad1d4ef9bf1829880
2a0f6b4636b
envelope: 2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1acacc4
a831916a15211679ac4d0731e49058f79917d87536c617ab8d7192ac87826a8f76b5f
handshake_secret: 72f5c4fa597d8b722fa6aa5ae837df06fd7a568a1584489c51d
11b1d43b68e46
server_mac_key: ec74ece1dce2352dd92693f0bcdb543e97d85d9a778078bad935b
ffb6b2b9a65
client_mac_key: f680934996037732c95caacc9f15910b60e5ebdba63b915ba9eaa
64c944ed47e
oprf_key: d153d662a1e7dd4383837aa7125685d2be6f8041472ecbfd610e46952a6
a24f1
~~~

#### Output Values

~~~
registration_request: 0325768a660df0c15f6f2a1dcbb7efd4f1c92702401edf3
e2f0742c8dce85d5fa8
registration_response: 0244211a4d2a067f7a61ed88dff6764856d347465f330d
0e15502700afd1865911025b95a6add1f2f3d038811b5ad3494bed73b1e2500d8dade
c592d88406e25c2f2
registration_upload: 0234cb18fb529a1cd33b4cf6b9330e4a429d8b8fbe8b2c43
a0d130713a190b3eb78efb26f2bb390fd23b90c49ae680c4560fbd2b3c4f32891505c
ad7d95b7bc58e2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1aca
cc4a831916a15211679ac4d0731e49058f79917d87536c617ab8d7192ac87826a8f76
b5f
KE1: 03884e56429f1ee53559f2e244392eb8f994fd46c8fd9ffdd24ac5a7af963a66
3b967fcded96ed46986e60fcbdf985232639f537377ca3fcf07ad489956b2e9019033
58b4eae039953116889466bfddeb40168e39ed83809fd5f0d5f2de9c5234398
KE2: 0383fff1b3e8003723dff1b1f90a7934a036bd6691aca0366b07a100bf2bb3dc
2acb792f3657240ce5296dd5633e7333531009c11ee6ab46b6111f156d96a160b23b6
a5ff1ce8035a1dca4776f32f43c7ce626d796da0f27fc9897522fc1fab70d2fb443d8
2a4333770057e929c2f9977d40a64e8b4a5a553d25a8b8392b4adbf0a03947082b3aa
9836bc20c7dd255e57b7d3a29c9cbee85481ed776cada975dae758018e88ecfc53891
529278c47239f8fe6f1be88972721898ef81cc0a76a0b5500242bc29993976185dacf
6be815cbfa923aac80fad8b7f020c9d4f18e0b6867a177d92ce531ed6f48a6592d14a
a9e7fee37fa1e8ef1ffb85181e66661196447dc0
KE3: 00afa7c015df8f9e9dcd491c88a41663320549b163761e11ea5aefb398e470be
export_key: a83a3fe26af0dadb63d15ed808a4dc2edb57f45212554ecc1af5e0273
50651de
session_key: 9cbab7cb765fe14d3a6bbcba0945ff6aaee8db71877842502fd61c24
2a12384e
~~~

### OPAQUE-3DH Real Test Vector 4

#### Configuration

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

#### Input Values

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
~~~

#### Intermediate Values

~~~
client_public_key: 028e38bb4030255ad81d48afba0ae8f8f65169a6ff17f536c8
91816cd2f47c9e89
auth_key: 76cba5b349c60c5a19ab06b70a3191d3418318b5a203fd298b18a0eda53
efd1a
randomized_pwd: 74649c9c7b0d7436c4873984732fe45e19dabd1a96d7e9175468a
85ed16bea65
envelope: 75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842e44
26e423938d818ea53f58fdaab8541765d5171e99b1bdc2c63e8e1eaf62d3a60aacabe
handshake_secret: 77ef201cd5f558cd2b184d5bc63e28ad2fe6171c4967e8962b7
83f0c9e9c5aea
server_mac_key: accc90a00130230aaee45ed5ff69dcb257d3dda31519ef7ed3fa7
575b6c8072d
client_mac_key: 8471a38dd92988b8d5139ffac80873921c01f34b9be332d819624
73218e10578
oprf_key: f14e1fc34ba1218bfd3f7373f036889bf4f35a8fbc9e8c9c07ccf2d2388
79d9c
~~~

#### Output Values

~~~
registration_request: 02792b0f4670aced5970a68b01bb951004ccad962159be4
b6783170c9ad68f6052
registration_response: 03cc3491b4bcb3e4804f3eadbc6a04c8fff18cc9ca5a4f
eeb577fdfebd71f5060f029a2c6097fbbcf3457fe3ff7d4ef8e89dab585a67dfed090
5c9f104d909138bae
registration_upload: 028e38bb4030255ad81d48afba0ae8f8f65169a6ff17f536
c891816cd2f47c9e89260603b2690f3d466fb0b747e256283bed94836ac98c10d4588
1372046d3b1e875c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842
e4426e423938d818ea53f58fdaab8541765d5171e99b1bdc2c63e8e1eaf62d3a60aac
abe
KE1: 02fe96fc48d9fc921edd8e92ada581cbcc2a65e30962d0002ea5242f5baf627f
f646498f95ec7986f0602019b3fbb646db87a2fdbc12176d4f7ab74fa5fadace6002a
9f857ad3eabe09047049e8b8cee72feea2acb7fc487777c0b22d3add6a0e0c0
KE2: 035115b21dde0992cb812926d65c7dccd5e0f8ffff573da4a7c1e603e0e40827
895947586f69259e0708bdfab794f689eec14c7deb7edde68c81645156cf278f21cef
3adc4e524db33258c5774efaec59750eaf3755a2dfa194ec593ce41a7a17f889978a2
f97ced10bd1592793497e58b5d05a02ebf003f8a8949a2f8a22a09e4d1b8ba19c9e77
4b6f31545ac4c02aba4ad8e26b4f43d65319f8d1c5a5a04668d4b581ac468101aee52
8cc6b69daac7a90de8837d49708e76310767cbe4af18594d022aa8746ab4329d59129
6652d44f6dfb04470103311bacd7ad51060ef5abac41b2a2eb8e68a375b1d2f55c77c
db2d1cb355df3ca50a966c3582f16a76e518e2ad
KE3: 9656352a2ae1c1569ff6bb69c5d533fff9aa174faad1f3980eaa3e6d0df2102e
export_key: 5b92e3454d59062460a87ad2ff6546d862f722c6fbd7678a0997b3c9d
c61e9a0
session_key: 7d9430d675055a95b323a012be00690382618f4f687cbe0c5f7c4d20
b1fb71c1
~~~

### OPAQUE-3DH Real Test Vector 5

#### Configuration

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

#### Input Values

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
~~~

#### Intermediate Values

~~~
client_public_key: cef8fa52ed24697b25418aa4703deb80a1e8f2caca405e2aaf
6758718ac7e33f
auth_key: 760cf1c679e1599d4ac3a8278f01c4494750c4038a713e7854b1d72af8f
9dd754e4e2819456f9d8a38b178d6472d4e893aff415ad93a7546c1dacb9b19fc9d25
randomized_pwd: 6df3b91dd1cf81df3b0b72998374dc446a8ade0fdc7eea49cb7a6
21ae27b90b883d94e7d528378e8f665977b5e03909511ee729c36f16fd6aba83613d8
c25142
envelope: 13e74aa6263b562b9764bfbcbbe54081383f3057c26fead2a8b3d5910e2
5fd293005c607b1e9e20601905d07de4b195e9f3812a14faa21bc7ec6b3aaeb4ff833
e36d0ea6c1c575161a16d3de1052fd1bca6d387a6dd0947d5284f1c27010dbc771b93
e986d552e1c808c4506d430532d01cfa6c577edbe2230f2b1d68899af19
handshake_secret: 5d37e08f982c39e4edf75d23d6c8e412c56eff600a1d2baf02e
3c8d67c41490ee34477e2bb6a58f5c555ac2a1292bdbfbbea9940d958dafa968ca6c4
a70b6933
server_mac_key: fb738205ec3bf99dce71a809f61c68f52d507260abb3ad67c7d7c
c6f6b673affce4b5166c965b0d1ad37aa0429ee6cc09c0063c5eff062e53db4d2adc8
fb7d4f
client_mac_key: f6f3c6826a01c16003ae99fa38a9efd63459e14a57071f3177f44
c3d4cd726db61c0de0297bb5c8ebb9c26cc9474899d92b453e8232e3feab9e8aba119
71ee46
oprf_key: ea5421a9d7d562bce7d5541d716a45e2e28430c33b50e2c54dee998e328
35503
~~~

#### Output Values

~~~
registration_request: f0c2f72afd000afa4cfde5eb4122f42c4082332d8783204
6dc4f7f9691e86c3f
registration_response: f033a257a3f77f2df98a46036738c20706b4d70015b59f
1c74a2606d03725b121ac449e9cdd633788069cca1aaea36ea359d7c2d493b254e5ff
e8d64212dcc59
registration_upload: cef8fa52ed24697b25418aa4703deb80a1e8f2caca405e2a
af6758718ac7e33fb3ab72316071ee2799c26865b8fbdbc87a0d861cc0b9f5bd9cb1e
a97569472896ee0bfc2a25f9d2031f409c323df56a5c2bd9c6317874c5a17935dfd79
26b2f413e74aa6263b562b9764bfbcbbe54081383f3057c26fead2a8b3d5910e25fd2
93005c607b1e9e20601905d07de4b195e9f3812a14faa21bc7ec6b3aaeb4ff833e36d
0ea6c1c575161a16d3de1052fd1bca6d387a6dd0947d5284f1c27010dbc771b93e986
d552e1c808c4506d430532d01cfa6c577edbe2230f2b1d68899af19
KE1: dea559cab899a46d045370d26c2551e74f1d0da2b090ca860c1379241d5f2900
077adba76f768fd0979f8dc006ca297e7954ebf0e81a893021ee24acc35e1a3ff27ab
6cb55389234dd3f045713b6fc7c1f3de0e84140ee8b07bee138ba587d79
KE2: 8433d62cb0db1a06942ce70567ea1b28ce01972d577fcc997b3951deadda5677
8837b6c0709160251cbebe0d55e4423554c45da7a8952367cf336eb623379e80db22c
f683b95f135f5ca1a9c2ee5af15577eb567303c95f7ea18355fb7f8c7cd209f0c156b
232d143d5b7aec3c9a495a5223017d18e4281e41b89456803f8eca42b419daee26218
1d43ad1794b467043bd882f1a19f3155d7d30fd1b5cdc2dd13aece79fd2f8905da3ab
1a98c3a0ef50995b4e30a8cc3e9882384e9576fb85ee4c1dabbbe1dd967f2ec96e6ba
df1a20a2ce6d583747feabd690992a44f5a4798ff26a6386c0a4077f512138e2203f2
47d56cbe900310cd43b4a55e4c54231cc6046a0fce623dc08f253b239bfc96850e7ed
02dc87f3e29830ccd128aaa365840ccaba8d6b2056626d9ac6b8983148f7685ebb5f0
31823e575e3ac75f4bc88086084f6f1a6ae2662a5079f6167ec55f52811a81e6d0a3c
8fafa337d66ac737d55
KE3: ce0d378f6590de86be61608c42a7a1379c58a0a8cf6f1ce6af0164fff7a65162
265f78e1ddbf056af34694b609d59ece78c101a0dcbb5ce2e0ff3f5cc39ea1c9
export_key: a656dd5acbaae4d7149d2edc825bd23b7b3505218c2dd3240f16c2a60
29d9d2837c8beed8467491e936fed5139a750bc979902017156aed40b6b2f8eae6c04
32
session_key: 0940f92334f093f39da5a9f36b76a137c4446796d5cb9f272a3d85e7
01f3b0160301bde0761dc96f8a8da0241c9f88afdc5d614d270c86d8249b0f425fa19
39e
~~~

### OPAQUE-3DH Real Test Vector 6

#### Configuration

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

#### Input Values

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
~~~

#### Intermediate Values

~~~
client_public_key: 262321548e1fbb06525167181fb3ca34409410120c7feb4144
26b4176f519264
auth_key: b89cd540fb9e954e7a622723120bcb9f82c5006570ca36d44424dcc4805
e4f7b90ce47c31e8a8c809fc666006a377ce68b19431378c68776ddbfa0617490f16a
randomized_pwd: b2828519c684910131dad09652c589fc77a307a7560fe78d2c8c7
02c8eeece38f470e695185e45be762c6e4732980715e535f411f02b916e18bf3d9f0c
249e69
envelope: 86e2b0916361fb6a69f9a097e3ef2f83f8fd5f95cc79432eabf3e01f002
0bac600880f67a9cc7800800677a52179746eb1426db885097a0d0a05f93d64f93ff1
498d75c646f7f836c53ca43e93ddccd0e8225e3d608d01e8620a4a71b1a5ee9be6219
79afc8c0114626fdd78fb1ee4bf7537a1743964b364b02ff7851284ae00
handshake_secret: 3d925e90f1b621e6e6c896c87d565a8ff6f6fc9ea375b46cd97
edc0ea8a576eb1e6bd1d202ff0f767302f21812b4f99186025f237f8f7778e8e27768
9ddfda11
server_mac_key: 40628b867618de054b613cb1d6563dba6dded5ba4dd10f6113b22
2744aa5252b68d5fc07442c30be318ff2c675e3d4cee5c76d66aa468c5b3c2f69ed7e
e2a8ee
client_mac_key: 3d3d749f7406a8e81eb431ab38e1bf1c5a4dfabec6a4e93ad8aa3
6671d81f18c167e8806a6c8ff62e2b263243acb6b4f36d2706e108b2fd7ddb34e0372
2c2ed8
oprf_key: 66234277859d85dc708f57e1f66448303ab5853c26f7f82f67bcfb2deaa
75c03
~~~

#### Output Values

~~~
registration_request: 34b611a08a5f7aff96a7a0f069c96c63db4018508da4589
b741ed538e1416234
registration_response: 1e96d9c134a103f1f961f16079f62a5468cc5b06a59d43
e20d37babea5043714846c28da13144e5908f1db4c8ba2c848ac34ae6b9a8855dcdb0
8d5ecfb000d73
registration_upload: 262321548e1fbb06525167181fb3ca34409410120c7feb41
4426b4176f519264846d97893ee0b033b318b220e7c9b3a6e63c05accae0929e086c7
7ffb9359fe9a17fffa244e400950c86a75ba7c4badbb87db74998c9f5d40967f38914
93738c86e2b0916361fb6a69f9a097e3ef2f83f8fd5f95cc79432eabf3e01f0020bac
600880f67a9cc7800800677a52179746eb1426db885097a0d0a05f93d64f93ff1498d
75c646f7f836c53ca43e93ddccd0e8225e3d608d01e8620a4a71b1a5ee9be621979af
c8c0114626fdd78fb1ee4bf7537a1743964b364b02ff7851284ae00
KE1: 703d6738685624f122e72d457bc966edbbf4a74ff8eeb530becb528762c89f7c
e0d04374ad9a276620c681abfca7bdb432e63509e5ec96ed2ec5542f6fc7db231c48c
e65e44088bb7f7503f7ad7f3a050177b727e9b490aac3d4e639be06e157
KE2: 222a32fe68ee4bc87992ab9eee9bca419aee14e3ca120020758459d85d59e639
f551feeed04ea7967c2d6c8847b6ca8bc09eced6848f0a73208e71e3f1b688e6877df
f33abacd0c5877dac42c7ebfb625a7bc11af54dc1fcc5ee9186a132e0032a49615db5
4038d2d75552e3c71188ce364e5967d6c419724b6b4d94eca4cf625c6289e300d63a7
0483156af8070f4ae27cfb2a2fc7f77405cf2431784c4c5117ceb4cb086f95fe87301
63ce6686a15a5ebd75785c973055a903cd49a90f7d98c350a8b7017c11d8f2b9c8393
241971b51e53a6a5d18f6001b4085f5a2ae62b6f35483b457e208972f1cbffbb70249
fa31064a8883002d3b8024a023b4feac41d856f10de218fc035faad7dddd3f3f01e2f
27ff589ebbe605fa8e4659652fa5286aa76afc3fc0f0d7a282848a8e49279949abb29
216a8a9105f3c419388ada5e0bba5ea621d540acd3ab0d2030cf9ba1b805571a971f9
b7b1e9cd3b422adc26c
KE3: e794a1d0ec961cf944e251270bff61ad8b262c59d7e60d465241ada6bed420bc
f1885458846463b551b9ab4ce687e0592e4f7335f46ad9dd3bb0028c0dc14225
export_key: 50235404f5212db6aa62b419e64607ab27a7070120491891ef290aa1d
d87e221a6cf8a2bb72302dd756776d1fb08da1d90bf1957d3154c76917a955fa41b95
a0
session_key: 9be2659064b28f5353414c37fff5f4f8a8f7e4c951b0637373bab2f5
75d805f02d87d34921ace763e185fa8b5ca47e98b25313195719cbc1602ef6ef61b2d
d06
~~~

### OPAQUE-3DH Real Test Vector 7

#### Configuration

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

#### Input Values

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
~~~

#### Intermediate Values

~~~
client_public_key: 026be6ae76a078ed03bada87b595104050b65951dbd2f4160b
7fe0153494e9dc9b
auth_key: df9b4d68e993a3ea006d592636c8f855952e467e1cf95eb74c65b6ed8d9
fda9a
randomized_pwd: b884ee3cb8ba6e559fad6c5a4fc90612e753e98096d111724beb9
ef28aa7d8f2
envelope: d761c8b636815f62dad9d7ed319efefe641bb4c3d1cc83a6a6600bbadfe
603adb4a1813f859cc062290962b036202f889e59c281dda3979b474117a4cf86566e
18b577bacfbf0a2d9952ee1a86a49aa05fb7535871c2289480845e6667a389f6
handshake_secret: 293c040ae3ba21f683e0322cfd437d883da62920d613ee14eec
d40f5ba50f95d
server_mac_key: 2f8eaaf0719aa329a2189f1a53ef467e601a2e5fc4536956ecbb1
8a98af74352
client_mac_key: 9c07ba7f8d3639820e4c457abcd0c80884a5d212e6df2a9d55643
e6445bb8c4d
oprf_key: 7d6f3b70621307fe8f1546f736fea87d9de2c3a05a6e0526dab36c04907
8a314
~~~

#### Output Values

~~~
registration_request: 02aa62e9c8e75283c03ac512eb720cfaabf4e8b880e3b19
2a2aecf44000fdf4556
registration_response: 03e09f760f9f24cee3d66fabf1abdbb2ec87933f8c7fb9
6a4d7be1227b874afd3a03d264f0e386387704da3d82a32883d2045326b32296ed102
812dd3ed6d26f3b8b
registration_upload: 026be6ae76a078ed03bada87b595104050b65951dbd2f416
0b7fe0153494e9dc9b489718a412643a0c432d5263a7f186229856e6369c6ff90b1f6
463481fac03f8d761c8b636815f62dad9d7ed319efefe641bb4c3d1cc83a6a6600bba
dfe603adb4a1813f859cc062290962b036202f889e59c281dda3979b474117a4cf865
66e18b577bacfbf0a2d9952ee1a86a49aa05fb7535871c2289480845e6667a389f6
KE1: 036ddd62a3852518a45d35bfdc610bd8d479817af6d522f753c5fb8d773b1008
8cb9e5e27d7077eec3be075d20ac4e145572a45beeeb6066b9533421c2cd4fee72027
78a3a12ae78faf76c59723a0b72ee134ac3977d297ce65d59b41a12a385975d
KE2: 02a0230a874e88e6361474924de4e674af5231547c5ab8b786aab29d71bda9f0
ab65ebd00e208f7a1c679eb9edc4b8943b0ffbe09577ecdb625726cb333292ebc77d8
17dadce52c16c0543ab1e42c5b7bf8a007facf4084cadb74740071c02bc801c152b54
22b29073ec39a52bf8752814e7525552dd79f4196360362e68fd8ce6a96d6577e6f02
ce6203f2b848a1794027bdeefc7e6b38b29d5b19a4786303546e8bcd0225a254e2840
18922507d5f0a49b29b2b8d7e7dacfbc5b0a527ea752adcb6819cd5cca28ea3ed382a
155205669141c9bcbdca0a2c66ad0adc66f43e4e82c02e47a5f856e1ad51f3c0e9e34
b620c2f7e2d4b70c59db7c1d0a3a108322242baa47ebb98243f0c332def12af18492c
68b133ab65b6ce280f08d9ff56f09b15d64
KE3: 8390976f35482624243d818f663fe572c861b38c11e079768e6513e95f1055a7
export_key: 22e0e8c776040c794313e61ea682c7b0625a13482e1fe2a8f53fafbba
2a66893
session_key: a6fff7dfb587e64683ecb38ef21be99e87c8e2f9a7b9cca92363bef8
a2c69bed
~~~

### OPAQUE-3DH Real Test Vector 8

#### Configuration

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

#### Input Values

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
~~~

#### Intermediate Values

~~~
client_public_key: 030833fa0933e79ed8dafa9cf3d537eec06987fb1c064d74f4
d45a480de9a179c9
auth_key: 635d3868cdfc288fd140f838f441cb7a12c15f4340791f2eea3d84abc14
c7e87
randomized_pwd: 40b63dd7162516849eacc4e9ba4a8a18ec56ccc8420b29b2963a5
29b3d1bf88c
envelope: 6244563994473ca960143fe2de622464f00e607813de02e1784fa9f7d6e
3b7bc7728fba39864da738a24a6d48a3941ebd0106ceea73d9cb14357fb3a11a80533
1745ac05fdedbcabd3d50f6e1064d2140918843fe71964cd0d6b380b783f5443
handshake_secret: c2c9412d7a7f789383e0dab5a3872a22b1485fe92ec5a6ccb70
c0573f0a61621
server_mac_key: 517bf63a14053d17ff76030b0646d7eb2c7cf337f68241e9a49ff
a4f312cbcb7
client_mac_key: d04bf6600a7286ffb4438a5c05ec1d0be439d19833786cf1033dc
a23e1a78b4e
oprf_key: 2ec7a8d9f98c0b936e38b56d802de8a663883588afba3f3e02b152a9e6d
12627
~~~

#### Output Values

~~~
registration_request: 033db40e9dfcd60acbb2aa08f5dcabd2e8bb8a0d7cd24a7
39ae669ddb7b6915eae
registration_response: 02d7007b0aee071ddaa1c5a61f52f7426a72daa071548b
597b4bd8fd0e4539330603512bae40ee42c0fce71f447611b39f2e91d68437f75fc1f
171e80ae8a09d30ce
registration_upload: 030833fa0933e79ed8dafa9cf3d537eec06987fb1c064d74
f4d45a480de9a179c9d15ebd9bcb3301043e0487e01bce0b4f7cdf142de83c9522b23
c734d863d86dc6244563994473ca960143fe2de622464f00e607813de02e1784fa9f7
d6e3b7bc7728fba39864da738a24a6d48a3941ebd0106ceea73d9cb14357fb3a11a80
5331745ac05fdedbcabd3d50f6e1064d2140918843fe71964cd0d6b380b783f5443
KE1: 035d2d3a97256fd02c323405c66e25ccf2298998fd3bc8cbbf92664f9ac50b38
16af0023091cb7e3e9c8581d8ca2837e78cd88fb76287d235b919bc757a0a70ab802e
f46b931a4b8a017235597c595090dac6f059f599a00f46e08c62fc266e28d04
KE2: 02249df93cafad8cdb0450827ddd6d35c3c289a8093e00e58e93c8a7f53767f9
78c68c15bf920702323ae20c552cdaefac7e1d665da7cc705485b75a3514b967a3b1c
efc1ba51c2cfaf32cd4e5aca3d5e2bc16ab5906680acc41efef0c7e728ad66c6afcdd
e89bc9a7b7c3cc2938aa97a28edc48761877b31c41d8c8c8904bde90d70b2d0d8cd57
58984f0f1314279ce2bb41f2be7ee04c8a7dc07241b14045509220f0f4e1008eda6ce
fadd21a4017c61e8d5d4082b88e0f189563da374c039ddb2dc4ff822a5e5865d2f9e8
6117a7480a8a64a166e1cb724f59c39f93a802f7f7003ba9d8ad954f80f5ee6053c6c
51f70a7ef7a65cc9f73c6e809d0eac701f412acbff584d94c888c14c84b82142ab60c
ab13ccfdcdfd2d7e07d34a8ea9b60cad807
KE3: 375521e87d669af1f619c5083b05ee12174a054a25c08d7088b30fd3fb3f271d
export_key: de041d0b4eb5b5a67ac994bef8836fb1402acc03fe3e3a21fdc97592e
54f52c1
session_key: a7ee3765471893e0983f373e3a49899a9212318e35adb1fde922e657
2254566b
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

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: d3cb00535339fe4063c7ba5506a990c243a2b5c77b06848a0be9a0568c
252fb0d7425382babd267deeed669e56d1d5654c036211f49b42f4489f96f37100779
f
credential_identifier: 31323334
masking_nonce: 3058799f42516228746821dc8c8530d0e8273ebde81941591d69ca
5aea773090
client_private_key: 83c9bcc31a9da0ffa4489900d3d1f85bb65c27f26e9ae4e3b
66f6e02e098c503
client_public_key: 56717b74a5e1770edb14c65f22cee0487046bd96e122ba97da
ffed06c4bf4052
server_private_key: 8d3a9355f9757e7071b3f836e3fb1461a6436e92971625b17
cd7e580dd27c009
server_public_key: 7a464761cb19c8b6e832fdfcfd18779b0edc246fe808f5de6c
e7bdb54df41b67
server_nonce: 4e2a8098173efa2968036f1762f2e5df41ab976fb1bfb91dae29950
f8526de4c
server_keyshare: 0e247410004d83d7cbe3af89c62ff03f942127aec4b0084c9eb5
88e74ce6dd06
server_private_keyshare: 326345820acc8aacf4948fce775a1fd265e4e93fd579
cec8177d6389ee379b0a
masking_key: e968bfe56ad934c3e1088115bcbf1af8b405fd0de94cdf301f9192cc
2781de00617e568b14b7235cc1189265811ea354031ea39b62e31a104f181c01d3dae
4b8
KE1: b61bfe5997b644e9654b7796203831ea9b9e86499c17db3331a40673832c9729
05603c1acb64ea417c0dabaab858a5f9da046d4a0cdbf092034c00451ccdc6e1ee835
5c91d5ed7aa5ea75b8a730ba8dc45f6b41ae9713e6aa7126211346e8754
~~~

#### Output Values

~~~
KE2: 0826f0581be79672ccf51276e4b4079bf05aa94530591b24acbf4106cf2fa34e
3058799f42516228746821dc8c8530d0e8273ebde81941591d69ca5aea77309078577
13efdc95f69166737cd7a80ead60e1a1f805c1da9cccbc0d29120f34be291518798c7
00793f232374e66182495b76b388d9e11f479580cc2297da02fecee88a99cea6bc411
b9467e8bfa9a4006aba7f21b74b4ce3bccd686785878b0ec9b3fc4200228014d5d073
69d42d1d1b1669ecd2ad8905734ca0a641d8f16667ca4e2a8098173efa2968036f176
2f2e5df41ab976fb1bfb91dae29950f8526de4c0e247410004d83d7cbe3af89c62ff0
3f942127aec4b0084c9eb588e74ce6dd0689ffd826511fa128dc90837369bb9ed14d0
794aa3a6e45d2ef533cf6b7e3b47d963eed736c71c8ca933af078af45f573bd3fb790
336c9b47cc40f3d7c091a552
~~~

### OPAQUE-3DH Fake Test Vector 2

#### Configuration

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

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 42cd4f606841ca8f403920a8ecf2d60399962f49d83f857ca86676b272
1c4366
credential_identifier: 31323334
masking_nonce: d3974af728aeafc9e5af4b4cab57d7e7dfbe0ef6b08df28fae5269
229cac2332
client_private_key: 0e6b97ef90ea8cedbada0e1295233ba417790ed8e99676903
71d527ddad59a64
client_public_key: 033043e30c3dd5fb22d0b3d167acc28878ea7c3ac49cf82b2e
b4b60a8299a67f7a
server_private_key: b08b686382820021a7d32ad3cb8ff60f15437b5cb00c53f21
f3fa17ac31d2bc0
server_public_key: 03983ac5783e6a460a526066f1398cdc648518a985cc26a66f
c7573a71ce36dbe5
server_nonce: 1a60a3e31bb007db74b7114aab2f196ef6bec942a9b4fe6c61143fa
c34d42143
server_keyshare: 03eefd21dd74c665064ebcbf63ac5ebce9a45097d47dfc08d845
52a105419b44aa
server_private_keyshare: 751e5012ba0c535e008b2389bea166a5d59a49353f12
20f5e345f0546463ccdf
masking_key: 5b8caab90accd4f239e85ec978f6a6346edc0019c5671e81034ead61
5ce096fc
KE1: 028bc054fff79a9e0f0315e31cc035384aedd9d50ea8ee36630d39876ca4e592
93d797d24fe5ad528130825016bfdc2eeaeef19914c366a615bcdbefd1f04b7208023
843b78440c0e79d828ac4c2658d1cedf7e9795f2242527a4c1a254501d2ca1a
~~~

#### Output Values

~~~
KE2: 0353685a152940706b1ed877b2da12f3c9f417d38fab56f3228c60f72429f602
d9d3974af728aeafc9e5af4b4cab57d7e7dfbe0ef6b08df28fae5269229cac23329a9
93151e43ac41ce18939444cea5d012b8a8316ed439d6fccf06b064f7564722f555750
61897fbb6051f37e3247d08804437259fb9b022cc12715caca4ac12ef7a8b2f101269
37619ce4725e6b821de5f44ddb71a8582883aa9b5aaefa9e3d0231a60a3e31bb007db
74b7114aab2f196ef6bec942a9b4fe6c61143fac34d4214303eefd21dd74c665064eb
cbf63ac5ebce9a45097d47dfc08d84552a105419b44aadb37380855acdd939b7eb300
708d78b17ff0f99cee4ca4777c7628fb8ff591d1
~~~

### OPAQUE-3DH Fake Test Vector 3

#### Configuration

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

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: f25de0448fe47b0e58b656838ca98ab353a8ad48d9d2594ab586bb07b2
aa57e125b63f13483a9999240c192f735821167786be727255a4dae656c5a01059cf3
a
credential_identifier: 31323334
masking_nonce: af63872227d860610466d7e3772e2092c5f770bc56d3b4961919c4
ad92059537
client_private_key: 6c1ce31656eb5fee3ead7db7565a3618a0c38fd7b4fdcfdff
48868c519ff2a0f
client_public_key: 7894b12117db10b45476e45c8d3de597c3a410287524d7b368
961afa0a556c28
server_private_key: 3777b07d6e40562f0789806a6244d71f68a66fe4eca45ab41
38c1933d7065d02
server_public_key: ce0f4be418e606efb13cc01415b35c775e546a75e539762d63
10a268bb64bb1e
server_nonce: 244c13e9e741425fef935fbfb85c70d69b4154e77bf116bdfc92cbe
93d7598f0
server_keyshare: e21b0c1506869330ada34bfcec71862762853fc95476543a0abd
89a0a3ee556d
server_private_keyshare: eedab29b34c52d3908e3c54a79d6a561182034fff5e2
99e9fcf9317fda782106
masking_key: 463d334336a31a7b1aeeed9c60ab5a3950eb508ef1a159a931abc976
049df4afb6cc6fea0f95ae3e34c802bdcc4da208c4dd68402b708c0ebb6ae0a72d59c
b90
KE1: 986d70a47ec6b689e2deafdf5f799be248e244e976f102b5ff4c9d1164351b6e
1854ee25966eeee2c830ac3f6e212b97809eced53f0d503d4c96c7e27257f4132ce34
8e52135164b0e7c16fd09b304686c39b90cb04091a1048c399b2e9d4270
~~~

#### Output Values

~~~
KE2: 28ae606956cc5c4bdcb854814993ef611eeaae6a8200a6ce484de35ff40f2073
af63872227d860610466d7e3772e2092c5f770bc56d3b4961919c4ad92059537e2df9
d67a4caab9b89d824a40a41d8c1e594b6c404e548abb83e47ce48b91b7905c575892c
985d33173f2c23cb1431b7ed0696f43853fde720a012a87a818b10e77787cd9a747ad
972537f6849795409a4515665783230bfc41c657f8fac5bbe78ab842cbedc3ef2df79
90cfa9d01dcacc177b9a779b5b1a453464eea16a294552c214f34c85ce3a9961b80d9
1ec028ec0f1bdf01b047989a5ee575ec7983736244c13e9e741425fef935fbfb85c70
d69b4154e77bf116bdfc92cbe93d7598f0e21b0c1506869330ada34bfcec718627628
53fc95476543a0abd89a0a3ee556d697cee3e6d2ac62405776abe1bc3ac76c71da021
9fc91ecae4806a444a0c3a8a6311671764d4d507f99cc4b57523ff5d1a8af7628ff29
dd4dfc8d223749290e1
~~~

### OPAQUE-3DH Fake Test Vector 4

#### Configuration

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

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 8f200b8f641a5697233757853f5f9d5184433cfa367aa55e8491fcd37b
efaf95
credential_identifier: 31323334
masking_nonce: 5cd3c47180f435d1387c5541d2cbaca3ff3818b0e1875a9b006ac7
c78ae01b6c
client_private_key: c46a5d117c6ffdebb3b958328884c080eb922b9d8ecae5d6b
f001b9670f2851a
client_public_key: 0244fe5b332845cca6b44101ea04d4c7d52108b5b7a2afd22a
ed2c2d9e555035f4
server_private_key: 046e8097602a7b16b1ed184c65c208d14792a661a7a99c495
049b803e18da601
server_public_key: 02071a35268c772719bc31f9533f9d3665d4ed96a6780894bd
99f6910059a62807
server_nonce: 68498d0a3bcbf95d086073de4572bcc707c8fe7fc297e4e9a8600f4
eb8f7730f
server_keyshare: 02bf50c918a085c33c8fdfb3d346c4f4959401cdc1c5870567f8
947040af079d2d
server_private_keyshare: c0a9b2285356d0b6ceb9c29a7932ea8039d3170a4963
85b65eee17df9e7119cf
masking_key: c533fc7175763b1f43bc46fc6fd1145e2c24964fd3fd3c88454d0390
ca876610
KE1: 03bb16bcad5d9b7bce9f9e157f732c3d78e74cf1b1eace86a32d92400ce25b7e
e7b30e7bfbc1054696ddbc54accfea2cf8a46ab37ba489e28504f3ca7a3267d8d7036
3c36c15a1593205f26ca2d31c7a61c83a138943a5754f85d249da210bb71406
~~~

#### Output Values

~~~
KE2: 02f0e6fbda156524e87f9639fffbf98e75cd78b9c756c67bf1bea24054688ba8
485cd3c47180f435d1387c5541d2cbaca3ff3818b0e1875a9b006ac7c78ae01b6c95c
700af3a8ad87e16b2b20f23cf596305f21d23ba619d53d4b19d1604f9347bf944f84b
cab9373990c8b3ba517cc6418a834c946acd543079256413dd25db9ebf9f009b7da2f
4cd6b73c450d7ec779405a3198e516d11afc103e9cd782a937ba813d4627d5c76ef7b
6afe4273abe2bc76b489a0a2d2d31050f004434771de9f5068498d0a3bcbf95d08607
3de4572bcc707c8fe7fc297e4e9a8600f4eb8f7730f02bf50c918a085c33c8fdfb3d3
46c4f4959401cdc1c5870567f8947040af079d2d96e9d294c33a0dd233e902982fe82
4106b9424f8df5ced750012489bbfb6b805
~~~
