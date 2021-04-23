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

  SIGMA:
    title: "SIGMA: The SIGn-and-MAc approach to authenticated Diffie-Hellman and its use in the IKE protocols"
    author:
      -
        ins: H. Krawczyk
        name: Hugo Krawczyk

    seriesinfo: CRYPTO
    date: 2003

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

Password authentication is ubiquitious in many applications. In a common
implementation, a client authenticates to a server by sending its client
ID and password to the server over a secure connection. This makes
the password vulnerable to server mishandling, including accidentally
logging the password or storing it in cleartext in a database. Server
compromise resulting in access to these plaintext passwords is not an
uncommon security incident, even among security-conscious companies.
Moreover, plaintext password authentication over secure channels like
TLS are also vulnerable to cases where TLS may fail, including: PKI
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
no change or awareness on the client side relative to a single-server implementation).

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

The following terms are used throughout this document to describe the
operations, roles, and behaviors of OPAQUE:

- Client (C): Entity that has knowledge of a password and wishes to authenticate.
- Server (S): Entity that authenticates clients using passwords.
- password: An opaque byte string containing the client's password.

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
- DeriveAuthKeyPair(seed): Derive a private and public authentication key key pair
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
encoded, encrypted, and stored on the server. {{offline-phase}} describes the
first registration stage of the protocol, and {{online-phase}} describes the
second authentication stage of the protocol. {{configurations}} describes how
to instantiate OPAQUE using different cryptographic dependencies and parameters.

# Client Credential Storage {#client-credential-storage}

OPAQUE makes use of a structure `Envelope` to manage client credentials.
This envelope holds information about its format and content for the client to
obtain its authentication material.

OPAQUE allows applications to either provide custom client private and public keys
for authentication or to generate them internally, making the application oblivious
to the client's private key. Each public and private key value is an opaque byte
string, specific to the AKE protocol in which OPAQUE is instantiated.

These two options are defined as the `internal` and `external` modes.
See {{envelope-modes}} for their specifications.

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
`InnerEnvelope` and `CleartextCredentials`.

inner_env: A mode dependent `InnerEnvelope` structure. See {{envelope-modes}} for its specifications.

The size of the serialized envelope is denoted `Ne` and varies based on the mode.
The exact value for `Ne` is specified in {{internal-mode}} and {{external-mode}}.

## Envelope Creation and Recovery {#envelope-creation-recovery}

Clients create an `Envelope` at registration with the function `CreateEnvelope` defined below.

For the `internal` mode, implementations can choose to leave out the `client_private_key`
parameter, as it is not used. For the `external` mode, implementations are free to
additionally provide `client_public_key` to this function. With this, the public key doesn't
need to be recovered by `BuildInnerEnvelope()` and that function should be adapted
accordingly.

~~~
CreateEnvelope(random_pwd, server_public_key,
               client_private_key, creds)

Parameter:
- mode, the EnvelopeMode mode

Input:
- random_pwd, randomized password.
- server_public_key, The encoded server public key for
  the AKE protocol.
- client_private_key, The encoded client private key for
  the AKE protocol. This is nil in the internal key mode.
- server_identity, The optional encoded server identity.
- client_identity, The optional encoded client identity.

Output:
- envelope, the client's `Envelope` structure.
- client_public_key, the client's AKE public key.
- masking_key, a key used by the server to preserve the
  confidentiality of the envelope during login.
- export_key, an additional client key.

Steps:
1. envelope_nonce = random(Nn)
2. auth_key = Expand(random_pwd, concat(envelope_nonce, "AuthKey"), Nh)
3. export_key = Expand(random_pwd, concat(envelope_nonce, "ExportKey"), Nh)
4. masking_key = Expand(random_pwd, "MaskingKey", Nh)
5. inner_env, client_public_key = BuildInnerEnvelope(random_pwd, envelope_nonce, client_private_key)
6. cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
7. auth_tag = MAC(auth_key, concat(envelope_nonce, inner_env, cleartext_creds))
8. Create Envelope envelope with (envelope_nonce, inner_env, auth_tag)
9. Output (envelope, client_public_key, masking_key, export_key)
~~~

Clients recover their `Envelope` during authentication with the `RecoverEnvelope`
function defined below.

~~~
RecoverEnvelope(random_pwd, server_public_key, creds, envelope)

Input:
- random_pwd, randomized password.
- server_public_key, The encoded server public key for the AKE protocol.
- creds, a Credentials structure.
- envelope, the client's `Envelope` structure.

Output:
- client_private_key, The encoded client private key for the AKE protocol
- export_key, an additional client key

Steps:
1. auth_key = Expand(random_pwd, concat(envelope.nonce, "AuthKey"), Nh)
2. export_key = Expand(random_pwd, concat(envelope.nonce, "ExportKey", Nh)
3. (client_private_key, client_public_key) =
    RecoverKeys(random_pwd, envelope.nonce, envelope.inner_env)
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

- `inner_env, client_public_key = BuildInnerEnvelope(random_pwd, nonce, client_private_key)`:
  Build and return the mode's `InnerEnvelope` structure and the client's public key.
- `client_private_key, client_public_key = RecoverKeys(random_pwd, nonce, inner_env)`:
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

Parameter:
- dst, domain separation tag for HashToScalar set to "OPAQUE-HashToScalar".

Input:
- seed, pseudo-random byte sequence used as a seed.

Output:
- private_key, a private key
- public_key, the associated public key

Steps:
1. private_key = HashToScalar(seed, dst)
2. public_key = private_key * G
3. Output (private_key, public_key)
~~~

HashToScalar(msg, dst) is as specified in {{I-D.irtf-cfrg-voprf}},
except that dst = "OPAQUE-HashToScalar".

~~~
BuildInnerEnvelope(random_pwd, nonce, client_private_key)

Input:
- random_pwd, randomized password.
- nonce, a unique nonce of length `Nn`.
- client_private_key, empty value. Not used in this function,
  it only serves to comply with the API.

Output:
- inner_env, nil value (serves to comply with the API).
- client_public_key, the client's AKE public key.

Steps:
1. seed = Expand(random_pwd, concat(nonce, "PrivateKey"), Nsk)
2. _, client_public_key = DeriveAuthKeyPair(seed)
3. Output (nil, client_public_key)
~~~

Note that implementations are free to leave out the `client_private_key`
parameter, as it is not used.

~~~
RecoverKeys(random_pwd, nonce, inner_env)

Input:
- random_pwd, randomized password.
- nonce, a unique nonce of length `Nn`.
- inner_env, an InnerEnvelope structure. Not used in this
  function, it only serves to comply with the API.

Output:
- client_private_key, The encoded client private key for the AKE protocol
- client_public_key, The encoded client public key for the AKE protocol

Steps:
1. seed = Expand(random_pwd, concat(nonce, "PrivateKey"), Nsk)
2. client_private_key, client_public_key = DeriveAuthKeyPair(seed)
4. Output (client_private_key, client_public_key)
~~~

Note that implementations are free to leave out the `inner_env` parameter,
as it is not used.

### External mode {#external-mode}

This mode allows applications to import custom keys for the client. This
specification only imports the client's private key and internally recovers the
corresponding public key. Implementations are free to import both, in which case
the functions `FinalizeRequest()`, `CreateEnvelope()`, and `BuildInnerEnvelope()`
must be adapted accordingly.

With the external key mode the `EnvelopeMode` value MUST be `external`, and the
size `Ne` of the serialized `Envelope` is `Nn + Nm + Nsk`.

An encryption key is generated from the hardened OPRF output and used to encrypt
the client's private key, which is then stored encrypted in the `InnerEnvelope`.
This encryption must follow the requirements in {{envelope-encryption}}. On key
recovery, the client's public key is recovered using the private key.

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
BuildInnerEnvelope(random_pwd, nonce, client_private_key)

Input:
- random_pwd, randomized password.
- nonce, a unique nonce of length `Nn`.
- client_private_key, the encoded client private key for the AKE protocol.

Output:
- inner_env, an InnerEnvelope structure.
- client_public_key, The encoded client public key for the AKE protocol.

Steps:
1. pseudorandom_pad = Expand(random_pwd, concat(nonce, "Pad"), len(client_private_key))
2. encrypted_creds = xor(client_private_key, pseudorandom_pad)
3. Create InnerEnvelope inner_env with encrypted_creds
4. client_public_key = RecoverPublicKey(client_private_key)
5. Output (inner_env, client_public_key)
~~~

~~~
RecoverKeys(random_pwd, nonce, inner_env)

Input:
- random_pwd, randomized password.
- nonce, a unique nonce of length `Nn`.
- inner_env, an InnerEnvelope structure.

Output:
- client_private_key, The encoded client private key for the AKE protocol.
- client_public_key, the client's AKE public key.

Steps:
1. encrypted_creds = inner_env.encrypted_creds
2. pseudorandom_pad = Expand(random_pwd, concat(nonce, "Pad"), len(encrypted_creds))
3. client_private_key = xor(encrypted_creds, pseudorandom_pad)
4. client_public_key = RecoverPublicKey(client_private_key)
5. Output (client_private_key, client_public_key)
~~~

# Offline Registration {#offline-phase}

This section describes the registration flow, message encoding, and helper functions.
In a setup phase, the client chooses its password, and the server chooses its own pair
of private-public AKE keys (server_private_key, server_public_key) for use with the
AKE, along with a Nh-byte oprf_seed. S can use the same pair of keys with multiple
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

- server_private_key: server private for the AKE protocol.
- server_public_key: server public for the AKE protocol.
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
                                        response)

                        record
              ------------------------->
~~~

{{registration-functions}} describes details of the functions and the
correspoding parameters referenced above.

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
(`external` mode). See {#envelope-creation-recovery} for more details.

~~~
FinalizeRequest(client_private_key, password, blind, response)

Input:
- client_private_key, the client's private key. In the internal key mode, this is nil.
- password, an opaque byte string containing the client's password.
- creds, a Credentials structure.
- blind, the OPRF scalar value used for blinding.
- response, a RegistrationResponse structure.

Output:
- record, a RegistrationUpload structure.
- export_key, an additional client key.

Steps:
1. y = Finalize(password, blind, response.data)
2. random_pwd = Extract("", Harden(y, params))
3. envelope, client_public_key, masking_key, export_key =
    CreateEnvelope(random_pwd, response.server_public_key, client_private_key, creds)
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
full forward security (without it, forward secrecy is only achieved against eavesdroppers
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

    ke3,
    server_info,
    session_key,
    export_key = ClientFinish(password, client_identity,
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
2. random_pwd = Extract("", Harden(y, params))
3. masking_key = Expand(random_pwd, "MaskingKey", Nh)
4. credential_response_pad = Expand(masking_key,
     concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
5. concat(server_public_key, envelope) = xor(credential_response_pad,
                                              response.masked_response)
6. client_private_key, export_key =
    RecoverEnvelope(random_pwd, server_public_key, creds, envelope)
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
- inner_ke2, a inner_ke2 structure as defined in KE2.

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
2. client_private_key, server_public_key, export_key =
    RecoverCredentials(password, state.blind, ke2.CredentialResponse)
3. ke3, server_info, session_key =
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
2. ke2, client_info = Response(server_identity, server_private_key,
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
to an output length limitations of the KDF Expand function. If HKDF is used, this means
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
function and of the underlying key exchange protocol. In turn, the
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
client_identity and server_identity contained in its envelope matches the client_identity
and server_identity supplied by the server.

However, if this extra layer of verification is unnecessary for the application, then simply
leaving client_identity and server_identity unspecified (and using client_public_key and
server_public_key instead) is acceptable.

## Envelope Encryption {#envelope-encryption}

The analysis of OPAQUE from {{OPAQUE}} requires the authenticated encryption scheme
used to produce the envelope in the external mode to have a special property called random key-robustness
(or key-committing). This specification enforces this property by utilizing
encrypt-then-MAC in the construction of the envelope. There is no option to use another
authenticated-encryption scheme with this specification. (Deviating from the
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

Applications must use the same envelope mode when using this prevention throughout its lifecycle.
The envelope size varies from one to another, and a switch in envelope mode could then be detected.

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

A SIGMA-I instantiation differs more drastically from OPAQUE-3DH, since authentication
uses digital signatures in lieu of Diffie Hellman. In particular, both KE2 and KE3
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
Name: 3DH
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
oprf_seed: 742e9fef85465fcd6255c3a4ad79d81afebe2dbea03800e0e8acb163cd
0d70df019c03fd0d2a1bf6e7d3819bdfd951e09ca2797206357821f38202d535483b2
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 8666a1908af1b98d3477e9f2c4bbc1479ba5e771ffc789ba91034
0c47dbb80b1
masking_nonce: c251cdb2648daef50733ba9cbb54182a4ffce66e3432a30af14110
ad2ff6a5a6
server_private_key: 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a
9706137886dce08
server_public_key: 4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b
78624cbd10b371
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 4ae0582e6e95da0cb1e512169e9fce0e2847803c2c031609b1e6ce1
f57eb0800
client_nonce: 39a2f02421058e0c2e0197e655691c853b92730b7db822994bf5111
8463151eb
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
oprf_key: 278bec6ccacf9405e6d19664885d2bb09688a75d2e414180e46b959f884
3ce09
~~~

### Intermediate Values

~~~
client_public_key: fc590b941b57164fcb8b24aab13bbbe3cdb1f863ff07f28ea0
2f453326abd661
auth_key: 1a75e7bef85e85bcf69a2edd7fba6427fa7948c7b7c47f6c8da503cba87
afc53829b7d14803b6fef1b17ff7b02154445ff5f43d7fda1f23bc8afae4db0b9e479
random_pwd: 35fa70546c5e11e4fe2c23b1d90e73e0fd88f420f6ea6e7dcf1eb652b
0007082419bb7dcee519c3a437953c1670eeb54bfa4822cbea56375dd5ceb2b515bb9
c5
envelope: 8666a1908af1b98d3477e9f2c4bbc1479ba5e771ffc789ba910340c47db
b80b191bb31570031e67898c35802d7cec763e33d089f5b9cfee3ba38f388ea03697c
22409d01b8b1f21f4a14afe5934f1b1235c54ddce341fb25b97f70bc9f83c66e
handshake_secret: 5aa4ccdefa0a5558be538d5876555bd3ef8f9c002f320897bbf
061578d51b1e747b30faa840f5afcf4ead7647761564731e8924ae19fd11b19293290
873744c4
handshake_encrypt_key: 2c81279aa9836e7f1db8ac30573dcaa42e0e5ad0cd9cb5
608e25e5c35aeb92cab86fe296d72f2a52a7e7e80cf15b8e8fcaef62cf0562b266276
d895068eee568
server_mac_key: 16ffffef65e867bc00ed9f6e1c54ee5f989c6ef146002970535fc
3ed74515d58fbb02d52d53c5254e0016dc232addabc3492ac3889826d7c2ac708800c
0bc8d7
client_mac_key: 5fb53657dbb564c40806803067622894ca092b7b80b1ca7653e2e
6fdfd4de791971d237bcf361485cd9df75473fd5b15951d12b9eff686645d83c5c79a
5485d2
~~~

### Output Values

~~~
registration_request: 24bbcabb15452642f709cb8567eff38f4cda6044aca3356
87a62b8453d849c18
registration_response: f248ea5e6a095656954e0fefd002db5ed1b8c507b6e1c4
e83899128592a32b7f4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b7
8624cbd10b371
registration_upload: fc590b941b57164fcb8b24aab13bbbe3cdb1f863ff07f28e
a02f453326abd661295a317a3ae7b930e174d0a22cd1d41436ca7dff2fd617cfd9749
d7d4dafa2eaa079366a7b7564070810f3f8378f5ad8153b148c1000d28182a1914737
44d5708666a1908af1b98d3477e9f2c4bbc1479ba5e771ffc789ba910340c47dbb80b
191bb31570031e67898c35802d7cec763e33d089f5b9cfee3ba38f388ea03697c2240
9d01b8b1f21f4a14afe5934f1b1235c54ddce341fb25b97f70bc9f83c66e
KE1: 0e8eeeb2ca0dbf5f690cfe0b76783d7667245f399b874a989f168fdd3e572663
39a2f02421058e0c2e0197e655691c853b92730b7db822994bf51118463151eb00096
8656c6c6f20626f624c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
KE2: 8e389adf96ab62db667fcb4094d421d87c229ce169961cf29fbeebd06060c01d
c251cdb2648daef50733ba9cbb54182a4ffce66e3432a30af14110ad2ff6a5a622895
ee67cbf70dc03bb25017629046bbdbb720be09293e9d6c4e2b014add5d2572d108a48
06316c12b354563541c9cb08dcbd78d60911c2462aedc9bc303bbcac628e4529e1fad
b8fee948a03a926b213348c475581d29a7d467714002f4b4758e07ed816c87eeba910
60daf480ed3970f26f51fa089d276e10c83dac85ccf04ae0582e6e95da0cb1e512169
e9fce0e2847803c2c031609b1e6ce1f57eb0800ca372e52516d51c19763ad5eb1a5b6
0dafb68c264dcf6bcc692f667a71c5a617000f21aab7df3c8d38b4f1b5978bba79680
ee2dc920b1ae3adab8579429e63a3567ebdc761dc837c7e25e07ecb384b93d83eb871
2056ed9577af44c5d9c6844f394fa6f6ad6dded64e9e4fa50e671f91bb
KE3: 8ed88961132e40fadf382fd41ba8c623fee59a7cd9fca0a20961ea5f0522c475
026ad5cf97df9367f8cd2132fdc4c2c0f8ac089042a18722823f473aa6d319d6
export_key: 0c21f31e984ec3d88504413675cfcf9a8c101b2f06949615258259de1
12154a592857ea9811432502c6c720aa0b79c91940885d0c05520de6c33b247f7a85a
c5
session_key: e2ea35c5ee315aedbec943552a51ed5e867cf0b7167a1a296cd4a8a8
e0684e20d5e0b621d6305c723f843fb08141f2e92b48fad58fda6bf22f515a79d1849
273
~~~

## OPAQUE-3DH Test Vector 2

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: a56a5b20e36fc977b708e93825ab3cf57e3f66881a4f5b5d0b8757d1a9
f9a0620f8604c6a513f177a9aa0869416ba582fa05bda4216863cef7489ea7e5e76f9
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 544eacd17c712c0929f63fef32682f7305879d91ffafe01250792
20fe9ceaa1f
masking_nonce: 86b9d93e976317c45244087d0609f3442c8ab8423db1fbcc9dd17b
239e12cbfe
server_private_key: de2e98f422bf7b99be19f7da7cac62f1599d35a225ec63401
49a0aaff3102003
server_public_key: a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e7874
92b98265a5e651
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 63e9650c6a1f16cb9162cd9f66f5e76383ece5304c649dffb3c79db
205a21ab4
client_nonce: 57a46ae7fc6dd0bb8132a780a892a35f3c47092b2b699c7464e57c9
d944b9b56
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
oprf_key: 02a956b69fe1c36c4037d3e3a262c2cade16d0cd9beda719362fffeb08f
3ce05
~~~

### Intermediate Values

~~~
client_public_key: faae2e48a6ea40be4ff9db74bab612e23b73ffeaaa0b8c2e4e
478b9617b9d427
auth_key: 639e872cffee1b15c0865d5724a7867c03debd0fc1632db741c82a43d4d
709af050376ce11f6a03a0078d5282dbdb57d00c5a8ab3d00ab44123a03acbed54042
random_pwd: 3c6e74a2462fbebdd60bae6170490c3fa5b41efb168dba122c95cfcf4
f1a6d6d3ac38c54069250166d563c531d03ae7a0d42bf8712826311ed5912ccf296c3
ec
envelope: 544eacd17c712c0929f63fef32682f7305879d91ffafe0125079220fe9c
eaa1f17cf057cb7282463507e76e62c784d05a51433b5a525b87112edfe0e2e9ba711
f5d67e4fce86857f5b080a0ff22ef87b3625143a8e2ff3d663779af6b57070a3
handshake_secret: f1878bba9e9ce0e18f9946e20975516e7e423dd4f0095ab7ade
3a2ec2ecfe34c87530334d0128b12cb5a0b09ffd28c428b6f3d9db80f8ce9e432a495
3720c3b5
handshake_encrypt_key: e49783e9e36928c19e79525e0c1a75c943af1eb58b163b
7ceeca84d7798140d1593e7c2880f58d45b4aada983d26311cbdfde095e85780b36c2
2b39af027e27f
server_mac_key: b0990276d041d5bdf44742a975aa965d1ed2b8248ff6c761469e1
a743ce14b799203fd558003889dd65a550c6d7b75b9c2852a3fa6e8833def9e04c6f2
a09b72
client_mac_key: 2dc37ba96a471a5491ce39e55b4b4fc327ace9715e6abf067a1bc
b3ad1b0807a1abb83c70c7df9ce176c1179a789e4aeae30e549f186e97faa05b8dcb6
c136c8
~~~

### Output Values

~~~
registration_request: fa8c0e0144f7b9cd1de1bfcf78104f94d63c0f90398c9df
ceee06ab5593ec500
registration_response: 74251c702a9249ee51fefc06cd67092dafbd9463ddf1db
33a40b22a76bd12516a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e78749
2b98265a5e651
registration_upload: faae2e48a6ea40be4ff9db74bab612e23b73ffeaaa0b8c2e
4e478b9617b9d427e3ea49ba88c0acad89294f70a48e5748a8b39343b585f4131d7c6
10eca44561d0ea05771d75dcc9437baad69bf99e17a8b55a48c54ea3ca4d2c70f77c7
f4efe9544eacd17c712c0929f63fef32682f7305879d91ffafe0125079220fe9ceaa1
f17cf057cb7282463507e76e62c784d05a51433b5a525b87112edfe0e2e9ba711f5d6
7e4fce86857f5b080a0ff22ef87b3625143a8e2ff3d663779af6b57070a3
KE1: dedef709c5faf24970b4fa77480a2c640dc8c6b7a53ae78a2dbf3fc75134a250
57a46ae7fc6dd0bb8132a780a892a35f3c47092b2b699c7464e57c9d944b9b5600096
8656c6c6f20626f62746987c9ba92c3636d92fa7afc0379009ed54a7fb2db3cf7e4c4
07d4ed2c6e35
KE2: 669e1d98e5e42ecf5d9dd92967a8be5566500f514c9a1c5afcb190910cbf230b
86b9d93e976317c45244087d0609f3442c8ab8423db1fbcc9dd17b239e12cbfe398ce
96af33af774668f023a9f2f6c768d8f0c5aa5716d2391b4da38f4ad78a2615ec4bb07
2bd2478f72052c719d1d12e511e720aa8cc60b29ce44e5f979984509c3d1febebf9b7
d038d2c1efa5897d300775d2be771c2465947c67b0ab4d8afd242b038aef619327831
cc3fe59c6a4619565d498a4bb87328f0a13d518fab5563e9650c6a1f16cb9162cd9f6
6f5e76383ece5304c649dffb3c79db205a21ab480d9b21c255bf04113a6d339fff579
c68475e516c0c98f625a90f6532a310f13000f3faae4f07b1385147c966ca2724e1c4
1078966e79d2711cfc968c7f809d37d0a58ac73a5e91d6a25b1bb9fb8e97bf703f7f3
b5f22048f3676e7be35861306803cfde699bd2de547dad2e604e8e9bb0
KE3: 9235a317b05924aac30d94ba93cb089efe52c8c4a9c78a81aeda81f3115540d4
3c9e0955a89827ffd3ecd7b820a6fd7813242481f968a807a8a1c61a4cf886a7
export_key: fb8a3972fd3259c3bfd30207cf231e1f3cc0823e4aa0bd0e33ad514f3
c10ebffe6195f682c506068f530f6fb1b567169eaf2d7b16dc7aa37d27b08ae35c835
8f
session_key: 810e89a9d5969a65ef999c80ed7ae7f10578f26aa6534e36df5298f6
fde464d18dc6be0345ee98c533dff1ba59da44742023e2e1c50589101db1fda48e71b
0a7
~~~

## OPAQUE-3DH Test Vector 3

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 0aa156c855ab4b734584a12c84c3bd06618f73c133a96d42d518b6d31c
411a35e62d79ae8d143acae339e16932a5e0de327483e74e7245d9f317eeca467799f
9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 71fc1907dfb0c614cfa7d5ebbf7906bcfbecdf36b335af81cf5f0
7a15c477fcb
masking_nonce: 69b1e47c6282deedb059db28468b13263613e70c8622ee3bd7cf45
492fd26374
server_private_key: be81db28eb1e147561c478a3f84cbf77037f010272fd51abc
ff08ac9537e750b
server_public_key: 5ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3
f459678b0e0d25
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: e76f52a29ae142f939a5c2541c3460c29f0b17013e1fabba1d5031b
f52e29098
client_nonce: 5ff66026afef630e907fb4f6b3b29865edf017f2610bc1a5c84690a
bbcb6fc91
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
oprf_key: 69be59dc8e13384a752b47c43790541ec43c6c2df7defbf31d47dc0909f
11a01
~~~

### Intermediate Values

~~~
client_public_key: da2635d28af0f54fd7569b3e17acdcbc4faa59846c6ee84f9b
cb2f2124618052
auth_key: 818442397be62b9bdc62946dbfa62c003b940505ca470f74721046d38ed
741715fd5daf53711a33f5084de95257e03cf2228084454b8380d745e5e5c4d5809a5
random_pwd: 4835a6bae73d6569c0fdffdfda7a15e9aedaa757862f208d556bb6da2
30ba826fbf2b361cd2f4f0b30b310a056beb3cd0756c43cc9e8009537d46bccd14168
11
envelope: 71fc1907dfb0c614cfa7d5ebbf7906bcfbecdf36b335af81cf5f07a15c4
77fcbf1f27e63cf8b78e7d9320acbdb2fafca9465bdca29bc63f2b3d0b489b8bce76c
352c59c1653776dc08433ef3ad08fcff82b9c00ed1962abeec74690a136bf7b9
handshake_secret: 4636d3183f8edaeb510c01372e5b66c831fe2f3f1e7ba1e9271
1c0db9b846e6a1abc1f4f674f503681985a5ff157036bb6324c032f40e9ac822fa327
df87b4ef
handshake_encrypt_key: 5a266023671bc664d0c1c91dae37af48cfe3a9bc6a6b94
57bceae2536cf3a92ad825dd8af8aa99c02c9173ffe8bee26fd4bcebf4f5cd9ee8ebb
4f8a35da79b1b
server_mac_key: 1e434947a3ffb6703837cc4600a41c6b7926b45aa605d9ab8b23c
fe698c7f9ac8e8198cfc27bccaef752b649e896ffe34bdfda872958a6ee796538cfca
490e04
client_mac_key: 51e8d4fb2fed00f670816f9f3e78df88fe99364f4849fe7bcec92
c99bab9ae95baba4d3fca3cc29435f2ed093c57b26a292bfa02156c2b3cb5bb7d6707
411150
~~~

### Output Values

~~~
registration_request: fa39a478c220a89929613f9e65c9a4617da96b62509c42b
39d7e3606ed2e8031
registration_response: f220077326466e5f511d2a77e3eeadf8f2ae2c3ff62a2d
3a7edf73174fd1bf2d5ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3f
459678b0e0d25
registration_upload: da2635d28af0f54fd7569b3e17acdcbc4faa59846c6ee84f
9bcb2f2124618052b8d7f5e1e180ea1d075e1e0fce90c5a900c85818efd828dff2672
f18546281f9ea89ba4c7ea125009201c6b5bfe51d1af5b7803c70a0658d7661d39cf7
fa654e71fc1907dfb0c614cfa7d5ebbf7906bcfbecdf36b335af81cf5f07a15c477fc
bf1f27e63cf8b78e7d9320acbdb2fafca9465bdca29bc63f2b3d0b489b8bce76c352c
59c1653776dc08433ef3ad08fcff82b9c00ed1962abeec74690a136bf7b9
KE1: 96f9f35ebc0ca71607fd2cfcd465e285eeeabdec61151b39b2b4fb735538aa0c
5ff66026afef630e907fb4f6b3b29865edf017f2610bc1a5c84690abbcb6fc9100096
8656c6c6f20626f622e8a05799d3c524ede0482f39e047df99d9a53dc2dc30e8947eb
5da98b8c4354
KE2: b68cb1c073c6cb522a3fc756ad86f77b7e7cbd8dd88a4c3c71bcee92f2be3d62
69b1e47c6282deedb059db28468b13263613e70c8622ee3bd7cf45492fd2637425434
a1689d49d81a80c47b806aeb0ab7abbeebae498243dab78ae23571084a91a15acaf30
08a5d4e4b39a480b9b25b5d8c54b7b6d51190044d9fb42d4b0bc333da43132b6dd1cf
635f0122c9d68b6aec0c12be2ff729f9a54cffa7274584a7fee50ce93494a88da9298
9bcd4ba8472330e2a280d18c084254e4c1437d0c50d3e76f52a29ae142f939a5c2541
c3460c29f0b17013e1fabba1d5031bf52e29098a6d76012999541f1ec0c014ec1606f
2bd2a517e51f731d59546951d9699e1739000f438dbafcde6103bff348369d4fe5231
5555756ac2a5f541809ad04ce1f309556637215bb9e1e0da68234cfa1ffb2f044ad77
d55e52ab3c343c4cf0acc7e4a8693fb9231fca119b578654d9f5cef451
KE3: 73ed38bbc097808236815854954e1409110f9b7e889388f80ef48059af440db5
367b236f3474c3bb01c2405887df68e6110e3ae3d84ee79af469e8581e5dcb7d
export_key: e24d83b8551918e5b2d4434f41d790a5ed76a462c02b79d6c05f1549d
173b299def4a61b9d9777dd73a13d8b7e433d35d01a1d3752d890cf981fb792e2d4ab
49
session_key: a4f7cadf344e1b7318639cbf6cd9dfde3304768a159e7b903f761639
8df67d1243a54d58da06d03a4c308149cd0fd57af1739bdf019070e95e9b5e0c7f038
7ce
~~~

## OPAQUE-3DH Test Vector 4

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 24feed512ecde9d011cc5e6041b80fb51d0f51ec1a7eefdc5b0f97b2a6
9619b58a6fec3cda72bdb2694df86bd6cc9654dc2bf6dbae92495072eea299b8ca83a
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e0fda4c4137b843017f1a6c153618193c9a3738b248e5d70e05ec
0e427547a0b
masking_nonce: bb81552840671b61eb7808f39f0a682194bad9b9d967bf42b146d1
282c6f4228
server_private_key: d49399dc3bc1022938dfb0e79db523d4e4e41f494c3898eac
652bf95f6efa108
server_public_key: fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce50
017dc037001c63
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 8d9060c2c5a36659a4fa54ab5a1a026c75fc0bfa84888edaacf186b
b74e8ddc1
client_nonce: d2f496e81ca3cf64dfdc58448f3957e91e41e4ba191b4b1b58a5b10
d1be80ec4
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
oprf_key: e505ca3f71a562711a756229c552eb7c076ea0c0bd38b34be3a6f11c2ba
08e0a
~~~

### Intermediate Values

~~~
client_public_key: c02f74c429a2627df08dbdff7a07884ce66b55681c7c6b8341
05d5d0eb34f76e
auth_key: 878309a5ba5c954e54c44b8b4c4638e5f9b0fe9d62a6ad9ee63878246bb
a78b596a856530de5f3d9c50660a4e9f319ca8216844bce952efbaa588abce4ed8700
random_pwd: c9743befddb0f389072098e1433851da63d2dccd101cd2afc48f81bff
a681c1dc116c5577d8fae1c711ab3f4befe68128f2fd4510bbe941ad883debbc2cde0
32
envelope: e0fda4c4137b843017f1a6c153618193c9a3738b248e5d70e05ec0e4275
47a0b718dfbcfc6d3720df9fad97f033d671ed6c73601a7de78e33734cd6da61dd8bf
c84b90ac9c6cfe8ca5768fa20f22c322cb047155537018d7b195e10f6b7e6d6f
handshake_secret: 02d22c1b010c0005074199f7fb2a66d9b98ad01004146b7625d
36e332bb009d1bd34f1d0484be0aa8993dbfa282beb54566722b13acb912c1856e944
c2c12f2d
handshake_encrypt_key: bbd95f5458bffa3eca18743c64db6c17481d5b81bdc5ba
fc25d11139bfc9b9666ed1040f90dbd3f9a012c3e28f518598d63e2f85c485213132c
e4ab60c3c32a7
server_mac_key: 276ae722fe4c85f726b18c3f21804ccb6deb2a1461883e2c2327e
2a5f5944b4668effe89fd6ece77d3af45c4d151596354e402212f7274a1639ab92da0
709042
client_mac_key: 8a671fcd69c0e2be043d2ff4fddc873eea113d10ec6501bf0b67e
e80aece6b1ef93372581cb92e9abe2c03413bfb82e80308942e89e6f8908301b71948
c6f9e8
~~~

### Output Values

~~~
registration_request: 307ff12c023cb5ce33a04efd497252442fa899505732b4c
322b02d1e7a655f21
registration_response: 6002f3f23b637b19097545b4fc5ee52dd8ad8829e44124
3cbf47b996f416dc7efc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce500
17dc037001c63
registration_upload: c02f74c429a2627df08dbdff7a07884ce66b55681c7c6b83
4105d5d0eb34f76e27cc6b06fc7e6b1427224895505e021bee3982c059cd28f0586a6
7f8bbac26cbf3dbffa04455f5dac150322e41c3090967d6a059b3fa326c737de4d133
f1dae0e0fda4c4137b843017f1a6c153618193c9a3738b248e5d70e05ec0e427547a0
b718dfbcfc6d3720df9fad97f033d671ed6c73601a7de78e33734cd6da61dd8bfc84b
90ac9c6cfe8ca5768fa20f22c322cb047155537018d7b195e10f6b7e6d6f
KE1: e6fb9b013986abe5f6e9586a0110395a97ad695dde622d58470adb0a0cdcb37e
d2f496e81ca3cf64dfdc58448f3957e91e41e4ba191b4b1b58a5b10d1be80ec400096
8656c6c6f20626f6214b434e33a39d7d9fd6dbe3638925edd7a0344a312a22971754b
d075d8347342
KE2: e6772d617a3d3d15e24d493add0df2d0f897caf847acebd5f333e765c02d7538
bb81552840671b61eb7808f39f0a682194bad9b9d967bf42b146d1282c6f4228cc490
d3ef96d9a74fd60e3a639e13e951fba0e44dbf27454047341d9bb251cde23a6631061
21a8d06650a1f54ef0125846133ddefb97c93205f72389ce75f21bc62d20a95af5db6
284b4cc5ae6c80f140d0926aab74ab5b3f77cbb3fc3ac9e6c6f36da1b0b896d836196
29cb967daaec66807bd1a12afde65764b209f06fe13b8d9060c2c5a36659a4fa54ab5
a1a026c75fc0bfa84888edaacf186bb74e8ddc16a398e50c4e395ee52ef332d6c2c0a
77187e2e0b3564617eb66d2878c41e6c47000f05bc7a379dd8886b8d7cbbd5e481487
b9486a2ff7e5c6a79534dc1a76ca0909fdd9906a1f00efebadfded761b0b346e6e054
6c42df94f119d2b08398a7e14c37e60a93fbaca95113a1364c47b977e4
KE3: 250019842f03b241c583e99dd18697717ca2a9c0b6067d004e42ab609c0faf8d
63b811168583d54f0382a2dabfbe3ec122785f3db9e7ae36c1cac952ab09ebbe
export_key: 2adda9423cc03ff8b86fb86acd1e73c0453eef8eede85b25176d034bc
c0530914781e431691ab9a017e9a232446dc74ab6f3113c9424a4f2ee423150414bd8
0b
session_key: faed13a74738f10a1304b2180b0ac184f4ebd9862fda7797263687c7
323ed1cd8f3a7a12697e4f292b87922ec2c78612b0ff96e3fcf9c0c75c09e5c03fd6f
78c
~~~

## OPAQUE-3DH Test Vector 5

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 65201e84cb473529c734275cbd46e64eb751b44cda6825be4ccf3f928f
43593aca1223e037abd8ff6c2f1f090648d21a38faffff21566a2215ffe958c6db8cc
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 6fa7a0d40a9e372b4509f30d6b3ad12abeaa0eb7fee8d23cd32fb
e4cae415e05
masking_nonce: 351119e1f1c26d82aca6c5ac664dda4b9b4f2297b88c4b3398901f
26e36f2281
server_private_key: 4b642526ef9910289315b71f7a977f7b265e46a6aea42c40b
78bd2f1281617519f3f790c8d0f42eacce68456c259202c352f233ae2dc6506
server_public_key: 7a9e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa
3e421385fd2194903385345e6ac39e2a9911b6e624b0928051af9a6834ce57
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 98f0cf3cd83036f6a0cc0174f30081c1e348b7ea65c7d1c06801c44
22c9629bb
client_nonce: de437a0feefd2d44f5437dccb88b8ff0aa5799e602093380e4afb67
e6ba61926
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
oprf_key: 09e2812f37d4a6f7c25e163d262437d8cdac3af0e622556cad242524860
c485fe7f100c657f106fb032d172495408875795879d108a41002
~~~

### Intermediate Values

~~~
client_public_key: 8acf06c641a80a8ac8aa759e8af0d4e493ebc818e09e2b1334
0cf64f9c8ba186290b790be7b2ef9f1e5382e06f745dcfb12b83f5480f6f33
auth_key: 437bb2e1cae6d2f3e8e7e93171a778e8d900a5e9aac6b5fa1a18fd2c57e
2586d526f28ca1659af245e40d745e339bad31f5fca37decd56bfb6bf596b630ba7e6
random_pwd: 6d37af437e8f56cf880826f256e8c300b4833bab211be54d67c550566
8394cca7b295d77c82c3b78cac222760cf940f82af6d333ef3d451254cfccaccb54ef
b6
envelope: 6fa7a0d40a9e372b4509f30d6b3ad12abeaa0eb7fee8d23cd32fbe4cae4
15e05c7f3f081c29d75998e060c2d13a96407404a4ce5831e05504cdfe437af2b89a3
1add3bb5b3816654be042042ed3e3c4576a0ffa784f4ef0077a768f8c6be1061
handshake_secret: e529e0bb5ec6388e3c5f05dcd253363993bb4f9cb853ea44a28
9154f3301e65b97854d918eae1346bb009f2a78263913a885fb3252bf85107b6bfe66
6361a794
handshake_encrypt_key: ebae046872aff58b6896ec1fd34bb9a0c2f41b1f2f9c6f
bb40366799c92db9aa76bd45d756afbf0e9a1acdd732c8df4896e3f1c1f819e420eda
3089aa9bed021
server_mac_key: c26ca93043c03d967bf65290f5642905e547450165a296b06e03e
67256b6dc0a1ee0ee46f8dda972831bec729098cd9585356f90eaf8c82eedd2637d9e
97a99c
client_mac_key: 89a236821d5904aa9a7b469412a7300240ff216543ff6f3388ef4
e0adcacf54d94156d6b1b9a132fc4e3e7dc798c6d42f44836bb36b3f15677143a304e
6b67c0
~~~

### Output Values

~~~
registration_request: a2c1e08d638fa00bdd13a4a2ec5a3e2d9f31c7c4784188d
441b6a709f47e2196911ce68a8add9ee7dd6e488cd1a00b0301766dd02af2aa3c
registration_response: b2db49e6b6da10ec29712ab17923276795863f7e579cb2
1df4506c0195f19a0bb04d585b23d77e1cd9c2846cf80960e8426e7b1ef46d1c927a9
e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa3e421385fd219490338534
5e6ac39e2a9911b6e624b0928051af9a6834ce57
registration_upload: 8acf06c641a80a8ac8aa759e8af0d4e493ebc818e09e2b13
340cf64f9c8ba186290b790be7b2ef9f1e5382e06f745dcfb12b83f5480f6f33af675
dde2b3155281564986ec4fbc66f0c95031af063d0cd0ce2c86a70538a18f3ea806a86
6e2c09c62dc3baf5022bfafece77029ad03bf23f4e8567fa28ebb86fa7a0d40a9e372
b4509f30d6b3ad12abeaa0eb7fee8d23cd32fbe4cae415e05c7f3f081c29d75998e06
0c2d13a96407404a4ce5831e05504cdfe437af2b89a31add3bb5b3816654be042042e
d3e3c4576a0ffa784f4ef0077a768f8c6be1061
KE1: 08d74cf75888a3c22b52d9ba2070f43e699a1439c8a312178e1605bbe7479731
9ab7898faf4f2c33d19679a257bca53e27a7c295b50b0d87de437a0feefd2d44f5437
dccb88b8ff0aa5799e602093380e4afb67e6ba61926000968656c6c6f20626f62de9b
fa627cb161dd7098c8a582f5fb3a38641e8df3d6e7c40dffec1adff5f0d148716cf15
cd11a04b80b11cc12a1056493b23ee23267704c
KE2: 12a116c33943a114d30b83f324336e2729db77b0f7f2c6eb9f2abb41379b2b21
3a0f34d7b1ea901d9aaf37bd94671a24c4d67248612094c2351119e1f1c26d82aca6c
5ac664dda4b9b4f2297b88c4b3398901f26e36f2281d014892c96941735ca1bd0ff7b
ae9b792ef966eeab875c469025868b3f32909f05224887e1fa831682c389ff37c3a25
509b13a03ce1067450b0b822760a1367ff2ac130de48373372a55e406a115cc54df15
a88936e9de235f0fa840bb0811ca3e2e3a60708a0c8796d2472308f833a15b5722533
ff2277e8b074be7835efc1275a91b7e5e8a793a8d997eee34bbda44d9a050b5a0dcd2
4c98f0cf3cd83036f6a0cc0174f30081c1e348b7ea65c7d1c06801c4422c9629bbb0f
d650f0efdf4cec17e85b9cca2fa7ac7f1ff76ca94ed07e8ac65afd6304ef8102bf243
76fc5b064edb55fe02027d7fef41d05db3652db0000f821531fa0460312822f9ca231
d11459acd046a4c0a15ace9152a78b172f87dae424464ce01dfcd666d62ae8076d6b3
7200b0cd0e0002735fe54bcdf51400db735a5dfb51db85cbde013a83a40bed91
KE3: 6381da16617abdf1f4763b419dfff127b5d63935bf61da3021ce0a078f3a3d79
fbbd629eec0d07fdd41b736a12b0d123ebb2b696b1f0c3ca8ba801f5f483c1d5
export_key: a37ece9bdbd54b7726151773463e32b9726535c1c54da437b3cca2fed
0036d648a7d89bc3a033da3e5b60a475d7aa9e30ac273fa13083a29f14299c7ff4d4b
4f
session_key: a7b0c0a8a17b49f441851bc0359e6a25dbcb33c1ffff2f58b2bde9d9
6588f4c15b274bfca661eef8396fd63740c9cc311c68df066a8e5ee4c7aa13cd9d5af
e4d
~~~

## OPAQUE-3DH Test Vector 6

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: e746bc4488f1e92d3d7408da44020bd8036c037c1c34392921fde79ff0
5e49b174ae5e21c3b5ba4d062310e0fc83f8b9ec9d0752e90a589a0b898d021bc7cd9
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 70b213ecd4180769d4b6d25b8cdd3b31acc1eb5d43e8cc8837f6c
36b162faf64
masking_nonce: b38d8d48c60b596332b642fe735d180236e4a9dfe0be4a4de55811
83a7b88d0a
server_private_key: f0a17b7f6b056dfcfbee5bd7db70a99bbabf1ebe98b192e93
cedceb9c0164e95b891bd8bc81721b8ea31835d6f9687a36c94592a6d591e3d
server_public_key: 741b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230
316ebd2b419ae2f0fbb21e308c1dfa0d745b702c2b375227b601859da5eb92
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: a6428f56c288ae8b6c241c1c8d505098e387770e2cad14d56e90afb
4fb698443
client_nonce: d876e076a0b5d4406a66457cd119dde678a35885ac514e004f35c91
b81e45004
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
oprf_key: ccf33e8f976c53f77efeb6a9d84c3962b0b7652c6b2a6a433563ad89e5a
b7878830f681616db09b4b287d41ecdb0cf9975d02d2ddbad4638
~~~

### Intermediate Values

~~~
client_public_key: 54e716093b7750f0883a8a83e21f81a96d71e2251e33e95c72
a6846e83d5c0a46f06b67894e3d515ccbfa754f0402c209d4a4894cccde8d3
auth_key: 2b743b9a09d0018b40f2b46ee21f233e1e2950295d5c0ae5f2dbbdc3457
39ae1c94557e3d5eabf9d347e1c9bbc204afe4414446f79c1d7365b37959c0384f78d
random_pwd: 25df0ab5d5bd5558c80c2ba8e5ef46d9f7c2d09cd8e00bbe903489648
8992b832df0a8c36358f0d804f513b46676cd53d35c15f84afad608d0c47927dd5cdc
45
envelope: 70b213ecd4180769d4b6d25b8cdd3b31acc1eb5d43e8cc8837f6c36b162
faf64f474a20be9376782b7d411afb5991aa8fa0bdf11ed3118441abc1b3454944318
172b73ddb9862b259271786e418bbf942dfa80325c4a85328c4b8243dcfe9240
handshake_secret: 1a48aff16b838035ccbe201aa9bb2f5b44e16685e4c3f5c429b
3a97c71bc82b464c55fe225092a87bb2625f3e1b5b1a7dafa3003d01b77368e3cb91a
68aeae9e
handshake_encrypt_key: ea5ec250a8545b3b085bf8511e1a2f0ffdf2e1adcc5c5e
fcbbced68f1f524926cfa520ea44b27e3f9de4b589178960f0207153b7c150979e8d5
db3369392425b
server_mac_key: 6eec19e9ffa9f8abe7abc3d06804ed88858bfc5e5469d10cfe799
19740cb3d07b1b4d168df9e263da2f8eae1571e27a98229c975db5169dfe773843e10
0d3659
client_mac_key: e2ff0acd7b036edc523026690c2d9987723b4863e29ebb4a424fb
9c8869d42415e38f768e88a771f9b647be2e5154b3590d93d73436e2b65ed6948da59
a5f58e
~~~

### Output Values

~~~
registration_request: 66660fc08075380d7c2d4728ed1a7b550647e8231d6d29e
60d3d1fa8fa3132c8dc445fa9c94de42e5f12e29de958e5daea84eba6a6410042
registration_response: 0ef017c4624022914f9cb6f019f486c8a99d600c9a278f
a283ceb46108b5356bb2493a8dddf394c4ef061d3ce4ec5abdd2ba49dcdc584669741
b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230316ebd2b419ae2f0fbb21e
308c1dfa0d745b702c2b375227b601859da5eb92
registration_upload: 54e716093b7750f0883a8a83e21f81a96d71e2251e33e95c
72a6846e83d5c0a46f06b67894e3d515ccbfa754f0402c209d4a4894cccde8d3f7e22
4d986ded23243216b4d69ea479f0f25d2cfd42f72bb6b64b1ddebd26335af3aa51c4a
c6fb6cf1b5dab00240f6ecffb8286db865b8ebab69f38608a8d1ca70b213ecd418076
9d4b6d25b8cdd3b31acc1eb5d43e8cc8837f6c36b162faf64f474a20be9376782b7d4
11afb5991aa8fa0bdf11ed3118441abc1b3454944318172b73ddb9862b259271786e4
18bbf942dfa80325c4a85328c4b8243dcfe9240
KE1: 1c83acd948f714989a2276ef0c3bb16d5b637942e6d642da9826fbcba741291f
0b093b8c94888ff0ab621f90344f5b8b72159e2eb80651c1d876e076a0b5d4406a664
57cd119dde678a35885ac514e004f35c91b81e45004000968656c6c6f20626f62ee78
4169a2abed53764292f2e7385c5dd99ee21d09a4df24405706a59abb6d91f3ed3dd8c
6649807d11cb59ddfa23fad081ddda04ea49075
KE2: 9648820917d61a921f3d61cdc4393b4b37953eb61f5bb14c89c588a60f8eb04f
19ca9f0f24d9435be5a4e6c80fba0223b784ab911a89d6cfb38d8d48c60b596332b64
2fe735d180236e4a9dfe0be4a4de5581183a7b88d0a3edc579ea2e2f7cb96d8805e6a
7e65fbdf8c8f1aed255de4f8500fd48ed18d18a065534b698c929dcbf5a6e7fbf1a17
4d3aa3f10f591bd3ba6e965ca384aee663831ee4dc513e6433125e5bbc30daeac2ba9
06c5fb94c46953647a5af342ae70e56cf7bb993ae102a02bd9d7ff6e4f8e2852f4c0c
7f237f1843fee46b7d05732e2a2c5a610906b1fa92c7b0126dd71b4fad76f18efd8d5
c2a6428f56c288ae8b6c241c1c8d505098e387770e2cad14d56e90afb4fb6984435cc
2a00d1b42d14ac07e05dca2dbc20661a4f30909137bc3274a25c3fb4310fc9c61d76f
c6576c8ed1c9816719433acc81722a2a5e23357b000f4004247ed37e56617dc42c4ae
bf505f69ee4c55c7201b00443aa5804e8f633348fb9e809e557820ee7f38baf234883
8c9ba2314b46225360ca90795605df432bc052b9c4e949d3a5d70ebf11152736
KE3: c8d11c384c80d5fb6c48cc183979b98999b98fd1cbed35e14ce2d8d0513d8c86
67ca596a08ff5aa64c1d972c549524f16c360b47ced92df97565464b105a8a89
export_key: 79721acfac8b93b43ab2215894a1998464a2c1a3d0ee483dd68a3cb23
b32f94f9ede9c28b67cbab27f2537ba730d06a0072c1b8424fcc004c5d32464054ff1
f1
session_key: 567d42c15dd0df338d99830983556e7bb0eeb3da9eea82d751a4abcd
2ec85702cde3a3f788da0c07ef7d4fb0df2dd8a31843197afeeeb17b47b76c1ae6998
546
~~~

## OPAQUE-3DH Test Vector 7

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: fcf17f9786dfbc52a8f742fb8b1cb652456b32798a2ad24d5263369778
5f67bdd46e0d298588bc519fe7322173492ea18c70b8820307dacc49a5cfa8b6f3c16
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d22db39cc17bdb78dd4a8dc735729d86463a70fdd1b5ed0caa30d
ab9affc8f4b
masking_nonce: a9a890967724f9e07a41176a24f48ee1055352361b43191ff48381
65a0b720d7
server_private_key: 8cd37bf60927fafeca73ed8093538a994b1a8bd463666faa0
68e5ff9e00d588446b7d6cdc09ae8df069b30987a2cdd39286e0481e87ae227
server_public_key: 684e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04
ef823fc5c55e19163c714071efcab7ec06ccce8e6b9eba74ca92444be54f3c
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 428dbb3cbba70b9c57c0f07f3b8123208a55dd70610043e09a55405
39b8a16d4
client_nonce: a4513606402e5974dbdf5b8665e23d672c661c7cb41a6ab0760d9b6
01d63fc56
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
oprf_key: e3850aaf3eb60a1f5132bd519116bd688deca6ff724d969a79dae6c00ac
a0b2c36782bcbe8c9ecf45456d8a7e6fe47052e272222583e8914
~~~

### Intermediate Values

~~~
client_public_key: 4ea97e037e16ed56fb4e656babe96c0d2878e8f8c7df22af69
7d1b86f48c2656acd0d704e65ee373a323e99b91f8c86083c35553400557fb
auth_key: efcfa214a3d22311e937640ba0d3c87b645a3b192eeebb185d1f72c64c3
240e9351e9a43e88f549304d16ce6fc97c2df5dba8917db2784e2f1c5d3264abe5eb5
random_pwd: 753af6ab0d59b14f9586165ddad15ed21b3c4c86c50e16526c75aca7e
59e0b1c8815b2293dcb1119e6304bad1fd55816926384d20f535772814aed908ef5aa
92
envelope: d22db39cc17bdb78dd4a8dc735729d86463a70fdd1b5ed0caa30dab9aff
c8f4b2fdc2f69da42641a12a4a55513d16698e315b4e5b9e88fee981fd06d4fb5724b
dc4f774194c19915ea4e49c088feb6795e5455e03d15283474c5e92b2f8c34a7
handshake_secret: 6b3e21f59491ee74bb1ff2ea372fb93893dbd273b166c07396c
faa35a5c9104613f24097fcc6b42e29deb0cc4351e9d589f6aa27d315dd73a677b8fa
2f95c311
handshake_encrypt_key: 37396c441ed78a3178de3a611d0409be3a795a46eac34d
202dea76cc7b2afb47ffba4d9747a2067828adc4a576c22c5582e0085973f6df97c31
3f39ca385e81f
server_mac_key: ec39518a836b44defcf67e427a83e6b405763792fedbb655163c9
29872a6429cb4b0f16d4ac73c00bc59459098c6b4eb05b5906e0714f5eba0c9db063a
7e2f21
client_mac_key: 1df5c5591f0898e84b742c8950066fc7b95aa4ba89961d509e1c3
ee4e4e392c5d961d15bd0c25ed8ce6ef04bf3680a45af033cc23522a7a7c70dc3ba23
777386
~~~

### Output Values

~~~
registration_request: 8a8f12abe7f223895549fd121f9d6124424273b7524e033
f610261caf6ff83eb92d848318e7574c06ccee189b8b447b0fd26a348942d787c
registration_response: 32de5be4e8b0de81d2e062d09fb68ef32f9a8eaa16e349
bf08769d3c6d8ff50137a5673c2aa51a11181eef6985d865fe6046de2544280a48684
e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04ef823fc5c55e19163c7140
71efcab7ec06ccce8e6b9eba74ca92444be54f3c
registration_upload: 4ea97e037e16ed56fb4e656babe96c0d2878e8f8c7df22af
697d1b86f48c2656acd0d704e65ee373a323e99b91f8c86083c35553400557fba2acd
646b30d54efe82c8d1d77ac576d6ca79ec639cb933d08a5e17415cdba346ea65d5007
74d196ed5a9aa948c60d42434ec8b6dbfd53e45a69b6f26808d7a1d22db39cc17bdb7
8dd4a8dc735729d86463a70fdd1b5ed0caa30dab9affc8f4b2fdc2f69da42641a12a4
a55513d16698e315b4e5b9e88fee981fd06d4fb5724bdc4f774194c19915ea4e49c08
8feb6795e5455e03d15283474c5e92b2f8c34a7
KE1: 442b8d7585abe08bbb6b03b3d73c7f5d81cba60845258a4174e7b8d25a6d7238
8ec7814b7f0a0559fff29ac97c329f2c7b0844c3adb1c6baa4513606402e5974dbdf5
b8665e23d672c661c7cb41a6ab0760d9b601d63fc56000968656c6c6f20626f62d0ce
cdcb40e68a8f2a3c472d1fb7f0d96ce9effb7b71281a588df2ca0666ce00126e14b9a
28bbe73ada49d059f7794e5da6be7e7bf0eee12
KE2: a4f4dd02673817e95878ec1f4f82c28a66007835228f0f6a8f058b4478540597
99b944bb6c786c4189d2e39f01830e3b4b1393852a4bbd5ea9a890967724f9e07a411
76a24f48ee1055352361b43191ff4838165a0b720d76ae54041e5a8d33a4697245221
52c85449d98e1d0d101dd6785fa9056b7555157fc984f554c7d5818c8f3e575792c9b
d6ec60389e739bc796c28cc40e9d9dd0bf646fa9f2e40d24b7e1837855f51b6a9b847
4774234ec3d075b758fb7ba4f2c5b35fac38ba90c29879b59642d7fff141eb4660149
cf4d97c2a6e91cbdc32180c5efded354140c8206e2cab7212d02f1e59096df649c8b1
a3428dbb3cbba70b9c57c0f07f3b8123208a55dd70610043e09a5540539b8a16d480f
64e52526682c9d332c4cb517bb261e21b86bc7199223b962c3d2906f90bbf3252a02b
f2889a01d0cfcd6390b8567854107e38abb21033000f4f9d0734a52d240411a55d2f7
5d3583af49d1d18e34a850b5fc0e4d7eae5ca018ecdc94b48116cf28a2e59e625d439
1c1a002e5bc81858d04c6244c42b5fef37e0138d28db5cf60abf2fff417925d9
KE3: 67b9f0dcb0e11e95c037eece077aab9433d01efd02770713d381204015967d8c
d02e0378d34f0b75eaab4f203338b9a367ebce51aa8cf4b90001e2306e4ceefe
export_key: 630284374814ec5afd99bdd97b3ae1477b3ea5d44dc3d3e8c27fb6dba
1b3428004c606c931c9065279d200a717599bb71fbf3878febd17818ae757dcccceac
ed
session_key: c8b30fc6467053be8cfc284eaca239f134765a9de75a53ef7dd3c577
65241d11038d764a2b5e2159071af17cac5d8a34c5f3258ddb786a17d66a3ef3aeb79
c37
~~~

## OPAQUE-3DH Test Vector 8

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: c83287390cee4a4182f33702ec2e3a0456b17947c38b5b7fbe66197a6e
306fdcefd5811ea808be7f9888b854ea66277b0d50d4280fea86d3786b9851a1f8592
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b28151ad15a70190f1ef9ffc374d5e7bf2613bfd7cad3c799c8e3
c6b84428f4a
masking_nonce: 643e359407c96c657223f4f11299eac8134426088b359989b7035a
b5bd887977
server_private_key: 0fb0bff035e9b9cbae6cfca36aa4827ccbac66177b64fabef
a67263087c0cb4e0d9cf547979e753c22548e3174abb5ac630d97dcd4af9830
server_public_key: 8071f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444b
a7ffe82aab916bc5ca6a11fd5fe1479e553040a8b724b6305c3f4289f3f39a
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 630a312ee7f60d8edb74fd2dfa507c06f590f408c3a9475cb6b5aa4
5b24f9c93
client_nonce: a2a4707538bac521518a0cbc015647bcfda01a6f1e8b5417580794c
1c6c70dbc
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
oprf_key: b8ceebb377f67041df499a6d6a6c9a0af0d7e8bebda52f32a6fce036c39
75acb72923c0e90ecf04992fe8b785fdcd1c1b3423f471e9ad60a
~~~

### Intermediate Values

~~~
client_public_key: f4f395d76e9224d12e247a0879c6bbd615e7553609f8a13fb1
b70f633842c4c88e46e3513465a7a0ff9c432753efd7967ca7cd61c6fa88eb
auth_key: 60e11086f9957e99d4645f102a7ff64e8d0c60453744208507e7450de3f
ca3517c63f63b1700fec78080411ee7757f93ebc307c481e4cb62c258764795760459
random_pwd: de4b971c05b4e0f3d314cb28cae8c88d6635f9ff62acf2f902cc00327
3690135127aac95d6b5f3d29cf4f8b7517dafccc3e11169af0235d91d6b3954033508
9e
envelope: b28151ad15a70190f1ef9ffc374d5e7bf2613bfd7cad3c799c8e3c6b844
28f4ad6e8f2344e1ddda2cc65d7ba2678ed4fee228b625986507a45621c73b984a087
94d67feefc8b3824fd59e8d7b2f5dba5bbe9974830b16736f1c7f52cb25d4de6
handshake_secret: 5e50ce5f3bec9ccf233df157bd52586a6ace319506f19ec0347
d3ef0e1fc3866ed6f517016947390adca6989132da8df13209b38da041020fa5514ec
81143324
handshake_encrypt_key: 1d20447ce07f4a2e34b013844cd076952fa3fcfa585053
a49fc40fa4faa368fdda8b256572df4a355baf7e9f1768e588dd07371ef36aec4252c
3f9987c08be43
server_mac_key: 9a14daac64d9a7be43a00082fbadc9b335e4d10bc480922c1fa39
413302cb92c98e5458119cb5d65e5c8ba67e7f80d4bd1c673a441e703c581bc115c9d
11ad13
client_mac_key: 6f795c660901f9b628ff4d725c0a052cd164e4f47aef8afa10ba0
c96ef73f3480adf342b4e46f82cd3feacd66979621f59e73cd4c0a9989d45d4332278
32a29e
~~~

### Output Values

~~~
registration_request: e499c1ea1a644df877a01f23ddc5dccbf3add4407605f67
dcc55f29c2ccec5daf9bc231dd62aa61cf2c9fdeaf59b3ed7a8f33af59ba20914
registration_response: 36010b9034b51344522680891043cc5409fd194bb2db2c
57def547ceb668052d80a37528a6bd0b7a3db533f22e75164dc25454829d13ab90807
1f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444ba7ffe82aab916bc5ca6a11
fd5fe1479e553040a8b724b6305c3f4289f3f39a
registration_upload: f4f395d76e9224d12e247a0879c6bbd615e7553609f8a13f
b1b70f633842c4c88e46e3513465a7a0ff9c432753efd7967ca7cd61c6fa88ebde25c
47ecd52cf15255ed63e54aa82f80b1e02568e36e26d104251f76d92c11c0f39025f89
edacef5d98c6fe1475e3d21d5ef4e1a545d21bc7d1d4084afece5fb28151ad15a7019
0f1ef9ffc374d5e7bf2613bfd7cad3c799c8e3c6b84428f4ad6e8f2344e1ddda2cc65
d7ba2678ed4fee228b625986507a45621c73b984a08794d67feefc8b3824fd59e8d7b
2f5dba5bbe9974830b16736f1c7f52cb25d4de6
KE1: 501e3dc8509cecfa36efadeba5efd0e4f66988ff9575c821b0128af06a2f5ebb
d77362f2a9e63b5a76cf5a636bad31b7a86f6c6803a2c995a2a4707538bac521518a0
cbc015647bcfda01a6f1e8b5417580794c1c6c70dbc000968656c6c6f20626f62f2a6
7ee95170c51833a88419529748e55dd13e23ffed8fefdc1d2b7c939b6371630031299
800b01a99f83129aa986369e4a188220d056f0b
KE2: ca332d5b03e176a4815c1fb5b083fd5ec97e317c1ca105681aa2fd0aae254705
4338fa6e66b9fd1425d1bb3c01e7b9d6788b57e954478a78643e359407c96c657223f
4f11299eac8134426088b359989b7035ab5bd887977db1b7007a459dca3fa16be3faa
f9ec0946c4d82f986807c9716107dd392e0d663593763743931ab4b6bdc95103e94f2
85c20366d7469e72f68e3cd6e555ff58de290905000d75d45850ebdddd8d28d004004
c01685d86619aad4a82610e07661c92f00095c01dc942def11f21020b849095058a2b
ea4f3b64ef842b11abf6847cc8a77efa711c4ddbaae86b05a6cf9684ac3a6e9ef4aef
b0630a312ee7f60d8edb74fd2dfa507c06f590f408c3a9475cb6b5aa45b24f9c93d41
0d142e679aee86adbe57da4801741034120c59fa942ef44c19ffcf4a4d65200d5e17e
7d287220037ab038ee08f96c9dee6db68f02cf18000f7d16b0ebba22d4a749d705b0d
862eed7e563647d2132ed2f505eb5adc72079751fa0e3ae96a6c3d7b4b442379247e5
8f2a066636684c7aef8c6feb49f8aeeae1f8ba80a02f89b9ebbbdef5184fb245
KE3: be832bec0fae28db1a9182a6e2859557db61a69972ac3a1eb54c1dde3857c9f8
059506ebe86892b3476d945ca0b99694cf6372be0f0b1a667c0c0176c84d5110
export_key: 9c4792bbfc3e8a36f63170721b0bd3c64522cecd1b967419807cf1fde
f4d8091f462d21001b145be89e3626cd08d9659f1e3e794ecff878e1ac50df96cba91
1c
session_key: 11d4b5b5e3ac2dcfa5317c10476e66f7ec080b14c2e372ebf9a4fdb3
bc4b8bed32218cc3d4f33e626562c184bc74c778763809b8c8b46d124604085aa109f
d81
~~~

## OPAQUE-3DH Test Vector 9

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Name: 3DH
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
oprf_seed: 905fabf46e46db14631a2fcab8dcfa10336d02d6acf3b3cbe9ec7d515d
06aa29
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 05cd6f5ee8819fa6a06fbec168e97ba94400f6caf751ddb193d1e
08612495e1c
masking_nonce: 28436e5e68992ae5adb26e32b9cf6386a5c767286e2d8f47face36
4b33630bb1
server_private_key: b3c9b3d78588213957ea3a5dfd0f1fe3cda63dff3137c9597
47ec1d27852fce5
server_public_key: 02e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398c
7100af2939f672bf
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: efb8d5b8f8be0833d049c440526b3d726dff1f52d79c1f3d9c20777
76611a701
client_nonce: 235dc25fce43d6ba14c2102f70a820d7bc94fe338e50ce7b87c213a
ae8ac491d
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
oprf_key: 341a6cc463b4a1026829a4b95965caa766716ad30e59f76804feb386a79
637f7
~~~

### Intermediate Values

~~~
client_public_key: 027fbf92992fc4d0a84df05584a13538cc3eab90023598d5ab
df324e1b2fd552d4
auth_key: 14d4491f603d91ca10d3d47d83a94f137caf5abe4994da09d6bb3ac26e0
6cb11
random_pwd: ef12509c1e84a31942964ef427cf002cb15a21b1696fa878e400ad48c
f670871
envelope: 05cd6f5ee8819fa6a06fbec168e97ba94400f6caf751ddb193d1e086124
95e1c480173d117c32e9e7c892dcbc1c82c7b7a4aee572804ee0a84bc28ad6968cfd6
handshake_secret: 60692c0af1c9fd45c409a48e1c26990afb7fb8626c45ae3755b
3f8339d981234
handshake_encrypt_key: 1f5ff7cdd3db21e3d1e4da45c59d1ae81865ecf6a8c22c
1c1d66294fca7d37fa
server_mac_key: 0b2e11d3d3ab52a73618652b7de250846bdbf93a55410713186fd
a99a9f06f31
client_mac_key: 22aa0814590fef9d704b12d81b6c9049e11c1ac22af73456b8513
3d5936f69ba
~~~

### Output Values

~~~
registration_request: 03761c2597a039a535c3180bd3fb6ea9830baa50376dafa
6e98bb41be2aaae0e91
registration_response: 02c946642077b6ddd15484271d9dcc7972e8ab3f58591d
23987916113def94f56d02e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398
c7100af2939f672bf
registration_upload: 027fbf92992fc4d0a84df05584a13538cc3eab90023598d5
abdf324e1b2fd552d4ca99d7ac54ff2bcc33382e93f6907b5d9bad5910d828e229273
e3a466ff3cd0105cd6f5ee8819fa6a06fbec168e97ba94400f6caf751ddb193d1e086
12495e1c480173d117c32e9e7c892dcbc1c82c7b7a4aee572804ee0a84bc28ad6968c
fd6
KE1: 021922b40d051877d0f03ccf2831eede9b328e22c8b173d5f28091af0b92421f
54235dc25fce43d6ba14c2102f70a820d7bc94fe338e50ce7b87c213aae8ac491d000
968656c6c6f20626f6203285470567bccdd3755aa8d00261e1ce65aa120e15571cc97
72789a361b4cafaf
KE2: 029ed36af05abffe09456e52d314bdeea2164e2bb2aec1cb61a5926b1fd5be10
0f28436e5e68992ae5adb26e32b9cf6386a5c767286e2d8f47face364b33630bb1f80
58408e74f5087f31769cfb7559aa0055c4670b314daf4561bb0c75c98958cff9c78ac
43f00f80a41195b2d6b65af89b7dd201e2a68fbab7fe2b23de9b5b03f2bebcd741b5c
7a00dfab208604332f01ab83362a719e116e3787d32ed7b0ac70befb8d5b8f8be0833
d049c440526b3d726dff1f52d79c1f3d9c2077776611a70103651207f3887f92cfec5
6edd9b9df0047c1d6b7bfc55b3650a9579d44f435b092000fbf0c5c207f13db0fed46
9051dc6715bc3e6d36e2f9250477f68cbf0c8bc310e93a43c68593cd0d4fde7ee549a
9db2c
KE3: ea1a8662f77659e3ccf1e8b2faeb52c0fbb01695f2170f85bd5149067d5d89e4
export_key: 41aa121b811247a937175d82a0c8ca83934c602d626044045338b75a9
9bec010
session_key: dd81071126c5e726d6b74b8f7292fba40b9d246b1ae3784286ff8ee1
8fa8eef6
~~~

## OPAQUE-3DH Test Vector 10

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Name: 3DH
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
oprf_seed: 495c602585da4a0a7d5a7ec0fe210c4a302dfa390aed91df5ece90ca62
7021a6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 5be1ecad2663abe434005576728bd3fdde3ba389403d4a85b1ef8
8526bf0d3c1
masking_nonce: cf46ab432f92c8b33e3cfda3d7a0ae96d913298fe04176f2d32978
8f3a7532c0
server_private_key: 2bc92534ac475d6a3649f3e9cdf20a7e882066be571714f5d
b073555bc1bfebf
server_public_key: 0206964a921521c993120098916f5000b21104a59f22ff90ea
4452ca976a671554
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 8ed3b3131fba9fe6ab89d44804548ca533fe47790df21090fa2d37a
f0bf4d3c2
client_nonce: c09eeae5942a28b7688429057f27a0122c873ebf2bd43d7075c035d
b38149360
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
oprf_key: 4fb4173659f22d389616aeeccf2172676140aaaf61b584151376839f473
6559f
~~~

### Intermediate Values

~~~
client_public_key: 035ca8846dd4d5d6b7c8e1e4b64d8c31e807206abfdedf7988
c75fe758f9e57af6
auth_key: 1ac948ed1d2055cdbac5f5315c5ccca0a3092ac02ed15a6285a44093318
e6fb6
random_pwd: ae0d17a3fc03e64fb34b8d76cc3ea400de8c351e1b63fab1821ce4ca1
2c8ec89
envelope: 5be1ecad2663abe434005576728bd3fdde3ba389403d4a85b1ef88526bf
0d3c132bf56eafbc8f02fe63d4f0d0d47d613a5097b00a1307807a7669ae4c0ff3020
handshake_secret: 9c3cbb17f1327223652f8ae4ae1a309756cdab49db1e580f961
4946e7574c276
handshake_encrypt_key: 996050f663b933215b5b172a498668fd7fb6149dec95d2
c888323c30bee50322
server_mac_key: ca794079c7b180d286d1d40eff650c1d2221e794fe6a3f1be0d0b
798376da1bd
client_mac_key: f6c2277ad545461d98207f765d9054b6553e1e485af32509862a7
423bb562574
~~~

### Output Values

~~~
registration_request: 02cd04a4a3c6b37f6013d848e1c63c204c4593377e9a14c
68e95097b615d29c129
registration_response: 035d0f454e840db9132b7a2f6fe76cc5def100980a4e2c
4679ecd7570cdb3ff9130206964a921521c993120098916f5000b21104a59f22ff90e
a4452ca976a671554
registration_upload: 035ca8846dd4d5d6b7c8e1e4b64d8c31e807206abfdedf79
88c75fe758f9e57af64ea73e4418ef9723ef034a934e46d730fa7b1262c1ddfc3d948
20d1b94ee562c5be1ecad2663abe434005576728bd3fdde3ba389403d4a85b1ef8852
6bf0d3c132bf56eafbc8f02fe63d4f0d0d47d613a5097b00a1307807a7669ae4c0ff3
020
KE1: 02e747d027881e63565ce0a611dae6da50c2a8b349010a52f5c936169be1e0f9
36c09eeae5942a28b7688429057f27a0122c873ebf2bd43d7075c035db38149360000
968656c6c6f20626f62031e7dcb77fdba4b7e7b1625e43dae84733b28eaf2b4fbd7df
141b1ee353748b44
KE2: 0230a7333bfaed91b1b9d77a358e0170bcf6a724b86093cade8e9ece3b8fc1e2
d5cf46ab432f92c8b33e3cfda3d7a0ae96d913298fe04176f2d329788f3a7532c0285
b2784ebc8671cc40476a510ad2e66677c7b9d4bf6567d1894a7cf675d7b2a6ca5bcba
4c7e72a3e4332c19bdb1723a0baf30fa6b1148d59c5435a62ceee612f304e641e5fcc
ffbc04439fafb309fa3752bc7ae75c12f8b36236dff14122d0de48ed3b3131fba9fe6
ab89d44804548ca533fe47790df21090fa2d37af0bf4d3c2036d85072a9cda8438f67
dd81042861349f697c06ad4efb068dceb58c98986409c000fb19a2d2d0bf4e8430bb5
2f6c2d7b85d68e898136150b9ae2956e255e695e4961a083899544eda5ea46b4d140a
65d63
KE3: bd99950902484701d9f1745d7b077ced27b99874427fbdb10d7587c23d0c2a93
export_key: 61be82caed6a587831e0331d780edf2ab14072af6e37e15c0df3bfec4
ae16717
session_key: 1e81b6ab25c0b121501fe5685bc87b0a2c75d3675a9926ccd8d12a63
c48f8b54
~~~

## OPAQUE-3DH Test Vector 11

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Name: 3DH
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
oprf_seed: 175797d0e357bdd8fb9e2b955dce987da4b76163b7999839f325ce9e80
cdb61e
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 57b84bcdeea2c24a6aac67c8039f3feb281a9e086bbc0d60704ff
8eddf0ab763
masking_nonce: 406d08b87de905db5c2f180d8c19e3dfe101cb65439ebe95014175
e674e4ea22
server_private_key: b0b4f35c14eb2477c52e1ffe177f193a485cccf5018abbf87
5b8e81c5ade0df0
server_public_key: 02e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e5
59ae18b6bf7bb5b2
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: c4462b8b0836513506553a5ec7acf694b3f7e813abb07ff6585385f
567bc9f8d
client_nonce: 33eb48bccc705b7199ad301b0f752eb7858178306f2bc042a1513e8
d1c9421cf
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
oprf_key: 5c80cadffa219bbbee1bcde00af085ea5a72ef17df6cda9d273c85d6a29
6ef83
~~~

### Intermediate Values

~~~
client_public_key: 039c5479a5355a1a4cc2b684c23c4afc4a3072d5bcf7c32ed1
c1c2810dd28e4691
auth_key: be00f535bd08f9389325e3c13600316e25149ea44b39634a7f0fca4724f
11c60
random_pwd: ec9e3681a05ae0efdf2964fb9dcc05f1b7d2502f7389d502e6ece4fc9
2813ca7
envelope: 57b84bcdeea2c24a6aac67c8039f3feb281a9e086bbc0d60704ff8eddf0
ab763b6160be7d90dc55a398a40b84653853df9d63994bd5cac69be9eed0a2a5bc437
handshake_secret: 62c5bf5423ad294c47cfdd81428607bc403fdc235d1e42ec6b7
d7816a2453353
handshake_encrypt_key: f73616c4f0f12ef711db68a9d41a68a416dd688e407708
9cbb32ccf1aabba869
server_mac_key: 6aaf2d780e5fdd1df438762384307bf9a452c75ad9c415a2d4c55
6b310f7ae2a
client_mac_key: 4721be38eab409f9eeea0c46611e7e304294e19fe95007969dd2d
109c7ccab50
~~~

### Output Values

~~~
registration_request: 026aa49819f2c29b9543cefa0850db7fd36352c6ad8f47b
631b5b621266b670f7b
registration_response: 02b098eace2136e9cd155c6ed812ff1ef2a02e58c207f1
34fbfd7885c9cb6cd41702e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e
559ae18b6bf7bb5b2
registration_upload: 039c5479a5355a1a4cc2b684c23c4afc4a3072d5bcf7c32e
d1c1c2810dd28e46913b2aafeedd35e19ad1154b1aeb1dd4a9fd3446315bc1fb2386b
19a76ad89397757b84bcdeea2c24a6aac67c8039f3feb281a9e086bbc0d60704ff8ed
df0ab763b6160be7d90dc55a398a40b84653853df9d63994bd5cac69be9eed0a2a5bc
437
KE1: 0223c6f12f3c763bdfea59c13d8f1e055b02277625aa06cb3d839e03a60268d7
c133eb48bccc705b7199ad301b0f752eb7858178306f2bc042a1513e8d1c9421cf000
968656c6c6f20626f62026ab0dc783fb12c9427dd0bcb4d95f5b5212f092406dd581b
d337c73468953226
KE2: 0319988bfff2348275355fb52f8dd9d6124b48b01acf3061e966e5fed1525c1f
e8406d08b87de905db5c2f180d8c19e3dfe101cb65439ebe95014175e674e4ea2271f
e8da153070f4a0c9b5718a9964cd923b71a3429256e51b0620ea046cdc31f4ef46126
c3c70df01a8882c76ec7c7c5887b56ac34e07eae6f04035e762321f328946c39585cb
437af4d05a3127c29f76029016fee30e3fea109d37d115ec0c8a8c4462b8b08365135
06553a5ec7acf694b3f7e813abb07ff6585385f567bc9f8d0222d4232635f4ee37067
59740d7a0d8fb6a4068f2fbd34be7cf065f9989b637cd000f0b5636eefdcefe7233af
806299818c2a44ae8f7d48014e53a527da084625c038017c722af2f2977c06e35ae56
c4861
KE3: 41cfc5dc40ec4769a79f85481ed653761d5dc34ece259769f9c37178e518d09c
export_key: 4a0e03801a5319d6b49889932f3243dd53af107ea62f97a71ad599c8a
c706817
session_key: a3af739fda39b4dba14299acff5e0fdb8ba81fd5a0985bef8616489c
04febbcf
~~~

## OPAQUE-3DH Test Vector 12

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Name: 3DH
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
oprf_seed: 38e304ba9266d57c104819e1e632c8e591beabfdf82ec8affe8a784494
0fe6dc
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 87a7dc333305a083b16058ef96547f336ba2573fa80f1e8e23bd1
6a1e1eee318
masking_nonce: 2db02dee1aad2e5dd4ce5c774e3920b37864332327596e90c2f08a
8600ccd808
server_private_key: f7493200a8a605644334de4987fb60d9aaec15b54fc65ef1e
10520556b439390
server_public_key: 021ab46fc27c946b526793af1134d77102e4f9579df6904360
4d75a3e087187a9f
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b6c2b60aa662ee2bcb656a6ec957cdc7da3fe1a483ec25ce0dbf37e
84221084e
client_nonce: b2d7255d0310819018ad15b8d2aef7b1e4157257793a9f013a745f5
bf746d25d
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
oprf_key: 34658adc3ca15e8e386f9ae77c1c54c10e933aa19552c1ea0c6e4f510fe
ee9c2
~~~

### Intermediate Values

~~~
client_public_key: 037943e73f0373f5c97cb5c76c184703a6bc0e1aed5f395d31
d71b5e4f04fd89d1
auth_key: 26622b4db0c76cbfc0bf7c9ee76d6ed86a31b9b932db8488d80467e45c9
d0398
random_pwd: f43032fc410e3d9d10a7115917dd822b38230fcba20f5ba8951aae99c
6656cc4
envelope: 87a7dc333305a083b16058ef96547f336ba2573fa80f1e8e23bd16a1e1e
ee318bcd4ee4f2da82bf15d561c6b634b30bad1c0f607e52c36abf05c7014548a56b7
handshake_secret: cf08ea5a5be05b618d4be2be5265b578d56cb8d5529a13711d7
9b1ff62b1c272
handshake_encrypt_key: ca562639a50c0452158ae680142edadd676b58fccf248b
59ad562ca169dfb5ab
server_mac_key: 30c5a18bea1f4b51795feafe8fe5bc01f8b6a0cf05ad49e21ec53
9b08bcd8678
client_mac_key: d0f5fae0edfe32275558f39c501f1894a21756af34747e4185147
8a4ed6fee64
~~~

### Output Values

~~~
registration_request: 03a120f6f2a0b858f546d1e2b60f810ad0ed8511ef0791d
c26d8413fe13b0181fe
registration_response: 02cacf40860569ada20c73c914608d28ea21dd23b4ec05
62015fe9e4dcaed97260021ab46fc27c946b526793af1134d77102e4f9579df690436
04d75a3e087187a9f
registration_upload: 037943e73f0373f5c97cb5c76c184703a6bc0e1aed5f395d
31d71b5e4f04fd89d19ec225ec7318a5427afa5f712a058bf0533856e6211c020f1db
8e427d0a6a0d787a7dc333305a083b16058ef96547f336ba2573fa80f1e8e23bd16a1
e1eee318bcd4ee4f2da82bf15d561c6b634b30bad1c0f607e52c36abf05c7014548a5
6b7
KE1: 03edd5c0afa7257bbaeacab64837430929df9b36bc2784e47577e071a7abd9f2
efb2d7255d0310819018ad15b8d2aef7b1e4157257793a9f013a745f5bf746d25d000
968656c6c6f20626f62033b64a07786c37f90b1abc757bf074c18326773bc296ec69f
38c111e4274a4071
KE2: 037d50ee1b2ccecdb4e5af839c83821e6fe76b1c1ef3667ad989ee744fc5cfc5
2b2db02dee1aad2e5dd4ce5c774e3920b37864332327596e90c2f08a8600ccd80889f
09b1179a14399ddaaa5c32997dab1fa94f7fe13fbefe2d7f35ca7dc64fce224627c89
2755fdb8d6653a23f4be6b7ec4e27a657a32bdb8cbd2ce2ea45f99efe028921fbf4ec
2dcc22696dac34e6007b717b2818c398a132f81c672141e07b958b6c2b60aa662ee2b
cb656a6ec957cdc7da3fe1a483ec25ce0dbf37e84221084e029ad3943fb8e838ed49e
4d64e5f0b84e120f175f30115009f18f009f7e35081b9000f4a77469d6258c1b2da1d
2cf0f774282e99598e5b1a2286321ab756ecbc66ab726aad7e3f993b39b7fd4b26cd7
af41f
KE3: a1f9a49c0b075bcb0cb1c719222aefa0fab28e0aa7608b1793f044a362a90988
export_key: 89c31c71cffc0e859a316ec7768a90421ba0822063baf97cdfcf690bd
938e7a8
session_key: 10551b389b16396040c063c996682ed489b3f072afe6ab915e173ce9
c0bf27c5
~~~

## OPAQUE-3DH Test Vector 13

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 74971db14194423692b6cfcc5b4654a11a6fe597d3d04298cae983150a
0ee9247ece874b489b2364af3e344e455160ed52e3f9b044c782614a81cbf347f6766
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e0a72615819d906412c2c4d78807129bfa232157d79e407dd7016
b96c98a85ee
masking_nonce: 6898e459ad72e22a55ea1671326375ae1219e449960e3bd2132d8b
a01de78937
server_private_key: 6b61028c0ce57aa6729d935ef02e2dd607cb7efcf4ae3bbac
5ec43774e65a9980f648a5af772f5e7337fbeefbee276ca
server_public_key: 023713c6af0a60612224a7ec8f87af0a8bf8586a42104a617a
b725ce73dc9fdb7aacbd21405bd0f7f6738504492c98b3e3
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 429cfafd959d1e7d9c1ad2030058a09133dbb1a5c19372908c76b20
b53545699
client_nonce: b14febdbec2243dccb863cfd8fccfbf4b6187d1999cea128c2194d8
d1f5d972a
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
oprf_key: f7694137578cde2d019dbbb44a1c618ae061dc7d1b2ac1de0a5c0540f6d
1fed22ead08b8cbccd2fa87778212bd42ab41
~~~

### Intermediate Values

~~~
client_public_key: 02eb8306b6a0e8c08c3c5a090ffa8aa7bfed7f38a12d440028
61c06049fd6ac497161fac289e5af451404dc46b7505eb78
auth_key: e6a6af2e91ac66780aec7711f8348d2169464f89fac4574e2b033ea885b
71d8c843bca925a7947f366b6d67b8c8f00c15e989a2017f15ec726bc2198a0f7327a
random_pwd: 4d91f1fe8d7aec2d2d8d0750a13f2b5b11b81d08679cb464335c50fcd
ce6ef79e31181a39cbe02f8f6524d40efe909fc775855463aa8d1aaad18817d621293
b7
envelope: e0a72615819d906412c2c4d78807129bfa232157d79e407dd7016b96c98
a85ee0d7472311b85819740906b91ba0bf762ed43fd5cb301ff9751c48b012b022803
7387db29db9f0cbaae73bd0177256f7c4ecac0450cf294412712b9ff3299dc3f
handshake_secret: 139ff4680f1622c69a3071c732e5ef767a5d3978de6d51e9df6
502021d27a922dc14d232bbca6bf0d295f5e1340f46057f908c082bc671dc436e113a
2928d2d2
handshake_encrypt_key: 7159d167b449300a814786da9a7ff9d27c191eed5bad4d
f224cc41db730f6aa419197291d06c8c7ce82d4b071da0114565251f19c6413e9e33d
f948cae876859
server_mac_key: 6d90ea5763794c62ddfa1804638d4cee40a8f9f15e0f9fd7c0f1e
bbf9823d34bba87ffa2e5cc09a6b882790e33dba130969f4b05ed8cc441194b9718a4
aa4547
client_mac_key: 3616f1020983abfcddfcc861e0d41e7c1a5b2ea0632443537e44a
7bfd00e73fd20130008ee78d14a088b948304016034914fef21869cf77ec52c447014
c85e62
~~~

### Output Values

~~~
registration_request: 032a1ed9cba49c4f38f62e77ca295b8dd95d4d928aeb7ec
db24e28d927909e4624e4ef5df6b729071abb6e557b809d5ae8
registration_response: 036703f46fedac95e50de78671e96b6dbc4e175dd5ec87
ab414bf6a448dd4d5a2884b7b980bb25d6454c7a626904c9805e023713c6af0a60612
224a7ec8f87af0a8bf8586a42104a617ab725ce73dc9fdb7aacbd21405bd0f7f67385
04492c98b3e3
registration_upload: 02eb8306b6a0e8c08c3c5a090ffa8aa7bfed7f38a12d4400
2861c06049fd6ac497161fac289e5af451404dc46b7505eb78f7d03ccfc61e23b0c35
9f5bf3d9bb7999f2171ffc07a588edb52b7148cb6eb80433e17e954e43375490dbd8e
9157b9f7de996a8a4306f6059a3c8d1bd4b82e48e0a72615819d906412c2c4d788071
29bfa232157d79e407dd7016b96c98a85ee0d7472311b85819740906b91ba0bf762ed
43fd5cb301ff9751c48b012b0228037387db29db9f0cbaae73bd0177256f7c4ecac04
50cf294412712b9ff3299dc3f
KE1: 036bb3b9d78c508490de49427658685d8a74bdb5acb7ca4fcfb6fa5488911b86
8e746c08a1260d828fc5fa7e4232a2e58fb14febdbec2243dccb863cfd8fccfbf4b61
87d1999cea128c2194d8d1f5d972a000968656c6c6f20626f62037e9c1e7bbf41bff8
ca6fabb630db2db73a92e57c6260f39d4024c619f8b4f2807473ec0f715d83e88ad62
b88ff3828f2
KE2: 03a154f884c2c050e3bce40cea3d1e70fcf7f0e7a220df5fbf90664f574a5436
378118f2c4172a661895761eb25360de506898e459ad72e22a55ea1671326375ae121
9e449960e3bd2132d8ba01de7893762ab4a4472bb882b2aa522b975d9d45846aed0d4
40a1ce7362099ef8ac73a747275eaefe9c76b7aaceb01419380c8794db8e3a5564c64
978ae977a0e88aeeda533ae8c1b018add1113f0e23c2c731aea142337797c3b428b55
bfeab814bd1da9252857f4750e1e4905f9c26480c8295c3020fe35b13a3b182a44550
bacaf6ad7f7b3b5277fa8c706ef7a5b1aa2e8d6bd4b429cfafd959d1e7d9c1ad20300
58a09133dbb1a5c19372908c76b20b5354569903196d22794e67e69232db19e4032d2
f2daa09828c4ef71e5a4f296a0edecaa5bf564c97a7e8c96a4977975a44eed2b37c00
0f65f188b725dfbe8c8e78d937c18a0df7e9878ecd06649fbfb6022c4f7e699c69913
be706c96843e476098534e3778f3e3f63ddc462c7fafc6aa634e5e9cd9f5c4dcc03a1
5eb5f17461c71d115117a7
KE3: 4dcd04e2621fa0ca5805710f4724c2a87f98ce7914ba44956564a535e94ba8eb
a7486abd90e0c03c762404542c3490e1da46746939b7b7078aba4a6ed114fae5
export_key: abb396dc2c8784fe5bc9cc87f2f08afda5bfc67d4c6808531c3c2149c
f7c6d566455abb8b0d68a120e382b909db8da7f30cb290f1ee8ca2a0ba197f132425f
5b
session_key: a2a8e1b5b47385849c7155b3f7c5779ef1a9dfe1e395a79c7c280e79
8a4cdd5842c6b087141f6c73f34205c5291e15434f33317294b3e58de0c99f5312c4e
ff3
~~~

## OPAQUE-3DH Test Vector 14

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: f2c9733ca0f6efc142089ef53375e122aac5a1371b4a4786d19e38d25d
1568bdceac6b36278e7f00c886ffae8c746ee553c65eac5496de30d0d45ba9f5378ba
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 2c16cabec268c29024e56bcd6df0572fe4f5781e7f98cf21ea50b
d5fa44df936
masking_nonce: 0187dd4fcda9129cd7c610c2ad423e4c8db6dbe57981f90a6cffe1
2fb734b8f3
server_private_key: f5acc7b0dbee75bcd8bb50363ec640038177f06904f2476ad
5274e2f9d258659e80b0fbd20e4761b22298eba98ae9dc5
server_public_key: 03ca37ed36b0b311e3241e6e96f49a44edaa971419d91fcabf
fbca0184afabd92827344da8379abfa84480d9ba3f9e4a99
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b30cc8c0dd8ec73fdca6ef3f7acbcbbf53549b9899a58d29dbefce2
07d1d8aea
client_nonce: 58dde8981e4d4698102b86b4ab8f78ca40dfcc0fb78b35d9c719b24
98b177490
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
oprf_key: eb7254fc1567e17a3baaef4c1bfd11142237bb86e2f270abe7818c3c954
269dfaf3c9807e1a4485e604730f66fe39bee
~~~

### Intermediate Values

~~~
client_public_key: 0312b7e4bd6bdd4c9d310a0f48de7706e055d4cd2586868754
bfd9e6ef63ba225ec22ec4cab7614567d0984f8abfcb344f
auth_key: 83e58b6c66380c190ebffd3d12290198f86e0336a1cb0a1eec7251e8bc7
869e1cc5848cd06da805447f44b375d446485b934f58b2b2d6ffb7fa2aba7c491b240
random_pwd: 1fe74c8b634e79350d7f1edea4db58ca887bb43c487c09b28aa02a373
8946cf9c94f3c4082eeb4a72ae59a9da3430ad338f1f7902df882f5352a6ba56f3248
a2
envelope: 2c16cabec268c29024e56bcd6df0572fe4f5781e7f98cf21ea50bd5fa44
df93687d869c8aa81232ee635b39f8c801250826d61eddc99591eb22f2edb71933fb9
276d9d87acd98c7e61bc15a55741b40cd4aec8503a52c79341793e75a725ac36
handshake_secret: 823650e75cb7991add611b57207d4cc6ebd2ade404aa97d2231
ef419304c48b736b104e1cf53392a97dd63bd0c6fb54aa6c9fae3ca1fc4367a32d7f9
c736d443
handshake_encrypt_key: cbc1a496d5c9bc658e878118f484e4c6e3f2af0423d51c
ab66f23447ca542443af957c11d7c9f95dbdab496a4ab4c9c9bee0060bbc14e1754a3
b856ef5357595
server_mac_key: e61ea8cb31668e218a43884bcf33dc305845aa49fb3f501a2b13a
1812b0aa39f786094ac875b9a565a557befb6c5695d9f54cefcd6d00c548f7e9e924b
f4d558
client_mac_key: c00a9e4370c9ce1ac0f8aa892d08c741b7a8109963173a273f3a7
62a36691bf445c24e56a6689016cd9b01287c2560dfc6d28b6e4a5882b64b0cf39e83
587cd6
~~~

### Output Values

~~~
registration_request: 03c11a1b33c831ff085bea647c06bb354083adeaf4e7c25
d4ef17e90a25e590b275d412a48b83c064f75a6fd383e4730a1
registration_response: 02236e626e644a84a73826cb21f7d8d1c484bce5275a11
9483e04679c24041f4ba5677d0a5b310114b70b748a017d4915b03ca37ed36b0b311e
3241e6e96f49a44edaa971419d91fcabffbca0184afabd92827344da8379abfa84480
d9ba3f9e4a99
registration_upload: 0312b7e4bd6bdd4c9d310a0f48de7706e055d4cd25868687
54bfd9e6ef63ba225ec22ec4cab7614567d0984f8abfcb344f46058dc34e0a54617f4
af0f0324ab87d90c4d135b863712d5d9c99bd7c4af78239024f157e8abf6d5c3a5604
c392c4f00f68c64ed148a498c0817b50d9e570b52c16cabec268c29024e56bcd6df05
72fe4f5781e7f98cf21ea50bd5fa44df93687d869c8aa81232ee635b39f8c80125082
6d61eddc99591eb22f2edb71933fb9276d9d87acd98c7e61bc15a55741b40cd4aec85
03a52c79341793e75a725ac36
KE1: 03569da14f7d483ae405bdbd365b7bc7cd11968aa5c105d6fdf21d83cbc77050
7be9fb3aea6709f4a37e940900bccb4ca858dde8981e4d4698102b86b4ab8f78ca40d
fcc0fb78b35d9c719b2498b177490000968656c6c6f20626f62021323ffcdb6e9971c
b3d0516ac4f70f48c50ce81c897b4c3459ab5aa664a410e20012f6a3eefc000449912
82868648a0f
KE2: 034640f67fb019e6b05b7b971b8c4ce5f880a37980cf8dcd41f33e14d1dd3e3f
77905d36f0a5b8603fa0f902790663f05b0187dd4fcda9129cd7c610c2ad423e4c8db
6dbe57981f90a6cffe12fb734b8f3de3f0c538f99a4db705bbce51924e73a8bc72156
5b7614ca5e868edf6f7311eb6bb95dae4e1075f084adc8a5d9ce27c33994a4dbec93a
132639f0f7f3741584acfde6784fb7f0f508fed7cf95f47d289dd7db56ca34229cd75
e784e7b96c902ed72fbb765e3841530091a92914cbcd4fb6b6d27be1675020dc7b1f3
2a63ca39503497664188181304a517c7b895b8c6beab30cc8c0dd8ec73fdca6ef3f7a
cbcbbf53549b9899a58d29dbefce207d1d8aea037b55471c1bb3a246d0030fda68aa8
0a79786fa060c0b56e7bc7d0000886e3d661be0afcaa0cf69519eb528a11af48a9c00
0f8cb203375040b50f17ccc2e2892c65947fab7b3e48acf41ecf3000dfe14ee82afb1
0105ef39b948557f9b4a605c0000c88b6ec7f57539852a20107b31c59d6187e219a9f
12562ea2c7cf160f80b8da
KE3: cae1bee288cf84692eeade74beeb4f26ff28ed4f2cf169009d7a5da46625729c
d1a04cecdb071de7e713021bba36e458bf983a073bb384f21cb2945b8c7c2c11
export_key: 86a607fe49f25d207d0b442fa507af46e1e6b61ca54ffb96d083c8795
70601f3c84238f596d907f17846242074a1d987cc21962439e66bd1d80c099bf24872
4c
session_key: 05904b3181b41ff422d378513267035acc49b52de83d42a7b3a0ddf7
e679c85ebeca7be972b7d40bd1e7b74b69bbec98e3787cf3782ae3d5fa93ffd5f5f04
c29
~~~

## OPAQUE-3DH Test Vector 15

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 4f4a50bc5855620717cd58bc15eb0135ecb389e8bd2fbbb5d13952a2dc
3a80414acd98387424f266249529db0cf0eed4c0042782977d634d52e6f325df2c90b
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 192a6fab69c63ebe8ecf8d70fce467406b1fa3da7a2847cb16da6
0da572a4fcd
masking_nonce: 1c28eee4dc5a8aa0672ad2c1e2b44e76eff34204c853d6aa871b6c
b0301a6131
server_private_key: 8099b50c7ed9444176251781b6a8575de7491bec330164821
b9b2a108e3ef8964622075015ac9ea0f8380dcce04b4c71
server_public_key: 03aa179347ce8e27d2122b8c2c43315635e5489dfe1a50ab77
186e4710cc489638b097b3302b550da04f5d76adfa826688
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 746e77bed504789e01eea8d7072c42993cc441ac772b48bee863bdf
3c8474185
client_nonce: 5f6b96ca9564cbcc5faf99dc270aa4315cb2400f1d16fdc4c696646
4a3587423
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
oprf_key: 6375cce6eb4630cfcee344b9fee2a78d8f57235e056db4f20865f30a1df
a4b8e22fe23fbdd86021a35d99884b4d2bc48
~~~

### Intermediate Values

~~~
client_public_key: 03974c19156784d3d4a644e055b9268968f01411b69713d2fa
8644d4177bc27afb68720cca5bf83a32151028608e7ea44e
auth_key: 3904e62579158ef43260aa7a293b664dfabcc2ba38c5682b225ea9f4298
011a17f52c3a93cd6d1253f8b393ec2a97302857a06b8996a6efd09332a03a44ca762
random_pwd: 6e54093fee0828d8c2c8f1a10b009f5ac003dee4e63bb96fde6d6a676
8e2cdd67ae3971d0b9c00d81ba2c5a0d10fbf378b1d8f531031e60b1ebc11d1a72ad9
4e
envelope: 192a6fab69c63ebe8ecf8d70fce467406b1fa3da7a2847cb16da60da572
a4fcdfcff1705ab162df4f07d7f7c8498233edca7cf428e93be1330b889bc5ff720a2
055d42ed4c1f8bd770ff14bda8474b1708a08864fe34353a9671f483c53d712d
handshake_secret: 0f656ede44531c04405642322a69c00ccd1c7134ea6c036d415
bc4f7e59354805eea819f691f50f7a85a3a98334e4089b297807b0af255aca40d02c5
6d42da8a
handshake_encrypt_key: e71a469fd326ce755d71ae9c551c631a3661e275c13cd8
ed537c30f764a522feeb4533cab1218c421f8115b9d37311fdd436c704ad29c2b36ac
3c5a2cf25b799
server_mac_key: 5a31c0956bf4c6d701ccd363a72e3c76aaf40f8ccd038a52f5d7d
6d93be1ad686a06b805dc36880c0d3892fd0150ecea032f33dc6851726fc87188002a
9cafc9
client_mac_key: 3e9ab52762a7f42f1dc2ad251d99a0b16e95cac5720215a79da83
5fbb46e1874673fddc7ac95469eb2d2f842bc51ac8a481db3a50cc824e08c6c84c496
50440f
~~~

### Output Values

~~~
registration_request: 0399b76973449a299bd2ad6be1ca983c8a1eccc7e05a36c
a120a30a8807d96bd4b98d076ddbd99e36adfd30b0886fe42f9
registration_response: 03110bc47c51a03c5b1c1d6ae58b4dc9a09754f4a50ec4
7b74413f1d295850251bc9a2d66fe4b0c385ea0d902f09c6bd9503aa179347ce8e27d
2122b8c2c43315635e5489dfe1a50ab77186e4710cc489638b097b3302b550da04f5d
76adfa826688
registration_upload: 03974c19156784d3d4a644e055b9268968f01411b69713d2
fa8644d4177bc27afb68720cca5bf83a32151028608e7ea44e0e19428a75e642bc27e
8f0d6f571adafbd711e5ac355a4ad5c6baf7d5c77486914b088af3ffba2d8e558cc04
72c43d139826506d6db4966174053e47ae1385fe192a6fab69c63ebe8ecf8d70fce46
7406b1fa3da7a2847cb16da60da572a4fcdfcff1705ab162df4f07d7f7c8498233edc
a7cf428e93be1330b889bc5ff720a2055d42ed4c1f8bd770ff14bda8474b1708a0886
4fe34353a9671f483c53d712d
KE1: 03bb6ba53426efb2307df620440d09e1b503d3d2135dd0c845b59f135ab39bb3
00aad505641fdbc2725c31d221feb82d9a5f6b96ca9564cbcc5faf99dc270aa4315cb
2400f1d16fdc4c6966464a3587423000968656c6c6f20626f62038d4077ad0d00842d
0d621527f8225c405f80049752378a4e111b3dcd52857d35f464202f22a17d717d5a3
be3455a93f9
KE2: 02227706f534072c3f226d7a4966d269ae144053fd2f742872ca735a18c6f7a8
94970f8f7e7994c48b5560d052cd031a811c28eee4dc5a8aa0672ad2c1e2b44e76eff
34204c853d6aa871b6cb0301a6131803b5593566ff7e6f6d1bcf66fcd2b9434da46f1
22c48ad1b572e429a42f52cd99efa0c68317f1388ae7e4768f51d5a9344c9b666a957
cb423499e23d608f64340e5fdcdd17b4f57c31c25ea7622704167c1d48f22d2850595
9693695dfee8448919232ca16891a652012310445b1c898adcb61a45f6fc52ba43728
658b42933a9e081b2db2680340a394af4260aadce74746e77bed504789e01eea8d707
2c42993cc441ac772b48bee863bdf3c847418503ed7dcbc8318a00c1f42c2b75682d0
beb532636c2e03c524bb5bf5af735812003bdc0d076ca0dc9aa7ea97273c7088f7800
0f94775571e22b0853586ac799accd84ad2d6df2564f863174b5b1ffedee9f1da97a7
37bf07d79b6b4fe70ae2d2fc5564fb1eeeefa77e16e79b742dcf9ac8a522c32b60d50
0e8b0cb8b4f0fba2fc98d1
KE3: b3ac230466de10dc41d54c81388d1f9838f51ac0f4fd5ce4aee615abf2062a06
8d28df47d2e23b73a8887a1a92f9a231b987adf61c3bb7dfc60fa61fcd9b5c9d
export_key: 5714a0cf6cc025b58cab8040a7bb98f4385005b541ed69f81eb6a785c
0fc0511c04361960cad7d59d500853d83814680b7d132284c63e7f989278c971b3666
37
session_key: 29cbed3b09b6698d3200af71141f41eae98204871b6aba32a6ee251b
5a717ee0e7357cbc953a4cc84527692cd5c6b55eed0efd4c58bbbbab96f918fa86513
0af
~~~

## OPAQUE-3DH Test Vector 16

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: c499773ddae9c66609907aac17deb5a49151d1e35eb3ace672d9a14099
35a0a3c5cd8a3f2d62c0aeeb129a9f6f23ca047fcd174d024a3e09bfee5d289e3e7ae
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b44c5f1556ef94eb39e98a4bd6c577d1a358ef47499cbd04afe01
07d5b8f735d
masking_nonce: 37536f84cf5221ee0b12c2210796863298bb5f5e514eca7218c813
7cf3667e93
server_private_key: c6c4dfa3a822d8f670e5aa46e733baaec9f93d5e14ad9ab99
dfcbcb2ad157a8aef1f3fec3f24bbc392c9755271e8792c
server_public_key: 028cde89b6908e81425fa8a597e3103021475346a146b1f1dd
ab47f09c76ed3b78a251cf390bdc086924bebd471063abec
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 2e93f8e38ac1f0b6f63ee3fd49c9f9fc5a6dd609f99fa882035a719
922606c94
client_nonce: da20da83714ffa4374cebbf80a1784aa99932be7e28f245c8082964
d463b7307
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
oprf_key: ec0719f55f9c6cf83a522edbe9e77ea6e5ecf05aa47b61dbf557bf68e32
750be2fee9ec4af77789fcbd36b8eb184ad8a
~~~

### Intermediate Values

~~~
client_public_key: 0336614c5bace0cf9af6f26927f1faaf80a0d25bab4900f09a
5184fc0ca1237a930cadf2d8a8067f5aafb543458d0624a2
auth_key: d1c8604f6640f866faa42feebeeb6cbdf8b71e25cfb557d3e620bd7c9c6
fbbdf339c59d4a79d3933f1e9717de75fe1c2826b824b4f9995ada82465fa5566e739
random_pwd: 62e80f1d423b9e205c0c4a50ba82acbb47ceda91fdf8f393022408e3b
0ed5ad1898f1f4adeae735e5a604655ea5e54c6ee9d101ba5092178c6e4bfac1b3f6a
d7
envelope: b44c5f1556ef94eb39e98a4bd6c577d1a358ef47499cbd04afe0107d5b8
f735de2b05e4e65e980472024f5eb21610e351e0b93ebd53f568952df8d0fc46b3930
4d8325e07e015e837075069e688f992dc18d5fc6fc9c319b46e045a2cf14c94d
handshake_secret: 1a2476123213277fe45816a382f3778c43b8708c72b0d484612
2f7253709f00a0f8ad5a09ab0a49c00226e57672773952503d1cb4a1f66c80cabaf27
7f942c88
handshake_encrypt_key: edb125ac6d4eb2196018a14c48b414bca4c81770ab1ba3
30797996541b7fc69a58972d4476b5cebcd8ea740c444928815655f302cc1ca7f2659
735a9167bd000
server_mac_key: 3cf11d42670c7501d736f068150b1437201a946ec4d2984134973
ccb115b22e77e540a18dc16503bcad6481aa094138c1608aeced0c54e098357b691ce
4a67ed
client_mac_key: 0211085d242e9aea094bbf425fad1ab84a1c8de569b1d4d3655ed
5ec30b5d13d58822737c6c26757f3931b91883e80d90e19320a70c94acec2c2300d3b
50d13a
~~~

### Output Values

~~~
registration_request: 03f8569ce50a023ad6518281322157e79e1207a96bb9214
95ccde8cf48eaf27895245a7b8f4b3b5c43ba54963a19cc488e
registration_response: 036ca8729b0e16cab3d51bb3fe7306bb42b84a62306303
50bb3a79ad9d7f4e323daaf64412af306b7beacfe375cd33ef93028cde89b6908e814
25fa8a597e3103021475346a146b1f1ddab47f09c76ed3b78a251cf390bdc086924be
bd471063abec
registration_upload: 0336614c5bace0cf9af6f26927f1faaf80a0d25bab4900f0
9a5184fc0ca1237a930cadf2d8a8067f5aafb543458d0624a2f74bc0626af89763a22
8dfdbff05ed82dd10778f5dcb1067847508ed61888ce17338a0bd0c3af5a410c0e4bd
25b8c0388b718f8dd194a7a39e83dd454d7da809b44c5f1556ef94eb39e98a4bd6c57
7d1a358ef47499cbd04afe0107d5b8f735de2b05e4e65e980472024f5eb21610e351e
0b93ebd53f568952df8d0fc46b39304d8325e07e015e837075069e688f992dc18d5fc
6fc9c319b46e045a2cf14c94d
KE1: 0255b2107d1a2192eb54c25c98bb7a95e581d7d23a38e1fceac9f8ce99f568a4
fad6c9bbc5abe4ff08f8b22e31bdfd6971da20da83714ffa4374cebbf80a1784aa999
32be7e28f245c8082964d463b7307000968656c6c6f20626f620246ba00038cfa5105
659e8c250d10618a2c7f9d09d174663bc5689e4778f7054534d9a4200a447510023af
3ad3c61ece7
KE2: 024a3f95e97f84cf2e21563ee0ef2b4a8841925eeaf2aa8667b7d31e921aceec
a838623979c07b52c3d0305beffe631ae937536f84cf5221ee0b12c2210796863298b
b5f5e514eca7218c8137cf3667e934c08b6759f9ecc43f94a196a0a52c791f957d45d
af1dba738ed25ff82e16149247f68b2f91e4c7471b0587a0fb91c813bb8dad4625ab3
6e0972d46fd34983fe20e0c3142975db3af41339b60c1965818f1d6300a0aa5ea73ac
88d9c67eb02f7e6b49c7ee14b67a5b11b5dd0de041b1ce40447576712da7c4b72908f
456cc9728f041ab1bcd972148556b46b023161f9a762e93f8e38ac1f0b6f63ee3fd49
c9f9fc5a6dd609f99fa882035a719922606c94030d570f50898367457561b3a5c7078
52633b4f9404cc45b4058f52f5da1ebf67cb737bfe5c272bfeb65efe6bf7255116f00
0f139c9042240ed567fdd75f7f71ff8c7fd1aba880259e15e7beb67bd63e195923aad
22365d60cbcc383cf3549a7a238fb0b8c9182131bbac51e6aba37f0bfed40d672236e
878864713cc227baa61c55
KE3: 0a9dc8a3dbcef4fd8ca5d9d41c108cf32c561ffc934d1defc696e5ca5dceaba1
361aea422e78e8dad1c75ae853abdceaf44faa14d985e8c676fef8435f5247bc
export_key: cf74b938ba7138f8b2a3c063afb68e19843c52ef212f2d047a24294fe
f1c6be91ffebf0d292feed63c09277262c5dbd8b2cff78fd0baaf4ea807df5d06a1d1
64
session_key: 29410bef8ffaab26a42e1219960eccaec1451d2449753c191f5f1cdf
05dd86f0f602e25ec035528494bff481e4e69dd58682afe69b50f9b6541aa67e0d3bb
b09
~~~

## OPAQUE-3DH Test Vector 17

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 305a9094e237708c3e47d39c713f3aa2f61d07ed54d00393faf9fdaa0e
2c71cd98251699c38a548699423e5a7e8e39f1df55e48923c83ec0e9e53a3812c2908
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cdd24865ce49f1dbbe114898aa4d7395874a38f7a80a889f25bfe
005cbd593a2
masking_nonce: 979242b7ea492bd5c6a43a4c1f33e388d4126501ce096e808384c2
b56e578107
server_private_key: 00648b7498e2122a7a6033b6261a1696a772404fce4089c8f
e443c9749d5cc3851c9b2766e9d2dc8026da0b90d9398e669221297e75bfdea0b8c6b
f74fcb24894335
server_public_key: 0200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b6e689634df73bf6149071db20a5b8f942758fba53e066311f14d6c
7af7cc749
client_nonce: b4e380951f00e5a6880972766649567141fcbdacbd212888b193a07
f053a2446
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
oprf_key: 0175846a1174e0e34a7ff324c455b2fe4d6f21c3faf84e97a107d1058cb
7a8460507f76428024a75b1eb1181003b808176c6e3fa01508a06c48505328f7c8bce
9461
~~~

### Intermediate Values

~~~
client_public_key: 0201e31607c0215ca990ec42aa07e449c869c8f67acd2c2a12
987a50356d0fb0ee19867d6d00c8e188a96a196c59f4a3d0976f1e995f15bf41a824c
9011365b993cd76
auth_key: 72526b0a1e0beab4e0c17beff6d4f6a42946b6b6b820d03b440a2725b6e
f28462079da9629dd353fedb75a9774122db8259690dd692d034786e58e3dc202189a
random_pwd: 473279eb11dc3754a85460851fdba18ec5b619d83e2de4f9be4d00bce
93a14b513ffcff3aea4c63094287b73f7d753920ccb05508b1d3cb930eaf397e8bfae
44
envelope: cdd24865ce49f1dbbe114898aa4d7395874a38f7a80a889f25bfe005cbd
593a208c711b4559cded535a154ef8be0d560d3f59e2b583aa1e24f48c76a190b240c
4cb504750d40b0ddc6ba1eeaeb1472fe027ff45cb61a4dc2d50202cfd4aa21c8
handshake_secret: e28dd47fbb956e6ab7a94ba2332c6f6e43da77471867698e815
8d9c6f8d7325cb5ddd6db28d62f26c8227cc809080bad6cf5e0cfc4269bf4972f0e88
52961022
handshake_encrypt_key: 475d94e2db45738f58a1d5c61057329e187b8a92020b5b
81e0ae5a74da79fee6e95f320b0063e22833a86aa7869b44d0ab495b44fbaacfc8890
5a7b43cfa5466
server_mac_key: 47181b87ef2f454ed5850e33a2612ebf04867c5c7cc279396e359
f527551b27f9f9ba51dcca0a9a5c84b4f13d720addbd879a60b6df6085ed5814dbe2c
97ca3f
client_mac_key: b338700a083d6d2da9a769c435f5dd4f75c9b4d6886d25ae97c55
c1534a2bf40f35ddf02a7622fdf4415049a6c1618e9f19cfa5a4ade6c5009b7b4d9f2
40cef3
~~~

### Output Values

~~~
registration_request: 03019f508a03d6d883f28a0afa477eac4dfad2ae9052a82
ef5736b24eab85dfc40309c5d205bb94b9a6697ac7b97b9b63e057f163905ec396db8
fe250544bd94e90c13
registration_response: 0301d2cc1df63cbbd9a66ae686296272c56a2739acf8c9
4ac402b6856fdecf8e39b60a480b9426a25039b4f61104a9a0887392d333a38235ea4
56d6aed3a231f27fb540200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
registration_upload: 0201e31607c0215ca990ec42aa07e449c869c8f67acd2c2a
12987a50356d0fb0ee19867d6d00c8e188a96a196c59f4a3d0976f1e995f15bf41a82
4c9011365b993cd7617ada4416aad2acca6216b9507aad444524d018caa68c96d4186
85a46f42a06ff75635510901d17b5580b51655cd24bb39b0a78e93f751d6704ff4617
e455e86cdd24865ce49f1dbbe114898aa4d7395874a38f7a80a889f25bfe005cbd593
a208c711b4559cded535a154ef8be0d560d3f59e2b583aa1e24f48c76a190b240c4cb
504750d40b0ddc6ba1eeaeb1472fe027ff45cb61a4dc2d50202cfd4aa21c8
KE1: 0200001c8b7065b1f65b9e87150b85b32e6a13738dfcfe40a947a3868b0504a9
c0b8f2d2f8261af3c4507f583ac24caee8981b3c2e7c6a81192d383aec9fb93e64203
5b4e380951f00e5a6880972766649567141fcbdacbd212888b193a07f053a24460009
68656c6c6f20626f62030187b0369b07402c41744c664239d0f9fad568f0ea5c13e4e
4d80c770fda054cca7fdebd3f91a803a3efe7353969e388623c224a86cc32575ef8cd
5e0cdc3c467343
KE2: 020131009ac300ecf143c00834e2ceea178df9304e99d8771cd6bedd8f8a39b9
11fdf97db2ad7479bb5e760810ae2bc43671c225a9c92a58d503ce61a655e07ebc4fe
3979242b7ea492bd5c6a43a4c1f33e388d4126501ce096e808384c2b56e578107bf53
98e4e94fed46c63b64b3843cb598d68114c0b949ac8e65f3eb0d959333833b5456bac
e2209b10465e59a8fe86f48e7e6ebe7e8a53e16e018a11807563ab80405af11f96194
62cc3ac8e2b736ac896c7aa6fe833f0f30c3af897aa71e474593417a2bc44dfa3163d
2a443aa2546a422f7aa56a63d66392d5a37e78aed357f63ee3fbd052624b890718645
a54e5f076beb699ea178757a72a6c43489038e800c0f5fb6e689634df73bf6149071d
b20a5b8f942758fba53e066311f14d6c7af7cc74902016c63c8e2b3feac6366e3dcf7
52a8c2a287c1fb4d648aedba86aa0ee07d2b1133d3282584d7c66357bfcab76526f18
4f7ff9af506f9eec01645b99b6918bdda600c000f2207b5bbaba357b688fafcb028b6
e73d2c1a285d576bcb84d308b0ca8bad892fa59f42ad54a3663a7a210d2c13976b622
807a8c50173680b2075aa0b08c6b5ab9f2978561358bcadd0f87d391811e0
KE3: afb54cab9cd81e4d939d71ec50e2d76694424e20cf7fef4db11f552a05074749
6c0736298d7fd02a707a31ab84894b59dbdf86429d53e5bb5b9f3531277467fd
export_key: 9023796f2dbfc4230f83411efdfc23b2842c955363d4af91223dc3325
8e601e87b1d1eab0c6e90674b7ece8964ed6b2df5bebaeb233c443ccfe7c1ce0b4777
97
session_key: af94f0f2c0af8eb35155a80b22086d46b6d701108fce8f7c228ef3f1
ab9c78e20b40c4f7216429fe9209a0a2f4e18860003b631dc65da19965d963a0cbc38
b94
~~~

## OPAQUE-3DH Test Vector 18

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: d99e699de0e4d1c9b6ae194712f6534fe91a80aa3fa1cccc3464dc5d9b
93c7c94750c48364e221c8bb4d554a197ef7a93076c526df183dca28a251cd27bb317
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0479a3b6102f8c32220c7c210959f6a9663572f47bf194fbba065
8fb02739767
masking_nonce: 85e13e64d885c7f538cb210a1a0ca6d97535a5a5ad65a0878f0ccc
45e09b8639
server_private_key: 01e58f3492c6da02dd7387bd1dc40065b23155fcc16e56ed3
586c3c2d80245859235d872c5266668cd562a2bd7f34654235b1b9961485ae246256d
f3935910d36507
server_public_key: 03000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: fe5f8b94d1a68532e4f396faddd2ad257888fcd047eb81e9c1e72b9
9939d9bab
client_nonce: eaaecc78985ac4f83a8c5704a6ee4364d21843759fa5a2fdb1caf2b
4076e6c8b
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
oprf_key: 012a7f58149cf1080f4b9572ce6ec33e31e1e6520031e4477347a3bd3c6
909b13e1662c472dc3bacf03bbbaf4e231eb53cbce043d79fce0fe7e64036d14d9740
14a1
~~~

### Intermediate Values

~~~
client_public_key: 0301573cb98db425459d3afd17f3f0725b5e6387e4f481e916
07d3ea2cf3103928ebe1136759a5dbdfaa36efa490e0a3d6e864efb852ab00f82e1ec
93449b2b8eb6612
auth_key: c30258adb8ebd21e7c46622dbc0a039c6933e29eed10a35d812cfa0a5d8
0cf7ff511922b1d669531b9fbf5cf94f1e80b45342b1b0ead11b6afd997a508e17a8c
random_pwd: 0be38c86dbe34895d337ff99e42e3cd8d5971be691fdb53ea62cf5680
0be7691f1b9d9bd22a96179840169dc6ac50c9b0e5d132d2a32a0658887bf5a4cabca
04
envelope: 0479a3b6102f8c32220c7c210959f6a9663572f47bf194fbba0658fb027
3976749eda3e9ebf9c695e551a995768a1b7adaeb6524ac720db1e845c42ee5e46abe
081e52ee6b2498dcb0ae9d686eabb9b95ca7fca3335af3ca213c383f4f2c53aa
handshake_secret: 5a73f52e1768014b84618b1cef7ae717acff1f8409c988c8f97
acd18a4ca2b23530f103512b1e0eb8c9a7aac812a2627018466c9291e8a7d0b65512a
9df10a5d
handshake_encrypt_key: 0a7cf65fb2050ccad1a5025b76d799aedb4104a03c2a6e
ecaa869d4df64969fd35c476c1fbe2ae262ec3e1e4f4ab91e3c83c72a75533e471fc5
cd76b0b4e73ea
server_mac_key: 0daf4018e22cbd803bf766165582a1a48298d275293219d215db2
a741d08fcb8ba92223eb73702b0f0d86eee7b4f968ad4fde5526bee55cbcf66f0d52e
101273
client_mac_key: 3d827db2e992ae2f47cf2f5868cb106a677fe5fc6ef33c7403583
c223f669f904354bf5e538d86afafad3e608daa7979e83a8d312a3beda984ae62965a
0a2c3e
~~~

### Output Values

~~~
registration_request: 0200bce08f110a6634cd66b75c0721208df3d8c392f86f2
feb9c20fb62c9a30df00b37caba143386c7880a96301814e425ba9df870cfbf19724e
b58411604b3a618f29
registration_response: 03001fa57a1a64468c54f26bf5f00a735d641844bae78d
cae18bcfebb1fbc75aa39126f69062322e25850d8481468b991b5c7175c1cfc8b6c15
8c01baca2d724156e6103000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
registration_upload: 0301573cb98db425459d3afd17f3f0725b5e6387e4f481e9
1607d3ea2cf3103928ebe1136759a5dbdfaa36efa490e0a3d6e864efb852ab00f82e1
ec93449b2b8eb66124e107018da386acbc451326c56edbea1b43502e3ed6e8ee787e9
f4eddc2c9f982697759456bb0278f092df26348a6bd0657dd168daf491397d52629ba
987df790479a3b6102f8c32220c7c210959f6a9663572f47bf194fbba0658fb027397
6749eda3e9ebf9c695e551a995768a1b7adaeb6524ac720db1e845c42ee5e46abe081
e52ee6b2498dcb0ae9d686eabb9b95ca7fca3335af3ca213c383f4f2c53aa
KE1: 0201e2974af3a0c9a479cf1589e9c7db8f3e04723123436453ec427f75974423
4a57a91a724879c5cfe93ed919501d567a6fad6ff5763647c351ad6dd925f39cdb04d
deaaecc78985ac4f83a8c5704a6ee4364d21843759fa5a2fdb1caf2b4076e6c8b0009
68656c6c6f20626f620301bcdfcaabb52a829a450fdeb63bf90b8c98c6b2717164f48
e27d4c737058feb556f81fe39aed7846313ff6a6fb9c4bf1d81083974f2babdb08004
8cc67e12f8ce2e
KE2: 02016d358783b3f561b5bc5d38cbca8495734c6cbeff262e3fef3acd4c69d1d0
6964a79995c8dfa1cc9f7ead66dd86fdf77121cad0683dbf1c38acb08e8445ec4d795
a85e13e64d885c7f538cb210a1a0ca6d97535a5a5ad65a0878f0ccc45e09b86395dc8
87d0a4b23f5cb7dd697e0df2e4ed77ac5c0cd7c6e968456ea804c0163c966975fb039
3bb12768f57cdf3f452662c600bfcfebccdadd17e883eaa416bbf8b4dc5349610bd1a
7fb3a9962c8e49f8323464225cd1e78be83f75e84cdbf4fcf61911d2e34bdb4074f42
31570b7c1e9c7cb58e6e098f947a7e6bd0b6fee7337be6643ec38417595da18304277
3fdf9bcd9f0c481ebbb938c89b260290b618a0e9604acffe5f8b94d1a68532e4f396f
addd2ad257888fcd047eb81e9c1e72b99939d9bab03015da5c9a33d3168383837d8d2
ae4d00f39a8a631cd126b4dc1b01f06c32ac86ce29440df0e45650879f65ad94a3d75
2f265254f7d5861046cc016567f9e36b873d0000fca0183ebff042057c39914498ce3
b410326541bf0e84fef04066e5cf1ad2c3ee330891079ba22ba7b287121c6bdc2fcdc
19315c51305f783ec18d119ac44b18576cdd6051800bed51b0d31bcac1646
KE3: 9feca74dd46696a2db37056a19f843c8b820479fba0904fec76bef89e7a75716
5f02af8840090664a4971888f15caccb31a412d9752bf420324cfdf91c29a425
export_key: d8a07da512901bb21f04bbe14534ab96b2ce4a1b7db6e21012690e2d7
ff1ead69fabd9aa9088deba47956a0ddd2123b30296d3763d522feabe2ff566dc3739
c2
session_key: e325c5feaac94047a00f1ef4671571ec59689672dc273da5f53b74c5
0afa01eb424e220564bab79cad9a0602b84fcec2d691c5787c775a86cb84ea061a2e0
98c
~~~

## OPAQUE-3DH Test Vector 19

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: bb570818efa0314faa4efe34231e858ebadf6171f10aefa228380c72ab
748ec16f0994f35e512e0de3419f61093e26b9fe4e64b10f5689a6b957fab89da8eb8
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0acaa52cfdbbeecc0398c26f673f744b51dba8d106c46608a6c16
f0fe6171f4f
masking_nonce: 4253c5b4c6d9241b94ed4733f49f78f7955ab5abfba8604271742d
79f6e081f6
server_private_key: 00deb3fb5eef3871cfaef0953ac3482c88f2bb4849b6ac355
3c3609aa005b2cb37316964371a39548566c5e4e4dfbfbe5faca38a62651e9a519143
d04ac366bd3097
server_public_key: 0200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 7c99a24e361db1381c0fbd1f18d4aa927e64ae88681926c17d661ff
2c92c84ae
client_nonce: 171062694b99e4088b7e6694300fbfb0b6ac5e01be86e17fe22563d
80517191d
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
oprf_key: 01eaadc37ccb0d4e5782f8b41bdb754ef563ad188f308b56781213723da
32dfc5c8a2e6183f71884afcda0f32e01909cd5066a2e7b97f8e968f1846efc2c38fb
a3f9
~~~

### Intermediate Values

~~~
client_public_key: 0201462fd934d0e58bd9705b269768f8c2c9e8ce2869367bc1
a756000a58c2a152b9fddeb8683c77830dfe3c787da9c56f22260177064da7bc1bbf6
2a87c7954c83f37
auth_key: 8d1ad8d4b8e32919e5a886e454cc1816c6dc41cc6f6bf23f8f05823cfa8
82e39e0b256bcda755d4cf53ec490229280488e589d58ee16c0cb94be39a28fe9c3c3
random_pwd: 409301dfcfdcef67c6ef6c478b9059b1d0af6ef9b1d5d799d5871feec
98d87ab316d5f0da2d220710ba9683771d883fbf2fc470b2ec0a8b7f549cbd4e51416
fc
envelope: 0acaa52cfdbbeecc0398c26f673f744b51dba8d106c46608a6c16f0fe61
71f4f7fa8b29ef090df5cbd3cee1bbf75e8083fde5cc9c4ee3ac80b4ec177ca20e9da
e1ffcab7f7d135874b5bcd2d98161cd6fbc1e061539ba6d8a132a598a9c9a8e7
handshake_secret: 081749c2beb4ac011887f96e7a3e80fb441d866eedcac0436ce
034c3fc3df81a3d902d72396244a365641bf70c8293660fe27d9879b165fc36af0dfa
8d8d1bf0
handshake_encrypt_key: 6a955d21c53ed84f8f5d8a429d1d36b44148d6bbb39048
1ab0d62bb3f32625662b1920d3bbbc0aa5139631eae4abc5c69408a8da9be12998460
021159983d886
server_mac_key: dc3b003d8dfd8677d18a1dc6ff0a325797b017b0f87bdd657e6c8
95c5359b63b3f296960fd05de5b8892f19220d1fb3616c64ff75c1e5b0af8ae7748c4
462b86
client_mac_key: 3159eafbaedb940c5bcb03e07685c59bc512b91925c5df07f39ba
1988f915f6b26ccad16b7303d1a457dcd283b8676e5245969a13428d32540609be54f
451414
~~~

### Output Values

~~~
registration_request: 0301fca4ee81d22c8e8cab4cd5e1724bae3cede81109f61
7910beaee9771549cf0090692d4342f0045a99a0707e09e38838e611a3f19c81bba90
12ad6c67ba55f40b1a
registration_response: 0200e0f5b31ef40c9ccea0d7afd3593dcaeb9270306b14
1a59e50fc63fcbae566186fe6149dcd7c54d8d27577b71ce7fdace1344335e7c8d573
c315a78ee1d39c735300200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
registration_upload: 0201462fd934d0e58bd9705b269768f8c2c9e8ce2869367b
c1a756000a58c2a152b9fddeb8683c77830dfe3c787da9c56f22260177064da7bc1bb
f62a87c7954c83f3740cc8660cb04781249fd79be6651b311ff0a06d3f273b3516e54
656f279c11d723fd863256431747cc6f7e1a309313da600d591c6af1a6869d8115fb0
2ef2cc90acaa52cfdbbeecc0398c26f673f744b51dba8d106c46608a6c16f0fe6171f
4f7fa8b29ef090df5cbd3cee1bbf75e8083fde5cc9c4ee3ac80b4ec177ca20e9dae1f
fcab7f7d135874b5bcd2d98161cd6fbc1e061539ba6d8a132a598a9c9a8e7
KE1: 020197ca02b425dfcae9aafd4608362a1dedd8998e6cf906191b4d888db30de6
dbbd22fb3a1bf310cc09f781d9c6fa0bf1f1e9a79c09eaf0df596801cb9a1030f9d2c
f171062694b99e4088b7e6694300fbfb0b6ac5e01be86e17fe22563d80517191d0009
68656c6c6f20626f6202018f831d92dd0355becccd11cc3904ddae5edc18d6e357ae4
3a7dc3459335316f842771994b3b411da7ad3c8911c806b322a9fad184e8b5586926b
e76313b87f3d9d
KE2: 0200a72979541e02127976609b78f1608fad87cac86d354ed3d4bbe82d91dace
9c179842889bc95fb5a20edca165f069eff2f3c22de7822a2dbe9743bb6d71ad8a967
34253c5b4c6d9241b94ed4733f49f78f7955ab5abfba8604271742d79f6e081f65f4d
f52881e0c2e033838c0873805c522cf395e8bb32217a232016bb95a7720aea8ab69ca
e0e867e04e08d43f29813a77f2875edc5502956f3f957098393880851a8665e823adf
16e3ccace58729ddbb09e1428496e194011e3cf04b1a8ae19c0544ea32908fd468078
559a7c11f41f23557af7d18c68957c189e52f17270de5a5598ea5577d9f3d2ceaf227
194457f99e5216b571e76e98ccb97ced7cc55a10e2b59c7c99a24e361db1381c0fbd1
f18d4aa927e64ae88681926c17d661ff2c92c84ae0300f8b6a63f05a1a6f6e3c856d5
12860d5700cb3ad37bc1dbf4ecfc4c77c3aab7bb6576f70be7b460143e577d0240952
4ef5fd5e82a85fec43cc2d66adc312fb27a1c000f35e2bf5d71d0d52c5f5af63c28db
4527d27976c89b105d70e077c002e0874e2d964496dd45fe8ccaa3afa1c218d80597c
fede110cfde1e2700a48ea6dd8203eafdd64a31434f8ebc4ae4dcd91393c3
KE3: 7bd6a517627d8e6e00574fe7a580d5dc8e739677e31c8f7e20d391e954b6e1ff
a88720e0e18a58b6ae98265754d5bc26bcc4192275eed73e63c8ee7637e5e4b7
export_key: 8736dc032f7b1f4adabea5b80112b1c9811642555c31c981a4a4f22a9
22fc87b30eb4bd55a14c90c641a57560626867b3872035b0e091ec54e85f6da32b5de
8c
session_key: 4899baefba121d00147c6b22119daf9764351d63e522d17b0ef70527
3e66114959a03b6d67196b387eac018ca323470210a02489bb1952d2f48d6d238f575
513
~~~

## OPAQUE-3DH Test Vector 20

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 19c407e43e6530d69c8b4d17c130c73cca97e06c7c49fc260b86b49591
4b1d062d7310336c3c0f9a4aea20c32320ce4ee1c822971521274983a504351436139
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 75151367a387ef7a2b9db47d5a798127220e874ecdc3eaa650ba9
227f1a31384
masking_nonce: 17e445558005c495a7e4bcbbb6484d5fa71c3d7e77bcaeec9357ab
88dda23bc1
server_private_key: 012bc7471bdb9fa3e113b809a86dcc379b782052bce3fc9f9
62d373217b0c266b1e0932c7a0727030de9ce81d360d97fa94f7ca377aa6969e1748c
9f8b0a3f230c50
server_public_key: 0200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b6ca115c39de7a83c73dbac4565cd39fe94a5df497692e00ccc749c
ba7c7cb0c
client_nonce: 7e0842d07393fe80cf1bb16de3a162b04c49032e32b3f689863afad
3905cecc7
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
oprf_key: 006faae0d55ec6496ec4b355439559ea028274977e5a9beae66540a2592
63786fb6e22bf3a4d61b0382f05727eb60c3a78a90f7d3c1816de34575c44d519e7d9
209b
~~~

### Intermediate Values

~~~
client_public_key: 03015551a0c84d565efa67945e7a1b66b9a24423c7eca093b3
04576e72f4e34f2c54a67229fd3b304ab9d4735cb6b6ddfec734409acbf3debbc6d94
4a5b9594a1c4c3b
auth_key: 55ca1a64c6c4fa692beaae2b9c06d62d2d66e2aed74feac39178e85bd2c
c5ec60ed26421a2162dd357e36d31ff2e717e99b2fd04643d45cefeff5edca9e9e975
random_pwd: 0b62b7402c04df2417b117fa088ca4c67d6cfecbe9896f439b6a3a2d5
9b6b4fd8c0f2d71e9ce0f4c3a2a8f38c436c180c1cb8d80214d5f68ecf71eecaf3a4f
78
envelope: 75151367a387ef7a2b9db47d5a798127220e874ecdc3eaa650ba9227f1a
313845c37bb477aae14a278e1f26b194d638b629e4031eb7d9012ee3ec22f9d9d9841
0d8e2bad50aa35c28a105beeb99e85c8933d90678fca02bcbcf4b3d1300f2e9c
handshake_secret: 44bdfb286223899ef0491ae9f60b2df0c44d061b4fbc5bd69a1
4014eb5d3d878af785043f76f64383f702171d7f564daaae833153bc93535fbfc5e69
12ea477a
handshake_encrypt_key: 6cc1cf167542c6d6bcc926cfa593cb45797207824ccd59
9e47b0f9e1ff99719f726d0c2fc420474f3f726ce9b483ded7c09a6867cb110806fc5
33e4ecf17f6f3
server_mac_key: 47194a31a8d82e8c8b1e7d6de7bf4e1295851e95e457da8f4066f
1a2185e246119c0784d082a2b33d8a0b884c2c63d48532029ebb743733e277be70d9f
93b150
client_mac_key: 0c20f3b7ac680310463b3d8312acb35ee34a29b88348c41acd84b
9064ec28a2f1f533651ff0a2044a34dd02fe62493b9a6a255786004b18f3421a2df95
0bc1bd
~~~

### Output Values

~~~
registration_request: 020178d37274cd1fa2512ca1d238613727201561218673a
d3fb6a391cf6dbe028dd8d953f0e36516eec3c69ab0293b19769074c4b16ca36d06ca
2765543e694fd8a2f5
registration_response: 0300375a48fafcaebf21fc1b8a455602a1a574219aba65
0e04a94a4235d2fd4262bfe9a16cdbd3adade1126491c13addf62308003cd28bd4972
3ee54e9c26ac098193b0200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
registration_upload: 03015551a0c84d565efa67945e7a1b66b9a24423c7eca093
b304576e72f4e34f2c54a67229fd3b304ab9d4735cb6b6ddfec734409acbf3debbc6d
944a5b9594a1c4c3b92ec18b1af071ba9eb7b6c8c322a43161d79b8d20ddfede0f013
7c8613cee032f104adf1b57fb4c733822eec8db6d63b88a416d4ad94c5719cded3767
73cb37875151367a387ef7a2b9db47d5a798127220e874ecdc3eaa650ba9227f1a313
845c37bb477aae14a278e1f26b194d638b629e4031eb7d9012ee3ec22f9d9d98410d8
e2bad50aa35c28a105beeb99e85c8933d90678fca02bcbcf4b3d1300f2e9c
KE1: 030041daee06de56612bc011e3fc1b5b1c5eb334b6cc0cd587b5c6fd9f94271f
dade91de48e730d2499eefc313038c54e3ff0326da0afd4f5defd0e4f88eb9fe6dde4
f7e0842d07393fe80cf1bb16de3a162b04c49032e32b3f689863afad3905cecc70009
68656c6c6f20626f620301125c341b183c9ed98ad735039a5aeb7a9c99c6a90eb2dbd
5a02ffa442393c1de1a7f11ef5a7395a3881525c7fb8674d74d842f0cbece5069f98e
2528ec903ba7e4
KE2: 02019b27ae9ca87edc2481dbeb59907452d6d317d3b9affd50b7690698145a8a
0eb27ce0979edd431eac8583a127f49a0b908b9fee349c894a538bb0b0cbb157394fe
a17e445558005c495a7e4bcbbb6484d5fa71c3d7e77bcaeec9357ab88dda23bc16c43
4781e9c7af59ec127a5372989c9c082cc1c812faa6bfaec5311256ddb0164c473cea9
6bb8224fe1c772821fac2cd290eed967b77efe07b52bca4eda868a8ff9eb845fd5c92
43900f82ccbcc5b4c243855894f7df50f425e6ce8ab515c1acfbd7233ac0aa75da3ba
cee07d006956d540a36387634ecfbfc1081afc4d10f7483a5ca71c87465227ab01d4b
9c6e754757e21346feec20de6223a6fd76593062ab02bcb6ca115c39de7a83c73dbac
4565cd39fe94a5df497692e00ccc749cba7c7cb0c030121f7821162fbe027849ad750
dab6227d5633a7148e1b09107d200d7fe63219f09a4e96ba8cb734b5b20941196edb4
71863e1785c22e950e3ee34c85aecc454fafb000fb14e0df67643892ed38f4d0a2eb4
1e8614977a877a9906db90563b4de74ba13671bf5489448c68dd756e413541a0b29dd
717161054f4207086f5d446549a67257ad49c1047e936cb213b20e26b1ec2
KE3: 5eb1dfdcf7b3dacfedf1b3a7e9acb6b2451b6261fd2b4df6758480e997359b0e
b47a16bd2c2689807340a25949830afcab316dab9554f189a27ff45ed737183d
export_key: c787482aefff98e2c1823e5c4099ee8439abbf9716960a4e17ef526e0
07338fab0ebd46b31c3ea11e1a0c87beec71a39aa7ffcd18473129990669b2e904b8a
54
session_key: eac72c273e341f2ea491ab2fc86318fe7b1edde424070547f81c0a77
88a8d13b60a5be931c090c30031affafa2aabd1cf1e819709c311ea6b68b4624671c4
08f
~~~

## OPAQUE-3DH Test Vector 21

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 50ae7f936969eb0e2b745e40743d1814ac738d888e244a15b45e11a77b
455b0621dec0255d7f599d7c5879162d75e15ef4c1f561d7cf6d4ec56fcc41118de13
0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 29df78d9938d1c8ea71ac25e9cee08c6528655e8039fc9b84b2eb
266fdbcf883
masking_nonce: 7dfe1f9623f8f897893e4a59e638ec4fdffe9eeec5222b979b003e
a0cf6982e5
client_private_key: 2d8cc16606d110ecf2ba00464406a0975452b63a3f27ce575
921f91146543b0a
server_private_key: 5a673fae0015e31ccb70006aa21ae18853489bcfd11c0b796
0a3b37fc3654402
server_public_key: 0c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd
9d2f936a37f14e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: eaadd446c0bb2a825cd871511a2580f949a369ef848e2f7e4a469b6
70092183d
client_nonce: 7149f9da5e311169e5fc360e6a395e9428689b9b0a70c84b5a57f64
52e8c6e87
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
oprf_key: b24704a1b34a0639674ef367e2aa067c69e59b87dd80c4d60d3e47372a5
52b05
~~~

### Intermediate Values

~~~
client_public_key: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c79
787e2df91e2371
auth_key: f8810122af45f26ab56caa58311cff2078d1efd77532e73a53fdddb8a24
96971a208494a1b7a232977386144e19058d4105c6db5ca5151bbe24a8551f179b73f
random_pwd: fdb2397c54a4ba7a0eb645be69dc66442dd1914480853dc13ac93e958
e225ab7091c4870486601def8525b0d080a11c32f271fcf33a62ad4f6943f265782df
b7
envelope: 29df78d9938d1c8ea71ac25e9cee08c6528655e8039fc9b84b2eb266fdb
cf883583c33716c7c98ae7a264e666cde4cdf260ce7dd6e42dcfc711803b5754966e5
56b5d9787bb508e5a75a37e33c775cdc5d4d2ea74efcba83bd8a1aec19045dac4e833
4497f080beaf03f30157ab863dad6336118a925d4496f2c37b4e934f830
handshake_secret: 49af45af95be00615ac85e6c14aee92932d7b72fc40e0cb2cd6
421ab5c385d2793c18519f853e44c7574e946dc9fc3d2fabc6d2a2d83b0853e15cfff
11b7aae3
handshake_encrypt_key: 61931e97e656a0e153dbde9e65c8eb447dbd43d0b8d8f1
9149af6f2c144288f276c51fca155150fc011a65ddc5bdc8a3cb86c4e35899ce34b79
8331c92ae9cd4
server_mac_key: 7abb36c3735b550148c5bbe776c4878faf9232c00559634e7d758
e47b5a7c909eceebbf69b7e92083d1409852f319864dbad2c55f1277722bfcc5d8b87
a8c88e
client_mac_key: 8f5790bb80ee7c61264c8024d64eb9836046f822a16fd5b5d53af
b16ca9aa75fdb01d856627e6d5a6cf9825774d7e2ca4571af531e3aae820b359d0304
8bb810
~~~

### Output Values

~~~
registration_request: ac2882512f36bc4d5914964e782418271371fa9bd16878a
5fb6c3b6d29c54422
registration_response: 62e8fbf751d25d8a48a9b194ffec4d57739e46c5bb6e9a
1e6faed5b17172be780c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd9
d2f936a37f14e
registration_upload: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c
79787e2df91e23715f75276ec7eeb42771c95f010e60c97359fb739ad4a90e2baf942
601eee6909306f011610c12cefd47c6ce56ccd51627212b7ac6c20ce2adf9b00d1d40
e9353029df78d9938d1c8ea71ac25e9cee08c6528655e8039fc9b84b2eb266fdbcf88
3583c33716c7c98ae7a264e666cde4cdf260ce7dd6e42dcfc711803b5754966e556b5
d9787bb508e5a75a37e33c775cdc5d4d2ea74efcba83bd8a1aec19045dac4e8334497
f080beaf03f30157ab863dad6336118a925d4496f2c37b4e934f830
KE1: ecb46e5c31b4044876ccb2a689efc82231d2995561841156db449c71637d145f
7149f9da5e311169e5fc360e6a395e9428689b9b0a70c84b5a57f6452e8c6e8700096
8656c6c6f20626f629698728bd0febdc164c410a6738962b955c08a36b25c89058c38
d4575592c12d
KE2: c2388704cd9002cac07e7ccab17ac13a5dbdb8889d55e70e9645ba6fe335fa7f
7dfe1f9623f8f897893e4a59e638ec4fdffe9eeec5222b979b003ea0cf6982e54a69d
1d6694d57e42cf4690910342d53a43fee96b38ee83b080e30876d40aa9c83b4630fa0
2b9d66cabf0af458aa91e69754afbdd94c3df55b1cea9f0a1949ebaee1ca41c8d51aa
7ecab8147a57cd6f8e8af11019281a135a14b4166a20acaf6d4224b36200eff589221
3aef96f00affa66c2f83a2aa6db03b4e3a19b10f8ad1f6bf9768ef749ad19e3bb09c3
f6f9fc4fa562394967475e18569135d0007a8baeaadd446c0bb2a825cd871511a2580
f949a369ef848e2f7e4a469b670092183d34be8693c06fc0168040b3321043f40ad79
648211e6604f883bdf23abb045813000fd53a2712069408937bd3eded4ab32707bb31
6d6068c34aecfba104bbd67efe3b2a79db3eadbf3032b9e8c149fc9d90eb36ca3c549
54da48eae6507d4c65ba8ccac6c35a7b26adf87c3533c4c243897
KE3: 12f31db6d0d02df96664148e92d44e80761e5f50300a08312d8d768cb9d51171
1d00bf1368e3f7df003efada0867b38c1fba88d2086486a7ea6a8ed034ade397
export_key: 40d5d84b040ce9986bc8b9822d03cacc55e8f20d9b375a2878ecc8b09
0d5697b9d6968e0d7561440f86b6afc82104c392b42b297aef3b409cbf14e0bdbf9bb
8a
session_key: dda604f0ad7262ec2f62f79199e6970e405edb66c1932a12435f119f
4c5155e0a0f8a63cf0d4b40fcf33b1e3749256d281a4983064d1d497e0af521afdfa5
3dd
~~~

## OPAQUE-3DH Test Vector 22

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 3d75331c5060868cd0bac17772b9e9e8e7a31f229eb6318184f53400a1
331cfca9c40a1a877712aa8adb34271ea3aacc70c928608a475acc52799de97ea1793
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: eddf5422823d76dcca80bc45402a812bf44b3cfc323be993d9458
0b27471ecac
masking_nonce: e187715f0d81ba0cde2794c3bf49430c9f9d54e85975c6b08d06e3
a58f1da8be
client_private_key: 10b3066e47db372d6cd714fd308d056c349df63a477498b28
ad3f0e75ba47b0e
server_private_key: b69bfaa8582bc1d07933c6354dace6674e72fb420b9c40cef
3a5fed717de1d03
server_public_key: 928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9
f4389fecd57073
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 4c3527bdb9d16d992698658a8672cc0bcde16ce53776d44a966eda7
5933f01e4
client_nonce: 2db20cef5dd352ee5651db0d43ac3008fdca1da0cac16bb464cf6b7
4f202600c
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
oprf_key: db026f2b8dc13d3945641a25a534faf2b05e545f6c8c62c4402ff9c606a
6fd0d
~~~

### Intermediate Values

~~~
client_public_key: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae5b
a927c3c6a9af07
auth_key: 46e5dd8b62b4cbb8f4a497a27cc2ff955689b6dc90c1c6b78387993a696
23a4987889824656e236ca67fff2ac47cc717c483aba623218289411bc17b09f54f99
random_pwd: c917ddd6fec8f13bc25ae942a27c119f2aedb9a9c3c098d32e7f1ad18
aa76f3dbfe39f1305609525bdea89e240f4055f08d5c8bbc6a13abab028bb150c03fc
25
envelope: eddf5422823d76dcca80bc45402a812bf44b3cfc323be993d94580b2747
1ecacc7f8fc351418062ce343d15f5862a18a473a9815cfb54e2b873f4fc63e528160
9694823a4ccf7601ea4490ab022e846ebb63ca7a55bf31b5acac74f8670ce0c685ced
3cf6b87ad0727ada68db31102ee680a166d740b336ddd25b22f31ee1d49
handshake_secret: c7d72cf681832ef089ed68e3096bf8b6c5cb2293ed2e3c3f155
eb10f9d1eaeef837cb8108fb1469515d53d4ceff225a0e988f8752724b9a1be35d943
eacb0288
handshake_encrypt_key: 494774f40dec4318ec30f11091f546c673e94b47d67b13
b0be4dd98594791a5d0f70839f07d4baee04598fe0137f44c29dbad6c45fd3af52992
a62eeff477bce
server_mac_key: 1e592c635637dbf162430f7d4ecf491429356ef3a64765b441bd8
709fa624ab2b6bb18d7cc1ffa0026c39b410b0e3f73f166cf8159ee6a36bcce08592a
a1fe5c
client_mac_key: a8ef09307371b27d3177a2ffad72fb8db05ca0fcd62dd6b8b15aa
654b9d875acceba0836341cc814ffcecec01b3082989b1742f3ccdaf6da08cbb5934f
a7d977
~~~

### Output Values

~~~
registration_request: 34fb6ba29e60511d9ce2d2a644a58b8b34af6516cc54f20
f7ff605e8134c1213
registration_response: 20b3941efe426f8c49884d951be489d848273688dc76a8
3ea42f743165fe4753928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9f
4389fecd57073
registration_upload: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae
5ba927c3c6a9af07a192377aaae1c828867cbfe56dbce3118968a05ad664c080ac52f
4b41c820b98b647af5e2810d2e0262892ccffec0be1a59d7c192b9c09c17fec139148
15bc59eddf5422823d76dcca80bc45402a812bf44b3cfc323be993d94580b27471eca
cc7f8fc351418062ce343d15f5862a18a473a9815cfb54e2b873f4fc63e5281609694
823a4ccf7601ea4490ab022e846ebb63ca7a55bf31b5acac74f8670ce0c685ced3cf6
b87ad0727ada68db31102ee680a166d740b336ddd25b22f31ee1d49
KE1: 9e642c6da6a475f89078708431aaa4e04d96097f7778b0de577bf4d08496ae5d
2db20cef5dd352ee5651db0d43ac3008fdca1da0cac16bb464cf6b74f202600c00096
8656c6c6f20626f6284a786fae7664759a8bae0cbe9065cd80b70cbf600efc695654c
93e356735c66
KE2: 8a0df418a58feec3080cbd5cd896107d8c588285e09f8a8327398c34382e057b
e187715f0d81ba0cde2794c3bf49430c9f9d54e85975c6b08d06e3a58f1da8be3969e
629ccd984d408fac6690758c680a456db21c52c197a918f4b005cc9ff5a4dbc23f336
17ff48058d8db0680c00bfa81106f4080c4b4ff869a2ebea5f212c242b50afcde5b76
604896a7cb445ece15134dd5937bf3b16a101d15f66d6fa552e82c0c9f3d783cb1ac4
f2d18463e3d51b14ad7612cf7ec0229d4b3d4703b447add471647e79315e66994aa0d
1c084170d959ec72c71fe8d6975de52a8b2aa8f4c3527bdb9d16d992698658a8672cc
0bcde16ce53776d44a966eda75933f01e45ef3502cc40e7ba5006845c131b661ba6eb
d0e6994b6f526e3b7cc108635912f000f91d4a79950385e0a78d77201ec089031e7b2
160413de9f408b7ba0a8a25adf4ac2c35ba1766c663834641a026df1c005e4e00d620
c28d1b64e0e7cb9f71d9cb8b85be6d53a426f0f6a987d814b86f4
KE3: 819110b7202e6e63ee3878ae340ff55e8922f6f59292de3ee3a3a7db79a19608
c5a090eae86e63b44e1a007d5c6eec13ec70fe1382547e9f42170b02fd355014
export_key: 57dab347b58f14a7ac8f0b54faf3fe6891eaceb2775df199b157ffe26
7fcf44b4bca029c5a0d70a14db3fc71d5996d6226d95e30c893d4da5979d7d6759fa4
5a
session_key: d235cbd956f00e0ad8dda35e3bbbb2a6e2f943155a482cc58c5251f3
db8af678476083cfa6977a2e73d4d24b9983a1f11db271373cdf5cbfb2c62eb814a39
607
~~~

## OPAQUE-3DH Test Vector 23

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 1efd7cb823a75cf8d3aa89e8c74698406f53edf97a509b9a14224400be
1d280889c33f584ca7f9eba83c0d769830baa54765aaae328c202a4ee5f0c16c47961
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 92f64a37d7380f838392d68566603521c2114c082733cd4e42429
a5033352047
masking_nonce: e4f7876c1a03f800742a9db1646d84dd650534d85c30be0e8e09a4
bcec4f594c
client_private_key: fee07a49ab54150e525557deebd0a14a8ea81876fdbbf94da
f03d5a2e3cc8306
server_private_key: ad52e51fb993d6053fd960279d81b6111a367246256f87159
8aaa2367eb1770d
server_public_key: c26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d
9d5eda7943266e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 01febe6ded3f1069ce1920b0713401e5c478f2a50dc85c7b6cf7678
50693914c
client_nonce: c50e098646ec9782c70048635a5f60dae8ca37df643e861631c51af
811012805
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
oprf_key: 3064be0811d201eef06efd33760a8f722bc270eca58b9ced8a7d9a2dd31
2f60b
~~~

### Intermediate Values

~~~
client_public_key: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f21f
51945a636d180d
auth_key: 24ef48bd4a2b36f3bcfd545558b8d3c41288ffaf52e16fbc53b9c7d7945
755cc9a246c19620ca6d2614dbbee25738c7baedf48c0a28db2f081257a90d417b668
random_pwd: 6ae99103a9fa7b6f304ab991ce2ad045549e69c67a42bbf5cd5a37990
d7e903e2ea3ec5231ba4c05afabd75dc40e3aefc2bb0ddfb357788108160f44d9df13
60
envelope: 92f64a37d7380f838392d68566603521c2114c082733cd4e42429a50333
520472375e16d89da268ee7141afeb32d6ed2def0a93ff7f445db96d9f7fbcee6da3d
bfa5daef068138b6763bebc4b8c7c8a9de24463ce76af0d172eea4cd162146e5a92a3
22a873bfcc15e39873d8d4204f2d8af8216d28d9e12c8b9487b4593af42
handshake_secret: 0d301f370a6fb9c9408662fc48331c4ed51ec5eedc2db05607b
b4a15c2cc56f7a9a9f5a8a7eae03ba9b3b2a13d713bf846e0f4a0b9a843f52c9acfd3
658535d4
handshake_encrypt_key: 81ac2225be6ed57d49de904bfa23bcf490fa2f55a43618
d92dd7f3869551d65a80af8f2adf73cd44a5ae12bffb4c2a54ff5f8c1d1ffbcee2ae0
d4e44e5644294
server_mac_key: 5443dd087f0188c2934974f29123dbb25a05608666b601ae80ef3
7319e7b935b4be1747b1dbbc1570919c42a4b8972fc408f767921dea69ee027e3c5fb
b8273e
client_mac_key: 1d6159a4859653e6c1c12c231cd93305b00ba6482af56d6cbdec6
e8a52f5911279e8bd996c310a1439cc03e34b4cbeb5af0987fc482a1f518063d02a88
f64a57
~~~

### Output Values

~~~
registration_request: b02294ae456aa0e055e49a09a3a4cd7176d9b34778a4dd9
493eaace4883c0016
registration_response: b862008bc987bb9fa19a936574ae7b53ed83d2697f476d
1bc10ebc8102a53928c26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d9
d5eda7943266e
registration_upload: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f2
1f51945a636d180d0ba5aec13eaa9bcca368747d3075c9f9446154775fb21a30a3bfd
747bc02e4a82576467360fac7213ede0e7319b0ea65308af7ba4ee8c67120dafd2ef8
74e84b92f64a37d7380f838392d68566603521c2114c082733cd4e42429a503335204
72375e16d89da268ee7141afeb32d6ed2def0a93ff7f445db96d9f7fbcee6da3dbfa5
daef068138b6763bebc4b8c7c8a9de24463ce76af0d172eea4cd162146e5a92a322a8
73bfcc15e39873d8d4204f2d8af8216d28d9e12c8b9487b4593af42
KE1: 7405ec93c531676eb9437f46cf3c3dbe9346fa83dda34a37da03d693a90e9f7e
c50e098646ec9782c70048635a5f60dae8ca37df643e861631c51af81101280500096
8656c6c6f20626f62c2b0aee89ec05d28e6f9638d2e056f7cb4bfb8b4d032239d3e4a
7960d7479e7c
KE2: 4a38dc2ba076fdc87edf69146d7ec5d4139c8614785868024ff7d07672831604
e4f7876c1a03f800742a9db1646d84dd650534d85c30be0e8e09a4bcec4f594cb145b
cb71f7e86e0e5562ceaf033b31ac5e4ee22f148a9283574c70e198a812271db20f67d
240b0ad839c64b4ff44c232f4baa1a6adb1f66deaa2fc3e0c6e9f926562e015f4658b
7546cb56198aa56c4f4f5c0f47bd66cca787bad83d56bcc0f7dfda69e1297f6d2dd06
9527e8f1a79f23a02cb9f4b4ad2240f7493a219088ceaf6e8d470403e570f891f1719
502396774ada682606fe4bc244f2012bbdf867001febe6ded3f1069ce1920b0713401
e5c478f2a50dc85c7b6cf767850693914c16041ea53924cafd460331043cb3ec0c7f1
7d6c246499b9c638118a606071e61000fb9e1a3ce5418063bc688d970f583a218c070
63541a72744646cdf501299102e65959c5e6532705b16e59babd682e8cefc1e849a34
3347421c9b2d8b2b26ae4e25a87d918fec7b799e85670dcd6d0b4
KE3: 113a04e89fd053f9281599851ae5d3667d51491236f4fefb189dd295ca464ff0
9abe7da9f4c34cab6ab37066173200a968117b8cd7ead80cdf4d1cab5590965b
export_key: 3a5162ee0bc2c3d47edb34d90aa5665d5fca992d314079e592a0acca1
3a0ca80bf47dd9f9421502df597f0387bfd7eb1fdeaeafef4723f0992e43b6e7da123
53
session_key: b5c8906d8b8e355e347d50ef6b2927d77b12bcddd6eb0037e05030c3
3a203801d655b1346f41b1d4942e07913355a10c8825a6eb51d34a55101247d21974c
29b
~~~

## OPAQUE-3DH Test Vector 24

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 92d551d49c7511d6ea9997cc23a1bfbd14a7de6079ef89660910d7a4d2
80103fcce0f42dfd3b3952f1c2e6d7d82e7ce9da52afe74dc03e34251cf167e6a1029
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 04cccaeee283652f7a9c04bd4bdc20d7ea82d8a674e2575bc1623
d4211fb2ff8
masking_nonce: a2d2a75cec89ae7726b19cb6ad37811038a02c8f4a815e4bbbead2
8cba527c3b
client_private_key: 75da35392023fcbfaa87fcf458b0344248870cd73a38e3fcc
d00a994e1a09e0e
server_private_key: a7f4d763822fcc14bb91a7b36b0a6d30f1ae8c3ca1c36505a
02610dbec29260f
server_public_key: 9023317b443158b83d4f4b49674209ad390595bd29758f5e86
b1fb217190e964
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 810c6baf22758e0d1a9acd1e60392a3622ad8b15e3b97b05608e4db
23bc1941e
client_nonce: dd5bfc352d151d647e0d47b2d40e2f77c1da80f9363c9fe9fb64d7d
f7bf7de55
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
oprf_key: d5382d7ac935e7a10233b5057ef3b148aa87d7af77cdb9c8bafee183d00
1460f
~~~

### Intermediate Values

~~~
client_public_key: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def633
28bec3a4f21146
auth_key: ddf68453826bbb13e7a826abc5cc2d251d08b058879a7b8b5771c19c291
e6c6bb14b7e8f9377bdc1d327526f6383220438052c394ab2be5aa57c795f6731313b
random_pwd: ee251172c15bf3d8ef75e9f00dbf5d3f9963014c7dc46d687358c1bd0
f3d6c16aeff7c2b9a16cdb0a4d043b068a594041bc15977706965383d2c6befaa4951
7f
envelope: 04cccaeee283652f7a9c04bd4bdc20d7ea82d8a674e2575bc1623d4211f
b2ff848c2877f7689e6dfe8fbe7b386cf0b694323594f8718617383434395744c40c3
7f57b90b70e5cccc25ed6e97a23bdd46ffd5ce5b6a03737e9641791256a8939a6e865
2699f53d03824d8d643a7822a350da54d9dd370daf1f79f8231441800b9
handshake_secret: 884b0b45a7c16b4075d488b899a2d8e261ff2e9f1e4788b61a3
114c8c43acfa54b3484d2cd6615e7bc098bc22bc2fb28f95f507cd2d11cd003092d85
80bb6c41
handshake_encrypt_key: a1d74beb8a34bca91ca8ee513293324c08a74a92e6a60b
16969046f585030ade282f3c3dbd845b5a2fb803d178b8ff3b4915261e9efcfe6c555
0085be3e63dbb
server_mac_key: 60cde9927fd06a2b6e277fcf4577db447e9c20579273b3aa8bd52
5e58cc3a6340c4c3c4afe24e3ec5dbc57d22f38fa0687bbe3de26ce04a7c79e1520b2
b3f687
client_mac_key: 9dbcaa64912ebd7b63324364ed370ac8c5acb006d219c2c97d9bc
1656bc7ddef8501a12628dffa8bcf34cb1719a5cfeb5c9fe61f9e09d96f9f995837d0
b3a7e8
~~~

### Output Values

~~~
registration_request: 6a525dc9419e2d0261fbcd6033f9d500503a27027a48d91
27ca1209e01690d29
registration_response: 64425cb833d1f0373fe30c5441fc354e2cd16bbfe4c676
c42d6669fdba2932289023317b443158b83d4f4b49674209ad390595bd29758f5e86b
1fb217190e964
registration_upload: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def6
3328bec3a4f21146161364b0365404f08ed96fe7ed1612d664bd4ca770de3e7593dcf
4781ca2880b87c6525ae7bad642817a0d52f7d1645ea891188a662e91e2e48dd86f6d
7a757404cccaeee283652f7a9c04bd4bdc20d7ea82d8a674e2575bc1623d4211fb2ff
848c2877f7689e6dfe8fbe7b386cf0b694323594f8718617383434395744c40c37f57
b90b70e5cccc25ed6e97a23bdd46ffd5ce5b6a03737e9641791256a8939a6e8652699
f53d03824d8d643a7822a350da54d9dd370daf1f79f8231441800b9
KE1: d6a8af82258885688aada828f32e04463c3739c7da0e63c5246711520dc16e37
dd5bfc352d151d647e0d47b2d40e2f77c1da80f9363c9fe9fb64d7df7bf7de5500096
8656c6c6f20626f622c8ffcf1bbc02dab15df7834ebdf85841395f07c8e7317285ba8
574b6eee3910
KE2: ec47487410012b3d09529690b909a3edd402fba9c7a39bce0c77abc0f6f8fd67
a2d2a75cec89ae7726b19cb6ad37811038a02c8f4a815e4bbbead28cba527c3b0f646
77cef68aa031ad63a19d26483ff24b8948cbf56dbc2734c45db39c1debafcff009e2f
01ffd38cd720d5ca83a518e8b4eae629179b2437e4e99671111826cf95997979712c4
dba6454d942a3a76bbcc6777f37d769a48f23d519eb4704e7754aaccb7582babf34a9
81ce0206b48f7c757eb228e54dde1a4424a070be84ae02e6e9f871018c2732ecf0162
2839b1b723b9fce40696fa952477751b415019a810c6baf22758e0d1a9acd1e60392a
3622ad8b15e3b97b05608e4db23bc1941e58a6c4fdb4b3da03df2e5b1f6ce1549402e
209712e5bf9d31efbdb82c00eef5c000f0a35a2f429e81a49a083a6621ecf6ef1d7c2
28981c02236aac46d04e36f7452857e383472e6a60c2a32e9647a6edd6bcff028fe23
76ee5b21eb8fb165760cdbbdf14047f94c6104565a4a848d0aeb7
KE3: d6f19a7eccb4b2c73f59f459617a7473546915cb51b67ae2b1ed7045775bdf40
f78d09ede2a2deec385b3cf8601447288f4daa71811f35947cef2ac3f36d96fb
export_key: 8967c53ae5cb626022a24d594e3e3babe2680e84d9491645f9e933750
fd136400255185baaa92acab382370e1d3da32bfab92917394c2b2c5f37883348fccf
73
session_key: d4b8b8067ba6bf86dc4ff6789cffbf0a953c11aaaf595de22746f2d6
784a96a48b634f3c94e489587a02f9225be8b0a5db9314622e04f2e5faeaabec84b64
f71
~~~

## OPAQUE-3DH Test Vector 25

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 4b438e1094eee7ef2c36061757b03d70630508d5049a693bd3a29913af
4cf036e65d87cb7a1a2e3059458c6d5ec279b9da4f022ba9f8bb9961ea579a5371918
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: f20ee238462e21aad594988a2905155cf294251641c6671e03ed4
b2c9b5d69d4
masking_nonce: 388b952906d7d974d0e89711684402ba619882164f035b7a6ac439
acff6020f3
client_private_key: f4ff0c84bacb98d40ef1b543bdec5009b450e4fea1c8aeefa
6022540fde3cac20b940bc918b0a16389fe160a1e6ae09a48d235acaa1d3735
server_private_key: a762ac7f6fc2f643032abc43fbb2ad4e6e012f48d106d10ed
ddb5b69d9e36d59b08eaa6830c6bfe473f50ccfb5c033b97885214dfe740e35
server_public_key: fcbb8bbe6f857883e38783acf58dcd6de556530055a2353c4e
584320e0916d28b8278212bd6405864ae84a5cd2508f09ea1185f82c9ba518
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 5cc1889a1f31cee6fb5baa94bf72601aaf4c16141365f73222a7d2d
86896fcb6
client_nonce: 286bf277adfadd706738bbfd2b2fa7ec56163be5bfa65b7b4171c54
16dc74ec4
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
oprf_key: 939ad0b341fedb343e3917261a9295e23516cf603cfea3910547d7fd01e
a121aa637f58b0bcbcea4ec6906e6ff3233dd18646d844f56db20
~~~

### Intermediate Values

~~~
client_public_key: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9fb6
86b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aa
auth_key: fd29c74ca334121161afd535afae7f04b01d2970a9d7b30efe490988017
a05d68f9930e971ab613eda187a42e3de7dcf5fbbf79939d7c9ba7a6393a63223c028
random_pwd: f9bcbb9b85a120edabe5e587eaf6f643ee5f890b965716fd44cd559fb
3e0c30eea2ab784ca0c9073e43dce8f0def739c2b106de8a8789154b57e829845fee5
a1
envelope: f20ee238462e21aad594988a2905155cf294251641c6671e03ed4b2c9b5
d69d4f640acbf7e4b10b95ea5487e2c6eca4d74160cfc5b07329dfc8bdc2911ba8b78
cf2851d481964bd85537c262d71178321816be900f58b9412b3b68158578e1d9eecf7
abe16cdd341132d863631316a48e4022a42f4320f33f5f1c4fd89e7af2d27dc425165
ab85f5635a47329b0e2072c6e8b9b3fb5a1243
handshake_secret: 2a9d31d93f3478448dbb5c850474fba1158a6557b9d2b0f76a7
da86e87a2113fe8a3b4a237a3d802bbdcc68bfa4618bdb4f5b2ef246c143e3aa73304
1028101c
handshake_encrypt_key: eb1d3ef844dd8b3605e684201b9fda3cc41079a6e7a567
11cf50e776e7935a99cc5cb26d983c04f0f77b169dc6cfb404087ae5cb75ab0d61da2
b4fc605fb96c5
server_mac_key: f578efa8daaa8c4036fc98b7b2fa45e1eb33fb23775c8e125c04e
d29d6f3f30dcc1cca262f1ce830579d9ae3b77bb775d0010b7147f5b16ef4ab4200a3
0380e5
client_mac_key: 900c6087a346357386f1ff76581cbcca1852feca658bfa8cb2a6a
e6d0db779ecab6603a5932c4f20a85e04c63ad8128d71e95dcb3255e8f0aaa10fd55c
973a66
~~~

### Output Values

~~~
registration_request: 56eba0e757af33e634107f2da32fbe987af1d37bfec1918
a2d42ed2f6b3714bdc1dd190ed6dc6da310536bb748cad363e76ad2fb1b05f1c3
registration_response: 769132f89b52be1efd60914e33299e9dcfc08ae8e83901
97e2a19ccc46edd5398e9b6f8a9d187a911dc3115e31838694e45c3c2a2d8907f2fcb
b8bbe6f857883e38783acf58dcd6de556530055a2353c4e584320e0916d28b8278212
bd6405864ae84a5cd2508f09ea1185f82c9ba518
registration_upload: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9f
b686b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aaf45cc
091ed72e6185588e40aff6aa8bbeadabe0ec71eb12a1d93122d897372c466ea3e4834
a16e5c689bf4ee6e69f9d5015396e979cf0ac57df35db2b78e6ef1f20ee238462e21a
ad594988a2905155cf294251641c6671e03ed4b2c9b5d69d4f640acbf7e4b10b95ea5
487e2c6eca4d74160cfc5b07329dfc8bdc2911ba8b78cf2851d481964bd85537c262d
71178321816be900f58b9412b3b68158578e1d9eecf7abe16cdd341132d863631316a
48e4022a42f4320f33f5f1c4fd89e7af2d27dc425165ab85f5635a47329b0e2072c6e
8b9b3fb5a1243
KE1: 16ecbe71c272b0b9cce77059395154ae766c95a7f10ad0e699aa0c773877225b
a13e0a8ace5007c53ce3631c7e7cee782a6c44cad6832e0a286bf277adfadd706738b
bfd2b2fa7ec56163be5bfa65b7b4171c5416dc74ec4000968656c6c6f20626f62d25b
52b3af68ebda6905d0db5d964660ec9ec81066ef7955559aa302e012006b1ce049556
666231483f56af9dcd1c27fdbafb4d954060091
KE2: b609216d947fb8f8e116bfddc98de812b5936a541024557c8bd5c52b7fefeb87
972263dab4af30c05b4de5e9596e9b121ae23396e72c1bb5388b952906d7d974d0e89
711684402ba619882164f035b7a6ac439acff6020f35d2ddb696c2587014e29c74250
da02f33f71745d16febf7da27ff33439eaf51989365624470f6dbca28707146385385
1ae86be6dbbe8195ad3d956179386dd49da5479d3135fc05036f96ce26a8d085a497b
b7270e52447e73f4476056978d77204d7704980bb50957a84e2d9486243e8e7b0db95
02a26ccab2f92b7f45d5563cb1bb19cf105a1fee8a6b4b0ed7581527af70a17d7a350
609717edaf9a75aa7150381efb55035461cd90038f776244dfb0ddf934401c3d7375e
e8b7fcb4ce4c3bfc1aa59c1469d14ca2022e6592c1d405cc1889a1f31cee6fb5baa94
bf72601aaf4c16141365f73222a7d2d86896fcb65898c178da53ad329a001103a6f2b
4ec6e0966c665fff16d88b87a83aa267c2be161d1a36a39b7b184828166f721b83ee1
5fe4753b05755e000f3cc1b199327335aa6339e244754101e77e4e7f0f4486d428e3f
53a2207be440fccfce3b67ac0268f44327440e4f2f5f6a1e1c7af200e54f38e3f9067
0498820061918fe012a11909284d7ac245ee9e
KE3: e4a167cb577b9b2daeafdf792367494dba3fca0028e1df50b5434f703adca61d
47597cd9babec56159587ff171ae447bb8978f385976683647473f5896693386
export_key: 278b3276079294de6a589044c992383a4f878f222176508ab325abc5a
d2d4394947b8b26d5cbe59ac81c6ea3db9d3d6b744796137b809f83bc53d37f36c976
60
session_key: ce6b7aab8ccc83e36e1e1ca0c06a07dcbfadae4733c1fc57f6daa40c
fec9bca0bf480090ed92888798f46b4b3e7f1cda1be75c6214a00d617e944aa4bd27d
0c6
~~~

## OPAQUE-3DH Test Vector 26

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: ecf05fd6c6030f687a38147851eab30c8136f3a827fdd001a69bcdacf5
31b4d4ca6295270265ceb1087e77d5802bd55d76ab525021c5d3c441bbe97ba2a9069
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 1b82c2b09e59137c6ea1c0d9160869b9a95eaf0a5edcfe7d563e2
c3239bd2346
masking_nonce: fca3baf2ac9ce8b09b5c8756f2d13a02495fd05e23111f3f84d754
9bb3460dec
client_private_key: 4f4b1b91c6a9c0dab6a8ad279201e00d358aed1a0ba88c458
589796b05ac19101d1119df1070dbd0911ca74b4634a51b9b1b093b74e1873c
server_private_key: 6ab03a76f031abde2e7d1f987c101064757d6133445217316
02876c29cc7d2652a7329cb8513ddcebb66b178194206a61256f5e14e70d23f
server_public_key: 2ef8f9560867402d20f9c34942bb26e63d2cc667851473334c
6cdf1f89ec0ea218e3ce0f73f9f1fd303f140bff958f80b7d4dd22a150a0aa
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 7f3ce3f5abcbed71e4799d052f3a1c6045b84ea2b4d93292e9a6738
def8b4fe7
client_nonce: b66d40e5b2945dd8b159f5df5bcde90b00c398d23f1d98e0d8e1348
e3bfcd6e5
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
oprf_key: 83d6e42aba37fda118eec03965549d28d819a2f662c530ec73322480628
b57c0b1adbb90408e2f89fb65963bbca62a8a512fb79c1d4a5517
~~~

### Intermediate Values

~~~
client_public_key: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec2a
f04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f357
auth_key: 18a52f53cd9a199c4b474b6dddb6b67ece09957bd0d0280ac8b3a745388
79aad62efae10a2141e1b14a80046b71cce1075d1389e4deab3929aaeebd58accd936
random_pwd: b8a031b3be8a579930d86a0e3648518c35bbb750f61e750c99a436880
8dd15d9216adfdf00871a0321f51e5bef8a9f7b5f4acf60cc2321201d0a265d7813ec
d0
envelope: 1b82c2b09e59137c6ea1c0d9160869b9a95eaf0a5edcfe7d563e2c3239b
d2346a918a25e6d03fe6d4e09a395f491f74faed44f27faca3c39aca6afe1cba5564d
0f00f17adb5387b1ab8ce13afb0f11de431c825ed6d5dd663a684b4e5542268e92e1f
f9592356e9d0057e3c2b2f2932558493aebc9ffb9e476831a5eb56c18068ef66a30b4
b5e7f6aae5a68724ca714d5d91119d8cff1661
handshake_secret: 8215a8ef096905e3f30fc7754b71a6425c4bff1ebadcc0dc839
d144f8cb2cadbba1aa74709853f08f047eb2e2b016daabf3b04bfab3110a6e1cdda5e
54f1661b
handshake_encrypt_key: 3fab58f1e957170a1ab6451282f62a28259c0f32eed787
4f95e072792d4851e45b92f7b7f318cd589c38b6fd4f268a266003f2f3ceb90637fa2
29eb11fb70a55
server_mac_key: b3c3bd42787589e3e3d6bc86d43b043acf427ef84bc3cce025858
bc5dcad6f49a15433b75b252d3a0139bebfd03dc9a120fbd66ab6b5fe332cbad4ce40
f03b7f
client_mac_key: f2bc89e944f0a8a1c51e6cd6bb1576868bba80c6baed19b77f6ce
8070f387a1678baf408f8af33fe8013c38b359bf6ca3830c6a9656e3a2ff4bce00f74
ac1c5b
~~~

### Output Values

~~~
registration_request: d287a62ca4d452ff3b5e2d800121dbb5785bb383db9bdb0
c541f8e643443dfe2ddb1162b8b7c758893fde1131a84ae57935e7b60b14058c1
registration_response: 9a77f4a8f646bfe8be5768beedaf0685e92a8cdae93269
8fd38f90e092958d2947b019f510f31da19e221a1a9c0d20fe0690ce248f863c852ef
8f9560867402d20f9c34942bb26e63d2cc667851473334c6cdf1f89ec0ea218e3ce0f
73f9f1fd303f140bff958f80b7d4dd22a150a0aa
registration_upload: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec
2af04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f357be568
225a57eeeecd3ed90de3fd7d45bc65ffc1f5122c8e3401e37b9116eb04f4525b3caf9
cf97aa4479efcf6ac71aa6a657ee3ef90572ba29bfbb228bc83ab01b82c2b09e59137
c6ea1c0d9160869b9a95eaf0a5edcfe7d563e2c3239bd2346a918a25e6d03fe6d4e09
a395f491f74faed44f27faca3c39aca6afe1cba5564d0f00f17adb5387b1ab8ce13af
b0f11de431c825ed6d5dd663a684b4e5542268e92e1ff9592356e9d0057e3c2b2f293
2558493aebc9ffb9e476831a5eb56c18068ef66a30b4b5e7f6aae5a68724ca714d5d9
1119d8cff1661
KE1: e4420dd6be305be0776f14c1140f0b36ca304c007827a8c5b4910c5432dd4caa
6214b4077d4a99e6d6dd7f756bb3531bd010eec2253afd1bb66d40e5b2945dd8b159f
5df5bcde90b00c398d23f1d98e0d8e1348e3bfcd6e5000968656c6c6f20626f62d878
99f024ee66ed5b8718f9966f2f34dde445da12078789f1e6208028cbc9b7ac7cff5ae
937856aa01321310e1858f0e3b89492e9e49f42
KE2: a827154dd01015fb25c4acfdb81f9ebc011845cd8bbc8cf9d5eb92be7940ae0f
2d373a2dca009fc1b093e2ea6f18a5223450f83ec1da8d1afca3baf2ac9ce8b09b5c8
756f2d13a02495fd05e23111f3f84d7549bb3460dec1d6328447bfcb2b59f42783162
50bba7d876731967aa0ce4dc987ab8359573a3dfb611d4e0607635f8cbc4bdbcaf4c2
3d2fd4a98b8bf8f405c0a8e353ad71a71f76e0f29019aa662b64a6e5f40fbd4530026
f0322702199964a9d7ed42a2451bfddcc91e5e5afd763ad83a3b661d61cb91a6d1cbe
15d6b51b995428a9a4b717210655602ccb7c64487870398ac15fb5bd31d6e9da4c379
3849844db3435e1e2605904c6a07db7cdadc62ec54ca28f96021ea16798e4f06fcd0c
e1114cf496ef11f76f7be99e69c9c2be4f1f651a9124b7f3ce3f5abcbed71e4799d05
2f3a1c6045b84ea2b4d93292e9a6738def8b4fe732751cb95f97035f22d498ed57a8a
f0d2495075aace642f152442da8485211d6a551142d9bc6771619ecf80ca8b4def396
f706ce555e2896000f7139f8fc1d7fffcc7812bc3c1b6c7900177ad9de39eff8879f1
9f2a2bd5c9980c71a4866cf7cf70091fdbdd1913b0a8ca1df63abaae6a58d075a1ac6
0303d67bd46868e807f83f55771a5d3506930d
KE3: 8b739d8f6276ee34b4b9023a4f5481b315f9499c5e1009961f6e88ae8ecee4d3
cf6e435e1566bbbae6a0d583490e84f65d3c936c6547f3184c96b5108e8e177e
export_key: 6ff43968ccbe5bfb03b0456c595038840b62c7dc7919c8ce6b34a492b
99757f39ed4e91d3aa4d24d635336f9adba00ac2a013e8fe1af9de5cec56908a40027
7f
session_key: f0dfbe4a47315485b14f97b3eabc136a03668672582efec6a81f25f2
02e3c45243c61838119bccfe1150816f8e6fa31a908b275a296b1daa21521168914be
9f7
~~~

## OPAQUE-3DH Test Vector 27

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: e2dca178c2b1472fc21e870dcbbefccf14def3124f44d4061c0467f731
9f426c67dfe72f19c2f31d5875bac10911556135292f249b4405e310906199dd949b5
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: dfcec8bfc96c8d35504993bb8e921fed4b312cf63e608d6d4eb2a
afb4c199e11
masking_nonce: c096e79ba9b7fd18ca2b28fa59a124e866a95632ee2e3791828b49
197b449638
client_private_key: 80b8326dd0c2b506b88b0b4025c0db89bb624a8b94861078d
88f88515adfc5374ba9326bc531c7ec458fa14a482339ce7854b1c044ba083b
server_private_key: 5315b843996e1c8dab628f7848b29fd8d4368a414eaaa9110
da1cc53752548548f132674a235f9ee105780d4ece5e1a760c147f744bb450d
server_public_key: bcd8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93
c99e1e9dc14db5c9c26b09e1980f7f5b45774012be6234ac5a8953ff69ef28
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 758b65209d4ab59f992b6cc73af931e5d12ff78967c9983a5508404
edbe30688
client_nonce: d369dec6ceccc831ab7953167491f9f9ea7cd0bd8216df60d4a3f7e
0edf915a5
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
oprf_key: 107edce8eb369b4093a38e3b35c0eb924ad25228e0cd1986fac95c2ecfa
9485e6bf9df3dbf50ad4edac9da5e4d4df03251ff728ab10fe211
~~~

### Intermediate Values

~~~
client_public_key: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e5f
4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948ef
auth_key: b5dc040a8c70a725640504544f0c21519f48c8e7a829bfb30b928f7b1cc
48f18ff917d3418d84cd2d37b138fcb13951970b38256a7f0fd00fcb6e4565b851de9
random_pwd: b87c7b3af688a875ffdd57a60c707621eb81851b4a988f83355827d27
bbae1e9b1c2282791c8fc5c9cd1497b25aeaab592cadb2bd666df9e748e369a5a8334
43
envelope: dfcec8bfc96c8d35504993bb8e921fed4b312cf63e608d6d4eb2aafb4c1
99e1182681885dc85025962559b523b5bc50c72d8a439c7b09783771425a3d5bed9c4
d25b2b94187143b4429171dfdc39614e8951ba5ce0777109c99786445b1a8d8a784c1
149e5542b922dadd4521077582ecbff76ce910fdcf4eae52112075b5aa4eea4f6ff8c
549655c57a1d83e4074fedef800dba6fed57ca
handshake_secret: 93f6749f4c768274591bdff1b18c5cf730517d0edaa13cc63cb
766fee3d03eabc46bbd2bcde23e301e759fe981cff160602ebd7efd98bc58d3c3bc7e
346646a9
handshake_encrypt_key: 0a910069952fadad580b1e38b573b8a30ae870123188da
d656f2cd0bfd7761b671b8b8b6d4973e2e81bce7c52fa0a6ae36207f983b337f5f6b8
5c9690c666e6d
server_mac_key: f1e8defd5acda15b0a1fd171d2d69ba43fa74332b9af2b0b69e27
84091bf09eebab856784490866103f60182c756122fb921278d4d08feaa2deee0c330
3187f8
client_mac_key: edebf037dbf79640e4d9d26b6b01ccff22b393a9c992c43997914
11bf16b8be73bfed1402d7691a51918aa56a94108d38229c2be4c4c92ba8cf833cd7c
6ea3b5
~~~

### Output Values

~~~
registration_request: cc1b854bfac5f36d7f09d18975d26bd031490a8810722e5
e84d13320bc6cc1ad88f2faefeeb84ac706985e2784da104dcfa376ea200241d6
registration_response: 460bd9575116fc18d186da49e0b37146547e36ca81204f
a189d6f48546a587fe43840f2dbde88967d7bf4fd0db2b1013dd59665ca1a58592bcd
8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93c99e1e9dc14db5c9c26b09
e1980f7f5b45774012be6234ac5a8953ff69ef28
registration_upload: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e
5f4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948effedf6
1a1b3dbc9fa0291be85d973f851ec908a73804ee01cb4b04fd5a1d4cd023205da074d
ac899f35087b6970bb187e4a8891727bfc2065d2b7c42cce122fb7dfcec8bfc96c8d3
5504993bb8e921fed4b312cf63e608d6d4eb2aafb4c199e1182681885dc8502596255
9b523b5bc50c72d8a439c7b09783771425a3d5bed9c4d25b2b94187143b4429171dfd
c39614e8951ba5ce0777109c99786445b1a8d8a784c1149e5542b922dadd452107758
2ecbff76ce910fdcf4eae52112075b5aa4eea4f6ff8c549655c57a1d83e4074fedef8
00dba6fed57ca
KE1: 8447080996dd1f729709b137aa45b6a6e68651f7f5794ec80d7aabca6f171226
e8c5ac7aadfe6b9ace4bc355d7b891907d50282031c15d9fd369dec6ceccc831ab795
3167491f9f9ea7cd0bd8216df60d4a3f7e0edf915a5000968656c6c6f20626f626e09
74f24da70adf24d24b5e267c80f6335a5cba9442a5658cdb76b3a2bc569d39ec6fedc
1a162f4e6c6a460b0978684aa5f30b3304cf04c
KE2: 82f56fa8decb2e567531093e824d82b1408866a698226a659ddb3c8dc542f873
ca32338f7f4fa5da53666d1fdca3228fc9a33389115368a3c096e79ba9b7fd18ca2b2
8fa59a124e866a95632ee2e3791828b49197b449638af72fb1d8ffc6c97e0ffb1a78f
9ed3a82ee6eb96f8c073c80fb4b303fbe1a63c8a6135c1ae2b27c61a7aff997455c6e
b920ef1e51f45844e03d97c4c2eb54d0adc8185320c171e3fe6cbe3b09d9e60fe7441
f77d43c6453cb053d3a84a1943e143cb5ea52d2158bca3012a9c81979d92f54933986
ce8a0895fab8288be0430e904dc20d9b6359edde2e4bb4cda18d2567ec918eb0726e7
5a5644fd0b580d2b9bfc940f16b10365e4ca805ddcdac1f0e421594be35f435f3987e
575f0e3358e258dc9d8827fcf1119dd2d0d9bb4b05cda758b65209d4ab59f992b6cc7
3af931e5d12ff78967c9983a5508404edbe306883ab8469c97f3394c729de0b4f980a
c06ea6a90dd077f924aac4210ce65521a90aa1ed82f46ad5cd948d1d96a179409a020
f8a01cc86cb7b2000f3eb09358fb5d17f01c6bfa1dc2909891cbf87e38ae98053ecf6
6ad43ec947fcff5de9cb2425d77aab7c0d573e2e91526ff0296177d4cad43cedade7e
4c5644920052d8aad7d719ca388261f7af04d6
KE3: 7c5017ec5cc35f1b32a898e71642f159bc9e1b1469895d7b66d8c5273aa563d2
a2c89da90a9409d298e002ce83c6b02c7bc97f3ab5070b8a0a94036683c2016c
export_key: c7ee497272363f7b8e44a57ed34fd4d7ca394c488edb2ad5247fba8c6
76fabed319f08da5209fc53bb6ad830f72c3810acaa5582c019d9a4a84aab745fb9f9
c2
session_key: e1dbcc7e276b27cc981e1531f5ada3af3766993964f328f8fd5fdc3e
1e04588677c45977ec506cdfbdfdfbeaa7b34e47013ac3675825040f0c79607ab1056
a35
~~~

## OPAQUE-3DH Test Vector 28

### Configuration

~~~
OPRF: 0002
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: c2e63c06402755ee0088e6720002c30570afe8830b73a229879822601d
b6c1ff7e378395bc2e853bf49617cc5825e6692f35a1a9bf5983099387abf6dd9447c
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a97722f77e8e8eda8cd8f1ecbe685383ab824c6e768003fcc61cf
06ac7899862
masking_nonce: ce3fe1a2c21e0160bd3279205acba316301d7604d5542791cbb5a0
737b6b7306
client_private_key: 771370125ea54cd3f86666bcf4155379dc1e0d5e6a8fbaa4c
0e0a570b44a311701b936a442f340c21a65638fe11c0e7b3bd1c3528e632d19
server_private_key: 7d455931c4f4efa18d5731a27e8ddbe8eac8be6eae6175f91
137a8cffccfcd6cb52345e2bf2ad8995f69ba5a19ffa1afe3cba5f538b0e629
server_public_key: 9cc2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8
e42262e63634ec59d0431f3878051eca9888bb45c17a68359bb55071e6f6e7
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: a92c704834d2cd13d113c3639e493b11875efbf23c3a7fa5f21efce
f2da5beff
client_nonce: a658780625dfab84cf9c2f5858b3a9ce887c291b77ba67be9be63b7
37668f803
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
oprf_key: 495460bc7dc3874108afacf493957fe91714218fe9bbeee11830fa98aa0
3cdcdad4f19d5ad8d78c97b37995375306f19cb1468f6e9a3601c
~~~

### Intermediate Values

~~~
client_public_key: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0c4
0dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc61844549
auth_key: 6a034e77372c8b257bb965b4987b27e238fcbc2e7896fed78c897c7691f
c6cd43d30c43f8cee6cab3899bbe0c903022a17cb717c749ee61fa75f8b95a5ec269d
random_pwd: bcefc476849cde4faf31b6eac0a0c25bad1ac39e000a4061d8248b114
ba14808ed6589cfe7566ac4aae0b15f6a31e914e5de3e6ced8dde9ad7c01ff47cab1e
14
envelope: a97722f77e8e8eda8cd8f1ecbe685383ab824c6e768003fcc61cf06ac78
99862266a6ab349bce6a366414ae0d986ee0fa259c95fe731f04ec6b4d420e4d25e46
a91222880b2de7c15c9dbd7f6a3546216112329fc50f3b1ec0a2be0911e28cf643bf9
f6c48e99e4ea8e8cc9f43bb2d64328bb4c34690bfcc28da1687427a3dad52e59a60d3
796a9d52dbd443e042c4861a546126878bb0ac
handshake_secret: 6df7c8a81b4a90c2e6fba79300d7fbc5dbaf3d3fd25c19fe3df
5aae80f9dff5c22ce85e64b45d0c94c05be07dc77425db40f531661e5acd0c7196b51
2d9765c5
handshake_encrypt_key: d4cf07489ce739280033756947c7b741af66c7f55f19c9
ec5aeafb720056b2e41d30e3d7d10ceecadb7544e5a678c11f0af73fff9ba79841c11
0c5ed507addbc
server_mac_key: 24af0b80a3aa30489c0f351b1fabbaf6e0aac3b0c9c8e05869677
b86e3900870933534161f1d593d3eed2ef90d0905daae92d2b1a56a7f031daa0bdb69
1b8d58
client_mac_key: c25d2864c071c07b4e5b86905144c1f010269f51dec48df2bcb24
f2a10292ebbf20525706391e857bb66f65cda96244977d17fd41a6955ba4d155ef1f1
e5f918
~~~

### Output Values

~~~
registration_request: 88c032a418dfb1e1cd1a3324ba5992452f93c66edbec9c3
65e92c1ea793cf76c05ae910ae194ca9c51e885d3c2bcba7d76989d0d824ace6e
registration_response: a032de64fc25a56ddd552a64e25725cf59c917b0a85b0b
b01a2f20c621a45766a52822f3e851ff72efe782a858f131b9fc101005200f14b99cc
2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8e42262e63634ec59d0431f
3878051eca9888bb45c17a68359bb55071e6f6e7
registration_upload: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0
c40dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc61844549ffa19
6231df42713074697adc0002f99dd20c43bd118971cf0e26ca54c50ac99f87e945b2d
05bf503baa13858ae3bfe4c1d488847137fe4cce3829446ae59ddaa97722f77e8e8ed
a8cd8f1ecbe685383ab824c6e768003fcc61cf06ac7899862266a6ab349bce6a36641
4ae0d986ee0fa259c95fe731f04ec6b4d420e4d25e46a91222880b2de7c15c9dbd7f6
a3546216112329fc50f3b1ec0a2be0911e28cf643bf9f6c48e99e4ea8e8cc9f43bb2d
64328bb4c34690bfcc28da1687427a3dad52e59a60d3796a9d52dbd443e042c4861a5
46126878bb0ac
KE1: b4f7627e7bdcfa7d9112301dd0081a3f51cf7e8853eb48a16c9078aeb0dd99b1
6e691ec45b6dacb2dc05b62f0e09c124c94b1b5390a68abfa658780625dfab84cf9c2
f5858b3a9ce887c291b77ba67be9be63b737668f803000968656c6c6f20626f62b8de
36842175636d346164767aa834a4bd1a0abe805678ced43406c4a09ce40145f03cd1d
620d6b3932243017098851f7003f34a849e6c46
KE2: a28a96159dd45416e2983a999df7128a253fb90570514fedca04c0abe7a402a4
9c09abe7f6ef99ea76f679b314bd6bd2852f44830da1cd9ece3fe1a2c21e0160bd327
9205acba316301d7604d5542791cbb5a0737b6b7306895767bd0b109b381828b52e5f
f78367390f37fa6dc5a2983e5bdfbe7c44c4ad3e5769e35ceea02e8106a0aab188a06
ad21a7f5c65cc1228f9d5d3549ab8e1a865bf2a450f0a80c73dcd792f93bed0ad8fc0
087e8f4a82cd22ffc14c06a3ef08d9630fcd6d7ca17a65adeec0e67f864de49622c75
12faeb9d2359fadd1f61ac4095e6eda7b55567aef12fbb08dc26d227b897fd06c8683
6787779ff37250ee81f6985ce27fdf4c5f2beb1703f91a43871d9bbacbf12d96072f5
c855496f35c42aa6ce8222fb74870f78d78e17a2773efa92c704834d2cd13d113c363
9e493b11875efbf23c3a7fa5f21efcef2da5beffb886b2c735272aa37e700b602edcd
fcf53f73ae463d94139dfd0e173feda40f8ec315c59dabf8b7db0a77cf9c3e5b35286
88b01849fd3523000f7d6b01c47746979c9c695bdfdeaff4ed170c87c46687efdec24
330f299ddfe8a037b7f9a13a8498716bbc453aec6283b0d0932eb07bd9759295d491e
2f3ff2ba15517d26dbd2167f3087c67728c4c5
KE3: 71c7567390927e8a676e27b3c0cd9f01cd3a404c1a04c63125bdebbd61361a42
9d18fa334db3c0a04d2224c38fc58fe1b086fa697c41a77707c8906a33c785d3
export_key: ae21c569e1777f8406c31c849738e11ae92264738c7c2863d1009fc26
b114878293f026aa7c9b747b232a1d70dd89d39fd8da69e81cff2ecca0edd44cffc9e
fb
session_key: 14baf411c03659f431f9692fb4d34bd9d11160d7da743969aaea4bd6
a3343bd5d28d089eb506c2e6f033fdf1679dc6e57a026e529ed5870e51a7ecc961465
825
~~~

## OPAQUE-3DH Test Vector 29

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Name: 3DH
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
oprf_seed: d0abf87d17a3309b28fa41111253db45faa06a87e2682785549b6061e5
b02ad3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: fe2c93ed07c52abb6d5ef4044ba55f95dd0d6009e2266be0e0b87
5e5894022b9
masking_nonce: 2371e02802f955f63738cebcb3d79676d6d43f17baeb5b3d7d8ccb
b5379b14ad
client_private_key: 5b1a8d0d1f59318d1a325244e784530a56f15f95cd7594b41
1ea8f7ac77652db
server_private_key: 40e02b1164d21f51b8022acbceb26069ac5ad37af70212b20
1e18725cb41a5e7
server_public_key: 02c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1b
f7dafca0807eb046
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 1cdab75945ce96072cc4bfea144aa825f666da5e1f3ed63e41c5666
15492ef30
client_nonce: f567c09f208b0271a658f2a7c4ab089faf84bbb14d0ccde79eaac6d
d2a00840d
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
oprf_key: 585d358d3b81d138c1dc033d3c9ca99541dda01467d15ae5521a5a6ac7b
0da22
~~~

### Intermediate Values

~~~
client_public_key: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430b5
2d36b1ccc475cc8d
auth_key: 44903b004eedc0cadcaab80bacd362b43043e45acc408322d11e7d06f04
b1014
random_pwd: f4a8d39a3ec78ad2d0d4b35be7bac177dea2f37c2d058fa5fb776da86
ab3dfbc
envelope: fe2c93ed07c52abb6d5ef4044ba55f95dd0d6009e2266be0e0b875e5894
022b94ce48ff131233fdc80cd84b9f5863641d4514ee903e09da65bda553570b2a093
095be528429392c7f1aba460cc0a81b6d5df6574720257aed20416fddbfada52
handshake_secret: eff37abdb4f1844ebf5133c6ca9835e0b03ef1e7ddf91455bcd
262343c53bb44
handshake_encrypt_key: dff116f7940c1b24055716b1599daf44d9ea8a2c805392
4a7ed1d3f058e1a61f
server_mac_key: 2c891587160e5838d69cae6eb3c873483de44f1775da1b60ee3fd
66b57c1a646
client_mac_key: ed05baf492ea55f1230e5166ab2d7926ce3a2c8fd9560efe8278d
1e80c417c49
~~~

### Output Values

~~~
registration_request: 039ae9435af572249db38975b192f1beeac30ed093c4d9f
40bb5236d3521035ab9
registration_response: 028f1dc3783489b6c21a1d91c1b67b2338bc1ac3c65bac
dab23bfe27015826610302c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1
bf7dafca0807eb046
registration_upload: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430
b52d36b1ccc475cc8d1ee6172ffac919f8fa2ef051e2de54a88b5d239c10967eb5bfe
5e4a2d6d0e952fe2c93ed07c52abb6d5ef4044ba55f95dd0d6009e2266be0e0b875e5
894022b94ce48ff131233fdc80cd84b9f5863641d4514ee903e09da65bda553570b2a
093095be528429392c7f1aba460cc0a81b6d5df6574720257aed20416fddbfada52
KE1: 03f86d270a693da19f82b655d8ffe6a26ac2b79ef779de92012d7fad3e15a7d1
5df567c09f208b0271a658f2a7c4ab089faf84bbb14d0ccde79eaac6dd2a00840d000
968656c6c6f20626f6202496d129c40fe6d255d57f6d92af5c0cf0ba277e8a0e7b67a
61df2dccd9b02c5f
KE2: 020df049fb4fc39b2590a8317d9d96cda8f0967ad853b84dba0cd3235377f8ae
942371e02802f955f63738cebcb3d79676d6d43f17baeb5b3d7d8ccbb5379b14ad576
ce189449ec014acd11ce34de9d9d4a686e3252eb998bfae6a9d7854cc1ba0d96310fb
b51a3ba5d2fb90ecea5fe1d5515f86e232a7d7f84faaed8a7c45dca07d573373acb10
ea4ab3ce38de9328cd237e23ce3d2d890ad0be6c42610bd688580e8534ab3355c7bc7
bb923e3a5102aa4afb3895858d6e4e8c37a3f6784a0a79911cdab75945ce96072cc4b
fea144aa825f666da5e1f3ed63e41c566615492ef3002c5583ec9a10dfa32344fe800
0007904dacd5e6be9eef27b0f94b50605b017126000f92e227bdbfe027e6ca173844e
ddba4824de3e3bbe81d5f619cc7c0fe92caa080798f85ce88daf4ec1270c3e8788b0b
KE3: 20bf9af3387388d0294e9ba5ffdf21213a834109cf7eb02e14b688720d61f9d5
export_key: 2ffe40d00f7dbd83501769f4a48ac69294db7e7e52ea0e914d1b236f5
4947d18
session_key: 853af4869744b95886b852e5389d615483e968aaa719c7863f97baa4
2d7ad233
~~~

## OPAQUE-3DH Test Vector 30

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Name: 3DH
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
oprf_seed: 7c3560417bea546f3fb0fef8c5915dfc22388bad536848dc5ba4771895
26c09d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 6258cabec73455bb3ece174437e286295d1b82172260a3d8cdadb
669c103df19
masking_nonce: 26d94b5f3ebc498905d6a346963cbf553588d4cca122822a9cf3e8
35845469ce
client_private_key: 03be3245a3830887fbce88f3eccc26f1639b91aa8f043ae61
75d146de19bef1d
server_private_key: 6a62ab611cc2ea77a7fcb3565850ac22c6d3a18b19541fce8
3b070cfa802882c
server_public_key: 02e1249c0906886b33b0ae59c981001448f2541fb718a158c4
b4f37d391e813fed
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: aac30804231a9b7d8c0562bbe2ee3f36fdfda155c9ca81b7be2ebe6
fa816bbaf
client_nonce: b143c07f1a14ea52b84f34b999c9a39f9b5ede86840a6db89fedb98
be652824d
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
oprf_key: 44f0699037c6ae54fb318b1c913a6246e0dbe2cc7c770269b1fde7c3402
f58ae
~~~

### Intermediate Values

~~~
client_public_key: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a264e
65baa2434709f808
auth_key: 8441c3842b19c88c576c25e3caacf9d032c95194eba9d666f0ee322a242
3172f
random_pwd: 0d5e2b60fc15051057aee38de344d70038ccfa297b762f685b3b21494
33415cf
envelope: 6258cabec73455bb3ece174437e286295d1b82172260a3d8cdadb669c10
3df19700268a0d53f824d10b8acdb3df08222d74ae835dd94a03ba23c31e38ec63dfc
73dd254b5d37c5f7a41a72a2558c3193958be3e0488c0e6a80182a54cf91f038
handshake_secret: 8c5edaafe761516bdd470cb3fb0ab9cdad305223c7b4b8b257a
83440986f06aa
handshake_encrypt_key: ffe4c25532908561eace89386e373762e896f1ffadb6b1
1ddbb9ae539ac0ffe1
server_mac_key: 48244ba9674fdfc6ab568e13fe3a4336e9b8a2d807326ede20558
3342187e927
client_mac_key: 1a42be390bccf34bf3e1e0d51ef81be7ab14ce7b132133493a1a1
640417ff1d7
~~~

### Output Values

~~~
registration_request: 037a055d502f2a882c021fda1ec2fe8e5d8cd0d2a913e5a
03b1e27e0fd06308275
registration_response: 03045f8b871f0b9c4dc30dfd39a3cc28fec466751fc22d
b14724a63e1e5872be1602e1249c0906886b33b0ae59c981001448f2541fb718a158c
4b4f37d391e813fed
registration_upload: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a26
4e65baa2434709f808cfa4b5aa2f9c7a70d310818deca6cb70ced8b30a5435d275f29
1c2feb8dea3276258cabec73455bb3ece174437e286295d1b82172260a3d8cdadb669
c103df19700268a0d53f824d10b8acdb3df08222d74ae835dd94a03ba23c31e38ec63
dfc73dd254b5d37c5f7a41a72a2558c3193958be3e0488c0e6a80182a54cf91f038
KE1: 02e532d2687a979f0a75112437e1f4c6d5411c555b2330a8d6c45c7c7c657aeb
b9b143c07f1a14ea52b84f34b999c9a39f9b5ede86840a6db89fedb98be652824d000
968656c6c6f20626f62026ec987d3b7ea3ef8cfdca092b9d6994d134e933a5fb78929
5335d5f6956399b6
KE2: 03a0e8f1a2a45fcffbb95083436a8e784747a5a853f1645308f4ff0d6ddf1bd5
9b26d94b5f3ebc498905d6a346963cbf553588d4cca122822a9cf3e835845469ce098
ee77ea76c96798fbfb642723240f46a93a44b4604dffb87a221687e6b455717c4a0dc
be0114386d38174cf8abe7eb0d69379f9c51167ce7f1c9a8842d46410f8fee334a33c
fd69b127fd0a4dc018749ac116b2f7c69e0d39ac21bd427ba3e66bf5a2386de688bd7
3f764f0e269da2c67ccea8a268a20ded16dbb20f3242c62daac30804231a9b7d8c056
2bbe2ee3f36fdfda155c9ca81b7be2ebe6fa816bbaf02178e9554d669786c2e9349f1
e178eb84961a7f8073d9ecbc5cf52bc2fef7791f000f42b4888611860d0d236a8e7ae
fad43c16a03ae3317855db64d989bb826634234df686be1f0b8118b4d784752a7707d
KE3: dda7d634a091c9b9028476a20d4d53be11379715c26e365183e8756bcca0c430
export_key: 2a0f3b52a605e62327d8311a1dfb676037ef7db8cfe5e9c0fafa9abd5
24a09fb
session_key: 58f4d84e26b78c957e69ec5abbcdc8429b198afd85d87d8f7d5ebfa2
b1317b23
~~~

## OPAQUE-3DH Test Vector 31

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Name: 3DH
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
oprf_seed: da0fb2f62cf6d6303bc7ed70a878ba3cbc353b9f5a296e717db6a77d0d
45b758
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: f14dbfcc767e332513e9f3d90499fa34272bdc8de6fc3fb3c2560
2de6039f889
masking_nonce: f7944e60c59baad817600812c70136b76a6734072c8493c0809a16
bdd3fa9dad
client_private_key: eb7d0ea4bf06b78e3ed83cb2d3feb9683cece55d800eb5196
e9304e50ac61518
server_private_key: b4cd2e42c0bbef01350751994440026574a20f677965ad056
1acb622a32651dc
server_public_key: 025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a2
5b74538d149fc226
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ccfad48bee622777794f570462a9b0cc6d7b08af183d1a0509f8c64
ea12b7241
client_nonce: ae8f1f7b2c5e4c804c9d1497ec114aede6d4ab60368e8920eb1df45
25cbabea0
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
oprf_key: 7a790c7d3c96b3bcc914d5dced385c7643e0109d34c260c01ee77fcb2de
41ac9
~~~

### Intermediate Values

~~~
client_public_key: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b00
3b652dc03e8b5304
auth_key: 54ea7612f1568756a6237ef3ba6c9b77b96ebff1fe78c7befcf1041e6ab
8612e
random_pwd: 1a6e1335a67fab09a8b6dfd56b9e156afa4408d1250229f3e23c97270
0c7ffad
envelope: f14dbfcc767e332513e9f3d90499fa34272bdc8de6fc3fb3c25602de603
9f8894f8993042513a5e95dcfe5e304f2d9cde2fa90708779e9c13c0ea770a923b9ab
38802f4e19c667b4e5cab044465c81672add3d08d6b198cbe89ad2cc47100192
handshake_secret: 9970399fbccc2d8be8fe71dd00a274c2fe6a656e50533de9474
1a3fe19289292
handshake_encrypt_key: e441fcf47a77d54bf83b159c92e8a0fe131db6d045e35d
d42e19bb5c0ef91620
server_mac_key: 0fa836d015f389e2c5cac3fb86aa471285945fc436f82c30f25fa
bd2712787dc
client_mac_key: 3c46a4070e349beb22274ae71cf6b69c9197281ad165458cb464d
181a4a6ba4b
~~~

### Output Values

~~~
registration_request: 029ead8cb71d9f802fc71737e16f75eda7843e5b961c9ef
0bdf8da0cb97a6364db
registration_response: 02a77b8bd45e25d02a6a52e9b3dadb72c48f98e8eb4b72
dd2f3e02ab32b2ab4b05025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a
25b74538d149fc226
registration_upload: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b
003b652dc03e8b5304d441b089a0ddfda0884043def4bdb3078f0ea3df77a07e2be53
9540436c2eff8f14dbfcc767e332513e9f3d90499fa34272bdc8de6fc3fb3c25602de
6039f8894f8993042513a5e95dcfe5e304f2d9cde2fa90708779e9c13c0ea770a923b
9ab38802f4e19c667b4e5cab044465c81672add3d08d6b198cbe89ad2cc47100192
KE1: 03fbe22a5b37f7345b2370c51a5290091f5af7b21cea757ca017b2a32279b543
f6ae8f1f7b2c5e4c804c9d1497ec114aede6d4ab60368e8920eb1df4525cbabea0000
968656c6c6f20626f6202736055b3c97c36bc8e7bfe53ae65bc38c5be6b46adf3d486
81df7bcfeb96770a
KE2: 034236afd4aaaab6580d4a5c7ec72ad5c23e061b2ceb31e2960abc8b7ba8080f
28f7944e60c59baad817600812c70136b76a6734072c8493c0809a16bdd3fa9dad632
95681f02782e2a6fba0f711a3f30cbee488fd8060eb7e9e6bbe6b5bb8744fe9f130f2
eda8c2e6285983ce261306beff0e8ebfd6123434eb73343c61a03f797552e0f99c7b6
e56e0bdf3ad7934a2ad4b56447fa42bcd23b1fd647339e04d6a5527286ddc42869e65
ad4bd7a7103a20cbf434811cde429101243938b3cece4cf4ccfad48bee622777794f5
70462a9b0cc6d7b08af183d1a0509f8c64ea12b724103981bb9a42c6f60750d2c9098
ec0e64d52dc1ef0b4d02a20b2ae9ce40b425a389000f17574003c0aa11b5c1b48d4b1
8b20d125f76c07323356984d6ea7848834b55eabbea54ff0bb058d4136b76271fb23b
KE3: c81734393a2e73860cd4cf926711769d8c3b398cf717fc9e5d5b5fcdd793c7e8
export_key: d69946973cdf729762f49b2016883f009771204ddbbac00aa50567d51
049bb7f
session_key: 0c62827214da82b8700040257f294bb144c95a15539b8c8a8e04e0e1
ae74f759
~~~

## OPAQUE-3DH Test Vector 32

### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Name: 3DH
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
oprf_seed: bc71f3a9060ad74a085bd162b33c06c55572d0c59975fce2b50b5f0706
0c95c2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 921c8456b01a9184c22e1d5f464a1cf13be4d37357e861122356c
a8720e6541c
masking_nonce: 3c53475e70e7d59120450a0d0b096e23025e2f1fcecd6635d52c47
ffab2f4de5
client_private_key: 02c14f564a29a05e39d4b9382c20686e41faa8407f03f5d2b
2b111efcb64be89
server_private_key: 759ebff988d2878fc2ac6619807ac6625d0ba08ab0d6c5a67
e15fdbd8e329839
server_public_key: 0249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c5
e37937a9187772af
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b54f93747121d3cacd4e892aacb1c7c77bb8535a8494835f48ad891
b5caad4f7
client_nonce: e7fe5d42ed2db0094f5bfd73fa91e423143aa5549608780b6b74fb3
414b1723c
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
oprf_key: 5206504c49942d51ba49fcd8c0fb5b9fd0a211d4d781656000d0b8fc6e6
82b74
~~~

### Intermediate Values

~~~
client_public_key: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f89a
da3ab1d4b3f89098
auth_key: d53e51482cca3e5898df55eb878c953d75f79ae3bcf29039d66def88f41
84db7
random_pwd: c973b8bbf3449f9e9e14080ea12093526dc503e87270f8f3f744d7031
66b56f5
envelope: 921c8456b01a9184c22e1d5f464a1cf13be4d37357e861122356ca8720e
6541c0880fff401f2e484bbd0bd0d4e73b5a02664065e7c44edc45e30967b52104ce7
4028c5333cd0e76fbf9c3ef7092eeb9d02a2cb2f6e47669d9de117eb4d828d60
handshake_secret: a442e53154a61de23bb90a766ea3d72396a5936bdedaa1ee40e
125975005e04c
handshake_encrypt_key: c3e6c6fcc182fd683ddb58e2fb89441ff977c9da24b436
243724196a52c5bb0b
server_mac_key: 8e8e089529073293944569f976a20c2c86ad4b299d3f0d269672d
3972a3cb39d
client_mac_key: 93bdfa9a7829dbb45fc9fd3b2114653967e1e6f3461c7cefdc83e
0ecdf1bbe55
~~~

### Output Values

~~~
registration_request: 024ff8b8c3636b93127c0c5350c4d2e64b47c78837d6edd
ece7dd67a260bde8085
registration_response: 035c2e9bcc4553843d238444e7fb8c490cb57f5c60831c
93902e4b9f76a42204fc0249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c
5e37937a9187772af
registration_upload: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f8
9ada3ab1d4b3f890981b9e0c838dd5692210e2bca6b0f66967fcd1f3bd03c8cd00b04
96ed50222fc21921c8456b01a9184c22e1d5f464a1cf13be4d37357e861122356ca87
20e6541c0880fff401f2e484bbd0bd0d4e73b5a02664065e7c44edc45e30967b52104
ce74028c5333cd0e76fbf9c3ef7092eeb9d02a2cb2f6e47669d9de117eb4d828d60
KE1: 027694e256efc51327333fba8ab1927b511c4152f93ddb0771370995407b4b25
fee7fe5d42ed2db0094f5bfd73fa91e423143aa5549608780b6b74fb3414b1723c000
968656c6c6f20626f6203eeb46969c8d3c0ff2160547e2ab719958b7e8686ca4d9b12
f604883194bb90a1
KE2: 03ec9e073c6e9b68ca88fb17433cd12c45a154e1dd1627151f8b3e7ca9de398a
1c3c53475e70e7d59120450a0d0b096e23025e2f1fcecd6635d52c47ffab2f4de5b81
9cdbee6b8e4440feb0a6b36123cbdfa30814b9b9954663d8ad499cf3d2140b193a92e
c0bcb95ce2aefe0ddec16f319731b3b0f70d40a86831717607becd97c86ee7667221e
faacd09c07aee94325254b770916a6dc5c16bb6862090b187cd965f49c541f007f1f8
431fe8acfee41dfe7971aada03646c2063463ec3ee2b0a02b54f93747121d3cacd4e8
92aacb1c7c77bb8535a8494835f48ad891b5caad4f703a05823236f8f28bd60569e51
b83712e6371b7006059bb8542216c9b9ec73ae8a000f2b0232b945dc4e2d38770a4d5
6fb8c5afca83ed3fb08c15a019e0ecfc9851aacad8dd38b022f4c0bf30540a1fc2712
KE3: 987ea300cc8bf5f2dca70ff6094cd0ebd1d73afa082e314907ffcc30b6cc2d31
export_key: a01dcee503aa412e4d83315f6bc43b0ef858200a84f0de9f70dad880a
d019fa5
session_key: 4d0412e3aa70fd60502e881fa03f26535ac94504f9d8a7a319efefee
15023b66
~~~

## OPAQUE-3DH Test Vector 33

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: c24b354fae9a34f96373404af5cc916205eb5386d997c53df148e42a51
caf26bc58d42003b7dab4d3bfb8deac32375610f7183e80fc48d3ec8c4f47df96013c
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a1cf3f7a80a7a9c9e8c035539eae03c252308211718260e060495
7840f51bacf
masking_nonce: c4dd9dd88e5885b6fecfcb68b296b405020ffb86410ba0ea61a8a7
98ec795111
client_private_key: a052da1e7263802eb5ea90bc30ebd07510b7997e0563f04cd
b0173a862ea1adfe5ebc2d261008f3dfe97647b8ae9d6d8
server_private_key: 32a099b199f3eae54592db460c87aa23e9dc4f969294ee264
5b5184d63c0e7f19fcbfb025d7dd9e32e4906883081c997
server_public_key: 02094306eaa9c62c5a873fee4afdf81c91a91556be8286e7c8
f5fadc077f810adb6bb760faf2e46f85cb0b7649ebdfc524
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ad91a1a887d8f907b0273757b3e34177e22fd14a7f3998179360343
39416dbb9
client_nonce: 5e368d863fbbb3e1f63eaeee4134ca91c8adf7ec612db23a7e8473b
f1a330e59
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
oprf_key: 57dc765a89ef3095e0f6ce5e92685caf61410ab789f3de42d256ad211f0
dcfa5b0fdf8698ebb1138779fce5cf145cede
~~~

### Intermediate Values

~~~
client_public_key: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132f2
2abd78a05172adde74d97f453b902fb2c454718c91fe403e
auth_key: 4f9b5b09f3d8521e143a700646e7daa8070726cb46b2898409d5bb9b7f9
060d2075ab57705da3a54158ff650f96ed00b13a3e34f6234db138d5939676ce11a10
random_pwd: 1346ac8aef2812aeb76674e9b384715c2cf83b6589a53be7d9fb60edf
432b83b14c6806c92f0ce73d2d0a2b8c695e76c449be7c4f463bf746fa69e19e8b1c1
59
envelope: a1cf3f7a80a7a9c9e8c035539eae03c252308211718260e0604957840f5
1bacf458d520e55080dd5a9785bc04909d988625fcee1cc47de674b6b2cf82f749de8
e3702d1c85cc25c6c6d4ca859927e96dcec13a7ac1dbfe1285e8172268ab0de1579d3
bd4496cb90a55aaf23850f5cbd50c274cfc0591fc12e5b6e3c691ab6405bc15fb4193
edefcd0312035908ef2655
handshake_secret: 1a9117ce9907e52104f51c8a0cb62a393f1e56352be0ba39134
caa2ff35e3ce59b5cb3b7e7305c6e56776ac9ee83b00e3dd02ed35c1e0e7b7bbdc83b
b721f74b
handshake_encrypt_key: dfbd1dbc3d3336acfa19914f066805c197d7f314d056b3
efedfc0688f69f72bc412fd71982dd78eb252b2537c49f989d64b25eb8a5bfefb1801
9ff5872fe860f
server_mac_key: e584079a1448f20166cdfd8977456428996cfee4b0c17b5d430a1
6950f84b05fd3176c2f820e0593a9b1f05f325ce5dec3b350dd5b6ec6f482bc5ba86a
a60540
client_mac_key: e1a3abf5ad1ec5711343bc53324d689a17537e7a15e891ad98b73
b7d446165f9cd8061ce3c64d472c622a99574b6611cdd50ecf5356224caa1b34598bc
2f60ab
~~~

### Output Values

~~~
registration_request: 032b5a44024063a5644913f145e01c5b787a77804a5ec25
588320d5ecea9d524c1f9321b9ae76a6bc168b1f99e7305b9ec
registration_response: 03072a0556ec832126bbabc0bd872bb04dc83ee8ea389d
9b030b07cf56eead8be26898e4431e43939d84d221fd30c75a3e02094306eaa9c62c5
a873fee4afdf81c91a91556be8286e7c8f5fadc077f810adb6bb760faf2e46f85cb0b
7649ebdfc524
registration_upload: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132
f22abd78a05172adde74d97f453b902fb2c454718c91fe403e303886ea6adb44098dd
39a556b1eba217b37374ec277fdfa4c755af307dcf6dbc36c2778571bccd335360fe2
e078f43067cb4cad73b975f1d932b20f7eb3bd65a1cf3f7a80a7a9c9e8c035539eae0
3c252308211718260e0604957840f51bacf458d520e55080dd5a9785bc04909d98862
5fcee1cc47de674b6b2cf82f749de8e3702d1c85cc25c6c6d4ca859927e96dcec13a7
ac1dbfe1285e8172268ab0de1579d3bd4496cb90a55aaf23850f5cbd50c274cfc0591
fc12e5b6e3c691ab6405bc15fb4193edefcd0312035908ef2655
KE1: 03cc36ccf48d3e8018af55ce86c309bf23f2789bac1bc8f6b4163fc107fbbc47
b92184dbba18bc9b984f29c7730463fba95e368d863fbbb3e1f63eaeee4134ca91c8a
df7ec612db23a7e8473bf1a330e59000968656c6c6f20626f6203f58c4669321d580f
98b4b166fbccd6da300ef7c4f0fe19d5576d3debceb23e50b5405ac264c31691e4517
154d993fbe1
KE2: 0257bc1da6c7196ff387fc1954ff75a469539fb38e912ae3e762ddd3e28ce40d
bd3d4743357693d235b2964866fe9b53dcc4dd9dd88e5885b6fecfcb68b296b405020
ffb86410ba0ea61a8a798ec79511126c9a98a7af58d35236bbd137bdcafd1fc0c5953
5bbc6ad1e5a5c7ae85a4f08f0cd487342f617ea6a49dad396358ea828bc71dcd69ee8
b6a4e966fa499713c7a4c88934e1b839576e5b929e057b4dd413eb20836fd1c7e8a8f
bd209c81f0a7e3b484592863cc0b7ff1c55a2cef13d1f22aa3f13f1f9ac75ad89a44e
02d93f950573eb755ba182001380b29aaddba419b80eecf746bcb66defa879a187e24
96cedae59610841647dc09e6b980e1a00fe4db7b3a0f6056cd2c9b7d5ecd81b595baa
9ad91a1a887d8f907b0273757b3e34177e22fd14a7f399817936034339416dbb90218
bb6548593c38236dd6991a1c556a5cfa81be6c235891e5a00cf4eef1bb3ab6d653e03
abcfe1634908971d19b9959f7000fa94b742bd16184a27b32363f3bab740963830e07
a1b2293df943b2d9da9986816ec71dfa7465263dca06847ce40ae6bf071a8190f43ea
e788d54cdf6a462c91d83bfe4542693422ebd3f7fec5d6bd2
KE3: ff86dfe8bac49a1b2cd9fefcfcc55d588b25f4bf89b7c3c154275135aedebed7
6d2c7f231476cb194c0ea5cb10febad5990885b292bc8d129325e41ec1d105b0
export_key: 7519276c78735ab01f884d141615ddc9e1344e45c14ec0d3193b4e791
da2c7fe6c654a59182cc2d60c47fe2d29be265a1ad4f49b03b55a24c01159c8eb02b3
7e
session_key: 0f89058d721df0ba5032d0069d501d0e32740750bc7cbb058fadc7e1
3228335d9db5bcf85ef8afbc860153d89817a9314ab3a4ee37aaf08e7c217c811f9a8
ab9
~~~

## OPAQUE-3DH Test Vector 34

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 979757f6e39f8454836e2c1ce4cc67ee70058d7e7f015ad3e4e39e1dc3
f2a6d7430fedd82238810544b0a1246f67351e48fcd83d10f0f2a895b839d06000271
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cc0b3e6554531afd5909e88174962217da469e2260a64058cc8a2
514a54a53fb
masking_nonce: dc894ea3368ca2c5a87c7566f5a6c9d548e3c64adf9626b70d1452
6100117478
client_private_key: 194f9a720f11c3f0f1613cef116e218267201ce0aa4f4f55b
68c5393aaa4101699ae3b0dfa984cb954913dea02087eab
server_private_key: d650dcda20f27d7bf4673d820cbf71e498ec903e4b3959af8
52f6d9edfa68f06f4d7ff89d5897912df4f9c633a6d925b
server_public_key: 030278df9fe8759989883c2ef9047b2449abcdbe9f508aad83
f227836ddda86b3dfe0aea33995cd76243a4319800bf8ff7
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 19edae31a7ccc1f1d7985b181623a395c1c0a9b08dfa320b2ec1649
a84a5d1a0
client_nonce: c63f8d9d358c419215dd2780c4676f636cd06d9889d86b4ae0ba79b
04a30758f
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
oprf_key: accc8e94225054df59cfe38e251b4d587a940b8a79c399f9e98a01ae54c
28efe13a4ad00096800763482d7db09376aa7
~~~

### Intermediate Values

~~~
client_public_key: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1b0
a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff59
auth_key: 376205875e4f9c50023662bd9d9d5b0a9762641d31d207c18a65a36cc1b
d0faf4bf31502791c0700e72499a456f5528224d867751652b031762ac10dd272c735
random_pwd: ca7ec198254496ff179ef8cfba98f0604b4e66cdb244b7580751e4001
ebfa19da3b1febfa54bd8edf9a07b51ccd47c7b791e02f3b34402dfc340ade5d2a635
ad
envelope: cc0b3e6554531afd5909e88174962217da469e2260a64058cc8a2514a54
a53fb2b6a666f389b00f4e515a9fc3377155316751c89b4d4d5a2108c37feea0bb054
b4bb2d50cff45dff5e899aa074d5cbc900c653d7338f5e7447df7cd5156eae7a81841
f6036c05dfed676d1e7178ad79c02d5b5c94109d5d5ec72929bb7147a8620032bb901
444d79a30f5d3e73057e97
handshake_secret: 2cfd510b430a9c5625a266e43d8527c253e16cbdf5eceafcaf9
e8e650b74f468184b61f86f0c3d6a120f6b3f08be0347e1b11e5342abcd2d893c5424
526720d8
handshake_encrypt_key: a5bfad9f03fd098562de1ec65f8ee87a05005d4320d8d3
5e58574e19fe50419ccd8154d71af8f86b32cd05841e374aebdc1690c7c39256bb799
f896b8677417d
server_mac_key: 9bd96a56bcebfe702e064bc4bfc2405123bb1ef8a2fb599e76ed2
fd42237f9fa0ce19a2a8a186713b5d79779bde7c1b5b2636ba2f36d0b0f6f1fea4255
8e1d8d
client_mac_key: 8bd37145a6750baf8fe29a6c8d61e892281a311a0130c14ae0692
4afe80e5d771237ac492f7acdd4be13fe95e5e734bb05c30a69d8d54e332483395834
e051ec
~~~

### Output Values

~~~
registration_request: 02bc8b8b2d8b96ba8f527f59dc0054349f0fbf4c7cda280
480d643909db6a8dbd4bcb455cc374050d8cce29147fab0a020
registration_response: 029efad1a5ec0219513bf21ea40394622536bde1987dc0
3ebc61afeb057f9e453e9f351c8ba6d72fa71299acbb33f68090030278df9fe875998
9883c2ef9047b2449abcdbe9f508aad83f227836ddda86b3dfe0aea33995cd76243a4
319800bf8ff7
registration_upload: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1
b0a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff59bb822e14de961b278f8
e1ef4539175d6e6b4461402feae7bbf7da7a1fd62306ccaf48cf97a595e8db9206f4f
9365997a0805861284733dab0bb1a1351094a7eecc0b3e6554531afd5909e88174962
217da469e2260a64058cc8a2514a54a53fb2b6a666f389b00f4e515a9fc3377155316
751c89b4d4d5a2108c37feea0bb054b4bb2d50cff45dff5e899aa074d5cbc900c653d
7338f5e7447df7cd5156eae7a81841f6036c05dfed676d1e7178ad79c02d5b5c94109
d5d5ec72929bb7147a8620032bb901444d79a30f5d3e73057e97
KE1: 0258fdc4ba750f504274ff4644f2f43a75759b77adb1817c8686340bb28059b2
af91d82801b94bbcb8326cc2e046a4df51c63f8d9d358c419215dd2780c4676f636cd
06d9889d86b4ae0ba79b04a30758f000968656c6c6f20626f6202313f18385e0f0c3c
88f3e60178a6727c9023e1044973eeb676b9a17a398424b1074d5e35246fc25be8302
8853dc22f1d
KE2: 03eaf0773e9c558849d387297d889ebcaf4cf5fc5a76d79d8c135405bc359f8e
f2013c14943df42e048cb9bb2496d63446dc894ea3368ca2c5a87c7566f5a6c9d548e
3c64adf9626b70d145261001174783e4cff5db7d73750cf960ba2abc6ece5bd321a86
dad33c017af9d25fb850600803c3ac677e7db81ae78599f0d3ae0831c7ebe90de573b
84d259a921a71490d05769d920df88f45b353635a7d4a560aa2bd41fee429761d5b96
66e28f9f5540026d481bd4656b464f471f6a2384a26c3cf18890a1745d80a81822fb5
a0811ca61d06b935f8cbb2e418bb18c6b002f92538474f0fd3bc2ea072063bf6034cc
f44f76247c88302258a2379dd89f1252486d6da85140604e3abebfbe27a1b846de03e
619edae31a7ccc1f1d7985b181623a395c1c0a9b08dfa320b2ec1649a84a5d1a003ba
3e99f4c2f39463fe214e7607ca3e9b1f6112d565d80bbdb388f52437ec89f0da6b802
79e10382bacc7cdab25a3a830000f047db0ed928c6a5157a040e1fb8b675166d84cc9
de0a9d1b2ee90859b85096172d75fc9aa4701cd6d07c3c60e18b13c1b7961c4ecbe81
b76d10e883286a979575888491b70ed7b58d05b8d3a9a84a9
KE3: 5455e49eb7421e5a75dd3a70ee5606fe65472cf6e1c9b3cc0f8f3a8642635ab6
4c65b7baadc3c5144b4590802612ac927150b7ef72d429cd83d5b90e44c522f9
export_key: 89ecf6a1ef6b497602ba56ae74538b9473687ca0b072fe3abc335c796
2f584f2348917f96d631e205a0cc0488b55db94bc2280c7f5d2b9d6e9eb529a4b434f
1b
session_key: ff2fad478708421b089f46e07d208184f233cc0f9b716b970f4aca1b
bdfcd422e51f053cee840db175a6276e88afc6339a087e9bebb89242bc297c246ff13
8cc
~~~

## OPAQUE-3DH Test Vector 35

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: a91ad13ec340178d0945dce72294a9a9e006e6b080e07d44dc8c0ba9e9
37b37491f3b78751c409cfccdf213ccf11d3b9a8082c0674e25fe498d5a0bf13fc219
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 51f9b8df987bd1dd4466c71f69aa4bb5e2d7d875c242d976e79bf
75e9b81d2bd
masking_nonce: 2ee1821e36981541a140342d076ed337f4eb87aeaebc7624e8fd13
bee87b4193
client_private_key: fd62874455ee10870acb5cd728e1e21943e18c3afc1fc668e
18c48250da37feea7768de6574b8b152dc64790a0fbd8ef
server_private_key: 9364031f78d6cfc1aec5bed89c718d3c8ff87115ed1526fde
d4495afe150eeeabc6195e48de31f2a5b24f798faea51fb
server_public_key: 03b73b7125c1d9517a42d63bf21b0c3eeed2b4f76005f72478
de3440dda2a2a580ef58077c145719505764689842231b65
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: f770b80e0b74f0fe64abe3da070da359b0d7a57b0d345f2f9c030c4
bd71e019c
client_nonce: 16564569f81b562921a85f59bde65055c3bd7e8bec8964fca23417a
7ff82c648
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
oprf_key: 61b3d30c4df52efa69b65ed2ad1e3e8b1db1c89c726097df98f19d28ab3
c4aaa5aaecdbfb3fb147ef7824a182812d6e5
~~~

### Intermediate Values

~~~
client_public_key: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab18
f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef0
auth_key: eb88848759e869f295f63656481d966b194d4d34479daa1a7374763dd72
e67fc89f7deb7b46bf4fe580359c3f02ede8929bbfc57ba4a22256beabcf7a4e02016
random_pwd: afbd70e44de194da57e7987ee0f6d762a752c72a5551e46c1d94bcb01
3d02bf6acb9e4aaa6734bb583fed40ba01f14f9e4d992619b39c92fffe35a1d3335ac
6a
envelope: 51f9b8df987bd1dd4466c71f69aa4bb5e2d7d875c242d976e79bf75e9b8
1d2bd41f5c2ed17115c1891ae50db3035ad9d68ab246a94d0851888f4f4e999255389
225bc7bd11780ee8c60579a90814303fd50e5d47728c2d0fb4c3c71a9555fb2183af1
cd5f42c5a1926cc2cc82eb60fd51c60908b2e02d122f922d0048c3afa5eec4a81c43f
184e5e50cb5916169c6810
handshake_secret: 33f91457d68ea4f213832825de6532ffc6681eba6bde443ba0d
36bf862da56c922651c967b186a4db67234a8cdc79dfb893709eb59c64f2316a42fed
46547276
handshake_encrypt_key: 03a3daba692ab9dedb8e2514a7cfd371725ab3ca97fee6
47670707e1773f81af8f1cd814537c37d5f7ff103dcb0518e9fd92e6df27d3d77775a
952c4d027efdf
server_mac_key: 853603d1765c11344239df203610d40c34c739c8d2e9162955eb0
791c1aa4f43e8bc61b1d5886868e9c09cf5dc0a92beb0990e7f38f515bddd68c678c2
2fdab3
client_mac_key: 332dfa7a50daab0545128f6c25d0454d0a80316c2a2d427e5f093
b62b2ae1540559bf86b2449db88892ea97bc84bc0ba001fe703579e10c3655905188d
cccc8a
~~~

### Output Values

~~~
registration_request: 03e0ffa19f9860931638c2a6a3fbcd8e0ec673cd39615a9
d80959edda6fc8d269bfc206586f1a10b46a895f8f17e730174
registration_response: 0209d0f483a301d01c27acafdd4fdc4435c4ee68eefa7c
c387557bbb6807a140a131f75b4f3548b91dd6aa7326829089fd03b73b7125c1d9517
a42d63bf21b0c3eeed2b4f76005f72478de3440dda2a2a580ef58077c145719505764
689842231b65
registration_upload: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab
18f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef0d194abeaedf055cbf1c
f65dc2fad700d574c25420be9ae689633c8fad4322b9633ac6af8bba44e7a58d70d92
67bdd395fd54841061899a2b71e0c9297e7d189951f9b8df987bd1dd4466c71f69aa4
bb5e2d7d875c242d976e79bf75e9b81d2bd41f5c2ed17115c1891ae50db3035ad9d68
ab246a94d0851888f4f4e999255389225bc7bd11780ee8c60579a90814303fd50e5d4
7728c2d0fb4c3c71a9555fb2183af1cd5f42c5a1926cc2cc82eb60fd51c60908b2e02
d122f922d0048c3afa5eec4a81c43f184e5e50cb5916169c6810
KE1: 027b40080d3b93d00403d4e7ce1944644d57cce6241c69181216ba7323afc9c6
2054300441470c06aff071717754a2fd6016564569f81b562921a85f59bde65055c3b
d7e8bec8964fca23417a7ff82c648000968656c6c6f20626f6203f07983f1b0b62e77
8918e7b15aa899a5c5c9fce3af75c5a424e114f3c9bc539cb3b290c4c4705829c21e2
185ab3eefcf
KE2: 03ab3249d3f06a222fd197776efb255d9002a2510f0b087b69fe2c416ad54f69
8799771869d9322b74ed2fba5686e11c452ee1821e36981541a140342d076ed337f4e
b87aeaebc7624e8fd13bee87b4193c3e5f93e115cd73c0fd5f59b93870ff37aa62f5e
e61a08bbb59c5400689b796b50edf7df08e900d77bb2b4e9f9c8afa4336c61129fc07
ede67875052047ffcdb18fbd9a8f88ac000ad312c77c60d782d84fdba13aa3bba9a1c
a18de67d9747b7d0d9022738beb8e7e5bc6f816da0207505d13a53415ac93862c4860
a9556a017f3f4daded9cb402c087bd535a87614119d25f1bb4f2f4464a004f2d543c9
9f851ec7f9359c1d40828ac478d66445ce5cd49a5546206b62c5bf4135420c266ce79
ef770b80e0b74f0fe64abe3da070da359b0d7a57b0d345f2f9c030c4bd71e019c02bb
887f84a3158bd1a95c26114059d1064a69dd87c8813ad1ab19b0cff29b48d0e945af1
4537ac16d8f4160bb027fdeae000fce5b72ee4ad2463c3002705f69d892f660967685
c9f47e3c3ef8b0e4a573eac3008cd2410ac06471d6ec28872d1cef1c2764ba6a71230
bd4f7d29f5cf7b3351e874ecf9784e0d2598fcd0db1eca546
KE3: 0b5734cbe97fba1343911e04f100907ced730ae27b3671bf8fb4362806e8be53
d479a126a1ce2b7097ce18a13827e276a5061fc4ac312894b3c5726823c54afa
export_key: adfcad909694ff52b1acddb814e9e878aacd5ab2d7e795533f71bcbc8
964d7d9341a5f83f3fff645b8e2d9c23493004f10f83bbc0429db9a342429c6391952
a3
session_key: 7fc04b4501922995bad7fa9843221585ca9cafed327df3379d20858b
67a38584effc1707feb0fbebdc6f2eb4e1e56a8650e873a0a28ada2ad75a00ca77fc7
a2d
~~~

## OPAQUE-3DH Test Vector 36

### Configuration

~~~
OPRF: 0004
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: ee326fc49e0dd56f492d40ce372e9084b64f8c37ab0e745fb0cf2dbdf6
7402795fc72dfa97ca11eeaf07ff8c2adf50aacc1e8d2be67e9d5ff1db71b0cbfa06b
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 57eb87c57354a9e70be9a670781c4fd9c841c9c7bab0470b87a32
733078d9b33
masking_nonce: 64bd3f80b3abe3e3c360e3077c4f2862061fb9bc4cd1cfb94f5cb5
493f5a8c3a
client_private_key: 4bbeadefc59f6beea6a2a9557781f5e37bb6ad6f76e66c82f
37070b975ef988bee3486703e469e30348af71c1050d94a
server_private_key: 8e510d60a068ab453634d9f74837185ea0d5483ac4f1dfd38
2792f1299390d98ffcd4e956fc02fe35df273276b75bd2e
server_public_key: 028beb3ce19f449deb6aa31eb19c661d4c4ba0fd08b4cc1e91
416b0c5b5ae74de003a76d68ac4f59b64b954717c4d843ba
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 4aef890299f1ec45e9ec5205cc93281ca420c15617d96fc7ff21eca
52176fd4d
client_nonce: 18b7f3078070411149ef8358f933e80a55e93c99b6f3e360665d9e1
924a508ad
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
oprf_key: 40c9916677cff682828b2ac80642289ae3ec91336904192ffc29bf23f36
b3ba93247e894603b7bb2db7a75b961f6002d
~~~

### Intermediate Values

~~~
client_public_key: 024954440156358f8db7a32b042020404c7918cfd0003699aa
1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce906040
auth_key: 0404997ddaba328c4cef990f0388a9d22dbfa2a75b523c5bb7ec35420f8
175fd34e42690d3690109ec5d580d0f8abd0233656c2bb29604266391149a71c59d10
random_pwd: 0a37e32ba538832707f46c43a6d16d8631a065a29d7a9d7a7f4ab1b36
6260766408af5f95ace4848c2cf9b4263e009818c7bf8046d20427f0722067846dc10
ac
envelope: 57eb87c57354a9e70be9a670781c4fd9c841c9c7bab0470b87a32733078
d9b339f78ba7c5dd4ec5cab4149781f35fa45dde303bc2843a2cc5143a94893bbfa11
3ae10a28b67019deb7bf423501d49eca9a6d7a2229a8907d10d93b485086bdb936c45
611fc8c94d4ae43dfdc7b84d2ae63957158857630b19fe500b23fb06ccbb12d9d28f2
5c4571d1d01586815777ca
handshake_secret: b38fb4d1e1944b940d186f6d9e5a6101d8085060c3d3bd75ecf
6a5697c6f2978b7be7b6930f24daceb6ca04505167896397722608b46c8c4ef87eaba
7f297c08
handshake_encrypt_key: afcade04886492439d82d359bcdf18d9628a58b7a9daa0
36bfc532cbb0047ad20e51c1939325776350975cf8c948694cf92da7905f072784f4d
6c5f5e3dbb370
server_mac_key: ef2e61eb156ef2de570f7f015aec690b6187d49de55a758b77b9f
83f8fb2d6935526cea2b3324e194cfd0a8347d50d7f2796d3cc73b0f7d56b43cbad08
f65cca
client_mac_key: 353dc66a50d5285fbc0363190a04834acb286b2373122bf393c01
77dfa9d2badcdc4aa777128171e3a1d4124104f1cebc00f201946e58d95333923ebef
49a22a
~~~

### Output Values

~~~
registration_request: 03a2e55f8d839d6b162d179f9b4f886337188f731db9ffe
0ac206b54096e6a9a8f30785c33d207ece91c4fb97530fd491d
registration_response: 02558087fcebc167f337095b97979d46c02dcb9933193d
5ab351da57966e8e6bee6846fee10a03be42b1aa78c93ac52692028beb3ce19f449de
b6aa31eb19c661d4c4ba0fd08b4cc1e91416b0c5b5ae74de003a76d68ac4f59b64b95
4717c4d843ba
registration_upload: 024954440156358f8db7a32b042020404c7918cfd0003699
aa1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce90604010e742be88e26e26eaa
c169d3105883dd6f02df89e393c60b27579f138fed3bbdcb5022244939cbbd6203154
090fe288f0f093765f6cb8c67962f394eb798f6857eb87c57354a9e70be9a670781c4
fd9c841c9c7bab0470b87a32733078d9b339f78ba7c5dd4ec5cab4149781f35fa45dd
e303bc2843a2cc5143a94893bbfa113ae10a28b67019deb7bf423501d49eca9a6d7a2
229a8907d10d93b485086bdb936c45611fc8c94d4ae43dfdc7b84d2ae639571588576
30b19fe500b23fb06ccbb12d9d28f25c4571d1d01586815777ca
KE1: 031b4f459c984d8a56589785181e03b93108602ccb92ef3e247651d9a9e72d36
0a93afc86dd79490fa621685779408ba3218b7f3078070411149ef8358f933e80a55e
93c99b6f3e360665d9e1924a508ad000968656c6c6f20626f6202a39a8a45c68e977d
b2ff70778f0d34c28f7cf430ca1045d4c48e6e749429f0f10b226c26cb0ab71bf2445
f6b9ccb81cb
KE2: 028054d8445fde951e90bb4d921b33ad467dfa860528fb22d81478904b8179dc
472ebac3c614f383517271cce0b781297664bd3f80b3abe3e3c360e3077c4f2862061
fb9bc4cd1cfb94f5cb5493f5a8c3aa3c7cb6ee16fe119eb3ec054c8bb6a1c6c7b7496
a1a6be7a2a9498e55ec15c84d9e906892fe1ed7e46c871b77e1976f2be78bf4f6f433
f4ab4b14eed116daee771b65cd2b09c0399b87b5fc6dd84dcf431d1f6f121d0b639dc
b06c6713b82c3adc825f70e0de46ef7a27f1264562575d885f090485ad7246c80a626
cbf06ce8ab03f159d2c2e99f00aec14c0ff84bc35e990c3f303a8bd126b0c8416c284
dde230f7582de6b30a2c2fab9a543a270a9d51964d49be67c0e898c3caf53b36448f6
c4aef890299f1ec45e9ec5205cc93281ca420c15617d96fc7ff21eca52176fd4d0363
57745dab9026251b2bfb2ccd847536219da8e475cd1f2dc4842206a8452c720e3ee24
c0abe77452903c64985b76a27000f8c6c2535f3c310e270763d6e189e1928b6c11941
d872cd2c520a4dd8af79f5df2c0c51f1420f34bb720897cab4ad1dd342e8c546c8533
8d4ca018202fa2fd2dbe9f713705d75d4face11cf286695e3
KE3: de65d8adb82a7169857f6b74ce9938377b7664d88dd104489771a85586964d90
7fe5c1607c363bf5e3030e8529ac3f199d2014c909c3f19d9e245211bc9764ea
export_key: b818442f1d00c7295d6a28deba068c07f159c1e085dc6e24d94a7dd84
1320134b4adb2074ba94582181d322187f16593b2eb9f48ca75ffa2e66d709f68a489
b4
session_key: 185d00b5cfd76a4a3b3d4e7dc0cea4553ab1e738b0313ec69e430a1d
d62f4e619d3f79125c123c8315fc4d9525b03cfc9d160dec811f8937ed6830177d3dd
7f6
~~~

## OPAQUE-3DH Test Vector 37

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 33a3671793a57f0369a3cef17874d24db14a983e69f995122cd0b07834
88cebd1272889862b538b674b01635522758a373c5ed2c44d40fc44506814db918ad8
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 5d79a9bc2f7b5f2d9ab664e1d6c8cdf45be64631aaa62b8262fcf
835117549d5
masking_nonce: 1f7f50d4fea1b0094160b68744049b2700538bb699439d1312ceaf
4b551ccaa5
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
server_nonce: c9e833d3fb3132640751e3a7b2088d7e663d6790415127a8d2455f3
8baae5529
client_nonce: 429258c4779a65a076cea82829fbc530a6c3aadfaca166d7848a990
10f9b5bb3
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
oprf_key: 012e2948514ec92fb9d347cb03a52717575276d94c8275d5ca1f39b24e3
c56ec2346188499ff2d375ba9a994a07e22a24ad6d2e3a8517236376da9693f472fb7
d1b6
~~~

### Intermediate Values

~~~
client_public_key: 0201d6bd681715e3d330475e72471c1218aa718d96be735325
1c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf1831f
811d49d120a8d45
auth_key: b93807af1dbb66ee3bf3a4ac1f3ed5df6201a25be9bed9b6b7832028ac2
195ae9705459ed539fc561737deb6e95092bd17742d30c2e2b8be63ad770c3a3d4e18
random_pwd: 83813e242baeb1789c3aa71e398d928d13bf15473e3b918361beef3cf
47dd95788030a87ab325ec1298ea4631cf11c7f6beb5e43c9343614326a27c459f228
ef
envelope: 5d79a9bc2f7b5f2d9ab664e1d6c8cdf45be64631aaa62b8262fcf835117
549d532a69873504edf07724602567b02da8633a0ab8f2d40b4af4cc1989090fab664
7080835ebebbe3de43e1a4619c7680d5ea13e575727bc5f6e636c34c64f52623c1222
66c8ddf4ebff66814d8796c5e4c9a451170258eb035d5aad3d338ec84c08b482c7351
82c76e9b85ac2214c980ce6fc42b98132c347a1b35ff93631c5b3f075e
handshake_secret: a43a80af2a25aed560da06a37b3f201afa4011816676ba848b2
c523f1db79963008a4e3bc323baa3a7380b79acbdb81578d3b3564cfbea11b16d8da3
f6c5b4e6
handshake_encrypt_key: aee99a7edf96c01d5e625ecf8d4869a7d9cd3524c77b21
824805864a2e5a31d89ade2db5534bfaa3c2107655f02e458c455e2df4ccc0ae198a4
d1323f87cddfa
server_mac_key: 87a9279710903fe706df9b3d85e6aaad6bb87742a61a8029c8372
e3910b2570f7f912815113c34d8ce0fafd511365a30a53bcc202effb079864ed824c5
7d5218
client_mac_key: 5e5157db9dd17d7c4d72df9178ef141e526359dcd1157a444b3cd
b5806e2fd530398b9222905e379f3c4af9718ee4683f4e61dc8d5cbe9873c7e355547
34e1e1
~~~

### Output Values

~~~
registration_request: 02015d0cf2aa22e0448949416bb4b3c246429439d4cee47
a52b3b9874aaf727dbde7f34b5112e91e97e1d98c9cb0fb58e015721456160aadd16a
d4f9a9ef2fa3d0ad8e
registration_response: 0300472e53b09af98e38d565491aa8500307955b390d8a
9418e2d285e2a059ecf47fafe4238f0fd8e10bae5165b61e221a7e8c40c06f003ec3e
62fd21d96ab39f6a0b303018fc6a77bc4127886d67871c03462740fc4d6fe66dc2226
365e994f8392a0b4c43cd6e67ce90ad594cb63c146011dc56b213bd42ef677cb6a5f0
1d0bd9944a9161a
registration_upload: 0201d6bd681715e3d330475e72471c1218aa718d96be7353
251c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf183
1f811d49d120a8d45934aea02900cbb8692f48f14651dd434396a5ce7d8291707bd41
a39414611bd850da9807adcd61d862bae72abd6e9f606a2d0e6ef2f2568d76fa7a1a6
4bbd6855d79a9bc2f7b5f2d9ab664e1d6c8cdf45be64631aaa62b8262fcf835117549
d532a69873504edf07724602567b02da8633a0ab8f2d40b4af4cc1989090fab664708
0835ebebbe3de43e1a4619c7680d5ea13e575727bc5f6e636c34c64f52623c122266c
8ddf4ebff66814d8796c5e4c9a451170258eb035d5aad3d338ec84c08b482c735182c
76e9b85ac2214c980ce6fc42b98132c347a1b35ff93631c5b3f075e
KE1: 0200c3bce8c2c7da1856b486576082a136f031304eeba82c3e582d920469621b
9657d018aabad67dd15d32492f0155ec944d11593c079c64c5d19088a72cddb12baaa
4429258c4779a65a076cea82829fbc530a6c3aadfaca166d7848a99010f9b5bb30009
68656c6c6f20626f62030080bf524d28ba64b134c0bd0c860c8b1f976e55d94eb35d4
2aa0cae1935a185c9f7c517875877aac4aa4e909dd5f25cc6ccfe125d031dcfe02459
7af1f7bfb5ed89
KE2: 020162c9ef4de57c5c3b665fbe190fbaca97dc8a5806cbd2faac0d9ae834cbc4
f686beb9d9e9efcd188f6e0fe1d567228923c7a881f1dbd570463ce268fd474f5e010
71f7f50d4fea1b0094160b68744049b2700538bb699439d1312ceaf4b551ccaa5c284
1a3606158d79756814bcea1b8093f23f2c61eb55e8dc249728fff42156e80b989b2d3
26e36c3878e5de12f25057c80f5fd280a56c34862a52f976f91605812fe71c8e2ed42
0d1e34d912632d90d096a5049159db3e4ca6251338d74903ad1e3b7f0bd789fbee193
1bf2561b33f0be69a9e5f451effe5624455378bf8b768c2fee9fcac294e47f850b0cf
57409814776e119bae9c2ee1654733e07b504f19236b9ce592e77bfdc8cdd2144ea83
4d5a274ec2b1b6ef961d58a6b893d866d67f0abaee9274ff7949052a9031903befb37
0da8ab4f2280e2f79325f4125d803b952ca22d21c9e833d3fb3132640751e3a7b2088
d7e663d6790415127a8d2455f38baae55290301ff9a97a3a4733b144d38330209bcea
5a6401eb4e08e0697ac4dcb8369e20d76d32c34b619c424d643dc47bd680c0ef66540
4643d2961ad051a7920c318ecd948f0000f9c4042aaf41d7ecf5672500b1ea4da892f
4f3e2e590a0001306b395e486e325960f4cae50fe69c73d72e9e48abdf32f2ee2f220
99774f33b405e3a047d336fbd1666564756f94c6d51cdb1c421fb49
KE3: 000d09b78bd551ed11677dcf11e03a89532402866c73eda78f757e9572d57716
4208b7f6f7b9f2f19eead3ed6d003ebba4ddab0d0f40f5bc9b9e9adc952796ac
export_key: 0fc7b2354fd91304c0dab1a43510cbc1ccaf9b5197aecb603545b9558
808cc50c0c3fbfea7718e0070c61fd7163e1103d4e3d5ed8cdf96643f0ab62fd5b598
18
session_key: 2e4fc6b1f0d084fb3b90eb49a2f151a4e7b729e3fd99de2dd77a060f
f61e66c3c06524e35e696eff5190f41720d7f3b247f60dabc9266bd39429cc7485c25
77d
~~~

## OPAQUE-3DH Test Vector 38

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 36bc12a486d171ed103cdf14c43c9f373cc316e379235080cd9b9698f0
8786e640c0727571c6fb5c296f44a0eb5fe33d9c424532297a72d378f821a26577224
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 252fa4e41d669b2658edff0572ff3cc10391c17eefc19eec475f1
e5cd6dd0666
masking_nonce: 8e0784d3053cc1fe568c431402c9ef623f2d0599a383c59650baf7
cd6f71bf9a
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
server_nonce: 5214be7760537d24771b34debb141a64b53f3c6d35c272ac54f0793
9eb1356ee
client_nonce: 9781741246dfc0a5a76b39dfb5a800013bcc1419c56fcd7ef2124f6
ebdc8a984
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
oprf_key: 00ff150ad6540343241a1506babbf63341dac444150d84c10a729559b29
7ac79bd034761085c84a900e2e20447cef8f3449d0d831aec0fcd0ff4bbaf0e342a20
cfa1
~~~

### Intermediate Values

~~~
client_public_key: 0301347c5fb96ce61b57ab45d42005522f77483664bd260ec7
f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a8290
cee86e55fe23462
auth_key: 86d495f20746bb13568d893888df071d65a95029cd0ed11a9ac00cbc6a4
c747bde03d8ae027e3e958f1ed703391deb05b47ba516ae885651d891ea5c8af3e9fc
random_pwd: 00c0a12bd9ce6e8b9008871c6c613b3197a0bf8345112c1d43507df91
56fb17e3a804ca8b4539a426561c6c83af0f5cac301482df418c86c662554cb120da7
f8
envelope: 252fa4e41d669b2658edff0572ff3cc10391c17eefc19eec475f1e5cd6d
d0666239e2b2b490f4214b81e05333699d7f3f85f24b00d621259ab4cf10b75837391
06f8b9826edcf0dc03f70a5dad5f6c42c3df60e0a81b084369a17140c8e2a8a076a4e
fda65dae62797459a604412379286aec60543dc58f3b36b9bb7e33248732a7598030e
f4dd6b3f87535a4d37c6225f09f9ecca6be2f27a2a295bd5d0b0ff9677
handshake_secret: d408d8cf91cc03f545188b2557f774456f81773302a9db35fee
0089425ea8946a700720715be9da38f8c8a8478ec4dc27beae863df998005a3f36188
d67c7f89
handshake_encrypt_key: bac7bdb188c9120976489609a7148939a2ce0b233839df
c2334c79f8440418fd8bb7953c0798143129297ab41e0606815ec1fcc4446638fde01
aaebd6087c3b1
server_mac_key: e337358b291d4aec331720425da20bd05e9e52c00dd4d37807cd2
2b316dc944cf8ea944367ffe18b657d41373aa5b81cdbcdfb56e3102a89ca7ee3a641
6a4729
client_mac_key: 00c2b77daf12b49519d7bf50fb667406a9da066fbe451fc82fcc7
554930bdb4020e5c1a8eea34d0ebb29e06f707b8c690f9325eabc1e0ab9952d8fe57a
2bf966
~~~

### Output Values

~~~
registration_request: 0200572541736c54fb88d0f50d1080d98cc390cec131e56
c5e3d038122c6655d23defe37f0946f3d3b5dcf73545a6df6277e20f9b377591bd443
034fdf53d008028969
registration_response: 02000d9cc124f69d89d3695ee1a8b00e8f3eccf2890ce0
32d4f5b3361bde5b7f5d3678c95e090bf687ddbe6279b6e8f60f514933aae7d3725cc
c2dd731ccc66b8fe8390200e85b446310593c25258991eeb8da130df718df2efeee93
29b6d6c7a3906749464ffb90f8e43122192f8e77b9f04f708aa5f9ecca9cbeab701f4
9929d82395d9928
registration_upload: 0301347c5fb96ce61b57ab45d42005522f77483664bd260e
c7f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a82
90cee86e55fe23462de285246d430e8e10ca96b84fd44363a2f8e9bfc216f89444304
c9393fd3c49ebcc471076606679216262288eae2fa0ada235068f95667df9ade41942
1ac2154252fa4e41d669b2658edff0572ff3cc10391c17eefc19eec475f1e5cd6dd06
66239e2b2b490f4214b81e05333699d7f3f85f24b00d621259ab4cf10b7583739106f
8b9826edcf0dc03f70a5dad5f6c42c3df60e0a81b084369a17140c8e2a8a076a4efda
65dae62797459a604412379286aec60543dc58f3b36b9bb7e33248732a7598030ef4d
d6b3f87535a4d37c6225f09f9ecca6be2f27a2a295bd5d0b0ff9677
KE1: 0201147f07392ddb5ab846130ce65a4c16d1eb26735fec1de7716b2c8bc935ad
1c65ebc30a6449adb8504b41fe61b9634a1ac3e429e03db700e6e6f852469e8e83bec
49781741246dfc0a5a76b39dfb5a800013bcc1419c56fcd7ef2124f6ebdc8a9840009
68656c6c6f20626f6203001f619d901664fc0a4916b616bf340eafded4dec3c9af08a
7d89f9442bf41048a8824f22d5ce906558f99250ba96a112c5ccf2ff02e062cf9158d
fbd1abc4a48e92
KE2: 0301ec538235e6051f482d626eee057408a1b03e139bef9c3ecce7263f556329
a60f3fb1fbe73c89d0b984ae399ae007ebf7a48f9dab9535fe3b043c859bbd8456026
38e0784d3053cc1fe568c431402c9ef623f2d0599a383c59650baf7cd6f71bf9ad0a9
c0c9f888ec8c8c6eec49b0bd7d47b83ab5fa207476690e8010ca66eba9c8e20b52268
d25923510af40bcbed79a3dc0bdc4ca773320b479fa0d63675fc02d4b0fd3ec900f7d
308b754519a93233d0d73fa37eba42afc66c6cfdc84a21557c1b4ea72106f65ce0e90
bda2621f9781c1a4ffe31a7ca45988a11a684ab39db169ba8eb133a22f76e029660fc
760506dfaef9d64974d3782ba5abab080130312f2482f6bae0d8f6e9e23a3893b3eed
718c8a858490174b60374e1b15269b80ee5297ea9441771be3f2054e29bbd5f162db8
58db7d8b5e557b62e17391e838a42b313e1da3b15214be7760537d24771b34debb141
a64b53f3c6d35c272ac54f07939eb1356ee0300ffcefd89e8ee736b4e6149934a1040
b8691ba4bc58b160d8c526e73cb99d7c45ce09264ae268a5afd07c1a3db59c5feb920
3ecffc694a41b1138deb9a11d6fecbd000f63250f6281585199ef3ee31e94956c7283
968257a457997538dcc4645ed6031cf2a4911f55d3817c362ef5cab7a61cec5c6911c
adcd57c5b905723481249d659767e62de0b8241a3534a0efadd1f62
KE3: e252410ef8adbc27f4ba148f3a6dd18412107413ccba1095be1fc2015788f212
76d149ece08850ce48160028b7495a1f39c36b7cb8c9cac8f81d703d8813822a
export_key: 5c551ebc735df1e370b7eec682b745ab724f5b5f31753c94fc525fd20
2c093dd803207b637d1bd8387c4d850a513d2e202d4b046d826efa8cd26e5231c1729
33
session_key: 68d2c58f6bc280c997e03801a902cdeba3b8898c472f1caf5640e2b8
8f66dc22a2bbabfbdee63b06176fcdb6d89edb3cf925c3f0133aafcac2052ece71403
183
~~~

## OPAQUE-3DH Test Vector 39

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: c49d24d684e08a0e2884d5b57ceb7fa4797231c3b1c5d1b2484dbaffe3
63f3c89a17d65313d263f83f8859a0e3968302f55b87064d0abd622c65aa2c155ca8a
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: c5c1afb4aa401e405bc2d13ac2e33631b24e6f2325437a4b2d98d
109c0b0f224
masking_nonce: 73a93750e011930fc4f7b28df901d252414a724317dfb84b662e43
3bdec6dedf
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
server_nonce: 6ed2d2bf3063fcb83f99047b1fc119468adbf9f960e94f425e8d0bb
ef93f4d6f
client_nonce: b7a4c42dcabb47896d72041c6596db9aca7607c1934907af16eec3c
d60ac24ff
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
oprf_key: 0007db5f9bf6227bd1aed0dc1f9a4e20d453a3deed2bc227b60e288252b
872bd8c63ea04ec4deb972cc3bd5b408bf96b9aeb5420e6be5a4a61b04278269fc8f5
9c15
~~~

### Intermediate Values

~~~
client_public_key: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4ca
15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1e7
ee4c024556f0808
auth_key: 7647ab1866bbdb4c4455a41f233138b488e49ce0c8d975c08b9b879eb31
f226a1dc2097c9dd7bd093370b9cde3e4c84c4aa9a79628aa8093644949bc494623b4
random_pwd: 574e008676480f7ef1ff6b8d816c2c55b143bedb34fa2fcd0665d196a
50aad67483a0f48aace766939d88fec8810e170cea3a4f365fed8a16748626ab171c0
ef
envelope: c5c1afb4aa401e405bc2d13ac2e33631b24e6f2325437a4b2d98d109c0b
0f2246d956dc075bda0bc0bc7871ffe6f54c9b9aa00aaa61498339bd11f6ad81b6af5
6605d4e504387e74e2f0c4fafc71647536c84bff3a6ae90c8e358158f80b2b3bd20e6
70ec6a337b0786ac549d24d17135029db3232f2990eddf1130968a549f4bd187456a0
805cff57f8782547de522a99a46dec7afab439ad5ee0f859b89218161c
handshake_secret: 8987311d8d195f937f7aec23abbae7c2bd3cb5a4162c8c2d58f
88754b9d3ffd6f222312e05b85282cfa7fe94c784efaaf8df7864bfeb7872564a0974
93f0541a
handshake_encrypt_key: 9158456ef7bcb003af38c3e2ef5ca55de94908206453c7
d6c045d729ad749727334aa890ddbd6cb86bb9327dfa08888e88b597ba426ebfb80cb
129d978addb95
server_mac_key: ad4c079ea07bd9ac9e5ee3cac5d1f4ca95ff2f2a3a42262f9cab7
c5a2f0ad0af30ac6c79e36be8310c967f2ac631a2556823b9b6b96c37a4afd2a9660a
9cb583
client_mac_key: 035a9ccc28f279fe0017c09242fc52c65b4cea480b99f709af9e4
50770d446591d2fb00d5c6739d32c57451c7a26a66a1262440db67820b4e2c1f4c786
bbbeb5
~~~

### Output Values

~~~
registration_request: 02000c53a2fa3c1dd1ed747b297b82020f316ee5b38d5ad
d8bfa68d9c6eb9b22ac651badd5d5751e7371cae832503f66442cdc156414f4a5ba0c
2db08b33530cde8dec
registration_response: 0301c65fe2a4b15a3a4acb63aa86323c4c29acb3245b16
50d8b8d6cd71d1fafa9bb9eef916de30ef0d2aec374d95ff394db9de4a309ae6ea8ff
b77f22d148a9cb82c830201a6573b69f46bf93cb3f18e2510c753f689097b7b96059c
3ca8f8e45c66a03b694fd8618c9a52c4104ca42186438849e73613cb25fbd4ecc16c5
a65f95345686984
registration_upload: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4
ca15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1
e7ee4c024556f08086a2e5ea1562691e77fe874a250c30edc24a81f3e09eb661c039e
404743d53f8beb87497c42576edee0e454aae4857c98d882dd1b7ca893b68f8f698fd
48f10eec5c1afb4aa401e405bc2d13ac2e33631b24e6f2325437a4b2d98d109c0b0f2
246d956dc075bda0bc0bc7871ffe6f54c9b9aa00aaa61498339bd11f6ad81b6af5660
5d4e504387e74e2f0c4fafc71647536c84bff3a6ae90c8e358158f80b2b3bd20e670e
c6a337b0786ac549d24d17135029db3232f2990eddf1130968a549f4bd187456a0805
cff57f8782547de522a99a46dec7afab439ad5ee0f859b89218161c
KE1: 03014f2799259882d01af61644db264602a3486a32f6b510aecb336456ce58af
6cdf6f5630ab4e3e7081f1e99b1688558f0a1bf15da34b7c0252f1036d916928a0f33
2b7a4c42dcabb47896d72041c6596db9aca7607c1934907af16eec3cd60ac24ff0009
68656c6c6f20626f620201e2f40c1d877219e9512862469e31da268ab014fdce9cb3f
9ed6b27fc01fe6d9b1ec37c6cee76131139ccc3eee0a35438250e9ecaff6cf223ad9f
a469dfaaa0f0a5
KE2: 03002e6e57758eb563357d8fe7155c10f7e078101ec156ce20e7eb3661304c0b
3386e86c02fb2aa463560637c9e95720e1ab7edc6a8c74aa939fb5e1cc960eb21cde5
373a93750e011930fc4f7b28df901d252414a724317dfb84b662e433bdec6dedf766a
d1560373b3423058b060dae864b1935ff032b73afb87b9ff95c12841a5ae349a2f159
455b2a6e53e2546e74650763dd1706b7bd1594abfbeed13fc23c116838f81339aa61f
50ee5d91627d82c070864e1be3b8df9c77e3dc4ca4f381f82576468bc31848085bf15
4ea2fc1ca12c33b156f62681b2bdd2b9d080af5ed8e3f71796e32314ee156958493a4
b79eb52d4f549e39604de14c751991df968e893affb26489c8ba5dd8eb7bb897b86c9
eba611422e31af92d77248f4869f108fcedec55796caf4dbbe669a9c4e362e8765ea9
0920d8808cb5002c396d905e7f0281c2c34f24236ed2d2bf3063fcb83f99047b1fc11
9468adbf9f960e94f425e8d0bbef93f4d6f030029562d54d53c7c51651334989bcc95
b45a1a07484448ef72bab708b55322b49a43736afc60bf85fc05d3c1d8b60a0b55a83
e37befa115e9625e00f35c1eeae27ba000f64b93948b079af44a97bea33360f032e17
ad32971be1f3d3b5bd31d0ca7848ef6d2590e593e82be7658b2616a42cdd0b29faf10
9cb77bca28d9ed159d8a871b295d8ce6f8fae7ed0919f18dce81c78
KE3: 8c6258751caafdeb8e7e12a303d2526fba30559c4476d6f684e7969dad978d51
fd7ac16b8cb4d3d8e3c8219a9bdeaf6b78bde40c2ef86ab110d2f59d32683b33
export_key: 1b824cf1ae893080c356e80e8f67d7ae57daa08219efb3921f9b502eb
d4047c3e661fd71bfd87319b429c31c9c19af4d966f693001f2c3585ce631eaba48d9
f9
session_key: b89ab6a9187a718247ce764bc350809c892898f8e89b1ae07f34f59b
d0aea21275ea1db36e9b032b43c225323bdf28ad37907925c46286094c3dce08ebe1d
326
~~~

## OPAQUE-3DH Test Vector 40

### Configuration

~~~
OPRF: 0005
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
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
oprf_seed: 30391e789b23defd2157684475ac8e0072c745191634c87a5a6f12536b
f75736995683f0c1d0cfb4561b840f6d614038bf600a0d2478daa06e43859459ccc4f
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d8fabb831225a425d1d00c20468094095e062285e86cc7aee95c8
4ce7087efcb
masking_nonce: e39c94d36e0faeae52fd294bae548ecd6310a5f298c175bef4f585
db995a12ee
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
server_nonce: 9fe6b6aa7df25b49127ae2ee76c02f9f604e17d5855bc2b790bdb68
32ccc615d
client_nonce: 3b48f9aca2f714db4094f74ff1da4505347e9cf5276813f32b23b21
03e1f16a4
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
oprf_key: 001c1fcd9454ecc3c8305afa432cb62f8f1ee8218cbf38b10a282eccde2
7d192ccdbc64a7cc7d3217f15e141c8585fdd70b78702988e3ed2cdd8a7c192d17dcf
f5ab
~~~

### Intermediate Values

~~~
client_public_key: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fef6
f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea03
e0379fb9127abe5
auth_key: 3a6096e30b42750dd83107d4f6179a7f0abd51b8e2e889165e6508c3466
f9985d3bb633bf22ccd3cf363ab15f3f9342ef06d7bb8fbaae114ba503bde3d5a0af8
random_pwd: 85d87f753ac795a72185e52c93c2c1edbb41f7adc84d83be30e4213f3
b32bbd6116c75cd7cf96df1900df934908af68011fa44397a43c97e8d93ee8710b0a0
86
envelope: d8fabb831225a425d1d00c20468094095e062285e86cc7aee95c84ce708
7efcb682c3277e812d6103119f8754e6697dfe8ef35c311a002d2a2a8860511583f32
55f408b1e896612e232feeb46742e9f46793d91759db118dfc1e6d04bf1de89045366
02d8818eb0e296d101cb4cb3625e174e1f12bd3b3308ddc0f0669665e57351df23eb8
9d2a676eba2e2d9978df8b01b6f2ddc5c8689f7fd78081d9c978009fe2
handshake_secret: 1d6f5bec50be444abf164bc22b4ec03a79071bd10c2a9c1f085
8d9b2ee173d7d93172814478864c3db9e4514d7ce1f030c4753cd16247ee994762250
917c646c
handshake_encrypt_key: e53f2a0794c4ac41006147795210f5fa17eb36746894db
efad63dbf93185a95c2141a8d714e1b87b2bc7771d45f875f4930d37b79110a00cb71
822a5a192e59a
server_mac_key: 82e32188524882c474b6ccbf8991317ce06f66b19df7c67f3300c
c05b5fb7c68cc6fe53993fb22febf01fcb2142057b55aafad3cab39a807b219bc1bd3
a6d893
client_mac_key: 86cbb80256f89b4cf2af060124449978214ccba58037c40bd026a
ea090fd308636869ec849b7280edb95e73f0f21f65633bb9975e2417cf172689029aa
f17f87
~~~

### Output Values

~~~
registration_request: 0201d22759697d1d91f6b1812d14acfee093886e889d913
cdffc78de009924d3d80a7aa9384149f163fd706498375c34402df2ccd8c1283cd250
477ce032c9e7c78ef8
registration_response: 020170af143a1ae290beeab128011e8f69b480b247af3a
d5200258ac81abbfb5be24075281d6859cf86e2aa2e5323dd18009db9bc5d11903fa0
5802d9f43a56406c4360200f944f464cfcbdfe94b720c0a59487456cca17580dd1982
4532d540642aa4017edec0b9308bf4f4fc00611115a145c1374680847e4815f6c8dd7
febdecef64998dc
registration_upload: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fe
f6f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea
03e0379fb9127abe5ec405238d99bed58a7d6724a0e7eaa4dc8605930356ef4948469
bd257dd0f83e9bb94734f704ce4d1e5f982d3239705b48b80d33688743baf0c5c58e2
d66ec53d8fabb831225a425d1d00c20468094095e062285e86cc7aee95c84ce7087ef
cb682c3277e812d6103119f8754e6697dfe8ef35c311a002d2a2a8860511583f3255f
408b1e896612e232feeb46742e9f46793d91759db118dfc1e6d04bf1de8904536602d
8818eb0e296d101cb4cb3625e174e1f12bd3b3308ddc0f0669665e57351df23eb89d2
a676eba2e2d9978df8b01b6f2ddc5c8689f7fd78081d9c978009fe2
KE1: 02002c6e65b998d160fbbde62484f39c2678bda170db547005889379b570e83e
4f6aa45200a183dc5cbf014bc7f94f28064bae53132dfb3a0736bf7b806b1091ce541
83b48f9aca2f714db4094f74ff1da4505347e9cf5276813f32b23b2103e1f16a40009
68656c6c6f20626f620300c566f59e65c950d86356e925ce1f87b3d4a7a9b2e556ece
f17041679c76f8afd8f7b1e9fb82549886fdedf29e4e86564475b0c2c200a9c7a4e08
9e846932e07d36
KE2: 03011cc1f78ce51c71959925a0ee41fb6c76ca6b6b1e88b0b96bf4a085672d99
a124eff1eeb45fee775fb864cc84f0f263e44c9c296c38c526fdcaa11d153fb91a512
1e39c94d36e0faeae52fd294bae548ecd6310a5f298c175bef4f585db995a12ee92a1
4d8efa7163a8ba9bf41858faae65d58d0d224d1050e72a1850259d5bcff09610ca5cd
6767055ccb891da98bf2304b04ac642c241a5bb071cb292038da462f3381a7a711475
b27ca7220b9d6e20f0800c54ed9a885cc8b736b779e86c03f6efcbb79d0d29a298404
55492f99d2b47b470ec8669f488ca9a153dc1e8535cffc4ad910cfd550f395bdf8201
a3c520a9e1b41b19d10b461cbd01193334e3349665ae41dea5255a364cafb60629cbb
27c36f5407fcde891e43e3feeb784f5102f63ee7ddb01c125e129b3aed545d6e9d186
329d38fdfcf311287159707fd85f45228dcdb31b9fe6b6aa7df25b49127ae2ee76c02
f9f604e17d5855bc2b790bdb6832ccc615d0300ed0fdc747de2ff4797c4b18da821ae
9ec83376c51d00a51b2d1701e5689e8dd720cca6fdd1a548b5b3ad34015006ce4f754
8be73295e07f15f8b0c60331cb65160000f021e29d553a8efd942a6961b71720cda56
12fe82d79acc3d1f61d32ed60b6ecc9d4a777cfcdaed7fde1ab082246d3585d713c65
3e3d0b4b5b706c141948c87daea57e8403b6d8f6a1f7a64226a3900
KE3: b0db13d1326c1880ebfe783fd7fc097d267e43cf4222a2f903e316fb4621f476
31322f613dd3d851acf32ae26c6fdf3007afc0ba1d131d175c27a9c836c0e111
export_key: 6dabdeaf4aa065bba51b8d6b922d5d3c24661762a906d665d54e405a2
eacbd696d0b730d144cf6c99a1c0447b93a1a4c494c97350724e9edd55397f6fe7eca
0b
session_key: 7761e4a34ac13a92db8ee44ac9c2868fd46b380b611672df0a42cf15
063247f86cadd80062cfb47827cc1550b8dbb8b332827ce348f90621b4dbcc0a2ab30
b74
~~~
