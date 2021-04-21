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
This document specifies the core OPAQUE protocol, along with several
instantiations in different authenticated key exchange protocols.

--- middle

# Introduction {#intro}

Password authentication is the prevalent form of authentication on
the web and in many other applications. In the most common
implementation, a client authenticates to a server by sending its client
ID and password to the server over a TLS connection. This makes
the password vulnerable to server mishandling, including accidentally
logging the password or storing it in cleartext in a database. Server
compromise resulting in access to these plaintext passwords is not an
uncommon security incident, even among security-conscious companies.
Moreover, plaintext password authentication over TLS is also vulnerable
to TLS failures, including many forms of PKI attacks, certificate
mishandling, termination outside the security perimeter, visibility
to middleboxes, and more.

Asymmetric (or Augmented) Password Authenticated Key Exchange (aPAKE)
protocols are designed to provide password authentication and
mutually authenticated key exchange in a client-server setting without relying on PKI (except
during client/password registration) and without disclosing passwords
to servers or other entities other than the client machine. A secure
aPAKE should provide the best possible security for a password
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
against pre-computation attacks and capable of using a secret salt.
OPAQUE provides forward secrecy (essential for
protecting past communications in case of password leakage) and the
ability to hide the password from the server - even during password
registration. Furthermore, OPAQUE enjoys good performance and an array of additional
features including the ability to increase
the difficulty of offline dictionary attacks via iterated hashing
or other hardening schemes, and offloading these operations to the
client (that also helps against online guessing attacks); extensibility of
the protocol to support storage and
retrieval of client's secrets solely based on a password; being
amenable to a multi-server distributed implementation where offline
dictionary attacks are not possible without breaking into a threshold
of servers (such a distributed solution requires no change or awareness
on the client side relative to a single-server implementation).

OPAQUE is defined and proven as the composition of two functionalities:
an oblivious pseudorandom function (OPRF) and an authenticated key exchange (AKE) protocol. It can be seen
as a "compiler" for transforming any suitable AKE protocol into a secure
aPAKE protocol. (See {{security-considerations}} for requirements of the
OPRF and AKE protocols.) This document specifies one OPAQUE instantiation
based on 3DH {{SIGNAL}}. Other instantiations are possible, as discussed in
{{alternate-akes}}, but their details are out of scope for this document.
In general, the modularity of OPAQUE's design makes it easy to integrate with
additional AKE protocols, e.g., IKEv2, and with future ones such as those
based on post-quantum techniques.

OPAQUE consists of two stages: registration and authenticated key exchange.
In the first stage, a client registers its password with the server and stores
its encrypted credentials on the server. In the second stage, a client obtains
those credentials, recovers them using the client's password, and subsequently uses
them as input to an AKE protocol.

Currently, the most widely deployed PKI-free aPAKE is SRP {{?RFC2945}}, which is
vulnerable to pre-computation attacks, lacks proof of security, and is less efficient
relative to OPAQUE. Moreover, SRP requires a ring as it mixes addition and
multiplication operations, and thus does not work over plain elliptic curves. OPAQUE
is therefore a suitable replacement for applications that use SRP.

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
- I2OSP and OS2IP: Convert a byte string to and from a non-negative integer as described in Section 4 of {{?RFC8017}}. Note that these functions operate on byte strings in big-endian byte order.
- concat(x0, ..., xN): Concatenate byte strings. For example,
  `concat(0x01, 0x0203, 0x040506) = 0x010203040506`.
- random(n): Generate a cryptographically secure pseudorandom byte string of length `n` bytes.
- xor(a,b): Apply XOR to byte strings. For example, `xor(0xF0F0, 0x1234) = 0xE2C4`.
  It is an error to call this function with two arguments of unequal length.
- ct_equal(a, b): Return `true` if `a` is equal to `b`, and false otherwise.
  This function is constant-time in the length of `a` and `b`, which are assumed to be of equal length, irrespective of the values `a` or `b`.

Except if said otherwise, random choices in this specification refer to
drawing with uniform distribution from a given set (i.e., "random" is short
for "uniformly random"). Random choices can be replaced with fresh outputs from
a cryptographically strong pseudorandom generator, according to the requirements
in {{!RFC4086}}, or pseudorandom function. We define `nil` as a lack of value.

The name OPAQUE is a homonym of O-PAKE where O is for Oblivious. The name
OPAKE was taken.

# Cryptographic Protocol and Algorithm Dependencies {#dependencies}

OPAQUE relies on the following protocols and primitives:

- Oblivious Pseudorandom Function (OPRF, {{!I-D.irtf-cfrg-voprf}}, version -06):
  - Blind(x): Convert input `x` into an element of the OPRF group, randomize it
    by some scalar `r`, producing `M`, and output (`r`, `M`).
  - Evaluate(k, M): Evaluate input element `M` using private key `k`, yielding
    output element `Z`.
  - Finalize(x, r, Z): Finalize the OPRF evaluation using input `x`,
    random scalar `r`, and evaluation output `Z`, yielding output `y`.
  - DeriveKeyPair(seed): Derive a private and public key pair deterministically from a seed.
  - SerializedElement: A serialized OPRF group element, a byte array of fixed
    length.
  - SerializedScalar: A serialized OPRF scalar, a byte array of fixed length.
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
This specification defines one particular AKE based on 3DH; see {{instantiations}}.
We let `Npk` and `Nsk` denote the size of public and private keys, respectively,
used in the AKE.

- Deterministic AKE Key Generation Functions:
  - RecoverPublicKey(private_key): Recover the public key related to the input private key.
  - DeriveAkeKeyPair(seed): Derive a private and public key pair deterministically from the seed.

Random nonces used in this protocol are of length `Nn = 32` bytes.

# Client Credential Storage {#client-credential-storage}

OPAQUE makes use of a structure `Envelope` to manage client credentials. This envelope holds information
about its format and content for the client to obtain its authentication material.

OPAQUE allows applications to either provide custom client private and public keys for authentication or
to generate them internally, making the application oblivious to the client's private key. Each public
and private key value is an opaque byte string, specific to the AKE protocol in which OPAQUE is instantiated.

These two options are defined as the `internal` and `external` modes.  See {{envelope-modes}} for their
specifications.

Applications may pin key material to identities if desired. If no identity is given for a party,
its value MUST default to its public key. The following types of application credential information
are hereby considered:

- client_private_key: The encoded client private key for the AKE protocol.
- client_public_key: The encoded client public key for the AKE protocol.
- server_public_key: The encoded server public key for the AKE protocol.
- client_identity: The client identity. This is an application-specific value, e.g., an e-mail address or
  normal account name. If not specified, it defaults to the client's public key.
- server_identity: The server identity. This is typically a domain name, e.g., example.com.  If not
  specified, it defaults to the server's public key.
  See {{identities}} for information about this identity.

These credential values are used in the `CleartextCredentials` structure as follows:

~~~
struct {
 opaque server_public_key[Npk];
 opaque server_identity<1..2^16-1>;
 opaque client_identity<1..2^16-1>;
} CleartextCredentials;
~~~

The function CreateCleartextCredentials constructs a `CleartextCredentials` structure given
application credential information.

~~~
CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)

Input:
- server_public_key, The encoded server public key for the AKE protocol
- client_public_key, The encoded client public key for the AKE protocol
- server_identity, The optional encoded server identity
- client_identity, The optional encoded client identity

Output:
- cleartext_credentials, a CleartextCredentials structure

Steps:
1. if server_identity == nil
2.  server_identity = server_public_key
3. if client_identity == nil
4.  client_identity = client_public_key
5. Create CleartextCredentials cleartext_credentials with (server_public_key, server_identity, client_identity)
6. Output cleartext_credentials
~~~

During protocol execution, the identity values can be stored in an implementation-specific `Credentials` object
with names matching the values.

~~~
struct {
 opaque server_identity;
 opaque client_identity;
} Credentials;
~~~

## Envelope Structure {#envelope-structure}

A client `Envelope` is constructed independently of the `EnvelopeMode`, but offers an `InnerEnvelope` entry
whose structure is determined by the mode. Future modes MAY introduce alternate `InnerEnvelope` contents.
`Envelope` is constructed as follows:

~~~
struct {
 opaque nonce[Nn];
 InnerEnvelope inner_env;
 opaque auth_tag[Nm];
} Envelope;
~~~

nonce : A unique nonce of length `Nn` used to protect this Envelope.

auth_tag : Authentication tag protecting the contents of the envelope, covering the envelope nonce,
`InnerEnvelope` and `CleartextCredentials`.

inner_env : A mode dependent `InnerEnvelope` structure. See {{envelope-modes}} for its specifications.

The size of the serialized envelope is denoted `Ne` and varies based on the mode. The exact value for `Ne` is
specified in {{internal-mode}} and {{external-mode}}.

## Envelope Creation and Recovery {#envelope-creation-recovery}

Clients create an `Envelope` at registration with the function `CreateEnvelope` defined below.

For the `internal` mode, implementations can choose to leave out the `client_private_key` parameter,
as it is not used.
For the `external` mode, implementations are free to additionally provide `client_public_key` to this
function. With this, the public key doesn't need to be recovered by `BuildInnerEnvelope()` and that
function should also be adapted accordingly.

~~~
CreateEnvelope(random_pwd, server_public_key, client_private_key, creds)

Parameter:
- mode, the EnvelopeMode mode

Input:
- random_pwd, randomized password
- server_public_key, The encoded server public key for the AKE protocol
- client_private_key, The encoded client private key for the AKE protocol. This is nil in the internal key mode
- server_identity, The optional encoded server identity
- client_identity, The optional encoded client identity

Output:
- envelope, the client's `Envelope` structure
- client_public_key, the client's AKE public key
- masking_key, a key used by the server to preserve the confidentiality of the envelope during login
- export_key, an additional key

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

Clients recover their `Envelope` during authentication with the `RecoverEnvelope` function defined below.

~~~
RecoverEnvelope(random_pwd, server_public_key, creds, envelope)

Input:
- random_pwd, randomized password
- server_public_key, The encoded server public key for the AKE protocol
- creds, a Credentials structure
- envelope, the client's `Envelope` structure

Output:
- client_private_key, The encoded client private key for the AKE protocol
- export_key, an additional key

Steps:
1. auth_key = Expand(random_pwd, concat(envelope.nonce, "AuthKey"), Nh)
2. export_key = Expand(random_pwd, concat(envelope.nonce, "ExportKey", Nh)
3. client_private_key, client_public_key = RecoverKeys(random_pwd, envelope.nonce, envelope.inner_env)
4. cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, creds.server_identity, creds.client_identity)
5. expected_tag = MAC(auth_key, concat(envelope.nonce, inner_env, cleartext_creds))
6. If !ct_equal(envelope.auth_tag, expected_tag),
     raise MacError
7. Output (client_private_key, export_key)
~~~

## Envelope Modes {#envelope-modes}

The `EnvelopeMode` specifies the structure and encoding of the corresponding `InnerEnvelope`.
This document specifies the values of the two aforementioned modes:

~~~
enum {
 internal(1),
 external(2),
 (255)
} EnvelopeMode;
~~~

Each `EnvelopeMode` defines its own `InnerEnvelope` structure and must implement the following interface:
- `inner_env, client_public_key = BuildInnerEnvelope(random_pwd, nonce, client_private_key)`: build and return the
  mode's `InnerEnvelope` structure and the client's public key.
- `client_private_key, client_public_key = RecoverKeys(random_pwd, nonce, inner_env)`: recover and return the
  client's private and public keys for the AKE protocol.

The implementations of this interface for both `internal` and `external` modes are in {{internal-mode}}
and {{external-mode}}, respectively.

The size of the envelope may vary between modes. If applications implement {{preventing-client-enumeration}}, they
MUST use the same envelope mode throughout their lifecycle in order to avoid activity leaks due to mode switching.

### Internal mode {#internal-mode}

In this mode, the client's private and public keys are deterministically derived from the OPRF output.

With the internal key mode the `EnvelopeMode` value MUST be `internal` and the `InnerEnvelope` is empty,
and the size `Ne` of the serialized `Envelope` is Nn + Nm.

To generate the private key OPAQUE-3DH implements `DeriveAkeKeyPair(seed)` as follows:

~~~
DeriveAkeKeyPair(seed)

Parameter:
- dst, domain separation tag for HashToScalar set to "OPAQUE-HashToScalar"

Input:
- seed, pseudo-random byte sequence used as a seed

Output:
- private_key, a private key
- public_key, the associated public key

Steps:
1. private_key = HashToScalar(seed, dst)
2. public_key = private_key * G
3. Output (private_key, public_key)
~~~

HashToScalar(msg, dst) is as specified in {{I-D.irtf-cfrg-voprf}}, except that dst = "OPAQUE-HashToScalar".

~~~
BuildInnerEnvelope(random_pwd, nonce, client_private_key)

Input:
- random_pwd, randomized password
- nonce, a unique nonce of length `Nn`
- client_private_key, empty value. Not used in this function, it only serves to comply with the API

Output:
- inner_env, nil value (serves to comply with the API)
- client_public_key, the client's AKE public key

Steps:
1. seed = Expand(random_pwd, concat(nonce, "PrivateKey"), Nsk)
2. _, client_public_key = DeriveAkeKeyPair(seed)
3. Output (nil, client_public_key)
~~~

Note that implementations are free to leave out the `client_private_key` parameter, as it is not used.

~~~
RecoverKeys(random_pwd, nonce, inner_env)

Input:
- random_pwd, randomized password
- nonce, a unique nonce of length `Nn`
- inner_env, an InnerEnvelope structure. Not used in this function, it only serves to comply with the API

Output:
- client_private_key, The encoded client private key for the AKE protocol
- client_public_key, The encoded client public key for the AKE protocol

Steps:
1. seed = Expand(random_pwd, concat(nonce, "PrivateKey"), Nh)
2. client_private_key, client_public_key = DeriveAkeKeyPair(seed)
4. Output (client_private_key, client_public_key)
~~~

Note that implementations are free to leave out the `inner_env` parameter, as it is not used.

### External Key mode {#external-mode}

This mode allows applications to import custom keys for the client. This specification only imports the
client's private key and internally recovers the corresponding public key. Implementations are free to
import both and thus spare a scalar multiplication at registration. In this case, the functions
`FinalizeRequest()`, `CreateEnvelope()`, and `BuildInnerEnvelope()` must be adapted accordingly.

With the external key mode the `EnvelopeMode` value MUST be `external`, and the size `Ne` of the serialized
`Envelope` is Nn + Nm + Nsk.

An encryption key is generated from the hardened OPRF output and used to encrypt the client's private key,
which is then stored encrypted in the `InnerEnvelope`. This encryption must follow the requirements in
{{envelope-encryption}}. On key recovery, the client's public key is recovered using the private key.

~~~
struct {
 opaque encrypted_creds[Nsk];
} InnerEnvelope;
~~~

encrypted_creds : Encrypted client_private_key. Authentication of this field is ensured with the `AuthTag` in
the envelope that covers this `InnerEnvelope`.

If the implementation provides the `client_public_key`, then `BuildInnerEnvelope()` can skip the
`RecoverPublicKey()` call.

~~~
BuildInnerEnvelope(random_pwd, nonce, client_private_key)

Input:
- random_pwd, randomized password
- nonce, a unique nonce of length `Nn`
- client_private_key, The encoded client private key for the AKE protocol

Output:
- inner_env, an InnerEnvelope structure
- client_public_key, The encoded client public key for the AKE protocol

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
- random_pwd, randomized password
- nonce, a unique nonce of length `Nn`
- inner_env, an InnerEnvelope structure

Output:
- client_private_key, The encoded client private key for the AKE protocol
- client_public_key, the client's AKE public key

Steps:
1. encrypted_creds = inner_env.encrypted_creds
2. pseudorandom_pad = Expand(random_pwd, concat(nonce, "Pad"), len(encrypted_creds))
3. client_private_key = xor(encrypted_creds, pseudorandom_pad)
4. client_public_key = RecoverPublicKey(client_private_key)
5. Output (client_private_key, client_public_key)
~~~

# Offline Registration {#offline-phase}

Registration is executed between a client C and a
server S. It is assumed S can identify C and the client can
authenticate S during this registration phase. This is the only part
in OPAQUE that requires an authenticated and confidential channel, either physical, out-of-band,
PKI-based, etc. This section describes the registration flow, message encoding,
and helper functions. Moreover, C has a key pair (client_private_key, client_public_key) for an AKE protocol
which is suitable for use with OPAQUE; See {{online-phase}}. The private-public keys (client_private_key,
client_public_key) may be randomly generated (using a cryptographically secure pseudorandom number generator)
for the account or provided by the calling client.
Clients MUST NOT use the same key pair (client_private_key, client_public_key) for two different accounts.

## Setup Phase {#setup-phase}

In a setup phase, C chooses its password, and S chooses its own pair of private-public
AKE keys (server_private_key, server_public_key) for use with the AKE, along with a Nh-byte oprf_seed. S can use
the same pair of keys with multiple clients and can opt to use multiple seeds (so long as they are
kept consistent for each client). These steps can happen offline, i.e., before the registration phase.

Once complete, the registration process proceeds as follows.

## Credential Registration

~~~
 Client (password, creds)            Server (server_private_key, server_public_key, credential_identifier, oprf_seed)
 --------------------------------------------------------------------
 (request, blind) = CreateRegistrationRequest(password)

                               request
                      ------------------------->

            (response, oprf_key) = CreateRegistrationResponse(request, server_public_key, credential_identifier, oprf_seed)

                               response
                      <-------------------------

 (record, export_key) = FinalizeRequest(client_private_key, password, blind, response)

                                record
                      ------------------------->
~~~

{{registration-functions}} describes details of the functions referenced above.

Both client and server MUST validate the other party's public key before use.
See {{validation}} for more details.

Upon completion, S stores C's credentials for later use.

## Registration Messages

~~~
struct {
    SerializedElement data;
} RegistrationRequest;
~~~

data
: A serialized OPRF group element.

~~~
struct {
    SerializedElement data;
    opaque server_public_key[Npk];
} RegistrationResponse;
~~~

data
: A serialized OPRF group element.

server_public_key
: The server's encoded public key that will be used for the online authenticated key exchange stage.

~~~
struct {
    opaque client_public_key[Npk];
    opaque masking_key[Nh];
    Envelope envelope;
} RegistrationUpload;
~~~

client_public_key
: The client's encoded public key, corresponding to the private key `client_private_key`.

masking_key
: A key used by the server to preserve confidentiality of the envelope during login

envelope
: The client's `Envelope` structure.

## Registration Functions {#registration-functions}

### CreateRegistrationRequest

~~~
CreateRegistrationRequest(password)

Input:
- password, an opaque byte string containing the client's password

Output:
- request, a RegistrationRequest structure
- blind, an OPRF scalar value

Steps:
1. (blind, M) = Blind(password)
2. Create RegistrationRequest request with M
3. Output (request, blind)
~~~

### CreateRegistrationResponse {#create-reg-response}

~~~
CreateRegistrationResponse(request, server_public_key, credential_identifier, oprf_seed)

Input:
- request, a RegistrationRequest structure
- server_public_key, the server's public key
- credential_identifier, an identifier that uniquely represents the credential being
  registered
- oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key

Output:
- response, a RegistrationResponse structure
- oprf_key, the per-client OPRF key known only to the server

Steps:
1. (oprf_key, _) = DeriveKeyPair(Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok))
2. Z = Evaluate(oprf_key, request.data)
3. Create RegistrationResponse response with (Z, server_public_key)
4. Output (response, oprf_key)
~~~

### FinalizeRequest {#finalize-request}

To create the user record used for further authentication, the client executes the following function. In the
internal key mode, the `client_private_key` is nil.

Depending on the mode, implementations are free to leave out the `client_private_key` parameter (`internal` mode),
or to additionally include `client_public_key` (`external` mode). See {#envelope-creation-recovery} for more details.

~~~
FinalizeRequest(client_private_key, password, blind, response)

Input:
- client_private_key, the client's private key. In the internal key mode, this is nil
- password, an opaque byte string containing the client's password
- creds, a Credentials structure
- blind, the OPRF scalar value used for blinding
- response, a RegistrationResponse structure

Output:
- record, a RegistrationUpload structure
- export_key, an additional key

Steps:
1. y = Finalize(password, blind, response.data)
2. random_pwd = Extract("", Harden(y, params))
3. envelope, client_public_key, masking_key, export_key = CreateEnvelope(random_pwd, response.server_public_key, client_private_key, creds)
4. Create RegistrationUpload record with (client_public_key, masking_key, envelope)
5. Output (record, export_key)
~~~

See {{online-phase}} for details about the output export_key usage.

Upon completion of this function, the client MUST send `record` to the server.

### Finalize Registration {#finalize-registration}

The server stores the `record` object as the credential file for each client along with the associated
`credential_identifier` and `client_identity` (if different).
Note that the values `oprf_seed` and `server_private_key` from the server's setup phase must also be persisted.

# Online Authenticated Key Exchange {#online-phase}

After registration, the client and server run the authenticated
key exchange stage of the OPAQUE protocol. This stage is composed of a concurrent
OPRF and key exchange flow. The key exchange protocol is authenticated using the
client and server credentials established during registration; see {{offline-phase}}.
The type of keys MUST be suitable for the key exchange protocol. For example, if
the key exchange protocol is 3DH, as described in {{opaque-3dh}}, then the private and
public keys must be Diffie-Hellman keys. In the end, the client proves its
knowledge of the password, and both client and server agree on a mutually authenticated
shared secret key.

OPAQUE produces two outputs: a session secret and an export key. The export key may be used
for additional application-specific purposes, as outlined in {{export-key-usage}}.
The output `export_key` MUST NOT be used in any way before the MAC value in the
envelope is validated. See {{envelope-encryption}} for more details about this requirement.

## Credential Retrieval

The online AKE stage of the protocol requires clients to obtain and decrypt their
credentials from the server-stored envelope. This process is similar to the offline
registration stage, as shown below.

~~~
 Client (password)             Server (server_private_key, server_public_key, oprf_seed, record)
 --------------------------------------------------------------------
 (request, blind) = CreateCredentialRequest(password)

                               request
                      ------------------------->

    response = CreateCredentialResponse(request, server_public_key, record, credential_identifier, oprf_seed)

                               response
                      <-------------------------

 (client_private_key, server_public_key, export_key) =
     RecoverCredentials(password, blind, response)
~~~

The rest of this section describes these credential retrieval functions in
more detail.

### Credential Retrieval Messages

~~~
struct {
    SerializedElement data;
} CredentialRequest;
~~~

data
: A serialized OPRF group element.

~~~
struct {
    SerializedElement data;
    opaque masking_nonce[Nn];
    opaque masked_response[Npk + Ne];
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
- password, an opaque byte string containing the client's password

Output:
- request, a CredentialRequest structure
- blind, an OPRF scalar value

Steps:
1. (blind, M) = Blind(password)
2. Create CredentialRequest request with M
3. Output (request, blind)
~~~

#### CreateCredentialResponse {#create-credential-response}

There are two scenarios to handle for the construction of a CredentialResponse object: either the
record for the client exists (corresponding to a properly registered client), or
it was never created (corresponding to a client that has yet to register).

In the case of an existing record with the corresponding identifier
`credential_identifier`, the server invokes the following function to
produce a CredentialResponse:

~~~
CreateCredentialResponse(request, server_public_key, record, credential_identifier, oprf_seed)

Input:
- request, a CredentialRequest structure
- server_public_key, the public key of the server
- record, an instance of RegistrationUpload which is the server's
  output from registration
- credential_identifier, an identifier that uniquely represents the credential being
  registered
- oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key

Output:
- response, a CredentialResponse structure

Steps:
1. (oprf_key, _) = DeriveKeyPair(Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok))
2. Z = Evaluate(oprf_key, request.data)
3. masking_nonce = random(32)
4. credential_response_pad = Expand(record.masking_key,
     concat(masking_nonce, "CredentialResponsePad"), Npk + Ne)
5. masked_response = xor(credential_response_pad, concat(server_public_key, record.envelope))
6. Create CredentialResponse response with (Z, masking_nonce, masked_response)
7. Output response
~~~

In the case of a record that does not exist, the server invokes the CreateCredentialResponse
function where the record argument is configured so that:
- record.masking_key is set to a random byte string of length Nh, and
- record.envelope is set to the byte string consisting only of zeros, of length Ne

Note that the responses output by either scenario are indistinguishable to an adversary
that is unable to guess the registered password for the client corresponding to credential_identifier.

#### RecoverCredentials {#recover-credentials}

~~~
RecoverCredentials(password, blind, response, creds)

Input:
- password, an opaque byte string containing the client's password
- blind, an OPRF scalar value
- response, a CredentialResponse structure
- creds, a Credentials structure

Output:
- client_private_key, the client's private key for the AKE protocol
- server_public_key, the public key of the server
- export_key, an additional key

Steps:
1. y = Finalize(password, blind, response.data)
2. random_pwd = Extract("", Harden(y, params))
3. masking_key = Expand(random_pwd, "MaskingKey", Nh)
4. credential_response_pad = Expand(masking_key,
     concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
5. concat(server_public_key, envelope) = xor(credential_response_pad, response.masked_response)
6. client_private_key, export_key = RecoverEnvelope(random_pwd, server_public_key, creds, envelope)
7. Output (client_private_key, response.server_public_key, export_key)
~~~

## AKE Instantiations {#instantiations}

This section describes instantiations of OPAQUE using 3-message AKEs which
satisfies the forward secrecy and KCI properties discussed in {{security-considerations}}.
As shown in {{OPAQUE}}, OPAQUE cannot use less than three messages, so the 3-message
instantiations presented here are optimal in terms of number of messages. On the other
hand, there is no impediment to using OPAQUE with protocols with more than 3 messages
as in the case of IKEv2 (or the underlying SIGMA-R protocol {{SIGMA}}).

The generic outline of OPAQUE with a 3-message AKE protocol includes three messages
KE1, KE2, and KE3, where KE1 and KE2 include key exchange shares, e.g., DH values, sent
by client and server, respectively, and KE3 provides explicit client authentication and
full forward security (without it, forward secrecy is only achieved against eavesdroppers
which is insufficient for OPAQUE security).

The output of the authentication phase is a session secret `session_key` and export
key `export_key`. Applications can use `session_key` to derive additional keying material
as needed. Key derivation and other details of the protocol are specified by the AKE scheme.
We note that by the results in {{OPAQUE}}, KE2 and KE3 must authenticate credential_request
and credential_response, respectively, for binding between the underlying OPRF protocol
messages and the KE session.

We use the parameters Npk and Nsk to denote the size of the public and private keys used
in the AKE instantiation.

The rest of this section includes key schedule utility functions used by OPAQUE-3DH,
and then provides a detailed specification for OPAQUE-3DH, including its wire format
messages.

### Key Schedule Utility Functions

The key derivation procedures for OPAQUE-3DH makes use of the functions below, re-purposed
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
   opaque context<0..255> = Context;
} CustomLabel;

Derive-Secret(Secret, Label, Transcript-Hash) =
    Expand-Label(Secret, Label, Transcript-Hash, Nx)
~~~

Note that the Label parameter is not a NULL-terminated string.

### OPAQUE-3DH Instantiation {#opaque-3dh}

OPAQUE-3DH is implemented using a suitable prime order group. All operations in
the key derivation steps in {{derive-3dh}} are performed in this group and
represented here using multiplicative notation. The output of OPAQUE-3DH is a
session secret `session_key` and export key `export_key`.

The parameters Npk and Nsk are set to be equal to the size of an element and
scalar, respectively, in the associated prime order group.

#### OPAQUE-3DH Messages

The three messages for OPAQUE-3DH are described below.

~~~
struct {
  CredentialRequest request;
  uint8 client_nonce[Nn];
  opaque client_info<0..2^16-1>;
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
  opaque enc_server_info<0..2^16-1>;
  uint8 mac[Nm];
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

mac
: An authentication tag computed over the handshake transcript computed using Km2,
defined below.

~~~
struct {
  uint8 mac[Nm];
} KE3;
~~~

mac
: An authentication tag computed over the handshake transcript computed using
Km3, defined below.

#### OPAQUE-3DH Key Schedule {#derive-3dh}

OPAQUE-3DH requires MAC keys `server_mac_key` and `client_mac_key` and
encryption key `handshake_encrypt_key`. Additionally, OPAQUE-3DH also
outputs `session_key`. The schedule for computing this key material is below.

~~~
Extract("", IKM)
    |
    +-> Derive-Secret(., "HandshakeSecret", Hash(preamble)) = handshake_secret
    |
    +-> Derive-Secret(., "SessionKey", Hash(preamble)) = session_key
~~~

From `handshake_secret`, Km2, Km3, and Ke2 are computed as follows:

~~~
server_mac_key =
  Expand-Label(handshake_secret, "ServerMAC", "", Nx)
client_mac_key =
  Expand-Label(handshake_secret, "ClientMAC", "", Nx)
handshake_encrypt_key =
  Expand-Label(handshake_secret, "HandshakeKey", "", Nx)
~~~

Nx is the output length of the Extract function, as specified in {{dependencies}}.

The Derive-Secret parameter `preamble` is computed as:

~~~
preamble = concat("3DH",
                  I2OSP(len(client_identity), 2), client_identity,
                  KE1,
                  I2OSP(len(server_identity), 2), server_identity,
                  KE2.inner_ke2)
~~~

See {{identities}} for more information about identities client_identity and
server_identity.

Let `epkS` and `eskS` be `server_keyshare` and the corresponding secret key,
and `epkU` and `eskU` be `client_keyshare` and the corresponding secret key.
The input parameter `IKM` the concatenation of three DH values computed by
the client as follows:

~~~
IKM = concat(epkS^eskU, pkS^eskU, epkS^skU)
~~~

Likewise, `IKM` is computed by the server as follows:

~~~
IKM = concat(epkU^eskS, epkU^skS, pkU^eskS)
~~~

#### OPAQUE-3DH Encryption and Key Confirmation {#3dh-core}

Clients and servers use keys Km2 and Km3 in computing KE2.mac and KE3.mac,
respectively. These values are computed as follows:

- KE2.mac = MAC(Km2, Hash(concat(preamble, KE2.enc_server_info))), where
  preamble is as defined in {{derive-3dh}}.
- KE3.mac = MAC(Km3, Hash(concat(preamble, KE2.enc_server_info, KE2.mac))),
  where preamble is as defined in {{derive-3dh}}.

The server application info, an opaque byte string `server_info`, is encrypted
using a technique similar to that used for secret credential encryption.
Specifically, a one-time-pad is derived from Ke2 and then used as input to XOR
with the plaintext. In pseudocode, this is done as follows:

~~~
info_pad = Expand(Ke2, "EncryptionPad", len(server_info))
enc_server_info = xor(info_pad, server_info)
~~~

# Configurations {#configurations}

An OPAQUE-3DH configuration is a tuple (OPRF, KDF, MAC, Hash, MHF, EnvelopeMode, Group)
such that the following conditions are met:

- The OPRF protocol uses the "base mode" variant of {{I-D.irtf-cfrg-voprf}} and implements
  the interface in {{dependencies}}. Examples include OPRF(ristretto255, SHA-512) and
  OPRF(P-256, SHA-256).
- The KDF, MAC, and Hash functions implement the interfaces in {{dependencies}}.
  Examples include HKDF {{RFC5869}} for the KDF, HMAC {{!RFC2104}} for the MAC,
  and SHA-256 and SHA-512 for the Hash functions.
- The MHF has fixed parameters, chosen by the application, and implements the
  interface in {{dependencies}}. Examples include Argon2 {{?I-D.irtf-cfrg-argon2}},
  scrypt {{?RFC7914}}, and PBKDF2 {{?RFC2898}} with fixed parameter choices.
- EnvelopeMode value is as defined in {{client-credential-storage}}, and is one of
  `internal` or `external`.
- The Group mode identifies the group used in the OPAQUE-3DH AKE. This SHOULD
  match that of the OPRF. For example, if the OPRF is OPRF(ristretto255, SHA-512),
  then Group SHOULD be ristretto255.

To recover a public key from a private key, OPAQUE-3DH implements `RecoverPublicKey(private_key)` as follows:

~~~
RecoverPublicKey(private_key)

Input:
- private_key, a scalar in the group interpreted as the private key

Output:
- public_key, a group element used as public key

Steps:
1. public_key = private_key * G
3. Output public_key
~~~

Absent an application-specific profile, the following configurations are RECOMMENDED:

- OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512, Scrypt(32768,8,1), internal, ristretto255
- OPRF(P-256, SHA-256), HKDF-SHA-256, HMAC-SHA-256, SHA-256, Scrypt(32768,8,1), internal, P-256

Future configurations may specify different combinations of dependent algorithms,
with the following consideration. The size of AKE public and private keys -- `Npk`
and `Nsk`, respectively -- must adhere to an output length limitations of the KDF
Expand function. If HKDF is used, this means Npk, Nsk <= 255 * Nx, where Nx is the
output size of the underlying hash function. See {{RFC5869}} for details.

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

<!-- TODO(caw): bring this back after updating later -->

<!-- ## Envelope considerations

It is possible to dispense with encryption in the construction of an envelope to
obtain a shorter envelope (resulting in less storage at the server and less
communication from server to client). The idea is to derive client_private_key from prk.
However, for cases where client_private_key is not a random string of a given length, we
define a more general procedure. Namely, what is derived from prk is a random
seed used as an input to a key generation procedure that generates the pair
(client_private_key, client_public_key). In this case, secret_credentials is empty and cleartext_credentials
contains server_public_key. The random key generation seed is defined as
Expand(KdKey; info="KG seed", L)
where L is the required seed length. We note that in this encryption-less
scheme, the authentication still needs to be random-key robust which HMAC
satisfies. -->

<!--
Mention advantage of avoidable equivocable encryption? Still needs equivocable
authentication, but that one gets by modeling HMAC as programmable RO - check.
-->

<!-- To further minimize storage space, the server can derive per-client OPRF keys
oprf_key from a single global secret key, and it can use the same pair
(server_private_key,server_public_key) for all clients. In this case, the per-client OPAQUE storage
consists of client_public_key and HMAC(Khmac; server_public_key), a total of 64-byte overhead with a
256-bit curve and hash. envelope communicated to the client is of the same length,
consisting of server_public_key and HMAC(Khmac; server_public_key). -->

<!-- Can provide AuCPace paper (sec 7.7) as reference to importance of small
envelope (for settings where storage and/or communication is expensive) -->

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
oprf_seed: 08a5b89846e20e429f88a3dff47a25e77db3e28f34444a0f466dcf6959
8752175f1d590f2fe9e7bbfe756138a6fc0d0d2fea2639e8f3bf78eed376e75aea0e4
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a8b25827b06c23d69da214d4719d7d3790e9362766f795d76d88d
5ff572f8b5b
masking_nonce: 74a3a0531623c439cecd04210aa9f68ebcad08fd4fd2fef24f9b34
67ae0e5424
server_private_key: 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a
9706137886dce08
server_public_key: 4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b
78624cbd10b371
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 5032f7f7643b020d2b96b3a5c7d6091fde8b00cbf2e707f018d819a
b298d9631
client_nonce: fa6b31dbaa7d43a40ab7dc6f8d47891316cbb7224f79d39aaf4bbf7
038f89026
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
oprf_key: 8c543d7d8bbe5f800fdd98bf091614545363f85d4464a74daf0ce8d1ea3
48a0b
~~~

### Intermediate Values

~~~
client_public_key: 34ca5edac79d8290d2993a572b30fde5d5cb19bb79c247c03c
787a836321b976
auth_key: 3a4d73041bebc18004574ba0bf3e29446a6a7deb7a9b58b87528b327760
3dcccea88a5ef97f4aa663da62ebaed8f0473db55709d5c68660cd9b7578cda22c290
random_pwd: a312bb12791e75a4c37b4dd407aba0dd04650648c9f401dea70012d33
7008ded6aa32a0c131cdae3035da32b7fab45f8f967d00b76a9e04106e1f481319b6d
3b
envelope: a8b25827b06c23d69da214d4719d7d3790e9362766f795d76d88d5ff572
f8b5bba81d9a59b4c21c434bc0d2fbb8f4de07daa2da89daaa468d11ae2d6f668615c
f5aa0558abf6b1183a5347398da5db46271ec79b975fe2e5956fcfde32dd4808
handshake_secret: 3837484110edcac7c39c78b89b74e093d7d86378178598f1279
d9455c241a917b372cac70b043264c4ee2032a080344442941448a3e0ad75c9b822cb
de1440bf
handshake_encrypt_key: f536a1a716e9b93649d2b17ed6b82cdac349bafbfafc6b
23684ca3080c0642ae6edd2752322ea83c74cd420f93577ee6284698e5f337d59bcd8
02298c7d9da88
server_mac_key: 543379abace30a7cf2daad5bae19a3fab80a60084a07b464b6f3f
3dbd24d9c6221d1be8a8cce84c4008fa5c7b0525bf8b0c2296e9473bb7a09c3f43e0b
bd90fd
client_mac_key: 97daa370e10f78b2f1b34e8adb094508adfa4561023c91498cdd9
e8a584fbc56b0f2da700705c48cfe92a5e7f9eea6f0dfcc16e18ff8a8ac7e9df7b36d
d88ff0
~~~

### Output Values

~~~
registration_request: 24bbcabb15452642f709cb8567eff38f4cda6044aca3356
87a62b8453d849c18
registration_response: 98b7be2a654b04bd7798687a198a0a9c5b88ccd93e6fed
d62957b2018130a5364c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b7
8624cbd10b371
registration_upload: 34ca5edac79d8290d2993a572b30fde5d5cb19bb79c247c0
3c787a836321b976d002ef024cc71dd75e012fb2f45a899c2aeeb5d651522c577d726
76da06cfb91c0733349acde4c2f94bc584f6dfcce60c5a2a94503042785bf83bf045e
49ce42a8b25827b06c23d69da214d4719d7d3790e9362766f795d76d88d5ff572f8b5
bba81d9a59b4c21c434bc0d2fbb8f4de07daa2da89daaa468d11ae2d6f668615cf5aa
0558abf6b1183a5347398da5db46271ec79b975fe2e5956fcfde32dd4808
KE1: 0e8eeeb2ca0dbf5f690cfe0b76783d7667245f399b874a989f168fdd3e572663
fa6b31dbaa7d43a40ab7dc6f8d47891316cbb7224f79d39aaf4bbf7038f8902600096
8656c6c6f20626f624c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
KE2: de68550e5bdd3d12a3308b5d30af45215cf4155b0a7ecef08c7391e54546d33c
74a3a0531623c439cecd04210aa9f68ebcad08fd4fd2fef24f9b3467ae0e54249c86a
7979393966ca7bcbaef426c23f1b816777d71f60823a76fdb19057dcb22ee4191aa1b
98a0119368e8990be71153626a4f0352097fac338cf5749ff7ccb2182dcf50904b377
52a1fc53c9a9e7832850a65fd53b5ce03ef0e8b2bb14129f17ce52bc437b0f13cec47
43fe2b09576908196aac50786763fd67a44431d170a55032f7f7643b020d2b96b3a5c
7d6091fde8b00cbf2e707f018d819ab298d9631ca372e52516d51c19763ad5eb1a5b6
0dafb68c264dcf6bcc692f667a71c5a617000f24bd3ea85075c62f988b1a38ffb278a
0b2a0ec3cab325d7639c0d7cc2e05cebb6485af21d751d379c34b7fbb3d793304995d
2f59909100f1131ba83c84ec011ef2e36a2448140c2f88586693648c92
KE3: 6f508fdae9b42d3164ce3b1c5ee6d93338039e5bd9dc2b0778b98fcba1f5a207
a13071e82a392555a3502a7ffc4200344a6d078ba228d3c22312bc7a079fcdd1
export_key: 27f8cd12a727f6567599d961119ac518deee1a3e932d049a08db647cf
20514d0b7c98a9df5f326f6d36740d576fc5fc43392aed9747d068dfbeb8c868701ad
be
session_key: a6a55a19ecce1bea22134f65ee268f3790cb80529f3820287a9baae0
ece349a28cdbe240553be0bac7f72c508e6a13ddc5143c122f6d540d093ae8c1febfd
4eb
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
oprf_seed: 13c90426d0c270b93cf8b485dfcc8a409f0688e92826008b03593168d0
2a4ac9a886cb5f882db78598eb38e0ed71f92ef6741be8b5790298d362436bdc959a1
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 2dafb7308e269c475f6fc752a6971562ab7be50e11ebd9a88b62c
7d43301b384
masking_nonce: d4d8c290cbc68a878309af0fe746ed36d29d7edb11af721f38aa17
d739a5154a
server_private_key: de2e98f422bf7b99be19f7da7cac62f1599d35a225ec63401
49a0aaff3102003
server_public_key: a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e7874
92b98265a5e651
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: a861be85afd0d828ac0602e9aed6adcbc19720dc4eae7b82866774d
24a6c4f5b
client_nonce: 04b1f1d8faf5105388451ac2e92eee8b64bc0c67df3926d1e7b5615
fa4b9f8ee
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
oprf_key: 0facb3ff6d204eae57354d539751c4ec690116cef25894dffb9ff502b37
f7904
~~~

### Intermediate Values

~~~
client_public_key: 000564a8bb1165619749660836572a165e52e6bbdb77fb47c2
f6a8f6623b2871
auth_key: f73c508096a546d3cb43695d4a716795c6e57e869821604aab11f196b05
01884414495a3ea44d2be1ee3607cee41b0e7ecebf979d0be037c684c893b1dafc5b2
random_pwd: 71d055f43026df142bcc9fdb6af5362e11eb7b12350e5c82ccc03b391
5f383f4371b799af2fcab6dd368b27085bc600ecce4d5a659617fe9d8b9e7caf9192f
c6
envelope: 2dafb7308e269c475f6fc752a6971562ab7be50e11ebd9a88b62c7d4330
1b3842704db722502defa3d5352d3f2a75c15ffb8bab3f140e7ad042c0e87596cd596
bfd1161a054f421103cd6ced928bc41e2211c34fc797d8375fa73af90709c413
handshake_secret: a133f228c6c303024401af97dd7f60a69116304f1a9d54c291b
b3672ed4a31cf1aaac462c6dd403ed1cfdd2823f82ed2f22bee7c20159226b673fac3
2b90e5d4
handshake_encrypt_key: a41182501a7ad4ff692bfb17e523322e2018127830c8eb
1867f84789a11b8479910d5de817172db5b53075c90356240aa8dd225cb3967c91521
b71991d835b1a
server_mac_key: c3bbf3ed8e92fe6b0c3c1ce7da2561e909b1c01f0798015a07b82
4e5551f63a40b9a3de979ab024d08088832056280f42c474aa4d9069df216464bc64d
80320f
client_mac_key: 9e08b0e7bac27daebec08474671d8ac60c248dd9a208ac70d5432
0cf6d7117e1a505cd2b79e490e44a09226c1219f0ba73db81b9207ab72bbc482ed118
2f35fd
~~~

### Output Values

~~~
registration_request: fa8c0e0144f7b9cd1de1bfcf78104f94d63c0f90398c9df
ceee06ab5593ec500
registration_response: b8ca5cffe47a6defd5f5c7bd3ab3187893ce65c2376f64
b89c5994002d82f349a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e78749
2b98265a5e651
registration_upload: 000564a8bb1165619749660836572a165e52e6bbdb77fb47
c2f6a8f6623b2871bbbf557ea891fdb42810c78156521003c22ecfbe93501a102f804
8e9c739935fa6539a2267149477ceb473836dbc5084f0fbf460365e74971af0167a46
98e8f92dafb7308e269c475f6fc752a6971562ab7be50e11ebd9a88b62c7d43301b38
42704db722502defa3d5352d3f2a75c15ffb8bab3f140e7ad042c0e87596cd596bfd1
161a054f421103cd6ced928bc41e2211c34fc797d8375fa73af90709c413
KE1: dedef709c5faf24970b4fa77480a2c640dc8c6b7a53ae78a2dbf3fc75134a250
04b1f1d8faf5105388451ac2e92eee8b64bc0c67df3926d1e7b5615fa4b9f8ee00096
8656c6c6f20626f62746987c9ba92c3636d92fa7afc0379009ed54a7fb2db3cf7e4c4
07d4ed2c6e35
KE2: f2556168fd6499a736ca4a6d002dfe31db92420513fd32e1027e36e0c002ca4d
d4d8c290cbc68a878309af0fe746ed36d29d7edb11af721f38aa17d739a5154a7f510
c8cb8dde6334256f003369ed6f538f3a4307e0e880442fe4eb12f9ba35a2beb56a179
b85c7f0a3083a3d891232257da594275b8d07c74dfbba3485cceb1c8dde097e0a0ad8
26a08da06faacb1c9a7d00c48dcc123ab021c5a92360ba1be3907fba9433a831583a3
3fa883e61e4539d2ee6f6152ab699a5804f4beabd334a861be85afd0d828ac0602e9a
ed6adcbc19720dc4eae7b82866774d24a6c4f5b80d9b21c255bf04113a6d339fff579
c68475e516c0c98f625a90f6532a310f13000f3d846d42575676a848926aa73ce6f5c
c64aa86427fa9b2e3f5af53f44ed88c17f85f2ca9c19038f626409640d1c5d8996f6c
9393e4d9e77661df5b59288d2f4851857827a80d0a3cde0cca5ae944b8
KE3: 5daad57bab45630890cad0e2a663bd50b7d6a01aa76a96c7ea08eac775c8bfe3
748b49c29558c331fc1f28288745849449bcca4d4048b85a4d4e8674206f8093
export_key: bb143f6cd17ce7868325b4b6b9e228b93f4b998a39e1809a3ae776920
a1ace2ba6d6b766382b97b5a717e7b6ceaea782d1ddf2cad2027930504970297cfb85
45
session_key: 3c49e92815843d7c166eb8e4e647aa060110e099f25db81a3132b6f5
139cc7470cdc35f87b994de060d89cbb2d19905f5fbf11ad56c187762dc05ef488ad9
e16
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
oprf_seed: 53a4c3c0a92bcab6a5098dd677702d6a2835bb8a9d32861b0acfdcbd68
087f24023d44060da3f5964472dd8eb5074cd34a7446d4a1eea99b7a8a500e78d3fac
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 24e1c33dfcfaa7df486d1ee7454ba5270a2d683e791ec5f845975
fd1a00451fa
masking_nonce: 2e7ec407afd67dfa291677615704156aa8b72604711e74b8e12f8e
5b2cd5648a
server_private_key: be81db28eb1e147561c478a3f84cbf77037f010272fd51abc
ff08ac9537e750b
server_public_key: 5ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3
f459678b0e0d25
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 732467e16f3c6f9a9d399620b4afd3aa9c9391d21bc3075d4020a0a
b34890d23
client_nonce: 677bdaaa4ee62ca7196f3d6ae90b26d45cb096d3f58da31b5dc493e
b3271fdbc
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
oprf_key: af1c3e281de09f060cf1d80ddc3957fa29044eed545d0fab5d7c823f282
96b03
~~~

### Intermediate Values

~~~
client_public_key: 18243b92bda959742f7bac225650e0af3847f8de6348e492cd
f7cdd58934a542
auth_key: da87ee6a245717ae58d2183c8d0e52d37013ddee317633a830f00d12443
84f394365aa256aa53a4da55c3a890a549383bf6ae17544f06be34217703b56156d25
random_pwd: 5344c2fd5ba9de174caeb701cf3fd5aa7d849f0e662f26702cf422115
b3aca77f333352c56377d1b36f0430c2af245829c556844dc3200e3ffc9eeac898ee2
ce
envelope: 24e1c33dfcfaa7df486d1ee7454ba5270a2d683e791ec5f845975fd1a00
451facdaf029e3723d33e819be32348eadcffa26dc23251d685d135d0e4a96720adbe
44e33df42b25b2ad9966b6e3ac9b87d6a386056bae3d231657f5c9392d2ef24f
handshake_secret: 8bb1fa8684ed103793b07ec4c9831be0c4aa1f3fc08567168e4
c49555cf939d3511d7552da67487b618f5128d20cabe3b76e806c19f18c4f387da3c7
1597d226
handshake_encrypt_key: 07f394af5b235263de45f9b251037621426f0f7a77bc53
4b292b3b726d47cdbeda8ea109776775716645c07bc96b82224cd85f3bc963f3f9243
6f1c0703ce2d8
server_mac_key: d2b38568c34f237b4467108ebae2da4c5e05852c86db1ffbf5825
851265262870f78134c2e0fdf9fe67e526f0d605fb30774cc16bad9df6fbafe9ed016
33c564
client_mac_key: a410750bcd547d9b839e8a669f899bfaaf5715f8943eaa3635845
c9c282953ac7f78163129ed4ff0f7f7057df66c7fa7df1e1c2fdbe5ea718babd87511
dec795
~~~

### Output Values

~~~
registration_request: fa39a478c220a89929613f9e65c9a4617da96b62509c42b
39d7e3606ed2e8031
registration_response: dc56b3f921aafdd71350e10a00bf4e3e2afe12df10b3df
35bc891bf14faa280e5ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3f
459678b0e0d25
registration_upload: 18243b92bda959742f7bac225650e0af3847f8de6348e492
cdf7cdd58934a542ab0c390aac54d2eea1e16a386eb2450c721735f27245c049fe9e0
45dd75d565936c342fed1b3f221fef086e842e6e9cacb6ad5bbca1950929c3c47cc33
08334624e1c33dfcfaa7df486d1ee7454ba5270a2d683e791ec5f845975fd1a00451f
acdaf029e3723d33e819be32348eadcffa26dc23251d685d135d0e4a96720adbe44e3
3df42b25b2ad9966b6e3ac9b87d6a386056bae3d231657f5c9392d2ef24f
KE1: 96f9f35ebc0ca71607fd2cfcd465e285eeeabdec61151b39b2b4fb735538aa0c
677bdaaa4ee62ca7196f3d6ae90b26d45cb096d3f58da31b5dc493eb3271fdbc00096
8656c6c6f20626f622e8a05799d3c524ede0482f39e047df99d9a53dc2dc30e8947eb
5da98b8c4354
KE2: b6e3c15709ac6435f3c2bcde98f397612e29f70a476f3230ed9398b726974e43
2e7ec407afd67dfa291677615704156aa8b72604711e74b8e12f8e5b2cd5648ab59eb
4a2d07897f9831b7e337266ba0321818328cab1ff7ffba67c0f34857ec5da49c426bc
1b02703b111435420b202f44d5e664f619ae1004821916c3c9606bba6b7dd794a3d1d
a51d27e0f92a1e0f4239f60963a6c926748eda53ea6e167f82f2849683b721ee8d3fa
4d0184ed0ccbc1a878d4e34ecc8633ce71e6ae002e1c732467e16f3c6f9a9d399620b
4afd3aa9c9391d21bc3075d4020a0ab34890d23a6d76012999541f1ec0c014ec1606f
2bd2a517e51f731d59546951d9699e1739000fb059f5d9810ec791f83dbf7252e887c
7ba189eade5d8c6678ae42068ce5532f3699d07b272a264861cd1c0f3757f40dc5203
42b5a0ae0e64370ebfaf0eef154293f5613378ee690909b61c70cd9007
KE3: 480430c02fbe8a30a4304a5c989b151286e89868ba427e40bfbbac5f2387fb88
4c4d4a59aa3c282bb4dbe152decf63b265fb2699f9feaa85a2b4cd16fcc1326d
export_key: 81442f30632037b8b033ef4c7119a596ee658cce565194f91eaab0bee
b3c04d3aabd3dce2216ffb12dbd1a996c85fb864d835e904c358eccb9eeadfbfec723
b9
session_key: 0d7f5ef10241bf3311bcc93ba8a8bf72f05dac0a27c240fd2fb22520
de9a50014a1bbbed5f5522de0416aa6060e5d6deec7d24d4cc3e6c1a75107f6f25801
424
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
oprf_seed: 23557dd1d1cbf73ecb6169b1af51bac65dcc391857a6b956308e63ec4d
39da7195e016acaa2c5b98a2820a396938df9a60e5de1c3fe5658e24c82d6cf5ced10
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a8fef064636235dac7976efccdfa35f27602d7badfcb97f3b9189
fb9bc6683d9
masking_nonce: f42dd7f763a416764954e2906070cf12680c0baac00efd58a5e79f
855ec2c966
server_private_key: d49399dc3bc1022938dfb0e79db523d4e4e41f494c3898eac
652bf95f6efa108
server_public_key: fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce50
017dc037001c63
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 74a02c10c19b49074d0ca48a185575f99e159ec4d8ae88fde21b846
582bc52e6
client_nonce: 37f935f7f3f385590ab7e79a62fae61e17c678aff637f1dc1f6928b
8cc25cb52
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
oprf_key: 9488b8ba563a7d4a0b50797ba4ae3e1df7addbd9abb1b73faabc007ea29
cac01
~~~

### Intermediate Values

~~~
client_public_key: 80c8e03f95d2254a7fcd5d8db96217b8772d87cb1dd5bba100
d16d54489c7d22
auth_key: 93865e60959a35926b97ba3dfff8235a8b078bae4c35d65c25bebffedf6
a67842ba651a0f4a5840041d95e866274c625e939cfd9e6f5719b6233e852c305c289
random_pwd: 43cb1e156539fa91455c45170e3d82574383cbadb48b769e3b043596b
3ac6e4caf242431ce1f8e9004ccc8d0e9e9c52ac0fca0feff53af46cdc0b042f6abf2
33
envelope: a8fef064636235dac7976efccdfa35f27602d7badfcb97f3b9189fb9bc6
683d96051b482407911880404982c268aca3572fb3bd7cace8cb7c45a8edbcf72aa5f
0e6f437cc676bdb604be2b5736081c5bea10637c306d6f77b7232089da953b2d
handshake_secret: 134c8a95d4b65707e3a61c1f041056196947ed4d0fdad0cac18
361f5d264d4f4b894f33bc8ac41a9573cd73e68e9665ab195631b08bf7c722f0a83c8
2bc6b1fa
handshake_encrypt_key: a6396c4ef7176e374532aec3af63a189c4abf0043a69ee
08cc38bb1ac1b7d3588d19c6147d251dd5ad111e64771ab76c9f747c5387877dd0585
0e58f9546f059
server_mac_key: 3628899bbe5a241f5853757893b1ce3c472832fb9ba6aa108cc83
838e7b0b82449fa382975ffe02c652082fbe26c9f05074cf91ca50e9ab5824a88ad08
4d7752
client_mac_key: 71d69cc5ddc55a0f543319ba2224b202ebdc6ffde6d9556497e71
d39eec72af3e3c2e3bb24e64e78384cf3b987f9a4f6e20e7e177913f9ae4d0dfd0a05
d71b50
~~~

### Output Values

~~~
registration_request: 307ff12c023cb5ce33a04efd497252442fa899505732b4c
322b02d1e7a655f21
registration_response: 8490bc8e31627726b1018dcd7d713f28a815b73037917f
111a17e19cd77ba21dfc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce500
17dc037001c63
registration_upload: 80c8e03f95d2254a7fcd5d8db96217b8772d87cb1dd5bba1
00d16d54489c7d2250235947e64550a79d94b802f32e43fae68a567610bad5df92bc1
fc7189709728f3c614cf35902799dd1a5f56eeacc3d2eb86cf8bf16d69a8f0a954653
b2d53ea8fef064636235dac7976efccdfa35f27602d7badfcb97f3b9189fb9bc6683d
96051b482407911880404982c268aca3572fb3bd7cace8cb7c45a8edbcf72aa5f0e6f
437cc676bdb604be2b5736081c5bea10637c306d6f77b7232089da953b2d
KE1: e6fb9b013986abe5f6e9586a0110395a97ad695dde622d58470adb0a0cdcb37e
37f935f7f3f385590ab7e79a62fae61e17c678aff637f1dc1f6928b8cc25cb5200096
8656c6c6f20626f6214b434e33a39d7d9fd6dbe3638925edd7a0344a312a22971754b
d075d8347342
KE2: a23b158231b742746d09240f067cb83d840034b2063e06b68399ea9e87337d10
f42dd7f763a416764954e2906070cf12680c0baac00efd58a5e79f855ec2c966b7418
b0f00b0d4b66d75f5576d5e81e19ec61d72e38b74404ed5a175bac7b8a15814c1095b
23f862b0a0a6f9bb5ca9c572d40150cc00ee58fc5d3dc29caf1662e3b2d76e008c3aa
ca570652bdfb30f49a3866f117351f99b8bd151e70a13597cdb92bc57d647415d8767
b4700b9ebe49a0d031caccea483f3be6b48aca01906674a02c10c19b49074d0ca48a1
85575f99e159ec4d8ae88fde21b846582bc52e66a398e50c4e395ee52ef332d6c2c0a
77187e2e0b3564617eb66d2878c41e6c47000f635b9a05c8af7957cba9110c3a97fa1
701644ccc03f1536560d3ab0813a8ec902aa4583d9f4b68c7365a8fc270c452cdb069
95808c8fdbc4f30936600fbeb5de66b7dc7316e89c943952a80469371f
KE3: c07ac1c850b47d882e5f6040b82720e271c30498c9b31555bc1bd6a72ed370e9
0e31c0725f7b8e9dc9a36778ff38d30f38c0e9d63cd952432509b9228caa4af7
export_key: a7ba2cafb0ed75ba39e7ea0cf687ee3b871de55c803b11ce2c8b09f08
0d55dea4de9c6d7d26fa245a2e0f93812c5c6c08608963d9e2d3eb968f1978aeb8bc2
6f
session_key: be48373b42f2427c7fcfd00337818ee10d16fdb526a971ab2c2bd905
67561d4930a17dca4214509b07d54ebef428755a15f4ad537c3c2eddb1b1a8666c966
e42
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
oprf_seed: 0373e1c2fc33aab0930f4d3ae271355105709f5fe626a4cdbff97d8a58
d5bdefbaae7801f6b661288feffef5d59d26ee725c5a3ee532b2f902311cc5e92a463
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 699e2e5ddc5aa50b551edc805ae2d33b1a20075c5218d67d4f6c5
15be2b91a4a
masking_nonce: 7d760dde6c7d2fb7a88d84b429972ed3ff3a6b35d9b5f30acc9bf3
ef86fdb3de
server_private_key: 4b642526ef9910289315b71f7a977f7b265e46a6aea42c40b
78bd2f1281617519f3f790c8d0f42eacce68456c259202c352f233ae2dc6506
server_public_key: 7a9e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa
3e421385fd2194903385345e6ac39e2a9911b6e624b0928051af9a6834ce57
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 809de01d04d92fa0f5c7f908126f734e7156833abf386e3cea81e37
fd88403e4
client_nonce: 8e9a95852bd36fceb71f486465190b60345e0c00d258066bc2ae006
b77a8f747
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
oprf_key: 80a462fe96d5ae5fabf2adbe90ca00b55382fe54faeebd597a20dd47988
96996a0d066e5c158299dd7ba1c995f904f7b1ce07a73b7e3210a
~~~

### Intermediate Values

~~~
client_public_key: a05c1725065d39fac2294418c85ab4acd54b1014bd5e2d4d69
bbd5be6bb81442e0c2746a9e13f903842568245b8a563c662dc359b757fccf
auth_key: 02a35b0204ac4c0c985d535c0029ca547d54c50559be19a13add3a03b8b
405966738de79d4496eea5882150bbb3717961351b167b5e21111d025cf45407da87b
random_pwd: 6b6179ce18b52adb5b5d9346573fd1a9795973504205ede6be4718689
3691a05bd751901f2e4bed881509aeb60719503311a780a93800ba848f9cbc4364b87
e2
envelope: 699e2e5ddc5aa50b551edc805ae2d33b1a20075c5218d67d4f6c515be2b
91a4a5787f4e1a17bd34808f2812d970756bccedd6599dd548f533e1b3d718b329cf9
3ac6a3ce3676cf9cde06741cb17423273b653b22319ad608db1aeae7031e6a52
handshake_secret: ef01ee8aa6d35c07c0b8d9bfd8386e66b6ae2812ae2aeb41287
cb378dd1ad7115f3b42497221346e130d040762635f757b96e45b87f531cbfd87cf6e
f5708d99
handshake_encrypt_key: b9e5c03de993c03f898430673d83d8f0dded47fb00358a
d2c5945dddeacac5b0ed5c24a3504c45316fa0e24d30c5a88fd8f259e7c3f1ae6d677
33eb02825e132
server_mac_key: 289e3a4a0e1eeff21728e64b9b172f029ee969963a2887f743f01
a49f4af7a219b4d6e3ec3adf1bebe77125731cb94536f079651077f364d7bdcb5486e
f9a0a1
client_mac_key: ca4bb0d475f47e0f117cdd93efcf5d396450b9346c7b6de06c701
152266df86ffbd642c1e63941d9a590ea793ee3bdca1f20083ad47036c86c9359a4a3
2da077
~~~

### Output Values

~~~
registration_request: a2c1e08d638fa00bdd13a4a2ec5a3e2d9f31c7c4784188d
441b6a709f47e2196911ce68a8add9ee7dd6e488cd1a00b0301766dd02af2aa3c
registration_response: c2ba2727c1da855d0f0ccc7e6268b21f6d425ec5553c71
a519281b58152cfeae61201d9c969f8f7b00b4d8037d89830c83326f3bacfd388c7a9
e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa3e421385fd219490338534
5e6ac39e2a9911b6e624b0928051af9a6834ce57
registration_upload: a05c1725065d39fac2294418c85ab4acd54b1014bd5e2d4d
69bbd5be6bb81442e0c2746a9e13f903842568245b8a563c662dc359b757fccfea6d3
55f5945738ba63207907bd8c4f0a28ed360eba7f6a4a5d56cb79e0cb774eb7f9f1232
b7d16c7186f8b4b2a3bfd6319b6535ef3fcb5cc3735ba58991959c699e2e5ddc5aa50
b551edc805ae2d33b1a20075c5218d67d4f6c515be2b91a4a5787f4e1a17bd34808f2
812d970756bccedd6599dd548f533e1b3d718b329cf93ac6a3ce3676cf9cde06741cb
17423273b653b22319ad608db1aeae7031e6a52
KE1: 08d74cf75888a3c22b52d9ba2070f43e699a1439c8a312178e1605bbe7479731
9ab7898faf4f2c33d19679a257bca53e27a7c295b50b0d878e9a95852bd36fceb71f4
86465190b60345e0c00d258066bc2ae006b77a8f747000968656c6c6f20626f62de9b
fa627cb161dd7098c8a582f5fb3a38641e8df3d6e7c40dffec1adff5f0d148716cf15
cd11a04b80b11cc12a1056493b23ee23267704c
KE2: d8233fcced29ef1fa71dfbb308b081406ab475d5290bf59707283e346f949a7b
3fc63bddf486242b03041ad6ce2cafd64f1b5e4761c79f667d760dde6c7d2fb7a88d8
4b429972ed3ff3a6b35d9b5f30acc9bf3ef86fdb3de5330363f69acdf7a710816af4b
4c7a96d0ff822ecd61716bb3694bc05c129e84a899a41f414d306dcaf7cce152c3539
6bf4bd5551871c3d8c37b7f9910df69006bf68da0d6b886dd877f883fa5239655c880
c0f4ae6b24f11d80ccd90db075768e35f6afab5a227065c2d4ddd62f6e2db5b47de20
2ef18e1af6aeb5cf27447c483ef7a5a6c5dc8e15249406c77ec9307e2c9af15a62add
9b809de01d04d92fa0f5c7f908126f734e7156833abf386e3cea81e37fd88403e4b0f
d650f0efdf4cec17e85b9cca2fa7ac7f1ff76ca94ed07e8ac65afd6304ef8102bf243
76fc5b064edb55fe02027d7fef41d05db3652db0000fa8df73e0e83d5f038d7349855
14d96f9582b8a28ff708885ed07ec5152b220022b43bf89e707cb5a104f12bfd202de
6cdf12c57cd850df2d96112dd96158b374ba82ead4c3af2d4848df3bcd98742d
KE3: 5c4db2f92d5983e0744ac276e4f552e1f365cd923125d3d2e4f06b3adf4c26dd
c9fb64f392841c665939f8dc501f5e23f89e12c5c3217d12a58f93b0c880cf7f
export_key: 5cb305aa150a893b2ec8419443f2a99cf71f0334ee2d904521599e498
d555b40a824bf6d3e04321e1d8dd623c731405d85381c76e3c715917a33817419c59a
48
session_key: 4af4ba258437b3c68b4a08ae1a534bc5fae8f2fde17ecabe6a786a52
4e2fac092c33ba98409f4a5cc8a0d3a3bffe1893a347fb2687522791474936c6924e6
e1b
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
oprf_seed: 4a93bd1818d5bba2da348875c39ffed18090aa4e64b9dda813f923f36f
2d81d16b0de9ccec1309cba763ca6fbc7c674d165e5e2b2b6b07d781a2c87387df5f0
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 54418b56df192a9221dc1017ec1a7d302dfc7bca27c873f4ea546
7a338e43bb3
masking_nonce: a9298385cbd06459747280afe6ec08d07cf1d73ca8ebea2af9cc50
cd5436c281
server_private_key: f0a17b7f6b056dfcfbee5bd7db70a99bbabf1ebe98b192e93
cedceb9c0164e95b891bd8bc81721b8ea31835d6f9687a36c94592a6d591e3d
server_public_key: 741b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230
316ebd2b419ae2f0fbb21e308c1dfa0d745b702c2b375227b601859da5eb92
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: dd355e4b158018757756b4d4698c593d4f438e1dd41d942810945e2
9be04cac5
client_nonce: cdf6aeeb3fd93e6791a524b98896c2d2a5ca5fb724b80ce01077bf6
70a821a46
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
oprf_key: 0654bd883a1a55f0579b4a049b8efb473697cc0e0aa5c5ddb232cffa552
a01cf596976c87ccf6521eb3dd80aa07a1aaf047c32b19c19ad28
~~~

### Intermediate Values

~~~
client_public_key: eaed7f4be09df2c8b4177b6cc09fb550be94efc6ae765a96fe
b4cc76028a66099d2f10e9a8d64817b7b89b5c2810b9f1358bf319c3baf59e
auth_key: c4b1c6f51a7696db4a4d01fe20612810d317c93f5a6165d997875b65035
04e15bb8faaac1bd68c94eb0388fde75b87b5ed08f516d05617f53e60f39c35c12420
random_pwd: eb50656d9c6b575eaef1c6224a2c528600df8fff9d2120a37ee9a6df3
4d596dea67a0a00eb789cc6163898d8793253c1a1d5b7555509df030c26286e9b4e53
ef
envelope: 54418b56df192a9221dc1017ec1a7d302dfc7bca27c873f4ea5467a338e
43bb3db2bcfcc5bab6285e224e5a617d65864856635d5b644c1a5bdfe2cff4c039b2a
c52ce9fbcc4aad35a9b3e72db39416845c4192ef3f05edce9c3b399ef2a93d89
handshake_secret: df4e2cbb606948b453957962ee67976049b3e9846d050e95953
9f477340a6d9fa050e2fafa6f211d7990d99ce816d8cd996b8ce807ac882d80d31cd2
1924b4c6
handshake_encrypt_key: 912f540f5865412d5e6d31fa0b9b8b63408af680cb6724
332a49f3bcdd867a28e1c0415744ddc95e5a8b9460dca6dfebd7889ed740283c30df9
99a70c37b5140
server_mac_key: 44b5ecd940580eb087a6756042747174772696d323f734361dc32
c8f383cc2d2b1a73fdf2e5cb046bb1d0da081fccd0f2fec4b6807192a4247c55df7d6
6c2ef8
client_mac_key: b02581e4fbecc0f292b83250f73b822fcdbe65e8db2c83ff59a28
7e995404b9fa1b517e11963b077baba49075c8566f870bd40a39c8ea107447e75e064
f11756
~~~

### Output Values

~~~
registration_request: 66660fc08075380d7c2d4728ed1a7b550647e8231d6d29e
60d3d1fa8fa3132c8dc445fa9c94de42e5f12e29de958e5daea84eba6a6410042
registration_response: 8a9be09febdbbc4354cf9f28833c346cd1b78d23c7789a
533a6c6ece3a05ee003dfcf8744f08a65fb0c9c97111f38d673193dc1ef9b1e62d741
b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230316ebd2b419ae2f0fbb21e
308c1dfa0d745b702c2b375227b601859da5eb92
registration_upload: eaed7f4be09df2c8b4177b6cc09fb550be94efc6ae765a96
feb4cc76028a66099d2f10e9a8d64817b7b89b5c2810b9f1358bf319c3baf59e2243e
7c2493c4135827454fe80ad6f12cf9e58e6916a83e6e56e42c507bbb982e9875a16a2
02eb3c0c124a384fa85c53875177b5709c664887739e3b832ecf9254418b56df192a9
221dc1017ec1a7d302dfc7bca27c873f4ea5467a338e43bb3db2bcfcc5bab6285e224
e5a617d65864856635d5b644c1a5bdfe2cff4c039b2ac52ce9fbcc4aad35a9b3e72db
39416845c4192ef3f05edce9c3b399ef2a93d89
KE1: 1c83acd948f714989a2276ef0c3bb16d5b637942e6d642da9826fbcba741291f
0b093b8c94888ff0ab621f90344f5b8b72159e2eb80651c1cdf6aeeb3fd93e6791a52
4b98896c2d2a5ca5fb724b80ce01077bf670a821a46000968656c6c6f20626f62ee78
4169a2abed53764292f2e7385c5dd99ee21d09a4df24405706a59abb6d91f3ed3dd8c
6649807d11cb59ddfa23fad081ddda04ea49075
KE2: 94feef13eb7f9d7692f9fc9f489e69d2ce8cad9bfda0093107ec833a673d82e6
4635cc133ca8f5859f3042ca53ad3785ec16d30ec7987bffa9298385cbd0645974728
0afe6ec08d07cf1d73ca8ebea2af9cc50cd5436c2818707d737d143ddc98f1707fc37
04a8417864415f68a0b7f8886478906fa073e73507f97c3d6065e13a58cd8eb2a29ba
9939406911fd99cfba0cb5d0b123fdb59a30e5ddc26ec3a77e2e9f6bb45d5d0e79f89
44fc46981fafa90f07621787e3256d0b7452cf2b21a0f8e6ba9fa09d7060d084669e2
744f8e2f7eddb45e15b855193f61b1fb717d70d89fc4ecd5ca1b43ef1f31744b441f1
84dd355e4b158018757756b4d4698c593d4f438e1dd41d942810945e29be04cac55cc
2a00d1b42d14ac07e05dca2dbc20661a4f30909137bc3274a25c3fb4310fc9c61d76f
c6576c8ed1c9816719433acc81722a2a5e23357b000fae6dee9353fda48b6c3b353d3
5001916816398b73fbabf06cb29d93aceb9c57aa23af5d867d2fbd24cb1e64a72ae99
2e8ff9a0a63a4ffde5f899a610d076c8f81f875c0eeb9cd5cdb7ac702a5d961f
KE3: dcfb4c62ad49187e8d101b0e56b894759821b1599db44acec9fa4d7940fe4274
3b33b08eaa2ef121fd7ad0deba64c4177cda716e2b7b412ab46321916d16cc34
export_key: 6313f5fe94432d50ac27ea1ee2f40fb7b71064dc9abb6098ad2d75133
6e9d431b65d2bc51698c92467a8a8e9e6079739de077984ee7d0e3f8d70b852a087c3
63
session_key: 24faf1af79df22005e17f606d2b9fc1445b1375b73dd92428d2f9248
0b38561cd8f528e0a46e1448c5fd9831e0217add12b1b68ac32b289dd8432e2ddb257
644
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
oprf_seed: 359a758a14587d82a8e9618af33fcc244e3d817fa2805b6530c7b06d45
f11e4ec81575014b73bfd06972c3137d4aaa1e7c473260e8f62771688271b64a0422a
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 5d9e5aa771430e57b1cf00fb11bfc581f10ee884d83ed9465abfa
47523b9b668
masking_nonce: ea5c0d905b70ab7519076037a49857ffe5be6429685449527fbea3
310bce2e14
server_private_key: 8cd37bf60927fafeca73ed8093538a994b1a8bd463666faa0
68e5ff9e00d588446b7d6cdc09ae8df069b30987a2cdd39286e0481e87ae227
server_public_key: 684e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04
ef823fc5c55e19163c714071efcab7ec06ccce8e6b9eba74ca92444be54f3c
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 67e0fa08179c3c662e6c6e2ab3d05071f95205de6ef42c4bdfc9749
862b24971
client_nonce: 210a33c6b2deee7dea34159b5818c371fb430ce278c346ea60a9b7f
361822528
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
oprf_key: 46621ed0a5ab77fa045fc7820a985bb7e82a6a7453c4828a5035aefe8e4
11bc1a6c3d6ac450a724019eb4c2fa5a0fc5244a027b0598e012f
~~~

### Intermediate Values

~~~
client_public_key: 98a828a8b62c7b24e7f582973dca526085e897c44a9e8b6a61
e7dd47ee5c3bda07d0782650a36e417695d9cc9708f2ef351b13769a38936e
auth_key: 3a5ee40e10cb063026082218acea834bb5bb11a0c97b61fac0e5957c379
8a253203485835a44860c750c4beefd3b6735e78dc9a7f31c4083d61d047136b52425
random_pwd: 2451ef1913b8fc0588af38fed9a87da9ec7736d105b0d66c91bde10e9
ab8f3b537480cd2fab5258d790fdd9325a680d0abc88234363d96c171b7b37a2b4084
f3
envelope: 5d9e5aa771430e57b1cf00fb11bfc581f10ee884d83ed9465abfa47523b
9b6686bcadbab2c9885a3cab0013cebac8f3a68c720210826d4076a3356d82d183c2f
fd6390324835edce926263f4251d208fbc0a2e80d464253d8b166bf9b4d01c85
handshake_secret: 08c2e1e1aa545a65e03309c7d310e6d33bfec15671b3872e956
bf32fac00dad9cda269cdd4b926feb740216a2c298b1af806d0e83571bc24870e56f1
4e3f0978
handshake_encrypt_key: 042e756f742af78471e8d51342505e734fa35b07e53aa3
8a3e00de1758d283e5dff1348fd20643c6dd7b50eed6a90fed58425ce247932225255
75bfcbc6eebc2
server_mac_key: 0a7720e6f7196a6f2db85e65037ed33300794be0cfd747df3040e
51bce51f4b42cfad0c112fca3b5722347892d08bd67d61f2057314c02c376875304f5
9f1357
client_mac_key: a13d15bbdb2e75455e1f80b4b6c677bf5d8476de4fa3798e50469
33042e336e6377c08a6949d0987364888e0773f5d691b8fd09820493d597534efca8c
2ed8bb
~~~

### Output Values

~~~
registration_request: 8a8f12abe7f223895549fd121f9d6124424273b7524e033
f610261caf6ff83eb92d848318e7574c06ccee189b8b447b0fd26a348942d787c
registration_response: 405c3912de770cba1ca204960e658e22de2b21b50028c1
f516556e375fe0442455ee3a0dffd90d3d198222781447ad96d63b8e3a135c829c684
e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04ef823fc5c55e19163c7140
71efcab7ec06ccce8e6b9eba74ca92444be54f3c
registration_upload: 98a828a8b62c7b24e7f582973dca526085e897c44a9e8b6a
61e7dd47ee5c3bda07d0782650a36e417695d9cc9708f2ef351b13769a38936e12eb5
9125d2876598a94dafbaad315080118f44696f7949e8498bf26e19eb12d63cebf6a53
07aac5ca68019a13caea7b61988dbf053d0652fd3db6b42b9d2f335d9e5aa771430e5
7b1cf00fb11bfc581f10ee884d83ed9465abfa47523b9b6686bcadbab2c9885a3cab0
013cebac8f3a68c720210826d4076a3356d82d183c2ffd6390324835edce926263f42
51d208fbc0a2e80d464253d8b166bf9b4d01c85
KE1: 442b8d7585abe08bbb6b03b3d73c7f5d81cba60845258a4174e7b8d25a6d7238
8ec7814b7f0a0559fff29ac97c329f2c7b0844c3adb1c6ba210a33c6b2deee7dea341
59b5818c371fb430ce278c346ea60a9b7f361822528000968656c6c6f20626f62d0ce
cdcb40e68a8f2a3c472d1fb7f0d96ce9effb7b71281a588df2ca0666ce00126e14b9a
28bbe73ada49d059f7794e5da6be7e7bf0eee12
KE2: 9ac1ff5eff1a59b74796c4976dca4e2614523313b41c3b88c52fa964a5591893
b755ed3f9a1550923b2029815fe6e188f98154686f8dbb03ea5c0d905b70ab7519076
037a49857ffe5be6429685449527fbea3310bce2e14aa88ef495522a82ae9d660dc10
f98f74c56f96fbc359219f6915d28a38b24c0fd9f0c6fb299dc1a3a76b883c4877ad8
0c0a1177353cfa5a1b41c819e6de7072f9daa664827467123b38c0975339c2b4173f8
99bd2335e9970481a00a4f4bee01d89646e7c1ba31bd48c8158b73685ebcdf052af27
781d2ad13a31535cbe081b128c70159de02fcaa1e0ad260aa64ebca958cd27b21a822
8567e0fa08179c3c662e6c6e2ab3d05071f95205de6ef42c4bdfc9749862b2497180f
64e52526682c9d332c4cb517bb261e21b86bc7199223b962c3d2906f90bbf3252a02b
f2889a01d0cfcd6390b8567854107e38abb21033000fd46d8f69a450636f1957732d5
79d67a558fec6805a86823a34459d1ee3052c46c082c40a11f222eaa7c3db28c046e8
dae2af9b36b52ce40fde03c91c3a982b077a7825c1a5a099bde3a70524548f70
KE3: 819ab4e479bb0cabdbe8b1d8e01d01a034fe824d48ae6ec37ade4f8c18bc8725
d9959cfff56f5633612fb1cd299274c86cc035b037bb22c7ec0fb46c7ee8082c
export_key: 6c92e9c44ef46ed490d435e4c2798c7237b3e023c024aceb7e89687a1
f0263e7d83efdf67923407b047e299dfc6ba877c594308fe71e686a0b491bd6db07a3
59
session_key: 4c7f315a28a598e85204680405d894deab86d0756f26520a52325d93
5d2e4b6bb37340c0157dad2d3f22506c66d77c9fe160296a9544d03e096b0b4d3c05a
a08
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
oprf_seed: 8da3443b70647670e7d9874e301decc78677b9f590a8c70bdeb397ac80
4bea2db0138425e50d03306388e18991b67aed01936c1f396f9bce6ec51cbcc0570a8
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 6ff7157502f2997edb76b4f27bdfd7daf7ae872eedac9e7ad4946
58b01575344
masking_nonce: 67b5f07f83a552d73594f759da0f2c6273c43ddf1764f9bf50a454
e1b4159e33
server_private_key: 0fb0bff035e9b9cbae6cfca36aa4827ccbac66177b64fabef
a67263087c0cb4e0d9cf547979e753c22548e3174abb5ac630d97dcd4af9830
server_public_key: 8071f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444b
a7ffe82aab916bc5ca6a11fd5fe1479e553040a8b724b6305c3f4289f3f39a
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b40f7113f62384bb73a9391eda777cdefa49f424aec2925e02aae22
c0a5adb23
client_nonce: 3ebb8675685c5370ee8832d574cef1eca7d01db686177ccce44a17d
92b6ced6b
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
oprf_key: 94f577a43cfe24d9b1cb890a1c07fe0a6494835d91a3aa1a2153fa72933
61ec573aadba1d05f2a4126d104073b57cccc0a8a1daefbd13a3d
~~~

### Intermediate Values

~~~
client_public_key: 2a1d32098cd3138c163c36d44b911016358ceb0037769a41ae
5aebbf461129f33b3d0e7ae1da32d088ea9c08e3df940b23232aa6471eae1d
auth_key: d498dc48c340d0ecefd3a73ab884618bff982b72a48e263025bf673fceb
333b0b4d1aa00fe0bdd03daf4b5c9c6585881672c7887d29092dbc62ed1314e4d8250
random_pwd: 97fb370e41c47292ef986687a95daf233a5ede9e3151fb7b7c9568105
767aac54368656212e89e21fc7a030dfc48454bcb7b291cc445706fbe4281451d3264
15
envelope: 6ff7157502f2997edb76b4f27bdfd7daf7ae872eedac9e7ad494658b015
75344a4963eb2ac0ab63482dd73bb6f9eb12b0a0ae0a69a977c4a6624e8c3a243fa1d
098ee1746bf3499da12f68c15d186ebaba69f623ed69597f2621c0cfd50ff105
handshake_secret: 044b7059dc79b4b8cbc443b3afae3f0235cfac97f11475a7c5f
bc13ba708c874f248f1e8b29602cdde131cd58e51f27e6a2afc0be566ca93f5790b77
22f633a5
handshake_encrypt_key: c86ebeab654379e8f9b87a716b55fcb174667a02263bb6
049d304642fdf6e6fd16bcf4dcde3cf09bc7d11afb0814dafa7644c63c5a4e36c297f
adea3bab487d6
server_mac_key: 230144b7d10ba392fe81e4dc28c23b38a8db859dffa63e2a98947
59253c255c515601bee37c69bbf316824a085347a506764c3f6a20e2a3db30cd0eda3
b6ed85
client_mac_key: 9646c08ab1c9345b161a817136c7030abee9095699684f8c3fcee
d3d0fd82fe96afa6ea998c7178ec3acc3d085d6e7d771262ba4773d7aef59bac211b2
f50046
~~~

### Output Values

~~~
registration_request: e499c1ea1a644df877a01f23ddc5dccbf3add4407605f67
dcc55f29c2ccec5daf9bc231dd62aa61cf2c9fdeaf59b3ed7a8f33af59ba20914
registration_response: 9a1acaf50b8759d07eaf8b0d6c170877b8ec4158aefce3
200ae397d8b6a57b2494a124eba14306c3757d162c3cc493f8dd54cf2c8b94f9f6807
1f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444ba7ffe82aab916bc5ca6a11
fd5fe1479e553040a8b724b6305c3f4289f3f39a
registration_upload: 2a1d32098cd3138c163c36d44b911016358ceb0037769a41
ae5aebbf461129f33b3d0e7ae1da32d088ea9c08e3df940b23232aa6471eae1d0db6c
eadc7d0049a87ea94855ba7370e8ee084a5f6fc519c4b023ef26e5f65cd61c5402dc1
eba62e989618aa6527c567979326a58101b0d960af461526bd00bf6ff7157502f2997
edb76b4f27bdfd7daf7ae872eedac9e7ad494658b01575344a4963eb2ac0ab63482dd
73bb6f9eb12b0a0ae0a69a977c4a6624e8c3a243fa1d098ee1746bf3499da12f68c15
d186ebaba69f623ed69597f2621c0cfd50ff105
KE1: 501e3dc8509cecfa36efadeba5efd0e4f66988ff9575c821b0128af06a2f5ebb
d77362f2a9e63b5a76cf5a636bad31b7a86f6c6803a2c9953ebb8675685c5370ee883
2d574cef1eca7d01db686177ccce44a17d92b6ced6b000968656c6c6f20626f62f2a6
7ee95170c51833a88419529748e55dd13e23ffed8fefdc1d2b7c939b6371630031299
800b01a99f83129aa986369e4a188220d056f0b
KE2: 686fccfad30ede30812b2a25a271a9374f53f1d3cfdc752f9cea358809bf8c6f
05157113eddaf52ef5dc7f0b5cc3c2236a3dbc33f46830b367b5f07f83a552d73594f
759da0f2c6273c43ddf1764f9bf50a454e1b4159e334077ff522ee666a27319e603db
251687354c8d8054bb6a92e5fa2c177c12c7bf892cae903437f9e7fef1f29be58cd58
b6dffea2c22c16740dbadda226bd0500e7bfbed12200af63cbf71e688457eb0bb81ee
837705a9f580fefa3ddf8754470b00f5be97ac5251e481963c26b895e2c413d4be6de
4219ce8a772f36feca7be6d0f45856c427a84e809c39bada78475d552448febcebb47
10b40f7113f62384bb73a9391eda777cdefa49f424aec2925e02aae22c0a5adb23d41
0d142e679aee86adbe57da4801741034120c59fa942ef44c19ffcf4a4d65200d5e17e
7d287220037ab038ee08f96c9dee6db68f02cf18000f666cc512640ce5fccd232c877
fa1bdefa2e44cdd82124216da51b9a65b63290933b80263b2a0a46fac878df4841846
2888a210ae929db2fda018ff1215a108d984dd979177de95fa71d1c3c2e1e458
KE3: 17969b0fd80f9ca62742c2fb695b605bac451de49785ce5a87df4b740ac139e0
3c29070dcaaa54f43de29c0b6fabf580a03a6c92e14f32bd28e21c6b13157aff
export_key: 5b964b80a64f1612aac6eebe163e5d400c3ffc39b7321abf3e8d6ec57
c607cc2243f0a6c6fa56987dfd7b4fe8c3a2eb27a8b2e5f7b42af7fea04bb672a736d
a1
session_key: 403a21fdaf3d1a22b473b49004c87fc4b8e0d4530bfa2288430397d5
d15c024f51e63d51e5e1cf96690e4f2bc9fd9176192b5b313b0df112504407ecb502a
5b9
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
oprf_seed: acef6f13fd82179b9d896a0e67f1438ea13b9b04582bae61b95c0e405a
2646e9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ac557b0259d3a1337a5118907c35f41e179d1f9d8e44412fa6da0
b086a7c871d
masking_nonce: 5e51bac363f66cb98f0e921f2cc0ae7b1b20e6db2d165c556bb06f
87952e128b
server_private_key: b3c9b3d78588213957ea3a5dfd0f1fe3cda63dff3137c9597
47ec1d27852fce5
server_public_key: 02e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398c
7100af2939f672bf
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 4448a0aa1f3e4c7adf0f41511b6028310d75604ae9fc988dccb46be
1ada3e1ca
client_nonce: c0159e3e2007c1c39e99b0876d5400cc0e594965a27da61f0c39e80
2ef5ce074
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
oprf_key: 1cd9df9c1711be0cd4df97bd9abdf7994fc31769e1cd5971e4bb28accd5
ceb99
~~~

### Intermediate Values

~~~
client_public_key: 03ed0695944d5318da817f4cd374ae184a27725a4ae4e92886
f8911c18689d3dbe
auth_key: 911c1244ae5456dc8f55e214740f0a7fc26b4be4c60d7911af1fd273bcb
d8b65
random_pwd: e181d6caf95884bdf04c2818e77f560bea6034cc37d539ea680cddd59
a955e81
envelope: ac557b0259d3a1337a5118907c35f41e179d1f9d8e44412fa6da0b086a7
c871dfe57cbba749afe8c5101da64084652024a417b3d45be59004108e95fb53dab0e
handshake_secret: 5dc2079cd3b1156721aef64eff2195a145117f93b14e954fa97
a48f7932de703
handshake_encrypt_key: 3913f9c3db258490c90503fcf2f0b02b44638a4235edc8
e65332cc0f62736672
server_mac_key: f6bc0ec65a57c99decacff55a4f22cc7bbc569ef791e0e74c3b06
9c69764b15e
client_mac_key: 19e6852c72aa1f81f10f568f46d3c6b7f6d471701135fd8eb8714
21980048d6c
~~~

### Output Values

~~~
registration_request: 03761c2597a039a535c3180bd3fb6ea9830baa50376dafa
6e98bb41be2aaae0e91
registration_response: 0302e9dc9d7bdb0d8a52787bbbbce4aad23872ed7f9344
318068231d4c3c6225bc02e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398
c7100af2939f672bf
registration_upload: 03ed0695944d5318da817f4cd374ae184a27725a4ae4e928
86f8911c18689d3dbe5de2ffc7af12c969942933e1a5961381ca7eb3de79c746d8fb6
cb228e4224ca0ac557b0259d3a1337a5118907c35f41e179d1f9d8e44412fa6da0b08
6a7c871dfe57cbba749afe8c5101da64084652024a417b3d45be59004108e95fb53da
b0e
KE1: 021922b40d051877d0f03ccf2831eede9b328e22c8b173d5f28091af0b92421f
54c0159e3e2007c1c39e99b0876d5400cc0e594965a27da61f0c39e802ef5ce074000
968656c6c6f20626f6203285470567bccdd3755aa8d00261e1ce65aa120e15571cc97
72789a361b4cafaf
KE2: 02f114aca700a14972b0530d4f04459455732211b8a7e4ecc39e29d05b27b634
b85e51bac363f66cb98f0e921f2cc0ae7b1b20e6db2d165c556bb06f87952e128b19d
9f1f2786ddbd60c1986cfe5092edf177d3c9f6c60c7abbae69e21cf9d9428f7bee1b9
35bd565cef566e75e30378730dbfc01f033b6811cb1ab53c6277e2e9595590e548568
cb04d4705f41f6f7966967c68d354a36a7ee502fec55d8e938adc4448a0aa1f3e4c7a
df0f41511b6028310d75604ae9fc988dccb46be1ada3e1ca03651207f3887f92cfec5
6edd9b9df0047c1d6b7bfc55b3650a9579d44f435b092000f1dc2f481006e6ac3a55b
b93fcd69ab0b8b512f7bde973a79a513d9ed859fbed7e51c67db4ff084e3f6287160d
8c067
KE3: 34986cec47a3d379f1aef64a4045025d54cbe813b1836bcd34bfea4cbf5fd387
export_key: 9e62c9db2f115149d293513451ddc206a5c9ef09a2a2a5e2185219ff7
c4a7ddc
session_key: 6879223133bf151e90226332404efc32cd668d4d9402d4a2849cd069
e3705b7f
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
oprf_seed: 3b39e40e9ddb6687003594c49bf4196038e20529663235bdc0536727ba
6f6da6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4c1b06bd49a9a8701c011e1a9afc49cb380597a369f51493162c3
73b7c7ceed4
masking_nonce: ad2045825d6b5bd3c66f242ffa3c11a05b88bdc6ccdb9387bfccd6
e8ae08b2ff
server_private_key: 2bc92534ac475d6a3649f3e9cdf20a7e882066be571714f5d
b073555bc1bfebf
server_public_key: 0206964a921521c993120098916f5000b21104a59f22ff90ea
4452ca976a671554
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ba15dd925b699046e114832866a028c72afa677a8cc73399d019a80
8d7a1188c
client_nonce: dd734434621db5c287c600687471a5689f77cb0784d613b7f408fbc
b2bb18e00
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
oprf_key: 4d497e253fbf81428b8995503392cbd5373f14a726e06ecc662f4a2413f
3db37
~~~

### Intermediate Values

~~~
client_public_key: 032ab1fb21439989391dc817fe2eab3a493fb0fee342499d0d
3015d0e584394248
auth_key: ca1a5fe815e4452693976fd065357e21cb7e635fb86e17f03484028715f
2f6e9
random_pwd: 03daadc70430fe90957c516e4fa462669fcae4ae6b2fc20044fd1ad5f
38c0994
envelope: 4c1b06bd49a9a8701c011e1a9afc49cb380597a369f51493162c373b7c7
ceed4c44647f3f3bd1119b0306c02337f76cc40202bb9c61410c73b275ff060516c29
handshake_secret: 2b12d2164df4b3df28ba6b94697a753c114fedf84c16dee720b
67b12581ffa67
handshake_encrypt_key: 91be90210ab821a2c9e39b79f89f668fc4e254897a9c1d
c81eacc83738689500
server_mac_key: 1d53dd554fe56ba8826d94af3fb2084866f70fb20409680cbd618
1b9d87fe32e
client_mac_key: fd3a45da48800a2fc3ea9414ddd6b81b72d2c060a43cbfcfa3d2c
f7effce806e
~~~

### Output Values

~~~
registration_request: 02cd04a4a3c6b37f6013d848e1c63c204c4593377e9a14c
68e95097b615d29c129
registration_response: 03f0158373133204a4053d7743f0836d52937e15783e00
fd3a35d5fd351406514c0206964a921521c993120098916f5000b21104a59f22ff90e
a4452ca976a671554
registration_upload: 032ab1fb21439989391dc817fe2eab3a493fb0fee342499d
0d3015d0e58439424875fd85cd2fe46c6e4c0a40d224646431c1db2d0fd83959bbaf5
42786d617f7ca4c1b06bd49a9a8701c011e1a9afc49cb380597a369f51493162c373b
7c7ceed4c44647f3f3bd1119b0306c02337f76cc40202bb9c61410c73b275ff060516
c29
KE1: 02e747d027881e63565ce0a611dae6da50c2a8b349010a52f5c936169be1e0f9
36dd734434621db5c287c600687471a5689f77cb0784d613b7f408fbcb2bb18e00000
968656c6c6f20626f62031e7dcb77fdba4b7e7b1625e43dae84733b28eaf2b4fbd7df
141b1ee353748b44
KE2: 03c9c6c1a12ef0a78384f2108cec1388f5ff5c8f09bf9d8f1337f4d46befbbac
eaad2045825d6b5bd3c66f242ffa3c11a05b88bdc6ccdb9387bfccd6e8ae08b2ffb22
9cc6f076e8569db995ba2d315b3e9415df76d1fe5c3dfa478ced6b5ab3a732c0e6301
f7c5fd792482ae082b9e1fa9559ee1df9388aadc8fdfcab794268449b0a52b0020627
1360486738be43a48290056c55ffd82d835b20086af648dc5a403ba15dd925b699046
e114832866a028c72afa677a8cc73399d019a808d7a1188c036d85072a9cda8438f67
dd81042861349f697c06ad4efb068dceb58c98986409c000fb738b2462696176c0a96
57a2f5e553cd08c229f5be3a316e33d0a8aaa6eccafb42fd8f52dbb6d0b0eaffd286f
7f07d
KE3: 5f32d069ec9e03f42516f2c95320fd3d6e3039ba678c8d40ca8add8ce0f10dee
export_key: f407a82f94047875899471c46da594b0703f855b76ebe7d0b7c862785
0c055b0
session_key: 2ada7dd4c6b9297e3853ba8b70e66e63f682dacb5ade7943860b4f8b
98e52e74
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
oprf_seed: 58bf43648c9cdfe5168d8c20b0bd45abb73ac45d059ec44fb209a1c34e
cd8294
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 7ed2ea1f5b4d18de64a16c4ebc14ebff765d1a3e3c858451a7ccb
cca3746c927
masking_nonce: 661ef75d7d42c0dd474135534be473f3ef9642d29fec1df6d77d63
d22cf50991
server_private_key: b0b4f35c14eb2477c52e1ffe177f193a485cccf5018abbf87
5b8e81c5ade0df0
server_public_key: 02e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e5
59ae18b6bf7bb5b2
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 87044b26500260f1307f315ae6390f90a958d29b3a94618400fb8c0
20f2b1133
client_nonce: a1fdb5cb48df17a303825ca47b7345ca8695fe4fd1c19d41e7be64b
dd8239572
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
oprf_key: b3beaa1040c33bbe497d25e1728b9c84221a91f6abf75c3547312db3ed1
e40bb
~~~

### Intermediate Values

~~~
client_public_key: 0318754d52414b4636dfa48d5f628c9f676d695c7c44f2907f
1c2cf208c49d3512
auth_key: d1cea706a45b68ac7024a1bc16b60008e766ccd93a5ca500b609b92683e
a1f3d
random_pwd: 19948411d5b037b290991a3350c6dfedbf47ab8941d906c3d0c25d435
d55ddbf
envelope: 7ed2ea1f5b4d18de64a16c4ebc14ebff765d1a3e3c858451a7ccbcca374
6c927051d4e3d043b7669597be0df1854b9ea2998dad363694bea2dc046bfddb1d0c5
handshake_secret: 83ef28847fd9fbaef134dacda0e6892517762216b565a676bbb
3f53ea7533e13
handshake_encrypt_key: c8757d4be1e8d1956612c6b15a3f63c54817a3d9a9ddc0
03225cd50685642a0c
server_mac_key: c51aa58432d12b0746d0420d73b0808981bdfe1df3474d42fe2b1
239cb554fef
client_mac_key: e938f72c809555db2986af109a8a484b981a5c2ff13ce937abc3b
45969095f66
~~~

### Output Values

~~~
registration_request: 026aa49819f2c29b9543cefa0850db7fd36352c6ad8f47b
631b5b621266b670f7b
registration_response: 031b1be0499ddc2ff428c222adb77b258baeaa8c471a20
6875803d525a56c656ab02e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e
559ae18b6bf7bb5b2
registration_upload: 0318754d52414b4636dfa48d5f628c9f676d695c7c44f290
7f1c2cf208c49d351280f37eafe7958918c209b58b82ab55c55170a59da1d32d95c64
3b33ecfe4d7977ed2ea1f5b4d18de64a16c4ebc14ebff765d1a3e3c858451a7ccbcca
3746c927051d4e3d043b7669597be0df1854b9ea2998dad363694bea2dc046bfddb1d
0c5
KE1: 0223c6f12f3c763bdfea59c13d8f1e055b02277625aa06cb3d839e03a60268d7
c1a1fdb5cb48df17a303825ca47b7345ca8695fe4fd1c19d41e7be64bdd8239572000
968656c6c6f20626f62026ab0dc783fb12c9427dd0bcb4d95f5b5212f092406dd581b
d337c73468953226
KE2: 034f1d14b1453be0d43b03fbfb71b0519357f0a3a73d4897a13efe745dc21a5e
d6661ef75d7d42c0dd474135534be473f3ef9642d29fec1df6d77d63d22cf50991f77
0166b7772654fc30a07663194dae3574bcd302f53b6c90d98a259ac29515e5e9a2976
de9f199d73172c568e18d447b2eab06b72a55516abce08a27baa417abbd9d711ec24f
0c72a7e21bcd7f58d885b4b0740b1f0a2b9dad99327f1325a8dc087044b26500260f1
307f315ae6390f90a958d29b3a94618400fb8c020f2b11330222d4232635f4ee37067
59740d7a0d8fb6a4068f2fbd34be7cf065f9989b637cd000f1e763c5b43237ad5c412
b698696a4c0ac72fdfc4e51dbea130ff62d4de51c8377df7fe2ba1cb9522adeaf16dc
9464a
KE3: cfda8b01540875bf2a5efa420d71f1aeabfdb9a5c3e91ddfb60b3235d7c7f03d
export_key: 103c144317297354c39757c283c8cce13e378a7df6a846eb4ec289797
da7d1ce
session_key: bce09d03986b738be2c5e8cae9b24ccebd619130b7249704fd56c1ec
5f98b497
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
oprf_seed: f4d9155aaa8478bc3c508d35b0c02e6823360fe5f6a59784977ee52bc8
cef7fa
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 69defc01cc359394d9a870f0127696da01807169d7fc5869c646c
f0a5594e9bc
masking_nonce: 24d17863e4d3e015ff270faec867e6d26b6983501332fbe5fa2180
56730b2042
server_private_key: f7493200a8a605644334de4987fb60d9aaec15b54fc65ef1e
10520556b439390
server_public_key: 021ab46fc27c946b526793af1134d77102e4f9579df6904360
4d75a3e087187a9f
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ba2caa7e2d8ffacea943079b4fe3532e2de7a4f927fcc705725a671
c8fe53946
client_nonce: f316817d6a723baf930d76db44076388fa88d20cbc4c5f6714a1f0a
54d524c12
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
oprf_key: 4c4bb037c846f851ee2c16fdfd4a02f48d43f4d9fc45f369f28d7dfd8c0
25899
~~~

### Intermediate Values

~~~
client_public_key: 0316a7837881d7e3a8ad79534d2c36ee7d463e7a3db77698a9
f818b205237cdab5
auth_key: ff1cb55295302c01b21b5f9e586c8a1c366d2b8921d7b15d2d5ed0b94a3
cadd4
random_pwd: 46d12a3e6a82f9ac93fe6473b79cd59f5c01baee2cadd29ce7e94506a
6be2bd0
envelope: 69defc01cc359394d9a870f0127696da01807169d7fc5869c646cf0a559
4e9bc226212e5cc98726487f6bf8d985244155310b5b9a33fd16c28763c319fca6b0f
handshake_secret: 5e203d38ba1ba946e7bf0aefc01875bb4dd7ab27b1229710e1c
48f73f8db1451
handshake_encrypt_key: 9a592e43faf02c55b3ea9bd0fbc8867d6b1bd85e04f632
0bafe8e935791da856
server_mac_key: e0cc0b24b4b873d03466d7a900a316f4ebb0b28a122dbf0ef733c
62a7b735d6c
client_mac_key: d1030d193b53090cbe39a4eb211cf5e0eb38c8330d07b06a6acfe
cad25105c13
~~~

### Output Values

~~~
registration_request: 03a120f6f2a0b858f546d1e2b60f810ad0ed8511ef0791d
c26d8413fe13b0181fe
registration_response: 0246182254fd8f83c9394f905da71386f6b37ffba81b72
3da94f8a07261e75bd27021ab46fc27c946b526793af1134d77102e4f9579df690436
04d75a3e087187a9f
registration_upload: 0316a7837881d7e3a8ad79534d2c36ee7d463e7a3db77698
a9f818b205237cdab5e1927c8d5ae1f6f09ef338c74f40d8955cc67bf0c8ffa7ce3de
9569ac85f36c869defc01cc359394d9a870f0127696da01807169d7fc5869c646cf0a
5594e9bc226212e5cc98726487f6bf8d985244155310b5b9a33fd16c28763c319fca6
b0f
KE1: 03edd5c0afa7257bbaeacab64837430929df9b36bc2784e47577e071a7abd9f2
eff316817d6a723baf930d76db44076388fa88d20cbc4c5f6714a1f0a54d524c12000
968656c6c6f20626f62033b64a07786c37f90b1abc757bf074c18326773bc296ec69f
38c111e4274a4071
KE2: 0293937e3d81dba86120f523eb81d45bafdaa34ea04058451f21c6c81e3b2cd4
f724d17863e4d3e015ff270faec867e6d26b6983501332fbe5fa218056730b2042505
990efa2346c6fac45428d56414b79bd28730ad71f711bf13141669e7e78467f25e7d5
7c420e574d188d838dc5e074122c1976ba029e9ae12a6ec53491cd781e5d755e17507
0f14cdb5075b9b894015b3eddfc4611fa8ccf99ec4bba6a6b62ebba2caa7e2d8fface
a943079b4fe3532e2de7a4f927fcc705725a671c8fe53946029ad3943fb8e838ed49e
4d64e5f0b84e120f175f30115009f18f009f7e35081b9000ffe48d16bebd643a45315
cb447086d0e838f225e2c950e174f584cb219aef24052717521cf5f2489bf2bdf2130
aece7
KE3: 4ecb14ceae2a300a345b5e7bfe7896015bb9c823cfc1330b6d33d3047fd211a8
export_key: 266330a8b933a90a35f312325dd2e4d4b2c8b4dc672dc2a12c80358fb
c01c5dd
session_key: 3bbc7ae5096788aa7bd39afc9e8343a74493da69946bb24710bca402
cf2773be
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
oprf_seed: 33ae40e92aa9325fa481e295195cb16e9e3374d560f4c86b42755c7383
3f0423027708f6acb95852a9175c51f112981843095835c7fde17ee228a54e22cec69
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 77c38cc0c7a01bc63d4510e949b00f705d26b9cdcc212f55a74c3
b4aa2865dee
masking_nonce: 9a49bf9259da2b0935c1b8f872fc201452b0e8d37bb9b8eeed5430
3736bb9121
server_private_key: 6b61028c0ce57aa6729d935ef02e2dd607cb7efcf4ae3bbac
5ec43774e65a9980f648a5af772f5e7337fbeefbee276ca
server_public_key: 023713c6af0a60612224a7ec8f87af0a8bf8586a42104a617a
b725ce73dc9fdb7aacbd21405bd0f7f6738504492c98b3e3
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ea2b681436e49b9cdc3ac8872b91b8968ffd6a9c5b0199af8b572bf
4bbdee8da
client_nonce: cc8c4ae3b2d6fb01caeb4ddcc1113d3f16c06446c8beea66d197c98
2b7d80006
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
oprf_key: 19af0177f070913827a211f951338a0f2f3765691bb141aa13963074263
07e7bc59cd05c59ab105d2ce16ce4ebf44df6
~~~

### Intermediate Values

~~~
client_public_key: 025616abf4c22777571706d0caf4aa82349432d3cc819201fa
a9ca20f7bfd5c784569157d2f055f8388c2374e51c118b1f
auth_key: 97713614aedbba03ca211d34c0d1be17b97380a9442fcd24b0f77f05efe
7d46c7af8d39fe72a8112f5ec9f74412985a7529ab2698abcd45d87615a976c58039c
random_pwd: ffc4c6d2732587d0086aaa7732240ecdf6cbb6e52e7ad213d9eb7d7ef
b761489aa7b35d7a4cfcd316ac8904159f80e4fd08c3e123ea588964ffa11089577ec
8e
envelope: 77c38cc0c7a01bc63d4510e949b00f705d26b9cdcc212f55a74c3b4aa28
65dee9839a3a26a4d7f0706a83183dd7c5c3028a88460ae09a054fdaaab4df496d1e9
82f5f7573d70fbcb5d3a2edbe69af20c12e8004c338a443d320fcf310c2ffb09
handshake_secret: e060eb19bbcd002a6fe3004df4f6c855cb0b8fddb5b09faedff
04732eb6ae7ac80ae5e07921241eafd490b2b3c472655b035c15c89046bbef4ebcb3b
98d7384f
handshake_encrypt_key: ca1f72785b9d58c6955632de8945af4c6c25eea510f043
66fcb8d6a43f49213d09e5c0c79d4f0301c1be374ea0308ac3dd761224f95e72f5d6b
1ae303acda96d
server_mac_key: 9c82c856b7f477cee61bb7d16aef7298f500f3520288502acb9fe
ebce1710c6751cea039edfc5953008ae543086770f4911f0fb1e2c3a71850768d45a8
2c8d09
client_mac_key: 402fc02a904a4caf21c4b4991fea65df06912d46631c50177eff7
d5ac8e1752e0a3b779986f55a003adf9fbc0275356fc047bc734ed0762f65dae653f4
99b961
~~~

### Output Values

~~~
registration_request: 032a1ed9cba49c4f38f62e77ca295b8dd95d4d928aeb7ec
db24e28d927909e4624e4ef5df6b729071abb6e557b809d5ae8
registration_response: 02c520aef405fdef6f1ad1b876bbabce3f04bbedf23852
c2d29aa5962df093b410140aff4e85b4f1037a5dc87a20a540d2023713c6af0a60612
224a7ec8f87af0a8bf8586a42104a617ab725ce73dc9fdb7aacbd21405bd0f7f67385
04492c98b3e3
registration_upload: 025616abf4c22777571706d0caf4aa82349432d3cc819201
faa9ca20f7bfd5c784569157d2f055f8388c2374e51c118b1f1be942ae42ef64093a5
d44539823b6a0cd58e526aa9f5de65901b362fe4572afd23ae191814980e645754aa5
ea5d935d81814e073a7a244a66f304296b45a82c77c38cc0c7a01bc63d4510e949b00
f705d26b9cdcc212f55a74c3b4aa2865dee9839a3a26a4d7f0706a83183dd7c5c3028
a88460ae09a054fdaaab4df496d1e982f5f7573d70fbcb5d3a2edbe69af20c12e8004
c338a443d320fcf310c2ffb09
KE1: 036bb3b9d78c508490de49427658685d8a74bdb5acb7ca4fcfb6fa5488911b86
8e746c08a1260d828fc5fa7e4232a2e58fcc8c4ae3b2d6fb01caeb4ddcc1113d3f16c
06446c8beea66d197c982b7d80006000968656c6c6f20626f62037e9c1e7bbf41bff8
ca6fabb630db2db73a92e57c6260f39d4024c619f8b4f2807473ec0f715d83e88ad62
b88ff3828f2
KE2: 03bb536336c777524c73f0208feaedd057078e672b865eb6ac4ab3ceb631d171
7050a1c74ca2bb8a963e4eae29b33b19b99a49bf9259da2b0935c1b8f872fc201452b
0e8d37bb9b8eeed54303736bb912163ff09cb564cf15be381369626e500e509b7d7e2
b465d4570a722be32fda147c0eefe072d88231710f111aa315d6c03e9053c494e67ac
99bb37277bae5c725e5abcc334b0b9acc2fbc43caddce585c84b2bd57c3e26fe8f212
e0ee6dee0c7381aafeec8123df21c0c1397ecdfe2047e7860951921a7bbfec6fd2d93
607c6dc1f4c81e909d4ebcb2ef5e21003bc45ef9121ea2b681436e49b9cdc3ac8872b
91b8968ffd6a9c5b0199af8b572bf4bbdee8da03196d22794e67e69232db19e4032d2
f2daa09828c4ef71e5a4f296a0edecaa5bf564c97a7e8c96a4977975a44eed2b37c00
0f61d2bc7e3eb2baa7e14d1a9774b5f46558a71e73524e61c07576205cde138cd0e08
a9ceeb310b9eac6ad4727d23259e3421a8012baa918b41fd2805f0194fb4f4cf921b8
f97edafd1e02c17fb93c30
KE3: 5f322a478fecc8e7f5b9d31924e7dd566db97099ed9af00acc9c203f443baf83
c0795f1a36cc91d341df801c3afb3807a88ec7791c45c38ce3d3b86b821a7325
export_key: e576c65d8d8d16f450bc1a12aeaaeb102fceff14f577bd05f9af16dc7
99d8d470cb9fd1ef90c5720a25011b70eb29a9d58f85e3fa16d6c665bb074861935ed
1b
session_key: bfaa5104fa6125561ca1636abc709087197b0d6f9ecad2b22c067a73
d1425a4e86f0c7f58aef0a64021e3b7052ec6941185968642c831471264fcd0a3530b
d0d
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
oprf_seed: d01e5e01bdbab3a021fa70384a5f85f67e1d76635ecb6ff004636ade66
f59e6e2acb11e757f2e2a45920dcffa78c3e205d1aab020d8e06f5ce3ead9b7d26598
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 75018e19eb0bb37ddc9ec9f247f25728773385b317cd06a615e2e
6f47d36634c
masking_nonce: c478578181020701165017ed5204e67a9cb29543354c86ec0abafa
a032a4a623
server_private_key: f5acc7b0dbee75bcd8bb50363ec640038177f06904f2476ad
5274e2f9d258659e80b0fbd20e4761b22298eba98ae9dc5
server_public_key: 03ca37ed36b0b311e3241e6e96f49a44edaa971419d91fcabf
fbca0184afabd92827344da8379abfa84480d9ba3f9e4a99
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 225ed39c9931f719fc89bbd03b64f3d8ae85153fb7add4734297896
ac2739a0f
client_nonce: 5e1830df0fb640769fc41f6550968ba2f9bfa3292937693cac5b86a
c1af9f98b
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
oprf_key: c8787b21e92d78bc4f36618a05aa5a6aa6c90d8f3f97fea6a0413b549c0
d18eb201c763fc5399777a5bd3e20b89c4d3e
~~~

### Intermediate Values

~~~
client_public_key: 0239ecbe2527ec99d4a26244225efb23da404acdcce1a89334
83afe54100b6476ac242fa857f61535baddd163bcd92a3f6
auth_key: 16c41fc750bb834f7b4855010a2b92a6b86216d0d984f31033c5e7f686c
e1f237c49859bc0c547800dfa4c023877cf00abbbaa75ee5b9fe9cca633b435064f9d
random_pwd: fc257b34fbec542bca7b52fdf50f216536e511a37ff92a7146380d122
259667b13b298f4c5ac0911186cedadd7d5dc66e29f2fe55ae61e02f83359501fa2a8
e3
envelope: 75018e19eb0bb37ddc9ec9f247f25728773385b317cd06a615e2e6f47d3
6634cdb401203b61c3168013208ca360e0a4d89bc6b973b152afcd39c36ae808cbcd7
5cf0e0293e654e3acc6bd865ea46018338bf43789054f537c5d88d0f89ab8939
handshake_secret: ca0e060cd7f0951564163c9987fce34c2213ea04d3d69a6fb14
cb59e7101deb0f9108819830779d0f9aa975d3461a2c95164cac59eea3657bd0eaec2
4105f2f6
handshake_encrypt_key: 71e52c72265e0b4750e1a3f34a5f553236a2924ee732f3
2bcd322df5efc9ff41072e3c970bb1ac8d091fdf969b5b84d6df30bd1962f0ffe6b24
4a443f8bb10d2
server_mac_key: 753d745b9a7d976071e72bfa370e7520399907bd84ac0d241ad83
fd8532e69a4a0f145ed5faf1c4da9026a68c551055ffeddabad68c1b53e69e11f84b0
08c536
client_mac_key: ea0940ed7ea0c8ae1228c0f102c32ad74055555e2269adf576ba1
cd7b0f90b283caf9ebb1d073f103aee6f633dcd95bcad967a7f1b0831e4f80b3d2eb3
3f1eb4
~~~

### Output Values

~~~
registration_request: 03c11a1b33c831ff085bea647c06bb354083adeaf4e7c25
d4ef17e90a25e590b275d412a48b83c064f75a6fd383e4730a1
registration_response: 033da63c2adfe6865ef64700d3bfa0ccfdfbd4877e737b
da4ef91c85c4d9fd68a6cd6bdbb21e1507fb5cf7e0818a555be703ca37ed36b0b311e
3241e6e96f49a44edaa971419d91fcabffbca0184afabd92827344da8379abfa84480
d9ba3f9e4a99
registration_upload: 0239ecbe2527ec99d4a26244225efb23da404acdcce1a893
3483afe54100b6476ac242fa857f61535baddd163bcd92a3f68b139683a16b7ae6799
95101968bea86cfc3e12ade2f8e2965afd692156b88a4589082aa157bb5e289e2814d
bfeeca4a3f7f604adf2bc1e7d94fe3b0f46afc1f75018e19eb0bb37ddc9ec9f247f25
728773385b317cd06a615e2e6f47d36634cdb401203b61c3168013208ca360e0a4d89
bc6b973b152afcd39c36ae808cbcd75cf0e0293e654e3acc6bd865ea46018338bf437
89054f537c5d88d0f89ab8939
KE1: 03569da14f7d483ae405bdbd365b7bc7cd11968aa5c105d6fdf21d83cbc77050
7be9fb3aea6709f4a37e940900bccb4ca85e1830df0fb640769fc41f6550968ba2f9b
fa3292937693cac5b86ac1af9f98b000968656c6c6f20626f62021323ffcdb6e9971c
b3d0516ac4f70f48c50ce81c897b4c3459ab5aa664a410e20012f6a3eefc000449912
82868648a0f
KE2: 0230994a1db8882a45528bff698deccd109a2f435b0eab95fdcc7016c1da2608
2d09f3cb6c98b9da61a1a13a15507aa29dc478578181020701165017ed5204e67a9cb
29543354c86ec0abafaa032a4a623988e507535a10a792055bc3824175d976b919e94
cb84b13122733d9ca3727a3221a464235f5605962c5d496b16a3b4956949f4d5d99c8
8ab20a11bef66a635399f708c979ecece79a75889a4e0648199cb15115ea05f718ae8
2552d4ca277c0ee1cf8bf7facd727e92fb622d7b12413304eac476475313a0e49c5de
add0439af2c0440b69c6aa9001fc81fdeac8b8194b7225ed39c9931f719fc89bbd03b
64f3d8ae85153fb7add4734297896ac2739a0f037b55471c1bb3a246d0030fda68aa8
0a79786fa060c0b56e7bc7d0000886e3d661be0afcaa0cf69519eb528a11af48a9c00
0fd7b0c096f6fb5a976b1cfd55e4f1006921523eb604abd8995283618a1922e4afbc6
b9099fd9ffb1eb165ccfe275e334a60ccf49d6199ca23151ddac5e07ce3b9bab6e462
9a573e27d30dae29421747
KE3: 2ca882f09ffd1906848f7ae4de658241b0c2dc975c3ce67bef7d00151b6ad264
8c944197e11b1ea30ba0014c2cfda85586f54d607844d5157f4eeca4da122b42
export_key: 0adb92c76e6d8e6ef197578387385def7acca4600e4fcda8967df258b
bdfcd0ac9501500dfbec5bf05d94af529eeace074cb5fdeed5ef3610a5be7e93bedfe
73
session_key: bf89d06754a4f7cdf683caec2159fce2f22814128ee75de6e02adc62
1e17403f95368eb4b4faae48febc897c9e4128bfca553cd2eaca0ea0ae955adab409e
8f6
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
oprf_seed: d5837ab90f05231834b3cbeb499c0cd0ac0401e7cd3e136d01b9123097
aae77ace084c93e34bf31bd67120f399be40f3529a9a96a5773f7f075b6d0169f1fb2
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 3f1c82c7cb2288a120ab743577b4ffe37e25b6bd9e28331eaae04
2c3f016c522
masking_nonce: eafb3c238c8b754ee611ed585209e97854e60543bb821be9c1b843
a51d7e36cb
server_private_key: 8099b50c7ed9444176251781b6a8575de7491bec330164821
b9b2a108e3ef8964622075015ac9ea0f8380dcce04b4c71
server_public_key: 03aa179347ce8e27d2122b8c2c43315635e5489dfe1a50ab77
186e4710cc489638b097b3302b550da04f5d76adfa826688
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b5db97a3c79ff3c281009d98995fd97f583cdff6602cec6aaf99de6
e206dee47
client_nonce: 48c18963a283a7ef5f6f2187802f9458fbfe0256e7a4a1d436418d4
adf953544
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
oprf_key: cae48831cc8793dfa75380e7dbb1d0817cdfcef69e31424f200a4dd071b
b64bb8fdc95556894a95396e91dfb037c41d8
~~~

### Intermediate Values

~~~
client_public_key: 024ce4835b86c68b2b9b0f6128c244153adcef9f1cf3dff1b0
f93734d0555083d58e0f722b18cb7f32f9e436a330f4983e
auth_key: 43160e14fd7eed71c38a79ce3856bc9d6bf9b053ec5dec3587e696cfee2
163d3d944449d3f57552bc9a7b9f3f6cdcf1aa25da8595a1422ca5b0874c48788f25e
random_pwd: 1b9f2faefe07d5c6d90e6dace8fe24b80db3bd37f1e6a4308ac1edaf4
3bd6e3fe23cf4122fe4715063565cbd87fc2e4f02de51fb1545ef34f227e9a6e58cdc
e5
envelope: 3f1c82c7cb2288a120ab743577b4ffe37e25b6bd9e28331eaae042c3f01
6c522ccdebabcc9a4bc571a5fb102f44b046242fd0f95733f065e8215b0f90826ecf0
419a6b0ea5ade35bfdbf812086ab164fcbcd19311d48194893742ada7a6f8e3b
handshake_secret: 165555cd21e78cc67fcf4b0d348cc6dbc195ea403de183105ac
00854aefcdcbef3d1d0cc82ebf598481b929848f077004d4fb54e17298f2037c475b9
dcaae8d2
handshake_encrypt_key: ab04da73392d9af14c8a44b5c9cf0563fed9cc2dbc46d7
5e27b724258a1a41d4ecabf396c1a9373bdf05b93669e806576ec7e49a32fdc16de13
ca43af5df8b34
server_mac_key: 9fcafaf80dc2949a10014c22d81a5382e7c689619a09a49ea79b3
76698b1423cc924fdb91433fc48b36af3c524dd04142370277c27ebcec8544690f9db
18cceb
client_mac_key: ce320736c6050d6e6ee7bf5480578809c04140271fc2b7887e2fd
1b29f7d0b3ef6c696c54aba574c84580c4d1d8378289fba5953d60e2d57ac24ccca68
75cd70
~~~

### Output Values

~~~
registration_request: 0399b76973449a299bd2ad6be1ca983c8a1eccc7e05a36c
a120a30a8807d96bd4b98d076ddbd99e36adfd30b0886fe42f9
registration_response: 03ec30790ef493672c7e024a4505f6da8f220775119ebe
416619399bde59f6740a15d61dc38810d598a82f67bf1aaf05d703aa179347ce8e27d
2122b8c2c43315635e5489dfe1a50ab77186e4710cc489638b097b3302b550da04f5d
76adfa826688
registration_upload: 024ce4835b86c68b2b9b0f6128c244153adcef9f1cf3dff1
b0f93734d0555083d58e0f722b18cb7f32f9e436a330f4983e8355fd0f4320fbe72a8
fa8b947c0ed233c61691fcd5540762e2b589eb4e7201bb463ebd8bc49b809ec9ca60c
9f3c74dcd18c9b3a8dad12879694f6ad04d1bc8f3f1c82c7cb2288a120ab743577b4f
fe37e25b6bd9e28331eaae042c3f016c522ccdebabcc9a4bc571a5fb102f44b046242
fd0f95733f065e8215b0f90826ecf0419a6b0ea5ade35bfdbf812086ab164fcbcd193
11d48194893742ada7a6f8e3b
KE1: 03bb6ba53426efb2307df620440d09e1b503d3d2135dd0c845b59f135ab39bb3
00aad505641fdbc2725c31d221feb82d9a48c18963a283a7ef5f6f2187802f9458fbf
e0256e7a4a1d436418d4adf953544000968656c6c6f20626f62038d4077ad0d00842d
0d621527f8225c405f80049752378a4e111b3dcd52857d35f464202f22a17d717d5a3
be3455a93f9
KE2: 03f7779f368711c8f7d7636674590945dba2df23899273ebbafa42a74de3c1d4
44f4edd18e89121df5c4408a3f90e81aaeeafb3c238c8b754ee611ed585209e97854e
60543bb821be9c1b843a51d7e36cbdc935083af3458237221a2ef4e88067164cee70e
dad8239083dbc9ebc4421a478c16c2e0248d85bcccf5ddb09744a95313865061b66a8
196f58bdef11144cd5d9dc1903597f7fd41a37e428e8c17b628e821c5dd4a07fae71d
7fe64330e3505ad0b2915d0887c3b15118d88f220621e2a068f6f3b7479ec0537b051
c307364a260f56a27141bcd0b8325b61e35dddccc10b5db97a3c79ff3c281009d9899
5fd97f583cdff6602cec6aaf99de6e206dee4703ed7dcbc8318a00c1f42c2b75682d0
beb532636c2e03c524bb5bf5af735812003bdc0d076ca0dc9aa7ea97273c7088f7800
0f02a4542156695d238de6ed2502f2d190e3539e4bd1d1d41a325ab97fa4853bb02f6
5a1baa67fcc16f61cd226af33d081bc9ba7e9fbf3ce9c78882f9cb3dd988e99d61ffc
c9a346ebe5badcd20798bf
KE3: b32116206e53785d41414697bdf85418c3369d45fad868448ffd8535b37d5280
988ea5fb1e1e8a7a85417b355885a1a011c35de96cf51fc80094ae48ebcde942
export_key: 9ad56ebb18c7dbe83183fa1ba59ebf140dbce6d7074788be1fa975328
e538dc8ceb6f54ade93c81f0f90527c2c32316953110d2a0ba56ef2c423126ba1c9ac
fc
session_key: 3b0b5edc4e9b1ed92e4dac5da8fa7ae370731d5fc9f83f549f642cfa
c6f84e8dacd4a6c10db998b4146cf77bf0b96bac4e85c819f564b0403056c347136f2
430
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
oprf_seed: 46ef1aef89926585ac55ccb358739599289692d2a506e045f9ce57d053
0e172185a49a10ad2c8db24f4c495bf0480b3b41e1e01bfe2ac5a383c92ed2667306e
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 03f2028d6a4c258e5b4fc3a5392530b010ef990bc134fad8945ef
17aff9d5344
masking_nonce: 585b74df05a028eedafa883bc09bcfe7d11b8a29d634e0f61d407f
d3c059ba68
server_private_key: c6c4dfa3a822d8f670e5aa46e733baaec9f93d5e14ad9ab99
dfcbcb2ad157a8aef1f3fec3f24bbc392c9755271e8792c
server_public_key: 028cde89b6908e81425fa8a597e3103021475346a146b1f1dd
ab47f09c76ed3b78a251cf390bdc086924bebd471063abec
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 1b646c0e24a8200b738378140f9c42d91e5a9c018b039b83c750bf3
3f30e85f1
client_nonce: a2c4c64ec1752a326d263b113d3bf8273555dd171a236c3a08c10d6
d44b14589
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
oprf_key: 86cc71fc49e66366c4855d327ada252b517e885feed4a5729ae45684e6e
21985a3cd6551adde9ac7506b820411272163
~~~

### Intermediate Values

~~~
client_public_key: 031799a38638636dc36baec6a17d1b63e9433313595f0f7b77
4fce23b145b654269a11041cc63489456beaed82d07fddba
auth_key: f14e1ba24a5cde9b6ca83bb53c6446efcaa0f02568ee0a9ed7e2741bc65
116b1a97caa92fddc377ac64fb32cb09deb484e27d79aa89d99ac51578226936a73c1
random_pwd: 167d35134160877b3483f2c4eccf2bea9e74282d776a4f556c0c7edbf
c8f04aced2ed8ef735e67bd6feb90155adea22d75360c35c79766e71ad3164984f2b7
96
envelope: 03f2028d6a4c258e5b4fc3a5392530b010ef990bc134fad8945ef17aff9
d5344980c087733010f994abe297e17811428c156be8053f3d674405bc2a6c700ddfc
8481f10c6237f66a30423ec74e0ebb4049ddf909b8257f16bedd2f4230b070c0
handshake_secret: a7cd5fc0f2bdf907493e263bc399267e4b5838b55a3caa2c3a3
3941e47a488a1826bbd2b53d84bbbd73d3c9c834f4e3062cd23ddd0066474131bc583
6265a96f
handshake_encrypt_key: b3856929e9749b029a8200586ad0f4b82182161ba529a0
c86e4cf48c9fd0b6823689296e128f75d9f1f61c7dcf8477514d9a42561ac8534621c
e82f43b81d960
server_mac_key: 14e7f02c08ea869f31403c9e904e96495f8084e22f1128b3b09b7
55d88459f53dc41dc4da2da33ece02f90ea9b02ba0c1f35c018a394b09d98c11b978c
ae1d58
client_mac_key: 213f31c5e89c1d1f0559a0de2798bbc2c27c77e2213b9636b873a
4237c7fe08e688220ad538a2f828cc362a9de33191f151b9be90c4a409ea9b9142296
f27d42
~~~

### Output Values

~~~
registration_request: 03f8569ce50a023ad6518281322157e79e1207a96bb9214
95ccde8cf48eaf27895245a7b8f4b3b5c43ba54963a19cc488e
registration_response: 0382df9b95b07036407fab1cb5eb1d2ccf73613ad4b266
c1fc2fc95c6a70afcd7a14fa7e9c135064d754dd8ec4fcb20805028cde89b6908e814
25fa8a597e3103021475346a146b1f1ddab47f09c76ed3b78a251cf390bdc086924be
bd471063abec
registration_upload: 031799a38638636dc36baec6a17d1b63e9433313595f0f7b
774fce23b145b654269a11041cc63489456beaed82d07fddba952c60691acb5561de4
f0a3f9aa26d09685fe34e49351c8665f5918c6ad23e1dd05369b97a817fdc123908ab
34c576eacbcb3a5c2ec87377aa28f1e8c2c2ee6e03f2028d6a4c258e5b4fc3a539253
0b010ef990bc134fad8945ef17aff9d5344980c087733010f994abe297e17811428c1
56be8053f3d674405bc2a6c700ddfc8481f10c6237f66a30423ec74e0ebb4049ddf90
9b8257f16bedd2f4230b070c0
KE1: 0255b2107d1a2192eb54c25c98bb7a95e581d7d23a38e1fceac9f8ce99f568a4
fad6c9bbc5abe4ff08f8b22e31bdfd6971a2c4c64ec1752a326d263b113d3bf827355
5dd171a236c3a08c10d6d44b14589000968656c6c6f20626f620246ba00038cfa5105
659e8c250d10618a2c7f9d09d174663bc5689e4778f7054534d9a4200a447510023af
3ad3c61ece7
KE2: 02ffcf58ba2d7eb8ebe85c4ff524f8fe34a9c592f4be07526bfd3b1708251c62
464a7d2c81170d076843725fecfb0b499c585b74df05a028eedafa883bc09bcfe7d11
b8a29d634e0f61d407fd3c059ba6856c00e1bc724f8c1cd6b8fec60460e83025e65c6
c447957c5660c533ec6e40b397e51983a5ff9ab343cc01c99f53a74e75ad6ef1783cb
86942ea0703055be90ef98e2613e6593abd1d109da68b0dee62a62d9fffee44292e70
c0dfc32d010eabf2ee017e28d3191bc08e218cde97c937727c7e6ecb0766f43a164c7
f63254d57183f39df82969f039f42582bc7c490839e1b646c0e24a8200b738378140f
9c42d91e5a9c018b039b83c750bf33f30e85f1030d570f50898367457561b3a5c7078
52633b4f9404cc45b4058f52f5da1ebf67cb737bfe5c272bfeb65efe6bf7255116f00
0fdd78abc40b7a8fb75955993a05c74f9c26ab99c8d7a1c2938f17f1eeb3e5133f024
25b4b1c96c063b5696dee124e0cac6f9e3d392dd45a109f12064b40bfa0b47f2fe1f7
29dd52652fd0f6a5cf6d51
KE3: a24e3c67bd57760fd2dea0c5763d236a58faff4b1c92d87ffc6a6bca1b86c66f
2452a4de7159b04e078579086e105c0f499a67d528711cdbe90f16e7318889ab
export_key: 82469fa77a22a3012616a9ceda4cca4a5ab7eab00b129818d49dfe01e
848f3c62a8090a2c7575761bf4b281f13aa4518257438d93c3f03c139924381e8a141
cd
session_key: dd2ea6f1090a0640848489f780295c9744a6cdf31880835a2b55f690
2cc4bf0be837d1f14e1547cc3b5a73ce9fd1bd8fb184245af437e0e6702b83de758b3
14d
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
oprf_seed: fe91b0bd67c22ed2955ecd073737109321020afabc37c9e9a66dca60e4
0b84cf8a9067190985eee02d40e354806be027fa34c6cca601159643dd8cc205d8a9f
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 9e1f8230dc23d04552eae3e2521874d8af5c83d29c46748aeef47
0789006cc8e
masking_nonce: 62a527c6afc872c68ea05c42e6561117f10dd5092619f1892fd6da
f585b8109b
server_private_key: 00648b7498e2122a7a6033b6261a1696a772404fce4089c8f
e443c9749d5cc3851c9b2766e9d2dc8026da0b90d9398e669221297e75bfdea0b8c6b
f74fcb24894335
server_public_key: 0200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: e2df6a952062b18566d86f4a884c62b239d0495ce80dccce8d044c1
c936b2f7d
client_nonce: 373a622890f26b5986acb69fe5cdb46f7371241950d4a33afdf7177
e98a370e7
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
oprf_key: 00d2be78fa438b1b29b8a01be2cdd829892d96ba724bea9a39c1696c99d
37c190eb3f7a2f07b9fa05abebe1dd568e9289456e679b433172f4b3174a298ae8e3a
34d0
~~~

### Intermediate Values

~~~
client_public_key: 0200c0dfe7d1cfc876a998335ed9778721406ae8a99be0fe72
da015f1df9e87ef65fef16ba3c62eae983e82baab38fd3ee9e7a851408e18f7ad6ec3
2d98897f21c8347
auth_key: ceec9988db8dd4aa78981dd31264275a5e3959cdfeb05b78cb473b52f1c
eab3a03e88e4634a30ee3aabadc5d7118edd13a07c66c0c7e6ac6096aacfcde9d8b13
random_pwd: f736119ebf07ecbf74bc42c19f4dba84223f545b4a835a6468cbe550f
0134d379e9f29300c1c2550b8e451b15ee209654c18fe5cc8025234067bd952c2846e
b2
envelope: 9e1f8230dc23d04552eae3e2521874d8af5c83d29c46748aeef47078900
6cc8e354d2518eaf2b13c7ce3d3634956986c50eb31e5ef88ff290af46751e673e7a7
39ad5836991f8823be1d1885e42243a364b8d02324a0d4cd756d5ddd1277715f
handshake_secret: 31a08d3a06c53554b5aae1645b3eb31d854be2a53e31d40a3ce
7fa5d49a074bd7538f0520b9abcc8f3bd575d28610d96abfe87f46ee5cf79402d0722
daf98811
handshake_encrypt_key: faea72926c26a8595711776e4ba2648b985a778fcc922a
0a534f474bd59e3a4544534fa4a32bb971d6e9e849b851baed1f3d2ba9fea7354e75c
0850cfa0902d1
server_mac_key: 4f3b8567ac85bed72e410c72a6b73acb55667c8e9b7de2fbe313a
81b432ed496118d1cf3d927fcd51924329846e1bc99db0b3e2c0ec73b24c82bf6cebe
e7dbb4
client_mac_key: ab2e2c76307a94385f4277481c7318cdf5bc601fd888bd2f4bd01
cb446afe1a3765c605740b28de8445203458d3972521bbb486f52dc7a1ae8367b0e89
ac467d
~~~

### Output Values

~~~
registration_request: 03019f508a03d6d883f28a0afa477eac4dfad2ae9052a82
ef5736b24eab85dfc40309c5d205bb94b9a6697ac7b97b9b63e057f163905ec396db8
fe250544bd94e90c13
registration_response: 02012764195b7146a6ced69ba8ecdc29728325a699343a
52ae8e267d090ca1fe8af6f3e738ced64275fff7cb21219b34e5942221d46579f32c2
c87720f3c31df31c6a30200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
registration_upload: 0200c0dfe7d1cfc876a998335ed9778721406ae8a99be0fe
72da015f1df9e87ef65fef16ba3c62eae983e82baab38fd3ee9e7a851408e18f7ad6e
c32d98897f21c8347bab9c93c925c424c3f2d9c5d5fbef2a8a454c965775c0d80ca7a
a4e094fead1c199f8befd2755776a380d78d3da406b2ceb155272933078b62ece9824
3fd00229e1f8230dc23d04552eae3e2521874d8af5c83d29c46748aeef470789006cc
8e354d2518eaf2b13c7ce3d3634956986c50eb31e5ef88ff290af46751e673e7a739a
d5836991f8823be1d1885e42243a364b8d02324a0d4cd756d5ddd1277715f
KE1: 0200001c8b7065b1f65b9e87150b85b32e6a13738dfcfe40a947a3868b0504a9
c0b8f2d2f8261af3c4507f583ac24caee8981b3c2e7c6a81192d383aec9fb93e64203
5373a622890f26b5986acb69fe5cdb46f7371241950d4a33afdf7177e98a370e70009
68656c6c6f20626f62030187b0369b07402c41744c664239d0f9fad568f0ea5c13e4e
4d80c770fda054cca7fdebd3f91a803a3efe7353969e388623c224a86cc32575ef8cd
5e0cdc3c467343
KE2: 0301e4ec4e2b6c371cf90e403e6bd47e5109464d98a7f9e2011a763aadf2960a
0701a0109c5ac8d205cb6c0af917da72bbba47379e9b2b3295e81cd670ef3cb5078e4
062a527c6afc872c68ea05c42e6561117f10dd5092619f1892fd6daf585b8109b197b
4aa543436ec19f843e6a70c511c755a8def21c90086243442134e889070a0bd8b3168
f95f0aa45aa1d6bb689db57da61e7feec123b89f98bd557152ea4f6d53d09b99e1401
9157c4e8edfa30fc2d39add258f707b3c52e34ae6e4222784166fe037b62fcb4fdd83
7dc0b0f366f286bbda2a4b1607c5785b0c71b7ffa07c874642fe5e0cfa8c4b4212e85
a17f585c43714ec27c9e88a712072fe978c6d598339e7de2df6a952062b18566d86f4
a884c62b239d0495ce80dccce8d044c1c936b2f7d02016c63c8e2b3feac6366e3dcf7
52a8c2a287c1fb4d648aedba86aa0ee07d2b1133d3282584d7c66357bfcab76526f18
4f7ff9af506f9eec01645b99b6918bdda600c000f75a4544ea1fa9c97f0c5203daa05
a5c02070d91d23b5f54db794bb71090b3bbcfbf8c59b38cc2532612430ca93e21bddb
0dffd9163affd92f2191e9d3ffdac230720335e9f6d66ad91b2d05c062519
KE3: 38fbda8957b59ec8fe22bf157252963d5aa0bb363b85c6864bdafc5fcd05f88a
166a0accdbf8b680a400ab68dc8c4dfa2fa3d5e228e41cb92f925dab9ad380c3
export_key: 1e2722ef14d619c9a5cb6b64e7a2910042eb541f6e53b1e732dfdb192
034d85b7a75b7a956b49e606ffbd1f78f33082bf24f26f7faf292cb1ac9839d4ad749
8a
session_key: f67b7f8db4e384d527e7531528e2b6c40b30c9157187da3d4b48b55b
4b0c0d418eb7e556553d09a2baccf797570682b72ce3c3a282af3fd49151bedc6e2b2
865
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
oprf_seed: c2bd6e836c6c6aff0acbc170f9bf67201f608044624cae7af9e8a1af23
7a9953c406e5a94c2ca822087babcf3c6bf3c5c7c76e6aa956eea73e1b5e28b80858b
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 85a7aaa6d91b0d021c4791bb9646b7994cf159063165d392e72a1
9552c197419
masking_nonce: 8194804d332ef7acde719e7a326dbce7e106fb63f7c2a1d734d04f
d27e117ccc
server_private_key: 01e58f3492c6da02dd7387bd1dc40065b23155fcc16e56ed3
586c3c2d80245859235d872c5266668cd562a2bd7f34654235b1b9961485ae246256d
f3935910d36507
server_public_key: 03000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: c66dcf921d593349c479ac132a9a7f956d8f76f9bdb72e29db2fb6b
49de41eff
client_nonce: 179515c3670c51675cebd52b9e667a7cc46ba7d3d84347bbdd94771
29c5123e0
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
oprf_key: 01ce15a050408e7645422e6ad96c338ebafacf927f9f8c9420edd75c902
3b65230588f7a8c1a0f071c9c2696c1ba871d449b1cfb1d6cc1048e6750862b28ac98
b013
~~~

### Intermediate Values

~~~
client_public_key: 02018611382e187912035ba86ce972c96103dfed69fc3c30b0
9b60b00cda303341f09cfd712ff514e97cfcb15e253d0a5833b2d6fec1f07e21db88a
3bb98cd5ceb0bc1
auth_key: 5f0bea790816dc3f3b278db242a4eb6d0120e7b63b4aa2a9f4c8d5d9b05
de18e5dda8f6e536aba1b0a02fec5ca47f50d1617a94d59e76495b8c17c13dff606aa
random_pwd: 289b0007ec5522e4a94838866c3a1ba4de863feae784f27845604ccb0
13bd7131ec4502b2b45465e8d40e47c92a501d3e0031dbf409f79e41d99d933762bed
63
envelope: 85a7aaa6d91b0d021c4791bb9646b7994cf159063165d392e72a19552c1
97419122668552d45120ea281b9d41e22170084325117ccf0752eb3dbeb6750a342f2
8c233bdb8b81e77985fc3071416142b961b4c41e36ffe6353ff72c90b9223241
handshake_secret: e3e4114704e6d4b8f5dee9d259118b0315f186af22d486b0d3f
5b4fade1deeab4aeea78d89bc08df1cf24aa1d06e0838bf64237211bf7ad4041d3c0f
27a51bad
handshake_encrypt_key: d144232e9257db8dd8693ec52f89f71386bc76142b28ff
15e117ffec90706ffd16ebf669e5a4c1842bf6221e805661e22d9303cd5c1e718ca37
f672803ed6e34
server_mac_key: 87ffd5c1cce95568395d75b6c24cbf31e4eb9ee4f55db8e74ae5f
28772c7bd29b58e0dcae7787a6e6187e4c29fce4f66680ebe8216a346a50b777c4347
721343
client_mac_key: c537b3d5bb7dbd37f630759712cbe0e5ac7ebee86a9f41909f44d
58fc297734d46059ebf9ce0824462d8d8af0bf36ee55f1ead240fc7b1f6e36ffcecb1
f53e0e
~~~

### Output Values

~~~
registration_request: 0200bce08f110a6634cd66b75c0721208df3d8c392f86f2
feb9c20fb62c9a30df00b37caba143386c7880a96301814e425ba9df870cfbf19724e
b58411604b3a618f29
registration_response: 020067aec419e27f635ff871a2ea7977d4476b9a9516b6
3a8d7aadd69c71758ff5753c1083009e67889c8990a74cd1e2a55f53743b836b76882
ef8c699544832be9e8a03000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
registration_upload: 02018611382e187912035ba86ce972c96103dfed69fc3c30
b09b60b00cda303341f09cfd712ff514e97cfcb15e253d0a5833b2d6fec1f07e21db8
8a3bb98cd5ceb0bc195f3929a2b1c1fb2267ceda1019c8893f08eeac57c1d368bb9cf
6c41b45bd355405158b01b32c981dfe0e5f60823f10def74efc1c466bc2fa8508d754
192f9d185a7aaa6d91b0d021c4791bb9646b7994cf159063165d392e72a19552c1974
19122668552d45120ea281b9d41e22170084325117ccf0752eb3dbeb6750a342f28c2
33bdb8b81e77985fc3071416142b961b4c41e36ffe6353ff72c90b9223241
KE1: 0201e2974af3a0c9a479cf1589e9c7db8f3e04723123436453ec427f75974423
4a57a91a724879c5cfe93ed919501d567a6fad6ff5763647c351ad6dd925f39cdb04d
d179515c3670c51675cebd52b9e667a7cc46ba7d3d84347bbdd9477129c5123e00009
68656c6c6f20626f620301bcdfcaabb52a829a450fdeb63bf90b8c98c6b2717164f48
e27d4c737058feb556f81fe39aed7846313ff6a6fb9c4bf1d81083974f2babdb08004
8cc67e12f8ce2e
KE2: 0201bb4111d0401ded04f6a75c9ce074a03be2ce3ecac2f4984eae23eeb1fc9e
854440c800646e7030edce4832452c1bf197fdfd29bb21136104eab1f51ed425cbb8a
48194804d332ef7acde719e7a326dbce7e106fb63f7c2a1d734d04fd27e117ccc3fb1
2f9afb402bc7ec0dd1122052ff3e3c987d506df6bcca77d6cccbd6f46956ddf743871
068d9eeac4988295e76b1362af1ce5216bf65314708b6a955cc9f1ad429b8a13376be
ec4308d107499af4ab3770f2b1c18c1d861986bcde0610d72d99c3a734e3ba5fa3f43
87de4b3e38298b3cc1da14566a31ff6bfc7becde5957ae3cfa1e57d01df2b9c72ed42
643f0b7648d303810b8580549674b2be0e97f53133963dc66dcf921d593349c479ac1
32a9a7f956d8f76f9bdb72e29db2fb6b49de41eff03015da5c9a33d3168383837d8d2
ae4d00f39a8a631cd126b4dc1b01f06c32ac86ce29440df0e45650879f65ad94a3d75
2f265254f7d5861046cc016567f9e36b873d0000fd0f6e8d4c7acab52e5b2a7c3197a
4d21a5a0885fbac2e484521e473dcadca2b20173f5dd1f57ef3eec07643308e8733ae
20330aee0b63b3a836d79282bc772c24da49aeba7191c2d10611798327d0b
KE3: bbd9c6b871ed9763b936f39212f5fc6dcec260ca5cac4caca627f9b152d8ead6
9e53b6e5fbadf803ddb9289ce7d65407b2b52073f7f549a2142933bd48c7d729
export_key: 84995c0641ae54a8394033ca74f6265d9942bf04ecc72ad07fe3553cb
e5eecbe2e992c2934ac2991b59f411a8fd83234c4ad59ef76c5fc7ed1312a15ae678d
3d
session_key: 2f210f1132da205ce49022d30d4d7a7d0a2e1e0ddffd72770694b90d
8248b9d0d43a82335dc4a07fb2b52f01e437b6ba501947291681a5c23f3dd2780aa44
6ee
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
oprf_seed: d4266df7b71b8d9490fd7e605395d6fc41efc6003c5124438e046a59ca
70d2a4193914e4c12d81085537ceba3e9488b0bff59bed3864efb2b595b71a5a79c3a
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: bcbbcb785d801e782a49fc3c4d4e2616460a838851ce19488b8bc
b2ecccfee42
masking_nonce: 6665900da27eae1f4e8f540cda448f963ae1ea1158eb69183f44a3
ae32982b1e
server_private_key: 00deb3fb5eef3871cfaef0953ac3482c88f2bb4849b6ac355
3c3609aa005b2cb37316964371a39548566c5e4e4dfbfbe5faca38a62651e9a519143
d04ac366bd3097
server_public_key: 0200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 67c48c1baf7cb3120ea2424ff020a6189a5ff6acce20fbc9aeeb6d3
2ebbe2527
client_nonce: 5b923e6077752626ad8889482607b639ffdbfad860fab23702585ce
3e03da5e0
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
oprf_key: 0038e8c09c7c967c3f57dd579237627208516217354d0edce013a56c8a1
e55e6af5235389f8213cabd5dfde2c82385fc2d224a475d10a2972b385e7ed8cce7cc
2bc3
~~~

### Intermediate Values

~~~
client_public_key: 0301a3e70b0165b835619aaf0a82ebedd51b88637cbe1079cd
6e239396aacab7ffca5c6fcce48d21c1b36acadf951a8924aed4cf17c003dd78ca77f
adad1092885ef1a
auth_key: be1a67d93a352cf8f2ecf807572deab2e40247e0a5d01604b0b7eeefd99
09ca6e65c72f64ad17cfd8ad1d5a8ab934561b811ac2379d8c7cef093d20df538bd2c
random_pwd: 00d8f785a8a473dfc0b2af5936fc7478ba327c1a539819c0f73b52a23
65183e99633109f59e983063bb6f5900e18dc10730659339c2f6f09675200d9a8831c
5c
envelope: bcbbcb785d801e782a49fc3c4d4e2616460a838851ce19488b8bcb2eccc
fee42a996501091ff9b5ca16e9be1fa1c582c6b83ad2940ea5958443ca2ee4345249e
1fd172816eb12e6c61eed8e617bf993162efc01319082feea232936ada925243
handshake_secret: 8f96112d25035a188e7adf11dbd03054753db833d86095d87b3
959803e4ca5ffc0a593b47a3b7cc762090736f791117a183cd7b5ad78003c2df0e786
da84cdcc
handshake_encrypt_key: 9e4848c2c3e524b79099f5b1c595fddc1e96aae88d375c
3ecb31581ab58580cbdf13db962815215a9269f923575a16278e5ec0cf9ec8eb924cc
4fe17fbc882fc
server_mac_key: 8aa4814fdb436114ee9baea20265d397ae1a89de71cff7361e78a
62aaa6e0399f0e80b676837a3288e4001d518bdc07b08272db885d334edaf4950676d
ddf64f
client_mac_key: 2b074bc2b50c11ac269fb03fa39cbb405faaec8d741a5816b75fc
b7db3ba206abf2b911510853cd1f9b0f67b09fa61b6e450fcd14e7eb0f5974d5a7869
3049c2
~~~

### Output Values

~~~
registration_request: 0301fca4ee81d22c8e8cab4cd5e1724bae3cede81109f61
7910beaee9771549cf0090692d4342f0045a99a0707e09e38838e611a3f19c81bba90
12ad6c67ba55f40b1a
registration_response: 03013ae2a5200e274b8993f841f2ff6b27371f334ca7f4
eb8a30a0a8d1e11b07950b8af8df482a21cd1ab19b71dcf96325ad8ac78df806f1368
600b95a8b7f064802cf0200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
registration_upload: 0301a3e70b0165b835619aaf0a82ebedd51b88637cbe1079
cd6e239396aacab7ffca5c6fcce48d21c1b36acadf951a8924aed4cf17c003dd78ca7
7fadad1092885ef1af719666b11be061beabb92c00b7e8e47e29fd8d2c3a1d319dc5f
65fe45e8e1808a8b0cc7a51a4de8f03c9a9df8705efbbff9be82d2d702e0d7fa6bb46
6b70677bcbbcb785d801e782a49fc3c4d4e2616460a838851ce19488b8bcb2ecccfee
42a996501091ff9b5ca16e9be1fa1c582c6b83ad2940ea5958443ca2ee4345249e1fd
172816eb12e6c61eed8e617bf993162efc01319082feea232936ada925243
KE1: 020197ca02b425dfcae9aafd4608362a1dedd8998e6cf906191b4d888db30de6
dbbd22fb3a1bf310cc09f781d9c6fa0bf1f1e9a79c09eaf0df596801cb9a1030f9d2c
f5b923e6077752626ad8889482607b639ffdbfad860fab23702585ce3e03da5e00009
68656c6c6f20626f6202018f831d92dd0355becccd11cc3904ddae5edc18d6e357ae4
3a7dc3459335316f842771994b3b411da7ad3c8911c806b322a9fad184e8b5586926b
e76313b87f3d9d
KE2: 020168c12692280b0dd0937a933c57c3fb5e1f3a8320dd99d56e26f4d8bed512
2bf381e46b8b1f2017896b71a84b5dd210444b46ffda8edda47d9dcdfb45ca35b837f
06665900da27eae1f4e8f540cda448f963ae1ea1158eb69183f44a3ae32982b1e7502
a6f0500e7fe14585ed29a8efe6f2892f3600cfc60788c119b8d6fa2beaa7eff8d581d
23bf3e6879c458fc4e9a3429a9e946323ecb4b6c7144406f711c7dd4c5085e5913588
08efc11e7404fc6d2ec17de99f9d1b0845e9552f831c30c89c15e10c277c9ed64c3df
40abd4710c8f9263d39df5ac6d8e8cfa2aa223280ce85f6c39fd4ff101ae5e7555f11
30bfe5cb49674a2a31d3c24202b9dd7e771da17227504767c48c1baf7cb3120ea2424
ff020a6189a5ff6acce20fbc9aeeb6d32ebbe25270300f8b6a63f05a1a6f6e3c856d5
12860d5700cb3ad37bc1dbf4ecfc4c77c3aab7bb6576f70be7b460143e577d0240952
4ef5fd5e82a85fec43cc2d66adc312fb27a1c000f6dbf8888bd5e539572da91579538
db82375e1ad673e1d6a65930b81e85ce793bb98a3d1145d052ddb667e4b9a25dd0823
86493f649e6022113c5b683439b2eeb7f43ec5590148158cecd07b420f9c3
KE3: 19864579c6d9d2c2a7deca89f13cc66e61481222a0fc56b6dda24aabb88c96f9
4156238484167e828574bac6268a2c2e216544dbcd6c8379966a66d64da91507
export_key: 1ed2450d9115fb9f3cef503d4420211a05b01e4cbcc4c64838381b9bf
85e72a6039576a7de4390df25967b81aa6c7ce68e931b435212d0cfcbadeeebfaf4e4
86
session_key: 5e734b7d028617b7805e4ef8852320e68103d96c8f01defa68e423c4
5289406ceb02012474b4488c569f2d39e67351a3721c678ee501f9c20daf026686cb4
db7
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
oprf_seed: 770c49dc45e42003570a70b3d7318d9c6f725e3df8459ebe13d5ed1f67
9fbadbf842a595a8163f23c00391702f43ba05b7f75c6eec168313b9b23e24fa540f1
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 3f4fa6b545833bce3c65734a3dec46f9bc696248c9641afe757b7
affc584c28c
masking_nonce: 373dd57867f26ba4c53528f88da94c4452bbd459740866542011db
59682b6396
server_private_key: 012bc7471bdb9fa3e113b809a86dcc379b782052bce3fc9f9
62d373217b0c266b1e0932c7a0727030de9ce81d360d97fa94f7ca377aa6969e1748c
9f8b0a3f230c50
server_public_key: 0200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: e16b61ad92769ce70d1636996ff2b83a2f15c959b14c626abfa4414
41efc2c65
client_nonce: 4c8193497c2479bea0b33cd96c77155df766bdf1c88a821523b2a3b
bdfabe569
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
oprf_key: 00a0b1acbef97999981915473a54b94abc4700f6081e298acc8be8aa065
d1fd879a4afcde3358bccb4ce5d37af3413344193b544768f3ba1e52884e8e766540d
a837
~~~

### Intermediate Values

~~~
client_public_key: 0200d01a0121a72de952f5e32379821cc60cbbb6cc68cac38b
1b20d0dc690d4afe7972770444d7f199a6bfcaa78c4949f720c5a03676715cdc186c0
c8828cbc18fd594
auth_key: 87831c269781a572a91df367b92a04f748624ac52effb9bff8c87c8969d
09a057268abe62c336ef90ad83d37f389f07b63e95cfa56e25804edf341fa0badeb8a
random_pwd: fe1e830a11e1e12e46d7a316406403052b02d624176cd0109e33451f4
da5c1e53c6f47fd8f684ce5ac9b32e2092e17dc1b9afe803eaaa758d78f491e570872
2f
envelope: 3f4fa6b545833bce3c65734a3dec46f9bc696248c9641afe757b7affc58
4c28c3eab33373f5348e7b7df128616b377b3e28fffeb66253e4d83a37b8cd9205f1c
6efe1014553ef9733bcf514009240bec29688b02cbd522ad4a26fcb0d831a95e
handshake_secret: 727c747ad3ad4beae5ca04e92130332f4f499b204474ac1ae69
0d8249c4330dadbc904c74d06a7239fa8ae8af0c5d08de6f72ebd2cf840bcd043abdf
eef5f12a
handshake_encrypt_key: 0cf72b994d35c6576c2919850a3b7dba0aa7c1a3ac2f4c
3e03e23398db8f8af439fb8a9a01bf75f52aa8bb68097fdc67ee4e14e904b3b2f28cb
bf3e0eb3a7cde
server_mac_key: 1a5442a05eb17de334c5d8dca5da4ef288774db402331b3e914c1
fda73067edcf5ab3822ddd1ff9b4be2f745f41ba5bfe90ca0776fc5d584e4f6a19dd4
af63d7
client_mac_key: 253445a3d2f9e031f0b0a4fec0c86384571eba71bf14f1135257c
23580ee70a4f588afc5638350395ad5a578b2dd8e43ca642906a2b35f3092bdf0a233
e49624
~~~

### Output Values

~~~
registration_request: 020178d37274cd1fa2512ca1d238613727201561218673a
d3fb6a391cf6dbe028dd8d953f0e36516eec3c69ab0293b19769074c4b16ca36d06ca
2765543e694fd8a2f5
registration_response: 03002a248dd3fd147435975d22732adf53a2276b78e3d1
0bcdb1c9c768f0dd1286bf106eab2cfec9d99aec07310625a02aa4272e693d24ec301
c7057ec0d3cadfa2cb60200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
registration_upload: 0200d01a0121a72de952f5e32379821cc60cbbb6cc68cac3
8b1b20d0dc690d4afe7972770444d7f199a6bfcaa78c4949f720c5a03676715cdc186
c0c8828cbc18fd594b5c09b00d8e0fcb7a91200eb64929faba49adfa7f2eb23a37ac8
9d08926a38da2846541dea3b0006b013dd9ef9c908ab4181eea9d9a4b1210ef670cea
579aa1e3f4fa6b545833bce3c65734a3dec46f9bc696248c9641afe757b7affc584c2
8c3eab33373f5348e7b7df128616b377b3e28fffeb66253e4d83a37b8cd9205f1c6ef
e1014553ef9733bcf514009240bec29688b02cbd522ad4a26fcb0d831a95e
KE1: 030041daee06de56612bc011e3fc1b5b1c5eb334b6cc0cd587b5c6fd9f94271f
dade91de48e730d2499eefc313038c54e3ff0326da0afd4f5defd0e4f88eb9fe6dde4
f4c8193497c2479bea0b33cd96c77155df766bdf1c88a821523b2a3bbdfabe5690009
68656c6c6f20626f620301125c341b183c9ed98ad735039a5aeb7a9c99c6a90eb2dbd
5a02ffa442393c1de1a7f11ef5a7395a3881525c7fb8674d74d842f0cbece5069f98e
2528ec903ba7e4
KE2: 02013e0017b32d11895cc6a5c1f1decb87a7ba2f776ad5ee444e294dcfe11e79
4f3e3eabe576dc20c36392fb2b06d1b99539bd804cf7fda54ecf6a16e056d625a7b6a
0373dd57867f26ba4c53528f88da94c4452bbd459740866542011db59682b63961a34
0813e62356d130fef4130d6b6abf1af58eaa19bda68efcd309bcaaec3400549af4c6c
b7f9e6ee443e24b72ebcce1400493fb3d6d368b7af4185b1a15cccc3fa34d1009298b
6f625c9c9d897be075e2137ecb92f19d5aeb10be3e69ab83ba69cb47667f5c1b0ebc3
8b43ad76264499d1e9ffb2504d405e384090769056623db5c2661340a21fc3c447e12
8f5b0322fa9f0dbabf8a3611c1694b99dd33c32f799faae16b61ad92769ce70d16369
96ff2b83a2f15c959b14c626abfa441441efc2c65030121f7821162fbe027849ad750
dab6227d5633a7148e1b09107d200d7fe63219f09a4e96ba8cb734b5b20941196edb4
71863e1785c22e950e3ee34c85aecc454fafb000fd5ab46c9d10a0f16f3b963d05459
cc1070cff553fd2f2216f810da301dae5e93c94d8e220a7d58cea81bdab50a5f5bbd5
e9e6076e1bbf10ae6be81ac6152a4fe419c955d89d2d24e03b6cf52ca52da
KE3: 0bcc4a08652d896ca25a8a0a4882f03209e076e40ce0271762432e5759f8bbd9
109fc268face1800e3a3528c5ec598fcb487f8b25cff35c02262136cdaf6b1b1
export_key: 39feb6787f362a6ece2ef84dfffec4cc2a2d52749853446d79d3fc5a6
5b236b189ec6cac567e431b7321a1977177f93f32de7446827af09e8182d2cf024552
21
session_key: 14212f1cf503dbac07eae80799307ee2e96820d24396dba60fd16b3b
7d1315f7d38264e125640e8490a9408fff6d3555265595d4fc5121ef11960d459c408
d76
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
oprf_seed: bf5ddf0eabebf042c44efc36118cb0984713a5f410dcbb0a180141338a
e58a3b0fca58d290e4f63503f4925168cad7f630f99f83d19e9fd680854869c67b0ae
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4619306019b7c6b57a665ccffd87fa0496219d831c35c6c7ba54f
567865a531d
masking_nonce: 4ea05cf405bd21f6c3b57b82eeabf8ef4766b8fd0f2a4faa74d2bb
f0bc4c2924
client_private_key: 2d8cc16606d110ecf2ba00464406a0975452b63a3f27ce575
921f91146543b0a
server_private_key: 5a673fae0015e31ccb70006aa21ae18853489bcfd11c0b796
0a3b37fc3654402
server_public_key: 0c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd
9d2f936a37f14e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 206f32e31dc7c364ea569e877d90dd8cc7da4217dfbaef09fbb6dd4
b9f6b817f
client_nonce: 7dad2bf20e3e24d4fc9121ae96ca41702307813dea565f5aa6fbd61
be15fd21e
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
oprf_key: 8d412ddd9e11da58cc35c07dc36da28bc5bfe96960c81c95fc64a677eac
c970f
~~~

### Intermediate Values

~~~
client_public_key: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c79
787e2df91e2371
auth_key: fed70c97ab1688c1bd3933f4050b004c25de54e43f20aeb1da49f317836
5f8873897783e433787b5b4a62e46aaafb7eedd4668cce178f8f32c5d5ad56aba8d29
random_pwd: 421dd8019dcd0c7e3fb56734745913591d4d14e73a88c711a721d9dca
b4f174c7a162dc3e5c2bc16ff1b913712f30a341a37bea8c74877a2f7a5073d37dd23
86
envelope: 4619306019b7c6b57a665ccffd87fa0496219d831c35c6c7ba54f567865
a531d0b69cd6deaa4d0fa83102d47592c5989f800814a448f37b42b9ffc8c703777a7
c0f9c0fdf99d80609e50531dec7958a6351ec52483ef87a68d71e914484d72df1e292
b9d58c792c2be6ee39a45f5de75693074fe089092f8bdc1e84dd7766927
handshake_secret: 36b785bfaf46108219b88602e0a6387627b7c32c96953419aba
22e02fa1e88524223594fe9819eb88b08e8ba40249bd2920eddee2a7ffbd93b678b41
4190d3fa
handshake_encrypt_key: f4e88ff581b4791decdfc81e4407ab3920f93eea9da44a
09580c97acac77f99105e3e3f9b241a13e846ab926f026057b9b8175255ce566c36c2
01b8dec868d12
server_mac_key: 017ebe696d30412246547512d6a5ccc43f21fc45e5fdef30fd9e2
5ab2f29b86fcf10dcb95afaf2d0357a360bc58a9a2a1921663a13916ee74db1acc038
f94ba7
client_mac_key: 5e9a80306d21d7b932896d4abd2dc5b4fdbf4251f2e283cea19ca
eeba9939b28ffe9a0a2a82301a0368f0d753787c3ed78d2bf156676dddbdb56e53ce1
2f69b3
~~~

### Output Values

~~~
registration_request: ac2882512f36bc4d5914964e782418271371fa9bd16878a
5fb6c3b6d29c54422
registration_response: fee6f6ecc113beb0f25556e77869f0e374f06031823a4f
475968b9f4bfee49270c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd9
d2f936a37f14e
registration_upload: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c
79787e2df91e2371907ae0234541412cbb59693b9fa15caacd64288d57843b5f33e32
9ff8722abb64f2a3174cf8fa3696149fb2e5d56a2bf32614653d756933bdaab200783
4ead454619306019b7c6b57a665ccffd87fa0496219d831c35c6c7ba54f567865a531
d0b69cd6deaa4d0fa83102d47592c5989f800814a448f37b42b9ffc8c703777a7c0f9
c0fdf99d80609e50531dec7958a6351ec52483ef87a68d71e914484d72df1e292b9d5
8c792c2be6ee39a45f5de75693074fe089092f8bdc1e84dd7766927
KE1: ecb46e5c31b4044876ccb2a689efc82231d2995561841156db449c71637d145f
7dad2bf20e3e24d4fc9121ae96ca41702307813dea565f5aa6fbd61be15fd21e00096
8656c6c6f20626f629698728bd0febdc164c410a6738962b955c08a36b25c89058c38
d4575592c12d
KE2: 8ecaf23ab80ca5471e573037543b6be8b87f6a436ad91763d5da5eb2bc4a131b
4ea05cf405bd21f6c3b57b82eeabf8ef4766b8fd0f2a4faa74d2bbf0bc4c2924e6453
5c5a8cf0311349c90b287a5357e010b520b4f7234aec55fa5c9cf4550098586b8bb04
6afc0a22a3fd14e908fe451be1cf6cffcfb9bb05068b95e120873182a87bf75b1d627
cdd97a0a466d7dac04795fefa704625a834bd745c8df30233fd036733dc1421d71cdb
cd4e66d9a0fa3d2c49cbb5f151f044aa83b2bdf9372ce9f7547a285f378ad98695182
f571ff965ff559f49f8aadfa17b54ae8b5238eb206f32e31dc7c364ea569e877d90dd
8cc7da4217dfbaef09fbb6dd4b9f6b817f34be8693c06fc0168040b3321043f40ad79
648211e6604f883bdf23abb045813000f6b442a9807660defec7b380d6d954f83ef6f
72d25395735eb75ddbeec0175a636edb225e20b01de2288b28bb804a5442d86c0f12e
477f935d1ed0878141b539e102f004f020ac6e52b30a01db5cf58
KE3: 741ba7d1f6f77a54a5a3000448b28f4f4c31606264f7a3c49a668c39d4cc9c05
de5fbcc37c5501bfe273ee9e6a885015efe62cc3887f576fbe5950102389af7d
export_key: 2918e6532d97e6a981a1f72e15f35371c862a82e2b5b254959014adfc
67dd656053088e591a4d3d5f059c0d649702e021538b6c26bd56523ac8cd48e7cddd2
7f
session_key: e6ca9f3a0d32bdb736174211a8aa8718ef075c81570b965c639132a4
4087cca64648a9732a251160a55f02347f36b422188f4e5ff4d33b5790a0eaf7d5f09
a86
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
oprf_seed: 3b2ab77410131ff0dbb458db31868968fa1ad42a29c3b8ee9a0abb5862
c442230c093573790ab68666a3c5f2c88b281e0c252f121b513e378bbc215391047ec
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4f476ae11bf5dccd031baa6b845b85da8127c95c53ce2d5924d52
75f2548cdcd
masking_nonce: 948f088137686bbe21551f627196e2e2d919fc87b87c1e123ec942
85d65cd669
client_private_key: 10b3066e47db372d6cd714fd308d056c349df63a477498b28
ad3f0e75ba47b0e
server_private_key: b69bfaa8582bc1d07933c6354dace6674e72fb420b9c40cef
3a5fed717de1d03
server_public_key: 928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9
f4389fecd57073
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: bab4356db440deb3edbc3c2f7ed71eabcdc2101bc0eef8569f123a3
3d2748e2b
client_nonce: 7c6e657937a82155c62e9fe2dcd5ea599a7a7e5887291fd0b308047
27c15a126
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
oprf_key: 254d6af449ce0fc731dd12e1d6ac2fc98eba4aaa2738145aed76e2395a0
64209
~~~

### Intermediate Values

~~~
client_public_key: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae5b
a927c3c6a9af07
auth_key: 949047eca8f54f51a069aaaf1238b4455a45c58c37ac0f1a77030bf5883
b7cbca7ca5342c31ccc714a917886c1a249826878e46316e14b9dd073867dd35ce4de
random_pwd: b734ebeb9ea6f760668ab4427658187b38a432c1c44da6106bbbc1f9c
5146c7947862854124b3c891de7915ca7ddcaefb3ea4803df6b1a61b8e30bdef99560
36
envelope: 4f476ae11bf5dccd031baa6b845b85da8127c95c53ce2d5924d5275f254
8cdcdc5514686a445778d99979812b01601533d223b58997f670a46f2c4ad7a6f80e5
b5d0fcc6424851de881c01435411caa4a069e47047d6728ba697f9135853cad1f6af6
4819f8126b73f82fc0162b5870e789817e49f3173aae933b7ae313ba2bb
handshake_secret: 2cd2a46e87b3db890923ea9776f60e1af1254055d157189e5e0
8b3705c6a29710348c5b046471c06914b7d32d1095167895b1c248408fdff65501675
96199648
handshake_encrypt_key: bbc3d7eb971d7371206c3e7833241a017667f9dd5666f1
e150264f4ab27b470923b8f27fe9c11363085b6966ef904d9a5a68a2c2379cb95bcd8
752da35e58b1d
server_mac_key: ae1d9770d25e3a55a68566ab50ee9e872f302435daf8ec6d8e6c6
cd02164733db0d61ac317cc64afe92694b280237c4a47d54a6f89c48a2dc139535dfa
b22988
client_mac_key: 9ac4941a86ee29bfe25961c6b983874b9803237444c6076e99e67
00d4ed8dbfdf972420edd10aaf9af2f814e075a42e33cab351826db35eab7fb448843
6ea881
~~~

### Output Values

~~~
registration_request: 34fb6ba29e60511d9ce2d2a644a58b8b34af6516cc54f20
f7ff605e8134c1213
registration_response: dc25f3e391317cd2b077196780c50cf2730ca3d1891d3c
d222d38534f13df67f928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9f
4389fecd57073
registration_upload: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae
5ba927c3c6a9af076f182d698657924a3ee8cc7d4b7c8a1f7744efccfa4174b38e0b6
bb57f50a53b60c08521a1ed18f6b2be7c58a5ec5802de3c22f73c62cbedd14fb64c43
b5b3104f476ae11bf5dccd031baa6b845b85da8127c95c53ce2d5924d5275f2548cdc
dc5514686a445778d99979812b01601533d223b58997f670a46f2c4ad7a6f80e5b5d0
fcc6424851de881c01435411caa4a069e47047d6728ba697f9135853cad1f6af64819
f8126b73f82fc0162b5870e789817e49f3173aae933b7ae313ba2bb
KE1: 9e642c6da6a475f89078708431aaa4e04d96097f7778b0de577bf4d08496ae5d
7c6e657937a82155c62e9fe2dcd5ea599a7a7e5887291fd0b30804727c15a12600096
8656c6c6f20626f6284a786fae7664759a8bae0cbe9065cd80b70cbf600efc695654c
93e356735c66
KE2: 1218a9ceef710bf0ae91783854c3d4919f2db7d97a1c1123994c50a8f3bd7d6a
948f088137686bbe21551f627196e2e2d919fc87b87c1e123ec94285d65cd669c8675
37ab99aee1dea79ca10f3d246ee998951b4d2c09d458cba81e6468ef85935668bad51
3d4959b73cfb2a62bf2b519e01ac51e3484a6f77a9a1ad4381fb7c50da61f79043e7a
a5370f702bf96329af3614bbc37e0ecec74e243f2b743d045aad75411f13cc9f321ce
88f53494b1a90e489f15b702b92bb9c7064729e65ea2919344a676b7089a1b00b2408
5d53bb5f16740faba1216b2845059a0a035658fbab4356db440deb3edbc3c2f7ed71e
abcdc2101bc0eef8569f123a33d2748e2b5ef3502cc40e7ba5006845c131b661ba6eb
d0e6994b6f526e3b7cc108635912f000f9154412f6f0bccc91664efae256806d3d0a8
1b2ada1284b29aecb9e017f1966da681558add7494080397da7b7ad52ad8e5f23c2c6
abd65a0f6c5c7bb3d6187df1dc9f3f22f6c84b5ddf619a9f23035
KE3: 556b663c0eff3fc4a975c518304b277f90a766661d660888e0f8ab6438a8b70f
46e301953c1dc868c382c818aeea70786492b9aa220ffe60d25b1c5353f27870
export_key: 91acb3a2c9dcb099b20f8017049043cc44e7adac1f9aeaf4a3c0dd504
6880c1188d0802e3a7856266da834653a8151dba4a16cb2138e5568a2f6ffe1970d81
66
session_key: 6e063f3b85f505a038b33fd26954c621444ac8368f064b5709e14035
82252cc9f16e51951e5911e82baadcd188d3d2212a9928cf2f7d6b8de4915b7bb9dc4
752
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
oprf_seed: 3cd151f11ee485a0aa9083e2551957f4a495708ff8cc18ab2cf7790f10
d05874ae35b9b9a9cb3d55335b2e690f9812cd83b803ca413964204ae008af69b8c81
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: fc06fc3204a8c55275d06669803f5ea6f0ecdd752a7d1b463de80
d89ad9da486
masking_nonce: 98d908d117f672bf07d306a274825a244060f798f0bf836092ac30
e8e81ccec6
client_private_key: fee07a49ab54150e525557deebd0a14a8ea81876fdbbf94da
f03d5a2e3cc8306
server_private_key: ad52e51fb993d6053fd960279d81b6111a367246256f87159
8aaa2367eb1770d
server_public_key: c26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d
9d5eda7943266e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 31d27b54c8024f8fae933a0fa609eabe77bb9493c084a8a58458764
230aac630
client_nonce: f0d4f48024426215ce315283f47497c6c7ed3abe25b9de400abbc4d
85ea8304a
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
oprf_key: 83f61de0d7c47b9004a60552dcb3cf2ad6d4cbcecd4009ab40c256f443d
fda06
~~~

### Intermediate Values

~~~
client_public_key: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f21f
51945a636d180d
auth_key: 5d0d5aceef75f8e04e61f958e16b576f66b61a2df788e184fb956b6344a
3ab834d495fd164f7465fe7070309229c57657f17853de4cd01e6617cb4d6a2860891
random_pwd: cbbb816b184c65f719365df591f36dfdac0aa7c729c03a3913f61ae87
05f67c3ce1600563cf4665fd289cecdd5fb17885133edcbd4429fcd5f966dc4da5b45
c6
envelope: fc06fc3204a8c55275d06669803f5ea6f0ecdd752a7d1b463de80d89ad9
da48603060b644f8014a3859e7920f990e9150a5ebb305289a74326bcb1aabf88b225
a8c09a2aa7b9656506286d35ba321e05c30cbf8cf36e0ebff434927834367d6a22dfb
9a37b7d7a24aabd31f8bf5405871c4f6095c697f8b16b2a697fdb35e420
handshake_secret: f17594bc9e0b5e5bd94e4248537947eb4820be6c942e6144a55
b9db8a493b4377ed62a9e04b6d38fd3e9cbe7f7eec4fc44eba80502c822d74029b308
da56f0ed
handshake_encrypt_key: 7119d68025822ac606acd438809c8d60582fb9294510f3
65292839d25c254db00cc27fd669e5c057ec4738885c696f627d92b4d0bc33b6334c6
9490d554c0002
server_mac_key: 60152044ab5e3a51b65ee456649bfad95978e323e485ab334ff74
bc090ede3d1c7c719212823d0dce49a43b30740aacfd3302115c88fda9de9b1757515
f72c4f
client_mac_key: 7c032c647226f7c8863b0c40466444e323660db1ba24ea9b6c7e9
6671aad3e8326be75323c69115bb59df1a4765d34fa56e9a2ff347112c9ec0cd91458
969197
~~~

### Output Values

~~~
registration_request: b02294ae456aa0e055e49a09a3a4cd7176d9b34778a4dd9
493eaace4883c0016
registration_response: 18f9258b9f5a21b9757449a1d8b673b46a1046c6fdde90
1fd5f33cc3cdfd4d20c26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d9
d5eda7943266e
registration_upload: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f2
1f51945a636d180daacf3472205f7c089134e09d4c7509e385a3c2e62a508954aa792
4a333e785dd26c144c8a8d996f03937a038df451fb0fdb089473a0a4e828ca952b93b
e306b0fc06fc3204a8c55275d06669803f5ea6f0ecdd752a7d1b463de80d89ad9da48
603060b644f8014a3859e7920f990e9150a5ebb305289a74326bcb1aabf88b225a8c0
9a2aa7b9656506286d35ba321e05c30cbf8cf36e0ebff434927834367d6a22dfb9a37
b7d7a24aabd31f8bf5405871c4f6095c697f8b16b2a697fdb35e420
KE1: 7405ec93c531676eb9437f46cf3c3dbe9346fa83dda34a37da03d693a90e9f7e
f0d4f48024426215ce315283f47497c6c7ed3abe25b9de400abbc4d85ea8304a00096
8656c6c6f20626f62c2b0aee89ec05d28e6f9638d2e056f7cb4bfb8b4d032239d3e4a
7960d7479e7c
KE2: 42297e2b781aa08037b14968dce6a2f8b9c0b419efdfad93843562ed19fbb800
98d908d117f672bf07d306a274825a244060f798f0bf836092ac30e8e81ccec60a52b
25b9666099de9270691bf5bc141e5a899636d62a856c3094d3b1b8103871525e2e3b1
c218b65cbbc9be68a638da5c945d7ca4481a56c6973e07685f64762fc61bcdf6f5be3
060fd8e7695713b0904fd2e3b024143d0c619fd90cd28c032781b1e10f5ec8fc4bfaa
f1625cb135e18de6c7f664dc9cbb7318f525560d0dd9b3791bdcbb453ad7a33e5060e
888d45f87fc8e2a693539747f51f1f39e56e05d31d27b54c8024f8fae933a0fa609ea
be77bb9493c084a8a58458764230aac63016041ea53924cafd460331043cb3ec0c7f1
7d6c246499b9c638118a606071e61000f1f62de9b8e3b4276feea0d6b4fbd75795ff1
9577a5749212e74e6cbf26d3c053f308cf49c7356680bab299c7a98fbac3599fd1bc6
3daee82614774f88297a14436286eeaa58c6cdb47f96651eee01a
KE3: 312f86df707aff2cb7edf8565eb3cb5a22fe39029b10fb220f8eab8f0195fa9f
e1aa7dc6f5ed6e4f575b74c776783de06dfe6db6efba9b181ea86ad917e05671
export_key: a405b8d211e283d09047fac20782c5c6ba694f9104f4552b3a43eda70
6e75cd7ec08e806bcd38c39d3c5172fa9393d9834e067078f74850984096bf327d1c7
86
session_key: dd26e3d724a837dbb167ae0c619aadb566735db9f4964a59e2157986
f10b9a07304254d467db69fab45e8f64fef818827c8d4cb2cebc882fa680a2f9fb8c8
32d
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
oprf_seed: b60d1643d95729306e4faa10fc4c8117a418e207fd554b53895dfa0ff1
98adc0face71b282679ab89dcc93d55f9a4e2dffac28ab16a01526618500f80020c79
0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: bdfeb71ba659e45f99dc878607b0777f8497bdd32b36dc78554f1
40cbaf943ad
masking_nonce: 0c12633078207a5c3af9bafda323a07d37f219280e5ab98975d943
8412531793
client_private_key: 75da35392023fcbfaa87fcf458b0344248870cd73a38e3fcc
d00a994e1a09e0e
server_private_key: a7f4d763822fcc14bb91a7b36b0a6d30f1ae8c3ca1c36505a
02610dbec29260f
server_public_key: 9023317b443158b83d4f4b49674209ad390595bd29758f5e86
b1fb217190e964
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 67e52aebf012702caed75037b66d027d319deb5be8863dedd8a2e94
16d2d201d
client_nonce: 663eaf808b6b1bb73498455d68e9769ab621c5593f2d5b7d2c1a600
4af6bf37c
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
oprf_key: 57dc5d6494f498518c3992893447f113d70844d90c49b0f447656124306
2390e
~~~

### Intermediate Values

~~~
client_public_key: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def633
28bec3a4f21146
auth_key: 60dc01a75ae232bf9421efc1ed79cb57eda470aafd05d74cb68fb151afa
55db5c92cb0164e1a0de039b75e20768378c9ac6f845ed1c7bad1fa1f323c945f45cc
random_pwd: 7006ff9dcb8c4d77e68b100f7437c44e8e177d8690e4bf1f77d352764
813ddf2d7307e272c2bce18c0f16d1e05edcafa86544f4dfa7758a11d96e838bd824d
5f
envelope: bdfeb71ba659e45f99dc878607b0777f8497bdd32b36dc78554f140cbaf
943ad23fe24987c2288a00e1de65b4e181321cc563cd276f49c85a2a1c7ff7efd368c
c6d95471a15db851c9e3bbff05de027f10f7382cd71a9855bab3a52026a91806a1372
0f39eb9bad6212a0baf346a8fb93d05e5dda8eb649e0224fa391de2b239
handshake_secret: 0f1be03707f3b724a50606c13e6a0609038bb985a053f11c5fc
48f5b0cfe5eb8d77d41c6debbff38328190ee842a0e61b6ddc4c459f74b6da407f590
5ab463a0
handshake_encrypt_key: e1096f7c40f316fbc6e6a73a2c2d8c6f05415df43b3e92
631de1e918a6140af414c48732399d95f241bf06c05efaed23667b3abfd2c375ae0bb
951da98833305
server_mac_key: f340c2c7fde51deca05ee3c7f40ef6a5ae85853f979d5dc97c2c0
1e9e833e2cca1b285622eadcee594a832ca652e6ebcb86ab473fd7457f7886cc94bd7
d27bfc
client_mac_key: cb2da11098c32a71ebcb5cc7ee47dddfa17a244cb339b7b9056ee
620f8234e97c491e25f5e3baa521049eb06d6c6bb89da7236a308d652587c7c175d90
e745fa
~~~

### Output Values

~~~
registration_request: 6a525dc9419e2d0261fbcd6033f9d500503a27027a48d91
27ca1209e01690d29
registration_response: 640a9fcdedc43cfc040768ee48da3c95d5a94fa51694f8
e207d9143431c8f82d9023317b443158b83d4f4b49674209ad390595bd29758f5e86b
1fb217190e964
registration_upload: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def6
3328bec3a4f211467802cbd2396b5d763e616c30f24c81fe9f6f75a8c4cdc89568b5e
e6a1f6985e63b21f554e70094e4d191ff2cb3ac5361721586afd25bd7a765c6be8e4a
694d2cbdfeb71ba659e45f99dc878607b0777f8497bdd32b36dc78554f140cbaf943a
d23fe24987c2288a00e1de65b4e181321cc563cd276f49c85a2a1c7ff7efd368cc6d9
5471a15db851c9e3bbff05de027f10f7382cd71a9855bab3a52026a91806a13720f39
eb9bad6212a0baf346a8fb93d05e5dda8eb649e0224fa391de2b239
KE1: d6a8af82258885688aada828f32e04463c3739c7da0e63c5246711520dc16e37
663eaf808b6b1bb73498455d68e9769ab621c5593f2d5b7d2c1a6004af6bf37c00096
8656c6c6f20626f622c8ffcf1bbc02dab15df7834ebdf85841395f07c8e7317285ba8
574b6eee3910
KE2: d40d38c031090fec5c91c18902eb1c01719314bf671d10aa32efcf8bb45d6016
0c12633078207a5c3af9bafda323a07d37f219280e5ab98975d943841253179396a67
b8e96d72c6151525a9c0ac3d11391f9a05a393dc9828d924f203b08c7045348723864
7ae7be46f18be3515dd23f2a43297bb56856a32aa9c2fc9296e47bcbf7cf6c58058d4
9bd94f7dbe18a10b59b4a1908d7a83ce53c762232b3f29215a0695cee7cf607534dbb
92d431778899baa782074be020f7c4673ad3929a118685dd0653b0f299f9707545300
89896e461a38e58c40f63b17748bd1d2a99f8f767e52aebf012702caed75037b66d02
7d319deb5be8863dedd8a2e9416d2d201d58a6c4fdb4b3da03df2e5b1f6ce1549402e
209712e5bf9d31efbdb82c00eef5c000f9be603cc0fa335ecc87c51629f62a44e7cfb
fe9cfb22467393a5fafff4f478915d4a409d1b2c38db12dd2550d7c68c9d2caf48f2b
1e20ccf47c876bd9a2fabca5d138fd10643505e1cdc2a9739904d
KE3: 6b264d1a1dffc8346cad06075077658ae1a4c18b45dcf0a19b4430a90b8eede5
bc7e35e746cf0957b6f310e79f2ea0067885521c64f2f46659a13c2294edb463
export_key: b3ebc2b7ee67b3757dc119acf69cc5f59fa2a8faba5c63d217a0759d1
127266f02c0a2713892b3527d26489c6443775084c32c7b89f4484b3fb5d8fd620539
cc
session_key: f6481a35228bf8ca59f30fdb95f07dc65c0ed4d505d9923bfea2e90f
ed98c455d613ba7d7215e85d3c7d1b971d7301c1ce24e46270b1a76cacd5f994839de
c9d
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
oprf_seed: 7af55b77424336ea94bf8705839cb86e2afcd2d33a4aba61181d630a99
a9f53c88d44af0e3746fe78c827a2a9c9e677ecaf8e80dba29717fa69fe6d4845a3a6
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a9677ff0778154d6a36467d1acfcad2d563f18229e219a530ac79
385e21c2468
masking_nonce: ef6b3725b82a43efddfc6f37b4f85de605f5ae62fc2f029559e8d9
227a175d34
client_private_key: f4ff0c84bacb98d40ef1b543bdec5009b450e4fea1c8aeefa
6022540fde3cac20b940bc918b0a16389fe160a1e6ae09a48d235acaa1d3735
server_private_key: a762ac7f6fc2f643032abc43fbb2ad4e6e012f48d106d10ed
ddb5b69d9e36d59b08eaa6830c6bfe473f50ccfb5c033b97885214dfe740e35
server_public_key: fcbb8bbe6f857883e38783acf58dcd6de556530055a2353c4e
584320e0916d28b8278212bd6405864ae84a5cd2508f09ea1185f82c9ba518
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: f0f32c8a7366922a2d42f59c7a68c94e61c7e43751daf52dce7f90a
443ad675f
client_nonce: 8e93c090071b1a5806abefa2d2d73bf6a5b5ea066b40a48a0a35e52
ef77f4993
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
oprf_key: 47f3c06d0edc249b18bc071db57d48cc82cc831a28f111add845d6c402c
7ee8b3b101e2fbf3a4f70fb821a08b2e0ce17016db58bdb354539
~~~

### Intermediate Values

~~~
client_public_key: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9fb6
86b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aa
auth_key: c68797fd65f20c654966dc4ea9017716a209f06ec3f2d19dffd6bd92236
c219c5c9a9e40ff95bfc1504fbe6eb47dbb31b09dd4edf029e6ddd36e5a73d5d36dc9
random_pwd: 2f585b45ac891782a389213dd2d6c3a251e451e2a709c853834d5ca0b
5d204c3a82631fa295e251ee8ea5b40b3737c5aea273dbead3c1982089bf08e1b1470
01
envelope: a9677ff0778154d6a36467d1acfcad2d563f18229e219a530ac79385e21
c2468b7d250a94eafeedad6d45ed809e5f299373f8e0e33c2a6b24f2b2c3e5fb8c0e9
147fb05854d4e6cc82f450e5a40a3a2ead00e1268cc676b74e837ccaf3c1912c64426
3620ba7d80b5edb9bb59b9fa3e4e19fb937af5b92d0ead28140d13e365ce430ae5a85
d11aaea4dff5783687cfeb85b6ab675901a521
handshake_secret: 1fc442e5510ed209472dd2a07fa079fd29128eeda40b1656ea8
b62e5d6dd9dd5ebb61e2089405d36c5c53d07f3030068a63fd21eb711193b0ee6ab7c
d9e96dc5
handshake_encrypt_key: a5a216d7806ee8d1b9bc259811abf458054977de5051eb
879750aa66a0a3013cfda6815c80bfeb3c64aadd6c4ba64dc2ae882d9d1eb81ddefb8
b7f56ef4cc593
server_mac_key: 0afbd167d4d83a9f847b2b70a9592354850fa4f8a81314098438d
2d3ed08f164eb5fead60e35fa7f555c95e960dcede8d9919791028fecf6773256ab31
7bfa5d
client_mac_key: effbed78fb2625565c2640c7424ed2bd9f0bf93b903130b63220a
914e8195c4a90fcd4635ad1b335d8bcfc4b783f8a293ff350264af9117ea109130593
0c9857
~~~

### Output Values

~~~
registration_request: 56eba0e757af33e634107f2da32fbe987af1d37bfec1918
a2d42ed2f6b3714bdc1dd190ed6dc6da310536bb748cad363e76ad2fb1b05f1c3
registration_response: 10564ea25b8a98400ad3a7c5d01b5841faabeee3bb5a60
ea7bd94d85eba57ed07992ef8c8d4771a1ccb9bf81ed3b52344038d844f16ce555fcb
b8bbe6f857883e38783acf58dcd6de556530055a2353c4e584320e0916d28b8278212
bd6405864ae84a5cd2508f09ea1185f82c9ba518
registration_upload: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9f
b686b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aab6bc3
6b015aa5a3f1d455f5a7989e62bbf809c3dd2925429f94bbb0389d2f2e52fd389f159
f839d4442e88628309cc089997a9c7b5cf246921889c6683488886a9677ff0778154d
6a36467d1acfcad2d563f18229e219a530ac79385e21c2468b7d250a94eafeedad6d4
5ed809e5f299373f8e0e33c2a6b24f2b2c3e5fb8c0e9147fb05854d4e6cc82f450e5a
40a3a2ead00e1268cc676b74e837ccaf3c1912c644263620ba7d80b5edb9bb59b9fa3
e4e19fb937af5b92d0ead28140d13e365ce430ae5a85d11aaea4dff5783687cfeb85b
6ab675901a521
KE1: 16ecbe71c272b0b9cce77059395154ae766c95a7f10ad0e699aa0c773877225b
a13e0a8ace5007c53ce3631c7e7cee782a6c44cad6832e0a8e93c090071b1a5806abe
fa2d2d73bf6a5b5ea066b40a48a0a35e52ef77f4993000968656c6c6f20626f62d25b
52b3af68ebda6905d0db5d964660ec9ec81066ef7955559aa302e012006b1ce049556
666231483f56af9dcd1c27fdbafb4d954060091
KE2: fe190264ee3bda48d6db583abc7a77fe8e1d8074b645516448a36a6bb54beed8
1f318f257674d1910115a6c6b2e1cadd85dfe22ee7adb312ef6b3725b82a43efddfc6
f37b4f85de605f5ae62fc2f029559e8d9227a175d34097eaa7dc353979552be44f160
f6096f44246df93ef04f9196f8d840e0798a2842e9ddf26042c6d6d248861b7062a9c
4b869dec13bad087837a1cdaaf372913699ba0dfdd519b93ac22ee1e3e27a66614178
d454ba39fa3568e217e0f8843a0c76727772344f0599b5a38e432e8ab0f8da876778a
7c508f573200a32a503a32340dfbaea7acc6f12f3eed44b600dccd91eaabb20e22ec6
1ffd29a23b0dd54e4a0eadd40ca03d70ccecc104387789195b08f9023304dbe8bbecc
b6d1bb7dda44d925d656a29d5f011f493b7f5ab606244f0f32c8a7366922a2d42f59c
7a68c94e61c7e43751daf52dce7f90a443ad675f5898c178da53ad329a001103a6f2b
4ec6e0966c665fff16d88b87a83aa267c2be161d1a36a39b7b184828166f721b83ee1
5fe4753b05755e000f5f2f6cb5fccca8c054177d0862f88f986f89214723b2ed88fbe
80481c07297d78df12c8f3b6028fc4fbaa75700d9f4c4f405e9582fa9c02e89147f7c
59c9b0cfa8c1fb72680ca743e550f1bb869c56
KE3: 1ede4c6a6cd4798a9d1fa364e85af8f8f48d1cce5f511c465720a8e08d661932
4b41ecbe03f677544364ee24ea2ab566c088a106ce6819d36762541c7b19167c
export_key: f769b9648e130fc679533ceb6eac010375ecdbd57b7433de761443aa2
76ee9f0a5d152c9fc9fb1902eafab2fc0927f57c622a0b6fa1e0c8cc0b9d975dfd4da
55
session_key: 70dbd1aaa46389269e1ee04e88dcd2aa90dae1b1b739b1ba085f3e03
40ab9a512d3f7c395399fa3267aa11af361cda7fe8c92a6f60bbc5d98f2b5da8f02c3
806
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
oprf_seed: d046f216c03155226cd75ab01b25653bf9a9b6a4a2bd2cd55dc29f22ff
4c38abffca783c22a0468ecb3e3f98c889c9fe04520ec45194535fa0dd1250fc95385
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: c0ac72a9ecc7ed1f2f0eb3922c343fe08551c14b061576ccbe006
455f32732a3
masking_nonce: ded6ac982230b4307271740bf5d7ec13433ef781f080023fc037b6
310b87c470
client_private_key: 4f4b1b91c6a9c0dab6a8ad279201e00d358aed1a0ba88c458
589796b05ac19101d1119df1070dbd0911ca74b4634a51b9b1b093b74e1873c
server_private_key: 6ab03a76f031abde2e7d1f987c101064757d6133445217316
02876c29cc7d2652a7329cb8513ddcebb66b178194206a61256f5e14e70d23f
server_public_key: 2ef8f9560867402d20f9c34942bb26e63d2cc667851473334c
6cdf1f89ec0ea218e3ce0f73f9f1fd303f140bff958f80b7d4dd22a150a0aa
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ccd05d00f812c5fb90af5c74462be80dc79552d6f5d22de9cda527f
6511b242e
client_nonce: 340e400cdd4c1debe4af6b6678ca55c9ed557e0bd34539f15723700
adcdd47bb
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
oprf_key: bf1a2605249852e7c6300b9161f91c327fa6f22b36121551461295232c4
e3212ade320918bc88c2b6667f6987a5dca21892f686d7ae52722
~~~

### Intermediate Values

~~~
client_public_key: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec2a
f04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f357
auth_key: 376c77f2f18c5b48b88918f954316e0aa3e257228eb7ac69adab0f18126
7ca53daf43fee5b5400325ec324cd92feac840cbaaf83b8ce3d89ae40c9c9c7736dd3
random_pwd: d25cb7bbdda596ce9e1f0916208359d35d18631f6d9fff26e4338cd16
a3b238cdf1ce6e0f39067cd64df51020505d93a9fd1ad35ddee8de144fd64b58adcfd
ea
envelope: c0ac72a9ecc7ed1f2f0eb3922c343fe08551c14b061576ccbe006455f32
732a3f74f1fb1b9d242488cf9f52fc79a9ff9a111c28bb4d73a65573ff1d068978f6f
a5695580e490905fe0edf760e61dd9bee9699c84e35ee0899c92fc8f2a6f73759e71c
88bfa66986a33eb967a53b511765070640c51e8e348fb832d0790cecdf4e7c67e1058
f5708eea05021aebde627493fb8cd580b65cc4
handshake_secret: 4c6ebfa97234981236f1931668d87b58750c4bef408b0b410b8
3eca7d5d73ff20f1ff13f6b325796ab00673d2a7dae1772d909323262ed34f2b95b60
118fc309
handshake_encrypt_key: d415fa736f07dde956ea440a7313d79a9384d63bc86e5b
cfaebe14668fcab5de48ae01ff19a0f3a41bff1111fac63ec5e744d855baab943cef0
0e74240c2ecf6
server_mac_key: ec8d93d74f6101a46ac85d417a23c1d260ecd35d38fde81d6d758
08782fa8a5feff4d290b1d92a0d1cf624719e276981a02c7ee038a4d359c011436252
0a0458
client_mac_key: cf7673d13058e84e6e9fe849fd476775721e93f19c3c41a2c9ef0
1e14c38896726af984288a994366a80291526288de708a67fbf693e70ba601615c162
c84101
~~~

### Output Values

~~~
registration_request: d287a62ca4d452ff3b5e2d800121dbb5785bb383db9bdb0
c541f8e643443dfe2ddb1162b8b7c758893fde1131a84ae57935e7b60b14058c1
registration_response: 20c14dc7e6866ef157862426db1d9992bfe307ac7e271a
d1033962e82eba48d07baadcfccdd1981a1975e3f354f4a9e820b6abe93d0208922ef
8f9560867402d20f9c34942bb26e63d2cc667851473334c6cdf1f89ec0ea218e3ce0f
73f9f1fd303f140bff958f80b7d4dd22a150a0aa
registration_upload: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec
2af04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f357bbb1d
123fd6025866fb3ef9ff31d411f5e320b088018de2bd2ca4c424b49db14b03f326245
cb10ff5301f2e9ac3bbcf23905726dadeeeaf9126aa2ef93260538c0ac72a9ecc7ed1
f2f0eb3922c343fe08551c14b061576ccbe006455f32732a3f74f1fb1b9d242488cf9
f52fc79a9ff9a111c28bb4d73a65573ff1d068978f6fa5695580e490905fe0edf760e
61dd9bee9699c84e35ee0899c92fc8f2a6f73759e71c88bfa66986a33eb967a53b511
765070640c51e8e348fb832d0790cecdf4e7c67e1058f5708eea05021aebde627493f
b8cd580b65cc4
KE1: e4420dd6be305be0776f14c1140f0b36ca304c007827a8c5b4910c5432dd4caa
6214b4077d4a99e6d6dd7f756bb3531bd010eec2253afd1b340e400cdd4c1debe4af6
b6678ca55c9ed557e0bd34539f15723700adcdd47bb000968656c6c6f20626f62d878
99f024ee66ed5b8718f9966f2f34dde445da12078789f1e6208028cbc9b7ac7cff5ae
937856aa01321310e1858f0e3b89492e9e49f42
KE2: 02073617801e68ebe46bea800ab675f942570dd3e32340ed239ac6c8993ee1e7
a3bde2228f1af7554348c5a947ce20e2ad97571ecc8ed14dded6ac982230b43072717
40bf5d7ec13433ef781f080023fc037b6310b87c47054c444ce989fb1c1b7457b28e1
1ea596968d27eb7ab3a4dffdd5f92197dc4776fd4f033c781563781cedcbff1395fee
7afb95225b5df91abbb629dd9983f9f87cb66c732bf7d9df358341c69b0c26d6bdd7f
beec0d1df38f572d7be1408923deb10e96ce319fca0016eb377212782f526cb8575da
9d39fd1e5e2f95ae9f1d5c3c81a97992fa1bb2338dd86b211a6bf07b7445abf31d919
bdf0df208180508bffc568640735f7e8b51dc653ff122e6d1a6caf899a83aaddb1d11
e623cb73a8c785ce1fbed90d11d37c25ce6d1bd60dca2ccd05d00f812c5fb90af5c74
462be80dc79552d6f5d22de9cda527f6511b242e32751cb95f97035f22d498ed57a8a
f0d2495075aace642f152442da8485211d6a551142d9bc6771619ecf80ca8b4def396
f706ce555e2896000f2281a0c4db0e5758beac921b7e58c2f16026e792d4cf95cc69a
d12c512d1855ffc15bb8281bfee47dec23108ba456aeb6051574c1fd055dd404ccfc6
25e696af138cbd7747578f03f40073b1e6195e
KE3: 5c071ad265734bd3c569b1290db2c05e00c26b7a81c5d00b466124f4556ef3be
1bfd3dd32f5f497e9ba8a8c18468e27eb4a3f8abec9061c4e3f55629222f2351
export_key: 3544f2007de66291657b28a522aa91f9c12cf8025f878955871ddad66
0cdf57402e37e856ee919210b1bcdbc4ece42b8e50d3d41fcdc733804d0a8c96f7083
7b
session_key: 2a24d60516332bb00986e8dbf49457568d0d83a402ce9fcedac064cb
f6eaae48256a16bf74f6920a81f75f38a283ce815224e3bf672472dc0d4c3d8299364
1da
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
oprf_seed: aadd74a675f237a068f19be98556a77643f8839f789141a79077d2ee42
706cffc3d03e2dfd8082ef0acb7c1bec638afa8ccf3fed6bf7889eda3dc51c784f981
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 9e57079382b3fa2de3b5e42e05ebad4d47b6ea3a2d1800ca82078
3b412f3f90c
masking_nonce: a1f23899bef06a3970d64a781a7f484f6303f122cdf411decf0605
1d96482182
client_private_key: 80b8326dd0c2b506b88b0b4025c0db89bb624a8b94861078d
88f88515adfc5374ba9326bc531c7ec458fa14a482339ce7854b1c044ba083b
server_private_key: 5315b843996e1c8dab628f7848b29fd8d4368a414eaaa9110
da1cc53752548548f132674a235f9ee105780d4ece5e1a760c147f744bb450d
server_public_key: bcd8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93
c99e1e9dc14db5c9c26b09e1980f7f5b45774012be6234ac5a8953ff69ef28
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 5d8d3e0477291dad5ea0b58e68fa11c1fc22e648c13bb2c048fa274
d333e463a
client_nonce: 717d807a3e7dad9c055aab596458b625d94bb5958c23fe78af47083
ad03af8a1
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
oprf_key: 9b8eede3ec85c52ca6e4b41cbbb7c7846b81cb14fa3c55ba60eded1ba85
4721e7a7910ce67dbb8b18a9d50389349cd7b7bf14ae2d015b80a
~~~

### Intermediate Values

~~~
client_public_key: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e5f
4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948ef
auth_key: 3ac1d73ffc2821b1abe649549712591dbad60112241670ac2229d785364
ee4a2a58b06107fe36c055452a24778652fb158b5740bb45bbfc5defe04eef562c1f9
random_pwd: 911c5edd69fa0604e369c2cfef6ef42e0bed2e1d31c26fb33a63dde28
b1522147a5a62519a63e77ac98db83619c80bef4e9db1ca766b62f2a3d9374117e880
6b
envelope: 9e57079382b3fa2de3b5e42e05ebad4d47b6ea3a2d1800ca820783b412f
3f90cede0e9400ee002754613547ec34e087389e60fb4b02da997da79775d5a2396e6
f7d3580e53bddc2e0ccb8168c58f3bfab9c74105a69afd867d2268eacc725bd30502b
d6c64fff6599ca2fb079894dfb5e35c0cf2d744042a79fd42a4413c86e7bb890f2acb
6725ed1c33e3402d592b238825526e17384407
handshake_secret: bf0c92cfb51ce088603287589b626c05f2767cbe0802e7ec8d6
795a694588825056ba87935915af36129e03b72155ed8d05dbbfbaef03aa728e1caf3
24c53ab6
handshake_encrypt_key: b5b2adc28a0fa9d44ec01fed7d27697c76217812a4d7fe
b5aa909a29e8430ec3b14888929dfbc6455ba5444765b0e4950e82f2a88917b8ee11f
3172f9a96dcd8
server_mac_key: a021a72bc4468d21d65a3674a90adb7f3461fa9b69938da02549b
3841df2950ac2b3ff319c1282fe7742dc1c8af3bfd73330be3cd3d64c7555e6431d5b
ded05b
client_mac_key: edd91974f5403cd32ec4739c5be020d8095dacfb72a90ce4a4e7c
04992bd99bedacea1231ddfc5b63064e435555a4d749eed68771e9b5a3661da023ec9
d47465
~~~

### Output Values

~~~
registration_request: cc1b854bfac5f36d7f09d18975d26bd031490a8810722e5
e84d13320bc6cc1ad88f2faefeeb84ac706985e2784da104dcfa376ea200241d6
registration_response: 68f2c9cf010cdc3e7914fcd30568d13481641159dd5dcd
584aae1bab0a94c3774b11a4684e69aa8f6de8775fe2bce6a9c96a1b3bd4a2aec5bcd
8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93c99e1e9dc14db5c9c26b09
e1980f7f5b45774012be6234ac5a8953ff69ef28
registration_upload: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e
5f4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948ef7bb74
58b2708bf4df990b9e894dfc19442ae693448f53bd4fbd7d73a451b4057d4344a2c6a
d7f205225f612d5f261ed59feb2965ec1a4ac332ce84ab86d6d5cf9e57079382b3fa2
de3b5e42e05ebad4d47b6ea3a2d1800ca820783b412f3f90cede0e9400ee002754613
547ec34e087389e60fb4b02da997da79775d5a2396e6f7d3580e53bddc2e0ccb8168c
58f3bfab9c74105a69afd867d2268eacc725bd30502bd6c64fff6599ca2fb079894df
b5e35c0cf2d744042a79fd42a4413c86e7bb890f2acb6725ed1c33e3402d592b23882
5526e17384407
KE1: 8447080996dd1f729709b137aa45b6a6e68651f7f5794ec80d7aabca6f171226
e8c5ac7aadfe6b9ace4bc355d7b891907d50282031c15d9f717d807a3e7dad9c055aa
b596458b625d94bb5958c23fe78af47083ad03af8a1000968656c6c6f20626f626e09
74f24da70adf24d24b5e267c80f6335a5cba9442a5658cdb76b3a2bc569d39ec6fedc
1a162f4e6c6a460b0978684aa5f30b3304cf04c
KE2: c4a30275e45ea69c360d6ab74bb109cfab8524adc34d379e028428ce42b2e772
7f7268dad703b1f7516897591b2532c2e9e38a3f0692e501a1f23899bef06a3970d64
a781a7f484f6303f122cdf411decf06051d96482182ab72630214f10a2cdfe7688597
eadc255417c3184f00c911e7565a28136aae2e7ae86c7c8d92dfc5d594c70409a5ece
7742258112eca492ef4ef472312e6049a0c8b8e5a7cd3e05b72b3b53c0c493d952ad7
525b16ad2f3aaf90d58adf952f42ea977fa88ef5d91fc065ae47a7cd0c89afe7c199e
0461fda1ce95d6cc70815a2e1c0e400e4f20b80aa9b60b437c3512213fa056be14d2b
f9d87f8982e139530a13e2a99f56b46e4fab29dcc3d9c507c36b2c2c2505d30617399
42053f4fcfeff65d56c4919bc7e1f6fd7081ef5fd1d0d5d8d3e0477291dad5ea0b58e
68fa11c1fc22e648c13bb2c048fa274d333e463a3ab8469c97f3394c729de0b4f980a
c06ea6a90dd077f924aac4210ce65521a90aa1ed82f46ad5cd948d1d96a179409a020
f8a01cc86cb7b2000fdb9b8351c6be1f9d51a6598ac051553a6e573149a16f5dd2f0a
7a6af2e1d0fea81b596a2653a369f1667b4f6a7a016d8991b4da2c7f017d2b2ac9d71
cd5b4bf96c0831bc085d818ec6b6ff7d94d55a
KE3: f532b2f53ed6082ac7c625e1a92774eb819676b829e4620e2a988b0add31bd3d
0a8f17b34a9fad8717e6553008471c63eb503474f5bbe7ef2ea19432c9535a61
export_key: 501b69c134d3e79df25e361c7aa5380dff3327159130c3bc5277f9b06
2748b189ef46416ecc28f60a979e0128f9af49a58cfdd85a5deb0da1cddabcff27fd2
45
session_key: 02b3b7952452b896fdef16a9395c66ad61ba080291cc523142e6fce2
cfad76b6d9bf3df9b1cba0a24d4991d7833fb669e27570ce56b9d63cd9212be1ce0b7
7a6
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
oprf_seed: b6e62b9295fd7892b311be39d536f1fae15f711d39308e33be5577c206
afcb38a41a09b39877d326ce9769fdc1066d31c543c0f25a913cddfac26a927e5e758
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 43459da2f501ede05779706e55d2b2753e5fb3fce391c2ad88a35
3c412c7aacc
masking_nonce: 8897552abfcc8148f5f43c51b15e66c20a937efa334b24f0917ff8
847176bf1d
client_private_key: 771370125ea54cd3f86666bcf4155379dc1e0d5e6a8fbaa4c
0e0a570b44a311701b936a442f340c21a65638fe11c0e7b3bd1c3528e632d19
server_private_key: 7d455931c4f4efa18d5731a27e8ddbe8eac8be6eae6175f91
137a8cffccfcd6cb52345e2bf2ad8995f69ba5a19ffa1afe3cba5f538b0e629
server_public_key: 9cc2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8
e42262e63634ec59d0431f3878051eca9888bb45c17a68359bb55071e6f6e7
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: d73bc21d845f92ac58c0b856b10fb70aae13fe5da24a422cb65554f
b85223c2e
client_nonce: 3bcfc3dbec4127f84e7f41104dad34b94e57dc6b88d3c4d02b85739
14f3ee9ce
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
oprf_key: 7d08c1a3a56dfdcd1d4d287ff41464b623ea1125df44f597b755cfd3568
c9061270e37418957b14bd926942fb6fec689b3c114ff530c4805
~~~

### Intermediate Values

~~~
client_public_key: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0c4
0dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc61844549
auth_key: 77277d611951c7ee097e18732f88364c5aa90e7d3f090bc2aaa5d242270
aab776efe17a09cf87eddb513ac661c7372dac900675ba5d1d3d390866f2dcaebe9de
random_pwd: 5a3f867f99c5674dc01bedfdcf8ed32d1a166818b7c952df61f2583b0
797bdc4e1d134e74c41f38ee6292b55089e60298caa42a39da8b0e2200d423917a154
e6
envelope: 43459da2f501ede05779706e55d2b2753e5fb3fce391c2ad88a353c412c
7aacc025d388d75a280581be565d94a48f84129a0641f90fe9c563ac5a93f18148623
6263b59848de612ee47c958808d586fecca1f31a7e6d69459ef49848c26e83717638a
9981b0f11af771999957104eba23a1c07370b634725797892aad1269fbdb10bc432b3
89ef14c543d71de512cf284b11191349ae430a
handshake_secret: 730a954a48a1ff4aa5a7dce39c980d78efcd7b81636e6a8a115
cbb343057016e147b99affeab7e8f029651f3754bdb9dbae07272f3833dfc58aa1c47
a69e6a85
handshake_encrypt_key: a91815c1f0b81888674cc81028feb62b19b893764fe782
068c3ac84ddfd6c631195cd597adeaa819314fdca640927e70262d2fb06c78892a593
e052c50865d87
server_mac_key: f8c9526bc3e3adc2e0d6add55d540c77dca4fb86dba77ff600eea
179156dca2f06a5c412e9364b57d09b75f7f9494e12c28f677cf9fc84d0e761998315
1abfb8
client_mac_key: bf39ea5c02fa4a1e5e5fda610983f368625c1dda6549580c3c07c
bc17de08b9ea118397018d1a14d91b9563d70c76511144b297d8b2172c84006381c64
f9cdcc
~~~

### Output Values

~~~
registration_request: 88c032a418dfb1e1cd1a3324ba5992452f93c66edbec9c3
65e92c1ea793cf76c05ae910ae194ca9c51e885d3c2bcba7d76989d0d824ace6e
registration_response: 7c830d3aabc3a1e2712edcdf00a8005bd42c053b30ddc7
0719b4729761ddf09f2fcc610f830136fb24120cdc62a9f0befa55d529b352482d9cc
2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8e42262e63634ec59d0431f
3878051eca9888bb45c17a68359bb55071e6f6e7
registration_upload: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0
c40dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc61844549fd477
c16ee3eb8c31a058de77774dd232dc9a228596201861650249275971f9f29a3851f91
424aa7a000ab0da12146695acad059ab5ffd3078f38a21b3b02b7b43459da2f501ede
05779706e55d2b2753e5fb3fce391c2ad88a353c412c7aacc025d388d75a280581be5
65d94a48f84129a0641f90fe9c563ac5a93f181486236263b59848de612ee47c95880
8d586fecca1f31a7e6d69459ef49848c26e83717638a9981b0f11af771999957104eb
a23a1c07370b634725797892aad1269fbdb10bc432b389ef14c543d71de512cf284b1
1191349ae430a
KE1: b4f7627e7bdcfa7d9112301dd0081a3f51cf7e8853eb48a16c9078aeb0dd99b1
6e691ec45b6dacb2dc05b62f0e09c124c94b1b5390a68abf3bcfc3dbec4127f84e7f4
1104dad34b94e57dc6b88d3c4d02b8573914f3ee9ce000968656c6c6f20626f62b8de
36842175636d346164767aa834a4bd1a0abe805678ced43406c4a09ce40145f03cd1d
620d6b3932243017098851f7003f34a849e6c46
KE2: ca332e5a34ba51550d7c21448d1465f8fe8d38e1adfd9b29dd152a6f7b18004f
790bdbcb163b4fe15cc78d597df846549a1ddd622d422ac38897552abfcc8148f5f43
c51b15e66c20a937efa334b24f0917ff8847176bf1da401ab9ff663f452e492f263f7
6f946ed79ac24d0f9ce615753a70f57fa8019ddf8d3d1137c926be31063603f48dd09
a66270b93443dd8a2f0001db746c770390c0602d1cc897790915d7bf25bc8796a9f65
fc6b4a7774a804ae67b55dff051e183e64f036d4eb97303c06ec2926d6fad1b9dd76f
97eaf9ce2211224f16e5eff5bb5f4a6483b2f38abea1fd4ef4c5cdb7ac4730f8c0d10
605768774dc3a3747c5d019288d1096db2c3382e34313f491b240990eb645961a2713
1bffbb9322d7a1d5e5350d1bfc24244ee8859a6dd02fcd73bc21d845f92ac58c0b856
b10fb70aae13fe5da24a422cb65554fb85223c2eb886b2c735272aa37e700b602edcd
fcf53f73ae463d94139dfd0e173feda40f8ec315c59dabf8b7db0a77cf9c3e5b35286
88b01849fd3523000fa9d70a800d3ee379c67cff6e0ea237bcb761d3df6c1afadf050
b7b0d74de3ef26579f631e2c355b05376533ffc2cc22d43f9efbe6f68a4153f494498
ad4a40084cb09ddd06b3daa04ab6ec8ce94875
KE3: 972dc4488ab83e61d7bf966b5111959d5331669deff7ea79723da08d9f01ede6
c5291a0655d8c86a180b949e8e0651c86b23860b400f71e19e0a0315816c2372
export_key: 625e493887ddd610cd46994db191604951b57863c76f8bbd05ad95896
a4222b7fab19fdc119d5eef4a3f948cfeb3ed8d43d45fdc1b511b1a48a2a4b6823b81
31
session_key: e24bf7a22fc26b20679b0db71148fa7a51715051a9812b93da9e9a46
0bf12a9da3d77456f4a8f7dbddf5ca6e5b4202d53586dda68780d7f8260bda58009bd
a97
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
oprf_seed: 0dde3f6130768dcdb725db323944601ef7bcae0aa550255100547a02f6
b31989
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 291d8bab801c4228d5a6f599ec21ab88f5ff2e48827cc17bbb024
1457dd5773b
masking_nonce: 666148f97d927908d45ea7c6963fe709b2eabb9ae5035ed51e1dc3
dda7025a48
client_private_key: 5b1a8d0d1f59318d1a325244e784530a56f15f95cd7594b41
1ea8f7ac77652db
server_private_key: 40e02b1164d21f51b8022acbceb26069ac5ad37af70212b20
1e18725cb41a5e7
server_public_key: 02c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1b
f7dafca0807eb046
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 4482d6e0c811788fd181b0f85d69ac18144c7adfd1a9f8d9f34462a
e9ab6c258
client_nonce: edb3f54bb4e4626aca8c40e3cd71f4771264545bb531c9dddd4f851
4dc035327
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
oprf_key: b3d42005759ef3b1c2d3a65d9ac93fc984d8be13329e097f35b4df48acb
feb33
~~~

### Intermediate Values

~~~
client_public_key: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430b5
2d36b1ccc475cc8d
auth_key: cb840e66f59c29ea4b9c51847020b98b518b38097745861928f71398481
14775
random_pwd: 4ab7183876935cac847f6b1547a3a94963e93598f42d4d850ba89487e
38f4411
envelope: 291d8bab801c4228d5a6f599ec21ab88f5ff2e48827cc17bbb0241457dd
5773b105bd736bb5960de765386f00fa3edfc40b9b4da436c128882f88b69f9c126ce
9fc2d4f7691a4c1fc86684dafc29de297cdc9898b442bbe7ec83d33a3f4890e4
handshake_secret: 7f52073de8c43bb3b7971fa66c500fb90eb5b20fcb3e0fa0ab4
db1bc5eab378f
handshake_encrypt_key: cc1292ebeee2bf08f5e49ba4c7ebc7f8cdf963607807ed
b69170ae117693cbbe
server_mac_key: e3c060650ac5c793cb93172b4b7d85d6f8977b88b84dea34a4e8b
c0cb1bad038
client_mac_key: 315b6f6e208363177de11d4d5cce1279d5cb4b1650a2e3eb95e50
3193348771b
~~~

### Output Values

~~~
registration_request: 039ae9435af572249db38975b192f1beeac30ed093c4d9f
40bb5236d3521035ab9
registration_response: 03ff83def71dfac33831c5a38013b94cfaa8d81de1a882
ea16770f308d30077ffa02c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1
bf7dafca0807eb046
registration_upload: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430
b52d36b1ccc475cc8d761cfed44e573eb39bd232a40db62ac6c5107bb4dca2855d0d0
5571d541cbf89291d8bab801c4228d5a6f599ec21ab88f5ff2e48827cc17bbb024145
7dd5773b105bd736bb5960de765386f00fa3edfc40b9b4da436c128882f88b69f9c12
6ce9fc2d4f7691a4c1fc86684dafc29de297cdc9898b442bbe7ec83d33a3f4890e4
KE1: 03f86d270a693da19f82b655d8ffe6a26ac2b79ef779de92012d7fad3e15a7d1
5dedb3f54bb4e4626aca8c40e3cd71f4771264545bb531c9dddd4f8514dc035327000
968656c6c6f20626f6202496d129c40fe6d255d57f6d92af5c0cf0ba277e8a0e7b67a
61df2dccd9b02c5f
KE2: 037e059449425fd1c4f052be3ce5f1b0d9fcacb499cbea6d3090ecd022fbfa25
fb666148f97d927908d45ea7c6963fe709b2eabb9ae5035ed51e1dc3dda7025a4840e
9ea19000a0d60df0eb3c0921b3863f448d3f0af7aff043fa4e370a70d5cfa085b8a63
7cfeae23fa801515bd97536a08e2094a8ec5c5a5e2e89d608857724dbb2e111f93c63
ff0c5143afd73f509815c688bd56937af1b24fd9609ede9e19bb48ad2d8ddb51f23ee
0247320b814ff4aa2691e4028cdac29ec5ef22dea0eda3ec4482d6e0c811788fd181b
0f85d69ac18144c7adfd1a9f8d9f34462ae9ab6c25802c5583ec9a10dfa32344fe800
0007904dacd5e6be9eef27b0f94b50605b017126000f5ce892d90bb0a3ee0f746cdd7
830393bbfbfeddd71c449c64aeed6b1383680dab6f8df1aee3d43647d83371a3fc482
KE3: b07ec8ad0bdb6b3e0b19aacaeae54b0f77ecb0a07069b706bc7416c28dc65363
export_key: 3b28a6fd684e4c143105c659fd477e26f17c15e7f0eb762eeafc979b8
54625b3
session_key: 8df744e0eff671c6951a7cb6e91f2c29c42792b250f0b4dbee0cab35
9033aae1
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
oprf_seed: 74b45daaa3655d23f07f8ba01e515d7dcac2d00633e628533fa570381a
96e64b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 73177e3c49019f79c36dbcb43ebf309ada7c4c013481d9bd9721f
c683335462c
masking_nonce: d12242ac4fecb2d32ae6715e4a72ea5bef7d00d88c1c107755b3f3
50e70701da
client_private_key: 03be3245a3830887fbce88f3eccc26f1639b91aa8f043ae61
75d146de19bef1d
server_private_key: 6a62ab611cc2ea77a7fcb3565850ac22c6d3a18b19541fce8
3b070cfa802882c
server_public_key: 02e1249c0906886b33b0ae59c981001448f2541fb718a158c4
b4f37d391e813fed
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 5e19e0a14c045d197ece90d94944bda12b0a5c9d377039f7b9971a8
933d43ad4
client_nonce: ff5172e28bd6515d45de6e22724ae3b05f6a51444b140c26e682a9f
2e09aedcf
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
oprf_key: 65d0c367d4447cf0b05ee13466bd1e2f7972c6a4fd6c83b98dd2b6ce7dd
53f50
~~~

### Intermediate Values

~~~
client_public_key: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a264e
65baa2434709f808
auth_key: 00d460bb60bd89ff22590ef5b79336d88e5bb5f4534e7198f2a1fb9887f
e0394
random_pwd: 77bb24c77aca25a1d32f65d04d0c199801e9edc6b990edfb66bb7ba43
4d78ade
envelope: 73177e3c49019f79c36dbcb43ebf309ada7c4c013481d9bd9721fc68333
5462c61ad6bfcd973dcff80a59e3de58ed1c9234ad5a6150e3439be899b1f79d1d657
de6aa5fdebd1eed3cad17930d93021e54c62a13545d7d0c77f48567fdc9dfb74
handshake_secret: ad4eadd8ae34f34713d41c898c645715726827321e2d0c6d7e2
b61bf5da7e9cd
handshake_encrypt_key: 4f98cb6d70cdeea1c2f1e85579897080f5d34e842c4302
63bd53dfbeebcd23af
server_mac_key: ffb67fcb2ba66112ffc3ab70ab1d5675fe6e15b204b40e9e3b16c
fb641ca72f1
client_mac_key: 43d4d45560193b8c47f84e3d19c338e3edcad2e41e755201891d2
0d960d1bcc4
~~~

### Output Values

~~~
registration_request: 037a055d502f2a882c021fda1ec2fe8e5d8cd0d2a913e5a
03b1e27e0fd06308275
registration_response: 020b0dc6e9f46391992387d02aedefc4df168c1618fb94
f1eef3cc8a95a639743d02e1249c0906886b33b0ae59c981001448f2541fb718a158c
4b4f37d391e813fed
registration_upload: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a26
4e65baa2434709f80866b0b555a7b954ac12fb19f07637fc199b72eaa95a9ad3abfb5
2babf68a2b1f473177e3c49019f79c36dbcb43ebf309ada7c4c013481d9bd9721fc68
3335462c61ad6bfcd973dcff80a59e3de58ed1c9234ad5a6150e3439be899b1f79d1d
657de6aa5fdebd1eed3cad17930d93021e54c62a13545d7d0c77f48567fdc9dfb74
KE1: 02e532d2687a979f0a75112437e1f4c6d5411c555b2330a8d6c45c7c7c657aeb
b9ff5172e28bd6515d45de6e22724ae3b05f6a51444b140c26e682a9f2e09aedcf000
968656c6c6f20626f62026ec987d3b7ea3ef8cfdca092b9d6994d134e933a5fb78929
5335d5f6956399b6
KE2: 02bf0e89f722f4fb7340edf2b2dc43e8e0e1642ac29c2ae56904f5ae424be53c
6bd12242ac4fecb2d32ae6715e4a72ea5bef7d00d88c1c107755b3f350e70701da160
2bd0e702d98ee5b27835add95cd9bf4974b3334ed918ec071e3b44e73412aee55a1f5
5d05110df03eda2177bea00c4b326f107208bc495356a4c287c0fd4b351630bf7747d
cad69b7cc54424ad22b7d3ef255a42207b0f94aa0d9033fb9c77acb4da03638243cb2
ac44eae3781d06d82d8a2c80863c37590cc599d18e5ba4725e19e0a14c045d197ece9
0d94944bda12b0a5c9d377039f7b9971a8933d43ad402178e9554d669786c2e9349f1
e178eb84961a7f8073d9ecbc5cf52bc2fef7791f000f7bbae6bd3cdc2be4670c16dd4
0b00f8111c4be8e58926da5edbf4531ab83f182af113d4ae76b52fe761fe05c4dc719
KE3: acbd56dda75d6dc10d281704721e62722c4728a398df1e9646e4077b4bc7457c
export_key: 68a9fd6a01e8d85f64fcc40cbdb8b43f2c0d931cb47fac4d9fed24c41
7ec7255
session_key: db0d9601717d2d820ba50796ec901982dc6908a19d443c7ea24c0b6c
d8222265
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
oprf_seed: 60a7c56a613f5be3211d92fe1304518c7c7019482c67dfc832994627b9
cb0941
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 55c8252a4ea80dd6aa7e1d12ce4aeb0d7692c29b2923fb7594979
a117e68d745
masking_nonce: 37eca08fb1c9040d6df6dfed2c970cac1b3521dd6b32164ec68730
402784eb3d
client_private_key: eb7d0ea4bf06b78e3ed83cb2d3feb9683cece55d800eb5196
e9304e50ac61518
server_private_key: b4cd2e42c0bbef01350751994440026574a20f677965ad056
1acb622a32651dc
server_public_key: 025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a2
5b74538d149fc226
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: f9f605ca9047ecee3fc5b44860c9415d6ceaa44f557dbee0f384ffd
a2b9597a3
client_nonce: b41a9e0472f4c0b87e3fee3eacf2aef90387525ca1f9ef63ffb2510
b75633ebb
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
oprf_key: 37a58f3523232579c21bb3fcd9a8a7cf99a10dfe0df32b41cdda46295f0
d42d4
~~~

### Intermediate Values

~~~
client_public_key: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b00
3b652dc03e8b5304
auth_key: 4b3e9c4f03a9a3ab87e1e450d74cfacf8e3bbb31dfb49cbea92eaa88602
49782
random_pwd: fb04ea65c6a6e952129b87bcf6a8cf149130715916940100f553d75ba
b324115
envelope: 55c8252a4ea80dd6aa7e1d12ce4aeb0d7692c29b2923fb7594979a117e6
8d74500abfa687ef10aab0f71d0505158e9117d3df72553b3f361fedd4d633d999fc9
dc6c9a66cd0263401812e123ebe1f22946f73106d536e4b801079dcbc53c04c5
handshake_secret: 2665c83dd31b60465c2571aa0ed4ab64cb1b8a8f371a6a27ade
2927286133cb7
handshake_encrypt_key: b5dedd3d01c54346ac2bb6a4ab1f6f233391605fdcbd9d
b90156f5011cb792ca
server_mac_key: 10a413ace7dca98dcde528b054b2f622874a07e69fbb6c4ad9b8f
fe31335971c
client_mac_key: 9db46f08202e6de81c1437ca6e21528e33ae5eeb153f3a2f27335
38ccd88e555
~~~

### Output Values

~~~
registration_request: 029ead8cb71d9f802fc71737e16f75eda7843e5b961c9ef
0bdf8da0cb97a6364db
registration_response: 0359ca5f49812c133b5c96b7a2fb8a0d15e2a362a7f2b4
92b6cf61bce8711f417e025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a
25b74538d149fc226
registration_upload: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b
003b652dc03e8b53044b709c188d9511453fc298e0956d83f3dc345368640a0f03fa6
fb5340b376fc355c8252a4ea80dd6aa7e1d12ce4aeb0d7692c29b2923fb7594979a11
7e68d74500abfa687ef10aab0f71d0505158e9117d3df72553b3f361fedd4d633d999
fc9dc6c9a66cd0263401812e123ebe1f22946f73106d536e4b801079dcbc53c04c5
KE1: 03fbe22a5b37f7345b2370c51a5290091f5af7b21cea757ca017b2a32279b543
f6b41a9e0472f4c0b87e3fee3eacf2aef90387525ca1f9ef63ffb2510b75633ebb000
968656c6c6f20626f6202736055b3c97c36bc8e7bfe53ae65bc38c5be6b46adf3d486
81df7bcfeb96770a
KE2: 02a92b5f5848ef361fc151bd46594da6fd52701c5d6a8355b21320a3a5c9cc71
a537eca08fb1c9040d6df6dfed2c970cac1b3521dd6b32164ec68730402784eb3d567
83250b74573e14ffe318bfd87b01a743dea9e6dcbb4666f395820c5add72617a1e4ef
a1c2a9110f9bc265a44e6d2a717fcce31c1f30f7bba48f47ae3b3e97b719cee89a106
aaf7efb9412afb049cc2dd570549b9d9c156c7eac46f50f0888f0859ddb7378a4431d
03af0e86cc4284136fa8d30a4c38fe7194455a2d0385c4d2f9f605ca9047ecee3fc5b
44860c9415d6ceaa44f557dbee0f384ffda2b9597a303981bb9a42c6f60750d2c9098
ec0e64d52dc1ef0b4d02a20b2ae9ce40b425a389000f65c580d423c63d0d86ee50fd7
2f090ad636ee04da7b60ba03a1de48f606422d389ae4105d9e673510892b71f5b4ea1
KE3: 8b1bf418df881f2ac897da10b3f31a0d5cdf3a276bae1aef227f4590ac0aa0c0
export_key: 67124b42d65b0c2d4a3688d98faf30899762aca3980cdd94dc651ce91
415b07e
session_key: 901fa28cdac430e378589abf319f0a7e7843e16993a314bda76f1371
9502b808
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
oprf_seed: b01e99b61ca3d4a2284f1bce2c248be028bb5149b315006924632a8206
c05f34
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e811d05a0fee75e114e6c337ed0b59391de375bfa19a6fada7ebc
9d0e9213b4a
masking_nonce: 5a5d3badbece00702b1edf296fe3fc7eb19a8dbeaa57d05dc5a1e5
29855604dd
client_private_key: 02c14f564a29a05e39d4b9382c20686e41faa8407f03f5d2b
2b111efcb64be89
server_private_key: 759ebff988d2878fc2ac6619807ac6625d0ba08ab0d6c5a67
e15fdbd8e329839
server_public_key: 0249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c5
e37937a9187772af
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: cbcaf9b392796969d4c9cc6a488aecd96fda907a3a9397cfbc41f21
4b93f0950
client_nonce: b8d87529fc7e4043852bb9fefff8250968ff0900a4c720a23c35773
00dff5e43
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
oprf_key: f06290af94f757d826716cbd47f0b6ec9cf3b270822671398b5d3361741
0a55a
~~~

### Intermediate Values

~~~
client_public_key: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f89a
da3ab1d4b3f89098
auth_key: e448eba62193464235467add48e2fcdf13352031b2493736de3d403126d
8b6d4
random_pwd: 9909c9974ad1ab1915c0bfd4c028e16a945075c1e38befc3f2a1495db
d356eb6
envelope: e811d05a0fee75e114e6c337ed0b59391de375bfa19a6fada7ebc9d0e92
13b4a6de3dc2425da0a54a34f2f7c67d91fda7405dba4eaeb5f38d3a15b7667cd4e38
56672f84b4c140e8f1e490cf4fadfb8fcedb59b7ad57c2dea738c39e590e9921
handshake_secret: d409168970345d38ffa778a6f18b33322e66d6e9c0b27e5b1a7
920ffc6161da2
handshake_encrypt_key: 9affa22ddf0b91de06974be4b246aa5f658005d83856f4
68c1df4f478b8f7cef
server_mac_key: fd3c2a17457e0fac38d78b7f74147df634aa5143792ee398714d1
2424247d764
client_mac_key: 6b1c2e171ae61dbefe46deebc505ac080978ae29d492d39ad9570
84ce8d856ce
~~~

### Output Values

~~~
registration_request: 024ff8b8c3636b93127c0c5350c4d2e64b47c78837d6edd
ece7dd67a260bde8085
registration_response: 031485c4d6577c534f8cafa6c2f2b631283dca2ecdca19
cde0923e1dba2f959e010249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c
5e37937a9187772af
registration_upload: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f8
9ada3ab1d4b3f89098a94c9ab050752a12e7f5b7668b10dc3c350f3024f9ed5e0125c
814e535840b3be811d05a0fee75e114e6c337ed0b59391de375bfa19a6fada7ebc9d0
e9213b4a6de3dc2425da0a54a34f2f7c67d91fda7405dba4eaeb5f38d3a15b7667cd4
e3856672f84b4c140e8f1e490cf4fadfb8fcedb59b7ad57c2dea738c39e590e9921
KE1: 027694e256efc51327333fba8ab1927b511c4152f93ddb0771370995407b4b25
feb8d87529fc7e4043852bb9fefff8250968ff0900a4c720a23c3577300dff5e43000
968656c6c6f20626f6203eeb46969c8d3c0ff2160547e2ab719958b7e8686ca4d9b12
f604883194bb90a1
KE2: 0359f2fcc9f5aeba3bbb365bd1d07fed30b041f54e39dbac126cbd9bff79a62a
c35a5d3badbece00702b1edf296fe3fc7eb19a8dbeaa57d05dc5a1e529855604ddeb5
75a97b63fcf8116d7e117444dafcb6e13a66cbc7902276267219f9283e181fcd9852f
963875ddd33299a005076950bd4d8126702988b4b29eb6f438355e9b169ada9650120
deb8f2af6ce511d3c698700ae00027388ac0c5023c0e215e2a955645f37fd494f4bc4
07e00154caafa0d27d77494c101746ab2a9fe89adf64da3ccbcaf9b392796969d4c9c
c6a488aecd96fda907a3a9397cfbc41f214b93f095003a05823236f8f28bd60569e51
b83712e6371b7006059bb8542216c9b9ec73ae8a000f768c7b04034319a9f05bed544
1b066e6e20998ed11305358d1961304c2bf734c48e3b0b089f4fac3c0ffec60c356a7
KE3: e102d9e8f6d64974389a7f8d0ea1b3c21698847dedad96ce1d1ddef5bc079db0
export_key: 804fcab329b88a9c8a693e16d882db2f0db58dd138ded1dd0e22ae6b6
323e927
session_key: 501bbd733678fcfe38251e017443eb27ddc34ec5865a5c333c7a84a1
a774acf1
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
oprf_seed: d91739852c880c6cf341bdfdb5763a4f2635d8e8f9cb7d18f7b4dad843
894a6500e0468efb535b9ad1cce940aa046532c59773d90fd940ddbc1e73c57331ca2
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 6402924b1c9534a26eb50335130c3ba40579fe45d2ca3c1db3177
c575c0305ce
masking_nonce: c57f7952c359412ca196772f98e9aad5925c0c75fc93c5cd176b30
b52d05dfe2
client_private_key: a052da1e7263802eb5ea90bc30ebd07510b7997e0563f04cd
b0173a862ea1adfe5ebc2d261008f3dfe97647b8ae9d6d8
server_private_key: 32a099b199f3eae54592db460c87aa23e9dc4f969294ee264
5b5184d63c0e7f19fcbfb025d7dd9e32e4906883081c997
server_public_key: 02094306eaa9c62c5a873fee4afdf81c91a91556be8286e7c8
f5fadc077f810adb6bb760faf2e46f85cb0b7649ebdfc524
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 32ba7af3e85ca0ef7ed0ca60433ac56d23e450416fd96ab28bf5546
0809a0a2a
client_nonce: 2681015924ae368a8cfcbe576a454a83619f50449e4638b494a667b
dd5660787
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
oprf_key: 37bcb3b3bb22d8735118bbc185953d5583e57b195a3c4638afa625bbb58
1c500e7c50631e84df4a34adc5064f4f0ae49
~~~

### Intermediate Values

~~~
client_public_key: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132f2
2abd78a05172adde74d97f453b902fb2c454718c91fe403e
auth_key: 97367637550b3aaf02a4cc00577a6004e0fdfbe0ba8ad1f764b94138ce2
7834e6d3b6ab75375d47c5c86d73ddfe4c989680ffa836491cb32066835ff40a129f6
random_pwd: faaed24003c95d79763d22d53c8d46ea9a432f3f47bd139f89a0299a2
e6e568ea23043c0f795815de8c564f20e13d6e87cff572730c46e3328ddd0dc8c0ecd
e7
envelope: 6402924b1c9534a26eb50335130c3ba40579fe45d2ca3c1db3177c575c0
305cea247f3b53b33910bad7a12de2e54cf2c69257245375f4df6bd4465c94ebe5b3f
18245a08ab64cd1a2dc98ae144e8f799e0a03a6c89764a3b7e58d81df62caf259cff6
4b9463e40e77828070494920adb9851f5f43962d5e017e9e093fda8181a7d41de68c4
70bbc36690dff4dfaa808c
handshake_secret: 9def532a763f22bf09b716bf1a72f93acc5980e762f084c4f4a
6b80a7504c5dc6377d7769e00acd9accbff7f045fc289ede9cf5bb6db5ee5185ca701
ea8bce7d
handshake_encrypt_key: c8e7455de3c6bd48f8bfd2109f4ab4d7686e30e1b8d1e1
671683dfd1a6d8a44e42ed046de8ade85330b5956f83ea3db5eebc3c30283d38e1e33
818eeaec7842e
server_mac_key: 10a9f4c728e52b02c6337012cd3083af5d2c4dd887b2bebf86bcf
aab45d5060aa2f30633d270df378e2b963a0b82edef7a6ed24b7398d00818483c6b91
cbfc57
client_mac_key: 40ce8396dff04e9a5eeb7dedb8bb5f3715c56657c9d134bc3c20e
3b6589a11d801aaf3e76af3e58ab7009d044b53bfe0773331dc95bafbf67a169db3d6
8c07ec
~~~

### Output Values

~~~
registration_request: 032b5a44024063a5644913f145e01c5b787a77804a5ec25
588320d5ecea9d524c1f9321b9ae76a6bc168b1f99e7305b9ec
registration_response: 037306f891c91a13bcaae0b489340d208a02a09f9ba238
1dbaa5acff84ef0048bcc1e78e4e8661ce55aa31e3e2de892bd402094306eaa9c62c5
a873fee4afdf81c91a91556be8286e7c8f5fadc077f810adb6bb760faf2e46f85cb0b
7649ebdfc524
registration_upload: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132
f22abd78a05172adde74d97f453b902fb2c454718c91fe403e93eba7e6a8b99e096cf
3346e95b41612b123dbb34363480a4795e1008e7f278b7e850e0b5499904543ae97b9
db0d6900fab896001cd5ece101b115c264517d316402924b1c9534a26eb50335130c3
ba40579fe45d2ca3c1db3177c575c0305cea247f3b53b33910bad7a12de2e54cf2c69
257245375f4df6bd4465c94ebe5b3f18245a08ab64cd1a2dc98ae144e8f799e0a03a6
c89764a3b7e58d81df62caf259cff64b9463e40e77828070494920adb9851f5f43962
d5e017e9e093fda8181a7d41de68c470bbc36690dff4dfaa808c
KE1: 03cc36ccf48d3e8018af55ce86c309bf23f2789bac1bc8f6b4163fc107fbbc47
b92184dbba18bc9b984f29c7730463fba92681015924ae368a8cfcbe576a454a83619
f50449e4638b494a667bdd5660787000968656c6c6f20626f6203f58c4669321d580f
98b4b166fbccd6da300ef7c4f0fe19d5576d3debceb23e50b5405ac264c31691e4517
154d993fbe1
KE2: 030756ae5913ae5d05de793ce75d17af855d926536103a080ffe230b5af1cca3
61e3476c0fd8b5769dcf953f1c100ba6abc57f7952c359412ca196772f98e9aad5925
c0c75fc93c5cd176b30b52d05dfe28e2f15b203b9c4e98f5009ca8fafdd8d659a218e
2cfd29296b2c37b331e2596f267837086ffdadd609affb4a4f5a9c46ee2eaddb0074f
d75fd13e164ee0f2c12492d67879dc0aa60c3689464baaaaa8ece282114e0d3aeb4c6
c67d3dfa74243ba3dacb95c1ad5788bb8ef5527e01c1798ed4ee89c07d2ff922e5010
13c4d75eaa68079f21d90cceb10360a5b5cee8d6d912e9ffb3ace8585521bc36441d3
5f5dfae41c94ad244b6bad8c7215e2f2a7a9fa409d6572a42302993daf1de4bf4924f
c32ba7af3e85ca0ef7ed0ca60433ac56d23e450416fd96ab28bf55460809a0a2a0218
bb6548593c38236dd6991a1c556a5cfa81be6c235891e5a00cf4eef1bb3ab6d653e03
abcfe1634908971d19b9959f7000fc556157a1c51f34b6724f3e3961de0339315716f
59806ece1d146b04136ecf973d1b1c4bc4d5ff5d8e94dd5bef096821fa9dd221dd9c9
b412a81d677c49f51822a96a0064852ced83754a89a2f13aa
KE3: aed255704d8cb2cc5b1c68ae9e018baa5dd423fb2d346c8defde2c10846d1400
9e4414a3182b3559a40877e23e12f82247cfb2cc2c96480b8a5dc12af1837537
export_key: 17e3cbe5b8b736101f308bef0b9efad2cfda1064b86e9b3711f31f559
ed0a3a0411adb20fc72454b747081991b2d61aec14d6c71a51dcdcda63526a0d8cb32
51
session_key: 0d5ecad3e1d13329a5b82c50e6f4624d17a33748039fed40b09fbfe6
923887604eff115dec1e94caf8111326fb808dc6361a6c9da9e810386622a9933d422
282
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
oprf_seed: 2d73d88014b44387b8ffa8fcd998fcc30eeaa579d439ac2fd291339e35
fc2ca08179b848069d6bba8bae401ce91284600bde00be2a1066970441133882db32d
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 046da51ed74afaf11069c0e430d269d7807ff622133a91b711da6
6da8b161b50
masking_nonce: 479e87e4079c8c86f6b52e81e42bcc328f3b48eab4f88b1a69dddd
90a36def30
client_private_key: 194f9a720f11c3f0f1613cef116e218267201ce0aa4f4f55b
68c5393aaa4101699ae3b0dfa984cb954913dea02087eab
server_private_key: d650dcda20f27d7bf4673d820cbf71e498ec903e4b3959af8
52f6d9edfa68f06f4d7ff89d5897912df4f9c633a6d925b
server_public_key: 030278df9fe8759989883c2ef9047b2449abcdbe9f508aad83
f227836ddda86b3dfe0aea33995cd76243a4319800bf8ff7
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 46ec6a3708aa7c32a4e0058cac387f21999d920df70e12ac5417037
7a8b24328
client_nonce: 3e8fe9ef61189805c4cd153876e22fbf34a2b686d5ce84a84135116
b3de25623
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
oprf_key: 5be164e74ef8fa0031ea14d4c08eef9f5db0aaaf1aa6bd8b0960737d2df
3ed178f3335d245f3ad525437d5f5458702d9
~~~

### Intermediate Values

~~~
client_public_key: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1b0
a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff59
auth_key: 2c205269f0c797beb9526220fab195fe44cfae8f52ac68bb5708d39a41b
e9a4e4e8e7fc8563fe4c602678ed16d3534f0b72bd467b27ef18b567c2c46ed6ee43b
random_pwd: d423275e0d6d7d046edd5b9c7451b2cac5ec356112e26d73f3b2c48f9
d311e09eca78a41e48373d87ea92aca44e3cb3757e77771528db629b2b77e0546e814
01
envelope: 046da51ed74afaf11069c0e430d269d7807ff622133a91b711da66da8b1
61b5011ef4e07c7a99c691eed3517fcfb20c5a906b34a0b740902707c5279edd5716b
bbd14a9ed1fb59a6b41a34171731bfaf792c20a006685be945e2dfc137e508892b983
a750d77bc4f2c148c650311bf7ef5d3ca07b6b486d707811605731c0b000a42b13e73
4e169fc5cecf30768174c6
handshake_secret: 175ed4b5190a3fb11a147aab8b7599431d414170569e8614cba
dd9dd76b7f6e291b87d38a5093d5c33b18584e8b68d667e2b638e138034629d0ef05f
08a0c871
handshake_encrypt_key: 67478e9f0c7a303c7b283a04c9418eabd13d38477c2a66
f7383eb76b452332ea65beab9a92514bc16d4c3b1bef1f143e6bdd1c4ccf88b67369e
e55af768d7c84
server_mac_key: 05c814e6f1bcaf4e2d26d27cdce0957069c579d3e355657a91e75
a2b4186bba7e6a50a087ee382d2730eae2651cc40b5fc0de260da7b4bd4804d517d24
e2a0d0
client_mac_key: dc1eb8dc024d919f9aac0773ad748e7fca8c8a306d53e1802657f
93854db8e383503190c16ea9c127355f8917225be86c00f3be8505edef0d94979c5b0
a4fc79
~~~

### Output Values

~~~
registration_request: 02bc8b8b2d8b96ba8f527f59dc0054349f0fbf4c7cda280
480d643909db6a8dbd4bcb455cc374050d8cce29147fab0a020
registration_response: 021975a929b7202e0ae8abe22005741d9922172f4940b7
4ada5e0bd1bd7e6e640480d1aa2132786070e4820047d374caf0030278df9fe875998
9883c2ef9047b2449abcdbe9f508aad83f227836ddda86b3dfe0aea33995cd76243a4
319800bf8ff7
registration_upload: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1
b0a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff5916a4da59482ffc558d0
250ff3690a64b36dea55397ac8433bf8d83de944756f9bbbef40bd5e92f2fccaba3d8
e12dd1a4c26218e4218ec8b65fc3a842717d09f9046da51ed74afaf11069c0e430d26
9d7807ff622133a91b711da66da8b161b5011ef4e07c7a99c691eed3517fcfb20c5a9
06b34a0b740902707c5279edd5716bbbd14a9ed1fb59a6b41a34171731bfaf792c20a
006685be945e2dfc137e508892b983a750d77bc4f2c148c650311bf7ef5d3ca07b6b4
86d707811605731c0b000a42b13e734e169fc5cecf30768174c6
KE1: 0258fdc4ba750f504274ff4644f2f43a75759b77adb1817c8686340bb28059b2
af91d82801b94bbcb8326cc2e046a4df513e8fe9ef61189805c4cd153876e22fbf34a
2b686d5ce84a84135116b3de25623000968656c6c6f20626f6202313f18385e0f0c3c
88f3e60178a6727c9023e1044973eeb676b9a17a398424b1074d5e35246fc25be8302
8853dc22f1d
KE2: 031cc0f37adf9cd185f3a97ab6903cc03612d18079708591eeaae8080970b99a
89b8236cfc321b5e778bce74dedccf1758479e87e4079c8c86f6b52e81e42bcc328f3
b48eab4f88b1a69dddd90a36def3031349a20dccf1ec444983628d013178fc834101f
90bc810877a79733bdad9345e95b16d432c08b01de25fe34aa1334720aef61a7947d9
deb5409f00acc45564e88d63327c9e6784b0f19602eb77d25ac4f45afb7a29e98621a
51e6f296a10c6627095a3bf433eae70b2b008af678621358e13a827ae549d3e3f57aa
0db9d993b6f57083bf38779c16ca0360301f4e365b6ad685f69ce22803a4bf4a87b8a
a38fe12359ea4fef5abe6e699951242173bd670c5ea52626a6af94a88a3726d80e83e
346ec6a3708aa7c32a4e0058cac387f21999d920df70e12ac54170377a8b2432803ba
3e99f4c2f39463fe214e7607ca3e9b1f6112d565d80bbdb388f52437ec89f0da6b802
79e10382bacc7cdab25a3a830000fee61eb2f9cfddf5d7b3373d99fac024b54310fa2
43165035dcc38ba2501ad15611f0c4e652c0183fafd30421f837e9aefb49ad43571ab
605a6b4e17ee64b8d6a918193cdf83767b9abf77a8fee3415
KE3: 1974fde53f7101d592086aefc1e8f7905838f94a10c4887a50004fe441b9ad45
a886bbaa1802b239182efcdabc53f8ec3b9d71a4957427f807ebe8a71e2d9bbf
export_key: 38077d34eaaafaea802952400e23105e05e28d2385a904209d4fe83a3
98955946f84b3f233aa5039a38a1861c2992b2fb01a7804fb7b7ba98334819010d2dc
81
session_key: a27eb23c1ab1dcc0294232c7629d8ff799b73e0d67af677d4a827e19
3be0f051f11deeb5e6f1757cf14dce3c2a49d39968b9b3b853f318df8638c5cfbb051
1e4
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
oprf_seed: b67d9ff99e29ebb5f80a0f39533e2c9d92f92cd39af29abd6a78c388c0
2f45a9a69f5635c9f5a1e1c991cd9e422f5d97a8478eca4d0807a74f3161464188a52
9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cedf2d039fa14e44095c869cf8523b2c0133762d89b34cdb954c1
6535ed304d6
masking_nonce: 1ab11bd83062c0b848a98c323a8859e17a6cb6de3a4e7b0891d6a4
fd517b2ccb
client_private_key: fd62874455ee10870acb5cd728e1e21943e18c3afc1fc668e
18c48250da37feea7768de6574b8b152dc64790a0fbd8ef
server_private_key: 9364031f78d6cfc1aec5bed89c718d3c8ff87115ed1526fde
d4495afe150eeeabc6195e48de31f2a5b24f798faea51fb
server_public_key: 03b73b7125c1d9517a42d63bf21b0c3eeed2b4f76005f72478
de3440dda2a2a580ef58077c145719505764689842231b65
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 3ee019f91efb2950327f5fe6707b338484437e4ba1bd674d0c15030
0b5f27834
client_nonce: eb77415c84871bddd5137278ef9ba3a3759d8d4eea1e7595785a9b1
9b577c97b
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
oprf_key: 0afd7a4f78260840bd46ff356aa6d0b00ddb54cad59ab1309d5474da602
42e0b68522b7841ca17dd8bb8b91a5572409d
~~~

### Intermediate Values

~~~
client_public_key: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab18
f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef0
auth_key: 02089f4414faaf61155e61cc5578d7246c52330bff52317cb05400232b1
67c7ff93ab4b49dd813d8d7aab8a87630c8b8c36f24b6e4161c7d55a0fa52f655b51f
random_pwd: 7d5ac294d720455329821f6d3f9b64b42950432c16d7c068404dc15ed
eb392e6b8c0b38e56daa5017ed6480dc0b0d526dfd202c8fd95b6ca4bce9537ccf949
9e
envelope: cedf2d039fa14e44095c869cf8523b2c0133762d89b34cdb954c16535ed
304d64815fc53a0660c8b648a904a864acc62728c726bd3d8a57026d25b62cd62ba20
e1a9e7e8402bf09d5ff1cd03bfb295d36026948f1743a14a816a32c7a3f1eb30d046c
66de3179a979565dee2c20c5a91b97deaa5e29b55bf5a7e41e8026dfb40a3638be019
4e5e7f581624a704e9910a
handshake_secret: 4dd8f2af183a62feac722b67abee23f54028a9c05370a0593f6
0809ab03af4a7061875b26797613dee911b332a58782b51658e5ba09e12cb033beb3b
78a79b48
handshake_encrypt_key: c3004a7594a0fc0637f5f7bc118006dccbe321c2d7f002
77e4e5fa229c161a8fa3e3da280aac35ea6508643927a34f2ac17830b274d09525340
596e368f347d0
server_mac_key: fb150937dae5d5862ac5315658c1195e089ca1d6d3f6c69c7409a
d89de7063a93192f0e879a5d014f3eac1c07c2487385964fe721596d228426108159c
53fd07
client_mac_key: f500f101692e3015ceb926c70ef77941fb1516cee1aefbe6bf29a
71e66b2eeb15d8b389ba52e8520523df13e5663ae38a8fc21d33acd63cab398a4258c
3eb36e
~~~

### Output Values

~~~
registration_request: 03e0ffa19f9860931638c2a6a3fbcd8e0ec673cd39615a9
d80959edda6fc8d269bfc206586f1a10b46a895f8f17e730174
registration_response: 0296007bfa5ced3e44302d7612b94f918c28c1d2887c15
8c07904eeae274e88e160361227c25f79dd53b9ea5cdf29e9e3c03b73b7125c1d9517
a42d63bf21b0c3eeed2b4f76005f72478de3440dda2a2a580ef58077c145719505764
689842231b65
registration_upload: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab
18f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef0c344f3d72ea200ad190
a7f8b67271e24cde795c25c0f81b0050ffc46c76af05657c499828796a1bfd3da6b59
83289e108bfa9e98f14da39ec2d3da7870cb5ee6cedf2d039fa14e44095c869cf8523
b2c0133762d89b34cdb954c16535ed304d64815fc53a0660c8b648a904a864acc6272
8c726bd3d8a57026d25b62cd62ba20e1a9e7e8402bf09d5ff1cd03bfb295d36026948
f1743a14a816a32c7a3f1eb30d046c66de3179a979565dee2c20c5a91b97deaa5e29b
55bf5a7e41e8026dfb40a3638be0194e5e7f581624a704e9910a
KE1: 027b40080d3b93d00403d4e7ce1944644d57cce6241c69181216ba7323afc9c6
2054300441470c06aff071717754a2fd60eb77415c84871bddd5137278ef9ba3a3759
d8d4eea1e7595785a9b19b577c97b000968656c6c6f20626f6203f07983f1b0b62e77
8918e7b15aa899a5c5c9fce3af75c5a424e114f3c9bc539cb3b290c4c4705829c21e2
185ab3eefcf
KE2: 032519c24372282800ec1242506564db8b76723c367858ad9e21120d100b54ea
d9c128c150c50377b9d98bb8c6807ceeca1ab11bd83062c0b848a98c323a8859e17a6
cb6de3a4e7b0891d6a4fd517b2ccbd60e833a046b3fff5efea707ecfb094ad0e34f9c
0290b34eedc378332b87bd1264849da28f84ff3a6eae871d7c19d2badd4a4944d9736
a860fa10fa54ac4d6731469fa3995672f725456b279b8358af2c96f128d7515013190
090867f891e6eb76ac11de520f081c82edfd207640f68bd9a8e9d35dbcc1dfe353951
96dca89df06497682b5673a50b7f0805aee5151164ddf591a28893eb77a277a62c0fd
168aa091681ef33d583deec0b1ea8e11568216d5f0c0d3c1aab7b96e1bd05fa8c2c43
b3ee019f91efb2950327f5fe6707b338484437e4ba1bd674d0c150300b5f2783402bb
887f84a3158bd1a95c26114059d1064a69dd87c8813ad1ab19b0cff29b48d0e945af1
4537ac16d8f4160bb027fdeae000f781a00a780bd12f56d917949975640044cfe9af6
2b7ebbf11b08b731bff11699a34f5cc3cc2a0ffe3adc23403779ef6e748be366e17ba
9bf6b4c46dc53d62a2ebaf997dd13c2013459a78bb75a3627
KE3: 461bf9c922d97adb3c7bbcd30cfeda9ef41e86e0b94e9b1bf9ae491afd579584
8f2a8dd91409246edc990589f0266dfdd2b8d18a5693251688cd7ea07d584b2d
export_key: 13990eb41d398be3e78aa42ea7e177fa4712f6e5ecd24aaa08f5a1cfa
893eef7d7eb5114dfc108d45428827e27e83d25f232f7c6c8690061b37f3cf2798e8d
10
session_key: 95ca802533dafc834f5178cd65c30a676d07bdbc945f56af010657ec
258dd898afcbb9811cc3a006c797886deaa5bfecc185d612da440a7cdb8f4ca5dcd70
512
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
oprf_seed: 776ddaeb03ffaad68ea5b0667b0ec55b74ff5dfb47230fa80acda7b71e
4e44fc7f09714569efbf5029f678c23ba01739f90f6a6fa5ce1e57164b0c7f57424f7
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: eb198bf617b6a217d9aa9fe31393c1293fd09430a3a107094684d
8147a184534
masking_nonce: 26fbdd8d9514d730c80f39d7bb68799b34ce4ef5f1b0ed120dddd6
8ca0557c8e
client_private_key: 4bbeadefc59f6beea6a2a9557781f5e37bb6ad6f76e66c82f
37070b975ef988bee3486703e469e30348af71c1050d94a
server_private_key: 8e510d60a068ab453634d9f74837185ea0d5483ac4f1dfd38
2792f1299390d98ffcd4e956fc02fe35df273276b75bd2e
server_public_key: 028beb3ce19f449deb6aa31eb19c661d4c4ba0fd08b4cc1e91
416b0c5b5ae74de003a76d68ac4f59b64b954717c4d843ba
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: e8a040bcebf8554c54643eaf4e31dec406c4ccdc1765ca14154385d
5ce5818a3
client_nonce: 49a321f2c90759ea884808fc009abf96a5ed342c95aaa63dd6087a2
2dd7a06c9
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
oprf_key: abcfa20ada50948a6473e7902fa3b0fb76639ea1e4f40ecd340aebf9f88
d2a4afa66341da99c0d08bb39e23e194c0b45
~~~

### Intermediate Values

~~~
client_public_key: 024954440156358f8db7a32b042020404c7918cfd0003699aa
1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce906040
auth_key: 0ba7b47c1d924cb7b35cbf10d35de348733d8b6109b2d2c709621605dc4
f96193db1321ca0b2a77c0662095438e1cce629ca79985be117dc66bbaea91408c941
random_pwd: afc7ba4798fdef89999a643828509c866a4c92f2da6d976fe48a2eccc
3c8d439ca1bb25a7a9aa8018023d3aa25a53707514e7d04afe64e35cb3f33831124ec
de
envelope: eb198bf617b6a217d9aa9fe31393c1293fd09430a3a107094684d8147a1
845340bdda3c71fecbbcf27006704040a7d245454f6c7d895c91c2fbde3cec167d2b2
b4232074c7ab5681b5b555a4cf1570184d8dbf31700a32fb00a99abc5711b49a5091c
d3f0e70ce5bbf96d9382e4c59c0f52115c590945c8ee192a34acbed3685018f38f911
932097bfb4349c0e257895
handshake_secret: 708d50f72ad3f44bbe7dd4c72854db6c2384d8df979c8d9cda3
8ccbb644f424c644628ba53c4bf91adab059e83445512fd6b26473d6002d1da953d94
533e57bd
handshake_encrypt_key: 5cd6cb4c312fb21eb2df3f0ca4ab945140d01e7b24fa8b
0dc28ed8f675ff57a6a6522b553f38c8b329e10ee95bf68681ce236fabf7ed54997d4
ef4341f588153
server_mac_key: 432119e7f2764c2aa94dc30f2b22cc765bbb929575a53dc1dc1e2
82c63c60fc6aaf75aa6caf3acd5c39242fac77ea91590743d8d83ef2eb0438df9e9c6
5c9c8a
client_mac_key: b48baf2a98fa16d9ad171afcba2e7819a4f3e23bdfab9e87775ea
cd10767f467041f8cce2fb1cfbc9b363a782537d1ccba0d660c955df7d6bc4b09c3dc
f79901
~~~

### Output Values

~~~
registration_request: 03a2e55f8d839d6b162d179f9b4f886337188f731db9ffe
0ac206b54096e6a9a8f30785c33d207ece91c4fb97530fd491d
registration_response: 02c0d6628410ec3705d33acc6ddeb8318c14282f33e5fd
a46532d761dbd8085d98d76cbaaae456bb52c7adb49212c4b362028beb3ce19f449de
b6aa31eb19c661d4c4ba0fd08b4cc1e91416b0c5b5ae74de003a76d68ac4f59b64b95
4717c4d843ba
registration_upload: 024954440156358f8db7a32b042020404c7918cfd0003699
aa1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce906040ccfe2886a12b9dfacfe
53d59ec7b9162db74cc94e33e149b0c36075777e7e16c04825e1b153254804ac20c2a
a42c16371a73c66492a22e6181d6417430065dbfeb198bf617b6a217d9aa9fe31393c
1293fd09430a3a107094684d8147a1845340bdda3c71fecbbcf27006704040a7d2454
54f6c7d895c91c2fbde3cec167d2b2b4232074c7ab5681b5b555a4cf1570184d8dbf3
1700a32fb00a99abc5711b49a5091cd3f0e70ce5bbf96d9382e4c59c0f52115c59094
5c8ee192a34acbed3685018f38f911932097bfb4349c0e257895
KE1: 031b4f459c984d8a56589785181e03b93108602ccb92ef3e247651d9a9e72d36
0a93afc86dd79490fa621685779408ba3249a321f2c90759ea884808fc009abf96a5e
d342c95aaa63dd6087a22dd7a06c9000968656c6c6f20626f6202a39a8a45c68e977d
b2ff70778f0d34c28f7cf430ca1045d4c48e6e749429f0f10b226c26cb0ab71bf2445
f6b9ccb81cb
KE2: 03970cbf2e80fa662e8196b185f503b4438f1cfc97a8340260275d43bf5ae7eb
3e9adf424745d2d16036e5054960acb5c426fbdd8d9514d730c80f39d7bb68799b34c
e4ef5f1b0ed120dddd68ca0557c8e6134140558213f7282646f16512c4808c70b3755
afcacc6b52ab08de83716a9522f855da596e26a1323628a7c6754e25db4f8dff4e08a
4a27323cb6d0dd5bf6b002dfd12d9e28c90926855b0208ca70f57ec3ae6b00c7084a2
5ae1b23b659df9d41fe0a85947392b4a5bedff0768c3862f5ccb31d8c1bcc7b0f05a7
6c7e573af0a59be40c73736394192961959eac07dceabd6134a0f7262bbe0ee4f3965
b9f94c947f81855f69428ae52ac788b8939c0e593af5a21ef8d12e23e9d3a0c7ec98d
8e8a040bcebf8554c54643eaf4e31dec406c4ccdc1765ca14154385d5ce5818a30363
57745dab9026251b2bfb2ccd847536219da8e475cd1f2dc4842206a8452c720e3ee24
c0abe77452903c64985b76a27000f6f492b4104606c171baa22bcf6889c832b951043
d78c1f0409561fc76f3afb8761060a886427ee1eaeec9e4e425edb7e5f62237870966
172c4a33e6b969f0df1c05b0b3708497067a551750bf7f7de
KE3: dd3041661a49bd525d639303eeaccba4cf4f88ce57be5251e13c3ea62b152f65
6a775b68b014110b0f204e2cb857d399bedd66876104f984158837aea98d3fd0
export_key: 802eb3081e91279737125fd6840ae7ba69f3eb22d72aaa8d3a302d2a0
64dfe72584eb93a84c97b7eb26dd3dc944707e314c8f38fbff3bc7ac9b84679ec8f21
70
session_key: f1a7bce81dcf81400ca97beeccf17a7cea6a56fe00ad9c057038caff
bb3dfd223cc354161c260aac5b1a9ebb29c174845d51ef821df8a01865af5da41647e
b3f
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
oprf_seed: 97d34e0de397d04839f2ecee0f56a1ed99b93ba4acef528bee903b8d4c
9c14651fd9dbd990de0b40197ed17d4b85c0fbac82f93fb3fa517194f88d322073db2
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0b9d60f50954f7848464fda8131f10b6a695a6733ac27bd094b3b
9934c8038e7
masking_nonce: d6c04ca5d7c6dfc7d0a9eef916cf4adf9fcdbc205af61c8887d866
edb30c11e1
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
server_nonce: 2eb58d4bcc4437ab340bf8cbc14a6e9dd97da5e03d896d1b2938b6e
81f80aa05
client_nonce: 9688865a2c4a9ce0e52718bc4eef0569a711428caec555c0b75e76d
531e7d484
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
oprf_key: 018d5521bb46e983808c170124ac8f905f7d5cf9174ca16add1c32be666
5e1fa058c1b40f746a468365381a3c89ad04b5d4f07bd0d69e94ae189f9a9710b4d05
358a
~~~

### Intermediate Values

~~~
client_public_key: 0201d6bd681715e3d330475e72471c1218aa718d96be735325
1c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf1831f
811d49d120a8d45
auth_key: 204b9780c497b4a8fa9bb015f0b9245c67ee575b668ce013f78de290a60
096df5c243c32de30922b8e608989a2f8d42cc5c569b8af2f697394235add7318555e
random_pwd: 3fca0c45a91fc7941581297fa4a7f24bdadee22c8a31da37dead9eb66
e70fbbd769b067990593cc0bc598542d7ae405b778d34024b25d5b5bf79118479c53b
34
envelope: 0b9d60f50954f7848464fda8131f10b6a695a6733ac27bd094b3b9934c8
038e7fa0b316bbab86be4afe509559cfd999253455ff75e41dcc05151b67ca61417be
d3e5a84af72bb69f94017666dea445d75e55db6e24ffae245363ae8f735337e59a95c
250876379ca14b4f7652111d90e413392f3e76fbc8892d966a5169c26ca85e9272326
64066563b72b0aa332989fa6d01891fb477611b6550b54babebc800ced
handshake_secret: c600dc15663aff0dabfe5e35c396b31ecd9de99042606aa6e0f
38349fc376db3866899dcd1303cabddf22ad75ee4ebad6241ffc1cb941ce017d2549a
3ae853c6
handshake_encrypt_key: b4252b1eaab3fede09895274650df8303a5751ee96da13
e9562759306bac7b6735c5a2f8c52e93dfb842e7e2da91a28791e7d928e6734c6c60d
5b3c3eed0e525
server_mac_key: 188e6649bc51372a0aa7646b94f90cae17bc59c14535fdb7ede56
d19fa098c9b7a3c14107800602f1085ab4e13bbc7d3866066a6980d6b6e580dde99cc
c1fb77
client_mac_key: 1fb76f9766695378e50261158bb687d142f2c907e4fb5790e2c44
6316a9e5012c706773aea6fb7d9f8c6f74388b2fdc4f3d2bc159541c7ac210e490260
0f40b9
~~~

### Output Values

~~~
registration_request: 02015d0cf2aa22e0448949416bb4b3c246429439d4cee47
a52b3b9874aaf727dbde7f34b5112e91e97e1d98c9cb0fb58e015721456160aadd16a
d4f9a9ef2fa3d0ad8e
registration_response: 02006d709d4a9b57f968ef6b3fd4a7533a52f274a1f968
f3e6ac8618109b1dfdf433cec99a6dbdf5d36f28d8bd067931278eff7763c67bc3c02
836a1eaa68fa895466903018fc6a77bc4127886d67871c03462740fc4d6fe66dc2226
365e994f8392a0b4c43cd6e67ce90ad594cb63c146011dc56b213bd42ef677cb6a5f0
1d0bd9944a9161a
registration_upload: 0201d6bd681715e3d330475e72471c1218aa718d96be7353
251c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf183
1f811d49d120a8d4571e3ffe0fae9be88fe17105c5c1f12c2fd414c2a11a22f68aacd
80a43823d4908df435d4c6d8a86a9cbf1174e2318ce3e704fa4fbcf2c79c19e78e4b8
4260ecd0b9d60f50954f7848464fda8131f10b6a695a6733ac27bd094b3b9934c8038
e7fa0b316bbab86be4afe509559cfd999253455ff75e41dcc05151b67ca61417bed3e
5a84af72bb69f94017666dea445d75e55db6e24ffae245363ae8f735337e59a95c250
876379ca14b4f7652111d90e413392f3e76fbc8892d966a5169c26ca85e9272326640
66563b72b0aa332989fa6d01891fb477611b6550b54babebc800ced
KE1: 0200c3bce8c2c7da1856b486576082a136f031304eeba82c3e582d920469621b
9657d018aabad67dd15d32492f0155ec944d11593c079c64c5d19088a72cddb12baaa
49688865a2c4a9ce0e52718bc4eef0569a711428caec555c0b75e76d531e7d4840009
68656c6c6f20626f62030080bf524d28ba64b134c0bd0c860c8b1f976e55d94eb35d4
2aa0cae1935a185c9f7c517875877aac4aa4e909dd5f25cc6ccfe125d031dcfe02459
7af1f7bfb5ed89
KE2: 03002c6545d8ff1735f6df9f9f6d8521e3c13486e0a25f6cac59c239c40542a5
782fdd6c4100100ab4a8c665b14dcc156afec5bb360b22da5cd1dcc79250f5eabffb8
bd6c04ca5d7c6dfc7d0a9eef916cf4adf9fcdbc205af61c8887d866edb30c11e12f76
1ae7c1e4a70247d53ad937a1450c250ef3da04b5fce700b3bb99935595e51d1ba409d
79cdca59bbc25494d8d18c4e12a811eff0c5c54879532212cb88b3697adca2819cc2a
8e302f8fe975c44c008b7f4cb771e8a7f50c2e40fede3511215f67186d3a1a81bc558
d1f26f3fe9eaf1dab8c35c01c8717c3d7e6c7dddf1dba2698c62ef8b873666892f0f9
953ce09dc82de433aebe35ba751b79a99d0ab3b30833f0bb860dbef9fb75611c3038f
f0c127f3f9537d02063bf1f88e3b8574f4b200560d869c9657c6183c98903f489267f
e751361f2c941c70d1dc1dbc292f26494053843e2eb58d4bcc4437ab340bf8cbc14a6
e9dd97da5e03d896d1b2938b6e81f80aa050301ff9a97a3a4733b144d38330209bcea
5a6401eb4e08e0697ac4dcb8369e20d76d32c34b619c424d643dc47bd680c0ef66540
4643d2961ad051a7920c318ecd948f0000fa8a6c7b91bb526b0ca431ee15514b2b50c
43930080d057bd7cc034c5f8863f108f8b4f3170cba219046e738c2cf69ec19fa6734
22dc64620edac062850ea065bc3f1df516e0139ac717476083ab554
KE3: 0c98b820b75731a5954f142b7a51a3e13f40680399810a3083ab76eaeb2edb99
ed80897172d5088108a7ab63b9e43ceb66dd98abf931f42ecad9e52289005770
export_key: f06da17e8add6495fe9b8adb02b4645b36a481a43f35bf13823597d2b
15b6e26076aa4cbb42b2855b6980454352606102e443e11b2ab9c09c60be46f23dbc6
0e
session_key: 04015bef78ebbd7e12923667f6d9f370a578a246b2105d30ded1b2c4
5c703dee0ae50f4999f245218df8c63bb99c425ab0cd30bd727ba1722ce87a1443b68
e4b
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
oprf_seed: 84411332484702aa69c9c320f44dcc27b93a9d38a3c7c434f70d72d7d8
8863553557d5d3069dbeeae93d9177233de62d79264505ddbdd5dce2795d5848fee98
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d5b12ab467195081a2ea6d165387aa2be6331175dce3f965bef1d
18639d69297
masking_nonce: 6362c04e4dfcd5c75e19cdeac7c403372a0df4287c669ae61adf52
25a5aab097
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
server_nonce: 9a4754c52f894b64902d7986b11ab724b54e9950cfc1e32eaa5b887
6b579a20b
client_nonce: 604ca74ffa710cd9b3aec0e51e984b8436cc42b820cec1366c74d58
1a795f36b
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
oprf_key: 01c610b16a5c8eadee0e49f9769dbcdf9cd61d4a36487250eb68cc99ce3
89fade23915b22757c69a72fe49848ff3a87cad9009db8133195f113cbf94027976c3
8990
~~~

### Intermediate Values

~~~
client_public_key: 0301347c5fb96ce61b57ab45d42005522f77483664bd260ec7
f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a8290
cee86e55fe23462
auth_key: a29ece48a9b8497170bbf34b43b86ab76a584692469c1181b73f8021381
21692737f507bb9611bd394fb4470d65186e5cbba14d3a15c188f4cfb25e0daf75606
random_pwd: d641794cb4645874f653e19c2bdbc99f53a006d3ded7ab069db8c1dd0
70bf5977b01d5720986526725a2a5cc422616991d83a16f1e76ae85c6012e43a8b667
7c
envelope: d5b12ab467195081a2ea6d165387aa2be6331175dce3f965bef1d18639d
69297392fd8a4d16ab95e5272f53592fcd9337dc17b929247897eab28b47599611ead
4088e54b2e3715d3dd71fcdb5e4d5f6bccc146b85fb1354b8df61d838d4eb4cabc4eb
35551da51a261297be567105e70890d7214c86ae93bcd8fb8c5a6faec51e91c94b5d3
be834e0ba48b2f3fc7f775d0899306e8352e380346e99489dd932ed5ce
handshake_secret: 1f5ac5d8cc3fc339c39a92fe68c0bd66c83cf5193c8382c54c3
5bbcfe6038288c5d24a5bba4d611120d6218b0ef5a66ee2d7edb699d6b463a0d0cf9d
4b366206
handshake_encrypt_key: 654069e6c34caff560cbabd9b1870d092b6d90e52dd99e
c12bd18458b34940f3191ba03f07176b1d6a33871988f72c5838fbfcd5dd14af4a4f5
f12138ea8f44b
server_mac_key: 3f24d277f27ee4f1d830d2414cf724a65f34f71349706fc046aaa
e68a9e3cbdd781270f26046faefff1e66864425dfe8d5a195e7b65fb5293f54ccc433
0acdea
client_mac_key: b85a6f60cbadfe55f49a3aa9303678a33c09dc24e769402797aa2
d38533237cfc1326d299502c4798c077196ca1ca2b3628597771d0030a3b61da92025
ab0064
~~~

### Output Values

~~~
registration_request: 0200572541736c54fb88d0f50d1080d98cc390cec131e56
c5e3d038122c6655d23defe37f0946f3d3b5dcf73545a6df6277e20f9b377591bd443
034fdf53d008028969
registration_response: 0200915e1e53ae51b3f024209875a18398b4f0b0cb210d
d932a8356c8dc9b90bfde1c666a33f3838efae431b6bc9dc99e63fa0df03eb6712aa9
8c265b9ef6e30fe410b0200e85b446310593c25258991eeb8da130df718df2efeee93
29b6d6c7a3906749464ffb90f8e43122192f8e77b9f04f708aa5f9ecca9cbeab701f4
9929d82395d9928
registration_upload: 0301347c5fb96ce61b57ab45d42005522f77483664bd260e
c7f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a82
90cee86e55fe23462aa223499d1ff75699e31bd217e94ae47a7e32b1e2be81bbb6680
4b66b7465281409599a7dae9d2c934422c4eabf199e7f26f5d7afc051c3eb50746801
dc611f2d5b12ab467195081a2ea6d165387aa2be6331175dce3f965bef1d18639d692
97392fd8a4d16ab95e5272f53592fcd9337dc17b929247897eab28b47599611ead408
8e54b2e3715d3dd71fcdb5e4d5f6bccc146b85fb1354b8df61d838d4eb4cabc4eb355
51da51a261297be567105e70890d7214c86ae93bcd8fb8c5a6faec51e91c94b5d3be8
34e0ba48b2f3fc7f775d0899306e8352e380346e99489dd932ed5ce
KE1: 0201147f07392ddb5ab846130ce65a4c16d1eb26735fec1de7716b2c8bc935ad
1c65ebc30a6449adb8504b41fe61b9634a1ac3e429e03db700e6e6f852469e8e83bec
4604ca74ffa710cd9b3aec0e51e984b8436cc42b820cec1366c74d581a795f36b0009
68656c6c6f20626f6203001f619d901664fc0a4916b616bf340eafded4dec3c9af08a
7d89f9442bf41048a8824f22d5ce906558f99250ba96a112c5ccf2ff02e062cf9158d
fbd1abc4a48e92
KE2: 0301655ecfbc18c80651da6ab7edb4d09adcb0d903fdb347bddd81c71171ddfe
52d6f53ab6d0ae2580e388a6df3a37792f9bfab96d86589c012dc60836c48f7de9aac
f6362c04e4dfcd5c75e19cdeac7c403372a0df4287c669ae61adf5225a5aab0974909
2ad5c97dd9d8958e0252e990f61edb22aefe44470337b17ea5b369ae439ddc1192b49
e7c742bf3afe90d6a828dc69de4c7e2bc84a00ee61242289acb0668384179275e9662
67a07099ef8d12456a19383e33df19edb0501709da89e279c8d851498d828a63da8d7
4533e5ab8c8fabec4a7754cad9b9797c6b2fcc03221f960750c071a188ec52cdbad07
966e19a725f823457010c6f9521258ace060df3707159a6f3608408d5411179e6f1af
9f2b539cba3fcbf4cabbdbd80974517a7e90aab920be44a504445796cc3596050b3d8
bffdc768faded5b7f590a917a0bd1724460e43659a4754c52f894b64902d7986b11ab
724b54e9950cfc1e32eaa5b8876b579a20b0300ffcefd89e8ee736b4e6149934a1040
b8691ba4bc58b160d8c526e73cb99d7c45ce09264ae268a5afd07c1a3db59c5feb920
3ecffc694a41b1138deb9a11d6fecbd000fa01cc4551b4577c2dd057a2484660eaada
8c5d5a224e8b928216f1ceed63db2d7bdd07e533d537edeb2fc0ab299fad0e13fd53a
6fe67255eb5de018e328aa6fe37145c5ebd3139588c0fbcab2e04ed
KE3: 9d643ac8f969825da9d2597f126311522fe33850742d4e85dca8a33118630da1
fd4734e4c6758d1dc4aebd61003e2e4043cc34aa35bc35bf392590f6c8e15cdd
export_key: 0088d5baf08f2225496791f8a731ce83eefa9f0efbb0efe48dcc7bf44
8bb904684ec6ba000dea65e613c58a0191288bdb598fb11249e520f73bab52c8127e0
3e
session_key: 3b8c1e25957d8e37f0278eb3364446d616ace8c276bf9b5eb9eb4ae9
e9326d43f00f783373a1d719c273474ec366d45765f388d08e852069d3f74871414c2
48f
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
oprf_seed: 8384002449d252e4dd7832e6e4efe82334478aa3a97904e315b7302d2f
d9a0bf63427e365d1fe599dd4a44efce1d3de0328ac94252eab1db2fda41d820a42c6
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: fd20d5135c809b0558ff11b467257606ed679b99f6bf204216a49
ec76235a331
masking_nonce: 7ae0ef21dd19325af7e209a1481dc2808b36cd4bdfa19f5f335220
3a124f6ce2
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
server_nonce: 30a88cfdab0ed9f040c0e1238b43e060ed62e3654c646d3edd7b17f
6d0b67d5c
client_nonce: 9506703820c6bc61c21715f2e56c46918026954dca069601704470e
9f100fa80
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
oprf_key: 00fb863db3e1c255c6b6995cc3de8c4e0beca0006c0503d746fb0cd50c9
f8772400f92084fabb94f4a26d73f42ff394ef0dc09547108b1d96d3a65755d94ceb7
c066
~~~

### Intermediate Values

~~~
client_public_key: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4ca
15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1e7
ee4c024556f0808
auth_key: cc68f84260b88828611055bbef9f82aa99fde8b9362da45efcebe5806e9
e0e60222e2d436e3e382909d5b451aa588395bcb03ffa54e81a4e8fa8c3264c947f21
random_pwd: c74bb6b097e9b248ef2ee47084d2b9b5a46dabd6bcb82b6d9039c6c3e
4a46446aff6be3028d303c467a3af40f9844648024531847320c38c90449a3808dfb9
51
envelope: fd20d5135c809b0558ff11b467257606ed679b99f6bf204216a49ec7623
5a3317b5c7a87c8b72ea4ef321c63eba2f4f137116d164f8c27fab6e760ff7e16b1a8
060c46ffb9edbd2c43c16af09e3c277effd76ce6b84956fe42e567b498fc545aef4a7
6b05aa9032715162e745638cc7d36450f6a54bec80927ca08241b13f6375f0918b985
c8cdbfa2ddf4ed981c59896142d26a3f0663d737814d4ee50c8300e457
handshake_secret: 2624469390fb2fb9908badd335235d31d46d184c4c93b6bff04
84aaad57f6480fd47c3f7ad8c4e9c8ce487526aad189671f8427d75cff45105773c9b
3edd7146
handshake_encrypt_key: 82fc917a4788ba5b1bb11b4c30a305a798267e49c5b224
ed121348ed599cd0c98613feab65999428be84de8b1278c70cc06f81c6203b37ffa14
c2e324a4a67ed
server_mac_key: 55f36de4c206684216aa9655bb80b45af504df8993a4566e39ca9
496e5671bf07f1c32cc3e63fb83f648403a0adcf39b23435e63f2dd2f60bde7633bc5
c6d9ad
client_mac_key: 135f308d7dfdc374e573210870a13c6648b6ee216aef7c45ea31e
139eec569f42f234b0050191fc0c0ff565707b4b391253e84af1711debecf16af38e6
60b356
~~~

### Output Values

~~~
registration_request: 02000c53a2fa3c1dd1ed747b297b82020f316ee5b38d5ad
d8bfa68d9c6eb9b22ac651badd5d5751e7371cae832503f66442cdc156414f4a5ba0c
2db08b33530cde8dec
registration_response: 03009c0401fdf17cba7255989ef68dd2456d85d4765bdf
92f3980717e07f29c9d705cce00322c66e4b62c8d6b1991ce22a38b04f3dcfc0c69f5
4ebdc83b7160ac971ba0201a6573b69f46bf93cb3f18e2510c753f689097b7b96059c
3ca8f8e45c66a03b694fd8618c9a52c4104ca42186438849e73613cb25fbd4ecc16c5
a65f95345686984
registration_upload: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4
ca15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1
e7ee4c024556f08087ba6fe32700117b31930ce63ea4eab4e8f5b964e9568c4f879a7
cdd671ffff439b23fa0c9506627e993bb4c45a439652ec9f878102d08129176190a56
074107dfd20d5135c809b0558ff11b467257606ed679b99f6bf204216a49ec76235a3
317b5c7a87c8b72ea4ef321c63eba2f4f137116d164f8c27fab6e760ff7e16b1a8060
c46ffb9edbd2c43c16af09e3c277effd76ce6b84956fe42e567b498fc545aef4a76b0
5aa9032715162e745638cc7d36450f6a54bec80927ca08241b13f6375f0918b985c8c
dbfa2ddf4ed981c59896142d26a3f0663d737814d4ee50c8300e457
KE1: 03014f2799259882d01af61644db264602a3486a32f6b510aecb336456ce58af
6cdf6f5630ab4e3e7081f1e99b1688558f0a1bf15da34b7c0252f1036d916928a0f33
29506703820c6bc61c21715f2e56c46918026954dca069601704470e9f100fa800009
68656c6c6f20626f620201e2f40c1d877219e9512862469e31da268ab014fdce9cb3f
9ed6b27fc01fe6d9b1ec37c6cee76131139ccc3eee0a35438250e9ecaff6cf223ad9f
a469dfaaa0f0a5
KE2: 0300eac8a73969edbcdd3a190212c744043fa588b72cd7212311a246778bfa95
2f9489e7f56fbaa7b07b77427f9c81d5e0214f60e349bf024664d9b550f8a582bf1e3
07ae0ef21dd19325af7e209a1481dc2808b36cd4bdfa19f5f3352203a124f6ce2d043
1f52ccaad31082a9abf131159a276f664835c4a3a29100485b903d5bb2a434e2bba11
638bc6515ef6d98170f5556259a5df9c04614fec6ec650c1050e35a6fd7f7fbbedf78
e0e1feaf0d9d3ef410dd49d5a0cd1d8da2f8f5b066f0772a414b6b789bf3c08fe607d
cd5fbe0c34457ceebbd72ddb5652d2a71ef2423abb467f0ac7e95a2d1ee62d28a11ae
c700d2ff4ceb9d61ef055cec00933a6087408f3e47f9953af86f15e126dde95833086
5ff4a8c2689096bacaa04e788342e11c08d5013cfe7508bbf6317cfa6925107dcc8a9
0f45d410ea50afe0077b46b9f176d6d9bcb0688230a88cfdab0ed9f040c0e1238b43e
060ed62e3654c646d3edd7b17f6d0b67d5c030029562d54d53c7c51651334989bcc95
b45a1a07484448ef72bab708b55322b49a43736afc60bf85fc05d3c1d8b60a0b55a83
e37befa115e9625e00f35c1eeae27ba000f41fcc16c2662df2f09b90a679477b91220
671986d4c6b4500e53d203169f9afc166d433c47c2ccf098c08c09520bb3003a07219
aaa32dc24edd4d5bfc8a503ee9b2096ba92ff96baa8948d56e52ecc
KE3: 86932c7fac1a3eaa1f2a8c20cc9cc91a696726326072f20eaccc3eaaca73f703
86909065273bdb7500d05c946a89a96c2b30ad4d57772a89130c78900d7601df
export_key: 05f56306b1e2f502d118b44aff7060c4029568e350a1096e4810ab4df
db5002df17f2ca6b6e54fb63f93b82c66f59aa29495c4126f7be09dbf2581a961105f
01
session_key: 837b93efc41e0f99652ef77d8f4320b9f9f0bfdeb8e7c88ebdfb5111
84c7996074fc796028731f51df177d515e6d72a3d7a45a5cad40f10d64fd9192fec71
cf3
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
oprf_seed: cdc0f9e353ace7644c3c128474bcb44a6b732b752cf6ecab2e32a52d38
dc16a1c30ae33be02caca1e7d002a874554b936eba95e85f67cfeff88f572cd9e721f
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: c2227e7128ca35c5cbd824973dd98682c82adf3b5cb6186accd3b
4ef82057bdc
masking_nonce: 82e8415d3c7bc52cca1d8e0cbebf5008d044b1116ce97121ac1f91
5c1d8de2f4
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
server_nonce: f85a8d6763d46d154b4aa92df27790561ec8ecbdab01d5d6491ffe1
bbe8fc2ae
client_nonce: 464a515ff43db28c92cbc9320af5f8fb4657a24214f5c47bfaf619c
1216e1b35
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
oprf_key: 007f0bc24d9da2e9516b4528d4626d63f95bc6696911478ce3968e668f3
d11426b22125078da2d446391f1818e4f80304d2d5098626328c3928ad1248de71676
81d7
~~~

### Intermediate Values

~~~
client_public_key: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fef6
f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea03
e0379fb9127abe5
auth_key: d05cac3106708550dc7de37a7184dce3717690e99a7abbc2e61afd8e468
1f16f2c43720a96bf6bd3209e4fa102c3f05119ca33c95fb321e1f091499d96dfb002
random_pwd: d585391de87a3eaae197b9a329dd1ee975d641a5f3384e46c108e9244
d55da4cb06c5418b7d48e6062f296e54cfea8a7d7d81616a4ac1df67c58f45cdaab86
e1
envelope: c2227e7128ca35c5cbd824973dd98682c82adf3b5cb6186accd3b4ef820
57bdce8644d89e5df82b3b18af3e39ea2b066617c4443da24aeec4e9c4c94242f5a97
a251aec892b7a7f4b01d1ed894750bc9b24698a19d682962a6d468f45684e165c3d4f
d99cc939c235ba28c8dad6340eb4c107977dda25b021b9e0b3c1422c515814ea15a25
df66130d1813f5c43d10251d4a033ecb24783d2abe8d43b42d16cef5a1
handshake_secret: e7c489d90f78b8d673f3300328a0bf1b9a262e915a54dcae6b5
b12112934477baef559d87023525efe3f5bf58f08229f3ac8d12c1d6364a451f39e8a
b5871128
handshake_encrypt_key: 06b68886509f297dbbe7cb86f3ea171c78f67259455d9f
f15cc0e7633a52f7b36a94f824af8b4ba197a5c862a839bf06cf47b91046a364b7faf
1fc0200b63bdc
server_mac_key: ccb7747d9ff361ec3092be6b6b11ff435fac0f9d4c675909eb148
0e2b4874dd461b60653dd7fa7ca83bb7f2664ab1f2e160f36840b5caa51d261dc2d72
4e2d3e
client_mac_key: a69f5483d8c594922690ba1f65debb06943f629a7d8b86779b49b
d7e21bb85af0bf818407c7f3cba1520cd628a4ab9ea66461b028e4b7eebd748840eb7
1f616e
~~~

### Output Values

~~~
registration_request: 0201d22759697d1d91f6b1812d14acfee093886e889d913
cdffc78de009924d3d80a7aa9384149f163fd706498375c34402df2ccd8c1283cd250
477ce032c9e7c78ef8
registration_response: 0200a8df02968162486ba7cfa61273e347d4f4115141fc
b359262a87ab8a33fd154eff32c98822bd30240e62e625dff1e8743b40be3f25478e3
a6f1ef24db4bd661ef50200f944f464cfcbdfe94b720c0a59487456cca17580dd1982
4532d540642aa4017edec0b9308bf4f4fc00611115a145c1374680847e4815f6c8dd7
febdecef64998dc
registration_upload: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fe
f6f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea
03e0379fb9127abe5000361ab1c0b120f01c17e0b5e49dd94e95db8ac99b702806996
ed0814985006fd283c5be1bda6ad7cce6056c4c8bfb81f15adc282ea174f6df588018
213b6bbc2227e7128ca35c5cbd824973dd98682c82adf3b5cb6186accd3b4ef82057b
dce8644d89e5df82b3b18af3e39ea2b066617c4443da24aeec4e9c4c94242f5a97a25
1aec892b7a7f4b01d1ed894750bc9b24698a19d682962a6d468f45684e165c3d4fd99
cc939c235ba28c8dad6340eb4c107977dda25b021b9e0b3c1422c515814ea15a25df6
6130d1813f5c43d10251d4a033ecb24783d2abe8d43b42d16cef5a1
KE1: 02002c6e65b998d160fbbde62484f39c2678bda170db547005889379b570e83e
4f6aa45200a183dc5cbf014bc7f94f28064bae53132dfb3a0736bf7b806b1091ce541
8464a515ff43db28c92cbc9320af5f8fb4657a24214f5c47bfaf619c1216e1b350009
68656c6c6f20626f620300c566f59e65c950d86356e925ce1f87b3d4a7a9b2e556ece
f17041679c76f8afd8f7b1e9fb82549886fdedf29e4e86564475b0c2c200a9c7a4e08
9e846932e07d36
KE2: 03015f370f7e2f2c5142331bb3fdde89034c8554922417f50f91d95d43ab0f03
cbb84930401f137693dbb56affda12f619f87dc4cabb75d247b1539acec6e1611f2c4
f82e8415d3c7bc52cca1d8e0cbebf5008d044b1116ce97121ac1f915c1d8de2f48f2a
a6332efae03e73422ba0a645a3d49381287b33c8953009fea655b1a4307fce06df39f
87ec8f85f0b314a1f21fe97886d97f361c3939771ce1a50316d8c2eb223bf28d83152
aed4e494b852490b1b3354fda10e3b6f7f39cccbd4f3ff6783329592aa7e3b5826367
d88132bb479fc93309a5371539c07bb92ce4a437631ca985880cbf0506d5a1c9ce597
2cbbee86d9ce89c0382c323c1be1dd78863aef05b41e1efb8d589218eb59a0be7d7c9
58bb10688f7a20cf89e8b53f1d685f294b3bd71827780bba5b93fcef640ecf4f81f03
5d7a1ea8f629ff1cc4c3a684a826837aa78f61b9f85a8d6763d46d154b4aa92df2779
0561ec8ecbdab01d5d6491ffe1bbe8fc2ae0300ed0fdc747de2ff4797c4b18da821ae
9ec83376c51d00a51b2d1701e5689e8dd720cca6fdd1a548b5b3ad34015006ce4f754
8be73295e07f15f8b0c60331cb65160000f260f9aaf8ffc49b51664ddb922d64ffebd
f1119b05fb73c170ef7744d89271ba6e73ccbd349b7a2852295230d968f54c5443a39
b4470e24e41563e2bd414801bd300ad92e959b45ef6346723338060
KE3: 37438c997234b3ef26575d5406f93d1c80a2eaf8d7c5ea126c697d14b3e1edc9
bb8f78d01bd6d841cc1a2158548a80fe5672b7a4589ca52c51b37414bf449d9a
export_key: c303f90b5c903865ae931f9e218dedc1e2a0cee1eeb2c6cef37d0d3f6
4224c0c477cd58362ecbdc03f66e9e26c1a476a53dddd49b83a49f4037c3f26d1da40
00
session_key: a403b1f4eca991eaaddbd92eab667233edac07cd7a7ff74f87be1a3e
5bf72bf258df7870a38ba20928017147afcb0571b37f579384d9468e06a2742349218
3e8
~~~
