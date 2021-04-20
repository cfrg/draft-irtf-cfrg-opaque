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

These two options are defined as the `Internal` and `External` modes.  See {{envelope-modes}} for their 
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
 EnvelopeMode mode;
 opaque nonce[Nn];
 InnerEnvelope inner_env;
 opaque auth_tag[Nm];
} Envelope;
~~~

mode : The `EnvelopeMode` used for the `Envelope`.

nonce : A unique nonce of length `Nn` used to protect this Envelope.

auth_tag : Authentication tag protecting the contents of the envelope, covering `EnvelopeMode`, envelope nonce, 
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
7. auth_tag = MAC(auth_key, concat(mode, envelope_nonce, inner_env, cleartext_creds))
8. Create Envelope envelope with (mode, envelope_nonce, inner_env, auth_tag)
9. Output (envelope, client_public_key, masking_key, export_key)
~~~

Clients recover their `Envelope` during authentication with the `RecoverEnvelope` function defined below.

~~~  
RecoverEnvelope(random_pwd, server_public_key, creds, envelope)

Parameter:
- mode, the EnvelopeMode mode

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
5. expected_tag = MAC(auth_key, concat(mode, envelope_nonce, inner_env, cleartext_creds))
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

The implementation of this interface for both `internal` and `external` modes is in {{internal-mode}} 
and {{external-mode}}, respectively.

### Internal mode {#internal-mode}

In this mode, the client's private and public keys are deterministically derived from the OPRF output. 

With the internal key mode the `EnvelopeMode` value MUST be `internal` and the `InnerEnvelope` is empty, 
and the size `Ne` of the serialized `Envelope` is 1 + Nn + Nm.

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
`Envelope` is 1 + Nn + Nm + Nsk.

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
or to additionally include `client_public_key`. See {#envelope-creation-recovery} for more details.

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
  `base` or `custom_identifier`.
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

- OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512, Scrypt(32768,8,1), ristretto255
- OPRF(P-256, SHA-256), HKDF-SHA-256, HMAC-SHA-256, SHA-256, Scrypt(32768,8,1), P-256

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

## Preventing Client Enumeration

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
oprf_seed: e24451d03e9f7abd5dfe14d9b9d5931b62bf62f22615343392cfe0647c
310bcd2167081b61a2a11f262d4455a247108d3550fb42cc062ff336c0e35ccc7ec55
e
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 43f99d491cbfdd2769c0b45eada13bbfb65bf3dbc5604fc1ebe34
e531289e584
masking_nonce: ea146a840e0638f403aa99ba57958f19c0a98612f91095d29aa117
3f9b5ba05b
client_public_key: 5ca3acb9d495dd42964cd4d859703fb030496cc5bbdb560177
84f2d2bb5dc66c
server_private_key: 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a
9706137886dce08
server_public_key: 4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b
78624cbd10b371
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 641679db1d2442f121764cf8278e7f769a322ffe2fe0ff6da577a42
ad0ce813c
client_nonce: ecf560c091017b79812bb4c7cc926b2bdc3120554ed2b18a26633cf
9ac2aa6ea
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
oprf_key: d7f7166b1419d875d4bb221cf3de9ebd6dfc00358dee58ae101336e227a
e1800
~~~

### Intermediate Values

~~~
auth_key: 15c4d11aa7470dde9609a6a802e4de3f99b5d77adcaf55705799fc05b3c
0ad89de0ff5fdc80b2148ec6659dc8d678c09e0c351e4f1a8aefd32c48058842950c0
random_pwd: 0f59366aa0ae2130442c2ffbab1e8a77973d1a93972fd1875377be484
4944099e59211daf083ff514c06781df3da8b8e6ace07a9e16e248cbdd1585743501c
5d
envelope: 0143f99d491cbfdd2769c0b45eada13bbfb65bf3dbc5604fc1ebe34e531
289e584ef530e2a0375b6ce941faba91f268c23fe3c662de71a7e13f0229d4d8af057
e262721f5b5963ac07770328af61a9233d4b0a78dcde4db76690518c4bf373b768
handshake_secret: 5539b3c2634d846350144d72ff972e82446fe725a5b078baf7b
5e354a143521b4235ac4465198313f0c3a0a6650b5e85425acf5166a4bddbbaeac6c3
c1e6bc37
handshake_encrypt_key: 27849646f876961ab6fd226d94075c3fcfb2d61b5d39c5
b96e44d967e594b8fb9e3a52b1d53c6e2aa3a0173df1746018faab4118b91b300cc1c
734dc93c06c91
server_mac_key: d60832296e1dd68e25a39609dead273519d222c7573de96c0ca39
27ce195c660e3c9605abbbbd71835cd4f53007c8509e8adcb55d6d9072001729e6649
a7e6a9
client_mac_key: 8dc838c15cf9f14f97c86b9f6f773372835be01460110e30783f9
e4c48e0eec98d9e8a20aa614d869070f7615e976705d87c977f8819c0daf6c17af661
7e10c9
~~~

### Output Values

~~~
registration_request: 24bbcabb15452642f709cb8567eff38f4cda6044aca3356
87a62b8453d849c18
registration_response: e02ec016440c7680f8091070a06606aecee8999d69b5a4
0a7e26950744bd98044c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b7
8624cbd10b371
registration_upload: 5ca3acb9d495dd42964cd4d859703fb030496cc5bbdb5601
7784f2d2bb5dc66cbedace8ced1389123c3ac72d84c9db4a9fff33f9347df642257ba
3181b1cf4f46c7da07c4d27034650fc834d5b53c1e8e1b948d61f59d896eefed5f483
bd38340143f99d491cbfdd2769c0b45eada13bbfb65bf3dbc5604fc1ebe34e531289e
584ef530e2a0375b6ce941faba91f268c23fe3c662de71a7e13f0229d4d8af057e262
721f5b5963ac07770328af61a9233d4b0a78dcde4db76690518c4bf373b768
KE1: 0e8eeeb2ca0dbf5f690cfe0b76783d7667245f399b874a989f168fdd3e572663
ecf560c091017b79812bb4c7cc926b2bdc3120554ed2b18a26633cf9ac2aa6ea00096
8656c6c6f20626f624c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
KE2: bec1e39b99c1c8b68e9e90e8c4e5d62cc0ec3e7701b14e5a6bb6e78d3ee19779
ea146a840e0638f403aa99ba57958f19c0a98612f91095d29aa1173f9b5ba05b34304
031191e292d037a9e467f7d9aff2f251bddc34ddd67a4b1e10155cf3343c14870e3ac
20d7373959c806d09fed79828d8941c1a1e43f01a5cf3ddde900058508600b03b4d54
590778bb2106b6cf308dfd9de8739e65fffd712d8268c4b3f2d2e1d960eef50a82e77
cf7c14c7ad1de818d70a6f95562bcd708ba1811d9c5971641679db1d2442f121764cf
8278e7f769a322ffe2fe0ff6da577a42ad0ce813cca372e52516d51c19763ad5eb1a5
b60dafb68c264dcf6bcc692f667a71c5a617000fd14b2c0eb8474c2a3a5e8f7184dc2
93dc1143b26fa8a0b95c0885ba1f1f49eaf9f6a3bb7d6fe04b64cbe1b613ba4d1da71
e87cfd3cbb41d287bfcd057c0ef7397a5c75e4e5d7221254bc583a71c321
KE3: b9a4b3c39e889a0027fc37555b06b63adad81d56bc4a53a49c04ac85bd73aea0
1b9c1d7231b2c636d6ba172981f33d78666b98701e5a187ef09383c6da4255af
export_key: 54f26a004b5db48d5215f6de962c8b42a36d1b7f010f25536df11a542
a5d72bd859257fb0bd21d1375df2e9be304b9d6e3d61f3d8227b6edc7b195f134782e
65
session_key: 5553225e73308ed77945b992c46780fdb797e3ad8d7f9157925b78a7
80cf892bfcccff19ff4c0bbfefac8a126f47dbc90e798aae2c7d49cd9f9c39a14be40
660
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
oprf_seed: 4b9437176a881641caab24a59a5ba05aeef5490bfe4c0f84cfa3c62f74
f9d66a8c6bec0c924cd3b59e600e4771f82a403aa8b43eda9eecf0261d3b0d98fc77b
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: bee180d76b78b62c16b2d920b150fb89c577d7daa0b83da16dcb2
4cddfa097a2
masking_nonce: 35a105c07342d25bed739e0b3b04dac1ba9a1eb4638d29f0f30e34
40dee1070e
client_public_key: e29d0cc083eb8106b1454d0a65333c4d268a81711362eb90c8
1c5f9de5a82969
server_private_key: de2e98f422bf7b99be19f7da7cac62f1599d35a225ec63401
49a0aaff3102003
server_public_key: a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e7874
92b98265a5e651
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 621c3779905a3c38de14409bf862023bb8c539a176ede4a7174dd98
a2eb02184
client_nonce: 8ed942dff13d250406bb8c7db15816080a70d02a317ca634ac0aff3
73f7566e2
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
oprf_key: c6e116fc5552ffcfae1d74be6dfd124e4b6821a00b65db684c6360f87e4
c6c0e
~~~

### Intermediate Values

~~~
auth_key: 20b8b4e952d1df2f223c5828853e5d791b2d7b1c905f8781ba60f032a04
08f035135e9623a4ed1c3724a2d368e422b705d6192880f0b533a88dde3ba382a887c
random_pwd: b4a2fd62c66f5cf0ec87dd1c3c46d3349ee75e63727534549f74d4628
58b1d28c69a5fde685401e42272443e80d0d83e36690e9c3919ab2bbe5e236eddca43
22
envelope: 01bee180d76b78b62c16b2d920b150fb89c577d7daa0b83da16dcb24cdd
fa097a21b07d1bbc21d453db8a28e87654b65f9af4e9ecb2ea76b822c9082e3322efa
49caf6e237f28851ab18ca148aed56158fb5707ac05eec702c95e34da1056efe38
handshake_secret: ca7abd40ca9741b2738296e6a47ce6148a94f9b150d1d4895dc
c864155bbe9fdb88819feacdf8db2bac714e4aa97959cafcd9babfae26e4f3e2d0de3
d1fb8c43
handshake_encrypt_key: 2cad137564dc28783a198bcda75955e8560167cd3c38c1
8849e1dc7ed2563912b1a740cff802f5e40ca12931f9bca62fefac6f42bb982f82174
f060fd4b021d2
server_mac_key: c70aa6e2b1d11ee554221cecb9b842733b896fa5b00929cc36e78
75f9a45e12e3fba281f64063786bf89cb7f55f7ed364dd0b3b4128faa62eef3f62ebe
6de8e6
client_mac_key: 9718d1a55a9c8b6fb05e187521fc91bcfd485557b9ea91c5ff0a5
6920d2550f0c9e7341986e5ed4c9c6a450d873bf7f90434d7f038070ddea7353be245
a5ed76
~~~

### Output Values

~~~
registration_request: fa8c0e0144f7b9cd1de1bfcf78104f94d63c0f90398c9df
ceee06ab5593ec500
registration_response: 268876be55c7e21c1b60f43818f8f3e20a65f71c3b92b0
bb0ba05604bcdb2648a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e78749
2b98265a5e651
registration_upload: e29d0cc083eb8106b1454d0a65333c4d268a81711362eb90
c81c5f9de5a82969291ab47a08a5001a19aef2c23a4fcc37e8f8ce0e5376488690d68
150a5247f7876bbad9e49bb529d9b1e88fb36a4873401de08b091e95b6dfe11f4a81c
8e461c01bee180d76b78b62c16b2d920b150fb89c577d7daa0b83da16dcb24cddfa09
7a21b07d1bbc21d453db8a28e87654b65f9af4e9ecb2ea76b822c9082e3322efa49ca
f6e237f28851ab18ca148aed56158fb5707ac05eec702c95e34da1056efe38
KE1: dedef709c5faf24970b4fa77480a2c640dc8c6b7a53ae78a2dbf3fc75134a250
8ed942dff13d250406bb8c7db15816080a70d02a317ca634ac0aff373f7566e200096
8656c6c6f20626f62746987c9ba92c3636d92fa7afc0379009ed54a7fb2db3cf7e4c4
07d4ed2c6e35
KE2: 22afd07bacb230c1e64e304c53e49a09e93ae2b2942a44258c7bd1755c620e7c
35a105c07342d25bed739e0b3b04dac1ba9a1eb4638d29f0f30e3440dee1070ec3536
24cbf97b1d867317514f09b7395023a877a11b1a0f85e0956c6d99d3b8afee71f8961
04f384cd692a9cf1cf60fcba2ae561234423c7a00eb78128c9bcc502c1a95c7c7769e
ba4fbd6ead8e59280a1a117d72c9d0ab2ccead13089408501d6feeb754584c45f9da6
74d93a4302f6bdfba6307e8783ebbf4d214f598b1c5b1b621c3779905a3c38de14409
bf862023bb8c539a176ede4a7174dd98a2eb0218480d9b21c255bf04113a6d339fff5
79c68475e516c0c98f625a90f6532a310f13000f038fd93a44394eb8e52fc72a0934e
1bc370e8824bc989664109c3b49d13ef38c10742527d199dc34ad70a0c46e6caf21c3
7a530ffcce5e814dc93c7afc5b07d188167c94e37be4adacfd95c68a515e
KE3: 0d423219134624d53bb8842b412698f006fa0220bc032d062bc686229154084f
d38a4a7307086e4c193d033f17ccc5e9f44f1387b3c59ed436ea50e745baf62b
export_key: 971eeec9e0d45edb423396a250be930fcfa31176780812ab1d5afc9b6
317ca75c378525538d2245e9b6c6cc71d5529539e047e3a0cd62102e1cd76e346873f
32
session_key: 06aec902b8c16a1635413588acaed04d645e085ba445ca8bcd51b918
1c1301b5ca129360ac5acae6d030129673232d1a41681c902e874c66391ac2ba6c151
8e0
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
oprf_seed: 7681cb29d46c89ea17deb747622aa34b6fed5ca12e0ce0b72e3694ee66
ccc785a6e98c0cc62d6d5709e000d052b354e9716cb4daa7c6a539f6631c0f2cab7ab
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 1fce68ef26732f0c9ae22c2d76f213dddc7752306bc9bb3c0ab1a
8155fc4e0af
masking_nonce: 50db5d5e784bebaf70eac840e00ac26b0182a318c84a333cceb09a
a0a6995e69
client_public_key: 1401f59efadff16ca9b9401c9397b454720b53fc400844d3d9
1ef7a967a7e513
server_private_key: be81db28eb1e147561c478a3f84cbf77037f010272fd51abc
ff08ac9537e750b
server_public_key: 5ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3
f459678b0e0d25
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 032695c969b072a7c6f63f65cb51ac99a588ccff1744c366bc84c2c
b305413b3
client_nonce: 8f0291a1603e0b8ebf45f328c31e2514586810e40012e2fa92e8fe5
471512794
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
oprf_key: 9bbcc329d5b61331c8cad70773ae2db7ef14ef158e2e6b92fa431092338
9c709
~~~

### Intermediate Values

~~~
auth_key: 92a839817fdaf84a48483418ef09e692b12f9fb4ec2379421cf443b302a
f4de95a8de323bc5d3a43bf0e96e1a64c661ad557df27876f3327810871c5aab4b504
random_pwd: 8803cec3efa5162d48657f3736ceb32283548c251c1ad6d71eaa93439
fcbf9c4038c3a1d1f1614e9543365f634aa166c735afe6735ea9af5756b582d22277d
c4
envelope: 011fce68ef26732f0c9ae22c2d76f213dddc7752306bc9bb3c0ab1a8155
fc4e0aff092bace6f26f5b365f43a50bdb789efb260be2af08ad3dd207d7baedacb2b
5b0b38e1e2255f808abee7af830fc46a4660080a8ca653fd0309c714afb74e7d9c
handshake_secret: c0f406b428d3fabcfb1a276e565da54841a213b547532ed328f
a34ec2bfe0835597df49d2e8f57095296f910e557814a6596a5e53914442457ea3207
44697d26
handshake_encrypt_key: 9aa175a8c357ea869b5d05d63f7efb0a9203632fc7592d
b5858c759210d1b86fe81216f8cf6a01fa7381e314cd14e50a1b3560c820786349208
1c81fb69be9fa
server_mac_key: c724f582001a90eeb6e667efa74f872966773b62c5f41015e9eab
fab0f9fb2148be8cfa065efade15e50a4b619d03435ee47f400df6e26af5b340d2192
8ab3f7
client_mac_key: f1e23e263474ae8aefe678a27005653610a1e6ef3983d8654b9e2
0cc7eb2cf64fd4af5638722fb9d083ac9e0165cd5a7ebfff1e1bcdc4793b64773a1cb
cb2546
~~~

### Output Values

~~~
registration_request: fa39a478c220a89929613f9e65c9a4617da96b62509c42b
39d7e3606ed2e8031
registration_response: 48780111929e5c9241ad814dfc45bb48d861a9d289987a
55d8487da9f7a528515ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3f
459678b0e0d25
registration_upload: 1401f59efadff16ca9b9401c9397b454720b53fc400844d3
d91ef7a967a7e513a90781cbd0945a00448116f1180389e3ecd1175e5ca8a898cd6e3
b707da23c84e4707b3d4f0c8ecd2f3d46e9b22cfd342307eaab9584154ff77802becc
59ebe7011fce68ef26732f0c9ae22c2d76f213dddc7752306bc9bb3c0ab1a8155fc4e
0aff092bace6f26f5b365f43a50bdb789efb260be2af08ad3dd207d7baedacb2b5b0b
38e1e2255f808abee7af830fc46a4660080a8ca653fd0309c714afb74e7d9c
KE1: 96f9f35ebc0ca71607fd2cfcd465e285eeeabdec61151b39b2b4fb735538aa0c
8f0291a1603e0b8ebf45f328c31e2514586810e40012e2fa92e8fe547151279400096
8656c6c6f20626f622e8a05799d3c524ede0482f39e047df99d9a53dc2dc30e8947eb
5da98b8c4354
KE2: 9ece2afd63419587f55d5db2e119d25064b73fd18d270f84f4c1a11b95f2c15d
50db5d5e784bebaf70eac840e00ac26b0182a318c84a333cceb09aa0a6995e69902cb
5e991bfa2a3d5f9935956afb36d2c59d379d7d7b3a0c4a270d0120c9eacda90cf9db8
0976e017f5526a8d2e5704456f091175107fd13d1e4fddf5e5eb44e1ed7962bcd983b
b473f09397370bc612518115477413290ea077a55dad1964cef509cb36b377a8a6d14
dc8f497a7362285f4acafa95a54dd59e4315a81709e411032695c969b072a7c6f63f6
5cb51ac99a588ccff1744c366bc84c2cb305413b3a6d76012999541f1ec0c014ec160
6f2bd2a517e51f731d59546951d9699e1739000f3f2e93f7c443a5524ca561635fb42
6d077acf02da2b2ccf38950490758769e1ddbce45e065c7ba585c94d237fc3a1146d7
99c85a7c8246d2ebeab7849371e1dc940aab9c02d63990a7a4edefd469b5
KE3: f427b8b1fddbd55f8ea879d00b3276fc16e8e23794541662385861f173ba0d80
7c022837155208dab61134f712efd900ad02b91f495487b6da90e93f07dcbd13
export_key: ba0c3e2dafe5098be01d65b76338baebd0858edae5824ee678f92e3d7
fc0113a9f6697152e4ece6bfcd72027c878fc80b9a5253800efd48a9287c02bf080bb
e4
session_key: ce2655338b259aa742908f5edb0d0bdacf5dec098e2ee40c994cf2c3
c1c9cee2f22ce57eb283777ae3a1314e1356e3f3040e5edbd23108d47b8101a15ad37
20c
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
oprf_seed: 8cbbed2973234561074a587fad3aabdaa5a177143178c7a75719ff8c0b
3b1b048d2756b416d817161463ad13c9ffd338239673e4f96b02c8d54cc28df65d09d
0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 9a25f60ccb67b65dfd6f56af2892b71984519f99bc92bc7a908ab
756d88f59b8
masking_nonce: f7e15b181f9b73806334dd25cf75926c9348cf4a5b51d4f2c253a8
c35fdace59
client_public_key: ac7323f1e6123380b8240070b4854cc4ecb6ae49e4e08adff1
bb38d95f6a7355
server_private_key: d49399dc3bc1022938dfb0e79db523d4e4e41f494c3898eac
652bf95f6efa108
server_public_key: fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce50
017dc037001c63
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: efc299eda6676e119527b9647cac4d4add4078aa34ce8f677837884
3b00badf6
client_nonce: e2a6ee99b73ef32f2493fe84985ad400080d9905815c8ec055df526
18b7aafd0
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
oprf_key: c238b5bf66ed55adbfcb5ed21c400e2e90bcc3a3dff953657f33b28e711
c4e0b
~~~

### Intermediate Values

~~~
auth_key: c4c799976fdcea68454f0ba1c340977b5914528530e068dec78cb1ffae3
b5d1755eb58384a2cf0f6f5956e691e5c65603729160b065c8ec69f67e0720602dddf
random_pwd: 060e7d02f2c416813263823bc8cdd5d4e79508c9b39b04d2f42eb77d5
e3b5481f1a4d450187de1e874c6182e53719a0ba69df6ad77960d6c2546fb51121d6b
6c
envelope: 019a25f60ccb67b65dfd6f56af2892b71984519f99bc92bc7a908ab756d
88f59b8610007ccdd882e71308376cf1925e2ad1399dbce008830ab2bb3e9a27114d8
d875ad6f80b89262313377db6c6703c7e7cb86362733e8a37e5bc7202f96cc295d
handshake_secret: fd1cd81ef4f7cdc74e0e8af3aaf7e940ae1251db8cf02dbb0d2
60def337d409ee4060f385f89c951102cae57e2cd5a9b7a63eb23e2678efff6f4eb5b
b6b56e1f
handshake_encrypt_key: 0c94e7ff90e3fc21c8923959184ac070b756deeb7230d5
26a3a6c5b53809cd3be9cea6968819c66f6da63042f22748bbcf025dbb377ef93fb4e
c4489aecd5f81
server_mac_key: cb3ee3321717c94d5897414a42ed8cecd14a08250dd8d33f7dd10
5e8726112a9bce034ad33fdab00558367b275c384bacd5ac5294ebefaa367d0db1dae
57e67e
client_mac_key: 913e5173ec0f0f76168b47d6383a7ecdd676fca13560472ee9813
fcac73eee333324e8138d14bbc3b3002cea6ca7548c30d2871e912a3e50aa64a4d191
0ec5eb
~~~

### Output Values

~~~
registration_request: 307ff12c023cb5ce33a04efd497252442fa899505732b4c
322b02d1e7a655f21
registration_response: 625b60bbd733a58b54ba8ba25142bf99ed691253869a8c
001e48bd6e2935aa51fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce500
17dc037001c63
registration_upload: ac7323f1e6123380b8240070b4854cc4ecb6ae49e4e08adf
f1bb38d95f6a7355f659f34a5736cfbd3a174fd8ad5116e3461f98b086f46548b3902
d35821b1dccc941786bb759fdc1edb5d7a7a436800ac872830bfbf47d8151dc59d543
9d367d019a25f60ccb67b65dfd6f56af2892b71984519f99bc92bc7a908ab756d88f5
9b8610007ccdd882e71308376cf1925e2ad1399dbce008830ab2bb3e9a27114d8d875
ad6f80b89262313377db6c6703c7e7cb86362733e8a37e5bc7202f96cc295d
KE1: e6fb9b013986abe5f6e9586a0110395a97ad695dde622d58470adb0a0cdcb37e
e2a6ee99b73ef32f2493fe84985ad400080d9905815c8ec055df52618b7aafd000096
8656c6c6f20626f6214b434e33a39d7d9fd6dbe3638925edd7a0344a312a22971754b
d075d8347342
KE2: 444e0980b165dec765ddb1a8a11157a599b0f58d81cd0e2b89da22b9e47f114d
f7e15b181f9b73806334dd25cf75926c9348cf4a5b51d4f2c253a8c35fdace59b4f44
9e4a37fa7a4b41360c73f67cc11f0af342ce001e8015fdf815829c7313c7a8d09e841
63a8bccc01c73dc7c98b99cb9217b7fd55d6dfc7efebe7f4af3985e9eea9f60192a7e
28bd81b0ea7788feb1a5a8ccba98e60882eb12051b8ddf94e43fe8c651881bd1eb392
a539dea32b65ee24c83a29065f93e5d553b22660500c1fefc299eda6676e119527b96
47cac4d4add4078aa34ce8f6778378843b00badf66a398e50c4e395ee52ef332d6c2c
0a77187e2e0b3564617eb66d2878c41e6c47000f08f29282f013115611b6ba5203742
ac8545c72435aaf3f76b2fdffba27b469e04fef2ac2fda19254a1d4fd681d27defcfb
46d76b1702e57e6bb160f10016f8b3170df9055f7b40b9e4ac9770d2f3a2
KE3: 4a62a1a2af4f05063fbdac6e53e7e37026bceb1013eb76914d08a9502300c0d3
fcf106cb162de893d50f78bee76ddc52d7f9848d9ac70e9f296758fa4b18c026
export_key: a4e99615cfe1c50f88fe350545ef8598fba2cfa4272fbeaa944cfbec1
ce8a1e4bc7f931b589279b0b805c4bd21b8f3d095cacbc2d622762c2b37441e859e73
43
session_key: 124aeb4e5509776de1cbe617bd190f726455c8bf869a77739bdc6619
875230589038ab91afdea9ac7a5a0e29503f130cea9ab2a718bf1477a8962292e5eb3
0e2
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
oprf_seed: f50de8645f69fd260a2aeec078c279782d5798b42aedda178e041b2974
1fd44fd8029542eb403df26949e22ddb2b9bb66db2c7aa36c66114a4caafb37ff9cf4
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 28a86539e86cc95e35a66855aecff09c820af977f38e7b1c0700f
5dcc813c7d7
masking_nonce: 0ceec9c4d5ada1763550cc5c5aec1895a4018fd7e7c79dd94d975c
7f0833c0c5
client_public_key: c46258daf62168b7cf5766cb14d6f596c89bf98bad1f1459ad
69a422ea7bbefbfbdad7ed2a02b4361c076b6b28aca7dbca4b17560cdd43a1
server_private_key: 4b642526ef9910289315b71f7a977f7b265e46a6aea42c40b
78bd2f1281617519f3f790c8d0f42eacce68456c259202c352f233ae2dc6506
server_public_key: 7a9e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa
3e421385fd2194903385345e6ac39e2a9911b6e624b0928051af9a6834ce57
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: f897782212d11a2c1f963b2508b528c81034ac80a05ba4026be4fdc
0d07de245
client_nonce: d07a98519ae18c35b21259c4ec254fc14736b616d4193f03b646fb5
cfca07c2d
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
oprf_key: 9f467b1cff15cc04d96c03d587c4c0856d2d1cf736355295b937e1bf752
aa94d66f6b40f5a00dd3b2bdd01cb0c2a6beca4cdc1d5ff19bc3b
~~~

### Intermediate Values

~~~
auth_key: 5fdb95ce8b43fb0dba38a2bae0c89b54d6c8ec66c2b4c0e07f6b1bf83e7
c815c64dc7e615f62d4c3d3f23892f105703378eefde4071902af3fa608b5d0071a51
random_pwd: f9d2a95d87643506b78b7a25e9765a903a0893162287dac998190ae68
4a710667daccd60e5f215080c7eba8a77d74289d602ba7abfdb607b0ecf1a66f67208
93
envelope: 0128a86539e86cc95e35a66855aecff09c820af977f38e7b1c0700f5dcc
813c7d7208922c2c08977bc81f1b0a29d2987cf7182ef87c78090f59f89931c427868
89d979d97bb58a103de634a40f435ad707e738f20340d1379cc31866d12ab12276
handshake_secret: 0de63483f95d0d03b18aa93ad676292636d8764147ee9d4f251
24bd78cab839c31e8dc1176de364327495a0eca822359515796420b563bfdcf6bae3d
aafcf2a8
handshake_encrypt_key: 5c374c4c79ad50f55d6aee2dd60eda989809f3f8d42c3c
53a039ec701e8218a0fbe319d636b6a61f84b4282a15d7ff25bc18abfc86fc13e6859
6a8437bd448f3
server_mac_key: 8dbfa0c3a9f1d172f832e1186240fb1717b894a379eef6d9cea7c
a952cbf76921b955d4973b31a327f8cc60a27221359d7bef8c79cdf63a2420ae37aff
9bc805
client_mac_key: 6cbf26f00973009aa47f61bbbdcf5b2b0bfcb3f55974980b0bbee
a474bcc7ce4affd34086d6bf0d2c828f70fd8c26fb7e37076de2f485c2505da94327e
7b0a2a
~~~

### Output Values

~~~
registration_request: a2c1e08d638fa00bdd13a4a2ec5a3e2d9f31c7c4784188d
441b6a709f47e2196911ce68a8add9ee7dd6e488cd1a00b0301766dd02af2aa3c
registration_response: 7c3014ae8189ce0a4b6513edc93bafa79630616009916a
cc88861e7792d93678d963684b53e66eec053d78339bd2b0038f999437a1c7ef357a9
e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa3e421385fd219490338534
5e6ac39e2a9911b6e624b0928051af9a6834ce57
registration_upload: c46258daf62168b7cf5766cb14d6f596c89bf98bad1f1459
ad69a422ea7bbefbfbdad7ed2a02b4361c076b6b28aca7dbca4b17560cdd43a1897fa
ad83409acc096aa5b50c646dbdadaac2d564498844a809a956f03962b42eb000121d0
9318006888e9afbbdf13358434a6e48de2dce2c8318993394404bc0128a86539e86cc
95e35a66855aecff09c820af977f38e7b1c0700f5dcc813c7d7208922c2c08977bc81
f1b0a29d2987cf7182ef87c78090f59f89931c42786889d979d97bb58a103de634a40
f435ad707e738f20340d1379cc31866d12ab12276
KE1: 08d74cf75888a3c22b52d9ba2070f43e699a1439c8a312178e1605bbe7479731
9ab7898faf4f2c33d19679a257bca53e27a7c295b50b0d87d07a98519ae18c35b2125
9c4ec254fc14736b616d4193f03b646fb5cfca07c2d000968656c6c6f20626f62de9b
fa627cb161dd7098c8a582f5fb3a38641e8df3d6e7c40dffec1adff5f0d148716cf15
cd11a04b80b11cc12a1056493b23ee23267704c
KE2: 4a36be2e2fc260c4c6ac4b5a2f94bf1190380b45a23ec97b7f631df3b8fad475
5e824d6abf468d92ed4e3f88a6741354476b2d44d4fed15c0ceec9c4d5ada1763550c
c5c5aec1895a4018fd7e7c79dd94d975c7f0833c0c5af0e86cab8a9e8092da43005e3
da68d2d65b7ee62e76cbf5e68432c6990f88ef3a67ed8c3a7a95b3a34b7c695cd1b4a
a0a4621d4c354d782b5ef4a7641405d97cacebf55c29d9f780c63f90eeea826b6211f
846b7eec953b02207f70c0b0b7411b1fdbc6ceda9768472b6cbf8f9f31721a7dd11cd
f8e740bdd1fe3671a2e7a951c96ef4522b1728a768539bf8372c96ff37ff5f7fcfc6a
c412f897782212d11a2c1f963b2508b528c81034ac80a05ba4026be4fdc0d07de245b
0fd650f0efdf4cec17e85b9cca2fa7ac7f1ff76ca94ed07e8ac65afd6304ef8102bf2
4376fc5b064edb55fe02027d7fef41d05db3652db0000f088eb7e63a8f1a8802adea5
4b0363a585a96b64c39575cce70c476bf577fa6854ba87a99e2076d151e797840f555
234d524dde7fc786ecc2ed74c2d8e6b55a90b8f94a02cca0dae4a237eaadfaaa29
KE3: 8baf72dbeb8350bf8e004ec38a7f5ebb0854c7483dfde21faa2a0ab8c839927e
d49bd05af4523494719b2d1beb6adfb6e650f1b5cce1e3a2832cecfbbbe763e8
export_key: 374b6c690b382aa82cd1716081d17b72389b22db8e8d1a813121dac26
fba0dff9cfcbd76b443c45de4e76f654c9203fd8bf8a9b450542773510c7828f29b12
4a
session_key: 97b11905d497c54824801eac7f5e7799544bc255ec5ae415bb785a4a
b3890e3cc36a8a3431262d2170042838a1b3524f203c2c4456bb49eb3e535eb35d9ee
755
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
oprf_seed: 72c8845026ee6b5450cca1c9a3ee0d05be122da50d0abd9367c573bcfa
d32c185826c92dec2b37cb892bc8248a3eda9d8e45db33b263ed73a850528a205201a
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b9a859958295a49f076220e52a2c26e26c2e0c8250a3288a3e05a
d3282680bc7
masking_nonce: 09e1cfd3c7585b18f4914efa7712cb51bbd8e5c16f3bc96ee5632e
efc5ada022
client_public_key: 5e76fdf3978dabf3ecf418f708d654c34f1f2932a3d1b95ef6
70180d898ba12c670e32da4863bfd274f567100e586fbe2d2b02a1974a6856
server_private_key: f0a17b7f6b056dfcfbee5bd7db70a99bbabf1ebe98b192e93
cedceb9c0164e95b891bd8bc81721b8ea31835d6f9687a36c94592a6d591e3d
server_public_key: 741b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230
316ebd2b419ae2f0fbb21e308c1dfa0d745b702c2b375227b601859da5eb92
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: c317842e0ca75218138410e3d762743e9bbb9ea4f278c82587799b5
de1575989
client_nonce: 83214198fe00b3ecabcca30f745cf8d04a1e2b2f4ebd68cc688a59b
205819d3c
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
oprf_key: cd90e6ef90b20c23d3802be25a62251b32abd7898b19bcf6d05b35eea9c
09516601f7a978857d4b355583caab4be233ba35cd72b59e4621b
~~~

### Intermediate Values

~~~
auth_key: 228f033b981aa4319f2e516663303114f16e4f21ac5647000f9c978640e
555771ca835a417e820741b91f2bcd080d3656a32ccc1283e5b4ec1c8aaf7f4f4ab4c
random_pwd: 0b03a470a41581f87d4b6aef5dc5a48ca31e69639930bd2df6241e35d
5b002fc736d1b4ab63e689fb7925cff3c84a3f195f54d5ad78b4e4e95100fef54d1ca
06
envelope: 01b9a859958295a49f076220e52a2c26e26c2e0c8250a3288a3e05ad328
2680bc7b8cf2574df092d23b77b0f1512ece4d718756f07a61bd4bfba32934adba4ba
7ddd0561c1d79364372013380c892811e875ca10b330590a3483c885999057c55e
handshake_secret: 4ae02dc07a694219fbe8fbe89e1121703dd39c00ac85d932fcc
f6131254e0f3b2e15cf911fd0e33a20aa283873084fcdf3cdc6d322ab46147e32f3c2
ab734caf
handshake_encrypt_key: 5574f1a145df95533c0e323c3677d81df6d68a17dc3147
cffe19a0e133d8b39d7b41c603eaf417aee868cc2542d90693acad107cfcb7f3dc1ab
96ba2d4212815
server_mac_key: 9517cc20e551dc8796fd7116b7ccf0f0325b2caa278aaa83b06f8
22b7cb3105a61374bd7ce36a49d0ed14cc045dfd68137d22f70d9e9f1dcca9fd7da45
f44629
client_mac_key: ff716cba1a72c251defc2d9129079cb5e81816e16d3f182d8a662
bc39df5241e07b2bd45aae0d0bfb7f447c1a83aaf06d368e3d12aa62f10a9f82d4cd7
54d48d
~~~

### Output Values

~~~
registration_request: 66660fc08075380d7c2d4728ed1a7b550647e8231d6d29e
60d3d1fa8fa3132c8dc445fa9c94de42e5f12e29de958e5daea84eba6a6410042
registration_response: 423fe5488eb2dbad0fcc9859b32f9cc5bbe1f385cf0277
4b32d4dfa342d102c18997fe10d15f8cab83411b30f0e467e7ef09d888819955ff741
b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230316ebd2b419ae2f0fbb21e
308c1dfa0d745b702c2b375227b601859da5eb92
registration_upload: 5e76fdf3978dabf3ecf418f708d654c34f1f2932a3d1b95e
f670180d898ba12c670e32da4863bfd274f567100e586fbe2d2b02a1974a685683e6c
3214b4e7ab4f431084b36bc9873bda21fdfd414981cdfad83e927b9ca030a82ec1ed9
86dafde61c4381ac509a90f32f3ae548926ae6d20f6a4133b1bf5d01b9a859958295a
49f076220e52a2c26e26c2e0c8250a3288a3e05ad3282680bc7b8cf2574df092d23b7
7b0f1512ece4d718756f07a61bd4bfba32934adba4ba7ddd0561c1d79364372013380
c892811e875ca10b330590a3483c885999057c55e
KE1: 1c83acd948f714989a2276ef0c3bb16d5b637942e6d642da9826fbcba741291f
0b093b8c94888ff0ab621f90344f5b8b72159e2eb80651c183214198fe00b3ecabcca
30f745cf8d04a1e2b2f4ebd68cc688a59b205819d3c000968656c6c6f20626f62ee78
4169a2abed53764292f2e7385c5dd99ee21d09a4df24405706a59abb6d91f3ed3dd8c
6649807d11cb59ddfa23fad081ddda04ea49075
KE2: 3c617e0d63e08da70f77f75c2871789285de897edf6495ed583f82d54dfa7227
4c687c0716ad6e84655de7f7587316ee44a4aca091dd9e1109e1cfd3c7585b18f4914
efa7712cb51bbd8e5c16f3bc96ee5632eefc5ada02235193d6dcae55c685543b41edc
f739e60e1b1deef9c48488946493eb09a0c83fec7246ee9467ae945b0352f0ab0575d
7d174609a38e84de2d771e2d86ff28c90c9971c1497629448db2f4f35dfd3f68ffb69
67a2568c439fafde84ccd48faf570679e885a1b122ba24ac50ab5d1d3f7ecc5da5294
969e5112b52fe4695deb397cdeab7379b1860d5147b57860b03362cdc459f2add1286
12bcc317842e0ca75218138410e3d762743e9bbb9ea4f278c82587799b5de15759895
cc2a00d1b42d14ac07e05dca2dbc20661a4f30909137bc3274a25c3fb4310fc9c61d7
6fc6576c8ed1c9816719433acc81722a2a5e23357b000f68ad15725678a92f4a87879
347506b932e798722a623ba6d166098ee7c90afd0b5bb3e6f71729e6806fa80173fea
1f4550057a7224f00073ffba9b5843dc8691b637a2304325f1192657fabc2f1dd4
KE3: e8be3690fc09c806d8f3f7ee2d2d53e4c90f8106ad98affc2137e5784d47b930
d702c173e2a8bae690bf0e767686b2fb678f1d9d280fca518135771e811a07a5
export_key: 1ab2e13ab6c6f0a5c6a9110f9d6426acbce5d84165902ab2ac70c7c6b
66df3e8615d59165589d114c7880e8e4144c913b6a0281c89f41eea74a590974d3bbe
6c
session_key: 2c894b970f7ecf38c911025e932c3c71a3a44f37f9092f6c6481c764
49f6f7869ea880540223a654a3e24ac10f91e98c0fa71f2e93937fe078c45f574b10b
230
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
oprf_seed: 17e04df46fbac5310676caa694a0456d2bb67ac22d6315b3108d4e82ab
6aad13373961604a6d9c25298ea5c0d30ed1da73505fa9fb73634dea8f97983a3f3c1
0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e5f6e127c97a67a5258a6f17fd17619e0bc976ae5eb766583caaa
6d847cf6497
masking_nonce: 2c7de8e1c7b3b27483d7503c29118982cbfdf84fab7fac55f275f5
cc28aff36b
client_public_key: 683148e4cb9316bf699f818fb9f4c13420bf744c0d7c0a095c
6e630858d3baa042d107a6d7f96d27c24a483bbb8f38082363f2461bc594ba
server_private_key: 8cd37bf60927fafeca73ed8093538a994b1a8bd463666faa0
68e5ff9e00d588446b7d6cdc09ae8df069b30987a2cdd39286e0481e87ae227
server_public_key: 684e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04
ef823fc5c55e19163c714071efcab7ec06ccce8e6b9eba74ca92444be54f3c
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 9b3469aee3f3c84bb2307dace10662c51f2eaba540a92e185fa8b3a
c6ea35aaf
client_nonce: f840a7bdf23d8696ce54b2d1f351ab245b871395c289a957261d5d6
71959a576
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
oprf_key: 0ef96dd841d737be02e53a046937c2cfed55b3afc3569e7a48031c6adfe
c07237d2dc598bcfa2e97180935aca04e743c60eface21860820d
~~~

### Intermediate Values

~~~
auth_key: 21d655c8604e850ec7fb2052a457bf096f1041161cc2c5311c89d01fa2a
1c7811ed0633f2b01eacb250d4af6061c2e9842c05808883c1fba827f4290f977f985
random_pwd: 3dea9e6bd283c1d7d19009b840bf57b2dcd24dabee1fdbf081cc8233f
fd4a90914c187b44346fa6247e005a05ab47eedcafd5190d6456b6aaae7888e9c77e2
a2
envelope: 01e5f6e127c97a67a5258a6f17fd17619e0bc976ae5eb766583caaa6d84
7cf64979fbef69650a2e60ba09630ea64a033b85e8541a4a0e0bb50242bcd61789e7c
77550a07ee3593e8fbff9c42388699094c0aa92a100f08b92865a897d03f8e97fc
handshake_secret: 7f7fb382f4eb6c1fb74fa7c60cc0f356471f588f737bf9bf468
964f33c1387223a34c43eb82163d112b78e7ccb1f2e644f0b259e5396fef217037b1c
182bd2ca
handshake_encrypt_key: b19fd726a0f92eadcc82cfa72eae0ad40ba154d93c1867
5095689cd12d3da89c5b47a2c88414f5823d32bcbe127fe84167ae39ea8da85ef705c
90462b5f57510
server_mac_key: e1ac9645a77cfaea3b5c2acd382f50385f1d75e0152b2d3eb0500
3c8db88a673bf1444eb0a7bf6cb0a136e8c4b44c374a9ef33c58a0ee892c70c644bd5
da1724
client_mac_key: 7427adeca0b3991c5875cda964dcc9f410ebe6df0d480eb2796c1
5d03e62078a1ca915cfe61061f46f95439914b8089ac368e42cc35e6e15a87a5c660f
90aa9d
~~~

### Output Values

~~~
registration_request: 8a8f12abe7f223895549fd121f9d6124424273b7524e033
f610261caf6ff83eb92d848318e7574c06ccee189b8b447b0fd26a348942d787c
registration_response: b42de5e245377c9a8464b450fe0bcbcf91cb6c7adea2c1
b7253d3e2b74fd5cc4d3a5b0d1e96b4def44dc27c56b52c27fb7cb2f52c5290dec684
e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04ef823fc5c55e19163c7140
71efcab7ec06ccce8e6b9eba74ca92444be54f3c
registration_upload: 683148e4cb9316bf699f818fb9f4c13420bf744c0d7c0a09
5c6e630858d3baa042d107a6d7f96d27c24a483bbb8f38082363f2461bc594badd3e4
81b81013729d2e336c2bbecf01852a664aba10dfb125780dc73fbe512085c3bce7836
e8cbda1f63085330066335176b7da94234498d0df4021b5b84c15c01e5f6e127c97a6
7a5258a6f17fd17619e0bc976ae5eb766583caaa6d847cf64979fbef69650a2e60ba0
9630ea64a033b85e8541a4a0e0bb50242bcd61789e7c77550a07ee3593e8fbff9c423
88699094c0aa92a100f08b92865a897d03f8e97fc
KE1: 442b8d7585abe08bbb6b03b3d73c7f5d81cba60845258a4174e7b8d25a6d7238
8ec7814b7f0a0559fff29ac97c329f2c7b0844c3adb1c6baf840a7bdf23d8696ce54b
2d1f351ab245b871395c289a957261d5d671959a576000968656c6c6f20626f62d0ce
cdcb40e68a8f2a3c472d1fb7f0d96ce9effb7b71281a588df2ca0666ce00126e14b9a
28bbe73ada49d059f7794e5da6be7e7bf0eee12
KE2: 5496ca2df6ba4deb70ef703fc82086c3704d54eb5c567517bf1fbb3708d44166
5f01601b0e5424903d93d1466c27d9bb3949b623840719b62c7de8e1c7b3b27483d75
03c29118982cbfdf84fab7fac55f275f5cc28aff36b9fe474c2b2071b768c9143777a
14ff275f21b84b34dda9944b5261d65254889333b8ba09d223879a96d63bb23bafa37
2aa4b42dfec717ae0710b791af7645d368238358a02891d47eae34a59d09e76e96756
a6db48ebb005fa7c2eb760becb36c072505c87708bb883c9522d34d9306e8a1af1892
96e787205ea9b07a48c7e9cfd70ac91136f0a8776f21ef193aa0078dfc99bb194bc9b
7c119b3469aee3f3c84bb2307dace10662c51f2eaba540a92e185fa8b3ac6ea35aaf8
0f64e52526682c9d332c4cb517bb261e21b86bc7199223b962c3d2906f90bbf3252a0
2bf2889a01d0cfcd6390b8567854107e38abb21033000f396a8cf1708ef04d2619ead
3e14f786279866d8ed03ec9652106235d5cd1be97a70afc1dc2e2fd6e9a8a2bc25e39
c04e284965a8d36cf0246388d8d1c7ea488424a249e78d962238211205d686517d
KE3: fd236c46dcff688641964a525af89c79d93437ff599ceb519120630d2a44142f
56f8029c9cf8ca5d21689ab9c419086687106f87736572c1e066ef16b88680f6
export_key: 8f3a5b3b021cb5ee1dd2bf1cd3a60d0dad7b7e41254d38abedde52061
efd2b1f4d261556e84570bd4cbcec3ad1751d00f655acc906ace9891e1c7141bc6cc5
f5
session_key: dd9be2ff8cb8aa9f76eb075b104769c977ad1d7829f5d7c9e77e8333
24bf77924979083180201c504e340b6e730de7780a5dda8ca2d57310d7c765c842997
d05
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
oprf_seed: d2d0e34897ed25471f35cad7e238da51c05ce294bfe80a60afdc0f88a0
dc1be6f99086871a7aad3053da9fe3dc714356f1f6b741981f5bfa535a5d3b7a7eab2
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 24e3d194eed47d99559d996ec6a4ce028a045cd36a94aa86f2047
1f3484e4ee2
masking_nonce: ae185eccaa1a2d77cc78b9636b555e755e23f29faaccbb497e0930
7d03985803
client_public_key: 1c1903d034850a14c50dff930e63f1fd286aeb344073b07a33
92c95194f756826978eb51bffe54847c271a58d8927a394c80fcaa14a56d4b
server_private_key: 0fb0bff035e9b9cbae6cfca36aa4827ccbac66177b64fabef
a67263087c0cb4e0d9cf547979e753c22548e3174abb5ac630d97dcd4af9830
server_public_key: 8071f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444b
a7ffe82aab916bc5ca6a11fd5fe1479e553040a8b724b6305c3f4289f3f39a
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 90862a02461a8e1ed2225416bc5fd20e912fc45510e11c32fc638e9
82c8de71b
client_nonce: 59d57e6be258e9b45036f3955f1a13f4cea1ae996130564abc6918d
524c48bb3
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
oprf_key: 3dd0afef61a6c39c574437b88fc82f65e4edc4584faaa31bdae33c3d048
e458119baf66eb634494e7b4be1f2ef4b84a51506a75ab2ce620d
~~~

### Intermediate Values

~~~
auth_key: 9de2b908692c44ee2f98f6de7cecf49779317ad575dc8d9853e33816f57
69531ec9d39de2150a27d3a1529c635dc458a6d61a7a7bd3ade925c549446afc6be66
random_pwd: eb63b457b9a971b0e6f84f457d683e173ba423affe7d6b270d87f33e5
4ab048eb5096b688cfcc3a8bbca31d3874134a685989204eea42de26fc59e92f8f92e
01
envelope: 0124e3d194eed47d99559d996ec6a4ce028a045cd36a94aa86f20471f34
84e4ee29430fbec694f8036c2d56cead6ced462f31d9c9e963b96bfb4533febc9f38f
0a3538a2d602f002ed9c81abb694acc32db28fe15439f7ed9cfa9e6e99ed5a8be6
handshake_secret: 2977dbf42a446d3701fe1e5e687ede43476fb827a52c7f6891e
f75968d02a8e0a7f3418378da5950c56280e9bd214e09998b14a6be6aea55a6850ec5
9cc72025
handshake_encrypt_key: ed7bf29f7540aa3af6a47c8226773e07fa7a5991b52dee
67d8f87425306c20af65ce26e1dc5579af7719fafab0892b3ecfdcd9c318dc5d8ab92
ed8f1bf016679
server_mac_key: 355bf2df86e0e97bbd560668918dbf410814671b704f5519dae6c
badf9c4d961d7faa073fed2c252081aaeb7a9bc38ad68214220d1de877bf5b3b311da
1041a5
client_mac_key: f84ad86b6f343e11f15ff3333e2c3ddc6d0d43a2bffd0f3783622
611955ff85f1f81c9d145848358ec0b903bd52a16d151c983e290a1b50e4e8520d41f
539904
~~~

### Output Values

~~~
registration_request: e499c1ea1a644df877a01f23ddc5dccbf3add4407605f67
dcc55f29c2ccec5daf9bc231dd62aa61cf2c9fdeaf59b3ed7a8f33af59ba20914
registration_response: 3c6d59315731bbdd0d6aebe840187f5f57d93f3699a230
9180c1a384929d9b3af6f48c8f3ee364c3994fd846ea0e8032afacbe2f83e3f244807
1f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444ba7ffe82aab916bc5ca6a11
fd5fe1479e553040a8b724b6305c3f4289f3f39a
registration_upload: 1c1903d034850a14c50dff930e63f1fd286aeb344073b07a
3392c95194f756826978eb51bffe54847c271a58d8927a394c80fcaa14a56d4bd595d
36011eef4734e2efcd3db57dc1a591a1dc76ad7a58b9158c6d1cd76aca830e0888a9c
f130b6181337b9499d63d33ec4b482ee13e24bb1ee64a8031bfc1e0124e3d194eed47
d99559d996ec6a4ce028a045cd36a94aa86f20471f3484e4ee29430fbec694f8036c2
d56cead6ced462f31d9c9e963b96bfb4533febc9f38f0a3538a2d602f002ed9c81abb
694acc32db28fe15439f7ed9cfa9e6e99ed5a8be6
KE1: 501e3dc8509cecfa36efadeba5efd0e4f66988ff9575c821b0128af06a2f5ebb
d77362f2a9e63b5a76cf5a636bad31b7a86f6c6803a2c99559d57e6be258e9b45036f
3955f1a13f4cea1ae996130564abc6918d524c48bb3000968656c6c6f20626f62f2a6
7ee95170c51833a88419529748e55dd13e23ffed8fefdc1d2b7c939b6371630031299
800b01a99f83129aa986369e4a188220d056f0b
KE2: 841791483daf3724f02d8e975eeb331859dba49ca95a91d687bf755430de9222
ac00eac5de7cad6af73465a832125031e09baf48009c27bdae185eccaa1a2d77cc78b
9636b555e755e23f29faaccbb497e09307d039858033745a84d4cd7ad96ad1e9973a9
9353ec98b61a849d7dc8c8ff02880b61e3865a3e726dceac17da9ddf91df81bd39f13
e2376f9578ad5a9680f65f20cfe9e9cf65b270db0f6910ee253e9de0e3a11c921b782
fa6848648d8e38ec16f110875968f567d362521e9c03603609463d513cf9297a659f5
6712a66f6b23128b2ea10b899b3187952f5553db8646b986287cb4d9ea2e0d81cc999
4c5490862a02461a8e1ed2225416bc5fd20e912fc45510e11c32fc638e982c8de71bd
410d142e679aee86adbe57da4801741034120c59fa942ef44c19ffcf4a4d65200d5e1
7e7d287220037ab038ee08f96c9dee6db68f02cf18000f68e94549e176bcdae874674
30bc1b25d7b40d907bdfcd9a7fa94e0236b3b1624a74acbfe5f9ca79a6a5c63bc9b8c
a8ad2a1dba15dd43b064af798e0f8702a5b1b0d2cf134015d7d6fd7b441020382e
KE3: 7a7a5fa8e25df6d1a0818889809e382b2875cd334f01f8479a9b6e55b91683c6
ce6d905c83205b2016af32f1c1c1d98f47950966830b289ba9f32d0a1b278329
export_key: a7601e6403ef50caefb9a8e5f0350fe69634496c24174cc53dba58937
0f327b74f1d3b6ebefe6d9a01c9235d59ef03117058fc11cf30a20308c5583f3c7acf
f5
session_key: 768b6230db09a4d6c723adbe4de7bdfe45003d096cbc1f8350d7dedf
7c1222a4faa3a10b21c81939b1591214b5b3311c9bab5c031d73a5b58eea938940404
cd1
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
oprf_seed: df3d7b1096b0589f561d4d65bb4355af048393f0336fdd3f70870e18a2
f33f07
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 630d9d43ae031c1feb3876ffaf8383eb36a83de5abe3bab4148ed
c442873313d
masking_nonce: bd4098003c11c5be09b3bd484a00ef0d46f07ed0395aa3cab0345d
174b8f45b4
client_public_key: 03b58392003909423fb5de2a8300a6c466571439e7862dd954
24c503ba1467ec44
server_private_key: b3c9b3d78588213957ea3a5dfd0f1fe3cda63dff3137c9597
47ec1d27852fce5
server_public_key: 02e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398c
7100af2939f672bf
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: c2f9212dd527d01c5c995f733454b7882450266173aed8c85432107
565ae3b29
client_nonce: f4a0f78d76690ecb974d13b87478102d4ca6a861000bc84918cd2b8
ed7bd704b
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
oprf_key: ceab69046f4be60cafed762ab172f82d21323ce9ec3ec7848063ccf8c69
80e67
~~~

### Intermediate Values

~~~
auth_key: 9e6bb3cbcc6458b3e207eea50bac3aee39633cc33807ed91c5e829e1b2e
4215b
random_pwd: d36c183688eea05b62eb7bb6b2907313b0b94ec4dd10b4178b674b055
0eea146
envelope: 01630d9d43ae031c1feb3876ffaf8383eb36a83de5abe3bab4148edc442
873313ddec409b1d01894fd7e620efefe7effe3b8820871cc13f72bfdfa841c69b429
aa
handshake_secret: 97ef923992d3d49360567bce76d0a01b01af667d3022d60c83d
0a246040b59bc
handshake_encrypt_key: c9d64b0551b8f2c4ddc128d8a0d40e30c5d27b6d587dd3
5a3d162700636d4a5d
server_mac_key: 0dc3c4351ffebedd3b73ed2636e58cf8b663fbbc55d4529b3fc45
6e6491e337d
client_mac_key: 19e3ec1917306fffb0c98a6f6c10d1b5140d5d01597ff05bcef09
41f41b51a5b
~~~

### Output Values

~~~
registration_request: 03761c2597a039a535c3180bd3fb6ea9830baa50376dafa
6e98bb41be2aaae0e91
registration_response: 032df5a045d66490787fd5d3ed5511f79524cf2c956862
fd83bb6b24d5859ed7e302e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398
c7100af2939f672bf
registration_upload: 03b58392003909423fb5de2a8300a6c466571439e7862dd9
5424c503ba1467ec44cc089675dc4fa8321eb49f2bb12f14ffa72dc9711e49c666de1
79aaa660e743801630d9d43ae031c1feb3876ffaf8383eb36a83de5abe3bab4148edc
442873313ddec409b1d01894fd7e620efefe7effe3b8820871cc13f72bfdfa841c69b
429aa
KE1: 021922b40d051877d0f03ccf2831eede9b328e22c8b173d5f28091af0b92421f
54f4a0f78d76690ecb974d13b87478102d4ca6a861000bc84918cd2b8ed7bd704b000
968656c6c6f20626f6203285470567bccdd3755aa8d00261e1ce65aa120e15571cc97
72789a361b4cafaf
KE2: 038c74ba198020d1842cce175c4d6bd086fc536d54fa5c896a7d682c4d179a28
b1bd4098003c11c5be09b3bd484a00ef0d46f07ed0395aa3cab0345d174b8f45b4575
70580194cac8fcbf9c023fb853c8d9bbc492d90cb2596dc4085818bb6d3613ff75e39
5dbfd232001305914c19a4e72d34b53cbac54c6868835a9c3289946543c9cb168a58a
b792931476c265efd2d74e7592bc1a4c30853293e9c68bb4e4acd9fc2f9212dd527d0
1c5c995f733454b7882450266173aed8c85432107565ae3b2903651207f3887f92cfe
c56edd9b9df0047c1d6b7bfc55b3650a9579d44f435b092000f07fb407e1930782ba5
a0e39323fd1392c72e451726198f576e00e43bddcb9bb5ed0a23bba305ebac13c6582
bebb85a
KE3: b70097478923ce09167ef439ed960909b82df12863bd6cca948ce6e2fd2e27eb
export_key: 3d4b26d5d52d47c23561dc67643d86b1b89cf5810aba9915492c2dbad
5dd90fb
session_key: 68802ef1a1ab2173a91aa77e1a05e3e2557ad49f6b8d96794b8577a9
07c304f4
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
oprf_seed: e6e829bd55386fed57c64d593a08db75132b6ac1a8ef7da86106c46613
57a7df
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 1e75549c9d75356df905a0c3dfa61ab833a427dd5f3f67d3d9ef6
fe4e8a04883
masking_nonce: 57e5bd7118099989ea0460284cf3678d6bfbf7da6a8e48b0221acf
d822df679f
client_public_key: 038dd5d679ec7de6d17e2d82a2e88a39c5f56fc1f867b7ae15
b189a30d035fd838
server_private_key: 2bc92534ac475d6a3649f3e9cdf20a7e882066be571714f5d
b073555bc1bfebf
server_public_key: 0206964a921521c993120098916f5000b21104a59f22ff90ea
4452ca976a671554
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 70b5dd422cad528d77711cccb59503414d47f0f1e6d31c13d81f8f0
4673e12f1
client_nonce: 3ad2a7299cd930ac289ac605919b225ca2a11239b596fd0cbff7026
308700fc1
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
oprf_key: c249e4bb4be5f8b641f5d71198313f9ae704bb86fe428a8e98b14de98a5
f65a0
~~~

### Intermediate Values

~~~
auth_key: 91b80ec5c55b3cead3dff996ab230760fa5b4574871f7d324b2dc650d9e
6aeae
random_pwd: f9e6c804200e28c13ff093d4a24af52874357acf4b05cced23e90c0a8
d169a79
envelope: 011e75549c9d75356df905a0c3dfa61ab833a427dd5f3f67d3d9ef6fe4e
8a04883105597a35bc0f0195f295a75f936b9adcc485314cce9a1fe6f073501c77e1e
12
handshake_secret: b5056c9c3719cef28629eeaa9d2273f950c4ca332905088978c
99dd80b6db7cd
handshake_encrypt_key: 8ccb453ac1c51ca491f83218778d6001590db765adab7b
1975e6cc82d553e6b5
server_mac_key: 0b73ceee073b78e21bdf84033ae58262aa2f6aa369c52bf285992
26178ecbf5f
client_mac_key: 05a0f62078f82712338595a80c851865c9e10b1c06320402dc5ab
8300c9660d8
~~~

### Output Values

~~~
registration_request: 02cd04a4a3c6b37f6013d848e1c63c204c4593377e9a14c
68e95097b615d29c129
registration_response: 02a29b6edd6f66ffa527db2d1ed4e07596562ff5158742
ecde9fe14f53dbfe7a890206964a921521c993120098916f5000b21104a59f22ff90e
a4452ca976a671554
registration_upload: 038dd5d679ec7de6d17e2d82a2e88a39c5f56fc1f867b7ae
15b189a30d035fd8380473f1f942a310a8ebf148401231783e35b5b56294c22a81260
4f203f51fac0b011e75549c9d75356df905a0c3dfa61ab833a427dd5f3f67d3d9ef6f
e4e8a04883105597a35bc0f0195f295a75f936b9adcc485314cce9a1fe6f073501c77
e1e12
KE1: 02e747d027881e63565ce0a611dae6da50c2a8b349010a52f5c936169be1e0f9
363ad2a7299cd930ac289ac605919b225ca2a11239b596fd0cbff7026308700fc1000
968656c6c6f20626f62031e7dcb77fdba4b7e7b1625e43dae84733b28eaf2b4fbd7df
141b1ee353748b44
KE2: 032ba72ae7303b3e2c04826b01f8918e5f2fe25d42ac2a9b0100df590f861c9e
1857e5bd7118099989ea0460284cf3678d6bfbf7da6a8e48b0221acfd822df679fca5
96c60379e3c3a0b2f83522e848fe326503901a917c33a6c3f1b1d05c258022ba4343e
0072a64875ef65ff0b7e334569edb94125fd52df39117ccfbd294cb8428af157db086
9d3e3a8f1967dd44167b15d3004d9a57d8c9b9d5c24c7c85733910770b5dd422cad52
8d77711cccb59503414d47f0f1e6d31c13d81f8f04673e12f1036d85072a9cda8438f
67dd81042861349f697c06ad4efb068dceb58c98986409c000f60bba9a53fb70ba010
fed150b7a5a651545e02630c84055373b82bdb2c062ecb80094cf8081dea91ad302a3
f6c53ed
KE3: a3ef9c38fd607c84f9e463d07f219012dd78635bedac0776e2543b221e12e49f
export_key: 00dbf6d1decfb491b7aca62b093348144d51d889e6c2472f908b28c6f
2a8bbb2
session_key: 0f73927468b8e9eeb255b3157722dd6ff4b4213a48b635f754829d0c
8a9bf311
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
oprf_seed: e9faa415b2d22fae16ca8db26028d4a3db86947312be89cbc3be366e49
84f997
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e97e6ab27a5c1ada4acb958202a87b8eb44626619c1707c517948
91b060c04de
masking_nonce: 09b72856b2297c2b200fa6b940d2c9348c826b6f4738901117b7e9
021832c540
client_public_key: 025afa5be865b08547b9b5c89743a2c34a2058f4ef0aae8437
ce57d769678d9a83
server_private_key: b0b4f35c14eb2477c52e1ffe177f193a485cccf5018abbf87
5b8e81c5ade0df0
server_public_key: 02e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e5
59ae18b6bf7bb5b2
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: c053118d2da9a5fc132491580dfd8dd11de057bb8a33bc5552f1ec5
015e632b0
client_nonce: 02101389af53b25226a308f329fdc2af0eb9a95f12a2e2f001996af
afef449d9
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
oprf_key: c7e0d9d7e27c20f7e537a52d2934657a6ce8527995f6090cdc72381c4fe
06f94
~~~

### Intermediate Values

~~~
auth_key: 338cacb3eb208f6743efc39ba8201fbd3be0d66a81b78ca4aacb5104c7e
5a970
random_pwd: 89bf845613c55370dd4c487d7571ee825c1b8fa63a5f975671d171859
5e50395
envelope: 01e97e6ab27a5c1ada4acb958202a87b8eb44626619c1707c51794891b0
60c04de994fc6429552c8cc6373621234fd1ae408b42fa535801d9c7e311a86ae8eb8
c6
handshake_secret: 35b8b1a4a5b430d6cc809d54cf2ceb2c41f909fdaaf71f6e6df
3b37ad76e5db3
handshake_encrypt_key: bfd31de640a93f74ebb6da82cfc95470feb66559573640
0bc748f66ce3018bf1
server_mac_key: af88674ea63d8f62d5f0aea9ee95fd1d7a6a4ac850ebb03e59af0
7b956e448e3
client_mac_key: 591bc708a502d3e79cd39f48be33784605b44d100673d5e952f96
7bf22e616ce
~~~

### Output Values

~~~
registration_request: 026aa49819f2c29b9543cefa0850db7fd36352c6ad8f47b
631b5b621266b670f7b
registration_response: 02d5dbb10f810967e6b3a79aa010b6b92177c36165cace
7f73b524cb29df7cccd902e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e
559ae18b6bf7bb5b2
registration_upload: 025afa5be865b08547b9b5c89743a2c34a2058f4ef0aae84
37ce57d769678d9a83d4e078d7ce982d1fd0ea465f9e9077f72633c83b81f62342c1d
c54fa44baf11c01e97e6ab27a5c1ada4acb958202a87b8eb44626619c1707c5179489
1b060c04de994fc6429552c8cc6373621234fd1ae408b42fa535801d9c7e311a86ae8
eb8c6
KE1: 0223c6f12f3c763bdfea59c13d8f1e055b02277625aa06cb3d839e03a60268d7
c102101389af53b25226a308f329fdc2af0eb9a95f12a2e2f001996afafef449d9000
968656c6c6f20626f62026ab0dc783fb12c9427dd0bcb4d95f5b5212f092406dd581b
d337c73468953226
KE2: 030820222ed12f32dde6995a9d6e4846b42d9aa139d866385cede98cbfffc8a3
c609b72856b2297c2b200fa6b940d2c9348c826b6f4738901117b7e9021832c540f29
1043433099d8ffb498b525678daed2a569ee74f3562c3100343e7077d330d837feebc
8790dd19147c04f885eff8a89ad223c514ce18264c218fdb611e4a9390f70b8ac0a4d
3e9624e88ccb09dd528e9173db90b020990d1bba430580f4fc4d7e1c053118d2da9a5
fc132491580dfd8dd11de057bb8a33bc5552f1ec5015e632b00222d4232635f4ee370
6759740d7a0d8fb6a4068f2fbd34be7cf065f9989b637cd000f87d6b3a2f85c2c295a
6f72ea20e9d6728ad84d1bea2028edee7f886fd73f5f6c50f4845cc4e02c5321897d6
522b8d0
KE3: 3821a30790c47bb47b4a5b006c5321e15edfe36ca71354b5926a596a1605b8b1
export_key: 8c4d843487d0d0c4bad7444b85055ffa1cc6b08f17fa879268ce1dabd
a79b480
session_key: e777e84b86aae6fb5ba598e362c534849fcc59e007e924a2406d777f
cae5071f
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
oprf_seed: f3124630a84f7ca89bf39fb934d13ebec854750db9f5b569648a03072b
54676b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: dc6f74bc261db8f657e1f7a644e77945a8837b5c32eb9e0500e2c
677b15f0b1d
masking_nonce: 2de9bb90ebf88b04078eec87ad7113a8f65630a4eae6faf9499834
3ac6e0a1b6
client_public_key: 02bd20251921f92156197acfabe8ae6acbdf9261ad03342ce7
d2551d51185a93dd
server_private_key: f7493200a8a605644334de4987fb60d9aaec15b54fc65ef1e
10520556b439390
server_public_key: 021ab46fc27c946b526793af1134d77102e4f9579df6904360
4d75a3e087187a9f
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 1bd9a0f2e8ba164a9276436ef2433865657d352d33dddfa46da721d
535d7bb71
client_nonce: eb26b39de8afbdece299b57cc106fec1d0d7e8dc2235e411c3752e9
57c8a9613
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
oprf_key: b23c96b76bb9c9ab5c833f9fe554cb6c80df2e7035d9878cb5747ab1f8c
c22ca
~~~

### Intermediate Values

~~~
auth_key: bcdce102c6e272ea1478cb85d704bf7a86d57b988f24a7d17f351f0566e
67463
random_pwd: 26041ba0435ff20cbd16b1c5336b9b0ab73e6792757427494d7e6b182
6058426
envelope: 01dc6f74bc261db8f657e1f7a644e77945a8837b5c32eb9e0500e2c677b
15f0b1d4a46a336fbdc8bf3da382a0481865b8fc2bd981f8484f7933fffd9f51f6c59
c0
handshake_secret: 694af25a028c8d0668b771ce80a1ac53abc9e3861aa3a2f9c7f
cf2dd0732b107
handshake_encrypt_key: 306678103f905ad922ecfe404348091f94eb98f2acb9ed
2f32045eddcc6fec5a
server_mac_key: f2660e5154efd2878e5da1376c248e98a416cfc6134a46729c8cd
2a79442bdb0
client_mac_key: 43ed45938a37d256155b620a0c5c9af45e6b08238979c968b3468
51dc02310a5
~~~

### Output Values

~~~
registration_request: 03a120f6f2a0b858f546d1e2b60f810ad0ed8511ef0791d
c26d8413fe13b0181fe
registration_response: 02d320e24581744f1b0e110b40de8113da99a9e5a8f45b
15b634f8012282668ccd021ab46fc27c946b526793af1134d77102e4f9579df690436
04d75a3e087187a9f
registration_upload: 02bd20251921f92156197acfabe8ae6acbdf9261ad03342c
e7d2551d51185a93ddb503a2c7f98ebccfa1ef28336e5f80463d0276c71deb185decd
abedaf116482a01dc6f74bc261db8f657e1f7a644e77945a8837b5c32eb9e0500e2c6
77b15f0b1d4a46a336fbdc8bf3da382a0481865b8fc2bd981f8484f7933fffd9f51f6
c59c0
KE1: 03edd5c0afa7257bbaeacab64837430929df9b36bc2784e47577e071a7abd9f2
efeb26b39de8afbdece299b57cc106fec1d0d7e8dc2235e411c3752e957c8a9613000
968656c6c6f20626f62033b64a07786c37f90b1abc757bf074c18326773bc296ec69f
38c111e4274a4071
KE2: 03a81921c8d20d6acb4e20b39fa046efd03d3e99feceb28543e1c500cca73bfa
782de9bb90ebf88b04078eec87ad7113a8f65630a4eae6faf94998343ac6e0a1b6acd
d703b6827c09f78e31a46843bb3d42cc007a5b0cc7b3e7a642d863b5729aa40d92dab
2b6382e4e7fb2cebc320b3da8e43b116256d50e30fd1a38ff4a505bcfc69adc8f7c8c
139212b391a32435f938f62e61c9031f4011ddd6893c19c541424e31bd9a0f2e8ba16
4a9276436ef2433865657d352d33dddfa46da721d535d7bb71029ad3943fb8e838ed4
9e4d64e5f0b84e120f175f30115009f18f009f7e35081b9000f3914380a1eb0189a89
82595c0a6f530b91c9986264cc17f23ca3018eb62b0f6717a6f71f3ae1475c2abdc2d
d1ce3cd
KE3: e80cc386cabdc1c1aa904deee586b9ee7a0441a6e61a025f9d082fa6b5ead7a0
export_key: ed5b6de135a57f0efed3efb96ec32cecc4a56cd3c0a1d5d62d57f7de7
9e28a88
session_key: 9260b013e8abf1519805f8ad33f67b508b4a5c51e2ce06e746f78352
cf88335f
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
oprf_seed: 66ee7c41aad87f8128cf16eeeecb8f8eb2def0af6d1f935f15d4b62bef
18a5bce8c70cc57f4fc02c7a053c29391ceba66d61554018d3e57b3d1f5026376a87a
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e1bc4821017f4411b82e5cf326cd539951ebaae051589c9f148d2
4860c3c8140
masking_nonce: f093af71a76b479b45b94ccc1b981d653ca7800479c58b51ae9545
438e4fde13
client_public_key: 02e6ba27fea0218afdfe89a96f484a66b2f4133ff621396ce7
bb183003bc1e48693736492f103008be511c1443d77b609b
server_private_key: 6b61028c0ce57aa6729d935ef02e2dd607cb7efcf4ae3bbac
5ec43774e65a9980f648a5af772f5e7337fbeefbee276ca
server_public_key: 023713c6af0a60612224a7ec8f87af0a8bf8586a42104a617a
b725ce73dc9fdb7aacbd21405bd0f7f6738504492c98b3e3
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 38a6c43453450186db0af52ecee93ed74be854768b32be607262c0b
e8ed44843
client_nonce: 220ee8ddc867f531a701bcd122aba671f8b9b9fa89d7a071fb4a7a4
71cc67e79
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
oprf_key: 2a92c09644a45b5b323ef30e911123805243c6ba0010641caf7830cc7b2
c66a09f073891a850a95f7a6109a6f1ad35f8
~~~

### Intermediate Values

~~~
auth_key: 0cf189a58a28a806712aa9f179764123d4b5168727c0ffaa5fa52ff97b4
bd2f8df8598c6bb522301c1e76305a7d24ee85db0b22e6497542148a69709fc8320f6
random_pwd: 3223c5ef64d73118e43055548062b673da29a05ccfde4eadc27a8d6ff
1a8fec1d7e42be70cd5162b851504b18bb3077289cfab012e4b3ddf035c30621edb49
91
envelope: 01e1bc4821017f4411b82e5cf326cd539951ebaae051589c9f148d24860
c3c8140fa083d841aaf2e9b5734d89ee4ec0981eb14267d392ad8b7597ceb58c59c01
c126f16bb654c145ab536a3c30cc9d103d2668d4476b13519edc64501506efa37c
handshake_secret: 687520013fc0b6351d8907cf6e43b9cf6a40067c42129bc86cb
6ac447dd3fbeee7978fa63bf30278db6c534f3fd8c494fa70da2af138477e07d3e06b
a2fd8913
handshake_encrypt_key: 20b2c3eb1bcd25c9ad5c1281c9a446496546ae45a184e9
e1c552718e9bab36a8354f4bd3e481c98f6523afd5015afba528f262cdf2bcd16eae8
4384ac461f714
server_mac_key: 5b938aac64eed802fbf0df857761baa0fe14b7513607f9ad512fb
17a40fbd135821d492cc912eb917042eeea3a1c193d79be0bd9ddcd4b3d26d2579673
5accc6
client_mac_key: 2bd7c93e4529aeb1ff72bd3bb8094b9cf6bef4bf4fd525b436cec
93687ddc0895713abd156a6b3d2a3984517ab183bede8c0add9031c7675835f9190ac
5cdebb
~~~

### Output Values

~~~
registration_request: 032a1ed9cba49c4f38f62e77ca295b8dd95d4d928aeb7ec
db24e28d927909e4624e4ef5df6b729071abb6e557b809d5ae8
registration_response: 02bd9aaabafffda161766cb909dd5b5fc54db0e4623159
fd26f657173fd440b7cddfba6b5cc2bdb1af4c2be9b08235bdc5023713c6af0a60612
224a7ec8f87af0a8bf8586a42104a617ab725ce73dc9fdb7aacbd21405bd0f7f67385
04492c98b3e3
registration_upload: 02e6ba27fea0218afdfe89a96f484a66b2f4133ff621396c
e7bb183003bc1e48693736492f103008be511c1443d77b609b55769dc65d322e7bfc7
74c529d7728c3efc4ecddfa812a45061f9649b4458f6409e92330d6b4d6538b2c09a9
997828e443ca5f16bcae4a1da06485d87f8cc17201e1bc4821017f4411b82e5cf326c
d539951ebaae051589c9f148d24860c3c8140fa083d841aaf2e9b5734d89ee4ec0981
eb14267d392ad8b7597ceb58c59c01c126f16bb654c145ab536a3c30cc9d103d2668d
4476b13519edc64501506efa37c
KE1: 036bb3b9d78c508490de49427658685d8a74bdb5acb7ca4fcfb6fa5488911b86
8e746c08a1260d828fc5fa7e4232a2e58f220ee8ddc867f531a701bcd122aba671f8b
9b9fa89d7a071fb4a7a471cc67e79000968656c6c6f20626f62037e9c1e7bbf41bff8
ca6fabb630db2db73a92e57c6260f39d4024c619f8b4f2807473ec0f715d83e88ad62
b88ff3828f2
KE2: 0317822ecc2703c4d06b07f9c9b095ca356cc9430801e7ab8a25e89a60c7ecc3
0d865b1ec94e5c09965ae0f96bc7a1704df093af71a76b479b45b94ccc1b981d653ca
7800479c58b51ae9545438e4fde1377a56d3a4b615c5df942675e8788c36f5add1c68
3a5b4c54a91f693d138a6fc16d345518959d28c110a1e9f1e7f31df100a17760f9f6c
9206656ce5d224c0a8df26eadc18b89e0e222e683dbb19b561c32afad6e877928747a
787e867a02826655e9c37bd76081c9dc7a3b882ade447e6a71df8b8b6207524b0efa8
782e129ffc237b52defd9b1f1aa7fb36e840c6246cf1c38a6c43453450186db0af52e
cee93ed74be854768b32be607262c0be8ed4484303196d22794e67e69232db19e4032
d2f2daa09828c4ef71e5a4f296a0edecaa5bf564c97a7e8c96a4977975a44eed2b37c
000f4f6d62e3a9f73b17ca7711932b20b8f45720a888f4ffada7679f492fed1a91cca
6621b5ca9dd3ef9740264e38fa19b54772144a455a8ee4a87c6cf6f4b5e49ecb6ce57
6e016141f16f24080103b22c
KE3: c04eceeb314000a6c02205cc04dc5463bc4f0bd5828d2279890a1c864379ea8b
f6e6e1699761c43a2e0effc5ba4ff51445ec7a85bd07e30741fb4f9add8cd4da
export_key: 496930c1a13b6cd449ae2fa0580e6c6a8c4e49e357d7db6ed85552979
b21f40f4f338efa21c7106fb5b14309dbe80292dcce907bc76e8d40545d9bee448d65
b8
session_key: 7a1ccc9035202a72e86e006965bfd23fe67fd41ffb382bd61bf9d077
b28b81d6f5729450721d83b686e8326c1df2d00c3a85d72e0fd9824e5efd8d264b0ef
cbe
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
oprf_seed: f3bc338daed5046c20032af5b5c5dbbc89f3a23285551c75cb8cd95e0e
3b5ce9db5c6ebcc69992d6b16717382ac6fc6cb57352dfe73c2eb1f730d1b0fa84ae7
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4f7818814d11583fd9b7ef76eebc5363061ea0634aef818a398b6
d6f2aeb33ef
masking_nonce: 968ac1436b1fabb32e31bccde096fa8c5e6f8376fee4a8927771a8
b61e738a4e
client_public_key: 021aaaddc0e3a9ef8530b80c43c3072be6efdba561211ef861
188275aa6f8ac3fb2f5495009f751c3a76b7530a721d22a9
server_private_key: f5acc7b0dbee75bcd8bb50363ec640038177f06904f2476ad
5274e2f9d258659e80b0fbd20e4761b22298eba98ae9dc5
server_public_key: 03ca37ed36b0b311e3241e6e96f49a44edaa971419d91fcabf
fbca0184afabd92827344da8379abfa84480d9ba3f9e4a99
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ea99457338ee9cb114ed2fd10815a0a942320e8eb5aa2ceebc2ac51
3c3131767
client_nonce: 1bd29a86b8307f8061ba63845342b409f153835fa5e13b778c5419e
c2333da80
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
oprf_key: 12f2f16373c924b314b734bb2cfeba05a050495b23d18e42e641f10c689
686897ed9c2af5bd8315e424bd189dc2cd67a
~~~

### Intermediate Values

~~~
auth_key: d2c2753de07df9beb3bc885a20f544dac45be96f7176436ef74d171c492
28c77de0870214a0210d1c87e97c1d19ac04ee4ceebfb68fd479098916d96e3f7e694
random_pwd: 273801772460dc8bdf349b072c83eab48748b0390098db8ba1702cf15
486483e601ee7933a95fa0436614110e1521bf29b022720ecacacc64f45356cdba001
c4
envelope: 014f7818814d11583fd9b7ef76eebc5363061ea0634aef818a398b6d6f2
aeb33ef2cf55eab4dc1fe00bced3ed899ddfa24b8a030b6883de550305818ca1180b4
cd2f7fae04f7c1569e93a313075eaacb96aed0014ef72aad1187de92b3faf200a0
handshake_secret: 64aa441382164b4a232abee9d3eba0aa99dc9f0704818c1adc6
24f3ac07c6c29aa9a70d1bdc13f810416ee95426a8d6341852c503b1b647857c29bfa
0484528e
handshake_encrypt_key: 6f72df280d2e182e6333cecaeadba9c3ba3963ec4d9a1f
dde7a28ef782cd81cc9485f8ee5d4a3f2fefa250bd09a509fc0b904826517800dab0c
40b3803f79ea3
server_mac_key: ef739053440e6841238d9dc166a20d368848992edfc2b7014016c
9bef36c1249154c61bc186674bbaf5b2b056f6095ad3683b35587513621210ff9a6b2
46de53
client_mac_key: bd3449e24b0864effcf4140ab2716ecff73a7fdfa45844f441c36
8fe9c5074c0fd74dd0387796662e4c9c7bcfe03ed48b2c18583fa5d2eb18d75acda79
99f376
~~~

### Output Values

~~~
registration_request: 03c11a1b33c831ff085bea647c06bb354083adeaf4e7c25
d4ef17e90a25e590b275d412a48b83c064f75a6fd383e4730a1
registration_response: 02d1e1417742852d4add842cdc962073c6857ad57f2003
59ccf21169bce878ecd100142e247367891be0d5a7cb6405932303ca37ed36b0b311e
3241e6e96f49a44edaa971419d91fcabffbca0184afabd92827344da8379abfa84480
d9ba3f9e4a99
registration_upload: 021aaaddc0e3a9ef8530b80c43c3072be6efdba561211ef8
61188275aa6f8ac3fb2f5495009f751c3a76b7530a721d22a975ef089b5f4452f6590
d5568a11c8b5e1a64be799e51e83f54ef74a04bb2e2959e2e60f44244a56c149faeb0
afbc8a08b9a926e6eb67ac1ef9a7ad7de598e718014f7818814d11583fd9b7ef76eeb
c5363061ea0634aef818a398b6d6f2aeb33ef2cf55eab4dc1fe00bced3ed899ddfa24
b8a030b6883de550305818ca1180b4cd2f7fae04f7c1569e93a313075eaacb96aed00
14ef72aad1187de92b3faf200a0
KE1: 03569da14f7d483ae405bdbd365b7bc7cd11968aa5c105d6fdf21d83cbc77050
7be9fb3aea6709f4a37e940900bccb4ca81bd29a86b8307f8061ba63845342b409f15
3835fa5e13b778c5419ec2333da80000968656c6c6f20626f62021323ffcdb6e9971c
b3d0516ac4f70f48c50ce81c897b4c3459ab5aa664a410e20012f6a3eefc000449912
82868648a0f
KE2: 02c887e7524eaf4b7e2f786786c4335127382957cf5771e1e9db16a13fd35119
38eae8387ebb9330e24484c5d10fa619cf968ac1436b1fabb32e31bccde096fa8c5e6
f8376fee4a8927771a8b61e738a4eb2e2dd631d97d3c51224bc5d51a8daf46e3dd592
86ed99a32bf8caf88799eb62c906ff73cbbe97bc5094f583e48bda652fdae4af71efc
483500a333362bef5a01bc0ec75d6505c17eb58523bf821e5528d62bb1531b162a16e
a532c7ed647ac219e25fbcb6548cb1cb446b791bcb04c9e82adba3fa1d05b0860721d
69a03c363dd6f7a1be33e785a8080da1ffeb3c478662aea99457338ee9cb114ed2fd1
0815a0a942320e8eb5aa2ceebc2ac513c3131767037b55471c1bb3a246d0030fda68a
a80a79786fa060c0b56e7bc7d0000886e3d661be0afcaa0cf69519eb528a11af48a9c
000fc39c5fc118ded2083b67389c6b0bea5938aa3a7abfa254e9cefac9161b97a9b91
e357f4bfa4813e57c72f43a5425a1b435faeeef6aa9fd0db6e5b6129ac4155a81770c
634dbff43b9812a323527557
KE3: 2a950d7ed25274c9beeaf6a12da69228d9f4586a6cec0b8e024e424c1455060b
9b8ecf18340aa683727b207f609189cb73fc02aa056c12c18297d39932379c77
export_key: b52f2243eac349cf2e4c38dd97b776e944c8f631980f30e2045f2f617
b6bf7a2d0b1168ddfea43e7201ce8c0c835f492bccb74011b7d8b911099fd6af85729
65
session_key: b994a51f2958f06c6cf5d657453b53d4db5547c932e42eff8a7ffaa2
92bbcbdf893c2a3163c926b14e58de32f938207efb86495efd5c5970d7927c7f57b54
356
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
oprf_seed: 2c4c59721f8d4bf359208050210e8bab210384c0152c75777f953272ee
fd06346b1443bdae3e587b33a00b616f80d540ad48985b997bdaad6c1478aa49d06b7
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 33f96014cf1e322f1c71755b70e95bca5ba11e6a9c52308c9ddf2
501da8fbd28
masking_nonce: 73c2a655b2ab258b839a9d577e3f22e023d264c96418b1909d96a2
6a1a6cb20f
client_public_key: 02adc650edec4a9df9adf568bfb730af8ac6022a5220e7e2e5
232a7d7101becef741c45c78e4ada514e288a91c36d4da0f
server_private_key: 8099b50c7ed9444176251781b6a8575de7491bec330164821
b9b2a108e3ef8964622075015ac9ea0f8380dcce04b4c71
server_public_key: 03aa179347ce8e27d2122b8c2c43315635e5489dfe1a50ab77
186e4710cc489638b097b3302b550da04f5d76adfa826688
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 779b72aeb37a825e43bbd17261f14c87f60175d3ad3758b1863d6df
dbe101ae5
client_nonce: 0602c41307ee57be1bb2eddfb6d437aa69eb18ffe592372bad00de3
e667d706b
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
oprf_key: 29fb0484966bec83b814f73a29ec76f4e3a745b19ae041307bc6971a3c0
1f309a61a564db6879ad9ef109a9e093a56e4
~~~

### Intermediate Values

~~~
auth_key: 1fd61dfc01f1c2686e0307aa1b3f7fd47f80ae72f5940b683ec0252836a
12673d0c69ffc59807e3be8dd6bf87e00e1bd6bced3282f169be5ef4eaa4383e45d3f
random_pwd: 9a4700e21107cf817cfde378b9370e444136a58a010892e1dd3c3aae2
c9a3b6dc3e31d4cda3c018032ea1f6aedfa43a679ccbb01e0a15873b30606764292b0
49
envelope: 0133f96014cf1e322f1c71755b70e95bca5ba11e6a9c52308c9ddf2501d
a8fbd28e6f67c7cbefee11d612e71e78e79038197ce9879f50237c48d88c84384db5c
9d7b2d2be5466b3d2ef01b19b5e32d8a6c007bca0b322056ac881fe682d0f0557f
handshake_secret: 6c3b48dc5d28cb3eeee63e92bef4c7e53686ca3e5bd524a9e4e
e5fda81a048143255285d344fd30a878d2c95d219aa78df80b95ec5e8a0ed70d7041a
1280d39a
handshake_encrypt_key: abd0232326faddaa1f9f2fdeccae52084427def8cdf3bc
837c8f5e14875be534d4c490f4cfd33cb90be97d3d13ee996b368ccd4936fc59dc277
7c88baa92e73e
server_mac_key: 31a5d54ea0cafbcc12101739e54a5282c84cfa6ae84a6d41c1c13
efe2a6a8fba2205dc1931926d677526b1b81b30efa9ba07051dbfb52b2988a19890f1
d02a8d
client_mac_key: 3dcd0fb92cd38b52de273ec5e997d2aef33c08828b60237fef48d
85d1d40be7ba3b332e205c0abf0a4a30d9022db77ed508e50d292afcfb9527ee47c36
8eb1f2
~~~

### Output Values

~~~
registration_request: 0399b76973449a299bd2ad6be1ca983c8a1eccc7e05a36c
a120a30a8807d96bd4b98d076ddbd99e36adfd30b0886fe42f9
registration_response: 022b52403d6d7d869fcaf04b93892d48d19dfd90f9eb03
3022f5e4f2149956153577e1f5cd055b1420b4cd1a8c4f9f9c6903aa179347ce8e27d
2122b8c2c43315635e5489dfe1a50ab77186e4710cc489638b097b3302b550da04f5d
76adfa826688
registration_upload: 02adc650edec4a9df9adf568bfb730af8ac6022a5220e7e2
e5232a7d7101becef741c45c78e4ada514e288a91c36d4da0fb6ba85592380035e785
1ec676d6d6cdb829229d96055761c2535978f1c1fecc203ee7852cde52b0604da95d2
f5c9bfc3c9d6293410a86f634ddb51d60666500b0133f96014cf1e322f1c71755b70e
95bca5ba11e6a9c52308c9ddf2501da8fbd28e6f67c7cbefee11d612e71e78e790381
97ce9879f50237c48d88c84384db5c9d7b2d2be5466b3d2ef01b19b5e32d8a6c007bc
a0b322056ac881fe682d0f0557f
KE1: 03bb6ba53426efb2307df620440d09e1b503d3d2135dd0c845b59f135ab39bb3
00aad505641fdbc2725c31d221feb82d9a0602c41307ee57be1bb2eddfb6d437aa69e
b18ffe592372bad00de3e667d706b000968656c6c6f20626f62038d4077ad0d00842d
0d621527f8225c405f80049752378a4e111b3dcd52857d35f464202f22a17d717d5a3
be3455a93f9
KE2: 03e22bfdf91553e2caace38170f1b18ff4eceddebf4c79b72acf889917ce0bab
3333c045413103cf8acca767cca8f9880673c2a655b2ab258b839a9d577e3f22e023d
264c96418b1909d96a26a1a6cb20f69d7f460facdb91e12c2bce375a71d1ddc0daad5
76944cd59ca8463aabd9f2fd32d17eb2211003787cc02f2f266db528a5a36ef9f0634
1082111413e39f5a8e320432a812e7b3ea466be4e83f8457862ee5b69c1b323801764
04b24df06b07f85695c940ab17983562ef6d11f247e98406b180adf64dbd8ff84338f
39cff66cc8712f4f9738a330f57a299b10f85ffc6b985779b72aeb37a825e43bbd172
61f14c87f60175d3ad3758b1863d6dfdbe101ae503ed7dcbc8318a00c1f42c2b75682
d0beb532636c2e03c524bb5bf5af735812003bdc0d076ca0dc9aa7ea97273c7088f78
000fc8243f909678ea039c965678bd873bdf527d467c1057aa8e75000f0a8d1c8aa51
743c9225156d64ed7adbbd3382268e824050dd6493e8534d75111b90153246459ac08
591a197c6264c7620cf651f1
KE3: d09618e3bf5755f0d21c2499083a3744fccfe5f0947745b9c1b4916c002b178a
16510ff24264d02302b29ae209c5429bae8aa601de57102582e87f898f92f7c2
export_key: c1856b7f6fc0659d3795ab3a480c0ab9cc46d398422c2a95e83b978e1
9f9aaaf41fe33b3d71c03eb45a9f2d6548a5c77e196a079d829a6f1e7337a01166109
63
session_key: 382f14b14a6484f0e4ffed34b4cdacc7613ee46d8d5488f54b8593f7
40b11b523e0b39554fbcd76fd501a94a97d1369974075000ed9a795ec44b192281765
bc4
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
oprf_seed: cfdad9be7d95d1681ae414cb1b813f89510deaa06a58bdeb0f2a3e1863
16b27df9f9189bea1e6dcd6454a55ed6b01db340fade5e239d3725b0101539afc6a2c
9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b3cbc1c0a59af43cb3e777beda93256e4dcb30c2c064aa1d6243e
511bfdb987f
masking_nonce: 559e1251302596a536448a863b943ffd796ccad0bdac773ad332f9
c209433dad
client_public_key: 0395fd86f816bee7e3af06936a4ecb8ddb46a2f7fb9c7735f6
5658f50fb441090fb77447c52fff7cf93f6903f5c8473f5a
server_private_key: c6c4dfa3a822d8f670e5aa46e733baaec9f93d5e14ad9ab99
dfcbcb2ad157a8aef1f3fec3f24bbc392c9755271e8792c
server_public_key: 028cde89b6908e81425fa8a597e3103021475346a146b1f1dd
ab47f09c76ed3b78a251cf390bdc086924bebd471063abec
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 426779897237805cc3dba937822c4ef329c9abaa234b07b6ea147f8
16eba8b05
client_nonce: cad34db82f4968cda8f5f277525102dcd3ec892496e8a2d553262b6
3ad66ef66
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
oprf_key: 903c98470a14483d81c9f97558a1acc956495c667582ec2ddf17e374040
083d1f5a6a3c9c1fe33a8c4e29481884cd5f5
~~~

### Intermediate Values

~~~
auth_key: 8edf99e5180c921194f4888cf3add2f03427c4791785d754b567df37019
3c77b3faca7faf0527a98e79bc4f61daafd4414eaae72208de435cf85f5d33e40afba
random_pwd: e10bf0d281750dfa5cbd008755499b996385c26f5cbc0e9bbef25ee4a
4f7d98333589071e677b66c0ec80c628ca3d6b30a9bdf5ad42d6577b52e52bb71ae8c
38
envelope: 01b3cbc1c0a59af43cb3e777beda93256e4dcb30c2c064aa1d6243e511b
fdb987f2bb8775d7135ae671bfa20791c51e9825a6bad36b531e0cfaca7e1429c9f09
e0b0f171e3cd0ea808de2f4c66f6cb65bd848fbb95dda2319f5dda582b43d43621
handshake_secret: 2e361e3ccf688e6051819e4e6214b66b951115adaa1758cfc80
abb71dd851bae3ed5a43e983de5baaa1ddd9a3b9d3e80d85b00d8cb7802fa8cea7390
460771a7
handshake_encrypt_key: 922c41460da45b97e95fcd5d8ae8629e808b9a5fe245c3
49147805a07e3fec8c50626fe0591716e7d8af3a77a112838652c63fa5e55b3cb8d28
61b6e887e3273
server_mac_key: fd167be16d756f0d8c9d75e61f40f64a7ed4f335a9dd523a9cc39
bf5ba5f037c00bd03e8d1f0146cbf670e62e9e78f8e69ede601793a699046c3b1ead0
79fc52
client_mac_key: d10d09ab14d51d4e739b171cb8969522e27b3e5c4df1b1348070a
2b9aeb98c90eac5c1f5efe55a3a0c2f0303fb8f80cf6eddb04de554ca2c4a45c69f2c
b070fd
~~~

### Output Values

~~~
registration_request: 03f8569ce50a023ad6518281322157e79e1207a96bb9214
95ccde8cf48eaf27895245a7b8f4b3b5c43ba54963a19cc488e
registration_response: 03b1ed5760b0109718b123c7d0a5a89e1639080b36ab34
37a3ca6f82c651791df308975f6a97fc67e5cf6ea514131cb158028cde89b6908e814
25fa8a597e3103021475346a146b1f1ddab47f09c76ed3b78a251cf390bdc086924be
bd471063abec
registration_upload: 0395fd86f816bee7e3af06936a4ecb8ddb46a2f7fb9c7735
f65658f50fb441090fb77447c52fff7cf93f6903f5c8473f5a13de19fc14f15d49aa0
908dbb44acefb0a1524e20dc9736873de97df1f4d9206ef08d43d3e535811f9be1fa2
2a6c974cd55a9762f7845be9aeae35f1e103268201b3cbc1c0a59af43cb3e777beda9
3256e4dcb30c2c064aa1d6243e511bfdb987f2bb8775d7135ae671bfa20791c51e982
5a6bad36b531e0cfaca7e1429c9f09e0b0f171e3cd0ea808de2f4c66f6cb65bd848fb
b95dda2319f5dda582b43d43621
KE1: 0255b2107d1a2192eb54c25c98bb7a95e581d7d23a38e1fceac9f8ce99f568a4
fad6c9bbc5abe4ff08f8b22e31bdfd6971cad34db82f4968cda8f5f277525102dcd3e
c892496e8a2d553262b63ad66ef66000968656c6c6f20626f620246ba00038cfa5105
659e8c250d10618a2c7f9d09d174663bc5689e4778f7054534d9a4200a447510023af
3ad3c61ece7
KE2: 03719795cf34f61a0ac78b0997a8c3fa0300f66a45d7dd0efe223c17a50076fa
9c21a2ea52552033754cb2474e987189c6559e1251302596a536448a863b943ffd796
ccad0bdac773ad332f9c209433dad182a22c52ff8761c3de02bb474aa27c941783fb8
db33aa4974bd73f46de1868080c5973c01629d58380565295187014a271633613592a
eaff56de3a69321954a31d7dc5dda1005d7c71d684327e087bd22b081bc1c4d890812
cf3379d49f78ef72acfbb1b851678b0ca6297a53c2e45db22a9730f8389d8d6dd43fd
f31dedb9d67e1caa217896fe25093d039968d81cfb1fe426779897237805cc3dba937
822c4ef329c9abaa234b07b6ea147f816eba8b05030d570f50898367457561b3a5c70
7852633b4f9404cc45b4058f52f5da1ebf67cb737bfe5c272bfeb65efe6bf7255116f
000f8fd230bd22a1f065eef9007b2998301300e588a9b4eb98c04f20f3bd71a4ca109
073a8c0e2d213ad12444a0f2536174f3a257eba274e2712807b80ef6abb15c5b83f4e
b5a201c592634470d2e6040d
KE3: 0a7bc5ab1a9920d7dd055ba33a89d50e7da609e7a4e6ca9b4b11345270d5e165
98ee0c869d29aa8c22526e1d9e631c999fed705dd25701034296c7b895bd4f34
export_key: ec5f001399f97856ca1e8d30ccc43df12b92b6215fb955e03110a63f4
5ad28dc27fb404ac7f6796f11cd6aad5bd4333ad56ff67fed055136c917facdc1acba
a4
session_key: f21a0214989e6d1a3bdc220e88f95dadecb4ce5d20ada83f236122ba
5d8604cb557d3fca3a37f5f2382c7cc550146b95e319bac5fd4d793627c2d600b3882
d26
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
oprf_seed: a461dd0dc394745eab68165d0d203b7388bd1ae0648e4d654b51d434dd
7d5aa8814d3849651d09378183b4c8fa1d7af3b2e5ff3a62793cb9c09e7c397ff3dcf
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a413bbb5e054e89d286fa0c71883ca8d8ef6e5d477ea71b4288a6
4d096ff8b5e
masking_nonce: b6b40774072169552a36b33cefd680cf08395b6e81ee1ab5dae6f6
54b58a78be
client_public_key: 0300bfb3bea5825b9eb2d6b476ca7d2d2c6606c36b2adcaf90
e111dd5a9b9ff93d22860ce32b6bdfbb2f91fdcfc1d9e6a493cbaea5b9c765e518426
da1413b28cfc653
server_private_key: 00648b7498e2122a7a6033b6261a1696a772404fce4089c8f
e443c9749d5cc3851c9b2766e9d2dc8026da0b90d9398e669221297e75bfdea0b8c6b
f74fcb24894335
server_public_key: 0200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 2db32540b4719f08a905c133de492e38500e8c71f8254de45e8e239
b22fd6317
client_nonce: 97dab522522d4cf52867f5858221c3fcd287c7590b49be29598fea2
b7f5b1df6
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
oprf_key: 00c8ee250a4a1914cdd2b74d6370ef22ab46e4869979124a95b8b47cb75
68a84839fa6f7de1ec8d6f928ce28f9468dd56395660a1532f8b7b07eec68a2ef5021
a0fa
~~~

### Intermediate Values

~~~
auth_key: 543ce03c6ad0c86234498e871bd4664cadb3c6a62e943ec9b79fe30d39f
6fc583c95aaa52948125107ca1731cdb63b41db66ccd239b1d41e947db303407b8b20
random_pwd: bf7e6cb1893917e2abac333f317937b7623a48358af752decb6dc74e0
51cd03724a68245a7910296425db058dfe907fd7f97ac414a02e025d640d81a20c941
1c
envelope: 01a413bbb5e054e89d286fa0c71883ca8d8ef6e5d477ea71b4288a64d09
6ff8b5e930238e2f40e3b6cd33aacd124a61c7bd5eda713fc334d2fe2b1a0f2a5a96e
4ec57f3bc2ae2fd8b60e89a214e47f727272afdd1f4e211afb2b312d7c83ca7562
handshake_secret: f2be5fc0491b497d22e3096a40ecc0a4b6a2920a09f3a6591b2
3b7eb054de72f2a85c9fc3fcf61c6aedd408f50d733880df4b4199758a1ce20cb9e4c
b72c4375
handshake_encrypt_key: 55679914a192807ff0f3433ba994c7edd647c5fb3456c3
54ad61290a9d56bb2f4da87b54e93fbe1de1be69e1ed308426dce933eb9f8614b3c2b
97d9c7db9eac2
server_mac_key: 1cbf5b2e3cdf78c6313d07e46d776ba992322b51197b851808271
2548f07639bc2f64a232c4287d2d680c5b3139cef32649a89b6ead805897c4a2c6e49
112ea0
client_mac_key: 7eeb9cab7e836ccd42da5ba040b42a73695775d69f1c7d2eb2668
8287bc7d901f71b1a4365667114dec982bfce6c53b0a63bcb0e9c5222e9cb04d39c30
d0e4c7
~~~

### Output Values

~~~
registration_request: 03019f508a03d6d883f28a0afa477eac4dfad2ae9052a82
ef5736b24eab85dfc40309c5d205bb94b9a6697ac7b97b9b63e057f163905ec396db8
fe250544bd94e90c13
registration_response: 0200289ad4d86dd5335b38dd431f6985cb44844c9997f7
07a69246efc7b38e27b6a2f666f543039f5f63a284b275d7bedd7a4ac9ab6d4ce9b1a
8d4516be2e31d086de40200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
registration_upload: 0300bfb3bea5825b9eb2d6b476ca7d2d2c6606c36b2adcaf
90e111dd5a9b9ff93d22860ce32b6bdfbb2f91fdcfc1d9e6a493cbaea5b9c765e5184
26da1413b28cfc6532194d8875a3423d4b6a12925b4c18e8f1f55ae09f7cabcb2b871
31206c960285ee3ab769ff5107114957cbfcab6bc1b926ba155fb4ba21b6e7b829788
4acba4f01a413bbb5e054e89d286fa0c71883ca8d8ef6e5d477ea71b4288a64d096ff
8b5e930238e2f40e3b6cd33aacd124a61c7bd5eda713fc334d2fe2b1a0f2a5a96e4ec
57f3bc2ae2fd8b60e89a214e47f727272afdd1f4e211afb2b312d7c83ca7562
KE1: 0200001c8b7065b1f65b9e87150b85b32e6a13738dfcfe40a947a3868b0504a9
c0b8f2d2f8261af3c4507f583ac24caee8981b3c2e7c6a81192d383aec9fb93e64203
597dab522522d4cf52867f5858221c3fcd287c7590b49be29598fea2b7f5b1df60009
68656c6c6f20626f62030187b0369b07402c41744c664239d0f9fad568f0ea5c13e4e
4d80c770fda054cca7fdebd3f91a803a3efe7353969e388623c224a86cc32575ef8cd
5e0cdc3c467343
KE2: 020098a3d23ef07a072479e5ce156a60b41966ef4ad6d41050542e1fa9fbecbb
b691df6d00804c9b91f2458ca319a145a1912cbed9c814f0e327feeac17c250173ea7
5b6b40774072169552a36b33cefd680cf08395b6e81ee1ab5dae6f654b58a78be66fb
f0b391a03c0bbdb04299f7250cdb2cc07e48b8a4211589c2feaee46933e070e0bc915
572cbee7575110aae8f416ac6bf2a2ef609c40d5e553353b732ce01d279d7d0f715d2
50c3160a0d3b93837971b9dc2920f25026de896a23b89b78ac10e09cb6a504556773b
63d01b5c4ae2a03dcf2618fac029ede653dbe96d9e6ff1916e6807be0816709a463ae
016294ba53a50fd1776724693f3967afee87cd14d2afc55f2db32540b4719f08a905c
133de492e38500e8c71f8254de45e8e239b22fd631702016c63c8e2b3feac6366e3dc
f752a8c2a287c1fb4d648aedba86aa0ee07d2b1133d3282584d7c66357bfcab76526f
184f7ff9af506f9eec01645b99b6918bdda600c000f81796b20cea582eb84519bac61
44c6e98b9b63e6915e09a3db578ea274624ff0774c6e8a2d6a20eae756137c61f6230
fabb936bb0a55ef2aaeef51254843bfd83742292f717b7270473e58a924d787
KE3: 4b3a418f208a8234eada2fba4ab73a9306ffd1289c2ede17b11bb75d82f4b372
692534a62442030d88bb5109167fce10858c8d5342b0ac219cd728abfe26d5ec
export_key: 3fe0f025e9aac92a5d9395fe5d0ba763478c1e2048956261112d461a9
f377e886c54f0263c20ad54d090704e906b0475ae222cb7256532adfbfa9f75f1c471
4d
session_key: 8bcde9e22c81e4c17a12756acb017cfd7633656d5254bc83c645b590
d362273ab20cc1284bc38616200f6e8ddf98ec56249982ea05a66dfea12e7485228f1
2d5
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
oprf_seed: 6c01873ee5bb4e2d93a0d5dfc7d203a32440e2c09fce89de161445eea5
e50957eee19899e8ef1071ca83486e9c46bad7de1602186e93da3f8c4c47dee6769d0
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 2e82f904fc7aae7139b2d9224fe4c35d668effb12dc47e13e665e
c31fe60d808
masking_nonce: 4e02f8b0edfb8f7d27df9983eae87deccefaeb2029850ecab3cdaa
f3784ad805
client_public_key: 02013e1b8f9f7b8b6d1fd42ff4df94565b0acbca31ae5712d3
0b51596f2bfecee13c7f3584b901661f4940f92c1a5523c7256a0c10bb8821b80eb87
1a496eb2513684f
server_private_key: 01e58f3492c6da02dd7387bd1dc40065b23155fcc16e56ed3
586c3c2d80245859235d872c5266668cd562a2bd7f34654235b1b9961485ae246256d
f3935910d36507
server_public_key: 03000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: d5f7917c5a6eb07c473d41a179d938941075138e9aaa567e7cf17d5
a5dae664c
client_nonce: ee0129d0ec43d53fbdfeedab9d0fb9983265979b8f26daef3b7a3fb
ca4623a87
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
oprf_key: 00dd1e0885d79c488aeb2c2bee0f8ffeb95eb737433cd24e4e183bc703e
2f32b7ea5d47b2018b6451f7f99e788b1943172cde25f852a0ef58a95debbad4b46c2
2ac5
~~~

### Intermediate Values

~~~
auth_key: 4fa4e8e7cfe161e377062b88324978cf4a87c92a08325fa917c204b0c29
445695c60f574be4c0449ac13c6a891be41df4d842cf7b1aef28721748157d15d60f9
random_pwd: 24d7adaa7b54a828032a0136e8e3559f301dc3ca9545813ea420bd4f3
54ab63e78ce69d626887efe4d1488d082de33189665a8771a3a38bd2fe2e056364699
33
envelope: 012e82f904fc7aae7139b2d9224fe4c35d668effb12dc47e13e665ec31f
e60d80813dfa720b6ad730d03718ae423fc504eac3ff07d85a6273bda404168e014a7
50fed5f5cd30aa7e65b0ff9e3a1827f9a05ca16ddbd6719e0bb53717f4b0891511
handshake_secret: 20dc77d5977d517b19b8c6a1846f4e4bda9daecf5bc08b02edc
c37bff503df72b6b01d240a1dfd7c24825adb708e2c1b8647e8e641ac71ea0a4f716d
a7c8b525
handshake_encrypt_key: 50953160cec64c7ad5e0f950f987fa58e8af9a7d0ddb8e
f4a72c98738997debde1ec17dcdc377f5870a309c64d3b667cb4fa96096ff6dfbc370
005b70215e62d
server_mac_key: 7706d0b0f18ba8811ebaadb30a715833adea941bde8d3fc2102f1
c60b8a818588223f662f3a8e2e113714a36d0e8a1342cd9fd9f0f2e8d4e3cad3bfb2b
641afb
client_mac_key: c3f8cbae1e007698c961b2f996b77dc15ac1879ba6c56fe5e92b4
2bd56e46ab66e96ff285f7b9382ab37e99e282e95d7f0f0bf6ca60745c19ccc40f766
69620d
~~~

### Output Values

~~~
registration_request: 0200bce08f110a6634cd66b75c0721208df3d8c392f86f2
feb9c20fb62c9a30df00b37caba143386c7880a96301814e425ba9df870cfbf19724e
b58411604b3a618f29
registration_response: 0300b1fa7b0a91f2cd92b20a204e8333f814362a7f3d38
f4b2e06826685795622b0ed3e52263a575ebfd6951ace5fc68a540a0c9c461062350e
44dab6b6fefa9cb0a1603000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
registration_upload: 02013e1b8f9f7b8b6d1fd42ff4df94565b0acbca31ae5712
d30b51596f2bfecee13c7f3584b901661f4940f92c1a5523c7256a0c10bb8821b80eb
871a496eb2513684f98c899dccb8ac2b8c3342c2857e5f149bc60aebaf95375627972
2361d8fbc21033db12325115655bf73cdd04879069957341afe6cc5d744f92bf04b61
dce28e8012e82f904fc7aae7139b2d9224fe4c35d668effb12dc47e13e665ec31fe60
d80813dfa720b6ad730d03718ae423fc504eac3ff07d85a6273bda404168e014a750f
ed5f5cd30aa7e65b0ff9e3a1827f9a05ca16ddbd6719e0bb53717f4b0891511
KE1: 0201e2974af3a0c9a479cf1589e9c7db8f3e04723123436453ec427f75974423
4a57a91a724879c5cfe93ed919501d567a6fad6ff5763647c351ad6dd925f39cdb04d
dee0129d0ec43d53fbdfeedab9d0fb9983265979b8f26daef3b7a3fbca4623a870009
68656c6c6f20626f620301bcdfcaabb52a829a450fdeb63bf90b8c98c6b2717164f48
e27d4c737058feb556f81fe39aed7846313ff6a6fb9c4bf1d81083974f2babdb08004
8cc67e12f8ce2e
KE2: 02003268be499b23cb9ffc5ece3ae6a19b97058527ad14a72023412d4c3ecd54
24f3cddadae0e7942bdb4910eef8950a20f13239e13877e8b4925dff0529634dc514c
b4e02f8b0edfb8f7d27df9983eae87deccefaeb2029850ecab3cdaaf3784ad805a8a8
e0e119b5a21596be7d4003fd2c66292e7298d3272874929e48899be8986b2f75d2728
28cfa64b250b89c18dd6ce977d1cd860dcc181aeac4e1770dce0bdc3a4fe28e70b519
17f94967ab03d25fa9183606544a77c5598e563a08b5c917d3df36f88db2368086019
fbd9d8d24090248a5f6228611f166184c22c26999f01c3fc967ce7c930aa7340b1cda
444e43e8e47f39ec4b7b424adc9900ad707bc5573374057fd5f7917c5a6eb07c473d4
1a179d938941075138e9aaa567e7cf17d5a5dae664c03015da5c9a33d3168383837d8
d2ae4d00f39a8a631cd126b4dc1b01f06c32ac86ce29440df0e45650879f65ad94a3d
752f265254f7d5861046cc016567f9e36b873d0000fcdc127659decc5eb063b9fec9a
ca94a867fb2d1ed61d0e8fb5530982fb143b5fb2dcbae624ef6f361a75f7373c1b68f
e686d4ac3da463188248f3a19a6522ae90273dd3a66296a874be67f5e1679cd
KE3: 8f3e068a35a3d337aa1f6630d352c432b9a24ab7b8522e20d7af604af62aa6df
39e68f151bdbdcb0d40db3790fe700a745956283f21a1517870fe8c3278db53f
export_key: adf42dc1b38ffb5ad8c44f69ba19d2e28d91dc6b9df8db60a21c3630d
1874c1ba9db83e102d10bf56c3eb52473fbf80e88402d373aaa99590ef8eec6b2caf9
e6
session_key: 1c9fee2a06bfae6a6343c259e037d12b48dedce7284b5473d7388472
8091a3c3ef3b0cba595237322f98b5fc0d9ee429b7a207a2524b2ea6a32d504a86876
854
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
oprf_seed: 6e81fdc5e1c5ca052559e4be3e13be77f76e3519ce63d07d340709999f
2b146b231f3860d4616e1080aa8d5c9a6bb337dc66fcb292753f2e00cb2e436b160bb
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 001d80e0812d0e7e2f422462ac17fbb7a41ae0ef78b037802b60c
417746dad05
masking_nonce: d286aaef60c5f851969c649e4f0d7c989802d5dcacc7a8c6e67a84
db12d546be
client_public_key: 020152007ad34a6dbcfbea039218b54997d1be27758fbc1bcb
9814257a07cad9b99869ad91ab1e86c04b6d66de5651bc3cc1b0e5c336bca809deda3
c7b6d5701866008
server_private_key: 00deb3fb5eef3871cfaef0953ac3482c88f2bb4849b6ac355
3c3609aa005b2cb37316964371a39548566c5e4e4dfbfbe5faca38a62651e9a519143
d04ac366bd3097
server_public_key: 0200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: b1f9ae97b3da6d6cd660e5cfb28c8efc1b259c781c1f0b07dfbbd07
4425a56e7
client_nonce: 65fd3216d1ac3558cf67d5282a3b18d3279fd0ed7f90395bd713dff
df0f8f98f
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
oprf_key: 01193d259996a54e68840a41ec88aa1e7a0f423374a84011cc486dec2a7
d50509d7cc05569a9e9c63b9ae9a8d70f442525e552dd817cbe6bc312d78e72da56cb
8edd
~~~

### Intermediate Values

~~~
auth_key: 58e6c28ae9116a419277da9bc93b646b08e50d6d9b5b3a4562c56667dad
a698598196cb93290d573622160ea4709804605d25d8e94ddd3826e02f843a015113e
random_pwd: bb1e0bbfcc08e78a9fad3942f272368f11527886c57cd0b83c98c961b
d08a08c16beed4cac9296237afb4ad0430fdd1ef2873141d73ad0daadd25cf801a605
09
envelope: 01001d80e0812d0e7e2f422462ac17fbb7a41ae0ef78b037802b60c4177
46dad05ec0e5cf781f1bbebeb5fa381e56738a11be575030706fc00ec7c83d9f8791c
fbb0c820608ea1ed1e65779b27304863e509875bdf4090a075327dd1c7cd19378a
handshake_secret: b18c2bc01d8ed42122f4bf93b79eb653e4f9e13c03d9be783be
0b99e7a8d1d97ccbe416c0db9756bd1e1a4339b9acac9ba88993fa5a9331b825b3882
75c2a7dc
handshake_encrypt_key: f2b3d37353c58014117f8134fbebfd7d99fee26cbe539d
6c691adaf4e364ebab3e548c02092b4b5a654b593d57afce0907de4afd94288eb5782
fed39e97afd41
server_mac_key: 341ba4ca49b4859feb427d5219b84b260c4281b895efd2a0c36e0
c92e1e804d8fe2419363bf24ae0373de163906054eb641b4103178c070245714bb684
2d1690
client_mac_key: ed39796cfa9e42c7e93bfc084e196e6a6715caab28c2388c33543
feb837d3cfdbda95c0dbe4566efc2e9262f88456864cfb6a5c21b4526b8f27fb5e8b2
a9821f
~~~

### Output Values

~~~
registration_request: 0301fca4ee81d22c8e8cab4cd5e1724bae3cede81109f61
7910beaee9771549cf0090692d4342f0045a99a0707e09e38838e611a3f19c81bba90
12ad6c67ba55f40b1a
registration_response: 02015639eac8a1e15f6aa5339ff023f9c48b74eb9405ab
61ae44fc5a08fef35ae1ab80ff8da67ef452f627159a25a027c75b7c893bd349fb7c8
9e8960ee3866881e1690200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
registration_upload: 020152007ad34a6dbcfbea039218b54997d1be27758fbc1b
cb9814257a07cad9b99869ad91ab1e86c04b6d66de5651bc3cc1b0e5c336bca809ded
a3c7b6d570186600865290f4a255537b7bcec4230edbbc71d204c2466873b429f37af
a9bbb9ccd55b4910bb8a57cc173c11159d42b00a3fd55b424f5193114b68c0809b5ab
b45941401001d80e0812d0e7e2f422462ac17fbb7a41ae0ef78b037802b60c417746d
ad05ec0e5cf781f1bbebeb5fa381e56738a11be575030706fc00ec7c83d9f8791cfbb
0c820608ea1ed1e65779b27304863e509875bdf4090a075327dd1c7cd19378a
KE1: 020197ca02b425dfcae9aafd4608362a1dedd8998e6cf906191b4d888db30de6
dbbd22fb3a1bf310cc09f781d9c6fa0bf1f1e9a79c09eaf0df596801cb9a1030f9d2c
f65fd3216d1ac3558cf67d5282a3b18d3279fd0ed7f90395bd713dffdf0f8f98f0009
68656c6c6f20626f6202018f831d92dd0355becccd11cc3904ddae5edc18d6e357ae4
3a7dc3459335316f842771994b3b411da7ad3c8911c806b322a9fad184e8b5586926b
e76313b87f3d9d
KE2: 03007b44b91a61244ddf71d6d85933af9e8d3d19b1c43661ffe0678c263fbbb4
0f5ff6773cb6c2180c129010a90ee980ccde288ff6957f8988ae5f2501cd45254d61d
dd286aaef60c5f851969c649e4f0d7c989802d5dcacc7a8c6e67a84db12d546bee1cb
6d70f9f473e81e6cf82a6699c4321e19f2345ba8d769cef55b6726db48392a659d2e3
13206360a73a0482abb507ba22814cd29eb6a4337000e8655069d482d06a6fb8aff90
2ee3f32dc4049f757dc54d697d590fa3e2fa559124b4a092457a85b1b097962584d42
f00d44ea66712e359baa6287f08b2e3098afa7f120155b4b752fcaecf7dbb80eb534a
0459d5ab08365a5199d7e83502eb16436c35a23dc06c32e0b1f9ae97b3da6d6cd660e
5cfb28c8efc1b259c781c1f0b07dfbbd074425a56e70300f8b6a63f05a1a6f6e3c856
d512860d5700cb3ad37bc1dbf4ecfc4c77c3aab7bb6576f70be7b460143e577d02409
524ef5fd5e82a85fec43cc2d66adc312fb27a1c000f9460a4a8dfcb5b4d339a392a74
aa0e7d77806ca2ee16ed4d6d7616a1cbc05694ae7c9f3810b4cc61b198b3a02588ca3
78f037b2732e2e093e081c198ae0e0ee2c413bafdbe51b9f5157697617e17ad
KE3: 8aaa188033e060f34c1e54338aa02876f866c3b0b1a34578c9e6b3bd09cd60d7
3837bcc190fe4c84d7d3620ffc0c45f7c485a0696df7fe6e9dd3e8170644795a
export_key: a09a6410c7644f094c072bef7f6c8b39799ad4c71024157601ec54cf5
0288ef02e3cf762001036017900f27be37190fa73b0ee03a7415f75575568abd606e9
bd
session_key: 17587609ed84c23011c3450a9c2b63c67e6cdf40eb037786a9fb1fac
4d26fe34d4663023bf2d52263b4089a95b6bdec906da071cb39f9fa6a1c3660bcfb76
254
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
oprf_seed: e26aee84e934535fcbf93abe03c12d9da74141c7ae43f58a42801977c8
9a3bac46c7aa6a30a0cdc3441b911677b1687f640dcb6a8a73c9d2bdff7fedad0265d
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d6a8020552989967630c0957dab1ea49a5b055d0d935c3a24c4d9
95a34116c0c
masking_nonce: 2bd1ddb66d2733be5a49e81497516463ecf244bc3123bed0ee92a0
6c47202c6b
client_public_key: 0300a326b966582e79bd151f2dfd7bc45f31275d15bdb9d496
9fe28b33a07bcab93e5f0a319393ec7ac2f579f36150db21c486d7e016bf3dd79a5b3
3a54dd9210093ef
server_private_key: 012bc7471bdb9fa3e113b809a86dcc379b782052bce3fc9f9
62d373217b0c266b1e0932c7a0727030de9ce81d360d97fa94f7ca377aa6969e1748c
9f8b0a3f230c50
server_public_key: 0200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 2b6b1cbbc5cb408f9dbe45e0627a5a8ebdb0d560edd9fcfb42842a0
d2588f540
client_nonce: ea37da6323c14405e123817feee4c753d4774e32eec365b2122be0d
6f12f4cdd
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
oprf_key: 01076386fbed8cd57bcca9d4e29145358dbd8fe34118dd511312bc555ca
7a6f9b79fbab0ca37c47160efc2fe6b9a2bf53a680a5b6e2e418dc95121c08983225f
adab
~~~

### Intermediate Values

~~~
auth_key: 4bd12fea293b4bb5fbbabfb46456ef3e8fb7aac735d14c9e3e210f23be4
3bf681b73903a1215e19148ba957b61b1dda96f333312e0e45e28c2ee19e6b5a7b58a
random_pwd: affc3bf973a5ef18afc772e1ae8adf9f51369ef02af77f7670e7cf4eb
e1bd3f98ea4b33c3df33f1d5bbdf4b6cbb6b7525893c7d9a1afd4812c3459e593a7ea
a1
envelope: 01d6a8020552989967630c0957dab1ea49a5b055d0d935c3a24c4d995a3
4116c0c56518267d13c2fb9c0456d1040f185199e4cd4f5a897065b51524398925f5c
a4fb01bc164f56da8e2a7003fb2bd67b16891217ea99fa4f6b13cfa706c56a0b57
handshake_secret: 5059bfd3282ec65cd8fc342fb6988c5bf8d5db2944cdd1ebca5
0a30348465b946c2dbf4a0e4b91249a27ca688dd464674e7bd368e8c9e6846d17e9c2
9d2ba7b7
handshake_encrypt_key: 0c56411fb7bd29ffe752c9ae5ac186efe57ff703982af9
6641ca87339982314e736e25101594cab91d8725c10ce81d23f8d49f795016548ec55
3c10144494559
server_mac_key: 64725bb00cb5e76d47fdd62059ecf3e6b2f5f8496f33ece5a2027
4457cac7e615aa6da71af58a106b9d439a741bc0dfb83d030631faaab191fada82415
c3c1c0
client_mac_key: 14277fc82b9ce1e54ca3ff89a48d940e873240a19df92cfb36400
cea93246c46a74c7fa3e183d896bf99fa6f95b9a054bd7a1b215f85537513d13a0f23
ad5710
~~~

### Output Values

~~~
registration_request: 020178d37274cd1fa2512ca1d238613727201561218673a
d3fb6a391cf6dbe028dd8d953f0e36516eec3c69ab0293b19769074c4b16ca36d06ca
2765543e694fd8a2f5
registration_response: 0301dc954e1d1d1cbdc432a72164ac053d7bfe3c61fc77
e70addf57cbb81ccc5fa8575cec3db83a2680432826840fcc80b13bc8057ffded260d
8271a0f875d39b730f00200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
registration_upload: 0300a326b966582e79bd151f2dfd7bc45f31275d15bdb9d4
969fe28b33a07bcab93e5f0a319393ec7ac2f579f36150db21c486d7e016bf3dd79a5
b33a54dd9210093ef4c4b12113eeafbd9a94d54967b2c9eaae509e9f82f9104d0ad79
1e0581817d8444e93010c0e791b47c9e777b33f3001b6ecf7ab85d5ee6d9f544520a7
92c460901d6a8020552989967630c0957dab1ea49a5b055d0d935c3a24c4d995a3411
6c0c56518267d13c2fb9c0456d1040f185199e4cd4f5a897065b51524398925f5ca4f
b01bc164f56da8e2a7003fb2bd67b16891217ea99fa4f6b13cfa706c56a0b57
KE1: 030041daee06de56612bc011e3fc1b5b1c5eb334b6cc0cd587b5c6fd9f94271f
dade91de48e730d2499eefc313038c54e3ff0326da0afd4f5defd0e4f88eb9fe6dde4
fea37da6323c14405e123817feee4c753d4774e32eec365b2122be0d6f12f4cdd0009
68656c6c6f20626f620301125c341b183c9ed98ad735039a5aeb7a9c99c6a90eb2dbd
5a02ffa442393c1de1a7f11ef5a7395a3881525c7fb8674d74d842f0cbece5069f98e
2528ec903ba7e4
KE2: 02016607306c72d7c6fbed09db4373758e868351ceefdea2ab636bdb3921c3fb
62104b8efaa2722e3b2af504aa29cc9326ee26f79655da1e25b1d3517945117224685
c2bd1ddb66d2733be5a49e81497516463ecf244bc3123bed0ee92a06c47202c6bc9d6
7a7739401613f39814613902d9070e30b8cd555d6d3770bf187f57706ae952e432ac0
fba049d1fa26bc01eb161f0d90b9469be1d8f1e17ddeb7785b0be78af94bd4ee4c42b
986ee475dd57adb8f8463e3df572c97790a59c12bd8fdff2023af243033ef7dceae2b
54105868e9fc17408d4ba73fb6303a9fe65c9f72d4b459713913c4264df43da80637f
66a84ff29e252d3d38b9d81f6d640b2ad9376b266c57b78e2b6b1cbbc5cb408f9dbe4
5e0627a5a8ebdb0d560edd9fcfb42842a0d2588f540030121f7821162fbe027849ad7
50dab6227d5633a7148e1b09107d200d7fe63219f09a4e96ba8cb734b5b20941196ed
b471863e1785c22e950e3ee34c85aecc454fafb000f3867eab183232474168380f473
6c423484f1816a84b51c2018a0da3fc44cfd4a33405e3b0b4853e712dea4ba5d7f52a
7e0b8f531850ae4855ba6aba35bc05a7abe05e7c890b409ae83d01382c380f9
KE3: 909497da2ae5356964fa623d8669cb05659680e57ad1ea8f8e6b133807976c52
33e79bc08de992c50e34b5ca66ffca63a4df5c4ec99e22a86a9408aafeb93ac5
export_key: d3488e967b2612210d54d95ded1f934acdaeab1067ede7a37e8fb0e88
ddca2f44e1900c42133de2282ba4fc8716f7da029c067070dc762f574b23aaff2d11b
cd
session_key: e400450035fdacf7a939b081b43ef020ccad114aec0177339f572d7d
73f4f19467f9a1772acfe32a832d18fcd30c853d1a48b2af5200c042bc5ddadf3a68e
f57
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
oprf_seed: c82dd6b4973e9ff801362c29e8cf8ef1744d268da21ef4be32928a716a
fc1f77ff01207e87a466e9c47ac0271f41dae4bcf5a8cb9431f625a7d97bb59ac1e50
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 15ac91791cdbb3bae5d04b08c746f1acb8f9945f9b095357395bd
7fd9d5658a5
masking_nonce: 8b03c1fd2c53ca31604851979387d6bb482a2e89445ad565f3912c
4334ac18bc
client_private_key: 2d8cc16606d110ecf2ba00464406a0975452b63a3f27ce575
921f91146543b0a
client_public_key: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c79
787e2df91e2371
server_private_key: 5a673fae0015e31ccb70006aa21ae18853489bcfd11c0b796
0a3b37fc3654402
server_public_key: 0c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd
9d2f936a37f14e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 753e3da8732c06a80d8918d862c86ec87c0acc5dc24990712cdcbcd
e59f59934
client_nonce: 7a24147c3b8bef44f792227bef5d879f8041173a0d34447e5023d5e
c70679cce
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
oprf_key: 56947003aea468a0ac234f187f7b0c1212c09e9a103fd9055564ecc1607
aef03
~~~

### Intermediate Values

~~~
auth_key: 8a3215b67a820f88b600af7fa07842a01f7ef33602de0c2cbb11df1b32b
34dfbf2a0448f2445ac7f9aab96d2f75a67980e39c089cb19d4fda6c1f552d2a482d3
random_pwd: b4b1a6b08601a74598b832894bcd7e3e6d0e9351a44f8b7a181a81230
97374d2179b80fbf393f6fd1e0db41d23b8c33494813da4d461f60e540277fc46d89f
fb
envelope: 0215ac91791cdbb3bae5d04b08c746f1acb8f9945f9b095357395bd7fd9
d5658a5f3d07a28c482c06f126c1e4887ab452cf276e5c23fd450335ceb47114ebf74
32fa5309ea2c5169fcd37e08324897418a7e7936ee541d1027944ce5e2bdd2c726519
306c855bebfec566ada51bca9f95a67e02decfbf985fc0c65ed1f1b8ca9c6
handshake_secret: eb39ed0c227086cd6efffc2c8b6af25934e7bba7acfed499a7b
269c65104ea15a9cfd063ecdf7ddb5271633fc80e5a2f37c88d9200f358e938ba1c8c
51ba245e
handshake_encrypt_key: e9965e8af2721f48cac8af78eee0826ce2919abb095fb3
cfe30340ab694bd8fc3dbaac53cef46e0d28d806414a862925b7ce30521d9713fd89f
d5fedef7d1351
server_mac_key: d22d5868e2113e479262c7d406fafccd9069f1a5ea3a31dab5a7f
c1e93a329cf4f5c363acd03a2087cfcdfeced94bce4988b27e93b2c3cfcd2c5d08194
fdef76
client_mac_key: 42f3baad40e4f7782b49de80f4062f6eb99c429fb2f679485ee21
c100908014eea05d78d65339e265b9635f0921bd24558ae58007b1a72f3bff445ac6d
6d3681
~~~

### Output Values

~~~
registration_request: ac2882512f36bc4d5914964e782418271371fa9bd16878a
5fb6c3b6d29c54422
registration_response: a836e4338e933909022c3c9f4f4ac25f4ae78452d30874
5d91fccfe4e4fabc140c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd9
d2f936a37f14e
registration_upload: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c
79787e2df91e2371c8d8edc43a4ffdbcc004a75cfca331550176b2ac7d3527cefb2bd
7547434a17207168e2df96b845c618417fe097fe468684cbd0e32e79d31d2267d15a7
5f85120215ac91791cdbb3bae5d04b08c746f1acb8f9945f9b095357395bd7fd9d565
8a5f3d07a28c482c06f126c1e4887ab452cf276e5c23fd450335ceb47114ebf7432fa
5309ea2c5169fcd37e08324897418a7e7936ee541d1027944ce5e2bdd2c726519306c
855bebfec566ada51bca9f95a67e02decfbf985fc0c65ed1f1b8ca9c6
KE1: ecb46e5c31b4044876ccb2a689efc82231d2995561841156db449c71637d145f
7a24147c3b8bef44f792227bef5d879f8041173a0d34447e5023d5ec70679cce00096
8656c6c6f20626f629698728bd0febdc164c410a6738962b955c08a36b25c89058c38
d4575592c12d
KE2: 2c28dde63306dc38bf6e03cfb881d3f35be34ee71aa20e5a2867bcc1bdfbf627
8b03c1fd2c53ca31604851979387d6bb482a2e89445ad565f3912c4334ac18bc54277
08d80a7cbd6579fb1407922db7d6e9a2c578ade30c80b8863253451d069d3c5888b99
00f5ad79bdf16bd5708da655b2c02f05cf677ca5fb0f57562a711e55d5196ab06ed39
8ea680ce5d5d2f50fd9c87fa23c8d1cc59cc11fc2332211b2ced056195adedc79c0d0
4aca6fb8ef0fb9eed206d649c15b4829e58b70befefcda6c45cfa8666033a65525964
da13fb8c0f5f218b8dc17c90b2d8123483701b8a5753e3da8732c06a80d8918d862c8
6ec87c0acc5dc24990712cdcbcde59f5993434be8693c06fc0168040b3321043f40ad
79648211e6604f883bdf23abb045813000f84957fa914388e54af46afaac5482c6624
768a78e62b7ec6f534baacb9e1bd709e901ef7dbb5864bf8023422f20489217e143d8
ececd5116479cbee827562f7eda778373017a9b2b9cd09c4f04aaba
KE3: f5ca299f692127f0ceaa295462920d72de0482ae9633234a34d6c217177f580e
cf5e8bc6bf34f30cbbbda1c56ef062167094ed4ee701a5cf9824f632f851558a
export_key: b693c2f355f9484b531eba2a7791be15ba7c5409476d28086d7bac50d
f2f4c8a6c6bb4ffdcd2c74271955611fdede4a37b4e23fdd09955cd37788bc7e0f2ec
01
session_key: f510b7e76a66366cc389c2ce59e4a431434fcdb12db0d2e5e4d5ef1d
a4a8f02eedf9c70e4bea961012be55925596f0ed4765f0b3c99fa63c61a7972e61275
d4d
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
oprf_seed: 12e984676e834a6faa84af3868c1365de2590ff64cc29fa4fce6300ad9
b78fe6003c2a203c9420cb76715e41aa0b889bb4776a8a9a5741ec0e7323c9aa3e9aa
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 22319bccd1ca44731be553f5d0f53b2d1555ecfc553e8ebc05da9
8fbe8453675
masking_nonce: ed665775368f065c72e70c1a9ec39cf4ad3a2e308101df3ce2a735
34608fb9fd
client_private_key: 10b3066e47db372d6cd714fd308d056c349df63a477498b28
ad3f0e75ba47b0e
client_public_key: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae5b
a927c3c6a9af07
server_private_key: b69bfaa8582bc1d07933c6354dace6674e72fb420b9c40cef
3a5fed717de1d03
server_public_key: 928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9
f4389fecd57073
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 732a88917326ca7dd8346958101d607bd19e7eac24da9a7b1d173d5
d7297294e
client_nonce: 0adf467b658566aa1e6a6ce5630fd62dd3aca01daa0195307fab68d
16d14e983
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
oprf_key: 8291d953869fcc11b4bfea31f6627e417f69dc0fd7c876446d142e1f571
30509
~~~

### Intermediate Values

~~~
auth_key: 6a3ded1e1756e554a415c3ebb752577dd8ab846dd9217f2c1c13ea19ed6
27a2897e7146d2cc142bdb0bf849e099b07e14caf7cf136c509e5eab890f2b4c734d7
random_pwd: 30b3bc36c49d0de11655474ae29af78d68b0ed14f67704b1b0813cbbd
f6c9f4ce9825ed771030c6cbffdbf5ffbdab7bc2eb52ad5827b99300f85b598c40927
ee
envelope: 0222319bccd1ca44731be553f5d0f53b2d1555ecfc553e8ebc05da98fbe
8453675f7dac51494ea4a8e51c9f485c9fadd2534bd92b940ccae7ce5684f1e2f9d68
d8e12840d2751dcb1f6744c3f146388b3bd87bca29557fc41d2f05691214fd5ba2a80
8fd4b98ab24280db7b5f4568708432262910b1740c967d51986cb1cf74cb0
handshake_secret: d0ca2cfe465bb3ba07535bf115f6f2b688c656d5f5aaf04c515
33220bdcc6d5d5f1d7d3cd2e95d679f97636687b6541295e2e3dd27cf8db43cf6961b
eaae3c45
handshake_encrypt_key: cb23bb08c9266ad7a17da1a2938bfafed29e1b86e1c51f
a5544f78073c2920f7266164b32cdf20e83d8c5c1e1d1a259c00b2f8c7c3e1ebc24fb
c81d27376246e
server_mac_key: c255c24e69e01abe7338fca5b6efead8e377fa60f4e68b13b642b
596f2a88242ad4e71ac31d9d93555497af995c8e8b988ba2fc716ee04e0722bd7f312
dee179
client_mac_key: f79427aeb2d30a7899efc5e3e298dc09a7e1ca3a23eb176991cdd
18b9b5e40d5bfeb8359a5a7ca4fb1e635d643eb1926fa264793370d4460bc54eee8e2
ae17c6
~~~

### Output Values

~~~
registration_request: 34fb6ba29e60511d9ce2d2a644a58b8b34af6516cc54f20
f7ff605e8134c1213
registration_response: 247a7d6e5989e9e98f088f4a4673d1e2461acd386f9973
5b8566fcc9fcea186f928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9f
4389fecd57073
registration_upload: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae
5ba927c3c6a9af07bb53f2205d924c8e8afb7f504e2903615e25581c533b4c484b1e1
d67c408afe15cc62f3f0706b284bd21fb02c6e335b37a57b63d5c2b52e3cf71ea8eb8
f489730222319bccd1ca44731be553f5d0f53b2d1555ecfc553e8ebc05da98fbe8453
675f7dac51494ea4a8e51c9f485c9fadd2534bd92b940ccae7ce5684f1e2f9d68d8e1
2840d2751dcb1f6744c3f146388b3bd87bca29557fc41d2f05691214fd5ba2a808fd4
b98ab24280db7b5f4568708432262910b1740c967d51986cb1cf74cb0
KE1: 9e642c6da6a475f89078708431aaa4e04d96097f7778b0de577bf4d08496ae5d
0adf467b658566aa1e6a6ce5630fd62dd3aca01daa0195307fab68d16d14e98300096
8656c6c6f20626f6284a786fae7664759a8bae0cbe9065cd80b70cbf600efc695654c
93e356735c66
KE2: e273c5a5e3fa20c47968ca87700c6d0a129c1a3bb72e6a07ec49388530f0d422
ed665775368f065c72e70c1a9ec39cf4ad3a2e308101df3ce2a73534608fb9fdb5040
1b58f9ca20a9fbdcc045c873b03b5b7670e3c08e22f6aaf168f8c01df8ef62d11a57f
9ca260819d72c4423ee40fe6e8f628e2e309a01137c8b4a429b5e86b8820b94899c5d
ab42061d2b93b6b3dc0fd44b75f1eddc04ac8f94fea2a101cb379b13cd56645ecfee8
169b75031d955bffaf978ed44868028315ae9fa3a7de0e71e16910f38e27c0ce8d1bc
7bfd26630c301cb55874030d4c2944a6799acb0bf732a88917326ca7dd8346958101d
607bd19e7eac24da9a7b1d173d5d7297294e5ef3502cc40e7ba5006845c131b661ba6
ebd0e6994b6f526e3b7cc108635912f000fd6f6ecc3c9961b12ce930152c0375fc7eb
46f0c4cb8c0030213084d0d7d539738f2005c3b67c124062e3e258f13fc39f2e58304
6776485ecacefea573844f4f4cbe2545358401ff3a11fe356d78395
KE3: 8c98a0066deef31669396d66bc30b3e357003f1fe62e8d9acc82b9594bdb6f1b
0265774f189c0abb5864d7fa674396fe058f842cf47feea1678ee473ea02bf46
export_key: eabcc956d25843d56509ccb8b5a5c9c08060db069d87418e59c83afa4
0d1fb9fa6ea5c4914cad422a9cc6bb35e0452e38a1cd5a3f997d83db2ff6f5d0aa9f1
a3
session_key: cae3a203e2d478c1bc8053c819d08e907559cdd17c6120ccba6aec0d
b45eb3ac11e6d75b22399f5fd0cc0f4e8f221994d791c223e7be440eb9b33efe04ac0
af0
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
oprf_seed: 9cacde091d9a7013455a374d983a3f30487b6141a3e57c770373deba91
f13eeb73c983d2a677c9f17e78076cc92015ed56412cd31e8ddcbe0a8a7d7b7cdc2ea
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a7e4c3238b9298e1e8134787dfa3720a63919ec60c932bc8cacc8
691db582353
masking_nonce: a376b2604809bb5436ebeee6dc299f6d99a7adc96a41d9a0fb08c6
2b7485d06f
client_private_key: fee07a49ab54150e525557deebd0a14a8ea81876fdbbf94da
f03d5a2e3cc8306
client_public_key: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f21f
51945a636d180d
server_private_key: ad52e51fb993d6053fd960279d81b6111a367246256f87159
8aaa2367eb1770d
server_public_key: c26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d
9d5eda7943266e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ff65a2a086dedc790c176d1da741099a8e6781e3eb7094b60ef0724
64b9f02b6
client_nonce: 6bbee2fbfa9789d2c588b9b0366b0942625bb8d4aa5100620391bd8
e7a03c522
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
oprf_key: febba9c0b94fdab8b74ef2fd1098f49333ec65d7946c255dc4e59be8377
9720d
~~~

### Intermediate Values

~~~
auth_key: f44f12c79f6b52ea55dbee4682eaaf1c7d1c1b5fc6321386158becdd3be
f4510327c561bfa7b09618766cbdcba5e3e86777e6f88be74157c95182cfe1e22e6d1
random_pwd: 02b13ee86b22dbb96854c237093f2683fee4ffeefb2f46b399a66a477
b99cde8fbb83df85217eb7bfa97d182ba8766f707817ddfd7bb38b5dc5b429012aabd
6a
envelope: 02a7e4c3238b9298e1e8134787dfa3720a63919ec60c932bc8cacc8691d
b582353d87cc913345d480eaabda6e4684d3906af9e84fa9bfe6013c99509ec88a1f3
faba571f97e89dbd418137dca6c4aa6907263967d9adf48fc0dfbc8a6dbee77310bd6
6d4b1b9bb2f11fd21262b24b5bdf83c958f7e8d9ad7b46111aba1fcff65e8
handshake_secret: 1baf236f86cf262cdc7b87057fdc19e748549d3dd7b6c1f7bcf
a5aff7714ab5eb2c65d8937c0bc982b19ae393bff7dfd7c3a72a0c1b808e0f689976f
31841b0b
handshake_encrypt_key: d220458674550fdb084fbe4ca2f5d10ad4c10b241eac1c
502bea82a565c260606c0c16604fc90c1b7f98f92a6ae53ae50a3ff93975a066fd9a4
48914fa5ce741
server_mac_key: 3aa39037d90032f40c637baed6a5c305144d428cfbf3a0791d7a9
13aa2cfbd898ce4136735d8c9deb5da40937894c5e7ff1e32e7266ac276ef8f84fa6c
ca56f9
client_mac_key: 3539c71355a548a72169ced27d1fcc670136f4e6aeae19eefe8b5
37d2baa12ab1c0867818da0a6724d5b62b0860c79550339a49ec3fbdf4a0dba60441a
ea06d7
~~~

### Output Values

~~~
registration_request: b02294ae456aa0e055e49a09a3a4cd7176d9b34778a4dd9
493eaace4883c0016
registration_response: 920f566edfdd10d1149c063a9de153c8a0ca90cd17c172
967518158877a19237c26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d9
d5eda7943266e
registration_upload: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f2
1f51945a636d180d01c93eb2a2d72d100ebaa9143cb2395fc36659017898bd0c00c03
5812366aed3726791dfa251fe0467f274c03dc7735faed6bf5ce8d4bb9182dfdf3f47
43318b02a7e4c3238b9298e1e8134787dfa3720a63919ec60c932bc8cacc8691db582
353d87cc913345d480eaabda6e4684d3906af9e84fa9bfe6013c99509ec88a1f3faba
571f97e89dbd418137dca6c4aa6907263967d9adf48fc0dfbc8a6dbee77310bd66d4b
1b9bb2f11fd21262b24b5bdf83c958f7e8d9ad7b46111aba1fcff65e8
KE1: 7405ec93c531676eb9437f46cf3c3dbe9346fa83dda34a37da03d693a90e9f7e
6bbee2fbfa9789d2c588b9b0366b0942625bb8d4aa5100620391bd8e7a03c52200096
8656c6c6f20626f62c2b0aee89ec05d28e6f9638d2e056f7cb4bfb8b4d032239d3e4a
7960d7479e7c
KE2: 941bdbe13341b48bb84fdd88af9f8eabbf143e745c47c28ebdfd12791e8d0a26
a376b2604809bb5436ebeee6dc299f6d99a7adc96a41d9a0fb08c62b7485d06f89d48
76fd6bd664d9fddf1005d3bcd66ead08217a92775b374b2872171ced9ec25460f7e52
6f5412886540533d0fbcbfbe7fe5650d25bab26077582fe17789c50b34eef2d8bab8d
8d6b6131c99ac43e10996caa7d9c8f7f57cb8e78f6f9df49f14016462332c06a25702
f4e6c972947fd72d3eeae713da9ad85eb20624d87ffa4e5d56a9fb5168148953f49f9
1f0b98a173fac5c9af44d60f3ff284d84045f75d5ff65a2a086dedc790c176d1da741
099a8e6781e3eb7094b60ef072464b9f02b616041ea53924cafd460331043cb3ec0c7
f17d6c246499b9c638118a606071e61000f136a3bf9502d086ee6d9b9a33d0b1a425b
6df3860add1adc0bb90489c46272949fe78d9bf3988a7b6cd91e5fe020377153d20a7
9ae2ec6acac4edc36ec5acbd1330afde018ddeb025b946fb1e5d5e7
KE3: b799d1334286d32fe4c02e692425d37ca6553d56722ec0e50b28641385ef74de
0c92c3c3c81ccde30903c45e44afcd84be12b030335fc57258181ff074c5a9e4
export_key: 1061d7002ca8cb42152c95728e3bedbfa41c26a195653bbf6b7d63c3b
f21baf65acf142732f8f5d0fd8b1923f5f8d84b4599316e80fa6b66c1c9f16c32ea18
c3
session_key: 8d2e45bb99099397ad65f923b3ff041c2f271af7f7f0812947b3d5a4
f557639942f39f29a6741499b618265983b8d8c05631f126eb4cdc810903e471e7d63
af0
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
oprf_seed: dcac59d9b96348439b20fe39a469810d2c72494c43aa4ae3487bb9d230
884a407305fbbfd76dfc4d1edca938484f2fd343e5b17dc0512ccf68ce85e50c9e4ea
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 344561127ccd24a909f7cbfc72ca63804eb3747877ad9f421c80c
62703f5afa6
masking_nonce: 85e26c09114cbc8e879cf28f42a7b7bb8fe4de1d6ba835afbd7341
bcef892a1c
client_private_key: 75da35392023fcbfaa87fcf458b0344248870cd73a38e3fcc
d00a994e1a09e0e
client_public_key: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def633
28bec3a4f21146
server_private_key: a7f4d763822fcc14bb91a7b36b0a6d30f1ae8c3ca1c36505a
02610dbec29260f
server_public_key: 9023317b443158b83d4f4b49674209ad390595bd29758f5e86
b1fb217190e964
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 427122079e8c4a7a3ce0829feec1b8881d7a0bcfb2a635510042576
d5715ad6a
client_nonce: f529fd70b9ab4f0d38dd89a29a61d8e355f2d22af550d4ffe32ae25
f9302aecb
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
oprf_key: 1d77270bd2b8d472ace315d019af5ded88f0acbdacf16a0b1c34cce93d1
76803
~~~

### Intermediate Values

~~~
auth_key: d2e41eb64327b122a837091d69344abb3927b8526e22f989b5089ea08b7
8f13af521d8d60d97641493c23c462d64c071c548ef7ffc481a715752354f581af31d
random_pwd: 10a5e55d482ebd18db9994a53d695234d2b56b8cad9417038c661c81d
b8f8461c0d59fc747ba46c7e37edcb9f8ab3f38a7c27505fc3ff761bed0845afe9913
51
envelope: 02344561127ccd24a909f7cbfc72ca63804eb3747877ad9f421c80c6270
3f5afa622a521cc47970dd7e428ae97e975e710b533d04a89b8c781ab83cd7e22b9e7
aee7745e2baf328df0bf09acf210b0c2e23b95f20f826647eed06305bed340cdc0398
f5d7ac64f5c124d476a914cc89894177e61217c738cf27acc256e89813701
handshake_secret: 5ca2b1ea4b6bff18a5c65ce157ab35c26c42382876eda04111a
91dd03ae93f6935a74a6384c57a0f29dfc7bdbc39e5435530714c401cf1b893c5c4b6
ecb9349d
handshake_encrypt_key: 4d89717456c454709b6dc24952f858f5dc8a658f9e5775
998ed465414b2ecc26789db1e3a680bf3e7f28c8596fd45afd20cea84a568b0687d70
1f51bbab9c039
server_mac_key: 451e63b79a4fad63cec37f50cdaa6a8449467f24939842b10aaea
9fd0941f9b8394d8cc94c22c794560ff35e006bdff474a36281283912f3bc3e59a86b
9cc06b
client_mac_key: be50e3027fa0cffd50bb07148948bbf91cfdbcf349aeb5e9c79fb
9e5688ef6cd0ab88783efd95ab800aa59b88ee993eaa56129e092094a4bb052792765
f07361
~~~

### Output Values

~~~
registration_request: 6a525dc9419e2d0261fbcd6033f9d500503a27027a48d91
27ca1209e01690d29
registration_response: 50dcab1317e5202399eed2d8cf7d14759dcad59a7f661a
bfb1502c410604ba7e9023317b443158b83d4f4b49674209ad390595bd29758f5e86b
1fb217190e964
registration_upload: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def6
3328bec3a4f21146e50b2584d7ba89b0da9b3e4d5c34c3065c3efa0f57203dd3dddde
883ca01099c92515c7f31c9290ee983e00af1e169189ffd15a550e535755266f47a18
7b808f02344561127ccd24a909f7cbfc72ca63804eb3747877ad9f421c80c62703f5a
fa622a521cc47970dd7e428ae97e975e710b533d04a89b8c781ab83cd7e22b9e7aee7
745e2baf328df0bf09acf210b0c2e23b95f20f826647eed06305bed340cdc0398f5d7
ac64f5c124d476a914cc89894177e61217c738cf27acc256e89813701
KE1: d6a8af82258885688aada828f32e04463c3739c7da0e63c5246711520dc16e37
f529fd70b9ab4f0d38dd89a29a61d8e355f2d22af550d4ffe32ae25f9302aecb00096
8656c6c6f20626f622c8ffcf1bbc02dab15df7834ebdf85841395f07c8e7317285ba8
574b6eee3910
KE2: b699a87902b9a8c5d84ee154a4365b0e20e695706a5a96fe34a7bb079124032d
85e26c09114cbc8e879cf28f42a7b7bb8fe4de1d6ba835afbd7341bcef892a1c6e517
b6075edef7a35a9fc0b916bb188d09ad92e19f8bf38bce7381f988d4f3943a22deb93
e9a4cb5573a1d3bb7f457390d142c2bfaf8c745363441b1f01236f9cae78830004859
b27923097e4cc9861037a8a2931836d587f3339ad52878856964de145473adf6b34e8
d6e6ac2ed973fb29b7d58374ed78bfafeab4a6d233edf7c35747deeb618f551ddbfcc
b5b6b1b1e7bfcd6523540fad6b9bc90e1fb4f43c0427122079e8c4a7a3ce0829feec1
b8881d7a0bcfb2a635510042576d5715ad6a58a6c4fdb4b3da03df2e5b1f6ce154940
2e209712e5bf9d31efbdb82c00eef5c000f27183274fe68ef896c2487de44dec90f26
297a710fc3727e6b4ad0538f2b58110e17856bae18993c5fb0f10ed58baecaa7f9d8b
e90200d49b2670f8f8c86b61845206355a48ced3cd5834d4c72257e
KE3: 092da62a0b63c0df3a2fa7d9b1540fee087d996b410eaaf5bdcd5ffa3ea4fa81
4204b97ffa45395a0bb601d1ae6dec2acfc54c20593f0f8adfc640db35d14221
export_key: 95224e7d80c3819aba7dd9f8701bdda560287d4d894587e22a79c5be6
a2ce0773d1eadc4551b145347c8e1b3d6c89bb55d5a71e17fe81c1f022821981569cf
ee
session_key: 407450be9183f6f871b0654cb33e356478317f08060c6ad8d3986d61
dd6aee6c1f026b540a7337097aaa3e9814a20aa8c02cb256a3a541c9e1580915c9a71
5c7
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
oprf_seed: 018e2f0b1141f7cfaddf937ba66a9039037edc5cdbe9e5ff5242d00a6d
9fd9423f13643e68a2c339d75e5612e9b80c2b15d7e634ebb01c6ec991727b2970905
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: be44b5496c992e031f9cceade5d703164bd413f4f2eaeb90291c2
f258e64df68
masking_nonce: 28565428dac58379dc1a57b2bbf648ec089ff92a4941ab73522419
0f5ce24efe
client_private_key: f4ff0c84bacb98d40ef1b543bdec5009b450e4fea1c8aeefa
6022540fde3cac20b940bc918b0a16389fe160a1e6ae09a48d235acaa1d3735
client_public_key: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9fb6
86b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aa
server_private_key: a762ac7f6fc2f643032abc43fbb2ad4e6e012f48d106d10ed
ddb5b69d9e36d59b08eaa6830c6bfe473f50ccfb5c033b97885214dfe740e35
server_public_key: fcbb8bbe6f857883e38783acf58dcd6de556530055a2353c4e
584320e0916d28b8278212bd6405864ae84a5cd2508f09ea1185f82c9ba518
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 3e0ead070a2eb929bddc4c1087641388a6014fa4fee1e7ba55557e5
1a64a8379
client_nonce: d25412154b006ad4b4b49ccf45858cec3ce4f39ad2c03d81c0e4728
d3eb40c90
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
oprf_key: 5d702f71e89a6d8e326509015878e65880290ef3294ae23d065b1ce2de8
76946464928be379ffd5e725d5f98970e5c4278de44b861f24a0d
~~~

### Intermediate Values

~~~
auth_key: cfa636bb12fefcebf35a80f9dcabb32de78c2b82aeeff0496d3babc8a6d
19e5e7cc85b2b03a89c7328c79f1dad295414753b387434738181549f204a68b7464c
random_pwd: 4b06179360635319c0d9922cfdff0e3a93929286c742f6d639da657c7
6094f94ec6cb206938990a0f13e7a410cd988b22f9e2d69e51756e3dc54674a3bb51c
03
envelope: 02be44b5496c992e031f9cceade5d703164bd413f4f2eaeb90291c2f258
e64df68c484bf05fa873894f238c721cd663f112f8972fe695dc2b100b647a3bd3378
4971f3e4b49a7419235d7d1c3bba072d28b83939733648a434f63e7272330bcbb6b6e
52c998f61dcca0755fb92760dc8fa80abcfa29486b18749d42af86d8a2c60f8ac43af
7ec93ccb7e0954a0218d24b4d4d8c98e4066cce6
handshake_secret: 6caa22f632865ba6a1559b0951c64680808b421ebaa04d883bd
aaf328ae388855af1fcf08a0c71ed966ef66d6ecb0421dd3bd34ad76d3d8cc0975728
ace7d469
handshake_encrypt_key: 080b2b54ef3f8004883b6fedc5eec9267c0040bf353337
6adc7a231c91573da875ae5972ca80840d43955500819c7d0686ff5f2eba093a8bde5
16f554dc0231c
server_mac_key: 2ab3954ac5008f17f2734ae4ecda63ec93a6e861b50193170072a
7786734d5672c41188aca33afe5b1f605b51f49cfc563beda6cc66d89dd82380fe9f0
dd96a3
client_mac_key: 2e4edf50afda28750ab95bf9c4f7d99a48dccdb0e1553df32beb9
573fae97ca10f577b352c76c8e43db2cd35067f9f2dd91fc8a46d5c22c4d329f09988
56cd5d
~~~

### Output Values

~~~
registration_request: 56eba0e757af33e634107f2da32fbe987af1d37bfec1918
a2d42ed2f6b3714bdc1dd190ed6dc6da310536bb748cad363e76ad2fb1b05f1c3
registration_response: ee8bbe87819861d9141fcf7119c6bfc7dbf34bf103fc16
007d1cee2401c86b9c36600cad70acab06f721311e3b50e8ab11df39e0bbf50df7fcb
b8bbe6f857883e38783acf58dcd6de556530055a2353c4e584320e0916d28b8278212
bd6405864ae84a5cd2508f09ea1185f82c9ba518
registration_upload: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9f
b686b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aace2a9
b275923d5536df1c65bd7bde54ac3f41ffa3e7584722e4e0cb546402ce6488e2191c1
0cf3bed14697528699087adf883ac6eec4731dbae91db899c06e0d02be44b5496c992
e031f9cceade5d703164bd413f4f2eaeb90291c2f258e64df68c484bf05fa873894f2
38c721cd663f112f8972fe695dc2b100b647a3bd33784971f3e4b49a7419235d7d1c3
bba072d28b83939733648a434f63e7272330bcbb6b6e52c998f61dcca0755fb92760d
c8fa80abcfa29486b18749d42af86d8a2c60f8ac43af7ec93ccb7e0954a0218d24b4d
4d8c98e4066cce6
KE1: 16ecbe71c272b0b9cce77059395154ae766c95a7f10ad0e699aa0c773877225b
a13e0a8ace5007c53ce3631c7e7cee782a6c44cad6832e0ad25412154b006ad4b4b49
ccf45858cec3ce4f39ad2c03d81c0e4728d3eb40c90000968656c6c6f20626f62d25b
52b3af68ebda6905d0db5d964660ec9ec81066ef7955559aa302e012006b1ce049556
666231483f56af9dcd1c27fdbafb4d954060091
KE2: fa86bc09c85d01b48afc1cf92413de304ba23bf054a1e0a6bbc6e2f7369bbb5e
18a9699c4c0d92a04ac731fca29fc3cdff696d2ac7cf15b328565428dac58379dc1a5
7b2bbf648ec089ff92a4941ab735224190f5ce24efe31fbbdde4904111bc88e9348b9
45b63111f2afa958ae1edbcce899b168a42b11caa200580d88a268eb50a3c6c64164d
9b7f859eca8ff5e81db921b7d56644cdbd46fce5a109a5dc655a66251b0fa66aac83e
5b8a59ad70d875d7bbd01bfabf7154f6d96a5c139a456121f62a5f500211978f1c294
cc83d8331278816ba5fc94ce99d08b0609cbd76608a70f45433261e8b93194f59ae8f
ca2d2c41e21f1bf6350c8752beb7c09ba278d31905092e0a6ebcf49756517fd13a282
3bbbe0d7af4321dfa577f9c2c5e218eb3d0817094053ed43e0ead070a2eb929bddc4c
1087641388a6014fa4fee1e7ba55557e51a64a83795898c178da53ad329a001103a6f
2b4ec6e0966c665fff16d88b87a83aa267c2be161d1a36a39b7b184828166f721b83e
e15fe4753b05755e000f39e64381175ef09e19bf51f8a687bac2e11049b4666f055ec
e7d0c468e0a17f8e5912ecdab167e1ddfd3bac90494dbb3411d24f90f3aa57349e88f
cf858c46e7c3517608a3dac39c61ed43e6bd5e08
KE3: d6c3afd167949f8f19742eec3063c11dbd2511a0199343d131680fecf9e7aae9
ff53af4b4e0c174be64a5ae14da237e474d1dbad77069ffdc18f49fde1ae84f5
export_key: 645e74b08a370edac293349946acde5c2a2f8c67e8ad6b445dfb48b99
6f290dc857a9a5a2f5540cda2e776761b8a9d304514ad57294f85a63d1f90ba3b7b16
5e
session_key: 40da20df3b5e19d4e299ca8b0493c9deedf3e91271dbdf9c04dfaf37
d34b9eeda82feaeda48b27e915ab5848779becb8ada726d2f0c2ce072dec0250c96a3
1dd
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
oprf_seed: 0d4c4ae4eee3bdafa77e530d8b2e20c2c07430679191c27b37f63e3202
7d17502a04fa077d8b233a671da834a47ea26dfd01935330fc31f112c8399890f108d
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ce1cabd1d9b2171add9364a4febddcb169f1b6645e9e892d2702e
437da805b64
masking_nonce: aefca54b2c4c54156b49dcf78e88a1e60b39fccac78f8e0270cf04
786da6ac1e
client_private_key: 4f4b1b91c6a9c0dab6a8ad279201e00d358aed1a0ba88c458
589796b05ac19101d1119df1070dbd0911ca74b4634a51b9b1b093b74e1873c
client_public_key: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec2a
f04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f357
server_private_key: 6ab03a76f031abde2e7d1f987c101064757d6133445217316
02876c29cc7d2652a7329cb8513ddcebb66b178194206a61256f5e14e70d23f
server_public_key: 2ef8f9560867402d20f9c34942bb26e63d2cc667851473334c
6cdf1f89ec0ea218e3ce0f73f9f1fd303f140bff958f80b7d4dd22a150a0aa
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: d29959a129de0949845d7432cfb8333bbf3db19e761b2fd4463320d
9c2d10480
client_nonce: fb94500fa650aac61bc490fe2683708fcacf59b77368d23effd0a99
260c8bb54
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
oprf_key: c3f640b8415638da69b0259d3cf27fcb244aa48450227f2aa787aa23740
c351fb63f50815743ac0b1fdd5e4c29ec339fc0784d4b849f142d
~~~

### Intermediate Values

~~~
auth_key: f3882674a5b200a0d4c2b3fd52103d1c07c147e89775e113afa998a2dcb
dbf5cedf9a3228892ba151add40d459d7480318bd347e31c1f6f036e401bf06d406c9
random_pwd: 1ace2876a94ac111d796e8b58ea77d429db5b49503a4a023fdcc918de
5b2c452784ad0616d99bcbe15ea4eeaed068266166cd2baccf6465505d5fb34d69a28
72
envelope: 02ce1cabd1d9b2171add9364a4febddcb169f1b6645e9e892d2702e437d
a805b64cdf99498b6c8a91033f95630eceb13db85a397f28bafb259dd0d00d105fa0d
46759bc5aa0ebcf3442db01653fbc711ec5dccd6f1032f0661a1b610ababe56db2c1f
39e8d589bc583bfbf97f1cd83fae90acda608a77736ae60974a8864a30e4492255a68
89bfc78f4e8cd60c413a35fa5fbfc3b9504c4668
handshake_secret: f32bdee0a08dbe6ca3110b064ad6f313d81228b0873b179efd7
eb3fa4778d6b06cdd3fa7bde7c29e03102a6ef446bce6e8d7b16374e7d7a5e45f14fb
7d5fa39b
handshake_encrypt_key: 21fbdf60e91e20a6868e534b5d89c129a524b73b808cf9
8ac768eb71363d0558b144d347e40786f96d7afc51ac3f7e1ddeebfe0ad5dbaf65275
79dfac6ba81a6
server_mac_key: c0bde9b4f1b3f13f88d42a106385925b1d985972973cc4be9b798
1464caaa22bc6dca33e48c31f7f547a1a3885246cbe837ab251685ae454a937fb02ae
f70a5b
client_mac_key: b23dad44bd209b5622d9df29f1b4a07d9944ca89a6cf7b32f440c
d81f68384e13fa24303a5932f38e927c601177522d916f26384e854db6a6e2c2ff9f0
e16890
~~~

### Output Values

~~~
registration_request: d287a62ca4d452ff3b5e2d800121dbb5785bb383db9bdb0
c541f8e643443dfe2ddb1162b8b7c758893fde1131a84ae57935e7b60b14058c1
registration_response: 288019e37bd5d504a64c5ded019f5b3d4af20ae65c6905
c6160687cff17711d8fcc261429d122a4730f6185764eea70db4ca501fa000cf5e2ef
8f9560867402d20f9c34942bb26e63d2cc667851473334c6cdf1f89ec0ea218e3ce0f
73f9f1fd303f140bff958f80b7d4dd22a150a0aa
registration_upload: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec
2af04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f357415df
a5be81daafefef48a19d9b89877a1357eb6ab7bc0228798d4b5c9044af98edbfd8a73
604701ca0e3e40b906eac6f3712e8cf7c9d68a7c8eaafa3f1fe03702ce1cabd1d9b21
71add9364a4febddcb169f1b6645e9e892d2702e437da805b64cdf99498b6c8a91033
f95630eceb13db85a397f28bafb259dd0d00d105fa0d46759bc5aa0ebcf3442db0165
3fbc711ec5dccd6f1032f0661a1b610ababe56db2c1f39e8d589bc583bfbf97f1cd83
fae90acda608a77736ae60974a8864a30e4492255a6889bfc78f4e8cd60c413a35fa5
fbfc3b9504c4668
KE1: e4420dd6be305be0776f14c1140f0b36ca304c007827a8c5b4910c5432dd4caa
6214b4077d4a99e6d6dd7f756bb3531bd010eec2253afd1bfb94500fa650aac61bc49
0fe2683708fcacf59b77368d23effd0a99260c8bb54000968656c6c6f20626f62d878
99f024ee66ed5b8718f9966f2f34dde445da12078789f1e6208028cbc9b7ac7cff5ae
937856aa01321310e1858f0e3b89492e9e49f42
KE2: 32c0db28268952c43709877dc61377402c5d6a9998fecfd3c87f45d15871dd30
61f80e42dd8ebc964d04ee9317e258791692e0b233bf361eaefca54b2c4c54156b49d
cf78e88a1e60b39fccac78f8e0270cf04786da6ac1eb1345ef6f9c03ff461bacc6215
fd7c6546a206df7b10af8fd28ba35242b72299259ded5cf6a39076d4f98139b4664b2
e837794aad116dbbdd4e080dbb51655008694e9320e80954aa5f85d251601070badb8
8af41cb697d7815835a904c0c9a23fe27775eeb330882a8243ee893063460c926c4f8
239f8de2b0cfd6ad3a9e309c027a60a236270f47f67bd05fef4aa50735845ceeb0a08
9decba54053e23d7af7154b457ec4d33c0c8dd84f020b35a9d473787a52261cb721a5
e4f6fb80890f66216cbb52868e69442fcd3edccb7fa5a19d29959a129de0949845d74
32cfb8333bbf3db19e761b2fd4463320d9c2d1048032751cb95f97035f22d498ed57a
8af0d2495075aace642f152442da8485211d6a551142d9bc6771619ecf80ca8b4def3
96f706ce555e2896000ffb13cb6eb48d564811941ecff59468e3246b957f76d532316
6ef1f85bcfaecdfd0a1c3be8826fccab576c5d7ebaf6f9c0bfd9a2c8053d6a04506f7
fce7abb2dc8a984f6d472606102f03efe896132f
KE3: 65ef74c8e029c14702ad3f4a3eca471fe3d4053ff5e83cecf80c873fce32b39a
bbc0c1a4ef37856e840499b1b9429bce75da5c26bfd6dbb0e7158f27c386537b
export_key: 552f429a03eaaee1e279568156fa3c60e9720599cf6bd909d00a56449
091890347ec14071dd3cb28efb357bbdf036a4a53979fa63cbb27e90acd8a999881d9
3b
session_key: 256650b139afdf838a6451be915b66d276756c2458c52eb0919c14ef
d6b7feb06203fd22c0024ad094af8e793b9988e2b01f27c1c9cb0309c90677e098fd8
cb5
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
oprf_seed: e6b20825f3bcfe4f919cff24f36d557fe8728c76628130cf8abfcc1cbb
f14c485798c1cbce1c4d49c49845f0c66284e8c2c3d543177b8cf64acca1f987c3fae
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4dc5907e24bc47dfd8dad35d68cdb51a0907528aeffffd19828b0
0cc3bf65365
masking_nonce: af4720f9843fb9334c6fe2462fb09243c9f2d8324967f28307b3b7
cf0ac59bd6
client_private_key: 80b8326dd0c2b506b88b0b4025c0db89bb624a8b94861078d
88f88515adfc5374ba9326bc531c7ec458fa14a482339ce7854b1c044ba083b
client_public_key: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e5f
4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948ef
server_private_key: 5315b843996e1c8dab628f7848b29fd8d4368a414eaaa9110
da1cc53752548548f132674a235f9ee105780d4ece5e1a760c147f744bb450d
server_public_key: bcd8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93
c99e1e9dc14db5c9c26b09e1980f7f5b45774012be6234ac5a8953ff69ef28
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: eb2c16a06f21e5b8e27409de2d760465986263ba054d68622275447
d98b13df0
client_nonce: 6d1c5b561246dce4246f69fc754f0b205ab0912710dfac12050f29c
af06dc23b
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
oprf_key: 5d7fcd1cd34d7cd7df93a375387ea88b68c0313cb22c2ac2933eea6eb33
9a627c21a162e5bbdbb20de7beb4420ca0b24e45faf9ec43daa08
~~~

### Intermediate Values

~~~
auth_key: b640dee8dc801c282157fd87de2d0bdc0b628e4835185435e8fcfe65622
63c35268fd0d5140211d4636d0e3192d26f695f588f585c84cc427b3d8f044aed2d81
random_pwd: 537f37db5b6ea8c5dd4037f20d19bcad5b82cea1851d43c1962a92662
7f8dcaf033ed4bb167d7b78f181598458bf2d38b973290019d3a49e7e299ccf23831a
e7
envelope: 024dc5907e24bc47dfd8dad35d68cdb51a0907528aeffffd19828b00cc3
bf6536561b704181a4354a6ffef0e1dd120d0a8df22cab5932791370441f5abaf0a12
bfc990e8d628c24be8a41f4ff84a3ac23ab272a535ebe94d656cc60bf7fe3e7eef25f
9abd4bd933bd4188791257d2387dbe5c61c7bae4f912c0044375fa3ada2fcf65ec078
15ef35c3b57111c0c0fcaf80fdcbed9b33e47a90
handshake_secret: 8e6f4a2b62d3c7d9a7246c701a31ac171999601a6c5a67f977e
29705a1839135d8cab98d0c5ed09557f1575e8eda5d10cf5a7d46fae5be8b373cac3e
c99c12cf
handshake_encrypt_key: 9603133e2acd11278f2c93d6bb13b75723a7ad074ca08d
09f620be03ff66f58a51142dab8e316c11ab906607714d38af07942223f0cd87b5c37
2f48e56632e6e
server_mac_key: 51b64277bd7049f156a82d6179b16209c6a8c3238ecba7118060b
7179ab9359d4d1a06286cf9ad0181da736ee13033d604eeaafa5eff3a818530f5391a
2d0215
client_mac_key: 2022023e93da9981c8f4aaa292a15b15a81e292d5e6d088a0e48e
dbba0f2188f3051f446dee2691cdc5c09ed871ce74629166cae6964604ff800e3f00f
953454
~~~

### Output Values

~~~
registration_request: cc1b854bfac5f36d7f09d18975d26bd031490a8810722e5
e84d13320bc6cc1ad88f2faefeeb84ac706985e2784da104dcfa376ea200241d6
registration_response: 1692ec3f6e60b590a35590f550ff1449363c5bf9526a8e
968c3128370fa08a8bd04f67d78c6be2014d763e103fbb2bbe8caaeb2c5923db1abcd
8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93c99e1e9dc14db5c9c26b09
e1980f7f5b45774012be6234ac5a8953ff69ef28
registration_upload: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e
5f4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948ef32fcb
931a96c5cb0393c641dc81777746bd59fbdf8f3b049cdb93fc5feb4970091c4564bd6
733b9517dbc7d9cbf46bcb23ff99392425fa866ecd21a174863ed0024dc5907e24bc4
7dfd8dad35d68cdb51a0907528aeffffd19828b00cc3bf6536561b704181a4354a6ff
ef0e1dd120d0a8df22cab5932791370441f5abaf0a12bfc990e8d628c24be8a41f4ff
84a3ac23ab272a535ebe94d656cc60bf7fe3e7eef25f9abd4bd933bd4188791257d23
87dbe5c61c7bae4f912c0044375fa3ada2fcf65ec07815ef35c3b57111c0c0fcaf80f
dcbed9b33e47a90
KE1: 8447080996dd1f729709b137aa45b6a6e68651f7f5794ec80d7aabca6f171226
e8c5ac7aadfe6b9ace4bc355d7b891907d50282031c15d9f6d1c5b561246dce4246f6
9fc754f0b205ab0912710dfac12050f29caf06dc23b000968656c6c6f20626f626e09
74f24da70adf24d24b5e267c80f6335a5cba9442a5658cdb76b3a2bc569d39ec6fedc
1a162f4e6c6a460b0978684aa5f30b3304cf04c
KE2: 12f8ee8c60a761d437ee86a9f47f83f4bd5a442c3c0827ddc60a0d87da518aa4
fce6d745a3f8a57d64291f4e55b122cd6857a44b3d006d93af4720f9843fb9334c6fe
2462fb09243c9f2d8324967f28307b3b7cf0ac59bd6911840a9cc45d2236601720633
e9c8d82772d0c6d9bc9a57201e2154f8e8c40ae3c241edbedac0467b8d60a1c534637
f460b9a9bbe0f37c601f40a02eb1f9ec9c39a0badd50ac901a7af7d3784991ad754d5
4ec16565671aeffb52f21d3d45b1e5ee2acee6778ba6f8f7641d284333ccbe99cbc4c
b5466d777790ad8dbbc362183b20b37da74022eb73d85bd0febc95db72163830cdc86
75e905524b566a4e7e575ad559fcd31cf133cdff480202c9d1d07ea8ffa618ce750fa
477ce2864bb5126135e68fdb7b2b9c8274160a4907a155eeb2c16a06f21e5b8e27409
de2d760465986263ba054d68622275447d98b13df03ab8469c97f3394c729de0b4f98
0ac06ea6a90dd077f924aac4210ce65521a90aa1ed82f46ad5cd948d1d96a179409a0
20f8a01cc86cb7b2000f4d1d92144bc1cbd5af501afbdaf10238e127ef6bbe31f51c0
2e9692feb7eede46a3e9c584dae86f764dda6cc4747b0e239c1eff8dbf74e3f174ac0
dad629f4c37110f981dada8bce1cffb56de6df47
KE3: 81dbb7d841025eb13eb3945d0f467c19a387b1fb3e7e66154843395c15624fbc
cea64e813f9c2f4c373519cf100c9d5b0fe38c0e3ab11968a2958958640b7e1e
export_key: 1f36f7285395930e4e28b8154820218306981f2ae4ecf21ff277254a9
4a0b696b5a4d097d7e42372ac1bb4bd0adf381ebca630ad0ec172d8a1bff2e9aacdc5
1a
session_key: 1042e4d648738b63996944316f9a8e4d0f0f9748780ad145303c2f62
818e3aaffb36cca624e1d2548a5bff9ab1a50303d382fcb65ea9d23b326e5c295dbe1
00f
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
oprf_seed: d627cbd1cc93f04dafd6c8d7c0e44232c655b806c3a47460d1451f2bd7
d3a2951003376a7316e08772273972e9a8520f1b059ba8541f004c07e700baa4ec2f7
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: bb399e25188d912bce364e252e853aa9e203dccf828dc96b2a640
b9e446f06e4
masking_nonce: 9bc50231edf47403dfc2f9b30b2e27f6363f364a54b0df47f45ead
5784f4b40c
client_private_key: 771370125ea54cd3f86666bcf4155379dc1e0d5e6a8fbaa4c
0e0a570b44a311701b936a442f340c21a65638fe11c0e7b3bd1c3528e632d19
client_public_key: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0c4
0dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc61844549
server_private_key: 7d455931c4f4efa18d5731a27e8ddbe8eac8be6eae6175f91
137a8cffccfcd6cb52345e2bf2ad8995f69ba5a19ffa1afe3cba5f538b0e629
server_public_key: 9cc2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8
e42262e63634ec59d0431f3878051eca9888bb45c17a68359bb55071e6f6e7
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 22706d38c42c0466f2c0ce0ded192c1c605b890fda0d4a8c106f239
a30eacf63
client_nonce: 0908b5c76d90adf085ce0cbb2ea610b1b3ac506f37e519cd8ac3b5a
3ca6987db
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
oprf_key: 61870602018249e3901f48416a2c9c219548b70789278bda8030f5526b9
188dbbaadb92c89dfb176e6aa32dccd63f94bf4354163f9839806
~~~

### Intermediate Values

~~~
auth_key: c90bb991dc1a13257d5fbd8d1569e235da5b73b36e04fab59a20997ae24
a09281a33adfee879325f5cb655d953b0f7d6722436ec3239a42ab6efbee142d0de23
random_pwd: 2463867198d070e0e104fed31fc14105652537e737057e9696dfb1341
28ea80795a47667dcb77571aee9de0ce8b3855cbb069b52eda0a2f3188f093be4a3d4
f3
envelope: 02bb399e25188d912bce364e252e853aa9e203dccf828dc96b2a640b9e4
46f06e44418f81bb6508b09195de52d58f38bf0b8601be14f6c9d94d32706bfea3ad9
ba7cb79325a05dbccabe02aa609e5423117f7dba738a08d21bd2f9975721ade6dec1b
646c2f2e0f87859424fe1ada252b90ee377474ea918dbdc09169bd4e673bded85592c
0191f9f31aa0363f61421a3caadcef3282ab754a
handshake_secret: 1561b63e65b340c7dee2d8a9d491b3d7b0dc5a38111cea5bfbc
0a6bbe86d766d37ff330f7f4b4f8965bf7b573466336e63bcc956c8a380f22d1bbaf7
9bb2d0da
handshake_encrypt_key: 556b2974f03a11c66e4d3ab66acd249ae7d2bda1a3bed4
d25200f916ecb59bf46778037af1d57da680e9d32f00af85457eed4563df4d7c035a0
a8f704c843b00
server_mac_key: 5c7275a75e657013df23c34531a234c27d1a877f5a03195fb9fe2
0e4beded05778bfbfa0458307934333c6f4456b7f1b803e3c34bda89a11bd350bff6e
01981a
client_mac_key: 2298304a6cbd0fbff7c760227ca879b48c86212043b3b0ca7e23c
ed1190ccd30d837bdbdee5b6d37300e7674f3df1bd7561a68876bbe8dc09286f72b0b
6817a4
~~~

### Output Values

~~~
registration_request: 88c032a418dfb1e1cd1a3324ba5992452f93c66edbec9c3
65e92c1ea793cf76c05ae910ae194ca9c51e885d3c2bcba7d76989d0d824ace6e
registration_response: cef071fca2a6bbd9992a7c26a2d6ca21ade5e9267fbc4e
3570037a63fe78c58a696970c23ba6bfba27a3f95ff5f884a167bbb522a841c2d29cc
2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8e42262e63634ec59d0431f
3878051eca9888bb45c17a68359bb55071e6f6e7
registration_upload: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0
c40dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc618445495d14b
9a54f181dddb4d989b01d8546c162805b076bc371fa414a04c830bb455fc4fcc25642
c90292b0815ec06973ee6a036d9308f822404fd053af509e7ccf8502bb399e25188d9
12bce364e252e853aa9e203dccf828dc96b2a640b9e446f06e44418f81bb6508b0919
5de52d58f38bf0b8601be14f6c9d94d32706bfea3ad9ba7cb79325a05dbccabe02aa6
09e5423117f7dba738a08d21bd2f9975721ade6dec1b646c2f2e0f87859424fe1ada2
52b90ee377474ea918dbdc09169bd4e673bded85592c0191f9f31aa0363f61421a3ca
adcef3282ab754a
KE1: b4f7627e7bdcfa7d9112301dd0081a3f51cf7e8853eb48a16c9078aeb0dd99b1
6e691ec45b6dacb2dc05b62f0e09c124c94b1b5390a68abf0908b5c76d90adf085ce0
cbb2ea610b1b3ac506f37e519cd8ac3b5a3ca6987db000968656c6c6f20626f62b8de
36842175636d346164767aa834a4bd1a0abe805678ced43406c4a09ce40145f03cd1d
620d6b3932243017098851f7003f34a849e6c46
KE2: 18222152f022ea1053250928771807c1c47ab0167857bb75ba986a8c827d699f
7b1e49a183d578839edb2ede61d7b4a1824246c7edc354689bc50231edf47403dfc2f
9b30b2e27f6363f364a54b0df47f45ead5784f4b40c9fef783c402f84ad8770f26e03
a757c921c8a2b8b2b7094693c228e5db58d7a7b961d6deae37a0ae2ec54c51aa0c2c6
f89674463819f4ca605dc7e5330680526316a3b0673232f9faa76a5ebfcce43ebfb76
37982fc72dcfbbb6fc2822b8b0946e900065f1af6509bd206cfabfc83e86b0e6ff6df
e08d852d73d706d2b997aebcee7b2379934c8051d4ce15eb163f56af8c3441dae05ef
3e3e67595ee3980e61db4872458eca64b96092bab17049d1e4eb62b89a37f149d57ae
b4fd75a5f87aab5cfb1c2c19efde44c7d9e157e663c304522706d38c42c0466f2c0ce
0ded192c1c605b890fda0d4a8c106f239a30eacf63b886b2c735272aa37e700b602ed
cdfcf53f73ae463d94139dfd0e173feda40f8ec315c59dabf8b7db0a77cf9c3e5b352
8688b01849fd3523000fdb9b9cd64a832e90957ffd8002ef003a22e6362244418c08b
7b83f8e0a4e3148dd10e246bbcbb50382114fbb12f261b9921358105a0d476a519644
637c1b4d106e5df2dc59615e755c198da0bb7375
KE3: 87c1c0c1dea47943f824dd98bd8e97ae5d308abf1e7141cc26231cf6d8ec24c2
499dc7f06eb497eedd222c7b8bf28bd7e802fd3e541625056abf0a7496b35533
export_key: dc601e1395af332198f662f6488bc624695aa26e7c25583703716d3d4
dfbc9d85833b07b3b795c5ccc2b55a2a25179753194bd3900b44bb944fce54293dbf6
f4
session_key: 463397cc9340917aaa834f63ec0aa2660b002617e18ac750cc6b06e2
fa8ede46b817b22eb5089196a0be4b188406578ad9e79c71255b4defb705399f396cc
7c0
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
oprf_seed: 4fd359d7c180f2beae897b04d5ffab9deec40a2f37cde226f22883f03f
590951
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b41547b074efafe0a45ad3e88bdf4619ac76aedb0ee5f6c87857b
65753f9faf1
masking_nonce: 5b20d5072a59d8f320319222522921e92bd8216d6be054a496049f
c596695fd3
client_private_key: 5b1a8d0d1f59318d1a325244e784530a56f15f95cd7594b41
1ea8f7ac77652db
client_public_key: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430b5
2d36b1ccc475cc8d
server_private_key: 40e02b1164d21f51b8022acbceb26069ac5ad37af70212b20
1e18725cb41a5e7
server_public_key: 02c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1b
f7dafca0807eb046
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: df748545b8ffdf82a1b5f464151b2de7276c82538fe91da03eb81a9
e99dee3d4
client_nonce: ad96dd1a5e7e67554a19c293ec68c7e4ee7787017e321b3a1773454
3b536834c
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
oprf_key: 3737cf2e7d7ecab578e817d0b7a91b34df5fea33b201e73d9ba2550be06
8870d
~~~

### Intermediate Values

~~~
auth_key: ae6c30d353930511385763111e606551a96d1d541ce2bc28870d2b3d35f
b7402
random_pwd: 494db709e8404954badd332a7a3b8bb25f810799fb056fd202261284e
f2a0991
envelope: 02b41547b074efafe0a45ad3e88bdf4619ac76aedb0ee5f6c87857b6575
3f9faf1d6a84db9cea87cd020686bcb672b88ba2c9484e32c893d36566b5b6df96803
e667cf7b47e652f2737b7aba50fcfdf4973e92c11bfa4908a8b5c0458b8c343545
handshake_secret: af209481ca9190d43920d41e7d9da2c6efc1f8da9d02aa116d0
553ac34e1e7cd
handshake_encrypt_key: 5dc0e7b998838c117c0c0d551c0fbb1ff7dfa4de3bc084
3fc5ed284fcbeca5d7
server_mac_key: 106e678dc44a470264473a0d18bf8ab0d11b34e450df3f357458e
536d3e6f519
client_mac_key: 3fdf5419e1c340268f1ec05b7c32474f67948d9adc022d50ce396
d2d4ce5f7eb
~~~

### Output Values

~~~
registration_request: 039ae9435af572249db38975b192f1beeac30ed093c4d9f
40bb5236d3521035ab9
registration_response: 03155a603f71d7cd853ff5ebf0eb1503215fc6f89b63f9
a3e1a818bc373919dfba02c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1
bf7dafca0807eb046
registration_upload: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430
b52d36b1ccc475cc8d9e5697dcf2e9c993de093858dd10b46dee565005c3bf0a6bee9
56306485508cc02b41547b074efafe0a45ad3e88bdf4619ac76aedb0ee5f6c87857b6
5753f9faf1d6a84db9cea87cd020686bcb672b88ba2c9484e32c893d36566b5b6df96
803e667cf7b47e652f2737b7aba50fcfdf4973e92c11bfa4908a8b5c0458b8c343545
KE1: 03f86d270a693da19f82b655d8ffe6a26ac2b79ef779de92012d7fad3e15a7d1
5dad96dd1a5e7e67554a19c293ec68c7e4ee7787017e321b3a17734543b536834c000
968656c6c6f20626f6202496d129c40fe6d255d57f6d92af5c0cf0ba277e8a0e7b67a
61df2dccd9b02c5f
KE2: 0378ecb31237540564e8115484918d6f07042b087ba1bae61d8f2c02bdb1c48b
0e5b20d5072a59d8f320319222522921e92bd8216d6be054a496049fc596695fd38c1
7171fe33f8075bac84b79190b71f02396767f5e73e8342df5a18d599805881a559e38
6a9f17c27f87e5e2bc66b1d99f1af6f28effc2728ea6e386c86bf890532322c5ba433
a33754627c1da03d1d67c746ac5a8e0bbd0e630d23d06b4ad5a8ed63113a7b9286e94
1a5de10d66cc15f39461423cbca56eb3539541e96251558049df748545b8ffdf82a1b
5f464151b2de7276c82538fe91da03eb81a9e99dee3d402c5583ec9a10dfa32344fe8
000007904dacd5e6be9eef27b0f94b50605b017126000f2a0049f4969a996d4bbc3a1
1ee70749c9bb94503f310b912a44155adb11a8149609bfbe71a80bc353995453f9dd8
e6
KE3: 3f2cac5afbd4a0e0db36d05e12cb1259b97c0bd5258f09133d8b5c9ae292932b
export_key: 2b27ef6ec6d92f31b5fe2a92fb09f9ec31aa4ee5cdd187f52b1dcb1e6
db88dda
session_key: e5644ee942124cf15e92e7fd6aadc2142cf1f529283bc170625749bd
b480f48e
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
oprf_seed: dc4bf89dfe1cc1813fe3a08293b765b3af747bafff704d543b306d3fed
11ff1a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: bd3eb740b125ef0ffa72def6a1c0eb410af4a26d097b82cfcec50
250b1c28d66
masking_nonce: f06fc89f7736596190779a2c866ef432f8c1fbf8f8c22805647a1d
e2c8a8ef6f
client_private_key: 03be3245a3830887fbce88f3eccc26f1639b91aa8f043ae61
75d146de19bef1d
client_public_key: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a264e
65baa2434709f808
server_private_key: 6a62ab611cc2ea77a7fcb3565850ac22c6d3a18b19541fce8
3b070cfa802882c
server_public_key: 02e1249c0906886b33b0ae59c981001448f2541fb718a158c4
b4f37d391e813fed
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: c2aabacf3171a1f764af1d9e5a5bc13422431aadce850e7eace6ba9
d84b7658c
client_nonce: 1733a0a3ba31c129c2b5884b15efdb4d80a513fcf292bfaf6b01190
ee1c3fdd2
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
oprf_key: 6c396cdcf3a7198ed2e48f9f92d717cf9db476597799a710a89b528e2d6
ec21f
~~~

### Intermediate Values

~~~
auth_key: 795612119e1edda3c8ef6e58962ca0af62cdc92d6298bbd1da04324f63e
ef73f
random_pwd: 1792aeb1740f1ed861009a53257913788163a1438009562c9ca93a8c3
f9b89a2
envelope: 02bd3eb740b125ef0ffa72def6a1c0eb410af4a26d097b82cfcec50250b
1c28d662f5197b89b3d4015a66835bd467dbd63173b9a12055d30b89b7ce0ffe38f63
7060f236eee51588428ab4dd01b61e6245794225522798479126674e51c0b363c8
handshake_secret: ed7207af119165742d06a475673c418aa0a2033008ecdeab4fd
55d1f094f89d9
handshake_encrypt_key: 2159c76fb58de0d16b9e303be73ce8e9e9b279f20da533
43ecc7585e0ae638ea
server_mac_key: 761c1aa1dcd058a14fa4f42be15a9bb9f842a9158334d247b919d
1c11044adc7
client_mac_key: 9f9cf23cb4cf643d91ea59da67e31f1d3ef15d5e5764aa1c95827
342f0b70ad6
~~~

### Output Values

~~~
registration_request: 037a055d502f2a882c021fda1ec2fe8e5d8cd0d2a913e5a
03b1e27e0fd06308275
registration_response: 0373e98775b93c744b7ace76b2f00df943a41194c72aff
4108a0c2aa686b2c6e4202e1249c0906886b33b0ae59c981001448f2541fb718a158c
4b4f37d391e813fed
registration_upload: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a26
4e65baa2434709f808f2a0dff8e4d935d06cdaf3f1a45cbcee7f6d8e299fa70017fe1
19a42394ec72102bd3eb740b125ef0ffa72def6a1c0eb410af4a26d097b82cfcec502
50b1c28d662f5197b89b3d4015a66835bd467dbd63173b9a12055d30b89b7ce0ffe38
f637060f236eee51588428ab4dd01b61e6245794225522798479126674e51c0b363c8
KE1: 02e532d2687a979f0a75112437e1f4c6d5411c555b2330a8d6c45c7c7c657aeb
b91733a0a3ba31c129c2b5884b15efdb4d80a513fcf292bfaf6b01190ee1c3fdd2000
968656c6c6f20626f62026ec987d3b7ea3ef8cfdca092b9d6994d134e933a5fb78929
5335d5f6956399b6
KE2: 03532d5386303f1dd35b05e9130dadaded77e8cdd000a76cf8acb92f4b68417e
99f06fc89f7736596190779a2c866ef432f8c1fbf8f8c22805647a1de2c8a8ef6fb03
55d3fd2f0c9c93966b71927c0416d5666764926035c70ac440a947cada8045494f02a
73f045010a1ee98086ebe5aed5ab73b50d7e2b9fa0dd5335b3c5de49e3cfbbcf3ed60
5e5196c8c33781a2e1da8a1252a23de36ab5b1e071838d9e6c7ffcf5afc5a8e55c2b1
491ea6dcdfb8925aeaca7cf6e60267d5999cfeb1f7b68c4a9bc2aabacf3171a1f764a
f1d9e5a5bc13422431aadce850e7eace6ba9d84b7658c02178e9554d669786c2e9349
f1e178eb84961a7f8073d9ecbc5cf52bc2fef7791f000f97988e835a857c60b36594b
ada87e5ae0dd58e54f91a027c8080070fd2d29091512baa0ccd6dae526e15795140c9
ed
KE3: ffbe8ad789beefd6052edc9646c73a40ea65fd4aa01fc14a34cf2e640fcbd100
export_key: 8599c918d62998864403994ff262ad8b1b0ff159dd8cb87009213d2b8
84bab18
session_key: cac30a81bf89cd9a2132660552793c7e8840e53810e6441cd6b16f03
4d767690
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
oprf_seed: 3d272a34b21b5d294bfc2e738ee410ec1f146b72f9f6b4608ee96905d0
aaca19
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4bd5d0f743ed3c12a5d74101fa8f28cf1f5eb2f38ebd27332da06
cc46a0d7345
masking_nonce: 0d0ddc3f3f22d82d432f0b215e13e237baa08ce36c7d56a9caf046
5eefd856f8
client_private_key: eb7d0ea4bf06b78e3ed83cb2d3feb9683cece55d800eb5196
e9304e50ac61518
client_public_key: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b00
3b652dc03e8b5304
server_private_key: b4cd2e42c0bbef01350751994440026574a20f677965ad056
1acb622a32651dc
server_public_key: 025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a2
5b74538d149fc226
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: d0e49fbc3f3760b33503cc3bb5ca1aa34bf4927d6f4a206cde89598
fe56af75c
client_nonce: 3612dd7a3fb7c23f86d7af812be63f6db8e6ea71dfc543830bc51aa
7b3930e9c
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
oprf_key: 74ba9cbe8945b70733b26745ee91db21eb09c83196822b50037670ac82a
21f1c
~~~

### Intermediate Values

~~~
auth_key: 1a27daae8bb66354bc771bb7aa7b1ea820c784a71181fae7e02359eb0f8
531ec
random_pwd: ada36c65274b5b1b625ee8065dd76b042d7b90f21f60db19f5b6f1002
04b418e
envelope: 024bd5d0f743ed3c12a5d74101fa8f28cf1f5eb2f38ebd27332da06cc46
a0d734574eee1f369faafa16eadd18d2931e872cb4ac9601fe4927f2bf5b8db507e8f
6e63b6a99927805c2be3f65020617c7cc301a48b28811ea50f7d0ccb995ce7c9b4
handshake_secret: 522e53fed8892023157a8afc327622cbffdc6288ef4aa574294
085e8208ca526
handshake_encrypt_key: 4b284e7564508cc86c219c513c736f8b937542198101d6
0dca1a42a99f725b83
server_mac_key: db4f5ba87b7965a38970a261be252d7877ea879cf28c4b2b5ebd6
6c9532f9928
client_mac_key: 5174162e8241402820812e09e5e0c0355fcd6c749562dba48eb12
5c090598e41
~~~

### Output Values

~~~
registration_request: 029ead8cb71d9f802fc71737e16f75eda7843e5b961c9ef
0bdf8da0cb97a6364db
registration_response: 0274ca47d05d7ed75c1700be5d5e3c9d82e0c827bde93e
dd77e8a7bfb453406ade025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a
25b74538d149fc226
registration_upload: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b
003b652dc03e8b5304be00a8dbce81af97f43886fc1479d1f2cfb1a79bd9bb96673f4
5cb6ce759b3d8024bd5d0f743ed3c12a5d74101fa8f28cf1f5eb2f38ebd27332da06c
c46a0d734574eee1f369faafa16eadd18d2931e872cb4ac9601fe4927f2bf5b8db507
e8f6e63b6a99927805c2be3f65020617c7cc301a48b28811ea50f7d0ccb995ce7c9b4
KE1: 03fbe22a5b37f7345b2370c51a5290091f5af7b21cea757ca017b2a32279b543
f63612dd7a3fb7c23f86d7af812be63f6db8e6ea71dfc543830bc51aa7b3930e9c000
968656c6c6f20626f6202736055b3c97c36bc8e7bfe53ae65bc38c5be6b46adf3d486
81df7bcfeb96770a
KE2: 03cd6e28335c91d55ccddd9fa21e372b05a6d7c47ef2671eafbda6d41e9fe216
c00d0ddc3f3f22d82d432f0b215e13e237baa08ce36c7d56a9caf0465eefd856f8d5f
4399e5d86969cb1309ba885fb8e48372d954e05c576f8f834ead83a85d27f9c6681bc
0653678e614399f2567f9ca79c02db43442b96a66009e4176bee07743f9ba6f70d9be
25f94e76d9db14f7c23f3d8df64736bc85d748c8c7b1ed2e832ddae7b120da7a405a4
c7ad82b39baf3714d58eea2e6384a2860cd789342863dfc76fd0e49fbc3f3760b3350
3cc3bb5ca1aa34bf4927d6f4a206cde89598fe56af75c03981bb9a42c6f60750d2c90
98ec0e64d52dc1ef0b4d02a20b2ae9ce40b425a389000ff154625c158e96425855f1e
b20854064b1e623db6fd418a43a9cbbd19b0ecdd38f8b2056db2de3b5065ec774b63b
cf
KE3: 0721f7dec9da0da92cadfa922e10afea51c469872b8f74fa47e7c14d513dd31e
export_key: 8ecbc5f5b9548659e77461dd5f6632f77040e768c5b76c58c62d912b9
a003dc1
session_key: d497f7f172a21fa336e3b9390e6bbd54ba81759c64acfb310b4c3c5f
607f3bde
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
oprf_seed: f45bde97288aff49450b9b707842cfcd36b729c59d884b1137b9a54990
178444
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 7382d6d3106ff199b0b7fd380f182046fb37b6d3da32f16c66dd9
e8c184e02a4
masking_nonce: fc81679d560b046e7c1d4dc503aa0d87535e5344e22842903f73ba
8331592e99
client_private_key: 02c14f564a29a05e39d4b9382c20686e41faa8407f03f5d2b
2b111efcb64be89
client_public_key: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f89a
da3ab1d4b3f89098
server_private_key: 759ebff988d2878fc2ac6619807ac6625d0ba08ab0d6c5a67
e15fdbd8e329839
server_public_key: 0249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c5
e37937a9187772af
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 3e50000eeed8544658506dde4b60ea4696f8cca1cecf28ae7916eaa
11511426e
client_nonce: c6274871b6a51a9ba84022928c1c44a564f9339b322899656a12ee1
16a439303
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
oprf_key: 0e9347bbf9acaf85663c3a2a39dffbbefdafaff6baec4d814ee337af7fc
6684b
~~~

### Intermediate Values

~~~
auth_key: b473dfbae657ef42ca740469351f683a631c5d5a88890bcfe66cda4d72e
84719
random_pwd: 6e87d6d2179a05f33f6a08d45c2aa91ff48d755a8c2c678ee9c63eaef
a5d002a
envelope: 027382d6d3106ff199b0b7fd380f182046fb37b6d3da32f16c66dd9e8c1
84e02a46fc846493d30c26d7a7c98d14d0950faee4445653f3c56197983d0c2ed0061
99af88288fc0f647faac4279ad99d30f8d1fecdf5c31b6bf22fa3c67d79fc320f3
handshake_secret: 47da764c966e5177c0eb9d7547f72ffee83d154849bbf5fe692
5316e3f5057e0
handshake_encrypt_key: 01649353115dda3340cfcc66f7bd67ea014e25dead5c6e
a7ca04b129e375960d
server_mac_key: faca634fb10b0dc3883f01ed327720bfa34f743005a6ba6973c86
7f9b4ba1542
client_mac_key: 309115092babdb316f81cca3a6aac59bf07888f008ea0027b0803
e0a356689c6
~~~

### Output Values

~~~
registration_request: 024ff8b8c3636b93127c0c5350c4d2e64b47c78837d6edd
ece7dd67a260bde8085
registration_response: 037793685b7040a809ad13a06090146599c327887e95b6
9378a10180b8b06e8d3f0249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c
5e37937a9187772af
registration_upload: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f8
9ada3ab1d4b3f8909891acf8bcb143814e7e3aa133e4d7bf3399ab1d21cdf8c63a4fe
853461f84d4ad027382d6d3106ff199b0b7fd380f182046fb37b6d3da32f16c66dd9e
8c184e02a46fc846493d30c26d7a7c98d14d0950faee4445653f3c56197983d0c2ed0
06199af88288fc0f647faac4279ad99d30f8d1fecdf5c31b6bf22fa3c67d79fc320f3
KE1: 027694e256efc51327333fba8ab1927b511c4152f93ddb0771370995407b4b25
fec6274871b6a51a9ba84022928c1c44a564f9339b322899656a12ee116a439303000
968656c6c6f20626f6203eeb46969c8d3c0ff2160547e2ab719958b7e8686ca4d9b12
f604883194bb90a1
KE2: 02994e6e43b6cbde4fd5aa5c9f454df7a9f0b223ba987f77a99361b88b743cf4
2cfc81679d560b046e7c1d4dc503aa0d87535e5344e22842903f73ba8331592e99f56
b9ec96d7e21e6f8d15e6fc1d6f4a2cad2b86ddff3bcb5cfe1b4f5e2bf5c00c2b2a1e8
64b3fcc94d448cd5d795023d5add610df8fa615d777b9d3d3aa984420337d343ea17e
fd3e074d50328214cffab82ac32c8edbff3df0b95b6dc7b0744154c4dcc505a47e825
1f586cc46efaa8b67842655fc9887ca603e4f015c88af2943a3e50000eeed85446585
06dde4b60ea4696f8cca1cecf28ae7916eaa11511426e03a05823236f8f28bd60569e
51b83712e6371b7006059bb8542216c9b9ec73ae8a000f9bc5258093a929a82511daa
2498ff2e503f8b89764f9e012cf4ac6e1b3194adf7054763a16f7826d372f042413cd
0d
KE3: e0c8b26b010e308edfc06ee25a96ca5b9914d439050f4ae9a91c987cec5c4f9d
export_key: 2d7e9079de28b5e4639f207def3d138984d827e6ef868175987d4eecc
9b5e562
session_key: f2c63e3d2a34979ec9304003146291e08e3d6afe6ce22de213148274
563f75fa
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
oprf_seed: e88cac5492e62ecb7eb1d57301fef4179f08573bb7bae57fb058f52d35
88daf01b284b34573547843a654816271a6b25414d7812a95232b2de2ecbea7a0cddc
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0c95e8d40fd1a59b1dcf111a53dd34d55c9e02a1a733e29658bc3
c854324055a
masking_nonce: 5f63c1fc91825ef7b4c01e7119a08c68218bf3b7233488edd8c642
c2241a01e9
client_private_key: a052da1e7263802eb5ea90bc30ebd07510b7997e0563f04cd
b0173a862ea1adfe5ebc2d261008f3dfe97647b8ae9d6d8
client_public_key: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132f2
2abd78a05172adde74d97f453b902fb2c454718c91fe403e
server_private_key: 32a099b199f3eae54592db460c87aa23e9dc4f969294ee264
5b5184d63c0e7f19fcbfb025d7dd9e32e4906883081c997
server_public_key: 02094306eaa9c62c5a873fee4afdf81c91a91556be8286e7c8
f5fadc077f810adb6bb760faf2e46f85cb0b7649ebdfc524
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: fa7c6dd13c4f2b0b40cb10e6c9d4dc199c7c9568cd764f9d63e298e
d9a3b48ec
client_nonce: fa4d84dda3843c2dc22ea445f8459f61b4c687ef67fff804f1730a3
a9387ffdd
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
oprf_key: a8c3a85d1d80e19e0aaf71419ce54c7256e746eb335bdb8f36a2a4d2da8
1bcc621f24d41f3c69c60dcc9ed2b2fb9457f
~~~

### Intermediate Values

~~~
auth_key: 4068eedef55afaf4ca07f8803ca817e487d02f0f08f15a8ed6c715d4656
1346f62ded27fc72b8f507e004f0ce4e970cee2087dc8754f29dc123eb10d51241d5d
random_pwd: 25630608b9049f1240f7506b1b4c5752988575910ede69b8668345e45
3b6795857c273c1abefe356058c28e8ae085296330c41f39208885ed5d9737d5f270b
ad
envelope: 020c95e8d40fd1a59b1dcf111a53dd34d55c9e02a1a733e29658bc3c854
324055a7544ae4ba85725f8cf414efd9334cf139794d0dbaee0910791c3821cfbae7f
a752318a24d29ae2875e43b06ca1d2c7f20dd254480f149fba9787e286e3f3422d3c6
6cc2097d54564849cf3a531cea60609349807d1466f3ed8912f35da88819ae082d481
edbad693f4d93e6794a477af
handshake_secret: 4d183e5441b94f0c5f5ba626cf333f40ce6dd4ac4a3a7b3fec9
a6ebca5eebfe620ae1d011d7d856cbbf114e8231caa79ee1f3fe65ea4e6430aa890a9
b9504e04
handshake_encrypt_key: b53eb638178fde3d236ac3f29b0a2246e7d1c48f28ad37
59c851b4db467bf1d6cd42035ff1cd1ca5c31d4d97ea69422c97a0df8b3d924b41cdb
48e01ec00b6de
server_mac_key: 821280f0f4d4ccebee711650709a6b1a8bf5cd9b5a38928d4ce04
d5fba2fcde3c4ac88a887c8f5af1a64ca9211849d72bcf874a6fceb98e7127cfc4e8a
22745c
client_mac_key: 906e47344a622f16889734876eb8df7a4b3f1dd19bac0e547304f
e53ff28e32802ce323be3a160bb5663c76625576406e4bc4b19eaed392b0edf64636c
70900d
~~~

### Output Values

~~~
registration_request: 032b5a44024063a5644913f145e01c5b787a77804a5ec25
588320d5ecea9d524c1f9321b9ae76a6bc168b1f99e7305b9ec
registration_response: 02184cbec4e3f3d2780bb281d3821e8f73bad969ccbded
31d47e42e927332be1787b80ff654f043b2aeb5df61bf5ac9f5902094306eaa9c62c5
a873fee4afdf81c91a91556be8286e7c8f5fadc077f810adb6bb760faf2e46f85cb0b
7649ebdfc524
registration_upload: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132
f22abd78a05172adde74d97f453b902fb2c454718c91fe403edefede227ba7954f26f
fc2d082980f0f8fcde086f7acef9fe9ad5d4fb971744b833b9b1c3ee932f8b63e3cb1
8e2511bcff3355b558aad8827f4ad2b7e563cf1a020c95e8d40fd1a59b1dcf111a53d
d34d55c9e02a1a733e29658bc3c854324055a7544ae4ba85725f8cf414efd9334cf13
9794d0dbaee0910791c3821cfbae7fa752318a24d29ae2875e43b06ca1d2c7f20dd25
4480f149fba9787e286e3f3422d3c66cc2097d54564849cf3a531cea60609349807d1
466f3ed8912f35da88819ae082d481edbad693f4d93e6794a477af
KE1: 03cc36ccf48d3e8018af55ce86c309bf23f2789bac1bc8f6b4163fc107fbbc47
b92184dbba18bc9b984f29c7730463fba9fa4d84dda3843c2dc22ea445f8459f61b4c
687ef67fff804f1730a3a9387ffdd000968656c6c6f20626f6203f58c4669321d580f
98b4b166fbccd6da300ef7c4f0fe19d5576d3debceb23e50b5405ac264c31691e4517
154d993fbe1
KE2: 027cb4b8215dec01c59a0c564f4a9e95c6f66e2b5dcd3d219244ed188f88a6c5
e0ebe3e200a0a81bff3a0d7e6f9f4a06c25f63c1fc91825ef7b4c01e7119a08c68218
bf3b7233488edd8c642c2241a01e92a5a9de91fb62c7d6f7a558bf788ea47a3fafcc1
2fcf88179a159cdc1bf08a914fedba0bc5cf50d48dd471db07959ab25c9e992d94566
a226531c9024cb2cff246c850886a104fdc43ce64bc3cb20b1960df3d937b05e3ead1
e5e67a98f21623de3d94753457306d641334012b4f0c66812bcf874ad51d972aeda81
3dcf8a1fb57765e96f5a8c4f8e83d6d7cc51f2c87c925d7c925d0609a06166ab167c8
bfec75cc5bc5aa724b872055fb43ead727d46de349283ea556b421b57032b22827549
6bcfa7c6dd13c4f2b0b40cb10e6c9d4dc199c7c9568cd764f9d63e298ed9a3b48ec02
18bb6548593c38236dd6991a1c556a5cfa81be6c235891e5a00cf4eef1bb3ab6d653e
03abcfe1634908971d19b9959f7000f20a41456d1d4a4f911422fda8116ae4ac38240
f131e91191217da51392cf87687a1bb0e6ef3df95d855f84126cde2752c2726664493
1e391757d8d015b4184878f55a4b3f45d3c6e8a0502787904d0
KE3: 5d763756212a1b99e7455140d5372d8831d75d3a21040857e715f60e0eeb4b1b
2ecb5017f8649640323415d16d046f6cbc07d7e3a9d10ee15fe333040a953fed
export_key: c5456b5e5e3670a3426d34779a148e3a0b25c7bb204b46f1a1ca3289c
dbe3a361a2c98cb85b601dc42bffb23fa96ebffa92b270dee7a7741e5e789183987fd
b7
session_key: 317e64b2abfcfa2381bfde28715d179a82c447b82f0e143f915b0497
9a70b0d0152419db720199562c9985403fcc8b02e4e57e47285b2b2d9a3c611e01a23
1d6
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
oprf_seed: 5d8beffa8dad029913272aefa1af98d1be95dc8f743e8220bddddd2da7
3441202027965de0dd31ec82509e59e9a30316b4ffc24f1e6e040579c3c840e966173
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ceaebf17ce6b1d9c359215dd04db3105ce5b0c73b00a257b723f4
f6098c913e9
masking_nonce: 882ca204024ceed16af052cd6d7828ab6d7bfeaee26d6fa7f9219c
412c59cbb0
client_private_key: 194f9a720f11c3f0f1613cef116e218267201ce0aa4f4f55b
68c5393aaa4101699ae3b0dfa984cb954913dea02087eab
client_public_key: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1b0
a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff59
server_private_key: d650dcda20f27d7bf4673d820cbf71e498ec903e4b3959af8
52f6d9edfa68f06f4d7ff89d5897912df4f9c633a6d925b
server_public_key: 030278df9fe8759989883c2ef9047b2449abcdbe9f508aad83
f227836ddda86b3dfe0aea33995cd76243a4319800bf8ff7
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 6bda696f9ce4148e07c063aae485cf1dadc7c035c537f72f79b44ab
2af6adb06
client_nonce: 8c7e6485fec4ee3370bc09afe8ba0feb6825902107cc0ddf15f558e
cc96884e2
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
oprf_key: eb8b9609d25f57e91daf893245f8e3b894e346315eef1c9c13e780728e9
f34ed4c32c74ecd3f653d2e2df45c0fad3f5e
~~~

### Intermediate Values

~~~
auth_key: 5775f4f3eca2f75a9b496c3a329c926d890d3720ca6e0e05a42bff5d803
d30c127da67823c27c661c4026cdc33a0efd68a3e4bd7915ff664a582f1dc336a7af0
random_pwd: fd8edec9a5cc7e61420e5b90087d07fca337294aef9c1681cd96ff5c5
fc43401e0599f027c94410c57b6183fddcbaa23935c02a641809ca59c976975bdcfbf
ee
envelope: 02ceaebf17ce6b1d9c359215dd04db3105ce5b0c73b00a257b723f4f609
8c913e9978613a4eafea7f8cc23920112a77e44d4af7a296fd764dfce1713e05c8ce8
6e12253bc9b8ef6d261c3f9b7e61dbfb19257c1a1b75d4989a532bb9fec9900ed6b56
ed964ca9d0448ca580ed3912a16079f43b92791ed264d9f2696cb47fe8bc8710edf8b
b4b58ef0290ce6cae61e6190
handshake_secret: 3eaa432c35efa857b73b046edd6e872d848ad423f2523c5b614
5a3f2e5b6bad68d377207385bb8d0d34e2a77873d6fe55d46c75d7ba0f39c6bcdf29f
4f7b88a3
handshake_encrypt_key: 13bb5d788f5b6691909dbbfdb866f747f3a902a8a8bd15
d8da04340bfbd48d5743f99c809aea6afd909533502682961de45428095588894c5a5
6f99e643dda98
server_mac_key: 779b220f7a4d025b8aeb029c9405bdd3c1b30c7bbd30bab10a8f0
35c59f8362c5a05d9e8d827e8e1e6ed36c48023bd4b377f178b6e8fc75558f584dfd3
066993
client_mac_key: 027eda048c613b5be1156f52d98cb37555d73a97b6acde2968e3a
13efe261f5fda5dfb21ef4336ee7a446b06f49d8c1696712035952406e56ac254ee34
582d4b
~~~

### Output Values

~~~
registration_request: 02bc8b8b2d8b96ba8f527f59dc0054349f0fbf4c7cda280
480d643909db6a8dbd4bcb455cc374050d8cce29147fab0a020
registration_response: 034f6dd095fe922cd7953b813884f93e865177dbf35783
b3f6579893c132af7cd3b25cb000e45b296001b0598c8b3e867c030278df9fe875998
9883c2ef9047b2449abcdbe9f508aad83f227836ddda86b3dfe0aea33995cd76243a4
319800bf8ff7
registration_upload: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1
b0a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff590d5d6d39a50938ecfa9
5dd741525e73cb2cbbdeabf4e1cdb31154b43009bfbe5204e2bb84cc2e9fb028e2f6b
9a788fcb24c0ebe202721135207c70fb0db1f50702ceaebf17ce6b1d9c359215dd04d
b3105ce5b0c73b00a257b723f4f6098c913e9978613a4eafea7f8cc23920112a77e44
d4af7a296fd764dfce1713e05c8ce86e12253bc9b8ef6d261c3f9b7e61dbfb19257c1
a1b75d4989a532bb9fec9900ed6b56ed964ca9d0448ca580ed3912a16079f43b92791
ed264d9f2696cb47fe8bc8710edf8bb4b58ef0290ce6cae61e6190
KE1: 0258fdc4ba750f504274ff4644f2f43a75759b77adb1817c8686340bb28059b2
af91d82801b94bbcb8326cc2e046a4df518c7e6485fec4ee3370bc09afe8ba0feb682
5902107cc0ddf15f558ecc96884e2000968656c6c6f20626f6202313f18385e0f0c3c
88f3e60178a6727c9023e1044973eeb676b9a17a398424b1074d5e35246fc25be8302
8853dc22f1d
KE2: 03fbc2d27c0e8de042fe6b6d35b907b183f4c422d48ae155368cacdf7c345b6f
84c74e3c671caea95be56c2468a0504403882ca204024ceed16af052cd6d7828ab6d7
bfeaee26d6fa7f9219c412c59cbb0ba2421b6a4f00dbe556ca6b10f4570408251f2ad
aab1aae6b04c0548d07c503d2b0ba034a867a5d771ddb6d3435c482e762f365c9bb6c
e0d4d95c41e2943d18108196615deca5e0d3699621ed33d1f653b22e482c387dd310b
04f10a49eca3594f2fd3c28522317a35bff13d7576fa160e128b9f6d5a194a71917d9
adde805e14c435c72a29b189588601d043a15ec62005ad02358ffe5f6c9ada0f5a7ed
db8596b17db28684c86023a1f037d4ca608def1f3d63652346fbd3a6de52a234cc1fd
01c6bda696f9ce4148e07c063aae485cf1dadc7c035c537f72f79b44ab2af6adb0603
ba3e99f4c2f39463fe214e7607ca3e9b1f6112d565d80bbdb388f52437ec89f0da6b8
0279e10382bacc7cdab25a3a830000fdae2036531b0b1392ee56240b1d1569f955e26
1373412740bf1879db8e52653dc64a0ed1d2fdac6be410e7813cc1163f71e310d99ee
89dc089fdf568f6626baa18cfd8ede62cc7abd0fdb4aa9a271f
KE3: b599cf6a983d9a02d373379712dfcce283efe50ce5863a548331e5f297b89374
499943d48cdc57e1ac07f7e629c13335b5d52d23880033546e0e7d21022d890f
export_key: 639ca972192b5e49880e079a478989a161b591bb26f624661ec2f4e5d
72013d776e70b28dfd06d2b55c187b2ce3367946340fb8ee614846ad051683f6cd0a3
72
session_key: 1bb6d143c98f2dc66343f23388754feb6d06f3190d8e140bc078b121
9412c7a1ec03955829d4cd2bab120287d36899b30e20e7d0a9bf146e8eef6b47fb53a
a50
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
oprf_seed: 52d80ab26e37041371099302ff267e98fc911a153f2e09bd3d53ad70c5
f0c59a10760b75d5f56a6bd2850663c6a95ace3c1845645ed9d8fb34a146919c9a289
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 91ea73cbebb3279bf5042fe72fd1f88bd827af91256cf66a1d977
c6b7f7b3090
masking_nonce: 98a030401431336bbd795cabaabcf24a53f0d04cd5c13878f2839a
138fb9e371
client_private_key: fd62874455ee10870acb5cd728e1e21943e18c3afc1fc668e
18c48250da37feea7768de6574b8b152dc64790a0fbd8ef
client_public_key: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab18
f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef0
server_private_key: 9364031f78d6cfc1aec5bed89c718d3c8ff87115ed1526fde
d4495afe150eeeabc6195e48de31f2a5b24f798faea51fb
server_public_key: 03b73b7125c1d9517a42d63bf21b0c3eeed2b4f76005f72478
de3440dda2a2a580ef58077c145719505764689842231b65
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 4df0c15dae8eb15be4e68df854d56ad65646a69e009227459ef9843
3ca5c99e9
client_nonce: 891c6715a7a1cb68a8c7c10cad27556e86b7ede75d9833dc49df3ff
eeeda0183
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
oprf_key: a10332e9deace18120659375cb28913dfc57ee6525603cfc2f07724d1bf
c2ef016f317729935289ac354e2ca398c7bc3
~~~

### Intermediate Values

~~~
auth_key: 22171b508171e4aaf70a80020800944da1dc54a7c26c41618aeee438fca
34d1d0f0c14387486515dcacc58bf58225973b3dcf5ae5e7bd31ad6c69db9b8d1fe58
random_pwd: 678c3c0225dbdfad3d441180fc9fc0f75cebedb0c9ee38bf0b2ecef94
b913cdfdd65b808fdf0c01152685278ee764fa545e47bc78337286991beae4a640eaa
f8
envelope: 0291ea73cbebb3279bf5042fe72fd1f88bd827af91256cf66a1d977c6b7
f7b3090846edbd6ef7ddb10ed9f5ef5b94e741ad39d750bae2415de1fb9574baf8deb
7d8ca546d4c8c9ac4e9b052d7e1d609801f3fba7919e12495374db4704c0c5400d948
4d249b1e5785773b99607eea7ad902572211deb28be1e915024a69e8e04e742a9b9f9
2ee38278d2315753628baf58
handshake_secret: 80185a6845515d5fa6087008713f730f413656d5c306974a031
5391e6099f9684d3fedbee291dcba1cf80a3c83ecb14b6dfb691154f29b83e438a910
7effd394
handshake_encrypt_key: b06ab1745f697f38164834ea76d36602c24bc64b59e4b9
df8d51a7347da7b35db7d97426ac08d2ab0c3a915e351ab34649e7ee96f97a20c53be
3dce20a819d1d
server_mac_key: 49509ddb4bd8936514b3af760ecd163d22137eb7bd727be860aac
3122cf931551475dba7a376fc9fca305fb4353f7dacaa08342639cf7368c80a275cd8
6adb69
client_mac_key: 67caf2d0adea1962bc5bc2b4f302b798fe973908a27b0de762b8a
783e76345f20d41307f1f510c527e5a46a40539421c0f495d7bc984849d8283a91ee2
b73316
~~~

### Output Values

~~~
registration_request: 03e0ffa19f9860931638c2a6a3fbcd8e0ec673cd39615a9
d80959edda6fc8d269bfc206586f1a10b46a895f8f17e730174
registration_response: 026db4601c84085ed9252f52b9723c8809ae3adf5fe65f
c67d8aca2436f782edf1a84c842f21ee372e5fbcf553b3bcb98f03b73b7125c1d9517
a42d63bf21b0c3eeed2b4f76005f72478de3440dda2a2a580ef58077c145719505764
689842231b65
registration_upload: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab
18f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef00bde82e258e640a6545
25962f60c4947d872d8334f492e15c8324622655cb7200e74f427596ae40cd6992076
f736b34cc3c9713dd2660fb7ec13e57c703a019a0291ea73cbebb3279bf5042fe72fd
1f88bd827af91256cf66a1d977c6b7f7b3090846edbd6ef7ddb10ed9f5ef5b94e741a
d39d750bae2415de1fb9574baf8deb7d8ca546d4c8c9ac4e9b052d7e1d609801f3fba
7919e12495374db4704c0c5400d9484d249b1e5785773b99607eea7ad902572211deb
28be1e915024a69e8e04e742a9b9f92ee38278d2315753628baf58
KE1: 027b40080d3b93d00403d4e7ce1944644d57cce6241c69181216ba7323afc9c6
2054300441470c06aff071717754a2fd60891c6715a7a1cb68a8c7c10cad27556e86b
7ede75d9833dc49df3ffeeeda0183000968656c6c6f20626f6203f07983f1b0b62e77
8918e7b15aa899a5c5c9fce3af75c5a424e114f3c9bc539cb3b290c4c4705829c21e2
185ab3eefcf
KE2: 023aa71abfc1704b2c3f9feb0d344b13ce596ba3208aae3d76bce9b43ddf09fd
fe34304d8c065ce1b73e05699daab3acf398a030401431336bbd795cabaabcf24a53f
0d04cd5c13878f2839a138fb9e371d0490dd700138e7ce18d100a1b55a2e73d7ebdea
bd3f2edec2ba501bf94c0d4c1f4b492075c6a114da33aeb586c5051c2843dafa3328c
1d10336d9d5f99b7f9a21e48610b78ebb1811e38547a95545085e34e6a38a1d2087f3
4998879bfca77aea5e3366474bdb4034f2b0dae0ee801507db590f7a34d1ef5a1ac69
e38a3bae008145ccea0994bfafd55c3d8f4d135c582dbc78d98b6c8f2e4d922441ae7
315e6301ebdf293e3af5c9c38de14b2c7ed557316693b706d310f8bf7de71a319c7bd
22f4df0c15dae8eb15be4e68df854d56ad65646a69e009227459ef98433ca5c99e902
bb887f84a3158bd1a95c26114059d1064a69dd87c8813ad1ab19b0cff29b48d0e945a
f14537ac16d8f4160bb027fdeae000f8a4c9e56aeae1f51f9fa7138b3e80302a3679b
38bd23e89110709de31e207a41751a21d0e8a081ec237fece3dad0f770a15b93683cb
3b042fc720178173efa9489c8c43fc159a462bd52b6787231c7
KE3: 41f74c75bd91f5511f199ff78f4aaa218887846b6cf07044116dd766de25724c
16f7838e328de807a8a22e993ac06e692ad02847469fa1ba208a20b82f51a801
export_key: 6fad9436b6869c98c7e631c311ffdd2120e06250b5cf0de2e1258a113
047cced96653c33a6faa3973e9d39c2d3d0e0d9861f63355c4345a2f2178d4f43b62e
35
session_key: baefb0ddff8c55c30e1fd8fe20fe9e4f192aa2122eba25ee8f57af12
e30e48e6c6575e88663a13c9245f95a2f4c9d4430efe0da42b34aa58a205ab3f3bec2
28f
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
oprf_seed: 19fbc21506d57425226c8427af5107da1ddb46d2b2b684885c7f6e59cd
84f8147dc00c7a013265df1cceebaa6ee7059ec9aba4f0abcfcead5eecfbfefa6b870
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a453bb105345dec0739f8b6758d667ff201deba6e4082060f9310
9a17f2ecaaa
masking_nonce: e5ec98ccb46c60e96b30eed98adc51be0f7d9374e3553ea8cbb3e3
d8f5458c71
client_private_key: 4bbeadefc59f6beea6a2a9557781f5e37bb6ad6f76e66c82f
37070b975ef988bee3486703e469e30348af71c1050d94a
client_public_key: 024954440156358f8db7a32b042020404c7918cfd0003699aa
1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce906040
server_private_key: 8e510d60a068ab453634d9f74837185ea0d5483ac4f1dfd38
2792f1299390d98ffcd4e956fc02fe35df273276b75bd2e
server_public_key: 028beb3ce19f449deb6aa31eb19c661d4c4ba0fd08b4cc1e91
416b0c5b5ae74de003a76d68ac4f59b64b954717c4d843ba
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ea703dfe8c420fe02a48b0f198a6737262cdb571ea51f882fa4fe83
b8d414389
client_nonce: 2496dabf239db3d62652265d57a2b04c574e67bee76ec2c2fbe7df5
1721239f0
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
oprf_key: a5811818a61fc8bb480e4a63ed8408e51ed96211aad2f2f486e962d34f9
edf98ed75775b3af533005f7e8be36387ed78
~~~

### Intermediate Values

~~~
auth_key: a4121f9151ec085b1bfedbdf33ddc762a4cbcac8030150afb9b27f8194c
950435cd5cd60a56dc1b1ec406495d78a82c6d9ccc3e9a92ed4bfe3caddf25a04c350
random_pwd: 4bea38fcf03acd6c581f95d352b0b9537fd30e3ca1cb28f013c994cc8
8acd76d67fae7772499047895573f478ee94ff2e620b59189c7baa94054ddec944d20
ee
envelope: 02a453bb105345dec0739f8b6758d667ff201deba6e4082060f93109a17
f2ecaaa0bdc7b2a65899080b41bd6f787c48f31d9b617b88260bbd064465f58daa195
184435f59b99bbd4dea3e9040b3945f66be361b142c573d02d574285690dc0a7e4f38
c31b600e37f10faf8ed683e82790cd6b04ed0ed5aa81a451f2b96c11fa2d72ef9baf4
54e406a5a15d33d251036b2d
handshake_secret: dd215f34ee948a7cdcbd662c5d0006191df7faaa04a7ebde82b
b66a4f475001cfcf8f646359ceefaded45d9027804fdfb73ab4467a100d3281d98aeb
3d458538
handshake_encrypt_key: 270682a378fe75edaa5657f7412e2f0e9f38c442a25ef5
7f4b7e235ef5b7346f068d6a9cd5a6e27b47f59733a95ae649067709811ba63ab77e1
dbe98071d5f31
server_mac_key: b890ecfad9a31d12f9fc6b5a897953234f9281ff80ea82f9a4ada
f97a9720fcae28c1d9677073b355a105862ca2d0a1d4ac544a436ac94cded2a03af1f
ba9964
client_mac_key: 8db70c9a096b4b21ba147067097896ca12781cde942b27cfe0006
465fa62967e7919b5ccbea2a4f0b38761785a8f5f9982b9bb8f15b8fb2a5dceb59d0a
d5182c
~~~

### Output Values

~~~
registration_request: 03a2e55f8d839d6b162d179f9b4f886337188f731db9ffe
0ac206b54096e6a9a8f30785c33d207ece91c4fb97530fd491d
registration_response: 022c27e5f2d60c3258520acf38404545fe7d646ab06d7d
340e6bf0bb0b2f63da87d50e2a42e1409046110b5e7055367773028beb3ce19f449de
b6aa31eb19c661d4c4ba0fd08b4cc1e91416b0c5b5ae74de003a76d68ac4f59b64b95
4717c4d843ba
registration_upload: 024954440156358f8db7a32b042020404c7918cfd0003699
aa1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce9060404ee5bb0adb4037892f6
0ea73916a4527036a11542e916fe34358f33c971bc4ab7d63b1c22d17947a25e67d78
8e95caea45d8ad0a48b5fea78c0161d0c403b20802a453bb105345dec0739f8b6758d
667ff201deba6e4082060f93109a17f2ecaaa0bdc7b2a65899080b41bd6f787c48f31
d9b617b88260bbd064465f58daa195184435f59b99bbd4dea3e9040b3945f66be361b
142c573d02d574285690dc0a7e4f38c31b600e37f10faf8ed683e82790cd6b04ed0ed
5aa81a451f2b96c11fa2d72ef9baf454e406a5a15d33d251036b2d
KE1: 031b4f459c984d8a56589785181e03b93108602ccb92ef3e247651d9a9e72d36
0a93afc86dd79490fa621685779408ba322496dabf239db3d62652265d57a2b04c574
e67bee76ec2c2fbe7df51721239f0000968656c6c6f20626f6202a39a8a45c68e977d
b2ff70778f0d34c28f7cf430ca1045d4c48e6e749429f0f10b226c26cb0ab71bf2445
f6b9ccb81cb
KE2: 03a551719f2c02419abd1a7eaff67373ce4eb9934da6ad8dc108c2bc71fc86d4
1312a65ac685aebf3343143167bded88ece5ec98ccb46c60e96b30eed98adc51be0f7
d9374e3553ea8cbb3e3d8f5458c711b1cc8410aa8dda2428f602db71315ec31a9fc81
21df9d5d60d5bec935d7b3fd8f0913ed32a098f01b0ff768e704205218742e4b61bb2
438a27fb6bff5fa18c88cbf133f8da0d1c95f3ee2dded9bc0789d9f27a0ff8d166715
378e1f05ba9ebeb6ef73ed7a1597b4df97cd2a67ace51f8dec838d55685736eaef052
dc73cfe1c7b7bcb76f4a5d5cc45f74241466c600e893d3f430f00634db69ff23a1e8c
9cc42be9b24af39a6c341e92b3575c9dc52eb108bd6b27ea9e3f91e8978a5d05031da
db0ea703dfe8c420fe02a48b0f198a6737262cdb571ea51f882fa4fe83b8d41438903
6357745dab9026251b2bfb2ccd847536219da8e475cd1f2dc4842206a8452c720e3ee
24c0abe77452903c64985b76a27000f653801c9b2e9d83d638e64a3d5690dd3de7009
7b6ac2a7af2786e27cfcedbc2075681bcd6bf4c0eb51b49cb30aa711adca94480e5ed
befa8ebc18b77a195cd5ef098cc7e18a12039ec811e2ec61dab
KE3: 74f29f9db01f7c75add5eadd7fd7cc2a9af1eff5042e712b5fd31ab2a8d51055
7082b9b15fb395acfd859705d15945ef6b42cebc142eed2390c83db15a16414a
export_key: 96324907acc6da9b5f64674973315dcfeb9d7370433d7cbfb6e5d3db4
f082f454ca7d0f054506e1990e61dff002be9e2eacecd95a23120bcb82fa0422f2f9c
15
session_key: f84d6759fc77f769fbf75c94f314b8e4b29bc0de05790d7867739b2f
30643bc1bca1e2f08082bc2dfc2ee83f555b55ac417aa5e97777eeefcce23dadb1d4c
2d8
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
oprf_seed: 0b89d7b4aacd259b387e5693e9e9b8e5acd885b5f63fffafed093c8041
0462b67ad75cb6aeeb10300291aef29697838f965a9e27a14da3a69171e6adf54d47c
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 5026c2c5f99ac188a172095e419975e853b087db9b80a0eea215b
1dd47f37097
masking_nonce: f1d5fb7cb17ce7e632d298ea0c962878ce087efc67eb1ddacfd467
a9bf5b85c6
client_private_key: 01e4eb0ddc00ee9c2e21a17727dd82145f8d42ce298b1b66f
34284b8c5f884619f8ff53ea8f950ef4306d01fe5610b278f19d0acc0e752f86eb4b5
3eb5acffbd5e7c
client_public_key: 0201d6bd681715e3d330475e72471c1218aa718d96be735325
1c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf1831f
811d49d120a8d45
server_private_key: 0180674b4b34953199004d4c6ab21b6667721b3ce89a5f440
f7f2b6ff1e3748041e66ebdcb789e3bbe63ce391c04598cab4ee6b5ea710911272f2a
8ff2de75057d81
server_public_key: 03018fc6a77bc4127886d67871c03462740fc4d6fe66dc2226
365e994f8392a0b4c43cd6e67ce90ad594cb63c146011dc56b213bd42ef677cb6a5f0
1d0bd9944a9161a
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: a366b69f542570d845332be54c526114a3b14231490fd188db399f0
047273b8e
client_nonce: 94c3bf74c6abe75c9829ea931bfda6967883cc74c094301fb405cba
d997c14a6
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
oprf_key: 0188241410642afd6f5fbc1435c312b16e166cf513423c327f28329976c
759666d3f815a061c2a502230b0f78a6cf7cfb24275b237015dcff6ca1d2d782d6bd3
27cb
~~~

### Intermediate Values

~~~
auth_key: 9ccdea20838bcebec36f54b74c8c35a50b9c1c77f3fda606b8eb30080b2
baea27b3f5cbf79a87879ddb5478e32175eb59660e2a4a5780e3b38b3122b9473f965
random_pwd: c70aef1184a2931f8d44a63bf5fa9dd8d366b6c67a05f55132457925d
d9b3d5ea9aaaa5479608aff2b7f975d15208f63902ab573d25b327633c39ad86c905a
69
envelope: 025026c2c5f99ac188a172095e419975e853b087db9b80a0eea215b1dd4
7f3709794cfb82b1b86a25c07b57bce27b4c0632fcbd4357c91cbda28eca072358419
e686d8ac2f4849a8c71a1f97f244f5da11634484383cd0ffbe90f42964f5d774938b5
b02d3982f7ebe85c2023ec8c74307ca4572f97408a11298cb0afe6f4e19e63aefebe7
eb5cf56df248885f48770e93e1b4fb6a944a41cd58a904e82134c9b8a31b
handshake_secret: b88c42800574ef78afecdd65d7589d8ba9de401e5119efb1a4e
d61fb389b13a56926ca9190c208d7ba0980f6975e085c0a2d318eb45e9be6125f9bb2
8f6b7111
handshake_encrypt_key: 1229f4764172962710eb9fa06155d6e444ea7c280f1768
6544f27dd68c943aa45bff4596790f250f37577fdf3f348b031fa0201362e17cba80b
f4cf9d190ed5a
server_mac_key: 3c7d4037148ce8e490ebe9464829b7aac2bef31e28a7b9bd14b01
a6d53fd12d7c92c060f7b1930341532249cfc9c0e0774d7416e767939391aed112503
44fc89
client_mac_key: f26dd279dcefd90eeddf89afde3d2b5269c79718d952e1709f7a5
d4e54f42d6c14a00afbb73e485d2e9fb1dc8100c615cf17b259e4797fd9ed31b28137
b17b29
~~~

### Output Values

~~~
registration_request: 02015d0cf2aa22e0448949416bb4b3c246429439d4cee47
a52b3b9874aaf727dbde7f34b5112e91e97e1d98c9cb0fb58e015721456160aadd16a
d4f9a9ef2fa3d0ad8e
registration_response: 0201c4758f67013b61b6f3aaf8d4e470806751bd1fdd8e
8a2870a634e510459aa8648317068a32f96efc9ca6c9be530dcfba78e3bde8c100448
42bb61ca0b418528b8b03018fc6a77bc4127886d67871c03462740fc4d6fe66dc2226
365e994f8392a0b4c43cd6e67ce90ad594cb63c146011dc56b213bd42ef677cb6a5f0
1d0bd9944a9161a
registration_upload: 0201d6bd681715e3d330475e72471c1218aa718d96be7353
251c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf183
1f811d49d120a8d4555c4077fd3484ae629725cae798d61a9ed725f46da0708c52908
52f833d3b006bb2e8fca98a8b574c8a04fba9644d1ac9f437605e7df9b2cd54957fd0
80d19f8025026c2c5f99ac188a172095e419975e853b087db9b80a0eea215b1dd47f3
709794cfb82b1b86a25c07b57bce27b4c0632fcbd4357c91cbda28eca072358419e68
6d8ac2f4849a8c71a1f97f244f5da11634484383cd0ffbe90f42964f5d774938b5b02
d3982f7ebe85c2023ec8c74307ca4572f97408a11298cb0afe6f4e19e63aefebe7eb5
cf56df248885f48770e93e1b4fb6a944a41cd58a904e82134c9b8a31b
KE1: 0200c3bce8c2c7da1856b486576082a136f031304eeba82c3e582d920469621b
9657d018aabad67dd15d32492f0155ec944d11593c079c64c5d19088a72cddb12baaa
494c3bf74c6abe75c9829ea931bfda6967883cc74c094301fb405cbad997c14a60009
68656c6c6f20626f62030080bf524d28ba64b134c0bd0c860c8b1f976e55d94eb35d4
2aa0cae1935a185c9f7c517875877aac4aa4e909dd5f25cc6ccfe125d031dcfe02459
7af1f7bfb5ed89
KE2: 0301fdbad33d99cb67f5d532ee52b32c28cd15a44afde379989571c0d7177c3d
d25c4dc4e9a2cc157e96549faf95674db538537d04ed3fc36892b52f52c7ca68b9f09
1f1d5fb7cb17ce7e632d298ea0c962878ce087efc67eb1ddacfd467a9bf5b85c60726
f33937f561a7b5c345b061f95e168c7147c3358283451fef08d3d896de428319443d2
6f47b67fed70f0f3bf42cd8a96466ac3da235c0ada9dd465b9997805800cb92d68fd4
6987d08aacd04aacd5f7214b7fa2c8dd188023b7f1a63214af9754452667ad216800e
95e94034f9279c0f4893b71a3c53c2155c686220f30fc89db5975234166da33ef530f
1f8cec6845b3724188c9df6590e96994baf220f6aaa6c6a9dca24f6212ab4cfc01b96
56556c886e7fdfd3b8ce1cd67c9b063cb8e8ccb6a88dc45dbd49d512f2ff032da0901
84af59ef1a71f810b0409429b226921fe002a867cea366b69f542570d845332be54c5
26114a3b14231490fd188db399f0047273b8e0301ff9a97a3a4733b144d38330209bc
ea5a6401eb4e08e0697ac4dcb8369e20d76d32c34b619c424d643dc47bd680c0ef665
404643d2961ad051a7920c318ecd948f0000f02c5168e2f51a6dd12ccd98f676d2f43
8cdfe13762277864358aad7d7172322eb849ed3bf4f58e5711fd231004aa09f1dda6c
953a55c36172517c6e48b4434e22cd5e77d1acb97583c732b99bc5674
KE3: a54936856b321509a0e68dd5cf4591ac29d77ddf9f195d74f94def5cc13a1fd9
17e1e3272881409f79fd2a10527c9375527d73b71e28bc8121378704809a438d
export_key: 95238bc55942a8de35dd57c6364cc4eb42cfe6a277a8e1078b82cb9be
22a979b38c0fb646d35c683be5e10caf28d4f6355884f640df5c0ed05d2cde928c635
25
session_key: 29cf9008487689373056e13592c31d4b0778d9b20ecfbd75be17f204
a2af90054be17321954af63ec13502c1eebe9413fce0056629b4909ba95ee1e5f163d
bc7
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
oprf_seed: fce47dabec99d8ad98e62ff5b6645d3ce5a735fb19932771374acef19d
e56a1b8ebf7bbe1508401bcd236d7fd1dd232bb9a2d5e4e5ed711772275347f959af8
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 7d316daf61f1a4e0a90b0440fa8d27f8846334b63c52072ab5adf
eb3bf1a30dc
masking_nonce: bf10032ce1e3d60f4d7671d0e3b5ba8be9ed643f03b6d448222d88
0cdfcce0b4
client_private_key: 01dbf86c586f691ca14b9ab40d70a9e5c73c0b8c027fb639c
9affddf316a4f24a457b33e0273c41c71c5ca880a54ed88d6eb7176277593cbb29d44
bb9daf835f3133
client_public_key: 0301347c5fb96ce61b57ab45d42005522f77483664bd260ec7
f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a8290
cee86e55fe23462
server_private_key: 015d65d73dfd2c51951ac649bb19095f1d02a822b02e5a86b
ae37e79a3ac7d05f1d1a02f58c3cc57af7318bd8c3aef01e27f343d5f8aa5197e80d7
2ed5ceacb845a9
server_public_key: 0200e85b446310593c25258991eeb8da130df718df2efeee93
29b6d6c7a3906749464ffb90f8e43122192f8e77b9f04f708aa5f9ecca9cbeab701f4
9929d82395d9928
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: daa845b4f4e8a139a894dd1de61bcab1c782a989a2495e2114570bb
8b390adc4
client_nonce: 021b9ffed5c067a6e1bbcd300f8b44b5f7123ab6a746624d8d6f54f
ab725c76a
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
oprf_key: 015d2a555979a9e537f94d47a861d2b57a5a46318677b8d906e16cc65d3
6e534cb18a43cb789940e151388f8ea3e084619cb1366d24c56fc6f46206867bb0aa7
b8f5
~~~

### Intermediate Values

~~~
auth_key: 66ad3c8def2655b31068f981a2433135c0bfefae4b9c23c18b5e9599af1
879696dc128ee51b25b81746db92df5345cbc86ce1521730536539a2b4def5dbd91b1
random_pwd: 2f645533ef3e2452bd0517f1ba929bee0e4e7f0a7286451e89a0ed596
aeb8b82d85c869775fc3187acba209c983c1d7064fdb8473255e91695069dee85150a
20
envelope: 027d316daf61f1a4e0a90b0440fa8d27f8846334b63c52072ab5adfeb3b
f1a30dcca7113033d0d04de25af37d23beedd900003f787a03c6cedadd60389def661
974b865295fe444360d1e78224715d78b35c88df168ae0e1900058bdd55300080eec8
8921fc7d1f61b25536ea4ef76b4e6a56a53e8694f5f7c35260d46aa41f28bf5342d22
7199f104b6dfb87dc19e5480fba0a0c34b1c9d930c5e5f4184feb008f71b
handshake_secret: c1a25c200c1a0f39a60aba5a2657e48fd6e9992724640a83188
5c0569dc5c09401ecc60d7abc2e9149902bc2a0ed9609128a1f7f6c0e02548f5a4235
bfd9fd21
handshake_encrypt_key: 1a74bc71690f18addc7083a6502057f912fd9bcb076ff0
d1c7ad5562ba8a20e79b6262c44fd85c72e17968900f0eedb480308c13107d3fb851c
3e69719bcc772
server_mac_key: 6a876787356cdb056e4cd66e48d861561591a74bfe702dc8d1523
6ccd3e0796f5f87848a8d548e01ed38410d4766852b55d7cda4c19444cdbbf4068df2
7c6a88
client_mac_key: b7bedee009122c931d2e50fc73b89a4d37f10570ea579b736dbe3
f74291102755920ae7efb5b3f1e589a6b700fd1005584581bf8a5ab6d0b94719bad34
f10d55
~~~

### Output Values

~~~
registration_request: 0200572541736c54fb88d0f50d1080d98cc390cec131e56
c5e3d038122c6655d23defe37f0946f3d3b5dcf73545a6df6277e20f9b377591bd443
034fdf53d008028969
registration_response: 020021f4277819dee209ff0c919f3d50b7a469322cb3f7
2e635f2c8208f1c3f42b117bf3c3f5a373eb050599c4d1873715824151690514340bb
ec38a83988b31bc7cf70200e85b446310593c25258991eeb8da130df718df2efeee93
29b6d6c7a3906749464ffb90f8e43122192f8e77b9f04f708aa5f9ecca9cbeab701f4
9929d82395d9928
registration_upload: 0301347c5fb96ce61b57ab45d42005522f77483664bd260e
c7f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a82
90cee86e55fe23462340fafa49721ae6b1788012f77c6899e672fa91f877d91b12edd
3120d1440043371ed9fb7101c1bd6b31d278cbdda03f603aa21849328d9bd844ad2df
8e1bb34027d316daf61f1a4e0a90b0440fa8d27f8846334b63c52072ab5adfeb3bf1a
30dcca7113033d0d04de25af37d23beedd900003f787a03c6cedadd60389def661974
b865295fe444360d1e78224715d78b35c88df168ae0e1900058bdd55300080eec8892
1fc7d1f61b25536ea4ef76b4e6a56a53e8694f5f7c35260d46aa41f28bf5342d22719
9f104b6dfb87dc19e5480fba0a0c34b1c9d930c5e5f4184feb008f71b
KE1: 0201147f07392ddb5ab846130ce65a4c16d1eb26735fec1de7716b2c8bc935ad
1c65ebc30a6449adb8504b41fe61b9634a1ac3e429e03db700e6e6f852469e8e83bec
4021b9ffed5c067a6e1bbcd300f8b44b5f7123ab6a746624d8d6f54fab725c76a0009
68656c6c6f20626f6203001f619d901664fc0a4916b616bf340eafded4dec3c9af08a
7d89f9442bf41048a8824f22d5ce906558f99250ba96a112c5ccf2ff02e062cf9158d
fbd1abc4a48e92
KE2: 0201e043f0dc6a2defb51cbd82fdc86a98adef424ac19ce01a99968b478c8125
e4abd6d3e111e58f819eb1862e59858c59d96f8d1f1a503825dacf635e10320d746da
3bf10032ce1e3d60f4d7671d0e3b5ba8be9ed643f03b6d448222d880cdfcce0b4a57d
baca84014b8e94d6012deba296e6bd98bb3ebf1864cdfacf44d1c5683cbb5c95d790b
f3e71bad7b839de7de9a5be6f00f1c46b4d95e7567faa7a06d6ef5b43f239526139c0
522bb71b85772d2604af13e1e756b20433a667c0a55c7e686143aa6e576df59fef0ae
9c7d8e6e7add56906730230f5c9bb5f726e430ce6db0193fd6b73f2c1e62e03188d9b
b374b8ea0b4e337da86508685ecf60f2e3f419c57f0312a23d105e93730d6f4290fcf
30539067d8e9af1988c2e5f443976e16f5609118495b1e5475dcb4fb0fcaf2496da6d
21b51e5114797a178d89f53bd83b7c0a45f8452c91daa845b4f4e8a139a894dd1de61
bcab1c782a989a2495e2114570bb8b390adc40300ffcefd89e8ee736b4e6149934a10
40b8691ba4bc58b160d8c526e73cb99d7c45ce09264ae268a5afd07c1a3db59c5feb9
203ecffc694a41b1138deb9a11d6fecbd000f982ea38bd6a0dbe06945b1e89272fbd2
7fca416a25549d62fccd80da1b3744f1a645b85ea56c37e88c9fca42518da135af80b
56825029a87ad47159bb16abab5877f2a1c90f32ac6756e8d7df596cc
KE3: cffbfa9e656cd0915e45b4b8d63cdf64713bdb892aebd5a0be5815c5dcbf6971
d30dbc736d278dbe88e1a35670cadbab4f68c8f4c616cc432bebfe4dd6537c4c
export_key: 5256c3e68ca321edee248ecb5ac22d62d5fbce8f5a35202c0ef694469
3d377dfd8aa0a44f12ead2526dddff160d273911faa8eac394ba42729468de8014d5d
d0
session_key: 05428832d76780ed857ab30bceda4f4411fd25739b8d0a21bccf4a63
3838450b09fb7e24fe0ee5aa206b7295c3f63167558ce4ee9d896b75dcbc70e93bdef
455
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
oprf_seed: d1b36ce3161b70e15a39c56a9d8c2a45e5c0d7349b4d2dca8bbaf6df2d
6da40af5b65d4b795e40055c218d2a9fb9f9a34583ccef9ded138a36dfe54babf1cee
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d1157b8e588bf913a3a65b8e48989a6e3d8cebdfd84d246c33300
f2818b563f6
masking_nonce: 30ef57bb6feda91f1e334cdf0833d295ac8c77d23acc959562fe4f
5ae51ce619
client_private_key: 01aa0739d3c390e0df1d6a83419001361e6494e0958c6268e
9a64bc44109b2f8e1784d38719b913380fff07f6d1fe601f5560987bb2828a484cf42
b97e93965448d3
client_public_key: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4ca
15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1e7
ee4c024556f0808
server_private_key: 00ac7137ef41e45bd9f1cf40ea91380647ac28462ad98e22b
5326fc0adc6757c67e0fdfb9fb3141a5595e168f85adb13e86ecbd0e8af169868d1c9
4aeadca2d95be0
server_public_key: 0201a6573b69f46bf93cb3f18e2510c753f689097b7b96059c
3ca8f8e45c66a03b694fd8618c9a52c4104ca42186438849e73613cb25fbd4ecc16c5
a65f95345686984
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 5edbd5d1068bbde589ca6059e088819c97a9aea36f4d5f32bfc118e
27e23bebe
client_nonce: 98caa66fb78fec6f05b95a5abab31de9a5cbfacbcad504ab0e66085
ae7fba5bf
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
oprf_key: 008130cd7d2d8aedf1a3036e19b257de13ee6abea2a1e71656349f8d5f8
1a5525536c88f2f1261f85e0db7943001aa0f614a69c3c8db203e052e75cb99902b76
3f20
~~~

### Intermediate Values

~~~
auth_key: 7cbb8f45584afb544f804387df23f967ec829c9ad5825339f4bc0316f48
8c0b4399a4cef231a946db699e0370ce77242c1abe96594bc842fdc501c65c73f87de
random_pwd: ecf3953b15f902ad7a1e8251a37b9e3a07348b0af3d0826f439cdaa23
9105e55716bba835f2b4145c2f0b8054627b896b0367695aab4dbacdf4b86b3dbf11d
5c
envelope: 02d1157b8e588bf913a3a65b8e48989a6e3d8cebdfd84d246c33300f281
8b563f6b5726c4b29a18d623ce87dea8625e4794a46ec4d45ae0aca07590638f48cd8
12cc03dc41b2f2cade3cd5a757a126b82f535afbcb628ac030b25febbcae883be9165
ef5c9c7b39fdbc8453a5147f47abb2c2e217f006c739fb94553039b0b98816f836757
99584d14a04e98cd25a4ea17ac88d66d7d508f6a99fd9b506637315a0355
handshake_secret: 313232877f7e3b37bebc43ec49bb717e01e5d2f31f8cd054e4e
362bdd7aa6653f43c0c8dcfd555e099b626ff4edba99332da1230507aea6c172bc147
c684df44
handshake_encrypt_key: 80b90dd6e87b8137505280346ad056f462226dcf955637
889466adbccde624c94237d41e5a5212265796f04ee7a8632a9a7c4b919e2aea48e04
b169739119f8e
server_mac_key: 45c46e0b4b0eb1c91002eab4395f56088d460b7da3118fecde3b2
9f14f723a012ccb683e61db2a227e1b6d13cf61ac7280253226fe88da48dbbf555345
768d6a
client_mac_key: 1ad7b5ee6a41a7f1aff0fb12dbeca464e93ec90728a4d4c2b0508
056f12ba7a135371b18dbaf738276dc3bdbd19460782d747cb7a62a1ff15643b3585f
ec0c67
~~~

### Output Values

~~~
registration_request: 02000c53a2fa3c1dd1ed747b297b82020f316ee5b38d5ad
d8bfa68d9c6eb9b22ac651badd5d5751e7371cae832503f66442cdc156414f4a5ba0c
2db08b33530cde8dec
registration_response: 030112f16ae9b345a2dc986ac80f06f9e835ff2c050d14
d43ce1d52ad9549b1ab133311f2c6d91af7344f47feb8b80ea5dc0127f4b3b949ed9a
d5137d290a6f0b25bf10201a6573b69f46bf93cb3f18e2510c753f689097b7b96059c
3ca8f8e45c66a03b694fd8618c9a52c4104ca42186438849e73613cb25fbd4ecc16c5
a65f95345686984
registration_upload: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4
ca15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1
e7ee4c024556f0808a1ef7eedaedafe68933cf3e238598ae3a36fd91ad85c8e0396ab
d8007d7bdf7cf20d26f416d53735b8513842578dfbdab9c4f38d011f795fee9c79780
6e6d6ce02d1157b8e588bf913a3a65b8e48989a6e3d8cebdfd84d246c33300f2818b5
63f6b5726c4b29a18d623ce87dea8625e4794a46ec4d45ae0aca07590638f48cd812c
c03dc41b2f2cade3cd5a757a126b82f535afbcb628ac030b25febbcae883be9165ef5
c9c7b39fdbc8453a5147f47abb2c2e217f006c739fb94553039b0b98816f836757995
84d14a04e98cd25a4ea17ac88d66d7d508f6a99fd9b506637315a0355
KE1: 03014f2799259882d01af61644db264602a3486a32f6b510aecb336456ce58af
6cdf6f5630ab4e3e7081f1e99b1688558f0a1bf15da34b7c0252f1036d916928a0f33
298caa66fb78fec6f05b95a5abab31de9a5cbfacbcad504ab0e66085ae7fba5bf0009
68656c6c6f20626f620201e2f40c1d877219e9512862469e31da268ab014fdce9cb3f
9ed6b27fc01fe6d9b1ec37c6cee76131139ccc3eee0a35438250e9ecaff6cf223ad9f
a469dfaaa0f0a5
KE2: 0300998af8c37442284a2a1da1e4b9bad036eb8157261a6e450befed2412007f
df6273eff6fc8df37d367601e31a0c0935112d12290f8a676aa4d0e4e6fcf8489cbdc
f30ef57bb6feda91f1e334cdf0833d295ac8c77d23acc959562fe4f5ae51ce6190b03
3977e4d7eb10150e284bf93e9ad447cd0f53b6ace6199f8a2f915ad155f241df906b8
b104ad6e15004c312ca70db2d25aa36d51f8e72e011bcf631a18c4db5dc0bc87abed6
13b8caa77b8f0daf918305e1e1504bd36d594217074b01a739addb090e5599a34c8a5
5bd6615af48b192581a8c6dc784fa6e606f149faae051a3e16f65a372cf77e5c14ffa
97681efd28597eda0dd3f131ef2b1f0d600578d77fcdad6338904000b4ffbe119046b
8a9efc71d0ebbe152f7718dba8999f9487cfedfa431282637e64d2e80ec3c17e66cf4
38c1489e0c6c10429c8f0bc68a252c9187c81be0f95edbd5d1068bbde589ca6059e08
8819c97a9aea36f4d5f32bfc118e27e23bebe030029562d54d53c7c51651334989bcc
95b45a1a07484448ef72bab708b55322b49a43736afc60bf85fc05d3c1d8b60a0b55a
83e37befa115e9625e00f35c1eeae27ba000ff95625d338361bef9c2465d33d7feaaa
6b0d4479ceca139f3e2161981c15fda3800015ac67b9072789f645e8a13e6820924b0
7c4c8605ca97f9cc5dcc2dff78e2552512a5e5d35d4c33fa797a87c40
KE3: 9a047dc438299b1d2f19c6f0ef563d5886e4a5d568f032d20a89e0231e78b407
cec9b7b4f06333e8d7e2a972e035cc9ed1d3eb923af6573754ffb2b00ce755ea
export_key: 5d5dd65805337f6e4b09c809091b2aeec23b14781dfe2d3d73b2a11c9
e34a3810666b50972e27b1e33fff7aff6246fb148f9aa133a16f20242d88319ecbba5
9f
session_key: 36ac6f964ac0e36ff262cad9c2df53b58ff100b1a58ca013cca0b4bc
cfce45f31e091a6fa9dddede614143c3f54113b71a73be189ca5c063f3947a8b31a19
77d
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
oprf_seed: 4808cc94155a93e5341e47076f932f1195c16d5c05ac345efe32f1c73c
43c011f0529016ea4d477a293469ed5d9966bfc9e0772510317b427a0f16fd677792b
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 7bfe09efd8a12bf0d50834316c2b48fa2a61afb3c11798917c8ab
2fad4191e9d
masking_nonce: 45360f81ad105e323ad19cf34275e0cd03de6692c6b9e004c3ab22
dfd522f4d7
client_private_key: 008fb26f2c88d274661db787733c175d7034e4da200a4ebb0
1c9589fd7a0d54771e479fce2a99af6a64f80e4106dcef77a750147dcf14217936a74
679455ddadece4
client_public_key: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fef6
f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea03
e0379fb9127abe5
server_private_key: 00b78f376d4dee066fa82592ffb702498326c37dadf63135c
ca8df4d8e19f5dc6e830163ea683e19a507b15a66ed74b1ce6ebbd902a5c74a51eeaa
2ec2bfc113d4fc
server_public_key: 0200f944f464cfcbdfe94b720c0a59487456cca17580dd1982
4532d540642aa4017edec0b9308bf4f4fc00611115a145c1374680847e4815f6c8dd7
febdecef64998dc
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: d6d4b417df79c3d5ef83042a892777f983c77acd4d181493c09260b
bc34cf44e
client_nonce: 9d2670736ce486de07f26fc5e63caf92524728c1022c258f1c4779c
837aa03bf
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
oprf_key: 00c4a82ceafef447aebc65c826c0e236d05287d9b4ad9625885d905c767
7d8bd4685033d4522ad99feda85c97213d03501506b029263179208fadd3a6ff8c79f
455d
~~~

### Intermediate Values

~~~
auth_key: 013cbd8dc4610d5a9a7a7fc4080f3ae913a03881ff727bb7747c7f7a127
b705ce59f8c313aa33f110126c0608d0e0b0d8592dce3c7092d7b8af24acca8b2e1d7
random_pwd: 04d7b7f8ec695ce4bc6f8e8dd499f479038bd1473ae842890ed6c90d0
c2d9abf06e6a95f9d1532d5adbc12cf89bd8a5e3f5991b72115f2b2bf2f9385ac7b01
8c
envelope: 027bfe09efd8a12bf0d50834316c2b48fa2a61afb3c11798917c8ab2fad
4191e9d041c05a2fc16a26a6c580f9776fff3919dd94e0ad7df7dc9275297d2cd87af
ed1309b8a8bd912548d93ac38151f6cb2d69beaf4f7ca947aaa51f1aae3ec21264c13
ac5d6e4c0ffa1b8b7ceb47fe7bf19cca924f92a208452d63195d32124a3af29a8758b
cd77413bb222aa9ed71da13ab0fb9d2d997a208a81ceb7ab70de7ac64b4b
handshake_secret: b155d7758877435ad6e865a8b82c2afb0c5aed8c257807a81e8
ed86781e63a2545c0246cbf523831edc139702167c3cb23b7759b303cc99af582700b
d3982a87
handshake_encrypt_key: 47fe7c8607ac06c19d03b01d847228b032f16877131a98
0e6ca848d2e57dceda844dc130323ab7f863a4cc4842a8158d96dcb697a28a24a2f6d
7dc2644d0e4f6
server_mac_key: a437d1ec396a4e7012e7a136428c2b4dbd587fdea59606b400a9b
fc0b8cbdd7d23ee27ab56b0da91f0a4f23a1f07fbd5072ed98c86f79de1d7d1c1fa9a
fb97d2
client_mac_key: 1dc3386548e2002262c991d55f9dc83885635049035ef61193649
5092291c6473f6bf7b558ead53dda48140cb3355dfd84501b8d896745fca92abac933
64da5f
~~~

### Output Values

~~~
registration_request: 0201d22759697d1d91f6b1812d14acfee093886e889d913
cdffc78de009924d3d80a7aa9384149f163fd706498375c34402df2ccd8c1283cd250
477ce032c9e7c78ef8
registration_response: 020085e654ac752e60bfac753d32636f5faa6227edee49
a33e41177aa64ae5a97ba6bdc871d9ae9da3e3fb82dd6c533e3354840809d484786c1
3d28f6c64dfb27dab9a0200f944f464cfcbdfe94b720c0a59487456cca17580dd1982
4532d540642aa4017edec0b9308bf4f4fc00611115a145c1374680847e4815f6c8dd7
febdecef64998dc
registration_upload: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fe
f6f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea
03e0379fb9127abe55cee2e5babf037e578259fc71af060e6624fbdc96834533de566
836656676bb8fbd003cbd5462363fb61659e5bc4af71e151f8e2a3a89afc451a7e331
c4c2ca2027bfe09efd8a12bf0d50834316c2b48fa2a61afb3c11798917c8ab2fad419
1e9d041c05a2fc16a26a6c580f9776fff3919dd94e0ad7df7dc9275297d2cd87afed1
309b8a8bd912548d93ac38151f6cb2d69beaf4f7ca947aaa51f1aae3ec21264c13ac5
d6e4c0ffa1b8b7ceb47fe7bf19cca924f92a208452d63195d32124a3af29a8758bcd7
7413bb222aa9ed71da13ab0fb9d2d997a208a81ceb7ab70de7ac64b4b
KE1: 02002c6e65b998d160fbbde62484f39c2678bda170db547005889379b570e83e
4f6aa45200a183dc5cbf014bc7f94f28064bae53132dfb3a0736bf7b806b1091ce541
89d2670736ce486de07f26fc5e63caf92524728c1022c258f1c4779c837aa03bf0009
68656c6c6f20626f620300c566f59e65c950d86356e925ce1f87b3d4a7a9b2e556ece
f17041679c76f8afd8f7b1e9fb82549886fdedf29e4e86564475b0c2c200a9c7a4e08
9e846932e07d36
KE2: 0201982bbfda41f8e53d7b2f6cb3cde1f793f54ebf71c503e40de80c7ff0bfed
f972041efef4a123d92200c0a89ba9abfa067e2c72d3d395db413417d0a8ad546251b
345360f81ad105e323ad19cf34275e0cd03de6692c6b9e004c3ab22dfd522f4d7f2e6
669731971db94e65dbe48ba20545c8fa0484bd39c2f8470b0e5671698ae34ed6cfa6c
f7b0e5c6437211042cdc284706ed17a2c5fb7669440b02898e15d8d9839d94a5c5933
883d29427f62cb02f5b68a878e072c06d36e493be3cc6aa9626c65cf69e1592ee207a
3def4901a7f73522b697fd0d4b06df9280037d652cb3015718c90abee1fe72e8a74f0
54f4f3e194b6c29e8ceb8b94b838e4529ac857793fa7dee4e94841e8b5bed936e3afa
60fe56d743b1171eb21ac7a2f460bc49c634d06ed9e0876f8a64bfe0e31531af2a3e9
27b7aab0aeab75ddb184388ec54ec93daee4e0a3cbd6d4b417df79c3d5ef83042a892
777f983c77acd4d181493c09260bbc34cf44e0300ed0fdc747de2ff4797c4b18da821
ae9ec83376c51d00a51b2d1701e5689e8dd720cca6fdd1a548b5b3ad34015006ce4f7
548be73295e07f15f8b0c60331cb65160000fa8726bc0c92bf17acc2c107b5931ae88
2ed9ecc315e56abdd82fcff9a77ff6895a69619082fdc4e272cfe4d8ab3df34e32883
5c9d06238db7ac6fa4e94f00943b14b083c4e47e471271835b04fbd84
KE3: af015ce5601ccd9b2e96e2d7ed7dde17af1e7691ed90b81988e439f01566d263
9d69c831d2f92cb2f73823db871b3bf4bcc282bd2317489d8f4f6921fc625e95
export_key: 7ced60db9175e189871fbc97d883f97c623b5dc0f3100ecaf5bab871f
dfb6210f8b6083d55f8baa2f37c5853466869f6b7657e5def850cd93ff57d13030287
c3
session_key: 4284a94be67de4314db786093b7d4f474e3c3e3380b2c6e9b1810e69
ae2dbe9b449813393f06883eafcf5989c940edae365295a8b542632824378ec5e22b6
805
~~~
