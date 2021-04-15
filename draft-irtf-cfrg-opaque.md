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
 opaque auth_tag[Nm];
 InnerEnvelope inner_env;
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
8. Create Envelope envelope with (mode, envelope_nonce, auth_tag, inner_env)
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
~~~

### Input Values

~~~
oprf_seed: fd1248eb625293a7345dfbf9a0f05552b85bb1b0c46bbf4443783dc823
7a98a2d5cfe9ce53d34cb647cd5723db032642c62bfbb80f3242cf3427fb2b8cbc66f
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 152c711827864fe997c19ef05e5f29aedb49aed97b0b2d7a54761
1f719d94e77
masking_nonce: 221d560b4d919339a8ff51d0d93d86d2325c9e813d58528507da34
321d7da21b
client_public_key: 9e04036c7f684dc22882feffa7ce51965b3b821d90dccb6241
4ceae1ff743779
server_private_key: 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a
9706137886dce08
server_public_key: 4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b
78624cbd10b371
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ce74f9cf6a5a808c0955b18f54bae7eba4b8e53347132716e519df7
7c1c38725
client_nonce: ae54ef7bdf21115617b5820fde3041ebd8b35ae5014cea3eef1fd38
4d8208cc7
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
oprf_key: e7db99940e6386ed91f35a40bffb54daface4ddf18eba7b948c4bb5ff1b
57905
~~~

### Intermediate Values

~~~
auth_key: 39774e5b024601ea92d44b45fc113bbd97c4250aa9e61a23f31e359e605
f8c9b1ffcb77180a85d45d17281e48cef962b7cf967b69ba34c3b9cd3cd75c165ada0
random_pwd: 5e42cee3657793c566e179a1b3361ad6f6587ad85bddb52f05152b96b
190e2df03e817cc3ebcecddd18efc25a50edca2e1ee0674e73f2bec8aa7f254b362c1
ee
envelope: 01152c711827864fe997c19ef05e5f29aedb49aed97b0b2d7a547611f71
9d94e772fa3458bb940fa54cecabf6013b05744eb718c74df277d885be80f66be7475
59de747ee9d7b7ee82d0d4eace53722b89880409332146f9df99fb5d0cb4d07ba5
handshake_secret: ae5d94a822f307a31f2821167af323a45eeb4a2fb076e697803
b0cd423a5ca9bba602b74b4784c0aa43f81bce8ed04925ff50d95de3bc834e1251fc9
a7f3e18d
handshake_encrypt_key: 79393807a5f6b2fc3284e81a7631929ce652bddbf11434
5a0f5065486ea60958c216b1d552a46d04ea018267ee7fa0d2f0c05924d4f8aae5eab
bee9bf0df3105
server_mac_key: fdb86ccda715e42fa4bc6ac5facd042943ed2368b76a7a8e178f1
5af93d7194c5117e0b7db4d927784883179f40137e7185f2ccb4326251035f2da3a65
3da453
client_mac_key: 5828dc15e8eafbe891e2109063c59506d923ddffdcf92c7306b19
d6bcb80171225ff70d85c1b61d53f90301caab9477a4dff6a21217855de3d4a691bc3
f36ca8
~~~

### Output Values

~~~
registration_request: 24bbcabb15452642f709cb8567eff38f4cda6044aca3356
87a62b8453d849c18
registration_response: baa4d0729d91499885284d5382d386e1022992d758ca7b
fefdebcc64377a725a4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b7
8624cbd10b371
registration_upload: 9e04036c7f684dc22882feffa7ce51965b3b821d90dccb62
414ceae1ff74377976de8b8f4e7c8f25945156397b3b1a208c144d890089e462d6e1e
e0a4aebdc6c36e6a3c35584cbb7e4bbafcd2605c18a040fd9295bc285b7041ba5834a
7342c101152c711827864fe997c19ef05e5f29aedb49aed97b0b2d7a547611f719d94
e772fa3458bb940fa54cecabf6013b05744eb718c74df277d885be80f66be747559de
747ee9d7b7ee82d0d4eace53722b89880409332146f9df99fb5d0cb4d07ba5
KE1: 0e8eeeb2ca0dbf5f690cfe0b76783d7667245f399b874a989f168fdd3e572663
ae54ef7bdf21115617b5820fde3041ebd8b35ae5014cea3eef1fd384d8208cc700096
8656c6c6f20626f624c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
KE2: 5cea01740792b4065044a33e4c9aac0405034aaa8751afde58caa0536b1e4b33
221d560b4d919339a8ff51d0d93d86d2325c9e813d58528507da34321d7da21b94287
9860b210c357eb68b88cb5ecd14a2ad9dde16f7e8fb91f07203ddec405e414f08ee00
15ee63855a87afb35dd98fa3a635f6e3da56ded871b30345cefdaf9a4590d23a8b329
a897d7dd6a66c5abab5179eac61f5aae113a90a0c3bba1a22ee419e1f745ef05b5e5a
90873df727c0698dd93a5103ea6632f916abad8af3b9c3ce74f9cf6a5a808c0955b18
f54bae7eba4b8e53347132716e519df77c1c38725ca372e52516d51c19763ad5eb1a5
b60dafb68c264dcf6bcc692f667a71c5a617000f53c91586408b92621572e79648c5d
afe72f73fbc76f0889728e28dc2a064b9d0a40c9e878d2db4c0cb915e788a42f4b691
177274ff563881539db54ca43755b33b180fda1b1489d70b79e5cae7994f
KE3: bf6360957bba6cd807d533e19d48dd19501325fcd3a9d60337329ac89d9a3d3a
6ab574b6225d1c628576a30c2e5b267eba1989fa2eaac8c79ed77c044eb37880
export_key: fbbe74dcf58c03075c14c2012d317782261e7c0e8a8c2852d40a9652d
c6fbe4cb04b264105cb3b92219f829d9372c9491da3d8206257eb763bf22cb11ffee2
27
session_key: 6b179e32858c50da6d12f2de747c7bb59dea1d949ae9e8f83b97a84e
35bff1d3e24f6a3b5ac67e09dea8281edb1cbb7d00bbc65a017f00486c8a6ce2fbfa7
6aa
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 040efabf11d6e78109b1b44998286d81745235ec675fbd3fb17d4c98ae
e730e3c610155899885e736f879b3764354cfc9dfead7e4aa0668a45c140f79a08eb5
0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 460dcf1943db0b190f9101a33be948a2949ee491dd4670071adee
e25c4b8e31f
masking_nonce: d5187f3dfc6f9c4de28da52aeddc8d37911f17ebd0017986130559
0460481f0d
client_public_key: 28e0ab4bdbacb09927363d90398b697b17bb92dee6822ca2ad
050843e5044720
server_private_key: de2e98f422bf7b99be19f7da7cac62f1599d35a225ec63401
49a0aaff3102003
server_public_key: a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e7874
92b98265a5e651
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 91fad138acb8a8b7ada6ea8d17a74791d95c7e92306a2725a5a87e9
a7383b73e
client_nonce: cbcc63d5e93a40f4433a0c17d761f7738028594b66b74d760f89af8
f1c08d512
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
oprf_key: e12b186c52c183bf02ce325f111052e1d05df659cb60ac5ed5ef4b407fa
6770f
~~~

### Intermediate Values

~~~
auth_key: 67f23edaedd373654ec87a213a320f83452278cb98e0f19f12bf5f4aca6
f6abe682bb94460b6e9bb5fc4abbbe346c6f749d19f4a1ff1d05f26276b7a462ba062
random_pwd: 7cb7869b09989b9759fa81c61c1b0c7a9ddc3467d722202329e31ff18
b96c034da9446f67497b384776177ee13ed1a0cbb4a9f717e9da1f1a2af07859f949a
01
envelope: 01460dcf1943db0b190f9101a33be948a2949ee491dd4670071adeee25c
4b8e31f88b86d0279b18037089fe873442cd6793af19793a0306e326baf07ce4752f4
83f1b5ac0e691beb8f1abf2f64f065af5201b0690e2930c7df5684dfce15f0ed9a
handshake_secret: 577291894c562069c0a6444863bbdc0fec9b02ca308aa2f6284
ab292d09be0e5d5065ed089c418e61c0d5dd693d29dde35d2439589ccf94386aca645
c6fdfcb1
handshake_encrypt_key: ce47bdc612133f9dd5a6972a5f3a2cf45fd61d4a91e541
720299b1c1d15fd82a91ef1464bdd1c5acefe873e62de143fff2134c7d744732101fb
b0ae7005362c4
server_mac_key: b0f42852bd27a42401639964cdc092d5d212efe95c6212ab9cd1a
0eb0da2f989b36847e9a3cc07acea180460d3aca2f669a9ae4736f617749e309b5c5f
7caf93
client_mac_key: f763ad8b51afce34c94d616651413848cc3305357dadf873529c3
f24a8b825215d43b79e404bda98742b7e9e8516fcf207064c67a136de699250e4f148
d49dd7
~~~

### Output Values

~~~
registration_request: fa8c0e0144f7b9cd1de1bfcf78104f94d63c0f90398c9df
ceee06ab5593ec500
registration_response: 9c05201842ff79b18e44ad0e5137c59135176a094409e5
3f8cf4cb5f1d0cc325a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e78749
2b98265a5e651
registration_upload: 28e0ab4bdbacb09927363d90398b697b17bb92dee6822ca2
ad050843e5044720a7f98850409b58cf95bd93ee7ab2f7f67c86b432ffd5ee92c2a8b
2b58f6fad18cda63b7b146148fb5db391b65921b14353860ae566956b8801c97ac9fe
4e74b301460dcf1943db0b190f9101a33be948a2949ee491dd4670071adeee25c4b8e
31f88b86d0279b18037089fe873442cd6793af19793a0306e326baf07ce4752f483f1
b5ac0e691beb8f1abf2f64f065af5201b0690e2930c7df5684dfce15f0ed9a
KE1: dedef709c5faf24970b4fa77480a2c640dc8c6b7a53ae78a2dbf3fc75134a250
cbcc63d5e93a40f4433a0c17d761f7738028594b66b74d760f89af8f1c08d51200096
8656c6c6f20626f62746987c9ba92c3636d92fa7afc0379009ed54a7fb2db3cf7e4c4
07d4ed2c6e35
KE2: 029173bf25923dd80dc06601370ad8964a43d4cbded76aa743ab56962f14240b
d5187f3dfc6f9c4de28da52aeddc8d37911f17ebd00179861305590460481f0d35156
9e93689f63ea18981e85a8561aa23da003e4f9b58911eed805cde599eb707edc8a310
f1ab882fa46b564c4c08d46f5c34f2fad6321e7635591f8f66077b16474e81da49451
7cf1a5d13b4dba302baa9c5ce43053985142f366cdfbde3e378aed88ffeeed5d73825
7635d6e0c946a01b65051c64b0e4142d0f817e1550100991fad138acb8a8b7ada6ea8
d17a74791d95c7e92306a2725a5a87e9a7383b73e80d9b21c255bf04113a6d339fff5
79c68475e516c0c98f625a90f6532a310f13000f2112bdeccd40579ceb50fdaa49cfa
a499d4dc2e52fd6a8da78c8c1b980f12d72262ecab0ad805dc2d544d98010b8a8efdf
ca5f0dc641a216d490a5f6549b80b9c5b9dbfcd450aa1093bfebfae719c4
KE3: 7e4859791f22fa46cf221ddfe4b123c9d79569c0df2b1385e2c258833843eee4
f164da0606b363b1ac0171cd15b21becaccac4e15be83584e7ded15992be4313
export_key: 8cca1155592fc131c092bbb6ff7107cf96b8aeae527f5acc2c9797ce3
af6e6cc66e016a408f0361e13ece494e00c544adae713d2276e84e3c6d1c93f7d435e
44
session_key: dfbb610ef7e441bc0d1fbee443d2e28f19a896fe4753fcf869d2ad7e
d3bf5a0c2eecaac65ac91122d82f8f330c17e09d2eb6cfa44b91e4c2bfa1c440f58d3
f89
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 7c21096ac1c379603185c86724510bac61ea6dba24eeb404a5518bcd8e
45671c6c502d1333a2810821f25a4e728216cc4592ff00d5011f666ab27fc568fe41a
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a53fdddf01fcbfba9053e3c316a4ebb27c638844740215023eea5
0b326effca3
masking_nonce: dda1cbd4867eecb10864dc0f5bac9c4da55e3b2b49c13b9578ba58
0059e8b3e9
client_public_key: 56b0581a20fee7d7fb9eb76dadc949d4baf6d5af96c425c44b
de068ef7085c6e
server_private_key: be81db28eb1e147561c478a3f84cbf77037f010272fd51abc
ff08ac9537e750b
server_public_key: 5ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3
f459678b0e0d25
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 958830b07b9f8b07b0059544298b2f37a3cee249bde7f7c36b312c1
d71ec0033
client_nonce: ebdeb0233b1a39e12afb8454039af1cbadd604881e993928c5ebbaa
e693d4ab9
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
oprf_key: aa9b80e8772a3f6832d6402bfadb0d1ec0b248a2d79e4c7fcddd105c456
e5e01
~~~

### Intermediate Values

~~~
auth_key: 0c2be5cf1f642083e5a416274477e78b1285cf3f2ca24bdcd0537031989
a2dca4482874d88e7bce75903fd3afe42cd7e212ce66755120886ab696449acdf76c7
random_pwd: db455dada2e63fba307a8d1a09e211f984dfaa03ea4ed3a40e8459c29
fbc4e94ddafe2901abb673929e30144a3a8591228957b6dce3b55e9cf8b6ded5251c3
2e
envelope: 01a53fdddf01fcbfba9053e3c316a4ebb27c638844740215023eea50b32
6effca3fa1200f0becdc8e5dacb6a750304aeb1e6dfe79d3e516321da25d464f40b5a
dba21aa4bb4e5370c7f21fd8d29bb89727394a3734f2730122f01df0d004956f77
handshake_secret: 718be930f6a4e0e4254540a1ccb7c06ff1879e59d137e053925
cc1187547895324ca543977717e5c42844af222d090d5e6f9bc3e383bfcfd18646625
55ff774f
handshake_encrypt_key: 6744823b750e697a3edeb65c01c373854e22c444f4f8cf
921090c69fbaf6f2dcde241761568f3b40c190989b79845428b7a7df02aa6bb5b421e
b60251c748f2c
server_mac_key: 74468f0b2124b860018c3098736ea9893abb5a8f773a8f6587696
ebe3f140ce0ba8778df98be0e3673802082e1e25d64b619b17666a0378acc3f8266fb
700315
client_mac_key: 2a5244a11bb246ef88ceb8d09c13690af24245a1998db91235d5d
0210af504f6a5f61b91a863d3c2ecea437dab7e3137c3aa287843356bbb02c6e6fc2c
c65213
~~~

### Output Values

~~~
registration_request: fa39a478c220a89929613f9e65c9a4617da96b62509c42b
39d7e3606ed2e8031
registration_response: d028dcd5039abc361ef5725df69b420b3a4ef284c2c568
939b28a944270b3e685ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3f
459678b0e0d25
registration_upload: 56b0581a20fee7d7fb9eb76dadc949d4baf6d5af96c425c4
4bde068ef7085c6e44a9bc024b6af19e8c5a54734e115e28bd316224df8afcc8bcc4d
27f2931fb3daaa67d6095d4477c6467f2e4d08c571803ec07d87ba8e0accd83585f75
3ada4901a53fdddf01fcbfba9053e3c316a4ebb27c638844740215023eea50b326eff
ca3fa1200f0becdc8e5dacb6a750304aeb1e6dfe79d3e516321da25d464f40b5adba2
1aa4bb4e5370c7f21fd8d29bb89727394a3734f2730122f01df0d004956f77
KE1: 96f9f35ebc0ca71607fd2cfcd465e285eeeabdec61151b39b2b4fb735538aa0c
ebdeb0233b1a39e12afb8454039af1cbadd604881e993928c5ebbaae693d4ab900096
8656c6c6f20626f622e8a05799d3c524ede0482f39e047df99d9a53dc2dc30e8947eb
5da98b8c4354
KE2: 64e93264e0defb464d2f9167c6aff3d3113e8da0ceff2bc3ea707145150edd17
dda1cbd4867eecb10864dc0f5bac9c4da55e3b2b49c13b9578ba580059e8b3e964ac1
4f1f10197dd5ddb1b1522eada2147e39504503df7688182ada2de88a615296ac49375
8a68d877ba6ac5834f9da3038e44d5db1d2ffc519cec47287d1f5d9dd976b238df16c
d61f0ba5f2f99ae461c4be4ed099503ca8e40feabf4b55d783960bba365dacd015cdd
0cf8ed4beedb6aa3734dfc570c6a73093b9d53b5fbecdf958830b07b9f8b07b005954
4298b2f37a3cee249bde7f7c36b312c1d71ec0033a6d76012999541f1ec0c014ec160
6f2bd2a517e51f731d59546951d9699e1739000f6101966a2d19abf1bcedba0c682d4
c6f1e25ad3b86669c2f3b090ba66a4709c904805d6e841670b6bc6f383a31c76fdd4b
20a19e1485e5bdf7c6a5d5ec753d4d1d666c378134817e2a1e832654a414
KE3: 72290f70d6c3cb353d9759a8e54a78ab33694e4e7cec45f955616d52906c8329
2e37d91edc36b181138d6c448373939c163761766abe85a5174ade4ccb9b69f7
export_key: 7052a1208dd2c7e04e3f2fa0a5584105fb46c4cffbd406bb79ddbf14d
af40e4cb81e10d02272a91a8b4bd10dd31151a582030ec05066f03c4b95117153ab5b
40
session_key: 3959fe5e9581b608498fea748f606bf1b850df84ef3b0e9efd8e7616
27496e99edee2948c641c34f54714188219e753993314433142c2eedd485256db3ece
213
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 820fceddde29f8c52a8f5e732d1af61312f3b83f38b1b48319c7e483dd
aedcca409dec0c515904080469476dc32631ba169d799056426bbc27d42828d501db7
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 698ef98f42312267bbd141a32b95a9a507f7b5a9aee4208606763
6a767087029
masking_nonce: 113a8437e9e2bd2adf430e8201eaed52e9b853906ed9b80d0d2189
d91b075ef0
client_public_key: 780db9fd2a6527193150755b92203dc6c36664be036b450d65
ea1c6053879d4d
server_private_key: d49399dc3bc1022938dfb0e79db523d4e4e41f494c3898eac
652bf95f6efa108
server_public_key: fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce50
017dc037001c63
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 955917069ff203fd9eb36ca4db4186b09bd21d1157a4dfbbd8af753
d3c80be06
client_nonce: 509c8a9808038ba7ed5651c86546beecba6a0a349e32804d3f41144
c52f7efc5
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
oprf_key: ee434a76f9ace211e52e507a0904422759a09e1b277d3111315dca2a2ce
43b07
~~~

### Intermediate Values

~~~
auth_key: 624a88b353da7886d3396630c7099651dacbfd7690d11a08193c213a725
b8f193bd398556e059042ce89b69ceaa21cc46dca1a752b575f4cd9ecdfd95e04403f
random_pwd: cff80d7205e0e80f3a1c4a6e419131e4c71072d5a09f3723fa5c99575
719be5f080bc4b8a1ad9e4399b42bda0368691c2a582e2d2affd704576def798f7527
38
envelope: 01698ef98f42312267bbd141a32b95a9a507f7b5a9aee42086067636a76
7087029aa4849995c288c6e43757242961b10420b6c2be164f479127988d864261ac7
999b1aae29eedc8abc2bc61c4ad3829754fa49b6978b119c7b8af07694b9e58419
handshake_secret: dbed072a3eb9b27064dc67774c76c00b1e36d12228e03ff6c39
cd57f773257f44466af1bec92ebfb4b1ad75d9bdb8d19227013cc8ba24b49793f2c89
51ea1cbf
handshake_encrypt_key: c63ad0a20f9fa61f94eaf1458a050fc44bd56678fb42d0
b35e520c8742f8eb7c8749a1321467589284fbcb566afee966a83b0d4c1a7651985e8
bcf97e71d8ec9
server_mac_key: 60b63e4266e4e3daffdf2ffd9e6f2aadb9c17532f2b2915ec2a61
f5f5746cc79f4e86e99cf6dac90eddb9120424944a4d66380c621ba02a064e033564c
737a52
client_mac_key: a2dec206f421babeb6ad5a3b1cfb89432f7e37ec8f65b7a1599c9
12929b8a35e6692fc1aa11bb9e1e06cf64411905a0c262e46d05933d61d432f4530dc
7b6040
~~~

### Output Values

~~~
registration_request: 307ff12c023cb5ce33a04efd497252442fa899505732b4c
322b02d1e7a655f21
registration_response: b682303072dbb649d1a15f24a262d61ebe6de427693153
cbdfd02b37755fd97dfc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce500
17dc037001c63
registration_upload: 780db9fd2a6527193150755b92203dc6c36664be036b450d
65ea1c6053879d4dd5359bfb5c56184f682a59f39dbf54af12bfbb623fd89a5e79a28
39a998440947d52363ab9da4519d3a385dfa8814f925913886c9097a5c0df2671927f
30cbcc01698ef98f42312267bbd141a32b95a9a507f7b5a9aee42086067636a767087
029aa4849995c288c6e43757242961b10420b6c2be164f479127988d864261ac7999b
1aae29eedc8abc2bc61c4ad3829754fa49b6978b119c7b8af07694b9e58419
KE1: e6fb9b013986abe5f6e9586a0110395a97ad695dde622d58470adb0a0cdcb37e
509c8a9808038ba7ed5651c86546beecba6a0a349e32804d3f41144c52f7efc500096
8656c6c6f20626f6214b434e33a39d7d9fd6dbe3638925edd7a0344a312a22971754b
d075d8347342
KE2: a22cc28124fddccab3b80b9affd775fd13d64d82022468ed87d276b234d9204e
113a8437e9e2bd2adf430e8201eaed52e9b853906ed9b80d0d2189d91b075ef052562
431de4ff83b37f1a4de5bdb117bb8fcb214bd59dde69f1ad005ec243695824271dea2
84972b9935855f9a47597afe6a572074c7fbf8c06913d5e3f5619869e5639cdfa38de
84cafa2bc169af47ae71dbf10d032444a3e723c73efbefc14764e153ebf72ee0c8bcc
24eb5770940c5cb0fafa7bd1e8fa900b9c0a0ed85b5e04955917069ff203fd9eb36ca
4db4186b09bd21d1157a4dfbbd8af753d3c80be066a398e50c4e395ee52ef332d6c2c
0a77187e2e0b3564617eb66d2878c41e6c47000f47f90aa6605d87912e626c228a9fc
5ba3fe9d5866b7d2b208d37cc4c7ce9736657460f8296ff3801df80e0ec70101d8e8f
cf15986936f9153ecdd96863d0cc8a555a3a9f04851ae522ac53b074ac00
KE3: 00107ba43b71935150f1f4e601137a6a8524cbe7eaf8c2287dd0b08f551d28f4
d05ee53b02c963e715248a1c29a62bc4cd7c1c03cbdc9bc137af73500067c4e7
export_key: 9fa2126b0ab767a9beee11ccdd02242647a91c3d80eedf08bce996b49
2ee7f7ff4e9f0e27ea6a10acba48f173b8c28f096d61d5b8d0a082ba83a086c16205b
c4
session_key: 3a225e87d411ca56b9cea88c5fcfe98b370468a136a41cc931da0601
a9e5d5dd087bc69e67a1969a3c8512efecb6f1f14444d3d6214edb0ae1342c2048827
946
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
~~~

### Input Values

~~~
oprf_seed: 6a2127e90ccac3fc084fc868124c592bd0911ad2aa0b793d49a6705a87
bbb842f6278e596e944175ba60c7c6c54f8c5ccdbc6cde043f34f6f61c53cc2d601e2
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 15fd27806124ba0e39a4288fff2248c5dc169ca7c4193fd0d264f
45006d5e2f5
masking_nonce: 7133b493044da9ae8a5dcf1760b61e72edf10624976aa7e9dce36a
92dcb63d36
client_public_key: e2ea23c8911072bd6d5ee266264799813074ddf16536b79c8d
a2621013f9963da57c4efadaebd97f9ca40a71284449ac89014bbf207e1dd1
server_private_key: 4b642526ef9910289315b71f7a977f7b265e46a6aea42c40b
78bd2f1281617519f3f790c8d0f42eacce68456c259202c352f233ae2dc6506
server_public_key: 7a9e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa
3e421385fd2194903385345e6ac39e2a9911b6e624b0928051af9a6834ce57
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 0253dd83308928375b7f985c91c6d609bd2f8c344b596fb43e94dba
02a7cfc6e
client_nonce: cf6baa4d6f99fd3cc3f40e5cb5699931ba5b46bb640d8cab3cb054c
ceab8e3c4
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
oprf_key: 327cc2be1c91fc8b46c9d1dfd635ece5c435d5a63cd1ff4c6b4500084fd
b32e9e48a08c803e2914c90116cde4c2303897da640a574858a3c
~~~

### Intermediate Values

~~~
auth_key: d6308b4a52ebe747fd6a6d2efc39c273860918d668f133cb20fad86822c
16bf4be5d3304f421d3d31a30e9ca68767b458471d4720f2174de7b57ceb0fdac01bd
random_pwd: e0f23c601a75d96eba157f0fb3d281271c3107b648e952459791b1252
5eb3aee9f0c7e17597d4739bd0759809df494d84a17d8c4b826abd24b81ae4d53c895
f2
envelope: 0115fd27806124ba0e39a4288fff2248c5dc169ca7c4193fd0d264f4500
6d5e2f531fad71437991087734cd5ad417f99d70e9cd1d846827f1b14590157767ca9
fd8bd3a368b7e0f19bbf4120403d3a451d2b318174de5cabf5cdc0bc475f0ce1e9
handshake_secret: 0a9a4ffee34c43e424ad2aca9208533e4659195b99facec9201
b91afcb3194edc67f433449f3f33805119516f3b9fccc9c4034730b7485909f602c54
0a2aef6b
handshake_encrypt_key: 146e316ae6b0200e997187904cbfff34d0e9900d3e628f
2caecf1e15c9c86c89e8a0aac94798120f3d8315a7960d74ff4d6e7239c2e12c4dbd8
0383591972a93
server_mac_key: 4bdb2b741939d08ec734b0739a8700f5c51e9dee43635c1f5b05b
2668d1c63b27a98ce3ba6342d59a708ede9d61b6c050af01b5d8ee324cad58b6c1861
afbe5e
client_mac_key: 68577a5545baf4627629a6d1e8c6b8080d05d2fb532991188114c
134dc527c2d5afae95f426143b9ba6dc0c79ec764d147413dee31638ee8e2b6a149fd
6ca0de
~~~

### Output Values

~~~
registration_request: a2c1e08d638fa00bdd13a4a2ec5a3e2d9f31c7c4784188d
441b6a709f47e2196911ce68a8add9ee7dd6e488cd1a00b0301766dd02af2aa3c
registration_response: be9b989e04ea9a4d1c7dacfacf2238ee0f572bec72d7d6
b587abdfcd084184f3857602d4a877eb87b132bc47ae6b5cd27a2900a54b344d4a7a9
e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa3e421385fd219490338534
5e6ac39e2a9911b6e624b0928051af9a6834ce57
registration_upload: e2ea23c8911072bd6d5ee266264799813074ddf16536b79c
8da2621013f9963da57c4efadaebd97f9ca40a71284449ac89014bbf207e1dd1f0cfb
e3e02df3c0cc075afe8ae12dec931a0e2ccd66c09f8e264c68d985cd548b21f13514f
4b7947fb25049edd5c9e53268a81fde5ab9d62ca88b8bd706645170115fd27806124b
a0e39a4288fff2248c5dc169ca7c4193fd0d264f45006d5e2f531fad7143799108773
4cd5ad417f99d70e9cd1d846827f1b14590157767ca9fd8bd3a368b7e0f19bbf41204
03d3a451d2b318174de5cabf5cdc0bc475f0ce1e9
KE1: 08d74cf75888a3c22b52d9ba2070f43e699a1439c8a312178e1605bbe7479731
9ab7898faf4f2c33d19679a257bca53e27a7c295b50b0d87cf6baa4d6f99fd3cc3f40
e5cb5699931ba5b46bb640d8cab3cb054cceab8e3c4000968656c6c6f20626f62de9b
fa627cb161dd7098c8a582f5fb3a38641e8df3d6e7c40dffec1adff5f0d148716cf15
cd11a04b80b11cc12a1056493b23ee23267704c
KE2: dcb5cd8d371bf831e015b9d8e20c4fa7fcd773e6863fa42dafd52e227f5ce40c
3d08fea94f3a498db8ee02e1c2bbf0f1c4074b670e30665a7133b493044da9ae8a5dc
f1760b61e72edf10624976aa7e9dce36a92dcb63d365cb83069e661b79778f0a4b87c
68fe9cd814ca391ad394f818aa69a51be64b2a22617fe61c246a368e5425e4f845dee
722be334475a7de8b23cecd963c929bc177f28d8cd76a90de6ecca353ae6c4a70f55c
54fd3763d65362832d5aed9790601d735e8fde1442d7afb33b91062d2f6d5e9c80948
8749da6c115d0f9e445ba0b30d4567dc9c4b987501782e6342134b2d7b1ac83db0931
dc430253dd83308928375b7f985c91c6d609bd2f8c344b596fb43e94dba02a7cfc6eb
0fd650f0efdf4cec17e85b9cca2fa7ac7f1ff76ca94ed07e8ac65afd6304ef8102bf2
4376fc5b064edb55fe02027d7fef41d05db3652db0000f6e2d06eb453bc2d4cab3e4f
d39f87084e612afc1199fdc0b77132a9456fc755f006fa416c13479f8c3004b34daa2
5d12f977080a850012fd453b3af8ece4f161e432016320afed09bf30ffd1a2b3a0
KE3: e4e4be5b31955038a4384519d25f8df037316ebc6967a8b3eeb91798af56ccc9
b1ee09239f63df78f8567770968afc16eda271db651d9d30f891924dd6ec0f69
export_key: 35c337de7cdf12d10aff839d1bdfd3fcf88649469e75cfd510fad7137
6da21526f7ffef7e13aa65df95a0bd35681ee802e8c6607afdfb243f618bce019bdc4
5c
session_key: 5582b912ac3e6ca12512ded8f128b760b046edc11d282ba1396800b1
15cea493235768e0b4702f3dc477610443c2fb4a520aff56ee59b4ff47382f459baf5
9ef
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 190122c4561e9e4c78f03fc979961e73fa9b34697d75fc88eafc95c27b
ce6b0c70acbeacbb6d18ac5640b9b88e0037f3acbd5ea25e317899d72ae0ee61c6606
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 30d66af115f83e7273ce1a5c2bace32d3602b0da84fa7d579f80c
49562db802a
masking_nonce: eda275f300a3b202d1197dd75f8213fde2651f4dea8e2a41744a83
788d9eaa36
client_public_key: a4faf481deb10841d4e2375268ee5a9c8b26a7072d33af688b
737bf278f85cf16904bf900a06766ee50a2bfbc668683d5855df0de4713166
server_private_key: f0a17b7f6b056dfcfbee5bd7db70a99bbabf1ebe98b192e93
cedceb9c0164e95b891bd8bc81721b8ea31835d6f9687a36c94592a6d591e3d
server_public_key: 741b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230
316ebd2b419ae2f0fbb21e308c1dfa0d745b702c2b375227b601859da5eb92
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 789a151f55d6559521e58c2d6736ed4b340ddf5ee5b5dcbf8f9d791
371b8e7d7
client_nonce: 89cb028eb1de35abbe0776ba94d005f43c4bad0fac053cc0cb85f61
136f19fdb
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
oprf_key: 696cb1a8d10790c9a10fac129416adca181bb149720087f1dc710a01a38
2a531b5cf92ac1e23141ccac8310905f7ac05dba98e6f4c2ef904
~~~

### Intermediate Values

~~~
auth_key: f035bf0253ef8a53a8c8f2eaff6a52501123c61a3640bd32c2e40fe92a4
a3ffb6d5774476b746fed8d177adcd20bdf92359a2c0cab4f9569d6a4927aca442d98
random_pwd: 193066ba0f86591b5dfb528929974cbd596a8204b7b333a5dc3b5c316
448359cd21c34c4d1cc072d61f16fb2e563a7c33a76f37c5dc1d47348861fb85fedca
7e
envelope: 0130d66af115f83e7273ce1a5c2bace32d3602b0da84fa7d579f80c4956
2db802ade33d6b3318817f61146eba2fbd14220df6176e31f4a70e83e0ac7e8b80d0e
06518f43372d432fcef6735fdafe4e1f180e5419e07a5852eb2109bb83ccfbe579
handshake_secret: 5e866ba36e0515af45fa4503b0ed73daa8af12e46d757139b7c
6969a4ea2238c3ec3dcf4cb8ba255350baac2dee226398cfb6abaaa56625326636907
81794f16
handshake_encrypt_key: f60474bf5530f511ddd9b80182b529166b05a2a45095af
70597697a2f3a07c2ce3e89b9e083891f8342ec2685f570f12345c45d42e086f5cfe4
b3231dac41c33
server_mac_key: 6e3bd517a081d5042e9753cc5ec71d874643cda18eb6be84a5ac0
75675b9674d684573aa93a7a3ab119602ca09eecd8f2202a56d7a504091af6b9e9c02
af083a
client_mac_key: 53383f51c041555db080735bf73f0fc4f72fd294f6b560cedec31
2324aff9c6e28a1a5b09d61b35c32e597b3e7c97a7ff613f54ee38e006941a51be7c8
cb849e
~~~

### Output Values

~~~
registration_request: 66660fc08075380d7c2d4728ed1a7b550647e8231d6d29e
60d3d1fa8fa3132c8dc445fa9c94de42e5f12e29de958e5daea84eba6a6410042
registration_response: 328c01e7e2deeb960c41882090c19b303b10180b0422d4
0ce8e8ee534732ff9599038ae8482a950a53dfc731a1685d35fa1c7e557a9e92ed741
b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230316ebd2b419ae2f0fbb21e
308c1dfa0d745b702c2b375227b601859da5eb92
registration_upload: a4faf481deb10841d4e2375268ee5a9c8b26a7072d33af68
8b737bf278f85cf16904bf900a06766ee50a2bfbc668683d5855df0de4713166786cf
18c34e5216a1164b366c4ebba0006e44f26fddfd82c7d3f663afe9019d82b7644ac11
13ae992ab6e98f0d98cdacb8e171a219c0714a6f42cd98f2c484ca0130d66af115f83
e7273ce1a5c2bace32d3602b0da84fa7d579f80c49562db802ade33d6b3318817f611
46eba2fbd14220df6176e31f4a70e83e0ac7e8b80d0e06518f43372d432fcef6735fd
afe4e1f180e5419e07a5852eb2109bb83ccfbe579
KE1: 1c83acd948f714989a2276ef0c3bb16d5b637942e6d642da9826fbcba741291f
0b093b8c94888ff0ab621f90344f5b8b72159e2eb80651c189cb028eb1de35abbe077
6ba94d005f43c4bad0fac053cc0cb85f61136f19fdb000968656c6c6f20626f62ee78
4169a2abed53764292f2e7385c5dd99ee21d09a4df24405706a59abb6d91f3ed3dd8c
6649807d11cb59ddfa23fad081ddda04ea49075
KE2: 6efa73574dcc6b87a8e0352c0005baff4168cb3bed0ccb9d7160f516ed392e1c
c40d3b11d2dc9505a586b2ca20c5f16b32e59ecd426315deeda275f300a3b202d1197
dd75f8213fde2651f4dea8e2a41744a83788d9eaa36815249e31cdf5a3a1dacf903fe
60e1373f7ad1359f7a927b1fe63473aedd907cf08cf68293daab01f051b51bb882e98
12e490a1f7369ec5ff82627be91b5d2d1295941ab45473b6a52270aa52eae538043b6
440e899531ec3c8da523a7220e8672f43df5e9e0a49cb356ba387ba69dbb1897f108f
51d4692a2f70c0fbca6ac58aa58bee39907ca8206680492b50f85e3da1f346a2b39cb
486e789a151f55d6559521e58c2d6736ed4b340ddf5ee5b5dcbf8f9d791371b8e7d75
cc2a00d1b42d14ac07e05dca2dbc20661a4f30909137bc3274a25c3fb4310fc9c61d7
6fc6576c8ed1c9816719433acc81722a2a5e23357b000f3d07f508a370dc7d5df4c72
353889a50cf31f56a754579af8580e38db8a055a472b68ee87b13616e0873bb20e700
b333e5261576704eae44741ece394be41d75ed7d7519a013bb9fc88bd68240d8f3
KE3: f0e14eae2da303af2adfec19d10319f89c41d8b5c75cec9b9c4d81641818f8be
19dcbb39ef0611b545df58d9931d774aa1540d22397e37c8bfd4aeef2a67ee30
export_key: 33341a87cb5eea641bd3d0d0e33edf4fee9c7c8abcca19c5419725a19
c370c2aae3c2c59c6ccb776e63ee6d8a76389a57b9413bbc24700a24afb7ac76a0496
b7
session_key: b6e01ca8f2ed56cbae1942cb7b91cfede89eab04d76c239bf33bb88d
3ba93aea3863242fb8201acffc8b8c4f01e06a4e21f4404057df22fb0e672ec3b6649
095
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 0b43c8528d14fab875b01658702093a48da5619a4ce2919dce7be4c6a3
3b59e9ac6447f4060d04622f4396b28e1c37cb8c757f61a40273ee89b3beba6b8b16e
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: faea1ca3335c46ea8445f2ba96d6f5552145d41c9ec4b428bf198
2fb00ffb144
masking_nonce: 9a356d31c570bfbbb7514f390341eeb9a3f1804e8ccd1159902062
826ba16af4
client_public_key: 5c5b58d906cb4b3e6546f384d021abc18b7cc4bb904f9216d8
04aecc49ef0ec952879accec37d4af17a71d76a8e7be2a3ee5c8010aa28b20
server_private_key: 8cd37bf60927fafeca73ed8093538a994b1a8bd463666faa0
68e5ff9e00d588446b7d6cdc09ae8df069b30987a2cdd39286e0481e87ae227
server_public_key: 684e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04
ef823fc5c55e19163c714071efcab7ec06ccce8e6b9eba74ca92444be54f3c
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: c39417cc6c066e705bb352a21fc31bbf4acefa5a0feab94106e1544
2ed431501
client_nonce: 6455d48bb5aeb0f50222e4f0e91eaeac43e415f39bbc0d83d9fb553
37fe36300
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
oprf_key: bc421bcbb7b7e3a79afe535026411b5c68f5764855bd939cb1c7037d386
12d77368b4bb42756f85ce14b10d4abeaa3968b146bd881ea5438
~~~

### Intermediate Values

~~~
auth_key: 57bda87a2e0eb0d3779064bbb4875d4517bceca5f060b62a2f837ebebf4
42f3b6e689ea31d321e202b48be0bbcd45acc27cdda8a3e5f3e5c94c23c60d18984c9
random_pwd: 48cd6cb45c453e4ba951ffcdf93cc9d44afbfc6118068c73523317f0b
ae77ad45d65314a22d6561b69e80fbc272d759aa3a2b3e4bb8852c09d596cb6ebcd30
60
envelope: 01faea1ca3335c46ea8445f2ba96d6f5552145d41c9ec4b428bf1982fb0
0ffb144fcde2bf571dcf5a5e97772abeaffceefd4cfccd006d11bd4f2c108cb39e660
4ed9f4dc304eed76b08ded353e585cebaf5c36380f5afd6326fc5dcbde5a7fd9fd
handshake_secret: 3acbf8e60556e877ba137633dd822606a27057b41c10e77662f
55c972ba3fcab24d07d8076dda81250f0f9085bb133a03633ba868d7bfbac028b95a8
377779a5
handshake_encrypt_key: be0188903e702a1eef6a82630c37ffbaea01df4e797f95
2848ead341ee45c0da91f680f737f1e534e5eb83e938b989c78d60cf303d351a726a1
6fd1616514ae2
server_mac_key: da01df05419ac4793799d6bda772be013dd0f0ecc97c23d8386c9
f8038513002d06055119d89ae03e490f6e8f48291507fb0bad556d20cdf585b59b1bd
d7ab4a
client_mac_key: 2f77372e9283f3ae5e6d609f9ec6321707705950a88ce26c14fb4
598afbaf72b462b26b2c7e41957370e5cdfc072f7cf250e39d295ca350470857b14da
e0941d
~~~

### Output Values

~~~
registration_request: 8a8f12abe7f223895549fd121f9d6124424273b7524e033
f610261caf6ff83eb92d848318e7574c06ccee189b8b447b0fd26a348942d787c
registration_response: c0e03fa9026bff08cc42a4ac2c8cd559a2f084bc376f2d
3afb8b8df7f1c545f1fdc750450425cbcafc1147070fbb2ef5fef285bdb51b290e684
e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04ef823fc5c55e19163c7140
71efcab7ec06ccce8e6b9eba74ca92444be54f3c
registration_upload: 5c5b58d906cb4b3e6546f384d021abc18b7cc4bb904f9216
d804aecc49ef0ec952879accec37d4af17a71d76a8e7be2a3ee5c8010aa28b20841c7
736cddaa01146c38f5fe7285e7634547a0c3bed4b7b7ace169756817ecc64da6577cf
9fe830c3ca2c2566781eb84a049ecbc4b3913b198ceca940e9981201faea1ca3335c4
6ea8445f2ba96d6f5552145d41c9ec4b428bf1982fb00ffb144fcde2bf571dcf5a5e9
7772abeaffceefd4cfccd006d11bd4f2c108cb39e6604ed9f4dc304eed76b08ded353
e585cebaf5c36380f5afd6326fc5dcbde5a7fd9fd
KE1: 442b8d7585abe08bbb6b03b3d73c7f5d81cba60845258a4174e7b8d25a6d7238
8ec7814b7f0a0559fff29ac97c329f2c7b0844c3adb1c6ba6455d48bb5aeb0f50222e
4f0e91eaeac43e415f39bbc0d83d9fb55337fe36300000968656c6c6f20626f62d0ce
cdcb40e68a8f2a3c472d1fb7f0d96ce9effb7b71281a588df2ca0666ce00126e14b9a
28bbe73ada49d059f7794e5da6be7e7bf0eee12
KE2: 98b1e035106a915e022abdc4282bf814c69ec685aee01cb3cb725e0271e5ba42
efc38af72f05d7681f8f02852d3c9a3f22ce7c1400b02c1a9a356d31c570bfbbb7514
f390341eeb9a3f1804e8ccd1159902062826ba16af4fc8e9c4f839b0fde73e4f73e44
97e1426845982dece0c94896ebb142357f56ebf3f21b6517d2334126128c45355a443
bb294fc7cdb33032f74508fee0a3f6541e0e745ad19af561268231854dc98e91b56a4
8233f2b2c9c1f2f78893fd50ab892b892d31446e17918c8935d09302ed1bbded5a92c
d32e0cc30b95778aecd84520275055c7d360b14d402074920fd0a9213a1c12124d999
99bac39417cc6c066e705bb352a21fc31bbf4acefa5a0feab94106e15442ed4315018
0f64e52526682c9d332c4cb517bb261e21b86bc7199223b962c3d2906f90bbf3252a0
2bf2889a01d0cfcd6390b8567854107e38abb21033000fee4014b14ddb50a2e1f9584
e4706590caebec9b79388cdd988b4a8059369d022a4c53e910d5ef6033ee9747e93ca
3f3b7b037edd9c02438501d33cf1e5d1e14d01beee625674c9cd4065cbd6af89c5
KE3: 51faeabd6fa11f040a1b7e9f402a8e05e6f4032494d949bd17ad32d34eaf4cc7
a03326240ef135c636b2412149f6d9430280a436117190957e6bcc165a0ec0e7
export_key: 20dc6777e94d2211716211ce4970e1ac737cf2cb0c744a0dbda37ce20
513ca7cadf910ff7a1dccf580cb829562e2b6f81de9ce6b49ac4d0ea3d4e6676dcfa2
b0
session_key: f4a9e741b199bb8093116680f2b178e589d02bf6e660a72744575db0
e66c3da0c881d741897162cc43e72ab68ed28e59c48fd349fdd50b3e9e820763a2db8
589
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: d219b649dcce66f384b11136cc336cb0d79ccf130d136e9e32091ec9be
a81519bc5a2cfc8b70156abaf3410123aea6da3edf2d1b9271fa96502e844ce6d4674
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 561f16f4f89f2e34fcac70fb8d64087073f30db5444a72a0293ce
f746c1fda81
masking_nonce: bc9ddd5966847fd0a8ea0c082ba059bbf7db5d89c04cd565a27db6
6852c62f75
client_public_key: 1080a503862afa59de08dff207372c93e19faf059837b38978
d32d46d172df67e0fd420d5b5ab4a48d3e7253561e1b5975aea4b2eeea80b4
server_private_key: 0fb0bff035e9b9cbae6cfca36aa4827ccbac66177b64fabef
a67263087c0cb4e0d9cf547979e753c22548e3174abb5ac630d97dcd4af9830
server_public_key: 8071f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444b
a7ffe82aab916bc5ca6a11fd5fe1479e553040a8b724b6305c3f4289f3f39a
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 56274a35f5129b42a817632e4bb7788c57c2e8231a21c64e5a310be
fc80067a0
client_nonce: 8ef3f8af2eebbb41d83235422f385ee01c2bb21ec7d473570891239
393d2b3fd
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
oprf_key: b30c1faf1f49c721d4fd4d05d1ebc9483826642c79a8cb1f2cbfed5467c
0c0b7e929a7f1cffdd7bb854712561f06c847b71b2ed3acd6fb39
~~~

### Intermediate Values

~~~
auth_key: 55c3f5e6e34e5d1861a57dfc89a4e2591a9a2c3f742f0dc003760b6ad99
e20eaa4cecdfd028d991d12b270edca3d3773b74291bd974c9fdf5acb6a8ef979cdfd
random_pwd: ddc0956a4155cc4679de111a4eb3f76d3fcf76799b0461544b0095f7c
033cd7a736e2b599583e828122546de3011401d3bbc3a4ba86554546290a43f1b34ad
ad
envelope: 01561f16f4f89f2e34fcac70fb8d64087073f30db5444a72a0293cef746
c1fda81ac86c8202f6bb77908718ff2295e4b17e94acada1f18baea5bff94a84d969e
46becb411b74d238ccf0f53c90513770f0f3e3b8d81cfba24cb537c099d4f92b58
handshake_secret: e2ad46f6973f2254a83a19c9e9c60e98e690739c4eb86eb8d35
bbb36f1e1337d3810c9f1e6e5a22ec111bf6ee483e94e189f12e1ac337c779087678c
e5a4b06f
handshake_encrypt_key: 63d75cad55601ec34282795c25b64cad53014e8e8a61be
369edd95a171b9fe356d5d2faba13bad7d2150820e0f7a3652f4bc5baa9716fcf699a
1b15f5a62559c
server_mac_key: bc59181e7bc8b76c3fdbb6ecc71ade3655419bbeb64af5e9cd417
53bc3e33a82a3b39934b145f3bb96f25a7bdbe5e84e26094c7428dd09402415e17c98
7f0316
client_mac_key: 407d300c4984333aca2dd54064c13bc265949bc669097fd135e16
e5d97f57c1550a96eb0e994ef9855bc40dac565858e593c672d15945b5a17fdac49be
bf8bd3
~~~

### Output Values

~~~
registration_request: e499c1ea1a644df877a01f23ddc5dccbf3add4407605f67
dcc55f29c2ccec5daf9bc231dd62aa61cf2c9fdeaf59b3ed7a8f33af59ba20914
registration_response: 4ad8cc75f904c940ee8a894ec44f1ac073e6cc0a71495a
e94cc2063b8982e107fb21fbe27b01a7952e2cce18067dbd2726f48cd4c50b06a8807
1f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444ba7ffe82aab916bc5ca6a11
fd5fe1479e553040a8b724b6305c3f4289f3f39a
registration_upload: 1080a503862afa59de08dff207372c93e19faf059837b389
78d32d46d172df67e0fd420d5b5ab4a48d3e7253561e1b5975aea4b2eeea80b4d9075
d5800ffc6e00659a4d81f3250ceb9554c5a959b073c5690cdec54156c567185b37477
5fb0eaa2245815561d9fe12ecbbf83c978ad63ea45df7bbdcb03d401561f16f4f89f2
e34fcac70fb8d64087073f30db5444a72a0293cef746c1fda81ac86c8202f6bb77908
718ff2295e4b17e94acada1f18baea5bff94a84d969e46becb411b74d238ccf0f53c9
0513770f0f3e3b8d81cfba24cb537c099d4f92b58
KE1: 501e3dc8509cecfa36efadeba5efd0e4f66988ff9575c821b0128af06a2f5ebb
d77362f2a9e63b5a76cf5a636bad31b7a86f6c6803a2c9958ef3f8af2eebbb41d8323
5422f385ee01c2bb21ec7d473570891239393d2b3fd000968656c6c6f20626f62f2a6
7ee95170c51833a88419529748e55dd13e23ffed8fefdc1d2b7c939b6371630031299
800b01a99f83129aa986369e4a188220d056f0b
KE2: f8f2ce120e0576baeb82509d38137b4409fa32a73ade5f4892729ac8c267a992
e65fbddfad450c74e7d12b303d1fd1db3faa4da973653157bc9ddd5966847fd0a8ea0
c082ba059bbf7db5d89c04cd565a27db66852c62f75059215a2ed2302d44c57da97ce
5270362af731eaf5cd10638c3034fb1cc8a6b1c658562ef769495ddbaf5604cb5b166
eaa5a6aa0b70e9728d5174f269ed256fe1d71366f1a5ac38716b896891247b25d4a0e
ef54a9134d54fc92978c869d98946a1272c182d498fb1f69bfd2e2ead2c936d4383dd
c0d7b5a4ba1cc65d2d1878bf7f7177b5db04361dab0e23fdf556f216792ed32bf3202
023556274a35f5129b42a817632e4bb7788c57c2e8231a21c64e5a310befc80067a0d
410d142e679aee86adbe57da4801741034120c59fa942ef44c19ffcf4a4d65200d5e1
7e7d287220037ab038ee08f96c9dee6db68f02cf18000fe20e9f8e9eb73d860334818
4f247700784a28ed9b10c0f0829819cf52b4da329b67ee48aa7a0ccaddd48a96beba5
03e99e40fbf4632cad163dff83c07e8576d63f0c6d84251093837531e48a58d852
KE3: 0c2f6dda6e6131413dc84c08d1c0ca31674837f5c7d7baf344b9708a2ff3edf2
cdbe8873e7b49c4a11f6bbe20191be302bd1a86964b83aa97bc3ff72464ed101
export_key: e020473407645a61e3ec0963b98992ff2b7cec5177132e2d4647d3182
c7d82f81012a312a5f0ffe034646d6d89a9fc4846817f3d635946f666842b6f9dfa20
41
session_key: 3d80e12002f8276255e43842b681e47254426e6278f286f074873ae0
893e07ec0d2487305c6e2e618a18f6d231360e8833b768ef3ac0d8a49a6d5e5bbb9ec
b62
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
~~~

### Input Values

~~~
oprf_seed: 7fcd85505ea2480937f14c3e449170b97f8b4726ded68c570460066d6a
bb3b83
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b19d12c453e4ce96872c3fbe64059592000647898a217ca827dea
6b132b68c6b
masking_nonce: 839a03b66d4c3072734f418764c93a844c29d072802dcd25dc478f
f721e5ea1a
client_public_key: 023acdfb8e523d1679a97f36ca14defc73319a71a42812fa2e
f6302c99014371cc
server_private_key: b3c9b3d78588213957ea3a5dfd0f1fe3cda63dff3137c9597
47ec1d27852fce5
server_public_key: 02e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398c
7100af2939f672bf
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 44e14cba9813ac6ce192da4df76cac4ffcd57fddccffc2ce35344f2
bef7e7acf
client_nonce: 68060fc42ba96bf985e9628be17970b38ed262334b6522e38c6b402
db06a50d6
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
oprf_key: de9cce8b29b8a09655c65e633e74d3355e40747318338d6b7d171fe6807
c9ad8
~~~

### Intermediate Values

~~~
auth_key: 1bfa332bce9ca20a81720705cfb6ce6885f8a378e3c263db3b62658c4dc
9a2b0
random_pwd: 77bc887f6331170a52215866ce0a406c91e39fc4f7d4fc5bff8dbd4fe
80542cf
envelope: 01b19d12c453e4ce96872c3fbe64059592000647898a217ca827dea6b13
2b68c6b0b6e606b5e08f322259537b516209ac492fbc076e2f1d1231a112ef9ff6fd7
f1
handshake_secret: 975c81e7787e0d10059e6ffc07933dd20173fae822c7f81b83d
9042661743e7f
handshake_encrypt_key: bcfa0124a4aac400d476a2babd536fd706de3090332390
7071807f516b95ecfa
server_mac_key: cbe3541f06987ef8553e0943e53106dfdab5e6c4c3d8bef901ba5
4323ed4f673
client_mac_key: 72d796639b64b61683bcef52ad1d6cb42505c710b5c9e07896bde
29a186fafc4
~~~

### Output Values

~~~
registration_request: 03761c2597a039a535c3180bd3fb6ea9830baa50376dafa
6e98bb41be2aaae0e91
registration_response: 02ef8a6a5865f4f68058664e06ca89919faf6e8de4d9c9
407590b563b27b274e3702e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398
c7100af2939f672bf
registration_upload: 023acdfb8e523d1679a97f36ca14defc73319a71a42812fa
2ef6302c99014371cccb81b64cd59115b30024579794dd81e1288f6dbb086da09b298
76609c62426df01b19d12c453e4ce96872c3fbe64059592000647898a217ca827dea6
b132b68c6b0b6e606b5e08f322259537b516209ac492fbc076e2f1d1231a112ef9ff6
fd7f1
KE1: 021922b40d051877d0f03ccf2831eede9b328e22c8b173d5f28091af0b92421f
5468060fc42ba96bf985e9628be17970b38ed262334b6522e38c6b402db06a50d6000
968656c6c6f20626f6203285470567bccdd3755aa8d00261e1ce65aa120e15571cc97
72789a361b4cafaf
KE2: 024c995d208ecedababc96c623146a883c496b41601c8d8f23514a0b5e3e0b7f
18839a03b66d4c3072734f418764c93a844c29d072802dcd25dc478ff721e5ea1a2e0
a09e268e25bf49a268aec96d3b7b862d09a4222d7ff04122fb804d0ec089a65798aa4
cc7f9d9bd9554bd688001c737f56a993570f81f762ab0501b83fcb0ed5833bc750296
f231a559310048b01ff52fb2d21889ef6b44e7fe49ee367d9975d0144e14cba9813ac
6ce192da4df76cac4ffcd57fddccffc2ce35344f2bef7e7acf03651207f3887f92cfe
c56edd9b9df0047c1d6b7bfc55b3650a9579d44f435b092000f8b3ac2f651bd1ad31b
36df72c455e81f2a01cae948d5aa17e64af76ec1009b292fa27b894e29bb402a54320
2162f97
KE3: 177a431645d75edf068cd22197692c54e560f5514c1158cd21059fa207d83547
export_key: f3b79f0ea8f54da6f090aee7d90aa9f3b1dc33d51303eebfcee587639
66549fe
session_key: a20a750552d9c73d748b4f5f933a3d2b45997541163c5373c09705d0
b1e6244b
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 30ef847b9577619b01227e186787bc994345900bb1c473516e2973850d
5d411c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d13bfb78415880d62966a18f047be91b6f24515f5935f96979404
f670ad73bff
masking_nonce: 5b8d004ab44cc0c947721694981f115173d6fefa3ea076647e516b
3242fa581f
client_public_key: 02cf4ea49ec5a64286be8fb1cc34d98d96f772ba652ca49af3
28c9d0710ce9d340
server_private_key: 2bc92534ac475d6a3649f3e9cdf20a7e882066be571714f5d
b073555bc1bfebf
server_public_key: 0206964a921521c993120098916f5000b21104a59f22ff90ea
4452ca976a671554
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: e4bffe91c47320cd09f285b5b209862c7b72ef4887aa0c1ee53a330
e5edcabfe
client_nonce: 3c7cef49023bf1d448f3debda41bb0c583c6f8c550d54ff074d984f
15e269018
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
oprf_key: dd5cfbd813aac03ec6ba7b050641a60e8b06cadc9b901b1330ad267cd07
cd56d
~~~

### Intermediate Values

~~~
auth_key: f12a31f2d39e732873bf833ab2e6a55c90ff6220b2ce28fab0018d76210
28422
random_pwd: b1840e4e6ba0600f34847cd043fb361c18f2ddae1689f6a9a366737a5
672a4e5
envelope: 01d13bfb78415880d62966a18f047be91b6f24515f5935f96979404f670
ad73bff51658135973310410dc3825421f73decf5c8fd98e8ef216782c89ce3562c69
3e
handshake_secret: 0f0126a38a11b7c589cd081b59802296eb7d3484534df06555e
22808a0ef05f3
handshake_encrypt_key: 578ca3a519227b90bdfb752ec288f864e7298a4c611387
b158f80e74d657b2ed
server_mac_key: a56ae9eb92613930611216ffc4a0a764789d86bb6d2c91405f24e
8ce22710a1b
client_mac_key: 6c62a4b1a79f1ec7d77718f9542cb61642682a4d574d7b688f017
8833819cadc
~~~

### Output Values

~~~
registration_request: 02cd04a4a3c6b37f6013d848e1c63c204c4593377e9a14c
68e95097b615d29c129
registration_response: 03b722d3e4b030978ab2b6f8e4a0b54ae00162563357b6
838258878158ede662910206964a921521c993120098916f5000b21104a59f22ff90e
a4452ca976a671554
registration_upload: 02cf4ea49ec5a64286be8fb1cc34d98d96f772ba652ca49a
f328c9d0710ce9d340d6ac9434d49dd72c182f1d23a8806152e14698e77ad11451b2a
3336232c798df01d13bfb78415880d62966a18f047be91b6f24515f5935f96979404f
670ad73bff51658135973310410dc3825421f73decf5c8fd98e8ef216782c89ce3562
c693e
KE1: 02e747d027881e63565ce0a611dae6da50c2a8b349010a52f5c936169be1e0f9
363c7cef49023bf1d448f3debda41bb0c583c6f8c550d54ff074d984f15e269018000
968656c6c6f20626f62031e7dcb77fdba4b7e7b1625e43dae84733b28eaf2b4fbd7df
141b1ee353748b44
KE2: 02bd833be4ebc6d8860cd4b7e4bf6c9df675d1b473f76ab817a8fc4446b26d75
075b8d004ab44cc0c947721694981f115173d6fefa3ea076647e516b3242fa581f63d
b092e41077114ee8ee080ddd33f8195ebf8d5186c7441fe3d4d8de40cb99f1d1a99f2
e066b4c44837040acdbc6f5e0df49c97a5de1ab0be0a46025deb31c5124bbb7860398
44bc5efcfb0ea35322622fb6074460469e64be9aa416335fd5252d9e4bffe91c47320
cd09f285b5b209862c7b72ef4887aa0c1ee53a330e5edcabfe036d85072a9cda8438f
67dd81042861349f697c06ad4efb068dceb58c98986409c000fbfc2c34777aaacce03
8aada34c2529bb9a2d87544e3f1b5e5f92ed4e6cc97de3996871e49940d167b206d66
9e4da5e
KE3: 39e6b5875e0d246baabf86415182b2dff195b373cb588d6bf3b57089de039a7f
export_key: 7cdaf250faf0bec503f90aff511d8f76ecdf30982f62bc2122971c086
f844a50
session_key: b24d56a110252943c3fb56d364471e60bdd214a3f0c3df5c5db98d4d
58e7b9fc
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: d06355c9667d2fd3ef2abf71f4627f0ff71d7a4ca5fe161351931d2c68
637928
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 3a81f1c7f0584f852faaf01217cf1889ccd17332f22ea2c54a65d
3b8b3934c56
masking_nonce: 784ffb210e243a21d7225e1ffcf6f057b5fc049a27f986ef25fac6
7cd36fb57d
client_public_key: 03b8a5e5e722156e7fdceaae1c7e44317a594e165c5f7ee4ec
ac77a818bc114206
server_private_key: b0b4f35c14eb2477c52e1ffe177f193a485cccf5018abbf87
5b8e81c5ade0df0
server_public_key: 02e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e5
59ae18b6bf7bb5b2
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: e727bf8fae8e1a1cf665edade027339199620ba0b856aee5a9c79e8
6a801721f
client_nonce: d6942a668dc47cb51adf9f26707286c681b866034454aabfb2f9923
bc4b95220
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
oprf_key: 77a257d8be2494fed00ae46477b8db07ded4969cef340edd0b2d8069cf5
31a67
~~~

### Intermediate Values

~~~
auth_key: e21fc628aa698eb692cab04547b0861f34dafdb1d3169c2498e5aa993a9
ba8ed
random_pwd: b6a6be266071f536c45721834c6ebed9d1be83ceb2a6cae5d5998f828
b88a0f3
envelope: 013a81f1c7f0584f852faaf01217cf1889ccd17332f22ea2c54a65d3b8b
3934c568c0cc87f729e34d0812accac781a75571b19400c7999defb51d8a04625c8ed
1a
handshake_secret: fca64ce4a75bd431c52dae547d733d0ffad27973580afe2cd08
8228dac810d90
handshake_encrypt_key: b66e8df691cc2719ba911564ed53c546f693cec9517341
e36e9d36a47c7aea8b
server_mac_key: 2b16c1508ed8b45fc82ca017b6dd4c9e7ab6a46518ac73090de22
fc3a8be5eda
client_mac_key: 7832131167637bea1783b132af88f923c0c59d2235328f79a9b94
a454be21fbf
~~~

### Output Values

~~~
registration_request: 026aa49819f2c29b9543cefa0850db7fd36352c6ad8f47b
631b5b621266b670f7b
registration_response: 03cde6c80f1191a60f4c3f348133259ca4385053258d4c
7e9dd7a024900baa29f702e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e
559ae18b6bf7bb5b2
registration_upload: 03b8a5e5e722156e7fdceaae1c7e44317a594e165c5f7ee4
ecac77a818bc114206717d9c27efd5c6c623412fe39595a3c21db8dda0b72f75536e5
e5d4a5b4e1aa3013a81f1c7f0584f852faaf01217cf1889ccd17332f22ea2c54a65d3
b8b3934c568c0cc87f729e34d0812accac781a75571b19400c7999defb51d8a04625c
8ed1a
KE1: 0223c6f12f3c763bdfea59c13d8f1e055b02277625aa06cb3d839e03a60268d7
c1d6942a668dc47cb51adf9f26707286c681b866034454aabfb2f9923bc4b95220000
968656c6c6f20626f62026ab0dc783fb12c9427dd0bcb4d95f5b5212f092406dd581b
d337c73468953226
KE2: 02b4a50226c2ade496727d52dc77b1ac2cd201d9645331376d4fcad6382c12f3
4b784ffb210e243a21d7225e1ffcf6f057b5fc049a27f986ef25fac67cd36fb57d7a8
818f3f000691c0f71d7bdfdf4fac72d7b21ca0b9797995f9bddda973f01e2008b9eef
54658aa0f76bb718c4d0cd865310307c86284a0b4fa32c73e91aca500aa0f7555a8d3
f65020110fe13c66455d68b2acb19e4d96cd84ac6729776678194dfe727bf8fae8e1a
1cf665edade027339199620ba0b856aee5a9c79e86a801721f0222d4232635f4ee370
6759740d7a0d8fb6a4068f2fbd34be7cf065f9989b637cd000f9334562da579e1da79
6f3cd5e42b7cbb08c6111b9c9ddb9dda86b7f55c56ddd757c07a56c0ce640d1e07043
134697b
KE3: ca8bab0632d1539fc3e3b51789a94e48ce5db9bc37a21843b6d241146cc3ae9d
export_key: 770301199aeffedc799c894dcd1ff73be57fb0ef79c1cee7217c5b619
b8fa337
session_key: e9b4011197661c3496797599c737d2d7c1d35e1b20768d44c564eb74
6443e579
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 2626232f3ce9e7838eb3e7fadad6d632c721452c397ffff073f62722fa
5d41e5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: eeddc37b6ffb78e2957b706e9396960aa38f5ba6aed38f62c98ac
ae309189ae4
masking_nonce: 7928894946e8ebae0e0ee362b2229963fe6b368417fa0b4359587b
5ae67579de
client_public_key: 039043f001d79edcc17e715baab84cba85c6b72dca06b88025
d55cd24fc4c87204
server_private_key: f7493200a8a605644334de4987fb60d9aaec15b54fc65ef1e
10520556b439390
server_public_key: 021ab46fc27c946b526793af1134d77102e4f9579df6904360
4d75a3e087187a9f
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: a2e05803e51fb76c3263a121207abbdebb23da10ef98455e384a72d
34c7c8b71
client_nonce: 0a2253f00fe72615d07c4d4fc6d7163b1b54ef0e353a366dda4517d
7c120c414
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
oprf_key: eb93cd1ecd42fae7d0489f637eaee4f1d277141c6e7b2a6ab50a2564412
a1571
~~~

### Intermediate Values

~~~
auth_key: 0ae57185bbcc3eefb8850047e5c7ee4be5306f67b1f0d42b95524206d76
c6ac5
random_pwd: d62bbd4ce3a0b32449ac95139769c10d762b295484cb64b9c1e0b08a9
885e6bd
envelope: 01eeddc37b6ffb78e2957b706e9396960aa38f5ba6aed38f62c98acae30
9189ae43017baad4a5d8deb9ee55affb9c7a36ccfc1d84eca0ca9a390351d4a1da641
ef
handshake_secret: d28f283a0bf4e87f3d6623e723ed90d3c6e8f42b0cee7568ea9
a128ff8d48b89
handshake_encrypt_key: 9a3b72c5fb7c518358222c136c441d0d8dccd06b56f84f
f70ccfb19debfb7049
server_mac_key: bfcaff76cd1039488fbcb6cdccd77d934e46065b16f9585b66bb9
c3da134304b
client_mac_key: 1250048194ef3294f112e014bc36f4764c30d17ffb5b2e9b4644d
896045c18bd
~~~

### Output Values

~~~
registration_request: 03a120f6f2a0b858f546d1e2b60f810ad0ed8511ef0791d
c26d8413fe13b0181fe
registration_response: 034e6245a51dfbc19daebfc2a9c9a0bbc4b82cb8953878
732e84cc2fd51572aa16021ab46fc27c946b526793af1134d77102e4f9579df690436
04d75a3e087187a9f
registration_upload: 039043f001d79edcc17e715baab84cba85c6b72dca06b880
25d55cd24fc4c87204f877daf19cb85bc7df1ae13590eaa7dfdbbe4258cf0cfeb3327
8adafcb874add01eeddc37b6ffb78e2957b706e9396960aa38f5ba6aed38f62c98aca
e309189ae43017baad4a5d8deb9ee55affb9c7a36ccfc1d84eca0ca9a390351d4a1da
641ef
KE1: 03edd5c0afa7257bbaeacab64837430929df9b36bc2784e47577e071a7abd9f2
ef0a2253f00fe72615d07c4d4fc6d7163b1b54ef0e353a366dda4517d7c120c414000
968656c6c6f20626f62033b64a07786c37f90b1abc757bf074c18326773bc296ec69f
38c111e4274a4071
KE2: 02ff18f0caff2ef4e335c115451a95d06693a067e53821d6dd2d96fbec1f4e90
237928894946e8ebae0e0ee362b2229963fe6b368417fa0b4359587b5ae67579defb1
298b9f3201e494b877080d05b28e590ce37542422fc0433d1ff70dee11bc9bab86bfd
3971ddd8b24b46179687c60ea959a357e72703c9bb40681fcefaa8a7b476ee81902a3
78e3a8f2b720c1cda2915e11ca2e3085b204423b98c8cdd841f5498a2e05803e51fb7
6c3263a121207abbdebb23da10ef98455e384a72d34c7c8b71029ad3943fb8e838ed4
9e4d64e5f0b84e120f175f30115009f18f009f7e35081b9000fd7281d7b0638a0d68c
560984a46613156afc93a222a48d33786719bf33458e32da316f92eee6a36a657d712
6bc0358
KE3: de0d5687af61d4397b55a3909a5299c43c2232022c02ef06b766abf5d14e0ebe
export_key: e7811e9f8bd5b8c9a43f0b571c4545970a75bd0b37aac02f9ee65d28b
af0eb74
session_key: 9f67891c86a2a1c2ced76871a584f9d05ba51f6c82f737ab2b15cec4
d4458b3e
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
~~~

### Input Values

~~~
oprf_seed: 57c17f95b4f1f02d04ca613d784dcd43c07178fff35fe9f423799f862d
c45fe63a5dfc53257b236bb8ffbe4d5fda1452c029cc4a92b6a907d40e6c0f52ccb6c
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 946e2072c6179dcbe6d14471865f29635113da5928521da16d42b
72524880347
masking_nonce: 617f386118627245e1460490ae47ec7dedac0872fd8824128761d8
838b5ab08d
client_public_key: 03ebee109625c9e1f398455b80df17b4ce16a27535fc37bc97
13d908eee8841778ae00139844b95c635371813705544723
server_private_key: 6b61028c0ce57aa6729d935ef02e2dd607cb7efcf4ae3bbac
5ec43774e65a9980f648a5af772f5e7337fbeefbee276ca
server_public_key: 023713c6af0a60612224a7ec8f87af0a8bf8586a42104a617a
b725ce73dc9fdb7aacbd21405bd0f7f6738504492c98b3e3
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 56bab72cc6a2490a0e08d4b1a4d30960ad39e6acf4e3ca49bbd43ec
f9d1cc12e
client_nonce: 0157d1c43e5ae019ce040dc3189a89297cede6df512582bc81994ab
31c0242f2
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
oprf_key: 997a63044285171a5f6d1129c46a205ca9b03bf9e179bce79141d139ee7
7c55176302ae6515b63f96893c454662b7572
~~~

### Intermediate Values

~~~
auth_key: 1cbfc74991641a9d8a4984897139b825132554d8a2198afef450e12eb34
1626a0d8ed68fd861424544431a69c044e6d1838db2435853e41a37604e41d8b8747f
random_pwd: 7cbe2fa369a6dc5fb84bdbc7ee88c7461ecbabe5edb34bd94243f606d
b3279763cc82173b1d6430492db2841441eca28f5b4156ecbbeeb8effb7087276e8ea
0d
envelope: 01946e2072c6179dcbe6d14471865f29635113da5928521da16d42b7252
488034767de411cacc589311ecf42b09ece6e17113a83fc68452e57e34cf60d69fc9b
c24bff589632f9c80d67802d9eb644c7c869738d2d4e4fab56c81d2b9015f82a36
handshake_secret: 681aa9cef0fe4c80690e162a64c81402450b731b650a56c9824
1d7b0f62e47caba6d8ebdafbc6f7c9b1a4841c79f31b63da1eebc70e489bc3c97783e
553f99a2
handshake_encrypt_key: 1f9a3a50d4e51447d6207997e054ebdda8ac8eeb15a6de
259424c44b1756f1ee564ff9ff22379e07dc91cede89fd336d27372f7c1d0c59ab417
611fff899b62b
server_mac_key: 713f2b439704cfb1cd98b39bb876ebbdf2b07960c25cee32a29d4
fc898bc36e7b8fdb2c55889fe0d72cf53d527cfd1b390b7c531b361fb09546c946a15
721655
client_mac_key: 89a27d093d74c894244942b525f40662fdd54619095dd004ca122
c27fa7120576eae9821d9a8d76703db3746a8f91dd4a2b4f4ed71ae0942a2b0539a61
3afa4f
~~~

### Output Values

~~~
registration_request: 032a1ed9cba49c4f38f62e77ca295b8dd95d4d928aeb7ec
db24e28d927909e4624e4ef5df6b729071abb6e557b809d5ae8
registration_response: 02ea60302e97a11309a826dd815720e9a54709a0e935ac
cdf051868a385dc9866d99af7e69a93212ff883a97d7cfa89892023713c6af0a60612
224a7ec8f87af0a8bf8586a42104a617ab725ce73dc9fdb7aacbd21405bd0f7f67385
04492c98b3e3
registration_upload: 03ebee109625c9e1f398455b80df17b4ce16a27535fc37bc
9713d908eee8841778ae00139844b95c63537181370554472351d952e3a3785e77acd
2136fcd840cc03e62be48a890a08a24128128874835425d858143599041ebfd8baa7d
1f3f820c3c82b2f3fa1e230b693f6751bb6a6a0b01946e2072c6179dcbe6d14471865
f29635113da5928521da16d42b7252488034767de411cacc589311ecf42b09ece6e17
113a83fc68452e57e34cf60d69fc9bc24bff589632f9c80d67802d9eb644c7c869738
d2d4e4fab56c81d2b9015f82a36
KE1: 036bb3b9d78c508490de49427658685d8a74bdb5acb7ca4fcfb6fa5488911b86
8e746c08a1260d828fc5fa7e4232a2e58f0157d1c43e5ae019ce040dc3189a89297ce
de6df512582bc81994ab31c0242f2000968656c6c6f20626f62037e9c1e7bbf41bff8
ca6fabb630db2db73a92e57c6260f39d4024c619f8b4f2807473ec0f715d83e88ad62
b88ff3828f2
KE2: 034ff52de764426f6376b831489b7b47301b50151253c2c96f8473041da91916
a258f229582de9e7496a618bf2c0e5d45b617f386118627245e1460490ae47ec7deda
c0872fd8824128761d8838b5ab08d8f29b9d15fd910238afdc3e8dd8349426ef4b14d
d10196e878148bbeab1271cff5ebfbe16224b77f4fa143b7a70cdc03c9a5e19d28d33
0322c560e89861f7c0ba01755e2bae0e56b1ba07f2aef0bd7794d111f27a24bb794d5
0b2b419f95f241f5299160fc085ea1586594d9fe5b2f79b65b3eccefea453e0bdbc73
924e7dc1e1ace19cba93d324afb3355aa8e7d1f85e04d56bab72cc6a2490a0e08d4b1
a4d30960ad39e6acf4e3ca49bbd43ecf9d1cc12e03196d22794e67e69232db19e4032
d2f2daa09828c4ef71e5a4f296a0edecaa5bf564c97a7e8c96a4977975a44eed2b37c
000f1e7de99716c8fce89d789c188d696fb3253ab0148110c8300598588c892e5f263
04efe8f0d545c4db495ace856da611621479291f8e0e38967dd5253b9cd633219dea8
7b3c485ab9baee1533c7f104
KE3: 735b5c8183098e6f16af31b5648190d3f3228e75fa41e60073f2d90896e28e99
f05658e9a7e6f06cadebfe7d5b125c0f5d97f423041dcd889ed5094dea2099f0
export_key: 5a2db06a22e31f8e81f3b814fcf6b4d154dd7ef6d4153cf4735a3613a
76f12e73a438f240e21856d618d15bb7e78069732b8becd0566b529dae900f6643ad4
3b
session_key: af6d0bfa8f621e3e71f3aaf8cfd3ebfe31322651336961cd85e13014
f484cb2b9d435b0c9192a17caad026b092a87cf8d5b528458b9f68ec538ae22a7f7ea
075
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 2b7cd1ab61e636def02142db6a584e472e92880cccabf764e5a1898b74
c59b8fb0e13312e642288c9d3a2b0b7b2815580aeb714850107d19cdc559bf42d198f
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 29ad11454458010c61e46f3c152d5d29907149172961b2b84816f
a4f1808bf05
masking_nonce: 112d79357b0109a2ac1d627d8d54399c78922d0386496b6385e715
f725df1c1e
client_public_key: 0265e2bbc1e038d1c2c0c4ab942a6e4805f92b04da29c980b0
7c9924764fe5e4ad903fe893900a8e93f7ffb9ef71c4b686
server_private_key: f5acc7b0dbee75bcd8bb50363ec640038177f06904f2476ad
5274e2f9d258659e80b0fbd20e4761b22298eba98ae9dc5
server_public_key: 03ca37ed36b0b311e3241e6e96f49a44edaa971419d91fcabf
fbca0184afabd92827344da8379abfa84480d9ba3f9e4a99
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 6def49a8c299fbaf1c41b711f24e3d7711ff06e889549832d57095a
c16fce691
client_nonce: 1198db7a981c6a9bc547929be0a6150b4f2c72678b085832b239150
1ccbaa10b
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
oprf_key: ca9d9901a62797cc11fd1212720f3110eaabb72288fa8ddde03caac0202
6197c93dc696e782b968280bc150ce8c529d7
~~~

### Intermediate Values

~~~
auth_key: 1c9586c52ae953ec86c9c194f718902257b50ed46b2a22c0d57861ef76b
34a8c9a1b8fb3fcd3e855b63feca1b198da7dfd5a0ab84cb8a1601f37a6fe3d02f242
random_pwd: 9b7e84de0a97fd39f2473e336ec0a0e662597aa4a71470b57a176163f
ee3b7717e0734f77f94bcd8f61f9724299d9f6b4e04da841c38f7af96d735e6477a81
9b
envelope: 0129ad11454458010c61e46f3c152d5d29907149172961b2b84816fa4f1
808bf0578e4cec2c13e53ca253eb13d0af9c1b59b9eed97393c36528c43e563f2116d
251dce926048e4a89f340d281c304a28a744443146502edb9ef8221e4c3d91e86f
handshake_secret: c6f21ba801680df27e5ace9d40cf0d8063e72310e434f971504
370a010c8b5164fe444adbd3f3597383fb71d2299a915bec64c1d625d18950b025d19
228d3436
handshake_encrypt_key: 92c6db0e790d9d0079b87da8be219d12cf2f59153d4a49
fbe31ba86dda47f37fab21e49325e54f912479a4e5aff36cf92ab0d671b4dad9859dc
044e45bc2baf1
server_mac_key: 105b5806e17d459f2e16eed33bcd1ff159179036d6ae857aafc86
ab923f32f52baf3088a77043259d3403b700c835e0fc93c1f99e5f7ad07970d2a8054
465197
client_mac_key: b6b1e0679f6a60db34d585e0c536893548253c84d8fe137ed7385
1012971aad7e79e8cfb252535ca02d35386feabe55ef4608d275ab570dcded9ad0d7d
d41744
~~~

### Output Values

~~~
registration_request: 03c11a1b33c831ff085bea647c06bb354083adeaf4e7c25
d4ef17e90a25e590b275d412a48b83c064f75a6fd383e4730a1
registration_response: 02ac40b0888303fb688a65bcb6915471f88f31f7b6de9a
9f970b96565514763d8896466ea0da4c84860c263139c0dd533203ca37ed36b0b311e
3241e6e96f49a44edaa971419d91fcabffbca0184afabd92827344da8379abfa84480
d9ba3f9e4a99
registration_upload: 0265e2bbc1e038d1c2c0c4ab942a6e4805f92b04da29c980
b07c9924764fe5e4ad903fe893900a8e93f7ffb9ef71c4b6867c3f1f182bf3f8b49a6
1153ea59c74666cf203df4b81fd6698a40b0e65d4269c0aa91e04507f69a8e26783ed
47cbf5e8069013b29ed971aa787a506f1b449fc50129ad11454458010c61e46f3c152
d5d29907149172961b2b84816fa4f1808bf0578e4cec2c13e53ca253eb13d0af9c1b5
9b9eed97393c36528c43e563f2116d251dce926048e4a89f340d281c304a28a744443
146502edb9ef8221e4c3d91e86f
KE1: 03569da14f7d483ae405bdbd365b7bc7cd11968aa5c105d6fdf21d83cbc77050
7be9fb3aea6709f4a37e940900bccb4ca81198db7a981c6a9bc547929be0a6150b4f2
c72678b085832b2391501ccbaa10b000968656c6c6f20626f62021323ffcdb6e9971c
b3d0516ac4f70f48c50ce81c897b4c3459ab5aa664a410e20012f6a3eefc000449912
82868648a0f
KE2: 035069658c920da382a5d7cc9ff426ae049515d848a37514225fb7367b7285c7
99dc330f6b9617755e3acfad9b01c4621a112d79357b0109a2ac1d627d8d54399c789
22d0386496b6385e715f725df1c1eb44023d1b214f46386c800f513ab235deb64e75c
d807524b16eab68e8b331754501e4b1d58aca8544c1f2ac3d37fcc7a9274c0624194d
1e90501646f10048fe9c4d50c001a5e537c24e7a882ad68f0fe9a5571e9a3eae07e48
ad9ddf34fba1d0544dcc549622f1222704f0e7147bccd06407c0745edee85daaa0d5e
251022d0acf84fae3146c1cfcbb8757f6432e0fda52c96def49a8c299fbaf1c41b711
f24e3d7711ff06e889549832d57095ac16fce691037b55471c1bb3a246d0030fda68a
a80a79786fa060c0b56e7bc7d0000886e3d661be0afcaa0cf69519eb528a11af48a9c
000f56622eaf1036b1666fdd589f5e5d4801e6e4d43859250f945878c2c770b56b6dd
acef6e783b5d7e52ab8ad7fe9fb91c1d1762fef67f6fd947abe96b22e3aa6904a4dd9
bf70e0b27cca49a55cd51cb5
KE3: 90e192315bce1f767d1bd61ef59745dd4b46b7a7af30d5c8766c3eec76cf9ef3
13f34d36efe4353c5ed0ac86ea05a73a16576580eefb0c0d6dbbbaabb785bd15
export_key: 7b25463149424e1b5bdc3efb296c4be63dcfd7c30fab6c68e63444ed4
8abc49e9887538397044e23643f3b678d4e08730a420ea5e1b2c3355b93ac424740fc
af
session_key: 6cecbdd7efa1f418daece9c827206f1b80ee62a8ee295822a013b96d
761aa854df23bc9bf5891403092fac686f12df53b11a27d731803ddc3e98b18e63ff0
3a6
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 0dd29fc6515f1630188a20baf3d4a5576e1adbdaf0700b799d74c24e7d
f32e71a38ad7d70b32ae4713baee6755d14835cb16661e93055ee7b7809cf7db71aeb
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 1ebe9ead21206182071305e7a25c703422e109ea1eeaf29a80014
9de015c4e79
masking_nonce: 8b6f7b1238e9a524aad0e1e6c61dcb3ca7b657029d9b62a77e93ae
867680f116
client_public_key: 0361edbbc5fffcd1918ceba2ea3d16f9b7decd8bc4c28a4f54
6d5cc8da1fdec88164bfaab528c079d25399364e64e9ae0d
server_private_key: 8099b50c7ed9444176251781b6a8575de7491bec330164821
b9b2a108e3ef8964622075015ac9ea0f8380dcce04b4c71
server_public_key: 03aa179347ce8e27d2122b8c2c43315635e5489dfe1a50ab77
186e4710cc489638b097b3302b550da04f5d76adfa826688
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 57a91860e58bce1bb68570af98d2a15ae4f8a7e6919b448c8398521
35542e1b2
client_nonce: 6f5ec25ade47cc18c218f03cd782f9ddc5f1942c08cff0849feb6af
212342f33
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
oprf_key: d7d4e333124dc2edfb3b9f6462eefa7015c10a7cfc3c9a106c76fc80f83
f1da558dfccf32d94d51c6475effbd55cde36
~~~

### Intermediate Values

~~~
auth_key: 64afd431ca4ea4e5cd6361dea8e2c60a9a38719f5820a7343351e2b2033
7ce9ebd962f67a6c8f5d3ce2dd7389e5c84370f18f06ad927681f3c529066e3d3a586
random_pwd: bec07ded8b816ca79b63dfca8fd447bf5da931ac603c4352e5c0ab35b
8f9b6e4df5485c2e9893db613a34d46743f7ab40d5ad83b3d3460682c989c84080041
e6
envelope: 011ebe9ead21206182071305e7a25c703422e109ea1eeaf29a800149de0
15c4e7991772749cec47f6b48bdd81265bd75c92e7c70180b9b2136c0b1f1582d2ae6
8001f0103ed9fe5ec3b68ae55ab284ce205778fd379f53be4ff26357a59ddf989d
handshake_secret: 8d2906629e0a0491b37de3fc080f26f60dacc2b6c6317d49f31
5875eb53168c70fbfcd98a37fec6185047e87a66211a6d6c08e0d4a689f91d6f24f29
56ee809f
handshake_encrypt_key: 5b5d5aa7fca7fb0b46d0013c22f8d2fe6d7e6408e876e9
3e1c168149a7b41b6b25beeccb2825caf92401d1b5b01a70d78aba2d1cd4ba32d3217
c064b92441d1e
server_mac_key: 19358ca1147ec2aca59372a2d4e529298d32d96171621bdedf239
61d58f53671a6bad39c20ff97aec144749b14a9fbd34ad96b4f1c22e1809ace631c29
bede16
client_mac_key: c9cf3f6fe5a31869303a24864ad18c78a029e37bff1ee29201ce3
937f20f07607423d70ee069cc6e86c8f3e5a59b6d679fb7e7aa74dd58801cfa41c515
77f94d
~~~

### Output Values

~~~
registration_request: 0399b76973449a299bd2ad6be1ca983c8a1eccc7e05a36c
a120a30a8807d96bd4b98d076ddbd99e36adfd30b0886fe42f9
registration_response: 02ae9a64ecaa673156b196f6966988377353ee068e527b
088789e9e7c38e37a28cc37667d9efd927761d2d614fb1cbbcbe03aa179347ce8e27d
2122b8c2c43315635e5489dfe1a50ab77186e4710cc489638b097b3302b550da04f5d
76adfa826688
registration_upload: 0361edbbc5fffcd1918ceba2ea3d16f9b7decd8bc4c28a4f
546d5cc8da1fdec88164bfaab528c079d25399364e64e9ae0da3a38ffa31a59231899
8118b92170c31b21ec560c4e784c2ed24deffed7c5be1da6c8d0dd37cb387b360faca
dfe16c1a0e29b025436bcb121fe4b7418f69e3a1011ebe9ead21206182071305e7a25
c703422e109ea1eeaf29a800149de015c4e7991772749cec47f6b48bdd81265bd75c9
2e7c70180b9b2136c0b1f1582d2ae68001f0103ed9fe5ec3b68ae55ab284ce205778f
d379f53be4ff26357a59ddf989d
KE1: 03bb6ba53426efb2307df620440d09e1b503d3d2135dd0c845b59f135ab39bb3
00aad505641fdbc2725c31d221feb82d9a6f5ec25ade47cc18c218f03cd782f9ddc5f
1942c08cff0849feb6af212342f33000968656c6c6f20626f62038d4077ad0d00842d
0d621527f8225c405f80049752378a4e111b3dcd52857d35f464202f22a17d717d5a3
be3455a93f9
KE2: 0372fc50df339629b9756353038fec94f10ba3dd0805d2b553a3253228a19f14
2058b1c83b0efcd12bdcbae7cdcecd53b38b6f7b1238e9a524aad0e1e6c61dcb3ca7b
657029d9b62a77e93ae867680f116df0058357061103a234f4d46f8901f23ce6c0e79
e8b3db67f86cde282ec548b785be776360da90ce863e7275ff31e81f1d46301e29d18
ff76ed63fc5d55c44f89471b3f6547d3ec38be3e5f852f03f90372c69e0217ccd5901
a7663af588a3e63ba2f0b29b6b46487bd5620a6c2001a22e09c0a0962eb9af9e0e568
12fa2b1efe5aede17b08e536e9fef87fe266e6417cb8657a91860e58bce1bb68570af
98d2a15ae4f8a7e6919b448c839852135542e1b203ed7dcbc8318a00c1f42c2b75682
d0beb532636c2e03c524bb5bf5af735812003bdc0d076ca0dc9aa7ea97273c7088f78
000fbfc420bf9d08ede48ff570bc2237346bfdc316f5578d6581d60d9aaa87fb03eac
28667aca966ddc3140372a51812b8c8aa06943601d9be502ac627b040eaf41d21cd5c
271de5596e82a40d818a4900
KE3: 21df485a34a35c11a64ffcb611587e44ed837fe776aad73ee334827a97fb6bbc
d679edc50ad107afab994cbd0eabe8893e1639a9bdbb5345b5b37a74fdf122a2
export_key: b1354ec2376a044a145dc0aa080b9f244c517d27e1ef7a69ab1da7f13
32952e86dc0e7c723f32589239345d1969cb3fbe9546fa016ff170adec68de94020a8
9d
session_key: 02c52c41033d1d9f965e38cc7f4490f10b358ca1c677ce6eb004ba1b
5e1bf50019c7332d6f20b1e91acd048f56593eba112e74718841c7c36e7334055cce1
6b6
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: f6174d6457d82fa5bd2bb31f00e96ca00f1a698a54686f1ec6f193e102
0e2fb5358afc4c3f2757edcd24c790134d65776a00a3ea0313fd57c448208aeeaf0a2
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cc55e43f2769e15b3545781c79f5e2ee238d5164f54b13771df5f
af8d80609ad
masking_nonce: fe582da481b4ad1471afa8d1b00a285fab11a1c8b67cd8222e537c
d3c8231c0d
client_public_key: 02b04085bdc5ed34d17ada67be4ac26d89fb6c5b632db77ac5
08abc084345aede0cf1740654d2ccaf3ee0b290cc807c0b9
server_private_key: c6c4dfa3a822d8f670e5aa46e733baaec9f93d5e14ad9ab99
dfcbcb2ad157a8aef1f3fec3f24bbc392c9755271e8792c
server_public_key: 028cde89b6908e81425fa8a597e3103021475346a146b1f1dd
ab47f09c76ed3b78a251cf390bdc086924bebd471063abec
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ac5d0963049215b96b4aa3f6932fef788d2c87f5782f38d15f0213a
967502d96
client_nonce: 61f7acca0274057698a69f10f7dd80ac855a9ab9e9c01a7f74015e9
889eeac45
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
oprf_key: 0d9f2b9676f3350cbc0bae1a8a53a0b9415f7685c0748c3563527255408
58a4a41901dfe7ac0011bd9f27a0bbc85143d
~~~

### Intermediate Values

~~~
auth_key: 92a5f55e95f8edf2f840fa363c11a9f1a4a9a269b28eb656afe6f83308a
7e8d1ee714de84854b1ffd1407bf388368f9a2b8f29a2882432b934f6cbc0cd97ec17
random_pwd: f5d6b4e0095c93db238206ad2f22a4a8d2f7f20c6f125e574484ad6a4
ce80ed36fcfd9c1278d5e20ab16ca1c5f1adb71db85a815571542f49e6defcd4631d1
51
envelope: 01cc55e43f2769e15b3545781c79f5e2ee238d5164f54b13771df5faf8d
80609ad31481039951599dd7413a23b4e7031a3ccec99bbd548045fe8b2230386003e
3c79f3ec6b446166bc22c7b315cbe307d703187b748945d55d1a87d518723fda20
handshake_secret: 1cde5370caf1b50cd615301f24fdd2341dc3981ef699e22dd15
9d37475a08e432a59087b845d9e58e7eb39cf4c8fdd5e26f3846c1bcdc4cfe8eb521d
8d7487e1
handshake_encrypt_key: 07fa4701b48a23f131ca8af1cb8aafb40026aef7f7b21b
4c128391789b9bee659f50e464ad94d08c8977c09fedb03bde28a362bf33f873acdf1
f8c6e1f61bbb2
server_mac_key: 64089ba0cb91f7f5c80ddc82c529a8dbcc00ca126eb77b25436cb
bf4042a69e41af1d1abf90d23e2e80c3321fd2bae20dc2186ef0124c7280ac651c32b
e79868
client_mac_key: 131aa0f8653aabc3c2686a7672f855dcd3055e39938f5faa2dfa6
e0eafcbeea8c423baf27f00d3cb090841e1bf4d2b31d1f5ddd15422287f9c9f5ca1fe
576352
~~~

### Output Values

~~~
registration_request: 03f8569ce50a023ad6518281322157e79e1207a96bb9214
95ccde8cf48eaf27895245a7b8f4b3b5c43ba54963a19cc488e
registration_response: 03f455fdca0f29de48bd5fc08824fea7d44b3ead68a982
2c4641a219e5d058de6afba6c93ef903b4de041f77ac0dcda38b028cde89b6908e814
25fa8a597e3103021475346a146b1f1ddab47f09c76ed3b78a251cf390bdc086924be
bd471063abec
registration_upload: 02b04085bdc5ed34d17ada67be4ac26d89fb6c5b632db77a
c508abc084345aede0cf1740654d2ccaf3ee0b290cc807c0b9b74f0e0bf8c8041a1cb
28650e02655b5f9ad75bcd1a1a8b3bbc0d0c8218f70987b09e2024446e9053bdd6433
f9018eccb74dfa9cf2df6c84e1602d5fcfe2ce1101cc55e43f2769e15b3545781c79f
5e2ee238d5164f54b13771df5faf8d80609ad31481039951599dd7413a23b4e7031a3
ccec99bbd548045fe8b2230386003e3c79f3ec6b446166bc22c7b315cbe307d703187
b748945d55d1a87d518723fda20
KE1: 0255b2107d1a2192eb54c25c98bb7a95e581d7d23a38e1fceac9f8ce99f568a4
fad6c9bbc5abe4ff08f8b22e31bdfd697161f7acca0274057698a69f10f7dd80ac855
a9ab9e9c01a7f74015e9889eeac45000968656c6c6f20626f620246ba00038cfa5105
659e8c250d10618a2c7f9d09d174663bc5689e4778f7054534d9a4200a447510023af
3ad3c61ece7
KE2: 03b7b2bdfdddad198d33ee362b4e0ddf91ca98161d74d244d97809de3db64bc1
86a84c9fea496304a1ba674abbb80f1337fe582da481b4ad1471afa8d1b00a285fab1
1a1c8b67cd8222e537cd3c8231c0deb320986d726affaa114b39c928464d04a607757
b2a445dbc01f3a82f566297a8c33dd31236652dff2a4a4083793855431358a04841d1
106864603d59e5d8c13e2ae3633f9609314da2c05d61f3b82b53f188804da0ebcdcad
feff4b3584c7f0f5a4b5d2b9f695b938bbfa962cbdb3e35f7ea8554dfc40d90d4acba
9869b044a7f1f731f51d027e0b420f86562724911745fac5d0963049215b96b4aa3f6
932fef788d2c87f5782f38d15f0213a967502d96030d570f50898367457561b3a5c70
7852633b4f9404cc45b4058f52f5da1ebf67cb737bfe5c272bfeb65efe6bf7255116f
000f4e8c7d3c6237cb6d6d0179506f0f8a3aa9a4dfd8b69467d8db3af06e02f49c8cf
a18a34b002744eb270f8a483667ae586ddadf53d45e83de03c394de02a1fcc8e010c6
6b017c3a594d9a71d27c8ab9
KE3: ec296e76536b1bd20d64c15cafa97c0409e6e2083cf43e32dd971e871561847c
ffe009e569e5b8d4ae9507ba388edb0762057763594824fd48ec24d8cdb57440
export_key: 1e01bd69193e9a082fa8689e16ac7b1aed6f5db2aa0cd3170b42c5b41
a901cc0b0b7867dec55833205bcf283082884d36ebd3aa823d7198330f893e012c9e4
ee
session_key: 0ddbeb7ff8cef3145c498f991b0a71ad9dbc4539eb81ae5a9985c918
29f020da8c269916457abab981004493a57ed9275ed02d530661ec1559001c3719ccc
73b
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
~~~

### Input Values

~~~
oprf_seed: d7b7f92b55f543992defbfe64f909225b4365d0c0e7674e4eff5fb0956
5caeb1065945291412de3573645f36769748b5adbd7bd06c8d459d1e94650870707ef
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e05110743e836c98715aac28d2d9327fe823dfe2a2825fbcc2b68
6d98d9a84ae
masking_nonce: 810f0e44588662849dc6168ee9c20f6ec026d35d334f70f9cad80e
47c798c25a
client_public_key: 0200398dd678a67fcb588a036e182a9bcf8dfdc9c30d86243d
faa5002ed93eaad8049c378cba862b7fc0622cdb548f485b59e7d22c6f132d8e93006
521460452160a54
server_private_key: 00648b7498e2122a7a6033b6261a1696a772404fce4089c8f
e443c9749d5cc3851c9b2766e9d2dc8026da0b90d9398e669221297e75bfdea0b8c6b
f74fcb24894335
server_public_key: 0200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 3e01872a46a151bd0a55bb646e517307b4e1ec020c63fc247833150
9d3bd448f
client_nonce: b6f59274f016d3078d48493c55f06ed52a8ae091a552a89233309b3
b8e15af7e
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
oprf_key: 013e9a4aa4cc6fc6565ccf6b1bf6e29ecd940b79121d0cbcf0d2c12d57e
28e5ef0f01ff59f3720438241f5e10fa109c3ca307a32dfdb0d6b74fca6633950bfe1
434e
~~~

### Intermediate Values

~~~
auth_key: 9ffc62c9a6f62ba507fa9d72e053a32aa8cff69e50c99dd1786fe7376a1
2cdfe286ccc38891819fb23506d9f973c937064655de1c19c33ae286012c646d3ff17
random_pwd: 9379017cfaeae40c1b53346c66864b8600cb42d4ef9b968315ad420e3
d3358ddd34797c70a02945368da364b5d5737f3ac32be5202248b050fd07924394d9c
a0
envelope: 01e05110743e836c98715aac28d2d9327fe823dfe2a2825fbcc2b686d98
d9a84aed26bae1eb6d2db5a3bee39b1853f2ee4d83a1d492ac30fa20e1400a5e376f3
700c11a63e2d64903e76e385726b2926aa5748ea274635f27d0003c86e4dd9e3ee
handshake_secret: 039a0adfbcb57efc612bcb99accf320d42216e2fcad932a2f10
38802ce9c38e43a33705844f7ba79b7f1648e117ae20e647d10a1d9532742db49d595
59e60e78
handshake_encrypt_key: 8bc385db0cd9285b3642ec7772c2c508ce527a5de04c9e
30481a6fe61e226767a4db9c3f1097e2f8d52ece3fe6f3f97f18ca8ce0484281f87b6
3cbb266958fa5
server_mac_key: b48791065d8d8f476e5d38018f730054036a8de17bb3fe1f1609c
39cdb095f39deb111c6059daf711e3d8cae2ce11a5d3451b86b5765ab37d2b024b63f
6148a1
client_mac_key: 09d4ac2198b91a624fafd16cd7d49b3aace04ec64a3f3134078c6
d1c9d65186c8002d0c4c406beed00c7661236faada5d6db251fef23e490410b184386
d8c4e7
~~~

### Output Values

~~~
registration_request: 03019f508a03d6d883f28a0afa477eac4dfad2ae9052a82
ef5736b24eab85dfc40309c5d205bb94b9a6697ac7b97b9b63e057f163905ec396db8
fe250544bd94e90c13
registration_response: 03008f53ee3d96a94fd58fea3393f42e69a29e4e4e8d16
2cf5f0b84a3d2a512ef6e1baed8512ab3d9779e9851a70d1c49ea1c892319b8120d52
08a8e105fef0f4c3b6a0200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
registration_upload: 0200398dd678a67fcb588a036e182a9bcf8dfdc9c30d8624
3dfaa5002ed93eaad8049c378cba862b7fc0622cdb548f485b59e7d22c6f132d8e930
06521460452160a546d5af7fdab580c0b4e09aafe86f8a885e7b15448da7a84504824
c305f42ad81992346b45808591c275b46a5a2198175da78fe2ff1c9ff222d06647500
ede48f301e05110743e836c98715aac28d2d9327fe823dfe2a2825fbcc2b686d98d9a
84aed26bae1eb6d2db5a3bee39b1853f2ee4d83a1d492ac30fa20e1400a5e376f3700
c11a63e2d64903e76e385726b2926aa5748ea274635f27d0003c86e4dd9e3ee
KE1: 0200001c8b7065b1f65b9e87150b85b32e6a13738dfcfe40a947a3868b0504a9
c0b8f2d2f8261af3c4507f583ac24caee8981b3c2e7c6a81192d383aec9fb93e64203
5b6f59274f016d3078d48493c55f06ed52a8ae091a552a89233309b3b8e15af7e0009
68656c6c6f20626f62030187b0369b07402c41744c664239d0f9fad568f0ea5c13e4e
4d80c770fda054cca7fdebd3f91a803a3efe7353969e388623c224a86cc32575ef8cd
5e0cdc3c467343
KE2: 0300c6fb079ed7337c602b92268e33d3977b538daf1a3f028a308981369d900d
7d5f1cf4b2766eea25583d9e1674d76b6a184cc39063de989b537d45f1596effb07a8
9810f0e44588662849dc6168ee9c20f6ec026d35d334f70f9cad80e47c798c25ae19e
6888f77e3d98a9abcfc25097e97d83b1fb9ba65caeb7cf0e9cb19d08b978f6869eb7d
222f9fbf6b31d8a998f16ae213fe38b846f6db88980c4096fd3684fcb17f1dd278558
ccea6f2e58bfd38c8fac4ddb2aca2b3a9ea290e47d5de45634a83113cd87476837a25
d0791cc553966ddf378290c65f40f7c953194e64f966677e936f7df122ba3a216b583
d351a5b35dc7f4a0ecf9b2b73a24a1c932711511c1ee4c333e01872a46a151bd0a55b
b646e517307b4e1ec020c63fc2478331509d3bd448f02016c63c8e2b3feac6366e3dc
f752a8c2a287c1fb4d648aedba86aa0ee07d2b1133d3282584d7c66357bfcab76526f
184f7ff9af506f9eec01645b99b6918bdda600c000f24715c345cdf2d4fac75406c9b
db636e4bf534691bc2d25e28ee626e5aa75cce28f7cd805e2cde9ae3d1e76ab545cf1
fdb121fb1bb7cb1f07b02c49bfa2ba63cc66b71c1ab3357da678e71238caed5
KE3: c590d940c9d47aa7576fee3d0cabfa9d358896dc111f6ca93253c13bf54fe872
1413852a2383a03878ea36a0f0a79fae011e7d873c0e254a5322376d6df2f596
export_key: 24ca1befd6a2c242f03d516b7d89721656bf2be8ed1799f5468c5448e
82ce3ef9c3a8670ff6f91680f9eaabe7cf044f4e435b6b843182048c2bb5679b3b0ac
87
session_key: 41271362d921ae947782bc5c4ca1cfe68c98e27f76eb0d9a6a08c684
a762278a835581a7d038803f0aac8e99e4bbbe99bfe6701e12209f1d473d35250d198
8ca
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 0888294d301c0c5a2a1a1392c0617f0906426e2369b50bcae16ce70cfe
4dae503e6b4cecdef4a17b61c4abb9327b306c5d010ebdbfc67af88b3aead9e69d659
0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 1d4067e49cbfad7b49714668509ba38d5c5a87880781979ce61b9
3e259b796a2
masking_nonce: 594778b31bcd7424995566e460dbf7e6a4779f21ccfb4a04198ff9
0072455a59
client_public_key: 03009754454ab5a415aaae3a46d9f938a9268f722e9e88f131
178fc4673f9d98470b5917d28ca61a5fb51f80b0cdb889f33b39af2f3933de649db9f
2227a25fbf32d2a
server_private_key: 01e58f3492c6da02dd7387bd1dc40065b23155fcc16e56ed3
586c3c2d80245859235d872c5266668cd562a2bd7f34654235b1b9961485ae246256d
f3935910d36507
server_public_key: 03000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 04a82b54168146ce0784766c0dca88e1885f9533c63c78bf7f919d0
a67bd196e
client_nonce: e2df468af730dc70101c320bbcaa99fbb6bcdf5a15281fd18d32430
957d93007
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
oprf_key: 004e0400dde0db3059fc378ac4eb3c1f71abba517e6b491871317019563
86f958bd355537c7e7b0fefa8d14a5141be5179819b8f4088c18bb742d71dd15c7346
00dc
~~~

### Intermediate Values

~~~
auth_key: 7c93a85ec4a289f6ddb6b6586bbe11350c36576f5e7b722be47503f304e
e49e46cc1db2c9b9afe76200fc5d8579c9359a98a74c92dc4cd52596a60de5205bbd9
random_pwd: 63fe136d82cf647367e2e5a8bd6de7e8463429e115de5377d0c384cbc
627455dcf6ca17bcf51c2160259e3b51a27308101adaf32541e0e681ed1df1b72d904
44
envelope: 011d4067e49cbfad7b49714668509ba38d5c5a87880781979ce61b93e25
9b796a26db842c13ef77c94e58c37abce3816df1e49be57c4ee454a78de662da7ab40
58a158439488883175f9565d7850e361344c44b1524d1b3774737781f909aa5f2f
handshake_secret: 9e5a08c80af6ed202fcc04e9dd96d2d127ffdf1edcff4b645d7
2e78580ac63735eabfcd1617f38d6d8030a4fc8a3e8d160b62051b551ea5b32018a86
5a6a0d7a
handshake_encrypt_key: 490a73454f89636afb6d6703396a367b9dc217bf8c2cd6
81443fedde7e7adba3d79f9bc5f9f033ff6aca4ad1f2a258c53e347f82bd32618f34b
0f76df4642905
server_mac_key: 86c2e445d0b5dbf17dae27c9929cede92b1ffe8e0e9006fcffc5d
4d6b35b36aa2c9b364aa3360f5952dfcb049eb3fcac3dd833c6714fcc165a4a897988
9d2467
client_mac_key: 70098487c63a872dc6703c8a020e667f61f7629f26a1972283260
f983a2e8ee5f90c64d1f77d0d07721df873b7076a7489c00adbdc2bd9702be9ec5666
9e682f
~~~

### Output Values

~~~
registration_request: 0200bce08f110a6634cd66b75c0721208df3d8c392f86f2
feb9c20fb62c9a30df00b37caba143386c7880a96301814e425ba9df870cfbf19724e
b58411604b3a618f29
registration_response: 03000da69626a98ff08a04db0f15a51fa0de7249af08f5
101f9778e587aeaddd57a009378ce2e45848d939e8a102a32ad709e3806c13ae68286
f59782d7e05d474b4ff03000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
registration_upload: 03009754454ab5a415aaae3a46d9f938a9268f722e9e88f1
31178fc4673f9d98470b5917d28ca61a5fb51f80b0cdb889f33b39af2f3933de649db
9f2227a25fbf32d2a58c79941918c4bde3e1c8b8f15b835ebcb93d7d26fc774a538b5
b6182f5dde2cb7bc08ba027fdf7cf1480aba9d76d2ffab244f02b42d02e849b7c27fe
03fd582011d4067e49cbfad7b49714668509ba38d5c5a87880781979ce61b93e259b7
96a26db842c13ef77c94e58c37abce3816df1e49be57c4ee454a78de662da7ab4058a
158439488883175f9565d7850e361344c44b1524d1b3774737781f909aa5f2f
KE1: 0201e2974af3a0c9a479cf1589e9c7db8f3e04723123436453ec427f75974423
4a57a91a724879c5cfe93ed919501d567a6fad6ff5763647c351ad6dd925f39cdb04d
de2df468af730dc70101c320bbcaa99fbb6bcdf5a15281fd18d32430957d930070009
68656c6c6f20626f620301bcdfcaabb52a829a450fdeb63bf90b8c98c6b2717164f48
e27d4c737058feb556f81fe39aed7846313ff6a6fb9c4bf1d81083974f2babdb08004
8cc67e12f8ce2e
KE2: 0300909fa1e7ccd813969034320558513f427dc4739ede1cbf0cd9685ddbd147
4dbae2cb9ebe3adff19b15c259a7e71a600b1ed084c940db4346bbfbab9b1f0e74d70
e594778b31bcd7424995566e460dbf7e6a4779f21ccfb4a04198ff90072455a598dca
8a44ea7c61a4a545020040d745299bfe524ddafb465171fdddc1cb0d622f3d1246d81
46e8f9e08464a1e96cbfdbacaeeaba37b65908802a147cb727a88c3f7b449461455d5
a59263b358faea41000f0a5dd686a479c1cc7e00bebd16787d5b49ef9d85f7f19e710
8f2fc1becabb93535fbd9245a45b04e006cd6c87f200fec56349b3fc0ceb4b2a6ba9a
12f9ce6a60335dff347fccba57864f88a0877266423826ff04a82b54168146ce07847
66c0dca88e1885f9533c63c78bf7f919d0a67bd196e03015da5c9a33d3168383837d8
d2ae4d00f39a8a631cd126b4dc1b01f06c32ac86ce29440df0e45650879f65ad94a3d
752f265254f7d5861046cc016567f9e36b873d0000f145969d7f342506c0d0d9785fd
8ff89f55a993db4fe81cc67f400efd16afd045e9a79aaac2bb45d58717d1d26054bad
f07640a3ca5dea68ec74f810944c90635eb2211ed2ffe5a0218944a8327f4ae
KE3: 929432031ec26c8e7f6117fe628384261c09facb17f6a346afb54566572e992f
025343c2de070291e086668da5c931a46258855c07eb2dba28bfaa851d4051af
export_key: 0bc0dc5e01cb50ef02f6614842cfdc75e36870e845295276da5027c05
6936e7e8053c51cefb4d8d3dc2f95771cb72dfddb3e27afa44bb499b3f115f1e7c8ef
4d
session_key: c01b663261ca40b06559b297d4bb6cdb41cfbd5e19b932d43e57eb4a
8ec45497c9959c91d127a7dc846e4b16dce4f2c706fa739a74547fcb4d40af82c6665
f11
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 0c3fc7b2c142055e5f83ec07b5048aede4480f22c12a06c3425a8b2e34
3cc3b4e2d3178a02e0a59149745d84fb94b4a2cb2f508997137b5cd31ba7d9e601413
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 97be41901e8187936b7b7f1408788231ff79b587c64ee255b2c34
3d73f95b9a9
masking_nonce: 5b9c6bad86095278af422062ebb907c6e81e645c4b3a24f57ef8be
8256a7127a
client_public_key: 030183817009cc7922be51486d57fb22459a99a6171273992b
876c2001ab8035827add36e6bdf6a38de8f31c5ded4ca0c08c25eee4b72426580eb1b
5d0d4066920bfea
server_private_key: 00deb3fb5eef3871cfaef0953ac3482c88f2bb4849b6ac355
3c3609aa005b2cb37316964371a39548566c5e4e4dfbfbe5faca38a62651e9a519143
d04ac366bd3097
server_public_key: 0200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: a04c2f38aa039d53bc293340168e2f3f0df92143376d862c7da70b3
760a1f504
client_nonce: c9541745ef7b75ec724104bbaedd9fb34de62a2fe4594b62fca5ebb
7e987bde5
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
oprf_key: 00298b44b28a51b3ef6319b4cadef50071d3c1e99d0615fb95f6f0dd981
23b0b8cacd97b6e6c9b78858561d19237c8e3f1bcbf882680522b344c621222bc2c90
dc78
~~~

### Intermediate Values

~~~
auth_key: 43e26779986ed59a02cfe905577bce1efe0f090055add6fef97885116b3
ff271a56adb4867bb9f10ac6d3c54cc4bc5a6f14e01eb9ed6d9cfeade8d5b307cd177
random_pwd: a939ce6d73184c2414d054c65fc67b3eb8c6f001dc3092e7a6b68079b
1f5d3aad896a11f8a40865404d79864d0bf753da4b6474c1f26b7a295bed7dc5ab07e
1b
envelope: 0197be41901e8187936b7b7f1408788231ff79b587c64ee255b2c343d73
f95b9a987d455e628f7337af3804762a0276ffd908b7805e7a5f7380675d079e974b5
b1a25e788dd933f0b36c04d639dea10c07b0850379727a95b98a63dc5d6a2790a4
handshake_secret: d0e7d1a65e60c066abe873b02bab898b47feb9b84a4937e3f67
0f354af329db032e9f53934fc557c207388b2debb6fe03cbbb6ce81ac476269787db2
8d8aa441
handshake_encrypt_key: cdb27d528a7ca0fa569400a62024fef34f8c7bb2e3d325
c972a894440056138dfb158b24ba3b6bc28b1a98de9fc599feb13fb293fe3ace710ae
0bdcf0bb6ec9d
server_mac_key: 3f20d2a55da79dbfba2341c33baa7322c5d72ae341e45a52b3396
b9c191b56bfddaefed40b30c0f16ee47398426ef28a9c5a5301f56ee2e4babe226b65
10abea
client_mac_key: 84a045a92f6a97a3fa6fbff65902a73093c064ec801b7ee44efbd
b9e754241127011d40d9c01a62bd9a516bd64643a6644ac11e63348adda31e743d48f
1b1861
~~~

### Output Values

~~~
registration_request: 0301fca4ee81d22c8e8cab4cd5e1724bae3cede81109f61
7910beaee9771549cf0090692d4342f0045a99a0707e09e38838e611a3f19c81bba90
12ad6c67ba55f40b1a
registration_response: 030140d01b6fc710348a3ab0ae61fa902fb3a517f67c7c
2a04ffd73c70087eb35dc9d312a6b1c17629144bc3e923f52e5a56acf4eec2ad046e8
ec58325e06a5c8155fe0200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
registration_upload: 030183817009cc7922be51486d57fb22459a99a617127399
2b876c2001ab8035827add36e6bdf6a38de8f31c5ded4ca0c08c25eee4b72426580eb
1b5d0d4066920bfea3da0b4b88c020a9817a748cebb63ec1f5dfc34a2c03887eda798
c4122c602c382bc386a48f12ba0d85161feb300f9a1ff8f64f4577abb235ba8eee6f5
f2e67200197be41901e8187936b7b7f1408788231ff79b587c64ee255b2c343d73f95
b9a987d455e628f7337af3804762a0276ffd908b7805e7a5f7380675d079e974b5b1a
25e788dd933f0b36c04d639dea10c07b0850379727a95b98a63dc5d6a2790a4
KE1: 020197ca02b425dfcae9aafd4608362a1dedd8998e6cf906191b4d888db30de6
dbbd22fb3a1bf310cc09f781d9c6fa0bf1f1e9a79c09eaf0df596801cb9a1030f9d2c
fc9541745ef7b75ec724104bbaedd9fb34de62a2fe4594b62fca5ebb7e987bde50009
68656c6c6f20626f6202018f831d92dd0355becccd11cc3904ddae5edc18d6e357ae4
3a7dc3459335316f842771994b3b411da7ad3c8911c806b322a9fad184e8b5586926b
e76313b87f3d9d
KE2: 0200e3ee811f3e17c9557c1db8e54962fc5c098991ea5bea277176961d6b2e7f
df8b8587c38880c50d8321a8f2b8eaf87693ca04bdedbbf4dd06ea0e25b2789c0c848
35b9c6bad86095278af422062ebb907c6e81e645c4b3a24f57ef8be8256a7127a85ea
da3cb31bb1830cae2c234828bb5a1727832bfedab67a3130efbb396b8e18a8175179c
106662d6365179c0163c295796e67ca75cbd33bb7100bcfc836e91ae0d0e0abd96eab
c3d11f5ad70ede63dd2456b46a48c5dd0e34452d8f767d199a96b17c9d8de26111911
5edb27fa12592034fbb41887e7b08e9ea7e54366ca0d337339fcd878cec91ef1908a2
6e06b18e1d95a961aa3387152167116b472948c3501c6de0a04c2f38aa039d53bc293
340168e2f3f0df92143376d862c7da70b3760a1f5040300f8b6a63f05a1a6f6e3c856
d512860d5700cb3ad37bc1dbf4ecfc4c77c3aab7bb6576f70be7b460143e577d02409
524ef5fd5e82a85fec43cc2d66adc312fb27a1c000f1dc348168877a794037bfec4e4
76af5632cddc27688e358090665e95cc488d14aac96dedfaac289408fe8d88478c758
c41e980f257e2293bdd9785c6a1b21cd067084709329c1d6edfc971c3233916
KE3: 2865ba753fd58ff4e9cf9f8b48cb5efcc2effc7391af36228a18635083bbf0c4
c7b2fa19cc5b8e7056ce27ad3c36781cea687f67716664fb71c39be7814f6a4a
export_key: 46978ae86548a4f082d61a77f8f5c531052b2d2455c1695bae56b42bf
ae543573e17a2a7b6f34d17dca93b6764f74f83be6e64e84a9cf477ff312c22a9f608
d6
session_key: e6c5e775c656cd0bb7a65e839970fc4de90f1c6af8e7f199e2896946
1ecd85766391181b8ef77b786aae0ea53df3575dfaeba000bc5c41f3ebb8889c6a994
e55
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 0d4f107cbc888c2ab2488f999dae4f041908ced9bcc01d71c24112d93d
ce3dea026833a543af8b018d4693ceb25e6f42c29a0a8b8d9fc9ccb6460784f4ee062
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d658d11456cdf67c01dc930056a87a3511fe6c1108376e3291efa
585e75d4c83
masking_nonce: 3a3d386f02dad419893bbdbb4481c339ede6e216ae47c048a06689
ebba342331
client_public_key: 03004c0c0854956c88705c9bac0e151fdd24efacd5b068d2e5
048006bbe0499b65881c88fc8da54929bd086273a2c43790e8cd05b46f0abc2871846
fe6a27dd10e1dc6
server_private_key: 012bc7471bdb9fa3e113b809a86dcc379b782052bce3fc9f9
62d373217b0c266b1e0932c7a0727030de9ce81d360d97fa94f7ca377aa6969e1748c
9f8b0a3f230c50
server_public_key: 0200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 324a66a2e0b28e98686d9ba5f520838a121f1a2e92d5cfe052d0776
ff99cd13a
client_nonce: 023603ee852ed4110c27622b770c0fc35fab715792cc619ac4139ce
ce8d48ddf
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
oprf_key: 01e0eb089b6cc2f12639983f0647026df159e124d7b810e64a8a4453f39
7011c1afc2b297067e527bc357200e511f286baf4f0765eba955c1ae56781cc7e1437
51d4
~~~

### Intermediate Values

~~~
auth_key: 9d5d40ce9a237cbe4a8ee0991346ba8ba04df6a391b47621205133c0676
fa5241a51861c424256121e1bc32986cf343b7050b9c1afcc2396ed8f5de140403cc9
random_pwd: b909f86173a0c14872308102f3fe20c967b405d896a06611876cfad80
1034d6d3aa10adf1cb619b4871cd519be311d0e21892530dc8f4b61dcec44c09efb7a
62
envelope: 01d658d11456cdf67c01dc930056a87a3511fe6c1108376e3291efa585e
75d4c835bab1498afc87d0dc01395416a7497ff6cc513d9fe057313fcb818732c652c
c2ec8a6696b55c446fb0b4ea786527c4c8d8db5559d7f34de4fdb07c2a3e8d219f
handshake_secret: 1223d5e600d2f72361e660a6e003318c44936df77757f156344
c27b6315a6f409890ebfd083185e42717a18823146d207b6bd64028bf9d0b0f74fe71
c087d1ff
handshake_encrypt_key: e714286d3a92b65079c9fe778bc0e5804a2e13c47ca068
e05b14a58cc71f4db8bb06bac386892f298ea735fa6e068451a8ea4abb5b1b996c07a
482f839e91f36
server_mac_key: d4e07cc8aeb8f13f04c0b77b38c87d8bc1853da29822b728524b9
9012133541e5773cafec539a133a8d72eed93ab44e1ef68cba9a51354399dede9cd60
df10e1
client_mac_key: f2c32acb7c0236f306903ae863f74fb1473b4547750575af6bd70
d36992d12d6235a2e238ad88c45401550d9476008a81b2d8844c8e8d7239c2bebb1cc
44d6e3
~~~

### Output Values

~~~
registration_request: 020178d37274cd1fa2512ca1d238613727201561218673a
d3fb6a391cf6dbe028dd8d953f0e36516eec3c69ab0293b19769074c4b16ca36d06ca
2765543e694fd8a2f5
registration_response: 0200924674a5d060a8eabc265d8bd683e4054f74ddf90e
299f16555135b9d81596186b70c32c7e0539c99c2fc23e590fdb80542c94b0ce02ecb
555dd8f5b84cf2188880200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
registration_upload: 03004c0c0854956c88705c9bac0e151fdd24efacd5b068d2
e5048006bbe0499b65881c88fc8da54929bd086273a2c43790e8cd05b46f0abc28718
46fe6a27dd10e1dc69bf6df603c0cf91d920aa5d730663bb49191471f55eef23a52bf
4c98c0f007710528e51463bd82889ee5df7fecf9e104df3e6903124581245e81da662
b4572a201d658d11456cdf67c01dc930056a87a3511fe6c1108376e3291efa585e75d
4c835bab1498afc87d0dc01395416a7497ff6cc513d9fe057313fcb818732c652cc2e
c8a6696b55c446fb0b4ea786527c4c8d8db5559d7f34de4fdb07c2a3e8d219f
KE1: 030041daee06de56612bc011e3fc1b5b1c5eb334b6cc0cd587b5c6fd9f94271f
dade91de48e730d2499eefc313038c54e3ff0326da0afd4f5defd0e4f88eb9fe6dde4
f023603ee852ed4110c27622b770c0fc35fab715792cc619ac4139cece8d48ddf0009
68656c6c6f20626f620301125c341b183c9ed98ad735039a5aeb7a9c99c6a90eb2dbd
5a02ffa442393c1de1a7f11ef5a7395a3881525c7fb8674d74d842f0cbece5069f98e
2528ec903ba7e4
KE2: 0301391102d87cc6facabc6d261c1f57577ec96df0c25ad04921d1299f61640d
60567ac06b06b487b25739ac94c47d902df422786afacd0cbc83f9dc396845d4f1c75
e3a3d386f02dad419893bbdbb4481c339ede6e216ae47c048a06689ebba3423312b1b
bab0adbc929360353742f14ee41f561d3b7b84c578ec8de1af226e0129419e4103f8c
afde517aeae20bcdeaa715b7899058999f19190c61a6a27b14de50c8e832fdfdadf52
6bb6869255d4b81afbdb5def3ce930d5a84a3e9a31932133d5c2c6bb390a48e56d96d
e3a22ba82e4073c61bd4950d1f4ed2379a34067c052c7f125aff7494c6cf37b9a425a
51e2d7081eb7e3a07868d923afe6ea6d4e5a8b4a62dee189324a66a2e0b28e98686d9
ba5f520838a121f1a2e92d5cfe052d0776ff99cd13a030121f7821162fbe027849ad7
50dab6227d5633a7148e1b09107d200d7fe63219f09a4e96ba8cb734b5b20941196ed
b471863e1785c22e950e3ee34c85aecc454fafb000f700d97fd28984f411144c3e43e
156a15853e558a606427f3e80ba20b5b77dcddd8fe5c5cd95d4f51309a705bcc4ed77
24a4d60a244b3e2e50651f7528990ee0ac08fe5fb307db374b72fe96154f6b4
KE3: 364ff3403b3fcc9d3bb37f819d0faee78ecf239ae3e60477f3e15f3a50a04f03
5e01d443c4a99d4345806f50adfcd4b55d5ade12d03a0df09da7071dba3defaf
export_key: 9ed333239e4a6c16c14795732c72313c474ef839cd42e023af1093407
7c78bedf5f355cc4990fadc6ad79f69d47ba738204cac43dc4c091d591cdfaf86f4c7
1f
session_key: a45d1ed1f6aeda9bd44c926bf78aabf3824b8ecdd41ae21fdb547993
583b270b146be2735550c4976a306e4e25aefae3828a0665f7c3260e0106686189850
2de
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
~~~

### Input Values

~~~
oprf_seed: 5680548a282ac9794df98340e0eb07eb7eb29c16244fc5120ea7088192
43d995188bc0517347cede815004a86602c16dca275c7c892f2f9568899c61561367f
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 57d08bf343432a47c6ef632bbcbef5be6b799c746d84f476c0406
f8da33bdf38
masking_nonce: f54e296d133f70f14654afa20691162bde3ef9faa22f54319504ef
63c785dbd8
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
server_nonce: 6677d61ec51f5fb08f4d66bd62f68f1b030aaab3812daac49aef507
b5aac91bf
client_nonce: 4e3ed8386e3890b4c13841d46314fa3c40838f739cadd025e70a3a5
17e18eb78
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
oprf_key: 0faf75bcb99b9c33456d26bc140c017e8e63af1eabd9cc3021674b529a1
f2904
~~~

### Intermediate Values

~~~
auth_key: e9060b308221ba9f389ca21f5c1b0e0c6ba4ba66f74e01e86786eb78d36
a92a4b09d4568d73607b195c95d1cba22e982c905772ee86e2842c315e38ba8e6b61b
random_pwd: 30ee2061f3e2798d00f34833daa3b56e46a8047ff7f44408afe5ac0b1
c4855fc10979ab31fef92eb0e32b4d7615e831f8018b05569e37f0d8ec2f6759847c9
b6
envelope: 0257d08bf343432a47c6ef632bbcbef5be6b799c746d84f476c0406f8da
33bdf3865ae13e769925b3c9bde386131adf00e90eb874fff9fc294b42528894c615a
0567931031777bb3be6e97c8eb95a2be22c10198a52c7c7479b407c909a6a0f83b965
77e8b92437daec940199150c59dda25c379cf21bcabfcc17d59e36ed0cd72
handshake_secret: 5358a11fbd433a7d84dd8a5a9df540930ca54fb2d698a358ec8
caf7457cee9e39be045734df11c2dc7d8e213a1b688a406ac4dbe481f99e4d9444acf
f3018517
handshake_encrypt_key: 77c7e25d6e7870cf5ffb3e63b4a41abe62ae2e5ce0a6a7
47889ed7aaab23efe3e732b9ffc922b6cba7943dfe12a217fdeb1380b9403e44604bf
d4f0e2c277b84
server_mac_key: 97281bab6446d57cca912c9a1e88cae268b4d2b549cbb11ca9a9c
bffda3a34ea789ea8e586593493e4133ce9edf50dca16012e1e8871d93511915b335d
3e1eac
client_mac_key: 6ebd5839840be18babaae2b8fc3500687324638999db9598acb57
a94edfb6bdb58149dc075b505a78972686a5efc4bcb394ebd614041c15e43851d8876
9da045
~~~

### Output Values

~~~
registration_request: ac2882512f36bc4d5914964e782418271371fa9bd16878a
5fb6c3b6d29c54422
registration_response: 0c444ddf8e6a3de0bfa25a5193f48f4206e28a84c1f7f6
2bd54fd24e370d5f720c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd9
d2f936a37f14e
registration_upload: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c
79787e2df91e237164f991d6347660124e02e031f286df039577fefb9207fe2c7e0e0
78e405f8ac3cebe3fca2559f8ac9351c25e560e45738a5a7485cd399b18f45f9fba3c
ad88b30257d08bf343432a47c6ef632bbcbef5be6b799c746d84f476c0406f8da33bd
f3865ae13e769925b3c9bde386131adf00e90eb874fff9fc294b42528894c615a0567
931031777bb3be6e97c8eb95a2be22c10198a52c7c7479b407c909a6a0f83b96577e8
b92437daec940199150c59dda25c379cf21bcabfcc17d59e36ed0cd72
KE1: ecb46e5c31b4044876ccb2a689efc82231d2995561841156db449c71637d145f
4e3ed8386e3890b4c13841d46314fa3c40838f739cadd025e70a3a517e18eb7800096
8656c6c6f20626f629698728bd0febdc164c410a6738962b955c08a36b25c89058c38
d4575592c12d
KE2: 8203032460b2c4b87d4693a5380942a634954775e3569334a91e3a0a10ba5a2d
f54e296d133f70f14654afa20691162bde3ef9faa22f54319504ef63c785dbd83b50e
b6512afd0adda3f34739212a47ebc70de684577bd0bdfe7a3c0ecddd57cb6e7c04e11
85b4aa82a690972452a39954e5cd2c9b40ef3a333dc5e7a5e6712e911e4473573d33a
02495c11989705da7f01ad6f9afb6c2cc5640df7a12cf74adade1c7bd5cc0fa783b23
bcdbf91f7e30d904cee38e16d106a0e17add35dbbe33decf4b529f2a2dea7fa8721e6
d733710dc6405aa9c7561bf56bb1f0dba2ec895836677d61ec51f5fb08f4d66bd62f6
8f1b030aaab3812daac49aef507b5aac91bf34be8693c06fc0168040b3321043f40ad
79648211e6604f883bdf23abb045813000fd2d0f8fdc1ce6200c30d2f1dc8672b0c30
7f2d3cab0f1dbafa61635d1937d70acaa0097161d02cea22f416a7967b9fb7f28c39f
093cee59a208bf9be6fbced6bf1b61de9f7af2ce766042ee0b1fbc7
KE3: cb7e27933a7fb1dc72ee7461370588a7ead2c7593bd428e395ce6d33afec64df
9fb81aafdfd035304e9622e53d9a9b7a00976670d25b1431fbb23c7984bc2a31
export_key: 746e680e162cfea9dc45d0ad5f4a3c5e84ec2acacaaead86d4647e6bf
0e44289a9dd69316713130766f3923f837c4bae9e9ba6dc0edab41bab07bc1a4a3901
ae
session_key: 16d447e80bdb456011e5c74b235bbbe28ac5ecbc8f162188ce2d4922
9069e5513ecaf8f1e4b3e6716ff2bf081c436900f8fa49fa2066022ad3bd3453098bb
a49
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 2b68a692386fa4cca588bb6c912e8f8b4d299af06644c5f9ccce120c45
cdbf537cdd24dd91aa699e6fa3611c77c9c79a5abf3f3f068327525dbebe3597a7903
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 6db3a425db84688a2163d528ce34ef87e153dcd1a829381b8d85e
d5285c362de
masking_nonce: 08fc4385d629d846cbed61419cc41bbffc368c669673fb12bf67d7
161d00fb38
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
server_nonce: bea1042de00e4b14bc59f3ec54e3c8e760d8dea9bed324cbae99e64
f825de8b8
client_nonce: a6ba2a6c8906039e72829cc0356cba3df78f1a1f56378219dc55e1c
2736bec4a
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
oprf_key: ebc74c6e08c76114a1a8938e0173c662de20c70284649d1f7b094bfa703
0720b
~~~

### Intermediate Values

~~~
auth_key: 0d3dd27bca6a6cd9e915eefa92e96c71c1a3757fbe8be2e97bfc6c6488a
9c81b392cb778a21cda9d2a9d962d99509a6a3451eb29bd8596f2141327f8b65427fe
random_pwd: 733a5bf625336fb34ac7d26e303275eea54380edd8f5b51f53eca1671
6368f5b494ff9d8122b74fc1d952674e0a63c7942c0fde8edf9e5d424ada6bcd3c5eb
4c
envelope: 026db3a425db84688a2163d528ce34ef87e153dcd1a829381b8d85ed528
5c362deb9226eb0b361c0ccf82e35dc431c73f92b8d648e691e8f046aa83945b449c1
7b022f7b01ca6266824be288ea1d22b9b75bd252724ef24ef590dd47f4ee52cac977e
bf59fde1b612bc17fe113c923ddbfe3d27e0c798f5e9cee4cff214bda469f
handshake_secret: 97f2bd93df695b06291f63521ad8ec076af030e270e76d900f1
e0cc8e1e304ed32e79ef02db9e84b68a3b7f38337bc60a331984d72029897e99ca336
f2dc5f84
handshake_encrypt_key: 13ca102b21194d3c1ff3765f348bf0d3cdbe6207705a5e
3e9289e61b1d8a5551eb4b548b0abc131a98d5545fce077bd939212423d894d5c3e65
1bf0e1b747bfa
server_mac_key: f7c72379b3c4895cfe393c5c4b37c8a69ef19f5f5cb0f86ffc7cf
3a65db38b5d98660d57164f1412f8324c55a2e029dac16dc9eea21b375984d9a6549d
73dd43
client_mac_key: bb67d4165f98af62f83699aea2608a5087d883c7fb611b32f9a90
c934fc53b5ebf33f10d0027a2157eee6568b8480b082dce3921cf8513dbd2bf0e8f68
f74d2d
~~~

### Output Values

~~~
registration_request: 34fb6ba29e60511d9ce2d2a644a58b8b34af6516cc54f20
f7ff605e8134c1213
registration_response: 30c383b5b3d3ef0ee8a2e383cb774a9defb4d28db7149c
9bd7e45903a2605a27928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9f
4389fecd57073
registration_upload: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae
5ba927c3c6a9af07ab4c7fa2f5d6c467087a64e3bbf8d74284bd8c5474cca8db396ea
2e347e63ca3f28a484aeffd7035796eeb4d06166c7bedd80b0778397787993546e17e
5b5887026db3a425db84688a2163d528ce34ef87e153dcd1a829381b8d85ed5285c36
2deb9226eb0b361c0ccf82e35dc431c73f92b8d648e691e8f046aa83945b449c17b02
2f7b01ca6266824be288ea1d22b9b75bd252724ef24ef590dd47f4ee52cac977ebf59
fde1b612bc17fe113c923ddbfe3d27e0c798f5e9cee4cff214bda469f
KE1: 9e642c6da6a475f89078708431aaa4e04d96097f7778b0de577bf4d08496ae5d
a6ba2a6c8906039e72829cc0356cba3df78f1a1f56378219dc55e1c2736bec4a00096
8656c6c6f20626f6284a786fae7664759a8bae0cbe9065cd80b70cbf600efc695654c
93e356735c66
KE2: ec19a5c2dddb687ebc36fa68fffe096a280b081ae8f9f2cbafb9275580b25151
08fc4385d629d846cbed61419cc41bbffc368c669673fb12bf67d7161d00fb382d6b8
b000742bff080f312e43143f69ae1becedaf7aa0468e99fa53b6b37dab03e2724f49b
a5680c439256d79e90ee104e9e6351125c4d7628c357579361ad800e69bd8049998e9
91227ca3e165e8722252be102208d82ded991790b43c45cfcc41247fc66d76be42fec
583fa4e112850deb98ddf2ad117684d80e513abf17e705117e139d21ad6f556060506
347b50d52d3c4c79ae6ed0e2715933644bf5a80d9bea1042de00e4b14bc59f3ec54e3
c8e760d8dea9bed324cbae99e64f825de8b85ef3502cc40e7ba5006845c131b661ba6
ebd0e6994b6f526e3b7cc108635912f000fcf4b3d90d179c610dbbccfa7b60988f32c
34b21f824c3b1cd30d063ea494bb2385bab6963796da987c278d23e91737a46492525
40d60150ec4bc28be6725a1b553c09bc34d0b779814ead83cbb1450
KE3: e4c3baf62f2ddeaa852fb6168325b447a41cf7b3f5cdc1059c5eb676c1800b09
e20e0ac8c5935f7e1d3c7cd0ee634cf7aebab4afacbce01c07595226e9ac9d82
export_key: 17f76ec322cb2829febbce77d56ce5f17638c6c70b6815f8eba983a01
4729c2680b79549ecb5afb9091e2a65ac1b31a2bcde9f2e7e15c8ebd0bffca6ad2a8d
04
session_key: f7d019c8931b423452e4ef0aea626bfd7b17ef0b887791d62a3662df
babd980a0021d80e3e6f64138ebf35b0ce158ca83914f04c96b78ece0428ded5ac394
34c
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: e1c2917d9a4d7d1ec49390a58dd27f1d46c9b14491af9d3769623fbb6c
33f40d47c68b54abc9376f75b91745486dc35003e7e4a16d90d9683a49eb96b6f4df3
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cfad1ccdddd1e3d06d31ef9326124a1f880e495d0256747bc0537
9647b114993
masking_nonce: 485629467efff1654d04a8a0d9ec3ab95e3865453313967cfd189b
40a2df66c9
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
server_nonce: 0c2fd53979a29c70aaaf038c76091193392d5d9a7bff266449eb306
662695a97
client_nonce: 4d2407a2c2b2252004d8dc6574af9e54f94ed9926ec6d108fe45470
54b8e9b1d
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
oprf_key: 0f7235263e7e691fab8a8248670521a9262fa895f1ddb33f97222e68d08
8b207
~~~

### Intermediate Values

~~~
auth_key: 0101d5bbfc8cfd6a8ddf42a3b6fdb16be9cb33ae6a0edb7b49ca320e6a6
c82a72b659a8fed7d92f2f3a45d58520f64a865e88c62e46c307692d6928198ca3846
random_pwd: 30ac2e3e33f8fadac74d9a782cc595c9c119e2017b7aa532f1afa1953
58986ef541f44122982fd3eca01ca9bb2669bbdac95ea2e2fe7cea41609ed7f102d1d
dc
envelope: 02cfad1ccdddd1e3d06d31ef9326124a1f880e495d0256747bc05379647
b114993c65d0f96334d363593c034d769bc3990f6881aca6d0626dd1924490b76eee8
680c1cb0f0abad9fa407946a618b50e95895111eb978d71834c6c7d826ce844b8cdba
9252b3450939976723e1c2f04e91b139f3368b3bd36aab070c8e067ad7692
handshake_secret: 757f726a6029a301ae41cca292aae9127e1a523d6048e224a4a
0da671d087cc5e6d7f1035a952a330768df33feec78541cb21d032e6f937e24220df2
cb95812b
handshake_encrypt_key: ab7ab5a998774a3c1849b8becbc89ec6c61e92152e4745
cf3d235c64c4f80d25b72302d0fe80a6fa6a85bb18c5213a8f6d74467d992d2b2625c
7e33d182adc0b
server_mac_key: d12adde57f70857a98bf4d4fd470b4b8f727bc259bf264a2f79b5
81ddf20e0e0e71e7eb77335e0647ffd16d90c1f14a60ac1762befcbd525af74fbb44b
e27776
client_mac_key: 36f43d8f2e60d94affab77d67aa1fcf585774d7ff3f841d498037
2bbdc4ffcfba01aac3478004e4f7c893729bae65eabbe9bb05943767dc015c2fa6927
847e9e
~~~

### Output Values

~~~
registration_request: b02294ae456aa0e055e49a09a3a4cd7176d9b34778a4dd9
493eaace4883c0016
registration_response: 1a4fc52a75d3238eb29a1a9667d082f58b9d05eef7532f
8c377d72736086d213c26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d9
d5eda7943266e
registration_upload: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f2
1f51945a636d180d996b151f750fb1542cb090376bfccb4969dfda4629e60628510c9
8cbd1326b95c9ce02b886aee0e408fc2b9441c46b5b697380cd1211da2907c6783828
8b6a7402cfad1ccdddd1e3d06d31ef9326124a1f880e495d0256747bc05379647b114
993c65d0f96334d363593c034d769bc3990f6881aca6d0626dd1924490b76eee8680c
1cb0f0abad9fa407946a618b50e95895111eb978d71834c6c7d826ce844b8cdba9252
b3450939976723e1c2f04e91b139f3368b3bd36aab070c8e067ad7692
KE1: 7405ec93c531676eb9437f46cf3c3dbe9346fa83dda34a37da03d693a90e9f7e
4d2407a2c2b2252004d8dc6574af9e54f94ed9926ec6d108fe4547054b8e9b1d00096
8656c6c6f20626f62c2b0aee89ec05d28e6f9638d2e056f7cb4bfb8b4d032239d3e4a
7960d7479e7c
KE2: c29e1669f3e08f0764e4f34ff34f8479efc41a39d2a0732648ef5ecc2c70b457
485629467efff1654d04a8a0d9ec3ab95e3865453313967cfd189b40a2df66c9802bd
f572f4c2819fa4d919885791181669ba3a609836a74c3e7e175028fbdaab01f7e5c88
db4599af5bcd3464d6ff11eef702ba22cebc34d6ab35a817d5764579592197f9bf0a9
2730b3289baf922dfdffe128073b160e5f0a12f60f29b5ff8f2913de6d37f2bb3025e
3495d9b5c60e1bd7452514b4503dc11ebf0fe35000ea4ef6135f20b5b7e4082c9758e
eeda65c16b7b42bdcdeeb7687a5edf5ff70f870490c2fd53979a29c70aaaf038c7609
1193392d5d9a7bff266449eb306662695a9716041ea53924cafd460331043cb3ec0c7
f17d6c246499b9c638118a606071e61000f221ae9d6d8070d98eb08c33edeb19b20d2
c856e339ac2651ca4c6b7fa63407fea898f44ddf2e73e74cf1f8bff433b1b79939d0d
6f929bab5d1ea5cca9abd672930e76174e9873596520ff9f57e9442
KE3: d04ff42660f0f4f55ee9e566d59df8090537531a655be62d53b47692b4c46cda
979849bd5b67ef65996325ee26dacf4476fedb943989deb936ef656ed22bac0f
export_key: 7c6d49877379976e41435bac6874298705f787c11a4cf38c8dd786d50
f3023e0a166db12d7e17bb8478a7b6b24f061e376153c7216a367937c245af4a9a8b3
c7
session_key: 28163f0d0542ddd25270006293612fd75c1a4df1403e8545bc9e06cc
7ac0c1499e9a4c2f955ec20a94ad400961d53c20deabf8d2ce95af25b95ef721dab8e
142
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: c7d8bea9845fbb857f5781cfa62ce8e39feb94d49732dc9de33f2437b4
89cbbc7a4af38e7e85a37c0974cca2da997bcb382633c14406485f3b84f0d56714700
e
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 6af45fde7234bab6ad66cb5650de6b7337db3bda3e6cd075264b8
6a1007c499f
masking_nonce: 745b1c9b74c358768c6bee8dd4592426bd3441046c3f373a2b175b
5f4cab6d37
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
server_nonce: 9adaaeded4e73734a760367eccc021a9c8a2eec410edd0870e6912f
a1184ac0a
client_nonce: c61ca2c0e9b6f55432ee5f81f84b8f9fa22ef365738734ca2661ba6
ddfd53ded
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
oprf_key: f81dfa8577e0ddd36f9f063eddf82a8aafa927ccb7cc5abf8d41076fe9b
b5d0c
~~~

### Intermediate Values

~~~
auth_key: 965b674a0020cc9be866f8b2ed37f9b8389ca7379554fc1a26c0f8df6d8
b06da20d9d7b3992b0d79c270b00f97fa5f3294eafcdeae30c6c3699711a2dbfc8223
random_pwd: 5a5db45220069dc8c036be78937e425539721b63b47264d8980784618
983dba25b8d5c8fdc109258e2447f618c4cc26eb306b2276dce3061848ffdedb7c61e
a3
envelope: 026af45fde7234bab6ad66cb5650de6b7337db3bda3e6cd075264b86a10
07c499f5412df2e2c9fd1850e79c51be1217ea1d498ef0f305dc519709b831fb4ded9
73f088c345732ac13b9cc0480203ce0cf6923c0bfb58657e43d90f0bb47e96631849f
fa97ba0266f3e4be9b66ff65a0ef4faf703902ef72f2263690fbe3a002359
handshake_secret: ef777dac4034b7a6b15270640e4d05aeb76c9249d0c18032719
f93012725cc1c7555b365a5521f714b6a2893ee890bcf37227b44d8589fb79dc83fbd
240684a7
handshake_encrypt_key: 76857b689c7ee789dfbac31557d7fd758d0fcdd1175eb7
4ca7ed15ff64f08789e64cdf1748e2675285268d502ca4a4421f8866db06fea01f7d2
855eea2d63f65
server_mac_key: 4024f89b44e6b1d59bae47dcba7d4a1eb5831d0132c263b850ebd
6557d0eb578f42d763f836c34f653fd614f4a01f22a12dc367393a446de57a3560194
afa92d
client_mac_key: 0185be999526c10aadb9d01f138933dd50a77df8f47cf141ad44f
6ccd92078823cc5bbe54dcca3f6f7d4861528fca151011727cbfffe1e8f33f0549cbe
b99432
~~~

### Output Values

~~~
registration_request: 6a525dc9419e2d0261fbcd6033f9d500503a27027a48d91
27ca1209e01690d29
registration_response: 7a8f1b9476d955b70789231a362fbfa3f0f164f1f3f7e8
4d44a551c14c8ed53d9023317b443158b83d4f4b49674209ad390595bd29758f5e86b
1fb217190e964
registration_upload: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def6
3328bec3a4f21146626b11f4d4cc63902a87dc7180d36a184b2b27e9a111c0a1ddca7
92df8d7039cb6cdeb881a9f7799b658caab15e7be4f9f93020b97d01b082895afaa16
c79bf0026af45fde7234bab6ad66cb5650de6b7337db3bda3e6cd075264b86a1007c4
99f5412df2e2c9fd1850e79c51be1217ea1d498ef0f305dc519709b831fb4ded973f0
88c345732ac13b9cc0480203ce0cf6923c0bfb58657e43d90f0bb47e96631849ffa97
ba0266f3e4be9b66ff65a0ef4faf703902ef72f2263690fbe3a002359
KE1: d6a8af82258885688aada828f32e04463c3739c7da0e63c5246711520dc16e37
c61ca2c0e9b6f55432ee5f81f84b8f9fa22ef365738734ca2661ba6ddfd53ded00096
8656c6c6f20626f622c8ffcf1bbc02dab15df7834ebdf85841395f07c8e7317285ba8
574b6eee3910
KE2: dac538865cc7b065f22b85a5739764d451ca9f39fcb957ceeebc3741c16a7820
745b1c9b74c358768c6bee8dd4592426bd3441046c3f373a2b175b5f4cab6d3762a8f
b15979c1be28263cc37a34e700cea2bd6737c7dbe8161deccb93a6a70fa86b857a811
767c9ce382195612444f66abddc9a5467a09c1ce234770e76659b48820a0e9ed1a7b5
4ca0f2dc97139e75fe5f54018bb0fc66b9d76f1e5baaafd6e49611757aa4e8a76bd3e
6323b1202df3fbf829ca638e8ca92825e1db87252cb264fc25d6dbfc674795b1ac37c
d7544a24f1f4cc51406278b7ab2fd6bc2013294979adaaeded4e73734a760367eccc0
21a9c8a2eec410edd0870e6912fa1184ac0a58a6c4fdb4b3da03df2e5b1f6ce154940
2e209712e5bf9d31efbdb82c00eef5c000f6126955fe2067acf1aa28dced6afad74c4
2c24bb12cdd49159fb19475b30d9dfa8210ee3101ccbe580be6a489f4fe8b1a78caf4
73164a5f16e7fe60c6d08aef4fdacf43ff75b14c43ba400ccdd3888
KE3: a19092a98d1a1546869532257d23fcdc47100409fe025a11b3155bf39000b900
f842e8242b065e86b3845353eedd0412a6cd9d4e0a83f2f8011eda51ec43f56f
export_key: c7891f2c90c0eb98b534019616c7077ab9c64ca1d684eefe987402ee7
f2b19b941abc25d28599094d75b08590925ad10004668018630c23d7d571c18edaae5
eb
session_key: 68b652142158799e0ce8ce6cd291d0a1c68bdfc074b9b37359e9eb71
9b0987343f2c7bd677b522b1633b3ed84b87ec2dc63a6eeb35f57373abce900fd4445
8d0
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
~~~

### Input Values

~~~
oprf_seed: 218c64022e4a43370fe0aa59007200650e493a40481b6b0084b1a0ff1f
47b7a6fb9080588128465a50e3286d52d74f2f699b32b218fec64cf5956664f14bb6f
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 12ee5f48b436fa9aa3b7d10e65573b955af279cc566e71c894199
2403bff9657
masking_nonce: 7228efaa8f6fa610e4289ae713efb5ad8c3d656ce2f8245d344ba1
4a658fb54f
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
server_nonce: 54723fb137b83c87f56ca520f9ae4f6bd6e03521b521e4a0cc75fb5
3e744e31a
client_nonce: dc0f14112756b595e6b9e3bbfd2bbc161a9bf8e0754e8cb3c8302df
5c0e80744
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
oprf_key: e77f4a3b78eb5ad3cbf9e264c56b84b6d37539f003dbd68b3c19cbc0e2e
42047a3364f728991fce0140dc98d6feb49aff1d9429098a35623
~~~

### Intermediate Values

~~~
auth_key: 74b53b1b022038788c0a89f37fe073254b7f6fe28ccb7f4b818bcd4cfde
80ab1e76b85d4d14f4fa21592a26e51f3ed4987468ff45923883f539cc05fc939504f
random_pwd: c2694c1fae7300feaad7f3496e9d038042a03c099feb4b63037576309
b5a92d771b0c5ab39857b79fd00474843e5aeac65affd293ec0d4d2b7f9b2c6eb9c70
a6
envelope: 0212ee5f48b436fa9aa3b7d10e65573b955af279cc566e71c8941992403
bff965739d8f75522c9fcd505d02c8fe500058910fbaf7f44a1e03c91fd28e9ff8356
1a43d9fae58c432a3e26dc5a1ffb34f00fcdeaee5b56880f4765285c7b61f729950f4
07be068c178071dfbb064868a3fb35b5537702b41d3f03f84a1c0db34021264437ee0
6ad23fb5c78b237b08a2c1b6734702535b93d036
handshake_secret: f59f1c781777338140af382b44d7a05c3c7bb78456334543def
494c75f5d722d4f80d736e573a81d7009399489c455bffe44fbb86e101ea68bff7195
67da1d81
handshake_encrypt_key: e3e150952b0d14b8ae4d71f76d951c9d0697f24eb9d07b
162cbe26ef8a1de8369dcf2874f6a190902fbd3cd71af3ca97fbfe19e0bbd441e27a1
1c947f731a828
server_mac_key: 3f54f320be4004ee778cc552aee3a3069e3354c28538c2112d14b
28f4ab0f3deecf813f21baba72a97c59e9154d71cb28b69656648803f38aa4fcfc24f
b5c71d
client_mac_key: 3b53b0b8e7a2f589e0fddb71fcb41e1b98143d0ff224fadb33106
5b1ff638b73ed924e27ab013e35ff79271bf2808fc96c7a4461eb39fb54a09ed4e20a
70f5a7
~~~

### Output Values

~~~
registration_request: 56eba0e757af33e634107f2da32fbe987af1d37bfec1918
a2d42ed2f6b3714bdc1dd190ed6dc6da310536bb748cad363e76ad2fb1b05f1c3
registration_response: bccf5edf7ccd7f153d3d51fdd2ad949bb5022d35c14901
881ee1bf681f9f53b661a4f44b26ce0f43e8d8e7a034a99a7cb64872d61f481eecfcb
b8bbe6f857883e38783acf58dcd6de556530055a2353c4e584320e0916d28b8278212
bd6405864ae84a5cd2508f09ea1185f82c9ba518
registration_upload: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9f
b686b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aa56b4f
e3beefad108a64935d9b416111bd2c1d379b179a393088082fb0d8ab3f49ff131d1ad
305a07d4aa064486d2fb45a801177254a47ce6daa9c3a7381d0a830212ee5f48b436f
a9aa3b7d10e65573b955af279cc566e71c8941992403bff965739d8f75522c9fcd505
d02c8fe500058910fbaf7f44a1e03c91fd28e9ff83561a43d9fae58c432a3e26dc5a1
ffb34f00fcdeaee5b56880f4765285c7b61f729950f407be068c178071dfbb064868a
3fb35b5537702b41d3f03f84a1c0db34021264437ee06ad23fb5c78b237b08a2c1b67
34702535b93d036
KE1: 16ecbe71c272b0b9cce77059395154ae766c95a7f10ad0e699aa0c773877225b
a13e0a8ace5007c53ce3631c7e7cee782a6c44cad6832e0adc0f14112756b595e6b9e
3bbfd2bbc161a9bf8e0754e8cb3c8302df5c0e80744000968656c6c6f20626f62d25b
52b3af68ebda6905d0db5d964660ec9ec81066ef7955559aa302e012006b1ce049556
666231483f56af9dcd1c27fdbafb4d954060091
KE2: e2fae8bc0189aed4a81691639fb54b8f8051f9e26c24b215b31700b80df08c3a
581c76a2189222b8f9700639677b797acb7496f0d6cbac5c7228efaa8f6fa610e4289
ae713efb5ad8c3d656ce2f8245d344ba14a658fb54f8f0c4f12bcab9900ae52592b22
a1bae55609cbcff7d4a88311a50eb22735a5f201b968886c3a0165f110b4ecaeecf96
66855389b6f70cea54740dbfeb90b7451750508913196a4361e762537933ea0fc3cce
6cb9c3dfcd8fbdfa1c120851df4c8d14938f19725b5ee20dc7ac66d00c865c3e905cd
c875d56e4b3dca524d478773244a307541d2ab7f94d29c9286b2d22542433b02f3485
b31d8809e7f2be35c588fbb9733c57b075ce92fa0d795413ea37760161afce58505f5
0c995739f6c6225c0da2ef402d39d7011d1c360641a9e7254723fb137b83c87f56ca5
20f9ae4f6bd6e03521b521e4a0cc75fb53e744e31a5898c178da53ad329a001103a6f
2b4ec6e0966c665fff16d88b87a83aa267c2be161d1a36a39b7b184828166f721b83e
e15fe4753b05755e000f473ff0e56259e1973dacad8e615ed66895cdf657aecbf7831
3a81a637025d104b8b678f323062b707fcd5cf105e0a63f4564b43afce091304f655b
cd01df7a8901414cf7a428766539fe1a4eb21394
KE3: 32b83e888bc518229807e36c307f3994969f52919bbbe0301888e052bed51863
ac18983eba6f0510e9af58c2abea16f294f81ca606599aa322ee666b69faf49f
export_key: b9ed42ee24e662d8da71cf811f941a30a8db74942a8a2686fad5dd2ac
391a123e61bb2336f3aff2a4f8d4cfb9836d1549f021cd1cada0eeb4000210e4ff002
5e
session_key: de17de94fc305baa93ef628a23c8f12ec3ff333cbcdcb9ae1e60a0cc
c6baca596699d288e3e79597e3abd97ec08e5334f4cba333ede547786efaf61194e5b
b92
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 56c2cbed4f40f7a3e1bb42b704f0473d565e3c2adc7c92a13c1958a5d5
d9b445bf7951a6f6e658d825a5ccfc90b8b4eab1809b7f388200731763c07d7bf5c5c
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: a3013abc0b31ae0187d59e8ab56912b929464357a142167846a87
5d54ae78504
masking_nonce: 2a7ea6741ae47e8719fb1bdc0ddafaf550d85bae2fdd7ac1b29d41
5b635d5321
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
server_nonce: abd0c0282ce7608dfb545035ef05d61e4942306846e53cecf968983
875aed20b
client_nonce: f292855181954ed2b8cf22a7219a24885424be585a457104474200f
9182de9e0
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
oprf_key: c71e0996e7dc75cd0e6d94477e06f4ee00474825a32bdbc85c29fee029a
376406c9f0e8d8468e08a4abf83741d398a45cc71abdee69d8b15
~~~

### Intermediate Values

~~~
auth_key: 1032abec5c045f4c900d9f1dc8cd27e3ffc1ffc9c35a32c9f895f07e70f
b884b8e05b0bb48a132da5a76da2bcc250318d6167af57b8da37d9e89e4a943a21f0b
random_pwd: 6307332863941be4d35334bee3ac2f35aba1b837a514dac46b3b4826a
741bb76d24f2b7d43b831e6201a2ac402737b6c02854ba83f1c52ee364fe68f8776e2
af
envelope: 02a3013abc0b31ae0187d59e8ab56912b929464357a142167846a875d54
ae78504b1ce9b52085a224ca237e08c721d266479f8e9eac96c0537b8858ae23a221e
75792aa65bf6aa699be281ac5c9ab098fe8ff192600d5b2aa831f970d6c895cc4f7cb
31c55c8b07813e06a47b54692ca021d0fe4e59bdeca22899114508e83e9a248c018a9
42dfa11ae738cb06415780bd2562be93d6df62ec
handshake_secret: cfa13a34432e711390afce98c1a42c66bf9f166491d8c636116
705b2a31bb73ac994831754807c47591d056ab529f05f9038e9af4f256188f111c408
82a4dbd2
handshake_encrypt_key: 99a1e0854cc2739b1347d5245fa293da9813b6ca4db916
6a66d8ca64f553288b3b9e8ce6fbba050c62e7e7fe44c725d8cb8b62b4b2c8bc7792b
84e8ef167f335
server_mac_key: 1be9a3aa4867ce9a3d074d1ba0b005fe765ff52759f7b7d40b1e1
c7182dd44e8413264b6fe68b01c315224d49d518d66cacd095ddeda607b5c325f2ee9
99a0b2
client_mac_key: 33d3d72172f5e0840ce213fc57b3e11702e6039031e61bca577a5
7a257a43c1255e160d329c19dda770f11119572dd47614e4e424e63224d8d79178c0a
ff992e
~~~

### Output Values

~~~
registration_request: d287a62ca4d452ff3b5e2d800121dbb5785bb383db9bdb0
c541f8e643443dfe2ddb1162b8b7c758893fde1131a84ae57935e7b60b14058c1
registration_response: 281cec9db60e489a16bafaa4c01f791089ef03d5d58dc7
541968942b261f6771b36d8a03c69e1b6423b9260a68851d44466ab95faabba3462ef
8f9560867402d20f9c34942bb26e63d2cc667851473334c6cdf1f89ec0ea218e3ce0f
73f9f1fd303f140bff958f80b7d4dd22a150a0aa
registration_upload: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec
2af04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f35726807
5af3bb6199392a380fa75e81faac2bb138dd3e1aa2d36df32572bc1b332707006561e
edbad5136ff97e89bcc14d957d70cf3ce77a9f384bea7545065c1b02a3013abc0b31a
e0187d59e8ab56912b929464357a142167846a875d54ae78504b1ce9b52085a224ca2
37e08c721d266479f8e9eac96c0537b8858ae23a221e75792aa65bf6aa699be281ac5
c9ab098fe8ff192600d5b2aa831f970d6c895cc4f7cb31c55c8b07813e06a47b54692
ca021d0fe4e59bdeca22899114508e83e9a248c018a942dfa11ae738cb06415780bd2
562be93d6df62ec
KE1: e4420dd6be305be0776f14c1140f0b36ca304c007827a8c5b4910c5432dd4caa
6214b4077d4a99e6d6dd7f756bb3531bd010eec2253afd1bf292855181954ed2b8cf2
2a7219a24885424be585a457104474200f9182de9e0000968656c6c6f20626f62d878
99f024ee66ed5b8718f9966f2f34dde445da12078789f1e6208028cbc9b7ac7cff5ae
937856aa01321310e1858f0e3b89492e9e49f42
KE2: f6d22369affa98224435debaacdec52a8659cdbe5118346740a421307e1de4bf
deda6bfb92f2388f1a6763016560584811eda12618f597c92a7ea6741ae47e8719fb1
bdc0ddafaf550d85bae2fdd7ac1b29d415b635d532128c8fd0f8d16a656336c0ed71e
19213c3b8a6748f17d0ea4443d2c5723d19a1757f6407216a41a84bd75c71dd87b549
51499865d9a4fa2b72e8710a0838cd96d98901172e938f43fe70953e9ca563ea61693
3f954ad23ac0cb945f98ec6a275be4cac912da2a4b3f54a993d6787aa7cb4cc5cc3f8
d0c2de2f0a82cb6105f3b6a1ddf04d39b6ddc11f46c2b4aa18f442fecf5fde7e931e8
af84665b271bbc3dcbed57747323b707af3e935eab834ada40ab09a46850a072a021e
8e8f763d10e3266266f5fcfd75dedc17198a772f31152edabd0c0282ce7608dfb5450
35ef05d61e4942306846e53cecf968983875aed20b32751cb95f97035f22d498ed57a
8af0d2495075aace642f152442da8485211d6a551142d9bc6771619ecf80ca8b4def3
96f706ce555e2896000ff44e923243a8c9e8f780d524d39ce5c129e1e6f92d8e5027b
8a5424ec3493f1afbf74aadfabe55da66b53cabb9055959d7a74222d957d8b6cd3e50
a3277639181845aa68d9952669751bbdddb64157
KE3: ed9998c089bdb67a245cf9faf6c3d1137a64c3d1795c8b580778c86f62fb0dab
150802625133c16548ef113a440c2bc2a43769df0adabda1006367942077a82a
export_key: dc3505adedcf350fae51b4c210d5e8d080915f25169f9c6df89cf384a
2c6e91d86d2985855bf48bceeda69d4d56e20780a84591d1c34747358a13505adf18d
2b
session_key: 5072470f802d6021701ed13ef2f792a76694551928aef0cad57b8407
0fe8efde88dd6dabb103fa9a6b47a1c278982dea0be67969db7a1e904898349f1d51b
14d
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 6c4d724b95e41dbb9a6aa65953f8dc18d630204803c32db0a3159c4beb
6ace23f1c72c1b74e5f14b304f2bbaf557fe540530b82db8e3e871d5bd3d1ec598d72
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 5708c903f1a71194e400e4a2fb5efcf7c1904fc51e19b95c3f9bf
49d53617a58
masking_nonce: bd826244268550bfa496f01f61cf313ee795efdacecb77059f9364
c5c28e1487
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
server_nonce: 34ce69db02c7ede3f58678065eb53e569f239b1f79f3bf48f864e5b
d26535fd6
client_nonce: ee12e24af74615d2da026e7efd0fb1faf88c1f00298a6478c8baf41
64b2074b4
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
oprf_key: cb562273a99510335ef2bc7a3589c767524e3a709f089668f2235142897
31c077db9812fb2ed10e30a2f8770e376f097d56e91125fde1437
~~~

### Intermediate Values

~~~
auth_key: a6e5065a8c66d30fa420277417bd366e9ffc6dce6be4280fcbcbb67e9f2
fc8bd2fa0b5391e60afc0a613ac06a3c021e7334c46c701d81594de07db5213ab54c2
random_pwd: bf79591d94b9ed8e2c9ff3b0d3affbb5418160da60e4168fce0abe061
1c179adbbfb729838acc91db4c013a59f27643ddcef47681e061cb1f8a813f78a8524
2a
envelope: 025708c903f1a71194e400e4a2fb5efcf7c1904fc51e19b95c3f9bf49d5
3617a583de22c4970c8bc096e6bb1e394cff7796e8528acf8b4904a8bc654466e8b23
b0edbcb63d9a32368e1ddd23f937f03424300eae916a530b44d345b025ef3f654faa4
4460b74b90f7fe7389e7503e5ed7e80e80b157f7afe569279e14f4c96641fbac7f775
497e71d00ba01cf9515d32912a6901ed33e99e61
handshake_secret: 7818439d92bf70bbe375b0749c32b7e83b754ee24e5b475ce30
94367aa2682ccf724be6b70bc7eb429c49ae5ae2bbb3ab7710af0603a5ce577e6cc92
f9058e4e
handshake_encrypt_key: 7ae2ce4b1a225a6707df50a4d99020e7d2411ce76437d2
27b24639f265abe08b9f6ccbde1ef6f7103c7638030b70e7e3ab70de0608142fa80b3
a0df26a334762
server_mac_key: 4300a84a9ba7c4194154f7ec48167f787531750e3ee84138f6a9a
63ddaa205c5f53b01249ffaffb412e25accc0affb32455a456d2603cbdddd28d0f823
84e14d
client_mac_key: 15bef0d7c5ca229506cdc51b0325b88b6c55b0b68b6ac0664ad79
749b4e8aec608475364a3af45321db382a80136aff4c174e341ca326c8cdeec5086a2
d56a94
~~~

### Output Values

~~~
registration_request: cc1b854bfac5f36d7f09d18975d26bd031490a8810722e5
e84d13320bc6cc1ad88f2faefeeb84ac706985e2784da104dcfa376ea200241d6
registration_response: 205f343aae89c4293d296463d2c44402d6b9cfa4ef7b84
a544fb6257302b2be19fe8d08dd46cb337053d7e7df4bbce885417fc90ea08684bbcd
8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93c99e1e9dc14db5c9c26b09
e1980f7f5b45774012be6234ac5a8953ff69ef28
registration_upload: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e
5f4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948ef78035
710b08c8cb8622c9a43ad45e37825a64dfe5b59583904055fe288b43e514fdc2f4d22
af6c39a49f6f37c37cc42432ee00079a1aefb27e70e6925177cbbe025708c903f1a71
194e400e4a2fb5efcf7c1904fc51e19b95c3f9bf49d53617a583de22c4970c8bc096e
6bb1e394cff7796e8528acf8b4904a8bc654466e8b23b0edbcb63d9a32368e1ddd23f
937f03424300eae916a530b44d345b025ef3f654faa44460b74b90f7fe7389e7503e5
ed7e80e80b157f7afe569279e14f4c96641fbac7f775497e71d00ba01cf9515d32912
a6901ed33e99e61
KE1: 8447080996dd1f729709b137aa45b6a6e68651f7f5794ec80d7aabca6f171226
e8c5ac7aadfe6b9ace4bc355d7b891907d50282031c15d9fee12e24af74615d2da026
e7efd0fb1faf88c1f00298a6478c8baf4164b2074b4000968656c6c6f20626f626e09
74f24da70adf24d24b5e267c80f6335a5cba9442a5658cdb76b3a2bc569d39ec6fedc
1a162f4e6c6a460b0978684aa5f30b3304cf04c
KE2: 4aff54c1e189a30404e0f5aca07fdd5efdffab1c07b570d298d0ddb196476be7
a11889398ca66544aa6dfc43b545f1d1425e4e74d6719190bd826244268550bfa496f
01f61cf313ee795efdacecb77059f9364c5c28e14870b2e88fd81d508ef56abf8de2c
de85e81a2d9e66de38429d0a234f707521aa7a61ade05a8c3178ccb4d5c8865f0042c
dd471482c1ad229de5f85ce9e64b26e9fe9d26d2b0779752cbe5d13f705473a99b2f1
2ab441d52d00fa53b4abcd63102d39e4742c05ac60592f2a1ce47eb665a51fd70c126
50f17e17ac2b4948e30b5c20072eb6b3b403dd58dd666d06e55993881e4109b6f59a4
71c33eaee7960afc4699b62d9fdf80901550e171c4736d676132853cb7c62c9618cb0
0c3bd3d8bffaf3dc85abe6dec9f74e2e45a66e954bcda3334ce69db02c7ede3f58678
065eb53e569f239b1f79f3bf48f864e5bd26535fd63ab8469c97f3394c729de0b4f98
0ac06ea6a90dd077f924aac4210ce65521a90aa1ed82f46ad5cd948d1d96a179409a0
20f8a01cc86cb7b2000f8feaad115edd905d3e1bf1b86502aa225399289a14055045a
e6285a2ed9f50e61c894ac6696a32685660bfe5a74311bdf83b4d92ebdf75f3312618
43e18c2a4aa87639069172ee53aad4fed20ad04b
KE3: 893cdec43a639c185076d46425a833f4294ab83ae23de0a771b7589ee24f3a79
64fafbf2411ad7a136b96bc828b89e4daa0821eb754edde113347ae21809734f
export_key: 6515b9b97e22ea765ecdba21e7399379182410fe785929cd06fd8b451
2c26a0bd23971678c6b5dc6d649e550304122d4412e2144e1ec01ba994b634eb826a3
30
session_key: 483bb1ff44025f496598274fa57da37fb007fb785778b3d47e62de50
f2f6f282fd8ce35249063de320391018e88bd8fe0ba1743730b11deb0fefe4068bec3
e7a
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: a61b95c3d22acfdf255c4942232e44ba4a37ead2a49ae929f3d3274fd7
32fd253b6755242ff5be5d7d222d69e27cc55a7d390df8ddff3f49e5bcb5feaabad61
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 2bbd50838dac3bc9f03f53937c0fd376c9bbce530ea74edc02580
b0776d926b0
masking_nonce: 96f78330526e507b3ba9437d6181f0739a756a493b49a45e1c8196
7a937218a5
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
server_nonce: e64e28d265ff7a4c70104929dd7fe2f181cc7489cfbf345e91e832b
0b1a41d64
client_nonce: d5b58caf68d92a1a5eb3507b74fc9fd5e3abe2ce8fa9e48596e7b15
fada8f96f
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
oprf_key: cdd797b70cb5efa7d62a01c3e3e8631270115202b2e064be6c11d172673
5cd2ec4cd52c2f6d3c9ac933ee9d38cd7d9a766ccbd77b4a55d05
~~~

### Intermediate Values

~~~
auth_key: 6d99af9002773142c97e78546e7d850dd907b26036f7f4688c86d7192b8
83fcf434d84108450338eb0ce022ae70324f5e671e161468d19afb25e4467f19f616e
random_pwd: 6781f05105481a8154d0d32a5fbf5d8adb6e0700b1fa89ece90ab0d2a
206b95e21f7fadb93b06b4da56c517870f5228c2625c88693141e23f3cde8bc606fa4
21
envelope: 022bbd50838dac3bc9f03f53937c0fd376c9bbce530ea74edc02580b077
6d926b03cc459a374b9efe4c2a4f981a5a5250878ae54690c1902c19e2897513ac818
064d78dd8d6b570038bb381e60b106b6e04a28c8ef12290e02c183510a6aa7ac4e860
954e5732962ca2a3933674e0ba9d21b8dcbffe3a857e718f05afffe44c9febc67856b
db300d462e7c1a657568d36ef622237e938d2869
handshake_secret: 583990732f8f3a2dd5f6fce0c8ab07e99df14edaf5eceb56027
bc2b81f394143d41599067c3b7e431575859f17aa6de4fe344f89f6315e67b8612e8a
fb36bd1c
handshake_encrypt_key: 92b404e791c03d73ff4ced34bf603e72fbdcfd8b5738ed
aadcbf942e26810d2f7f08bb2223b36a277b38504de5c952a3a4a314191ce4a31d679
36a5ae44c650c
server_mac_key: 017db69b0a0e786ad26cde5374f2c9743bfacb02763f8e42b1261
27858f1c5bb9ee0686971b677f87c39fa6ce6d8e16c3109ae67c96ff0ff8a1e660e0a
e4f315
client_mac_key: 7d53024397de2792285b20b31925711124b55b4af2c1ef12e02f9
7c40c8ea1e763fa832dff7acb4cb9f47461dc6c563655f12f5c7b6eef71de9c6af1d3
936a23
~~~

### Output Values

~~~
registration_request: 88c032a418dfb1e1cd1a3324ba5992452f93c66edbec9c3
65e92c1ea793cf76c05ae910ae194ca9c51e885d3c2bcba7d76989d0d824ace6e
registration_response: c457f15562f732465280431373a4a59b9fc37de201cd5a
7d4db88aad89becba0ced9ca7208da834f6653f1dc6550a10c905c8135aaa32a0f9cc
2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8e42262e63634ec59d0431f
3878051eca9888bb45c17a68359bb55071e6f6e7
registration_upload: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0
c40dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc61844549a22e4
32fbbee8d9bc2e88a13c0f21564b77abda60d40672f00aaf8c6bc2996b58b43b29faa
668cce9affed78c01b32c74beea9eab13c9baef709e36d51468a1c022bbd50838dac3
bc9f03f53937c0fd376c9bbce530ea74edc02580b0776d926b03cc459a374b9efe4c2
a4f981a5a5250878ae54690c1902c19e2897513ac818064d78dd8d6b570038bb381e6
0b106b6e04a28c8ef12290e02c183510a6aa7ac4e860954e5732962ca2a3933674e0b
a9d21b8dcbffe3a857e718f05afffe44c9febc67856bdb300d462e7c1a657568d36ef
622237e938d2869
KE1: b4f7627e7bdcfa7d9112301dd0081a3f51cf7e8853eb48a16c9078aeb0dd99b1
6e691ec45b6dacb2dc05b62f0e09c124c94b1b5390a68abfd5b58caf68d92a1a5eb35
07b74fc9fd5e3abe2ce8fa9e48596e7b15fada8f96f000968656c6c6f20626f62b8de
36842175636d346164767aa834a4bd1a0abe805678ced43406c4a09ce40145f03cd1d
620d6b3932243017098851f7003f34a849e6c46
KE2: 2ad8c54643359f861281c4f4fe751836472cbca6191bf4b4e2ec028d5197de9a
c939ab41acb652781ed6ffff5b76d570bea1f5cd0018c0d496f78330526e507b3ba94
37d6181f0739a756a493b49a45e1c81967a937218a5792794e034c437d31f2251553a
6c73edc54395e86929eca83cbc98412ca6cf38e737f1f5389720263470f752ef17a7a
dc0daeb8539ae0ceed5f64a78b618fc575323b68e9bc966b610970cf1f474c5095077
ff958dc832638f4106b806b81fd9a0083517f3dff2490a2e6110a2b538ff3e473253c
1a017b2cc4bf2731b2f7696663a8c1af0c1cb0f963ed20f45c2bb268eddc8f5707a23
fd99f510754c825de80efa0d80fd9598a400ed734f02d1a86564ec49d26eb1e7e4e03
b900535d5ba6463e57b2df156228f5078282d3c5a510ab4e64e28d265ff7a4c701049
29dd7fe2f181cc7489cfbf345e91e832b0b1a41d64b886b2c735272aa37e700b602ed
cdfcf53f73ae463d94139dfd0e173feda40f8ec315c59dabf8b7db0a77cf9c3e5b352
8688b01849fd3523000f888cd492f8141e7eccdf9cdc0afb88e432b3bc04f07c7f282
58240661ed95b2ea0f0b81c740d45aa15c2d3efed91d6b096e4a5bf09b4a1169898bb
9faf6b2c8fb93312cf356883d990eb880a320f95
KE3: 2ace2f89b3833e39e2c01510b737af7207d05b2c80bf8b86a39cc7c535c1651c
ef9f2f6060b4f27af7cacff07b0ba1f8c7052cb64b556316374517c81df91df0
export_key: ea96ee775b3eb59584327af94a9610fbf46f7a15f3d204c5c0e156aa7
4958fc6345e9c0419abf544bec3bdd9b748caf8311999d8522153008441dbd27fca1a
e0
session_key: 20ec8637a2bbebffa283b1d909f647ce2f8264cbd805693342a05afd
699fe190eb4bd6740bdb0bb6e0f0f17d93bd26e96daa33a02ed6e78abb57829b9af6c
f48
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
~~~

### Input Values

~~~
oprf_seed: c8a1af32768aaf6cbf48de60c8120925e8b882fd6298e2b0f98a3c852b
a3114e
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 41bb9961129fea2f8fb128ebe8263d6feb068b2b6f63b62cec30a
7a2e2bda0c0
masking_nonce: d2170df2cc033a17df727a6b71a1ce1d13809858485976307e9648
3552f8ebb1
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
server_nonce: db8eb0d70a73b2b5e3f25e9db804ab088a675f894fac4c960bba0db
b16bd1cdd
client_nonce: 1ec6e66bd929624873e51ba891c59688b56d25c923caa5ab7a196e0
6aad9b7f5
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
oprf_key: fdc1674f4805d42678b280f20d69df267d209ba910e96826d403dfdd765
6807d
~~~

### Intermediate Values

~~~
auth_key: bdfdec2c979432fdff3144f6c543a540c341167d9262ce1d755aca1d689
6bad2
random_pwd: 9873023ed726366e7e28a3e52b49b51f7644ec6e4401b373327489312
1d362ca
envelope: 0241bb9961129fea2f8fb128ebe8263d6feb068b2b6f63b62cec30a7a2e
2bda0c09fda4a51500c695c536f81b707010638c994855f62b5403a87fb5f4114ce32
a62814a88f8097b938254dd75fa476d21bd7e98956a111f59d35be7def4698179f
handshake_secret: 887be744e5c8e77a76b55d50c2654cfbcbc01e6c75fb0c9b496
7f20634076bd2
handshake_encrypt_key: 01f49fb85facc38972a068627365760295012dbfb2fbae
4e12724716d4222e65
server_mac_key: 169424a9bd1cdd01563ff48c0d7a0900c8669af08b59cde7d68d5
880fc7d609d
client_mac_key: 05e669595c6ced6a622101be4298d5c9b0ab5e0a01a611ca9d0f2
94d3fa017fb
~~~

### Output Values

~~~
registration_request: 039ae9435af572249db38975b192f1beeac30ed093c4d9f
40bb5236d3521035ab9
registration_response: 0255ac79390f3b34b90d0287d54a68aadd864dd8b88f0a
dcc29689b69d8043675002c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1
bf7dafca0807eb046
registration_upload: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430
b52d36b1ccc475cc8db40b95687e425a679b67b2fa39592f98c05beb6fd7497e43f53
a141ed3b8c3c40241bb9961129fea2f8fb128ebe8263d6feb068b2b6f63b62cec30a7
a2e2bda0c09fda4a51500c695c536f81b707010638c994855f62b5403a87fb5f4114c
e32a62814a88f8097b938254dd75fa476d21bd7e98956a111f59d35be7def4698179f
KE1: 03f86d270a693da19f82b655d8ffe6a26ac2b79ef779de92012d7fad3e15a7d1
5d1ec6e66bd929624873e51ba891c59688b56d25c923caa5ab7a196e06aad9b7f5000
968656c6c6f20626f6202496d129c40fe6d255d57f6d92af5c0cf0ba277e8a0e7b67a
61df2dccd9b02c5f
KE2: 024866fc218394f1be619ce2a17c93a7a91146eb7e31bf4fc65863f2e76d5da7
32d2170df2cc033a17df727a6b71a1ce1d13809858485976307e96483552f8ebb1d3b
dcf82b353ed08b4ac4f5e4da3f96b769464ca59d2ef74b0dfdafe86bfb421047d0f7b
c87b8f2e57d1422923457e93302d1b6fa20d24e8c471fc06940a959efe6fb15840b5f
87c08a1fa761426a54eb50c794b5a0f6a978f614cfb517e70c155b896050b6ad8f2a6
f82c75dbd709ca160e92d0906ce8636d778a7a9399f209f281db8eb0d70a73b2b5e3f
25e9db804ab088a675f894fac4c960bba0dbb16bd1cdd02c5583ec9a10dfa32344fe8
000007904dacd5e6be9eef27b0f94b50605b017126000ff363e1eb71637925a091aaf
acd72ceac54604d01ac90a5911486810908ec63f8b52fa05f9dcd38599b6a3dacb2bc
8d
KE3: 0b9576a58adb06c81834b6c60e498c5de668f1b065ba8a972ce640bdd1ac8a2a
export_key: 3f4c2503814cbf4949e0a1fbeec4dd865691c8427e5823c0e1b3c5dd9
b1ae061
session_key: 065606885fb26ad76b1ef296755934b4d93264681e6bd39738d2c2dc
f6904683
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 549c2c699f83864d13da1503f0d00705be341e6e2fe9452e80125bbf25
b18b45
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 481d41948b1988afb34c90cb28fdec50da708293a56188ca63bc0
d9363c2a369
masking_nonce: bbec8ed0263496bc13c7b956aea8adad5967906ee97743f356528b
e7044b3797
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
server_nonce: 23819ebb3e43cf42a4ee6640433f77575189fd66f63a49799ca3be4
64e558780
client_nonce: 405ba7f518f3d5b6a9f9b82e43f215e11d940d42d7f163deaff7d8f
e6f6b5a09
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
oprf_key: 3f30fcc2579e9d59e18030c4162d743e7c9be303d8640eb9de24b68bc2c
0505b
~~~

### Intermediate Values

~~~
auth_key: a943c52cf218295cea8cb09f1fea7825469614ae624ec2f08d144aeeeee
ef17a
random_pwd: b71a7ccf65e0afcd6271ee818214bfcfd7242df5aa6d83cafb0633796
583f557
envelope: 02481d41948b1988afb34c90cb28fdec50da708293a56188ca63bc0d936
3c2a369757221baf704acec72ff3fa912a12a84f0686dc8494bcad9b1f2d3a6f5e075
45743457174611f37a604e67a44fde0c03880f79458c378fd3eda0ffd3e6b9edec
handshake_secret: 6664b5085f69f51cddc94dedd0f2875ada513241e51a33fca0a
83d1bb9695a8e
handshake_encrypt_key: 09042f7ea131d565d135516951c5a3bc928ea59efa1d46
9cbc5a93ee25d43546
server_mac_key: e10045690a0c0cc815760c39eaab03be8df8f24543c1d0c8639a6
dd2635746cc
client_mac_key: c6d61e86167714df9c93a75ad1b3ef0c350076a5cdee52ac0ba49
3aa2db0db85
~~~

### Output Values

~~~
registration_request: 037a055d502f2a882c021fda1ec2fe8e5d8cd0d2a913e5a
03b1e27e0fd06308275
registration_response: 02aef797b152e20cf7b3b28eea62e88d9922c9b3d24453
08423f53d01e445499e402e1249c0906886b33b0ae59c981001448f2541fb718a158c
4b4f37d391e813fed
registration_upload: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a26
4e65baa2434709f8083531aca9e99cf5df11b767a5fb5823b8d906e95c5b46195bee7
5df776d8b875e02481d41948b1988afb34c90cb28fdec50da708293a56188ca63bc0d
9363c2a369757221baf704acec72ff3fa912a12a84f0686dc8494bcad9b1f2d3a6f5e
07545743457174611f37a604e67a44fde0c03880f79458c378fd3eda0ffd3e6b9edec
KE1: 02e532d2687a979f0a75112437e1f4c6d5411c555b2330a8d6c45c7c7c657aeb
b9405ba7f518f3d5b6a9f9b82e43f215e11d940d42d7f163deaff7d8fe6f6b5a09000
968656c6c6f20626f62026ec987d3b7ea3ef8cfdca092b9d6994d134e933a5fb78929
5335d5f6956399b6
KE2: 0342d0f6c582e581277296ad73598fb54dfdf5f004fa95ff722fc1831886741a
35bbec8ed0263496bc13c7b956aea8adad5967906ee97743f356528be7044b3797f09
7d7ba874ad7f3aa4122144420b6a9f1e4c76a2984a6c9865336b33199ffedbd12df80
b8af55db475f6ed590a349422ed4719798d29ef938f0af180bcaa6bdd3ee04ea912a8
3fd351d075b191c4aee8d680e274a818eda6b504aca3417410b86cbdf82a7919b24a3
5962d257764f4dcdf48317798504e45240e5ca708d8e444e8c23819ebb3e43cf42a4e
e6640433f77575189fd66f63a49799ca3be464e55878002178e9554d669786c2e9349
f1e178eb84961a7f8073d9ecbc5cf52bc2fef7791f000f459645bca54f6635cdc30b4
42417e7e8df09ced9cffdcf01ec42510c8404f70fa476ab70d1e992bad09071bb6dd6
48
KE3: 0fc7052768eca82c7c25cdf35c711521457c8bf4ee122412c20c46f57e0c41c6
export_key: d3e5d244d88727ec5be7895c7dc73f8935f89e17639992ad70aef3a41
2680203
session_key: 8dfcc65c2fd3884307211bcdfb6849a1ab40050b40f97c9c004cf9a2
829d6a19
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 868c860300467687a218a7fd92575e70364f948967fb313f35c97b536f
71ed61
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e1a4cb9b796de480d7798158d12804e42a84dc2b5cea2c4072b86
f27d3aef994
masking_nonce: 6da1c7689d825da80295d374e41fe5a8c4b6a1b02a8f30e1448608
c06a5321f5
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
server_nonce: 67bbe504836d9f5a38799a06f75dc04a91ff6e890ce14a754c0b876
c31074d6d
client_nonce: 08d8138f8d374efdb5606d87e2e7a96a93d50393cc6ab3c1fa41e1c
e3047b9b6
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
oprf_key: 9ead554d4d8f01d4093bfcf26fea74b1ef605d8219d27d19ed18e61e9e2
910d3
~~~

### Intermediate Values

~~~
auth_key: ae39de762a07d72329d4e3276001afcc62b08f1e69d2f1b847b77023116
ce373
random_pwd: 03f998c8c4386f34dafcc1d3a4216deac4b8d5b4d07c1fea715ba52b2
0ffe4ce
envelope: 02e1a4cb9b796de480d7798158d12804e42a84dc2b5cea2c4072b86f27d
3aef9949faf82b8683f3bdc4e7cc1166359a631c866f8ab8839cf76bffcdc80d12e0b
fb91841730611e0ba4e9c28a78a1f2891fd078c90e367b3210a49d82ed179d3fb4
handshake_secret: bc9b17f2ab9277b0d50024bc4eeac65d095be027187e25d4758
9b2effe288192
handshake_encrypt_key: 7d7bc003d9502ef1b29657ed1515c704bd52bce5182ed4
649c2fc65faea504be
server_mac_key: d5cc782ab1bad150b7baeed1efdd8958d3d8e809dd6895dff1b28
07ee15f0a0e
client_mac_key: 8ca47762edd95f351116e76a58481ed81efd17a6aa5cdbbd4b4dc
b5b8f543c4d
~~~

### Output Values

~~~
registration_request: 029ead8cb71d9f802fc71737e16f75eda7843e5b961c9ef
0bdf8da0cb97a6364db
registration_response: 039f677a67e5d23efa2a3563fb71726143f75ff1a1a8b7
1f44358a73a2361efc39025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a
25b74538d149fc226
registration_upload: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b
003b652dc03e8b530402347d199129ae4a0532b2f50c00ab3c57855b59a91426847f2
8c523991f103f02e1a4cb9b796de480d7798158d12804e42a84dc2b5cea2c4072b86f
27d3aef9949faf82b8683f3bdc4e7cc1166359a631c866f8ab8839cf76bffcdc80d12
e0bfb91841730611e0ba4e9c28a78a1f2891fd078c90e367b3210a49d82ed179d3fb4
KE1: 03fbe22a5b37f7345b2370c51a5290091f5af7b21cea757ca017b2a32279b543
f608d8138f8d374efdb5606d87e2e7a96a93d50393cc6ab3c1fa41e1ce3047b9b6000
968656c6c6f20626f6202736055b3c97c36bc8e7bfe53ae65bc38c5be6b46adf3d486
81df7bcfeb96770a
KE2: 0262e6be72f9675e4af2d19ed66cc7b8a3d6178b432e4df5f907c5da7de8531a
0d6da1c7689d825da80295d374e41fe5a8c4b6a1b02a8f30e1448608c06a5321f5e32
742248dd57b0441f32a54bda2e0f901c751798c12002bf9bc12f979bca2f7657cc660
f827916ec4f4eb5b76766a545c2016074806c008fb3814c578eecd85373253765d6e6
4840c1bb360bae067ea4c4d60483e315a75a53a78a8efdc5378cd0d9bce6183b36675
664d34ac535472b93af9b9f3155e69b1008c84e2fc89b4817d67bbe504836d9f5a387
99a06f75dc04a91ff6e890ce14a754c0b876c31074d6d03981bb9a42c6f60750d2c90
98ec0e64d52dc1ef0b4d02a20b2ae9ce40b425a389000f9e944a0e7647526ba0a89db
224f4c520cd24e62e52ef3ca4b35facacba307f209a727dca6b81e48fa2de204c3098
84
KE3: cb8b2d7dcaec72c7d4c1f1efa3dd7350f331a5452e47bb4d533521e8306f72ea
export_key: d61c9aac35a9f5bc2c7e02f54f2f1685b4fb7cc2ec7df8997a766dcab
a112351
session_key: da688a17d4ffc46edabab5ad5ae25fef2e0dd606bae9563ff9a8aa88
9e68fd38
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 4a6932afd4481eddfe5529282f03fd23921a3abc136c9ef692e89ff70c
0561d0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 58b551e739cf8c93c01b37239e942de676c5309c91d82bc9be170
6fec065d403
masking_nonce: 4e0cb6a1db14484f519cd643fca5f1233813514270ef55913d9e55
2f25c2e46e
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
server_nonce: fb3163988d90fd0061ed4399e8ac8f69c885ba596eb5913adfd6e40
6967492fb
client_nonce: 6900653258ee8f8eb99c40406df8234bbf6a32b2e4d29f25f231897
9d1a603e1
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
oprf_key: 3800f493867f9d72742342b38e815a6ca866cacb2e5004d758d80238cd2
6142d
~~~

### Intermediate Values

~~~
auth_key: c1bc78dfd8bdfb4478d693d94304a6e64d8c37f0d86d8d3be80f8e9b935
cd567
random_pwd: dd13b74824cfe609bba22da66ca899765a4229b5ac3323b1d343ceca0
5c50793
envelope: 0258b551e739cf8c93c01b37239e942de676c5309c91d82bc9be1706fec
065d403785844a7c78ad5e570db3557703a0b1eed30d9505c4d2cf2558f491c074bdb
cd556d955837c877b4b0a3f1dcdc24404a2a7d74c3f655959a8bb7a1cff6197441
handshake_secret: 3a0580dc0651cb19fbfdcf1b85ecb2b4190a1c765cad0b7a3ed
679b163388f55
handshake_encrypt_key: c695f23a62a370ac5d2e230afebf9cbd519c71dd618b27
119f46dbaccc935b45
server_mac_key: a97f64b0ab668f66f76f18f3fba1fae7e38102f18a8453fe11b4d
0b9709e46b9
client_mac_key: 07e80d12722da6c966dedfd8264ead800e71fcbc9772576eb5678
17603bbdf52
~~~

### Output Values

~~~
registration_request: 024ff8b8c3636b93127c0c5350c4d2e64b47c78837d6edd
ece7dd67a260bde8085
registration_response: 037cfb799bc5892fe6673b2df41335979ffcbae6b7ee7f
b35d6385cef8f70b46570249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c
5e37937a9187772af
registration_upload: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f8
9ada3ab1d4b3f8909822acbe59774328bbd43bdad1b4a3da37c34668c74629ce4e82e
c303a7fe84ee60258b551e739cf8c93c01b37239e942de676c5309c91d82bc9be1706
fec065d403785844a7c78ad5e570db3557703a0b1eed30d9505c4d2cf2558f491c074
bdbcd556d955837c877b4b0a3f1dcdc24404a2a7d74c3f655959a8bb7a1cff6197441
KE1: 027694e256efc51327333fba8ab1927b511c4152f93ddb0771370995407b4b25
fe6900653258ee8f8eb99c40406df8234bbf6a32b2e4d29f25f2318979d1a603e1000
968656c6c6f20626f6203eeb46969c8d3c0ff2160547e2ab719958b7e8686ca4d9b12
f604883194bb90a1
KE2: 0355d6a21a784ec84539f401329c212e6e080da96b6520067f49e890079158cb
ed4e0cb6a1db14484f519cd643fca5f1233813514270ef55913d9e552f25c2e46eade
0f68afd75cbc7d590560765c743205a3fcfa8180e5c17048765b6bef08a46a58921d1
9a80e274b1bb48fca08a62778078dc0d37cc541c52b2d0e9fc1b653c499b5d5da002b
d01fcab1dac845674fb84c56d393e3811e2b4404e04183494c9e93395a88e700f436f
e24a33f3573398fc8995134b075a933740611861e4303b17aefb3163988d90fd0061e
d4399e8ac8f69c885ba596eb5913adfd6e406967492fb03a05823236f8f28bd60569e
51b83712e6371b7006059bb8542216c9b9ec73ae8a000f7dc9ffbaf9f2b2e03b2ba86
16c9b925d7f7d30c86e4716495666f390edc6c4901086014888f3c50c572da08ce281
9b
KE3: d52217b62e27ceb60d0e6660f5407a9dd1f4d21de9ad284b54af6c6b5b0a5662
export_key: 609ba7d561eac207acc4effd2260f4f80524adff8c12e1a8a9944d548
b398275
session_key: 7c19c91c6f4afdd4ee1bbade41fd0339729246ece92a3baf3b4ea9ce
8b1095e2
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
~~~

### Input Values

~~~
oprf_seed: 4e4ed71c5aade46241ccab7881d507f0179aded12a10d8c89b9f41dfe7
d6176947882ec4aac9968fd436be00298cac98ecc38415d9852d683fd60e61be218c7
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4080cded98baaf37a82d2dc918b91916ee7ab77833db530cb3e89
1797b45cc88
masking_nonce: 9da97bd3982f8420f3c98379d64ffa19433aa726e679646bf82a16
38b734e9e1
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
server_nonce: d25ee42c312fe498f5186d337213f6f62df56755f22a7673fa32349
83b80d88d
client_nonce: 76598f9d0cea3e39b6bfff6458f48781232f8d3e61d484fad0af482
a933c5835
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
oprf_key: f8b9e854d32c7a36013643c8acb47081acf9e0d471d4f8393bcb4e3a387
1599b2412577c9278e3d06f7e1b046bc1460e
~~~

### Intermediate Values

~~~
auth_key: ad896806238cefd6945108b4c0ea7272e15c3d4d2502af2dc62d1b411e2
a9bc42b62e6a0e704b6a84f823d758ff58e9fc7f093b6e9c659a041cf5d089b168bf9
random_pwd: ce9c75be7db1655ccf044af32f05d11963a355f3b76c4c2c4efecf8ce
0778739c16855ac51f35c74648351bb3714c372aa69d8de24b01e64d6dca7df0d31d6
56
envelope: 024080cded98baaf37a82d2dc918b91916ee7ab77833db530cb3e891797
b45cc8869799c3cf1c114a19c5a987691068f0f80890aaabaeb9d594c96bc952b4bf2
84b5f1934d33a39da54fe4764fb5163fa2e7bdcbd3ec7e9014ccaf49a6f7192bf1ab9
4192d6b2d2aa5210c5f0a5c19eb61341133fdcc4dd506071c8cd757f5a4409b09de4b
a1cb0392fa7fd940c0cdefc2
handshake_secret: 3d577a3ea3fd50bf4b8985f6590d5772e0c5cdab5e113a0f27f
254e9e5f382c114cddb2d98375951a62acd09b67f101a9e7e1e4fc1889f6a8dfbb9a6
d9f4b82b
handshake_encrypt_key: e4773c5d82d65fabe8956a77c56164c0e7ae30c993beeb
e8d086a1065911cd63ec5e24a9b16ccbe89c1873c9c52407dd4d82bdb386a6ad15577
e793e24008bb1
server_mac_key: 4db7dd3a3a66135e9bbe59d2993aa77f42a01a11309aa853e53a5
195281b5f8c991b316697ba3c76873026d659eb6fe22bd244e45489e67b311141b07f
b78e43
client_mac_key: fdc9b462529764074fb6dd071d7e06db3d31df0e174eb276fef80
3c9a29ae6cb4f3ecaf33839f7a35508817ef6011240b1f457cfe9929e3f4bdaeb2ad8
7df8ed
~~~

### Output Values

~~~
registration_request: 032b5a44024063a5644913f145e01c5b787a77804a5ec25
588320d5ecea9d524c1f9321b9ae76a6bc168b1f99e7305b9ec
registration_response: 0331948bc954c718c248adeedc9a2418820c0c489cfd87
844bd764804ce0a95902d435f9c9921308399839c8aea8eb6f0a02094306eaa9c62c5
a873fee4afdf81c91a91556be8286e7c8f5fadc077f810adb6bb760faf2e46f85cb0b
7649ebdfc524
registration_upload: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132
f22abd78a05172adde74d97f453b902fb2c454718c91fe403eba43d78ab9dd29ef74c
fcdf2f3246ee1554ea5cb689f2de1da9c85e43f28198fde8204ab891943d45a1fe6a8
8c1207c4953cebc372d25df35dd209483afd2e78024080cded98baaf37a82d2dc918b
91916ee7ab77833db530cb3e891797b45cc8869799c3cf1c114a19c5a987691068f0f
80890aaabaeb9d594c96bc952b4bf284b5f1934d33a39da54fe4764fb5163fa2e7bdc
bd3ec7e9014ccaf49a6f7192bf1ab94192d6b2d2aa5210c5f0a5c19eb61341133fdcc
4dd506071c8cd757f5a4409b09de4ba1cb0392fa7fd940c0cdefc2
KE1: 03cc36ccf48d3e8018af55ce86c309bf23f2789bac1bc8f6b4163fc107fbbc47
b92184dbba18bc9b984f29c7730463fba976598f9d0cea3e39b6bfff6458f48781232
f8d3e61d484fad0af482a933c5835000968656c6c6f20626f6203f58c4669321d580f
98b4b166fbccd6da300ef7c4f0fe19d5576d3debceb23e50b5405ac264c31691e4517
154d993fbe1
KE2: 0312319fe303bd9083f1578e3c8ec0d0620f38ee40cb9f387c3966115289a6b5
21d739cf3b3d7f69995dd67fb2c5715c829da97bd3982f8420f3c98379d64ffa19433
aa726e679646bf82a1638b734e9e1ac675f0f907f656adb83c0a4134c064d6d39ec65
ae6337aa8e35b8991bdcaaffcca783084c5abe819549deee28e91d5724cecd4aa4d8e
ac0e587d4dd9f8615f9aa1af0ab9bc1ad1ba102ce8c073fde0cdf76dda85456512b08
a1f9ca416c618d4604bc92d5a69dfebeb67e7b0b77d2e002ea2a4e54f15657f723db4
0f1eec15aa4fae2faf63a983cbb99acca962b3ee7062f8bb88b1f6c9a42f80fbeac91
db0c97939eb2d32eaecbf5a70234f4a604b51cfcb6b2856e23c017e4aa7eea16875b4
9c1d25ee42c312fe498f5186d337213f6f62df56755f22a7673fa3234983b80d88d02
18bb6548593c38236dd6991a1c556a5cfa81be6c235891e5a00cf4eef1bb3ab6d653e
03abcfe1634908971d19b9959f7000f1af44a204591536a5670274ef95f8301cc6b49
febc9983050242e778dadf25c7cebe0827742d0e6e41d2de7e6231b336f38c9681513
2929f9c87616b2204da4d0095fb4dd1b5748c850ddce1a0f135
KE3: 3f4a66ec3e49fc73a78df21a239429eaba5a390a1832aca9a7921b301af70357
14d82aa04bdeaa6209d27a66f123c338d60f31097cab0a356c218c188ef249d4
export_key: fdd1d72fa2b6566f8dddd88328b0ff427da5c45b457a1146f64dcad87
64acd47f6c80aca7cce513eaf96d2eaf071e9dfd574b91ed1b22404b139b2f2813265
4f
session_key: 4ffd9c8d898c7bf5f9cbeb211029d6aaa4d05b6ba1127add413bf60c
4ca25264862c41bf4ca2f0e2c1069ce49573a6ca67fd8b3c9ebc2af03f410212ffd9a
69b
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 76217385dabdcd04302b93c68f9cb08d42e39701c9f179a2bd46859a68
068b12301c090445170e726370a18986c9d77e52237706d83aad30e39419e69c208fd
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 1aa50ec6d2f3e2c7f86dba642c907ed5383f1fe8b720602be1848
c003242fa01
masking_nonce: 242e1db8cb5d10beaaeca313a5dc97b11bf56793865642f6936974
7a01dd7ca4
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
server_nonce: 8f45366acab9d8b1a73eecb7fb26af42d8a2aea2c44c784b825488b
4951852b5
client_nonce: 8f666aaa6c309b2ea27c7350baa5440848906941f51fa6820b5a14e
0f1744f27
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
oprf_key: d03739382897b8652dbfcd8371c7ee1ebb5d4358038ecc9735516bd16ab
be404f5a0e71a39dd00852548f66ef09b4763
~~~

### Intermediate Values

~~~
auth_key: a681ab6d348e92dcfa958eaa06b03354d1d9291c63edfcffe76ef377d81
5c479d69d4da7051b1e9adc910e826603ad0de578b0fcbdf585bb4bf6f96a66fe5c67
random_pwd: 71589c44896dd03dfa8bea733723b696793abc41c531187c89c22eb7c
24fd6be056f8c47044eb3c8c58f4e9b1c65f8a65df5c7d7b33fea13156f723bfb7a31
48
envelope: 021aa50ec6d2f3e2c7f86dba642c907ed5383f1fe8b720602be1848c003
242fa01403024c18168a433031b31db35356e8b6b85663f7621208fb8cfe8cb37803b
1dd4d53447393e4cd0d2f2d1a195c144856443ac2a9ebd730fccd4fe44c9a7776e209
f6b1b749b3e7f1dcd3e2ecf8eb2f0af35be1a958659f016f0a3f6606670754fd35734
9e6f68d886dfad114a0c43d9
handshake_secret: 553373ac297d26c77ca69b40ce05369ab52a75a25f2013a6b3a
f203f2656ab768624a00327ba0dc0e0b5c9cb105fcc7352b4cf53b9a549fb1b786317
5bb67acd
handshake_encrypt_key: 3488b1d0abf6f9f7308e4f04c4c5b5c05aaf7e24dcc3d1
fcdc081929483599ecf43760113da46db0f7df59326def2cdb42c966c09b7bc636ffe
61ea08c426d10
server_mac_key: ba26d6a20dee9006256df860221259c8d32b847f964f631b1b544
d708925f4b4a9928be06cae61b14c17e2ccb907234d5b1da958da106b466a6e991f0d
c86e2a
client_mac_key: d6556d987bdde82e3a80674cf40a3a59f595e69a37a7784e2b894
bcf460db7b0c959fe358de49ef48b72b92c2553ce70459c2add74a0aac742c9b3784b
68b17c
~~~

### Output Values

~~~
registration_request: 02bc8b8b2d8b96ba8f527f59dc0054349f0fbf4c7cda280
480d643909db6a8dbd4bcb455cc374050d8cce29147fab0a020
registration_response: 02f299309c5b8460bd062e697c171afad77d300b53d0f1
ac4848bd57f02f2556ca7bfd0abdb77dc56b203e6c624364a11b030278df9fe875998
9883c2ef9047b2449abcdbe9f508aad83f227836ddda86b3dfe0aea33995cd76243a4
319800bf8ff7
registration_upload: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1
b0a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff591fa5f508d1475d55624
8c316438696cc442da11bc12185719acc81efd500e099b8ecd3dfb0261b4408d5881d
555386dde23358fe1b68d372b916634c3ae3c70e021aa50ec6d2f3e2c7f86dba642c9
07ed5383f1fe8b720602be1848c003242fa01403024c18168a433031b31db35356e8b
6b85663f7621208fb8cfe8cb37803b1dd4d53447393e4cd0d2f2d1a195c144856443a
c2a9ebd730fccd4fe44c9a7776e209f6b1b749b3e7f1dcd3e2ecf8eb2f0af35be1a95
8659f016f0a3f6606670754fd357349e6f68d886dfad114a0c43d9
KE1: 0258fdc4ba750f504274ff4644f2f43a75759b77adb1817c8686340bb28059b2
af91d82801b94bbcb8326cc2e046a4df518f666aaa6c309b2ea27c7350baa54408489
06941f51fa6820b5a14e0f1744f27000968656c6c6f20626f6202313f18385e0f0c3c
88f3e60178a6727c9023e1044973eeb676b9a17a398424b1074d5e35246fc25be8302
8853dc22f1d
KE2: 02e8c87ca0b4a47aa82205d567b2e06455d8f919e04733faedb93194b5520c87
9930eee23214c396734f7359653a7ae932242e1db8cb5d10beaaeca313a5dc97b11bf
56793865642f69369747a01dd7ca4d4a8590aa148dd9a46da064496503e0a3c02e80d
2a8123eecdf37d2a1ec891b02477d2bd3c778b280445003ed544e4839dea3bd297cf5
e9cea461d5eeee387d7272586bc8e4d3779957b172d4afc6e11b56a503852d518795f
6a21b2e6748c6e30413635e784dac36438b204fdf98fdd42be698d07889f1b07aa241
061dea3f5cf85961766a88470bce9b2480c8d6bcf36d2fdc5da0f9a6ebeed3d72b61e
b7d572c659c15437124d0aa50cbcc9a7f437696c4dc438ee97a115fc163e60301561f
9508f45366acab9d8b1a73eecb7fb26af42d8a2aea2c44c784b825488b4951852b503
ba3e99f4c2f39463fe214e7607ca3e9b1f6112d565d80bbdb388f52437ec89f0da6b8
0279e10382bacc7cdab25a3a830000f995217dc5c8936b4009e41916b25120c6cc952
9861ab394192074204e13100280e21af439c9f5a7ac0b5aa379f02988519d7f1982d1
f4dd16ea04e214fc9e04a037008ac2786042f7c3cd56932b6f7
KE3: 7a4ae0456ee9d54c57e54ebd604c8a77bac67201e4cca54cf84736d0c03f35d2
0b558e9f461d947f7ff891bcd165505317cd0e9f6b75ae4dab5b0f00472f2ef9
export_key: bc34462e034ad756bc8e9bea6325f0659f11680ca1201acc358f27fe1
d447cac18a1c40ec43e15e153392e7ac51804a9daefdd309bf3e7dd4f92bb2417b4ef
ac
session_key: f4f1086042d63fc77758922012a4a7414476ecd35c15531d051886b2
2468223cdbb0ba56b3a722e8a6a548d53e7cbc503c31b61a0f4b3fae64fcdef998da6
e33
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 8230b2ab77143de2d43e13205ce50241b3ce583bbb2e1ed83deeffd177
8343cd5f8dcd049180095ec2e21095112e02de7309fb93b099ccae9d895dc09e3eab4
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: f95565bb4a9029f35b49640dfa90dd76247ea8c875ff5479395b0
c901ce676bf
masking_nonce: dc3df8fae2c016a6be2327fa6efe09dfdfe6b5219a848ee19681ee
df2de9bf16
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
server_nonce: 9bcf0f6399607a85a60b00be80a90e1c4e6e1deb4145c196bc52c29
4c13ad253
client_nonce: fd99638b511d506b5f887e014d98cdc3ea348a819650d9e4f984681
87ae45c54
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
oprf_key: e12cbc20646cb586e42ef58fde9304ef6682f96cff66078b487bce93575
5638b222854d7cdb4e1fbf1f4431f82a14ecb
~~~

### Intermediate Values

~~~
auth_key: 9e59e3154a8f5cf1c08fda366961a26be9bf734315ddc395821f2f556b1
46c9fe96dcdec363119f35b98acb897a59d7cf60b33a51d0528ad33086c4163f3311b
random_pwd: e182bda69183a9bb057ef932e71983b5add96f820db6b3b9c5b8ff907
55147d75b6218d32581458ac2e2cdf45d66591073b50df5f5473121336a8ba4b446d0
91
envelope: 02f95565bb4a9029f35b49640dfa90dd76247ea8c875ff5479395b0c901
ce676bfc45b9a9c2e8f0eed927dcdc799b45aec68e76c757af728430e17fa6d74efc4
0907084ea236533570c082a1e5f0f6f42c80375acf393437730c7d04c42eff305e7e8
408b87845894b98c460e2a5f0b46af75810bbdcc5a79cf27eb508f9b8400d70b0879d
efb90f96f768628777f8df40
handshake_secret: f6a4caf8e52a8c84fcc2c026853d87fd11ce1a8f18c90448ee9
995444c877f662ed8a9260deda87eb3a17f036d51494991debc1eeeb770de9643dc52
8a681254
handshake_encrypt_key: e87253bfbe3d9a5c78c9cad342ce0e3c6c51b68d3690a5
6c4b4b9e4c1220cc01592356af75a7326d0b26ae08d31bf21e56c6addf3cbc7f374bb
e5a8b68c5d987
server_mac_key: 33b0f9a7202b22be70d5cf40df99214e6a60a7c379b76f58d10ec
5b66dda667cc1395e5464cfb356b639898fdf95a6bbb46bd8d7983d07073562e1248c
53f9cb
client_mac_key: 76869afe87d250c514451e0cd06c56ec7fd1bb9715bed55d87c15
31d5637e6fbd530bc50c822cf223759a092d8e3cbb245be4545bdfb62d95623f74686
7b7d93
~~~

### Output Values

~~~
registration_request: 03e0ffa19f9860931638c2a6a3fbcd8e0ec673cd39615a9
d80959edda6fc8d269bfc206586f1a10b46a895f8f17e730174
registration_response: 0319ce89d3eeb4d85c49b8f6505067bb947af17707bae7
ba019cc9e725afed014f6839d91ebdca8942b38ae10115ba587003b73b7125c1d9517
a42d63bf21b0c3eeed2b4f76005f72478de3440dda2a2a580ef58077c145719505764
689842231b65
registration_upload: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab
18f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef0d1d84e6116f9afe6429
b7a6e2c610f67632aaea1304bf9bcd4b9d38d6a15fe24bf3ea41dcff9b0dc8c3f15b8
d424d9d319eda235181ed664ab7540cf0b7ef54802f95565bb4a9029f35b49640dfa9
0dd76247ea8c875ff5479395b0c901ce676bfc45b9a9c2e8f0eed927dcdc799b45aec
68e76c757af728430e17fa6d74efc40907084ea236533570c082a1e5f0f6f42c80375
acf393437730c7d04c42eff305e7e8408b87845894b98c460e2a5f0b46af75810bbdc
c5a79cf27eb508f9b8400d70b0879defb90f96f768628777f8df40
KE1: 027b40080d3b93d00403d4e7ce1944644d57cce6241c69181216ba7323afc9c6
2054300441470c06aff071717754a2fd60fd99638b511d506b5f887e014d98cdc3ea3
48a819650d9e4f98468187ae45c54000968656c6c6f20626f6203f07983f1b0b62e77
8918e7b15aa899a5c5c9fce3af75c5a424e114f3c9bc539cb3b290c4c4705829c21e2
185ab3eefcf
KE2: 02396c7d51d83c749ab5efb97e7fef46741f6c4ab95a418c57bbfa4b76074680
9e023e9b598a8ed488d52e7dc4523cece6dc3df8fae2c016a6be2327fa6efe09dfdfe
6b5219a848ee19681eedf2de9bf1614ecaf695ba34c58b7d629af07b68e0124bad649
e55638d8945d74ea73d7f926d2ebb6f310eb2e5bc4728b645b7b43460792300442e27
a46531ec01118e6f2119c9d5ae91db327a5b3379789bdbd520bcdafde21811ce40e5f
d479304d1681f156c509c279ebaa5cab7a5e80144159849e05de8f8cf4476cc4e5de6
4c544e993ef64de05bdea486ad9addf83f26cde1729c52ceaedc124ec3d689dd1bb41
416e380dced37ee34a24d635c36de0d887970946c3fa2225f7914eaed62276033ac3b
a6a9bcf0f6399607a85a60b00be80a90e1c4e6e1deb4145c196bc52c294c13ad25302
bb887f84a3158bd1a95c26114059d1064a69dd87c8813ad1ab19b0cff29b48d0e945a
f14537ac16d8f4160bb027fdeae000f242b667456d9afdc0cf13805e19afad4447cc4
b1d1d82df1a21b3e283966a77db6995b3876087d8ee8d98f419b5fd10fc2b4e39fccf
68bf2150f8f0c354e54a5639157205a9a4a1c039b17c7bcb95d
KE3: a5e7b11a94908029c8fdd271617060dc60372110dfba6481e7bc5e4ee84a0998
ae9b7d5e94fcbb7063057c357d125fe2ec5c29e98a6ae9aea037846be6c2ad0c
export_key: 5717653a60a3af9bfbcdd36cd05f0a0bca4af99641bfb89a7cb2bcd71
8b99c53cb0abc911f677d1216164e8b296d02c8b70820058db75747e7ad53aa13df3a
be
session_key: d857a747bb9f84b8b8f05e0979502a9ec922adb107a4d4072b5b4933
8a333f765bd6a8c7665ca31196463c7e2a4e22037988bb0ad5bd15d4e833fdcf2c443
1d0
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: a4bc501248a0f66326002fdbe335cce40e0c2fea048b5d9330f47c96ca
d1a4b94d3ab8be7beaa996142c0f945fc07add640d316aa1ee48def052fc15055c6ca
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: f73319cc2796af7e1a2c9b5030365782e737a8eb714a51296da6a
02faa969418
masking_nonce: 3cc75745e9974b12d3c2bae7c88ccdb2240e037fc5f3b453b01a1b
09da56e1b8
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
server_nonce: ded9e64d3443264edfd994c99a039918f8302715ac39c6300c37659
372036847
client_nonce: aa40573f61823a3351917d70e52c529224065b12bbeb68d73134905
87bdf5acb
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
oprf_key: a9b9ae2e3991054a32eb8c6e738f7faf90c0f11a78cdce308c1a841f693
6e28e449c2bd7c34c99406d86278efb86b052
~~~

### Intermediate Values

~~~
auth_key: 903b823db25fc3ecfec94b9284f004d2472fe24510feb81ac08ca84af24
366c7f6c52c7ce44509c6ad9aef4568b8d4fb257cc8a928a809e9cb1805a23a7d4aab
random_pwd: f0e15ed3483b17428f29bee00c5648d43dbf8fab8c74c824d1a21eea2
734e8983fb314e56e7e4fac25e4ac246e582b8182139bbd759413bafab0ac2e79ad4f
6e
envelope: 02f73319cc2796af7e1a2c9b5030365782e737a8eb714a51296da6a02fa
a969418fb6f65ca52073c18c6c88956294a3479ae78ad4965a9223eeeaa1eb7e0fb35
54d1a19503b6399c200cfbcf5c3f5f0ff63869389ca7fb5a1bc8ed8ec80881f945538
e4b4b71efd6d24e23384097b50594b8ef37ea2e96ef268367144864eabac501afe273
f3aa457f2015ddf7eceb2af7
handshake_secret: f4a4032b31950ed4e030561a9e36f88b04f98f198794c6ef1bf
291711ccafcfba4cd2e3d0236bd5eca5764205e32823fb926249c70169fa6b49442b2
68e4dca1
handshake_encrypt_key: ae4cbed16854b2e4433f7cf4a1fdacf9224ea592fe911f
e88fd6d3410546121e2fa8be70ad610690ff1d3b15f65fda476992340836d60ed530f
3907cd1b31e38
server_mac_key: 64b33edd7c0edc5061bc3f15e2cfab3a65f20b5f2dc0d957f6f4a
8087f0c4cc80a76f5b3b7018603a32f3c3127085d907e8f929cfef74e5e9aeea8f11d
836d0a
client_mac_key: b89a111adadad9dd308731bdbd2c17252735326f880160441a7f2
af81afa080e6b72230104a74d8ae529d49c9f374213c94e4355017efe6a89a4aed704
a7f54b
~~~

### Output Values

~~~
registration_request: 03a2e55f8d839d6b162d179f9b4f886337188f731db9ffe
0ac206b54096e6a9a8f30785c33d207ece91c4fb97530fd491d
registration_response: 033fa31d7fd2357e5da582af49fb2baa3ba2189c9e1368
0618ac7585316b60d701bc3640c74cc6a96e51da6256b9fa2b98028beb3ce19f449de
b6aa31eb19c661d4c4ba0fd08b4cc1e91416b0c5b5ae74de003a76d68ac4f59b64b95
4717c4d843ba
registration_upload: 024954440156358f8db7a32b042020404c7918cfd0003699
aa1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce9060405a8c3611270d9ab89fa
ef4fa2f5a1ad8c65672ab3513c6d3ce024dd4e528658c07ff70d6cb3afc8f6e877ce9
5d9f4de28e2777ab25505614c4da7d0d1d82ddcd02f73319cc2796af7e1a2c9b50303
65782e737a8eb714a51296da6a02faa969418fb6f65ca52073c18c6c88956294a3479
ae78ad4965a9223eeeaa1eb7e0fb3554d1a19503b6399c200cfbcf5c3f5f0ff638693
89ca7fb5a1bc8ed8ec80881f945538e4b4b71efd6d24e23384097b50594b8ef37ea2e
96ef268367144864eabac501afe273f3aa457f2015ddf7eceb2af7
KE1: 031b4f459c984d8a56589785181e03b93108602ccb92ef3e247651d9a9e72d36
0a93afc86dd79490fa621685779408ba32aa40573f61823a3351917d70e52c5292240
65b12bbeb68d7313490587bdf5acb000968656c6c6f20626f6202a39a8a45c68e977d
b2ff70778f0d34c28f7cf430ca1045d4c48e6e749429f0f10b226c26cb0ab71bf2445
f6b9ccb81cb
KE2: 020d07246851aef77b4825e2698f5fe28b435fcf66ddf7f508a05bf490d4e05a
5aeedf8c50adb3cb073eb96a72f3bd16b53cc75745e9974b12d3c2bae7c88ccdb2240
e037fc5f3b453b01a1b09da56e1b8c76801c91201240b0caaae2d17518f18f6082c57
62dedf28a404ad62425cb6e79d2d9d3f31421be297f2957bf9c763da4a48fcdc94f45
6f10867697ca6b47964f0aa03c7a3e3a4de5e6c4807c5213dd5dcbac719a902e929b8
5bc9adda8c72a03fb43684bdc2740a0c30f11dfe03303ff493e654bfb867189fb2933
e39a3ebbf41c90981cc4234776ca61f4e86930720cb567b1d53684cc858283360b394
4771f4adf2da8d9ae7bb20aeeed78a3c1155ce54641571e901b71bf5dc66ecdf0d70e
760ded9e64d3443264edfd994c99a039918f8302715ac39c6300c3765937203684703
6357745dab9026251b2bfb2ccd847536219da8e475cd1f2dc4842206a8452c720e3ee
24c0abe77452903c64985b76a27000fdded328b70d1e62d4d84eb7bd47dbe32fa55d2
2e53cf8d65b8fb722dff14d43d06711fcaa5987a5325da793197a40fc207190956f5b
98429576b8348a0ad1308945a9d8d2c803129b55b426ca2f98f
KE3: cfe91065798b09f11d582b83b2f90cc62a93e20eeaa5a3bd9fe75217faed64cb
7c34870059db61593aefef3feeeb6dfad04e3816788cb70ec68282c19102cefb
export_key: 4ab9fcfd3ba2a247e03756b70e9a1906e27dae98e5b72368594dba986
c71d382b7f932046f0348aef78d7a0b8dfc3f856cd780dbe7477954a3acfced5bd643
b2
session_key: 0e2d9de8d9ccc05aba446f9a246e77ee0540f8038f1a7e42292c1230
bee29d51d9e0cd878c19490daebddcbf4de1db3d874e3a3e75c97fe0b7c1652b4f279
c92
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
~~~

### Input Values

~~~
oprf_seed: ce25a59d5e6459880dfdefedd978c4d9f92c24e27ed8f3db7dae43d9e5
25ef97cecb4a502e11a36f76076642785881ffa941e5010f71a7e728779920904b592
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: bba0f239205a51b7dd934497189d78712cbe4ab5a6c0d62d7bd95
8328dfc7862
masking_nonce: e080f09e41a69a0c3320a282694d07f0d7401bb47eba53399cc31a
52551a90f1
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
server_nonce: f38eb1790625490e49640edda6cbe8eb9e02ffff68367d5443ed48f
bb880c3d1
client_nonce: 411b299dd3344d826005fdd55bf7e955f6b53fee6eae3ea67d4fb3a
4063a702d
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
oprf_key: 00e0d3d5c253b78901dd1134d1518a6eb93309828654f3e4ea35b69cae4
a20454ce69ae2fcd36bfd968554763b8660eec9517a0c5f38cfdafccb428bff124a37
46ba
~~~

### Intermediate Values

~~~
auth_key: 67176cb689f85d94096fedd968b381aa923686330790226b61d765e141e
3e532f0e70d1f2b455c2908c8e09229d519e7833b96f65064fd259512fb55ea3c8a35
random_pwd: 73f800d81408acfb7a4ff1dcd7bbc06f1c51aad1d35994304cf33cfa1
a475afe5deb3f6213b05edd069c4938b6511edd50f80e67f4ffd0da1a9855d21b858b
a0
envelope: 02bba0f239205a51b7dd934497189d78712cbe4ab5a6c0d62d7bd958328
dfc7862e9769da4d85a9c1b429ef45839cf67aeb78dd9fca6f54338d131c401db573f
4bc05c263618b12026e96a505b6ecde850eb343fcab2effedbdf8018bbe45eb59ea0a
b763ce15d9a8385e76f9d4b5177d0193b52b666f4caef4a1db012667616d145a802c8
12359d2fb6e5029180fc21d582fb3357897cfdba82c0c81a3039fcf80e5f
handshake_secret: 16d87e5f4f2e0bbe60ef510c0df3c4392778ec502a5d8c6a8b6
c179584646cb656daab959f01ea8df9cf38598c38654830b4e4ae59bba6956ae30f3b
346a2b12
handshake_encrypt_key: 37cedc634184c6483fc923537e08627f58a471bb542be8
7a98d969bf589f9d52c95ce89b20c7b08f7f0702a8ae3e29498019fc8c84471d3cefd
176ae14aa2bc9
server_mac_key: 412cc2aa1dea1175dada413faee4dbecdc6b35ddeb2ae7e622a85
d14e975eb8d9175a8ce28acef50366fe5b2b622005120fc57b8cc5e3151c1ef1fa498
79bd59
client_mac_key: f4607763257119ecabcc4962c4797515fa9f6fa3345916e6e123f
9b98df6441b0fb3ee6732613edbcbd6e889b1cc2f89bfc72e4574f4eca725e72b64f5
6b1fc4
~~~

### Output Values

~~~
registration_request: 02015d0cf2aa22e0448949416bb4b3c246429439d4cee47
a52b3b9874aaf727dbde7f34b5112e91e97e1d98c9cb0fb58e015721456160aadd16a
d4f9a9ef2fa3d0ad8e
registration_response: 03002e712deb228d5cadea98013dfbbdd5209ab64f8716
e3a55f2cdcec2b8093ae9d5a26240ad231ad00402d5870c4174010c9a556d271b5b54
3e443f7f4f8a318341703018fc6a77bc4127886d67871c03462740fc4d6fe66dc2226
365e994f8392a0b4c43cd6e67ce90ad594cb63c146011dc56b213bd42ef677cb6a5f0
1d0bd9944a9161a
registration_upload: 0201d6bd681715e3d330475e72471c1218aa718d96be7353
251c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf183
1f811d49d120a8d45012a8d60bbb640bd736c2b75f1363f5d356ccdcd1097f2789cf2
ad03159e93e873df63c80871257691b7c0cd266ae6c39adf1c68b66268f63ecd52e78
b105fe302bba0f239205a51b7dd934497189d78712cbe4ab5a6c0d62d7bd958328dfc
7862e9769da4d85a9c1b429ef45839cf67aeb78dd9fca6f54338d131c401db573f4bc
05c263618b12026e96a505b6ecde850eb343fcab2effedbdf8018bbe45eb59ea0ab76
3ce15d9a8385e76f9d4b5177d0193b52b666f4caef4a1db012667616d145a802c8123
59d2fb6e5029180fc21d582fb3357897cfdba82c0c81a3039fcf80e5f
KE1: 0200c3bce8c2c7da1856b486576082a136f031304eeba82c3e582d920469621b
9657d018aabad67dd15d32492f0155ec944d11593c079c64c5d19088a72cddb12baaa
4411b299dd3344d826005fdd55bf7e955f6b53fee6eae3ea67d4fb3a4063a702d0009
68656c6c6f20626f62030080bf524d28ba64b134c0bd0c860c8b1f976e55d94eb35d4
2aa0cae1935a185c9f7c517875877aac4aa4e909dd5f25cc6ccfe125d031dcfe02459
7af1f7bfb5ed89
KE2: 030159b8d7cd8d21d0bcb95889d0c617b6e54a25279e74c833c5778cf1d01e58
d80ebed7665ec9f6dd30a5abf57b001c29d68a307b638d8cffacd50c1b60481bce6ba
2e080f09e41a69a0c3320a282694d07f0d7401bb47eba53399cc31a52551a90f198e5
345d706b8d0d4930eb5d2c5fa0c6e738163ce6d8ba0ef323b751a097a16f27a8da514
6bcee34a91852afa7287fcdba7ad1cfc9d09e60d0f38577c896f347a78b33df3dabcb
b5b07851965373e4fead990291fb1ef00608ffa0cfe798576b72f03c774f00138cacc
7699856f5d1ba38c4fcf29760052add3b426ba57ccf1b15768737084d84ec5d76d98a
5c515dc2f91412c1be3224dbf8146417ce7e26ec9744b800773eb9a1ad856ed2fd170
f7d66bdc3fdaca9e8a5a6f543291553631dbbf5e6f92779fa44c37af9ec7aeb1911c9
275e087951cd50f4367cd67d5a6efac786f07acb64f38eb1790625490e49640edda6c
be8eb9e02ffff68367d5443ed48fbb880c3d10301ff9a97a3a4733b144d38330209bc
ea5a6401eb4e08e0697ac4dcb8369e20d76d32c34b619c424d643dc47bd680c0ef665
404643d2961ad051a7920c318ecd948f0000f29eeed194406d2fb066d1b5c733975f7
04e897c6128c1a177c7c88d2588d8a3003e2550443b7c069744ea496cd7e10f668931
c31a5d6f789170678f7606a8f6f64637a4348cc09f0555df20f22debd
KE3: 9c56096ecc14243e2582e50d8f99e231a11000250fe601ba8a1a2a3b3b1fedf7
bffa256b84f4f52318c85a28dc69defdce457ca917db0df1e5fa9ac437594b7c
export_key: 1d438b9cef15d180d77596d1e2f40aef13783441d1d4454e69e026515
e188b836bad66439352403ec76b4aa73b68a2b78400d06724dce1cb7c94cc4d127c36
eb
session_key: 4355344ee218e43531874fd72b82815fb7e07ac7e03c852469054670
83f243ba31c699b850b41cd24ad1865eb35bef0df82b9d69bdada7178591acbcd2d96
cca
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
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 7eaa644bbb9bd10d3f71215b70c1d025d036cb2c0e8e9ba08a83b2698d
5284e1a09306ed5baf2fb5bc2009a4899c02879dd6bc82bb993bbc3b26b9e90d835f8
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cd668af2f9ad40edbe0a05b71bd1fbb8d1b34386b2b1b96334b98
528f4d9913f
masking_nonce: 9281a361381712effea01cb3fcd96d9268193c95252d0c88c7d8e7
d76bb93463
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
server_nonce: 62c080cf739e37b57900790ea18732ff2cd83879ed9d810a2196f82
abb4198d7
client_nonce: 1f5125ce982e21d922921099c337a667ba65d8675126c32dc1c2901
80c2e6ea2
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
oprf_key: 01e9c84b18f2548968a7ab4abfc785f520af6f683fdf38ddded22c97817
e57cdaad5cdc7e0dfb357a38ad512e24df703d027efde9620a6abe95957769f9c03c3
755d
~~~

### Intermediate Values

~~~
auth_key: 0afcc7743dc20eec1b8c2c7e7e8900d1905136abab303f2567f59888783
6e95ed63109e139717f4e8a7675133a15de2ede17ce0197edffdff29a69e392da98c4
random_pwd: b388499f2ce3a6dadc31e8d214f49a386ffea00126decf46ece51f44d
0c3d614626d82f02069628706befca9fd3797d896b06dda1b1d9346d69553f33d7d23
7f
envelope: 02cd668af2f9ad40edbe0a05b71bd1fbb8d1b34386b2b1b96334b98528f
4d9913f0cc8c4087693668038f2049bacef1c4556c4bb265ba337c6739f91cfd79243
342998900bd6430d35e91f3ebf777a0e446e1a2a2808a7dcd10c8fbcd6aa4699b4489
36f9520464d0774ec10f2be2f89273558b75577985b6e27f9e11b94be15a682390d3d
ad869ab9bd7256a3a884252c4cb589b8781c465e41d13edf6e148ea8614b
handshake_secret: 263fd026af8e757c80cd0166850ac91bee9bed7905ee4fbf167
c75bc769fc61c2315d5d95cd8ac49694797d1cf4498212f7b7550b2f2c0bde64b5fc1
1aff3e54
handshake_encrypt_key: e97bb43b54749b0db9600d9f1533eec54c6f22fde1d890
ef59bd9edf33d15b270580633a178eae3b6d38776c2a08b13539681e36acbc1016f58
4763a0200fceb
server_mac_key: 9268b5409fb41693f682039b20e1e9952822e640e8ae5fc018bab
91bf1aa309becf3d81948df8126a7f4867f6c7a461f4c79d7459f409a40d2642e78fe
21d6e8
client_mac_key: 2ada07091134a1e3fadbfaa575bd985d7482481adb70aea19dd7f
6fea41b55af06731fef8e3a49a0b205ccea62e9bc2cf2f38252dec1745d1208426940
9632e2
~~~

### Output Values

~~~
registration_request: 0200572541736c54fb88d0f50d1080d98cc390cec131e56
c5e3d038122c6655d23defe37f0946f3d3b5dcf73545a6df6277e20f9b377591bd443
034fdf53d008028969
registration_response: 0301aafef2da1a5b1900e63afac4597b577a819bf59c13
f2d9d96ad0eb6075f2c641b20520824d3c20761018e18b28724301bcc7378c98ef98d
e7b4f4666bd89a685380200e85b446310593c25258991eeb8da130df718df2efeee93
29b6d6c7a3906749464ffb90f8e43122192f8e77b9f04f708aa5f9ecca9cbeab701f4
9929d82395d9928
registration_upload: 0301347c5fb96ce61b57ab45d42005522f77483664bd260e
c7f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a82
90cee86e55fe234623d4ee2fa80b266235ba507fcc83d2ca1d5e12c55865806882317
55973725bd587ec4f078b1040332efbad6757fc6e2154dde2fc4ca363e3dbd52eea56
b29a17202cd668af2f9ad40edbe0a05b71bd1fbb8d1b34386b2b1b96334b98528f4d9
913f0cc8c4087693668038f2049bacef1c4556c4bb265ba337c6739f91cfd79243342
998900bd6430d35e91f3ebf777a0e446e1a2a2808a7dcd10c8fbcd6aa4699b448936f
9520464d0774ec10f2be2f89273558b75577985b6e27f9e11b94be15a682390d3dad8
69ab9bd7256a3a884252c4cb589b8781c465e41d13edf6e148ea8614b
KE1: 0201147f07392ddb5ab846130ce65a4c16d1eb26735fec1de7716b2c8bc935ad
1c65ebc30a6449adb8504b41fe61b9634a1ac3e429e03db700e6e6f852469e8e83bec
41f5125ce982e21d922921099c337a667ba65d8675126c32dc1c290180c2e6ea20009
68656c6c6f20626f6203001f619d901664fc0a4916b616bf340eafded4dec3c9af08a
7d89f9442bf41048a8824f22d5ce906558f99250ba96a112c5ccf2ff02e062cf9158d
fbd1abc4a48e92
KE2: 0301a54bb7ca29b76759cb9b513f4039856d79be8df0bc9dd3fa781600fcaa49
6c0efa71edaa7fff1884b80805d88a7e0a0de3388e9393e79f017ce7f6c6782cefd03
e9281a361381712effea01cb3fcd96d9268193c95252d0c88c7d8e7d76bb934639cc1
584daa49d1478de7d3f6d78c071f08a3de34a9b251588958a604f9d58752fa0f24b7d
a2d7bdb525a34eec79b7aee313a585e607163384e046023b4207c36cf172f56199da3
f5f9bbe7aa37e42c8ac69595866603e80387b5f4dcefef05e716826e8f77a2957b236
e4f94107d360756d872cb446bd4694f57c5b5db12b4aab4219a1953153adbdcd29a17
853b10033a76044276a07eb2aefe0281a7261b91f3a7e5acf851718ba052c3a276e44
fe0367db526926d36702b98059fef3ec07c3387c9cc9c607d5635d327779822821400
1999dce6c5c7ca38805d678f5cc987372657709f2e62c080cf739e37b57900790ea18
732ff2cd83879ed9d810a2196f82abb4198d70300ffcefd89e8ee736b4e6149934a10
40b8691ba4bc58b160d8c526e73cb99d7c45ce09264ae268a5afd07c1a3db59c5feb9
203ecffc694a41b1138deb9a11d6fecbd000f8fb6a1c5fb9dc73e092055c795f7d7a1
e99c1d6a6fa7cfb191847f666c663b361c20adb6e1aad4523b1b2c1915e2380b7776a
7ec2916ff24836172a3dbdc4de6ebb00d938d0c267ea918c36ae61a3f
KE3: 0eefcaa6e5d6414735560472a56b422ad2972b3c5b4c5e31a17a3820473420ed
ed29a72efbdb634ff5eb0fe45317238ae3ef9642118cb5b09ef83f088523866d
export_key: c1b87d0f72cb0ffab863749eddf40c5f15dcf06ac800ffc7a11c875ce
df029b06fcf3eb19d9729801fa0b6fa4b50bc5943eabdbb544cd85f5b7de0285e23cf
4b
session_key: 0b04056ec74160d1bd9e31e90004de71272ecfd585b54185f316df28
257e61e9f213c3a6a97f23412d7408e1bbad735a0749a916b99f6054cf29ed7418573
044
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
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 40101270c0751f65d549de2320b00f07b2f2ff659ab72c725e2b20085e
d2aaaa8688a5da46c1e3c1843fddf925fc9c5b812ca66f9d9aa6d021f0adeb7b79414
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 44c277924e8ffc798449f08a3215c907bd2e441b8e10a1393b2ba
0ad62435fd5
masking_nonce: 903e5cb7d5250f67825541ccc2e6518f3f9f0ee793a0d39a890bb3
e0ff5e7021
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
server_nonce: aa7d5a649a8e9155c2ba9d4f1fdc04b3486122f580afe9a85ac10d7
d0554bdd8
client_nonce: 2da5fef44990387c3e6e24ed9f49ae148fead9eef38e41645841513
1d12da39a
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
oprf_key: 012188a77c3daf387fd3995800337d45684c944a5afe3fd2254cd8837f4
9f74f519bfadd5ade5c2f26ec336f48f458df65fe50a41eb7b423734e5e3271b95e3e
e06d
~~~

### Intermediate Values

~~~
auth_key: 1606876740ad42ae4c53fcc0412734e9560178a3a56e62d155f22716116
40f018370ba2183ace67a5ec1e7bbb3ce61ecc5ac54f0c0b3702f25bbf93f1ccee8e1
random_pwd: ba3ff2fa2386f2eace0cbe1b7848930cfa7d0bda5b360c2b3e844e517
3143d780a078496c30548b1dd7d4b81535bd5f485502087b1ad1252f3ecd5696d655b
cd
envelope: 0244c277924e8ffc798449f08a3215c907bd2e441b8e10a1393b2ba0ad6
2435fd5f06691a993e4db82206479625f996ceb6ad3cd49eb925620a1e5caeae6ffdb
eb8408108b04efab320702dc82c39a698bdfe7cfd7fa65f2912165074adb5f3900ba6
6e930aa5d5f76b54efc089ad627a15d455466e147d9bfada5583d1e16e5ffe44354b2
cc2ff505f26bb6db1c26e962ba7d4c4c82d3b882714c094a7ad536774eac
handshake_secret: f92afd70388369966d1d2124b7c8e721ae8bc824b3ecdeef876
b476db170dcc0395bb420eb863a2294a9fa8895b8871a9b8a3a9ab17cd293fd71cc7c
63c79cd4
handshake_encrypt_key: 920ee05225ed8297d33896479376ed99210b70f21d5daf
6eab937c4d0bcdf7484cfa1a0d80298cf90b6528706a1331868207ef8bec9524fe9ee
a33ce80de23be
server_mac_key: fb03b6e96b37270fbbd4d4b118e8385866a7394892406c874d952
3d6fabb32cef0711d819a39c8c0785da0a2077bb04724e8bd779bad97526fefafe1d1
94b3f0
client_mac_key: 91772e48ce22264e65eeb1ab992d29bab01f4309ec3670db55ce2
334c8a23a8832fa3a27f27d96e0a5d6e3996fba92ba86a9eaca75a190ba9b57450e76
64d350
~~~

### Output Values

~~~
registration_request: 02000c53a2fa3c1dd1ed747b297b82020f316ee5b38d5ad
d8bfa68d9c6eb9b22ac651badd5d5751e7371cae832503f66442cdc156414f4a5ba0c
2db08b33530cde8dec
registration_response: 0201195b296c9357cb88a4099ee0b814a55c4e10f47afd
b6bde94fcd4a833aa551aa54db7986097aa1b2c7d31a726b3714f3493653b0a34f93c
a48e6747716ee35e8710201a6573b69f46bf93cb3f18e2510c753f689097b7b96059c
3ca8f8e45c66a03b694fd8618c9a52c4104ca42186438849e73613cb25fbd4ecc16c5
a65f95345686984
registration_upload: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4
ca15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1
e7ee4c024556f0808a6608e396f2a6cf42ece6992e3ac7fcab74e8c37b0bde7cb134f
9357515fe786f0112f5894cf8d7320c57cc2607436f2667ccdd570172dafda0bfbb73
ca641370244c277924e8ffc798449f08a3215c907bd2e441b8e10a1393b2ba0ad6243
5fd5f06691a993e4db82206479625f996ceb6ad3cd49eb925620a1e5caeae6ffdbeb8
408108b04efab320702dc82c39a698bdfe7cfd7fa65f2912165074adb5f3900ba66e9
30aa5d5f76b54efc089ad627a15d455466e147d9bfada5583d1e16e5ffe44354b2cc2
ff505f26bb6db1c26e962ba7d4c4c82d3b882714c094a7ad536774eac
KE1: 03014f2799259882d01af61644db264602a3486a32f6b510aecb336456ce58af
6cdf6f5630ab4e3e7081f1e99b1688558f0a1bf15da34b7c0252f1036d916928a0f33
22da5fef44990387c3e6e24ed9f49ae148fead9eef38e416458415131d12da39a0009
68656c6c6f20626f620201e2f40c1d877219e9512862469e31da268ab014fdce9cb3f
9ed6b27fc01fe6d9b1ec37c6cee76131139ccc3eee0a35438250e9ecaff6cf223ad9f
a469dfaaa0f0a5
KE2: 0301492e509e16fdfbbcce3dae523a8dcecdddec601c469acf26a84d0c944edb
1d654e970563a6443efc88ff57215f8644a0db3af939db02c3d3eff8d085fd41fded6
7903e5cb7d5250f67825541ccc2e6518f3f9f0ee793a0d39a890bb3e0ff5e7021426e
f0eacf20fc17dbf71397ae2bac7944b289a5a8565981aba83c69aa4251390cc1e1508
dbb8a6d88e3681abfc29424225931436aa47a44c104381f7e910e13826d7c6d3c2873
082006433b6c4a8b03270fa5527c2b1072ffb5b10265980bcf3b541badd57fd5499d5
41ec6721f3e5007bc93e4e072a471c4334d1f179136ec467a0dd0ae4c6eadfca6f251
4734432bd885f040e8f53bfa517ccb042d05e76e76f45d2f0f07a17ba319d8a80cb9d
2637e1978bef5fd3ac111e2b1090a02f6269e964e8594f923626f791dc5ecc8af8856
6dca71c32bb63d521ea87a76b9cb07ab85c6816d7faa7d5a649a8e9155c2ba9d4f1fd
c04b3486122f580afe9a85ac10d7d0554bdd8030029562d54d53c7c51651334989bcc
95b45a1a07484448ef72bab708b55322b49a43736afc60bf85fc05d3c1d8b60a0b55a
83e37befa115e9625e00f35c1eeae27ba000fe53b77b0fd661c778cd8a0fd1061b52c
7b077e73335dc55b060571bfeb6b15b730ff3ad0ba63c556699a46e07536e934de06e
ec1bb9458e63716f8ff84c9141a632140a06353415bcd595b8dbe15b1
KE3: 6d34e72abc4e07b281a2ed9b951275f67b54f21cdd77cab64c3fa13d0539ea1f
820e32026953c751953d543fc6e9b90dd766fdf2d00ddb20cfd68ce299edb80c
export_key: ed56efddc2d4eb6bd26ff00e723a8488f66684f04a40e173510e7a6e5
02c899ae829ad8753fbddc63caf79e7abecf3631b9941971c0f951573e3c37b5a157c
1d
session_key: d1675cdc564c5ff679acc1f519437a960f41850289e879bb7af0eb79
a5bfd4032598d9a94d47b35414d9d764e74c4a00123035b714698ad0e6cde62456f0e
638
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
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: f85a85a6f8b0685d9787cb655a431c6054cbacdd95d18ef584fc2b69d6
8106ed7012a7990055833f8d71e65ccaf5bb2d1fd9a457fe91369fc072a48b356c73a
9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 16de6b986bce6b4773e614b0abe8a6660a4b9122c589b8b38a0ea
0478b601bc3
masking_nonce: 0a2cb32e7978447129b8a18001b10d4358fe68dab1ca8776583404
3d21f3f18d
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
server_nonce: 250c8912c56574943f2a6e586dab49e7fc25c702e396de5ca9aed25
dc90f4ac3
client_nonce: 2291f5ffad6b93db7f119436e95613e6f45e72bc6b7706afc874e02
b3bd7b1d6
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
oprf_key: 0029b5b992f141cad45c7fc65ecaf3c17120e907f49f0825d7e18a528b8
baffc154f51938aa74c1a17f0e313d4fd65fca0451c2a94418f80fcc731787001a8e7
b696
~~~

### Intermediate Values

~~~
auth_key: 9570808e505dd54dacde60b0298f674d8afe5e1791b62206f412f90430a
637c183f85c669aa0ced0b7805001010b1c745c3ffdd887fd2339fa7c25452f8e595d
random_pwd: 17ffe9e544c20e376846d105fa2cfef774419644735a12d62e5dcd77a
677b13cbc339d318e789c8fc75e6230a35edf6b4dd09b11a09ca9b219a972fb06f539
4f
envelope: 0216de6b986bce6b4773e614b0abe8a6660a4b9122c589b8b38a0ea0478
b601bc30ddc67241845dd50753b4a27c3b1aaadd94ec01c5a5af97cc72760c6a5365d
0f783ef99b86005273f70dfd7f24ac7671109c455822191bd9c61f4f7e5367414cff7
8adb639e93c3a758b12e717be9f0d623f9db574e33b97b2933461a6f03d0aac8048d5
9e74abf51b52c8e95a9614ba669cd5a4544ad0d93babd1f3221669fc1620
handshake_secret: 2230835759b1a1080229430b70dc59ee2f87b086997956c35c5
e75d762ef058e3ebf7aba9c394ea97584d7ec0fa29beb3a3440b2a76960e82fb2e5f1
278ee823
handshake_encrypt_key: 343244b9079d360eb78548b1b6ae39e0ab1b7f5494e760
eddd3094c894ff44df87ae754c38d68ae1f31c98aa7c0e0edba6d8991885635c74ca5
087e4d16ba2a2
server_mac_key: baa8140f03f886540a74306b9c72301898feb8d25fdc73b5d6211
3636b9e92624ca7c279f1955643976edfdd62a12a1726329f05d955c3e41fbc4e063b
9bb1c4
client_mac_key: 5ac660a29e0aca1d0b86cdb491a0f187baa1ef769271f82fb933b
d71d5bd0a54f155a0497042103083761e7e48a1dad9c7152fbae6d7b087ceeb25f7cf
876049
~~~

### Output Values

~~~
registration_request: 0201d22759697d1d91f6b1812d14acfee093886e889d913
cdffc78de009924d3d80a7aa9384149f163fd706498375c34402df2ccd8c1283cd250
477ce032c9e7c78ef8
registration_response: 0200bbc00304a88f263dd1d5f9464aed95de9573729cf9
35348b45af27ca60b81239c4afe8a0b0da9b225a1405333feda90bc69588cf8224b52
114ef131d03dd5df4bc0200f944f464cfcbdfe94b720c0a59487456cca17580dd1982
4532d540642aa4017edec0b9308bf4f4fc00611115a145c1374680847e4815f6c8dd7
febdecef64998dc
registration_upload: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fe
f6f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea
03e0379fb9127abe52c36bd52a80a3970c96ace9bd4aa8ef8088601fa256896f4793f
8e62767d0142fcd4357116679cc44eddf837a9880fb6b507f2be031b8accc6794d6d4
dd091680216de6b986bce6b4773e614b0abe8a6660a4b9122c589b8b38a0ea0478b60
1bc30ddc67241845dd50753b4a27c3b1aaadd94ec01c5a5af97cc72760c6a5365d0f7
83ef99b86005273f70dfd7f24ac7671109c455822191bd9c61f4f7e5367414cff78ad
b639e93c3a758b12e717be9f0d623f9db574e33b97b2933461a6f03d0aac8048d59e7
4abf51b52c8e95a9614ba669cd5a4544ad0d93babd1f3221669fc1620
KE1: 02002c6e65b998d160fbbde62484f39c2678bda170db547005889379b570e83e
4f6aa45200a183dc5cbf014bc7f94f28064bae53132dfb3a0736bf7b806b1091ce541
82291f5ffad6b93db7f119436e95613e6f45e72bc6b7706afc874e02b3bd7b1d60009
68656c6c6f20626f620300c566f59e65c950d86356e925ce1f87b3d4a7a9b2e556ece
f17041679c76f8afd8f7b1e9fb82549886fdedf29e4e86564475b0c2c200a9c7a4e08
9e846932e07d36
KE2: 03016c6be2e2833a5ee7d8984d3d969a4a09dade044913bbd6e6ca063158ee18
808b6ce91857426c9d320c8d7c82571c95202605bdd4eeca49abaf8acbdeeb18a207e
40a2cb32e7978447129b8a18001b10d4358fe68dab1ca87765834043d21f3f18dda8e
df86b91ed3d97fc433dc2e2e0e8679aa97487933e3a15312c07a9b95d88b0aef40784
bb87c7ad41940a3322e1561f7de67d3228c9255cb8000c7dcb524b61d7b11d0dfb537
6e98d11870adc5ad0ccd4e3827c10376e7ea87cf75d4625247209e371fb1548aee848
24d722a94bbf13c29b395a422a681a8f1c9738f544be7627ff183144a3ec5e9b23602
9e50575a697c907635cb125b199507cd1acaff1755ba0fdf8e8623253f6b61090b422
919bd7961aa01843f2711268097f369e6d1748eb3b7e1212abecf3a4ecc2bed776e67
787347c9e22d92bb9f21132ec9726e59195ea486c3250c8912c56574943f2a6e586da
b49e7fc25c702e396de5ca9aed25dc90f4ac30300ed0fdc747de2ff4797c4b18da821
ae9ec83376c51d00a51b2d1701e5689e8dd720cca6fdd1a548b5b3ad34015006ce4f7
548be73295e07f15f8b0c60331cb65160000f8d550d2b6739c2decaadea347345aa7c
dcc442b2d05b838637746ee5732eb771a51755b30d5fe92557ae55f68764be558be1c
4d5aeed5e0b4371a7755780c36d6f3ccbf20d9b3b1f411e4dfab6e85f
KE3: ef2bbc46f232fce35a9afba7d12a44ec6c695c1abfd8e53c1f190887505d8c5b
e466c5a197b4b400c6b8c31ac79a44bc3d43121ea0405868247728a51ad08e21
export_key: 79f8483162275cc3883b92b168f94885ef0d321dffec55602562d4713
e48d7dad6646740986dc0870d473c8039526b68b289ba34a6d3699c40ba17c99d4ac4
7d
session_key: a54d1473b20b92fe7880a15f193f53e58f084a79337bb985f8298031
f4cd2199222fceffae140bce8b54dbc00d6586e02a15e2c25a84e326977d9b57485f7
579
~~~
