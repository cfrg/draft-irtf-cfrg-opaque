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
    Envelope envelope[Ne];
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
oprf_seed: bfead7c9c144dfc753a81ab1014d15d0f856b84c4350f5b186e04bf643
c0a34d9e5a36d3b73969c2e29aacf48cbab386d445c0eafc487cbd13d3c57a42db94d
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: fd983947a06fcc2bfd95db338d0eccf17315cfe5f265135009b0b
531821a4648
masking_nonce: e0d73bb71e3e3a4f3c229cb20c16d58782a2faf7558c1ae6218756
5dca52b4be
client_public_key: 26ddd7202e766f52c451d5ee1d63627721728bba1068cb51cd
4daf2e1182b443
server_private_key: 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a
9706137886dce08
server_public_key: 4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b
78624cbd10b371
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 47c9bd01ee99d5fc8523f2f04eb9bc9762b35f062ca10e4527b12d3
4e746739a
client_nonce: dcd67b6e215503d403c720b3759cfe5b110329637ed35c407eac20e
2d2244f1e
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
oprf_key: 6f2bb9a7c4b2fa6a04e74d12051ed70dfeb5c9b0aae450e432d4bd7d2dc
3e304
~~~

### Intermediate Values

~~~
auth_key: d5cd6ade44ad9ccbdda17af5500264ccbe972321cc61bd3c585404a3eaf
cbb353d093cd005322a3838a17bf1ae25178a522fe32e9aaddf760a22878e59471cd5
random_pwd: e38282f4e1e1925d76cb50a5cd6f5890baae6773ab13af3240236bd22
ca8daa4d08d5b352c0713528efbd6903fb9ed9ef2ce0050b7c1f13716601ef6bb0180
8c
envelope: 01fd983947a06fcc2bfd95db338d0eccf17315cfe5f265135009b0b5318
21a46487e953a0820db6704c7479f3536216642a9b8337114ea8add2c1a07f98a72e5
4edde4652bb14b228a6a4c9826c21244deb4f31cc93e5f02a076c2f6caec11d90b
handshake_secret: 8d14aeb31594b3792e64609046b1b0f93f76c70dd4d7cc04661
24280f163fbd50a65b62e9c18a2963558ada58bb2f1cfaec7e16a5be850db60b31bf9
78841e4a
handshake_encrypt_key: e8de218b0b785bfc5daeaf43d7706ee107fda2e0365772
b72bb88ec3148bc968bcae10f0c1be3505808ee6c5a6ac7367557cb3283c161000576
83651d785292c
server_mac_key: 6fdb48e6ad1eae27761c87d4d5c612075533d54e7e88fcde261e9
9060a98170786049102d60abce8be296133f24d8e27cf2afb9c4d7640b2086bbe60aa
cfbbe2
client_mac_key: 2429c743ee3e9fbb2c75c5f8bbec36555d5dde35e8ee05d2f3b29
f78aa71a6e95ec625abf092dbc4305ff2a5fe6543598f41f12a198e50070d7db89c55
fc9a91
~~~

### Output Values

~~~
registration_request: 24bbcabb15452642f709cb8567eff38f4cda6044aca3356
87a62b8453d849c18
registration_response: b8a5418b9b076e107c2712cf28db8ac9c57c35035264ce
965c386da25fa199214c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b7
8624cbd10b371
registration_upload: 26ddd7202e766f52c451d5ee1d63627721728bba1068cb51
cd4daf2e1182b44354db0d4cd9011e5c6921be4b256e6d7a45fa444669ae7d0ddfeb4
8e6d8c2bde03a2336e7745c6f65c26a14ab31a84a187b4ac0175d6f71c2f16aa322aa
21422001fd983947a06fcc2bfd95db338d0eccf17315cfe5f265135009b0b531821a4
6487e953a0820db6704c7479f3536216642a9b8337114ea8add2c1a07f98a72e54edd
e4652bb14b228a6a4c9826c21244deb4f31cc93e5f02a076c2f6caec11d90b
KE1: 0e8eeeb2ca0dbf5f690cfe0b76783d7667245f399b874a989f168fdd3e572663
dcd67b6e215503d403c720b3759cfe5b110329637ed35c407eac20e2d2244f1e00096
8656c6c6f20626f624c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
KE2: 30b2601f611a4750de42b91ad66eea012275913f84c7a79e672ed35f5eb5a262
e0d73bb71e3e3a4f3c229cb20c16d58782a2faf7558c1ae62187565dca52b4be64fdc
90aa45f1866029e8cfcc0e3ee78d0f0b6ef9fc75c7f402114021ab2ff660e744e79c3
344d3e63a658286be5670922d78916980a0f6a01308041095b45cfe502f47a740fe8a
9c59056cf8031f2a129cdb89e3a7e92841a0db1613413e3f3770212515da6ea71057b
0df6b9ec1040def820e6db5d286f51c35790bc75896cf847c9bd01ee99d5fc8523f2f
04eb9bc9762b35f062ca10e4527b12d34e746739aca372e52516d51c19763ad5eb1a5
b60dafb68c264dcf6bcc692f667a71c5a617000f403c5c4cbb5223d593c5d97afadeb
6f50e9bd1d88559edc8f903d06f65e0a288f5be7083db883334339c13df6823c8bead
ffd8d5f57db4fb87a33483fd00ce39f705043d5d31d86594117078217150
KE3: 5896a9ff6931c4da50ff2ec9ca4c78786e0deb85586bec1dc6b523bf30f9554c
468f5853c650f06c0166851292eadcaf9b41318370e6a579eadae112b400c3a9
export_key: 799db11929dd086fd7eddbb79ca0b9092f16d73970c064a4666b05987
a74aabe7c7ac2072f9d1d16fe0d7c6f4dacea70add4055ffe37f969532bf3882a1ad7
b9
session_key: 1c4a81af4c07a2ffe79449c64092627e939a45d6e6421868ec9b5e35
6aca28770448ddf6a66402417c7c1748a4c6be36ab56d8f38453192792e8258599752
589
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
oprf_seed: 17bbc99a766f5e444c81f66fb758906fb5dc8e1137421036e33962d17c
6613e203fa626027dce0bbe098d7741778d505941ee1aa242ab6a4559bf7c8812d8d3
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ba7ad869c776c3d231b661f87eb120597eb8b782012c10b4d324f
79f3835e6d2
masking_nonce: 8512c18364fed55ce3c7c6f075891ef643481c1646ca1e5077b030
b448a1ef75
client_public_key: 34171a08ef7cd0196763640692499e3b34afa7b2953cf25ee7
2ebdd695584f6d
server_private_key: de2e98f422bf7b99be19f7da7cac62f1599d35a225ec63401
49a0aaff3102003
server_public_key: a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e7874
92b98265a5e651
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: f3ad91ddd72efef5649f91cae1f45a1f6a9f060865218d0e602505a
f8b5ba0c0
client_nonce: 0ef406e04380f16717ca817d01be3ad2609e661d57272332dd1dd62
9d9e66a41
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
oprf_key: 18816ecf365e4abae0152bc83cce64df36536071b2c2d0480cd6dd64753
1560c
~~~

### Intermediate Values

~~~
auth_key: 3cad66ff5300572c2f6e6d7a3f5e961ed6aff6e1612bcf9f8e3daeba189
6d84a4c87e27c847d357a7ed150ac5ebc9df74145ae1e30c4d81bc0ab630d23a4e665
random_pwd: a4edd6b08169aedb3c60312f27aec6d440c37cc45b764e81a5ef7a37a
38bfee91bc91443a76442ffd03aac9dc5ba8b67d94909c07d6e44eb4e77bc9ece358c
34
envelope: 01ba7ad869c776c3d231b661f87eb120597eb8b782012c10b4d324f79f3
835e6d2fe5d34c6bba628d46f6572663e8d8527e74492f8ed38ae0584406872e1aaa7
d94ab51a9956162f8f973405d2b045b140b112b23b81129114ff3f74f32d19d0ac
handshake_secret: dbc99d48e496e56782d594f3532b6eeca1df32ff8719e5dc6aa
e6bbe9bbac01f468d5bf2bc9b24fa5e9dcc3830152d167a7538e26b3e9aa634a69d1c
9092b7e0
handshake_encrypt_key: 4f82bb4c76d9afbb071569463e7dc6e53cf9362ccf5a9b
a90a0477eec96a90758749e54b3dbdfb94f9d3c1232ceb297e54262a497dea2a71274
9c120ffb0d627
server_mac_key: b4b714afb8e87aa6f963a1baed33a0d8c2ef9ab24054483c78d75
389059cc75fe5a301564efe01ea62265f9f6dfce1753776986c287fc99b9a315058d6
53a54d
client_mac_key: bb4e9be7e2fa0c72570e05362706ad840942b7133994d85bfb08f
963bb1ec5294c778573998a8f467ceee001d41c003121c2fe2117201956164e41825c
95025c
~~~

### Output Values

~~~
registration_request: fa8c0e0144f7b9cd1de1bfcf78104f94d63c0f90398c9df
ceee06ab5593ec500
registration_response: fa981e659bd41b0628391094fe5ea5abeb00783ce2a7ee
1b4c358d4d24f6977ea4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e78749
2b98265a5e651
registration_upload: 34171a08ef7cd0196763640692499e3b34afa7b2953cf25e
e72ebdd695584f6db5b9238d19c191a75d913050df790a67967afa4b11cc08365683d
fb186dc2f40f4d71b9135153d2ce1c7142e04b513c6ce2c8e70c781db5f923b5c2857
b44f9901ba7ad869c776c3d231b661f87eb120597eb8b782012c10b4d324f79f3835e
6d2fe5d34c6bba628d46f6572663e8d8527e74492f8ed38ae0584406872e1aaa7d94a
b51a9956162f8f973405d2b045b140b112b23b81129114ff3f74f32d19d0ac
KE1: dedef709c5faf24970b4fa77480a2c640dc8c6b7a53ae78a2dbf3fc75134a250
0ef406e04380f16717ca817d01be3ad2609e661d57272332dd1dd629d9e66a4100096
8656c6c6f20626f62746987c9ba92c3636d92fa7afc0379009ed54a7fb2db3cf7e4c4
07d4ed2c6e35
KE2: 3016b07983d802f40fa5120c50c6d3ecb5ddb028b3b936c5e332f9c8faa9866a
8512c18364fed55ce3c7c6f075891ef643481c1646ca1e5077b030b448a1ef7578195
104963a178dede59ce0d6d0d62135b7c15359a0afd2c9a4ff3848981e283e63ab7481
09487a0b8d3d67e119a567110feb5e9f7698f3a3bcd627cdcd30e9c4b5c27586a178e
dce88bf35430564cedf513014e3951e198ba8514d34ff55115d381d175917fe1bebb5
0b70afc6beaa75f005e2213bfb4347f6b2ca1b8f4ca670f3ad91ddd72efef5649f91c
ae1f45a1f6a9f060865218d0e602505af8b5ba0c080d9b21c255bf04113a6d339fff5
79c68475e516c0c98f625a90f6532a310f13000f35c15c6e5a6d330b679a2da7caa29
bc0d595f270925a9d2f831014766a18c99747b2a9f981a6524a697ab8831a348596d4
efdf9b960e3d55c6aa2ddbc4dec8abb0da15ff5a93163b1aa249c490a9fc
KE3: 78b842800a114956d6377990ede93ff8c94788f85d1c8a55ddcf212a7070c357
8e626eccd19c89b620fbd6b76d29ad49157685b29381fcba3c02b91eee8f484e
export_key: 4efaeae7b7bf50100f371fdc0e05b8570d68993e02b3505d15bf1dd6f
223a3f7e4d1d7fba4c798c44a5858e6cc005bb45b9792272aca6f1757aab7e466af15
a4
session_key: d1d304aac1f0c00903aaaedc4871357bd20aaea87bcdf6f7bc4b6812
9d6606f6947d6d2d31e52a48fc4ab093f4f2d4f84810b0d7135ca0f61e58ec9eeef51
fae
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
oprf_seed: 97ea31bdd1d5e3fed83edfcaaab3b9902c2b7f056052c2642ccfc967a9
046a1073560f9431e34f7b13371c786e58901fa95cde5a711253f04ff051551a3c569
9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e0b04ec3631529259a8be900e29c8e43285adc9f927037cbed373
2816b27dc57
masking_nonce: 7324f2a4dd0ce6634d624c80cf59fe7223f3491d1df9946ae3de11
9e96bfa3e8
client_public_key: 765d5df731918e800322d3eeccfc57017c1e3a4b0936e88e87
0eb98d2e13d73c
server_private_key: be81db28eb1e147561c478a3f84cbf77037f010272fd51abc
ff08ac9537e750b
server_public_key: 5ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3
f459678b0e0d25
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: afcea4cd164f343d834c732e988a6838f1ac6aed81db29f76ded48a
19eff407b
client_nonce: e8d25ee0b8862672b0961f14f26a22ce00d7e904c3ba10dbdd5540b
70214ac23
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
oprf_key: c2808f2798ae846c91708200a7795652abadab1bc0d56b23a0dafd8cfc1
efe09
~~~

### Intermediate Values

~~~
auth_key: c652d82e2380815d8b5cb761f6dbed0f555095dda856b7ee40b54d74dd3
6e811033b9033b804f25c20a35f04dc6ae43e8a6a769546d1b43af78fcd14926e38c8
random_pwd: 3c807e0a74ee313d0022d14119bf4b1ad0d203a39356359c6b6d9478d
e39c7e473f52c1bb81bd4e1abacf5d5aefaa3ef3893878cc8b6c5f7bbfb93109cea3c
58
envelope: 01e0b04ec3631529259a8be900e29c8e43285adc9f927037cbed3732816
b27dc578187330e32162c317cffe190e01df69d3a8f917f7a629aeba90612207341c6
0649bb339f52fac3c468142c17f204e50e4ae3119b8fa499bfc1bd5ef4678fcdc1
handshake_secret: 8506047549f8e32bcd3006616dde3aa168f58777c3373b4fe5e
7ff80d5b7b344e548aaeda6be42aa66a939880eea55d875f3c30c85e286c88ad1fd88
abbbbc66
handshake_encrypt_key: 6069795df834374579952f6fc1b02f61e66b1dbb7fd88a
1f3c4b2e35b9e1269cb41f36e7903afc66884b62514f670671e9f410cd09d025b9930
e8169951a874a
server_mac_key: 4e9e87b6a1c5cf321aa2c1daf806056a08ab8a1d29b9d76d48deb
f1ad0da72501689765dc59bf1c7d7b70fee0be17533526c11c4af88e764f5d12673a1
967089
client_mac_key: e31d14242b626a061ca32060b45d5c5f03ace645017f9cb8988f1
36f69e3f8202fffee46a3360d1ccc514db16ef267efbd171c900ecced2ff23752ad01
6bad79
~~~

### Output Values

~~~
registration_request: fa39a478c220a89929613f9e65c9a4617da96b62509c42b
39d7e3606ed2e8031
registration_response: 0ebe2561e52d4bc260f65f85e80e33046d32ab8542fe0d
4562152681f25154535ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3f
459678b0e0d25
registration_upload: 765d5df731918e800322d3eeccfc57017c1e3a4b0936e88e
870eb98d2e13d73cfb478b87b88403d626e5e185b9a5554efafc940fbe3cd99d24879
10ba2cd7858bf570fdb4c37da6186491b9cf318c675f640b1feb24d6a1e98631c8384
9fff0601e0b04ec3631529259a8be900e29c8e43285adc9f927037cbed3732816b27d
c578187330e32162c317cffe190e01df69d3a8f917f7a629aeba90612207341c60649
bb339f52fac3c468142c17f204e50e4ae3119b8fa499bfc1bd5ef4678fcdc1
KE1: 96f9f35ebc0ca71607fd2cfcd465e285eeeabdec61151b39b2b4fb735538aa0c
e8d25ee0b8862672b0961f14f26a22ce00d7e904c3ba10dbdd5540b70214ac2300096
8656c6c6f20626f622e8a05799d3c524ede0482f39e047df99d9a53dc2dc30e8947eb
5da98b8c4354
KE2: 54432c8df1dc89461e51134d439dd6a87fb01ad7e592f76957148eea28f11c7c
7324f2a4dd0ce6634d624c80cf59fe7223f3491d1df9946ae3de119e96bfa3e8a665d
ec9b0c3383ef1cdbe7959273c2186f62a187274feaa7b367d79da9acd4b0a47824c58
e5dacd808464d2fdc8c2647d53531046f93d98632fe8f80689ad88d0a1a498b5935cd
165b321415ccbd78d5d7b2c5c0fa7fbd3ecfdf36d752917beffd68fdf4a447ed54317
f21d1932d130748658688c8729a525c80afc262f24e826afcea4cd164f343d834c732
e988a6838f1ac6aed81db29f76ded48a19eff407ba6d76012999541f1ec0c014ec160
6f2bd2a517e51f731d59546951d9699e1739000fb38718768c890545beda8b7343c6f
e8a9631ad768fad45468bea6d529d15aca048063b36fa344d05b8d77b1dd0f468dbf7
90cd9faff0a97bc198fea0ac545c63f8a4b44a2a6bedfbf180144a73d356
KE3: a7f6db1c110ef54b74f7adea48b523166d7fa202843e7f014a892737ec4a363c
67c68f28922e6f47eb44163854464f74b434cc1e23c607cd0acf18514a5b176a
export_key: 16eb0197312137180134701d6292de4a15a9483837b1ce18da2a894d5
b238ee46096352adad9ecfd57f0d99029b898e63b87846577827625798bd2197eca1a
dc
session_key: ea6a3fdba848c6173405a7a36fa0c816dd9d4deb22f59b1dfde8baa0
2bc65280d4fc05eb520e22094c3622775fa3b794b4a6df43ec993789de0f10f775661
e7f
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
oprf_seed: c6bcbee1c4e989a92b4b9109f8c94ad030d6e173b8494c9168f33ef33f
5a6a84b07abde3f7cb7e6328356992ccb61d257481542fbf895d5acc712ea35917037
e
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 1cac0433fb8401510f0088e25bfef8637449502f0d1d3c9f71ad9
859903e127e
masking_nonce: c19108540008b5369e2684b41a960485db96c2838cd5a67e0fbc5d
8374a70677
client_public_key: fa0ccb4f9dfb731a8b7b0f528ff187cf069c5f038330c18d6f
a0e42cfca13b7b
server_private_key: d49399dc3bc1022938dfb0e79db523d4e4e41f494c3898eac
652bf95f6efa108
server_public_key: fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce50
017dc037001c63
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 2ff0892217ed2a91d1dcc46e7414611c6420093493aecf5aad4f968
55dbc9236
client_nonce: 1b6c097062f852eb0c7e3590102500de469d58b701ff1bb8ce22f38
525b0d4b0
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
oprf_key: 382053015e784e15f2c7daee26a78dfeeb54db4c04929d12086879a00c2
1620c
~~~

### Intermediate Values

~~~
auth_key: c947b5f74efa75416d063d72d23c83baac08ab67383d3c75504b378eb71
510152e9f9ab23cd670b0755691bcc060701af2827f0fa61e215fd34a863f898682a2
random_pwd: 07077daf7020d80dce16b0ea96a1ecb43c7726208867922eaddb6f48a
8ddd5c8e109cc46fd5c20baa99d3d9dd0b595bb72bc9a414d1870132339a75624abe9
db
envelope: 011cac0433fb8401510f0088e25bfef8637449502f0d1d3c9f71ad98599
03e127e2c5124b935c2307b3d5f0837c1b5e7c9a5123dc13bbf39e36653bf743e478e
1dc8e301963aedd5d947cff09401379f0e4dcb24386851ed168c699b8ea191742e
handshake_secret: 5d34457cdf4157e4f9739899321ebe7c2ce6d62a1d4975f093e
33a004e018861c4e7b75ba695296d59b22cc4b5c64fc919a38fbcfbeb1025f5f0e565
1538c8d9
handshake_encrypt_key: f7365851481ac5a066288df7e5f3b757f1d1b5239de6f0
1700ac8f468c1b3b33f5bcb20377fad2ba16b5b43dbe7b37f2f7b07b5cb27606712c3
705aa79b6e67b
server_mac_key: cecbc91b656a4e0691aa2b85d4a57bc02dd0ee0aab2e804e58835
99316b0d3174b9bdf8beb4d12922275376c9decc7009c9c9d152e5553078b5fbed290
a2353e
client_mac_key: 0eb340f679a9832b4412e8ce1d75f36a696302d475278d95e9950
006723efee77daa56d723f1fa533b4c48ab257bd8be6fa31c284ccce42584eeff45a4
00898f
~~~

### Output Values

~~~
registration_request: 307ff12c023cb5ce33a04efd497252442fa899505732b4c
322b02d1e7a655f21
registration_response: cc7af005ccfba2ee197d5edce3b38518af6d161de20986
170b281ff64b7aa528fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce500
17dc037001c63
registration_upload: fa0ccb4f9dfb731a8b7b0f528ff187cf069c5f038330c18d
6fa0e42cfca13b7b2d43a942e982ba6288fc65b433292e773a443d72a8b123c98fb56
ef77100303500a7046ba7640ff2f3fedb8550dde2c33d1e8da4018617a5dbbf9af421
11a80b011cac0433fb8401510f0088e25bfef8637449502f0d1d3c9f71ad9859903e1
27e2c5124b935c2307b3d5f0837c1b5e7c9a5123dc13bbf39e36653bf743e478e1dc8
e301963aedd5d947cff09401379f0e4dcb24386851ed168c699b8ea191742e
KE1: e6fb9b013986abe5f6e9586a0110395a97ad695dde622d58470adb0a0cdcb37e
1b6c097062f852eb0c7e3590102500de469d58b701ff1bb8ce22f38525b0d4b000096
8656c6c6f20626f6214b434e33a39d7d9fd6dbe3638925edd7a0344a312a22971754b
d075d8347342
KE2: 60070d254d903396a1233774ed46fb608da274af693748b3a544a2115b49e337
c19108540008b5369e2684b41a960485db96c2838cd5a67e0fbc5d8374a706773df3a
cf278ada3fdbc9fa19be522f9e388160e98beca7924ad7c0f0c059a64b7ae658e2e01
b69421ab1403be40c20724b867f9c8bdbf18090c34a3c0dc3103a955e13933de69fda
e3fd556b3979cd65df3f12d52e338af59ae6e71c6a029dff2308ab685cf68617a8fe3
2aa23531f57b9ec375d76fd08be46a9ac93a16378604ed2ff0892217ed2a91d1dcc46
e7414611c6420093493aecf5aad4f96855dbc92366a398e50c4e395ee52ef332d6c2c
0a77187e2e0b3564617eb66d2878c41e6c47000fd9de9b0125b1b25a5932008997de4
2a58e8b5d3462c6cbf34717a0caca90d06d8155e74b8bf2ebedf9c85cc566db3963a1
2677512796e27d9a61ef37e1ff520954393b37cd411848305c1a9a653d55
KE3: ad6343c3c639476a8dae9785058e336913d107529427a94a6a97eee855389533
f0ff8b3180c8e34416b850313bd2fa05b41295efd789b0b20848c4e460152b66
export_key: 55c96e7876d45ab8316f16e69a701d9b5207698e0fd25938459ee7575
85f44c366891db77c6a81385fd615fdc60a25e07bc82b77adc7f6aa7ea93f28dfccac
04
session_key: a3015313be0b65f900db0898f218ddb2ac31969cbb8c97ff1aa60b7a
d418a86323291b8d2c212c089140de2ce34ed3ddc4bd8ddf5eca1fabf25c8f13faffd
fe2
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
oprf_seed: 984147d390fce162e579fcd1078239f5f176175a852ea782eb33fce2ce
bf1678d40c978351c71d6b5fa094606ecd41e3332a33200139f26766c29171f2af0a8
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 8c5bc152ec81f7800a37278a2cbc28db27a31c010d5a432d29c47
24a0ebf8013
masking_nonce: c3d6f63314f7f51388e73d46009b810bac4240ba6dcc195cacb2e0
adaba7f2b2
client_public_key: aa4034b20383a45939c4ceaded40d26fc5d3946f8cf5b5dbd0
25efdd09ba524f43119023f6afba89309c2e9775cbf93107b9980b70131f04
server_private_key: 4b642526ef9910289315b71f7a977f7b265e46a6aea42c40b
78bd2f1281617519f3f790c8d0f42eacce68456c259202c352f233ae2dc6506
server_public_key: 7a9e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa
3e421385fd2194903385345e6ac39e2a9911b6e624b0928051af9a6834ce57
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: a075927398a68dabf2efee8989a2ca510e0c28228aaa933b25aa665
f96afa685
client_nonce: 025f7cdb2636ab76a4f36d7c05c8d7f2a4564c3220674ef53e7a375
a4949b6ee
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
oprf_key: ef79d27180aa9c0bfbdcc5f87c1966579318aaee2bd060ba0745fd5ddff
262bfdc57a9bd6037e78a32ea3c3db7e8d8e765a83adf97741004
~~~

### Intermediate Values

~~~
auth_key: be36a895580d28c07c67f79f3fb2745e6f84f80e65b9f60d13d4933eb36
0fcfc47827dce0f4faed7a074c41f241f36123605139f6c84a7f1f52261729835d7e6
random_pwd: 0b533dfa0e7237fd2bfa2a9399847c2c8df71e082802afa7ef900b07f
d0b7de096680efba2cdeaa33d093c5883ff13d980317042157b5f4c62d87bf120ad4e
04
envelope: 018c5bc152ec81f7800a37278a2cbc28db27a31c010d5a432d29c4724a0
ebf8013b64327147858db2970016df90a297314fd60df8f4992636ab10bebe0db231f
ae980da61ea953ff10aaf7b008dd82440bf133a34b4638c375c9b34d17b3d46d7d
handshake_secret: 95bfd0442f4ce40eb8fae90f81f20632a6814d0842b86966577
81bae1a9f8f9b4438015e0cb60873334d78375bee353cd9563e7af6dbd9054a1957e5
1aa7b234
handshake_encrypt_key: cc44176efb15c5b86d9446ef2e05ab468b9823451b7a92
ea269bd17695ab6bc9ef846404569cc47f52ad189ec6e22db28c604541c9970876f5b
9a493fd18dcee
server_mac_key: f73ce584eb468d3891f54a3213803d2829fd98f7e4f8159bf1998
964238dc75209d67f854217cc42dfe750c36a2af735be7bf314100543c9d79162ae00
93a0f7
client_mac_key: 0c4fee2abef82c9811acfa3390bc3ff153192bdb2caff8580724c
2599edaf65392d3681e2127eb2d4674f791e4132f63d899d88701ab2ef7e702cbb3b6
ad3bd8
~~~

### Output Values

~~~
registration_request: a2c1e08d638fa00bdd13a4a2ec5a3e2d9f31c7c4784188d
441b6a709f47e2196911ce68a8add9ee7dd6e488cd1a00b0301766dd02af2aa3c
registration_response: 229711a8c95f01c2ce8bb9a242c81e96f2be6a255bc4d5
dcbd069790f53917645261446d3131351c7b1ad39c6f928edc2ffabab242bd5eaa7a9
e44dda0839cf2fd0461eccb8fc704c39e3da227ceb4baaa3e421385fd219490338534
5e6ac39e2a9911b6e624b0928051af9a6834ce57
registration_upload: aa4034b20383a45939c4ceaded40d26fc5d3946f8cf5b5db
d025efdd09ba524f43119023f6afba89309c2e9775cbf93107b9980b70131f04798ab
fe92048e98dda6418771dae2eba7f285a2b54620b1a94f9e46212d1b4f3d9c951bcc3
43f8cb4b797a9790eb856df0afe0f76523ffa356eaccc7b868f3eb018c5bc152ec81f
7800a37278a2cbc28db27a31c010d5a432d29c4724a0ebf8013b64327147858db2970
016df90a297314fd60df8f4992636ab10bebe0db231fae980da61ea953ff10aaf7b00
8dd82440bf133a34b4638c375c9b34d17b3d46d7d
KE1: 08d74cf75888a3c22b52d9ba2070f43e699a1439c8a312178e1605bbe7479731
9ab7898faf4f2c33d19679a257bca53e27a7c295b50b0d87025f7cdb2636ab76a4f36
d7c05c8d7f2a4564c3220674ef53e7a375a4949b6ee000968656c6c6f20626f62de9b
fa627cb161dd7098c8a582f5fb3a38641e8df3d6e7c40dffec1adff5f0d148716cf15
cd11a04b80b11cc12a1056493b23ee23267704c
KE2: fcc882bd97a82c5123c68db84c7396caff56654439a696001a77388a78312846
000671630b97b11b1764d74141ba3410c84dfe1286a9bf55c3d6f63314f7f51388e73
d46009b810bac4240ba6dcc195cacb2e0adaba7f2b221caddbb5aa9ace0754d5e01c1
fa978fe91906f7aa78485a90c590c0fa695494bd2e03a774511c42985a0a26c4e4c33
848699e6859f003ac132c3665364eb962f33aaaa24e627be29b0e048e45cd974733ef
fb07379a6612d55a518abbb1c375ef581887328cc293f52b1f798c85cc2a4d8856f6d
cfcffd4dc009d1609e9497c4e8519f2ccde98a9a1cc93c023c79af7bfb50fa4c1d2e6
e6fda075927398a68dabf2efee8989a2ca510e0c28228aaa933b25aa665f96afa685b
0fd650f0efdf4cec17e85b9cca2fa7ac7f1ff76ca94ed07e8ac65afd6304ef8102bf2
4376fc5b064edb55fe02027d7fef41d05db3652db0000fd97e630556151b0784eee8a
b2b0f217fb717ef32420532c4fdfc23a0bc9b01dc7da933b3ac15ebdf0a40c33852f9
71fd09b229cc8268f4a0281ff3521d403705a1d87784a9e3452b8cbfede39da1b2
KE3: 5bab5f2e3930391314221bfa59e155b8b6cfbec90fe28db67e178017c2ea0c18
3cb12d3ac11384ba63b0e205e92575d59f67fdb0ec14c4340367e63ab2d5badd
export_key: 52f0d2f3851ae167decf6ad7f069041e337e7da5578af1145fe37be6f
c813f157e2c539ff590ee9ce20665bf1fd939448e3f3b81e052e1ef0ed7473cd3638e
15
session_key: b0cf0800f56e32914cf3b99576a1666d5cf9fee42cb8e2ed81b8a27c
2fb620f25b85dee9d2307632a873c0e7b9868225d79d17fa0b1a91b10f02d63f32d95
116
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
oprf_seed: 678bb71adc6ce4152ad06da8ae657506ccd1e2ad96b0c39c4b605f0f8c
3e4aa2999b5e3a666de7ec0228df414967a86e4726ab9147a727ea20cad949b08ed71
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: f404a1864d451bea2b9d709c9aea33073380f615b8604aee07836
a221e543df2
masking_nonce: 848d40bf6eec1a9fb493f2c1539b20ff17e4ec005ea7e1ed3a0ad3
1fe831be7d
client_public_key: 885d2b7a48657cebcf339eed9a751af3e850cb7940456c0e82
0ec4d4d86248658fb1a8a525431c0bb020a435c4c3871f9a8bf5ab28b6772b
server_private_key: f0a17b7f6b056dfcfbee5bd7db70a99bbabf1ebe98b192e93
cedceb9c0164e95b891bd8bc81721b8ea31835d6f9687a36c94592a6d591e3d
server_public_key: 741b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230
316ebd2b419ae2f0fbb21e308c1dfa0d745b702c2b375227b601859da5eb92
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: df4742a529a27baf9032ca3f58a015c7c2bd976b060a1c6a9527b81
3a4647c16
client_nonce: 8d24004230da11429b7eae731dc1b7eebcabfa5896298c78154e42e
f6f39ed70
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
oprf_key: 2350f086363fcb8925413d2c8025bdccf6d9e4e454c4c0a928b52158321
a57d913be3a705e3ea4bd47be0fd06f736e81cf3ab1dcf8ec932a
~~~

### Intermediate Values

~~~
auth_key: d078e629e6b2828d90720f1c78e4bf3202e4f3628ab762436360506cb49
0359703899e700ad2e6fd06bff58f4a61fc1090b27950fda5c4a93baf189ea03d813b
random_pwd: 146329d87909e6aeeae66858882b30d8a489f0975bb015208b1e22d07
ec12b7da0062905b8ba77f78bfdfc870df7ae07d8a8bb6f09104a1ef878f120f5f7f1
48
envelope: 01f404a1864d451bea2b9d709c9aea33073380f615b8604aee07836a221
e543df21a84a28d80095ca5889575a09840702fdfa93fd31b67e718b282339f9709a3
673d5d78331ab239f0ac0f6071d224ce85c7ef886d8b35e3225ed9b3248856a3e7
handshake_secret: 351c13580b15738c70f088937b5465951a16ac94610c78884f0
208c9d87c7a1f1510f2bd6001aa0001779346474f4f4ce30050ab25d70034ada4185e
19d9077a
handshake_encrypt_key: 4484e07efb92c4949561b0fd1c6d015a0d3d95d2027ec5
d4f8ec3aaaae78772d862ccdb6c651a962fc117fef03bcb6db3facbb190b798f9c1bb
b9dfc3360c6a1
server_mac_key: 2de27bb4dd9279bd991e5d81b6467051c5c1d08010e683d58882b
cab7183d852a26aee42a2addb2bd74b51d973cd661e1dba89e1b688f0009aed348613
f2a893
client_mac_key: fc3fd2739c3ae340d0d6f04699eafae14e008c4441a1e0aeb6eef
d6f43523693015ecfef11395c1d6c7fc4c4e5cf580428acd092a3e6e6612a4cfbefa1
cb1788
~~~

### Output Values

~~~
registration_request: 66660fc08075380d7c2d4728ed1a7b550647e8231d6d29e
60d3d1fa8fa3132c8dc445fa9c94de42e5f12e29de958e5daea84eba6a6410042
registration_response: fac659c2deda634cc44db51c4247fe256b669ed72b585c
aa174a41624b9b330fe7817c30e7bb5076367311c6861d6491169e7f35fecd84c4741
b6d4ed36766c6996f8017ca9bd6fa5f83f648f2f17d1230316ebd2b419ae2f0fbb21e
308c1dfa0d745b702c2b375227b601859da5eb92
registration_upload: 885d2b7a48657cebcf339eed9a751af3e850cb7940456c0e
820ec4d4d86248658fb1a8a525431c0bb020a435c4c3871f9a8bf5ab28b6772ba4d34
decb9ee66a16ce4bd3e957426ddf74eeb968a592d277d85d8b7b16f7071ae5f8bffef
93bc9b6c2ebb54f0184703c86a1a7869fc2d2a6fe4c651fbeb5e8701f404a1864d451
bea2b9d709c9aea33073380f615b8604aee07836a221e543df21a84a28d80095ca588
9575a09840702fdfa93fd31b67e718b282339f9709a3673d5d78331ab239f0ac0f607
1d224ce85c7ef886d8b35e3225ed9b3248856a3e7
KE1: 1c83acd948f714989a2276ef0c3bb16d5b637942e6d642da9826fbcba741291f
0b093b8c94888ff0ab621f90344f5b8b72159e2eb80651c18d24004230da11429b7ea
e731dc1b7eebcabfa5896298c78154e42ef6f39ed70000968656c6c6f20626f62ee78
4169a2abed53764292f2e7385c5dd99ee21d09a4df24405706a59abb6d91f3ed3dd8c
6649807d11cb59ddfa23fad081ddda04ea49075
KE2: 18be8c4eee276a67d1e8142139ed0a04ec1bfcc9d77c2dfc7c298b4b39c43e56
6214415af7a0cf040cec20a80f77556883b8ca62687143f0848d40bf6eec1a9fb493f
2c1539b20ff17e4ec005ea7e1ed3a0ad31fe831be7d048d69a3dfcac9ce4a7d5de24b
b28dbf65c17ce5b85a357da32e191de0514e6419c73617ab0734f94ff538669a32750
d0c973c77d51decd3972b0f7ec12db6ccc52b89a46e9ca83152f23b68f54abf4c5c3c
c21e00d36120191fd90fc3accc17ecd8bf191a51457bb54ab8723d526a134085073dd
e24b4c1116173a47c58b821075d53cc393a3241c1ec79e7c57044eb64edd1891d08d2
7975df4742a529a27baf9032ca3f58a015c7c2bd976b060a1c6a9527b813a4647c165
cc2a00d1b42d14ac07e05dca2dbc20661a4f30909137bc3274a25c3fb4310fc9c61d7
6fc6576c8ed1c9816719433acc81722a2a5e23357b000f8e3fce3e8d2c8776a610ab0
158d89338b9142d436938d6dff6f87ea9b2f472233304562665bb327fa01b21354294
8c4c0f1aa362f25e4f3bf6ba7672d2faaba3f13c7cfdabdaa24109c0aabc360047
KE3: 6615c557196d5cde693390ac640f854111eeb4437b885097f58293b76ace5702
1af095330a5ba2b3cfb67c5fb9750094ca3a3239d92129163d8058f1b28fb2da
export_key: 2ffbf8c6ddbcbfa22940ff48a9feaeed82587a50f87b6b596146352c3
bab3a375281969878eb6508acdc10db762972f3282b19e326fd027bf8619964132684
f2
session_key: 2e358adaac72388a27e1605ffd0a298e7378d1a6b6095839800c71e7
fe780b6adf7f9e5456addc5e5193b5bd4d93435e9841f51922bf2db31a56dab39b59c
896
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
oprf_seed: 8fbcfc2de3f719d8024dfe535e5cffc282fc07de765b3ef1765f12bbc3
4f2044c4b43b4ed161b0df9b2f3401c170520230f8c6a8b8a6ca1c3ca5d221f0195a2
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 295b55df5f2772972deefa9aa5e1818aca2b6884441fe218c3f42
c688c60ebde
masking_nonce: e076b54449a0cd8931fdd681640ac78371ae99ffaf807fc8465999
3d83cef2f7
client_public_key: 007028cdff6bd7b7d7ff0acca54df2db10bae24466b8ceeaa5
919e86163184d241497e789adf131728b5466e420e9bcd3cfa8b8b10ab9716
server_private_key: 8cd37bf60927fafeca73ed8093538a994b1a8bd463666faa0
68e5ff9e00d588446b7d6cdc09ae8df069b30987a2cdd39286e0481e87ae227
server_public_key: 684e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04
ef823fc5c55e19163c714071efcab7ec06ccce8e6b9eba74ca92444be54f3c
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 1539c0816c15560ecf7df207d5be21808d91c2770bff7aa1cade908
acc52c825
client_nonce: ca91932c8c4bae4d748205baac8865f38c821c7df0a8e8d11b493de
2411e6ad1
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
oprf_key: 2159d6f5861ef7adc2875cee526f5429fe4cd87cf700241e89b8da50c3e
a6dbf4b0ec80625e1ae3ded3557c7bdf035edaa680ba0c1728434
~~~

### Intermediate Values

~~~
auth_key: 835df9440ffce55bb9b39242be1afc767eb9a212ca0e02f2e449d1ffdcb
a622579e2b8ff403c0ee70dbf40e9bf2dee41f26a4f5c3bf1c7572dafcd0e1e3aaf57
random_pwd: 2c4c598ae710b9697a078154d629566525e1afb52a91cd03b25430d05
7cfe2d313bdefe541f743e36a4e73cdad9a3406ea67e1b2c78c852d29bbb4488fca10
78
envelope: 01295b55df5f2772972deefa9aa5e1818aca2b6884441fe218c3f42c688
c60ebdee3d3eaca83716caefe173bd984cd9144df785ec73ac049ca6164a50c9f78c9
5fa6c7a5d2542c47c7a720ce4870d0dde4b72297641011b0675332c0ddab475817
handshake_secret: f628cfb5e79b6c48e5581cfd09a72cd047f386665ebcd4e8ad1
54056d5f864de90d09e04995b144e557bb6310391f6460908983e576ef89361f04a09
c9b75692
handshake_encrypt_key: 87e0a15f9f232f6358653163980bd9d45fae70360cf73d
971764a4c27f3d38d1711a2156865f2e63c74a774a91c1831f3b177b9d30054fd5375
6358e74d44435
server_mac_key: 9dc8c91c4e6c7250bce2122948e32dd3162d6b726f44e519aa4d8
6a9b3001a58c52b595638eb37eea072bdbed7573cbe6ad1c7d342f8d6421bcf361474
724abf
client_mac_key: d6cc3f7a30b387fb7699c8000628655f456d1342baf462f43613d
e38826c31e84e8eb62d989bebdc07a6af9ce0ca0bd12afbb674965ccad2214a63ff1e
c68cd0
~~~

### Output Values

~~~
registration_request: 8a8f12abe7f223895549fd121f9d6124424273b7524e033
f610261caf6ff83eb92d848318e7574c06ccee189b8b447b0fd26a348942d787c
registration_response: 66facc294d245e52a1886ebaec1098b7e837102c05d93c
b50b7561fb78e35d452352f90f3101d4e17ebb1f9006d89cac326edb6866d0a282684
e5378dc98d8e9d61e9dc02b77471318a1b15eb26272dd04ef823fc5c55e19163c7140
71efcab7ec06ccce8e6b9eba74ca92444be54f3c
registration_upload: 007028cdff6bd7b7d7ff0acca54df2db10bae24466b8ceea
a5919e86163184d241497e789adf131728b5466e420e9bcd3cfa8b8b10ab9716e4377
f59bc11c57777dd997cc27d2c2009b36d7e5b2fa6249d19cb1611c0402ccf4e6888fa
5b35d14a9a8ec7d29da69b6845678ed75ba40ae87793149e265bab01295b55df5f277
2972deefa9aa5e1818aca2b6884441fe218c3f42c688c60ebdee3d3eaca83716caefe
173bd984cd9144df785ec73ac049ca6164a50c9f78c95fa6c7a5d2542c47c7a720ce4
870d0dde4b72297641011b0675332c0ddab475817
KE1: 442b8d7585abe08bbb6b03b3d73c7f5d81cba60845258a4174e7b8d25a6d7238
8ec7814b7f0a0559fff29ac97c329f2c7b0844c3adb1c6baca91932c8c4bae4d74820
5baac8865f38c821c7df0a8e8d11b493de2411e6ad1000968656c6c6f20626f62d0ce
cdcb40e68a8f2a3c472d1fb7f0d96ce9effb7b71281a588df2ca0666ce00126e14b9a
28bbe73ada49d059f7794e5da6be7e7bf0eee12
KE2: 8ed5355bc5902ae5721cf67fef7b252a54f0caa4a1dd8e9c6511dd3e54ce6261
6a02423cd3d50d93c5cecef100d44d956f546b0ffdc8f8e1e076b54449a0cd8931fdd
681640ac78371ae99ffaf807fc84659993d83cef2f70032fd5c8d40bf8591ab82ada3
2aeb32d431acb7f6ea3723fe0b7a927bbab081140c9366945f0749f2ac48f09c5dc26
d72b9d0193be6d851c8c210b7d3f4303f8b24f28a9dbda1c03b6a91007769f0ce111b
6142693b1a4e833486a277a565abe850a2d247d0647f6352a7f6fb9dc6dfdd361f72a
f974b5f1bcdd89ff66e9c308dc935b1e53ec0485f6da1e0a7826191a2597667208a7d
14a71539c0816c15560ecf7df207d5be21808d91c2770bff7aa1cade908acc52c8258
0f64e52526682c9d332c4cb517bb261e21b86bc7199223b962c3d2906f90bbf3252a0
2bf2889a01d0cfcd6390b8567854107e38abb21033000f34b0265bc5477bfacf351cd
4d3f1dc75c872860e6e8c708fd8e7133818de1eb42a0d88e6aeeb4ab89c61d9cea514
883d7b76a7a9557a1dcdc0153bfad795323086a7291c114e36c7c8f4acd9d74684
KE3: 9026638375df03b7b2bbc958d21e2cfa083d7b26ca8ab9afcd1aeed9e3bb5af1
99ff7d30e452c413452b8ca1001a9c0d9ed22023ae5f2fbaf63d54aa74089623
export_key: dd16d1c369b80642d2c2ce9b840ff5e908cf8b1ae3e648ea63a2932f1
d9cedb9e2ad4cfce507749b058d41a87db7e5e734ff2b93bd022fae1e4d578f0fac00
dd
session_key: bbdb08f0a9617e2fe42fc2b17f8bda899f344f8fadd2e88f575bf96d
3f7113e693a93b012078b9117b5342aadcdeb9eb407d048a3276fcba220f8f1ee41ea
14d
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
oprf_seed: 49b8c1f51565a8e13d999efdd7b14449a6f9721cb647ddbb204cd3af8e
87f045d4420a6247f8b542e13ca8c56f60e8ee7a7fed33c52bee2d90f264b8ef6f23b
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cc4953767930a1fb41e2390eb08b62566bc5aee08a9ffabab317f
d2fc8aa7705
masking_nonce: 51037845a74668ccea5d44d449aba360b66e9bf7b27e07e2bc894e
533b685e6c
client_public_key: 74caab810cc8f86ed7d855a2132d199eb3fddb7f7fd99f75ff
8cc43bdd9611809c25eaf309c72346c5ecfe3ba2de165eb88514ceff2c0ebb
server_private_key: 0fb0bff035e9b9cbae6cfca36aa4827ccbac66177b64fabef
a67263087c0cb4e0d9cf547979e753c22548e3174abb5ac630d97dcd4af9830
server_public_key: 8071f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444b
a7ffe82aab916bc5ca6a11fd5fe1479e553040a8b724b6305c3f4289f3f39a
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 94239b19b247044d7c1aa253a07c8f110872737d9d7ce582e442c1b
689db651e
client_nonce: 377ffa058bc9dcd71399ad32a9dd8ddd38844f9fda75ece13b74fc0
ea7e5b1b0
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
oprf_key: f403d602afdc4411e56ff199440347e179698ab4be62017a4acb7cb3276
1fd61dc8a5b367666e07f7e5dc1ccc22b74da5b49321b4617260e
~~~

### Intermediate Values

~~~
auth_key: 0f6ec79c4fe52fb8dac66e985f18e4465604cc882f11b316dc3010add8a
6667601580c606181e75d58096a372f01078f3072cbb84b9ff26e06e2e0fdd9e5d9cf
random_pwd: dd59b31571f4f2d7f0de1493f3223f94f715b34ef55394bb9aeb398c2
0c9fd5e08fa75e644c6da0c3dc04fc7f8d66a562b4d5d3294e9c05846878dcf9c96b6
d3
envelope: 01cc4953767930a1fb41e2390eb08b62566bc5aee08a9ffabab317fd2fc
8aa7705f01e35d315214ee90397b42028521dd2b1f51ece157dec74b52911a46de07a
d7dec6f38a4bf29a393f9a7ee2298002171af54aa19d3766513df8d8a5328a6fc6
handshake_secret: 65ea436916705f148d70be267aeb9cb61d33c2a04abc1199eb5
016ab900b76f3670971cad1e023bc8426e3107221205b34b7f8d00e9fc221690e1b62
593ed6d8
handshake_encrypt_key: d0c8bc2d0fa76d045be42a74d8a067e8104437552ed59f
31a44b3e0130a128da08367ff1336f3633ccbc43399988681c2320bbcd1a853923573
e913ff18be6f1
server_mac_key: 790a4f55b73ace5e7074699e819f89141e80281fa99c631241cce
9e6424d5615333c214a98ed9287c88f143a5526ecf88b589c1c4246b260298105da67
6f1610
client_mac_key: b8b95f39a5bca27f5945c6450929dcdb9f5d353646f99334902a3
551a83dfb1fe97c05ddc5dfea277fb5949fa9fffbb337a187992aa6cadd72cbdecedb
792b44
~~~

### Output Values

~~~
registration_request: e499c1ea1a644df877a01f23ddc5dccbf3add4407605f67
dcc55f29c2ccec5daf9bc231dd62aa61cf2c9fdeaf59b3ed7a8f33af59ba20914
registration_response: 60111ab5a2f7656419c37f83bb4229517d2da9b33bd70a
cc34fe6acefaf917213ef8d1fcd617313f40b1a8b65f0ea680cf380be20b4fc55d807
1f74545bebb75f9b82ce1ee0949e7ed1ab5dedbb0e5444ba7ffe82aab916bc5ca6a11
fd5fe1479e553040a8b724b6305c3f4289f3f39a
registration_upload: 74caab810cc8f86ed7d855a2132d199eb3fddb7f7fd99f75
ff8cc43bdd9611809c25eaf309c72346c5ecfe3ba2de165eb88514ceff2c0ebb16d25
a53024038860e0e72e88ab84c6eefb8a223bc4b318b0533ffa85228ed2ee797ecba44
662b8bb0903783b70b294ef9a292683f80b9f54d19c2ab86a927f201cc4953767930a
1fb41e2390eb08b62566bc5aee08a9ffabab317fd2fc8aa7705f01e35d315214ee903
97b42028521dd2b1f51ece157dec74b52911a46de07ad7dec6f38a4bf29a393f9a7ee
2298002171af54aa19d3766513df8d8a5328a6fc6
KE1: 501e3dc8509cecfa36efadeba5efd0e4f66988ff9575c821b0128af06a2f5ebb
d77362f2a9e63b5a76cf5a636bad31b7a86f6c6803a2c995377ffa058bc9dcd71399a
d32a9dd8ddd38844f9fda75ece13b74fc0ea7e5b1b0000968656c6c6f20626f62f2a6
7ee95170c51833a88419529748e55dd13e23ffed8fefdc1d2b7c939b6371630031299
800b01a99f83129aa986369e4a188220d056f0b
KE2: 9a1dbc6905bfabaccdc42725a87da35b242e3864b0cd9033cb0f68a6b95f7816
4fbae51981e01ea4a241c90cf08ada79ca02af4aa9d1d21a51037845a74668ccea5d4
4d449aba360b66e9bf7b27e07e2bc894e533b685e6c880bd69c2aa9b242ce153c4d30
17d00e3e8e2e2c08f45c303e5bfe60a5ad5a38ad9de7e3ed726f5e9d12155017ef0df
58b79da6175b2572546b0baa03efec628fecea8f668db1a3c93a04ce5467cbc5fedd4
82509935a7bd2f61d14078003bb30fbf559cf7a653a5417c464d2e0363cab7fd521bb
6e680aaff9453b121b6bae1fed16d546fb8f8147a0330c3f889d20ab4cfe88aac83c0
1b5a94239b19b247044d7c1aa253a07c8f110872737d9d7ce582e442c1b689db651ed
410d142e679aee86adbe57da4801741034120c59fa942ef44c19ffcf4a4d65200d5e1
7e7d287220037ab038ee08f96c9dee6db68f02cf18000fe11b82ecc4cc65c43a37f0b
0599bb20ac52f53695e85d1212a5edafdaee7b794540ea1de2da2074185de29f997e7
a0987561b7440c24fd13a1bc45a2ce77537c69cc1de121e7b0f3bd3ae352b70e8b
KE3: c2b80ba6946d97e4d68f3a3a791f63a6c7506f4088f409280eca28831477d59b
d69f6ceab16f144f5e73f7815143aec8889218cfed4b6e9d97527e4c79965e99
export_key: 52be427fb5ef5b3f71770df9d2874f03378b7b28b6d8abbdca29478f5
7396d5628da5479eda2bad6ea453a3feb6296af0984114096e468fac1cf867153e817
04
session_key: 8d28a8c78d5d9a2e4f6a599d29c1ec3ce6ce3e40fa6384715abb8a90
39cd2dc5edd44124933575b691deb995c3a6d0053289bc307cae368245b6cb9575bdf
f92
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
oprf_seed: f307c5d82351b7b435b4bedb45cb44c9ff4dfc6265dd15b01ae9c96e44
d48e08
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: bf6b3d57278ed63f8aa93c9825d67578b96249024557adb16d7bf
ff14864f06f
masking_nonce: 546b05b5eeb45facb700a4592267d60413a40481607bf77c1c00ea
f7c08fd4f3
client_public_key: 02233b7419c00347ed642d6052c2f7bca2d0f9e3b19941ed72
c622ce7805ef975c
server_private_key: b3c9b3d78588213957ea3a5dfd0f1fe3cda63dff3137c9597
47ec1d27852fce5
server_public_key: 02e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398c
7100af2939f672bf
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 7a13c68ad1ad916ea6756211d2d94485f0497b696cfbc1bb43793af
a92d62ba8
client_nonce: 086703ac7ba5d45ee2d9d3ae89d057f4b536aa107881da5ddf9623c
ab48fa3df
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
oprf_key: 8bebb7b70edcc6564250fb4631015d770d0a4ebeb0ec9bd8a479a6525cd
2f99b
~~~

### Intermediate Values

~~~
auth_key: d456412d12115cb3d7452bdb544da52b9ee727c0cac132b6833557f7cfd
d8a89
random_pwd: 8a388c47c20342320a922d8c1f3be7f49ee8702f2de4fff6cab6806b2
4244e20
envelope: 01bf6b3d57278ed63f8aa93c9825d67578b96249024557adb16d7bfff14
864f06f8fb8a1aacde50277fcb228945865b2618a8e12bd70ac75201ff1f1c22b3c96
1c
handshake_secret: 8ba84d8f456af15591dcfcd8128754103296bfd09d6eb354cfb
cbefeec91af6f
handshake_encrypt_key: e47a974ab2b1ccaeaadf58053ce180f0bbb80ba2e440a3
ed06d47abccd218852
server_mac_key: 80d1a5c7a4fc7b50303861fe5944795b94e70b2c0aa8d92d9f543
1be293421b6
client_mac_key: 77f38fec694bcad26a63b03df58c5aeacfcda874118ae2ed567ce
6404f4a46d0
~~~

### Output Values

~~~
registration_request: 03761c2597a039a535c3180bd3fb6ea9830baa50376dafa
6e98bb41be2aaae0e91
registration_response: 02950335f24119aadd206c5ec40a50972687d87b4d5a52
62c81b54c9b0083a352b02e175463b7aa67dac8a3e0b4b3f4aa259d2fc56dfad40398
c7100af2939f672bf
registration_upload: 02233b7419c00347ed642d6052c2f7bca2d0f9e3b19941ed
72c622ce7805ef975c10227380620ee798bf1a29b1f4e8234c2d062bd172619c839f8
779459141f0f301bf6b3d57278ed63f8aa93c9825d67578b96249024557adb16d7bff
f14864f06f8fb8a1aacde50277fcb228945865b2618a8e12bd70ac75201ff1f1c22b3
c961c
KE1: 021922b40d051877d0f03ccf2831eede9b328e22c8b173d5f28091af0b92421f
54086703ac7ba5d45ee2d9d3ae89d057f4b536aa107881da5ddf9623cab48fa3df000
968656c6c6f20626f6203285470567bccdd3755aa8d00261e1ce65aa120e15571cc97
72789a361b4cafaf
KE2: 036222560ea388fe3af0bae182590dee7c093d846dff14f4d3c7cb4dd6f82e1f
3d546b05b5eeb45facb700a4592267d60413a40481607bf77c1c00eaf7c08fd4f352f
a81cbdafb7dbc08b384b8e1caea78ac1df4b5427882bdc442e451c73e8044d3008f74
6ddf5e6d983afdf254061b4494f57f81636dd2a6f554ed63379324079e9449de51a86
84939adf89958222530d5d005450a87db63e99470ff7c458e7148037a13c68ad1ad91
6ea6756211d2d94485f0497b696cfbc1bb43793afa92d62ba803651207f3887f92cfe
c56edd9b9df0047c1d6b7bfc55b3650a9579d44f435b092000f68c494a7be166869da
8d1ef21155df2f9e7738ff196e24370681e8b354e694236f2fb3c4f305a1572b0a02d
d59e5d7
KE3: 5dde86b4f57a6b84f5e80984e40268330b335d07aa8dc049262605c3178a3566
export_key: bc577c2c356b55e57e503283053ec2639a76a66a5b1d23c770a272c26
ac8c92b
session_key: fe16c1827dca05e2b24550b700e23cd16c0827e55a47cdeba71e4cf4
f33d81c6
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
oprf_seed: f97e928774b1c073b8d8baa15ed3f55a4b594282b6574b0b92947fe41d
b94083
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 75146119fd60218284ec5619dca38622b6306cbc94199f0d73403
2d9dd695fa5
masking_nonce: 6457376888a3b208c3939efad855c27e65e4e0b975299c1c9cc72a
00e2f8f965
client_public_key: 03bc9f3c3a5c62f644d1da5c46cfa8c04ac3ad1bfc7850b6c8
01994bdd97e003cd
server_private_key: 2bc92534ac475d6a3649f3e9cdf20a7e882066be571714f5d
b073555bc1bfebf
server_public_key: 0206964a921521c993120098916f5000b21104a59f22ff90ea
4452ca976a671554
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 7ce023cfe4ece242fc81a497eab602181fc34dc1deea4db9937b645
c423decd7
client_nonce: b3be89a095eed67689fa6f3801003820900acd77339a44d0d448997
19bfe9dc2
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
oprf_key: 21a4552e78caee39bcc24f9311fdd17476f0aa225ecfe3bc15fb3a9f4b1
05972
~~~

### Intermediate Values

~~~
auth_key: b6aaa4194f65f871eb9178a49dad31b6e51e2ae31fae1f300ad6145761d
4bdaf
random_pwd: 7643b2d69c79c0114be7c73f04e133dd9209d5253e39544d2573eb590
5db1b45
envelope: 0175146119fd60218284ec5619dca38622b6306cbc94199f0d734032d9d
d695fa5c9eef9157a653f3e53293afeea3f9ae875f19293635f44a890f02d2a9fa4b8
24
handshake_secret: 461aa21a5f7927897eb7dc6ba177ce6b0d423980a474e2c5ed1
68f90f54cc6da
handshake_encrypt_key: 47d9923555e5c093b36f90b328c4fc210a49a2932246bf
720c3118f851c68aa5
server_mac_key: 326f3ca6c08c03aa9627be89e3e213b2c9035a88ea5a8ca426eba
27bc074676a
client_mac_key: a4acb35f82af807e35f39228c8a6832d4e45fa3dd45a6d229110b
0a86bf984a3
~~~

### Output Values

~~~
registration_request: 02cd04a4a3c6b37f6013d848e1c63c204c4593377e9a14c
68e95097b615d29c129
registration_response: 03b4d8bfbd74ba3ce70803bcd5e9c4e1073ce2f8b7e432
d14b137b39622a9fbcf70206964a921521c993120098916f5000b21104a59f22ff90e
a4452ca976a671554
registration_upload: 03bc9f3c3a5c62f644d1da5c46cfa8c04ac3ad1bfc7850b6
c801994bdd97e003cd58d2c51461e7de9ba86719ada65ace60eee50e2c4ed5035e14a
cb0247f50127d0175146119fd60218284ec5619dca38622b6306cbc94199f0d734032
d9dd695fa5c9eef9157a653f3e53293afeea3f9ae875f19293635f44a890f02d2a9fa
4b824
KE1: 02e747d027881e63565ce0a611dae6da50c2a8b349010a52f5c936169be1e0f9
36b3be89a095eed67689fa6f3801003820900acd77339a44d0d44899719bfe9dc2000
968656c6c6f20626f62031e7dcb77fdba4b7e7b1625e43dae84733b28eaf2b4fbd7df
141b1ee353748b44
KE2: 02fa26857b5e7c578c948310e6c949ebee6557c543fed74c96214f0c474ea3e8
376457376888a3b208c3939efad855c27e65e4e0b975299c1c9cc72a00e2f8f965f48
55deb32a329765c7eeda37cba6d71107045def71f29efcbd5b07dcedeb2f367f143db
fa17a496068bd09a2415a7e70ff9eb97aca1e3668c3e3cdae5aef0f463729ace61110
ae4c73b2e90900fe042ee00d8d0d61cee1e2d6ef5480db9d25e216d7ce023cfe4ece2
42fc81a497eab602181fc34dc1deea4db9937b645c423decd7036d85072a9cda8438f
67dd81042861349f697c06ad4efb068dceb58c98986409c000f4bf2306d0a3fdcf91a
c0389985284c7ffdbb62da74e3e7bb5a2813c793986ae88aded9e2c83085333a4e140
cce5bbe
KE3: 927cf4f077629ee0f163222ea0fca42877625b096143534970469b8e269f7421
export_key: 727cc9e9dac17741c9a3d3812d4d3cf28646338c4f7fc37d0161a7595
8245ba4
session_key: a9c8713d3a21a2e6bcbff63d3ae58d18fec8fbe158d5cdeb6e4fc122
443de3be
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
oprf_seed: 5c131606e2b5c6390b0a723bdf6ca48725aafa0fc6cfaaa1413f3e08aa
2f6603
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 653b941fffdbe027919fc5b2008e79339560965f6515adcc454cf
30c0c50e79c
masking_nonce: 0bfe2ecba770496e9a7f7986df7fe29c74ea8151f97c000ac63e67
9ae9c46894
client_public_key: 039052b3c840a745dbf2e9ce7045a710bac4e7914210a4aeb3
33433e74f655286d
server_private_key: b0b4f35c14eb2477c52e1ffe177f193a485cccf5018abbf87
5b8e81c5ade0df0
server_public_key: 02e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e5
59ae18b6bf7bb5b2
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 780425ac34b00ec2e58a7e241fc438d114f04c7460aa245477608ff
b11144ebf
client_nonce: 28bc6b153e6d421d200f6a16a23ce6832e40153a1d4a06352af5818
3f867dc20
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
oprf_key: 6444eda70914cf4b8421bc23bd8109d09ae65c7c82121a749d36086b3bf
d1aaa
~~~

### Intermediate Values

~~~
auth_key: eed32fdec65be63ec80f88879dac9ee3605650c96ffef2ff6452cdca1f9
ac8e9
random_pwd: 3c9c52ce589002046a9ce6274211895a8fe95e55cd789c697c953d8c5
9208df9
envelope: 01653b941fffdbe027919fc5b2008e79339560965f6515adcc454cf30c0
c50e79cbf3b1072fc618d5d1fde2dd564c49074f9eabd4270c2f4dae7694f634d4b2d
ed
handshake_secret: c7de4e3d6a516914a103719a22c27f3a0ef450af336e66fc74d
7412964f1ffe3
handshake_encrypt_key: 6010732758a8ca8617be602d93fa79cc189aedf3df9881
fa68bb3a89e263e5e3
server_mac_key: 49079691ac47ea62b586f6256a9e089193224f29c8bd58581b105
8cf5318ddaa
client_mac_key: 913be998cc5471e91df4af265758e2c2bb0c9c737e61859bcae7a
4d75b2c1d6a
~~~

### Output Values

~~~
registration_request: 026aa49819f2c29b9543cefa0850db7fd36352c6ad8f47b
631b5b621266b670f7b
registration_response: 025189ffbda989b70a5bb66d3a307c19bea923cc8baa02
5818b6a0365c21a8c8c302e8d79aa24bcd2bea4e9bb7362b004daa0bb6be442d8557e
559ae18b6bf7bb5b2
registration_upload: 039052b3c840a745dbf2e9ce7045a710bac4e7914210a4ae
b333433e74f655286d2a5518c5cece2a941de4684d9ee0e76a00b7e1898d5b181d81e
77dbb2705c6f701653b941fffdbe027919fc5b2008e79339560965f6515adcc454cf3
0c0c50e79cbf3b1072fc618d5d1fde2dd564c49074f9eabd4270c2f4dae7694f634d4
b2ded
KE1: 0223c6f12f3c763bdfea59c13d8f1e055b02277625aa06cb3d839e03a60268d7
c128bc6b153e6d421d200f6a16a23ce6832e40153a1d4a06352af58183f867dc20000
968656c6c6f20626f62026ab0dc783fb12c9427dd0bcb4d95f5b5212f092406dd581b
d337c73468953226
KE2: 021451552feac39dc48a18f0a6dd62ed7049e9a29cbf617f2d82b8304da11436
d60bfe2ecba770496e9a7f7986df7fe29c74ea8151f97c000ac63e679ae9c46894cd9
c8a74852a47698bfc51a576fba0e29c7340c6923e4dcc02a731c2b94af578591260e7
7ec71317a1278dc640a0a82d123c53d50b9ed530778d2e5962f1e141f1057b176cea2
1ca30d2ef187204eab3c016e9e5870770e79b53a11f9a49f3cc3260780425ac34b00e
c2e58a7e241fc438d114f04c7460aa245477608ffb11144ebf0222d4232635f4ee370
6759740d7a0d8fb6a4068f2fbd34be7cf065f9989b637cd000f0f194c2aca9adddf7e
ccfe7a10cd6db4d9b3073ef7ca0889e20280cd205c66b61465695b54a6e89d047c106
0e21f0f
KE3: 3e03fe128ce8a582b4616a303967a58c347d062eb2b53e723e000c6f3ff7b928
export_key: 0bfe2c1dded650abc40fb507bccb7418839f25c7ea9c5c2d0a189b5bd
56e5371
session_key: d6efbf6db34a11b061d452ab70e45edf84ce18d32ee6320720226865
8509b980
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
oprf_seed: 507116149f5e6dd2125ef83f5a08a7be2c676c50509ddd01cd9172cc40
628f08
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0cd8ce020f60241ade2c82c75d3d134c9ecb18fceee70ab3c3791
a8f282271b0
masking_nonce: efec5e5f0a3e4e02fe60afa0241b344c546bad4c6cddc711ce14de
32361b71f8
client_public_key: 02bb781f4ea2d5ced91a6bb0145e995156b2631e06515e73dd
98fedf77c6cffd15
server_private_key: f7493200a8a605644334de4987fb60d9aaec15b54fc65ef1e
10520556b439390
server_public_key: 021ab46fc27c946b526793af1134d77102e4f9579df6904360
4d75a3e087187a9f
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 2daeb9d50c537add080fa2a5fb078b69d10009ffd0b72d7abcd08cf
03b7bb04a
client_nonce: 5306696c0f051315946cefd704cad68adf113ad5690e87c8172d64c
7d73bc3e8
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
oprf_key: a7c8552c443c1985594f2f943e3f5db454e70681cfbeb41d96e6d5b9be2
a238f
~~~

### Intermediate Values

~~~
auth_key: 3d1c84c2f273780271bceadef6816a91b13423076fca9cb836309cb5bb7
28398
random_pwd: 82ac39fc97084bb8fb6b4d9debd389b0a6cfcc3502454067699154a9a
2a81760
envelope: 010cd8ce020f60241ade2c82c75d3d134c9ecb18fceee70ab3c3791a8f2
82271b094253e1282c8d5bbbd703e8826b7004ad9cc138b6d3c2c08f6e01f06abb621
3f
handshake_secret: 69ce3865356ce43056dd03099c5ae88c9e22ec6729de70ff6b1
e2954ca0ace83
handshake_encrypt_key: 8e32450c6fc06240660a104767870e5aaba359361ac80f
e17422a686523c710c
server_mac_key: 705118a1b996be64806c93d69d16a3b362a55dfce924ed072547c
1dd5221691f
client_mac_key: 20410f2eba57ecf24d9202baac3fdfce92c8e8c9314a18f42a09a
718562f8d35
~~~

### Output Values

~~~
registration_request: 03a120f6f2a0b858f546d1e2b60f810ad0ed8511ef0791d
c26d8413fe13b0181fe
registration_response: 02ee9431937fc152e6491d25e52c26588711565239c4bf
e907bec194a9a44e482d021ab46fc27c946b526793af1134d77102e4f9579df690436
04d75a3e087187a9f
registration_upload: 02bb781f4ea2d5ced91a6bb0145e995156b2631e06515e73
dd98fedf77c6cffd156245b3bc0a6728923f6fe1ecf32692b5a04e01f6c25b2b7e020
cf41855a88990010cd8ce020f60241ade2c82c75d3d134c9ecb18fceee70ab3c3791a
8f282271b094253e1282c8d5bbbd703e8826b7004ad9cc138b6d3c2c08f6e01f06abb
6213f
KE1: 03edd5c0afa7257bbaeacab64837430929df9b36bc2784e47577e071a7abd9f2
ef5306696c0f051315946cefd704cad68adf113ad5690e87c8172d64c7d73bc3e8000
968656c6c6f20626f62033b64a07786c37f90b1abc757bf074c18326773bc296ec69f
38c111e4274a4071
KE2: 028d0211e461c8533b6c5fabb666448fb88a2d823a46abe7723558943b8e34f4
94efec5e5f0a3e4e02fe60afa0241b344c546bad4c6cddc711ce14de32361b71f8ed1
10d1c92715c0302bcde42a5daac7ef3a01db0f505eefd7528626fcb4f0aaa1bfbec79
c77c861bb21fc3617c2339265eacc86662e893294808b09094582e8ad46d6fde65205
877aaefba45c1429ef5e0b8dfd71a14752b7b416b8b61b4644068a22daeb9d50c537a
dd080fa2a5fb078b69d10009ffd0b72d7abcd08cf03b7bb04a029ad3943fb8e838ed4
9e4d64e5f0b84e120f175f30115009f18f009f7e35081b9000fbf20491174bf973a42
50b033d8620a350c05f6211a508f8c61eed647dafdb88e7cf2666a27d02004cfc3619
9e15899
KE3: 1aceeafc58f2353b0a5b5ea59eea456b5ce8948c06691d871563426862825c38
export_key: dff0526f3f072e7545f80cf5bf0ee358c32157c1b2b2b4444d742fa4d
c4cf4de
session_key: d1ce220131129ee428475687129a632a69977c85320850b02f292767
9d2e7f41
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
oprf_seed: 64fd84d5f8fcea3709931a487564a2f716823d394143985a208765960a
dd842d10c817e65a14df4f8c85bc27ad85ba3d72aa6c11b2ba449cfdffeb7ffdb8a4d
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d200018890c9ded8dca3616076dfaeb4438f8017fff11e4e6e0dd
38cc7044ca8
masking_nonce: ac28079019f6dfff918b48794de756812c3e57cd5702ce0122de14
26bc06dce1
client_public_key: 02cb3cd435fdd8989ee4404a02da56b4c4db6cb7ec75b01222
fe20d8e974225de9a2a8e2394d8a18a07da7137de56dccba
server_private_key: 6b61028c0ce57aa6729d935ef02e2dd607cb7efcf4ae3bbac
5ec43774e65a9980f648a5af772f5e7337fbeefbee276ca
server_public_key: 023713c6af0a60612224a7ec8f87af0a8bf8586a42104a617a
b725ce73dc9fdb7aacbd21405bd0f7f6738504492c98b3e3
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 914f717d50ba6995acf49bfeb2a65df826662815eda89bfd0a5808d
f54532a93
client_nonce: 6de3019ac382feea58f3891a5b6904e5e5639ddffce90d464bbdc55
5c166bf20
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
oprf_key: 7b49acf448f4b632933292843333cecddb7282b4eae653de0288b8a1825
afa82daf5045d01c6ae4b3420b097a7e9e8b0
~~~

### Intermediate Values

~~~
auth_key: 3e54f0ff9f75a178307b6901e0b00586a8b8f2b2609b6768de1cc41ffb6
b52faa838e1f5948ee71da57cc77b2b18168d59bbe8a6fe6a387df1481ffb54db9ec2
random_pwd: a9d7e2a20047043d77420835afa6e3bba33d7a2b5742643edb90f521c
98f6b31ddbd294c46b6ee1b5f04dd63f07def643cc8594b8967633c06a29aa0451852
e3
envelope: 01d200018890c9ded8dca3616076dfaeb4438f8017fff11e4e6e0dd38cc
7044ca85e59d271547a9390ccabb7ffdfaf9bb71bede37928167a6d7fe143960207fd
1392ffcde6344b78e33c6cd8a791b277ac46c9eeb6a3b6def3eb7ef876bb95e6c6
handshake_secret: 6e774c45518b231ade7ac1060ac02045c87eed88ffa0e72748d
b5358c4c6dd6c0ae4cc5c62d05480b073ddef21cc83173b595a327c03ef13b5e4fb2b
419b44db
handshake_encrypt_key: 55a7d56beb10caf1062c8551a131f17723a03380dc1c1d
a491383993c57968c2edeef266ab3b3c6090f74d9d74429bacfc4a3ed290c75168a87
df9451a7d9312
server_mac_key: c2bab0d9156c3d4d68f85c624f76c4962cd646f32554876b498ce
97c87c8000a1f933000b06acb8a7b23db339c8075acb32cca92a5c7cd33f44b4338d3
97efe0
client_mac_key: 94eff03cb9e6f18bc49ca6a17c21e9599cd8dbc0b0282d5b214e7
4b523c2b09cc42e2d13d3f6b69bb34a3a117eb9d4dcbd71329ac298ede546f4a5d929
d7dbc9
~~~

### Output Values

~~~
registration_request: 032a1ed9cba49c4f38f62e77ca295b8dd95d4d928aeb7ec
db24e28d927909e4624e4ef5df6b729071abb6e557b809d5ae8
registration_response: 02eb9de42a66d8c5d1c109dad18785dc7dd3c49e1c0d2b
a43a5c41566ce4002c8c721e67fa7cf86c09ab7cc57fad4905c2023713c6af0a60612
224a7ec8f87af0a8bf8586a42104a617ab725ce73dc9fdb7aacbd21405bd0f7f67385
04492c98b3e3
registration_upload: 02cb3cd435fdd8989ee4404a02da56b4c4db6cb7ec75b012
22fe20d8e974225de9a2a8e2394d8a18a07da7137de56dccba413ee985f32cc097947
eb537c2c81f8ba21309d0599e1e530c8b76b55ab440a8a88a6608aee6cdea6fec14f1
8d83236ef7ff4e614521749970ec3cf0b2e3b70301d200018890c9ded8dca3616076d
faeb4438f8017fff11e4e6e0dd38cc7044ca85e59d271547a9390ccabb7ffdfaf9bb7
1bede37928167a6d7fe143960207fd1392ffcde6344b78e33c6cd8a791b277ac46c9e
eb6a3b6def3eb7ef876bb95e6c6
KE1: 036bb3b9d78c508490de49427658685d8a74bdb5acb7ca4fcfb6fa5488911b86
8e746c08a1260d828fc5fa7e4232a2e58f6de3019ac382feea58f3891a5b6904e5e56
39ddffce90d464bbdc555c166bf20000968656c6c6f20626f62037e9c1e7bbf41bff8
ca6fabb630db2db73a92e57c6260f39d4024c619f8b4f2807473ec0f715d83e88ad62
b88ff3828f2
KE2: 02e95f8f3532a2492ae5a2b53af4118c4e1f6111458930cc598d3b9f16b9f89b
6322ba6cb88921b5dc7775978dc18d9775ac28079019f6dfff918b48794de756812c3
e57cd5702ce0122de1426bc06dce11950c6603f0a86fe1acdda2dc4340b22abada9b4
2874dda4d9d49aaaa8652b8de2aca44589a2839b5d12738d5c6788d7ab6337f5684bf
eeef00dfe116dcb28d6aeae74c9b265c4bda399e6715ff9afc9d49dc72c1d3ba8abed
e7fc6178d9e9613bff9f13e37554f14cfa566df63c4cd6cede5d7b50f7f2278591785
4e5e6dcdf02e9f7e6981eccc08feb6bdf332161328016914f717d50ba6995acf49bfe
b2a65df826662815eda89bfd0a5808df54532a9303196d22794e67e69232db19e4032
d2f2daa09828c4ef71e5a4f296a0edecaa5bf564c97a7e8c96a4977975a44eed2b37c
000fc03cde3311081459e1c1d9dea684edfb4f581124aac8b1002ab1e996e5488c6ac
cd4630b430d89d2074a5597c1758c2fa430c2e16c5eead15b06202be4d83db66246b3
e41b5dd28991d930c69ff584
KE3: ad7ae9779231cb3a9f6dccf057e5651ec996c19c49b52627feff7159a0dba987
f4e913c556ed8e964ec72f8c76b9b9ae74089f5074888af58dec40716124e462
export_key: 555a95fecad212bb712c6b969296b4afc6b3263989e08f3f3922ab062
a230a364fb49d501acffbb1b6ed4d74ab162825d76473b3c48483ee6597f067023ded
fd
session_key: cbdc7e2977e1cce8a379522133c9199068d58450fdef475af577c754
2e437bb2d1b6716980acab3abcd019764a942f675bbfe5113d8e9e739b559d081dec5
b2f
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
oprf_seed: 21af5a255bddcb7fd77a1890a0e6450a5a3325771010618ad7f3178868
401b36b047baa867c42ebd1e22cf134eed26d9a936857f5888674e92eda06a56319b6
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d88b32b7072ca2662ae01a9795a64519a3b5eb0831561766e1fb8
ec4d0679c6e
masking_nonce: 9c512a91bc58a3af3234aa0897b7291894b21a611cb25f1163afaa
4521a5f592
client_public_key: 032df2328e2cf48c09b61363155b1ed55af08e4f9421c01834
7039b5ed40f9c37819b8142b16c43e5559ee117bd90a6abe
server_private_key: f5acc7b0dbee75bcd8bb50363ec640038177f06904f2476ad
5274e2f9d258659e80b0fbd20e4761b22298eba98ae9dc5
server_public_key: 03ca37ed36b0b311e3241e6e96f49a44edaa971419d91fcabf
fbca0184afabd92827344da8379abfa84480d9ba3f9e4a99
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 09113651219b317ddd5e1cffd7f9029b3ca3c35a2f4078887298fd2
34e472190
client_nonce: 54d9ac67fc9db77029f8b9ae045c5ce7a7ea95b30bbaca24577c440
7ca73c328
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
oprf_key: 79d361ee76c711eb6830615cbf5fe785f5d9e6f42e220259d7c73822549
f844c32634c552a5e9be974ce95e3ae685dbf
~~~

### Intermediate Values

~~~
auth_key: f64cf3fd895617592cfc1e1e315de1e0c1895a106478c21f029e5b380de
398ab3382666b331533ffb43af165a97cd939ec72e2984b0b10077d0c9a59341f926c
random_pwd: fed625de9850cfbea89ed978c4465a135d6f3188acd6b5d8a10b5ff90
c2554fa882d6b3cf64e9fd0de48631c468c4b678c176b286be66869ed632336b3fe32
62
envelope: 01d88b32b7072ca2662ae01a9795a64519a3b5eb0831561766e1fb8ec4d
0679c6e109954c4b94350865f37f43831a8a2e8ae919300ff47e30584603deb5e14ab
dbde0c3a1e1680d02109818e8063646e5c18c06b6ce2f624257b3fa7953382e8e2
handshake_secret: 2259066a669f31bf641ccbadc233b1f0e9c9634562148aa874d
c868eac35314cb8369c3368c6cac565a6120bfa20b3bbb0598b15f56eeceab4560880
e2b823c6
handshake_encrypt_key: 8832a8103d9e8fd02ddd2bb7e7cb2ec4649b7e78159008
9c698ada98117b1d39f45579c7c69307fe9fd3fe62b845334bf586315e7a655f57110
9db165633fbee
server_mac_key: 53c5d51bb68a78c667fb741044d3cbfd40727fb1b90dde6c64ccf
00e49c7632650e889c268207ff5406352fff24f1435d03af2f9137e88b193488d0fd8
66c0d2
client_mac_key: 56a9720a3e00d18a7e5d8867aa39ac4ac729c8efb135a5a55bedf
8fa6238471f781b12ef7883178455099e82ac6dd0ea500994a869d388dc6eb1fc7b1e
47e78e
~~~

### Output Values

~~~
registration_request: 03c11a1b33c831ff085bea647c06bb354083adeaf4e7c25
d4ef17e90a25e590b275d412a48b83c064f75a6fd383e4730a1
registration_response: 024da9d21aa805664a24b6701b9383f3619f27235e112e
9e1c4530625e725010d1688907c6d31709ea8a7305bf8b21c80903ca37ed36b0b311e
3241e6e96f49a44edaa971419d91fcabffbca0184afabd92827344da8379abfa84480
d9ba3f9e4a99
registration_upload: 032df2328e2cf48c09b61363155b1ed55af08e4f9421c018
347039b5ed40f9c37819b8142b16c43e5559ee117bd90a6abe0b7f6216c188de739e9
157e4cc31b2cee627a71039e729ed5e86fddd4e13eee0be1c31d0bc146abdd99fbb70
01c6b116d6f57baab1d71efff4bbac6f427be32f01d88b32b7072ca2662ae01a9795a
64519a3b5eb0831561766e1fb8ec4d0679c6e109954c4b94350865f37f43831a8a2e8
ae919300ff47e30584603deb5e14abdbde0c3a1e1680d02109818e8063646e5c18c06
b6ce2f624257b3fa7953382e8e2
KE1: 03569da14f7d483ae405bdbd365b7bc7cd11968aa5c105d6fdf21d83cbc77050
7be9fb3aea6709f4a37e940900bccb4ca854d9ac67fc9db77029f8b9ae045c5ce7a7e
a95b30bbaca24577c4407ca73c328000968656c6c6f20626f62021323ffcdb6e9971c
b3d0516ac4f70f48c50ce81c897b4c3459ab5aa664a410e20012f6a3eefc000449912
82868648a0f
KE2: 0384d52d58a968a9460e5437b0ad6240bc463804d5a1a15560d44d7109158631
7148d8f39233af6dec892618596f491ed29c512a91bc58a3af3234aa0897b7291894b
21a611cb25f1163afaa4521a5f5923b68d3a3a108432ffa6a88f25442aa376f9f4444
aefd7cebe6c216172a38f1020d9410974d68acabbb7695584040b504f80fa075cef85
8afac82feb8b3743c8238894a0e585810b52563fb0496325b29ca4943d15692cbbc8e
5c6c11eef981282db17e1e929d60b997fada13dcd6d4b1f5737b8ed0160f7159b6396
7292a791604df60d81a5214e9d62f3ac783c864e70a8e09113651219b317ddd5e1cff
d7f9029b3ca3c35a2f4078887298fd234e472190037b55471c1bb3a246d0030fda68a
a80a79786fa060c0b56e7bc7d0000886e3d661be0afcaa0cf69519eb528a11af48a9c
000f8f9c340550faf760d5e9450173628f55f8b85c2c852e4b63554a09231d9d5b3e3
5f895a0039999d18c2a4f0875a4dca6790e68a3176f780566c9501ff42a2943a68723
6ef2d3c6f0e49b6d15cd503f
KE3: b7c0a2832703350c2ba88e929e40141d9abc90ceb60b3f70c316462a79c07fad
dc04046d93edcde254620864d5ddb1ab770056e7cb23fcce976b289139025bda
export_key: 2f28c50fcdd0db5c250ac33c6bd5a8cd16e840c66006cc61e68848a5a
2946b966e02cd9d29505e6a98d3698920d455ba93c0455f3d2513ed10461016106f38
33
session_key: 5a5b5312716f694bb3909727d1f6e9dca998f2ec86ae3cd8aa7644a7
dc66a80c239a3e1b8c44daa24cae995ad655aff25d3851afae5aeb341e6fa0a94f544
ad9
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
oprf_seed: 6660ced4175da69ac9714f1619f5ded53bacd80eb17e74dabc1d09a289
b05741f43614b0e0cce7f9f29b0391a42eec1d742c950b45e9156341b4263928460c8
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 9665505a2890da67bc6427cd24322305f89ced3021509b55f4808
916de12f095
masking_nonce: 8c492f60b98778df07701c5902cedfb045c2514cfb6abf274c6b6a
3a3507c28a
client_public_key: 02edeaf3593fb8ea4c97adc000da40e64e99e509e88358db5a
343a0732b5dd3b10beb3b274a0cc0a8ec1bad4802b173260
server_private_key: 8099b50c7ed9444176251781b6a8575de7491bec330164821
b9b2a108e3ef8964622075015ac9ea0f8380dcce04b4c71
server_public_key: 03aa179347ce8e27d2122b8c2c43315635e5489dfe1a50ab77
186e4710cc489638b097b3302b550da04f5d76adfa826688
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: c0f702ef8774fb1f10b8e2ae5da6f71992f2b7a760f370b21bac5c1
01566a3ad
client_nonce: 622742728975878e515c0bc051bbb3aba95ae8386b580ee99eedc75
39377cfa8
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
oprf_key: 93b78c4e7a68d719a2e2c37987ab3fab5c95239a44479a1a4a014a52142
3e15c136614b253b32c1137bcbd4026761003
~~~

### Intermediate Values

~~~
auth_key: 2604c2a2f78c9b931e6929fe3308b862a94e34077b959847ccf63c3cc5b
6056ce3735362b1ec9a1efeafb595a1951e766563482202fe670dd2840a5db9374056
random_pwd: aad58f2b4bed1392c4a8db48c918a4ee47d0c1d96eafb49e076b6a644
c4afb89ee4a34231a06b3aff49927f6c18d79719ce98cd33d10ebe678ae66e219cb1b
fd
envelope: 019665505a2890da67bc6427cd24322305f89ced3021509b55f4808916d
e12f0956e55d9c8fdb621843bcd6d00ac9559f1c7db82fd5d3379cff8884143ee0aea
336bc918255d7381e2167c826167faeee1a005eb02cc0dbf0f65332cc7a4d96a2f
handshake_secret: 145312aa3875ae83d968165ea8c5c9e1e80e5b9f2feb648c7da
93d5640b3c0286ee987b2698adec284ed676a0205b6a751c0078c88d2f19eec36c1a5
711c869f
handshake_encrypt_key: 6098768a99c8300c6b7c22b89a9645bbe51d291cf08bc4
56fee837eeebbd7fd6225dd229430fd24593f3560dd1754fc462d648e3b72d0644ef8
980c8932e65fc
server_mac_key: ab8ac8909154881798b3e9bcb49d4ccc1365954547d549a8e6749
4d809b6b9906d7212b1f198397a06a68b7717fbfcb9254b07e3fc98b60ad2314ba120
554207
client_mac_key: adb19e90f8968bc81f5cd71d830a2dd4483a655ca57505e0b0fab
c4ac72a18caa137a20a1e358405ca8641b95b26cf2f7251716b609e96be79aada81ab
85a434
~~~

### Output Values

~~~
registration_request: 0399b76973449a299bd2ad6be1ca983c8a1eccc7e05a36c
a120a30a8807d96bd4b98d076ddbd99e36adfd30b0886fe42f9
registration_response: 029a796089c10fde2d0cb9ab510d2e47f579fb99b7d3de
1eeb7e1cf3c2ccf7a8f487e4df863865b24ecf0c7f56d13518c603aa179347ce8e27d
2122b8c2c43315635e5489dfe1a50ab77186e4710cc489638b097b3302b550da04f5d
76adfa826688
registration_upload: 02edeaf3593fb8ea4c97adc000da40e64e99e509e88358db
5a343a0732b5dd3b10beb3b274a0cc0a8ec1bad4802b1732603d327661f234f53c5a1
eb18c4c6fd95c65ba093889df8de909e0558781d9b888dfa02cd2e201aacdb35f9605
5f35a318e4c4761ac4dacbe5559dafd082be4f66019665505a2890da67bc6427cd243
22305f89ced3021509b55f4808916de12f0956e55d9c8fdb621843bcd6d00ac9559f1
c7db82fd5d3379cff8884143ee0aea336bc918255d7381e2167c826167faeee1a005e
b02cc0dbf0f65332cc7a4d96a2f
KE1: 03bb6ba53426efb2307df620440d09e1b503d3d2135dd0c845b59f135ab39bb3
00aad505641fdbc2725c31d221feb82d9a622742728975878e515c0bc051bbb3aba95
ae8386b580ee99eedc7539377cfa8000968656c6c6f20626f62038d4077ad0d00842d
0d621527f8225c405f80049752378a4e111b3dcd52857d35f464202f22a17d717d5a3
be3455a93f9
KE2: 02d1bbf9b9202a1a6ce683e2d52bbeecc0356409b8a29c35640a95439a7f5b8f
7eafbb8383bcf97b3eba66198707d20f048c492f60b98778df07701c5902cedfb045c
2514cfb6abf274c6b6a3a3507c28ad0020bb19f3cf0a1a079da218ef5e177f8468f68
10bf50a71479c7d154d21df4251989bc0dc04dc6574ceaa1d8c5d08348eba425a74f0
769c5a00fd84572427e97777327a05c4b38f22350a86c9cd5680b2858b16990ac9d05
ab5b0e76b140bd1791a760133db0b9f9d107feb4149a3bdaf0bab01340ca3311a1a1d
cc4b3f691313990723163f9a19ecea4712fd3423403d6c0f702ef8774fb1f10b8e2ae
5da6f71992f2b7a760f370b21bac5c101566a3ad03ed7dcbc8318a00c1f42c2b75682
d0beb532636c2e03c524bb5bf5af735812003bdc0d076ca0dc9aa7ea97273c7088f78
000fc4444047532a7a6c8ade4d6f21f127cb6de9b84c8ebb7433ebad73f548a5d37d2
69d8ec1f027f83a3190625d0218752d6ac94ee1a1ab0b0db444af249016178edd2444
d6bb7b64869ea43200a72463
KE3: 8d13ea60cdef42dfc593409d2e23c4ce6fd67ee5df9d3f58527cd112226b4ff9
94833136f5889baabbbdf6dc9cd2351311689ae36a22e179bdd2428bc2a52222
export_key: 2024bc7fcf1ea9a122cb00e3054a6ab3170716848ba23974f0f09b1dc
9a853e08be27353027222511db107fa727ca87b399bd4da5083fdbd80beb1affe72e7
a2
session_key: 9f4c1db650b3f25e646d69fc93c1ef179e74a12689121f57aaaa6a84
c2d8a11ea8148827ac6023f026de00523fff2026b41b4445fa514569b64e02bfae8cf
338
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
oprf_seed: f0b95a14b47b905d6cd52f098d0d3a67aff33478422fbfe9e11a94cf81
3462aebd29e9fc95bbe5435cd38a02df86bb078ed177cf6a1ba1edbc8938c218edf68
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0c51a4308e8a66c975ebb84dbdb698c5e8c4472c611d79dc7bc0c
461c20cb06d
masking_nonce: ed0f3a3a52eb00cdc4f32cd7c10c7c90c235a0bbd834c75c6e733b
f3c7118217
client_public_key: 038f06a17eb11f657cbe57c009e104eb3a5725e4ca0b17ffbf
6803a3727a25795781ae8eb4dada7846ce5bf0e21f4e58ce
server_private_key: c6c4dfa3a822d8f670e5aa46e733baaec9f93d5e14ad9ab99
dfcbcb2ad157a8aef1f3fec3f24bbc392c9755271e8792c
server_public_key: 028cde89b6908e81425fa8a597e3103021475346a146b1f1dd
ab47f09c76ed3b78a251cf390bdc086924bebd471063abec
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: bc245f4410d5f7f904d2900b862bc88d15fbc31e65d711baf4da7d8
c5fd44d45
client_nonce: 381c83e3bc66d454d665b9783ac46ec8933b9d80d3bd0284e78650f
1c0369c92
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
oprf_key: 94d29ea72cc1ce16bcd67dabefcc1ac0c57a29bef4968018317a24f96c0
3a6bc96bd576003bba8bd433e3506140d0b84
~~~

### Intermediate Values

~~~
auth_key: c14f6f97d2662fed50057bbca9bf34bc1b7acff3ad983bd74fc169d4b02
7b51a3afdcdef99a2f263cf6e19467f3b0305b87cfae3e9e9b6d090b5aa656177b8ef
random_pwd: 6343bdd53cc3cc41dbe3fd528847b0de3ec0d4f59d4c0b49e9590f484
8c720ceca2771fabc5f4f4d7f55f23182f40b21838400bb4943e7151391fe7312e415
7c
envelope: 010c51a4308e8a66c975ebb84dbdb698c5e8c4472c611d79dc7bc0c461c
20cb06d6d55b017826bce8540a03603f6520da1078d0619988329c7b01f15e90930eb
41dd59a73bc46740ad92c33fef245d6241777f045919d9f8c83a0970c0670bfc22
handshake_secret: 39fa743ddd5958e7e6a6777977cb6fc9c9098482ec5af2f1f6e
116be359beb85aa29070a0e7ee98c5b11c561101a706bf78338999b9a8e5bf17d9059
b9c9c05f
handshake_encrypt_key: 4fa0c7ff76418bd75e71b044102b54afeb98cc686773f0
53c1118fe0ccbeb25eff6be2b14bb3227fa6396de088ca3d2ef9324f8b3ae92a619ae
96aa6860f769f
server_mac_key: d64a5d355f575899e4f01558f0abb7f300891c2c514605c238473
e4724c297e2edce3a32cb8495dfc90ac5cd3594d44620b35571beeafdd4cc1761c20b
eb38cb
client_mac_key: e368ef9cfdbd2bf0c701f0e7ae9b72555a9d69e376d77f0db37a8
c10f637899177c424646141c00d34f4d4d31fc04401a53122515f2182c71971af8adc
e4f316
~~~

### Output Values

~~~
registration_request: 03f8569ce50a023ad6518281322157e79e1207a96bb9214
95ccde8cf48eaf27895245a7b8f4b3b5c43ba54963a19cc488e
registration_response: 024a14c0bf76525a53aee9386b7e61802892225174b7fc
401a37d21c99d390d64fa1c8c7a4be79eb28798863cbe7645ad7028cde89b6908e814
25fa8a597e3103021475346a146b1f1ddab47f09c76ed3b78a251cf390bdc086924be
bd471063abec
registration_upload: 038f06a17eb11f657cbe57c009e104eb3a5725e4ca0b17ff
bf6803a3727a25795781ae8eb4dada7846ce5bf0e21f4e58ce33fadec85b9e88214c9
b4cbcfa3ad77dbf8d4e13e3764324573bca4e8d0d88de9551c5f34a6cdda34c7925f2
826d6450c0d0d45858d43785e2c107b9694a3971010c51a4308e8a66c975ebb84dbdb
698c5e8c4472c611d79dc7bc0c461c20cb06d6d55b017826bce8540a03603f6520da1
078d0619988329c7b01f15e90930eb41dd59a73bc46740ad92c33fef245d6241777f0
45919d9f8c83a0970c0670bfc22
KE1: 0255b2107d1a2192eb54c25c98bb7a95e581d7d23a38e1fceac9f8ce99f568a4
fad6c9bbc5abe4ff08f8b22e31bdfd6971381c83e3bc66d454d665b9783ac46ec8933
b9d80d3bd0284e78650f1c0369c92000968656c6c6f20626f620246ba00038cfa5105
659e8c250d10618a2c7f9d09d174663bc5689e4778f7054534d9a4200a447510023af
3ad3c61ece7
KE2: 023e5b13621deb51f74409b3e9ca9b62437be5fb8c8f5bb43a4926acb0da6806
92e8b2c066cf4e39b6880af63e7ec304e8ed0f3a3a52eb00cdc4f32cd7c10c7c90c23
5a0bbd834c75c6e733bf3c7118217d7082918f06b0aef647d521794abf8cb76ae8894
7c9bb955ffc45b5637156108ac68aa04d7498c1f0e76eb2aa20acec8904baea3613b2
fd491f1396f951c463d57c812f58486ef35325a7956191c1270c3831de1bb1b2e8276
11d2dac1b441cbb4a62f1fd71f5b87f64359b18456bfebb3406a666ef6f3348b24785
47830beb41a1c8a5c508390b7cc2037f2ac81a28f4eadbc245f4410d5f7f904d2900b
862bc88d15fbc31e65d711baf4da7d8c5fd44d45030d570f50898367457561b3a5c70
7852633b4f9404cc45b4058f52f5da1ebf67cb737bfe5c272bfeb65efe6bf7255116f
000f7628df5446de8fbc5e2af7d1e6e15483894feecf1042861c52cf0ab3a84a56447
1e5ed492b56f74655f36314c2f3e46e08fbd3d2c20db31eb613f0bd6f1f0be6648129
36e54de8cdccbbad0e010d67
KE3: fe0f274aa2e1fb7adda1e1413e1e47a2afde94e48158e5fa8f3ebdf2e14aa598
e9f7a5d874a97877ca25e339a64b1232b1f67fc17201b569e9379f4e36af6738
export_key: c9af34d414bdfd87a64690de8ca8f8ea5bac2c5ec05dfcec336200cf4
c8c18687525001dc5f64f807b2a21df1dc1ab73c524f2931272246d0c26417b0ee0b3
58
session_key: ca9a9af4db642c7f6a4b4a008df89050c1ade5c16eb878be6c20378b
0c0696e41d802fd481686b8ed53ee30327d8d17772fd9737d20b3354eb0833539c7ed
d21
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
oprf_seed: aa27cacbfcc9c802558a1f285d354012fe492932a1584a12f145e3b330
85d2bbfcfae5a2b6460ce6bc0fa16b60a56c950465401bc8182ef9b9fbc8405e0a8f0
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d7327c552dc88d381030ff59d4627ff1c656e26654646fd555f82
eaba0416854
masking_nonce: 86664427c85e97b60b12bcf9b6b7ef8beedaf7b0a15289c5360036
d99a5b7cb2
client_public_key: 0301ce558f96c4a6dc3cee02d4d1fb2731ec3d79e26277210d
5979add9cc0fcc319e06fb805de58d0110c5cfa3f852fb0565617ccac1e674a014eea
7b2a62d41fdc580
server_private_key: 00648b7498e2122a7a6033b6261a1696a772404fce4089c8f
e443c9749d5cc3851c9b2766e9d2dc8026da0b90d9398e669221297e75bfdea0b8c6b
f74fcb24894335
server_public_key: 0200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: fe7f22c8d8ed03a6e760c01e0c2304792e47d8b521e1f5c840946b5
31d2fc728
client_nonce: 6891dd93df58d453428a7b999e90e4bcc80bdae720b39cfaf5155fc
716695907
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
oprf_key: 00dbed3eb63db33f89e7a317f022bd6e1b253a50912dcb744d8d1d5a4a0
4d316bcde755198a5a0e83325fd70a2d4bc185b23d3ffbfaf87c037efb785d38b9e87
bba6
~~~

### Intermediate Values

~~~
auth_key: c73f0753c8f142e97a0d55ffe7e88578745de97b33c8496b61678b7c246
bd19452ba277a04d8b245cae7b263292de6029227cd7788c9306dab00fd228874e606
random_pwd: e1a6fe9125e55cbd5f6e1e82867486d27d6b9ee70ab40fb2b126f8e62
4459baa43b071760bb2218311114e6689c1a55c593caf4eaf71bb065e9a7bedba43a1
8a
envelope: 01d7327c552dc88d381030ff59d4627ff1c656e26654646fd555f82eaba
0416854e2b4b4ed766a41334bea118dc6e72df9db77b3c0c2152d505af21c44cd33ba
c225a684ec5b6a801e1c6e0320d51e20931c359dedc384094d6d2a392d10bcd031
handshake_secret: db25f0aea030b62fd2513e42e584d0b4d2d673784b24ac58830
11e60642d60835d45a27c01313970832547db9cf4417ea6c9baf7ece7f0fa2ea0bd2d
34c4646d
handshake_encrypt_key: 26803742fb4d5f93a12a2fb58cd733d82c49f3ab78aaac
317651a6731917f8bd7ed79059951999446a8967c8e79fb92c59a8365ff99856f3a0f
c6fd76e5e8eea
server_mac_key: a6e99863a91fac997371273110a92f6ea9cd55c74b58e1bab89de
e5bae6ef4bd0587b667f64c4e5c6a851991e60014798b3a15f0379c4aebd086963a16
76dcc1
client_mac_key: 677c5cf58c90aef9a99418803af5c04ffabbe7a12d54659d1bac4
85f462a7623a5721024c161bfbae448b3b22162e66d12302ad8f1ab84df54540082f3
8b59ea
~~~

### Output Values

~~~
registration_request: 03019f508a03d6d883f28a0afa477eac4dfad2ae9052a82
ef5736b24eab85dfc40309c5d205bb94b9a6697ac7b97b9b63e057f163905ec396db8
fe250544bd94e90c13
registration_response: 0200816d6f08c42dc383fef49e40922bfe0ee2e9a8cea1
497495b1177ba4d6acc19c80f206a1aafff3851436ab9bab1b8c2b2a09ba63714451d
24e1ec319d1543e58dd0200be1ff2041b4f0f5a8c110dfce0f002e6bcfc8fb4a36b4f
bdcde40d8a20b470c62e20ec1f86edfdc571fa90fc6b04d78a621a96676570969ee2c
b6461e06e2cb61e
registration_upload: 0301ce558f96c4a6dc3cee02d4d1fb2731ec3d79e2627721
0d5979add9cc0fcc319e06fb805de58d0110c5cfa3f852fb0565617ccac1e674a014e
ea7b2a62d41fdc58051c6eff7bb1c117d8c87caa850540a037bd4b2049c0700e5320b
77beb68e82fcdf0b47375d5632a0feaf18b1f1d2d87c5218c9d0ccc83fd358232eb13
5dfea2701d7327c552dc88d381030ff59d4627ff1c656e26654646fd555f82eaba041
6854e2b4b4ed766a41334bea118dc6e72df9db77b3c0c2152d505af21c44cd33bac22
5a684ec5b6a801e1c6e0320d51e20931c359dedc384094d6d2a392d10bcd031
KE1: 0200001c8b7065b1f65b9e87150b85b32e6a13738dfcfe40a947a3868b0504a9
c0b8f2d2f8261af3c4507f583ac24caee8981b3c2e7c6a81192d383aec9fb93e64203
56891dd93df58d453428a7b999e90e4bcc80bdae720b39cfaf5155fc7166959070009
68656c6c6f20626f62030187b0369b07402c41744c664239d0f9fad568f0ea5c13e4e
4d80c770fda054cca7fdebd3f91a803a3efe7353969e388623c224a86cc32575ef8cd
5e0cdc3c467343
KE2: 030131be8801d8737a75bd2cd7d234d7a74502f73ea2e121aea7e3d2097a8f10
a36b25975b28a4cfcc56f2c446c4ad28f911d421b360dcd594f2d16005671c3475f29
586664427c85e97b60b12bcf9b6b7ef8beedaf7b0a15289c5360036d99a5b7cb2d720
73a2c817c526dc10ca85bfd3c585fa9c2146e81b1744cc32ea808f40e9e28777416e1
eaf8393910dc56869a79ab8e37ea3cd58fe3d299f4dcd56cb7518c004a79d89eb455b
23c3121cb6be14e4afd58bbb239bbcd91b2da93c436e9da47a924afe84f676dd749c6
3e83bfa6176ae6ce72b7aec1ff8ce3c4472f6e491d670d4a7e849756aac8a48bb78ef
3413b119872c79d2dcd3d1b94027360bf8abe0b601b04c59fe7f22c8d8ed03a6e760c
01e0c2304792e47d8b521e1f5c840946b531d2fc72802016c63c8e2b3feac6366e3dc
f752a8c2a287c1fb4d648aedba86aa0ee07d2b1133d3282584d7c66357bfcab76526f
184f7ff9af506f9eec01645b99b6918bdda600c000f6c8d9c20948702a5f36b2c11df
7d282ce80bc3ba2a667431d0c6d5772f2845e896cfa466dc0f8795c6fc929456d1499
56b4591ad72c4ef4cc2fe61ee1a5b3c2f58c5bff67ebaeb04a3a3b73261b75d
KE3: 82a35d6277aec37a0c87bfa4542cbcc14190571794589b863e81b8175e881c9c
0ed26b66b3dc644f7a86d9e1844ce79d26203f74070060e79a65dc8ff989e18a
export_key: fc198530a52b9c9f3d3ce7e01d2a9834737239e9a35e68ac0a88ded03
6260a241971b97a79e0b0d4efb631b3a9593a615a719393062e73eeeaddbd2a1819c4
4a
session_key: cfa5bc203b01e66e74f0d451925d108ccd016c8c43340b31c9ce5425
d734c2403f7d9e0342885631910bfbed9c749b3910f690b96d5289914528bc2ad7bdb
197
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
oprf_seed: 066e4b7a2d37327f95809fc2355eabda3a5c1dbc232c2387d365f4a9d1
3b877abd36cea577eee9446736c839bb7cae1be923873137c354ac5d11a8bdfb5798f
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0c7677b8e0c0b4f066cd8e29e6bd2c4157f7b9e615e1347bc6a16
929dce0379b
masking_nonce: 706d029351382e0ea2a5c5aaddeffd8961fce0e68f2f9c4cc5f58e
0f16f1c6af
client_public_key: 03005bf295da011da57f319d97d38c8184ee18b50f471bc6b3
2ba69c6c509f302879f6ee21d71591dc461abb7d6ab61aa820c23be2e9b5e16e45d6d
85294ea2c3d11f5
server_private_key: 01e58f3492c6da02dd7387bd1dc40065b23155fcc16e56ed3
586c3c2d80245859235d872c5266668cd562a2bd7f34654235b1b9961485ae246256d
f3935910d36507
server_public_key: 03000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 86805ba2f30e7d6017dae082f902d37323713e1dfed69da9ab30239
bf126700e
client_nonce: 88076cecf7314883a85dc82c0e542e0778652aad86e1ea5a02f1607
62f49ce97
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
oprf_key: 01b5d36001c4112711d36d934a0bdd66eb99d1fef7046cb6846aae35817
8c1c681d9a9448c0b2dc94d3ab167d3c0f21c9f62d6194ef773bd093e7ad3cc37bef0
36b1
~~~

### Intermediate Values

~~~
auth_key: ccaa1b426185b2c8caa1abeb1e90019be77ee150dea243e9e79ad934af1
46520812888f727c4400978c94c26523db5c63acba5e70e0a10b79f47b201e903f7c0
random_pwd: 6b2e45076230b7a7d76beee657aa94ba6f7ef11ddd07b4de3c881011a
1863b4e5d33b2094b4269f533150cb17b8c8d719ccb03e80851959b67bf3079b1a24f
85
envelope: 010c7677b8e0c0b4f066cd8e29e6bd2c4157f7b9e615e1347bc6a16929d
ce0379bd3f238cff8da664e16bdf478faf68ad432e06d6dd9adb44b04c2c9e5fc71e5
52e2e61ae7ba076c05efb0596e8eaa65e1d6a1bfe199b9824ed53b70383af28931
handshake_secret: 5bc66b3b0f51b8078d8d4cd624b130ced75e6c613a8118491df
6f57fc4a7ef3a3b05c2b626bb5e573eb10ec502e1e5aa6d65b2e3748c723f6573b39d
8e5aeba8
handshake_encrypt_key: 50c0534fa06cea2e38f4065d7e57938867edf47467471e
88d2cdb3258ba06a3a1f84817bc870a4a10c06d41339bc3bf8750cdb7738d1abb14fe
4329a900b6078
server_mac_key: 9ace47eb87022db3c8b8a57c4ec5c619d0eaed1cb62533f44e5f5
dd8e523e0a96578ca1471abd692de9bff99e5086a789a5612267987277519e5d72ff7
c4604a
client_mac_key: cf77e227546edfc70423910ddbd25e358817c59855f2a51b49cc6
d5a76c9641e954187310b073b8d0f1f701922f6c65657efb206547159d4b1c6662e23
f22f19
~~~

### Output Values

~~~
registration_request: 0200bce08f110a6634cd66b75c0721208df3d8c392f86f2
feb9c20fb62c9a30df00b37caba143386c7880a96301814e425ba9df870cfbf19724e
b58411604b3a618f29
registration_response: 030032b46dd196754b6ce072434e11c5d65be6e8acc82c
d88464a987d90ed35febfe919458d7f41a76d59c9e8e7567957b54ab4b3f3c565873a
8bf59dc3464a33461d203000ac6fbea5abad2eff1e768bd39834b82166c06aa6021ee
7517b040d221966b827ca6162621a938d6fda5fd8e39b3b785cb477924b8a400fd285
f41c5c248574db8
registration_upload: 03005bf295da011da57f319d97d38c8184ee18b50f471bc6
b32ba69c6c509f302879f6ee21d71591dc461abb7d6ab61aa820c23be2e9b5e16e45d
6d85294ea2c3d11f50ac207de80eda3ca80ffbd9c023edffedf6ff31c2b28b1528c5d
c438e832af5855474911e7c57ec81efeb3cfe4238cc5b4f8e5998ecf116c6edb1095e
f7a0ffe010c7677b8e0c0b4f066cd8e29e6bd2c4157f7b9e615e1347bc6a16929dce0
379bd3f238cff8da664e16bdf478faf68ad432e06d6dd9adb44b04c2c9e5fc71e552e
2e61ae7ba076c05efb0596e8eaa65e1d6a1bfe199b9824ed53b70383af28931
KE1: 0201e2974af3a0c9a479cf1589e9c7db8f3e04723123436453ec427f75974423
4a57a91a724879c5cfe93ed919501d567a6fad6ff5763647c351ad6dd925f39cdb04d
d88076cecf7314883a85dc82c0e542e0778652aad86e1ea5a02f160762f49ce970009
68656c6c6f20626f620301bcdfcaabb52a829a450fdeb63bf90b8c98c6b2717164f48
e27d4c737058feb556f81fe39aed7846313ff6a6fb9c4bf1d81083974f2babdb08004
8cc67e12f8ce2e
KE2: 0201d0157388f4b9727f3469b0cea99fe69652aa19c920ab22f4c1e460b0f695
2799595050c3ed292198697316c3bd230b43f7f9f0540082dfb31c0b4c420b9cbc04e
1706d029351382e0ea2a5c5aaddeffd8961fce0e68f2f9c4cc5f58e0f16f1c6afc0be
b4b88fdd5f750a99072f6d59a55cc66ea15337e94086e86582957389edc099d536df8
68d2f24418fc3dc2f10ee75eb80496269a50ea612bde5ecab8721fc04e5f87082fcee
3e16413309f8bbe96af1c8f01e505f0aba0a405de451058a3a4f589f92b27be389cc5
d1dc284db2efea4d0707f90e1de03cc80dc3a409ecdec826ae390318466fc56a7b772
6d0eda9947a6d5584d4662f1d3123427fbc47dd22d30748c86805ba2f30e7d6017dae
082f902d37323713e1dfed69da9ab30239bf126700e03015da5c9a33d3168383837d8
d2ae4d00f39a8a631cd126b4dc1b01f06c32ac86ce29440df0e45650879f65ad94a3d
752f265254f7d5861046cc016567f9e36b873d0000fe5d5d1cc9bf0f6a69490385f1f
1b8808df58222e17653f7f888f972367530288fe9d5e697f92cf19529db82a3280b9a
a0e71032620bd70b2674cf03ded7be322edb417f17991e44e8bc4cad50a90dd
KE3: 04608c3e302305a06f7be7f3e28e866da1a6cebc7d68bceee927e7ae9d251382
362b7704c7299d674c654b98bd70e49c38dacb18448041f0fc0ce5646854e794
export_key: 2f4bd65b77adeae02dc3a359532f9d70889299a500c9f5e82cf99dac1
da896e19ac75f901ac4c640d550e0dcc40c08363e8e5f2317b08b9778193db351b1d3
87
session_key: ad44b5ef579d957710068706c514869377e135d4ab311ebfd9466186
293d22a84ce419f069943e46a4b7475ebc2d230498d4295eea5a6e491b0828c7ef526
c86
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
oprf_seed: bbc378488a940073db6da47c38682a457e75f1f1f7f6eb348fa272e1c7
e0ae4c69850395f312cca8ad78a997eb2ebbc35928f54c5712e08d238f2fdc2841790
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: da251589508b8324b1b4866d856da541deb68376f7b3f6b5ae061
62db187d8e8
masking_nonce: 3780748146cfdc68ddb5f3dd9321817103c32f7aa2f17c46aaae48
68ab74992f
client_public_key: 030023aee719a7a6ca458f50adaeddc84bd236f99611bf40ac
a8497ae08f78361a97fe708a0c26cf80f41493995a2c6e521be36806aee13f91075bf
54f11542851fb3f
server_private_key: 00deb3fb5eef3871cfaef0953ac3482c88f2bb4849b6ac355
3c3609aa005b2cb37316964371a39548566c5e4e4dfbfbe5faca38a62651e9a519143
d04ac366bd3097
server_public_key: 0200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 3f18c2ea5773248a904efd3e6a9eef4a3dcc0dd7dc15a69788bcf77
ed4e7ff05
client_nonce: bb3945e5edbc4b1ab96b1045446d61159342d02f575245f2c42f74d
cf91d4052
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
oprf_key: 015c3118ada081a64b3407b77fa40a4279806ed886e06e5fb461b17b340
42309f13ae8058fbd692acc580d5c35b3296c70617a73947b6f9e310c03c8b2354882
362e
~~~

### Intermediate Values

~~~
auth_key: 71a51e7f0827075e19c98015ad69c8af1a5cc31b3bf704c7f0bcce890bb
6af1422d8362a8620b1fd753cd4ea013f2c0669ee91e046752e6c5b0d486bbb7e2ff2
random_pwd: 58793f10230afa0679be4c45f968085f04227901b69a584459b227b4c
bcdd224999e4cc30fd9f4b668e567e35c4f4a28b60a3690e169676c6868d5942c86d7
17
envelope: 01da251589508b8324b1b4866d856da541deb68376f7b3f6b5ae06162db
187d8e83cf8a1e01a8af91816a14d52ca0d0de088f53169d2b5295aea3b356a012964
ac0e463932ba1a5b810d460cf72b7e2c680d1d36058d900c0db3c6c6f6de15d497
handshake_secret: 3c0bcdf37ba693bbf8ffc565ee7180b93bd0b931215a7667072
1a5a0977cf1b67e3c45306d7cc5cbda149a47849aad986184e04f607e518e80e40853
29e79f76
handshake_encrypt_key: a70fd7bcec43532b42c636eb7a99fa49fb5f60268b50ce
1916a3142d89b4b549e32001330e0c449811de3290a9be4c9bd1602185d700a03f6af
d0d8fff244ef9
server_mac_key: b23b5a7f024c80ecea0a0f53b9cb703e99088e8a87c862429ce24
45df090baaa9fc1e50b2040edeeecb03a5f5c39e7d4da32a393df154e405ab8c96645
03e522
client_mac_key: 2e8e1df4f01276665c2bf99f8dd8a4ecd0ee6d037c7e415c3b24e
a999ca432617479f5e078cdef13a4d9076053819f1956207fa4176a5f77d9edb85974
34ef88
~~~

### Output Values

~~~
registration_request: 0301fca4ee81d22c8e8cab4cd5e1724bae3cede81109f61
7910beaee9771549cf0090692d4342f0045a99a0707e09e38838e611a3f19c81bba90
12ad6c67ba55f40b1a
registration_response: 0301c1dca7d0180691bed42305be7af6128e49e4ff1acb
ff5b7aa314fa00aa40aef14ac3112aba9aff1940f005372c899c9025b618f58804323
3f1bde852de506d25e50200c689bc30525e075588345866abebfc27a312bc2edb3222
3b95f7479534b02c139cee9475816987c9a3b12ea04984670c674f3d42f47ba7a3670
768f2bdbc7c7ad6
registration_upload: 030023aee719a7a6ca458f50adaeddc84bd236f99611bf40
aca8497ae08f78361a97fe708a0c26cf80f41493995a2c6e521be36806aee13f91075
bf54f11542851fb3fae50b968937e9e826b1ba0511150f201ebf5acc5c1587434d759
6331efd6beb87f29d9af4506ee8dfe48ff673cdc74303ea7bd6d18267e4ee114b11a9
603d0bf01da251589508b8324b1b4866d856da541deb68376f7b3f6b5ae06162db187
d8e83cf8a1e01a8af91816a14d52ca0d0de088f53169d2b5295aea3b356a012964ac0
e463932ba1a5b810d460cf72b7e2c680d1d36058d900c0db3c6c6f6de15d497
KE1: 020197ca02b425dfcae9aafd4608362a1dedd8998e6cf906191b4d888db30de6
dbbd22fb3a1bf310cc09f781d9c6fa0bf1f1e9a79c09eaf0df596801cb9a1030f9d2c
fbb3945e5edbc4b1ab96b1045446d61159342d02f575245f2c42f74dcf91d40520009
68656c6c6f20626f6202018f831d92dd0355becccd11cc3904ddae5edc18d6e357ae4
3a7dc3459335316f842771994b3b411da7ad3c8911c806b322a9fad184e8b5586926b
e76313b87f3d9d
KE2: 0200c074c0f19c6715650023a391442829cdbaa2c01475258ea4cc95455122cf
e298a84d780cc492a5b619a13f137413fd4e29f67154fa53b0687af32d37e5431b7ed
63780748146cfdc68ddb5f3dd9321817103c32f7aa2f17c46aaae4868ab74992f8f40
c771e0d121d713b048a6e4b35becbd1adc80be698265c67170107328da820c66a71e4
b75c47ffda0afa7e9cd42913e69d2363f4dd0a452d95969e1939ef831d85cf7dd38cc
a751d667db9b2305879789b53deb0892156b97812552c5a0069f4f6bb8530ab675c7c
a440f6fba89f9ffd2f9b09011aaf26bec6d6acd3648876c692518857ef97ce6dfce44
43f04bd610127bde1a485f290cd04bc467ffb16fbde0db953f18c2ea5773248a904ef
d3e6a9eef4a3dcc0dd7dc15a69788bcf77ed4e7ff050300f8b6a63f05a1a6f6e3c856
d512860d5700cb3ad37bc1dbf4ecfc4c77c3aab7bb6576f70be7b460143e577d02409
524ef5fd5e82a85fec43cc2d66adc312fb27a1c000f70ece3fc62797103154161ef8f
321d5acbd29dd4aa237e6e45b80c5d09a2c9d41591bd6d707d7abcdf702dc326aa446
d05e4fa6b0d5197e28aacc7ec5d81747afad15317697bd8258ae5fb157a3eca
KE3: 580710836fd635839100d1982d716fe97bf59bf91ca3a6f28c33efacff28b3d2
9f948c3a85238b3c8eabe11c97e8eea7921cb9ad90a19539c410ac1cbc155aed
export_key: c821db787ee587a158ea8feea64b0748a6744d7c283e7b080dbcc0d76
5efb33fc7f1a4171d9939c6cb0c390aa86ceec2b438d8ce50fd5b997d6a012e8b4bf2
6a
session_key: c3e45217eba21a656f6edda21c96d551147ef1ddc32d49f2e0f1ee44
d223bd74b326051e86a1875577284fbc1ea917eb67e6704de434d6bc481a24e43074c
1d8
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
oprf_seed: 72e1f25fac74ebaeed0c4271e8fd1694c2547d9de077bb787bfee2d102
92fe8b7acca98297ad5db05f185e0e28c860430fc1f75ea9bef69eb612427c9cc0465
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 5b5eb16749d044d49852d8530dd83ecba0efac11f0209ae273f2e
f5bcb01a4e6
masking_nonce: e33da918e66832aef32dabad6cb3cc4028717995f58364887f46cb
2666e39f8a
client_public_key: 02008f2105ab351d57178d736cf051ab76170240a8fb824403
83a893f11c241a28525f2b1016ad7eabfb7b4ca5e47ae20df6d7f70f03b7e7a469a02
4dd586ae01f28fb
server_private_key: 012bc7471bdb9fa3e113b809a86dcc379b782052bce3fc9f9
62d373217b0c266b1e0932c7a0727030de9ce81d360d97fa94f7ca377aa6969e1748c
9f8b0a3f230c50
server_public_key: 0200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 6eb788a252f4e0f0e3ad805379ee973b90cf010feb075c736adaa5b
e04fbd5f9
client_nonce: 5cd5b0b3b77974fac872a88ffc7c14aff8bcf3b1e692ef60ef6d42a
00c0d5a02
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
oprf_key: 0169484985fe2d054acec6b49307d30fabb6066e18a1f848a34c7ff6bfe
75cdfb4a77d0087b402aa1d83d5ceb27ac41cc39e1768b69184656bc93538fb22001d
df0d
~~~

### Intermediate Values

~~~
auth_key: f73b94842e90a47969d5e091b39ae58518ce8c8abfdc36a14bda95e5865
cf262240f5f192cf0b656ba73feaf649f19ec38790840a0c87dc6b232af8b4a4d40d4
random_pwd: 01ecd59c188b77fa6e13599f169f34ce5fd6e8c684c97fed435b0a3ca
51a3641ca7be669823cbc29b8ea4e016a0ab128000c2114b5db2e9a04290f2a8042a5
71
envelope: 015b5eb16749d044d49852d8530dd83ecba0efac11f0209ae273f2ef5bc
b01a4e6a1f686b85f3b32bd1bc0c675c58462a6e39b91cdfd05776ddd0e7568511ae7
4b04ca690253a3e62bcd3737dc5a44cbf356d53b43fd3bc23911d7f67918202c58
handshake_secret: c840f06d622823e803a94bc508be60b05ef4cb0ad5499fb5c7f
07249258a9166f623dba6767afbcf80a45134b8e7af0a3cc98becfc22e2f3a1668475
70d54513
handshake_encrypt_key: 2ccf13ec7b54797fb659926eb7b0f51a3036e7857c53d6
df96d5fbf4b8538b806888c7030c21dce25862e845cdb6c7f7e1fb02f7c2c5bf0a6a1
f7932819fc528
server_mac_key: 3c40f016ffe7dd285583a814602dbf33b1b858ee8207e8f832450
f3dd8ee86d5b62d7453f3faeaf37c217ee2114cfdaaee8e9f2bf98b76760e144f22f3
81f5ba
client_mac_key: e698bc452e6f675642c867fe0d75336eca135b6e361d7f25ff75a
295d24190dfe161b0e64f296ecf49899f1ecb68f5c60cb59b38789242e6e2df71a1b6
764e93
~~~

### Output Values

~~~
registration_request: 020178d37274cd1fa2512ca1d238613727201561218673a
d3fb6a391cf6dbe028dd8d953f0e36516eec3c69ab0293b19769074c4b16ca36d06ca
2765543e694fd8a2f5
registration_response: 0300054abf2483681282f16f71d2cf421c7374eae6610c
05ac3adf7119b4d3a88434a12f4f579c5c65283c833171feb72291f4c1d18c888e3dd
b011647cf4fca46d8c40200c11aefb178441adf284549abd3bd4d21641252d611c178
f328e818165ef0f777865fc84dd96972650b007feea93c11738c499ebd5ba80b7be79
defa6a717da56d0
registration_upload: 02008f2105ab351d57178d736cf051ab76170240a8fb8244
0383a893f11c241a28525f2b1016ad7eabfb7b4ca5e47ae20df6d7f70f03b7e7a469a
024dd586ae01f28fb946f0191ac464a02693d71aefe7f9c9752ef1b2202c41bb20066
c8d44a7e112c7cbdab1509397d64445dc56793fa16adc129cb6859ae16bfcb37af44f
bd566ab015b5eb16749d044d49852d8530dd83ecba0efac11f0209ae273f2ef5bcb01
a4e6a1f686b85f3b32bd1bc0c675c58462a6e39b91cdfd05776ddd0e7568511ae74b0
4ca690253a3e62bcd3737dc5a44cbf356d53b43fd3bc23911d7f67918202c58
KE1: 030041daee06de56612bc011e3fc1b5b1c5eb334b6cc0cd587b5c6fd9f94271f
dade91de48e730d2499eefc313038c54e3ff0326da0afd4f5defd0e4f88eb9fe6dde4
f5cd5b0b3b77974fac872a88ffc7c14aff8bcf3b1e692ef60ef6d42a00c0d5a020009
68656c6c6f20626f620301125c341b183c9ed98ad735039a5aeb7a9c99c6a90eb2dbd
5a02ffa442393c1de1a7f11ef5a7395a3881525c7fb8674d74d842f0cbece5069f98e
2528ec903ba7e4
KE2: 0300ac60718da5a874ff68da621ee246890254c46d458302a2ae8cef4d026785
6958b71b109f286d4e3f214f6d710214408344ab676391f26b5d2ebf550bad0273c7b
be33da918e66832aef32dabad6cb3cc4028717995f58364887f46cb2666e39f8a788f
234c04e0397743f604a2ccf8171154e53034c1effc309861becbd037fce0cab828130
3cbcd2650d63b61aba32026717f403e1bb5cdb01b9a730d257f6bd4e7facaa4512cce
98946f424c62b9888d92b2e997d6a829722a0200c52aa366e6a300c0c7a558b7e3cc9
ee18d67548e84129f730415a399bffa38eda02a128dce4b22f4702ab1d21762e2e1bf
48a7da9009f9f92cca4237ee200ece0507b379612de839cd6eb788a252f4e0f0e3ad8
05379ee973b90cf010feb075c736adaa5be04fbd5f9030121f7821162fbe027849ad7
50dab6227d5633a7148e1b09107d200d7fe63219f09a4e96ba8cb734b5b20941196ed
b471863e1785c22e950e3ee34c85aecc454fafb000f7d03ca5eb8479b32375a934c9e
54e99af7bef553fbab6a19344c2ff934dd2d195cf8b5bcd76c9f77e4a7e2dbf0142f9
bbfab91f3860defd96fe2a2d081cfc1db884ba74b1711f79a4ee8dcd8f395f7
KE3: f8b251df3ece47d99bb5fa7f4e4423276d325ee216c3218ffc86e57bbfa77530
daaaeb5e969dde8bd735b41e6a7bd22527c8dda2e2885485c609f21fc1952483
export_key: c9e232bb5650eb48df95141e529d58d8602acd1d7d749c40bb54057bc
f477320c4f91b682f31bfbe2a430bcc789af3891eefb887aa0cc151629fda0cd73dbc
2c
session_key: bc9c8fa9e13c7bb14beed42a97fbfe295ec05534edbc66433debd6cb
16e598e2d28134183a44c58db7397e033f91cae1c5578940cc81df621572554d47254
e6b
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
oprf_seed: 1341938e5fe2a94110c1f7ade78c300614b72b87e2dd7db8f62bd09cb5
8b359df8f9266dcc309ece7f65cb935c4d152e73a087c58c5a84ed5714f6722b95e9b
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 0efd4b8703d921e8c740bfd2236f616144105278b26e5ba001cf7
136c227e83f
masking_nonce: 4f2814cf47cdf2a45857caf576054e42e5cebf877a9125d2a752ed
9b84eb07e1
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
server_nonce: 6a5c05a8fd39bca3c36fcd0624d70713346a9b5a26927176d6eaba3
5c4e485e5
client_nonce: fa3a6b9f37124bb9e2aeeaaeeb93282e7bfee76c1caf580abaf61be
18dd713fc
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
oprf_key: 6ab350e1e11e62148a6d1b01ddab5e39599cb42e97d162cd7e4fa137224
f660d
~~~

### Intermediate Values

~~~
auth_key: f8c315001991a525d2eda5774c753d20611120b114512a824a074a2041c
48d723905277c564458f8235ff69179248569e358740529ed1fcd72bc81e745d149b3
random_pwd: 4cdb28f1c402fbc3292a6db5bbf13d0c6afc973de4ba0fbaf83489d83
420f692cc0f9736a553a0b7e3321c3e497bd26064dfe18dbe522f0b18ca0be3b34823
39
envelope: 020efd4b8703d921e8c740bfd2236f616144105278b26e5ba001cf7136c
227e83f89a43a91caa4367423d8f0a057a967d652c43f83e1952bc5d7b7564b688212
f80112eeb98f389a8467f52a04beb95724396bbc4ad553dbf74b4e3b71a5e1cffef51
449386e4d7daab43b56db390a9febba907491415cf3f303fcf2ac666ce80c
handshake_secret: 6a91512f4e334c0b4519b3603cceb9f49927d1466ed00b18301
d6eaeca3f188a881b32d5b399aa2ab708e1d2167d4bfce375d40eab4e2f34a041d193
717dc15b
handshake_encrypt_key: cb39b668784e23a4f9ca4c43027fcb1cf39826eab99a82
a7774a643985f3dc8bf61681089bc7b5e026e0e8425ec655dbef537c5f542d7baa3dd
c73c5a8b71316
server_mac_key: ff51f4abb666b190e2cbd92816d8f70108e5444a60545fd44da3e
61eeaacb966211111889cf49817dd9e2b7e24bc9db3ca2333d47bc9b9eee42afcd842
4793e2
client_mac_key: 70e8ef775e6324655611871b323cf03b817b9e55094749dbb509f
00926c3d428529b19db98285114af699be10c90e4a1cb9422f01b87ad2a1f198ddd89
9033e8
~~~

### Output Values

~~~
registration_request: ac2882512f36bc4d5914964e782418271371fa9bd16878a
5fb6c3b6d29c54422
registration_response: f016c933be350f716a9ee0e011108df6f950a10e3ce21d
9f3c9b72e1082bb1090c8f3dc121e9f9bbbe76c4f1f664d2309e669b293597322afd9
d2f936a37f14e
registration_upload: e2a529d4f403f4c1712bc609c635b5c776a4285f86a51e4c
79787e2df91e237156f9641574224c41eab1401057e41bd0c3aecc32c7519e5cb0669
b20bd401ddc8ebae606b81ce4ab8fbe6322aefc84d7fa140c952cbf6b8c8c5b6d0325
b9f599020efd4b8703d921e8c740bfd2236f616144105278b26e5ba001cf7136c227e
83f89a43a91caa4367423d8f0a057a967d652c43f83e1952bc5d7b7564b688212f801
12eeb98f389a8467f52a04beb95724396bbc4ad553dbf74b4e3b71a5e1cffef514493
86e4d7daab43b56db390a9febba907491415cf3f303fcf2ac666ce80c
KE1: ecb46e5c31b4044876ccb2a689efc82231d2995561841156db449c71637d145f
fa3a6b9f37124bb9e2aeeaaeeb93282e7bfee76c1caf580abaf61be18dd713fc00096
8656c6c6f20626f629698728bd0febdc164c410a6738962b955c08a36b25c89058c38
d4575592c12d
KE2: 8e272f8e6cc909be18043df8a8cc14359080ff8507159d16b550b59a65401052
4f2814cf47cdf2a45857caf576054e42e5cebf877a9125d2a752ed9b84eb07e1ecb24
51b63ced4666267fc3f19a60ad4abb212d950438f509f3bf837ef66b25148b46529fe
b169ebc51ba5e6b89602f0af3e93634e30a84a6b26a0aa401535c8e5106d6dc0e1efc
379d96081055e03c91f523c3ee66ac3ebeb18615994e95fb071ea3cd51976f4dea9e3
5ef05f950cab7346f5567163e18e2cc426407dc92e06d766667c144239ea9eeea9728
867d2a519ceaf6f258d072a9084db945c2c2e15346a5c05a8fd39bca3c36fcd0624d7
0713346a9b5a26927176d6eaba35c4e485e534be8693c06fc0168040b3321043f40ad
79648211e6604f883bdf23abb045813000f6973ad59367c24246bb4a6a077d7f6b426
88be470856e378373603bc9f67b90177a68c9ccc502a11355a07efefe7c30a72c30d6
d877bf93b8b37288890a21efab29f604109f25aed7d4b45b12a5d3d
KE3: 4292ac6d005d1f3d8a94fab6f146753b60ca2f7ac8e41c81ef4352450ab4effe
e9d51bd5b0bc8b2c7f77e94cc83646bee0e7e63a4ab4a06b4d3099258d8e4343
export_key: fd819b9424c89985787b3269f9f50616c714c3d6db04b05a574e3fd76
bdaf71f2b162c03898dd9356bb36b776b60cb04ad3d04b0c5482253ab8895bd30c130
1e
session_key: f636a84fa383543091b8f36cc7a6618324cafb7d1f9b15f55aa3263a
53d415571563bbe4f2c72675df5ca1f659783d5e4b01c60880884821097b1f236c6be
6e8
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
oprf_seed: 71d3b6c2e09facf599c41313852cccf43e17b9b131aa00a60bfe20a662
d4a449a5af869e5177f8ced39dd8c61d7277f8bfec9532d48fc82734afc84b14eb27a
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: dff9fd211c55a0fc6fff386654bdf94d6978128f10bb275c82a8c
f1324a4031d
masking_nonce: 210a81edd2090f84735d30582dc9b4a261ba68346713df2f5c6aa4
00fa1b4e0e
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
server_nonce: 4e3b739d79608d5149af0a7691a336e330eb8d0301326a70f9e52c3
edaed9461
client_nonce: 5fc61b598fbaddcd99f114f3d1f5cb290f9347654ad074e6176a08c
5579da656
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
oprf_key: 48ef29f7316f6f4276983528b80dd882ec987fe9e57d75fb37769fa5a72
8e708
~~~

### Intermediate Values

~~~
auth_key: b01b468e8b1440534a4ad84e8732245f879ef0ef7f0774b57270f76bb64
97a56b0f5740a2e418cc6ce83c08ea2209ed20141f5b2476c0e08403ba3fcf307dbec
random_pwd: 6a75176b48436635e74fedbfecdd114bfeb3e4ed4dcdf1313dad621f9
0612e8229da73ee879560f4bf3423dbb67e5397003973d110be93f02e1d0ce4705f20
83
envelope: 02dff9fd211c55a0fc6fff386654bdf94d6978128f10bb275c82a8cf132
4a4031d9b058949eabd6b223915a8a0002f4ea3ac2ea0a6ef68a8d9ee7fdf2e6261d1
7f0cf9a7b9dd09387ad4486b284ed559fec7ec115fbdd9e962e20ee4be62d1115e144
14b0f4cc2f6d94ee8909d522716e749550334b5551f3cd7a9b7b1cc38c1e3
handshake_secret: 5009b4ce1c5d68f141a07638d6e8f52d66df5f50e5e67608788
379574106b318e6f3a3244491d3ed75b2e282bd440967e358737fc5ee573e405577d4
a47d0091
handshake_encrypt_key: 9494d7bdad9629cec66505ec3cbe4af1221f206631c541
b702c45087fcd24fecbe6aa2968666f97630ad30f3b98d650bbc26fde9891bda06fa7
b1fa029e64deb
server_mac_key: 17ff1336ffd349f8b2a142d9d2323f78ca5fa25a92e8fba21e806
22a855172ea0ba88cf71b08f31a793f8f7ab63aefe371c369a70c9902890895196409
391bae
client_mac_key: 632f71425c064f60c72c2a9741bc8fc8c0c6fdb98d397d0d2a9a3
22e4415aeae19fbe8eb09d72a700b661af084f97094b355ce62aab0c17a5ef7bfeaed
da69a2
~~~

### Output Values

~~~
registration_request: 34fb6ba29e60511d9ce2d2a644a58b8b34af6516cc54f20
f7ff605e8134c1213
registration_response: 9c902c87d08c6b7915c3c1a4c42bf8fb5da98a0b07ceab
573349365e531a885c928eb99d8771526762cb6eff0ebaf085d10102934ab78d1cd9f
4389fecd57073
registration_upload: 88073089dcaf094d0d5d73105a99bc5e5c68bbe5173f80ae
5ba927c3c6a9af0772efcdfafc9548e6b622088a932949a0709e72a6fb591f0148532
c31a7cd828a40bb6d2605e2771b2c566d44240a1a98dde4fe5802a8f9ef3d0bc3c6fc
c7a7d602dff9fd211c55a0fc6fff386654bdf94d6978128f10bb275c82a8cf1324a40
31d9b058949eabd6b223915a8a0002f4ea3ac2ea0a6ef68a8d9ee7fdf2e6261d17f0c
f9a7b9dd09387ad4486b284ed559fec7ec115fbdd9e962e20ee4be62d1115e14414b0
f4cc2f6d94ee8909d522716e749550334b5551f3cd7a9b7b1cc38c1e3
KE1: 9e642c6da6a475f89078708431aaa4e04d96097f7778b0de577bf4d08496ae5d
5fc61b598fbaddcd99f114f3d1f5cb290f9347654ad074e6176a08c5579da65600096
8656c6c6f20626f6284a786fae7664759a8bae0cbe9065cd80b70cbf600efc695654c
93e356735c66
KE2: 90d9f9bd1d19656ba4e612e63f8ea4ca3f34ed006af6e4ab73ac9fe786f0e445
210a81edd2090f84735d30582dc9b4a261ba68346713df2f5c6aa400fa1b4e0e822f2
7d5eb91a53c623600c6658c57f80ab007a2e39c4031f7408a951ed763d17f821d1ac9
a9d5e9b2f1b7c4b4d0372500a92c4e8965e1eba63d6a9cdbedd9d8ac65e39564c10ad
cdd608d0dc1bfa6823eaa9b24ea2ddb05a154bd64de749c103b6eb4ecaf9f3cf8f028
e9fe545409a559bb320c6171623bfffc0394f64db5eb1febb739c572d49b683b7cc12
c83440f83fb568a94e947940bd7cc01102d415d6a4e3b739d79608d5149af0a7691a3
36e330eb8d0301326a70f9e52c3edaed94615ef3502cc40e7ba5006845c131b661ba6
ebd0e6994b6f526e3b7cc108635912f000f766709b35637ea47d890062bfa90fd9166
a9b36b632aefeb0837a3680fd5a31aabe45355c4292c564931d95be2a464156040efb
d6c6df481b70d0de90acd299ce04cb58261dec2a48c44fe1bdf2e59
KE3: 63986f218a044ed0752045d249666f61a98fdb90d52a05a516482fd238cbf071
8c6252a75a570b440db64cf737716d9385353589182fbff1756dbc008450978c
export_key: c896e3bbd61fe845d22dd1247edcb7856505fdc5bc3123447eed79ee2
e7df08c346ad1d5813e210f4dcf92a68f93b416694ae0d8d82d64e0b1e81970dd0965
c5
session_key: ec75b559225296023b965501aaaaf113adeb71233ff8ab786a1eecad
25c18274326209e3bbf395976744ea1ab902274f2b20470d57f03c2bf5cb606e55db5
339
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
oprf_seed: 0744453cd346ecdf12b28bdb4cd8a920964ed3229d5ef248a7c705c871
68a967ed517654c0635f89c2402841297eba68b00174911e19cd1f1a3b2d35061c073
0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d7e160776c8f12c3084f40888bc54f4c3128ad758d89b22b084d6
842bc8a87c6
masking_nonce: 7b2312da5a60f21596c1d8cbece43c1524da1644e2bf63d9e31c72
f8c22de69a
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
server_nonce: 587178414e280f5f4d2e78e2e287baface2132ec51743d96b429cde
a220d77dd
client_nonce: cb7341840226c49aa9c98021cb3baef9879c5eb569e6b6c1a1eba42
78cb29390
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
oprf_key: d56fb95f6b130f75f1ee7fa05e09637a254220ac282c76750b665186f3f
9df07
~~~

### Intermediate Values

~~~
auth_key: 267df5044b8da904931b4ff741529b2ca374532213e02d3068c989e0e3d
1b0cb7a838b5902258b3439ec53a03a60b7aae0cb2218987f993084b16e33d878bf2f
random_pwd: 70f4e588b8c8f462d29f62ff61c4ba817027177861624305d83c1fc64
2c9c6e4e5fd22e41ebecf31b27c5bdf2ca042c4022149c2e7f5f3bdf679f9a2f515f2
e7
envelope: 02d7e160776c8f12c3084f40888bc54f4c3128ad758d89b22b084d6842b
c8a87c648c0c644ccaf0490873d96cda760a8c1f61aba0f45c33132c3ae72d0f9c717
637645148614c92c8c1a80390dad92bdd6cc6ac2515c5ba66865cf80dbe3b469db51b
700468469ee1b8a0d48c0da28dfa714a6aeaef63482b319fc4b2caa985a70
handshake_secret: 26761a5374d5a84c48fc0f7b53468009f1604e83f4c12523ff9
c066bbcf1d47ecf584a7767712d95646117ba7ec515d1d9908e3c02cc6c4a2de71d91
b2ce9fa0
handshake_encrypt_key: 0e8569bcdd79b9f12c9391202805047d6c3dd30d5b2222
3e1f0eb3b2463ffe11cf804f79311dfb26bde3f114340be594b9e08a08285ddf50d4b
6afa1d2adbb5d
server_mac_key: e0f31880893e39f965d5b605c933454ccaba9975db1927141ba74
670b509b8af13b4133fe0ac7cec9748315bd29c260d788566d27502ffba3e7888c7d3
b39410
client_mac_key: 6a4a08b5aeb0bf9f9b965a3906bd7495ea56701a30a91ce96fa54
ae32acb800dfdadb379c2eff4baab6f1e088650d89231ea551f1dc4da83b060b247f1
776d60
~~~

### Output Values

~~~
registration_request: b02294ae456aa0e055e49a09a3a4cd7176d9b34778a4dd9
493eaace4883c0016
registration_response: f42cabeefd941a064438946e3be19f356c19504db140b9
f714080c9610e97235c26c575e0048fed852257002c72e6cc0fddacc1df65e81d80d9
d5eda7943266e
registration_upload: 8463bc96f84a2fcbcf67658a19b22ecaae9ecd976e8b58f2
1f51945a636d180de0a76ad3c5997fc2db329a8f7f8441728fed526b34cb924ff55fc
4cb8dfdeaddca846d07d006a03787615ba60bd043adbc048c734c3b8bdd1b26e8ceb9
27d49002d7e160776c8f12c3084f40888bc54f4c3128ad758d89b22b084d6842bc8a8
7c648c0c644ccaf0490873d96cda760a8c1f61aba0f45c33132c3ae72d0f9c7176376
45148614c92c8c1a80390dad92bdd6cc6ac2515c5ba66865cf80dbe3b469db51b7004
68469ee1b8a0d48c0da28dfa714a6aeaef63482b319fc4b2caa985a70
KE1: 7405ec93c531676eb9437f46cf3c3dbe9346fa83dda34a37da03d693a90e9f7e
cb7341840226c49aa9c98021cb3baef9879c5eb569e6b6c1a1eba4278cb2939000096
8656c6c6f20626f62c2b0aee89ec05d28e6f9638d2e056f7cb4bfb8b4d032239d3e4a
7960d7479e7c
KE2: 5a2cce2b868980dd1eaeb5f1c5d73f7516a87d672f7e44a44ac668ed397d2036
7b2312da5a60f21596c1d8cbece43c1524da1644e2bf63d9e31c72f8c22de69a92f14
f8dcce8e22104e5ff08dd08087338e69d0654782011c8304237a5fa4967a5d516fc4c
4da92b173a8b87249ec0104aacd48a0d4475bf18e6acb3f31548d1d113b7cdd5be569
4e67bc65abe8bf98fad46886df42c25380eb146e7ac4dae181794624a1d4ac83f6840
dc0c2404616281ff6f228c3b86abed8feb03b5dd9239dc433b943ce6c2f4f1623f100
7e06e4f1a837ce7aea2c4e8edbf7c71bbd4168487587178414e280f5f4d2e78e2e287
baface2132ec51743d96b429cdea220d77dd16041ea53924cafd460331043cb3ec0c7
f17d6c246499b9c638118a606071e61000f39564834fb90a8ccc8251ae7fcf9cfb89b
1cf04d4e91d024770e422e109209e2457594daea64f53a5ae19faa4df54f0477c8e5a
58898ceaa302dffb08a3dc80cedbd8dac44417a8f5fe189c38e8aa9
KE3: 1c5d3204b18ea222c97080bf67eb91035fd5f2e5a97eab45b68be64fe86b8ee0
9bf58956cb8e8f09f10e36e44205d2a9112501bd87ed5e21dbe7a7a28a4cefcc
export_key: 62d2fd8e12d8f93d8b296181a2656b9a9bf8f208162c2cb6d1fe52db9
daa54bd202628c05c0b01244c13b36378b78a7a93688a748dcd89d6b6f84420fea813
f4
session_key: b67ea363bdb38e9dded248bd83cfb6bb8f52acd7fb4e018e08e5ed8e
933cae86bc6f2fae3f39a3e16dd5116452914c899cbe5cb94c95bf58f3da9d519bf56
c51
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
oprf_seed: b850630b52045b35b769b214e87a39beb4b63ebcc18de915de46c2c753
11891d84d9628a81a2272f0ce4fe562006c3b82d9760162159d859cecf25b2d2226d9
6
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 71831f27998e3c7251cf84b41bda8db9ce2ce9ce9ee3e3bea9670
793b4a38ad7
masking_nonce: 4e101ab06b3b765045bdcadc6eb53d64c78fcc0b8535a02b1907e7
b1d2e89857
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
server_nonce: 5bbbe689f01621f5c793f3842ea50012d1ba5762232e3cb48ac66ab
76c691444
client_nonce: 18666b5fd187e90efc4db08a261cc5de043ffec862956229a91e90d
aca2097ad
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
oprf_key: b6badba39e6c18c81c4556521405dc25201eb44e5595c6a8efd1391ff41
c5005
~~~

### Intermediate Values

~~~
auth_key: 6ce4a700a73d2c472f09a2a68cb25089f1d8addb44aa5f8e134885718f8
4c4342c83469d90d68b0df5f3c0f737c2e6ddf37b8453573b678bb51971dca746253b
random_pwd: 3616507cf13c17b5826259420e8bc95131a5846104eb6d3242d22703b
e73562f1cd4dc29af638a4b4de6a04aeaddf31f58b6929c890bc30b235e290de413c6
e2
envelope: 0271831f27998e3c7251cf84b41bda8db9ce2ce9ce9ee3e3bea9670793b
4a38ad76664ef2fd8d0050ebeefbb0336c4db7143dd5063ad8530030b53ad7d8eb1b4
90dfeefada0f731f931fbd549cf9849c8daed97e0681d61c60bf6c7b64564d6959939
6ca40a0bd5767caa52bf61276807f48c46e308135bfb6068743a66aa83092
handshake_secret: 68c36c4d52db4a4803b12cda0c1478d2b794644db234ccccd0b
10b5ed82429f194b147b41b42eb31fbcd292074b2860935e3e41928ff2fb2e8c81039
d48db6e1
handshake_encrypt_key: a7f407166e4b171702ca86e96d242b6f60d325e25c0e46
baea77173f236f25b389001f73fc6b312f5e56bde0f33e58bbcce70ce7ccb3382eaee
5d77e1727d01e
server_mac_key: 616557a73404c6e4f18285fc8ae4519f7b5ad4477105917827415
1b167afed90bfc5b0d8a263312646326599700b6612dccec39ea9d58862172a46b646
a4e4e8
client_mac_key: 55774774c26a6341f5080230a2de38cfb1f91b890518bc40d64ca
d1327206812bfd6c0a0842894270a4d545fe96e8413ea70645635b3785eda2b68a42f
d4201e
~~~

### Output Values

~~~
registration_request: 6a525dc9419e2d0261fbcd6033f9d500503a27027a48d91
27ca1209e01690d29
registration_response: ccb71572971056d2290d897152aecdd1d253a66a8854de
866da9543cb7562b589023317b443158b83d4f4b49674209ad390595bd29758f5e86b
1fb217190e964
registration_upload: 2e7f449922d1b7b73c979920fc5eaf21787a6a52e5b4def6
3328bec3a4f211469ecabe6be2d75bdfee6ae87f800ce6709f73ec706316c8907b64f
065e15aa5a096388fc29f7418aff1db88cb904f15c3f26f664c2b385f161569a4c2ef
5e2d620271831f27998e3c7251cf84b41bda8db9ce2ce9ce9ee3e3bea9670793b4a38
ad76664ef2fd8d0050ebeefbb0336c4db7143dd5063ad8530030b53ad7d8eb1b490df
eefada0f731f931fbd549cf9849c8daed97e0681d61c60bf6c7b64564d69599396ca4
0a0bd5767caa52bf61276807f48c46e308135bfb6068743a66aa83092
KE1: d6a8af82258885688aada828f32e04463c3739c7da0e63c5246711520dc16e37
18666b5fd187e90efc4db08a261cc5de043ffec862956229a91e90daca2097ad00096
8656c6c6f20626f622c8ffcf1bbc02dab15df7834ebdf85841395f07c8e7317285ba8
574b6eee3910
KE2: 502d958fbf7249f0aa279b333e5e4392a587dd0ba139ddf985549d5c2021254e
4e101ab06b3b765045bdcadc6eb53d64c78fcc0b8535a02b1907e7b1d2e8985717c63
7c79dff7ffb686e95f17ac5364ffa546bb040f50f3005ac0eed2b143f1157b2f40901
793b767a496197bbe3425a27190681b61c67c4a2329acc17d963248e09be8124a8112
a3d07de87d834a8cb7d1d32df755cd74617e49534e5f57645617feff9ad1f01d796a9
f6436c17567ac129807660022435cfc1fd2896ed6df02d87ea3bc262bb35cedec23bb
ee32ec3b684df2ef22497e16cea83802fc905cf225bbbe689f01621f5c793f3842ea5
0012d1ba5762232e3cb48ac66ab76c69144458a6c4fdb4b3da03df2e5b1f6ce154940
2e209712e5bf9d31efbdb82c00eef5c000f252110dfdc519d6b3ef39f2c6b583259b4
368039ccb4a0dafd721f0f9fd9f4c5856d7acb971e1fe8aae3c1e83da942ba20cbc7c
99fe5bc201e34e0d5839617813ef65c3f3818efadec9ff23a437329
KE3: 2d28541fa726fe246378c49c731e6570f7ca173251e08da1e47f0ed21e3ff351
0dba6b0029b63af1aee35f048883f62727fa5be1406b882a6af4128e0ad375f3
export_key: 37222476076d1afeb735080772b1c9bf791d76923b409c63b0073cf1f
19d826e89768e9246dd26822fdc7255d8b34899f9cbd7349ea96e595bc3454836dcd1
22
session_key: f58685510a6d09e39073a1e3535f121ae0d96f669f3fffe205d72582
0782b97c204a1f8121fcd5f8e0edb3f50e0237dc8b7d6581401f0484415e7a9497da5
69b
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
oprf_seed: e66f427152d231955aefeb40dd5dbce7a12c7461a13e8c041bb3ee8e49
d8f7abee7b887766a87130a1b4dcb4d8441439d76ad3580ea5bd4a8b13748b48e120a
f
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 7f6e4f0ebe46a04dacd768180bee55eea3b40d4a8fa25f5971895
e34edb626e4
masking_nonce: 0d77061d3f32724815ada81492ca0584bcffbcfef2f316e8c7a7ca
af696a94a5
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
server_nonce: 10773679d19e95613ef482ee2209ae78eb5e1778a0870a389c2fb05
66487327b
client_nonce: c915e703bf2f577fccf265e00494d13936febe0ae6ce6aec3951057
9318dd552
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
oprf_key: 0454a21a8602bc77ff199d5ec13a96455b76b265bedba1a32d4e1b20b3d
6cd8694bc2db814c503d9ed1e2fb1f1edc7baf67daaefd08a0038
~~~

### Intermediate Values

~~~
auth_key: 538e0e9ef012d63c7ad8568f610c91eb66b260f31d4fb810e70f32443b9
85f715b4ceb15bd10a4341b3c0e4cc885838c1788ad3724a5467e1d50d7d030f7c18e
random_pwd: 9bfd04a55f454d7827f2698aba2219b513c9cb58603cfa90d84294586
8af4c7749143e886d5b4da5bacb689831cf0a7eae7d31bdc2d457905ac0413127945e
de
envelope: 027f6e4f0ebe46a04dacd768180bee55eea3b40d4a8fa25f5971895e34e
db626e43f48aca3badf3979a0770c2af8604c021b1224de9d6532cb2f757933eb44f8
11e72629a6c649399c399fddc8edb68cf915aea2d17b240e32c7373270a562f9ed863
912cd9c9620b769e8a11334ac7899b5e3bc7a74c1d43391a460635d8ca518deba0849
0c73938b1f95ada457fe6263ba1817d98c802f24
handshake_secret: ce3e48091755d118b8912ff230d87c55d56af3903457900ce11
3a13b21ab713b3d5da8bc66795e6821aa1c20eeded3f226e50fa751f5ef9441a212fa
a20c3ba8
handshake_encrypt_key: 26056e92bfdbdae6271c2bec0ab4461ec7a2cdfcad2bdf
398dfaa82c359a8e7af79677ccbafda4b49dca49934f5830c578797284256ed56d521
ef911210aae71
server_mac_key: 3d48e7e5281af0ea7afdcc61af855a8424ba7f929fad13c01df58
7093e8ebce7dbc16def217bf7bc5637d8b188b0c8004dda5cd8c2b31bed94fd9f3ff3
c339d2
client_mac_key: 0c1c1425bb636d12a3b731a92292b899d0b004a5132e1d29c1ac7
8afb64fb9ac1a38ec99ae43be6f3ee524c341a807bd2ac124ad6db3514cf9d965a77c
6f24a4
~~~

### Output Values

~~~
registration_request: 56eba0e757af33e634107f2da32fbe987af1d37bfec1918
a2d42ed2f6b3714bdc1dd190ed6dc6da310536bb748cad363e76ad2fb1b05f1c3
registration_response: 7ad69e4b9dbdb6c392b0de82ef601d5b6554ae5986c093
6fa75ed17dec63a701d26be625b06cbdef934fd5214654885de15c9d73df852611fcb
b8bbe6f857883e38783acf58dcd6de556530055a2353c4e584320e0916d28b8278212
bd6405864ae84a5cd2508f09ea1185f82c9ba518
registration_upload: aca7c206bb8f25ac19b3436b1f4c8022f03e13c7763edf9f
b686b00b2c04b999f40d3f01507342017e83ef917616358cbf50d2d86063b2aa1fb24
2c43cb43b96d5f0ccc15e047c12da06c2d10a8a79ec7040486472678697c66bc681ea
9e33d3f53ea64d33eda501795bb7f4b1033e30853ff47482933311027f6e4f0ebe46a
04dacd768180bee55eea3b40d4a8fa25f5971895e34edb626e43f48aca3badf3979a0
770c2af8604c021b1224de9d6532cb2f757933eb44f811e72629a6c649399c399fddc
8edb68cf915aea2d17b240e32c7373270a562f9ed863912cd9c9620b769e8a11334ac
7899b5e3bc7a74c1d43391a460635d8ca518deba08490c73938b1f95ada457fe6263b
a1817d98c802f24
KE1: 16ecbe71c272b0b9cce77059395154ae766c95a7f10ad0e699aa0c773877225b
a13e0a8ace5007c53ce3631c7e7cee782a6c44cad6832e0ac915e703bf2f577fccf26
5e00494d13936febe0ae6ce6aec39510579318dd552000968656c6c6f20626f62d25b
52b3af68ebda6905d0db5d964660ec9ec81066ef7955559aa302e012006b1ce049556
666231483f56af9dcd1c27fdbafb4d954060091
KE2: dc56ec86c7873b8ce8239ca4eedb3611941d38486c7b3d28e6e40490cc8fae0d
c470505329a26de1e340bd2b48ef50d2752182d6decc67830d77061d3f32724815ada
81492ca0584bcffbcfef2f316e8c7a7caaf696a94a547dbcdd989cd321bfa43f01883
f1705de6dfe1dfcbf5ffc5ae719918446eca570df701e767fb7c5ef0a62f442998596
b53d2d30556de35c1ecdc81411867ecc9511ba7be24187651961b663f5edff78c3035
961527c2bc8820f953abb12007e6e63d7a8e0ab57881d53bfc631662f2fd72ceddd60
fa527ca3a721d42560d97e9e44a8614a5b09f3ae27c320e085620ae5496a5e260b17a
0e4a5fa8c3c51a159fb75c5d982888bb013c1246c6a83c3c728543c872fba066c5d17
5603c5de920a90886acf4dd04403541b198c94e3d94c0e210773679d19e95613ef482
ee2209ae78eb5e1778a0870a389c2fb0566487327b5898c178da53ad329a001103a6f
2b4ec6e0966c665fff16d88b87a83aa267c2be161d1a36a39b7b184828166f721b83e
e15fe4753b05755e000f572ba68b5be4e8f44d5308cebd5ea5d6200553055aca94081
a395b3b3c5610db4183266aa278434215745eb8b407ad65b0fd19c9e0349bb7ab186a
c46a7ef8c5f1f99ec847365627e175c6a2519ea7
KE3: c19b45d2ed3ef74fa67473abda4938c65c1cc3b373bc25fc52e010d8d3891abd
9f82bcb30992d9f72d1bc4239998a83f8209fc07abb8d699d5c6d7a440dd9b86
export_key: 9564a837ea3f29df9558e8cbd67f2d1bd976dc80ef887e1a715096413
a9895658b47a50065d269d641dd6dc7996602e1b86bb8280915d4f64b00f36b1b083a
30
session_key: 6f568b61d594d1ceaacac82c19e79991e147d949f4fd7fc1a26206e8
28bf4e2be222dafb41a52ce25e6121b5170d3a417ef80974a368a62aa11ccc15c63bf
8dc
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
oprf_seed: 161c27188ba2c7ec0a16826e0a73a75017a3b9b9039d35690a5a290503
b6bee971ba1fe40ce056a514b7b6e98576774e437c5b97af64bd06d098ec2c79a1536
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b2d9f14455e6cc806dbb85dcfd0f0f984140e268046c0e619d1ec
306262bfc93
masking_nonce: 4a7edf517d64ca5848c9cd198567da7b663062f96c13d4aae16ee0
7630ee8265
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
server_nonce: 2ddbecce8ed6f5b2cead04c19f0daf63cd35510004a1a63f6d36a93
2d14e7986
client_nonce: 54d2d5bd6e6539e032975ba669a525500a3fcbcbcac903946d90cc5
e9ac69e22
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
oprf_key: 5d27c764fa1d0fdfefc39bc7423742a996583b69a7f38c6b9eb119e35e4
1fdc12769faeccc610dacc09201786e347adec794f5b0fbedd625
~~~

### Intermediate Values

~~~
auth_key: 03341ca63fd557e9dd711f3bae7d65310213d6aa3153982f03fe8b3f856
aed3b5352881fc68936dfbacc8b83d9bf1e966d5ab7d148ec24301d8e89f5f993fe28
random_pwd: 44a6348ec0516ed122517dfa6365f973fc5ae3897fa710bcaeef2a78a
b4f4717382b94eb61a3a1a7612b5423c1d70d15a4ecfad6b5807a541f205988a55bbf
40
envelope: 02b2d9f14455e6cc806dbb85dcfd0f0f984140e268046c0e619d1ec3062
62bfc9318975c173fac968257b6b3555ff65d830aa56522a35d7c3d742fac7df614fd
8c21b3d3411a118e2d9779f98b0c5a458b066380c712880fad77b2faf7e32f4074264
c9a20aca09a51f8e0effbd6c4dda9e939a4d1daf1d52fe738b500758b2f5180186d23
3b4c77e5c1e283bf6fa48fb7d9973b1c6f7fa393
handshake_secret: df9a36b0a9c85b5e00ecaf646de220df9a6d83663a402363906
f40e7ef5784f448a1fbd5b39142e0b626b0f88f0405a87dc72f6f43b3488abcda215a
e86bc732
handshake_encrypt_key: 74add9467a5773529faefbb9f7b743adc20cccb7c1397b
a582bdb14b054839bb5cfde0d190827e48e3c52838d17629681c99b9d67e59880dee9
9fe60177a9761
server_mac_key: cc619d0b094657d87947edebaf0a44df00ae68c1ef7105e1a245e
65ee3bcb0c7e808c1e43e4a020963b8d029b17b94c2c4fd0e4ae7bdf2ffe6ebfdfd80
33cbcf
client_mac_key: 60ef4b8d54c6a4e36403923fdcc4665b57330b52bd2c432c8cb5c
d0b3bd5d58962f52e37799ef2052ec02932df65c50b7139eba97aaeed6426c7402e7f
fc749b
~~~

### Output Values

~~~
registration_request: d287a62ca4d452ff3b5e2d800121dbb5785bb383db9bdb0
c541f8e643443dfe2ddb1162b8b7c758893fde1131a84ae57935e7b60b14058c1
registration_response: e0e9c898b5c4083854a83869011ae5afa28a46b2f4b29a
68c6dd2e94f00b48828011ef6ae7901ce6472c765e806361461097c0fce8ac70aa2ef
8f9560867402d20f9c34942bb26e63d2cc667851473334c6cdf1f89ec0ea218e3ce0f
73f9f1fd303f140bff958f80b7d4dd22a150a0aa
registration_upload: 30b7ffad2fdce2c282ec205685afe5d9e0551773c14c23ec
2af04c13af62b8df5558f6dbd310fd41bb2fb37c8377796be92aaa21bf60f357f2f0e
df922af38b3d9cb2007a5d958b6fce5a6c2eb880e017e23b95fabb1c730edac9a8fac
7c61614c5cd605e5ec4e89a60c251d681f2ad5e06637c04c48ff1a02b2d9f14455e6c
c806dbb85dcfd0f0f984140e268046c0e619d1ec306262bfc9318975c173fac968257
b6b3555ff65d830aa56522a35d7c3d742fac7df614fd8c21b3d3411a118e2d9779f98
b0c5a458b066380c712880fad77b2faf7e32f4074264c9a20aca09a51f8e0effbd6c4
dda9e939a4d1daf1d52fe738b500758b2f5180186d233b4c77e5c1e283bf6fa48fb7d
9973b1c6f7fa393
KE1: e4420dd6be305be0776f14c1140f0b36ca304c007827a8c5b4910c5432dd4caa
6214b4077d4a99e6d6dd7f756bb3531bd010eec2253afd1b54d2d5bd6e6539e032975
ba669a525500a3fcbcbcac903946d90cc5e9ac69e22000968656c6c6f20626f62d878
99f024ee66ed5b8718f9966f2f34dde445da12078789f1e6208028cbc9b7ac7cff5ae
937856aa01321310e1858f0e3b89492e9e49f42
KE2: cae80e4a2bfbbdee773259f27a51828997b7891990c73df674fbcb6045f4c7bc
b18761ef11c0ef248ad2cb049cd2403d317547c1ec5576464a7edf517d64ca5848c9c
d198567da7b663062f96c13d4aae16ee07630ee826515efaab86dcbe116fe4d3a1f78
4c2a6dbe425bec7008c080090c90c099173ebcf639eb3f824632eaa160730702811db
3659f86223d622c3fdbe0562dbbc987e4861479b735018bdf8cda3b86f7ec0e0b2719
6296e27756095dd85637bcdc015cf6fb2f0792c05bfe7b0fea98cec5642166f70c53c
cc73d736567ce20bc59fc790b882721e55c146a4e4f53e0e5da818741125f31dfb68d
bd2e306aa83b05b48d77c7d60d04cae0d672eba5565aec701c36f45b01c9ab441e2e7
1e7b9f472f4d9617952e9035bcae2e5be411d7fb81d11c52ddbecce8ed6f5b2cead04
c19f0daf63cd35510004a1a63f6d36a932d14e798632751cb95f97035f22d498ed57a
8af0d2495075aace642f152442da8485211d6a551142d9bc6771619ecf80ca8b4def3
96f706ce555e2896000f53af7af7d0e6a210bdff9019deaee3bab57f16aae9f32498e
6b360217b2ab378be1ee723da5dcc6b89b35395e6c3a77382d5239c57a70b3f78bc44
89791b6b7bddd58056908fb0366bab1bd166c7e5
KE3: 6cedbc6454bcd755ca71d88b061d7a67a2011ceefd8f30993c924feef46107f2
088c2d5e4da7973acc0f45e9c297e2ac2a8bb1b1a8bf603785b7bc4f57bf525a
export_key: 541b076a39722d131b55b0d305af4ec3edaa0b284e8421d1acc29e79c
9fde09958a188b86c7c7c03f2107cbfb20b99be255cf9c99b0a2a29e457517acd80b3
ca
session_key: f3ea1fc5802d1c5a9c2e1613a409c16b7a132321fcedd30b7131ede9
2ad15f320eb808cedda64591a62273b1bea97cf7acbc02a1d6443081f8cbf2c5f4f22
e7a
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
oprf_seed: 1be3870b801a63f56291c357c4b90ebf3a79924f2f927ac3a1df73dc39
0785b2abd52fa49ac56ce44f37ef1c178cc48dfd5e1a833e9be8fc51e24fba80b9e8f
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: c83d3b4ae73ab2fd0c297c54b7c915bd8920b9b4d3ae72a075f71
f29ffde742d
masking_nonce: 22994ee890e5f487dba2c3b86a6c76cdd1a65984c1cd582ae2aa6e
a72195e3a2
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
server_nonce: dae3345586c7061724600f3493c080c087308d45532c04f9bf2405e
1d6c8f611
client_nonce: 749d6298ac595f85cd735dc6a88c2eee47da62d7c032396ba458254
bbf530985
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
oprf_key: 2a2f2c185d17ff5d1c4d2dd671c77d13aa9f941d91ad12234b904b00239
6c2e6da9066a644c8b827d8af2c32c741b4aba0af85e69afc0623
~~~

### Intermediate Values

~~~
auth_key: af4481e1b4d9412f34349afaeaaf85683321d0a2e5d2a8298c500b9685b
08e8a3094f6344ebc94b173240f68c764d3c41b3340968c5f7f42ebbc6c47055691d3
random_pwd: a0bc414c3d032d52cb12bfff2696bab7f9c79c598616d7e5bead46334
89b401bde4732a0842e900dbd51b69b698bb490db7ba969d2ace464f22fd47cee8af7
31
envelope: 02c83d3b4ae73ab2fd0c297c54b7c915bd8920b9b4d3ae72a075f71f29f
fde742d298f643831f0335ebde21c665656ea471f85dc188503160e14f38d29439a3e
9c0eec7144e89cc0df05800afa922c481e5e1d1c52896c4e27c50af2e870573ac1607
1e72e5da71b44d4f10555f2ed34d1bfc2e3df46bfd597a36b7b19d6ef3f124b104fc0
41349454c6289ce163a68d0134f5f5f78da10661
handshake_secret: 7ff803ee315b51842f13880203d5a605b1567011ffe5fc4eb86
11b71ed335feaa5ed51a5cbe7aa91eb9121338e862b633d5dfb5dbec4b8ae19fe6564
1d82ab53
handshake_encrypt_key: 934b11c43144814b82e08c6a038203d240a03f58b129e0
35c339c1af0b1f162988c627856afec65d639100cb144ec8f5e2bafd7b3aa2aeb8221
30a1fb7ea14d6
server_mac_key: 098f22474a7042493afdc40af5e19921723c05ad6045a60d092e9
1d418b5cbe681fc1bba8fa9428a57f5232878aafee013cee2967db0dcbbb7d04b1a76
877471
client_mac_key: 844704a8c5ab4a08399c3ff2139b90f401d55e4dda09b44f8eef9
b8676e50e033a5c51472b812d1fcd639bd30370090d1c6712c890fea6eab78b7c28ad
4bfa69
~~~

### Output Values

~~~
registration_request: cc1b854bfac5f36d7f09d18975d26bd031490a8810722e5
e84d13320bc6cc1ad88f2faefeeb84ac706985e2784da104dcfa376ea200241d6
registration_response: 10a5ce760d890127fb10c3eca3cbc3d3514ada25ce8b28
badcb336e9633651775f071a1fd45c9dbddf7f66f48ecb96c10e9c439f6b19bfd0bcd
8a3897346eb85679f52067ff50f69dfb9fc0ae776fcac93c99e1e9dc14db5c9c26b09
e1980f7f5b45774012be6234ac5a8953ff69ef28
registration_upload: 06b7fb8ec9beee7a168a7a820bd710d1b72d05a433fcf53e
5f4ee0a2a5c3a1d48d16121594b272656efcc614aff77386030ae72e47d948ef44d48
97ff027dc60dcb12811c113d304690f3db4908db96b3b9cb3f101f36748f92a8fafa7
005937eea0872266e70a9a7a8a2cc7afecfc831653e741d8df395802c83d3b4ae73ab
2fd0c297c54b7c915bd8920b9b4d3ae72a075f71f29ffde742d298f643831f0335ebd
e21c665656ea471f85dc188503160e14f38d29439a3e9c0eec7144e89cc0df05800af
a922c481e5e1d1c52896c4e27c50af2e870573ac16071e72e5da71b44d4f10555f2ed
34d1bfc2e3df46bfd597a36b7b19d6ef3f124b104fc041349454c6289ce163a68d013
4f5f5f78da10661
KE1: 8447080996dd1f729709b137aa45b6a6e68651f7f5794ec80d7aabca6f171226
e8c5ac7aadfe6b9ace4bc355d7b891907d50282031c15d9f749d6298ac595f85cd735
dc6a88c2eee47da62d7c032396ba458254bbf530985000968656c6c6f20626f626e09
74f24da70adf24d24b5e267c80f6335a5cba9442a5658cdb76b3a2bc569d39ec6fedc
1a162f4e6c6a460b0978684aa5f30b3304cf04c
KE2: c862d89c70adc455b977246652933bddc08166a03f8bb20aceefe1fd11ea7f90
21ced06b2846261a4cb3dd5fa69acdcbf3a499448aaba43822994ee890e5f487dba2c
3b86a6c76cdd1a65984c1cd582ae2aa6ea72195e3a27d592171b52af4c954b7e0a8c2
0e384c94b37b74e56670c7354f5c199eb496cde26f838b38a435bbced23c930ae7825
3afdd500ad03ecddae34bb461fc7645799119915b8be44162198f46299e594a97e859
a25e6375b953efc6768064a7e3d5375a6ceb4cae96294a79f1ca160c6e407357c5a24
abd11479b3738ac39c18a0487a0a5fec480e5739c1f582a5ffca104159dbeb643e97f
832c3c4291d6061cf1ee2e74d615e1132156eddf878cbbfe4511601542117366014cd
d7ee684dea5aa509cbc7a45760da3577e4a11cfaa5be54ddae3345586c7061724600f
3493c080c087308d45532c04f9bf2405e1d6c8f6113ab8469c97f3394c729de0b4f98
0ac06ea6a90dd077f924aac4210ce65521a90aa1ed82f46ad5cd948d1d96a179409a0
20f8a01cc86cb7b2000f3f883a4192bbcee36c752953c979f2977834be8f76eb8312a
d4a86ec66eda882e29aa5df76bb325f1fcb5e6b56311f871f4a00ee2d492f3dd9bb06
adda1816e39675b762c17192a5e34d56c9bfb165
KE3: 2162ac22baeb669826b98e3bf59c412fe59c6e8608fbb5873c4e515e127ddfb8
07e3c5d4f1f1c6ceebde3ca7c19bb46784823c28dc9f33174f3438785be7b48a
export_key: a965ee5216c42b35faf75a407763eacd8498374c83a59ef3ca13be619
a65d71ab4ed4aac40bc20e3602bd9a79f3dfea1cae0aa4d1f0a9e53ebb8d11bb37ce9
d4
session_key: 8ec5cdb9c5adabe57169e5b3a632eb394cac402db21b65016f947a7a
93f1f63102eafad5f0ec6baf5a4f69d4277c06c5e18dd2b56a292029ce60dd4c9efa9
c2a
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
oprf_seed: 9c27e9b40ab198a945c32c2dc2a2695c091750a2690453b97aee490429
725747302f84464b2fa8313adcfbd0bc687389ab98e03aceabc59d59b17eb8ea0e5bc
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 8609f860a805cfa29550523156484fca633d2f29aee2d1c4bfdb2
ccd8be04776
masking_nonce: 195e4fadc8e0dfc4a57a2794d930dded3bbd99853e1c36a01a1f7e
18f5c0900f
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
server_nonce: 3ba7e831213faa68b84f9af8b6bc20d505531b480c82c075bb577b1
0e17b04f6
client_nonce: 428c72244e32b6e2edc36ef425eb50d1bde4b19432059bc21ce0841
8d9738bac
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
oprf_key: 96dc81063186f04e1763b4420415dc5191cee1816558c20278783ddceb8
db0d9d2c059eecf5206ba92e7991e8e196f243058ae7f33190408
~~~

### Intermediate Values

~~~
auth_key: 13d7507991e84abf99d1ed1b392bd4378faf46b9b513ff427585e7a015b
146f52c1f999eeb36f0d3c62140b420c7f85f0d22afca48891d300330ea4c8a8cab9c
random_pwd: 22129feb37615d0277f3cfaa4e71d655a44146f8a4d497b772789c5dd
6572f746a126e7a98ee15ef88fade37a6fa381a956c03f38dcfb7e4f4b2f1bf8e7926
93
envelope: 028609f860a805cfa29550523156484fca633d2f29aee2d1c4bfdb2ccd8
be04776446d625bad64e9f708c864a090d445f055a1ef93234b67e126c44aac0fdaa3
ff30692ba5ab12004cfaf0c2a10f7ce86d53839e65daaba41df9778beac269fbdce1f
c039ceb9c87fd6494b312d53e7363771aecd08be5e255b2ad54d74e7bbbb3ccec614b
4376451c4750659ede656ea480d7053aa12f360a
handshake_secret: d79a55b82b41f4824e6d6afeab3e70887cfe2b18b6064edf1e3
7570bb5a01bffeae82dab229dd845553854c3d272c96dd4b7119c7da97d7c71dd1d55
eebf3cc5
handshake_encrypt_key: 8881c78bca89b339769b1399fcdfd5faa4fafbeb07e558
b45ccd182c6046b7cb7f2fe64eecdb6374442d8573c40af9db2f6816268d2e12b279a
fff298350babb
server_mac_key: d3410c44cee6160702b1643361196fc78d368c9477e961eafa626
0101c59fc8c78afec86a648b8210e8db2a57462a49b7e74aae099354f19b7baabca7d
429189
client_mac_key: a438584f4fd942bb0f4f73a7bfcda3dbe5bdeea8ba80ceadd4c5f
28631071f742484a40402be6d33379ff5eabfe49df77a771599aa5c79d7c94bf1cf02
0223a0
~~~

### Output Values

~~~
registration_request: 88c032a418dfb1e1cd1a3324ba5992452f93c66edbec9c3
65e92c1ea793cf76c05ae910ae194ca9c51e885d3c2bcba7d76989d0d824ace6e
registration_response: 082a84f6f37d542ee65e0eccb42bd895a6b66029865056
cee3cdedfc7c365df681e9842f8c44f7b33c28c5eacd63bb2e75d5810607bb05f89cc
2b31fb6677ce38ad340c70ad2a48fb8a11dfff6537994a8e42262e63634ec59d0431f
3878051eca9888bb45c17a68359bb55071e6f6e7
registration_upload: 7a9df676f00d588a90e562ab1ddb58fc1a860a3e6b6abcf0
c40dd4f64a94c634a1dd46ab02d02ca293f601406d881538bcc122cc61844549daffd
43ce3d5a98b2a308685d147e9942c5999309f7d79424df0f1b0f4db64ca7869627589
4af810153f66777f8ab63274c4502d8361f119fd8a94c939556abe028609f860a805c
fa29550523156484fca633d2f29aee2d1c4bfdb2ccd8be04776446d625bad64e9f708
c864a090d445f055a1ef93234b67e126c44aac0fdaa3ff30692ba5ab12004cfaf0c2a
10f7ce86d53839e65daaba41df9778beac269fbdce1fc039ceb9c87fd6494b312d53e
7363771aecd08be5e255b2ad54d74e7bbbb3ccec614b4376451c4750659ede656ea48
0d7053aa12f360a
KE1: b4f7627e7bdcfa7d9112301dd0081a3f51cf7e8853eb48a16c9078aeb0dd99b1
6e691ec45b6dacb2dc05b62f0e09c124c94b1b5390a68abf428c72244e32b6e2edc36
ef425eb50d1bde4b19432059bc21ce08418d9738bac000968656c6c6f20626f62b8de
36842175636d346164767aa834a4bd1a0abe805678ced43406c4a09ce40145f03cd1d
620d6b3932243017098851f7003f34a849e6c46
KE2: 2e605b27e8744ab1e9fae3ebf412f57b23bf4c2cf774f360fc002e91e55e2f84
3bba005fbbda8f219d4548d1ac3cec11cfe16605b1eaeb16195e4fadc8e0dfc4a57a2
794d930dded3bbd99853e1c36a01a1f7e18f5c0900fe0c5dd533302552a016ba71fb8
977503b6fe972717b51bdf8386f8f35025d49308e078d4d899be94f6fef7ee8b93250
15bd8498027e7524cab58a1bd7783e2f23a7afc8a615b03bd4b11bd9d120d91077a72
1e101e1ed7cad9eaa403783f08d9b15d08582544ce2df22184b36f6188c3af4a7a932
339c7484b1f72bccb1bfd06a1521533bd29a90da1890764cef6725629b98daa88f114
44856ad4114bbefad1af3a9dd3306bc648ea4d90cec15272ab08f82af639596dede4b
8886ab647031241bf9f3387dca5f908316a5c9c201d45453ba7e831213faa68b84f9a
f8b6bc20d505531b480c82c075bb577b10e17b04f6b886b2c735272aa37e700b602ed
cdfcf53f73ae463d94139dfd0e173feda40f8ec315c59dabf8b7db0a77cf9c3e5b352
8688b01849fd3523000f30a4a9abcf622f1b020500dd77e3aab3ce8edccd28346e909
6c2692d2fdd4bc0dbb9b47c4f75931bcc9a5f887ca5577058c61dccedd79e88275df3
75e5d5208d482298fcedbedb53b1b48877918b7c
KE3: df1d7f620bf88a8bfbf982bc41156606877ce59da7395576ce70ce1706a2825a
1d47bb4aca3801ab5b0efb8b46b884f0464f2a31f67df4062c90cc0c47572be9
export_key: 2d9cd1d8fc2213f2886d6dc0416094c70ea124f7513c02aab377be492
d850af1e90ed49caf5b4df75b247cd1bdfc993106c05b159eb4d3669d3beb59b18f76
30
session_key: 66f4a8a03ab0c9790ac81eac2f5b341094dcfb7c60126bcfe7dbe19c
69197f07ffc7d046e2626dd4edd504c9950655d976ead13e28a4cb4bbe35de6ae024d
455
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
oprf_seed: 976b1f628f1bc5b4fb502171c3370f730f2e3dd87e3037376fb6d7151d
709161
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4bc7b399de40cde0dc506c6267f952a09b0388ae7a2f3359aabd3
78bc7a47e9f
masking_nonce: 3dd3ba233e8c03aff061c7c73ef96ba6933a0d1a3f988615cd7b2a
e661bc58c2
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
server_nonce: 851b6d0908057295ee98ddc3ddc6c889d432005ed2803aa5b4146bb
884cef4da
client_nonce: d4a3460b4798ce4a946b58d76947a6729e81fcc65e281a7577f6b0f
9e55fdcf5
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
oprf_key: 4b90ac5b2c226481edc8f88c081f2ede7d80db76aea6e238e51a7b322d3
eaa39
~~~

### Intermediate Values

~~~
auth_key: 6c05346f1d44cdcf02517342e85f53552a9cb9cc257e38e6e74cb363f3a
8e849
random_pwd: 9ca637a0bdc7f5ae80eb1676b9e17735f326a72fbd3c8b8d7546c0549
607e7ff
envelope: 024bc7b399de40cde0dc506c6267f952a09b0388ae7a2f3359aabd378bc
7a47e9f680dffe2bc76720bd9c96aa785f25a4a42ed3a72d39ac2187c36c08c908ac4
d4f0670d2a87093d4aaa71120b9b4407ce4b7ce131ef0f0da10b4f2a3749f848c8
handshake_secret: 741b0b02969f13a8227236f037074b553701eaba5ac4b855fde
deb10e2efb19b
handshake_encrypt_key: 99fced644d56e5e5a01c57abfddcfc38dda1afc9fc6014
5c380cc551cc66a4b1
server_mac_key: 46bf8743c290d24fe8a0543ac6f8a4ae5cf5033856c16a43ff57b
8bc79b05fca
client_mac_key: e0b23256e9fa76d7cc93060488c14d461de8dba50fbe1d9fb9dbd
c232838d340
~~~

### Output Values

~~~
registration_request: 039ae9435af572249db38975b192f1beeac30ed093c4d9f
40bb5236d3521035ab9
registration_response: 037c4c2b525b3599af79a47244495ba30489c9106c9588
4a94bcb91ba79d5844dd02c136a2fc727c674b2e49783d5a79bee0c6ff8ccee9190d1
bf7dafca0807eb046
registration_upload: 02ea5098f6b7283d5481f1500a7b589214499b26484c4430
b52d36b1ccc475cc8db1e897f4d3e1727ca20a547538ba3a7303cac22742ade042b65
f924312b229ac024bc7b399de40cde0dc506c6267f952a09b0388ae7a2f3359aabd37
8bc7a47e9f680dffe2bc76720bd9c96aa785f25a4a42ed3a72d39ac2187c36c08c908
ac4d4f0670d2a87093d4aaa71120b9b4407ce4b7ce131ef0f0da10b4f2a3749f848c8
KE1: 03f86d270a693da19f82b655d8ffe6a26ac2b79ef779de92012d7fad3e15a7d1
5dd4a3460b4798ce4a946b58d76947a6729e81fcc65e281a7577f6b0f9e55fdcf5000
968656c6c6f20626f6202496d129c40fe6d255d57f6d92af5c0cf0ba277e8a0e7b67a
61df2dccd9b02c5f
KE2: 03c4b7795afb634f4bc4213d7eb5c0ae409e094d1a34e452983a1372d2f42e69
313dd3ba233e8c03aff061c7c73ef96ba6933a0d1a3f988615cd7b2ae661bc58c2c06
78f019d6e8b6bcaefc09159e3431fb8e4790dfcf938b4de9a2b3eca2a9e34dd66bb63
0aca3dbaac7e7d30ebecf45dbb505ae3c5bcee3227ca90ffccd63d1e39502d2bf1233
3c1e63d86f1b86b7a5124a3061b71c74b30ad077add21a6912efb2c25bf63e50d9cca
3dfade5e6a285dffd1d52f1c07695b2f032eca13ed06c683e0851b6d0908057295ee9
8ddc3ddc6c889d432005ed2803aa5b4146bb884cef4da02c5583ec9a10dfa32344fe8
000007904dacd5e6be9eef27b0f94b50605b017126000f438248b747da20b94e8c964
3f8c7566ad9625efe0375473ede705c0293685c79f3e382619f4a89d0a179673238ed
8d
KE3: 909e9edda3e3fed13caa9bba46af6bd181b751b24384c2c944e1041bb707114c
export_key: ff2d5018452a4369e99ea2c2a895d15b5793ba901d196527891f14d95
d13dd7d
session_key: 36f00d739f52fe6fb00922ecd568287dee57c6adc04c65421d52b7a4
0f669634
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
oprf_seed: 058b349dda417ea35fa8ade6d1dd35bb8c90b6a3160a6c76440e52696c
585d3b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ae32c8dd03de55d1ad271c599f3f34bdef493cc0ff03203b4d923
1eb2a0bbe3f
masking_nonce: f6b16baa6cea6e6aeb3de0d00c45d46c0517c95ea0cd6971bc3722
1994b2d868
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
server_nonce: 1821e9aabc29dcabad42f38372c7c136acef29012bcbc703c5b9f4d
beef29e16
client_nonce: 527ca21687accea99ea1ea4ee79ebc2ef512fb1ae4a84c0d7721780
05c118d25
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
oprf_key: 484ea6560967618b29b794809cce634343fcb79fbb7b59619cb7ab83ba2
0d15d
~~~

### Intermediate Values

~~~
auth_key: a449ed408c2711359a458370fdb2c5054d74940bbe554bbe53b706d9813
4b148
random_pwd: 6fd5e0e7c6f028abae17d4f72afb6e0775864c518828a2e38db5438e4
e227eff
envelope: 02ae32c8dd03de55d1ad271c599f3f34bdef493cc0ff03203b4d9231eb2
a0bbe3fb7b92e49ca1e2a3988e89099a0b3d56928e4808d5b8331fb5a0065a8a04a6d
8b4402a1f73dacd1178916fdeb6b99c71930166bb9f2e5f63e2809e379e8d5679e
handshake_secret: 2900ff5812081762242729cbcd148e58030a3c04a0f3eaa7e0c
df7c8897b0b30
handshake_encrypt_key: b812407832f04d819a8320cda3e7b1b815ffa6a34ef27f
6a12d4b8d0b42ae4a4
server_mac_key: 46be5c9f6f4a831a58e5bd4e815a4fa2711ee58545d363c43c3fb
48488c480b0
client_mac_key: af8286e234a0b66a62b6450bbe4a2501da84f5db9618223c6a9ef
a8a9c441c03
~~~

### Output Values

~~~
registration_request: 037a055d502f2a882c021fda1ec2fe8e5d8cd0d2a913e5a
03b1e27e0fd06308275
registration_response: 02ed5fbd8eaeeb0bb4cfdee090afb4dba19bb53d54fc5d
7999ecfa145ae2d58bef02e1249c0906886b33b0ae59c981001448f2541fb718a158c
4b4f37d391e813fed
registration_upload: 028ed3215a26f2763d4f9211ab13c415ba0e228fea364a26
4e65baa2434709f80870236f91ec31dd7994ae2cdb21a8fa03104b23bb4093bbca150
2d8afa5e2310902ae32c8dd03de55d1ad271c599f3f34bdef493cc0ff03203b4d9231
eb2a0bbe3fb7b92e49ca1e2a3988e89099a0b3d56928e4808d5b8331fb5a0065a8a04
a6d8b4402a1f73dacd1178916fdeb6b99c71930166bb9f2e5f63e2809e379e8d5679e
KE1: 02e532d2687a979f0a75112437e1f4c6d5411c555b2330a8d6c45c7c7c657aeb
b9527ca21687accea99ea1ea4ee79ebc2ef512fb1ae4a84c0d772178005c118d25000
968656c6c6f20626f62026ec987d3b7ea3ef8cfdca092b9d6994d134e933a5fb78929
5335d5f6956399b6
KE2: 03379f8a2ab0f3fddc8cde9a14121e858baf0eb3496ca0bf0843a6f547f1525c
2ef6b16baa6cea6e6aeb3de0d00c45d46c0517c95ea0cd6971bc37221994b2d868d03
96377d65c5db67ba5c98b5a4e5ae0702de659eafb9caebdf217ca085e45422c5cae11
91fb9b760b263575c769f8e57b26fbd8d83e7255effe794f7156dc6c3091681485cf8
454926fc88014d040cc36a9fb63663d6d9fdde6634a4b95d0283d6fb95e8e25159d72
b0d3d0dabe03ae063a2fa07fffaa18b7559364429703e86df01821e9aabc29dcabad4
2f38372c7c136acef29012bcbc703c5b9f4dbeef29e1602178e9554d669786c2e9349
f1e178eb84961a7f8073d9ecbc5cf52bc2fef7791f000f4aa48f170ba4d206e4c0688
ae05cade28663c9bf1eb69994df1c13ddde5ac765f65dc5d4e8f7f7ce3cf87fbadd5b
3b
KE3: 70d67e1d53775a975d9b449dad9af5a2d19444781662e4109e3c764498f795bf
export_key: 5d51d48ac8e1f21bd743924b0be04a4540d6d6873261c508ae1330ac8
73da583
session_key: e384fe34a0a6b6c122aa277f5405dfc83a76fe6d68a90e457d1a8ab5
fe8cfd76
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
oprf_seed: 9e1b789bc4e9b77cc3694a002c51bec41fd6c592eb69ffd4c57a9b7c4b
adafee
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 9a6f3b07f8ae3c374694999c3fa7d4913a9fd10ed8407acbfe73c
356eeaf8150
masking_nonce: 344b8ff1ee5ad48e64225568e68a70423cf5f0d60195a0941a9426
6d9877d01f
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
server_nonce: 0feff10674acc44f15cee714a4d73791fa9dea0fc3c5cc3ccce1502
38d5e6bc1
client_nonce: 28b96a3186102967e9ba7259177a5d37c958cf14412549dc2294ec5
ca122b34b
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
oprf_key: 4c2e5222acc2d235dd344c3c7d994f895302bd24305ccb7eec09c3fd587
97ce0
~~~

### Intermediate Values

~~~
auth_key: b98bc4520e616b68a48fce5839e98ae1a426aef47a59026ebfa84378a97
1e43b
random_pwd: 7c41d98efa0054d6f7a2cf857cbbe38df4c3fa657f2fbde52745bce49
5629fcf
envelope: 029a6f3b07f8ae3c374694999c3fa7d4913a9fd10ed8407acbfe73c356e
eaf81507c23c6349384fb694c87de42aa22b38f3a81361e8d3a0f540339ddfc6375a9
5f30ad47ce8093d5afa64899af1ea77b0d3eaadd7a216a441b393c32bbda554e7a
handshake_secret: 62274f7b7576b1f2aa4d5b8a5482805d7135d1729e5c18ac6cc
97b1b2ba859bb
handshake_encrypt_key: 5c3210aeba665191a57abb64c2ec641b3fa27a24ec49fd
fa97a8a9ff40c24718
server_mac_key: 81a3081b5baef22c4ed3667d78f55e1b9f6d0a9a570eda4c3efca
b3121f55fc2
client_mac_key: 25e5f57cc2a554ee85ff40dc77dc9bd4edd880a1b49fd1904524a
97cde012072
~~~

### Output Values

~~~
registration_request: 029ead8cb71d9f802fc71737e16f75eda7843e5b961c9ef
0bdf8da0cb97a6364db
registration_response: 03aa66fe0c40f2abc683a7596bb62e43cf2011a61b99b1
577f6e07c073575d1118025cbaa4ddfc060bb49a281a97663ce9e20bfdcd9d11bb10a
25b74538d149fc226
registration_upload: 031049be572a6e15f68e2d758a7ca7926e7ff85ab351ce2b
003b652dc03e8b5304b9fb02b3378fb2dbd56906f6d983af4199b0a6838e361f4cc4d
d791f52f73c29029a6f3b07f8ae3c374694999c3fa7d4913a9fd10ed8407acbfe73c3
56eeaf81507c23c6349384fb694c87de42aa22b38f3a81361e8d3a0f540339ddfc637
5a95f30ad47ce8093d5afa64899af1ea77b0d3eaadd7a216a441b393c32bbda554e7a
KE1: 03fbe22a5b37f7345b2370c51a5290091f5af7b21cea757ca017b2a32279b543
f628b96a3186102967e9ba7259177a5d37c958cf14412549dc2294ec5ca122b34b000
968656c6c6f20626f6202736055b3c97c36bc8e7bfe53ae65bc38c5be6b46adf3d486
81df7bcfeb96770a
KE2: 029c8893ae992e1aae5e0826b80b72b1169cd83393607b43aa78b44ea5dd8a13
eb344b8ff1ee5ad48e64225568e68a70423cf5f0d60195a0941a94266d9877d01fa47
b514e804c2250ad6b9febe2194ad53367c73e4729df33cc685615975359986c568248
fde12cac6f42be7fa43a6840062a00d217b2063c09f2cc78c1aa0f645d3dd8c81c479
de6cd8af4d3d216a19cb18f0a62aa82831690cd57bacd2c4d96e965fdf1263b78687f
07b3fb17561ce23909eaac6a26b19c2be0b21735db66c24e040feff10674acc44f15c
ee714a4d73791fa9dea0fc3c5cc3ccce150238d5e6bc103981bb9a42c6f60750d2c90
98ec0e64d52dc1ef0b4d02a20b2ae9ce40b425a389000fa45375ba5e29fe773c899cf
e95f8d2c26221d2fd4f405b45331dc2f3545d205f38d53c60bed56bd89e4069cbce97
b4
KE3: 4d8796a6045d697bdc929769d988678c3c65122eda3eb0c00d64a06d5764b902
export_key: 429efe9b0290c3aa764264396a978482992b52da97ac0b3f147f5b89a
0e278af
session_key: fb54d003541befd33b6e3640080a57524e82057d8bd0b2e35229e0a2
a406bdea
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
oprf_seed: ce6584461400dcbda3c8e2b30a98a68f8c7aa889855a681405cadb2beb
03cfcb
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 172d8af4c95f4d0c7843c5a16a27db0f37fc5507d4a7f573f2941
bf9b9d83e20
masking_nonce: 06c97c30c1cb4bf86ac4e122a59c1cf9e8f7470021f37e2efe77cd
ee31cd22d3
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
server_nonce: e9e7f6baa4307cf9636f9f45e4c8e235933ac3f64e3dcc6af653658
2d75d4409
client_nonce: 9f8fdc33b656214f66997fdc2e7f6b28b5dff4c8c50befbd65ffcb7
4789b3834
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
oprf_key: 7e66e667f7223b202e60a90f1fe8eb3a6cd4afd4ca59ecc36b16a02064c
8c963
~~~

### Intermediate Values

~~~
auth_key: 298a79ce43388c3d34e1a1347270d5fc3632cd4465c3fc12dc73c20d47f
be58e
random_pwd: ca9177122d96ff9f26f3d9c9d96a95b1dbdfc8f014906b188866f1c1a
2700aa9
envelope: 02172d8af4c95f4d0c7843c5a16a27db0f37fc5507d4a7f573f2941bf9b
9d83e2085f7429a1853a075b75bf86b98a8b36001c4f89556f0e0800b604efeb14867
8ece3685e67d2cbb41befcaf4f10d7e4762a04d412341b1050b78f9776abb86a86
handshake_secret: 9637f0827d46145770fba58bd374f7f18608e281ffc3bee2f95
826d8116ff35b
handshake_encrypt_key: 5fb34ec6ac3d25bdb32b52422c5df0bdfc806fa9a756fa
2652974324fb7ca2b4
server_mac_key: 75af63b31186125d566bdc7281a16bcfedae3163526148dd90382
a9a17657818
client_mac_key: ea4663b1d51a29b11131763564372a7bf365810f4625b7a3af117
f1f38d73ff2
~~~

### Output Values

~~~
registration_request: 024ff8b8c3636b93127c0c5350c4d2e64b47c78837d6edd
ece7dd67a260bde8085
registration_response: 03004de148343d294f3b69e55e0a2f0fdc962fbcbbc63f
35e8c74891f3f9ce0c3e0249b8ed908a9b67d5f5f2f409502ad1b0e08b5dda755c15c
5e37937a9187772af
registration_upload: 02148f47b6a57019ddb58b5f1feaeefccd9f5e979c1364f8
9ada3ab1d4b3f89098017cee00a0cdb7c8580f1f8efd0f364536a02b9d6ce83ec07df
0607f00476c6602172d8af4c95f4d0c7843c5a16a27db0f37fc5507d4a7f573f2941b
f9b9d83e2085f7429a1853a075b75bf86b98a8b36001c4f89556f0e0800b604efeb14
8678ece3685e67d2cbb41befcaf4f10d7e4762a04d412341b1050b78f9776abb86a86
KE1: 027694e256efc51327333fba8ab1927b511c4152f93ddb0771370995407b4b25
fe9f8fdc33b656214f66997fdc2e7f6b28b5dff4c8c50befbd65ffcb74789b3834000
968656c6c6f20626f6203eeb46969c8d3c0ff2160547e2ab719958b7e8686ca4d9b12
f604883194bb90a1
KE2: 024cf5a3bae4c617bcc91bc10d99ba643f5040d6bec3d259cd68e62021ab3224
7306c97c30c1cb4bf86ac4e122a59c1cf9e8f7470021f37e2efe77cdee31cd22d360d
b3228cd17498ed2361c634cb7fea3544b2c35765ef14e41e38cc2a3a954d8917a4762
15c84cb8cd93fa4c0d3675d066511584c765ac05290b1fdc51d91693df37aabf3a41a
9718bdb89bf9e482aacdabc08a125fed5549eb5fff4cbb38374bb4e07bc725f048760
fd7e9a71373aafe0ccf86b899358b4ee28321c6ef9286acd17e9e7f6baa4307cf9636
f9f45e4c8e235933ac3f64e3dcc6af6536582d75d440903a05823236f8f28bd60569e
51b83712e6371b7006059bb8542216c9b9ec73ae8a000f88d2b3af73005845b517a3a
3563baec06c808af55fe5b3a97ab6f21ca0c83cc0f8ea36a027a39e41507318bfbe11
67
KE3: 6529d6f179e60b8056c1527c95c77f82a7273ac94a2c386eafc8250f88075d45
export_key: 8b4bda5931ae5e68d6437f23c04e139f2688a44708f25c7964cbc2029
f2478c2
session_key: f0295858d8501ed08987b718849ff440c8b0e28d640261abc48ba6f2
a7a70e9a
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
oprf_seed: 86f8aab812d0dd7f52d14240d26ecf810fe9dba46d0947bcfeb17e8478
49e84c11f41cf75136f8deb9a33afc943f6082898f6fb7009bfbf1594e4439f9fe075
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 99bef65b0a57153cd16cd0f85c5b2443003ccbaeb5126f5595185
226992c782b
masking_nonce: 3323efb149aa44b330e66e8f4f14cd0c63ae429d1fe4b3496a6681
a06403603d
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
server_nonce: 58a03f1998dc7973a25056f4e3c747e8fa0b2bf8931baf3f478bbb5
17e2ea03e
client_nonce: e5b6b52366e683cc7ebbf164f0add4c9b7b34630a1448dd4588196a
f8c2149a6
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
oprf_key: b20794ef2046362c1c2bf50370483735a7b3cbe23da3f599bc8a0349b32
3637f6dabe1d1c7f7ae728c78f32406fb013a
~~~

### Intermediate Values

~~~
auth_key: d83d6dfbb42cfa86f12d737beeb31464a4b47002c035aa7e17281ee3383
3b8f9e5cc27d0cef723207da0e0898fa9c7c1b03a077fe247022697d0b6db220989bd
random_pwd: a5360be58fcbbf66b19613fb65734469976b6cf1484239e5dfd795f7b
54299ded9fe0a3c695b77c3e8a62724d2769498aaf21a89d1df2f11a2a937bd7ba8f8
59
envelope: 0299bef65b0a57153cd16cd0f85c5b2443003ccbaeb5126f55951852269
92c782b78a0419fa8e426affc0f5e68c1ddb40af918dbc57355f09b9a500cdff7e63d
8ebfae60b2292597cebd2a9cff356c8dc2d47fabded8b98c220c09908a17e60cab71b
ee9938735df0c503f803e5172c7959911e1ad5cf60b0b6e45b30394f9835b90939a51
043fd1e2125f4971bd5f6922
handshake_secret: b1cf5a9e69354c8fb2deb6db4a5070b0409af104978e39a0c98
f50c0f9c177e20d9a1cbb4fa076bc54b0b86cefef647cb008e03c9e6ab5f9dd2f9c7d
6c7c64a4
handshake_encrypt_key: 9ad35a27404b68e509ebccf993af5f2031c69390952fa2
fcf33f5b4057e6e2c3ed07922ea9ddf5ce2f1e29264b7ff0102d1a59875e397c1d890
f94cf49ad3b60
server_mac_key: 30ddb396173dd9f0790fe400e7a9c2e80245919a75656557bff36
727cbd122a0fa672179c289105bc63388c4eb3c65645bb1b8fabb94c2771accfc8989
9b12a8
client_mac_key: 25a7a054c44bf37f1363121a37aaf96da5e3f2e6190758f2e3467
5b3c4dff654a4725290681bc65358f0ba01fe73206502e29aa875c0d93055352af587
edaf3f
~~~

### Output Values

~~~
registration_request: 032b5a44024063a5644913f145e01c5b787a77804a5ec25
588320d5ecea9d524c1f9321b9ae76a6bc168b1f99e7305b9ec
registration_response: 02a822166cdc5744a5df3017417c91db58cd6cabda82dd
1a8eb2decb041647e22915afb7a668ccb5a9bdbb6829c3058d3302094306eaa9c62c5
a873fee4afdf81c91a91556be8286e7c8f5fadc077f810adb6bb760faf2e46f85cb0b
7649ebdfc524
registration_upload: 0215d10d7067b3567d5a7ae9317329da934296ce40fc0132
f22abd78a05172adde74d97f453b902fb2c454718c91fe403e9b41baf524620b175b6
af026e6097e256f0df04e0170ed01835c59a48faaee00129556dca6f33a05cbf09a11
19d848b3e3a1d591ecb6067995126ed414ade0140299bef65b0a57153cd16cd0f85c5
b2443003ccbaeb5126f5595185226992c782b78a0419fa8e426affc0f5e68c1ddb40a
f918dbc57355f09b9a500cdff7e63d8ebfae60b2292597cebd2a9cff356c8dc2d47fa
bded8b98c220c09908a17e60cab71bee9938735df0c503f803e5172c7959911e1ad5c
f60b0b6e45b30394f9835b90939a51043fd1e2125f4971bd5f6922
KE1: 03cc36ccf48d3e8018af55ce86c309bf23f2789bac1bc8f6b4163fc107fbbc47
b92184dbba18bc9b984f29c7730463fba9e5b6b52366e683cc7ebbf164f0add4c9b7b
34630a1448dd4588196af8c2149a6000968656c6c6f20626f6203f58c4669321d580f
98b4b166fbccd6da300ef7c4f0fe19d5576d3debceb23e50b5405ac264c31691e4517
154d993fbe1
KE2: 03db922060e76fc773f444a56e7c247a5f169bfba56a0f2e01401798df8f70c2
2f29954d63305d9f25da1e54d117f079413323efb149aa44b330e66e8f4f14cd0c63a
e429d1fe4b3496a6681a06403603d73a10878709d76dd9d0e91ed186a4741147b498d
2925f5c8b7c9ac6b847d4a0d6e60f98e1133b50d504a9d823b0835e6c300a8b7c3eeb
d455a783c47aeb9115ae29a0245358c73414748ba15daa24434fc6ffe304cd3fd52cf
2cd29c878d47012f838d8cb72d23f71799c64e82faef12072671a8e3426affd442830
9cbb76d2721afec997e45022fe3fe32448dc601aee146172518768ec349e8fa7f35e5
a0cef4e50cc90bcdb3770aad33805c951892e6551aacb75847574883b3f9b8f355301
9be58a03f1998dc7973a25056f4e3c747e8fa0b2bf8931baf3f478bbb517e2ea03e02
18bb6548593c38236dd6991a1c556a5cfa81be6c235891e5a00cf4eef1bb3ab6d653e
03abcfe1634908971d19b9959f7000f2ea02f0b1290b221c4710cf06e32799844bfa5
eb7fa613b3f70bd7108332f4335f6df4483235feb1fc9514f8ff3be4a6b91f263d65c
3734947e953b1ed6dbfd521eddc57023b2a8ecd5efdf1310bee
KE3: 19ca87f49bcb9ce6e30ad3d214633b972496ebb1afdd593bb8f94cd9fe86a8fb
14a1585945f2eabf506f431a70038ea86334c2cffc4fa99932785bf178393867
export_key: d1e8c4ba661fb37e345b9ddf4cf4b83d304c210c8095a357ad96542b5
1d3ffce95d877274a0c5a41f55f542fa80a746cf7539486b3f5700de9f9e583aaa1fb
4f
session_key: 10fe61bdf2ae4c95dab647ca06787333d78f074ca743c5d6d02abc69
c12c2275f72a9497f2be73e2204b0b8049eab6052fda17c8969f9d82b903914182a0d
311
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
oprf_seed: b89ecfb19e18fb4ecd2316f507c8a2a94473aad2795157cd11658ca88f
5d361ee1af8e7396204d1e4d8e6069b482d206b0c396c86c041260f5ed500dc3e2fb6
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 6f14a54d8d747c1920ac346ff2df10c3250151826ec85e0e40160
88587596c6e
masking_nonce: cf8dabdc7be8e9d12e9a0c74540f9a4dbb61df5d8f542d4317d2bc
50adaadc85
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
server_nonce: 1a335c37bed10932dd1160ef9a221e08632b79b6d5b951f207c0657
3e6c6a9c6
client_nonce: 872e84d6a39cdd15899d68d31dc05366057dad5f76be2e248ba0a8d
751ced9ee
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
oprf_key: 376c378d28df9e5390ad5eb95e0718f8698847a7c020d24699bc21d9401
9a086c25170a6494ef7e918f809aefc519841
~~~

### Intermediate Values

~~~
auth_key: e4a332aa81707de7387ccb178772ae50836bad67eee99da4031937280fa
af5ea3cff2935ff6fc80b258733b1d91e0481c80c0a31aa97b095359bf287d2e4698f
random_pwd: 371bc9aaa2c05830cc2b1f5d3f65ab6daaecd2ba46cd1d56eb83131bd
60baf9b7c867884a1d615c0afbfd82b2fd88f6db77eedc6ea8b2a0c4a49da9a961f61
23
envelope: 026f14a54d8d747c1920ac346ff2df10c3250151826ec85e0e401608858
7596c6eda1c9b09ad58c0b9ce66a5cbf4959d5316db21b8a4e63599d696c7fbeb916e
1f726f78d1f13696ad4b7617e60fe872934e5625d6d74eabea8e3356a47e62a0ba665
85e45ec28d52fd8ce2c8bda87b6cc11c769b6c06a1836e2a227e806588fa74baccbd3
ebda0fdbae677ad536af3d00
handshake_secret: 50ad9c4ea9d9605ee4471e7e439cd96d0531df0c8d21088e762
2901af692bac1fb039c8eba4d5d8b6fe8151c0729b1927e6eb8e5d3c6808d51b80ea8
335eab30
handshake_encrypt_key: 2d846fa9a8d87f92f20219c34ffce406e478188d48c93b
5137d2e3de2869eb888f97ef86978cd483d9758c5a53c113e20d454d81a7b76818054
ceda0204dbc35
server_mac_key: 2d9f85ffb235e526ad767819170cef7330569aec4ac77b774ce5b
eb7eefdfc48a7497ad966058ed9cb2883f653f75317404fd7b5227883065b461dc7bc
ee68e6
client_mac_key: 8c5bd13302262c82cd2aa64a952da6d9e0f5f273b7d88f75fffa6
fe3b409ef61cf25d87fe584dae0d5bb4bb6d6f71f170afcaeb433d83a09b0dc9351e2
e72c62
~~~

### Output Values

~~~
registration_request: 02bc8b8b2d8b96ba8f527f59dc0054349f0fbf4c7cda280
480d643909db6a8dbd4bcb455cc374050d8cce29147fab0a020
registration_response: 035401d98d9af21de3778664ed7a87eb467199a9da3995
d32bc429d27c839c15f8819b7d29f09d261e6120276bccc67c54030278df9fe875998
9883c2ef9047b2449abcdbe9f508aad83f227836ddda86b3dfe0aea33995cd76243a4
319800bf8ff7
registration_upload: 02592ee25abd015bd1f2ab94e91e0c6ab9decc55ae84a6d1
b0a881e04fd39eebd626f3bc5edd60555e18d62dc84d81ff5952fcd8a6dc112baef3d
206372a10df6c23494e7ccd9316fc56b0f169693213f039636736e07962aef30bfa40
ba27e7e4e471ad551cf4bdfcab06d6715142eee2026f14a54d8d747c1920ac346ff2d
f10c3250151826ec85e0e4016088587596c6eda1c9b09ad58c0b9ce66a5cbf4959d53
16db21b8a4e63599d696c7fbeb916e1f726f78d1f13696ad4b7617e60fe872934e562
5d6d74eabea8e3356a47e62a0ba66585e45ec28d52fd8ce2c8bda87b6cc11c769b6c0
6a1836e2a227e806588fa74baccbd3ebda0fdbae677ad536af3d00
KE1: 0258fdc4ba750f504274ff4644f2f43a75759b77adb1817c8686340bb28059b2
af91d82801b94bbcb8326cc2e046a4df51872e84d6a39cdd15899d68d31dc05366057
dad5f76be2e248ba0a8d751ced9ee000968656c6c6f20626f6202313f18385e0f0c3c
88f3e60178a6727c9023e1044973eeb676b9a17a398424b1074d5e35246fc25be8302
8853dc22f1d
KE2: 0321653e9fd647f0ec78ee24ccf67d2eaabd5981ad6d83905848cc6d3ec01ce1
64c2cf756e2901097c4a8852beb0275976cf8dabdc7be8e9d12e9a0c74540f9a4dbb6
1df5d8f542d4317d2bc50adaadc8561ba396a9c488d84f90d6c8b5ed2ce21f0559c39
5a08040bfb46bdc0cd37bd60df1a8cab8c5de6db44e7c4d26ebf865ca6e9320a61fa1
fa2f2749aef223d8560abcf184a626a4a7d84c58c7e7ce490b5c0a75c1e0343d3662b
1519fe983e90ffb3061d7244b362fc1353b596957879595e13300ae0a3041748d7f8f
190a28a2f8463ac82c6a4574c12ffb200937934ec849371950dcd83d183b116049070
834b0cfcbebbd3cf2939d5b5eec380cef468e112a136b7bffb03704d75fcc2e0a5246
48d1a335c37bed10932dd1160ef9a221e08632b79b6d5b951f207c06573e6c6a9c603
ba3e99f4c2f39463fe214e7607ca3e9b1f6112d565d80bbdb388f52437ec89f0da6b8
0279e10382bacc7cdab25a3a830000f8b903a1e41f8c4e65298320015a7d76b4ad151
55bfcaf7fd17dff8edbcf773384af475ae2c512cd1b8fd5cfd99cceeb3fc404e78889
05f0c2891680e7bb503e574ff6757e7c287df1ec0eeb90a7a43
KE3: 0326dde48f34839dd2354578dc115592d796ab38df45a8ce54f6457f0c6ae1ef
5b640dc4c1e95a9baba110f865aa78f1ed1bf9c75bf820992edcd25a40f3c1c7
export_key: b53ba27098d3e1f00abc625a6f48c9de081449dd037befc917136d827
64f5096e9d2fb17c54842bca755a8adbf43e409e496412cd32fb304a75f46ba430985
7a
session_key: cb84e3a383965755dddd0b5e6acedffc60a977286dbbaead103dadec
f36a5a2496c6481942047112063120b1649328a1e2fb0eb15b55e23856a98d3f69465
f7d
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
oprf_seed: c5e2c269409a95596dd6da21ea47f773890995a6b99776403060713efc
500b69306895ee898f57ec19b68f839c51d985e3239d5ee2b53fdd51c23b28e6fe04c
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 8b68eb5689cbcaf039788c1294a7d348baf57b053bb6cd387de0f
a50e73ba278
masking_nonce: eb3e5c45f266db87234f53a84cb98bce8e65fb775abfb32103accd
03326e75a9
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
server_nonce: 01389233f40d7a36cac715a365528e27109621a2787ce45e4b01a07
2da1e1467
client_nonce: 87f21361392a7d66afacd6bb517891a666c2d9c70056602c409563f
11b3b52a4
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
oprf_key: decad3ba71ba30ee628b84e3c2a7dd0c3a14c6e031f39aee816831aca57
8824916090875303ce525fdaef7a168d99d34
~~~

### Intermediate Values

~~~
auth_key: 7f2727a4777cf01d9368939e89875ac5cd34583ce74d3a17e216a3816fe
325d15799e4876123051e07a55654dfcf6f09e7caa983577db928f24d4baef30c4c8e
random_pwd: ceb76c899cda65f5e2ca9f4f223c83514469c3a6302f9a575aec5c049
b1414097da1943322147a2a69151a3009e052f38a7726dc99f17b7a7e62cf3b883e42
4a
envelope: 028b68eb5689cbcaf039788c1294a7d348baf57b053bb6cd387de0fa50e
73ba278d97b930d237f5ad4ee71b8dbaa09d59b98bbc06e939cf6102b994fcb29d87f
fe23c79884f7a66ba97aeef719583ec8756861dc816d076a80fa8ead5b413d105d282
90a812c08dfce38ca5f90ffa38d753d4297d366d0ef9a28b59ac44551c4c3b05fd966
eb8b888b2a23a08ed24f64eb
handshake_secret: 4bf3f2124dfd7f4d681511f647ae9d7d4f7b3d7c9b9148ba02f
b87af44c0b0c32348ba3de589ef0d0da4fbdffaf0d614bc385460ad6bede308dc2c4b
2e08fc3d
handshake_encrypt_key: aa7058097aecad64742c05f521ca7904589d860ff4e7fd
c6f84c3a17219e19681433f7c89e2fd6e9693f3d999a273b0b3bda6423befd08aed24
700d2054a65d9
server_mac_key: 3d4fa38aecc1e93a88fb13d2d839e2960e628622782a83dd95c2d
0d2ad7e31cfb94bf07ad0782161cfc5eb5082d3de72b4479b4d57070178af7a24d506
12097d
client_mac_key: 4465027198c4c6dffb9fcbc6cacb647c2cd64db8a02b489282957
0350d41edfe593825c4b6319f68a3d78df578c1ec831293c2ef3391128a9a7c210bc7
d5483a
~~~

### Output Values

~~~
registration_request: 03e0ffa19f9860931638c2a6a3fbcd8e0ec673cd39615a9
d80959edda6fc8d269bfc206586f1a10b46a895f8f17e730174
registration_response: 0374fded6c6508f2e79775013341b2bec5dabdd896faec
e3b0b826457f66f25437d0a2f511b21fc00bb8564fd96edd76ce03b73b7125c1d9517
a42d63bf21b0c3eeed2b4f76005f72478de3440dda2a2a580ef58077c145719505764
689842231b65
registration_upload: 03f9f34e551fc2ca9b36f4c44dbe6189a22ae0bcfa6213ab
18f3a4dc31ac55508e7fe05c28cf0734536fafb05c6eafdef064606a1cbb85076b9fe
8919ec31f39151374492a7a662b2d6fc0b685a016aaedc0583d4ae4ed37d9dfd8b989
9fa850888fa6cafaf91ba8824a7aa1b5f0213918028b68eb5689cbcaf039788c1294a
7d348baf57b053bb6cd387de0fa50e73ba278d97b930d237f5ad4ee71b8dbaa09d59b
98bbc06e939cf6102b994fcb29d87ffe23c79884f7a66ba97aeef719583ec8756861d
c816d076a80fa8ead5b413d105d28290a812c08dfce38ca5f90ffa38d753d4297d366
d0ef9a28b59ac44551c4c3b05fd966eb8b888b2a23a08ed24f64eb
KE1: 027b40080d3b93d00403d4e7ce1944644d57cce6241c69181216ba7323afc9c6
2054300441470c06aff071717754a2fd6087f21361392a7d66afacd6bb517891a666c
2d9c70056602c409563f11b3b52a4000968656c6c6f20626f6203f07983f1b0b62e77
8918e7b15aa899a5c5c9fce3af75c5a424e114f3c9bc539cb3b290c4c4705829c21e2
185ab3eefcf
KE2: 02a1bb56cbc2dd174fd877bff71b42e8989ac5d39c611133a5d63b2d12dcfb18
9457061a065bd167b6975f1c55a2cf780feb3e5c45f266db87234f53a84cb98bce8e6
5fb775abfb32103accd03326e75a9c5a764e9ce64896269c3dc42c2c3d769dcad0439
c5cb7df86f1c013417f4c555ffc0fe57c48a1dc9caf35e0facf04c2bd5286caa858f0
ee2e71cdfd104d1d1e90f584f69867bcf2aec790b9d84a329fd57e304887b168e038b
28981de89d0a618712bc7716d3bded9edf6df6d8daf43c767c7e999d8ebd21b9b9a93
c8dc7ac9731c8ae54938cc487cbc0be72cb2a327cbfa1ab9342734e3051025417e0df
6a9ba7789388a5b92c17dd244c347419aa13997bf91bd35fabc921cd1753127b9eac0
c3001389233f40d7a36cac715a365528e27109621a2787ce45e4b01a072da1e146702
bb887f84a3158bd1a95c26114059d1064a69dd87c8813ad1ab19b0cff29b48d0e945a
f14537ac16d8f4160bb027fdeae000f7b2bc10aecae75222434b41e61a40178b3ce0b
afe389f4af404ede73a9de6cf3761c32e3dfe67d084d35e72fba1b375331b976bfe9e
724ce89322039b00be7d05c7347edb0934fd99de55751c83a34
KE3: 12fa71392272514c3cc8a272f49a3c627b03377160b4ed999d751df7e999cbf7
c0cac321970f2a9e44d03376c85a5912bbed0cb6606e07033bd09fec058739b2
export_key: 161a1edbb368ba1aef7187476b511cdc0d881edc0e2dc60f3e019b545
6faa1bc0a88a5d443fc667efc59c24443da6653daee5f33b085bd3e8cc28873247415
4f
session_key: 0630573085d91a4204ca7c8ec165089b18f328f9adff00cd402ece53
783f061de2e61073a7791d76b52f1042ed092bfea5117c537c3e087b9bf0f93ed1011
0db
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
oprf_seed: 0bfa4df1718206b74402d91a84e51a063e2b74601388b1d444888ea5ff
332975da14573a4161a56072ef7d165bcd5681b2ef8daeac036124a39f3f0f71bb4eb
2
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d969b846b24dba51dd0fa4dcf92db81a4f42ab612430687bd9279
f1c536f0605
masking_nonce: 2906fa66ce92e506c6e670f3f62a72589f0ee78d5d363ff8d829d3
0b0d8f40d9
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
server_nonce: 667490736fea040e52f9afd9ed2715e81ebd73bfd577190c407d2c9
8b23d6ff2
client_nonce: 2f1f862104fa457ebb04fb0a675a5408d835d079b299a7f9ab73fd5
b54b36530
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
oprf_key: 1a2cdbfe39363c5bee4dab7b0cdeac3b7cecf8a3726a5f655f4c1e4b14f
caf2b8f3087caff8ee695f923b5bb43b0ea82
~~~

### Intermediate Values

~~~
auth_key: 973ace55a5b768dd670d534e39bd1c3a036b45c8c646073f6b77c76c0ca
bec3d3a590cb7af630aaf8378c105bb7b34ec7780d2cf601c83ee1f92e674b074c912
random_pwd: 86e68842d2c673283a7cddfcbf54f8d9ee3cccfa52e44d4ed921ecc96
3a086bb89423cd59ea28911fcb835fffafbce43a0189eac426c9412e53e2343a4e7c0
bb
envelope: 02d969b846b24dba51dd0fa4dcf92db81a4f42ab612430687bd9279f1c5
36f06051f077804653f3c1643b85f1d13da6522f39321099a9bc49aef30e5484c5757
28d2ca09b7ea3ba589b6bcd5c18c6cd529cab9398314d16563b56fdb9f560b0c2449f
ed8935b4f8c9574bfbba673df13e0d1e1b02895feb02702aea15f99d11380999623d0
b0a575326ee16129bce28eea
handshake_secret: 4e2d6053b104c156838e14b4fffc6c9b18116aada01ec15a720
83ab5be3d1c702d074b2505869ce5ace5662a433a3e5e8186cd7ef378166ec0deef22
710ab9ce
handshake_encrypt_key: 16bf5dd36cd89054aa614c30ef2ab869e1330e6ad66709
cd3d05a704c721f18898612f0565ad87bb194a2e652f52c36f0cd52a68891007e46c0
840dfe846fc4a
server_mac_key: 83f52fea18ba9282c8e85321d39feefec414b3b193c85bf0a13e5
a36c159e037e646a7444b8dd6b67916624be9731146eb82456b2a82c6ba6c49fa1ad4
c12f3e
client_mac_key: 00d72eafca1b91c1606735750b546cf488a017e1b4cbdf940786b
3608388f725c26db77045f6e5a77b093e8349644d33d78f1f6668f89226a515ff6e1f
18bb06
~~~

### Output Values

~~~
registration_request: 03a2e55f8d839d6b162d179f9b4f886337188f731db9ffe
0ac206b54096e6a9a8f30785c33d207ece91c4fb97530fd491d
registration_response: 02367ca14ba6dfe89e6e5dcde462461333155257a07aff
385b1f912ed27b32b17bad34b5b2b376009fae47e4a8e86fc050028beb3ce19f449de
b6aa31eb19c661d4c4ba0fd08b4cc1e91416b0c5b5ae74de003a76d68ac4f59b64b95
4717c4d843ba
registration_upload: 024954440156358f8db7a32b042020404c7918cfd0003699
aa1e783ba913f31f54abbde5bfa0cb6c26ca9aa90fce90604053982e14381b73a7626
22ec25284c03e1662c53174d0e09ab9a1601e4c7d0773ca957998392e732c8e134576
012b5b0c5be788417c7b9ecd26455801e96a441e02d969b846b24dba51dd0fa4dcf92
db81a4f42ab612430687bd9279f1c536f06051f077804653f3c1643b85f1d13da6522
f39321099a9bc49aef30e5484c575728d2ca09b7ea3ba589b6bcd5c18c6cd529cab93
98314d16563b56fdb9f560b0c2449fed8935b4f8c9574bfbba673df13e0d1e1b02895
feb02702aea15f99d11380999623d0b0a575326ee16129bce28eea
KE1: 031b4f459c984d8a56589785181e03b93108602ccb92ef3e247651d9a9e72d36
0a93afc86dd79490fa621685779408ba322f1f862104fa457ebb04fb0a675a5408d83
5d079b299a7f9ab73fd5b54b36530000968656c6c6f20626f6202a39a8a45c68e977d
b2ff70778f0d34c28f7cf430ca1045d4c48e6e749429f0f10b226c26cb0ab71bf2445
f6b9ccb81cb
KE2: 03a4571afcf94f61827a30190879df058c9a1bcb0d90b5c43dfe23c761e433f7
37308983894147fb0da48d0e544e8f87f02906fa66ce92e506c6e670f3f62a72589f0
ee78d5d363ff8d829d30b0d8f40d9712fbb77fc96cf9b3758dfdc90288baead2b7025
13e522740ab355f81dc2d084072165bf3eabbde345995f50547893b2d990d3a828676
e3238acad95b56c7ec554dcde9c5f6f28c2fcfdbbf95bb13d2183676dee92cc7be036
0ab27be4982ad7f81c8c30dfbb3364790d50d49eba48fb0a2343bad1eeff1b8843495
a873fe94407887414e816c7922778b26a67871e16e4c570690b3549a3c091870bcb56
bd853297565920dfda65f275f6f146fc3b411edab3cf6251a9cbb28636b80712793b4
dd1667490736fea040e52f9afd9ed2715e81ebd73bfd577190c407d2c98b23d6ff203
6357745dab9026251b2bfb2ccd847536219da8e475cd1f2dc4842206a8452c720e3ee
24c0abe77452903c64985b76a27000fb2e03a4307320b4d93483e619fa5840cd5fe33
392dddbfdfe20c7b166b691186066612f4d39750487f5d01aac56c6b1125bbc8f317d
66fa72e6fc774ac88e8056fce47b97a61a94ea6ce4f3bb4ff2a
KE3: a32f0318db46beb9f69d6caf3d6d6c006b7c5986c204d602478e126b5556fdaa
54a764d2b4542f8d397e913f08b96a3f8a647e51e8f50d01526559484a754f65
export_key: 3d3792179ba5ea81f8cea5d1ae6dd2266c31b2025de55c38198d26c2f
a0c2a26bb5f9131d34a3d713ef591842939b252392920e70ad8dc93c1b7745dcb4721
35
session_key: 5d660628bd79093af259be10c607c1c6978cf1aa1d95c34b744cdc41
0fabdcb38f0e88dd586dd85fb15a99d3bc9a1bb1a0638c26acb2e06acbf1380c6b42f
f06
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
oprf_seed: c01565885ab04d8d15d0e20a67a8ee27419d230da414f7d0634a48d2dc
3adc8b013d147db526928cd5fff931cd0e178b611a549afdc22b8903b4a0d3c9c35ac
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4009b7f95a9e1bb5be575742b90586f2c452e242f789711efb97d
6bd9a2a31c4
masking_nonce: f8b27594e296533dea75aba16c527d6894513b45869bf06dd6c538
527cdfd28f
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
server_nonce: 0b5dd9cfb5e685d08b7b9692029db0908f6f500d1ac5df20858c923
80bca4e8f
client_nonce: 6df1827b123ad4155d1e4b3d2af6ef640ff85f6693c18ea3161be9e
d3222175a
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
oprf_key: 00c61c9feb1761b9aee68883a31279108adec0b4db5305cb79b00605e4a
8e9d344b9a9f40167a7fd392769722ee0f8eeb43c35b0e045939fc76261df6aadd55b
f2aa
~~~

### Intermediate Values

~~~
auth_key: f7618bc320e1d3f15b72f7482ee429694b6e412d72fee26ae6ed0b789bf
236f459f2ea17d7ef3522e073e19f67a230307e9b08d20da147b86082305047a21c15
random_pwd: e38f39e37618b866e2bc4f0679fd65c923bd513c773dab2acb994918c
46e34bb6a642b31fd6a0501a27a5910bb0696e58b3460c0046d45f13aaac1cb1d50ac
65
envelope: 024009b7f95a9e1bb5be575742b90586f2c452e242f789711efb97d6bd9
a2a31c48b164158a945a4c8cdc337619d0db71e4943461edc694f2d2a125177ec2844
4768aff4b7d4f77af8ca7e327b370093395290be8696aef0e582cd1718ef659c27fa5
2cfcc8a25a325dba17639f6daa1caecc8ce115f2b5ca68ff48d35239b364c8cb86d02
5e33fe139d1ff9dccf7c1f516190d22651d6c833d553f40053a2568d668b
handshake_secret: 63771738a5a6a79b128e07993d84da62fa4d0b7148f83a07756
efc6982cec5774d69c9726d4e1dc5e28ea72e522abe7b9feb3cd894f0fde5933cf075
d370c0ac
handshake_encrypt_key: b46fba192117d682872957227a5a0e458b6627d8bacc57
50d5ab893fb6c13f9fdfc11723b9ceab72f4e665db45b940b50e0c3fa92605224bc53
5ccb673baa395
server_mac_key: ea2dea19e12a1c92f09212eabf3ba5361218d49eebafa516519d8
7bde5b5099ee1258118efe4f3f239401f8178e7e50e55f90d3b077f7efb3ddd71c387
2757ec
client_mac_key: bb25d99680526f1792e23da02aced4c411032fc5f1570584deabb
030037ca242fcb4e7ca1799efa97eb7ab94dab2d5340cb8e6e281e93caa82bb4b3a2a
8f12e0
~~~

### Output Values

~~~
registration_request: 02015d0cf2aa22e0448949416bb4b3c246429439d4cee47
a52b3b9874aaf727dbde7f34b5112e91e97e1d98c9cb0fb58e015721456160aadd16a
d4f9a9ef2fa3d0ad8e
registration_response: 03019d4e900d459ad8c49458ffadf4a0e8d1681de9b88c
8e388033c76640602b101d95a8d7d7f707c3441a12642ad313b3a7a7e411af604bdc9
8a58a3bfb06e9e4bf0a03018fc6a77bc4127886d67871c03462740fc4d6fe66dc2226
365e994f8392a0b4c43cd6e67ce90ad594cb63c146011dc56b213bd42ef677cb6a5f0
1d0bd9944a9161a
registration_upload: 0201d6bd681715e3d330475e72471c1218aa718d96be7353
251c9564f7be3a506b77361670f9a05f1e9bd648751b8494f78c4f1c788951efbf183
1f811d49d120a8d45472b8c55a83808e499d58f0f81c119dc99a6176313b51ef4396b
d317880374e36d77e58a47db201222ab74714c6c8ef467e8a8c91d7d658ef464f75ff
3132717024009b7f95a9e1bb5be575742b90586f2c452e242f789711efb97d6bd9a2a
31c48b164158a945a4c8cdc337619d0db71e4943461edc694f2d2a125177ec2844476
8aff4b7d4f77af8ca7e327b370093395290be8696aef0e582cd1718ef659c27fa52cf
cc8a25a325dba17639f6daa1caecc8ce115f2b5ca68ff48d35239b364c8cb86d025e3
3fe139d1ff9dccf7c1f516190d22651d6c833d553f40053a2568d668b
KE1: 0200c3bce8c2c7da1856b486576082a136f031304eeba82c3e582d920469621b
9657d018aabad67dd15d32492f0155ec944d11593c079c64c5d19088a72cddb12baaa
46df1827b123ad4155d1e4b3d2af6ef640ff85f6693c18ea3161be9ed3222175a0009
68656c6c6f20626f62030080bf524d28ba64b134c0bd0c860c8b1f976e55d94eb35d4
2aa0cae1935a185c9f7c517875877aac4aa4e909dd5f25cc6ccfe125d031dcfe02459
7af1f7bfb5ed89
KE2: 0300e92a71752faced7f4813106f6c083e14c4ccbb1194d5e8e1adfb2cf2ab54
6bbded56e081d5e5b4f10edbbbaa81190dd3f6756b802691f53687140d3889bf1ef7a
0f8b27594e296533dea75aba16c527d6894513b45869bf06dd6c538527cdfd28f3fa3
2398e17e16a53586e47abbbe887a45305869936e04cb1fe42b4236ee2928db0aab268
210dbf970b1b7fa2adfbae929fd6d59a6517d1db54709867b2caee8a2503e1804d28c
ad6ddbc931a7c109098a6485540f6fa07398ffbcec702d0ed1f568099727896e97de7
77e2c971ca5b18444f926c10eb794bd1f6158e2352bdaf89eaffef30b34586ab594fa
7f4923821b55db1c1af130090fdf419b9b59198d15b0448de08c0987de18be6ed5edb
fee93599cdcf5086e93e81c16b0b0242ba21129f5114d55d340aff2d134f0c8e32372
9d60ff7b8d69813fe98f4bac105605e44d09bfd2060b5dd9cfb5e685d08b7b9692029
db0908f6f500d1ac5df20858c92380bca4e8f0301ff9a97a3a4733b144d38330209bc
ea5a6401eb4e08e0697ac4dcb8369e20d76d32c34b619c424d643dc47bd680c0ef665
404643d2961ad051a7920c318ecd948f0000fbaec2bea93fc528e503d6537cfaa95b4
9404993e682f2fa90d331f15b19055c29a7bcca0fa12cda19ad924ab353272c29137b
5c1afdc8161dc0fd8858d1eb78a0479f2a09010a6f97eaac04691dc5f
KE3: 0a2c577bb2ee6f0b9b81f5ae01c8b8f0f781246835b197b4108a5c219b129c9a
67de042c1d57e2f01f8df6e1063a745071dc90319c34117fb0a8d4112832a6e5
export_key: 9b2250a6e84fe1a71a6a69b4bb1893f8349409981511179dbf8aa1e2e
afaefa9e02d7a90ef8cd21688151c304072aa7aed8e387c5ac4c4a44735c2a1cbd8e7
76
session_key: 032e01e8396517cf350742a8d0e24eaf67783c28abf63ca163d9427c
03c4b39ba2b9625fef9fbb514129d90e5fac657f9aba4aae541619f90702b9c485ac0
5c8
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
oprf_seed: d7036a41ad58f07f1350e9d009f9085f9401b301056953e9b6b6652549
a9ccd7b6067676c7418c117815eb0eb41eccd1b037f8fecbe3ded89ab52f133027e24
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 96f2a9f32ca77f66e645ff43ef30991b8fde9ef5af47312e3a2ab
022688ac3ab
masking_nonce: e963bb28068d3a2e31e0ea9d44f97b5376d3f9e574ec0639a987d2
f92dfd4d48
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
server_nonce: 666b72fd0082ebf840260ac598f3c5f6e50af0463cb7a3676a757dd
a20cdc77b
client_nonce: d3e350118bc8ffb48a34f9134d5812bee4f62630bf0b8cc37fbfdd8
5ebf997a8
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
oprf_key: 00ba5e37539db205c6063c3709be828b600c258286b8e605b10d3d72b0e
7d751fe78aaf0c1c385908e8e97177e74e70d2d9ad5db5b34ec661890a2e7a29c1d88
98a3
~~~

### Intermediate Values

~~~
auth_key: 5dba7ef5648b28bfd8bd93293656ca0c47da18e4de89e01c087de2a04a8
e39ec42ec12e7f18e4dfaa06cecad49f12b0a79ef5782581b8b5a3988018423ab9b20
random_pwd: e48f5edce8266ece35d2a6be1be448ecaf2eea6f89f5a87cadc6407d7
c6f351eb4d14e5d6bd5e363fa47dca4f3be7b29605a6fb63182c6125ff309ca289648
12
envelope: 0296f2a9f32ca77f66e645ff43ef30991b8fde9ef5af47312e3a2ab0226
88ac3ab3b05397339b12964b187ac0648af95f590b7f3da2c04818e47e4576f0048ee
36f382b76f39f1046e0817eeccce7aa5db22010009daad60cd64378fee2e5024c5e21
d6c154f5d6efb9213213bec81aa3568045801597ae7327c288b97eb8c76f05cccdb46
809f888d54a4a9940fe44e2b022da597f2e17644c43864c53461f4865bf1
handshake_secret: 044a0e30ff4f42d385b02e137a22f372100094a17ec1b15a206
4e7c55dc541bfedef4fe5794d836fd3794f328d939b369fcfaac4dc0da61e2b581122
ec48f1e6
handshake_encrypt_key: 264c07f8c4b8fc8d78731e0994573ac2cc02e0de388732
bea255a9406973a6462f26995b1f2529f3dd61a23b8cd5302193a81eac9d7f424332d
907df0f0edd62
server_mac_key: 87ace2eda67d95ad02ada739f3f876fda3df7682ae0b666307487
54ca62df30b3f120261ba621538692e1798971b9deb368793272fd797e292dacf6580
99e27b
client_mac_key: 931513239f6b651f2752822db92abbc91015369bc4718cdf8d3ab
1c01c059e4eca44cd9e459491a959edb333dd5b51c4ab872c139b60b8f05b3600daca
961bad
~~~

### Output Values

~~~
registration_request: 0200572541736c54fb88d0f50d1080d98cc390cec131e56
c5e3d038122c6655d23defe37f0946f3d3b5dcf73545a6df6277e20f9b377591bd443
034fdf53d008028969
registration_response: 0200efab4ab3cf3d676f014b020a25ef15c98ac44b9c61
e4e28d15ca4995348f0e765d31c7fc260a107d06ccfd90656f0b0fdafadaa5c6c1d3e
d1d741b493962f269290200e85b446310593c25258991eeb8da130df718df2efeee93
29b6d6c7a3906749464ffb90f8e43122192f8e77b9f04f708aa5f9ecca9cbeab701f4
9929d82395d9928
registration_upload: 0301347c5fb96ce61b57ab45d42005522f77483664bd260e
c7f6a0c6bf4e7b9f2a6c873193d8ee75f62ba7d4b36d93cda144fd99dae7422a31a82
90cee86e55fe23462b44decdb45e0ac7bc258aff751faf9f92397eb78f00b189fcb35
09feb101d463d0ba081199e4a966b48ec24b1f175e2bd6158ef868b04bf66d9f4c41f
d7ba68b0296f2a9f32ca77f66e645ff43ef30991b8fde9ef5af47312e3a2ab022688a
c3ab3b05397339b12964b187ac0648af95f590b7f3da2c04818e47e4576f0048ee36f
382b76f39f1046e0817eeccce7aa5db22010009daad60cd64378fee2e5024c5e21d6c
154f5d6efb9213213bec81aa3568045801597ae7327c288b97eb8c76f05cccdb46809
f888d54a4a9940fe44e2b022da597f2e17644c43864c53461f4865bf1
KE1: 0201147f07392ddb5ab846130ce65a4c16d1eb26735fec1de7716b2c8bc935ad
1c65ebc30a6449adb8504b41fe61b9634a1ac3e429e03db700e6e6f852469e8e83bec
4d3e350118bc8ffb48a34f9134d5812bee4f62630bf0b8cc37fbfdd85ebf997a80009
68656c6c6f20626f6203001f619d901664fc0a4916b616bf340eafded4dec3c9af08a
7d89f9442bf41048a8824f22d5ce906558f99250ba96a112c5ccf2ff02e062cf9158d
fbd1abc4a48e92
KE2: 0201f8813bb6d09afd381c5a2b6cfbafd938924fa2a5915d1c5692c95a92a448
6d59a668fefcbaff60efd8cdd2bc5657343128ac295625ba97cd267bfa165ea98fd5c
6e963bb28068d3a2e31e0ea9d44f97b5376d3f9e574ec0639a987d2f92dfd4d483a1a
64c9e9239f1e646189cd0a65fb05bc2f4b18683dbb73a34415e0b3901bc715097c3ac
7e1d29e8efcae151e3fe189e864f51eca1a88a0949da8b940b5ac1d09b915e06f0216
31d681439991e425e6559ddb144b578b3e1dff94124ef3fff1d63209e9c27e741bddc
53ee5122e31e558ee11934805fabd78474947cdeffe4f2e5cca4bc3c752cb2434b05b
f956e912528da70888da90ac114a3668671ad4e3b662ea5e3ba7c7ba5eea313c78efb
f77fb5c97c6e1620927c88edb2c72941f33efb82bfe1b895d297f746a48427a129cf8
dd1a63fad112733a42feb54d8f08c854fe44b445a6666b72fd0082ebf840260ac598f
3c5f6e50af0463cb7a3676a757dda20cdc77b0300ffcefd89e8ee736b4e6149934a10
40b8691ba4bc58b160d8c526e73cb99d7c45ce09264ae268a5afd07c1a3db59c5feb9
203ecffc694a41b1138deb9a11d6fecbd000fead7cee48cad44695b3acbc7978d56a0
dba047138abc4195f2766f27b6f26bf9bc0d990e60ef3d8bce1df9b4d74f9e357b385
ed60d3b9a17547d587a1e82914d94f880d727a6391b20825db710d275
KE3: 96a1be25c5de707680cb1996548b5d901e66e1525b4d2c01e8a2eb3573fc3a0d
061e94bc1b33f000e8941984c6b1fdc021cf4f9a0099c0c9898f1decb98a85fa
export_key: 037df3309efa8f0c3652bb134ee8675fa8b4d8f11a3c1bb094df49130
bb061e50612f8b244ec23d5a88be0e08a097ec06ae149eb6ebcf7d95a621fc31b1fa7
de
session_key: 5c159e1e7b71dfcc8723ab1bb78ca1f999c913d60953a20977074ac1
c14beddcf0ab6897bf28b1f9fdca818f3f34a85335482d0561f5b4e14604682af8dc1
cce
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
oprf_seed: 22374ff9bdc092ca87ec2dcfc6059b33a22c9244ae0afc88ae073fd015
71357e20bbbaeed3a62c782757d6a2332a48932aab2d19e8bd9808ddbc98e944b4805
e
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 2811ccfea7156426b5b397dbd55b1c246e60daa18e5dbd7f2aa41
9a5394c29f9
masking_nonce: a009160840509143258c3eac15f20cf18e26a2be59654a281cbe44
21de43fe64
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
server_nonce: 3e466a399782fd02b4415d06bfa5354482f02f9ae2d96413d6a5ce3
252cc3dbd
client_nonce: 6173fb8547ea3b77e32b8c475194ea86c0e0dd2e25e8ff219bf46ca
3eb488288
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
oprf_key: 004c3147cf7990f16b30d4f80aef00f398ffd2f93c1c0f25a204711b582
19a1f61cec51948d733d747ef0031dfd42c042520d917871c5a030e4fa002d308dbea
eb57
~~~

### Intermediate Values

~~~
auth_key: e6a5a56981b8b2514258045ad0f942ad14d180964811ea4e88f71f6ef1d
821b3c23eecbb3e96559d2b398198ca30312758cc427986fde77c597feef3f735740d
random_pwd: 886d025641863b91cd2d4e491eb37af33360698cd11d1cb8cf4f71412
5a82e5ef095b668f8c52a05e31f66e87ec55ce140a89b3dcced163d26b977b5d2583b
84
envelope: 022811ccfea7156426b5b397dbd55b1c246e60daa18e5dbd7f2aa419a53
94c29f9f733fee01d2720efc243061c9e4a00b86302c806a50c3d373c4fa0a5f47339
a16e369d0a31cce1a22c65478c96ab46121e256f362b44ec93c5047e2960019598094
7cce4d283a53da7c5c08c8d85abff78dfaf4508d9ff20cddb8f644dfe8079559e76b3
5edfa6b9b2575865aee92d812aedadad67c298c6b6de8db47f07ff6ac00b
handshake_secret: db131322e3ad03d2ac4fddc279f840d97de10926d3ba4927fae
e9bc65ef32864c57cbfc72f2b7705c682972f2e9a0c98703e867cb6efab71281caab1
529b6e13
handshake_encrypt_key: 5730b86dd5ad87c45fa60f9c6a9a7c65239bb738792dce
e74d1452907e611418acb6d290bf2a26f5e365120464bacdb9f3be59930b39fc137f8
4c963e40c0c25
server_mac_key: 342a2cbda06dda99d432aa81816e40724549c999b057e1c51b721
6ccae3f668902f45db349609471ad82903ce8d8e8e0577babded43e2faa88c5820742
a31ed3
client_mac_key: ea77d9d5332df5d6657ce9c5f3320516eb1efb11795fd9e16e4f4
d7275eaee01703d8b1bebb47dacdd501bca160ae119283da0adb7c70b4dd0173de3d1
2fd6cc
~~~

### Output Values

~~~
registration_request: 02000c53a2fa3c1dd1ed747b297b82020f316ee5b38d5ad
d8bfa68d9c6eb9b22ac651badd5d5751e7371cae832503f66442cdc156414f4a5ba0c
2db08b33530cde8dec
registration_response: 020058a95aeaee3d744499510ba6c2a972a7284f2589ab
fbf1dd9be9cd5551adf239e38ead61d97a521cfcc3d8ec38e370f9b9817e6ee309248
d5a3dc7e937f25c2c140201a6573b69f46bf93cb3f18e2510c753f689097b7b96059c
3ca8f8e45c66a03b694fd8618c9a52c4104ca42186438849e73613cb25fbd4ecc16c5
a65f95345686984
registration_upload: 0300ddde60161dc32b29345ac9ce18ecf102284bde1013e4
ca15d2e6cef0207da6b4099be218142b531926f99a2f1112392aff5a985d451b37dc1
e7ee4c024556f0808a7e7568d529df58ff7c412425efb9060c5207ff96daf052bf9e0
91363db61e71c36bad9af6809aa4560ad2e28e2db9d90702b012a5a21e34a264258d8
12f0dc4022811ccfea7156426b5b397dbd55b1c246e60daa18e5dbd7f2aa419a5394c
29f9f733fee01d2720efc243061c9e4a00b86302c806a50c3d373c4fa0a5f47339a16
e369d0a31cce1a22c65478c96ab46121e256f362b44ec93c5047e29600195980947cc
e4d283a53da7c5c08c8d85abff78dfaf4508d9ff20cddb8f644dfe8079559e76b35ed
fa6b9b2575865aee92d812aedadad67c298c6b6de8db47f07ff6ac00b
KE1: 03014f2799259882d01af61644db264602a3486a32f6b510aecb336456ce58af
6cdf6f5630ab4e3e7081f1e99b1688558f0a1bf15da34b7c0252f1036d916928a0f33
26173fb8547ea3b77e32b8c475194ea86c0e0dd2e25e8ff219bf46ca3eb4882880009
68656c6c6f20626f620201e2f40c1d877219e9512862469e31da268ab014fdce9cb3f
9ed6b27fc01fe6d9b1ec37c6cee76131139ccc3eee0a35438250e9ecaff6cf223ad9f
a469dfaaa0f0a5
KE2: 03003d1a513ad22fb9f0abcc9ae3055d541233e214bd86e7bd89d7b06b3769b1
baf0bc4e3a33f264bf1cb13b12a98ca85b9305a548fe6c19307f427551bd31ff0a075
7a009160840509143258c3eac15f20cf18e26a2be59654a281cbe4421de43fe64e4a3
299996c6280236ca54f3e905ac0b21f647a124448c79cda7ceb8acec21a1670344cf8
2f0b561fbea314ac922124e3004d5ccd506b7e1179200e8b7b57f8d30647dbda4b248
788d4177e20ad264b528eab8065eb82f93b1c5e213754e4e8f89ea66e893a73d1c4df
6d9f34f112581fe123c5eb419ca2fe4bcfb6cdcabba49b99e2dee230ec22bc26b52a3
4f9ec02d8e8fa41f9492dbcce0a1748594df0b41e00910fa71746009b28b730f9a03e
62063b680a9537d984ebcad50134a9b2b3d66a16d5d309e834664183aa6918732aba9
9bba7159d6ae32b4a7a0342d099e7ed4d2717079563e466a399782fd02b4415d06bfa
5354482f02f9ae2d96413d6a5ce3252cc3dbd030029562d54d53c7c51651334989bcc
95b45a1a07484448ef72bab708b55322b49a43736afc60bf85fc05d3c1d8b60a0b55a
83e37befa115e9625e00f35c1eeae27ba000f7e0c8b9b60d4268c2b8fa0e6ac89307e
ca92f71543b183cb38ac9df6bbace65a230024a417e4e019653f970fd6c83de96b385
676cf8ab90c346aa4dabe9e713d284a9b4df944b681fb3edbc7f68f03
KE3: 9e24b63782dc1725d2ca3d85c129fe0628ba72c86ae52dc7e8536b1fe5336477
7ae2b8399db80b356c441f4ce20c56a35ac89c144056efc228e37de756213d61
export_key: db3ad1004d6d742b49288cb3a6126cfd46d3800de0056de56ebb1b205
c3ba5d16b22aeb2048c23923a28bcf9573ebef5cbb39b210abfbd4dfe2ed5c62e5ee6
3e
session_key: ce9b7aea6838d1bec10a0093252a29a7a4332d28d70ad355fac41072
c19c69b3b2b6697ea9c09451520a938f0638c89fe47f5876aa21eabbf967e14b2f8ec
43b
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
oprf_seed: 5e30606c08752fbd9b22758c152f17c8bf7080b78d4834108b2e4ca64d
48f239940d1a1f1ea9b9dc2565401bed9d6eb07cdef0a68e3a39b84e8a72c2cd700ca
3
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 334df92b47d6f492bf798b140f77f910e82068e809889cbe82c0a
513a05454cc
masking_nonce: ac6c7b34eb67a97e13e7004fe8cce434e7a5e5b1712d43de5f0a7a
ca44dfcaba
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
server_nonce: 30a3a4d80c81466d0d0f91be62362b34c0695e483cfd6d827fa86d9
01bc27b32
client_nonce: 696977ad73d5fb23d007db360f53d478c5d2615501ed9753f647e69
e6b2f9d72
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
oprf_key: 00ebe05301cdb5d3227de223fca76c6e6a220d94e70afe655bbcf0e8332
27d5c3caff5a240af61600a7120be901a96e32530b3ea3d533280940a719f23e7eadd
3410
~~~

### Intermediate Values

~~~
auth_key: 015bfcd3ff3f9ffce68edd5dc9d439cc21e8f552e3b0697b616d2017e37
06133816f1d4851fae48b650e3201811664e5856348820b9fda2bb4dbe35f2c3dafd2
random_pwd: 2d7e09c0860f9cd7684ae2ebd1a1a12852c0a5248b96b09a865fdeb6a
f2484603570e14391f0e9604be3ab1467a7a97dc29ee2ea4638022e60e3368b740da1
3d
envelope: 02334df92b47d6f492bf798b140f77f910e82068e809889cbe82c0a513a
05454cc1fb1f6188c0188a0cb5a41e592ca8abf8e50b3f27b7cf19bd5b7bc6e73e927
e129dd2fd5462f4dacce5c4c8466cb1ed851994c982b287bde15f87327e55db8c165b
527ecec7d12ef0d58cbcca62a4bcccaa26cf165bd81479ee3b7f94adc857d2f1dc0ea
06c6008eb47f97bc260630018670d9dd3c22a55d1e287d2dad7a83544c94
handshake_secret: e14c6902f2be4e39f41ce5e2504a858f9061c546c88c2bb5f02
3e19c6a9c81aaff97bcf646851f39e6ff998301412c5626208f3ba6936e9ae5c2b87a
8a9036b3
handshake_encrypt_key: d9159a9797b87535607eba1ea39f2aa624de6527987c0e
546e441ad1f1d349ac35e365155486e8c0e6a6832ff7114d09bf725275e3fe9fe2dda
4e6c03052a7b8
server_mac_key: caa779382e29392753ab46d8daaa82f4d8bea81f2a0e3d8440b72
7000ad71612779d656695a767e6675982f17b665d12f830c9880b263ed6caaf4c38aa
589344
client_mac_key: afda80121fcf7a9146fb75492c848126e1283692b721e99dbe522
9665a7d0328879096cf2355772f598869d7fa9b053e9227c67f82407718d3541bea0d
2c83bc
~~~

### Output Values

~~~
registration_request: 0201d22759697d1d91f6b1812d14acfee093886e889d913
cdffc78de009924d3d80a7aa9384149f163fd706498375c34402df2ccd8c1283cd250
477ce032c9e7c78ef8
registration_response: 02005502fb60b910903742575956546586c6426280e054
a027e5286ba02775cf4f1d0b6db0e9ef35de3bcc99987901aecdafe73607b64e30190
0627c0a86f5a8c0593d0200f944f464cfcbdfe94b720c0a59487456cca17580dd1982
4532d540642aa4017edec0b9308bf4f4fc00611115a145c1374680847e4815f6c8dd7
febdecef64998dc
registration_upload: 0201ef259e80ef427390cf74d1cf31778645e53d0ab4a7fe
f6f57a56a0c2b5f4b602d0dd906fa77bdf011b9b7e6bb4098102bb9806b3d74d12bea
03e0379fb9127abe518a1d70057f0a519940947892258c3ece7cdb90d99a7877c2591
4e22c99e0747adeea9886a9f1a39638381fdcd13c877f0d7e62cea574cec9efe327ac
fd1afd002334df92b47d6f492bf798b140f77f910e82068e809889cbe82c0a513a054
54cc1fb1f6188c0188a0cb5a41e592ca8abf8e50b3f27b7cf19bd5b7bc6e73e927e12
9dd2fd5462f4dacce5c4c8466cb1ed851994c982b287bde15f87327e55db8c165b527
ecec7d12ef0d58cbcca62a4bcccaa26cf165bd81479ee3b7f94adc857d2f1dc0ea06c
6008eb47f97bc260630018670d9dd3c22a55d1e287d2dad7a83544c94
KE1: 02002c6e65b998d160fbbde62484f39c2678bda170db547005889379b570e83e
4f6aa45200a183dc5cbf014bc7f94f28064bae53132dfb3a0736bf7b806b1091ce541
8696977ad73d5fb23d007db360f53d478c5d2615501ed9753f647e69e6b2f9d720009
68656c6c6f20626f620300c566f59e65c950d86356e925ce1f87b3d4a7a9b2e556ece
f17041679c76f8afd8f7b1e9fb82549886fdedf29e4e86564475b0c2c200a9c7a4e08
9e846932e07d36
KE2: 02005de4f349614dd3f979abb37c23991781ecbae10dba640811f06af90162d9
439dbc2c3e31cb31bdbd584eb62d694067646716f964ba74552dbe6a14be4158a1b1e
1ac6c7b34eb67a97e13e7004fe8cce434e7a5e5b1712d43de5f0a7aca44dfcaba057f
7e940565c62a69eb20c899ad8bbd6358c52eb84c0a430f4903aa86833ccb0cf09d8e0
2ddc2f93706c2ca108749a0890429fecaa385ec65f22af9a535f5b0aae853fa3868d9
ea0e16fcad14484449878a274b53ddebe6c2ed4132581782181b12fedbe11faeaa77c
79d82fe95a6a68f85ecd10479aed91d67cd9ad4e4d16b645ba81b95fb878ea90746bf
1ca31aae05928371383f744b53b699b02e606bbd00e277fac1a1c7c50137c79f55b3f
428d41c9b5dabf4e8fc1f74d685e25276469df6d495a5ec4f6344803ef9b73bee501e
ec81479759264c3bfa942a8283db0576837eaa06cf30a3a4d80c81466d0d0f91be623
62b34c0695e483cfd6d827fa86d901bc27b320300ed0fdc747de2ff4797c4b18da821
ae9ec83376c51d00a51b2d1701e5689e8dd720cca6fdd1a548b5b3ad34015006ce4f7
548be73295e07f15f8b0c60331cb65160000f3de4af3d8548e3ea963d1b738621c961
b4b72ab491b5536281f03039910784dd76b74584508e7e7d99a7059ee752fba2c7ccd
1ecfe4be584b2508dbb6d946008b9c0791162aeb6ec19cfaf36eca9a2
KE3: c68079599a72ee9e051c247e356493bb8809d44337c77a5255188411596783d4
59f7bef3f7698903f3974b1845a55f83667ae6e8c71473fd63d05adaa4750277
export_key: e7e99db020f7cbfbc6b3c28c021a80f5c016e890c881d25e127df6100
1ac8f7a0a997d38c1afa0cb9d991206baf985ffac4db7f40af1fdbc4231610f002457
19
session_key: c0e11962d1dbd4a0aff0e8209d8d772ee8671286b79dd2aa99e4fbca
a463a2d4c6671fd6e991c4ea6864a86afc24b9d6e4b33c540e7b493c9f7ea87e87e4a
9a7
~~~
