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
- Key Recovery Mechanism; {{deps-keyrec}}
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

This specification defines one particular AKE based on 3DH; see {{ake-protocol}}.
3DH assumes a prime-order group as described in
{{I-D.irtf-cfrg-voprf, Section 2.1}}. We let `Npk` and `Nsk` denote the size of
public and private keys, respectively, used in the AKE.

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
{{client-material}} describes how client credential information is
generated, encoded, stored on the server on registration, and recovered on login. {{offline-phase}} describes the
first registration stage of the protocol, and {{online-phase}} describes the
second authentication stage of the protocol. {{configurations}} describes how
to instantiate OPAQUE using different cryptographic dependencies and parameters.

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

## Key Recovery {#key-recovery}

This specification defines a key recovery mechanism that uses the hardened OPRF output
as a seed to directly derive the private and public key using the `DeriveAuthKeyPair()`
function defined in {{key-creation}}.

### Envelope Structure {#envelope-structure}

The key recovery mechanism defines its `Envelope` as follows:

~~~
struct {
  uint8 nonce[Nn];
  uint8 auth_tag[Nm];
} Envelope;
~~~

nonce: A unique nonce of length `Nn` used to protect this Envelope.

auth_tag: Authentication tag protecting the contents of the envelope, covering the envelope nonce,
and `CleartextCredentials`.

### Envelope Creation {#envelope-creation}

Clients create an `Envelope` at registration with the function `Store` defined below.

~~~
Store(randomized_pwd, server_public_key, client_private_key,
               server_identity, client_identity)

Input:
- randomized_pwd, randomized password.
- server_public_key, The encoded server public key for
  the AKE protocol.
- client_private_key, The encoded client private key for
  the AKE protocol.
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
2. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
3. auth_key = Expand(randomized_pwd, concat(envelope_nonce, "AuthKey"), Nh)
4. export_key = Expand(randomized_pwd, concat(envelope_nonce, "ExportKey"), Nh)
5. seed = Expand(randomized_pwd, concat(envelope_nonce, "PrivateKey"), Nsk)
6. _, client_public_key = DeriveAuthKeyPair(seed)
7. cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
8. auth_tag = MAC(auth_key, concat(envelope_nonce, cleartext_creds))
9. Create Envelope envelope with (envelope_nonce, auth_tag)
10. Output (envelope, client_public_key, masking_key, export_key)
~~~

### Envelope Recovery {#envelope-recovery}

Clients recover their `Envelope` during login with the `Recover` function
defined below.

~~~
Recover(randomized_pwd, server_public_key, envelope,
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
3. seed = Expand(randomized_pwd, concat(envelope.nonce, "PrivateKey"), Nsk)
4. client_private_key, client_public_key = DeriveAuthKeyPair(seed)
5. cleartext_creds = CreateCleartextCredentials(server_public_key,
                      client_public_key, server_identity, client_identity)
6. expected_tag = MAC(auth_key,
                      concat(envelope.nonce, inner_env, cleartext_creds))
7. If !ct_equal(envelope.auth_tag, expected_tag),
     raise KeyRecoveryError
8. Output (client_private_key, export_key)
~~~

# Offline Registration {#offline-phase}

This section describes the registration flow, message encoding, and helper functions.
In a setup phase, the client chooses its password, and the server chooses its own pair
of private-public AKE keys (server_private_key, server_public_key) for use with the
AKE, along with a Nh-byte oprf_seed. The server can use the same pair of keys with multiple
clients and can opt to use multiple seeds (so long as they are kept consistent for
each client). These steps can happen offline, i.e., before the registration phase.

Once complete, the registration process proceeds as follows. The client inputs
the following values:

- password: client password.
- creds: client credentials, as described in {{client-material}}.

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
the following function.

~~~
FinalizeRequest(password, blind, response, server_identity, client_identity)

Input:
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
    Store(randomized_pwd, response.server_public_key,
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
- credential_identifier: client credential identifier.
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
    Recover(randomized_pwd, server_public_key, envelope,
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

The implementation of DeriveAuthKeyPair is as follows:

~~~
DeriveAuthKeyPair(seed)

Input:
- seed, pseudo-random byte sequence used as a seed.

Output:
- private_key, a private key.
- public_key, the associated public key.

Steps:
1. private_key = HashToScalar(seed, dst="OPAQUE-HashToScalar")
2. public_key = ScalarBaseMult(private_key)
3. Output (private_key, public_key)
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
ClientFinish(client_identity, password, server_identity, ke2)

State:
- state, a ClientState structure

Input:
- client_identity, the optional encoded client identity, which is set
  to client_public_key if not specified.
- password, an opaque byte string containing the client's password.
- server_identity, the optional encoded server identity, which is set
  to server_public_key if not specified.
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
                    server_public_key, ke2)
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
5. state.ke1 = ke1
6. Output (ke1, client_secret)
~~~

~~~
ClientFinalize(client_identity, client_private_key, server_identity,
               server_public_key, ke2)

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
5. ikm = TripleDHIKM(server_secret, ke1.client_keyshare,
                    server_private_key, ke1.client_keyshare,
                    server_secret, client_public_key)
6. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
7. server_mac = MAC(Km2, Hash(preamble))
8. expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
9. Populate state with ServerState(expected_client_mac, session_key)
10. Create KE2 ke2 with (ike2, server_mac)
11. Output ke2
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
  interface in {{dependencies}}. Examples include Argon2 {{?I-D.irtf-cfrg-argon2}},
  scrypt {{?RFC7914}}, and PBKDF2 {{?RFC2898}} with fixed parameter choices.
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
- Client and server identifier: As described in {{client-material}}, clients
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

# Flowchart

## Login

~~~
              Server                             Client
                                        |
                                        |    | ID  | Password
                                        |    |     |
                                        |    |     v
                                        |    |   +---------+ +---------+
                                        |    |   | OPRF    | | AKE     |
                                        |    |   | Blind() | | Start() |
                                        |    |   +-------+-+ +----+----+
                                        |    v     OPRF-1|        |
                                        |  +-----+ <-----+        |
+-------+----------+-----------------------+ KE1 |         AKE-1  |
|       |          |                    |  +-----+ <--------------+
|       v ID       | OPRF-1             |
| +-------------+  |                    |
| | User Lookup |  |                    |
| ++-+-+--------+  |                    |
|  | | |           v                    |
|  | | |    +-----------+               |
|  | | | kU | OPRF      |               |
|  | | +--> | Evaluate()+-+ OPRF-2      |
|  | |      +-----------+ |             |
|  | |                    v             |
|  | |         +------------+           |
|  | |Envelope | Credential |   +-----+ |
|  | +-------> | Response   +-> | KE2 +----+---+---------------+
|  |           +------------+   +-----+ |  |   |               | OPRF-2
|  |  pkc                          ^    |  |   |          +----+------+
|  +------> +------------+         |    |  |   |          | OPRF      |
|           | AKE        | AKE-1   |    |  |   |          | Unblind() |
|           | Response() +---------+    |  |   |          +----+------+
+---------> +------------+              |  |   | Masking       |
   AKE-1                                |  |   | - nonce       | OPRF
                                        |  |   | - response    | Output
                                        |  |   |               v
                                        |  |   |           +----------+
                                        |  |   v           | Harden() |
                                        |  | +--------+    +---+------+
                                        |  | | Unmask |        |
                                        |  | +-+------+ <------+ randomized_pwd
                                        |  |   |               |
                                        |  |   | - pkc         |
                                        |  |   | - Envelope    v
                                        |  |   +------------> +----------+
                                        |  |                  | Key      |
                                        |  | AKE-2            | Recovery |
                                        |  +--------------->  ++--------++
                                        |                      | sku    |
                                        |                      v        |
               +---------+              | +-----+   AKE-3  +----------+ |
               | AKE     | <--------------+ KE3 | <--------+ AKE      | |
               | Finish()|              | +-----+          | Finish() | |
               +----+----+              |                  +-+--------+ |
                    |                   |                    |          |
                    v                   |                    v          v
             Session Key                |             Session Key  Export Key
~~~

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
oprf_seed: 98ee70b2c51d3e89d9c08b00889a1fa8f3947a48dac9ad994e946f408a
2c31250ee34f9d04a7d85661bab11c67048ecfb7a68c657a3df87cff3d09c6af9912a
1
credential_identifier: 31323334
masking_nonce: 7cb33db5ba8082e4f4bfb830e8e3f525b0ddcb70469b34224758d7
25ce53ac76
client_private_key: 21c97ffc56be5d93f86441023b7c8a4b629399933b3f845f5
852e8c716a60408
client_public_key: 5cc46fdc0337a684e126f8663deacc67872a7daffc75312a1d
6377783935f932
server_private_key: 030c7634ae24b9c6d4e2c07176719e7a246850b8e019f1c71
a23af6bdb847b0b
server_public_key: 1ac449e9cdd633788069cca1aaea36ea359d7c2d493b254e5f
fe8d64212dcc59
server_nonce: cae1f4fee4ee4ba509fda550ea0421a85762305b1db20e37f4539b2
327d37b80
server_keyshare: 5e5c0ac2904c7d9bf38f99e0050594e484b4d8ded8038ef6e0c1
41a985fa6b35
server_private_keyshare: a4abffe3bef8082b78323ea4507fbb0ce8105ca62b38
1919a35767deaa699709
masking_key: 077adba76f768fd0979f8dc006ca297e7954ebf0e81a893021ee24ac
c35e1a3f4b5e0366c15771133082ec21035ae0ef0d8bcd0e59d26775ae953b9552fdf
bf2
KE1: 1ef5fc13fa7695e81b5fcadf57eb49a579b10e4f51bbee11afb278608592456b
8837b6c0709160251cbebe0d55e4423554c45da7a8952367cf336eb623379e80dae2f
1e0cd79b733131d499fb9e77efe0f235d73c1f920bdc5816259ad3a7429
~~~

#### Output Values

~~~
KE2: 2e1bb024ff255d0f35eb7b1f11174b3e60d8aaabb11ea347a6da0c1964594f4f
7cb33db5ba8082e4f4bfb830e8e3f525b0ddcb70469b34224758d725ce53ac76094c0
aa800d9a0884392e4efbc0479e3cb84a38c9ead879f1ff755ad762c06812b9858f82c
9722acc61b8eb1d156bc994839bf9ed8a760615258d23e0f94fa2cffadc655ed0d6ff
6914066427366019d4e6989b65d13e38e8edc5ae6f82aa1b6a46bfe6ca0256c64d0cf
db50a3eb7676e1d212e155e152e3bbc9d1fae3c679aacae1f4fee4ee4ba509fda550e
a0421a85762305b1db20e37f4539b2327d37b805e5c0ac2904c7d9bf38f99e0050594
e484b4d8ded8038ef6e0c141a985fa6b3528ef79e28dbd3783322ab69900a43be8919
a840cfcc5aa31a8f42b6f2a0c1ce1f9fa50c58dc5787a957af588580117b70d304639
dc68851224301bbbae9cd654
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
oprf_seed: f7664fae89be455ee3350b04a85eab390b2dc63256fbd311d8de944b45
b859e6
credential_identifier: 31323334
masking_nonce: 21cd364318a92b2afbfccea5d80d337f07defe40d92673a52f3844
058f5d949a
client_private_key: 41ffab7c86e2b0916361fb6a69f9a097e3ef2f83f8fd5f95c
c79432eabf3e020
client_public_key: 0251bc2a7e0cb7c043eec5ee7d1b769b69f85b0fa19d1ae907
5416e93fa01689de
server_private_key: 61764783412278e6ce3c6c66f1995a2a30b5824be6a6d31ca
d35a578ec3d9353
server_public_key: 03727dd31712275905b1a3cca3bbb33bc71034a1d0c3801be0
20541933dd497f18
server_nonce: 2b772c1eb569cc2b57741bf3be630e377c8245b11d0b6ad1fe1d606
490c27208
server_keyshare: 02a59205c836a2ab86e19dbd9a417818052179e9a5c99221e2d1
d8a780dfe4734d
server_private_keyshare: e8c25741b201c2ba00abe390e5a3933a75efdb71b50e
1e0087cc7235f6f9448a
masking_key: 5bb4d884375d7dcbd562a62190cc569ccc809cff9d5aa5e176d48e96
46b558eb
KE1: 031ac7e5c8099fcb7de5ad5b6cf33ff53078dbee1da64f15f6cd53b2afe6e332
06a91c9485d74c9010185f462ce1eec52f588a8e392f36915849b6bfcb6bd5b904037
6a35db8f7e582569dba2e573c4af1462f91c59a9bdee253ed13f60108746252
~~~

#### Output Values

~~~
KE2: 02200f91b03819f6a4b0957216fc94a2230d75d0e1be1fe0ced9434b0ec9d23a
5621cd364318a92b2afbfccea5d80d337f07defe40d92673a52f3844058f5d949a604
39294e7567fc29643e0d5c8799d0dffbbfc8609558b982012fa90aef2ce52b1ffdd8f
96bda49f5306ae346cd745812d3a953ff94712e4ed0acc67c99b432860e337fe3234b
ba88415ac55368b938106cca4049b5c13496fe167d3a092bd990e2b772c1eb569cc2b
57741bf3be630e377c8245b11d0b6ad1fe1d606490c2720802a59205c836a2ab86e19
dbd9a417818052179e9a5c99221e2d1d8a780dfe4734d7325a81225091665460460ec
37fcf0431f738ba6cb80b63756ee70c6e43aeae5
~~~
