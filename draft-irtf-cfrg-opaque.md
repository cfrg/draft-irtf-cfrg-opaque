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
    title: "HPAKE: Password authentication secure against cross-site user
impersonation"
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
    title: "A method for making password-based
key exchange resilient to server compromise"

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

  I-D.irtf-cfrg-hash-to-curve:
  I-D.irtf-cfrg-voprf:
  I-D.sullivan-tls-opaque:

  keyagreement: DOI.10.6028/NIST.SP.800-56Ar3

  OPAQUE:
    title: "OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation
    Attacks"
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
    title: "Highly-efficient and composable
password-protected secret sharing (or: how to protect your bitcoin wallet
online)"
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

Password authentication is the prevalent form of authentication in
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
to middle boxes, and more.

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
retrieval of client's secrets solely based on a password; and being
amenable to a multi-server distributed implementation where offline
dictionary attacks are not possible without breaking into a threshold
of servers (such a distributed solution requires no change or awareness
on the client side relative to a single-server implementation).

OPAQUE is defined and proven as the composition of two functionalities:
an oblivious pseudorandom function (OPRF) and an authenticated key exchange (AKE) protocol. It can be seen
as a "compiler" for transforming any suitable AKE protocol into a secure
aPAKE protocol. (See {{security-considerations}} for requirements of the
OPRF and AKE protocols.) This document specifies OPAQUE instantiations based
on a variety of AKE protocols, including HMQV {{HMQV}}, 3DH {{SIGNAL}}
and SIGMA {{SIGMA}}. In general, the modularity of OPAQUE's design makes it
easy to integrate with additional AKE protocols, e.g., IKEv2, and with future
ones such as those based on post-quantum techniques.

OPAQUE consists of two stages: registration and authenticated key exchange.
In the first stage, a client registers its password with the server and stores
its encrypted credentials on the server. In the second stage, a client obtains
those credentials, recovers them using the client's password, and subsequently uses
them as input to an AKE protocol.

Currently, the most widely deployed PKI-free aPAKE is SRP {{?RFC2945}}, which is
vulnerable to pre-computation attacks, lacks a proof of security, and is less efficient
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

- Client (C): Entity which has knowledge of a password and wishes to authenticate.
- Server (S): Entity which authenticates clients using passwords.
- password: An opaque byte string containing the client's password.
- (skX, pkX): An AKE key pair used in role X; skX is the private key and pkX is
  the public key. For example, (client_private_key, client_public_key) refers to C's private and public key.
- kX: An OPRF private key used for role X. For example, as described in
  {{create-reg-response}}, oprf_key refers to the private OPRF key for client C known
  only to the server.
- I2OSP and OS2IP: Convert a byte string to and from a non-negative integer as
  described in {{?RFC8017}}. Note that these functions operate on byte strings in
  big-endian byte order.
- concat(x0, ..., xN): Concatenate byte strings. For example,
  `concat(0x01, 0x0203, 0x040506) = 0x010203040506`.
- random(n): Generate a random byte string of length `n` bytes.
- xor(a,b): Apply XOR to byte strings. For example, `xor(0xF0F0, 0x1234) = 0xE2C4`.
  It is an error to call this function with two arguments of unequal
  length.
- ct_equal(a, b): Return `true` if `a` is equal to `b`, and false otherwise.
  This function is constant-time in the length of `a` and `b`, which are assumed
  to be of equal length, irrespective of the values `a` or `b`.

Except if said otherwise, random choices in this specification refer to
drawing with uniform distribution from a given set (i.e., "random" is short
for "uniformly random"). Random choices can be replaced with fresh outputs from
a cryptographically strong pseudorandom generator, according to the requirements
in {{!RFC4086}}, or pseudorandom function.

The name OPAQUE is a homonym of O-PAKE where O is for Oblivious. The name
OPAKE was taken.

# Cryptographic Protocol and Algorithm Dependencies {#dependencies}

OPAQUE relies on the following protocols and primitives:

- Oblivious Pseudorandom Function (OPRF, {{I-D.irtf-cfrg-voprf}}):
  - Blind(x): Convert input `x` into an element of the OPRF group, randomize it
    by some scalar `r`, producing `M`, and output (`r`, `M`).
  - KeyGen(): Generate an OPRF private and public key. OPAQUE only requires an
    OPRF private key. We write `(oprf_key, _) = KeyGen()` to denote use of this
    function for generating secret key `oprf_key` (and discarding the corresponding
    public key).
  - Evaluate(k, M): Evaluate input element `M` using private key `k`, yielding
    output element `Z`.
  - Unblind(r, Z): Remove random scalar `r` from `Z`, yielding output `N`.
  - Finalize(x, N, info): Compute the OPRF output using input `x`, `N`, and domain
    separation tag `info`.
  - SerializeScalar(s): Map a scalar `s` to a unique byte array `buf` of fixed
    length.
  - DeserializeScalar(buf): Map a byte array `buf` to a scalar `s`, or fail if
    the input is not a valid byte representation of a scalar.
  - SerializedElement: A serialized OPRF group element, a byte array of fixed
    length.
  - SerializedScalar: A serialized OPRF scalar, a byte array of fixed length.

- Cryptographic hash function:
  - Hash(m): Compute the cryptographic hash of input message `m`. The type of the
    hash is determined by the chosen OPRF group.
  - Nh: The output size of the Hash function.

- Memory Hard Function (MHF):
  - Harden(msg, params): Repeatedly apply a memory hard function with parameters
    `params` to strengthen the input `msg` against offline dictionary attacks.
    This function also needs to satisfy collision resistance.

Note that we only need the base mode variant (as opposed to the verifiable mode
variant) of the OPRF described in {{I-D.irtf-cfrg-voprf}}.

# Offline Registration {#offline-phase}

Registration is executed between a client C and a
server S. It is assumed S can identify C and the client can
authenticate S during this registration phase. This is the only part
in OPAQUE that requires an authenticated channel, either physical, out-of-band,
PKI-based, etc. This section describes the registration flow, message encoding,
and helper functions. Moreover, C has a key pair (client_private_key, client_public_key) for an AKE protocol
which is suitable for use with OPAQUE; See {{online-phase}}. (client_private_key, client_public_key) may be
randomly generated for the account or provided by the calling client.
Clients MUST NOT use the same key pair (client_private_key, client_public_key) for two different accounts.

To begin, C chooses password password, and S chooses its own pair of private-public
keys server_private_key and server_public_key for use with the AKE. S can use
the same pair of keys with multiple clients. These steps can happen offline, i.e.,
before the registration phase. Once complete, the registration process proceeds as follows:

~~~
 Client (password, creds)            Server (server_private_key, server_public_key)
 --------------------------------------------------------------------
 (request, blind) = CreateRegistrationRequest(password)

                               request
                      ------------------------->

            (response, oprf_key) = CreateRegistrationResponse(request, server_public_key)

                               response
                      <-------------------------

 (record, export_key) = FinalizeRequest(password, creds, blind, response)

                                record
                      ------------------------->
~~~

{{registration-functions}} describes details of the functions referenced above.

Both client and server MUST validate the other party's public key before use.
See {{validation}} for more details.

Upon completion, S stores C's credentials for later use. See {{credential-file}}
for a recommended storage format.

## Credential Storage {#credential-storage}

OPAQUE makes use of a structure `Envelope` to store client credentials.
The `Envelope` structure embeds the following types of credentials:

- client_private_key: The encoded client private key for the AKE protocol.
- server_public_key: The encoded server public key for the AKE protocol.
- client_identity: The client identity. This is an application-specific value, e.g., an e-mail
  address or normal account name.
- server_identity: The server identity. This is typically a domain name, e.g., example.com.
  See {{identities}} for information about this identity.

Each public and private key value is an opaque byte string, specific to the AKE
protocol in which OPAQUE is instantiated. For example, if used as raw public keys
for TLS 1.3 {{?RFC8446}}, they may be RSA or ECDSA keys as per {{?RFC7250}}.

These credentials are incorporated in the `SecretCredentials` and `CleartextCredentials` structs,
depending on the mode set by the value of `EnvelopeMode`:

~~~
enum {
  base(1),
  custom_identifier(2),
  (255)
} EnvelopeMode;
~~~

The `base` mode defines `SecretCredentials` and `CleartextCredentials` as follows:

~~~
struct {
  opaque client_private_key<1..255>;
} SecretCredentials;

struct {
  opaque server_public_key<1..255>;
} CleartextCredentials;
~~~

The `custom_identifier` mode defines `SecretCredentials` and `CleartextCredentials` as follows:

~~~
struct {
  opaque client_private_key<1..255>;
} SecretCredentials;

struct {
  opaque server_public_key<1..255>;
  opaque client_identity<0..2^16-1>;
  opaque server_identity<0..2^16-1>;
} CleartextCredentials;
~~~

These credentials are embedded into the following `Envelope` structure with
encryption and authentication.

~~~
struct {
  EnvelopeMode mode;
  opaque nonce[32];
  opaque encrypted_creds<1..255>;
} InnerEnvelope;

struct {
  InnerEnvelope inner_env;
  opaque auth_tag[Nh];
} Envelope;
~~~

mode
: The `EnvelopeMode` value. This MUST be one of `base` or `custom_identifier`.

nonce
: A unique 32-byte nonce used to protect this Envelope.

encrypted_creds
: Encoding of encrypted and authenticated `SecretCredentials`.

auth_tag
: Authentication tag protecting the contents of the envelope,
covering `InnerEnvelope` and `CleartextCredentials`.

The full procedure for constructing `Envelope` and `InnerEnvelope` from
`SecretCredentials` and `CleartextCredentials` is described in {{finalize-request}}.
Note that only `SecretCredentials` are stored in the `Envelope` (in encrypted form).

The `EnvelopeMode` value is specified as part of the configuration (see {{configurations}}).

Credential information corresponding to the configuration-specific mode,
along with the client public key `client_public_key` and private key `client_private_key`,
are stored in a `Credentials` object with the following named fields:

- `client_private_key`, the client's private key
- `client_public_key`, the client's public key corresponding to `client_private_key`
- `client_identity`, an optional client identity (present only in the `custom_identifier` mode)
- `server_identity`, an optional server identity (present only in the `custom_identifier` mode)

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
    opaque server_public_key<1..255>;
} RegistrationResponse;
~~~

data
: A serialized OPRF group element.

server_public_key
: An encoded public key that will be used for the online authenticated key exchange stage.

~~~
struct {
    opaque client_public_key<1..255>;
    Envelope envelope;
} RegistrationUpload;
~~~

client_public_key
: An encoded public key, corresponding to the private key `client_private_key`.

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
CreateRegistrationResponse(request, server_public_key)

Input:
- request, a RegistrationRequest structure
- server_public_key, the server's public key

Output:
- response, a RegistrationResponse structure
- oprf_key, the per-client OPRF key known only to the server

Steps:
1. (oprf_key, _) = KeyGen()
2. Z = Evaluate(oprf_key, request.data)
3. Create RegistrationResponse response with (Z, server_public_key)
4. Output (response, oprf_key)
~~~

### FinalizeRequest {#finalize-request}

~~~
FinalizeRequest(password, creds, blind, response)

Parameters:
- params, the MHF parameters established out of band
- mode, the InnerEnvelope mode
- Nh, the output size of the Hash function

Input:
- password, an opaque byte string containing the client's password
- creds, a Credentials structure
- blind, an OPRF scalar value
- response, a RegistrationResponse structure

Output:
- record, a RegistrationUpload structure
- export_key, an additional key

Steps:
1. N = Unblind(blind, response.data)
2. y = Finalize(password, N, "OPAQUE")
3. envelope_nonce = random(32)
4. prk = HKDF-Extract(envelope_nonce, Harden(y, params))
5. Create SecretCredentials secret_creds with creds.client_private_key
6. Create CleartextCredentials cleartext_creds with response.server_public_key
   and custom identifiers creds.client_identity and creds.server_identity if
   mode is custom_identifier
7. pseudorandom_pad =
     HKDF-Expand(prk, "Pad", len(secret_creds))
8. auth_key = HKDF-Expand(prk, "AuthKey", Nh)
9. export_key = HKDF-Expand(prk, "ExportKey", Nh)
10. encrypted_creds = xor(secret_creds, pseudorandom_pad)
11. Create InnerEnvelope inner_env
      with (mode, envelope_nonce, encrypted_creds)
12. auth_tag = HMAC(auth_key, concat(inner_env, cleartext_creds))
13. Create Envelope envelope with (inner_env, auth_tag)
14. Create RegistrationUpload record with (envelope, creds.client_public_key)
15. Output (record, export_key)
~~~

The inputs to HKDF-Extract and HKDF-Expand are as specified in {{RFC5869}}. The underlying hash function
is that which is associated with the OPAQUE configuration (see {{configurations}}).

See {{online-phase}} for details about the output export_key usage.

Upon completion of this function, the client MUST send `record` to the server.

### Credential File {#credential-file}

The server then constructs and stores the `credential_file` object, where `envelope` and `client_public_key`
are obtained from `record`, and `oprf_key` is retained from the output of `CreateRegistrationResponse`.
`oprf_key` is serialized using `SerializeScalar`.

~~~
struct {
    SerializedScalar oprf_key;
    opaque client_public_key<1..255>;
    Envelope envelope;
} credential_file;
~~~

# Online Authenticated Key Exchange {#online-phase}

After registration, the client and server run the authenticated
key exchange stage of the OPAQUE protocol. This stage is composed of a concurrent
OPRF and key exchange flow. The key exchange protocol is authenticated using the
client and server credentials established during registration; see {{offline-phase}}.
The type of keys MUST be suitable for the key exchange protocol. For example, if
the key exchange protocol is 3DH, as described in {{opaque-3dh}}, then the private and
public keys must be Diffie-Hellman keys. At the end, the client proves its
knowledge of the password, and both client and server agree on a mutually authenticated
shared secret key.

OPAQUE produces two outputs: a session secret and an export key. The export key may be used
for additional application-specific purposes, as outlined in {{export-key-usage}}.
The output `export_key` MUST NOT be used in any way before the HMAC value in the
envelope is validated. See {{envelope-encryption}} for more details about this requirement.

## Credential Retrieval

The online AKE stage of the protocol requires clients to obtain and decrypt their
credentials from the server-stored envelope. This process is similar to the offline
registration stage, as shown below.

~~~
 Client (password)             Server (server_private_key, server_public_key, credential_file)
 --------------------------------------------------------------------
 (request, blind) = CreateCredentialRequest(password)

                               request
                      ------------------------->

    response = CreateCredentialResponse(request, server_public_key, credential_file)

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
    opaque server_public_key<1..255>;
    Envelope envelope;
} CredentialResponse;
~~~

data
: A serialized OPRF group element.

server_public_key
: An encoded public key that will be used for the online authenticated
key exchange stage.

envelope
: The client's `Envelope` structure.

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

~~~
CreateCredentialResponse(request, server_public_key, credential_file)

Input:
- request, a CredentialRequest structure
- server_public_key, the public key of the server
- credential_file, the server's output from registration
  (see {{credential-file}})

Output:
- response, a CredentialResponse structure

Steps:
1. Z = Evaluate(DeserializeScalar(credential_file.oprf_key), request.data)
2. Create CredentialResponse response
    with (Z, server_public_key, credential_file.envelope)
3. Output response
~~~

#### RecoverCredentials {#recover-credentials}

~~~
RecoverCredentials(password, blind, response)

Parameters:
- params, the MHF parameters established out of band
- Nh, the output size of the Hash function

Input:
- password, an opaque byte string containing the client's password
- blind, an OPRF scalar value
- response, a CredentialResponse structure

Output:
- client_private_key, the client's private key for the AKE protocol
- server_public_key, the public key of the server
- export_key, an additional key

Steps:
1. N = Unblind(blind, response.data)
2. y = Finalize(password, N, "OPAQUE")
3. contents = response.envelope.contents
4. envelope_nonce = contents.nonce
5. prk = HKDF-Extract(envelope_nonce, Harden(y, params))
6. pseudorandom_pad =
    HKDF-Expand(prk, "Pad", len(contents.encrypted_creds))
7. auth_key = HKDF-Expand(prk, "AuthKey", Nh)
8. export_key = HKDF-Expand(prk, "ExportKey", Nh)
9. Create CleartextCredentials cleartext_creds with response.server_public_key
   and custom identifiers creds.client_identity and creds.server_identity if mode is
   custom_identifier
10. expected_tag = HMAC(auth_key, concat(contents, cleartext_creds))
11. If !ct_equal(response.envelope.auth_tag, expected_tag),
    raise DecryptionError
12. secret_creds = xor(contents.encrypted_creds, pseudorandom_pad)
13. Output (secret_creds.client_private_key, response.server_public_key, export_key)
~~~

## AKE Instantiations {#instantiations}

This section describes instantiations of OPAQUE using 3-message AKEs which
satisfies the forward secrecy and KCI properties discussed in {{security-considerations}}.
As shown in {{OPAQUE}}, OPAQUE cannot use less than three messages so the 3-message
instantiations presented here are optimal in terms of number of messages. On the other
hand, there is no impediment of using OPAQUE with protocols with more than 3 messages
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

The rest of this section is outlined as follows:

- Key schedule utility functions
- 3DH instantiation, including wire format messages
- Outlines of other AKE instantiations, including HMQV and SIGMA-I

### Key Schedule Utility Functions

The key derivation procedures for HMQV, 3DH, and SIGMA-I instantiations
all make use of the functions below, re-purposed from TLS 1.3 {{?RFC8446}}.

~~~
HKDF-Expand-Label(Secret, Label, Context, Length) =
  HKDF-Expand(Secret, HkdfLabel, Length)
~~~

Where HkdfLabel is specified as:

~~~
struct {
   uint16 length = Length;
   opaque label<8..255> = "OPAQUE " + Label;
   opaque context<0..255> = Context;
} HkdfLabel;

Derive-Secret(Secret, Label, Transcript) =
    HKDF-Expand-Label(Secret, Label, Hash(Transcript), Nh)
~~~

HKDF uses Hash as its underlying hash function, which is the same as that
which is indicated by the OPAQUE instantiation. Note that the Label parameter
is not a NULL-terminated string.

### OPAQUE-3DH Instantiation {#opaque-3dh}

OPAQUE-3DH is implemented using a suitable prime order group. All operations in
the key derivation steps in {{derive-3dh}} are performed in this group and
represented here using multiplicative notation. The output of OPAQUE-3DH is a
session secret `session_key` and export key `export_key`.

#### OPAQUE-3DH Messages

The three messages for OPAQUE-3DH are described below.

~~~
struct {
  CredentialRequest request;
  uint8 client_nonce[32];
  opaque client_info<0..2^16-1>;
  uint8 client_keyshare[Npk];
} KE1;
~~~

request
: A `CredentialRequest` generated according to {{create-credential-request}}.

client_nonce
: A fresh 32-byte randomly generated nonce.

client_info
: Optional application-specific information to exchange during the protocol.

client_keyshare
: Client ephemeral key share of fixed size Npk, where Npk depends on the corresponding
prime order group.

~~~
struct {
  CredentialResponse response;
  uint8 server_nonce[32];
  uint8 server_keyshare[Npk];
  opaque enc_server_info<0..2^16-1>;
  uint8 mac[Nh];
} KE2;
~~~

response
: A `CredentialResponse` generated according to {{create-credential-response}}.

server_nonce
: A fresh 32-byte randomly generated nonce.

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
  uint8 mac[Nh];
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
HKDF-Extract(salt=0, IKM)
    |
    +-> Derive-Secret(., "handshake secret", info) = handshake_secret
    |
    +-> Derive-Secret(., "session secret", info) = session_key
~~~

From `handshake_secret`, Km2, Km3, and Ke2 are computed as follows:

~~~
server_mac_key =
  HKDF-Expand-Label(handshake_secret, "server mac", "", Nh)
client_mac_key =
  HKDF-Expand-Label(handshake_secret, "client mac", "", Nh)
handshake_encrypt_key =
  HKDF-Expand-Label(handshake_secret, "handshake enc", "", Nh)
~~~

Nh is the output length of the underlying hash function.

The HKDF input parameter `info` is computed as follows:

~~~
info = "3DH keys" || I2OSP(len(client_nonce), 2) || client_nonce
                  || I2OSP(len(server_nonce), 2) || server_nonce
                  || I2OSP(len(client_identity), 2) || client_identity
                  || I2OSP(len(server_identity), 2) || server_identity
~~~

See {{identities}} for more information about identities client_identity and server_identity.

Let `epkS` and `eskS` be `server_keyshare` and the corresponding secret key,
and `epkU` and `eskU` be `client_keyshare` and the corresponding secret key.
The input parameter `IKM` the concatenation of three DH values computed by
the client as follows:

~~~
IKM = epkS^eskU || pkS^eskU || epkS^skU
~~~

Likewise, `IKM` is computed by the server as follows:

~~~
IKM = epkU^eskS || epkU^skS || pkU^eskS
~~~

#### OPAQUE-3DH Encryption and Key Confirmation {#hmqv-core}

Clients and servers use keys Km2 and Km3 in computing KE2.mac and KE3.mac,
respectively. These values are computed as HMAC(mac_key, transcript), where
mac_key and transcript are as follows:

- KE2.mac: mac_key is Km2 and transcript is the concatenation of KE1 and KE2,
excluding KE2.mac.
- KE3.mac: mac_key is Km3 and transcript is the concatenation of KE1 and KE2,
including KE2.mac.

The server applicaton info, an opaque byte string `server_info`, is encrypted
using a technique similar to that used for secret credential encryption.
Specifically, a one-time-pad is derived from Ke2 and then used as input to XOR
with the plaintext. In pseudocode, this is done as follows:

~~~
info_pad = HKDF-Expand(Ke2, "encryption pad", len(server_info))
enc_server_info = xor(info_pad, server_info)
~~~

### Alternate AKE instantiations

It is possible to instantiate OPAQUE with other AKEs, such as HMQV {{HMQV}} and SIGMA-I.
HMQV is similar to 3DH but varies in its key schedule. SIGMA-I uses digital signatures
rather than static DH keys for authentication. Specification of these instantiations is
left to future documents.

OPAQUE may also be instantiated with any post-quantum (PQ) AKE protocol that has the message
flow above and security properties (KCI resistance and forward secrecy) outlined
in {{security-considerations}}. Note that such an instantiation is not quantum safe unless
the OPRF is quantum safe. However, an OPAQUE instantiation where the AKE is quantum safe,
but the OPRF is not, would still ensure the confidentiality of application data encrypted
under session_key (or a key derived from it) with a quantum-safe encryption function.

# Configurations {#configurations}

An OPAQUE configuration is a tuple (OPRF, Hash, MHF, EnvelopeMode). The OPAQUE OPRF
protocol is drawn from the "base mode" variant of {{I-D.irtf-cfrg-voprf}}. The
following OPRF ciphersuites supports are supported:

- OPRF(ristretto255, SHA-512)
- OPRF(decaf448, SHA-512)
- OPRF(P-256, SHA-256)
- OPRF(P-384, SHA-512)
- OPRF(P-521, SHA-512)

Future configurations may specify different OPRF constructions.

The OPAQUE hash function is that which is associated with the OPRF variant.
For the variants specified here, only SHA-512 and SHA-256 are supported.

The OPAQUE MHFs include Argon2 {{?I-D.irtf-cfrg-argon2}}, scrypt {{?RFC7914}},
and PBKDF2 {{?RFC2898}} with suitable parameter choices. These may be constant
values or set at the time of password registration and stored at the server.
In the latter case, the server communicates these parameters to the client during
login.

The EnvelopeMode value is defined in {{credential-storage}}. It MUST be one of `base`
or `custom_identifier`.

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
authenticated protocols (e.g., HMQV) but not all of them. We also note that
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

### Identities {#identities}

AKE protocols generate keys that need to be uniquely and verifiably bound to a pair
of identities. In the case of OPAQUE, those identities correspond to client_identity and server_identity.
Thus, it is essential for the parties to agree on such identities, including an
agreed bit representation of these identities as needed.

Applications may have different policies about how and when identities are
determined. A natural approach is to tie client_identity to the identity the server uses
to fetch envelope (hence determined during password registration) and to tie server_identity
to the server identity used by the client to initiate an offline password
registration or online authenticated key exchange session. server_identity and client_identity can also
be part of envelope or be tied to the parties' public keys. In principle, it is possible
that identities change across different sessions as long as there is a policy that
can establish if the identity is acceptable or not to the peer. However, we note
that the public keys of both the server and the client must always be those defined
at time of password registration.

## Envelope Encryption {#envelope-encryption}

The analysis of OPAQUE from {{OPAQUE}} requires the authenticated encryption scheme
used to produce envelope to have a special property called random key-robustness
(or key-committing). This specification enforces this property by utilizing
encrypt-then-HMAC in the construction of envelope. There is no option to use another
authenticated-encryption scheme with this specification. (Deviating from the
key-robustness requirement may open the protocol to attacks, e.g., {{LGR20}}.)
We remark that export_key for authentication or encryption requires no special
properties from the authentication or encryption schemes as long as export_key
is used only after the envelope is validated, i.e., after the HMAC in RecoverCredentials
passes verification.

## Export Key Usage {#export-key-usage}

The export key can be used (separately from the OPAQUE protocol) to provide
confidentiality and integrity to other data which only the client should be
able to process. For instance, if the server is expected to maintain any
client-side secrets which require a password to access, then this export key
can be used to encrypt these secrets so that they remain hidden from the
server.

## Configuration Choice

Best practices regarding implementation of cryptographic schemes
apply to OPAQUE. Particular care needs to be given to the
implementation of the OPRF regarding testing group membership and
avoiding timing and other side channel leakage in the hash-to-curve
mapping. Drafts {{I-D.irtf-cfrg-hash-to-curve}} and
{{I-D.irtf-cfrg-voprf}} have detailed instantiation and
implementation guidance.

## Static Diffie-Hellman Oracles

While one can expect the practical security of the OPRF function
(namely, the hardness of computing the function without knowing the
key) to be in the order of computing discrete logarithms or solving
Diffie-Hellman, Brown and Gallant [BG04] and Cheon {{Cheon06}} show an
attack that slightly improves on generic attacks. For the case that
q-1 or q+1, where q is the order of the group G, has a t-bit divisor,
they show an attack that calls the OPRF on 2^t chosen inputs and
reduces security by t/2 bits, i.e., it can find the OPRF key in time
2^{q/2-t/2} and 2^{q/2-t/2} memory. For typical curves, the attack
requires an infeasible number of calls and/or results in insignificant
security loss (\*). Moreover, in the OPAQUE application, these
attacks are completely impractical as the number of calls to the function
translates to an equal number of failed authentication attempts by a
_single_ client. For example, one would need a billion impersonation attempts
to reduce security by 15 bits and a trillion to reduce it by 20 bits - and
most curves will not even allow for such attacks in the first place
(note that this theoretical loss of security is with respect to computing
discrete logarithms, not in reducing the password strength).

(\*) Some examples (courtesy of Dan Brown): For P-384, 2^90 calls reduce
security from 192 to 147 bits; for NIST P-256 the options are 6-bit
reduction with 2153 OPRF calls, about 14 bit reduction with 187 million
calls and 20 bits with a trillion calls. For Curve25519, attacks are
completely infeasible (require over 2^100 calls) but its twist form allows
an attack with 25759 calls that reduces security by 7 bits and one with
117223 calls that reduces security by 8.4 bits.

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
not the point at infinity. For X25519 and X448, validation is as described in
{{?RFC7748}}. In particular, where applicable, endpoints MUST check whether
the Diffie-Hellman shared secret is the all-zero value and abort if so.

## OPRF Hardening

Hardening the output of the OPRF greatly increases the cost of an offline
attack upon the compromise of the password file at the server. Applications
SHOULD select parameters that balance cost and complexity.

## Client and Server Identities

The client identity (client_identity) and server identity (server_identity) are optional parameters
which are left to the application to designate as monikers for the client
and server. If the application layer does not supply values for these
parameters, then they will be omitted from the creation of the envelope
during the registration stage. Furthermore, they will be substituted with
client_identity = client_public_key and server_identity = server_public_key during the authenticated key exchange stage.

The advantage to supplying a custom client_identity and server_identity (instead of simply relying
on a fallback to client_public_key and server_public_key) is that the client can then ensure that any
mappings between client_identity and client_public_key (and server_identity and server_public_key) are protected by the
authentication from the envelope. Then, the client can verify that the
client_identity and server_identity contained in its envelope matches the client_identity and server_identity supplied by
the server.

However, if this extra layer of verification is unnecessary for the
application, then simply leaving client_identity and server_identity unspecified (and using client_public_key and
server_public_key instead) is acceptable.

<!-- TODO(caw): bring this back after updating later -->

<!-- ## Envelope considerations

It is possible to dispense with encryption in the construction of envelope to
obtain a shorter envelope (resulting in less storage at the server and less
communication from server to client). The idea is to derive client_private_key from prk.
However, for cases where client_private_key is not a random string of a given length, we
define a more general procedure. Namely, what is derived from prk is a random
seed used as an input to a key generation procedure that generates the pair
(client_private_key, client_public_key). In this case, secret_credentials is empty and cleartext_credentials
contains server_public_key. The random key generation seed is defined as
HKDF-Expand(KdKey; info="KG seed", L)
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

## Client Enumeration {#SecEnumeration}

Client enumeration refers to attacks where the attacker tries to learn
whether a given client identity is registered with a server. Preventing
such attacks requires the server to act with unknown client identities
in a way that is indistinguishable from its behavior with existing
clients. Here we suggest a way to implement such defense, namely, a way for
simulating a CredentialResponse for non-existing clients.
Note that if the same CredentialRequest is received
twice by the server, the response needs to be the same in both cases (since
this would be the case for real clients).
For protection against this attack, one would apply the encryption function in
the construction of envelope to all the key material in envelope.
The server S will have two keys MK, MK' for a pseudorandom function f.
f refers to a regular pseudorandom function such as HMAC or CMAC.
Upon receiving a CredentialRequest for a non-existing
client client_identity, S computes oprf_key=f(MK; client_identity) and oprf_key'=f(MK'; client_identity) and responds with
CredentialResponse carrying Z=M^oprf_key and envelope, where the latter is computed as follows.
prk is set to oprf_key' and secret_creds is set to the all-zero string (of the
length of a regular envelope plaintext). Care needs to be taken to avoid side
channel leakage (e.g., timing) from helping differentiate these
operations from a regular server response.
The above requires changes to the server-side implementation but not to the
protocol itself or the client side.

There is one form of leakage that the above allows and whose prevention would
require a change in OPAQUE.
An attacker that attempts authentication with the same CredentialRequest twice and receives
different responses can conclude that either the client registered with the
service between these two activations or that the client was registered before
but changed its password in between the activations (assuming the server
changes oprf_key at the time of a password change). In any case, this
indicates that client_identity is a registered client at the time of the second activation.
To conceal this information, S can implement the derivation of oprf_key
as oprf_key=f(MK; client_identity) also for registered clients. Hiding changes in envelope, however,
requires a change in the protocol. Instead of sending envelope as is,
S would send an encryption of envelope under a key that the client derives from the
OPRF result (similarly to prk) and that S stores during password
registration. During the authenticated key exchange stage, the client will derive
this key from the OPRF result, will use it to decrypt envelope, and continue with the
regular protocol. If S uses a randomized encryption, the encrypted envelope will look
each time as a fresh random string, hence S can simulate the encrypted envelope also
for non-existing clients.

Note that the first case above does not change the protocol so its
implementation is a server's decision (the client side is not changed).
The second case, requires changes on the client side so it changes OPAQUE
itself.

[[https://github.com/cfrg/draft-irtf-cfrg-opaque/issues/22: Should this variant be documented/standardized?]]

## Password Salt and Storage Implications

In OPAQUE, the OPRF key acts as the secret salt value that ensures the infeasibility
of pre-computation attacks. No extra salt value is needed. Also, clients never
disclose their password to the server, even during registration. Note that a corrupted
server can run an exhaustive offline dictionary attack to validate guesses for the client's
password; this is inevitable in any aPAKE protocol. (OPAQUE enables a defense against such
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
to Richard Barnes, Dan Brown, Eric Crockett, Paul Grubbs, Fredrik oprf_keyivinen,
Payman Mohassel, Jason Resch, Greg Rubin, and Nick Sullivan.

# Test Vectors

This section contains test vectors for the OPAQUE-3DH specification. Each test
vector specifies the configuration information, protocol inputs, intermeidate
values computed during registration and authentication, and protocol outputs.
All values are encoded in hexadecimal strings. The configuration information
includes the (OPRF, Hash, MHF, EnvelopeMode) tuple, along with the group
to which the AKE authentication keys correspond.

## OPAQUE-3DH Test Vector 1

### Configuration

~~~
Group: ristretto255
EnvelopeMode: 00
OPRF: 0001
SlowHash: Identity
Hash: SHA512
~~~

### Input Values

~~~
server_nonce: 534a8d6ca099313c73f909ecadd9973644203036913b162134def00
fdf8b8a18
oprf_key: 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be03
7e50b
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63
e3263503
server_private_keyshare: bfd25bddcd9190db01fdc127247eb2461d78281233d8
77b4564a00404cb79700
client_nonce: 1a7c15f8ca50bb7a8d654035ad59488a33758b80fc1cc1fa7cc4d92
50c00f567
server_info: 6772656574696e677320616c696365
client_info: 68656c6c6f20626f62
client_private_keyshare: 1d6078acf052615f1e3206b9aa9aed95cb0f04daa534
0ccb52534871f1158f09
envelope_nonce: ff05735be871d25c4fa25f2a65e26386fad3eda2ba1e093562844
1ed18bbe818
server_keyshare: dcc991d13fa137302cc1adce95e6f9087f503d88e12d90200682
2e6da438ec22
blind_registration: c604c785ada70d77a5256ae21767de8c3304115237d262134
f5e46e512cf8e03
client_public_key: fcca4fd8732b9887f566bbdcdb738c884f5390b360f43b5b3a
4b81b3bb7e060d
client_private_key: 31aca12a23a2a03db43c91fafe6d32589e2d8f09d8004d605
0ec275317cc7f08
client_keyshare: 408c2a2025080d6507b6250f3dc1ac420c37134bf14d7b1be542
c4d8cfd64a52
server_public_key: 76ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14856
974424a8561115
server_private_key: ccde5849510d7175da028ccccba666e446b9418cf7ba9383b
9530c75474bcb04
~~~

### Intermediate Values

~~~
auth_key: c0ee18ecc5ae7012bcf641a28c2d21ebc198492f1d75ed7ee7cc60b6c5f
c2a6e5f0ad974fc8f0f48dacfcac765d2b626fce0728f3abbee16d522fe2fa108270c
server_mac_key: 18685231e1442f5547af5f9c965fc6a951428a963f26ef99cea69
53873296df81b71e89c05d9bd4abf6863a1e3215f3fe4a202e33f7164c90d250d00a8
dd4a91
envelope: 00ff05735be871d25c4fa25f2a65e26386fad3eda2ba1e0935628441ed1
8bbe81800228f595ba5f6cf5b9c590bc270cbdc1b46b570b76db941ff14035630294f
b8c42ae21c6d965b5ee07b9a86687941dc9594b3f0c92317b367fd19d168b810d7b08
787319d837367607662e9d545c5e5abecc469e544903a570e2efdb168bbb8603d11c8
prk: ec754de047f914e9adf78a82925d70f90478c0e74ea4124de5ba92e8bd935691
641b6a6ad00ad7d101d232c11fdbe1a578d4795bc62e73fb7e42d6ef234bf2e1
client_mac_key: 1b73e32b32aad3e94a8bfd664532c9cf8c3385d8ec62badd59873
270e02f854436b68ade26d0efa0c6b4b41e4970d950d6e7a5ca292427952730105bba
f89896
pseudorandom_pad: 8f796a0957e5783ef936764c5a26e52b87282940364827144e3
660c568ebd3e69d14
handshake_encrypt_key: 26eea148eeaad14bba63d6d30cac46ddb1d37971f6fe1d
dfc80955271f4d242c0db5824d5df69b3a6f619753733a26640d20e35b8589c6b7448
df7d902155ed4
handshake_secret: 46c0c3d90c38b9cf3a0c3f19248adef96365e059a4a0034b4b2
d36efda24174620e0894bcb0916dcaa79cdb1a7f475e9b809c0f4a072c8bf4b6b4735
87838641
~~~

### Output Values

~~~
registration_response: 1867301bcc67bdf8e640b7d6edcbe2a65488446417b50d
30cdba66ccb379e572002076ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14
856974424a8561115
export_key: 39a81bd85c701bcb4396d7d6fad5a67712aff40a4a7d806094f84dbbb
56bf371d8b9b522abba314dc5203cf387c4be187128e3270b151023221c9fc86fff11
4a
registration_upload: 0020fcca4fd8732b9887f566bbdcdb738c884f5390b360f4
3b5b3a4b81b3bb7e060d00ff05735be871d25c4fa25f2a65e26386fad3eda2ba1e093
5628441ed18bbe81800228f595ba5f6cf5b9c590bc270cbdc1b46b570b76db941ff14
035630294fb8c42ae21c6d965b5ee07b9a86687941dc9594b3f0c92317b367fd19d16
8b810d7b08787319d837367607662e9d545c5e5abecc469e544903a570e2efdb168bb
b8603d11c8
registration_request: 241b621c417c0705b5ea7a8b7cdd5039fd61e6b63effe2a
44418164c4d49003e
session_key: f27806d4c588eac72b3da00dba21a2852cf3a91d5164d9ac4dcfa896
a3cbbb2836785a33ba9d5fb193068347b0ed20bcde94a4482e4456d9c5666eb6191de
a47
KE3: bf680d0471ffd1885f050b51c3e57b59e4b3ec31c49dd893644028f30e4bca44
6cf2f047abd75f739bffccac0af3fe24b8255d3391c4899608df9539f97b5c91
KE2: e83812f06568d57b8cdfdcc90fe91454e21bd25dd2a1c32dd1599a2e4a4b6c35
002076ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14856974424a85611150
0ff05735be871d25c4fa25f2a65e26386fad3eda2ba1e0935628441ed18bbe8180022
8f595ba5f6cf5b9c590bc270cbdc1b46b570b76db941ff14035630294fb8c42ae21c6
d965b5ee07b9a86687941dc9594b3f0c92317b367fd19d168b810d7b08787319d8373
67607662e9d545c5e5abecc469e544903a570e2efdb168bbb8603d11c8534a8d6ca09
9313c73f909ecadd9973644203036913b162134def00fdf8b8a18dcc991d13fa13730
2cc1adce95e6f9087f503d88e12d902006822e6da438ec22000f1e4413f30f38967bd
8c1f3a65da5f825ec34bf0c56f7c50117388593922db7bf53b1f451f6623df88c355a
a7fb7f9464e00c14683bbab1386ee43e59952a44b73af76d7659a81b219270f2543de
fc1
KE1: b68e0e356f8490fa9c3bed952e16cc02db21eda686b3c484f3d9d912caa41f76
1a7c15f8ca50bb7a8d654035ad59488a33758b80fc1cc1fa7cc4d9250c00f56700096
8656c6c6f20626f62408c2a2025080d6507b6250f3dc1ac420c37134bf14d7b1be542
c4d8cfd64a52
~~~

## OPAQUE-3DH Test Vector 2

### Configuration

~~~
Group: ristretto255
EnvelopeMode: 01
OPRF: 0001
SlowHash: Identity
Hash: SHA512
~~~

### Input Values

~~~
server_nonce: be1b6a9ee06b76c648efd2e57300cae3418a2137ee3abcfa018431e
e50876be4
oprf_key: 89c61a42c8191a5ca41f2fe959843d333bcf43173b7de4c5c119e0e0d8b
0e707
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd
4171ea02
server_private_keyshare: 79450906dc147d9b73edf5c98f7d1970ebcc825c474c
ecddc671f3290038c205
client_nonce: 79a442d9fbebbd244e27fd10ea255dcec9f43e9b2c6a33575eb3377
5b081d77e
server_info: 6772656574696e677320616c696365
server_identity: 76ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf1485697
4424a8561115
client_info: 68656c6c6f20626f62
client_private_keyshare: 46124f54f47fec6b66c53e4154475d27a0e046c5d1c8
54b2f3680defdff14a0e
envelope_nonce: f627cf8e027b5fca94ba970dc06866b79d5914abb16526835bbbd
6c46d705cf2
server_public_key: 76ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14856
974424a8561115
client_identity: fcca4fd8732b9887f566bbdcdb738c884f5390b360f43b5b3a4b
81b3bb7e060d
blind_registration: 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9db
cec831b8c681a09
client_public_key: fcca4fd8732b9887f566bbdcdb738c884f5390b360f43b5b3a
4b81b3bb7e060d
client_private_key: 31aca12a23a2a03db43c91fafe6d32589e2d8f09d8004d605
0ec275317cc7f08
client_keyshare: 5a7396b6e6e0dbb1690ba3b69061ba864fda0c2c078520f01804
ef15c0b25d56
server_keyshare: ea25f0b5ed03ec29b5eaacf21dde7d4c1fcb4e34ddb2d7c6e4a7
1b6d10e3d870
server_private_key: ccde5849510d7175da028ccccba666e446b9418cf7ba9383b
9530c75474bcb04
~~~

### Intermediate Values

~~~
auth_key: 3f5312f1c60350f5c46ab368434035f5740eef83a6d5cbc7ed3720fb78a
c32a5ea9fc734296efc9167350492903c449d85ac774b05f37efcc3ea0bcd9c600f55
server_mac_key: 341d064d83d7415f28f9528771f10d768891ac552409d44ee7324
8eed0ed4b58f48ac7406fe8c7fce9cb13029bc30d4e2bc48711fe5932b499a55cb7c1
85ce1b
envelope: 01f627cf8e027b5fca94ba970dc06866b79d5914abb16526835bbbd6c46
d705cf20022ceffb2fded3ff3dfd323ef4411cc213014316463bdd6692907cd4caffd
885530d0d9ceb917641b2550623727461b647b81b1e81ae67fcb0f57ad93175306ff3
26b1ec66433a67ed4da46f1cb54c80c24cf805f3df77a2b81c7f5fda0bcb06f093fa9
prk: 8923bf6277c4593732d3cdfaa559f531acd20e5cbec5bc180ddf6795d7a4d7ab
a39404eed4f94adcf25c84d6e8764fb9bb943db894ac9655fed08b68097de0f9
client_mac_key: 37ffae79ea8bd0b83884ca45e65ce63d4a4210a39d8c158e8772b
31fa96a9e174b6badeb15454a14ac46ce4f758a1c9fe1748b7b598c7cb6c7431dbac4
448b45
pseudorandom_pad: cedf83514c15d07d731e5b788036df5d2669fa4e32dfb1294aa
d1c43dadb42fcafd1
handshake_encrypt_key: 7eec22c81178c6f91176961bc78ccb8a9459f9a54c565b
f44ab8d2445074bd994672f02e8d7a9974722acfca87a56ffbed3d4092d4ef5e8941c
5b117227e07d9
handshake_secret: cc5ce99088b2459ed11e6664e479c19d285878dc0961c47e741
221029f9ca3df00b2cd35b643a263a872e49de7f6bb95d68cb5793d36087b1d6a0b3c
7565f3c8
~~~

### Output Values

~~~
registration_response: 088ac01ebf5700f0c96bc2988509343cb7e2dd6f0df820
d0fb807faa11a26f56002076ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14
856974424a8561115
export_key: 38b7c0fc66819d9cd51e0e0051d87e159c2be9829f3e2c2ad42560b12
b7b7950588be9bf8db36bfd9fe26ff55a57e42a5345ee1fa9734f78c8e4e427ede4ee
9e
registration_upload: 0020fcca4fd8732b9887f566bbdcdb738c884f5390b360f4
3b5b3a4b81b3bb7e060d01f627cf8e027b5fca94ba970dc06866b79d5914abb165268
35bbbd6c46d705cf20022ceffb2fded3ff3dfd323ef4411cc213014316463bdd66929
07cd4caffd885530d0d9ceb917641b2550623727461b647b81b1e81ae67fcb0f57ad9
3175306ff326b1ec66433a67ed4da46f1cb54c80c24cf805f3df77a2b81c7f5fda0bc
b06f093fa9
registration_request: c8d2e9ba503bf3f8821226653314427edb1ec8a3ecc94a5
dfbbe33d59d07b645
session_key: db9fa3c0bec6ce623b1b124b843c5b8a8d79f93247396eed72e8c06a
dba2d5389692f988d65e3adb0d59ed477e37fab31633daa514780522ada541eb354d7
d49
KE3: 3e2538f0a28344ba9db33e55270e1db37fedde130e13b088bad31239e3bbf358
7922f8039e205e842f2a012f8db39cb66994b9970363d24f128b882b2b696724
KE2: 5079b16709b195b3b63257b419efb752bd0603170160fa72b828ce9ff9209c0c
002076ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14856974424a85611150
1f627cf8e027b5fca94ba970dc06866b79d5914abb16526835bbbd6c46d705cf20022
ceffb2fded3ff3dfd323ef4411cc213014316463bdd6692907cd4caffd885530d0d9c
eb917641b2550623727461b647b81b1e81ae67fcb0f57ad93175306ff326b1ec66433
a67ed4da46f1cb54c80c24cf805f3df77a2b81c7f5fda0bcb06f093fa9be1b6a9ee06
b76c648efd2e57300cae3418a2137ee3abcfa018431ee50876be4ea25f0b5ed03ec29
b5eaacf21dde7d4c1fcb4e34ddb2d7c6e4a71b6d10e3d870000f853360d8962c60208
1c1a7f11e0ab10b045d752511f9254a95e390e72b9c60f073c85bf789649883a1c712
6b1150e6db4607ac5491833b25f91211ab4e7fc292912562f1397c15e6e91a4972b00
052
KE1: 7024ca0d5423176294fbb9ca968d8ce3fc879a231f1ceef69e672c89e02ded59
79a442d9fbebbd244e27fd10ea255dcec9f43e9b2c6a33575eb33775b081d77e00096
8656c6c6f20626f625a7396b6e6e0dbb1690ba3b69061ba864fda0c2c078520f01804
ef15c0b25d56
~~~
