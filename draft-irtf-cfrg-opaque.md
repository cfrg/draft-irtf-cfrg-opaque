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
- (client/server_private_key, client/server_public_key): An AKE key pair used by
  either the client and server, denoting either the private or public key. For example,
  (client_private_key, client_public_key) refers to C's private and public key.
- oprf_key: An OPRF private key known only to the server.
- I2OSP and OS2IP: Convert a byte string to and from a non-negative integer as
  described in Section 4 of {{?RFC8017}}. Note that these functions operate on byte strings in
  big-endian byte order.
- concat(x0, ..., xN): Concatenate byte strings. For example,
  `concat(0x01, 0x0203, 0x040506) = 0x010203040506`.
- random(n): Generate a cryptographically secure pseudorandom byte string of length `n` bytes.
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
  - SerializedScalar: A serialized OPRF scalar, a byte array of fixed length.\

Note that we only need the base mode variant (as opposed to the verifiable mode
variant) of the OPRF described in {{I-D.irtf-cfrg-voprf}}.

- Cryptographic hash function:
  - Hash(m): Compute the cryptographic hash of input message `m`. The type of the
    hash is determined by the chosen OPRF group.
  - Nh: The output size of the Hash function.

- Authenticated Key Exchange (AKE, {{instantiations}}):
  - Npk: The size of the public keys used for the key exchange protocol
  - Nsk: The size of the private keys used for the key exchange protocol

- Memory Hard Function (MHF):
  - Harden(msg, params): Repeatedly apply a memory hard function with parameters
    `params` to strengthen the input `msg` against offline dictionary attacks.
    This function also needs to satisfy collision resistance.


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
  opaque client_private_key[Nsk];
} SecretCredentials;

struct {
  opaque server_public_key[Npk];
} CleartextCredentials;
~~~

The `custom_identifier` mode defines `SecretCredentials` and `CleartextCredentials` as follows:

~~~
struct {
  opaque client_private_key[Nsk];
} SecretCredentials;

struct {
  opaque server_public_key[Npk];
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
  opaque encrypted_creds[Nsk];
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
are recommended to be stored in a `Credentials` object with the following named fields:

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
    Envelope envelope;
} RegistrationUpload;
~~~

client_public_key
: The client's encoded public key, corresponding to the private key `client_private_key`.

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
`oprf_key` is serialized using `SerializeScalar`. The below structure represents an example of how
these values might be conveniently stored together.

~~~
struct {
    SerializedScalar oprf_key;
    opaque client_public_key[Npk];
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
    opaque server_public_key[Npk];
    Envelope envelope;
} CredentialResponse;
~~~

data
: A serialized OPRF group element.

server_public_key
: The server's encoded public key that will be used for the online authenticated
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

We use the parameters Npk and Nsk to denote the size of the public and private keys used
in the AKE instantation. Npk and Nsk must adhere to the output size limitations of the
HKDF Expand function from {{RFC5869}}, which means that Npk, Nsk <= 255 * Nh.

The rest of this section includes key schedule utility functions used by OPAQUE-3DH,
and then provides a detailed specification for OPAQUE-3DH, including its wire format
messages.

### Key Schedule Utility Functions

The key derivation procedures for OPAQUE-3DH makes use of the functions below, re-purposed
from TLS 1.3 {{?RFC8446}}.

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

Derive-Secret(Secret, Label, Transcript-Hash) =
    HKDF-Expand-Label(Secret, Label, Transcript-Hash, Nh)
~~~

HKDF uses Hash as its underlying hash function, which is the same as that
which is indicated by the OPAQUE instantiation. Note that the Label parameter
is not a NULL-terminated string.

### OPAQUE-3DH Instantiation {#opaque-3dh}

OPAQUE-3DH is implemented using a suitable prime order group. All operations in
the key derivation steps in {{derive-3dh}} are performed in this group and
represented here using multiplicative notation. The output of OPAQUE-3DH is a
session secret `session_key` and export key `export_key`.

The parameters Npk and Nsk are set to be equal to the size of a scalar in the
associated prime order group.

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
  struct {
    CredentialResponse response;
    uint8 server_nonce[32];
    uint8 server_keyshare[Npk];
  } inner_ke2;
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
    +-> Derive-Secret(., "handshake secret", Hash(preamble)) = handshake_secret
    |
    +-> Derive-Secret(., "session secret", Hash(preamble)) = session_key
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

- KE2.mac = HMAC(Km2, Hash(concat(preamble, KE2.enc_server_info)), where
  preamble is as defined in {{derive-3dh}}.
- KE3.mac = HMAC(Km3, Hash(concat(preamble, KE2.enc_server_info, KE2.mac)),
  where preamble is as defined in {{derive-3dh}}.

The server applicaton info, an opaque byte string `server_info`, is encrypted
using a technique similar to that used for secret credential encryption.
Specifically, a one-time-pad is derived from Ke2 and then used as input to XOR
with the plaintext. In pseudocode, this is done as follows:

~~~
info_pad = HKDF-Expand(Ke2, "encryption pad", len(server_info))
enc_server_info = xor(info_pad, server_info)
~~~

# Configurations {#configurations}

An OPAQUE configuration is a tuple (OPRF, Hash, MHF, EnvelopeMode, Group). The OPAQUE
OPRF protocol is drawn from the "base mode" variant of {{I-D.irtf-cfrg-voprf}}. The
following OPRF ciphersuites are supported:

- OPRF(ristretto255, SHA-512)
- OPRF(decaf448, SHA-512)
- OPRF(P-256, SHA-256)
- OPRF(P-384, SHA-512)
- OPRF(P-521, SHA-512)

Future configurations may specify different OPRF constructions.

The OPAQUE hash function is that which is associated with the OPRF ciphersuite.
For the ciphersuites specified here, only SHA-512 and SHA-256 are supported.

The OPAQUE MHFs include Argon2 {{?I-D.irtf-cfrg-argon2}}, scrypt {{?RFC7914}},
and PBKDF2 {{?RFC2898}} with fixed parameter choices.

The EnvelopeMode value is defined in {{credential-storage}}. It MUST be one
of `base` or `custom_identifier`. Future specifications may specify alternate
EnvelopeMode values and their corresponding Envelope structure.

The Group mode identifies the group used in the OPAQUE-3DH AKE. This SHOULD
match that of the OPRF.

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
be part of envelope or be tied to the parties' public keys. In principle, it is possible
that identities change across different sessions as long as there is a policy that
can establish if the identity is acceptable or not to the peer. However, we note
that the public keys of both the server and the client must always be those defined
at time of password registration.

The client identity (client_identity) and server identity (server_identity) are
optional parameters which are left to the application to designate as monikers for the client
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
to Richard Barnes, Dan Brown, Eric Crockett, Paul Grubbs, Fredrik Kuivinen,
Payman Mohassel, Jason Resch, Greg Rubin, and Nick Sullivan.

# Alternate AKE Instantiations {#alternate-akes}

It is possible to instantiate OPAQUE with other AKEs, such as HMQV {{HMQV}} and SIGMA-I.
HMQV is similar to 3DH but varies in its key schedule. SIGMA-I uses digital signatures
rather than static DH keys for authentication. Specification of these instantiations is
left to future documents. A sketch of how these instantiations might change is included
in the next subsection for posterity.

The AKE private key size (Nsk) is limited to the output size of the HKDF Expand function
from {{RFC5869}}.  Future specifications which have keys exceeding this size should
specify a mechanism by which private keys and their corresponding public keys can be
deterministically derived from a fixed-length seed.

OPAQUE may also be instantiated with any post-quantum (PQ) AKE protocol that has the message
flow above and security properties (KCI resistance and forward secrecy) outlined
in {{security-considerations}}. Note that such an instantiation is not quantum safe unless
the OPRF is quantum safe. However, an OPAQUE instantiation where the AKE is quantum safe,
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
vector specifies the configuration information, protocol inputs, intermeidate
values computed during registration and authentication, and protocol outputs.
All values are encoded in hexadecimal strings. The configuration information
includes the (OPRF, Hash, MHF, EnvelopeMode, Group) tuple, where the Group
matches that which is used in the OPRF.

## OPAQUE-3DH Test Vector 1

### Configuration

~~~
OPRF: 0001
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 01
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
~~~

### Input Values

~~~
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4b0d024592b44b45b5ab575ed2c30be4fb4e2cad6381d1d19658f
291f1b34d16
client_private_key: 8bcb0b70dac18de24eef12e737d6b28724d3e37774e0b092f
9f70b255defaf04
client_public_key: 360e716c676cfe4d9968d1a352ed3faf17603863e0a7aa1905
df6ea129343b09
server_private_key: f3a0829898a89239dce29ccc98ec8b449a34b255ba1e6f944
829d18e0d589b0f
server_public_key: 66e130c6eb5b41f851b235b03a0eafeaa883f64147bc62cb74
9c22c762389c3c
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ec4d31ad299933daea56b0d10a16da583546b0f456c3688b40fa74e
c76b27533
client_nonce: d6660d1c7c131df831f54627bb9937094d16df1e2d91657b7ed7c4b
ba0bdf61c
server_keyshare: 5214e3ddc73db786480b79fa2da787f2080b82cbe922c2a9592b
44597d9a702e
client_keyshare: a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e787492
b98265a5e651
server_private_keyshare: c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a7
4432f685b2b6a4b42a0c
client_private_keyshare: de2e98f422bf7b99be19f7da7cac62f1599d35a225ec
6340149a0aaff3102003
blind_registration: 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc1e921
3a043b743b95800
blind_login: c4d5a15f0d5ffc354e340454ec779f575e4573a3886ab5e57e4da298
4bdd5306
oprf_key: 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6ca5b914b335512fe
70508
~~~

### Intermediate Values

~~~
auth_key: e284d678e1b4d2e6872919b4ebe6050ee8accb42b1a8c93b75e785a93b1
d550848582ef16f8869b02e05e964bcb0a69c7f5657ed1b1b8badaf6461ec70703883
prk: 443b6799745582a80289c40108edcc843f6f0980455b25f316388646c2ae24f1
adecc91a0e7152a8308f0d04657f9c19a61ffa82fcf1de914ae98dc0697fdf23
pseudorandom_pad: cf5993a028468d8effed2b20cdba881a4f79b895dea0faea418
9b5156f1da80a
envelope: 014b0d024592b44b45b5ab575ed2c30be4fb4e2cad6381d1d19658f291f
1b34d16449298d0f287006cb10239c7fa6c3a9d6baa5be2aa404a78b87ebe3032f207
0e9bcd0b3d94741f9459f19fbae2a3b8a0e928067d4942161eae56ae8df68f7562e7f
ef26746cfa1d57970efa05b972bc0464096d4b9afe16dc03a3ee99cae4c13
handshake_secret: fe23b16e6b2ded7729541ac5e79eb299d08af69e399e85e3639
6624ca30b9295383128be2d765209ffd76f86beda5791a89cf066c0bbf2bf7b28bb52
cb433b6a
handshake_encrypt_key: 92d15a1ea096ff2b7267a20060c8e221dd2439b7a5257e
5270dfb2fe71feb9bea7127939b81842cb828fa7e118aa22878d8906a936bc68855a4
9cc5264eb8050
server_mac_key: 991c6bdc198659af61b011fd27b1ada125599cec957edcd5162a9
e256893108d22c7bfee954445dbdb994bd4a9e95eba5df718a032974d123d9667c997
d36927
client_mac_key: e70a23c5393d7a78bdc463b76721dc1d35db5532e785e4dab9110
aa86cf52d4c8749dcf579dcb5d803045ef32fdd928129597b2a5e8db982e6ca8d9f6a
e9e32e
~~~

### Output Values

~~~
registration_request: ec9027daa5e9a901d641286a7ded51364142936ac7636e1
42e3f4368b4bd8124
registration_response: 8867d7c8c2c576a6322d49d46078ea32f479aed917c70a
636d3ada4397ea1c0e66e130c6eb5b41f851b235b03a0eafeaa883f64147bc62cb749
c22c762389c3c
registration_upload: 360e716c676cfe4d9968d1a352ed3faf17603863e0a7aa19
05df6ea129343b09014b0d024592b44b45b5ab575ed2c30be4fb4e2cad6381d1d1965
8f291f1b34d16449298d0f287006cb10239c7fa6c3a9d6baa5be2aa404a78b87ebe30
32f2070e9bcd0b3d94741f9459f19fbae2a3b8a0e928067d4942161eae56ae8df68f7
562e7fef26746cfa1d57970efa05b972bc0464096d4b9afe16dc03a3ee99cae4c13
KE1: e06a32011e1b1704eb686b263e5d132fff4e9f6429cd93b98db107485006792c
d6660d1c7c131df831f54627bb9937094d16df1e2d91657b7ed7c4bba0bdf61c00096
8656c6c6f20626f62a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e787492
b98265a5e651
KE2: 66f6b5fa1a4eb6bd7a0c93ed2639a31cba0d02e2df744003641d5a30a4a12364
66e130c6eb5b41f851b235b03a0eafeaa883f64147bc62cb749c22c762389c3c014b0
d024592b44b45b5ab575ed2c30be4fb4e2cad6381d1d19658f291f1b34d16449298d0
f287006cb10239c7fa6c3a9d6baa5be2aa404a78b87ebe3032f2070e9bcd0b3d94741
f9459f19fbae2a3b8a0e928067d4942161eae56ae8df68f7562e7fef26746cfa1d579
70efa05b972bc0464096d4b9afe16dc03a3ee99cae4c13ec4d31ad299933daea56b0d
10a16da583546b0f456c3688b40fa74ec76b275335214e3ddc73db786480b79fa2da7
87f2080b82cbe922c2a9592b44597d9a702e000f7b6ceecdb40fdf1862821800f8f90
c915d421a4c5e6dd3cd9001130bebc214df436a88c94e80ccd063f66ae356005de40f
750995a464e6db4d2518cae9c3f01bf079abe6ee2830e5e0943a2201b378
KE3: 566c1d7569c868b01c38d185cd52260052f24db7464ffcb6de98374bda9276f4
91756f73b2955c67eab3815c6b6597065c5235e95e8cdcc5f39b6912a8ebe8eb
export_key: bc5e5d68ea86c68afdf6a87a805279583d04c780912bde1090c3f8bed
7244aed1aaa2aaa8856fece02ef6a89c70ff130e7b5b6af323c7f8cee22b40008de06
79
session_key: a45af1884e01e765274c6b526fa14230cca096c174d1b8a788a5cfd5
18edbdf827dad2b32b0c3ec53539a8c137f73ddae095284e256a35faa81f70671f6b7
fc9
~~~

## OPAQUE-3DH Test Vector 2

### Configuration

~~~
OPRF: 0002
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 01
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
~~~

### Input Values

~~~
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 48e0756fcb5444eec63cdd491f43aa063a75b9cbf6de822c1720f
bce2ceec9bd
client_private_key: 614bb578f29cc677ea9e7aea3e4839413997e020f9377b63c
13584156a09a46dd2a425c41eac0e313a47e99d05df72c6e1d58e6592577a0d
client_public_key: a8f6d7dad9ec587964d6dffb1b63f951dc30a934137eb42057
f390d593dfafb6a687ec5c3ad3c35bb6a71338dc8106bd53b3a4fcec6110a1
server_private_key: 4c115060bca87db7d73e00cbb8559f84cb7a221b235b0950a
0ab553f03f10e1386abe954011b7da62bb6599418ef90b5d4ea98cc28aff517
server_public_key: bc66494bf44cdfed66f6b4c482a18e00a3d16a09d11775064f
963cc7bae3b6592a6b03fb982f5b5676972005a29d1dcfd46b6986088ca9d4
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 358bed9420d3ea5989cf28ce49a9434272c5ed7f20976f45a594f8f
e31404aca
client_nonce: 35463401907d0075bc097ab16d4c4a8360b2d092c2396b15ee4e6f7
c7708e8ed
server_keyshare: 5472ca0fc98d652ded1ba4edc7d876a791b2c2a61c1201ffe354
8e0f3a1d479e1629a35a7f910ef27f46c93ade70ee4cbdf9a2183f6d0754
client_keyshare: 46770873fdab1e43177a9f1b2d127a44e0b4c2becf3ac4545248
ef410d143cce32f76df27f47cf19347b42e3cd1f9432cda204701e188c32
server_private_keyshare: 0676f161ab555182908dbd7947b1c988956fa73b17b3
73b72fd4e3c0264a26aa4cab20fd864de6ceab345e8d755997956ddd1f265e8be105
client_private_keyshare: d0f08ac99ef2ab5b26fa7b2a6d920c76cf03fb57bdea
cc2ec39330fd6e7f9e5dbdfcb571168f337dd52851d4bc07947c858dc735bab8ca2b
blind_registration: a614f1894bcf6a1c7cef33909b794fe6e69a642b20f4c9118
febffaf6b6a31471fe7794aa77ced123f07e56cc27de60b0ab106c0b8eab127
blind_login: 668b3aab5207735beb86c5379228da260159dc24f7c5c2483a81aff8
d9ff676ebd81db28eb1e147561c478a3f84cbf77037f01025c7fd42a
oprf_key: 93dd2d051e90efe4e2e093bc1e82b80e8cce6afa798ac214abffabac2a2
58015d93e9faf0f2009d16c797646097d761e2b84e0df971d7b39
~~~

### Intermediate Values

~~~
auth_key: 8cf17b875c1d8520d68516589be90128069cb2e0cd5872a81a144b30979
7932905bdc96ebb7947516d2e0bd36fbfef10718f49623f080d9082d19750c00eb838
prk: c9a58588d00a70b56486e69ad1e98bb1c6e085af245af66407ea25af804305c7
06843c12bc930351881a9687d334b722363d32e2e1c5d2bcf2a024db6b97eff3
pseudorandom_pad: 90018b02347a97de1de0136d01560db389a48bb233c658584c8
d419f62175d16e336b5933fc97ccdc32fc908259eea3c7579de2a6710ff33
envelope: 0148e0756fcb5444eec63cdd491f43aa063a75b9cbf6de822c1720fbce2
ceec9bdf14a3e7ac6e651a9f77e69873f1e34f2b0336b92caf1233b8db8c58a081ef9
7b31929057216572fcf9682095204198fa94ac504ff547853e15471802357ad919658
bf36bff1c6ef2a6e3fce48ac9f0df03de17bf4d48d747f4baab312915fff554c6a62e
e5d938d7d21c86c0b9d2bd2166c81e855d993872
handshake_secret: a28a002ff874724e93a91233929161d07ed39bd830c71a0f67e
f3be5297b28e8420a800590665b121f6ac243d269934cfdccf853ee18f02d80966404
a2a6a407
handshake_encrypt_key: 5fb3091aba28ca5730955b1c9292237ed3e3878ca9c330
3370db72580e4551633c377518b384e48362392e3207f76b54dad633af5d15245a3fd
696d132b08803
server_mac_key: 28fe4ae5172f73c6fca40277e76a87d36b4f6e8c39828fd45a6cd
b11d3371b2588907dea61a5d881eadb9e1a32c146c143137644d5296555ea3cce34d4
f08202
client_mac_key: 8a4461e7dd55b87d41cd4e58f1ad1056a49ad4a7361de12cd3caf
ba4304fedd70afb1497a1d2ad1894b9a78cb30ee9904d4ae4d01cff79b5bc22f0b8e5
ce6e53
~~~

### Output Values

~~~
registration_request: d21b318acf1b255d0f009bf3cb24b7b2f88cb58880775b8
dff43a81ab49fe73f0356b70ff3e5c251bc9810767c98491d8187d2cf11dff618
registration_response: c023432da8f17d6e5e740d9d1a0fb55dbc8e1830bd72ec
2e1f59da065858170b05c1f711ca085d8cf5a52ae1ea5198196bd9907dca045c6fbc6
6494bf44cdfed66f6b4c482a18e00a3d16a09d11775064f963cc7bae3b6592a6b03fb
982f5b5676972005a29d1dcfd46b6986088ca9d4
registration_upload: a8f6d7dad9ec587964d6dffb1b63f951dc30a934137eb420
57f390d593dfafb6a687ec5c3ad3c35bb6a71338dc8106bd53b3a4fcec6110a10148e
0756fcb5444eec63cdd491f43aa063a75b9cbf6de822c1720fbce2ceec9bdf14a3e7a
c6e651a9f77e69873f1e34f2b0336b92caf1233b8db8c58a081ef97b3192905721657
2fcf9682095204198fa94ac504ff547853e15471802357ad919658bf36bff1c6ef2a6
e3fce48ac9f0df03de17bf4d48d747f4baab312915fff554c6a62ee5d938d7d21c86c
0b9d2bd2166c81e855d993872
KE1: 30a31f471b8adc9e3fcb796a6ee1ee97edabf6a77468c58621a0cfaecee3c1ac
1a1dbe16a0fbf6fc4d2f882d8431303bded7a16d207f840c35463401907d0075bc097
ab16d4c4a8360b2d092c2396b15ee4e6f7c7708e8ed000968656c6c6f20626f624677
0873fdab1e43177a9f1b2d127a44e0b4c2becf3ac4545248ef410d143cce32f76df27
f47cf19347b42e3cd1f9432cda204701e188c32
KE2: 2453710eb7a3226bfedb501efe06772d9450aa9ba9eed8adddd931964364e3d3
d5d2a22822f0d85569fa396b8e9c6657ff5115dbd4c0a218bc66494bf44cdfed66f6b
4c482a18e00a3d16a09d11775064f963cc7bae3b6592a6b03fb982f5b5676972005a2
9d1dcfd46b6986088ca9d40148e0756fcb5444eec63cdd491f43aa063a75b9cbf6de8
22c1720fbce2ceec9bdf14a3e7ac6e651a9f77e69873f1e34f2b0336b92caf1233b8d
b8c58a081ef97b31929057216572fcf9682095204198fa94ac504ff547853e1547180
2357ad919658bf36bff1c6ef2a6e3fce48ac9f0df03de17bf4d48d747f4baab312915
fff554c6a62ee5d938d7d21c86c0b9d2bd2166c81e855d993872358bed9420d3ea598
9cf28ce49a9434272c5ed7f20976f45a594f8fe31404aca5472ca0fc98d652ded1ba4
edc7d876a791b2c2a61c1201ffe3548e0f3a1d479e1629a35a7f910ef27f46c93ade7
0ee4cbdf9a2183f6d0754000f2b395f8374de23ab55d5df4f3c231dba69dc7555d669
7aa07ab21b25753c89cce0cd4eab76e052e1cedc4975d172cc68e9a5bab4b76a04566
d0090db13106e5665de977cf2938e316b4512aa895385
KE3: c48cbf3f0f3044981f480f95f1dbf3d318d4fd36d89d34e9f8ec270c550a3fda
fd6ab538c2265cf6e1eee1ba9211028093f11e51541c2e7e5df768ff5b69d43a
export_key: ebecedc130354dfce0f422bf20b32df3255253d86477c5ac01fd831ec
923e73187df33cfdcb001ee3000d66cf7586df87c2e82670be7d7bcf15798315cd59a
43
session_key: fc68992d26fd5ef68047bce1122e8cd9cf5ae4f37174aa35685992a9
e1665b1723ed60f5dd88da589abd99fae06029a6561c893dd444af497503e9969393c
eef
~~~

## OPAQUE-3DH Test Vector 3

### Configuration

~~~
OPRF: 0003
Hash: SHA256
SlowHash: Identity
EnvelopeMode: 01
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
~~~

### Input Values

~~~
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ec3ae53be6348ca77b048fc4b438b2122838a64bebdeade29df00
c950f23691c
client_private_key: 67b5bcebad6393e2d0b7db3d2b4597a670a5204b2b606f5a2
8328916e1e5ea5b
client_public_key: 030e2b9005157dfd740a13c9525a2132512a463927174d9728
0f80f962d1a650e3
server_private_key: fc2e715b2db1e7a3ad4ff8af1b24daa1922d13757ac9df4ad
c7e4e0b6b399433
server_public_key: 03ca5ebe2c9b87ff1e76e2e72f8a59273fe5c9688fee7dd2f2
8964187a0940c397
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 8fb04cbf47e4f1c82dff07d9a74a1d1308ee8e059fe450989d7b0ef
e2f3e1ff9
client_nonce: 41b8b9e4a15fe4b97f1f67950e6d8baf30996b3560c14c3bdd14dcc
178901608
server_keyshare: 03a716d72106b7ad668ae097e553a46f4dd96961816fbe8e2243
43a7f0ab95a05a
client_keyshare: 037086638b1beb10b9a6a44ea0ee5b369081004df36cba0c16c8
d485482de57ff6
server_private_keyshare: a6532c99c1ea3f03d05f6e78dc1edabd3b9631be9f8b
274d9aaf671bfb6a7753
client_private_keyshare: 29bf435021b89c683259773bc686956af0c7822ba317
fb5e86028c44b92bd3af
blind_registration: 3e7c5057e09e220065ea8c257c0dd6055c4b401063eff0bf2
42b4cd534a79bad
blind_login: dcf6744d388ca013ef33edd369304ed96fc56c7c6c0bd369f8e926ff
e4854a59
oprf_key: f6b3e908bdb38e3c626a939e19daca653b9217801b5d51cef66d9fdbd94
a5354
~~~

### Intermediate Values

~~~
auth_key: c6728b90093ec2c9e30c40d735a9c86e4796df87e944b347a2d1ba37d4e
3ad6c
prk: 0718c7f6b8da2b4ab0dedc4a9065fb5f23074ccc3e9359339d8cf342d3e86cca
pseudorandom_pad: 3906c723e3e214fc89eed793446361f5b74252906463b9baa8e
68b38b43635cb
envelope: 01ec3ae53be6348ca77b048fc4b438b2122838a64bebdeade29df00c950
f23691c5eb37bc84e81871e59590cae6f26f653c7e772db4f03d6e080d4022e55d3df
90f2587ceff5ae97ed173d2608175ebe0b62c928b133e4686a7b49adcca432908e
handshake_secret: c08513d97b72b063c0b3b32a5548188b90c9118641280cfb38e
e7269fd8a1f25
handshake_encrypt_key: 8ebb03db32a571fffdf45d87625b32f1b8204a9973a54b
d10d733ae6e274af91
server_mac_key: 1dd0a19c52360cac630e6797642414ea8969a59dd3cae2d3cdef7
9e06d7bdf90
client_mac_key: 99e7d9a887dfed0fe61e4e7bd69e0d5ec7352a15db46c46b009a5
9b1dc0501a7
~~~

### Output Values

~~~
registration_request: 0295067c743d15a0a9d4c6c15511b67e3858e9e22f8c44a
0c1de6e33cda494024b
registration_response: 02465cd175b404fc1426b3b9518a79ee219007679909f4
59f92cfc89929c89458e03ca5ebe2c9b87ff1e76e2e72f8a59273fe5c9688fee7dd2f
28964187a0940c397
registration_upload: 030e2b9005157dfd740a13c9525a2132512a463927174d97
280f80f962d1a650e301ec3ae53be6348ca77b048fc4b438b2122838a64bebdeade29
df00c950f23691c5eb37bc84e81871e59590cae6f26f653c7e772db4f03d6e080d402
2e55d3df90f2587ceff5ae97ed173d2608175ebe0b62c928b133e4686a7b49adcca43
2908e
KE1: 0230e8f9b3689b65b952bf044702673c4d5278119b25d3833a3de655b9289f89
e141b8b9e4a15fe4b97f1f67950e6d8baf30996b3560c14c3bdd14dcc178901608000
968656c6c6f20626f62037086638b1beb10b9a6a44ea0ee5b369081004df36cba0c16
c8d485482de57ff6
KE2: 025c6387cee347fa24a57c7021890ee13f435ea5e92b20fb488c3984e060ad4d
6f03ca5ebe2c9b87ff1e76e2e72f8a59273fe5c9688fee7dd2f28964187a0940c3970
1ec3ae53be6348ca77b048fc4b438b2122838a64bebdeade29df00c950f23691c5eb3
7bc84e81871e59590cae6f26f653c7e772db4f03d6e080d4022e55d3df90f2587ceff
5ae97ed173d2608175ebe0b62c928b133e4686a7b49adcca432908e8fb04cbf47e4f1
c82dff07d9a74a1d1308ee8e059fe450989d7b0efe2f3e1ff903a716d72106b7ad668
ae097e553a46f4dd96961816fbe8e224343a7f0ab95a05a000fee2295da79d1439cff
f7228e70e8a0b847886020646b8e7e0d11a701aa26de11287571ea830fc6e27c533cc
0ccd06f
KE3: 152ee6541400f1fcc1d12b693cc5be09e0179243c5b9b8e39a3dc3b47f163a83
export_key: 84117edbfc902081e0602232d0a265650561d46e2fa4a19bcc4b1a2a1
1a0bf2a
session_key: 5c4e9693ec859274ff048d5ca26c5b93b17b65169056e58a4656e8bd
51b0b326
~~~

## OPAQUE-3DH Test Vector 4

### Configuration

~~~
OPRF: 0004
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 01
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
~~~

### Input Values

~~~
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 3c0b7617acd16ad894b744f13f184f600276b202faad251748c05
0459d7ec6e4
client_private_key: f3cfa0420080cbff2e3431bcc25f80b409c533dd21924d77b
cbd10873989b7e58306b863276ae74049615162a416d508
client_public_key: 02c86369d6eae0978bdd4030b43e0619ce46ea9d91fa6e0e75
75bb12aa4857db98b952d8af9d92f75899c49d0d18793c1e
server_private_key: 2902c13bdc9993d3717bda68fc080b9802ae4effd5dc972d9
f9fb3bbbf106add174393effaf0a175fa8e85f898568620
server_public_key: 0251f78cbd5c7a3fbf4cdaeb755eb8cc4159edb0ef38baebb5
03dbefed5c89c14f7c2b99ed242b3d1de890f7515bad94bd
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 61f5f4b9ced01f90753e5e24c9f9ba8806121d75661894522160b01
7f71b00c1
client_nonce: b46d4178ae6edfc4ec9891ccfa058e8a0f18cb4b9daaf21ca933f5d
6f4a45d34
server_keyshare: 035684e8cdae6ce360c2d3f41e4b059f34f986e92dd50c8255f7
d7dc0c16252ef9b8c9fb9e0c2846053355e7fcfa46781f
client_keyshare: 027044d31354b5b98587d7d144526f6c8528317cc3e9675c90a1
952f4bc2725a6a154f59aed10e4ff7ec68d4917d74122b
server_private_keyshare: 3e3869237f74106241777f230582e849076f08753056
c186437ded8ee22f96e44bd5b6ec07cb131d51cf1324c1238699
client_private_keyshare: 59b596174a682828f3934d510217ce7890f67cafc0ff
aa7a1e1d1ced3c477fea691e696032c8709c86cbcda2b184ad01
blind_registration: 3382c7ec9bdd6e75898e4877d8e2bc16359073c015b92d154
50f7fb395bf52c6ea98384c491fe4e4d423b59de7b0df39
blind_login: 29d29abeabede9788d11782429bff296102f6338df84c9602bfa9e7d
690b1f7a173d07e6d54a419db4a6308f8b09589f
oprf_key: 4283efb9cd1ee4061c6bf884e60a877321ece4f9b6ffd01ce8208254541
3bd9bb5e8f3c63b86ae88d9ce0530b01cb1c3
~~~

### Intermediate Values

~~~
auth_key: 99d7674d17c0de1d77935243b367f76ad6b7934a73187810109468d425e
05a3cf1dec2b96d3c0a9cd05551d3c44a18fb81e394e02c62107444c28624b8c89812
prk: 3f5ea52ab11b79d3bf31a3ef38ac2973255b75dc189da926ed9c8b494d789236
416e905251fefd13a0e4cdf3e9fc0e596d4969fafc39a4f7b3eb43410cc34778
pseudorandom_pad: 22e80b5859da8230c6a8ebb24a6066f290c6fa23b98958811e9
d46e6e89fb49a91dd806d3cc9f6f206112a3381740a1f
envelope: 013c0b7617acd16ad894b744f13f184f600276b202faad251748c050459
d7ec6e4d127ab1a595a49cfe89cda0e883fe6469903c9fe981b15f6a2205661d11603
7f12db380e1ba311b24f707b512562df1780d326472a6fd4440e1fb6b5036dd14fb89
aeb762d43cfc7c9d5ac12826a00eedcaf3b915f780703d40123aaaa441d654d7add91
4d1cf02b5a45e5fb056cdc0d
handshake_secret: d4d05a859a040acb13d06796895020defbb1886c7f2370c8978
44e376cdd59a5dc72d0b80cbb723850228a248fd4029c0b7faf1570ac5ca2ecf19e23
e5c64e0e
handshake_encrypt_key: 1a2b9d8141fc9cb2813e2699ceecebe8146d1bef1bcdfd
ea91601174d0540c83a6121eccbc076395220a66a7b8dfe0768d985d3ad1362f2a4ef
30a7dbc5a0b38
server_mac_key: c403adfc3655a7227c2679fd2417202304fc65cd42e1cbde55537
53be86c2109a4c516536f1758c6cd7ad00ecfdd93e1de686ccb1cc9d0978bc282dfd0
758e2a
client_mac_key: ea69799c01ed83ee5573540b8ca979359bea99ae116444044ff6a
8940ee565e1fd08b2f281e1d59321798470b5c9dbfdbb5c0b4de30d0a0d6716030992
dafaad
~~~

### Output Values

~~~
registration_request: 02fc4b3addc3978fba0bdfacc4fc662bc8af59e00392b0b
6b5fad9a5d6a60a015b4a0e2d1c8e2f95e229fdbdf50ab93a7f
registration_response: 02ba75a6a537e88c57e67208566dfa0193387002d3028c
a8cb0a2c08c2880f1ed91335a6c289d1620feea05b6243b181280251f78cbd5c7a3fb
f4cdaeb755eb8cc4159edb0ef38baebb503dbefed5c89c14f7c2b99ed242b3d1de890
f7515bad94bd
registration_upload: 02c86369d6eae0978bdd4030b43e0619ce46ea9d91fa6e0e
7575bb12aa4857db98b952d8af9d92f75899c49d0d18793c1e013c0b7617acd16ad89
4b744f13f184f600276b202faad251748c050459d7ec6e4d127ab1a595a49cfe89cda
0e883fe6469903c9fe981b15f6a2205661d116037f12db380e1ba311b24f707b51256
2df1780d326472a6fd4440e1fb6b5036dd14fb89aeb762d43cfc7c9d5ac12826a00ee
dcaf3b915f780703d40123aaaa441d654d7add914d1cf02b5a45e5fb056cdc0d
KE1: 02778d77bae1e5e05311469840b632fc724f55070922598457dcb06b22f8fa87
d6ba7886fe34283d8727a1e1d30251a5c9b46d4178ae6edfc4ec9891ccfa058e8a0f1
8cb4b9daaf21ca933f5d6f4a45d34000968656c6c6f20626f62027044d31354b5b985
87d7d144526f6c8528317cc3e9675c90a1952f4bc2725a6a154f59aed10e4ff7ec68d
4917d74122b
KE2: 03ad08056e57dc6424c6210d7e12801ec7de62e2de9decc6f034d000dca821ab
aca9d733e8807d072bb8c211c477d27fc20251f78cbd5c7a3fbf4cdaeb755eb8cc415
9edb0ef38baebb503dbefed5c89c14f7c2b99ed242b3d1de890f7515bad94bd013c0b
7617acd16ad894b744f13f184f600276b202faad251748c050459d7ec6e4d127ab1a5
95a49cfe89cda0e883fe6469903c9fe981b15f6a2205661d116037f12db380e1ba311
b24f707b512562df1780d326472a6fd4440e1fb6b5036dd14fb89aeb762d43cfc7c9d
5ac12826a00eedcaf3b915f780703d40123aaaa441d654d7add914d1cf02b5a45e5fb
056cdc0d61f5f4b9ced01f90753e5e24c9f9ba8806121d75661894522160b017f71b0
0c1035684e8cdae6ce360c2d3f41e4b059f34f986e92dd50c8255f7d7dc0c16252ef9
b8c9fb9e0c2846053355e7fcfa46781f000f43b7d27437fab590ee0722656db7d778f
d888221aa74e2820b817fd096e1766bcee4ce436a0904b97d9cc77daef99b2530c943
436159fbd2460a63a1b08643c85f02874bb58fcf6fbea35d6cb4333c
KE3: a19ee81549cac039c5ee75af3ff058318792e576f60f78829edf047b6aebda23
3bd6356cc6dbb93898d1779c59b9f083715c3a150b37ad511367a18e3ec1314a
export_key: 03d25687e9c23b9a3918b178933b1d04bed7a0cf66524636d1a9cd61f
c84436cb355a89ba24438a5176ea7cf3a2217e194991334062882841b6129834f2e18
4c
session_key: f2c505133a0ace97a89c559789691da03ec6a70490042e55f3c4ed3e
7e6f25dbc47af926e1ceac60e97a4f3f6ffedf93ab70be492b3db904d9565f3fc5783
467
~~~

## OPAQUE-3DH Test Vector 5

### Configuration

~~~
OPRF: 0005
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 01
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
~~~

### Input Values

~~~
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ded7134d0d1d44a2e0d61e53cb8be9b1b339593941444666eb0fa
097b3f60e71
client_private_key: 004274252f29a6e19915f81b0c7dcea93ce6580e089ede31c
1b6b5b33494581b48678aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5
778ac7f67becfc
client_public_key: 02000202cbe2dcdfe616ffe600cbe24768cdba3066d53d2b58
feffa43e199c833f85963a612b79a2fbfb065f34e2edf51e39ba3db9cbdec0fffcce0
113a5c05b2c28b1
server_private_key: 000739878b22e5c4833d34c486a8510e7cca4c1b81ece04f4
7e8d2554a5ebd83679b4c1e67ed82f2891751aa7094602be672c324929abb1876a7f7
165ac7ec79bfd6
server_public_key: 0300159aed22eed3a1ca9e7a8b063b1b62c3a48b00b7b83edf
6047defdb1b05e14b14faa77afb5f08ffaa04cc8c5df59983e42677f7b6c8d63c0348
15367374543ed1c
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ddb19bf427a720577ab7713a074d0266e8d9c01cc416a4603730106
e072bd617
client_nonce: 6ddafda30afe266fb89dcbabb1b63b67343ad8cf38ba8d1d742ad3a
fdd244a20
server_keyshare: 02003fe52f2e417b5c448309d4a54363aa84725feff99da4639f
caa9d60e5b1bea54a7f5661b05bd4d3a662d6688a76f177c63d1f1a548ff00d5d6c6f
b331b56e1b890
client_keyshare: 0201a487b80b1f7927e7e44eb0cea2498ce462ab21fcb4b8e987
27aac9e91dd8f8e22338953560a0e088934084f2a27b85b31a3ba55b73ff9a0d17333
4667996078929
server_private_keyshare: 0134471b1e6eb4b043b9644c8539857abe3a2022e9c9
fd6a1695bbabe8add48bcd149ff3b840dc8a5d2483705fcc9a39607288b935b0797ac
6b3c4b2e848823ac9af
client_private_keyshare: 002d816be03432370deb7c3c17d9fc7cb4e0ce646e04
e42d638e0fa7a434ed340772a8b5d6253d35895f4cff282d86b2358d89a82ee6523ef
f8db014d9b8b53ad7b1
blind_registration: 003f281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf5
39a41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77eb20c2a
e6ba52fe31e13f
blind_login: 01c28b45f65717a40c38f671d326e196e8a21bf6cfd40327a95f1ccf
c82a9f83a75dae86286729214a1ba9a359ab01833477b8cb91932d0c81667a0e3244b
896ac15
oprf_key: 00363749be19e92df82df1acd3f606cc9faa9dc7ab251997738a3a232f3
52c2059c25684e6ccea420f8d0c793f9f51171628f1d28bb7402ca4aea6465e267b7f
977b
~~~

### Intermediate Values

~~~
auth_key: f0afd01c28e0f482f696541883dcf1bd99b9d7caa31e3df010fdb1c358f
2a5cbc1227d76490e581c3bfdc6f750b07bce108103bb5ad993095e93eb3dec61d4d9
prk: 28c09be7caf34b4d7433f8d95c00c317c85f48f642ed258d7191f748ced451b0
110ff63cddc91f420ca5ab7bea6e46112fccdc4e3417b7b32bf05951ea18cf18
pseudorandom_pad: 881a2b9dbf6f8c008285397a83ab83247c5b8d9c539294285d1
651fe5acde6f365743c33eda01101cd27a44b56f5f5834e12a10d3cea9995cd5321eb
18a9d03f9704
envelope: 01ded7134d0d1d44a2e0d61e53cb8be9b1b339593941444666eb0fa097b
3f60e7188585fb890462ae11b90c1618fd64d8d40bdd5925b0c4a199ca0e44d6e59be
e82d13b6dff0ac2c1762f796912d5c94c7d4446fcbc77b1706e655f49c926e26447bf
87f49fbb5af83378cd494fd6e7a75774622ec97e09150bba77a207726d375890a3148
688de94fbe2e6e5fdb376d623a2180a1f8149d88efc8e10cfa14d88be0dc
handshake_secret: ff9f9a5df820d4c46032faae885e0cdae0df85e457933a099c6
1a57a5f870705d6cccbe6951edb473991357f209d7d2812f6e6b2d8f9ff6edc58188a
7d7377c3
handshake_encrypt_key: 59d9dcad32e375bd6e27a28f94a95453a76d7ca06a29dc
b22f6901b2c6a6b4bfda5f41b2bb106425eb15686a2e08cb03e2ce11692063b953f0a
b1b503cab9806
server_mac_key: a1a277e3a81d84e4528a5ec6701a18a86e90bcc7deeb44f571eef
9e6e3ea5b8de553a543cfd6f188af852c2ca807847b60fd996128956a4595f80534a6
3f7384
client_mac_key: c1f24467fb3733e23f1d1fa5c72de6888713d044ade6e3a5b73a9
2d635af682f3f97b3066c2c1a01ca18e3331bcc4a041c439c337dec80246ec336d8cf
42c9b5
~~~

### Output Values

~~~
registration_request: 03016af598df5549c18c7f904ff395006449477bd594663
b2948142db6d2aac90d204900d669b5e73cfefdc91d7bee857d9522eb996601d2c3f8
25221ed46f51c89ec7
registration_response: 0201b7e055f71ebc3020873cd002596dfce243891fc7f2
278ab1c5bf768886067e779ce4d922dfaa87e3dae9ed4d1ba2bd19ee24c2f33f3f19f
89d5b0eb6865880659c0300159aed22eed3a1ca9e7a8b063b1b62c3a48b00b7b83edf
6047defdb1b05e14b14faa77afb5f08ffaa04cc8c5df59983e42677f7b6c8d63c0348
15367374543ed1c
registration_upload: 02000202cbe2dcdfe616ffe600cbe24768cdba3066d53d2b
58feffa43e199c833f85963a612b79a2fbfb065f34e2edf51e39ba3db9cbdec0fffcc
e0113a5c05b2c28b101ded7134d0d1d44a2e0d61e53cb8be9b1b339593941444666eb
0fa097b3f60e7188585fb890462ae11b90c1618fd64d8d40bdd5925b0c4a199ca0e44
d6e59bee82d13b6dff0ac2c1762f796912d5c94c7d4446fcbc77b1706e655f49c926e
26447bf87f49fbb5af83378cd494fd6e7a75774622ec97e09150bba77a207726d3758
90a3148688de94fbe2e6e5fdb376d623a2180a1f8149d88efc8e10cfa14d88be0dc
KE1: 020142931e5e870e35226b46f8a9692babfabede9ca86ffded305ba079274920
aa78f9a45341b6693765e601237d6a6bce8ddf194f6161144e9a2a1bcaa5860e6637c
d6ddafda30afe266fb89dcbabb1b63b67343ad8cf38ba8d1d742ad3afdd244a200009
68656c6c6f20626f620201a487b80b1f7927e7e44eb0cea2498ce462ab21fcb4b8e98
727aac9e91dd8f8e22338953560a0e088934084f2a27b85b31a3ba55b73ff9a0d1733
34667996078929
KE2: 02000c9ca900d4b470d043136562cd7d9debe13d6595a274e46a1bd9a7a2e3d6
19f6a7cc0324f30fc8fa10f8eefcb7e968c6f2e50cf0e2ee3487d9a80cbe24255600e
b0300159aed22eed3a1ca9e7a8b063b1b62c3a48b00b7b83edf6047defdb1b05e14b1
4faa77afb5f08ffaa04cc8c5df59983e42677f7b6c8d63c034815367374543ed1c01d
ed7134d0d1d44a2e0d61e53cb8be9b1b339593941444666eb0fa097b3f60e7188585f
b890462ae11b90c1618fd64d8d40bdd5925b0c4a199ca0e44d6e59bee82d13b6dff0a
c2c1762f796912d5c94c7d4446fcbc77b1706e655f49c926e26447bf87f49fbb5af83
378cd494fd6e7a75774622ec97e09150bba77a207726d375890a3148688de94fbe2e6
e5fdb376d623a2180a1f8149d88efc8e10cfa14d88be0dcddb19bf427a720577ab771
3a074d0266e8d9c01cc416a4603730106e072bd61702003fe52f2e417b5c448309d4a
54363aa84725feff99da4639fcaa9d60e5b1bea54a7f5661b05bd4d3a662d6688a76f
177c63d1f1a548ff00d5d6c6fb331b56e1b890000ff4c96031fc5dcce08dce6b260b2
24c0697d7eabb487d198f0ebc2d04c60067c8304bb1acd41cc8a1ae37ed9f86aaf6c1
a45a0c0b918cbf8771fd68e9afef9cf3e7a2d05b6165e51643311b84c0834e
KE3: 28dd7ffad8f9a0c9cc882eb6b053368b4f8a42cb38825044e859a91522ee440c
a90dfacaa5248ab869cea4477f9c34fda293719c52d41a4238fe85ca613413a1
export_key: b9af23373f252ab0979b561299de85f0180e04a8edadb334bab37b446
69b5e94817e7d1cb59316433be6cb02f65afeeb9f63a23c388606cc8e7182a3a2a72a
27
session_key: c2036e5e7f315276da62b054ef1c45edf68acaadeccee959d1a6d156
acdf726d4c5505dab8cd4a8510a1e8367f573de95946389f1c121fb2eeb6a8b60272e
07b
~~~

## OPAQUE-3DH Test Vector 6

### Configuration

~~~
OPRF: 0001
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 02
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
~~~

### Input Values

~~~
client_identity: 20fa92f2e4b7ea5b5e677ac4930ff3b93b0043481ab70bc613b2
e16a6dde6b05
server_identity: eae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c8e
de8d6d272c65
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: cb6f425611791dfcfd69d6776e8159bf0c1ad8e9782aed5e9fd54
5a9fa509f56
client_private_key: dc70a99bbabf1ebe98b192e93cedceb9c0164e95b891bd8bc
81721b83d66b00b
client_public_key: 20fa92f2e4b7ea5b5e677ac4930ff3b93b0043481ab70bc613
b2e16a6dde6b05
server_private_key: 709687a36c94592ab76579f42ce1be6961f0700496e71df80
6ebd5320554720d
server_public_key: eae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c
8ede8d6d272c65
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 3a07ad5d3a37413cc30170207f205f5002e8fdbab45f4d24a238168
f20c6bbaf
client_nonce: 5e4a86d3ad25bde635eb1e73daad5acbd9f1a61c4fa8becde4c59cb
618b273de
server_keyshare: 96a9587e233e67f2397f10fec6355b68102534f1f1b115b4ddf7
485840efcd7c
client_keyshare: 54f35db3a52fb0cf2a97918a6987993231d227e28711eaef19a3
e5033632611a
server_private_keyshare: 6650d64df70618a878504ce73dcca27b1af125c67e48
1e7bd49d0b24709b200f
client_private_keyshare: ebb01c59f99bc955df622548e247f7ef180732909ff3
c5f87ff8c7867b8be704
blind_registration: 308f1d3fa1fea402f3c90b04601274050a3c6f467387c2f48
878823949b0e109
blind_login: 141e21373228a44b09d4c00da9a6bbaf9a5e54a1687c07f327833643
4245510b
oprf_key: b7126967aa0cb69c311b71343843ea041bae30e2bde41b548b8fbd8bced
97604
~~~

### Intermediate Values

~~~
auth_key: 6c9e32438cf53661ee6fce9a22ca039cb4d81ef337ff3b02c90bdabfdc3
b2c97c526f455ba28d8b9072441d3923c791761948d2b4144400e32dc517565ae1891
prk: ab659f06f6767ea951a6f832f5ad513d51fcf9ebca89fc8b324f294d67405026
e3143139fcc322ab7bbe619e2a5e9b4eb0deb87cf479ad373442ba5194f6c970
pseudorandom_pad: e5f3a533fe95b02e2f3a7417b561531512a96a922d31adda73f
62edd1c476b10
envelope: 02cb6f425611791dfcfd69d6776e8159bf0c1ad8e9782aed5e9fd545a9f
a509f5639830ca8442aae90b78be6fe898c9dacd2bf240795a01051bbe10f652121db
1b2981438a1648a63465c2d3a7e9cad63494d7adf2c51a3bd40bad0a77f7ca4d29b2b
fb98ce90073e8a079b9e3eff5e498b5096b1727ce9b88c07e385ba6db255c
handshake_secret: b2e4118a508da2a008e429314e22ccd040e918c263710b73118
ffbef05d0868880f6b8ec5e6e9b5b35b0230c684b0102f80f1c01e3140e2046e33862
c8ca17e9
handshake_encrypt_key: c38a172a75104dddac0f02726782a7452f19d41f1bfe18
88d2803f5a857e31f344ad941db9e2d691ef361419fe7bf1a2c1eb7a0389a6ba9da47
ebe6deef7ac3f
server_mac_key: 3af7c8920b89d21d41c2a82d3b89a80d10d5b2449f73175cd04dc
983ef2101669b391f729cb3e26b5beab982fcc257f3124b3c7237beb5f78b8b787f73
47ce09
client_mac_key: 6a113716575eb3b572b8408d81bd79d47a5aa2f0a157201165d1d
71cb0609c1f8ce9948553ace5c94614041606d831885b2cd336412770a54c0e01b8b8
a96f6e
~~~

### Output Values

~~~
registration_request: 3c8b89966e261a5aaf7aeb6dcdd94c87ce311bf197221b8
7ef44632d58f18a05
registration_response: caf9243d7ef3e267815632bf79c85a27a23f218a438815
2a523f6a310949807beae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c8
ede8d6d272c65
registration_upload: 20fa92f2e4b7ea5b5e677ac4930ff3b93b0043481ab70bc6
13b2e16a6dde6b0502cb6f425611791dfcfd69d6776e8159bf0c1ad8e9782aed5e9fd
545a9fa509f5639830ca8442aae90b78be6fe898c9dacd2bf240795a01051bbe10f65
2121db1b2981438a1648a63465c2d3a7e9cad63494d7adf2c51a3bd40bad0a77f7ca4
d29b2bfb98ce90073e8a079b9e3eff5e498b5096b1727ce9b88c07e385ba6db255c
KE1: 8261a1efd78bea73faf256a23c200d729259886530fa43b875c1ca124b09bc7e
5e4a86d3ad25bde635eb1e73daad5acbd9f1a61c4fa8becde4c59cb618b273de00096
8656c6c6f20626f6254f35db3a52fb0cf2a97918a6987993231d227e28711eaef19a3
e5033632611a
KE2: fa1f33a43a03123ebe35345ef93aa23b57ea8bfbee7022b05a179d60768ba02e
eae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c8ede8d6d272c6502cb6
f425611791dfcfd69d6776e8159bf0c1ad8e9782aed5e9fd545a9fa509f5639830ca8
442aae90b78be6fe898c9dacd2bf240795a01051bbe10f652121db1b2981438a1648a
63465c2d3a7e9cad63494d7adf2c51a3bd40bad0a77f7ca4d29b2bfb98ce90073e8a0
79b9e3eff5e498b5096b1727ce9b88c07e385ba6db255c3a07ad5d3a37413cc301702
07f205f5002e8fdbab45f4d24a238168f20c6bbaf96a9587e233e67f2397f10fec635
5b68102534f1f1b115b4ddf7485840efcd7c000f3bd520753cad8c89f1427f0665818
6c969d82e23dd87e80d6aa1b43085cef7af20d8020cf2d033c0c119295af3ffb9383d
01890c582e7bc4b8ced29d547e631f08be2da59690a194921f1793c49613
KE3: a6cb832ee2f1ea8142eaaaf2a3b4e49ac8f1889afb12551db180bc6b4770a1c9
145a24f7a7c5ce4b69245e586812eae39021d1333fd9fe65427830c27d6ea1cd
export_key: 2cc99333ed1f5dfc8a2c4fbec780fe92d4f10f89637590e472ec43617
0f55633896cd83e195424eade961ce85e526d69870d19e828c93250fe07146a2c3e63
aa
session_key: 3a13048fcf62535eded1f23ecef8e0b4f3211771c90970f70102546c
118670a4fc7258b041292a19c2a09612a2a0329d2b389738266a25ce273c7b488e798
de0
~~~

## OPAQUE-3DH Test Vector 7

### Configuration

~~~
OPRF: 0002
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 02
Group: decaf448
Nh: 64
Npk: 56
Nsk: 56
~~~

### Input Values

~~~
client_identity: e0f6146168d32f4b68e042ed5d5608d1108e84a08b6688798ead
0810b4f10d7a91f0767e197e946ebfc487bf62a5ed5684e7ab9137ee1862
server_identity: d49500848e7c06c8a5dd5bda74930ffd20fbef9a2de24a0068e5
bf3dc356852b10327be9803983271450bc6a8c683abcdd73883ee63543e9
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: aa9640f1a4adba93c53e08809a8a0eaae36af9444ad7cc4f0363a
b366c6686e5
client_private_key: 0a45c82e38a6ab6fb99ec1df7423e25a7851f9558e7a05166
03c9d0201b409c3fd0f0fe78bd37bf60927fafeca73ed8093538a9992c62235
client_public_key: e0f6146168d32f4b68e042ed5d5608d1108e84a08b6688798e
ad0810b4f10d7a91f0767e197e946ebfc487bf62a5ed5684e7ab9137ee1862
server_private_key: 64666faa068e5ff9e00d588446b7d6cdc09ae8df069b30987
a2cdd39286e0481a2eb899f4e0db672264527a8115f176c53709a4f6534f328
server_public_key: d49500848e7c06c8a5dd5bda74930ffd20fbef9a2de24a0068
e5bf3dc356852b10327be9803983271450bc6a8c683abcdd73883ee63543e9
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: beee86e1513d30476339f18ad2cbd8436e4bc1ab29cf150afe32870
4bc85a23f
client_nonce: dd44e81d844719f3b73781512521c979975678bf3ea454e3a268780
913dffc17
server_keyshare: 720df48b9e395c40448cf06a80bc9c1d90ae1a3080e4ba3368ca
056ba92921f79d67073fb91b7c94c3f3d33cc01613d7221f54fecd80bcbb
client_keyshare: e6f2ab22efb569a19f48355c7d5d4f728faf3a9142d45c20c098
bcbcb6c12fd92480bfb4e532923e64b9620b6bc84ac5f2d8f84ad466fd18
server_private_keyshare: e5d7202d6ed8cc45c4502850974076d720343b566089
1b5ab5655c3defb4b39b35b27ea20eb0bff035e9b9cbae6cfca36aa4827c32abd905
client_private_keyshare: a54c0d7bf4ee396a0e4a3f023b35698aaa93a2be8bb6
32747671b3edeaedff07116afbb5e73cbc273e2e0d0876780343578338425ed81d3b
blind_registration: 9d557ee103479baef585ba8017f7659cdd0b804c093852519
9d88853b52ccfc7802d09cf38ba35e36db24404602da8a616e7ad8f1c05cb36
blind_login: eaadba538bf67207633a956ea71fbd02ea2dbfe7e195dbd26ea562c6
f2406fe1df1367f98f6707dee9b2e3ebd9842b0442e25d086e099231
oprf_key: 98a5689edb98ed3424fa5c8584423c6b047121fc36fcec934c8ad24a98c
86d00e1e1d6d3d923a46519065977331abaa1e3c0d86591458b25
~~~

### Intermediate Values

~~~
auth_key: a6e2296fc21046d638d2ba7810e463b4b99c81aea580517194ac7653223
24a8ca8868b2606a0df0ce9f725071aa2762ffb3eb2d3f31348ba230ef3192b46b82e
prk: 28e37547e17b263375b398e3773b1ec05ae2b6a74c30f9852f3cdabddeea27a6
d1885bef063b59b6d104f8e69ed8acbbe097cba5041f3acb958e3059cd27e440
pseudorandom_pad: b8f66f33b546edf97896f278fc834d30899b969637dafee1648
863fc89f072d01b6bfa629ed931b1d51df1aff0e89a2b220d8f3436e0f77a
envelope: 02aa9640f1a4adba93c53e08809a8a0eaae36af9444ad7cc4f0363ab366
c6686e5b2b3a71d8de04696c10833a788a0af6af1ca6fc3b9a0fbf704b4fefe88447b
13e664f585150a4a47dc3a0b513a9b77abb15e05ada426d54f595a1dfe66dd7cfdff1
e8d83032e86cfa87dd1d2642d9c3be7f9b13c15d637c991e43cfbc56ee9feb75d0739
8c9a32659e4b7a8a9afa0e83b28780f1e6feb26b
handshake_secret: 45cf4e589ad50bcd95a4b7b2585dbf50090404886a0c37b9b20
ed69c320e7974a6bcd09fb0fc3159dd17b9e6c5a4c1b99426c3dc546b00ec27c90d93
ca50dbb4
handshake_encrypt_key: 013436b2bc1b8e73c266c1b763fada0b400970a38f9a40
10dd7d94e1f3de028be2eb8ad52a3baadde7611f872270bd5c138a126a09774a81335
1fb46f1f56660
server_mac_key: 9abff8ab8e552fd6f09ac1abdb51e465e07c8e82b192b192e0928
aff803638f1088440bf76952b5a34c5e2c7f0ddf2145297373be7f9bd6131721915bb
c664ea
client_mac_key: 2df8f32d3cebd2db83092ac39c5b8a6c644b486749b0345c86a94
b559b7c659879966c378cd5a39251bfaa91ece78ce29e8f98ee7e640fbb0b4ac2ed85
42c0e2
~~~

### Output Values

~~~
registration_request: 90cca9013769f28f3992f77a043084edbfe6c89b7e2305e
4a6765e50df565fa8e18aba470238c6ed7992af20e962a641bc6bd678ceba640a
registration_response: e45f47bc6f41bb6de778775aa3f746b31cd17969183beb
e8b3757ba8dd546534996ccc686709c1a0fd6ecb4313936940a470333d1ae3c70ed49
500848e7c06c8a5dd5bda74930ffd20fbef9a2de24a0068e5bf3dc356852b10327be9
803983271450bc6a8c683abcdd73883ee63543e9
registration_upload: e0f6146168d32f4b68e042ed5d5608d1108e84a08b668879
8ead0810b4f10d7a91f0767e197e946ebfc487bf62a5ed5684e7ab9137ee186202aa9
640f1a4adba93c53e08809a8a0eaae36af9444ad7cc4f0363ab366c6686e5b2b3a71d
8de04696c10833a788a0af6af1ca6fc3b9a0fbf704b4fefe88447b13e664f585150a4
a47dc3a0b513a9b77abb15e05ada426d54f595a1dfe66dd7cfdff1e8d83032e86cfa8
7dd1d2642d9c3be7f9b13c15d637c991e43cfbc56ee9feb75d07398c9a32659e4b7a8
a9afa0e83b28780f1e6feb26b
KE1: a8f3c6290c4a31a2f696ac5c4f933c85dc3a8fde4247e8733fae3502b9f895ed
40a43c53547891e0a6305a12f7bbbed8696a774f2f352b1fdd44e81d844719f3b7378
1512521c979975678bf3ea454e3a268780913dffc17000968656c6c6f20626f62e6f2
ab22efb569a19f48355c7d5d4f728faf3a9142d45c20c098bcbcb6c12fd92480bfb4e
532923e64b9620b6bc84ac5f2d8f84ad466fd18
KE2: 3c86de1f2ef35f9044b08421334c2ea2020300a3c5259bab2fd525dd4e68e03a
90d3460479849e12847a3600cf2428a4c424741b96f76aa9d49500848e7c06c8a5dd5
bda74930ffd20fbef9a2de24a0068e5bf3dc356852b10327be9803983271450bc6a8c
683abcdd73883ee63543e902aa9640f1a4adba93c53e08809a8a0eaae36af9444ad7c
c4f0363ab366c6686e5b2b3a71d8de04696c10833a788a0af6af1ca6fc3b9a0fbf704
b4fefe88447b13e664f585150a4a47dc3a0b513a9b77abb15e05ada426d54f595a1df
e66dd7cfdff1e8d83032e86cfa87dd1d2642d9c3be7f9b13c15d637c991e43cfbc56e
e9feb75d07398c9a32659e4b7a8a9afa0e83b28780f1e6feb26bbeee86e1513d30476
339f18ad2cbd8436e4bc1ab29cf150afe328704bc85a23f720df48b9e395c40448cf0
6a80bc9c1d90ae1a3080e4ba3368ca056ba92921f79d67073fb91b7c94c3f3d33cc01
613d7221f54fecd80bcbb000fafdce8403ef9f78d51317479a9616e378974a5aad23d
aaea7081153b70339910c9723a707d79c754797d1c819545ee4345f5dd125ffe4fbb9
38ac778304ff4fce7e52756e4e42244029f26a0e27b9c
KE3: 1be9526e27dcaa1fd85eaa54d119bf3ffdc1dd3eb3d063c5b447677c9021ecae
6152d3284de7bb5363a54b06d23291c65c4af2a89e61cb55f80a0539592e765e
export_key: 3034b2d19b697784ee8b07a93dc6440477b13a101c45ad25dccdd20ae
97f8eee79cb0811e27de08c3bb3ac5b82f6d158c0e6e2669f4e28fef08d67511825f3
08
session_key: f3a60b22bbee35b8897a0593d8901c62526ec229a67694fca5a1399b
1d7b4b114ce7a71c8cecc9e614f5387aa27bae18868e42346b0167b742969112394a2
b92
~~~

## OPAQUE-3DH Test Vector 8

### Configuration

~~~
OPRF: 0003
Hash: SHA256
SlowHash: Identity
EnvelopeMode: 02
Group: P256_XMD:SHA-256_SSWU_RO_
Nh: 32
Npk: 33
Nsk: 32
~~~

### Input Values

~~~
client_identity: 0227aa37ade0cd6231bd385333cc8ccdf3872e75d9f6506192ed
7bcc6e5819f5d7
server_identity: 039178fd762b694fc67cc2df224079dd59ccd00d22621929a0a7
e5ecac96814260
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 2193c3cb5bd733c1e1b6cca309b1328b72f5ac21996feb6134299
eea188a3bc4
client_private_key: dc970d63acb5ab74318e54223c759e9747f59c0d4ecbc0873
02667fabefa647c
client_public_key: 0227aa37ade0cd6231bd385333cc8ccdf3872e75d9f6506192
ed7bcc6e5819f5d7
server_private_key: fcd9a655f77ff0b2ebcfe21e1a1ca4a84361e9f1b18e24c9a
40ed5eec262bf52
server_public_key: 039178fd762b694fc67cc2df224079dd59ccd00d22621929a0
a7e5ecac96814260
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 88524a7fbeb5c2d9bf7642b76364154c9cedf012d20801aec257b2a
2b5f97110
client_nonce: 43ce36dfe083a87c77c6a5c3174292f62348f0bd15f4d10e14b1887
f8777915e
server_keyshare: 0233c66a7b8735e362aa803f2e5677f48f4cab048edd74381667
82858e46381fd8
client_keyshare: 021ed435f437b88157c9af824de01811f5afc20de9dfdb49f0b4
454ec1df60af60
server_private_keyshare: 4fb9234e93a8bd048ad9f44b428026396a810328c405
a354e666f086fa0ea476
client_private_keyshare: 4fb56527be010296ea880e1c6a4dbbc9ede543a2ad0f
83fd60fdacb59801a9d9
blind_registration: a54f137dbe5f5eb4a34dcb73609c6693f28cd3d57ed77bf66
e0ab7d86c6990f1
blind_login: 3b5d1c0fc0812c10e18f146b14d7eb94755a918bac1ef8d69d21a7c1
3f95c9b2
oprf_key: 334d8af16ae1e69f5adc24e5aa89ebb63637c835fd39b17a1a4453eb5d9
63d23
~~~

### Intermediate Values

~~~
auth_key: ab5666ddaf10ef56a41d7c0939f8a35429734bbcb4d71c2ff392da1f25f
b3c34
prk: 0157ad57304dbc445622f2b5b0ba7f5b553acb39dfdf883b8f887602092ceee6
pseudorandom_pad: 8225dc7b3aac99301b92466105fa8c982342d487a4261f352f8
939a01167101a
envelope: 022193c3cb5bd733c1e1b6cca309b1328b72f5ac21996feb6134299eea1
88a3bc45eb2d118961932442a1c1243398f120f64b7488aeaeddfb21faf5e5aaf9d74
66d6db4a184a08fb21a980e90536d078670608e946084c271d7dba38be4ba7cb96
handshake_secret: 8bc2a04c6f75b8cb1d7813c15a802e015c209ff4be248c08290
ae1327c98f33f
handshake_encrypt_key: 99c24ed6305471d5da9e836f376bf9fbd13ffd071ee303
68dbbc72eec108b94e
server_mac_key: b904c8ebc0c6ae05e870486b153c4b74e79501ac7d34ffd6d19fe
34ce668f07c
client_mac_key: 9d8f810652856af01225ed0818f51baa16f66359799945500e81d
520bcd1fb26
~~~

### Output Values

~~~
registration_request: 02327e93445af116df70f57d18ab2a0ef9f492aa3d76c94
6d98260fa1edfa5b832
registration_response: 03480ac383e647d1f78b19bd902c7126024ccc76da605d
cc416581a32e4202d62a039178fd762b694fc67cc2df224079dd59ccd00d22621929a
0a7e5ecac96814260
registration_upload: 0227aa37ade0cd6231bd385333cc8ccdf3872e75d9f65061
92ed7bcc6e5819f5d7022193c3cb5bd733c1e1b6cca309b1328b72f5ac21996feb613
4299eea188a3bc45eb2d118961932442a1c1243398f120f64b7488aeaeddfb21faf5e
5aaf9d7466d6db4a184a08fb21a980e90536d078670608e946084c271d7dba38be4ba
7cb96
KE1: 02dad65138d90eb5fffdd93d1ad84b7e86e5b3f1964756d092e154d6a135c6e4
ce43ce36dfe083a87c77c6a5c3174292f62348f0bd15f4d10e14b1887f8777915e000
968656c6c6f20626f62021ed435f437b88157c9af824de01811f5afc20de9dfdb49f0
b4454ec1df60af60
KE2: 038782ee7c0ca885bd49d7105f9f43f89d34b2ad39b98e02a1a4ceed9e7de3f6
6a039178fd762b694fc67cc2df224079dd59ccd00d22621929a0a7e5ecac968142600
22193c3cb5bd733c1e1b6cca309b1328b72f5ac21996feb6134299eea188a3bc45eb2
d118961932442a1c1243398f120f64b7488aeaeddfb21faf5e5aaf9d7466d6db4a184
a08fb21a980e90536d078670608e946084c271d7dba38be4ba7cb9688524a7fbeb5c2
d9bf7642b76364154c9cedf012d20801aec257b2a2b5f971100233c66a7b8735e362a
a803f2e5677f48f4cab048edd7438166782858e46381fd8000f2db7206f9fe15a5a77
3a3535f547d0873a84d154d849d2fb99b9d34496910868403aae2253a8bbeefc16a45
6da069c
KE3: bb95f06d569fbea5eef7a8f80d4abee5be89d04616da384e76f51067f8e9dd24
export_key: cd7bd0f8a367c04b125f76b6845ab7754246c72e828551f8e76add3d3
8466525
session_key: 0e0dadb8f10a68f47c01754b8fb7ee40ac518d8d99e167f96ecc5715
7836cb2c
~~~

## OPAQUE-3DH Test Vector 9

### Configuration

~~~
OPRF: 0004
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 02
Group: P384_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 49
Nsk: 48
~~~

### Input Values

~~~
client_identity: 0368f5bbaaa438e2e87de012dec549a4a89a6d4deb262b133834
d1d90ed3eeceb12a2c5cfd5702077bfb47b0e36e48904d
server_identity: 024ecf37a198ab5431962c820df129c60356bc801d3584da5ce1
19c15554d0183a3b9a6b833cd2a019a882c620020c8a3a
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d46aea21c518a11cb4e21521044bfdce1dc43e5186f0f3f678c0c
1601e2a9bd4
client_private_key: 26fec54d4567adabd7951ad51ea3741feab175ac5cf7fa02f
3ad744eb5baf418275e45ab31ade30669dbae98fb087953
client_public_key: 0368f5bbaaa438e2e87de012dec549a4a89a6d4deb262b1338
34d1d90ed3eeceb12a2c5cfd5702077bfb47b0e36e48904d
server_private_key: 8588213957ea3a5dfd0f1fe3cda63dff3137c959747ec1d27
852fce42d79fc710159f349e7da18455479e27473269d2a
server_public_key: 024ecf37a198ab5431962c820df129c60356bc801d3584da5c
e119c15554d0183a3b9a6b833cd2a019a882c620020c8a3a
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 34c06078492a8ca4d94158d78a9c89a483938ccd1310cfbbb566474
ea3db7c7d
client_nonce: b3dd0981f82f032984f044e4330db128c0386d1a8a92564528f7776
32af22bda
server_keyshare: 036b981c4a2265b4376e2edc3186a45c2e2f820b1092784f6448
354779578b442b0369640e2f10a856cf8dfd60b28c68c9
client_keyshare: 03526fe798e9ab52137d8c3408b131430eadae49f6e93a4fa228
c0338081e6090f75c2b3d55da4b2abfa4f2e2a52bd3330
server_private_keyshare: eb81ae8c1af769a56d4fc42aef54a703503046d8272e
aea47cfa963b696f07af04cbc6545ca16de56540574e2bc92535
client_private_keyshare: ac475d6a3649f3e9cdf20a7e882066be571714f5db07
3555bc1bfebe1d50a04fd6656a439cf465109653bf8e484c01c6
blind_registration: c044df390ab5683964fc7aabf9e066cf04a050c4fd762bff1
0c1b9bd5d37afc6f3644f8545b9a09a6d7a3073b3c9b3d8
blind_login: f8516f98f3159b3fed13a409f5685928c72d9dab8ddfe45de734ce0d
4ff5823d2e40c4fcf880e9a8272b46eea593b10a
oprf_key: 5e7d38ba6ff37c42b3c4859761247a74d0c62c98ddff1365bb9b82b279e
775b7220c673c782e351691bea8206a6b6857
~~~

### Intermediate Values

~~~
auth_key: 60c033242628ce511d8127972b35767f01b28a00c621c26013d308384ff
6141bb3adec0cd64d88ee0e074a5335c1ff37cf1bac69fbca8844bed29936670fb4f7
prk: d67b1858aba9734905938268faf4ae5a5a90a8239d2a8362a7d12eccaf5f3555
659a0a0cf9713ee0bf61c3e644a5f63ff78c0935142685a8871f2c6c29998381
pseudorandom_pad: 804dfdbc896062cb19538c57df555acd4238e5b28ebc6a4002b
a687e609a40086ef7e91bf4c19bb83538f8a374b405f1
envelope: 02d46aea21c518a11cb4e21521044bfdce1dc43e5186f0f3f678c0c1601
e2a9bd4a6b338f1cc07cf60cec69682c1f62ed2a889901ed24b9042f1171c30d520b4
1049a9acb0c56c78be5ce3563b8fbc7ca25f311956a727f239eaf8d3591ab06ad5b6d
22073e65412a044534ca6ab556f55411bc6247d9e07eea59cc05aabc368dae67547c2
1a5e85b2e452ea29f6f658c8
handshake_secret: cea7d8e6d0494a76ef29cec43bd172870afc2d0076aa9207ded
3ee4e2cc7658945e9c74b4af15d4c968aace033dc6e8b4db287bb52a1eab257c452c7
d1a06c79
handshake_encrypt_key: 3ad1fa14ab50746891c3142426fcc293af062855a9d2e5
981802ed6e6a9bc658942d59cc9369348bb834eeec39cb53f37064b1f493a5463fb70
b0a8e8e8ff7d0
server_mac_key: e82e85c0fd4b864ede1a8f09deb96e1aed19444d86de9a2606169
9024b82cda3b3a2f8ce497da48ec8f2c6b3c3b9055d4913e1041695cc77c9e6acc092
ca8064
client_mac_key: b95be9621b3d8b3caef902ae442cef7d2565890fc67250584346f
a883c6023fa48ac0bf52863bba01efdc2c33a7f0b2d12f0c69c043c46f2939dc867c1
238477
~~~

### Output Values

~~~
registration_request: 029674b50d9bec795e53084cb5d6e0f4813804ea378a672
e5e0514f79e98055b79eafa67deed65b040dc1368a7216c8071
registration_response: 02da545d424e985f21cfcac7dd74ceca2177e513ebf484
3659160649ab4a0e5a9caeeba5e79c1fe86ebb5776e8bd4873db024ecf37a198ab543
1962c820df129c60356bc801d3584da5ce119c15554d0183a3b9a6b833cd2a019a882
c620020c8a3a
registration_upload: 0368f5bbaaa438e2e87de012dec549a4a89a6d4deb262b13
3834d1d90ed3eeceb12a2c5cfd5702077bfb47b0e36e48904d02d46aea21c518a11cb
4e21521044bfdce1dc43e5186f0f3f678c0c1601e2a9bd4a6b338f1cc07cf60cec696
82c1f62ed2a889901ed24b9042f1171c30d520b41049a9acb0c56c78be5ce3563b8fb
c7ca25f311956a727f239eaf8d3591ab06ad5b6d22073e65412a044534ca6ab556f55
411bc6247d9e07eea59cc05aabc368dae67547c21a5e85b2e452ea29f6f658c8
KE1: 02ab0cdb1bf7038717c03d583e311f14c6004c73f78383d4cc6248751aa68ca9
29d717dc6f003de949a17732875bd1aa67b3dd0981f82f032984f044e4330db128c03
86d1a8a92564528f777632af22bda000968656c6c6f20626f6203526fe798e9ab5213
7d8c3408b131430eadae49f6e93a4fa228c0338081e6090f75c2b3d55da4b2abfa4f2
e2a52bd3330
KE2: 03ed6cdbc3a3b78a9504aeaa0df8a3ff996ab5b8dbd2d74cfeec3c976c434a85
860d6367df02c62989c8ee9b88a354ea30024ecf37a198ab5431962c820df129c6035
6bc801d3584da5ce119c15554d0183a3b9a6b833cd2a019a882c620020c8a3a02d46a
ea21c518a11cb4e21521044bfdce1dc43e5186f0f3f678c0c1601e2a9bd4a6b338f1c
c07cf60cec69682c1f62ed2a889901ed24b9042f1171c30d520b41049a9acb0c56c78
be5ce3563b8fbc7ca25f311956a727f239eaf8d3591ab06ad5b6d22073e65412a0445
34ca6ab556f55411bc6247d9e07eea59cc05aabc368dae67547c21a5e85b2e452ea29
f6f658c834c06078492a8ca4d94158d78a9c89a483938ccd1310cfbbb566474ea3db7
c7d036b981c4a2265b4376e2edc3186a45c2e2f820b1092784f6448354779578b442b
0369640e2f10a856cf8dfd60b28c68c9000f47ede9c6180847cc4400bfa9d544297e3
eee239c15c518ca4a2a18b5115c689d39b6ed5c69b468db1724a6485e37fd606614b7
5f8990bca56121abdb681a9e189dc2bc71c3a391efbccfd59a4624d8
KE3: 8b8a6875e3075bc8b4702039e7fedc50264a8ebc934a0ceec29d9096b151b9e5
4fe56241d4ac5809f23f61fab44e8914ccddfb83b9833dd18678d14916d89255
export_key: b3302eb69f1874ae3ef4986e5754c0b4895d173bc480709a6a9b82414
07eaf7151f1e2fbc7c316046101f1d84183d96aa5d39ee30f1f974656f0093fda28c2
ec
session_key: c3c931718cddc11b2bc6ba89aa6f2da7130c94290a5015f4df40bda3
4131a5e426b697591cfb7fe5736c464f95cec0c613dd50faff0de622da33dcbf62706
8f4
~~~

## OPAQUE-3DH Test Vector 10

### Configuration

~~~
OPRF: 0005
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 02
Group: P521_XMD:SHA-512_SSWU_RO_
Nh: 64
Npk: 67
Nsk: 66
~~~

### Input Values

~~~
client_identity: 0300ec0addd1ade650f8c2be98b2d7b5b5eb7e1eab56823f9413
327e056e1413055ede83bd893a26f61094a87d108431dc4f95366741da7ec6465208b
9080d17ed304a
server_identity: 0300d1df68b2171f58ffc6a2cdf6cd47f4a672e0c06660ad5ec9
cccbd8fafd4593dc847b3a3a7aedd1baf2d03dad24f1da95e884f3554c0d4915b0d47
172f33eab7f0e
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 7eba0eaf9cc1eda3d6c19f3bfe845b6c6c1081791f78a2aae175d
5882216da15
client_private_key: 0077881aa5fd937ec7932e725ac43a07cb3ea0e90b40e0501
e6bdc3c97510cdd9475ad6d9e630235ff21b634bc650bf837aaa273530dc66aa53bb9
adb4f0ed499872
client_public_key: 0300ec0addd1ade650f8c2be98b2d7b5b5eb7e1eab56823f94
13327e056e1413055ede83bd893a26f61094a87d108431dc4f95366741da7ec646520
8b9080d17ed304a
server_private_key: 002e485cccf5018abbf875b8e81c5ade0def4fe6fa8dfc153
88367a60f23616cd1468dae601875f7dd570624d0ae9d7be2e6196708f773cf65852b
da777210337d8c
server_public_key: 0300d1df68b2171f58ffc6a2cdf6cd47f4a672e0c06660ad5e
c9cccbd8fafd4593dc847b3a3a7aedd1baf2d03dad24f1da95e884f3554c0d4915b0d
47172f33eab7f0e
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: bdaa80959bacabb318dcbe6a8a04dcd528d137b3899292c2a602003
8d136ba10
client_nonce: 4afc453ea57ad3618b54533c5401336a1bc2f409347f812b1320248
299fb699a
server_keyshare: 03009af99de97de5c0b5bb5299c406e53294dc48a78ba4933df0
e01bf8e1c5e46fe1de6e82060a08a9110c435fd784b9ae31ecb639eabd464a1681912
6be3b865b05e9
client_keyshare: 030035c078a34aacc22e0e759115b9c7c45192d97e4970f40376
76039e7bc2d270c3964e81a9009a788b022eac506ac16c9704efe50ff6041bd3c9422
9673d2073d8bc
server_private_keyshare: 00708286c5fb629de5cfea56c0532dd8254a5a6e7fcc
9e51e20a1cf4f254335ca57ce603ae7cf03fc00b7a2d495298d84c8c83b686b67e825
69cb56d97e9c20e5932
client_private_keyshare: 0037735d573abb787b251879b77de4df554c91e25e11
7919a9db2af19b32ce0d501c9572d3a8a106f875023c9722b2de94efaa02c8e46a9e4
8f3e2ee00241f9a75f4
blind_registration: 0071a04b0f2180dda3c36e3d43c3a8f127158d010944b0d53
a6f8da29c3cf4f8695135d645424c747bec642bc91375ff142da4687426b0b4f35c14
eb2477c52e1fff
blind_login: 01eea8a605644334de4987fb60d9aaec15b54fc65ef1e10520556b43
938fbf81d4fbc8c36d787161fa4f1e6cf4f842989634f76f3320fdd24777894218769
fc19651
oprf_key: 0066b06b578fe36ef23a5b9872ade82b9261cc447670debcf78318add68
2f6055089b0a2484abc37f110b36f4c2a140b7a3c53dd8efb6171d3bb4d73591be848
3a1b
~~~

### Intermediate Values

~~~
auth_key: feb091fb16d90ba9fc11b1a9902827c801b2c12fcb594a9c66bfb00dd41
2b1681e7221e2020852df1f17a57cbbd0b67bf032a5f96e330e48d360eda84972aea5
prk: 4d523ec8de8c0b8b7849eb2e33e7aea04426206e83245d8ab5bcfab0b77a7231
9ac5ab2c0f33d5df8b74be6f466de8086c1f133cef8873897fd616db1c59765a
pseudorandom_pad: 0e82302219c3c6269b037918dda7569252206adfb5dd644264f
7e422a7c536edaa7c3049449f8c18c757329c650d4721732c286608c3c608808af364
d1e718754675
envelope: 027eba0eaf9cc1eda3d6c19f3bfe845b6c6c1081791f78a2aae175d5882
216da150ef5b838bc3e55585c90576a87636c95991eca36be9d84127a9c381e30943a
303e099d24dafc8e2d387684a8d9684cd944868a155bce006225b14ac96517f53cde0
78e66d6f7b1d67ff58d4bfac32079d6614ed23f62b9b65ba633d6c2852c61aa2e42bb
ce82b7e76230420b7f9d1d692be752805dd18fc47a83ff3e8629b6c540de
handshake_secret: 6bcca9bd157a15c185bd7b36e4fd8ffabbd9cac4c48b846bb83
98798ba83bee5888207c6b4565cbf5aa0734c4dd2561f9a1aa52c5fe8adf995e928e7
824995d6
handshake_encrypt_key: b34e23a710d36568edef0f90ced7373b83866687ed61cc
ad518be844d95cb19d2ae8bc31fc91ba46945211704e0eb93afb44d26a45047eef861
bcc1903358eb3
server_mac_key: b0c2464e60ceeb636f8aa752d1ce277ea668d1c076b93d7c4c454
c966ba9824ff03cfe15902b74aeb5b65fadbeb61f55ed2f77708271ee3c8d233091c0
ab7cd9
client_mac_key: 59c6434dfbbdc334795deb1367736e2253a8c1c29a69329d791cc
59628e595f50f6b6091fc74664bd1dae6ba088c32e2bc62f3f2b84541e0a2f72f930b
137f6d
~~~

### Output Values

~~~
registration_request: 020197d8111818258667ffbc0d377602f74350b7a54e684
1fb15ba96ac07095bcfc961a2c21e2e0061ba28cd4ea0ed93fa0404f1383b777483c3
31537c8e6e69af85b0
registration_response: 020013e275bf8d4c305cd3793a5be014f9b338b12c6f97
7aef5d523cff2c753b5e6d0f2602fa8359918eaf2fb4ccfb0ae79c383f698ee0fff3a
05d6ce9e5b28e762b0b0300d1df68b2171f58ffc6a2cdf6cd47f4a672e0c06660ad5e
c9cccbd8fafd4593dc847b3a3a7aedd1baf2d03dad24f1da95e884f3554c0d4915b0d
47172f33eab7f0e
registration_upload: 0300ec0addd1ade650f8c2be98b2d7b5b5eb7e1eab56823f
9413327e056e1413055ede83bd893a26f61094a87d108431dc4f95366741da7ec6465
208b9080d17ed304a027eba0eaf9cc1eda3d6c19f3bfe845b6c6c1081791f78a2aae1
75d5882216da150ef5b838bc3e55585c90576a87636c95991eca36be9d84127a9c381
e30943a303e099d24dafc8e2d387684a8d9684cd944868a155bce006225b14ac96517
f53cde078e66d6f7b1d67ff58d4bfac32079d6614ed23f62b9b65ba633d6c2852c61a
a2e42bbce82b7e76230420b7f9d1d692be752805dd18fc47a83ff3e8629b6c540de
KE1: 02013ffd159c4d44f7fe2441c05614ef421e7fc7285432d5dd3b67ada061f3e3
a230d1ab200864a9a716cd001d2a6abea298d58fded61f7d9ce02fc1bb037a1bbf9c7
c4afc453ea57ad3618b54533c5401336a1bc2f409347f812b1320248299fb699a0009
68656c6c6f20626f62030035c078a34aacc22e0e759115b9c7c45192d97e4970f4037
676039e7bc2d270c3964e81a9009a788b022eac506ac16c9704efe50ff6041bd3c942
29673d2073d8bc
KE2: 0200e302a5573d3625a0f9d0f63398f4c5053d4f816c743ab77bb365a36c3cdd
00fe21ae2a7e56c01f0857ecdb4d129480c189cbe61f78a2aaaa4687126b76a6cf0ce
20300d1df68b2171f58ffc6a2cdf6cd47f4a672e0c06660ad5ec9cccbd8fafd4593dc
847b3a3a7aedd1baf2d03dad24f1da95e884f3554c0d4915b0d47172f33eab7f0e027
eba0eaf9cc1eda3d6c19f3bfe845b6c6c1081791f78a2aae175d5882216da150ef5b8
38bc3e55585c90576a87636c95991eca36be9d84127a9c381e30943a303e099d24daf
c8e2d387684a8d9684cd944868a155bce006225b14ac96517f53cde078e66d6f7b1d6
7ff58d4bfac32079d6614ed23f62b9b65ba633d6c2852c61aa2e42bbce82b7e762304
20b7f9d1d692be752805dd18fc47a83ff3e8629b6c540debdaa80959bacabb318dcbe
6a8a04dcd528d137b3899292c2a6020038d136ba1003009af99de97de5c0b5bb5299c
406e53294dc48a78ba4933df0e01bf8e1c5e46fe1de6e82060a08a9110c435fd784b9
ae31ecb639eabd464a16819126be3b865b05e9000ff24a8be5be01a944caf666b1ff1
f5aab3a32e79e2d5533028007074544c7617e9d0a0e8ce2554a4575c36368b61e9bcd
4fa1ba8606d0d30241e2223c5c02f123856f71499720029d9f8362e4d47d9d
KE3: ec619f716beb33963096b4b3895ba5eb3e9129fa24dda52fb66e25344666b3d4
1f2dafd6bb26e60d57cf145701c9b4dea4e742d14508f3d0cb406a74124562ee
export_key: 0811892692d57c9c0588133820fd6c7e982cf7d7d1827532847d14e30
4b2a8558afc4eeb89740eba11ef72aa319be7095cc45294a88f25951c4167a227d3c1
72
session_key: 9cc9fc9c7706808ad6c98bbefd177733f30f6930f6e12175e98f8aba
3f9972f6a63b575b7a7de2591e44518a8e414445f0678a097ef9110aaeebcc0c61c55
da7
~~~
