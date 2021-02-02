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
implementation, a user authenticates to a server by sending its user
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
during user/password registration) and without disclosing passwords
to servers or other entities other than the client machine. A secure
aPAKE should provide the best possible security for a password
protocol. Namely, it should only be open to inevitable attacks, such as
online impersonation attempts with guessed user passwords and offline
dictionary attacks upon the compromise of a server and leakage of its
password file. In the latter case, the attacker learns a mapping of
a user's password under a one-way function and uses such a mapping to
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
transmit the salt from server to user in the clear, hence losing the
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
retrieval of user's secrets solely based on a password; and being
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
those credentials, recovers them using the user's password, and subsequently uses
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

- Client (U): Entity which has knowledge of a password and wishes to authenticate.
- Server (S): Entity which authenticates clients using passwords.
- password: An opaque byte string containing the user's password.
- (skX, pkX): An AKE key pair used in role X; skX is the private key and pkX is
  the public key. For example, (client_private_key, client_public_key) refers to U's private and public key.
- kX: An OPRF private key used for role X. For example, as described in
  {{create-reg-response}}, oprf_key refers to the private OPRF key for user U known
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

Registration is executed between a user U (running on a client machine) and a
server S. It is assumed S can identify U and the client can
authenticate S during this registration phase. This is the only part
in OPAQUE that requires an authenticated channel, either physical, out-of-band,
PKI-based, etc. This section describes the registration flow, message encoding,
and helper functions. Moreover, U has a key pair (client_private_key, client_public_key) for an AKE protocol
which is suitable for use with OPAQUE; See {{online-phase}}. (client_private_key, client_public_key) may be
randomly generated for the account or provided by the calling client.
Clients MUST NOT use the same key pair (client_private_key, client_public_key) for two different accounts.

To begin, U chooses password password, and S chooses its own pair of private-public
keys server_private_key and server_public_key for use with the AKE. S can use
the same pair of keys with multiple users. These steps can happen offline, i.e.,
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

Upon completion, S stores U's credentials for later use. See {{credential-file}}
for a recommended storage format.

## Credential Storage {#credential-storage}

OPAQUE makes use of a structure `Envelope` to store client credentials.
The `Envelope` structure embeds the following types of credentials:

- client_private_key: The encoded user private key for the AKE protocol.
- server_public_key: The encoded server public key for the AKE protocol.
- client_identity: The user identity. This is an application-specific value, e.g., an e-mail
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
  opaque client_private_key<1..2^16-1>;
} SecretCredentials;

struct {
  opaque server_public_key<1..2^16-1>;
} CleartextCredentials;
~~~

The `custom_identifier` mode defines `SecretCredentials` and `CleartextCredentials` as follows:

~~~
struct {
  opaque client_private_key<1..2^16-1>;
} SecretCredentials;

struct {
  opaque server_public_key<1..2^16-1>;
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
  opaque encrypted_creds<1..2^16-1>;
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
along with the user public key `client_public_key` and private key `client_private_key`,
are stored in a `Credentials` object with the following named fields:

- `client_private_key`, the user's private key
- `client_public_key`, the user's public key corresponding to `client_private_key`
- `client_identity`, an optional user identity (present only in the `custom_identifier` mode)
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
    opaque server_public_key<1..2^16-1>;
} RegistrationResponse;
~~~

data
: A serialized OPRF group element.

server_public_key
: An encoded public key that will be used for the online authenticated key exchange stage.

~~~
struct {
    opaque client_public_key<1..2^16-1>;
    Envelope envelope;
} RegistrationUpload;
~~~

client_public_key
: An encoded public key, corresponding to the private key `client_private_key`.

envelope
: The user's `Envelope` structure.

## Registration Functions {#registration-functions}

### CreateRegistrationRequest

~~~
CreateRegistrationRequest(password)

Input:
- password, an opaque byte string containing the user's password

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
- oprf_key, the per-user OPRF key known only to the server

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
- password, an opaque byte string containing the user's password
- creds, a Credentials structure
- blind, an OPRF scalar value
- response, a RegistrationResponse structure

Output:
- record, a RegistrationUpload structure
- export_key, an additional key

Steps:
1. N = Unblind(blind, response.data)
2. y = Finalize(password, N, "OPAQUE01")
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

[[RFC editor: please change "OPAQUE01" to the correct RFC identifier before publication.]]

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
    opaque client_public_key<1..2^16-1>;
    Envelope envelope;
} credential_file;
~~~

# Online Authenticated Key Exchange {#online-phase}

After registration, the user (through a client machine) and server run the authenticated
key exchange stage of the OPAQUE protocol. This stage is composed of a concurrent
OPRF and key exchange flow. The key exchange protocol is authenticated using the
client and server credentials established during registration; see {{offline-phase}}.
The type of keys MUST be suitable for the key exchange protocol. For example, if
the key exchange protocol is 3DH, as described in {{opaque-3dh}}, then the private and
public keys must be Diffie-Hellman keys. At the end, the client proves the user's
knowledge of the password, and both client and server agree on a mutually authenticated
shared secret key.

OPAQUE produces two outputs: a session secret and an export key. The export key may be used
for additional application-specific purposes. For example, one might expand the use of OPAQUE
with a credential-retrieval functionality that is separate from the contents of the `Envelope`
structure. The output `export_key` MUST NOT be used in any way before the HMAC value in the
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
    opaque server_public_key<1..2^16-1>;
    Envelope envelope;
} CredentialResponse;
~~~

data
: A serialized OPRF group element.

server_public_key
: An encoded public key that will be used for the online authenticated
key exchange stage.

envelope
: The user's `Envelope` structure.

### Credential Retrieval Functions

#### CreateCredentialRequest {#create-credential-request}

~~~
CreateCredentialRequest(password)

Input:
- password, an opaque byte string containing the user's password

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
- password, an opaque byte string containing the user's password
- blind, an OPRF scalar value
- response, a CredentialResponse structure

Output:
- client_private_key, the user's private key for the AKE protocol
- server_public_key, the public key of the server
- export_key, an additional key

Steps:
1. N = Unblind(blind, response.data)
2. y = Finalize(password, N, "OPAQUE01")
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

[[RFC editor: please change "OPAQUE01" to the correct RFC identifier before publication.]]

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
into a secure aPAKE protocol. In OPAQUE, the user stores a secret private key at the
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
account information sent by the user to the server prior to authentication.

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
compromise of the server, the attacker cannot impersonate the user to the
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
that the public keys of both the server and the user must always be those defined
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
_single_ user. For example, one would need a billion impersonation attempts
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

## User and Server Identities

The user identity (client_identity) and server identity (server_identity) are optional parameters
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

<!-- To further minimize storage space, the server can derive per-user OPRF keys
oprf_key from a single global secret key, and it can use the same pair
(server_private_key,server_public_key) for all users. In this case, the per-user OPAQUE storage
consists of client_public_key and HMAC(Khmac; server_public_key), a total of 64-byte overhead with a
256-bit curve and hash. envelope communicated to the user is of the same length,
consisting of server_public_key and HMAC(Khmac; server_public_key). -->

<!-- Can provide AuCPace paper (sec 7.7) as reference to importance of small
envelope (for settings where storage and/or communication is expensive) -->

## User Enumeration {#SecEnumeration}

User enumeration refers to attacks where the attacker tries to learn
whether a given user identity is registered with a server. Preventing
such attacks requires the server to act with unknown user identities
in a way that is indistinguishable from its behavior with existing
users. Here we suggest a way to implement such defense, namely, a way for
simulating a CredentialResponse for non-existing users.
Note that if the same CredentialRequest is received
twice by the server, the response needs to be the same in both cases (since
this would be the case for real users).
For protection against this attack, one would apply the encryption function in
the construction of envelope to all the key material in envelope.
The server S will have two keys MK, MK' for a pseudorandom function f.
f refers to a regular pseudorandom function such as HMAC or CMAC.
Upon receiving a CredentialRequest for a non-existing
user client_identity, S computes oprf_key=f(MK; client_identity) and oprf_key'=f(MK'; client_identity) and responds with
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
different responses can conclude that either the user registered with the
service between these two activations or that the user was registered before
but changed its password in between the activations (assuming the server
changes oprf_key at the time of a password change). In any case, this
indicates that client_identity is a registered user at the time of the second activation.
To conceal this information, S can implement the derivation of oprf_key
as oprf_key=f(MK; client_identity) also for registered users. Hiding changes in envelope, however,
requires a change in the protocol. Instead of sending envelope as is,
S would send an encryption of envelope under a key that the user derives from the
OPRF result (similarly to prk) and that S stores during password
registration. During the authenticated key exchange stage, the user will derive
this key from the OPRF result, will use it to decrypt envelope, and continue with the
regular protocol. If S uses a randomized encryption, the encrypted envelope will look
each time as a fresh random string, hence S can simulate the encrypted envelope also
for non-existing users.

Note that the first case above does not change the protocol so its
implementation is a server's decision (the client side is not changed).
The second case, requires changes on the client side so it changes OPAQUE
itself.

[[https://github.com/cfrg/draft-irtf-cfrg-opaque/issues/22: Should this variant be documented/standardized?]]

## Password Salt and Storage Implications

In OPAQUE, the OPRF key acts as the secret salt value that ensures the infeasibility
of pre-computation attacks. No extra salt value is needed. Also, clients never
disclose their password to the server, even during registration. Note that a corrupted
server can run an exhaustive offline dictionary attack to validate guesses for the user's
password; this is inevitable in any aPAKE protocol. (OPAQUE enables a defense against such
offline dictionary attacks by distributing the server so that an offline attack is only
possible if all - or a minimal number of - servers are compromised {{OPAQUE}}.)

Some applications may require learning the user's password for enforcing password
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

## OPAQUE-3DH Test Vectors

### Example0

#### Configuration

~~~
Group: ristretto255
EnvelopeMode: 00
OPRF: 0001
SlowHash: Identity
Hash: SHA512
~~~

#### Input Values

~~~
client_private_key: 2ab84263d6ab5a41f3b7d147efdc2e1a81803c682066b941f
25255265edb4107
server_identity: 1218201bd0c2b3b30348e68cf0c71151e63ea6f50a46ec7493b8
05f02765a265
client_identity: 7eee935bd83d1b146c0740d2c2c49cef5955ec8a90bc860e40f1
69638915b625
client_public_key: 7eee935bd83d1b146c0740d2c2c49cef5955ec8a90bc860e40
f169638915b625
password: 436f7272656374486f72736542617474657279537461706c65
server_public_key: 1218201bd0c2b3b30348e68cf0c71151e63ea6f50a46ec7493
b805f02765a265
server_private_key: 8d5a577b03081018ee6d958b63b39acdff8f7eab95e8bc1fc
d08dd8acb04570c
~~~

#### Intermediate Values

~~~
server_mac_key: 0b036d6163349b816ddb86e0c815857ea1ccbe3505c120c0bf892
16a2399da346fd10fe33f4be6a13768211eb0ab677aa29c760f19fb01d7b5b81ffa0f
eb5565
KE2: e83812f06568d57b8cdfdcc90fe91454e21bd25dd2a1c32dd1599a2e4a4b6c35
00201218201bd0c2b3b30348e68cf0c71151e63ea6f50a46ec7493b805f02765a2650
033117c0fd4aa9137e410b38c6f919a1cc0ced198f3ccc78f68da7680b8268e270022
731824cbf1219caa4c5b28995dcc43f3070fed87a96c36f9b4d1aa3d96a9333185cb7
2661e1646f6cebcd71468334ea11fcb6f78fbc767b7d9c050a8aafe753424825a1a85
b62765e0fab92fc20bc9c97dfc0a4c4b13ed14ffaa34fc1bcc5750f7e7c4b2d6ba5f6
23e5ddf46ea1240e42de43da044bc8cda8db06c1505687fd58271e6364f48734bfbe1
73a4a63b8943f3d45f8cae75c78dfe3d61bc36dce768ad41000f31e4f3fca57077f0c
a09e996796dff4ddcfb587493cf94df7903d1aabf9332ccc0bd3385b7bfc2740b5b7b
32b808a8f1e8de6ab5d825ff66aee91c10deadb25e8bd0802aea6bc3deab725bd3134
917
client_nonce: c90600a38320a407ddb3eb907756e94ec2d0870e15d92f2db313439
fe3db7ac7
prk: c40355d9770adf4552bc7665dc9bd3b309fef8a6b757d0e253891b54de4e7f37
c2a6001616ab2db71ab96f3de98f2c4c7552435c56aac3ab117c0f81a26e928b
envelope_nonce: 33117c0fd4aa9137e410b38c6f919a1cc0ced198f3ccc78f68da7
680b8268e27
registration_request: 241b621c417c0705b5ea7a8b7cdd5039fd61e6b63effe2a
44418164c4d49003e
KE3: b15adc3fdc1aca39721f87a424c4d7e6fab0114c8ca14408becc3cb13e354fa9
fbbbd588f896f4d6959171897ab6274aa3c0193dba4f2111309cc1b3cb0fc4df
client_keyshare: 342fdae63e85da782399d7b165d596601b11f8f84973bf057fb4
e8fc0662645a
KE1: b68e0e356f8490fa9c3bed952e16cc02db21eda686b3c484f3d9d912caa41f76
c90600a38320a407ddb3eb907756e94ec2d0870e15d92f2db313439fe3db7ac700096
8656c6c6f20626f62342fdae63e85da782399d7b165d596601b11f8f84973bf057fb4
e8fc0662645a
handshake_encrypt_key: 8c898e3c2aa3a6a76da5fb47022851c75f5dc276ed0145
4b2ec7e35d5e9da35df398cc7f0084bbadb0fb543df71f8947674b3ab1c9dd38b5c2e
d78236c7fd27a
registration_upload: 00207eee935bd83d1b146c0740d2c2c49cef5955ec8a90bc
860e40f169638915b6250033117c0fd4aa9137e410b38c6f919a1cc0ced198f3ccc78
f68da7680b8268e270022731824cbf1219caa4c5b28995dcc43f3070fed87a96c36f9
b4d1aa3d96a9333185cb72661e1646f6cebcd71468334ea11fcb6f78fbc767b7d9c05
0a8aafe753424825a1a85b62765e0fab92fc20bc9c97dfc0a4c4b13ed14ffaa34fc1b
cc5750f7e7
server_nonce: c4b2d6ba5f623e5ddf46ea1240e42de43da044bc8cda8db06c15056
87fd58271
server_keyshare: e6364f48734bfbe173a4a63b8943f3d45f8cae75c78dfe3d61bc
36dce768ad41
registration_response: 1867301bcc67bdf8e640b7d6edcbe2a65488446417b50d
30cdba66ccb379e57200201218201bd0c2b3b30348e68cf0c71151e63ea6f50a46ec7
493b805f02765a265
envelope: 0033117c0fd4aa9137e410b38c6f919a1cc0ced198f3ccc78f68da7680b
8268e270022731824cbf1219caa4c5b28995dcc43f3070fed87a96c36f9b4d1aa3d96
a9333185cb72661e1646f6cebcd71468334ea11fcb6f78fbc767b7d9c050a8aafe753
424825a1a85b62765e0fab92fc20bc9c97dfc0a4c4b13ed14ffaa34fc1bcc5750f7e7
client_mac_key: 3ffafbd00dbbcf337ef291d9ed9bbe7bfd0edc8cb5d65ad52a3f6
4690d46f7143250ff8ad95c64d8c7c001f9493067afa0823b2ab394307c82f0c10b12
8492db
pseudorandom_pad: 73380e73b3424a01161adb2e8c8bac2f29156c079504169f0d9
0586fc38f6deac4cc
blind_registration: c604c785ada70d77a5256ae21767de8c3304115237d262134
f5e46e512cf8e03
blind_login: ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63
e3263503
auth_key: f762b3eac567b538f286e483265bb7500c7b02da37799f0eeb6db956e5e
d96a4e81d6529d9a813c3228225661da28fdc9c9d60277c41a4ed0935c3b03b875f1c
handshake_secret: 8f9588fa6ccdbaa19f49fa7c39be139413997ff86c04e848291
65cd9782f73a6bca5908a66efa599fc73c18c2187879dc2d109607d03afae9d9de074
2673bce6
server_private_keyshare: 10a49596441d118472a1bd42646d96096400a9ab24cb
4d037738f7925771d00c
client_private_keyshare: f8db810c39064457720e44eeaeb49719a4095aa1323a
3c69c551f618d6eaa105
~~~

#### Output Values

~~~
session_key: 10ca7304046e4a85a74428fd72d6ea92fded05db74b35207cbc13438
820db64a0266c81c510bdb2ac97edff2f7ab2623ad68b29219440c413c07fdbe9325d
a94
export_key: 8513e4400b09f9fbbf89621e13d71b542e3c9f6e7bbe7a08c0f72ac2d
dc299c7295197c8c70aa7bc48cd19311c5c6c4a34854c62a4d5d22e324dbbaa633411
44
~~~

## OPAQUE-3DH Test Vectors

### Example1

#### Configuration

~~~
Group: ristretto255
EnvelopeMode: 01
OPRF: 0001
SlowHash: Identity
Hash: SHA512
~~~

#### Input Values

~~~
client_private_key: 2ab84263d6ab5a41f3b7d147efdc2e1a81803c682066b941f
25255265edb4107
server_identity: 1218201bd0c2b3b30348e68cf0c71151e63ea6f50a46ec7493b8
05f02765a265
client_identity: 7eee935bd83d1b146c0740d2c2c49cef5955ec8a90bc860e40f1
69638915b625
client_public_key: 7eee935bd83d1b146c0740d2c2c49cef5955ec8a90bc860e40
f169638915b625
password: 436f7272656374486f72736542617474657279537461706c65
server_public_key: 1218201bd0c2b3b30348e68cf0c71151e63ea6f50a46ec7493
b805f02765a265
server_private_key: 8d5a577b03081018ee6d958b63b39acdff8f7eab95e8bc1fc
d08dd8acb04570c
~~~

#### Intermediate Values

~~~
server_mac_key: afee0cac92ec6214c0b10530d9368a31463cf45818411edffdcd8
2083b7d792adacb32e1117fb454293d7118d7c3a5cb8d9c820694199b2e6ac004e8ed
ae9b57
KE2: 5079b16709b195b3b63257b419efb752bd0603170160fa72b828ce9ff9209c0c
00201218201bd0c2b3b30348e68cf0c71151e63ea6f50a46ec7493b805f02765a2650
151c68e03d1686869cf2990eef51b9982268c21789e02826e9b165413e5651d430022
0d1293046326920181e667c7672d7b71a00fb627d7f8117291994fcd0778b1093ccb3
cb85035f38bf1ae741463b32ea0766617c6e3235284e4928b76ba2411105fab4e73dd
b8e672bd9932e9999ccf598972d4af5067152a275258de80e939517b8c8be8fd3efd2
9d233661f20dc89583fedf78f479e29098f728961e3acde8060199419179c6a4d01ea
218f570b4c867c397b4d0ea9beb06977ddca043621f79f40000faedf1496175a7421f
69a9c73cd713e2887406ff79b46a5ddaacd5da9532c109397930b7090d5f688f658d1
72c8d6f619adb0832cd68f8e787dbe0eb7938783f0ee9a9d9f2d9d28e5ea618e5233b
1c7
client_nonce: 9c904cf6ad461d22de25db20b4190fe3cc1223fc8b63235370ef968
eaa6ad5a5
prk: b957af137358da8d84a1e79277d08f8210a81ed7a6938214a5b60478b15ce001
cc1b47c493bc339c6227a6f17ccb82e9103d06baf62b7b423aa3060233a36834
envelope_nonce: 51c68e03d1686869cf2990eef51b9982268c21789e02826e9b165
413e5651d43
registration_request: c8d2e9ba503bf3f8821226653314427edb1ec8a3ecc94a5
dfbbe33d59d07b645
KE3: 7284759753cdc0988f9376d3baf371cf9f9eae96d55f3a75e097cff9b86a6b94
3668ba014dd4a5f85fd5a1dd3fca25f31cf734b8c090637c42b7d4705b5824fc
client_keyshare: 1436574fbeb7501956446b5cda86674ca0934f1027110c165f79
a4dc7fdd1f24
KE1: 7024ca0d5423176294fbb9ca968d8ce3fc879a231f1ceef69e672c89e02ded59
9c904cf6ad461d22de25db20b4190fe3cc1223fc8b63235370ef968eaa6ad5a500096
8656c6c6f20626f621436574fbeb7501956446b5cda86674ca0934f1027110c165f79
a4dc7fdd1f24
handshake_encrypt_key: 72f17a0a64308093738e35ac390ddf8a3c77fa52545f9e
7449d766fd280899cae2e7d48efbc62e2a6257731e4db210877e7f10fd23572e6d1fb
c2dc87a137d0e
registration_upload: 00207eee935bd83d1b146c0740d2c2c49cef5955ec8a90bc
860e40f169638915b6250151c68e03d1686869cf2990eef51b9982268c21789e02826
e9b165413e5651d4300220d1293046326920181e667c7672d7b71a00fb627d7f81172
91994fcd0778b1093ccb3cb85035f38bf1ae741463b32ea0766617c6e3235284e4928
b76ba2411105fab4e73ddb8e672bd9932e9999ccf598972d4af5067152a275258de80
e939517b8c
server_nonce: 8be8fd3efd29d233661f20dc89583fedf78f479e29098f728961e3a
cde806019
server_keyshare: 9419179c6a4d01ea218f570b4c867c397b4d0ea9beb06977ddca
043621f79f40
registration_response: 088ac01ebf5700f0c96bc2988509343cb7e2dd6f0df820
d0fb807faa11a26f5600201218201bd0c2b3b30348e68cf0c71151e63ea6f50a46ec7
493b805f02765a265
envelope: 0151c68e03d1686869cf2990eef51b9982268c21789e02826e9b165413e
5651d4300220d1293046326920181e667c7672d7b71a00fb627d7f8117291994fcd07
78b1093ccb3cb85035f38bf1ae741463b32ea0766617c6e3235284e4928b76ba24111
05fab4e73ddb8e672bd9932e9999ccf598972d4af5067152a275258de80e939517b8c
client_mac_key: c4cd9a172cb53bdb18be165822774ba1667a34007885b54341904
140aed87f0937e638c5eac56fe8ef022d72dc87bfa94f3d0be1da92f8bcaa40dd630d
03ad5c
pseudorandom_pad: 0d32b9bc214544aadba79470b66a94ad8e1537a7eb90311428d
8bd9f525eefd27dcc
blind_registration: 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9db
cec831b8c681a09
blind_login: e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd
4171ea02
auth_key: f3ee7a7b87c2df458e521e02f73994e32f8a3d3ddbd189910d33cbfae0a
b2b2405dbae114cc609ccca18a5eb79e366a17ded7e4f2c7be1cc62ecd8aaf2df755b
handshake_secret: 2931228a9a761f4561296c2207180b4549f6baa49241b2c228f
7bbe47123a1edcf95449b319fccd3429064631ad293075fcacd6912a245b20f50510c
b78629aa
server_private_keyshare: 46d9d2a4a995dcfe60413ea12bbce8076b169da5cc2d
8cecceaa330d26966101
client_private_keyshare: c6a6419bf8bb66cbf31a6150cd351e46da9b8d53ffaf
01c47fdd034bfc947d06
~~~

#### Output Values

~~~
session_key: 474faf06421009ff18118ae07f7a323ea2695a157a0aa20b832f9b58
291dc0a6f905cc0b7523f0f2fcc982cbb92d4150c85d5b2b7cb41fb66d8170a435245
952
export_key: 15b47f21b1f05e94314516ec399cfe3c28f17f7021fc66dd84bdf9cc0
48662c16d5ff80d8c29a2fe81e8bac1b569711b61c6a039de92e82e060bb1f7ddb334
6a
~~~

