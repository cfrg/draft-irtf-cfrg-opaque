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
server_nonce: edcfcd8b40568b775e78d156760d509863538b6945e1289fd2ffacb
d2a5e523c
oprf_key: 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be03
7e50b
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63
e3263503
server_private_keyshare: ea0838457430cd992ba7f01d8e6cffeb5ca2727987a2
3d5bf0f1d2bf76a9e604
client_nonce: 8e68070e545ad4194f18fb83ab4b3c7328c11de7ba1f5288c15206f
bfcd7aeb3
server_info: 6772656574696e677320616c696365
server_identity: f4b4e41a869ae0ddf94a4af84029cf85963c14dc3fad2f6848ea
a2ca6cd2ba75
client_info: 68656c6c6f20626f62
client_private_keyshare: a54797ff24f4b7d522ac0b81bd36abf257ca5418643f
660505e65e1525ce8f02
envelope_nonce: f00b817b205ccbd7e019b17119377d20c1bb630f8f8803fd4f4da
c63e37c4d82
server_public_key: f4b4e41a869ae0ddf94a4af84029cf85963c14dc3fad2f6848
eaa2ca6cd2ba75
client_identity: 3aab142c6bdbd4f4c21daad4ba65c01ada9d6eea061e3a367d97
c25997060100
blind_registration: c604c785ada70d77a5256ae21767de8c3304115237d262134
f5e46e512cf8e03
client_public_key: 3aab142c6bdbd4f4c21daad4ba65c01ada9d6eea061e3a367d
97c25997060100
client_private_key: af6c58ca17b06f860dd90baded57b7e0b6038038996598e09
6a546fa811f4d0a
client_keyshare: 0a6fa5436dace1cf6fe383d67cb0453537e4f2ab0683c82d04ce
90cb88e3f07f
server_keyshare: 7a512c60e27429eb02f30d691e92bf7b4cc8397b8971eafc0935
811be77e686d
server_private_key: fff643b272864955fd70cba31f4e70dc0ce107eca6f9e4b46
81e72d23e3dab0d
~~~

### Intermediate Values

~~~
auth_key: 6aa9091833526d8f38e919b4b6cfc0b1bc1991d303191a2982fccfa0336
bc253b4f90466c9e718577221ef260a838f6acc499f8cdfbeab74cfa09db4ae1aed54
server_mac_key: efa28d0b7e913eabce52c088210aefe88c1ae44228d6db5af19b2
866849641b072992decf7c636a70e184628331da2a422fa132e32b418d66853fecdc9
2373a1
envelope: 00f00b817b205ccbd7e019b17119377d20c1bb630f8f8803fd4f4dac63e
37c4d82002270baeabd19c6e11cd89dcfa01dd9e52fdf081b5521402546028038e483
ba82e40d86d0c0caefad373dc9a4ca8b42499529d47e05ecaec20d454e14e75bc7706
0c66c1efe1ea9ef35ddcfaa4dbdaf020d8a6002b56f2f27e108935d90127663dcfc11
prk: af4694799e7eedc8845057d484d6d85fb4c0f4799ae506f5a5cf22b1ff2d080c
12e72ce66b06a4057d861c073eaca0d63ad8ca919b609130b9aab2610b36e3df
client_mac_key: 5b1caec2166d2e9012a8c0df0719732e10ef7944ed47d546de3df
7fbcbfce47ff1727319c1a548591f29e9d02490b63eac3442867315e857bff092f377
fdd9f3
pseudorandom_pad: 709a45d1410cf6acb71bc2791674087868e8ad56a178bc239a6
0ae41c54003fb408c
handshake_encrypt_key: fc407e81c73878699562fdd1f618709e82538c80fb1790
6154ac21a5865b2e4793b4721738b3c5fbce8721dd40c6e2e8d92186a75909030c1bc
0efd77e733579
handshake_secret: f39715d0a7973bce9ca5aecc0e1931c2663b9d06a904b9ffc07
f8889478452d8f89c227b51042d6a326154982197eaaaefc01ce749de53fcf4af8ac1
b62f09e1
~~~

### Output Values

~~~
registration_response: 1867301bcc67bdf8e640b7d6edcbe2a65488446417b50d
30cdba66ccb379e5720020f4b4e41a869ae0ddf94a4af84029cf85963c14dc3fad2f6
848eaa2ca6cd2ba75
export_key: 664ccad1041c5052f55a153cfb98617441f894e22fae527bc0a1ee0c1
6614b4bce638c857a5328e16e2da8a5d4a97bee3f033885f41ef5dda8345d789b58e1
17
registration_upload: 00203aab142c6bdbd4f4c21daad4ba65c01ada9d6eea061e
3a367d97c2599706010000f00b817b205ccbd7e019b17119377d20c1bb630f8f8803f
d4f4dac63e37c4d82002270baeabd19c6e11cd89dcfa01dd9e52fdf081b5521402546
028038e483ba82e40d86d0c0caefad373dc9a4ca8b42499529d47e05ecaec20d454e1
4e75bc77060c66c1efe1ea9ef35ddcfaa4dbdaf020d8a6002b56f2f27e108935d9012
7663dcfc11
registration_request: 241b621c417c0705b5ea7a8b7cdd5039fd61e6b63effe2a
44418164c4d49003e
session_key: 49808d005fcae31a29bcb5c0a9d208c7abe20327d666260b8e87b1c1
772283405e53f3c5b5bda2ee358d3e98978474b6c48024edf8798b058bd904cf6dfd8
0f2
KE3: 4d1ac42643c2df4e634202c3a8f7eee9b689875a857c1983d261ff6ded00afce
bafadef3591d54be5748de9d362421211fec93e9937a8d31c9afedd73b13436b
KE2: e83812f06568d57b8cdfdcc90fe91454e21bd25dd2a1c32dd1599a2e4a4b6c35
0020f4b4e41a869ae0ddf94a4af84029cf85963c14dc3fad2f6848eaa2ca6cd2ba750
0f00b817b205ccbd7e019b17119377d20c1bb630f8f8803fd4f4dac63e37c4d820022
70baeabd19c6e11cd89dcfa01dd9e52fdf081b5521402546028038e483ba82e40d86d
0c0caefad373dc9a4ca8b42499529d47e05ecaec20d454e14e75bc77060c66c1efe1e
a9ef35ddcfaa4dbdaf020d8a6002b56f2f27e108935d90127663dcfc11edcfcd8b405
68b775e78d156760d509863538b6945e1289fd2ffacbd2a5e523c7a512c60e27429eb
02f30d691e92bf7b4cc8397b8971eafc0935811be77e686d000f48b825d7b18adbb8d
767532b0a25cf452f2d692d5686f2e23dd4bf4a16a58d14938876ca62f6c052e34748
c6afc0ef3cc4e83451959817239a2795d066c774c6ed9781d29ca8764292551cd45d4
e77
KE1: b68e0e356f8490fa9c3bed952e16cc02db21eda686b3c484f3d9d912caa41f76
8e68070e545ad4194f18fb83ab4b3c7328c11de7ba1f5288c15206fbfcd7aeb300096
8656c6c6f20626f620a6fa5436dace1cf6fe383d67cb0453537e4f2ab0683c82d04ce
90cb88e3f07f
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
server_nonce: 590db8f24cfd9f86bfc293f191b91601eecf729822cc5120bbff1f6
58e9cff68
oprf_key: 89c61a42c8191a5ca41f2fe959843d333bcf43173b7de4c5c119e0e0d8b
0e707
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd
4171ea02
server_private_keyshare: c23ab6d249e17f1a257bf425c530e62f5cdaaca96fc0
377e62094ae520aedd0c
client_nonce: c4b0d1ee6cb58d2c168e64a890d9bcbe6ab6e61f92713ad2006354b
ed898c9cb
server_info: 6772656574696e677320616c696365
server_identity: f4b4e41a869ae0ddf94a4af84029cf85963c14dc3fad2f6848ea
a2ca6cd2ba75
client_info: 68656c6c6f20626f62
client_private_keyshare: f69cccc93fe5f9eefcd10eece3099395f7f82ee92727
a047206c6c9bba34080b
envelope_nonce: e7c8d8bca70bef8918d99bae50b0b1b3b2d9bb391f7c287a06395
ef0a060fe8f
server_public_key: f4b4e41a869ae0ddf94a4af84029cf85963c14dc3fad2f6848
eaa2ca6cd2ba75
client_identity: 3aab142c6bdbd4f4c21daad4ba65c01ada9d6eea061e3a367d97
c25997060100
blind_registration: 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9db
cec831b8c681a09
client_public_key: 3aab142c6bdbd4f4c21daad4ba65c01ada9d6eea061e3a367d
97c25997060100
client_private_key: af6c58ca17b06f860dd90baded57b7e0b6038038996598e09
6a546fa811f4d0a
client_keyshare: 928103b62fb59408e3227e79bf8a852d1293a50228dc189363db
4caaef93f03d
server_keyshare: 5cee9a28742f3ecb8de59d1f70b2b601f8b2f0c8697efb0e7ce6
9a81cc81761d
server_private_key: fff643b272864955fd70cba31f4e70dc0ce107eca6f9e4b46
81e72d23e3dab0d
~~~

### Intermediate Values

~~~
auth_key: d1274f878e21fdcd8d9dc9b81995f03a65b7869c16ba7eb88ffb62eddb5
7cb638821175bea44b2c51579fb7df0592938146b8ffada691210c30ed7da45d9b1f8
server_mac_key: a3604ccd2299000069f31824a982b8484c4664b6c88ced569c80b
7905f34cd0a0f5ddcc93a9f575e617e10c439134f261e885a83978880a5077300d1de
9ebd09
envelope: 01e7c8d8bca70bef8918d99bae50b0b1b3b2d9bb391f7c287a06395ef0a
060fe8f00224577c8447aef32a69033396ed5cb24f6d62594166916f40925717648dc
47255b3508bb6a350c8d51d1367a0f3719251f90c50a4d1bed2d9cc5687f2ff0f3754
ef623864b247a7770c2c3133659580a8163230039f2a36adb15b673ff5c1666c98254
prk: 0df0fde7766660bd0cd9b57fc38d2df9c3d80ce67166e86ae2814be2ccb157c2
d5c90dc90ef6e43846262388c7036d662142268e5bbcc055bdf8fc5c43a5ccee
client_mac_key: f45c13cb334095b024d58f28f0d31930fe52c90100f8eb79167ec
a207062ef000cca7ecb9b45e98a95632d0d0873155683b299f8c25457f1531467c10e
1d6b20
pseudorandom_pad: 4557672822252516ffb534b7de66c9a161c52215e92e6d6cbd9
1e0ed9abda4447802
handshake_encrypt_key: ea405c1f14783891d3da87ed51500afadf798bcd120868
9af26e0c1da8f45d3a466fbbd8469e669527cc9e56ed5f4478c185e263e7ee0741f51
e46ac4e59e778
handshake_secret: e18d9222551000b63881a547ef3156d99d6836ce394ee973e26
806d3d10e8a6ceece2f98dea96c9a913b42f1b76f47fbe6504ce0f4be07fbcdbe022f
53baac04
~~~

### Output Values

~~~
registration_response: 088ac01ebf5700f0c96bc2988509343cb7e2dd6f0df820
d0fb807faa11a26f560020f4b4e41a869ae0ddf94a4af84029cf85963c14dc3fad2f6
848eaa2ca6cd2ba75
export_key: 712635c7c4441dfa7661190f5301b068a14576fc9fa7917461a8849fe
50cb9b1fe0c0aacb84c551599e38b310f9fbf702542d0491badca2b3f7e4fcab79561
14
registration_upload: 00203aab142c6bdbd4f4c21daad4ba65c01ada9d6eea061e
3a367d97c2599706010001e7c8d8bca70bef8918d99bae50b0b1b3b2d9bb391f7c287
a06395ef0a060fe8f00224577c8447aef32a69033396ed5cb24f6d62594166916f409
25717648dc47255b3508bb6a350c8d51d1367a0f3719251f90c50a4d1bed2d9cc5687
f2ff0f3754ef623864b247a7770c2c3133659580a8163230039f2a36adb15b673ff5c
1666c98254
registration_request: c8d2e9ba503bf3f8821226653314427edb1ec8a3ecc94a5
dfbbe33d59d07b645
session_key: 08bc8befac196b62e8b8d2e40c364efa2c63c189b32cd9daf690a6db
63c5746aae28c93546912b7e7b2a4c8c5b4ab0f267dfc564c4a239a9e40219a8e92bf
9ad
KE3: 70abb1709b5bda490a50163e523774a00a09c0ee323f27bae8b983a599ea3b3e
fe9a71fcd362c6ab90ebb3fbc0ad9f3ab7eb3ddad22c09d42c41d1fe5ed6a927
KE2: 5079b16709b195b3b63257b419efb752bd0603170160fa72b828ce9ff9209c0c
0020f4b4e41a869ae0ddf94a4af84029cf85963c14dc3fad2f6848eaa2ca6cd2ba750
1e7c8d8bca70bef8918d99bae50b0b1b3b2d9bb391f7c287a06395ef0a060fe8f0022
4577c8447aef32a69033396ed5cb24f6d62594166916f40925717648dc47255b3508b
b6a350c8d51d1367a0f3719251f90c50a4d1bed2d9cc5687f2ff0f3754ef623864b24
7a7770c2c3133659580a8163230039f2a36adb15b673ff5c1666c98254590db8f24cf
d9f86bfc293f191b91601eecf729822cc5120bbff1f658e9cff685cee9a28742f3ecb
8de59d1f70b2b601f8b2f0c8697efb0e7ce69a81cc81761d000fe04aad1bcedd7e0cf
65f2f7ddae5fce15c9191f76d7d9778dac7977ba465cd6b4ed95bc6a3b245007b52fc
3c4f2bb92b1b9ae4f1665cbc3ab65fcaa4d94786d9248df2f2f393ae737db423ef91d
17c
KE1: 7024ca0d5423176294fbb9ca968d8ce3fc879a231f1ceef69e672c89e02ded59
c4b0d1ee6cb58d2c168e64a890d9bcbe6ab6e61f92713ad2006354bed898c9cb00096
8656c6c6f20626f62928103b62fb59408e3227e79bf8a852d1293a50228dc189363db
4caaef93f03d
~~~

