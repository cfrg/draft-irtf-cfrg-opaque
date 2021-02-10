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
    opaque server_public_key<1..2^16-1>;
} RegistrationResponse;
~~~

data
: A serialized OPRF group element.

server_public_key
: The server's encoded public key that will be used for the online authenticated key exchange stage.

~~~
struct {
    opaque client_public_key<1..2^16-1>;
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
    opaque client_public_key<1..2^16-1>;
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
    opaque server_public_key<1..2^16-1>;
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

#### OPAQUE-3DH Encryption and Key Confirmation {#3dh-core}

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

# Configurations {#configurations}

An OPAQUE configuration is a tuple (OPRF, Hash, MHF, EnvelopeMode). The OPAQUE OPRF
protocol is drawn from the "base mode" variant of {{I-D.irtf-cfrg-voprf}}. The
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

While one can expect the practical security of the OPRF function
(namely, the hardness of computing the function without knowing the
key) to be in the order of computing discrete logarithms or solving
Diffie-Hellman, Brown and Gallant {{BG04}} and Cheon {{Cheon06}} show an
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
below for posterity.

OPAQUE may also be instantiated with any post-quantum (PQ) AKE protocol that has the message
flow above and security properties (KCI resistance and forward secrecy) outlined
in {{security-considerations}}. Note that such an instantiation is not quantum safe unless
the OPRF is quantum safe. However, an OPAQUE instantiation where the AKE is quantum safe,
but the OPRF is not, would still ensure the confidentiality of application data encrypted
under session_key (or a key derived from it) with a quantum-safe encryption function.

## HMQV Instantiation Sketch

An HMQV instantiation would work similar to OPAQUE-3DH, differing primarily in the key
schedule {{HMQV}}. First, the key schedule `info` value would use a different constant prefix
-- "HMQV keys" instead of "3DH keys" -- as shown below.

~~~
info = "HMQV keys" || I2OSP(len(client_nonce), 2) || client_nonce
                   || I2OSP(len(server_nonce), 2) || server_nonce
                   || I2OSP(len(client_identity), 2) || client_identity
                   || I2OSP(len(server_identity), 2) || server_identity
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
hashInput = I2OSP(len(epkU), 2) || epkU ||
            I2OSP(len(info), 2) || info ||
            I2OSP(len("client"), 2) || "client"
u = Hash(hashInput) mod L
~~~

Likewise, `s` would be computed as follows:

~~~
hashInput = I2OSP(len(epkS), 2) || epkS ||
            I2OSP(len(info), 2) || info ||
            I2OSP(len("server"), 2) || "server"
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

The key schedule would also change. Specifically, the key schedule `info` value would
use a different constant prefix -- "SIGMA-I keys" instead of "3DH keys" -- and the `IKM`
computation would use only the ephemeral key shares exchanged between client and server.

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
EnvelopeMode: 01
OPRF: 0001
SlowHash: Identity
Hash: SHA512
~~~

### Input Values

~~~
server_nonce: a4997137a8fa0d4baf7052a499bf877057f9404e03c889d641a0d7c
807b6a518
oprf_key: 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be03
7e50b
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63
e3263503
server_private_keyshare: 31587dff30b8001d9d43584decc22e358fa7f9d6e606
29fb1223081c3bae7103
client_nonce: 75a1ad27ab77578bc08b44c4318f09b31d53145c9ba3b42abf0ea08
a781277a6
server_info: 6772656574696e677320616c696365
client_info: 68656c6c6f20626f62
client_private_keyshare: fbbf4ad24119f08a35bf999f8ae0c779ed7b3e266bf3
3f793f6bf9ebf4578005
envelope_nonce: 6c6bb9021b9833c788dd25994d3ce7f3811338744fd6dc556e037
585783444c0
server_keyshare: 82be40ef93bf7c6edd43d4ed9f52fa19827649b819de39c52a22
43e985b75d62
blind_registration: c604c785ada70d77a5256ae21767de8c3304115237d262134
f5e46e512cf8e03
client_public_key: b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9aa2c3ef
caba4f1c4ae861
client_private_key: f0f56cfb488649fe28691dd9aa5dc9ff4c0e6028075baa3c5
615398a2cb12304
client_keyshare: 484e47e31b3132f4ee512e41805a1690891111a7b885bc526198
22c14cabf360
server_public_key: 5442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdc
eeeb935924a903
server_private_key: d63d709e3a739a128929a9f289ff263fdcbc457f2f47f7c43
ccafbbfee72290c
~~~

### Intermediate Values

~~~
auth_key: 22198da4ad73b1d35cd8bb875e64ce1a9fc2edeb073d760e114d1d7a2f8
6d47411caf1787907e2ff96cd3190b14d101101d74cff234259d9f19a18f2cfe29d0b
server_mac_key: 9de28e2f7107afe266570934c033dd6a403fb2b09a9f1a1357a81
9fb072d25e6651626638d77bd7f0adf4b2b715d0a0bee2ac531fd0f7da699aba6e9ed
717466
envelope: 016c6bb9021b9833c788dd25994d3ce7f3811338744fd6dc556e0375857
83444c00022e9b28440a1dc99cca7513e8eb754d427caf8515642b45a92c73838c043
fc316deeb83deface81589bc8e5c2c767b5ab79218834fbf4fa4f87cf23775aa54633
ed75665cd88f451e044cac1b282d890269476d1ac18ff9a4c0cb832e1143ffa7d447a
prk: 732303f65e76c39f30876aec31af1f5bcd8861626c922baa2e842209c7d5bf2e
024912db2d6cac00b1260c437d34ec588a664a55fc7a0a40251915d2b15d8ec9
client_mac_key: 1536168d48218d08dcbed3438e897d98eff566894240d8d136be0
4ba46b2c788883fd165ce7614c52a6a9c926bf55d249e6c29bc4a23d5a1775ad294a7
858922
pseudorandom_pad: e99274b5cd27d14aeeaf16e7aa8d7e7a03071d58229c5dc96d0
46ed57a761ddccdbc
handshake_encrypt_key: c646def7a8ca75282ac1a0ad15630834cba2772837d7a3
a26d00b36923e55b3f5d065679c715e4c799654f261c865f1a55bc94cabc29a6e2e72
296dfc494a984
handshake_secret: cc887e128c28064106d4101ac3de633e9096e170f2c4a9913d3
50f306274b1665a5b251f761672c12db4c403a615c22cee96adb3539fa62662a17f2e
18cd5fed
~~~

### Output Values

~~~
registration_response: 1867301bcc67bdf8e640b7d6edcbe2a65488446417b50d
30cdba66ccb379e57200205442a6f57333a332b4c6f07308f6fa846bde3ed27425820
cdceeeb935924a903
export_key: 6ca2c344763e5bc9e3d2bbfe3d982b826b709da597e28e85f9594ec54
2a20c697d55de277ccce1d1af7c48ab7fea1467ac1e3a99c71dcf6326a909d280bd2f
6f
registration_upload: 0020b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9a
a2c3efcaba4f1c4ae861016c6bb9021b9833c788dd25994d3ce7f3811338744fd6dc5
56e037585783444c00022e9b28440a1dc99cca7513e8eb754d427caf8515642b45a92
c73838c043fc316deeb83deface81589bc8e5c2c767b5ab79218834fbf4fa4f87cf23
775aa54633ed75665cd88f451e044cac1b282d890269476d1ac18ff9a4c0cb832e114
3ffa7d447a
registration_request: 241b621c417c0705b5ea7a8b7cdd5039fd61e6b63effe2a
44418164c4d49003e
session_key: ee9f1ef224d498858f6c9b3a121016a38bad7816055c452b1c7edf3d
d439c42a4cc78cbd672e985a20910df14f8f1af4ce5793303ffe6954ff5f1a264e3fd
515
KE3: e771daf28bc5e8068dead67c3db19f9ad03ee919e52f6c7a6e79cf1085bd7448
1e76512c77f37762578eb2faff8fe98e4185ca2d01957216c556d33a6fba3028
KE2: e83812f06568d57b8cdfdcc90fe91454e21bd25dd2a1c32dd1599a2e4a4b6c35
00205442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdceeeb935924a9030
16c6bb9021b9833c788dd25994d3ce7f3811338744fd6dc556e037585783444c00022
e9b28440a1dc99cca7513e8eb754d427caf8515642b45a92c73838c043fc316deeb83
deface81589bc8e5c2c767b5ab79218834fbf4fa4f87cf23775aa54633ed75665cd88
f451e044cac1b282d890269476d1ac18ff9a4c0cb832e1143ffa7d447aa4997137a8f
a0d4baf7052a499bf877057f9404e03c889d641a0d7c807b6a51882be40ef93bf7c6e
dd43d4ed9f52fa19827649b819de39c52a2243e985b75d62000f13aed85ae30aee2f8
9ac5e1c5dd53609b890267ef2d765bb56000bc704c2ba4e4256107befee6655cdb084
64e6c75d8b251642e0d721b3fce38f245568b50e7f6c98825d54cc1a26d6eafadcc1d
344
KE1: b68e0e356f8490fa9c3bed952e16cc02db21eda686b3c484f3d9d912caa41f76
75a1ad27ab77578bc08b44c4318f09b31d53145c9ba3b42abf0ea08a781277a600096
8656c6c6f20626f62484e47e31b3132f4ee512e41805a1690891111a7b885bc526198
22c14cabf360
~~~

## OPAQUE-3DH Test Vector 2

### Configuration

~~~
Group: ristretto255
EnvelopeMode: 02
OPRF: 0001
SlowHash: Identity
Hash: SHA512
~~~

### Input Values

~~~
server_nonce: 0f3a6da8b667bc7a383c987586bee749c5f2787691baca68757e78b
6128b0a0f
oprf_key: 89c61a42c8191a5ca41f2fe959843d333bcf43173b7de4c5c119e0e0d8b
0e707
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd
4171ea02
server_private_keyshare: 70c944dcb7f4dddde168ecb48dd9488c62b6fc7e9bb4
2a16d291afca9dd25b07
client_nonce: 480917b09c6720680b4a7a0ba9f54b69d870f640a4a7994b47ad07d
1a95c984f
server_info: 6772656574696e677320616c696365
server_identity: 5442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdcee
eb935924a903
client_info: 68656c6c6f20626f62
client_private_keyshare: a4ba6cb7e16ab76eccdb4c0b9261eedd426d7863f00b
fc4a0e09476d3121e70c
envelope_nonce: e38fb444afe3df13ae05e6876d10eca7661196375518eb66d7dee
b8cfb42d13f
server_public_key: 5442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdc
eeeb935924a903
client_identity: b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9aa2c3efca
ba4f1c4ae861
blind_registration: 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9db
cec831b8c681a09
client_public_key: b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9aa2c3ef
caba4f1c4ae861
client_private_key: f0f56cfb488649fe28691dd9aa5dc9ff4c0e6028075baa3c5
615398a2cb12304
client_keyshare: 4ae7d50bb80cc8f5034d36c1c27edc30caca0983677a941bc0ac
e5e10b18300a
server_keyshare: a2e9e0809b270a1d5c8208f3498a3188538265e6a9e6b274cb38
c4c5d9b1792d
server_private_key: d63d709e3a739a128929a9f289ff263fdcbc457f2f47f7c43
ccafbbfee72290c
~~~

### Intermediate Values

~~~
auth_key: 4c7c0ae950ad7e9c518266f953d4a01bd2232695f92fb028aa6c124996e
31a205f621305fd4997edf8a5fce04a51252ba8430227c134b81d7093a58e01c70752
server_mac_key: 974bde939ef1d30ba29f9ec2addcaff1eeb105a1f534e04113f9f
0b5c3b9a0797e3fa5f7006e63dfb2b0ce74d002bd1161767c361507bfb1fa0fed5063
1cdcb7
envelope: 02e38fb444afe3df13ae05e6876d10eca7661196375518eb66d7deeb8cf
b42d13f00227ed4654d4452340f26c6304dceeeb1fddb142fcd91b3b26ecd566d7688
095f9478a721e5a592be9dd3bda76ed97421819aca4a30752813223d33bc7ea443be9
76754605116278c7fffda4de142674ed154f540bd3285080637eb4b929e1378336b11
prk: e3bb74ca5f88a95571578e921489e1b6119b438e4efce6e955ae9b6453f24aa4
e3a34fa22bc5f470cfc134ca0784a9cd7df64be46ff3b325fc19f4009979bf2e
client_mac_key: 1c55ecba64d98dc2db8f45faa72b8fdd63cad8677b8665cc575cf
8ad36ef38ec63c9dfc5552007573215983f55d8f5cfa1651da8417e3f27094dde5254
7f5b89
pseudorandom_pad: 7ef495b828a97c896f381824d3371ba012eb63c3f19bb535676
a3b63b18373255ba3
handshake_encrypt_key: 0852fb826109073be6e7c065b6e2d1f872c16f9977c177
cd2f945b26bb933fe6252f226f40483f7aa52f545f801d1e4430f30f80fd42070494e
a77fdcecd6595
handshake_secret: bfd3bfbe451520880975d0e568cbd3b5155b23c02de504fccb9
dd5a8195266cd94d49d040530b3d6b0a585d542eb24da708a2b6f6dc34dee4652d0c1
c62c4e59
~~~

### Output Values

~~~
registration_response: 088ac01ebf5700f0c96bc2988509343cb7e2dd6f0df820
d0fb807faa11a26f5600205442a6f57333a332b4c6f07308f6fa846bde3ed27425820
cdceeeb935924a903
export_key: 0effa605dc47ba4fe565c423b782b8b6697b26ee2ede7059b0e17510d
f8b11554ce053409671480a56ffbe77b91edc95205c213caeaf9dcb0841790ff834a0
09
registration_upload: 0020b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9a
a2c3efcaba4f1c4ae86102e38fb444afe3df13ae05e6876d10eca7661196375518eb6
6d7deeb8cfb42d13f00227ed4654d4452340f26c6304dceeeb1fddb142fcd91b3b26e
cd566d7688095f9478a721e5a592be9dd3bda76ed97421819aca4a30752813223d33b
c7ea443be976754605116278c7fffda4de142674ed154f540bd3285080637eb4b929e
1378336b11
registration_request: c8d2e9ba503bf3f8821226653314427edb1ec8a3ecc94a5
dfbbe33d59d07b645
session_key: 8dc21ff264f2774de95955d35544ba314e92d07f4a3b32c89ead5e70
c83ac4c0221deadd34ed11d43fc4d3651aec612d696c63979c96bf1ddd1ee44da5d0c
d68
KE3: c178e45ed9b314653685cdbf5f7730e3e40f8652ceb9b10f47d1c784fdd75dd1
07c4ae3f7683de5a692359178c8f13f41a043fc1dcfc14b1fb7cb411514efc6c
KE2: 5079b16709b195b3b63257b419efb752bd0603170160fa72b828ce9ff9209c0c
00205442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdceeeb935924a9030
2e38fb444afe3df13ae05e6876d10eca7661196375518eb66d7deeb8cfb42d13f0022
7ed4654d4452340f26c6304dceeeb1fddb142fcd91b3b26ecd566d7688095f9478a72
1e5a592be9dd3bda76ed97421819aca4a30752813223d33bc7ea443be976754605116
278c7fffda4de142674ed154f540bd3285080637eb4b929e1378336b110f3a6da8b66
7bc7a383c987586bee749c5f2787691baca68757e78b6128b0a0fa2e9e0809b270a1d
5c8208f3498a3188538265e6a9e6b274cb38c4c5d9b1792d000f5a1a0b34573bf728b
14f53485f3bf62fd91154dc9ca01b21945b2204f96adc87bd80e8283ecf3522b6d893
7527f2e9b9782a94fedab0fa304590d1d4f03d72fb1664fca1523a3be95f6c3a97d0a
2ed
KE1: 7024ca0d5423176294fbb9ca968d8ce3fc879a231f1ceef69e672c89e02ded59
480917b09c6720680b4a7a0ba9f54b69d870f640a4a7994b47ad07d1a95c984f00096
8656c6c6f20626f624ae7d50bb80cc8f5034d36c1c27edc30caca0983677a941bc0ac
e5e10b18300a
~~~
