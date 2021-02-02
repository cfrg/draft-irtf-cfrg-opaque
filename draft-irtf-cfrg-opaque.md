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
- pwdU: An opaque byte string containing the user's password.
- (skX, pkX): An AKE key pair used in role X; skX is the private key and pkX is
  the public key. For example, (skU, pkU) refers to U's private and public key.
- kX: An OPRF private key used for role X. For example, as described in
  {{create-reg-response}}, kU refers to the private OPRF key for user U known
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
    OPRF private key. We write `(kU, _) = KeyGen()` to denote use of this
    function for generating secret key `kU` (and discarding the corresponding
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
and helper functions. Moreover, U has a key pair (skU, pkU) for an AKE protocol
which is suitable for use with OPAQUE; See {{online-phase}}. (skU, pkU) may be
randomly generated for the account or provided by the calling client.
Clients MUST NOT use the same key pair (skU, pkU) for two different accounts.

To begin, U chooses password pwdU, and S chooses its own pair of private-public
keys skS and pkS for use with the AKE. S can use the same pair of keys with
multiple users. These steps can happen offline, i.e., before the registration phase.
Once complete, the registration process proceeds as follows:

~~~
 Client (pwdU, creds)                               Server (skS, pkS)
 --------------------------------------------------------------------
 (request, blind) = CreateRegistrationRequest(pwdU)

                               request
                      ------------------------->

            (response, kU) = CreateRegistrationResponse(request, pkS)

                               response
                      <-------------------------

 (record, export_key) = FinalizeRequest(pwdU, creds, blind, response)

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

- skU: The encoded user private key for the AKE protocol.
- pkS: The encoded server public key for the AKE protocol.
- idU: The user identity. This is an application-specific value, e.g., an e-mail
  address or normal account name.
- idS: The server identity. This is typically a domain name, e.g., example.com.
  See {{identities}} for information about this identity.

Each public and private key value is an opaque byte string, specific to the AKE
protocol in which OPAQUE is instantiated. For example, if used as raw public keys
for TLS 1.3 {{?RFC8446}}, they may be RSA or ECDSA keys as per {{?RFC7250}}.

These credentials are incorporated in the `SecretCredentials` and `CleartextCredentials` structs,
depending on the mode set by the value of `EnvelopeMode`:

~~~
enum {
  base(1),
  customIdentifier(2),
  (255)
} EnvelopeMode;
~~~

The `base` mode defines `SecretCredentials` and `CleartextCredentials` as follows:

~~~
struct {
  opaque skU<1..2^16-1>;
} SecretCredentials;

struct {
  opaque pkS<1..2^16-1>;
} CleartextCredentials;
~~~

The `customIdentifier` mode defines `SecretCredentials` and `CleartextCredentials` as follows:

~~~
struct {
  opaque skU<1..2^16-1>;
} SecretCredentials;

struct {
  opaque pkS<1..2^16-1>;
  opaque idU<0..2^16-1>;
  opaque idS<0..2^16-1>;
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
: The `EnvelopeMode` value. This MUST be one of `base` or `customIdentifier`.

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
along with the user public key `pkU` and private key `skU`, are stored
in a `Credentials` object with the following named fields:

- `skU`, the user's private key
- `pkU`, the user's public key corresponding to `skU`
- `idU`, an optional user identity (present only in the `customIdentifier` mode)
- `idS`, an optional server identity (present only in the `customIdentifier` mode)

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
    opaque pkS<1..2^16-1>;
} RegistrationResponse;
~~~

data
: A serialized OPRF group element.

pkS
: An encoded public key that will be used for the online authenticated key exchange stage.

~~~
struct {
    opaque pkU<1..2^16-1>;
    Envelope envU;
} RegistrationUpload;
~~~

pkU
: An encoded public key, corresponding to the private key `skU`.

envU
: The user's `Envelope` structure.

## Registration Functions {#registration-functions}

### CreateRegistrationRequest

~~~
CreateRegistrationRequest(pwdU)

Input:
- pwdU, an opaque byte string containing the user's password

Output:
- request, a RegistrationRequest structure
- blind, an OPRF scalar value

Steps:
1. (blind, M) = Blind(pwdU)
2. Create RegistrationRequest request with M
3. Output (request, blind)
~~~

### CreateRegistrationResponse {#create-reg-response}

~~~
CreateRegistrationResponse(request, pkS)

Input:
- request, a RegistrationRequest structure
- pkS, the server's public key

Output:
- response, a RegistrationResponse structure
- kU, the per-user OPRF key known only to the server

Steps:
1. (kU, _) = KeyGen()
2. Z = Evaluate(kU, request.data)
3. Create RegistrationResponse response with (Z, pkS)
4. Output (response, kU)
~~~

### FinalizeRequest {#finalize-request}

~~~
FinalizeRequest(pwdU, creds, blind, response)

Parameters:
- params, the MHF parameters established out of band
- mode, the InnerEnvelope mode
- Nh, the output size of the Hash function

Input:
- pwdU, an opaque byte string containing the user's password
- creds, a Credentials structure
- blind, an OPRF scalar value
- response, a RegistrationResponse structure

Output:
- record, a RegistrationUpload structure
- export_key, an additional key

Steps:
1. N = Unblind(blind, response.data)
2. y = Finalize(pwdU, N, "OPAQUE01")
3. nonce = random(32)
4. rwdU = HKDF-Extract(nonce, Harden(y, params))
5. Create SecretCredentials secret_creds with creds.skU
6. Create CleartextCredentials cleartext_creds with response.pkS
   and custom identifiers creds.idU and creds.idS if mode is
   customIdentifier
7. pseudorandom_pad =
     HKDF-Expand(rwdU, "Pad", len(secret_creds))
8. auth_key = HKDF-Expand(rwdU, "AuthKey", Nh)
9. export_key = HKDF-Expand(rwdU, "ExportKey", Nh)
10. encrypted_creds = xor(secret_creds, pseudorandom_pad)
11. Create InnerEnvelope inner_env
      with (mode, nonce, encrypted_creds)
12. auth_tag = HMAC(auth_key, concat(inner_env, cleartext_creds))
13. Create Envelope envU with (inner_env, auth_tag)
14. Create RegistrationUpload record with (envU, creds.pkU)
15. Output (record, export_key)
~~~

[[RFC editor: please change "OPAQUE01" to the correct RFC identifier before publication.]]

The inputs to HKDF-Extract and HKDF-Expand are as specified in {{RFC5869}}. The underlying hash function
is that which is associated with the OPAQUE configuration (see {{configurations}}).

See {{online-phase}} for details about the output export_key usage.

Upon completion of this function, the client MUST send `record` to the server.

### CredentialFile {#credential-file}

The server then constructs and stores the `CredentialFile` object, where `envU` and `pkU`
are obtained from `record`, and `kU` is retained from the output of `CreateRegistrationResponse`.
`kU` is serialized using `SerializeScalar`.

~~~
struct {
    SerializedScalar kU;
    opaque pkU<1..2^16-1>;
    Envelope envU;
} CredentialFile;
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
 Client (pwdU)                      Server (skS, pkS, credentialFile)
 --------------------------------------------------------------------
 (request, blind) = CreateCredentialRequest(pwdU)

                               request
                      ------------------------->

    response = CreateCredentialResponse(request, pkS, credentialFile)

                               response
                      <-------------------------

 (skU, pkS, export_key) = RecoverCredentials(pwdU, blind, response)
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
    opaque pkS<1..2^16-1>;
    Envelope envU;
} CredentialResponse;
~~~

data
: A serialized OPRF group element.

pkS
: An encoded public key that will be used for the online authenticated
key exchange stage.

envU
: The user's `Envelope` structure.

### Credential Retrieval Functions

#### CreateCredentialRequest {#create-credential-request}

~~~
CreateCredentialRequest(pwdU)

Input:
- pwdU, an opaque byte string containing the user's password

Output:
- request, a CredentialRequest structure
- blind, an OPRF scalar value

Steps:
1. (blind, M) = Blind(pwdU)
2. Create CredentialRequest request with M
3. Output (request, blind)
~~~

#### CreateCredentialResponse {#create-credential-response}

~~~
CreateCredentialResponse(request, pkS, credentialFile)

Input:
- request, a CredentialRequest structure
- pkS, the public key of the server
- credentialFile, the server's output from registration
  (see {{credential-file}})

Output:
- response, a CredentialResponse structure

Steps:
1. Z = Evaluate(DeserializeScalar(credentialFile.kU), request.data)
2. Create CredentialResponse response
    with (Z, pkS, credentialFile.envU)
3. Output response
~~~

#### RecoverCredentials {#recover-credentials}

~~~
RecoverCredentials(pwdU, blind, response)

Parameters:
- params, the MHF parameters established out of band
- Nh, the output size of the Hash function

Input:
- pwdU, an opaque byte string containing the user's password
- blind, an OPRF scalar value
- response, a CredentialResponse structure

Output:
- skU, the user's private key for the AKE protocol
- pkS, the public key of the server
- export_key, an additional key

Steps:
1. N = Unblind(blind, response.data)
2. y = Finalize(pwdU, N, "OPAQUE01")
3. contents = response.envU.contents
4. nonce = contents.nonce
5. rwdU = HKDF-Extract(nonce, Harden(y, params))
6. pseudorandom_pad =
    HKDF-Expand(rwdU, "Pad", len(contents.encrypted_creds))
7. auth_key = HKDF-Expand(rwdU, "AuthKey", Nh)
8. export_key = HKDF-Expand(rwdU, "ExportKey", Nh)
9. Create CleartextCredentials cleartext_creds with response.pkS
   and custom identifiers creds.idU and creds.idS if mode is
   customIdentifier
10. expected_tag = HMAC(auth_key, concat(contents, cleartext_creds))
11. If !ct_equal(response.envU.auth_tag, expected_tag),
    raise DecryptionError
12. secret_creds = xor(contents.encrypted_creds, pseudorandom_pad)
13. Output (secret_creds.skU, response.pkS, export_key)
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
  uint8 nonceU[32];
  opaque client_info<0..2^16-1>;
  uint8 epkU[Npk];
} KE1;
~~~

request
: A `CredentialRequest` generated according to {{create-credential-request}}.

nonceU
: A fresh 32-byte randomly generated nonce.

client_info
: Optional application-specific information to exchange during the protocol.

epkU
: Client ephemeral key share of fixed size Npk, where Npk depends on the corresponding
prime order group.

~~~
struct {
  CredentialResponse response;
  uint8 nonceS[32];
  uint8 epkS[Npk];
  opaque enc_server_info<0..2^16-1>;
  uint8 mac[Nh];
} KE2;
~~~

response
: A `CredentialResponse` generated according to {{create-credential-response}}.

nonceS
: A fresh 32-byte randomly generated nonce.

epkS
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
info = "3DH keys" || I2OSP(len(nonceU), 2) || nonceU
                  || I2OSP(len(nonceS), 2) || nonceS
                  || I2OSP(len(idU), 2) || idU
                  || I2OSP(len(idS), 2) || idS
~~~

See {{identities}} for more information about identities idU and idS.

The input parameter `IKM` is `K3dh`, where `K3dh` is the concatenation of
three DH values computed by the client as follows:

~~~
K3dh = epkS^eskU || pkS^eskU || epkS^skU
~~~

Likewise, `K3dh` is computed by the server as follows:

~~~
K3dh = epkU^eskS || epkU^skS || pkU^eskS
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
or `customIdentifier`.

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
of identities. In the case of OPAQUE, those identities correspond to idU and idS.
Thus, it is essential for the parties to agree on such identities, including an
agreed bit representation of these identities as needed.

Applications may have different policies about how and when identities are
determined. A natural approach is to tie idU to the identity the server uses
to fetch envU (hence determined during password registration) and to tie idS
to the server identity used by the client to initiate an offline password
registration or online authenticated key exchange session. idS and idU can also
be part of envU or be tied to the parties' public keys. In principle, it is possible
that identities change across different sessions as long as there is a policy that
can establish if the identity is acceptable or not to the peer. However, we note
that the public keys of both the server and the user must always be those defined
at time of password registration.

## Envelope Encryption {#envelope-encryption}

The analysis of OPAQUE from {{OPAQUE}} requires the authenticated encryption scheme
used to produce envU to have a special property called random key-robustness
(or key-committing). This specification enforces this property by utilizing
encrypt-then-HMAC in the construction of envU. There is no option to use another
authenticated-encryption scheme with this specification. (Deviating from the
key-robustness requirement may open the protocol to attacks, e.g., {{LGR20}}.)
We remark that export_key for authentication or encryption requires no special
properties from the authentication or encryption schemes as long as export_key
is used only after the envU is validated, i.e., after the HMAC in RecoverCredentials
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

The user identity (idU) and server identity (idS) are optional parameters
which are left to the application to designate as monikers for the client
and server. If the application layer does not supply values for these
parameters, then they will be omitted from the creation of the envelope
during the registration stage. Furthermore, they will be substituted with
idU = pkU and idS = pkS during the authenticated key exchange stage.

The advantage to supplying a custom idU and idS (instead of simply relying
on a fallback to pkU and pkS) is that the client can then ensure that any
mappings between idU and pkU (and idS and pkS) are protected by the
authentication from the envelope. Then, the client can verify that the
idU and idS contained in its envelope matches the idU and idS supplied by
the server.

However, if this extra layer of verification is unnecessary for the
application, then simply leaving idU and idS unspecified (and using pkU and
pkS instead) is acceptable.

<!-- TODO(caw): bring this back after updating later -->

<!-- ## Envelope considerations

It is possible to dispense with encryption in the construction of envU to
obtain a shorter envU (resulting in less storage at the server and less
communication from server to client). The idea is to derive skU from rwdU.
However, for cases where skU is not a random string of a given length, we
define a more general procedure. Namely, what is derived from rwdU is a random
seed used as an input to a key generation procedure that generates the pair
(skU, pkU). In this case, secret_credentials is empty and cleartext_credentials
contains pkS. The random key generation seed is defined as
HKDF-Expand(KdKey; info="KG seed", L)
where L is the required seed length. We note that in this encryption-less
scheme, the authentication still needs to be random-key robust which HMAC
satisfies. -->

<!--
Mention advantage of avoidable equivocable encryption? Still needs equivocable
authentication, but that one gets by modeling HMAC as programmable RO - check.
-->

<!-- To further minimize storage space, the server can derive per-user OPRF keys
kU from a single global secret key, and it can use the same pair
(skS,pkS) for all users. In this case, the per-user OPAQUE storage
consists of pkU and HMAC(Khmac; pkS), a total of 64-byte overhead with a
256-bit curve and hash. envU communicated to the user is of the same length,
consisting of pkS and HMAC(Khmac; pkS). -->

<!-- Can provide AuCPace paper (sec 7.7) as reference to importance of small
envU (for settings where storage and/or communication is expensive) -->

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
the construction of envU to all the key material in envU.
The server S will have two keys MK, MK' for a pseudorandom function f.
f refers to a regular pseudorandom function such as HMAC or CMAC.
Upon receiving a CredentialRequest for a non-existing
user idU, S computes kU=f(MK; idU) and kU'=f(MK'; idU) and responds with
CredentialResponse carrying Z=M^kU and envU, where the latter is computed as follows.
rwdU is set to kU' and secret_creds is set to the all-zero string (of the
length of a regular envU plaintext). Care needs to be taken to avoid side
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
changes kU at the time of a password change). In any case, this
indicates that idU is a registered user at the time of the second activation.
To conceal this information, S can implement the derivation of kU
as kU=f(MK; idU) also for registered users. Hiding changes in envU, however,
requires a change in the protocol. Instead of sending envU as is,
S would send an encryption of envU under a key that the user derives from the
OPRF result (similarly to rwdU) and that S stores during password
registration. During the authenticated key exchange stage, the user will derive
this key from the OPRF result, will use it to decrypt envU, and continue with the
regular protocol. If S uses a randomized encryption, the encrypted envU will look
each time as a fresh random string, hence S can simulate the encrypted envU also
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
to Richard Barnes, Dan Brown, Eric Crockett, Paul Grubbs, Fredrik Kuivinen,
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
skU: f56324b58f2a297f0817808d6c4265c906d2cd1bda6a509054de016cc01bfb0e
pkS: 2eeea0cd9f15af232f94f2981cb653183613b16d10b3cd99e1a93cd26a10551b
skS: b5d3406930dfe077b921d4ee646419d2e44ad37cd5445ae6709b45abcea8fe05
pkU: 48764a414784304e869d72d2016ee777c0af0d40c18b5ce2f5b8ef3d94d46f7e
idU: 48764a414784304e869d72d2016ee777c0af0d40c18b5ce2f5b8ef3d94d46f7e
idS: 2eeea0cd9f15af232f94f2981cb653183613b16d10b3cd99e1a93cd26a10551b
password: 436f7272656374486f72736542617474657279537461706c65
~~~

#### Intermediate Values

~~~
envU: 00e9c2d7e7ca7a9271c9ba1f76398b09c002b6e599e0db5751f1e5790c62a21
7470022992a7fd9fb92d21ee9c2f9233898e466ff41a216eeecca6a28b84cd1129671
15c58081c0d29204ff12dd39b3caf5720cadb9156f6e209e2ea05784cf4a142a52a7a
95efe7b688fd0a6e044b4a8e76ead8a14a106cb2facc0d4f73edba9c78060bbe9
envelope_nonce: e9c2d7e7ca7a9271c9ba1f76398b09c002b6e599e0db5751f1e57
90c62a21747
registration_request: 241b621c417c0705b5ea7a8b7cdd5039fd61e6b63effe2a
44418164c4d49003e
eskS: 810f6f0c6af4fa8fa73223de63ab31f2d7817b28709b6997bba85080e5e7120
4
eskU: b4b0588d5eaae9816d21e5969e7cb4b4ea523dc6023cd0e97cf8361f84bc2a0
e
epkU: 4c477753ff00490fd1e44aaff80c17b9dec99f44ff27a3d2203a9f891cd7627
5
handshake_encrypt_key: 89364f009d43b3a902a0bfb6a881bb6bad66acb086640a
8486bfdf5a4f60845e685f891216ca30b0721b4c55f7a4d3ed5b1ab6e5539e14ef5fb
8e5feb5a47019
epkS: e67219c832a57c2b304ae1ce4cb4ac9b0df9bfbb973b5d87ce5d0e6f92cf250
8
registration_upload: 002048764a414784304e869d72d2016ee777c0af0d40c18b
5ce2f5b8ef3d94d46f7e00e9c2d7e7ca7a9271c9ba1f76398b09c002b6e599e0db575
1f1e5790c62a217470022992a7fd9fb92d21ee9c2f9233898e466ff41a216eeecca6a
28b84cd112967115c58081c0d29204ff12dd39b3caf5720cadb9156f6e209e2ea0578
4cf4a142a52a7a95efe7b688fd0a6e044b4a8e76ead8a14a106cb2facc0d4f73edba9
c78060bbe9
rwdU: e4c31ea7f3c104500a695ae7107f9e971b0e029e5d3c9ac03f73d1ef3d076c7
a7e09fecd140db8286cfd459b17196d52672bfaaed9087d52574d316736441d85
registration_response: 1867301bcc67bdf8e640b7d6edcbe2a65488446417b50d
30cdba66ccb379e57200202eeea0cd9f15af232f94f2981cb653183613b16d10b3cd9
9e1a93cd26a10551b
client_mac_key: 88f7b18cb4df5b278506bd177eebc7db6f89ce250f1278fe7eef1
3ae9d3ba400d7b295dfddf5a4cda9213bddc28fc2d474048985aecd8fea58d0f45184
c7de7b
pseudorandom_pad: 990a8abadf275d34c0bdf134b81588249a88a4c423f71000782
8180f13fab10e3e8e
kU: 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b
blind_registration: c604c785ada70d77a5256ae21767de8c3304115237d262134
f5e46e512cf8e03
nonceS: d0f8eddf8f54d4672755e220671e5aa354f672bca9620ba0eb0e705eee27f
0b4
nonceU: 9b737f956bb72a6c23b004542b342771e578e3f381a15ee55eaf2e27d8270
04a
blind_login: ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63
e3263503
auth_key: 3c5f9be666211ac6e7cc6f01b59c7aaedb27c388a1cb6bc08e65967dc3b
d9517a209336fd8e1817c1ec8299bbb9b34fec29cfab9d24e1ae7a5a050c27d72e676
server_mac_key: 3239ec03365743d4485b7622f74175d6f6a779d644fd036ad1488
7299cef5c737a84f5265a317572aa17eafa2e2e040d2df523398798b6fe8f978864d7
e96cf9
handshake_secret: 9e6a08d974e5aacd467e52833d26e52bdc945adbedabd27ea39
21b75fba46d055acd1b3bafad8aafde89de93814a879dfa5197327457e46c1aa0f16e
ca973e7b
~~~

#### Output Values

~~~
session_key: f381cd5bfc9596f97f4e1b9e37b165c703fee8551575bb164081cfb0
6dd262e815714446bccff3286528b89e00418acdcc4322f593c4cb974638dd3dc2f47
533
export_key: c53808fc583cacee48c192cf5ee0ffd3438ddca1686a4083c81b60a9f
71a20fe12a35c81a11dc4a8190008b11827b09d72feb0d61ea35c2a731911ba5b5a28
56
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
skU: f56324b58f2a297f0817808d6c4265c906d2cd1bda6a509054de016cc01bfb0e
pkS: 2eeea0cd9f15af232f94f2981cb653183613b16d10b3cd99e1a93cd26a10551b
skS: b5d3406930dfe077b921d4ee646419d2e44ad37cd5445ae6709b45abcea8fe05
pkU: 48764a414784304e869d72d2016ee777c0af0d40c18b5ce2f5b8ef3d94d46f7e
idU: 48764a414784304e869d72d2016ee777c0af0d40c18b5ce2f5b8ef3d94d46f7e
idS: 2eeea0cd9f15af232f94f2981cb653183613b16d10b3cd99e1a93cd26a10551b
password: 436f7272656374486f72736542617474657279537461706c65
~~~

#### Intermediate Values

~~~
envU: 0162c469c4667b873542f2c4d02f04d03404a9926d2a55f6404a7f39867299e
0230022a0dc75ce1a0eadfa38c0a2bcd63ddefd33e4865b2cbda892dd8661a0978fc1
f69eadbd2c0b480c7a7944927c2a4ca9df52566fe2ddd7336c4792e164bb8eace1b2c
297346e50f258bc2bb89dbfeb2e7f7c122d90e040de3019dfbc6e9e5481ef12d0
envelope_nonce: 62c469c4667b873542f2c4d02f04d03404a9926d2a55f6404a7f3
9867299e023
registration_request: c8d2e9ba503bf3f8821226653314427edb1ec8a3ecc94a5
dfbbe33d59d07b645
eskS: 58ff086664522f9cdb35ce701328bc4e1b9b373715e79ca08e9a8a764e0e990
c
eskU: 93d18a1d733ad9ac49332131f339956aa8289724c69609f5add55a42ec131f0
4
epkU: 12ebab684c2461fb83a0c11735a347f35948d798293a1c4d49a9674cae6fa02
8
handshake_encrypt_key: 11e28a82586044f99aab7c8481b151f967fdf96178062a
ea21ad86cd0b81f048b081d387245c19cb3c837220175a6504b5a192d371ff54e30e6
ce631a92fd523
epkS: 0a47dbdbe9cd36c8c853716a1167acd9eb3338ff3650e19e51575977babff67
e
registration_upload: 002048764a414784304e869d72d2016ee777c0af0d40c18b
5ce2f5b8ef3d94d46f7e0162c469c4667b873542f2c4d02f04d03404a9926d2a55f64
04a7f39867299e0230022a0dc75ce1a0eadfa38c0a2bcd63ddefd33e4865b2cbda892
dd8661a0978fc1f69eadbd2c0b480c7a7944927c2a4ca9df52566fe2ddd7336c4792e
164bb8eace1b2c297346e50f258bc2bb89dbfeb2e7f7c122d90e040de3019dfbc6e9e
5481ef12d0
rwdU: 8815a865c85948ca950ffad2c10e7cc491dacc1dd44d77b75666a94cf858d6a
e94da3993ac83b48846a2132a9b1595bbd4a0b63c0b3b191e8aa0602c6c0a1b56
registration_response: 088ac01ebf5700f0c96bc2988509343cb7e2dd6f0df820
d0fb807faa11a26f5600202eeea0cd9f15af232f94f2981cb653183613b16d10b3cd9
9e1a93cd26a10551b
client_mac_key: 292a693f76a0e75fb7ea134d10d2ba41282f55dd3f4ec3efc2eff
a63564f0ce3090fa37f4dd949cc7de26a7718dce4454d477504a2876b78179ee1a131
31cbfc
pseudorandom_pad: a0fc80ad3ebb22d011bfaaab56b0b2bf562d8089e1a672f88d1
6357e96e301ed65a3
kU: 89c61a42c8191a5ca41f2fe959843d333bcf43173b7de4c5c119e0e0d8b0e707
blind_registration: 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9db
cec831b8c681a09
nonceS: c7c2267c51cd0753122e20cdcabd3a432e6c4c87d72fa2f7a0eb19f2bb670
35c
nonceU: fcd7e17f207b6a56f2eda8219bef3c3cca519ae9ac9c3ec767a025547afd2
541
blind_login: e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd
4171ea02
auth_key: 1ec78c3a6acb45826333c6821266ed33cd3bbb823e5012bee32086b2e6b
1feeb49eef885db9066f575d1cea3b84fcf730529439559746b7d19b61182c8bbef1b
server_mac_key: 3d9d98bce7a956540f1e11e4ff078aaf7312710139766b72ab9f1
d8279c115501a2bb4abe97c8c47df68d3ecbb6a2df070295de0013585fbb025d3119f
ba291e
handshake_secret: f3c10823f243700c933f35a3cd82307a30248dba8dd1ae3ee78
b87207f42360b5a6cd901110ef56c6007f2c3363a0459f6e26b9d6cd774e4d7a10ac0
c5939d37
~~~

#### Output Values

~~~
session_key: ff999f46b13675cc851e95c31dda209cbefea96105cd52358a9ea576
02e5689d6004b54f3d58e3b5316422951d76fb2f4d65f0f5eda3be807230925effc27
070
export_key: c8a93ee1b0db4dfb9c36784211797ce004ea94c514a1536411fc17319
68c64e6dc4f1032f61e5db53991fb94c4ff44e6e9f1442124b6e00be896301b57d0f5
60
~~~

