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
vulnerable to pre-computation attacks, lacks proof of security and is less efficient
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
  It is an error to call this function with two arguments of unequal
  length.
- ct_equal(a, b): Return `true` if `a` is equal to `b`, and false otherwise.
  This function is constant-time in the length of `a` and `b`, which are assumed to be of equal length, irrespective of the values `a` or `b`.

Except if said otherwise, random choices in this specification refer to
drawing with uniform distribution from a given set (i.e., "random" is short
for "uniformly random"). Random choices can be replaced with fresh outputs from
a cryptographically strong pseudorandom generator, according to the requirements
in {{!RFC4086}}, or pseudorandom function.

The name OPAQUE is a homonym of O-PAKE where O is for Oblivious. The name
OPAKE was taken.

# Cryptographic Protocol and Algorithm Dependencies {#dependencies}

OPAQUE relies on the following protocols and primitives:

- Oblivious Pseudorandom Function (OPRF, {{I-D.irtf-cfrg-voprf}}, version -06):
  - Blind(x): Convert input `x` into an element of the OPRF group, randomize it
    by some scalar `r`, producing `M`, and output (`r`, `M`).
  - Evaluate(k, M): Evaluate input element `M` using private key `k`, yielding
    output element `Z`.
  - Finalize(x, r, Z): Finalize the OPRF evaluation using input `x`,
    random scalar `r`, and evaluation output `Z`, yielding output `y`.
  - DeriveKeyPair(seed): Derive a private and public key pair deterministically
    from a seed.
  - SerializedElement: A serialized OPRF group element, a byte array of fixed
    length.
  - SerializedScalar: A serialized OPRF scalar, a byte array of fixed length.
  - Nok: The size of an OPRF private key

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
  - Hash(msg): Apply a cryptographic hash function to input `msg`, producing an
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

# Offline Registration {#offline-phase}

Registration is executed between a client C and a
server S. It is assumed S can identify C and the client can
authenticate S during this registration phase. This is the only part
in OPAQUE that requires an authenticated and confidential channel, either physical, out-of-band,
PKI-based, etc. This section describes the registration flow, message encoding,
and helper functions. Moreover, C has a key pair (client_private_key, client_public_key) for an AKE protocol
which is suitable for use with OPAQUE; See {{online-phase}}. The private-public keys (client_private_key, client_public_key) may be randomly generated (using a cryptographically secure pseudorandom number generator) for the account or provided by the calling client.
Clients MUST NOT use the same key pair (client_private_key, client_public_key) for two different accounts.

## Setup Phase {#setup-phase}

In a setup phase, C chooses its password, and S chooses its own pair of private-public
AKE keys (server_private_key, server_public_key) for use with the AKE, along with a Nh-byte oprf_seed. S can use
the same pair of keys with multiple clients, and can opt to use multiple seeds (so long as they are
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

 (record, export_key) = FinalizeRequest(password, creds, blind, response)

                                record
                      ------------------------->
~~~

{{registration-functions}} describes details of the functions referenced above.

Both client and server MUST validate the other party's public key before use.
See {{validation}} for more details.

Upon completion, S stores C's credentials for later use.

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
  opaque auth_tag[Nm];
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

Note that the total size of the Envelope is equal to Nsk + Nh + 33 bytes.

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

~~~
FinalizeRequest(password, creds, blind, response)

Parameters:
- params, the MHF parameters established out of band
- mode, the InnerEnvelope mode
- Nx, the output size of the Extract function

Input:
- password, an opaque byte string containing the client's password
- creds, a Credentials structure
- blind, an OPRF scalar value
- response, a RegistrationResponse structure

Output:
- record, a RegistrationUpload structure
- export_key, an additional key

Steps:
1. y = Finalize(password, blind, response.data)
2. envelope_nonce = random(32)
3. prk = Extract("", Harden(y, params))
4. Create SecretCredentials secret_creds with creds.client_private_key
5. Create CleartextCredentials cleartext_creds with response.server_public_key
   and custom identifiers creds.client_identity and creds.server_identity if
   mode is custom_identifier
6. pseudorandom_pad = Expand(prk, concat(envelope_nonce, "Pad"), len(secret_creds))
7. auth_key = Expand(prk, concat(envelope_nonce, "AuthKey"), Nh)
8. export_key = Expand(prk, concat(envelope_nonce, "ExportKey"), Nh)
9. masking_key = Expand(prk, "MaskingKey", Nh)
10. encrypted_creds = xor(secret_creds, pseudorandom_pad)
11. Create InnerEnvelope inner_env
      with (mode, envelope_nonce, encrypted_creds)
12. auth_tag = MAC(auth_key, concat(inner_env, cleartext_creds))
13. Create Envelope envelope with (inner_env, auth_tag)
14. Create RegistrationUpload record with (creds.client_public_key, masking_key, envelope)
15. Output (record, export_key)
~~~

The inputs to Extract and Expand are as specified in {{dependencies}}.

See {{online-phase}} for details about the output export_key usage.

Upon completion of this function, the client MUST send `record` to the server.

The server then directly stores the `record` object as the credential file for each client. Note that
the values `oprf_seed` and `server_private_key` from the server's setup phase must also be persisted.

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
The output `export_key` MUST NOT be used in any way before the HMAC value in the
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
    opaque masking_nonce[32];
    opaque masked_response[Npk + Nsk + Nh + 33];
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
     concat(masking_nonce, "CredentialResponsePad"), Npk + Nsk + Nh + 33)
5. masked_response = xor(credential_response_pad, concat(server_public_key, record.envelope))
6. Create CredentialResponse response with (Z, masking_nonce, masked_response)
7. Output response
~~~

In the case of a record that does not exist, the server invokes the CreateCredentialResponse
function where the record argument is configured so that:
- record.masking_key is set to a random byte string of length Nh, and
- record.envelope is set to the byte string consisting only of zeros, of length Nsk + Nh + 33

Note that the responses output by either scenario are indistinguishable to an adversary
that is unable to guess the registered password for the client corresponding to credential_identifier.

#### RecoverCredentials {#recover-credentials}

~~~
RecoverCredentials(password, blind, response)

Parameters:
- params, the MHF parameters established out of band
- Nx, the output size of the Extract function

Input:
- password, an opaque byte string containing the client's password
- blind, an OPRF scalar value
- response, a CredentialResponse structure

Output:
- client_private_key, the client's private key for the AKE protocol
- server_public_key, the public key of the server
- export_key, an additional key

Steps:
1. y = Finalize(password, blind, response.data)
2. prk = Extract("", Harden(y, params))
3. masking_key = Expand(prk, "MaskingKey", Nh)
4. credential_response_pad = Expand(masking_key,
     concat(response.masking_nonce, "CredentialResponsePad"), Npk + Nsk + Nh + 33)
5. concat(server_public_key, envelope) = xor(credential_response_pad, response.masked_response)
6. contents = envelope.contents
7. envelope_nonce = contents.nonce
8. pseudorandom_pad =
    Expand(prk, concat(envelope_nonce, "Pad"), len(contents.encrypted_creds))
9. auth_key = Expand(prk, concat(envelope_nonce, "AuthKey"), Nh)
10. export_key = Expand(prk, concat(envelope_nonce, "ExportKey"), Nh)
11. Create CleartextCredentials cleartext_creds with server_public_key
   and custom identifiers creds.client_identity and creds.server_identity if mode is
   custom_identifier
12. expected_tag = MAC(auth_key, concat(contents, cleartext_creds))
13. If !ct_equal(envelope.auth_tag, expected_tag),
    raise DecryptionError
14. secret_creds = xor(contents.encrypted_creds, pseudorandom_pad)
15. Output (secret_creds.client_private_key, server_public_key, export_key)
~~~

## AKE Instantiations {#instantiations}

This section describes instantiations of OPAQUE using 3-message AKEs which
satisfies the forward secrecy and KCI properties discussed in {{security-considerations}}.
As shown in {{OPAQUE}}, OPAQUE cannot use less than three messages so the 3-message
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
   opaque label<8..255> = "OPAQUE " + Label;
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
  uint8 mac[Nm];
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
    +-> Derive-Secret(., "handshake secret", Hash(preamble)) = handshake_secret
    |
    +-> Derive-Secret(., "session secret", Hash(preamble)) = session_key
~~~

From `handshake_secret`, Km2, Km3, and Ke2 are computed as follows:

~~~
server_mac_key =
  Expand-Label(handshake_secret, "server mac", "", Nx)
client_mac_key =
  Expand-Label(handshake_secret, "client mac", "", Nx)
handshake_encrypt_key =
  Expand-Label(handshake_secret, "handshake enc", "", Nx)
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

- KE2.mac = MAC(Km2, Hash(concat(preamble, KE2.enc_server_info)), where
  preamble is as defined in {{derive-3dh}}.
- KE3.mac = MAC(Km3, Hash(concat(preamble, KE2.enc_server_info, KE2.mac)),
  where preamble is as defined in {{derive-3dh}}.

The server application info, an opaque byte string `server_info`, is encrypted
using a technique similar to that used for secret credential encryption.
Specifically, a one-time-pad is derived from Ke2 and then used as input to XOR
with the plaintext. In pseudocode, this is done as follows:

~~~
info_pad = Expand(Ke2, "encryption pad", len(server_info))
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
- EnvelopeMode value is as defined in {{credential-storage}}, and is one of
  `base` or `custom_identifier`.
- The Group mode identifies the group used in the OPAQUE-3DH AKE. This SHOULD
  match that of the OPRF. For example, if the OPRF is OPRF(ristretto255, SHA-512),
  then Group SHOULD be ristretto255.

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
used to produce envelope to have a special property called random key-robustness
(or key-committing). This specification enforces this property by utilizing
encrypt-then-HMAC in the construction of the envelope. There is no option to use another
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
oprf_seed: ea9b156e36f82c03f85bf45d64037460778f68ba37c40da8eef9791124
16523eeafeeaf99e8d629dc7d1fac5ee91a508bbf7d40ee58d2666886ad9cfc03215e
a
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 601c990a406261f61f8e0ce634be2f8f836209d65d08f5898db14
936a5d51803
masking_nonce: 4b106286480b50275fea1cabd53752c0e27debf465d04b6c436820
327b95dda0
client_private_key: 533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3
bddafbda99e2e0c
client_public_key: a07d9609083613e2d7521b8f77f1cd7a07d89ea03aa0045080
775edc37949341
server_private_key: 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a
9706137886dce08
server_public_key: 4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b
78624cbd10b371
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 7a795ec1469a08784af696043dec10a05eb90f32de42dc1a366a7ad
28d310877
client_nonce: de7769fe6cf71e8fc9ef94ccd95d041314a7c498a5ec15b67f5dd45
44b9141f0
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
oprf_key: 40f275335fc170fd112c9e0218b3a3a9fd35f8e81c513d9bb8b32d79796
7dd03
~~~

### Intermediate Values

~~~
auth_key: d806834c1f12362a869e6423345cd5f342bb3392bed28ac752d4445145d
f2f6f58e25d484d9d0eff7cd94a7635ed10f357616c9559050d33c051eac3f78ac449
prk: 5bcc418610c47e60eb7e3017370c6de95735e8ea941ae53581c6a41412a8573d
903d9a0ccbf6794f3ff603170e0daa2d0b845aa396039a003c8930bd5eb54796
pseudorandom_pad: 84b89715a3988aec6aa19e1db7be022024187472ba0ab2553f2
8e272bbcaa4aa
envelope: 01601c990a406261f61f8e0ce634be2f8f836209d65d08f5898db14936a
5d51803d784b9783251be15730dbf94c400579a29635733daaa669a04f54dcf12548a
a64a6f6de996177c6fe7f78f56818f3b8bde06449b31c8ffedb7211aee22a3b389904
d7c40a0e611aab87e3dd6f2c1d682ba07931aac9ba1625b5634c996dda49f
handshake_secret: 455f713c6ce380bb648b095193ef264f281768563cc9d9a82c8
d3f38c624ce053a5031b7a7f474fe8c86f7e411fdff3bc3452f901d5a94826b2e6967
cdffb266
handshake_encrypt_key: 1679f426a28c2735985a6de9dbf61289181471b010d8d4
9fddd4fffa0d1af69ec35b4e8dbe2a6a9975e23bca00f5e5f6672dfff0dbcc66236bc
71ce31c267eb7
server_mac_key: fa747a5bcc501e1c2e088045124b65e7f133dd5e9adad74833e03
5c1eeedd215bdc47fb932a3ee9b5b298ec79b803f34c353ae0d8b5a2f2eea93514bb4
9432b2
client_mac_key: 55b146cfc5b72147e8f78ab2c66416ec1341cb458141d61e579b1
32d3f3a6fe2312bf18a5ea2f6004fe17331753f844b0e83a1f72c44b3967654d5b3ac
c2efbe
~~~

### Output Values

~~~
registration_request: 24bbcabb15452642f709cb8567eff38f4cda6044aca3356
87a62b8453d849c18
registration_response: a82dde5efcce27af7430c55a2a38b37508215bc04ca570
351916a9a79aac5c1c4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b7
8624cbd10b371
registration_upload: a07d9609083613e2d7521b8f77f1cd7a07d89ea03aa00450
80775edc379493415ada757344170715cef5c7c2c81a5bdad725b18afbb8ecaf4bf9b
44410fc3fcef01d9ec3b84231c5e1b1236025cdd14ed6905388e5251dcced3929dae2
166ddb01601c990a406261f61f8e0ce634be2f8f836209d65d08f5898db14936a5d51
803d784b9783251be15730dbf94c400579a29635733daaa669a04f54dcf12548aa64a
6f6de996177c6fe7f78f56818f3b8bde06449b31c8ffedb7211aee22a3b389904d7c4
0a0e611aab87e3dd6f2c1d682ba07931aac9ba1625b5634c996dda49f
KE1: 0e8eeeb2ca0dbf5f690cfe0b76783d7667245f399b874a989f168fdd3e572663
de7769fe6cf71e8fc9ef94ccd95d041314a7c498a5ec15b67f5dd4544b9141f000096
8656c6c6f20626f624c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
KE2: 1c9f8ec52bbb6ebc9d35c34793e3dcf463f60365d241eff64fec6fa9ed9b8e48
4b106286480b50275fea1cabd53752c0e27debf465d04b6c436820327b95dda0b2cf3
2de38eceb515ba3a897f60db79b58081d804857065de0902aa5be724a76a7ef96eae4
bccfa7601d9efbeb100e43e6b6cea4d5c9c743a131d2e155bfbe768b3f62d4d0c1b64
8e75bbab3dede3ae2fe3eaecd0bf8a3f3a24c1cd97e89eb4db944b3ba280d20a63e6a
b80f1fdaf2105ca3f5d1d28e2f88bcfa1c1dd4ca4db6e2191a66ea132cceddb0a8303
28d89ec95f1eb021ed6e17b1a263ad63d7403db437a795ec1469a08784af696043dec
10a05eb90f32de42dc1a366a7ad28d310877ca372e52516d51c19763ad5eb1a5b60da
fb68c264dcf6bcc692f667a71c5a617000f7a62300e5e2b4f5d666d77c75d46c6f391
3c56b7505f1b9a1bd4bc9886020fc941fa2b1bb4e431e9944b5399b2daa4c4e903200
0967e77ce2dec3bbda448077a21b621907580cb3721255aa75a057c
KE3: 6136621991dcd352deeb80ddc1ee4cb71a6a83c114821b041fea4bfce4666daf
bc9ce30b8bc38cf6c856daf95b8a3f37c308b11b38506cf80f6dbc42736b0aa9
export_key: e19f0a894c96769350396796d39317cd6faaedd0cf69923afbd7242d5
42a613f6c33d700da141ddcfcacc9e45705a4ad00e5153aa104fad75f88b22f2e8fee
74
session_key: ddd18e9999c59ced1be6262e97fff2364c1c7fecebe0c90cee5d91da
c0eb35676b3ba7ecd6dc80fef12b30231246651689fb7210234762f64af86aa0d7d4c
a11
~~~

## OPAQUE-3DH Test Vector 2

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
oprf_seed: 84af710b52309eb52d378204bc5ce720c86ec30ff0eed2cf5d0d727ce5
6e42b21d471301910ddc96d9e2efd16c81a55a5fe5c3dd41e9cf870735a57463d33db
e
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 39bda7c1b17e02023ae7559101dd55b23ad8bbb30425103b6b3af
0e8f7731a23
masking_nonce: efe7c36640c48df708d765c9de118169518248f12eec968a8dd159
695195c018
client_private_key: c4d5a15f0d5ffc354e340454ec779f575e4573a3886ab5e57
e4da2985cea9e32f6d95539ce2c7189e1bd7462a21723e92e2e9955ef20a92c
client_public_key: fa62b671b96719815ec36461206766abc7eb1f46a969a7cbb8
07e97a95b030cc099939aa21f1949dbe417fea9b8e49899fbecaf48e89c2d1
server_private_key: 5843ebd3618d4fad8b7288477da50bed9befa58af639ddd95
0fec34205f8a4f166fadcb8fa71a3ffdd2e98f422bf7b99be19f7da1fab583c
server_public_key: 9ec51bc9645cbd7a765d4c1aeea840546d46d634c71176124e
8c167f2ba4609a5f53fa6e9e28cd5330db92c552c90d01e23a4103b3447ee3
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 166af6d52ac37aa5d34514b942fdaa68d675e59f622c5e62c32bcbd
536f5dad8
client_nonce: 6f2c5e9c4c49c74f38958d2c58829560a02a7f430f5f13f096a873e
5b8068ab3
server_keyshare: a6254b70ba6b0661ac023219d3f9151fece07a906dedfdd192e1
832c85a0fdf2d22cbe6e13f88ffc6856a45fc6c939f7d86c928c0a49579b
client_keyshare: 28579a4439cf59039e6cc7aafd09baf78027dd4657004954ef5d
b78ef982c02d687a68ca87ec4c4463792b66d258b354128dea2d72087be5
server_private_keyshare: 7def33909b794fe6e69a642b20f4c9118febffaf6b6a
31471fe7794aa77ced123f07e56cc27de60b0ab106c0e1aac79e92dd2d0507e43b39
client_private_keyshare: d83e00cbb8559f84cb7a221b235b0950a0ab553f03f1
0e1386abe954011b7da62bb6599418ef90b5d4ea98cca1bcd65fa514f189d2b31a07
blind_registration: 5a9d35a225ec6340149a0aaf99870019c3d002aa4cfcf2816
57cf36fe562bc60d9133e0e72a74432f685b2b620a55561604bb5783ca7f11d
blind_login: eb9e7aea3e4839413997e020f9377b63c13584156a09a46dd2a425c4
1eac0e313a47e99d05df72c6e1d58e654a5ee9354b1150602f6adf2d
oprf_key: 3d1451f603ca1aa0a2c2cf71e38bfdc5fdba2962eddeca8edb6bd989915
5f8550adbf79c921d5c7124376968570c1f7e8290f2260666cf03
~~~

### Intermediate Values

~~~
auth_key: ca31be46b36d9656069191fda39dc63e614e5291fa33ab71606b172cba5
6c993230240e3c01e2ac1722d0c1f8d0f466f8cb4454de7c24aa22c1b7021c3dfa769
prk: 15ab295a4753d2aaa6e910c6c0f1431c8d318355b3bcfa80c996e0ede0d03f4d
098c8f99d8bbe880aba6ccc5d8ea7e0a0bbd5095906f21257ad1d17d4aec42c2
pseudorandom_pad: 30b5399d5b49dd58bead7292f8f5bc3865b4057f81906729d6e
44b0e5e879b401851cb0eb13747b9a15e660e3d882eff237fafe7073a3e34
envelope: 0139bda7c1b17e02023ae7559101dd55b23ad8bbb30425103b6b3af0e8f
7731a23f46098c25616216df09976c61482236f3bf176dc09fad2cca8a9e996026d05
72ee889e377f1b363040e3126c9f9f0d160d5136b2e81a971867ca246a44ce8c8a80f
acbaa554b06a498936a0b3f59609fb2d39e5ea15f70df7fee2e884845ad35f7fe4238
79d9088795c78c3fb036f6ea167dccbad3bbaeac
handshake_secret: bfcea2daa5f6b0dd956d8ea2f8129a9396952b94503d3025496
37dcb89862255d112e2aa0789427e62641e935ae41ff7fc833d3789469e28fe7c18b2
e36e8c36
handshake_encrypt_key: daa81b7b3ebac35f51aeff14fe182a63055d0a7d8d5d9c
732c3bb52eac1beaeca2af20466956b6d3e22a09d701bd9c6c91c3b1df711d7403068
0c84fefa128c1
server_mac_key: ce84efc74eecfe9595bd3197b138cbb87579d8fc343659027738e
01f53d67b79a4f8442009ff4f6b83118e424abf4640733ceaf60fec81bfd1ff76db69
6d536f
client_mac_key: da3448328edbac3c48c83356d73e399551f946f01c7eacd8ac680
c92f8f0bf62ba49b18f67cf694ac466601a18a6c04dd91ae68c5618f4629cb7dc6a2c
318688
~~~

### Output Values

~~~
registration_request: fc78edf05434b6eef7990ff3b51356e9a2f4bb74e3f54dd
449c262bb50079e857b5f94b8630033654cd601fe57c4c474d55a98bb1fb6bf52
registration_response: c28142f565b2927eb3f153bd9203004357d2937b56839d
a0cc87b635673d00fb61e5d16605285b4ae7c04c314593fe8075c2aa2d7727fb3a9ec
51bc9645cbd7a765d4c1aeea840546d46d634c71176124e8c167f2ba4609a5f53fa6e
9e28cd5330db92c552c90d01e23a4103b3447ee3
registration_upload: fa62b671b96719815ec36461206766abc7eb1f46a969a7cb
b807e97a95b030cc099939aa21f1949dbe417fea9b8e49899fbecaf48e89c2d137c34
75746a6409ab71983123501acecb3b43f6ef92a3f44628c1fe4b2614c7788c328e711
9c061bb983943264d0f40868726cfad685880fb87035488edd84f40139bda7c1b17e0
2023ae7559101dd55b23ad8bbb30425103b6b3af0e8f7731a23f46098c25616216df0
9976c61482236f3bf176dc09fad2cca8a9e996026d0572ee889e377f1b363040e3126
c9f9f0d160d5136b2e81a971867ca246a44ce8c8a80facbaa554b06a498936a0b3f59
609fb2d39e5ea15f70df7fee2e884845ad35f7fe423879d9088795c78c3fb036f6ea1
67dccbad3bbaeac
KE1: 2679593badc25cd59dc786d12a74f81fd0189042d0aeb7d5f868c46f0b928574
f3e97b8a994eb752dad3fd4d4da80209ad8d9f2e3a594cae6f2c5e9c4c49c74f38958
d2c58829560a02a7f430f5f13f096a873e5b8068ab3000968656c6c6f20626f622857
9a4439cf59039e6cc7aafd09baf78027dd4657004954ef5db78ef982c02d687a68ca8
7ec4c4463792b66d258b354128dea2d72087be5
KE2: 90f94abefbe226becbb50fe1714e7f4e4afa4adb7ba548afe2f5a112f0fb1903
09f46d57ad8f4983b43cf7bb1d4cc9457bf42a76e6e5bab7efe7c36640c48df708d76
5c9de118169518248f12eec968a8dd159695195c018363e49b4d48be6e5abbd1062a4
0f2a51e5e7b7c6bb36a0acc75a5ded9489b538b6517a3a7383fda378d74fccf99b7d8
1fef5e0f22ed58f8a725ba7121ddd17c5875178cf400647863028a233e7d9803c9aba
21fdeaba6f8dae0dd1a62ecd1a739ac26a22fbcc5c560e33ceb15bd40aa0dfe32755a
58d93f938850e94eef9755e6dedb40ee9db98a3ac7a99c7a3bdeb67ad7d94357ff9d4
7da91d869a617d413739dfe8d70ddefaf02928a77b7067ed2ab90861ba0690ebb2fc8
f0981a45585ce3f523681d7accc3d3991bf798167e624a9166af6d52ac37aa5d34514
b942fdaa68d675e59f622c5e62c32bcbd536f5dad8a6254b70ba6b0661ac023219d3f
9151fece07a906dedfdd192e1832c85a0fdf2d22cbe6e13f88ffc6856a45fc6c939f7
d86c928c0a49579b000f3e597505b11377190b8e35531e72e1bb3d5e9fcf209a59a96
1b4f1232996bc549d550369869b25122ea91bface0c6e65b850d9994c09072115cee3
2cf820dfc8ae6f6d7a16607e0e6f90c7cfd24ee4
KE3: 370a8ea4fbed38b2a702a9bd4640657a6075e67a2f7130e70ed202a04949fa69
e2c6b75249c24fda8c9dd0409c6780d5fec3b2e629aa0b261b5e5f3e8f6ab508
export_key: 0eb094b8b9071a9a7a75adab1d126b3200b80e0bebc87e069c3a5fadb
cda8e6734d2509c954cdcd7424444a10e1f659691ee9e938b43222fb5201218ae4048
9b
session_key: 9a62182ff9831be6abe8483880ae9e4b3d93d7df409a6d7957da4e59
e3d8df2d75bd63d6d2fb8ef15db9af69b9bd9565e0a2355c57b1b40ee75e5b8e60b08
ebf
~~~

## OPAQUE-3DH Test Vector 3

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
oprf_seed: 2568801a80c9040b13907b4fa2ee10b9a0c04dc70cf90c54446e6e6eef
602a7c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 4348ffe7bf3136d48f7fffbbd723fa04346810067fcea3612d087
922d425a37a
masking_nonce: 9b53be35d1051fe1a2bdd5c3dd9849afed2fbae882420455f4eed5
756dacfdd4
client_private_key: d109200faf9f3ed91580252aacabffab14c28a79fa6ace8c0
eb8821ebc93e0e3
client_public_key: 035dfacb64b4fc01608fed13f30613c480a651b61f51f1b723
194a9b0b087a6bce
server_private_key: 26da289237c586eb5b730752ab3a8b65e5ec765ddfe0842b1
e767d094676796d
server_public_key: 03d8e300e96f45df1730e4f024c613c8b7c8c8870763062670
77eb2d429469b247
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: dc4b7022edc4928cc2c90044d987531da17de1cd68bda17944b37ed
13b453577
client_nonce: a91a5b1c75ce0c4d3656a9df31a593b6191511e1e281fadcc8cc9fd
200aed80a
server_keyshare: 02408cd991c504479b74ca729ea989e6c9ca6d258588221fb2bb
82a65e25bfa7ba
client_keyshare: 037d58532742d4512bf51e14b660bbffe9aa1633dfbe61ad1953
67317cc28d30d1
server_private_keyshare: aa264a26c0e3d42fb773b3173ba76f9588c9b14779bd
8d90825155ab61f17606
client_private_keyshare: af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbd5d9e7f6efd3093c4
blind_registration: 77bf4cf8a378c46175141eeb28db81bd6e67ffd9f8af813a4
8c2c5f724dc5902
blind_login: 2ecceabd57fb03cf760c926d2a7bfa265babf29ec98af0cfab51fd72
02017f04
oprf_key: 2e48997f665d147dc7732ca57a95113ae935c4c5653e2612659cc528261
e098f
~~~

### Intermediate Values

~~~
auth_key: 172c08d0b97369ec191b7911477fce03c4c57e0f107f97bfe6b3d51e0ae
6de01
prk: c099af89e8558d5be8f17634930e93668f082e45371851f809dc2a0bec928e6c
pseudorandom_pad: 95ae6352a58cad23d0dbf477d420c694b8635158c7ca77356c7
45e7fd6337a23
envelope: 014348ffe7bf3136d48f7fffbbd723fa04346810067fcea3612d087922d
425a37a44a7435d0a1393fac55bd15d788b393faca1db213da0b9b962ccdc616aa09a
c0d762626cb3734e1af0582380e8eefeba837bd2fc104081444a330deb3b010618
handshake_secret: 2e95d55aaa73439db43d2a28f0e9b71f7c772f67016ab8d82d5
303438c3445c0
handshake_encrypt_key: 22706564bb471dbca9ac1674955d982f9f761b66bf8078
02721251bdab2d29eb
server_mac_key: 0c8f0f9effe03e3c94c4761afa51806e91729be44e0a2f2bd5a06
775a8e53c50
client_mac_key: 8a333331aebc7b5d4814229ae83fb7ff3e75e5cffc176bf0a081e
f3caef6f2dc
~~~

### Output Values

~~~
registration_request: 027897d82c6b60bf46aee77613bbd25a0451b2d1227ece9
1dc75ae31167056b8b1
registration_response: 0357c09b740564df53a4515610c304b285ea1ddd064c66
96c2f99fe98fe651df5203d8e300e96f45df1730e4f024c613c8b7c8c887076306267
077eb2d429469b247
registration_upload: 035dfacb64b4fc01608fed13f30613c480a651b61f51f1b7
23194a9b0b087a6bce4d227a0a279ea8c9a12b0a1865c289274a3148638ff54194c16
378bfc8e97850014348ffe7bf3136d48f7fffbbd723fa04346810067fcea3612d0879
22d425a37a44a7435d0a1393fac55bd15d788b393faca1db213da0b9b962ccdc616aa
09ac0d762626cb3734e1af0582380e8eefeba837bd2fc104081444a330deb3b010618
KE1: 034a4f7341740160fd422ef457b455180d67c7106bc7f4790133a9cb5dc6239a
dca91a5b1c75ce0c4d3656a9df31a593b6191511e1e281fadcc8cc9fd200aed80a000
968656c6c6f20626f62037d58532742d4512bf51e14b660bbffe9aa1633dfbe61ad19
5367317cc28d30d1
KE2: 02165529fa05c3ef1ee26439e9e7fd0bdf3e77aa0291096b551a618154b0d96f
ef9b53be35d1051fe1a2bdd5c3dd9849afed2fbae882420455f4eed5756dacfdd40ac
dc9d4dc508c0fa5d8f6a739704e4c0a01dd84ca616f6594b8ffc81916a640e83fd935
dda1fbf92542cef3999272e99fca6de47cc77c374eb5ffe9d9beedd0dbc0ee022c063
91aa80ab2e8667383116cbdea74f714d5fcfafaeac4195908040efa1cdedfeff0e451
5ac3d98cded83aaf472dc4e00b0bfce2c619650268d9345fc7dc4b7022edc4928cc2c
90044d987531da17de1cd68bda17944b37ed13b45357702408cd991c504479b74ca72
9ea989e6c9ca6d258588221fb2bb82a65e25bfa7ba000fbfc2e9844316d44a1ade991
09eb38605c091717ba1c5b8463b66a3268c73ff06d80d4761d32b57326bcc73b92d52
9b
KE3: 694909cf99e042abba2d895879e198f13d3590a76fcd98cff996a3905d6f069a
export_key: 7aadb57da96959e89d1ce179d023de0e308ecccab088a5fc2f413d837
cdd769a
session_key: 8d80fa554e1ca1ceb3b7808cb6471bf4ac6d82047cc2e29f4bd6632c
c7206fa6
~~~

## OPAQUE-3DH Test Vector 4

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
oprf_seed: a763e8adfe11add9530442f740bc68c9bb229994f26804c3ed81a88d85
f1b14efcea1bc47a40408d49de7ef6373488638315fc629b21cf0b1f62f6fc26020d4
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: c3924c09bec273656e2bd94bfb62298dd285005933dbe1d55e7a6
d4726c60123
masking_nonce: 23418cbce393a6b317de9fc3a112b4be65dbf2a3c2642b8ebc27a8
ef7bae59af
client_private_key: d0b7db3d2b4597a670a5204b2b606f5a28328916e1e5ea5a1
7862d7a261fdd6d959759758d5e34abcee64d86fd20ab4d
client_public_key: 02427e85ad90b76452c06bc253d5b06f00dcf142bb6ba53108
ce07c0fb0f50d842930afbbd9593b911e799c49c60cc3a47
server_private_key: 242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24daa19
22d13757ac9df4adc7e4e0b6b39943267b5bcebad6393e3
server_public_key: 022a448ce78e089cd76160451272b32c68dc162b5e20622cb8
1e5529930a50100c3cad3db88b97700acb574a7535fdc6b4
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 40e13f227cd5e4f4360087196ff3b3517ed5c5ffd4c1ba1be79bed8
a238200fa
client_nonce: d158ce034e8889a4b80494038aae295496253ec4819b3fff08e8bde
185a96c39
server_keyshare: 0270fa6de7a309107d8783d1fbddcfde02a39352a0c7f7f0b7a3
c5306b26df7db6f9676c8263e38d5a562b613fdd66e2ec
client_keyshare: 02cb5d5a8e64a5cc2c0e6ad6cf981f9fb77b9171e92693df21f3
ff4cbf53fbdf99726a197dcf7e180381914ffdf48f3f56
server_private_keyshare: 2e3431bcc25f80b409c533dd21924d77bcbd10873989
b7e58306b863276ae74049615162a416d507a6532c99c1ea3f04
client_private_keyshare: d05f6e78dc1edabd3b9631be9f8b274d9aaf671bfb6a
775229bf435021b89c683259773bc686956af0c7822ba317fb5f
blind_registration: 626a939e19daca653b9217801b5d51cef66d9fdbd94a53533
e7c5057e09e220065ea8c257c0dd6055c4b401063eff0c0
blind_login: 86028c44b92bd3aedcf6744d388ca013ef33edd369304ed96fc56c7c
6c0bd369f8e926ffe4854a58f6b3e908bdb38e3d
oprf_key: db85bd48cb707cc366e975ca16c3a27956ba8b7ecd00999dd64bf4d7a94
468b175850b3799ec46b8fb47cf3abb890de3
~~~

### Intermediate Values

~~~
auth_key: 1f800a2827973a1e0d7f84d098b97d45fd6fc519ff0a76e71c26ebe35d1
6199db6adb0dae96976b790630e9040dbd456e7f756a3c1fd7d9166c5a4916d473c61
prk: d1914994c4af361c1be31581bfee30428dfabf5e7e793ab98df90ee4160c71be
364c09b6f87f92ff9256990fcff2b4b0c3b593942381da5d79cdd639f15963df
pseudorandom_pad: 1947ac1d791f25c553978a713277297e7233a76c0044d19caa8
6ec588c8d08782778b23b24f112092b40a2e8b210b11a
envelope: 01c3924c09bec273656e2bd94bfb62298dd285005933dbe1d55e7a6d472
6c60123c9f07720525ab2632332aa3a191746245a012e7ae1a13bc6bd00c122aa92d5
15b2efeb4ea9af26a2e5a6ef6e4f301a577817c649cd1e52ab3d7088e51c5495df230
c0ed36d8dcb677f13ee3fd42dc5705f4ee2dc4f00bd5c36d81eca52cef5ac54328dcc
aee393a2cbd71257331fe633
handshake_secret: 5850af39b46a626a6c031660ce2b8afab0cc328e8d6b003808c
092955b8ee20ff6a72bf3dfd2ad00e58e602e526da36f124773083a772ddd078468d7
f6452735
handshake_encrypt_key: 5fbbba6214c0fb64d9d3aa9743b8acf7aca268cdf48f1a
980e96edb7c378f631b9286f59740a38219224121b5c8bd86b8259f64aaabbcc4ded7
48eadab12dfa7
server_mac_key: 8e73c182079d023abd1061a206862766bbdbf62af8c959de26c15
bc7ddf1ec051b724106924cfe5e138a4db01c26d2885b980e94ebe9689c312dbe593d
a5a337
client_mac_key: 81a94e15b3a31c7817f7d08fa7955d30573782aa4613bbb081eca
8c4e258c390cb1ee1188f81ac541761f7f097d4d17314c614f089ac292d460708666e
01a118
~~~

### Output Values

~~~
registration_request: 02723f7c16f5b16bbc41c64654282414ce3275fb0213b88
6fedc0b79b64c24ce058b560727cbac1be4f4329bea1dee4b49
registration_response: 020da58ed0d1392e457c7fa30b1f1ee405fd2f5296669c
174b4f47f72327b298320ab88c586f0dcd7c8f6bd929a3f6e773022a448ce78e089cd
76160451272b32c68dc162b5e20622cb81e5529930a50100c3cad3db88b97700acb57
4a7535fdc6b4
registration_upload: 02427e85ad90b76452c06bc253d5b06f00dcf142bb6ba531
08ce07c0fb0f50d842930afbbd9593b911e799c49c60cc3a4755b9a0e7f8733cb66bd
2f12096f61e88a609d6a8c9bf6ef3dd83b099fee435eaa801019adcde4b889c5aa630
778e73ace40d8c31dc5b455af67b6b4883f5f70301c3924c09bec273656e2bd94bfb6
2298dd285005933dbe1d55e7a6d4726c60123c9f07720525ab2632332aa3a19174624
5a012e7ae1a13bc6bd00c122aa92d515b2efeb4ea9af26a2e5a6ef6e4f301a577817c
649cd1e52ab3d7088e51c5495df230c0ed36d8dcb677f13ee3fd42dc5705f4ee2dc4f
00bd5c36d81eca52cef5ac54328dccaee393a2cbd71257331fe633
KE1: 032421d61ea387df2e22c3c897a0279ec39e370f7dc6194433ad2ac44bd2e314
49139c165e087059b457cbf600f5a695a5d158ce034e8889a4b80494038aae2954962
53ec4819b3fff08e8bde185a96c39000968656c6c6f20626f6202cb5d5a8e64a5cc2c
0e6ad6cf981f9fb77b9171e92693df21f3ff4cbf53fbdf99726a197dcf7e180381914
ffdf48f3f56
KE2: 02daf4453c09050b1a57e2363db8844940b956cb1d98eb0e3af25db2334c64ef
0a9e0b8c5ec05b4f44fb884f36f986c25423418cbce393a6b317de9fc3a112b4be65d
bf2a3c2642b8ebc27a8ef7bae59af3c8732369f44eb0d7987b655d7b3c44ef904a936
a307863df2d03d87cfe43135c2b7ea580cf489bccfa90132b20ed65cd35c7bedb4ecf
c9dcd2738c18e2ee84b9617fd5b195ab1f27e50d3f1847c248a7a6393845287191da6
e784d7c4e6928db21e67437f7c6ee88628c3aa29c80099c91e017945c8c60051226d2
8e8419c5bd7dffa0dc379a12a14222bba62d59cb5fce5f3fd2829c0fcad3a935005f0
f8152d3d576a9411d28da870ee3bf94dc254f07c1ae6a0370538ce744861221b16c75
f7840e13f227cd5e4f4360087196ff3b3517ed5c5ffd4c1ba1be79bed8a238200fa02
70fa6de7a309107d8783d1fbddcfde02a39352a0c7f7f0b7a3c5306b26df7db6f9676
c8263e38d5a562b613fdd66e2ec000f4ac65e5b082211f9a528c52ce8839de64e5334
37b4d8890acd38251be9c2071c8f844da915cd4dc45723145e6e8c2e3365dbaf11e54
0401cde1ef0edf97bc923d1bb563147d01204a4b8ab4ce9ec5e
KE3: 8cd7d8ca6d5cce383e0fd582392fdfe288e9ba1bcc13a5297ca9b163f007fabc
76520f9b49a1b44e4351abb8952331db2d435adbcd4b17e9b1ff8a6189394a42
export_key: 5d25b55fa72006b1aa9fbc39aaeb3d4173555f74f11cefa86ded91a0a
841f715224cd3151b06ae8193c2206db6b326681872df799b09e9b6a8277dba168e4c
f8
session_key: 9da76b583a1ba6da0874b0b31f7275ae00c75f53c027b5927e4ff644
f3fbef25f6a0cd8b8e372e53ee621263e8e9b074bfe10b31cd48fb9e87bdb76a4a81c
012
~~~

## OPAQUE-3DH Test Vector 5

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
oprf_seed: 561095cfdf1ec4b2846e7fa8e81beb195ce2b1fc093c61797d47f0a3b4
2bf026d830d2d72a391ecf3f75305d739d0fca3f1c00753d53dd3cbba58820d0cccfd
0
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b3d697684a4e36e173064e393b95cfcb5cf792b23520a62c7e57b
24cc23bbf05
masking_nonce: 469453be07c587b430861edc75b908349430cba023b7954ce8e817
5b5226fdbe
client_private_key: 0092d423b59de7b0df382902c13bdc9993d3717bda68fc080
b9802ae4effd5dc972d9f9fb3bbbf106add174393effaf0a175fa8e85f89856861ff3
cfa0420080cc00
client_public_key: 0301f50bb75c663f99a4b66d3b3afbaac889cf4e783ccef62e
cf9fcfdf6e5c60c1efa267865cb8f35e32b04d4b9cda80a08abd6c50293983197ed50
a7297d0fd43dffa
server_private_key: 0043b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0
530b01cb1c23382c7ec9bdd6e75898e4877d8e2bc16359073c015b92d15450f7fb395
bf52c6ea98384d
server_public_key: 020018e69f8ba0d5a13037a646944b773d02fb8ad2e1f27240
8fd451a75968555973e8223597f1d7641d44d9e9009e9717650c6e25e7c249a167c86
59f432d37782532
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: f4f237d71d0b29b958930b6d2b895cba57920f8088f95579f4b5561
90be5b1cf
client_nonce: ed10bbcaedb48d233ef05009c5bbb055d9e9d8410f793245cfc0746
d6053d6fc
server_keyshare: 03006c62b6d7651e886ae8a87aed62b65cd5f2cca5a69156d436
a194a1fb2429e305abb58d085edc5bb46bdb07e4aaf067109ce467b69c557547d9fb4
fb27dcc4dbdf8
client_keyshare: 02010405bb811f3e01c1a2945e9eb295cd1b8c5970bcd55faaf5
d717c46d4c38f85062d6a28e4a9bd0840654560c1fc7dae2d2d0c6a77f7641b5f157c
b437fe680ef31
server_private_keyshare: 01c0d2554a5ebd83679b4c1e67ed82f2891751aa7094
602be672c324929abb1876a7f7165ac7ec79bfd5213ea2e374252f29a6e19915f81b0
c7dcea93ce6580e089f
client_private_keyshare: 01bcb5b33494581b48678aec1d0c3d16afd032da7ba9
61449a56cec6fb918e932b06d5778ac7f67becfb3e3869237f74106241777f230582e
849076f08753056c187
blind_registration: 016329d29abeabede9788d11782429bff296102f6338df84c
9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09589e4283efb9cd1ee4061c
6bf884e60a8774
blind_login: 0086e22f96e44bd5b6ec07cb131d51cf1324c123869859b596174a68
2828f3934d510217ce7890f67cafc0ffaa7a1e1d1ced3c477fea691e696032c8709c8
6cbcda3
oprf_key: 00717ffafdee01c32742491a94f0d847cef4093a85e9d0e0b72d6ef2230
5605dc013c8d1c0363f2dbc735deba3f7059c910f55691ebb003a9ef89183eec792dc
b523
~~~

### Intermediate Values

~~~
auth_key: 6949065131a3428200e721ebf3e0c74dcf0cabb8962f33160d5ab781a6f
7eca82c9744ea6222abaf6068e4dff4ee08e315e5cba73b6976d1cf5b6ad673927e2c
prk: 344245cda3c85fc07eeb037b8a5bdb6a5e964aba2a74127ade269e29849eba11
435f4689b2d9574e1406175724df75b2a66e6819fa83a3dd4bd8e889fcb853a6
pseudorandom_pad: a142bb66a0e6e6955e54322fe3e6febfdfdb64a7efb0dc31b3c
4cf27fe10a5d3388c1140ae13ff590c644733b7f14456b4397d91154afe9bc6c0a4a8
d8fbd2ee255f
envelope: 01b3d697684a4e36e173064e393b95cfcb5cf792b23520a62c7e57b24cc
23bbf05a1d06f45157b0125816c1b2d22dd22264c0815dc35d82039b85ccd89b0ef70
0fafa18edf1da8404966b95070241ebea6154c871f90b266cd40df576778b9d26ee95
f9ba0545a7d701df0ef378ddd93f7b505330b5e18125ba8534cfaa05fed52d80cb4f6
2f9d7cbed9c8b59262e156d7a3d3cf0eb62450a29800542b022dcb5b7f47
handshake_secret: a728341dbc63736cb53a60dbe7ce8e1f18266d9a0f610e58711
9db9c836cb1cfe41a8013a8c509d3027473faec0a03e0d90b8eefe91544e53a58b7a7
1f9a33bb
handshake_encrypt_key: 12363cd1246268600780fc580a12dcb25ab1c4d6611e4d
a8e6cb68cf7634f73e31b683673ec004ff82ad7ab9c711e0a71516c2ac24fce50c681
715bfee089d63
server_mac_key: f9fa495d2844f8dd9dc89ace44073fcc4eb9d87bcdea05cce6b26
0bf948e9d02a36ac9fa2b158a8f7e83fa5f5f4fddc1ddf12a579e8b125252c9356fcd
03d878
client_mac_key: 511ad7e198974f9a8e3b655a84276a26520f36d9ec97018578bb3
ca9254d3246849c8c3efe0a487f3fd64c9e718e05d12aa6110137f6f4cf9610502b4b
2fee1b
~~~

### Output Values

~~~
registration_request: 02002641300bc7c8c9c08a37d1132ba5d1402d0a2c37d12
248d6e88a9362fffdfe734d3d0ff8801e31fa33f25548515545791cccda2ed47a1582
9244e90516384b1f93
registration_response: 02002282cd96372032789df6660f1a584ead0ddcc105c6
df012d92c772e71e82fbee10d3b74ed63c0bf1c43655c7a48ef816e67e8ee2ae3cd6b
5011351c52b2b937c5c020018e69f8ba0d5a13037a646944b773d02fb8ad2e1f27240
8fd451a75968555973e8223597f1d7641d44d9e9009e9717650c6e25e7c249a167c86
59f432d37782532
registration_upload: 0301f50bb75c663f99a4b66d3b3afbaac889cf4e783ccef6
2ecf9fcfdf6e5c60c1efa267865cb8f35e32b04d4b9cda80a08abd6c50293983197ed
50a7297d0fd43dffae1f6b3d57dbe277adfc84f68eb4ae73e856ea8ac5cd36d02116f
e32a05f0c547626539c9e045c771002d04348d757de674562309bf72c23438c32b10d
4a1dea201b3d697684a4e36e173064e393b95cfcb5cf792b23520a62c7e57b24cc23b
bf05a1d06f45157b0125816c1b2d22dd22264c0815dc35d82039b85ccd89b0ef700fa
fa18edf1da8404966b95070241ebea6154c871f90b266cd40df576778b9d26ee95f9b
a0545a7d701df0ef378ddd93f7b505330b5e18125ba8534cfaa05fed52d80cb4f62f9
d7cbed9c8b59262e156d7a3d3cf0eb62450a29800542b022dcb5b7f47
KE1: 0201f033bf7f66029643b03296ee28bfe3022e41457e238c0546da1ebbf08519
502d742e81e3a771046970b78737d748bb6853fcd782c053137cc8b5c84c6926c07b9
1ed10bbcaedb48d233ef05009c5bbb055d9e9d8410f793245cfc0746d6053d6fc0009
68656c6c6f20626f6202010405bb811f3e01c1a2945e9eb295cd1b8c5970bcd55faaf
5d717c46d4c38f85062d6a28e4a9bd0840654560c1fc7dae2d2d0c6a77f7641b5f157
cb437fe680ef31
KE2: 0201031525970fb5f2ccfd64f84b941976308d79406189339a2acb584ea05f75
4131e475f8241c244f4dfbad7ad8aeb80c526efebc5354c6b3c66c04d94af59b6a97e
b469453be07c587b430861edc75b908349430cba023b7954ce8e8175b5226fdbe2f26
da48db7608d8b13dde2d12f19c0f1a593817253252c09d3cad10b113a8cf43db1e5bd
1dd9eb085475f88b77860472e702c5f17abeff232b7c7da18d2094fe417cbf34ba3fd
70c7fe98e4eea8536151a81b8c989ced372b308f5667de667e2c6514002c26fb8b528
423edfe3476637f0ada194796c012199f993dcc6a806e82e523359f43cec72bf9eddf
3cdde738e6546d203321c82b782fa585bdf2acfc9a018f58317a2defa1754396fb12b
f532d643c9fdd2e5c905c6e649af46a776340a6256b77df2e91a69f75873a3f7fef9c
492ae3eb9183875bb254536156a09e54ced254c141f4f237d71d0b29b958930b6d2b8
95cba57920f8088f95579f4b556190be5b1cf03006c62b6d7651e886ae8a87aed62b6
5cd5f2cca5a69156d436a194a1fb2429e305abb58d085edc5bb46bdb07e4aaf067109
ce467b69c557547d9fb4fb27dcc4dbdf8000faca5f82be62f953c85c4304b83838ce7
d3bdc5a73f2f835715866e8d0d62956246247c071e61ad45f291f5b090f2b3979e83b
a394fbc241f32407af48336d0679912f55b857e12a8b49360725490fd
KE3: a33214df14735638ce39528256c7b0b27b8ef1954cc0d92a5d76bd60a4fbc713
72395e9a3d16d4a48e54eb283dd238a4340643c6d3fbd0f50c83861b367b9135
export_key: 3830155b1b9d43d2b6773ddc5fe87a96cdb800abaa4dccb9d6f0c33a2
cbf87c2de2aa0dc39b2d894064781cdcbda8a53c0e4b440621c1399f74682e9178657
e5
session_key: 5a180deb300c8e491fdf11952790fb0ceb80edaf20e6ab96ac53a376
395f6ae114a7d6507cc6172482752949dd23ec34109c3de8dde7c93162ef55eec5582
e31
~~~

## OPAQUE-3DH Test Vector 6

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
client_identity: 36840cc4f3fd4f57bad888ff6e75a120a6ae132b128df738fbc3
16e5bd57356a
server_identity: 3e2651ff8442883bb83ec1b46a76f99a556ab182fd4828da3fe9
65b145a0dc7f
oprf_seed: 4f0643f554428981ab04a60d0aeb3ef224c4eb629295d7b87191424dad
8b30db8b6f893c20bc0120491bbd9eafe5459aac359b19860cb2883877dfc4b763d8b
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 394d31e2ac6eede7814c5c5ebb3ff5a3fdd2d17f2464451f95897
24c28387a87
masking_nonce: cc35992c2aa0697a7726495f3293b4aab425db5f07ee41d1f1f406
2deec73ce5
client_private_key: ed811b4cca7c0e51a886c4343d83c4e5228b87399f1dbf033
ee131fe4ad75c05
client_public_key: 36840cc4f3fd4f57bad888ff6e75a120a6ae132b128df738fb
c316e5bd57356a
server_private_key: 0db27eb7aef2af92c3b297c662a87631531aade91c0558d87
224d922a8573f08
server_public_key: 3e2651ff8442883bb83ec1b46a76f99a556ab182fd4828da3f
e965b145a0dc7f
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 05bfc2f8d9969fabea50e0f69db17f45f4fbe9a4a863d2d5ba79c2c
5d52c2956
client_nonce: 907b40b368a0f40289c520fce12a7118bd0e9b5719b5f2e3f6c45f6
50eb6f037
server_keyshare: 264af8bc6a2c78acb503cd838ae3e5e3715df02d19dd4ddfbca9
e4f46b0a0e2d
client_keyshare: 223228d3df70ac6e0b179a48609517304386692952f49cff086e
0bea06f5363f
server_private_keyshare: 94b049e1b0d73ab5b8d914b08dff3e52e62ea8898d35
b2862d28ff4c2bb1a607
client_private_keyshare: 362f233a8a73971925abc79daa9fcc06f6d3acf12df8
2de919be4937fe716a03
blind_registration: 9b53af4cbdb352b0a2016e5e5f6c0bee4a642526ef9910289
315b71feff26f0f
blind_login: 275e46a6aea42c40b78bd2f1281617519f3f790c8d0f42eacce68456
380b8405
oprf_key: 49e8215d524c701a74e6785f6d1cd436d12458541dc40da2be455ae5bbe
b2a0f
~~~

### Intermediate Values

~~~
auth_key: d8272fb5d468fbde2cada52e4320415c9b89d1fd71cbd0325389466cc91
df619f4f0f3fb7315386d4352d1cf55369da3b8e0cbbb4b9d8cc4207384ddfd6fccde
prk: bca2e8050680879bc325c0c10620872b4295ee27a26db311f85eccf7cd78b70f
62d9588cb501b3da0f23b5a87ee1c52f3270089a57cbff4445c787e0cd21682c
pseudorandom_pad: b59c1c4c0a9c35185e82814bab3e15283ff2f26e6b2cb1d7903
8e1cbf77de9ff
envelope: 02394d31e2ac6eede7814c5c5ebb3ff5a3fdd2d17f2464451f9589724c2
8387a87581d0700c0e03b49f604457f96bdd1cd1d797557f4310ed4aed9d035bdaab5
faa3b4a5f176cba639b77f145117198091787f09db5ed805f31ba97bf4d6e1a0e38f0
ca03fde6f4e2541fed07a1d63acff51a8ac67d801d3dcb10c028504bcd95c
handshake_secret: 9f97eea2ddb1d4a5739048c96ac017203ca7c54b7447f869674
d4ca3c8041b492af7e8daf921a1912dc60b6e079625bb5cabfcc2a43e2166034805df
5063893b
handshake_encrypt_key: 812c2475def756ce61471d0c0a8281313e242379d3824f
7679ac50ab97086f255cb121f5f67c1c89004e41c6c9339a4b573ba07c93d6ef93f85
f4804b7c1e6d6
server_mac_key: 50fca2e486fb38dcf6b36572a2d78af57e56db1eac8fc3df98049
a79137e9e77bd239d35d00e9be9e4304e3633bc4d6deaeb8a3c4351ed0ef17392afd8
cd15e7
client_mac_key: f6bdf3ec53f3a5e4b560fdbaca652ad7ecb6c4b3e85a87db62ba5
30c9e617db36088f6aa33bafa1e6831a0a69ab76a527ece7adf4db9e2c5f73293f95c
04d1dc
~~~

### Output Values

~~~
registration_request: 1e026d981ad38a4c03e5785f151fc42cf932ec153a1134a
3e6f7f3cb9b2c632d
registration_response: 387265325ad8fd2af1827149287df43d4efb0386a39a5b
bb23cc88ae4f25bb363e2651ff8442883bb83ec1b46a76f99a556ab182fd4828da3fe
965b145a0dc7f
registration_upload: 36840cc4f3fd4f57bad888ff6e75a120a6ae132b128df738
fbc316e5bd57356a0a771a24d12f1d021daa45267ad29896e686e4f132bd6ad9aa757
4805c63638a008ff1f58ffdac7614be456d296e802c017756893d345523468ebdcd1a
63e93402394d31e2ac6eede7814c5c5ebb3ff5a3fdd2d17f2464451f9589724c28387
a87581d0700c0e03b49f604457f96bdd1cd1d797557f4310ed4aed9d035bdaab5faa3
b4a5f176cba639b77f145117198091787f09db5ed805f31ba97bf4d6e1a0e38f0ca03
fde6f4e2541fed07a1d63acff51a8ac67d801d3dcb10c028504bcd95c
KE1: be5993d16412c8452d6b320ea8025a8f0b405a0d62dce14bee5dda17c3ef2645
907b40b368a0f40289c520fce12a7118bd0e9b5719b5f2e3f6c45f650eb6f03700096
8656c6c6f20626f62223228d3df70ac6e0b179a48609517304386692952f49cff086e
0bea06f5363f
KE2: 44a2e3f529c3a8faeda9c40dd74a71b6ec665f554edc5816e3acc2b1ee647452
cc35992c2aa0697a7726495f3293b4aab425db5f07ee41d1f1f4062deec73ce532aa7
b4fa723ff09fc11d7972912013042f182607f8d845ed5483ed7fa82f7ef28a8b1a93a
a8f49ce7309a8aef78afefbb50dcc8125a2977569618edb3fac0e50289198efe6b260
e4addf00c3d2e479eeb8c226d0ed994853edcecc8a910739d077e63cb61d1b2b34ea6
60d1cf86f3f5bcb947051a0f8a7db8d82041e86fa5777a2c073e4ef1121edb261bd8e
96c6ba5321871b000f54607f91307cd8613b9c5ca05bfc2f8d9969fabea50e0f69db1
7f45f4fbe9a4a863d2d5ba79c2c5d52c2956264af8bc6a2c78acb503cd838ae3e5e37
15df02d19dd4ddfbca9e4f46b0a0e2d000f394e0361363349ea227f1579ab77816899
c5476fc1f47232323a046125551172b9d78e2f3937e0a12ecd71946e75c3c9005b85d
ec69f07e96d4beeda3ca1d288c6e209a93f88eeb4576750bfd0c2f7
KE3: 425d7c46132d8b57ae9fc5ba04826509180db653d7b2e1afe3d2cc0e1b06181c
339e7653055e821bf4ce0b0dc6b99d52d39a6319e20c938189239d3d490fc8bd
export_key: 4b5d5ab0ca820d15dcec677e98649a4bb333ad3f912c8378cd5d2b7aa
56d26be20dfd90c77ba5d870ef1a0b4fa81aae7d506ecca969b2df4fd7b6a0876145f
4b
session_key: e0a3841d69c7b375ee4bb68c8ca1cb6d32632f4970cab3ba1514b2b1
9d8ee3c7b668ef10b54c199a5f410042d0486070178ed465ee0b8c4f900d1a7943010
a47
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
EnvelopeMode: 02
Group: decaf448
~~~

### Input Values

~~~
client_identity: 602119370fac6fa03edfc658255bdb02ba17b576432bc3f8a411
6fad516e598e0568ffd22838e27cacc5c493b8ebbdcf2fa5ef899dedef69
server_identity: 40ba75d4f2c1cccdad284ca2dfe122f6b7464a44d7b0b15886ab
e89a58712392ae3fc1db9270e4dae08566ea0284f62013aeb00e73be39f5
oprf_seed: 1bfeb02f55c885251fc18b8dd483fae07175aaefd2edc6b8c07a4ba909
157404c07b0be44f07bd76415b8efdf1e93995479549cafee153d0ffbd9ddc3c2b9d7
9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 13d7eb71c23dd82c541d0a07260dbbea66d0786bbfed7fb7f5418
32526d6fc29
masking_nonce: 0fe7cf5dbe6a71131c4ccbea2d401a0b658f9e38d403aee887f06d
4151350748
client_private_key: 26d6b5a8720734ed34a4a70f8e632de4046e64cee0b47cfcd
9173c7ceb0d373234e06b81b5a3b316aec93a8248e8b2c4b3c67a796c4d2e22
client_public_key: 602119370fac6fa03edfc658255bdb02ba17b576432bc3f8a4
116fad516e598e0568ffd22838e27cacc5c493b8ebbdcf2fa5ef899dedef69
server_private_key: 7360399acc5f7083245d8adc40b8f39f14cd8bd4ade8abbb9
5166afdc9e922203abe7a8539854c64b943b0b46e1e1b47cfb52e9ac2197233
server_public_key: 40ba75d4f2c1cccdad284ca2dfe122f6b7464a44d7b0b15886
abe89a58712392ae3fc1db9270e4dae08566ea0284f62013aeb00e73be39f5
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 44cff9a4a39048002c284bb13c1ef253a02da7b0caa010beaffb548
0b1c62cd1
client_nonce: 2e24418b9541da7bf84b51e4ff2629045bf529d31fa0b348c01180d
26f52322c
server_keyshare: b8319c2444e2de175391e0365050b155bd1af372c4a91957e7e6
31c77759beb0f3a00705be4cf979c9f6893a2bf8772af26de8d708270529
client_keyshare: 7222843d9d125e25e8309c3bc3cd2454c9fef724b2a50fd626ac
86a634662478e07fca05c29c15636c09e77cab1050a28b069dc19a605132
server_private_keyshare: 3943ea041bae30e2bde41b548b8fbd8b77ceb62325f2
5986ce21cef85c92e3399433661eeeb9c1150a9cc64cfed4c204c96f309f8447c80d
client_private_keyshare: 97e71df806ebd5322aa0926b2f8f1d3fa1fea402f3c9
0b04601274050a3c6f467387c2f48878823949820d4fb6126967aa0cb69ccc461c0d
blind_registration: e32bcbddc8357d2670bd897c56c86b31b096103b7e2d26d0f
4d66be95299379b41668dbbc5ece26cc212d9f2cbfaf479efa17b7f5a411b3f
blind_login: fcee5bd7db70a99bbabf1ebe98b192e93cedceb9c0164e95b891bd8b
c81721b8ea31835d6f9687a36c94592ab76579f42ce1be69183c1c01
oprf_key: 7d2c51d8690b0c65d27834d5e97ee9f689a64730c50fa8df417c90932e6
4570c99ad25309fd49ea85084cd0256961f45c9f777b657d02933
~~~

### Intermediate Values

~~~
auth_key: 6f95238119d251d302d22393d78bc55d0e8b1816729d7f11b112fbc3352
4b5265157f52e6c6023d401a16b8b5959480992deb549120b749bed7abf023fd2ff4c
prk: bc35412c0f12e7f198a2dffda6a58ff5948eb21d517722dd30f988e8f9ecd3c8
66c66e2e9f66dcc0cb0eae0969a93d92ea49524e2579186891c7a3b8f95b901d
pseudorandom_pad: 8e5ebfde15a025be8e71de4eaf04aeff2c6649ad02877548216
fb495e09ea286cfbf56cde78f33723e76912df92e7daea36a47fa581a4e67
envelope: 0213d7eb71c23dd82c541d0a07260dbbea66d0786bbfed7fb7f54183252
6d6fc29a8880a7667a71153bad579412167831b28082d63e23309b4f87888e90b9395
b4fb5f3d4c522c806490bfabafb1c6cf6a10ac3d833457604544c14b5c82c17a1f3c2
ca013d9490e2c1862cfeddd9dc097337ef3f38f0df4318f605f72d1a034b87ff69bab
db346c57120377e6ced2bb6a7f47fae1db4b3019
handshake_secret: f5b1173fbeb1d5f59499416d0f6d20421b6b70f1069bbc89815
fdd74313a671d7c85f0b0832898c6d312ffd572573c4d56b7ab5759808009d726db30
dae19f85
handshake_encrypt_key: 9e4a23706aaf6427cf06912956b3e7c4f8d97dce147b8d
c18cbca8375e51205b28b8930f43b81a0713b6fccf0e8510482a7e333cd5299b908a5
df137566b66a3
server_mac_key: 61413ff8fd498c3c482eec586421f12a19bd2df8ccc3a01e36fd6
75e3de4fc29b1239da7c95b3b7b42ee67f54ccd0c2d3b2ab4c95d50da6da2a80a40f5
20a908
client_mac_key: c8885b097b7735bff80930bb530d73899d02533dbd32b12b132bd
5ffc6c71bbd685fc1f7f1829ae4e758ee2e077b365c4abff03aaa8a1f40ce821a6dc6
900abc
~~~

### Output Values

~~~
registration_request: da669c85c565d06322a39fb25fa1cdc338592dcb9529ada
a1de7bf79685af7ff00f8a509db940af669bfd87c560a0a0b767de3306a9074c6
registration_response: 5a2261d2ff324023e9b1d24eed5f5909ccff90cd9557af
4096c3a7bcd11fb28541569b695c98cf3f16cc1de4131c4a1b7308dfd14c53def440b
a75d4f2c1cccdad284ca2dfe122f6b7464a44d7b0b15886abe89a58712392ae3fc1db
9270e4dae08566ea0284f62013aeb00e73be39f5
registration_upload: 602119370fac6fa03edfc658255bdb02ba17b576432bc3f8
a4116fad516e598e0568ffd22838e27cacc5c493b8ebbdcf2fa5ef899dedef69ae598
b623ca149ef6a7ffe6aec3a8bd976c33ae0ba4124d6f22c24bb78c78f65befaee5f23
451a4aaa5521c8ca560daf6d16265efe73b78b3062b19acf8a2b9b0213d7eb71c23dd
82c541d0a07260dbbea66d0786bbfed7fb7f541832526d6fc29a8880a7667a71153ba
d579412167831b28082d63e23309b4f87888e90b9395b4fb5f3d4c522c806490bfaba
fb1c6cf6a10ac3d833457604544c14b5c82c17a1f3c2ca013d9490e2c1862cfeddd9d
c097337ef3f38f0df4318f605f72d1a034b87ff69babdb346c57120377e6ced2bb6a7
f47fae1db4b3019
KE1: 5282003828617159ebb98867d14c998d90d0b23c97c118946bf4979ffe95709a
125d21228839063085f7d6185b3827cba16d1c9cd9c7d5422e24418b9541da7bf84b5
1e4ff2629045bf529d31fa0b348c01180d26f52322c000968656c6c6f20626f627222
843d9d125e25e8309c3bc3cd2454c9fef724b2a50fd626ac86a634662478e07fca05c
29c15636c09e77cab1050a28b069dc19a605132
KE2: 967675b88807bcb47d6b680dbc231c0d202b6d2422626971c663c540f728b844
ddc0c54c3244c27919e59205629edc49eef9fb97051f87260fe7cf5dbe6a71131c4cc
bea2d401a0b658f9e38d403aee887f06d4151350748a2af06fbdab830b1816c92e9f5
ff8c7fd19b889a484465703983b0931de970828506aa9c453dba999c6296534cc0a59
c58f2637b3c2f62f305dda26f2820d54de3e6a26f2de4b8d412c0dd708eca700dd78e
581cc678e4011939971ffd3f8a058b76d501b254b9d32379fb9ab5b0c4a5ad7b81822
06aafc59a425ad9ef93d47edd538b065a2d087cfd541160e5f4af41d3a6b17268c69f
fed672c139c7ce6adc73f4ca0611fe2132b4802a5449ec37fd466da4ae56b00e7c0bd
50c11e84aec2ce9d0991a80f1e3a3fb7388514600ebfa3544cff9a4a39048002c284b
b13c1ef253a02da7b0caa010beaffb5480b1c62cd1b8319c2444e2de175391e036505
0b155bd1af372c4a91957e7e631c77759beb0f3a00705be4cf979c9f6893a2bf8772a
f26de8d708270529000ff0c116c8ae29b35a71db9eebfbf7daa66362e67e569734e76
220a0424eb3a89a23578d09c6a328f25047a33e7ea2b9ae1c8f29107579a13d35af0b
24f0ae44a158738f3cead5d49b874b448cf200ff
KE3: d645fb7af4b074f4507cf0525cac12cfadaa93f72d10b009c21856c020c2fa16
b6ab7c7f058fad7eb4ae7f2e9215178dda50ec576f689fa380ca119e48277a42
export_key: 29bbb780a1b29ae418bd6fea9bddbd1e79bfe1d6a120e8b01da9a35c0
69d34f2f47fb5e5de8c66ddb7b6c36fdfaf26d5ae72de424a7e0c67aff17ce7e3fd07
d6
session_key: 8be0ed88ee1154767ea8a267636131d6806df34522b59f45174152b9
3d45ba4009334db1fd18c95a09c94ea71ac26f88bbf95894be58afc1b46b584bf285b
155
~~~

## OPAQUE-3DH Test Vector 8

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
client_identity: 039ab932e2206f4886746f01df9e227f105059ac92ecc52132b6
dc0fd55330255d
server_identity: 03d94f7f32c91db52e761cc0916b9991a165e64ae1a827bf60c5
eae172c96635af
oprf_seed: a62d84f3c2f0f717a88d75adfff4df6b4c48d1184ccff7fbcc7b33faf9
4296b5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: ddd59c7dcadc277ce75708a7eb5c23aef7cfd533a266a9efa6ece
341ae5afaf6
masking_nonce: d20479563b3b0f4e983bcbaa914e27fbfe5fc0c166aadab11f4720
cb540faaa5
client_private_key: a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90
dc0d4094ba42833
client_public_key: 039ab932e2206f4886746f01df9e227f105059ac92ecc52132
b6dc0fd55330255d
server_private_key: 591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688f
70cf205f782fa12
server_public_key: 03d94f7f32c91db52e761cc0916b9991a165e64ae1a827bf60
c5eae172c96635af
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: a79c96e1c0275489c3c7a6d8e90e73e3b900dc93c6a9bed5db3b085
b07660b28
client_nonce: 111e0cbe17863607ffcaec07bfe119181dd8112355fd064f4c8b448
d7d4b0502
server_keyshare: 03e402e5964bbfe8f41ec29dfebb8e5cbbb9394c8a2735380a94
845984c4541a5d
client_keyshare: 03f013aa47f2051a91546821073e90a43299ba5ac5e5afaa6951
e8f8000fdbdc73
server_private_keyshare: 84580de0f95f8e06aa6f6663d48b1a4b998a539380ed
73cafefa2709f67bd38c
client_private_keyshare: e70f0ffdc309b401029d3c6016057a8e55f951785ae2
2374dfc19eb96faba639
blind_registration: 4dd65065273c5bd886c7f87ff8c5f39f90320718eff747e24
82562df55c99bfa
blind_login: 2ec845097904db87240b9dd47b1e487ec625f11a7ba2cc3de74c5078
a81806f8
oprf_key: 8ea8b598907902d4e113c27204e6de207348c6fc84de80e75e02e6ee4f1
d06b2
~~~

### Intermediate Values

~~~
auth_key: d6b4b7e3bdd796f37c577b6b892ee99395c409c4916b513c38617e6b88f
a7256
prk: d45cfea579b066c76afe71268166f6051aaf92f5de230453f18a9f543dc42520
pseudorandom_pad: dcfd4ba910a5c9ad91c49ed3931f13e0b3c3c4625b1818e6c0d
68e40412636f3
envelope: 02ddd59c7dcadc277ce75708a7eb5c23aef7cfd533a266a9efa6ece341a
e5afaf67c2b50864a2fe3bcd2f21df460186f8812979af8f4a3be4fcd165a490a821e
c06ff8a005482ccaf13db939729495aa63349ef47ede2f0f9f71d69eb15e28227d
handshake_secret: 52861b06f7a9c271f6a405d83fa756ae1e01d5942491f55b9c0
4f547a80ea6ae
handshake_encrypt_key: 9462d460bb0e68453163bb0394172ced06b997180b6e0b
6974d585a1671e7ac9
server_mac_key: c537b2c7b15640214f3a087c784086ba4ce795ab3f80b999323ba
7eeda41409a
client_mac_key: 45766874af210259dce41882b3587b885ead22d004e300561df85
349be94288d
~~~

### Output Values

~~~
registration_request: 02664e16c09184ba4d0805c8322aa3d6af6f1935bbfa2a3
59188f3899ab5c51688
registration_response: 026663d12152c3012f3fd7c5136ae8326b1cb628cdb342
2701ca4f1f32a6fc9ec903d94f7f32c91db52e761cc0916b9991a165e64ae1a827bf6
0c5eae172c96635af
registration_upload: 039ab932e2206f4886746f01df9e227f105059ac92ecc521
32b6dc0fd55330255db6aa66ec3d67d970044e80984851f22d3451ef2b45e7f82f33e
1052b385af67a02ddd59c7dcadc277ce75708a7eb5c23aef7cfd533a266a9efa6ece3
41ae5afaf67c2b50864a2fe3bcd2f21df460186f8812979af8f4a3be4fcd165a490a8
21ec06ff8a005482ccaf13db939729495aa63349ef47ede2f0f9f71d69eb15e28227d
KE1: 02623c04d58d889045a7bba21f6d8388b4326cabce05553c59f33ab60d51ce4a
5b111e0cbe17863607ffcaec07bfe119181dd8112355fd064f4c8b448d7d4b0502000
968656c6c6f20626f6203f013aa47f2051a91546821073e90a43299ba5ac5e5afaa69
51e8f8000fdbdc73
KE2: 033af8c2402ae43332873da0941fe90623981951a07e88b59617da78beb69996
60d20479563b3b0f4e983bcbaa914e27fbfe5fc0c166aadab11f4720cb540faaa599a
b5582b10b50bb529eaf02ed7b7e4b3e444def1062052945efe9d4eae956f489aa3325
4a17c9ff8ee4998fa598ff86ce6856b160c6067cc67362c2fe2918cc5da854ea53c01
9188c6da009e5a1c29ed61e4be9f3fc9849a0df46d03f4e56384d7dc8963ad98b6cf0
2ee69ff9874c4c3ead2d43334eeaff3ebea274746704ce0be2a79c96e1c0275489c3c
7a6d8e90e73e3b900dc93c6a9bed5db3b085b07660b2803e402e5964bbfe8f41ec29d
febb8e5cbbb9394c8a2735380a94845984c4541a5d000f9a25ae4a879202fb35a6740
828845476a59f9517ea11218ddc8d10a233abe7b3495d48f030550c4db73710ce0fac
7f
KE3: b8f31a822c3945df879cc59b682e6fb37567458b85c6cf1f76fc7a3256e31be5
export_key: 46875c2e5f190d065c285183fc12d26ca326859b2978cf671d6f266d5
030d414
session_key: 0ab74e416516e66dda731e42ddd9b7a341c54d84e94e75026569801c
be0faa36
~~~

## OPAQUE-3DH Test Vector 9

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
client_identity: 039c1bdb75db3a00c66c76eb9b8fae563549d4b9c3172af2e826
84e2c0f9b66e362209e31be8e5c1c4c4757c96b9c94521
server_identity: 02d2a6cf099320587c4d6d53ee59aa3d55b5e9c3aa993827cc42
1c84aca41b1f1726c911ca8a44b07ce213fbbbccd226bd
oprf_seed: a90b155a43d9d5c622140ea8109ba098cfa994e0f50537a572a0a959d2
d871888f96fbecf91b6e81652a714c7b70438b8df278822dbf6d89641fcf95ec94d03
7
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 85b04a4f9f50f81332483b6b43937916ddc19ae6adfd09d583bd8
16a5b7f12bf
masking_nonce: f77a171fc279ef3362da567866ee415db91c1930cc80841e91f1de
1d5ec62409
client_private_key: e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e9
f89eba281046e2839dd2c7a98309b06dfe89ac0cdd6b747
client_public_key: 039c1bdb75db3a00c66c76eb9b8fae563549d4b9c3172af2e8
2684e2c0f9b66e362209e31be8e5c1c4c4757c96b9c94521
server_private_key: 8fade716a6a82d600444b26de335ba38cf092d80c7cf2cb55
388d899515238094c800bdd9c65f71780ba85f5ae9b4704
server_public_key: 02d2a6cf099320587c4d6d53ee59aa3d55b5e9c3aa993827cc
421c84aca41b1f1726c911ca8a44b07ce213fbbbccd226bd
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: bc25e6e1e3a4fa45a65be38d1393cf95b08cf7bebd7de9071b1660f
44c15d1e5
client_nonce: 27b7c3dfc126a071541d6f23c0b6b6fb16cbe26c80d40519d80e308
b7fea62ae
server_keyshare: 02516adc8085bc6757ce590bd107321a28afea27f30847c9a36a
da6353b533317d8f412c3e1872ebf0f35ebc2319781bde
client_keyshare: 02ab0b96d89059d22483e7f4dd7ef3399fa95ee6abc178a6e95b
a7109a414aa27c3b17a96c246af578cb0561be124102f7
server_private_keyshare: 563b3420d7764097502850c445ccd86e2d20d7e4ec77
617a4238835743037876080d2e3e27bc3ce7b5fb6a1107ffedeb
client_private_keyshare: edb371767432b68bbea293aa8a69353b023f4a0e6a39
eef47b0d4ca4c64825ba085de242042b84d9ebe3b2e9de076790
blind_registration: 7759061965a423d9d3d6e1e1006dc8984ad28a4c93ecfc36f
c2171046b3c4284855cfa2434ed98db9e68a597db2c1473
blind_login: f96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd1fa76e953a63
0772f68b53baade9962d164565d8c0e3a1ba1a34
oprf_key: 42cad1fbd39d362815ba71701928f43c4108727d33ad37bc20ad5d1be6c
33e192dd932bd7e650d83f7022de2c25072cb
~~~

### Intermediate Values

~~~
auth_key: d664be321da4d4d3c884ae5611ef232f3ae3dc475ffc3556452dfe5506d
32e7f0b6a629af11894b698860c20ccfd9a921389540cdf6a908473a2cd54232ed46d
prk: 2329ca3870f248bf63cf75e08fc83f680340a49cd5e81152b946840579379b8c
db923e1274df2ac86291b18ac2855e8885cda956cc4b9c58fc5a4ddd43e14ea8
pseudorandom_pad: 4fd852854721b92e69a13da7ae6f15cf75682986355ace76c2d
c872eeda707e20556425130e7541e510111bee089583e
envelope: 0285b04a4f9f50f81332483b6b43937916ddc19ae6adfd09d583bd816a5
b7f12bfaea60719e4ed68ba263b4df4c2784adedd4f6ca047ecc3385d556c8c6ca369
ca3c8b6e2ba8d7cf188ee98b7e2d5fef79158187151e96b126eb58e3b77a2fd1184b9
086d18be2c3073c27833f8191c14f8c0f769127a1785771bafb7d76b5db14e1a3d56a
657beae6b2abe67e262039d1
handshake_secret: 03971e2c03fd23794c0fc3f89db077d4f0cf7abb6bea1a66b66
d0ce8bba6fda93aa948343f90fd9c33c640ea10fd0f5f041a690127df8c6fd0014499
12f57e84
handshake_encrypt_key: c34a8c792598396a0ce87be20a02d7916f51c22865575f
b2840e6a50dd4fbdf119348653f592cf09ec4762ff6928d44c82e05606af36a47e88e
9af74a6da6434
server_mac_key: 2d630a9eac8eee0724885c5c9d0b0d846bc7a4685917c1ad3dc1e
6c186e1d14f5b38247f6377dcd8116ba38efba428b7c86e8d43af4ccbc8a20c4722ad
fe6c02
client_mac_key: 0f2ef565dba86f8d09de9c0295af1d73db9ed29c0a3d0a0910a90
9b936e3a0d4798172f49e22a0c828ec61f029ae6d068ff5f9229b23fd5a4fdb824081
fda2f0
~~~

### Output Values

~~~
registration_request: 03f5460f79c0283e3e64899379055f1e517133244e814b1
b07ea71e64f032e70e9c689637e70b405019979f11239e72924
registration_response: 02f4d8837460d2c812106f5b8b61111d7f13415a62eef9
57489bd457720b080d37f84657bf7cf9441e1c4c4f0772f5a7fa02d2a6cf099320587
c4d6d53ee59aa3d55b5e9c3aa993827cc421c84aca41b1f1726c911ca8a44b07ce213
fbbbccd226bd
registration_upload: 039c1bdb75db3a00c66c76eb9b8fae563549d4b9c3172af2
e82684e2c0f9b66e362209e31be8e5c1c4c4757c96b9c9452128fb133a93de65b039f
41a680e6142c777f8695741f79ba0c46aa28dab04277ae9f964e237e3ec1ad11162f2
b30783c12633fc9faa137f5ef81f5988f84c34860285b04a4f9f50f81332483b6b439
37916ddc19ae6adfd09d583bd816a5b7f12bfaea60719e4ed68ba263b4df4c2784ade
dd4f6ca047ecc3385d556c8c6ca369ca3c8b6e2ba8d7cf188ee98b7e2d5fef7915818
7151e96b126eb58e3b77a2fd1184b9086d18be2c3073c27833f8191c14f8c0f769127
a1785771bafb7d76b5db14e1a3d56a657beae6b2abe67e262039d1
KE1: 022cc3645e83dd295870ff44d1bd79c50cb167fcdb3f175ba6d6bdd5a3f22734
691b39eaaaeaa81daf426f1d1f7777d4c927b7c3dfc126a071541d6f23c0b6b6fb16c
be26c80d40519d80e308b7fea62ae000968656c6c6f20626f6202ab0b96d89059d224
83e7f4dd7ef3399fa95ee6abc178a6e95ba7109a414aa27c3b17a96c246af578cb056
1be124102f7
KE2: 026d5b061aa967bc1b6654c0d0e824c05364c608e873d9eebe1a88215d726c20
628a8509ed438d3c27b9de6094c28cf451f77a171fc279ef3362da567866ee415db91
c1930cc80841e91f1de1d5ec624090b601f12f26f82014dd590c099af317701cf105d
3abc93eb1c5f8591767503cd4a0ddd856bf88d0c3aded090613443b55f0a1353217b4
d3784b260c6ee5c636369e15466cc968fb844301d493ad32870c922758298d2dab47b
44d265a953df87b23b187b9fb15babd5afb6ee62d47492407112d211f48bad99186ea
f85e0eceac59b144ba8eb11c07d0378204210eee4885d489879b0e4191a1666f88afc
2e7aaf619226089c694664f69d411b3fe08ffc0f35e4cb0ed191625c66b2b72f8a40b
623bc25e6e1e3a4fa45a65be38d1393cf95b08cf7bebd7de9071b1660f44c15d1e502
516adc8085bc6757ce590bd107321a28afea27f30847c9a36ada6353b533317d8f412
c3e1872ebf0f35ebc2319781bde000f0acadcd6db5ed413ce6fc62600200b71b93f52
e7a99401c202ae4e36eba41dc5e7375590d2310da35e035fc3010df0f67485b550338
1bbbf7fff335e7c27cff718e26ea50fcfa46c007d35c3a27d25
KE3: 390e8466cef23d8af6eb3a6674663f5e8394756728b3bff4749dc7eea54ec14c
acec268da6995e6262dc1ca5da6f1633a9d83b5a6352f52d938410170cb6e351
export_key: a39310f940597cb9f592d9dc790cd428d0d23668d6b5b4f22ad84cac3
10f7a7f0d8b4ab20cc524aa6f79e4558fc26e1540e678a5e04a6d9f8204c5c7db9ed0
db
session_key: 4385db5c4478aa530c61b7de959f33b28ce1501a82efa5c233e7d804
4dfb65e4857be5ed087d5869ec8d467f294e8ec0411a6ea899eb20ece1c114b7b356e
2ac
~~~

## OPAQUE-3DH Test Vector 10

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
client_identity: 03015c1bdb9b9d298616e13914637cca31db6b993dccebe3e7c1
4fbfb7b71ff96775712deda5a5a7d4ac8a9baa705851fb528ba7add85272edab69dcc
e4c7f64354938
server_identity: 03012abcc6c769ebd1b458d8c244a75a876c7a8e30475c78568f
2fcd6df699a659537983eafbd14d33c55a5ebc6b7baa1eccdff2b5b859cc889086cdf
78bd67e1f2c72
oprf_seed: 164c9fc9476fe80bff99c667d1e69555482585fcebf6f5d89a2e61f20c
05de43ff584993d9854e0b75db98bc138d7af5142556ac77ac76de2dada9bdec73133
d
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 3c02f5dfa66613716856168b31d68447179c73c3b6066b28e5553
05c8ed8d316
masking_nonce: 680245b3e2a052188ca557afddc5e96e6e7b2cbd6c572d2fe91f9c
ab663cfc6a
client_private_key: 01b9acb5ab74318e54223c759e9747f59c0d4ecbc08730266
7fabefa647b1766accb7c82a46aa3fc6caecbb9e935f0bfb00ea27eb2359bb3b4ef3d
5c65b55a1b8961
client_public_key: 03015c1bdb9b9d298616e13914637cca31db6b993dccebe3e7
c14fbfb7b71ff96775712deda5a5a7d4ac8a9baa705851fb528ba7add85272edab69d
cce4c7f64354938
server_private_key: 00bba54f137dbe5f5eb4a34dcb73609c6693f28cd3d57ed77
bf66e0ab7d86c6990f0fcd9a655f77ff0b2ebcfe21e1a1ca4a84361e9f1b18e24c9a4
0ed5eec262bf52
server_public_key: 03012abcc6c769ebd1b458d8c244a75a876c7a8e30475c7856
8f2fcd6df699a659537983eafbd14d33c55a5ebc6b7baa1eccdff2b5b859cc889086c
df78bd67e1f2c72
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 52b45ac1a9c9f3983543ae3c793fe4e6a8e3ced17d7ae211a0fe9fa
e92c01c14
client_nonce: 24a48577a7765d175df3d0f09ea02203e18b9b168a9fb6481972e60
e9016d591
server_keyshare: 0300d95d91bfac6946b7c7c54eb60c2b3de628f788c948fe85db
242d259fbf91414eae123029582dd9fc124877ae95810637ff304a33d8f0488e39055
d84ad98c1758c
client_keyshare: 03003d03c8b3d89868d991888d11e39942e7655bdd427ac69d35
755abf2b7cf26ab41bb53d379fbc1359bd423e89b36d0bc7cea52bf5fbc57b3bbf816
82a4d69da7ad3
server_private_keyshare: 00d4c044df390ab5683964fc7aabf9e066cf04a050c4
fd762bff10c1b9bd5d37afc6f3644f8545b9a09a6d7a3073b3c9b3d78588213957ea3
a5dfd0f1fe3cda63e00
client_private_keyshare: 0062747ec1d27852fce42d79fc710159f349e7da1845
5479e27473269d2926fec54d4567adabd7951ad51ea3741feab175ac5cf7fa02f3ad7
44eb5baf418275e45ac
blind_registration: 00c19801a9d83b5d1c0fc0812c10e18f146b14d7eb94755a9
18bac1ef8d69d21a7c13f95c9b1334d8af16ae1e69f5adc24e5aa89ebb63637c835fd
39b17a1a4453ec
blind_login: 006369dbae98fb0879524fb9234e93a8bd048ad9f44b428026396a81
0328c405a354e666f086fa0ea4754fb56527be010296ea880e1c6a4dbbc9ede543a2a
d0f83fe
oprf_key: 0143835b041d1462cbbbaa65515fe3d6d782f6b95a4dcc310d47d010040
5c885d23db7a461efb0f3faf74d66dfcb6441c701afe8d3a83c0f713c90829945959e
ed96
~~~

### Intermediate Values

~~~
auth_key: f7e63739c82bfe0e548c47284cb5651476bc272433c269e92ddc1283ed9
bfe7bd6e05c3744f5ba3f8b35fecd618a78772594598d2eff8f1d633cc35e32f33d9e
prk: 87a1fc1ad017fb23644fbdb24dd58b440f4edd9d59a0831f4928e2d347d0fd87
5caf66a9164ea871a7016ed9e04bd2e96a4de600c7fb6d7b31c3edb7563de9c3
pseudorandom_pad: 411ca7ef5f3096ad084438603a1eed80e49b4bd2c9c406072f5
8722bee0fd750a4348bb35c161009cf2a496d65b56e7e15e56cbb7e71a21f402275c6
b89aa11a6ed6
envelope: 023c02f5dfa66613716856168b31d68447179c73c3b6066b28e555305c8
ed8d31640a50b5af444a7235c660415a489aa75789605190943362148a2ccd18a74c0
3608fff731f87cb3f5a38482d48c809ec1a5ebcec5cc4439acf4cd489add2ffb01e7b
710bbab1e0faf55afa16e3ba2c8bf9a09dd4754d21c7557967394d41b3c33bfabeda6
95d6cbda37c2cdaebc8bc6dc1b07b43f31b6ab562516c7dc290aa57f0353
handshake_secret: 4ea2150a48f480a47b52eab7e79975a4cb2b49c6078770622eb
3d616a36a9e4c63ead5705de938509dfedc01306179403380179b82c7f5e1b313fc54
f9985926
handshake_encrypt_key: 4bac56fa952db36c862a0fa4e87329201e5ce401592f60
8b0e2020affe3c93b3065515aece9aba3ad1cb608e36647d2b99d94ab5e4014b213a8
6dc55da8f14ed
server_mac_key: 61328de5ab6c2afd84fd8db99cb6cbe9c2fda037ef7e8b3d4c571
7e8668c2edc79fb9befb73d28edbeaa96f0d1a0e0b3d644210fca0d47d3497f31722e
a0e109
client_mac_key: 6714b889b558c7e6c9c34aa941dc9466e6cb9cd151a8eb2c08f35
046c3d92a59fefa6d852e40ee17653cfa2f4e10676cb5d5d4538d56ab08244dc316fb
528a40
~~~

### Output Values

~~~
registration_request: 030156c6fc994d9eeb6a0dad3c76d0a617f1b0bfba250f5
2a5f3cd5185dacacbc2a6e86252578b4a4f1b05a6e92a269733fed34e4dc61baceb0f
6a4e6f6427f80992b9
registration_response: 030199eff83e88eb40d9ffa6567dfd89dfc3d17b83f34f
48d40fa36daff25238f1914b730516b9528d0d0894d1f2bef5ec92da8889cfd28b371
86c4f274b09e3db752703012abcc6c769ebd1b458d8c244a75a876c7a8e30475c7856
8f2fcd6df699a659537983eafbd14d33c55a5ebc6b7baa1eccdff2b5b859cc889086c
df78bd67e1f2c72
registration_upload: 03015c1bdb9b9d298616e13914637cca31db6b993dccebe3
e7c14fbfb7b71ff96775712deda5a5a7d4ac8a9baa705851fb528ba7add85272edab6
9dcce4c7f6435493828891a5df189c2526182a061ab0173e18e0503b22595f76fe580
17f53e4509bcd14f0cb863b7333b11f6f8c429daa4f1b9e42ac97f831c358cb1a56cf
d714d6a023c02f5dfa66613716856168b31d68447179c73c3b6066b28e555305c8ed8
d31640a50b5af444a7235c660415a489aa75789605190943362148a2ccd18a74c0360
8fff731f87cb3f5a38482d48c809ec1a5ebcec5cc4439acf4cd489add2ffb01e7b710
bbab1e0faf55afa16e3ba2c8bf9a09dd4754d21c7557967394d41b3c33bfabeda695d
6cbda37c2cdaebc8bc6dc1b07b43f31b6ab562516c7dc290aa57f0353
KE1: 0300f19cbda2e013fe4184e7c3e12bea61df22dc5b7d725e715bf7e3bcd058ad
e2f6de5252e655873c8e33effc9bbf77b5a0060b556fcd0600fe0961ce69e088638e7
724a48577a7765d175df3d0f09ea02203e18b9b168a9fb6481972e60e9016d5910009
68656c6c6f20626f6203003d03c8b3d89868d991888d11e39942e7655bdd427ac69d3
5755abf2b7cf26ab41bb53d379fbc1359bd423e89b36d0bc7cea52bf5fbc57b3bbf81
682a4d69da7ad3
KE2: 02013950b6a8324f560b58591a11aa8f9781452aaeaf53923c3fb9ffc2829c0d
16bbb1d30ff62b8c86f2f377a4ec37c1184aaafe50698e32f06dcd0675c3990472cb0
b680245b3e2a052188ca557afddc5e96e6e7b2cbd6c572d2fe91f9cab663cfc6ae901
048f6d183a389fc44798abb4b1d2ec8c86644ea0332284fce639f7440920304480c58
5746dd250533f68deecc3f7eb57bcc395327a8268c366aa8c731800b4a50058fd329c
77df0b13d7d2846d1c991466d91ab4ccedd18c481957a00cfe66eb036861ad3e6cbe0
ecd4acf872d5c14b1d50b582ab2cb8200166317807c68c4ac4754cf883e4481f04c05
0f9a31311b0f2ec44f0d1506bd6d2e0bd872c2e5b8260a54f864c78a9746b044a181a
f278dbb8413f8fe40a302945c127b01849e3cebb90a35f70822473aa3b06c6f13f0bf
50f5ece19ecc9e8ffc957a7925719959c50e2f31b352b45ac1a9c9f3983543ae3c793
fe4e6a8e3ced17d7ae211a0fe9fae92c01c140300d95d91bfac6946b7c7c54eb60c2b
3de628f788c948fe85db242d259fbf91414eae123029582dd9fc124877ae95810637f
f304a33d8f0488e39055d84ad98c1758c000f85b6c492c57143f2847f5fd3334de2df
11a1ef16e86aabce1af1477084b692506d639adcd661e9996c168ea346af40eb53b55
d1ade1e9be643ec02a407363aa1659675eaf1d23ef1f2f45c8472601a
KE3: c312f1c86f8f91990791b5e45ada29fa05da45dea3ac0482b68bcb755676026e
67ac6b51b638c390881dd98a69724876c9f6dfdb1662d26cd7337bb13eb640d0
export_key: ee73898e4f669a2ef3cfecd0b5f346f95b1c075bdec0f693c4ec96204
d8791125c90bc2e0b51940d7e97e44da73d0f4b78baeb4abea3fb2529a69fb8b11379
65
session_key: e102fe2be64eaa94c3bebea3b1c9aa9bd074017e000b6035178c8a6c
77aff936d8c0ddf9300f76aa50a480413ab7af36a64899b3a92cc149655f31bddf359
42e
~~~

