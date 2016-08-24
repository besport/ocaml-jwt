OCaml JWT
=========

JSON Web Token (JWT) is a compact claims representation format intended for space constrained environments such as HTTP
Authorization headers and URI query parameters. JWTs encode claims to be transmitted as a JSON [RFC7159] object that is used as the
payload of a JSON Web Signature (JWS) [JWS] structure or as the plaintext of a JSON Web Encryption (JWE) [JWE] structure, enabling
the claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted.  JWTs are always
represented using the JWS Compact Serialization or the JWE Compact Serialization.

The suggested pronunciation of JWT is the same as the English word "jot".

[RFC7519](https://tools.ietf.org/html/rfc7519)

## Documentation

A JWT object is represented by a type `Jwt.t` containing the header (of type
`Jwt.header`) and the payload (of type `Jwt.payload`).

#### Header

You can choose the algorithm you want to sign the token. An header contains the
attribute *typ* and *alg*. The attribute *alg* is represented by a sum type
`Jwt.algorithm`.
For the moment, only HS256 is supported. You need to give the secret key when
create an algorithm value.

You can create a header with `Jwt.header_of_algorithm_and_type`.

For example:
```OCaml
Jwt.header_of_algorithm_and_typ (Jwt.HS256 "SecretKeyNotReallySecret") "JWT"
```

#### Payload

Possible claims are represented by a type `Jwt.claim`. You can create a new
claim with `Jwt.claim "claim name"` and get the claim name with
`Jwt.claim_to_str claim`. Here a list of predefined claims:

* iss
* sub
* aud
* exp
* nbf
* iat
* jti
* typ
* ctyp
* alg
* auth_time
* nonce
* acr
* amr
* azp

An empty payload can be created with `Jwt.empty_payload` and you can add claim
with `Jwt.add_claim claim "claim value" payload`

For example:
```OCaml
let payload =
  let open Jwt in
  empty_payload
  |> add_claim iss "https://github.com"
  |> add_claim sub "github"
```

#### Get the token representation.

You can get the token representation of a type t with `Jwt.token_of_t`.

#### Decode a token.

As JWT data are encoded with B64, we can retrieve the information like the
header and payload from the token.

You can use `Jwt.t_of_token` to get a type t with the header and payload encoded
in the token.
