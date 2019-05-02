(* ocaml-jwt
 * https://github.com/besport/ocaml-jwt
 *
 * Copyright (C) Be Sport
 * Author Danny Willems
 *
 * This program is released under the LGPL version 2.1 or later (see the text
 * below) with the additional exemption that compiling, linking, and/or using
 * OpenSSL is allowed.
 *
 * As a special exception to the GNU Library General Public License, you
 * may also link, statically or dynamically, a "work that uses the Library"
 * with a publicly distributed version of the Library to produce an
 * executable file containing portions of the Library, and distribute
 * that executable file under terms of your choice, without any of the
 * additional requirements listed in clause 6 of the GNU Library General
 * Public License.  By "a publicly distributed version of the Library",
 * we mean either the unmodified Library, or a
 * modified version of the Library that is distributed under the
 * conditions defined in clause 3 of the GNU Library General Public
 * License.  This exception does not however invalidate any other reasons
 * why the executable file might be covered by the GNU Library General
 * Public License.
*)

exception Bad_token

exception Bad_payload

(* ------------------------------- *)
(* ---------- Algorithm ---------- *)

(* IMPROVEME: add other algorithm *)
type algorithm =
  | RS256 of Nocrypto.Rsa.priv option
  | HS256 of string (* the argument is the secret key *)
  | HS512 of string (* the argument is the secret key *)
  | Unknown

val string_of_algorithm :
  algorithm ->
  string

val algorithm_of_string :
  string    ->
  algorithm

(* ---------- Algorithm ---------- *)
(* ------------------------------- *)

(* ----------------------------- *)
(* ----------- Header ---------- *)

type header

val make_header :
  alg:algorithm ->
  ?typ:string ->
  ?kid:string ->
  unit ->
  header

val header_of_algorithm_and_typ :
  algorithm ->
  string option ->
  header

(* ------- *)
(* getters *)

(* IMPROVEME: for the moment, only HS256 and HS512 are supported. *)
val algorithm_of_header : header -> algorithm

val typ_of_header : header -> string option

val kid_of_header : header -> string option

(* getters *)
(* ------- *)

val string_of_header : header -> string

val json_of_header : header -> Yojson.Basic.t

val header_of_string : string -> header

val header_of_json : Yojson.Basic.t -> header

(* ----------- Header ---------- *)
(* ----------------------------- *)

(* ---------------------------- *)
(* ----------- Claim ---------- *)

type claim

val claim : string -> claim

val string_of_claim : claim -> string

(* ------------- *)
(* Common claims *)

(* Issuer: identifies principal that issued the JWT *)
val iss            : claim

(* Subject: identifies the subject of the JWT *)
val sub            : claim

(* Audience: The "aud" (audience) claim identifies the recipients that the JWT
 * is intended for. Each principal intended to process the JWT MUST identify
 * itself with a value in the audience claim. If the principal processing the
 * claim does not identify itself with a value in the aud claim when this claim
 * is present, then the JWT MUST be rejected. *)
val aud            : claim

(* Expiration time: The "exp" (expiration time) claim identifies the expiration
 * time on or after which the JWT MUST NOT be accepted for processing. *)
val exp            : claim

(* Not before: Similarly, the not-before time claim identifies the time on which
 * the JWT will start to be accepted for processing. *)
val nbf            : claim

(* Issued at: The "iat" (issued at) claim identifies the time at which the JWT
 * was issued.
 *)
val iat            : claim

(* JWT ID: case sensitive unique identifier of the token even among different
 * issuers.
 *)
val jti            : claim

(* Token type *)
val typ            : claim

(* Content type: This claim should always be JWT *)
val ctyp           : claim

(* Message authentication code algorithm (alg) - The issuer can freely set an
 * algorithm to verify the signature on the token. However, some asymmetrical
 * algorithms pose security concerns.
 *)
val alg            : claim

(* Common claims *)
(* ------------- *)

(* ------------------------- *)
(* Defined in OpenID Connect *)

(* Time when the End-User authentication occurred. Its value is a JSON number
 * representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC
 * until the date/time.
 *)
val auth_time      : claim

(* String value used to associate a Client session with an ID Token, and to
 * mitigate replay attacks. The value is passed through unmodified from the
 * Authentication Request to the ID Token. If present in the ID Token, Clients
 * MUST verify that the nonce Claim Value is equal to the value of the nonce
 * parameter sent in the Authentication Request. If present in the
 * Authentication Request, Authorization Servers MUST include a nonce Claim in
 * the ID Token with the Claim Value being the nonce value sent in the
 * Authentication Request. Authorization Servers SHOULD perform no other
 * processing on nonce values used. The nonce value is a case sensitive string.
 *)
val nonce          : claim

val acr            : claim

val amr            : claim

val azp            : claim

(* Defined in OpenID Connect *)
(* ------------------------- *)


(* ----------- Claim ---------- *)
(* ---------------------------- *)

(* ------------------------------ *)
(* ----------- Payload ---------- *)

type payload

val empty_payload : payload

val add_claim :
  claim   ->
  string  ->
  payload ->
  payload

val find_claim :
  claim ->
  payload ->
  string

val string_of_payload :
  payload ->
  string

val payload_of_json :
  Yojson.Basic.t ->
  payload

val json_of_payload :
  payload ->
  Yojson.Basic.t

(* ----------- Payload ---------- *)
(* ------------------------------ *)

(* -------------------------------- *)
(* ----------- JWT type ----------- *)

type t

val t_of_header_and_payload :
  header ->
  payload ->
  t
(* ------- *)
(* getters *)

val header_of_t : t -> header

val payload_of_t : t -> payload

val signature_of_t : t -> string

val unsigned_token_of_t : t -> string

(* getters *)
(* ------- *)

val token_of_t : t -> string

val t_of_token : string -> t

(* ----------- JWT type ----------- *)
(* -------------------------------- *)

val verify : alg:string -> jwks:Yojson.Basic.t -> t -> bool
