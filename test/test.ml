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

let generate_random_string length =
  let random_character () = match Random.int (26 + 26 + 10) with
    n when n < 26 -> int_of_char 'a' + n
  | n when n < 26 + 26 -> int_of_char 'A' + n - 26
  | n -> int_of_char '0' + n - 26 - 26 in
  let random_character _ = String.make 1 (char_of_int (random_character ())) in
  String.concat "" (Array.to_list (Array.init length random_character))

(* ------ *)
(* HEADER *)

(* From JSON *)
let header =
  Jwt.header_of_json
  (
    `Assoc
    [
      ("alg", `String "HS256") ;
      ("typ", `String "JWT")
    ]
  )

let _ =
  print_endline "Test header_of_json" ;
  print_endline (Jwt.string_of_header header) ;
  print_endline "----------"

(* From build function *)
let header =
  Jwt.header_of_algorithm_and_typ (Jwt.HS256 (generate_random_string 100)) (Some "JWT")

let _ =
  print_endline "Test header_of_algorithm_and_typ" ;
  print_endline (Jwt.string_of_header header) ;
  print_endline "----------"

(* HEADER *)
(* ------ *)

(* ------- *)
(* PAYLOAD *)

let payload =
  let open Jwt in
  empty_payload
  |> add_claim iss "https://chat.besport.com"
  |> add_claim sub "BeSport Connect"

let _ =
  print_endline "Test payload" ;
  print_endline (Jwt.string_of_payload payload) ;
  print_endline "----------"

let payload =
  Jwt.payload_of_json
  (
    `Assoc
    [
      ("iss", `String "https://chat.besport.com") ;
      ("sub", `String "BeSport Connect")
    ]
  )

let _ =
  print_endline "Test payload_of_json" ;
  print_endline (Jwt.string_of_payload payload) ;
  print_endline "----------"

(* PAYLOAD *)
(* ------- *)

(* ------ *)
(* TYPE T *)

let _ =
  let t = Jwt.t_of_header_and_payload header payload in
  print_endline "Test token generation from a type t" ;
  print_endline (Jwt.token_of_t t) ;
  print_endline "----------"

let _ =
  let t = Jwt.t_of_header_and_payload header payload in
  let t_2 = Jwt.t_of_token (Jwt.token_of_t t) in
  let encoded_signature_t =
    match Base64.encode (Jwt.signature_of_t t) with
    | Ok s -> s
    | Error _ -> failwith "Error while encoding"
  in
  let encoded_signature_t2 = match Base64.encode (Jwt.signature_of_t t_2) with
  | Ok s -> s
  | Error _ -> failwith "Error while encoding"
  in
  print_endline "Test t_of_token. The next lines must be equal.";
  print_endline (Jwt.string_of_header header) ;
  print_endline (Jwt.string_of_header (Jwt.header_of_t t_2)) ;
  print_endline (Jwt.string_of_payload payload) ;
  print_endline (Jwt.string_of_payload (Jwt.payload_of_t t_2)) ;
  print_endline encoded_signature_t;
  print_endline encoded_signature_t2
