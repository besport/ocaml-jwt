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
  print_endline (Jwt.header_to_str header) ;
  print_endline "----------"

(* From build function *)
let header =
  Jwt.header_of_algorithm_and_typ (Jwt.HS256 (generate_random_string 100)) "JWT"

let _ =
  print_endline "Test header_of_algorithm_and_typ" ;
  print_endline (Jwt.header_to_str header) ;
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
  print_endline (Jwt.payload_to_str payload) ;
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
  print_endline (Jwt.payload_to_str payload) ;
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
  print_endline "Test t_of_token. The next lines must be equal.";
  print_endline (Jwt.header_to_str header) ;
  print_endline (Jwt.header_to_str (Jwt.header_of_t t_2)) ;
  print_endline (Jwt.payload_to_str payload) ;
  print_endline (Jwt.payload_to_str (Jwt.payload_of_t t_2)) ;
  print_endline (B64.encode (Jwt.signature_of_t t)) ;
  print_endline (B64.encode (Jwt.signature_of_t t_2))
