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

let _ = print_endline (Jwt.header_to_str header)

(* From build function *)
let header =
  Jwt.header_of_algorithm_and_typ (Jwt.HS256 (Eba_lib.generate_random_string 42)) "JWT"

let _ = print_endline (Jwt.header_to_str header)

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
  print_endline (Jwt.payload_to_str payload)

(* PAYLOAD *)
(* ------- *)

(* ------ *)
(* TYPE T *)

let _ =
  let t = Jwt.t_of_header_and_payload header payload in
  print_endline (Jwt.token_of_t t)
