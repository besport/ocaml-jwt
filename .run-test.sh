opam pin add nocrypto https://github.com/mirleft/ocaml-nocrypto.git
opam pin add jwt .
opam install jwt
dune build
dune runtest
