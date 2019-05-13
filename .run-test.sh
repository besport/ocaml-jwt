opam pin add nocrypto https://github.com/mirleft/ocaml-nocrypto.git -y
opam pin add jwt . -y
eval $(opam env)
dune runtest
