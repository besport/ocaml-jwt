MLI_FILES	= jwt.mli
ML_FILES	= jwt.ml

CMO_FILES	= $(patsubst %.ml, %.cmo, $(ML_FILES))
CMX_FILES	= $(patsubst %.ml, %.cmx, $(ML_FILES))
OBJ_FILES	= $(patsubst %.ml, %.o, $(ML_FILES))
CMI_FILES	= $(patsubst %.mli, %.cmi, $(MLI_FILES))

LIB_NAME	= jwt
CMA_FILE	= $(LIB_NAME).cma
CMXA_FILE	= $(LIB_NAME).cmxa
A_FILE		= $(LIB_NAME).a

PACKAGES	= -package base64 -package yojson -package cryptokit -package nocrypto -package re.str

all: build

build: $(CMI_FILES) $(CMO_FILES) $(CMX_FILES)
	ocamlfind ocamlc -a -o $(CMA_FILE) $(CMO_FILES)
	ocamlfind ocamlopt -a -o $(CMXA_FILE) $(CMX_FILES)

install: build
	ocamlfind install $(LIB_NAME) META $(CMA_FILE) \
	    $(CMXA_FILE) $(A_FILE) $(CMI_FILES) $(CMX_FILES) $(CMO_FILES) \
	    $(OBJ_FILES)

remove:
	ocamlfind remove $(LIB_NAME)

%.cmo: %.ml
	ocamlfind ocamlc -c -o $@ $(PACKAGES) -linkpkg $<

%.cmi: %.mli
	ocamlfind ocamlc -c -o $@ $(PACKAGES) -linkpkg $<

%.cmx: %.ml
	ocamlfind ocamlopt -c -o $@ $(PACKAGES) -linkpkg $<

clean:
	$(RM) $(CMI_FILES) $(CMX_FILES) $(CMO_FILES) $(OBJ_FILES)

fclean: clean
	$(RM) $(CMXA_FILE) $(CMA_FILE) $(A_FILE)

test:
	ocamlfind ocamlc -o test.out $(PACKAGES) -package jwt -linkpkg test/test.ml

test_clean:
	$(RM) test.out test.cmo test.cmi
.PHONY: test
