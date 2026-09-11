# Parallax one-shot run targets.
#
#   make quick       regenerate spec cases if absent, build, run quick tier
#   make standard    same, standard tier (IR-generated excluded)
#   make full        same, full tier (everything, ~2h with 6 clients)
#   make regenerate  force spec -> knowledge -> cases regeneration
#
# The hive path is the default backend; pass PARALLAX_ENV=kurtosis plus
# ARGS_FILE to run through ethereum-package instead.

PARALLAX_BIN  := dist/parallax-final
SPECS_DIR     ?= /tmp/opencode/consensus-specs/specs
ENCLAVE       ?= hivesmoke
HIVE_CLIENTS  ?= lighthouse,teku,prysm,nimbus,lodestar,grandine
PARALLAX_ENV  ?= hive
ARGS_FILE     ?= configs/net-geth6.yaml

KNOWLEDGE_MARK := knowledge/spec/rule_ast.json

.PHONY: build regenerate quick standard full

regenerate:
	go run ./cmd/specchain all -specs $(SPECS_DIR)

$(KNOWLEDGE_MARK):
	$(MAKE) regenerate

build: $(KNOWLEDGE_MARK)
	go build -o $(PARALLAX_BIN) ./cmd/parallax

define RUN
	$(PARALLAX_BIN) run -env $(PARALLAX_ENV) -enclave $(ENCLAVE) \
		$(if $(filter hive,$(PARALLAX_ENV)),-hive-clients $(HIVE_CLIENTS),-args-file $(ARGS_FILE)) \
		-suite $(1) -out results/$(1)
endef

quick:    ; $(call RUN,quick)
standard: ; $(call RUN,standard)
full:     ; $(call RUN,full)

quick:    build
standard: build
full:     build
