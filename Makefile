CARGO = cargo
RUNNER = sudo -E

RUN_ARGS = # User provided args could go here, or be specified at cmd line

DEBUG   = target/debug/suidsnoop
RELEASE = target/release/suidsnoop

DEBUG_BPF   = target/bpfel-unknown-none/debug/suidsnoop
RELEASE_BPF = target/bpfel-unknown-none/release/suidsnoop

USER_SRCS   =  $(wildcard suidsnoop-common/*) $(wildcard suidsnoop-common/**/*)
COMMON_SRCS =  $(wildcard suidsnoop/*) $(wildcard suidsnoop/**/*)
BPF_SRCS    =  $(wildcard suidsnoop-ebpf/*) $(wildcard suidsnoop-ebpf/**/*)

.PHONY: build
build: $(DEBUG)

.PHONY: run
run: $(DEBUG)
	$(RUNNER) ./$(DEBUG) $(RUN_ARGS)

.PHONY: build-release
build-release: $(RELEASE)

.PHONY: run-release
run-release: $(RELEASE)
	$(RUNNER) ./$(RELEASE) $(RUN_ARGS)

.PHONY: install
install: $(RELEASE)
	$(CARGO) install --path suidsnoop

.PHONY: clean
clean:
	$(CARGO) clean

$(DEBUG): $(DEBUG_BPF) $(USER_SRCS) $(COMMON_SRCS)
	$(CARGO) build

$(DEBUG_BPF): $(BPF_SRCS) $(COMMON_SRCS)
	$(CARGO) xtask build-ebpf

$(RELEASE): $(RELEASE_BPF) $(USER_SRCS) $(COMMON_SRCS)
	$(CARGO) build --release

$(RELEASE_BPF): $(BPF_SRCS) $(COMMON_SRCS)
	$(CARGO) xtask build-ebpf --release
