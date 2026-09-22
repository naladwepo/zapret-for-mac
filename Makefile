# zapret-mac — macOS (Apple Silicon) DPI-desync daemon.
#
# Everything here runs without an Apple developer account: Go's linker ad-hoc
# signs the binaries, which is all arm64 requires. Nothing needs SIP disabled,
# a kext, a NetworkExtension entitlement, or a reboot.

SHELL     := /bin/bash
GO        ?= go
BIN       := bin
PREFIX    ?= /usr/local
LIBEXEC   := $(PREFIX)/libexec
DATADIR   ?= /Library/Application Support/zapret-mac
PLIST     := /Library/LaunchDaemons/io.zapretmac.zapretd.plist
LABEL     := io.zapretmac.zapretd

# arm64-only by default (this is an Apple Silicon project); make ARCHS="arm64 amd64"
# to get a universal binary.
ARCHS     ?= arm64
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
GOFLAGS   := CGO_ENABLED=0 GOOS=darwin

CMDS      := zapretd zaprctl batconv

.PHONY: all build test vet fmt clean install uninstall reinstall probe status logs check

all: build

build: $(addprefix $(BIN)/,$(CMDS))

# Single-arch fast path; for several ARCHS build each and lipo them together.
$(BIN)/%: FORCE
	@mkdir -p $(BIN)
	@if [ "$(words $(ARCHS))" = "1" ]; then \
	  $(GOFLAGS) GOARCH=$(ARCHS) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/$*/ ; \
	else \
	  for a in $(ARCHS); do \
	    $(GOFLAGS) GOARCH=$$a $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@.$$a ./cmd/$*/ || exit 1; \
	  done; \
	  lipo -create -output $@ $(addprefix $@.,$(ARCHS)); \
	  rm -f $(addprefix $@.,$(ARCHS)); \
	  codesign -f -s - $@; \
	fi
	@echo "built $@ ($(VERSION), $(ARCHS))"

FORCE:

test:
	CGO_ENABLED=0 $(GO) test ./...

race:
	$(GO) test -race ./internal/...

vet:
	CGO_ENABLED=0 $(GO) vet ./...

fmt:
	gofmt -l -w $(shell git ls-files '*.go' 2>/dev/null || find . -name '*.go' -not -path './.upstream/*')

check: fmt vet test

# ---- capability probe -------------------------------------------------------
# Answers whether the packet-level datapath works on THIS machine. Needs root;
# reverts every change it makes.
probe: $(BIN)/zaprctl
	@echo "==> running the capability probe (needs your password, changes nothing permanently)"
	sudo $(BIN)/zaprctl probe

# ---- install ----------------------------------------------------------------
install: build
	sudo install -d -m 0755 "$(LIBEXEC)" "$(DATADIR)" "$(DATADIR)/lists" "$(DATADIR)/fakes" "$(DATADIR)/strategies"
	sudo install -m 0755 $(BIN)/zapretd "$(LIBEXEC)/zapretd"
	sudo install -m 0755 $(BIN)/zaprctl "$(PREFIX)/bin/zaprctl"
	sudo install -m 0644 lists/*.txt "$(DATADIR)/lists/"
	sudo install -m 0644 fakes/*.bin "$(DATADIR)/fakes/"
	sudo install -m 0644 strategies/*.toml "$(DATADIR)/strategies/"
	sudo $(LIBEXEC)/zapretd install-daemon --plist "$(PLIST)" --data "$(DATADIR)" \
		--transport divert --allow-vpn
	@for attempt in 1 2 3 4 5; do \
		sudo $(PREFIX)/bin/zaprctl use cloud-gaming && exit 0; \
		sleep 1; \
	done; exit 1
	@echo "==> installed with pflog/BPF, active-VPN support and cloud-gaming default"
	@echo "==> split routing: zaprctl router happ --install, accept it in Happ, then reconnect the VPN"
	@echo "==> verify: zaprctl test --suite discord"

uninstall:
	-sudo $(PREFIX)/bin/zaprctl stop
	-sudo $(LIBEXEC)/zapretd uninstall-daemon --plist "$(PLIST)"
	-sudo rm -f "$(LIBEXEC)/zapretd" "$(PREFIX)/bin/zaprctl"
	@echo "==> removed binaries and the daemon. Data left in $(DATADIR) (rm -rf it yourself)."

reinstall: uninstall install

status:
	@zaprctl status || true

logs:
	@sudo log stream --predicate 'process == "zapretd"' --level info

clean:
	rm -rf $(BIN)
