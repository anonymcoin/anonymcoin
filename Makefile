# ANONYMCOIN Makefile
# Original Project Author and Founder: Iury Lee
# Copyright © 2026 Iury Lee

GO    ?= go
BINARY ?= anonymcoin

.PHONY: build test vet fmt bench fuzz zip clean

build:
	$(GO) build -o $(BINARY) ./cmd/anonymcoin

test:
	$(GO) test ./... -count=1 -timeout 400s

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

bench:
	$(GO) test ./anonymbwt/ -run '^$$' -bench . -benchmem -benchtime 2s

fuzz:
	$(GO) test ./tests/ -run '^$$' -fuzz FuzzTxDecode -fuzztime 60s
	$(GO) test ./tests/ -run '^$$' -fuzz FuzzBlockDecode -fuzztime 60s

zip: test
	cd .. && rm -f anonymcoin-main.zip && \
	zip -qr anonymcoin-main.zip anonymcoin-main -x "anonymcoin-main/anonymcoin" -x "anonymcoin-main/data/*" && \
	echo "packaged: download/anonymcoin-main.zip (see ../download)"

clean:
	rm -f $(BINARY)
	$(GO) clean -cache -testcache 2>/dev/null || true
