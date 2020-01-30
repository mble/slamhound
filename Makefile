UNAME := $(shell uname)

build:
ifeq ($(UNAME),Linux)
	go build -v -o bin/slamhound ./cmd/slamhound
endif
ifeq ($(UNAME),Darwin)
	PKG_CONFIG_PATH="$$(brew --prefix yara)/lib/pkgconfig:$$(brew --prefix openssl@1.1)/lib/pkgconfig" go build -v -o bin/slamhound ./cmd/slamhound
endif

test:
ifeq ($(UNAME),Linux)
	go test -v ./...
endif
ifeq ($(UNAME),Darwin)
	PKG_CONFIG_PATH="$$(brew --prefix yara)/lib/pkgconfig:$$(brew --prefix openssl@1.1)/lib/pkgconfig" go test -v ./...
endif
