build: main.go
	PKG_CONFIG_PATH="$$(brew --prefix yara)/lib/pkgconfig:$$(brew --prefix openssl@1.1)/lib/pkgconfig" go build .
