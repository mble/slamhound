# Slamhound

_Go on boy, git!_

## Prerequisites

- `yara`
- `openssl`

You'll need to install these with your relevant package manger for your platform.

## Installation

### Linux

```
go install -i github.com/mble/slamhound/cmd/slamhound
```

### macOS

```
PKG_CONFIG_PATH="$(brew --prefix yara)/lib/pkgconfig:$(brew --prefix openssl@1.1)/lib/pkgconfig" go install -i github.com/mble/slamhound/cmd/slamhound
```

You can also clone the repo and use `make` to build. The built binary will at `bin/slamhound`.

## Usage

`slamhound` is a wrapper around `go-yara` intended to provide high performance scanning of gzipped tarballs and directories, and accepts the following options:

```
$ slamhound --help
Usage of slamhound:
  -profile-cpu
    	enable CPU profile
  -profile-mem
    	enable memory profile
  -rule string
    	compile specific rule
  -rules string
    	compile rules from directory
  -skiplist string
    	comma-delimited list of filepath patterns to skip when scanning
```

Example usage:

```
$ slamhound -rule rules/APT_Carbanak.yar -skiplist=.git,.ssh evil_archive.tar.gz
2020/02/29 15:21:58 [+] {"path":"test.txt","matches":["rules.APT_Carbanak.Carbanak_0915_2"]}
```

Targets can be gzipped tarballs or directories. Other file types are not valid inputs.
It is also possible to specify a directory rules to be used. This directory will be traversed recursively and compile all rule files contained within the tree:

```
$ slamhound -rules rules/ -skiplist=.git,.ssh evil_archive.tar.gz
2020/02/29 15:21:58 [+] {"path":"test.txt","matches":["rules.APT_Carbanak.Carbanak_0915_2"]}
2020/02/29 15:21:58 [+] {"path":"test2.txt","matches":["rules.RAT_CrossRAT.CrossRAT"]}
```

### Limitations

- Does not currently support additional external variables. `filename` and `filepath` are exposed to YARA rules through `slamhound`.
- Does not accept archives other than gzipped tarballs.
- Developed against YARA 3.11.

### Trivia

Named after the _slamhound_ in William Gibson's _Count Zero_.
