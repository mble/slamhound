# Slamhound

_Go on boy, git!_

## Prerequisites

- [YARA-X](https://github.com/VirusTotal/yara-x) C library (`libyara_x_capi`)

The YARA-X C library, headers, and pkgconfig file must be installed to a standard path (e.g. `/usr/local`). See the [YARA-X documentation](https://virustotal.github.io/yara-x/) for build instructions.

## Installation

```
go install github.com/mble/slamhound/cmd/slamhound@latest
```

You can also clone the repo and use `make` to build. The built binary will be at `bin/slamhound`.

## Usage

`slamhound` uses [YARA-X](https://github.com/VirusTotal/yara-x) to provide high performance scanning of gzipped tarballs and directories, and accepts the following options:

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
{"path":"test.txt","matches":["rules.APT_Carbanak.Carbanak_0915_2"]}
```

Targets can be gzipped tarballs or directories. Other file types are not valid inputs.
It is also possible to specify a directory of rules to be used. This directory will be traversed recursively and compile all rule files contained within the tree:

```
$ slamhound -rules rules/ -skiplist=.git,.ssh evil_archive.tar.gz
{"path":"test.txt","matches":["rules.APT_Carbanak.Carbanak_0915_2"]}
{"path":"test2.txt","matches":["rules.RAT_CrossRAT.CrossRAT"]}
```

### Limitations

- Does not currently support additional external variables. `filename` and `filepath` are exposed to YARA rules through `slamhound`.
- Does not accept archives other than gzipped tarballs.

### Trivia

Named after the _slamhound_ in William Gibson's _Count Zero_.
