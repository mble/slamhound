# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Slamhound

A Go CLI tool using YARA-X for high-performance scanning of gzipped tarballs and directories. Named after the slamhound in William Gibson's *Count Zero*.

## Prerequisites

Requires the [YARA-X](https://github.com/VirusTotal/yara-x) C library (`libyara_x_capi`), headers, and pkgconfig installed to a standard path (e.g. `/usr/local`).

## Build & Test Commands

**Build:**
```
make build
```
Output binary: `bin/slamhound`

**Test (all):**
```
make test
```

**Test (single package):**
```
go test -v ./pkg/slamhound/
```

## Architecture

### Packages

- **`cmd/slamhound`** — CLI entry point. Parses flags (`-rule`, `-rules`, `-skiplist`, `-profile-cpu`, `-profile-mem`), determines if target is archive or directory, dispatches to scanner.
- **`pkg/slamhound`** — Core scanner. `Hound` struct holds config and compiled YARA-X rules. Two scanning modes:
  - `ScanArchive` → `inMemoryScan`: streams tar.gz contents, scans each file entry in memory via pgzip.
  - `ScanDirectory` → `fileWalkScan`: concurrent directory walk with 32 parallel workers, each with its own `yara_x.Scanner` instance.
- **`pkg/cfg`** — Configuration loading and validation. Enforces mutual exclusivity of `-rule` and `-rules` flags.
- **`pkg/untar`** — Archive utilities including skiplist matching (`IsSkippable`), zip-slip prevention (`IsIllegalPath`), and full extraction (`Untar`).

### Key Design Details

- YARA-X global variables `filename` and `filepath` are set per-scan via `scanner.SetGlobal()` in `pipeline.go`.
- Rules can be a single file (`.yara`/`.yar`) or a directory compiled recursively.
- Results are JSON-formatted: `{"path":"...","matches":["namespace.rulename"]}`.
- Uses `klauspost/pgzip` for parallel gzip decompression and stdlib `filepath.WalkDir` for directory traversal.
- Logging via `log/slog` with structured output.

## Go Module

Module path: `github.com/mble/slamhound` (go 1.26).
