package slamhound

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	yara_x "github.com/VirusTotal/yara-x/go"
	gzip "github.com/klauspost/pgzip"

	"github.com/mble/slamhound/pkg/untar"
)

// maxScanSize is the maximum file size (512 MiB) that will be scanned
// in memory from an archive. Files larger than this are skipped with a warning.
const maxScanSize = 512 << 20

func setVariables(scanner *yara_x.Scanner, relPath string) error {
	if err := scanner.SetGlobal("filename", filepath.Base(relPath)); err != nil {
		return err
	}
	if err := scanner.SetGlobal("filepath", relPath); err != nil {
		return err
	}
	return nil
}

func scanResultsToMatchInfo(results *yara_x.ScanResults) []MatchInfo {
	rules := results.MatchingRules()
	infos := make([]MatchInfo, len(rules))
	for i, r := range rules {
		infos[i] = MatchInfo{Namespace: r.Namespace(), Identifier: r.Identifier()}
	}
	return infos
}

func inMemoryScan(rules *yara_x.Rules, filename string, skipList []string) ([]Result, error) {
	results := []Result{}
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %w", filename, err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()
	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar reading error: %v", err)
		}
		rel := filepath.FromSlash(header.Name)
		mode := header.FileInfo().Mode()

		switch {
		case untar.IsSkippable(rel, skipList):
		case mode.IsRegular():
			size := header.Size
			if size == 0 {
				continue
			}
			if size > maxScanSize {
				slog.Warn("skipping oversized file in archive", "path", rel, "size", size, "max", maxScanSize)
				continue
			}
			buf := make([]byte, size)
			if _, err := io.ReadFull(tr, buf); err != nil {
				return nil, fmt.Errorf("error while reading into buffer: %v", err)
			}
			err = setVariables(scanner, rel)
			if err != nil {
				return nil, err
			}
			scanResults, err := scanner.Scan(buf)
			if err != nil {
				return nil, err
			}
			results = append(results, Result{Path: rel, Matches: scanResultsToMatchInfo(scanResults)})
		default:
		}
	}
	return results, nil
}

func fileWalkScan(rules *yara_x.Rules, directory string, skipList []string) ([]Result, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	paths, errc := walkFiles(ctx, directory, skipList)
	res := make(chan Result)
	var wg sync.WaitGroup
	numScanners := runtime.NumCPU()
	wg.Add(numScanners)
	for range numScanners {
		go func() {
			defer wg.Done()
			fileScanner(ctx, rules, paths, res)
		}()
	}
	go func() {
		wg.Wait()
		close(res)
	}()

	var results []Result
	var scanErr error
	for r := range res {
		if r.Err != nil {
			scanErr = r.Err
			cancel()
			break
		}
		results = append(results, r)
	}
	// Drain remaining results to let goroutines exit.
	if scanErr != nil {
		for range res {
		}
	}

	if err := <-errc; err != nil && scanErr == nil {
		return nil, err
	}
	if scanErr != nil {
		return nil, scanErr
	}
	return results, nil
}

func walkFiles(ctx context.Context, directory string, skipList []string) (<-chan string, <-chan error) {
	paths := make(chan string)
	errc := make(chan error, 1)

	go func() {
		defer close(paths)
		errc <- filepath.WalkDir(directory, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			switch {
			case untar.IsSkippable(path, skipList):
			case d.Type().IsRegular():
				select {
				case paths <- path:
				case <-ctx.Done():
					return fmt.Errorf("walk cancelled")
				}
			default:
			}
			return nil
		})
	}()
	return paths, errc
}

func fileScanner(ctx context.Context, rules *yara_x.Rules, paths <-chan string, results chan<- Result) {
	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()
	for path := range paths {
		err := setVariables(scanner, path)
		if err != nil {
			select {
			case results <- Result{Err: err}:
			case <-ctx.Done():
				return
			}
			continue
		}
		scanResults, err := scanner.ScanFile(path)
		if err != nil {
			select {
			case results <- Result{Err: err}:
			case <-ctx.Done():
				return
			}
			continue
		}
		select {
		case results <- Result{Path: path, Matches: scanResultsToMatchInfo(scanResults)}:
		case <-ctx.Done():
			return
		}
	}
}
