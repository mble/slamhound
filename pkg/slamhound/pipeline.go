package slamhound

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	yara_x "github.com/VirusTotal/yara-x/go"
	gzip "github.com/klauspost/pgzip"

	"github.com/mble/slamhound/pkg/untar"
)

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
		if err == io.EOF {
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
			buf := make([]byte, header.FileInfo().Size())
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
	results := []Result{}
	done := make(chan struct{})
	defer close(done)

	paths, errc := walkFiles(done, directory, skipList)
	res := make(chan Result)
	var wg sync.WaitGroup
	const numScanners = 32
	wg.Add(numScanners)
	for i := 0; i < numScanners; i++ {
		go func() {
			fileScanner(rules, done, paths, res)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(res)
	}()

	for r := range res {
		if r.Err != nil {
			return nil, r.Err
		}
		results = append(results, r)
	}

	if err := <-errc; err != nil {
		return nil, err
	}

	return results, nil
}

func walkFiles(done <-chan struct{}, directory string, skipList []string) (<-chan string, <-chan error) {
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
				case <-done:
					return fmt.Errorf("walk cancelled")
				}
			default:
			}
			return nil
		})
	}()
	return paths, errc
}

func fileScanner(rules *yara_x.Rules, done <-chan struct{}, paths <-chan string, results chan<- Result) {
	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()
	for path := range paths {
		err := setVariables(scanner, path)
		if err != nil {
			select {
			case results <- Result{Err: err}:
			case <-done:
				return
			}
			continue
		}
		scanResults, err := scanner.ScanFile(path)
		if err != nil {
			select {
			case results <- Result{Err: err}:
			case <-done:
				return
			}
			continue
		}
		select {
		case results <- Result{Path: path, Matches: scanResultsToMatchInfo(scanResults)}:
		case <-done:
			return
		}
	}
}
