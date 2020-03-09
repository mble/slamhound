package slamhound

import (
	"archive/tar"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/karrick/godirwalk"
	gzip "github.com/klauspost/pgzip"

	"github.com/mble/go-yara"
	"github.com/mble/slamhound/pkg/untar"
)

func setVariables(scanner *yara.Scanner, relPath string) error {
	err := scanner.DefineVariable("filename", filepath.Base(relPath))
	if err != nil {
		return err
	}
	err = scanner.DefineVariable("filepath", relPath)
	if err != nil {
		return err
	}
	return nil
}

func inMemoryScan(rules yara.Rules, filename string, skipList []string) ([]Result, error) {
	runtime.LockOSThread()
	results := []Result{}
	// Set up the tar reader
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %w", filename, err)
	}
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	scanner, err := yara.NewScanner(&rules)
	if err != nil {
		log.Fatal(err)
	}
	tr := tar.NewReader(gzr)

	// Scan each tar segment non-recursively
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
		// Noop if skippable
		case untar.IsSkippable(rel, skipList):
		case mode.IsRegular():
			buf := make([]byte, header.FileInfo().Size())
			_, err := tr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, fmt.Errorf("error while reading into buffer: %v", err)
			}
			// buf is essentially an in memory file. We need to set up the external variables
			err = setVariables(scanner, rel)
			if err != nil {
				return nil, err
			}
			matches, err := scanner.ScanMem(buf, 0, 0)
			if err != nil {
				return nil, err
			}
			results = append(results, Result{rel, matches, err})
		default:
			// Noop, we don't care about directories or symlinks
			// right now
		}
	}
	return results, nil
}

func fileWalkScan(rules yara.Rules, directory string, skipList []string) ([]Result, error) {
	results := []Result{}
	done := make(chan struct{})
	defer close(done)

	paths, errc := walkFiles(done, directory, skipList)
	res := make(chan Result)
	var wg sync.WaitGroup
	const numScanners = 32 // YR_MAX_THREADS
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
		errc <- godirwalk.Walk(directory, &godirwalk.Options{
			Unsorted: true,
			Callback: func(path string, de *godirwalk.Dirent) error {
				switch {
				case untar.IsSkippable(path, skipList):
				case de.ModeType().IsRegular():
					select {
					case paths <- path:
					case <-done:
						return fmt.Errorf("walk cancelled")
					}
				default:
				}
				return nil
			},
		})
	}()
	return paths, errc
}

func fileScanner(rules yara.Rules, done <-chan struct{}, paths <-chan string, results chan<- Result) {
	runtime.LockOSThread()
	scanner, err := yara.NewScanner(&rules)
	if err != nil {
		results <- Result{Err: err}
		return
	}
	for path := range paths {
		err = setVariables(scanner, path)
		if err != nil {
			select {
			case results <- Result{Err: err}:
			case <-done:
				return
			}
		}
		matches, err := scanner.ScanFile(path, 0, 0)
		select {
		case results <- Result{path, matches, err}:
		case <-done:
			return
		}
	}
}
