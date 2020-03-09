package untar

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	gzip "github.com/klauspost/pgzip"
)

// IsSkippable checks if a given path is skippable based
// on matching the patterns in skipList
func IsSkippable(path string, skipList []string) bool {
	skippable := false
	for _, pattern := range skipList {
		if strings.Contains(path, pattern) {
			skippable = true
		}
	}
	return skippable
}

// IsIllegalPath is a zip-slip mitigation. symlinks can be used to get around this,
// see https://github.com/mholt/archiver/pull/65#issuecomment-395988244
// fortunately we don't care about symlinks
func IsIllegalPath(filePath string, destination string) bool {
	isIllegal := false
	destpath := filepath.Join(destination, filePath)
	if !strings.HasPrefix(destpath, filepath.Clean(destination)+string(os.PathSeparator)) {
		isIllegal = true
	}
	return isIllegal
}

// Untar reads from reader, checks if the archive is compressed,
// then uncompresses then untars into dir. skipList contains patterns
// to skip when untaring
func Untar(reader io.Reader, dir string, skipList []string) error {
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		// End of file, so break
		if err == io.EOF {
			break
		}
		// Something went wrong
		if err != nil {
			return fmt.Errorf("tar reading error: %v", err)
		}
		// Extract relative and absolute filepaths
		rel := filepath.FromSlash(header.Name)
		abs := filepath.Join(dir, rel)

		// Extract file mode for processing
		fileInfo := header.FileInfo()
		mode := fileInfo.Mode()

		switch {
		// Noop if skippable path
		case IsSkippable(rel, skipList):
		// Noop if an illegal path
		case IsIllegalPath(rel, dir):
		// Directory, create if not exists
		case mode.IsDir():
			if _, err := os.Stat(abs); err != nil {
				if err := os.MkdirAll(abs, 0755); err != nil {
					return fmt.Errorf("could not create output dir %s: %v", abs, err)
				}
			}
		// File, create it
		case mode.IsRegular():
			file, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR|os.O_TRUNC, mode.Perm())
			if err != nil {
				return fmt.Errorf("could not create file handle %s: %v", abs, err)
			}
			sizeBytes, err := io.Copy(file, tr)
			if closeErr := file.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			if err != nil {
				return fmt.Errorf("error writing to %s: %v", abs, err)
			}
			// Handle not writing the correct number of bytes out
			if sizeBytes != header.Size {
				return fmt.Errorf("only wrote %d bytes to %s; expected %d", sizeBytes, abs, header.Size)
			}
		// File type isn't supported. Given we don't care about reconstructing filesystems, ignore it
		default:
		}
	}
	return nil
}
