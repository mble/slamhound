package untar

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestIsSkippable(t *testing.T) {
	testCases := []struct {
		desc     string
		path     string
		skipList []string
		expected bool
	}{
		{
			desc: "returns true when path contains a pattern in the skiplist",
			path: "app/.git/index",
			skipList: []string{
				".git",
				".profile.d",
			},
			expected: true,
		},
		{
			desc: "returns false when path does not contain a pattern in the skiplist",
			path: "app/.git/index",
			skipList: []string{
				".profile.d",
			},
			expected: false,
		},
		{
			desc:     "returns false when skiplist is empty",
			path:     "app/.git/index",
			skipList: []string{},
			expected: false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			outcome := IsSkippable(tC.path, tC.skipList)
			if outcome != tC.expected {
				t.Errorf("expected: %v, got: %v", tC.expected, outcome)
			}
		})
	}
}

// createTestTarGz builds a tar.gz in memory with the given file entries.
func createTestTarGz(t *testing.T, files map[string]string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestUntar(t *testing.T) {
	t.Run("extracts valid files to destination", func(t *testing.T) {
		dir := t.TempDir()
		reader := createTestTarGz(t, map[string]string{
			"hello.txt": "hello world",
			"sub/a.txt": "nested file",
		})
		// Create the subdirectory needed for nested file
		if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := Untar(reader, dir, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		content, err := os.ReadFile(filepath.Join(dir, "hello.txt"))
		if err != nil {
			t.Fatalf("expected hello.txt to exist: %v", err)
		}
		if string(content) != "hello world" {
			t.Errorf("expected 'hello world', got %q", string(content))
		}
		content, err = os.ReadFile(filepath.Join(dir, "sub", "a.txt"))
		if err != nil {
			t.Fatalf("expected sub/a.txt to exist: %v", err)
		}
		if string(content) != "nested file" {
			t.Errorf("expected 'nested file', got %q", string(content))
		}
	})

	t.Run("skips files matching skiplist", func(t *testing.T) {
		dir := t.TempDir()
		reader := createTestTarGz(t, map[string]string{
			"keep.txt":        "keep",
			".git/config":     "secret",
			".profile.d/init": "skip",
		})
		if err := Untar(reader, dir, []string{".git", ".profile.d"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "keep.txt")); err != nil {
			t.Errorf("expected keep.txt to exist: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, ".git", "config")); !os.IsNotExist(err) {
			t.Errorf("expected .git/config to not be extracted")
		}
		if _, err := os.Stat(filepath.Join(dir, ".profile.d", "init")); !os.IsNotExist(err) {
			t.Errorf("expected .profile.d/init to not be extracted")
		}
	})

	t.Run("skips illegal paths (directory traversal)", func(t *testing.T) {
		dir := t.TempDir()
		reader := createTestTarGz(t, map[string]string{
			"good.txt":               "safe",
			"../../../etc/evil.txt":  "evil",
		})
		if err := Untar(reader, dir, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "good.txt")); err != nil {
			t.Errorf("expected good.txt to exist: %v", err)
		}
		// The evil file should not exist outside the destination
		if _, err := os.Stat(filepath.Join(dir, "..", "..", "..", "etc", "evil.txt")); !os.IsNotExist(err) {
			t.Errorf("expected traversal path to not be extracted")
		}
	})
}

func TestIsIllegalPath(t *testing.T) {
	dest := "app/"
	testCases := []struct {
		desc     string
		path     string
		expected bool
	}{
		{
			desc:     "returns true when path is illegal",
			path:     "../../../../../../../../tmp/evil.txt",
			expected: true,
		},
		{
			desc:     "returns false when path is not illegal",
			path:     "/tmp/good.txt",
			expected: false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			outcome := IsIllegalPath(tC.path, dest)
			if outcome != tC.expected {
				t.Errorf("expected: %v, got: %v", tC.expected, outcome)
			}
		})
	}
}
