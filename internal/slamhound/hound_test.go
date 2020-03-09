package slamhound

import (
	"reflect"
	"testing"

	"github.com/mble/slamhound/internal/cfg"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		desc        string
		conf        *cfg.Config
		expectedErr string
	}{
		{
			desc: "returns initialised hound struct when rules dir passed",
			conf: &cfg.Config{
				RulesDir: "testdata/rules",
				SkipList: []string{".git", ".profile.d"},
			},
		},
		{
			desc: "returns initialised hound struct when rule file passed",
			conf: &cfg.Config{
				Rule:     "testdata/rules/test.yara",
				SkipList: []string{".git", ".profile.d"},
			},
		},
		{
			desc: "gracefully handled errors on initialisation",
			conf: &cfg.Config{
				Rule:     "testdata/rules/nonexistant.yara",
				SkipList: []string{".git", ".profile.d"},
			},
			expectedErr: "could not open rule file testdata/rules/nonexistant.yara: open testdata/rules/nonexistant.yara: no such file or directory",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			hound, err := New(tC.conf)
			if err != nil {
				if err.Error() != tC.expectedErr {
					t.Errorf("expected: %s, got: %s", tC.expectedErr, err.Error())
				}
			}
			if !reflect.DeepEqual(hound.config, tC.conf) {
				t.Fail()
			}
		})
	}
}

func TestScanArchive(t *testing.T) {
	testCases := []struct {
		desc           string
		conf           *cfg.Config
		target         string
		expectedErr    string
		expectedResLen int
	}{
		{
			desc:   "scans archive successfully with valid config",
			target: "testdata/test.tar.gz",
			conf: &cfg.Config{
				Rule:     "testdata/rules/test.yara",
				SkipList: []string{".git", ".profile.d"},
			},
			expectedResLen: 1,
		},
		{
			desc:   "gracefully handles error with invalid target",
			target: "testdata/nonexistant.tar.gz",
			conf: &cfg.Config{
				Rule:     "testdata/rules/test.yara",
				SkipList: []string{".git", ".profile.d"},
			},
			expectedErr:    "could not open file testdata/nonexistant.tar.gz: open testdata/nonexistant.tar.gz: no such file or directory",
			expectedResLen: 0,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			hound, err := New(tC.conf)
			if err != nil {
				t.Errorf("error: %s", err.Error())
			}
			res, err := hound.ScanArchive(tC.target)
			if err != nil {
				if err.Error() != tC.expectedErr {
					t.Errorf("expected: %s, got: %s", tC.expectedErr, err.Error())
				}
			}
			if len(res) != tC.expectedResLen {
				t.Errorf("expected: %d, got: %d", tC.expectedResLen, len(res))
			}
		})
	}
}

func TestScanDirectory(t *testing.T) {
	testCases := []struct {
		desc           string
		conf           *cfg.Config
		target         string
		expectedErr    string
		expectedResLen int
	}{
		{
			desc:   "scans directory successfully with valid config",
			target: "testdata",
			conf: &cfg.Config{
				Rule:     "testdata/rules/test.yara",
				SkipList: []string{".git", ".profile.d"},
			},
			expectedResLen: 3,
		},
		{
			desc:   "gracefully handles error with invalid target",
			target: "testdata/nonexistant",
			conf: &cfg.Config{
				Rule:     "testdata/rules/test.yara",
				SkipList: []string{".git", ".profile.d"},
			},
			expectedErr:    "lstat testdata/nonexistant: no such file or directory",
			expectedResLen: 0,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			hound, err := New(tC.conf)
			if err != nil {
				t.Errorf("error: %s", err.Error())
			}
			res, err := hound.ScanDirectory(tC.target)
			if err != nil {
				if err.Error() != tC.expectedErr {
					t.Errorf("expected: %s, got: %s", tC.expectedErr, err.Error())
				}
			}
			if len(res) != tC.expectedResLen {
				t.Errorf("expected: %d, got: %d", tC.expectedResLen, len(res))
			}
		})
	}
}
