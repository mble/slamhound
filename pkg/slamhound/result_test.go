package slamhound

import (
	"reflect"
	"testing"

	"github.com/mble/go-yara"
)

func TestFormatMatches(t *testing.T) {
	testCases := []struct {
		desc     string
		result   Result
		expected []string
	}{
		{
			desc: "correctly formats matches when only one match",
			result: Result{
				Path: "test.txt",
				Matches: []yara.MatchRule{{
					Rule:      "ruleset",
					Namespace: "rules.test",
					Tags:      []string{},
				}},
			},
			expected: []string{
				"rules.test.ruleset",
			},
		},
		{
			desc: "correctly formats matches when multiple matches",
			result: Result{
				Path: "test.txt",
				Matches: []yara.MatchRule{
					{
						Rule:      "ruleset",
						Namespace: "rules.test",
						Tags:      []string{},
					},
					{
						Rule:      "ruleset",
						Namespace: "rules.test2",
						Tags:      []string{},
					},
				},
			},
			expected: []string{
				"rules.test.ruleset",
				"rules.test2.ruleset",
			},
		},
		{
			desc: "correctly formats matches when no matches",
			result: Result{
				Path:    "test.txt",
				Matches: []yara.MatchRule{},
			},
			expected: []string{},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			formatted := tC.result.FormatMatches()
			if !reflect.DeepEqual(tC.expected, formatted) && len(tC.expected) > 0 {
				t.Errorf("expected: %v, got: %v", tC.expected, formatted)
			}
		})
	}
}

func TestMarshsalJSON(t *testing.T) {
	testCases := []struct {
		desc     string
		result   Result
		expected string
	}{
		{
			desc: "correctly marshals result into JSON when there are matches",
			result: Result{
				Path: "test.txt",
				Matches: []yara.MatchRule{
					{
						Rule:      "ruleset",
						Namespace: "rules.test",
						Tags:      []string{},
					},
					{
						Rule:      "ruleset",
						Namespace: "rules.test2",
						Tags:      []string{},
					},
				},
			},
			expected: `{"path":"test.txt","matches":["rules.test.ruleset","rules.test2.ruleset"]}`,
		},
		{
			desc: "correctly marshals result into JSON when there are no matches",
			result: Result{
				Path:    "test.txt",
				Matches: []yara.MatchRule{},
			},
			expected: `{"path":"test.txt","matches":null}`,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			marshalled, err := tC.result.MarshalJSON()
			if err != nil {
				t.Error(err)
			}
			if string(marshalled) != tC.expected {
				t.Errorf("expected: %v, got: %v", tC.expected, string(marshalled))
			}
		})
	}
}
