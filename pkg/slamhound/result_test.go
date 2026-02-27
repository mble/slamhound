package slamhound

import (
	"errors"
	"reflect"
	"testing"
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
				Matches: []MatchInfo{{
					Namespace:  "rules.test",
					Identifier: "ruleset",
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
				Matches: []MatchInfo{
					{
						Namespace:  "rules.test",
						Identifier: "ruleset",
					},
					{
						Namespace:  "rules.test2",
						Identifier: "ruleset",
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
				Matches: nil,
			},
			expected: nil,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			formatted := tC.result.FormatMatches()
			if !reflect.DeepEqual(tC.expected, formatted) {
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
				Matches: []MatchInfo{
					{
						Namespace:  "rules.test",
						Identifier: "ruleset",
					},
					{
						Namespace:  "rules.test2",
						Identifier: "ruleset",
					},
				},
			},
			expected: `{"path":"test.txt","matches":["rules.test.ruleset","rules.test2.ruleset"]}`,
		},
		{
			desc: "correctly marshals result into JSON when there are no matches",
			result: Result{
				Path:    "test.txt",
				Matches: []MatchInfo{},
			},
			expected: `{"path":"test.txt","matches":null}`,
		},
		{
			desc: "correctly marshals error as string in JSON",
			result: Result{
				Path:    "test.txt",
				Matches: []MatchInfo{},
				Err:     errors.New("scan failed"),
			},
			expected: `{"path":"test.txt","matches":null,"error":"scan failed"}`,
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
