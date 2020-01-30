package untar

import "testing"

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
