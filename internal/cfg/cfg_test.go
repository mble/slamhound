package cfg

import "testing"

func TestLoadConfig(t *testing.T) {
	testCases := []struct {
		desc             string
		skipList         string
		rule             string
		ruleDir          string
		enableCPUProfile bool
		enableMemProfile bool
		expectedErr      string
	}{
		{
			desc:        "errors when no rule or rule dir provided",
			rule:        "",
			ruleDir:     "",
			expectedErr: "no rule directory or rule specified",
		},
		{
			desc:    "does not error when only rule is provided",
			rule:    "test.yara",
			ruleDir: "",
		},
		{
			desc:    "does not error when only ruleDir is provided",
			ruleDir: "rules",
			rule:    "",
		},
		{
			desc:        "errors when both rule and ruleDir are provided",
			rule:        "test.yara",
			ruleDir:     "rules",
			expectedErr: "can't pass both singular rule and rule directory",
		},
		{
			desc:     "does not error when skipList is empty",
			rule:     "test.yara",
			ruleDir:  "",
			skipList: "",
		},
		{
			desc:             "does not error when profiling flags are provided",
			rule:             "test.yara",
			enableCPUProfile: true,
			enableMemProfile: true,
		},
		{
			desc:             "does not error when valid config is provided",
			rule:             "test.yara",
			enableCPUProfile: true,
			enableMemProfile: true,
			skipList:         ".git,.profile.d",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			c := &Config{}
			c, err := c.LoadConfig(tC.rule, tC.ruleDir, tC.skipList, tC.enableCPUProfile, tC.enableMemProfile)
			if err != nil {
				if err.Error() != tC.expectedErr {
					t.Error(err)
				}
			}
		})
	}
}
