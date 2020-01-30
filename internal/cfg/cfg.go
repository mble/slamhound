package cfg

import (
	"errors"
	"strings"
)

// Config is a struct that holds the config for the scanner
type Config struct {
	// SkipList defines patterns to skip during tar extraction,
	// and therefore scanning
	SkipList         []string
	EnableCPUProfile bool
	EnableMemProfile bool
	RulesDir         string
	Rule             string
	TargetDir        string
}

// LoadConfig loads config from given flags
func (c Config) LoadConfig(rule, ruleDir, skipList string, enableCPUProfile, enableMemProfile bool) (*Config, error) {
	if ruleDir == "" && rule == "" {
		return nil, errors.New("no rule directory or rule specified")
	}
	if ruleDir != "" && rule != "" {
		return nil, errors.New("can't pass both singular rule and rule directory")
	}
	c.Rule = rule
	c.RulesDir = ruleDir
	c.SkipList = processSkipList(skipList)
	c.EnableCPUProfile = enableCPUProfile
	c.EnableMemProfile = enableMemProfile
	return &c, nil
}

func processSkipList(rawList string) []string {
	skipList := []string{}
	if len(rawList) > 0 {
		skipList = strings.Split(rawList, ",")
	}
	return skipList
}
