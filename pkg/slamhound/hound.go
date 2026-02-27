package slamhound

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/go-yara/v4"
	"github.com/mble/slamhound/pkg/cfg"
)

// Hound is a struct that holds the relevant information,
// such as the rules and config for the scanner
type Hound struct {
	config *cfg.Config
	rules  *yara.Rules
}

// Compile compiles the rules based on configuration and readies
// the scanner
func (h *Hound) Compile(rulesDir string) error {
	c, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("Failed to initialize YARA compiler: %w", err)
	}
	err = compileRules(c, rulesDir)
	if err != nil {
		return fmt.Errorf("Failed to compile from rules dir %s: %w", rulesDir, err)
	}
	rules, err := c.GetRules()
	if err != nil {
		return fmt.Errorf("Failed to compile rules: %w", err)
	}
	h.rules = rules
	return err
}

// CompileSingularRule compiles a single rule into the scanner
func (h *Hound) CompileSingularRule(rule string) error {
	c, err := yara.NewCompiler()
	defer c.Destroy()
	if err != nil {
		return fmt.Errorf("Failed to initialize YARA compiler: %w", err)
	}
	err = prepareExternalVars(c)
	if err != nil {
		return err
	}
	err = addRuleToCompiler(c, rule)
	if err != nil {
		return err
	}
	rules, err := c.GetRules()
	if err != nil {
		return err
	}
	h.rules = rules
	return err
}

// ScanArchive extracts from the target archive and scans using the
// the compiled rules
func (h *Hound) ScanArchive(filename string) ([]Result, error) {
	// This is much faster – do it all in memory and avoid the syscall
	// overheads
	results, err := inMemoryScan(h.rules, filename, h.config.SkipList)
	return results, err
}

// ScanDirectory uses the file walk scan to scan a directory
func (h *Hound) ScanDirectory(directory string) ([]Result, error) {
	// This is very slow to do – we walk all of the directory,
	// and scan it.
	results, err := fileWalkScan(h.rules, directory, h.config.SkipList)
	return results, err
}

// New returns an initalised Hound struct
func New(config *cfg.Config) (*Hound, error) {
	var err error
	h := &Hound{config: config}

	if config.RulesDir != "" {
		err = h.Compile(config.RulesDir)
	}
	if config.Rule != "" {
		err = h.CompileSingularRule(config.Rule)
	}
	return h, err
}

func prepareExternalVars(compiler *yara.Compiler) error {
	vars := map[string]interface{}{
		"filename": "",
		"filepath": "",
	}
	for k, v := range vars {
		err := compiler.DefineVariable(k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func addRuleToCompiler(compiler *yara.Compiler, rule string) error {
	if filepath.Ext(rule) == ".yara" || filepath.Ext(rule) == ".yar" {
		namespace := strings.ReplaceAll(strings.ReplaceAll(rule, filepath.Ext(rule), ""), "/", ".")
		ruleFile, err := os.Open(rule)
		if err != nil {
			return fmt.Errorf("could not open rule file %s: %w", rule, err)
		}
		err = compiler.AddFile(ruleFile, namespace)
		if err != nil {
			return fmt.Errorf("could not compile rule file %s: %w", rule, err)
		}
	}
	return nil
}

func compileRules(compiler *yara.Compiler, ruleDir string) error {
	err := prepareExternalVars(compiler)
	if err != nil {
		return err
	}
	return filepath.WalkDir(ruleDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			return addRuleToCompiler(compiler, path)
		}
		return nil
	})
}
