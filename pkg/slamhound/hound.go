package slamhound

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	yara_x "github.com/VirusTotal/yara-x/go"
	"github.com/mble/slamhound/pkg/cfg"
)

// Hound is a struct that holds the relevant information,
// such as the rules and config for the scanner
type Hound struct {
	config *cfg.Config
	rules  *yara_x.Rules
}

// Compile compiles the rules based on configuration and readies
// the scanner
func (h *Hound) Compile(rulesDir string) error {
	c, err := yara_x.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to initialize YARA-X compiler: %w", err)
	}
	defer c.Destroy()
	err = compileRules(c, rulesDir)
	if err != nil {
		return fmt.Errorf("failed to compile from rules dir %s: %w", rulesDir, err)
	}
	h.rules = c.Build()
	return nil
}

// CompileSingularRule compiles a single rule into the scanner
func (h *Hound) CompileSingularRule(rule string) error {
	c, err := yara_x.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to initialize YARA-X compiler: %w", err)
	}
	defer c.Destroy()
	err = prepareExternalVars(c)
	if err != nil {
		return err
	}
	err = addRuleToCompiler(c, rule)
	if err != nil {
		return err
	}
	h.rules = c.Build()
	return nil
}

// ScanArchive extracts from the target archive and scans using the
// the compiled rules
func (h *Hound) ScanArchive(filename string) ([]Result, error) {
	results, err := inMemoryScan(h.rules, filename, h.config.SkipList)
	return results, err
}

// ScanDirectory uses the file walk scan to scan a directory
func (h *Hound) ScanDirectory(directory string) ([]Result, error) {
	results, err := fileWalkScan(h.rules, directory, h.config.SkipList)
	return results, err
}

// New returns an initialised Hound struct
func New(config *cfg.Config) (*Hound, error) {
	h := &Hound{config: config}
	if config.RulesDir != "" {
		if err := h.Compile(config.RulesDir); err != nil {
			return h, err
		}
	}
	if config.Rule != "" {
		if err := h.CompileSingularRule(config.Rule); err != nil {
			return h, err
		}
	}
	return h, nil
}

func prepareExternalVars(compiler *yara_x.Compiler) error {
	if err := compiler.DefineGlobal("filename", ""); err != nil {
		return err
	}
	if err := compiler.DefineGlobal("filepath", ""); err != nil {
		return err
	}
	return nil
}

func addRuleToCompiler(compiler *yara_x.Compiler, rule string) error {
	ext := filepath.Ext(rule)
	if ext == ".yara" || ext == ".yar" {
		content, err := os.ReadFile(rule)
		if err != nil {
			return fmt.Errorf("could not open rule file %s: %w", rule, err)
		}
		namespace := strings.ReplaceAll(strings.ReplaceAll(rule, ext, ""), "/", ".")
		compiler.NewNamespace(namespace)
		if err := compiler.AddSource(string(content), yara_x.WithOrigin(rule)); err != nil {
			return fmt.Errorf("could not compile rule file %s: %w", rule, err)
		}
	}
	return nil
}

func compileRules(compiler *yara_x.Compiler, ruleDir string) error {
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
