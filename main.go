package main

import (
	"os"
	"path/filepath"

	"github.com/hillu/go-yara"

	"errors"
	"flag"
	"log"
	"strconv"
	"strings"
)

type rule struct{ namespace, filename string }
type rules []rule

func (r *rules) Set(arg string) error {
	if len(arg) == 0 {
		return errors.New("empty rule specification")
	}
	a := strings.SplitN(arg, ":", 2)
	switch len(a) {
	case 1:
		*r = append(*r, rule{filename: a[0]})
	case 2:
		*r = append(*r, rule{namespace: a[0], filename: a[1]})
	}
	return nil
}

func (r *rules) String() string {
	var s string
	for _, rule := range *r {
		if len(s) > 0 {
			s += " "
		}
		if rule.namespace != "" {
			s += rule.namespace + ":"
		}
		s += rule.filename
	}
	return s
}

func printMatches(m []yara.MatchRule, err error) {
	if err == nil {
		if len(m) > 0 {
			for _, match := range m {
				log.Printf("[+] %s.%s", match.Namespace, match.Rule)
			}
		} else {
			log.Print("no matches.")
		}
	} else {
		log.Printf("error: %s.", err)
	}
}

func main() {
	var (
		ruleDir     string
		rules       rules
		processScan bool
		pids        []int
	)
	flag.BoolVar(&processScan, "processes", false, "scan processes instead of files")
	flag.Var(&rules, "rule", "add rule")
	flag.StringVar(&ruleDir, "directory", "", "compile rules from directory")
	flag.Parse()

	if len(rules) == 0 && ruleDir == "" {
		log.Fatal("no rules or rule directory specified")
	}

	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("no files or processes specified")
	}

	if processScan {
		for _, arg := range args {
			if pid, err := strconv.Atoi(arg); err != nil {
				log.Fatalf("Could not parse %s ad number", arg)
			} else {
				pids = append(pids, pid)
			}
		}
	}

	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}

	if ruleDir != "" {
		err := filepath.Walk(ruleDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("prevent panic by handling failure accessing a path %q: %v\n", path, err)
				return err
			}
			if filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar" {
				namespace := strings.ReplaceAll(strings.ReplaceAll(path, filepath.Ext(path), ""), "/", ".")
				ruleFile, err := os.Open(path)
				if err != nil {
					log.Fatalf("could not open rule file %s: %s", path, err)
				}
				c.AddFile(ruleFile, namespace)
			}
			return nil
		})
		if err != nil {
			log.Fatalf("Could not open rule directory %s: %s", ruleDir, err)
		}
	}

	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}

	if processScan {
		for _, pid := range pids {
			log.Printf("Scanning process %d...", pid)
			m, err := r.ScanProc(pid, 0, 0)
			printMatches(m, err)
		}
	} else {
		for _, filename := range args {
			log.Printf("Scanning file %s... ", filename)
			m, err := r.ScanFile(filename, 0, 0)
			printMatches(m, err)
		}
	}
}
