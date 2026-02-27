package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/mble/slamhound/pkg/cfg"
	"github.com/mble/slamhound/pkg/slamhound"
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {
	var (
		rule             string
		ruleDir          string
		skipList         string
		enableCPUProfile bool
		enableMemProfile bool
	)
	flag.StringVar(&rule, "rule", "", "compile specific rule")
	flag.StringVar(&ruleDir, "rules", "", "compile rules from directory")
	flag.StringVar(&skipList, "skiplist", "", "comma-delimited list of filepath patterns to skip when scanning")
	flag.BoolVar(&enableCPUProfile, "profile-cpu", false, "enable CPU profile")
	flag.BoolVar(&enableMemProfile, "profile-mem", false, "enable memory profile")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		return fmt.Errorf("no targets specified")
	}

	config, err := cfg.NewConfig(
		rule,
		ruleDir,
		skipList,
		enableCPUProfile,
		enableMemProfile,
	)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if config.EnableCPUProfile {
		f, err := os.Create("cpu.prof")
		if err != nil {
			return fmt.Errorf("could not create CPU profile: %w", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			return fmt.Errorf("could not start CPU profile: %w", err)
		}
		defer pprof.StopCPUProfile()
	}

	hound, err := slamhound.New(config)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	for _, target := range args {
		var (
			results []slamhound.Result
			scanErr error
		)

		fi, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("failed to stat target %s: %w", target, err)
		}
		switch mode := fi.Mode(); {
		case mode.IsDir():
			results, scanErr = hound.ScanDirectory(target)
		case mode.IsRegular():
			results, scanErr = hound.ScanArchive(target)
		default:
			return fmt.Errorf("cannot scan non-directory or non-file: %s", target)
		}

		if scanErr != nil {
			return fmt.Errorf("error while scanning %s: %w", target, scanErr)
		}
		for _, result := range results {
			result.LogResult()
		}
	}

	if config.EnableMemProfile {
		f, err := os.Create("mem.prof")
		if err != nil {
			return fmt.Errorf("could not create memory profile: %w", err)
		}
		defer f.Close()
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			return fmt.Errorf("could not write memory profile: %w", err)
		}
	}

	return nil
}
