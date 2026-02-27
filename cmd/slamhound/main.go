package main

import (
	"flag"
	"log/slog"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/mble/slamhound/pkg/cfg"
	"github.com/mble/slamhound/pkg/slamhound"
)

func main() {
	var (
		rule             string
		ruleDir          string
		skipList         string
		enableCPUProfile bool
		enableMemProfile bool
		conf             cfg.Config
	)
	flag.StringVar(&rule, "rule", "", "compile specific rule")
	flag.StringVar(&ruleDir, "rules", "", "compile rules from directory")
	flag.StringVar(&skipList, "skiplist", "", "comma-delimited list of filepath patterns to skip when scanning")
	flag.BoolVar(&enableCPUProfile, "profile-cpu", false, "enable CPU profile")
	flag.BoolVar(&enableMemProfile, "profile-mem", false, "enable memory profile")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		slog.Error("no targets specified")
		os.Exit(1)
	}

	config, err := conf.LoadConfig(
		rule,
		ruleDir,
		skipList,
		enableCPUProfile,
		enableMemProfile,
	)

	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if config.EnableCPUProfile {
		f, err := os.Create("cpu.prof")
		if err != nil {
			slog.Error("could not create CPU profile", "error", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			slog.Error("could not start CPU profile", "error", err)
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}

	hound, err := slamhound.New(config)
	if err != nil {
		slog.Error("failed to create scanner", "error", err)
		os.Exit(1)
	}

	for _, target := range args {
		var (
			results []slamhound.Result
			err     error
		)

		fi, err := os.Stat(target)
		if err != nil {
			slog.Error("failed to stat target", "target", target, "error", err)
			os.Exit(1)
		}
		switch mode := fi.Mode(); {
		case mode.IsDir():
			results, err = hound.ScanDirectory(target)
		case mode.IsRegular():
			results, err = hound.ScanArchive(target)
		default:
			slog.Error("cannot scan non-directories or non-files", "target", target)
			os.Exit(1)
		}

		if err != nil {
			slog.Error("error while scanning", "target", target, "error", err)
			os.Exit(1)
		}
		for _, result := range results {
			result.LogResult()
		}
	}

	if config.EnableMemProfile {
		f, err := os.Create("mem.prof")
		if err != nil {
			slog.Error("could not create memory profile", "error", err)
			os.Exit(1)
		}
		defer f.Close()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			slog.Error("could not write memory profile", "error", err)
			os.Exit(1)
		}
	}
}
