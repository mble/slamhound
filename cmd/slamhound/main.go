package main

import (
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/mble/slamhound/pkg/cfg"
	"github.com/mble/slamhound/pkg/slamhound"

	"flag"
	"log"
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
		log.Fatal("no targets specified")
	}

	config, err := conf.LoadConfig(
		rule,
		ruleDir,
		skipList,
		enableCPUProfile,
		enableMemProfile,
	)

	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	if config.EnableCPUProfile {
		f, err := os.Create("cpu.prof")
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	hound, err := slamhound.New(config)
	if err != nil {
		log.Fatalf("failed to create scanner: %v", err)
	}

	for _, target := range args {
		var (
			results []slamhound.Result
			err     error
		)

		fi, err := os.Stat(target)
		if err != nil {
			log.Fatal(err)
		}
		switch mode := fi.Mode(); {
		case mode.IsDir():
			results, err = hound.ScanDirectory(target)
		case mode.IsRegular():
			results, err = hound.ScanArchive(target)
		default:
			log.Fatalf("cannot scan non-directories or non-files")
		}

		if err != nil {
			log.Fatalf("error while scanning: %v", err)
		}
		for _, result := range results {
			result.LogResult()
		}
	}

	if config.EnableMemProfile {
		f, err := os.Create("mem.prof")
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
}
