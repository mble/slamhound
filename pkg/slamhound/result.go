package slamhound

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hillu/go-yara/v4"
)

// Result is a struct containing the results of scanning a file
type Result struct {
	Path    string           `json:"path"`
	Matches []yara.MatchRule `json:"matches"`
	Err     error            `json:"error,omitempty"`
}

// FormatMatches returns a slice of strings corresponding to the matched
// namespaced rules
func (r *Result) FormatMatches() []string {
	var formatted []string
	for _, match := range r.Matches {
		f := fmt.Sprintf("%s.%s", match.Namespace, match.Rule)
		formatted = append(formatted, f)
	}
	return formatted
}

// MarshalJSON marshals a Result into JSON
func (r *Result) MarshalJSON() ([]byte, error) {
	type Alias Result
	marshalled, err := json.Marshal(&struct {
		*Alias
		Matches []string `json:"matches"`
	}{
		Alias:   (*Alias)(r),
		Matches: r.FormatMatches(),
	})

	if err != nil {
		log.Fatal(err)
	}
	return marshalled, nil
}

// LogResult prints the result, showing matches for a particular filepath
func (r *Result) LogResult() {
	if r.Err == nil {
		if len(r.Matches) > 0 {
			marshalled, err := json.Marshal(r)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("[+] %s", marshalled)
		}
	} else {
		log.Printf("error: %s.", r.Err)
	}
}
