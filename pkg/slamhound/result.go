package slamhound

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// MatchInfo holds the namespace and identifier of a matched rule
type MatchInfo struct {
	Namespace  string
	Identifier string
}

// Result is a struct containing the results of scanning a file
type Result struct {
	Path    string      `json:"path"`
	Matches []MatchInfo `json:"matches"`
	Err     error       `json:"error,omitempty"`
}

// FormatMatches returns a slice of strings corresponding to the matched
// namespaced rules
func (r *Result) FormatMatches() []string {
	var formatted []string
	for _, match := range r.Matches {
		f := fmt.Sprintf("%s.%s", match.Namespace, match.Identifier)
		formatted = append(formatted, f)
	}
	return formatted
}

// MarshalJSON marshals a Result into JSON
func (r *Result) MarshalJSON() ([]byte, error) {
	type Alias Result
	aux := &struct {
		*Alias
		Matches []string `json:"matches"`
		Error   string   `json:"error,omitempty"`
	}{
		Alias:   (*Alias)(r),
		Matches: r.FormatMatches(),
	}
	if r.Err != nil {
		aux.Error = r.Err.Error()
	}
	return json.Marshal(aux)
}

// LogResult prints the result, showing matches for a particular filepath
func (r *Result) LogResult() {
	if r.Err == nil {
		if len(r.Matches) > 0 {
			slog.Info("match",
				"path", r.Path,
				"matches", r.FormatMatches(),
			)
		}
	} else {
		slog.Error("scan error", "error", r.Err)
	}
}
