package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/aquasecurity/trivy/pkg/types"
)

type EnrichedVulnerability struct {
	types.DetectedVulnerability
	KEV *KevVulnerability `json:"KEV,omitempty"`
}

type EnrichedResult struct {
	types.Result
	Vulnerabilities []EnrichedVulnerability `json:"Vulnerabilities,omitempty"`
}

type EnrichedReport struct {
	types.Report
	Results []EnrichedResult `json:"Results,omitempty"`
}

func main() {
	kevDBPath, err := parseArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(os.Stdout)
			return
		}
		_, _ = fmt.Fprintln(os.Stderr, err)
		printUsage(os.Stderr)
		os.Exit(2)
	}

	if err := run(os.Stdin, os.Stdout, fetchFunc(kevDBPath)); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("trivy-plugin-kevin", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	kevDB := fs.String("kev-db", "", "path to a local KEV database JSON file; when set, the online catalog is not fetched")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() > 0 {
		return "", fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "kev-db" {
			set = true
		}
	})
	if set && *kevDB == "" {
		return "", errors.New("--kev-db requires a non-empty path")
	}
	return *kevDB, nil
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, "usage: trivy-plugin-kevin [--kev-db <path>]\n\n")
	_, _ = fmt.Fprintln(w, "Reads a Trivy JSON report from stdin and writes the report enriched")
	_, _ = fmt.Fprintln(w, "with KEV (Known Exploited Vulnerabilities) data to stdout.")
	_, _ = fmt.Fprintln(w, "\nflags:")
	_, _ = fmt.Fprintln(w, "  --kev-db <path>   use a local KEV database JSON file instead of fetching the online catalog")
}

func fetchFunc(kevDBPath string) func() (*KevDatabase, error) {
	if kevDBPath != "" {
		return func() (*KevDatabase, error) {
			return readKevDatabaseFromFile(kevDBPath)
		}
	}

	client := &http.Client{Timeout: time.Second * 10}
	return func() (*KevDatabase, error) {
		return readKevDatabase(client, KevDbUrl)
	}
}

func hasVulnerability(report types.Report) bool {
	return slices.ContainsFunc(report.Results, func(r types.Result) bool {
		return len(r.Vulnerabilities) > 0
	})
}

func run(in io.Reader, out io.Writer, fetch func() (*KevDatabase, error)) error {
	var report types.Report

	if err := json.NewDecoder(in).Decode(&report); err != nil {
		return fmt.Errorf("failed to decode trivy report: %w. did you use json output?", err)
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	// skip fetching the database if no vulnerability is present
	if !hasVulnerability(report) {
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("failed to encode trivy report: %w", err)
		}
		return nil
	}

	db, err := fetch()
	if err != nil {
		return fmt.Errorf("failed to retrieve kev database: %w", err)
	}

	db.createLookup()

	if err := enc.Encode(enrich(report, db)); err != nil {
		return fmt.Errorf("failed to encode enriched trivy report: %w", err)
	}
	return nil
}

func enrich(report types.Report, db *KevDatabase) EnrichedReport {
	enrichedResults := make([]EnrichedResult, len(report.Results))
	for i, result := range report.Results {
		enrichedResults[i] = EnrichedResult{
			Result:          result,
			Vulnerabilities: make([]EnrichedVulnerability, len(result.Vulnerabilities)),
		}
		for j, vuln := range result.Vulnerabilities {
			enrichedResults[i].Vulnerabilities[j] = EnrichedVulnerability{
				DetectedVulnerability: vuln,
			}
			id := vuln.VulnerabilityID
			if kevVuln, ok := db.lookup[id]; ok {
				enrichedResults[i].Vulnerabilities[j].KEV = &kevVuln
			}
		}
	}

	return EnrichedReport{
		Report:  report,
		Results: enrichedResults,
	}
}
