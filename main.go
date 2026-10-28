package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

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
	fetch := func() (*KevDatabase, error) {
		return readKevDatabase(http.DefaultClient, KevDbUrl)
	}

	if err := run(os.Stdin, os.Stdout, fetch); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer, fetch func() (*KevDatabase, error)) error {
	var report types.Report

	if err := json.NewDecoder(in).Decode(&report); err != nil {
		return fmt.Errorf("failed to decode trivy report: %w. did you use json output?", err)
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	if len(report.Results) == 0 {
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
