package main

import (
	"encoding/json"
	"fmt"
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
	var report types.Report

	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to decode trivy report: %v\n", err)
		os.Exit(1)
	}

	if len(report.Results) == 0 {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to encode trivy report: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	db, err := readKevDatabase()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to retrieve kev database: %v\n", err)
		os.Exit(1)
	}

	db.createLookup()

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

	enrichedReport := EnrichedReport{
		Report:  report,
		Results: enrichedResults,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if err := enc.Encode(enrichedReport); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to encode enriched trivy report: %v\n", err)
		os.Exit(1)
	}
}
