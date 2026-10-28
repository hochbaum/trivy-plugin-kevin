package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const reportFixture = `{
  "SchemaVersion": 2,
  "ArtifactName": "ghcr.io/christophetd/log4shell-vulnerable-app",
  "ArtifactType": "container_image",
  "Results": [
    {
      "Target": "app.jar",
      "Class": "lang-pkgs",
      "Type": "jar",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": "org.apache.logging.log4j:log4j-core", "InstalledVersion": "2.14.1", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-2021-45046", "PkgName": "org.apache.logging.log4j:log4j-core", "InstalledVersion": "2.14.1", "Severity": "CRITICAL"}
      ]
    },
    {
      "Target": "alpine 3.9",
      "Class": "os-pkgs",
      "Type": "alpine"
    }
  ]
}`

func testDB(vulns ...KevVulnerability) *KevDatabase {
	db := &KevDatabase{Vulnerabilities: vulns}
	db.createLookup()
	return db
}

func fetchDB(db *KevDatabase) func() (*KevDatabase, error) {
	return func() (*KevDatabase, error) { return db, nil }
}

func vuln(id string) types.DetectedVulnerability {
	return types.DetectedVulnerability{VulnerabilityID: id}
}

func TestEnrich(t *testing.T) {
	log4shell := KevVulnerability{CveID: "CVE-2021-44228", Product: "Log4j2", Cwes: []string{"CWE-502"}}
	heartbleed := KevVulnerability{CveID: "CVE-2014-0160", Product: "OpenSSL"}
	db := testDB(log4shell, heartbleed)

	report := types.Report{
		ArtifactName: "image",
		Results: types.Results{
			{Target: "a", Vulnerabilities: []types.DetectedVulnerability{
				vuln("CVE-2021-44228"),
				vuln("CVE-2099-0001"),
				vuln("CVE-2014-0160"),
			}},
			{Target: "b"},
		},
	}

	got := enrich(report, db)

	assert.Equal(t, "image", got.ArtifactName)
	require.Len(t, got.Results, 2)

	a := got.Results[0]
	assert.Equal(t, "a", a.Target)
	require.Len(t, a.Vulnerabilities, 3)
	assert.Equal(t, "CVE-2021-44228", a.Vulnerabilities[0].VulnerabilityID)
	assert.Equal(t, &log4shell, a.Vulnerabilities[0].KEV)
	assert.Equal(t, "CVE-2099-0001", a.Vulnerabilities[1].VulnerabilityID)
	assert.Nil(t, a.Vulnerabilities[1].KEV, "unknown CVE must not be enriched")
	assert.Equal(t, &heartbleed, a.Vulnerabilities[2].KEV)

	b := got.Results[1]
	assert.Equal(t, "b", b.Target)
	assert.Empty(t, b.Vulnerabilities)
}

func TestEnrichSameCVEGetsIndependentCopies(t *testing.T) {
	db := testDB(KevVulnerability{CveID: "CVE-2021-44228", Product: "Log4j2"})
	report := types.Report{Results: types.Results{
		{Vulnerabilities: []types.DetectedVulnerability{vuln("CVE-2021-44228"), vuln("CVE-2021-44228")}},
	}}

	got := enrich(report, db)

	first, second := got.Results[0].Vulnerabilities[0].KEV, got.Results[0].Vulnerabilities[1].KEV
	require.NotNil(t, first)
	require.NotNil(t, second)
	assert.NotSame(t, first, second)

	first.Product = "mutated"
	assert.Equal(t, "Log4j2", second.Product)
	assert.Equal(t, "Log4j2", db.lookup["CVE-2021-44228"].Product, "lookup must not be mutated through the result")
}

func TestEnrichEmptyDatabase(t *testing.T) {
	report := types.Report{Results: types.Results{
		{Vulnerabilities: []types.DetectedVulnerability{vuln("CVE-2021-44228")}},
	}}

	got := enrich(report, testDB())

	assert.Nil(t, got.Results[0].Vulnerabilities[0].KEV)
}

func TestRun(t *testing.T) {
	db := testDB(KevVulnerability{
		CveID:         "CVE-2021-44228",
		VendorProject: "Apache",
		Product:       "Log4j2",
		Cwes:          []string{"CWE-20", "CWE-400", "CWE-502"},
	})

	var out bytes.Buffer
	require.NoError(t, run(strings.NewReader(reportFixture), &out, fetchDB(db)))

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))

	assert.EqualValues(t, 2, got["SchemaVersion"])
	assert.Equal(t, "ghcr.io/christophetd/log4shell-vulnerable-app", got["ArtifactName"])

	results := got["Results"].([]any)
	require.Len(t, results, 2)

	jar := results[0].(map[string]any)
	assert.Equal(t, "app.jar", jar["Target"])
	vulns := jar["Vulnerabilities"].([]any)
	require.Len(t, vulns, 2)

	log4shell := vulns[0].(map[string]any)
	assert.Equal(t, "CVE-2021-44228", log4shell["VulnerabilityID"])
	assert.Equal(t, "org.apache.logging.log4j:log4j-core", log4shell["PkgName"])
	assert.Equal(t, "2.14.1", log4shell["InstalledVersion"])
	assert.Equal(t, map[string]any{
		"cveID":                      "CVE-2021-44228",
		"vendorProject":              "Apache",
		"product":                    "Log4j2",
		"vulnerabilityName":          "",
		"dateAdded":                  "",
		"shortDescription":           "",
		"requiredAction":             "",
		"dueDate":                    "",
		"knownRansomwareCampaignUse": "",
		"forensicTriage":             "",
		"notes":                      "",
		"cwes":                       []any{"CWE-20", "CWE-400", "CWE-502"},
	}, log4shell["KEV"])

	other := vulns[1].(map[string]any)
	assert.Equal(t, "CVE-2021-45046", other["VulnerabilityID"])
	assert.NotContains(t, other, "KEV", "KEV node is omitted when not found")

	alpine := results[1].(map[string]any)
	assert.Equal(t, "alpine 3.9", alpine["Target"])
	assert.NotContains(t, alpine, "Vulnerabilities", "empty vulnerabilities are omitted")

	assert.True(t, strings.HasPrefix(out.String(), "{\n  \""), "output is indented")
}

func TestRunWithoutResultsSkipsFetch(t *testing.T) {
	input := `{"SchemaVersion": 2, "ArtifactName": "scratch"}`
	fetch := func() (*KevDatabase, error) {
		t.Fatal("kev database must not be fetched when there are no results")
		return nil, nil
	}

	var out bytes.Buffer
	require.NoError(t, run(strings.NewReader(input), &out, fetch))

	assert.JSONEq(t, input, out.String())
	assert.Equal(t, "{\n  \"SchemaVersion\": 2,\n  \"ArtifactName\": \"scratch\"\n}\n", out.String(), "output is indented")
}

func TestRunInvalidReport(t *testing.T) {
	tests := map[string]string{
		"not json":      "this is a table, not json",
		"empty input":   "",
		"wrong type":    `{"Results": "nope"}`,
		"truncated doc": `{"Results": [`,
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(strings.NewReader(input), &out, fetchDB(testDB()))

			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to decode trivy report")
			assert.Contains(t, err.Error(), "did you use json output?")
			assert.Empty(t, out.String())
		})
	}
}

func TestRunFetchError(t *testing.T) {
	fetchErr := errors.New("boom")
	fetch := func() (*KevDatabase, error) { return nil, fetchErr }

	var out bytes.Buffer
	err := run(strings.NewReader(reportFixture), &out, fetch)

	require.ErrorIs(t, err, fetchErr)
	assert.Contains(t, err.Error(), "failed to retrieve kev database")
	assert.Empty(t, out.String())
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRunWriteError(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "without results", input: `{"ArtifactName": "scratch"}`, wantErr: "failed to encode trivy report"},
		{name: "with results", input: reportFixture, wantErr: "failed to encode enriched trivy report"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(strings.NewReader(tt.input), failingWriter{}, fetchDB(testDB()))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Contains(t, err.Error(), "disk full")
		})
	}
}
