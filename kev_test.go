package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const kevFixture = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.10.27",
  "dateReleased": "2026-10-27T17:02:11.6829Z",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "JNDI features do not protect against attacker-controlled endpoints.",
      "requiredAction": "Apply updates.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known",
      "forensicTriage": "No",
      "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      "cwes": ["CWE-20", "CWE-400", "CWE-502"]
    },
    {
      "cveID": "CVE-2014-0160",
      "vendorProject": "OpenSSL",
      "product": "OpenSSL",
      "vulnerabilityName": "OpenSSL Information Disclosure Vulnerability",
      "dateAdded": "2022-05-04",
      "shortDescription": "Heartbleed.",
      "requiredAction": "Apply updates.",
      "dueDate": "2022-05-25",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "",
      "cwes": ["CWE-125"]
    }
  ]
}`

func serveKev(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestReadKevDatabase(t *testing.T) {
	srv := serveKev(t, http.StatusOK, kevFixture)

	db, err := readKevDatabase(srv.Client(), srv.URL)
	require.NoError(t, err)

	assert.Equal(t, "CISA Catalog of Known Exploited Vulnerabilities", db.Title)
	assert.Equal(t, "2026.10.27", db.CatalogVersion)
	assert.Equal(t, time.Date(2026, 10, 27, 17, 2, 11, 682900000, time.UTC), db.DateReleased)
	assert.Equal(t, 2, db.Count)
	require.Len(t, db.Vulnerabilities, 2)

	assert.Equal(t, KevVulnerability{
		CveID:                      "CVE-2021-44228",
		VendorProject:              "Apache",
		Product:                    "Log4j2",
		VulnerabilityName:          "Apache Log4j2 Remote Code Execution Vulnerability",
		DateAdded:                  "2021-12-10",
		ShortDescription:           "JNDI features do not protect against attacker-controlled endpoints.",
		RequiredAction:             "Apply updates.",
		DueDate:                    "2021-12-24",
		KnownRansomwareCampaignUse: "Known",
		ForensicTriage:             "No",
		Notes:                      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
		Cwes:                       []string{"CWE-20", "CWE-400", "CWE-502"},
	}, db.Vulnerabilities[0])
	assert.Empty(t, db.Vulnerabilities[1].ForensicTriage, "missing fields decode to zero values")

	assert.Nil(t, db.lookup, "lookup is built separately by createLookup")
}

func TestReadKevDatabaseErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{name: "not found", status: http.StatusNotFound, body: "404: Not Found", wantErr: "unexpected status 404 Not Found"},
		{name: "server error", status: http.StatusInternalServerError, body: kevFixture, wantErr: "unexpected status 500 Internal Server Error"},
		{name: "invalid json", status: http.StatusOK, body: "<html>rate limited</html>", wantErr: "invalid character"},
		{name: "empty body", status: http.StatusOK, body: "", wantErr: "EOF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := serveKev(t, tt.status, tt.body)

			_, err := readKevDatabase(srv.Client(), srv.URL)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestReadKevDatabaseUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	_, err := readKevDatabase(http.DefaultClient, url)
	require.Error(t, err)
}

func TestReadKevDatabaseInvalidURL(t *testing.T) {
	_, err := readKevDatabase(http.DefaultClient, "://not a url")
	require.Error(t, err)
}

func TestCreateLookup(t *testing.T) {
	t.Run("indexes by CVE ID", func(t *testing.T) {
		db := &KevDatabase{Vulnerabilities: []KevVulnerability{
			{CveID: "CVE-2021-44228", Product: "Log4j2"},
			{CveID: "CVE-2014-0160", Product: "OpenSSL"},
		}}
		db.createLookup()

		require.Len(t, db.lookup, 2)
		assert.Equal(t, "Log4j2", db.lookup["CVE-2021-44228"].Product)
		assert.Equal(t, "OpenSSL", db.lookup["CVE-2014-0160"].Product)
		assert.NotContains(t, db.lookup, "CVE-0000-0000")
	})

	t.Run("empty database", func(t *testing.T) {
		db := &KevDatabase{}
		db.createLookup()

		assert.NotNil(t, db.lookup)
		assert.Empty(t, db.lookup)
	})

	t.Run("duplicate CVE keeps last entry", func(t *testing.T) {
		db := &KevDatabase{Vulnerabilities: []KevVulnerability{
			{CveID: "CVE-2021-44228", Product: "first"},
			{CveID: "CVE-2021-44228", Product: "second"},
		}}
		db.createLookup()

		require.Len(t, db.lookup, 1)
		assert.Equal(t, "second", db.lookup["CVE-2021-44228"].Product)
	})

	t.Run("rebuilding replaces previous lookup", func(t *testing.T) {
		db := &KevDatabase{Vulnerabilities: []KevVulnerability{{CveID: "CVE-2021-44228"}}}
		db.createLookup()
		db.Vulnerabilities = []KevVulnerability{{CveID: "CVE-2014-0160"}}
		db.createLookup()

		assert.NotContains(t, db.lookup, "CVE-2021-44228")
		assert.Contains(t, db.lookup, "CVE-2014-0160")
	})
}
