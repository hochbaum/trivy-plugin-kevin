package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	// KevDbUrl points to the GitHub mirror of CISA.
	// This cannot point to the official download of CISA as its proxy prevents headless downloads.
	KevDbUrl = "https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/known_exploited_vulnerabilities.json"
)

type KevVulnerability struct {
	CveID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	ForensicTriage             string   `json:"forensicTriage"`
	Notes                      string   `json:"notes"`
	Cwes                       []string `json:"cwes"`
}

type KevDatabase struct {
	Title           string             `json:"title"`
	CatalogVersion  string             `json:"catalogVersion"`
	DateReleased    time.Time          `json:"dateReleased"`
	Count           int                `json:"count"`
	Vulnerabilities []KevVulnerability `json:"vulnerabilities"`

	lookup map[string]KevVulnerability
}

func (db *KevDatabase) createLookup() {
	db.lookup = make(map[string]KevVulnerability)
	for _, vuln := range db.Vulnerabilities {
		db.lookup[vuln.CveID] = vuln
	}
}

func readKevDatabase(client *http.Client, url string) (*KevDatabase, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	return decodeKevDatabase(resp.Body)
}

func decodeKevDatabase(r io.Reader) (*KevDatabase, error) {
	const maxKevDbSize = 10 * 1024 * 1024
	db := new(KevDatabase)
	limitReader := io.LimitReader(r, maxKevDbSize)
	return db, json.NewDecoder(limitReader).Decode(db)
}

func readKevDatabaseFromFile(path string) (*KevDatabase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open local kev database %q: %w", path, err)
	}
	defer f.Close()

	db, err := decodeKevDatabase(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse local kev database %q: %w", path, err)
	}
	return db, nil
}
