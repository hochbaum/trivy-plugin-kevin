package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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

	db := new(KevDatabase)
	return db, json.NewDecoder(resp.Body).Decode(db)
}
