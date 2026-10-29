# Kevin

Kevin is a Trivy plugin that enriches JSON scan results with data from the Known Exploited Vulnerability (KEV) database.
It fetches the KEV database and attaches the respective status to each vulnerability, if found.

## Installation

Until the plugin is available in the Trivy plugin registry, you can install it manually:
```shell
make
make install
```

Note that at this time, this is a toy plugin. Support for multiple platforms will be added later.

## Usage

Tell Trivy to use the plugin:

```shell
trivy image -f json --output plugin=kevin ghcr.io/christophetd/log4shell-vulnerable-app
```

You will then notice that the vulnerabilities are enriched with a `KEV` node, indicating whether the vulnerability is known to be exploited or not and containing additional information from the KEV database:

```json
  "KEV": {
    "cveID": "CVE-2021-44228",
    "vendorProject": "Apache",
    "product": "Log4j2",
    "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
    "dateAdded": "2021-12-10",
    "shortDescription": "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.",
    "requiredAction": "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.",
    "dueDate": "2021-12-24",
    "knownRansomwareCampaignUse": "Known",
    "forensicTriage": "No",
    "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    "cwes": [
      "CWE-20",
      "CWE-400",
      "CWE-502"
    ]
  }
```

## Offline usage

To enrich scan results without an internet connection, point the plugin at a local copy of the KEV database using `--kev-db` (passed through Trivy's `--output-plugin-arg`):

```shell
curl -fsSL -o kev.json https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/known_exploited_vulnerabilities.json
trivy image -f json --output plugin=kevin --output-plugin-arg "--kev-db ./kev.json" ghcr.io/christophetd/log4shell-vulnerable-app
```

The local file must use the same JSON schema as the online catalog. When `--kev-db` is set, the online catalog is never fetched: if the file is missing, unreadable, or invalid, the plugin exits with an error. Without `--kev-db`, the plugin fetches the online catalog as before.