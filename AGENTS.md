# AGENTS.md — trivy-plugin-kevin

## What this is
Kevin is a Trivy plugin (GPL-3.0) that enriches Trivy JSON scan results with
CISA KEV (Known Exploited Vulnerabilities) data. Trivy pipes a JSON report to
the plugin's stdin; the plugin writes the enriched report to stdout.
Usage: `trivy image -f json --output plugin=kevin <image>`

## Layout
- `main.go` — pipeline: `run(in, out, fetch)` decodes a trivy `types.Report`
  from stdin, fetches the KEV DB (only when `Results` is non-empty), and
  `enrich()` attaches a `KEV` node per vulnerability. `main()` wires real
  stdin/stdout/HTTP.
- `kev.go` — KEV schema (`KevVulnerability`, `KevDatabase`), `createLookup()`
  (map keyed by CVE ID), `readKevDatabase(client, url)`.
- `main_test.go`, `kev_test.go` — tests (testify, table-driven, httptest).
- `plugin.yaml` — Trivy plugin manifest (name `kevin`, linux/amd64 only for now).
- `Makefile` — `make` builds `dist/trivy-plugin-kevin.tar.gz`, `make install`
  installs it via `trivy plugin install dist/`, `make clean` removes `dist/`.

## Commands
- Build: `make` (uses `CGO_ENABLED=0 go build ./...`)
- Test: `go test ./...`
- Vet/fmt: `go vet ./...`, `gofmt -l .`
- Install locally: `make && make install`
- Manual smoke test: `trivy image -f json --output plugin=kevin ghcr.io/christophetd/log4shell-vulnerable-app`

## Conventions & invariants
- Keep output a valid Trivy report: embed `types.Report`/`types.Result`/
  `types.DetectedVulnerability` (see `Enriched*` types); don't redefine the
  schema. Encode with 2-space indent.
- The `KEV` node uses `json:"KEV,omitempty"` — omit it for CVEs not in the DB.
- Give each enriched vulnerability an independent copy of the KEV entry
  (value semantics) so callers can't mutate the lookup through results.
- Do NOT fetch the KEV DB when the report has no `Results` (pass through as-is).
- Wrap errors with `fmt.Errorf("...: %w", err)` and add actionable hints
  (e.g. "did you use json output?").
- Tests: testify (`assert`/`require`), table-driven, `httptest` servers,
  inline JSON fixtures, inject dependencies as function params (see `fetch`).
- `KevDbUrl` must stay on the GitHub mirror of cisagov/kev-data: CISA's own
  download endpoint blocks headless/proxied requests (see code comment).

## Notes
- Toy plugin: only linux/amd64 in `plugin.yaml` for now; multi-platform later.
