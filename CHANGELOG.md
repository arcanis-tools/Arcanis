# Changelog

## v5.1.2 (2026-02-16)
### New Features
- **WAF oscillation fix** — 90-second cooldown prevents stealth↔resume bouncing
- **Deep stealth escalation** — drops to 1 worker / 0.5 req/s when WAF persists
- **Smart retry backoff** — stealth mode reduces retries, skips heavily-blocked domains
- **WAF intelligence summary** — block rate, scan efficiency, recommendations in output
- **PDF 4-engine fallback** — weasyprint → wkhtmltopdf → chromium → xhtml2pdf
- **Premium banner** — 256-color gradient, Unicode frame, hex signature

### Bug Fixes
- Fixed Top Targets showing empty modules (smart_modules key mismatch)
- Cautious WAF recovery for heavy targets (50+ blocks → 33% worker recovery)

## v5.1.1 (2026-02-16)
### New Features
- WAF adaptive intelligence (auto-stealth under 403 pressure)
- Exploit path suggestions with probability scoring
- Differential scanning (`--diff` mode)
- Progress ETA with live retry/WAF counters
- Early exit intelligence for low-value sites
- Smart no-findings report with attack surface guidance
- HTML finding deduplication by value hash
- Auto-scope warning for external domains
- Supply chain inventory table in HTML reports

### Bug Fixes
- Source map deduplication (88→4 findings)
- SRI missing deduplication (90→5 findings)
- Stack trace prevention in PDF generation
- Database None handling in getattr() calls

## v5.0.0 (2026-01-28)
- Initial release
- 90+ secret patterns, 50+ API verifiers
- 13 scanning modules
- 6-factor confidence scoring (0-100)
- SmartRouter asset classification
- Subdomain recon (CT logs + DNS)
- SQLite persistence
- HTML/PDF/JSON/SARIF output
- CI/CD generators (GitHub Actions, GitLab CI, pre-commit)
