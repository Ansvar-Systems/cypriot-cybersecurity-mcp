# Cypriot Cybersecurity MCP

<!-- ANSVAR-CTA-BEGIN -->
> ### ▶ Try this MCP instantly via Ansvar Gateway
> **50 free queries/day · no card required · OAuth signup at [ansvar.eu/gateway](https://ansvar.eu/gateway)**
>
> One endpoint, one OAuth signup, access from any MCP-compatible client.

### Connect

**Claude Code** (one line):

```bash
claude mcp add ansvar --transport http https://gateway.ansvar.eu/mcp
```

**Claude Desktop / Cursor** — add to `claude_desktop_config.json` (or `mcp.json`):

```json
{
  "mcpServers": {
    "ansvar": {
      "type": "url",
      "url": "https://gateway.ansvar.eu/mcp"
    }
  }
}
```

**Claude.ai** — Settings → Connectors → Add custom connector → paste `https://gateway.ansvar.eu/mcp`

First request opens an OAuth flow at [ansvar.eu/gateway](https://ansvar.eu/gateway). After signup, your client is bound to your account; tier (free / premium / team / company) determines fan-out, quota, and which downstream MCPs are reachable.

---

## Self-host this MCP

You can also clone this repo and build the corpus yourself. The schema,
fetcher, and tool implementations all live here. What is not in the repo is
the pre-built database — TDM and standards-licensing constraints on the
upstream sources mean we host the corpus on Ansvar infrastructure rather
than redistribute it as a public artifact.

Build your own: run this repo's ingestion script (entry-point varies per
repo — typically `scripts/ingest.sh`, `npm run ingest`, or `make ingest`;
check the repo root).
<!-- ANSVAR-CTA-END -->


**Cypriot cybersecurity data for AI compliance tools.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build](https://github.com/Ansvar-Systems/cypriot-cybersecurity-mcp/actions/workflows/ghcr-build.yml/badge.svg)](https://github.com/Ansvar-Systems/cypriot-cybersecurity-mcp/actions/workflows/ghcr-build.yml)

Query Cypriot cybersecurity data -- regulations, decisions, and requirements from CSIRT-CY (Digital Security Authority) -- directly from Claude, Cursor, or any MCP-compatible client.

Built by [Ansvar Systems](https://ansvar.eu) -- Stockholm, Sweden

---

## Available Tools (6)

| Tool | Description |
|------|-------------|
| `cy_cyber_search_guidance` | Full-text search across CSIRT-CY cybersecurity guidelines and technical recommendations. Covers NIS2 implementation g... |
| `cy_cyber_get_guidance` | Get a specific CSIRT-CY guidance document by reference (e.g., |
| `cy_cyber_search_advisories` | Search CSIRT-CY security advisories and incident alerts. Returns advisories with severity, affected products, and CVE... |
| `cy_cyber_get_advisory` | Get a specific CSIRT-CY security advisory by reference (e.g., |
| `cy_cyber_list_frameworks` | List all CSIRT-CY cybersecurity frameworks covered in this MCP, including national cybersecurity strategy and NIS2 im... |
| `cy_cyber_about` | Return metadata about this MCP server: version, data source, coverage, and tool list. |

All tools return structured data with source references and timestamps.

---

## Data Sources and Freshness

All content is sourced from official Cypriot regulatory publications:

- **CSIRT-CY (Digital Security Authority)** -- Official regulatory authority

### Data Currency

- Database updates are periodic and may lag official publications
- Freshness checks run via GitHub Actions workflows
- Last-updated timestamps in tool responses indicate data age

See [COVERAGE.md](COVERAGE.md) for full provenance metadata.

---

## Security

This project uses multiple layers of automated security scanning:

| Scanner | What It Does | Schedule |
|---------|-------------|----------|
| **CodeQL** | Static analysis for security vulnerabilities | Weekly + PRs |
| **Semgrep** | SAST scanning (OWASP top 10, secrets, TypeScript) | Every push |
| **Gitleaks** | Secret detection across git history | Every push |
| **Trivy** | CVE scanning on filesystem and npm dependencies | Daily |
| **Docker Security** | Container image scanning + SBOM generation | Daily |
| **Socket.dev** | Supply chain attack detection | PRs |
| **Dependabot** | Automated dependency updates | Weekly |

See [SECURITY.md](SECURITY.md) for the full policy and vulnerability reporting.

---

## Important Disclaimers

### Not Regulatory Advice

> **THIS TOOL IS NOT REGULATORY OR LEGAL ADVICE**
>
> Regulatory data is sourced from official publications by CSIRT-CY (Digital Security Authority). However:
> - This is a **research tool**, not a substitute for professional regulatory counsel
> - **Verify all references** against primary sources before making compliance decisions
> - **Coverage may be incomplete** -- do not rely solely on this for regulatory research

**Before using professionally, read:** [DISCLAIMER.md](DISCLAIMER.md) | [PRIVACY.md](PRIVACY.md)

### Confidentiality

Queries go through the Claude API. For privileged or confidential matters, use on-premise deployment. See [PRIVACY.md](PRIVACY.md) for details.

---

## Development

### Setup

```bash
git clone https://github.com/Ansvar-Systems/cypriot-cybersecurity-mcp
cd cypriot-cybersecurity-mcp
npm install
npm run build
```

### Running Locally

```bash
npm run dev                                       # Start MCP server
npx @anthropic/mcp-inspector node dist/index.js   # Test with MCP Inspector
```

### Data Management

```bash
npm run ingest   # Ingest data from CSIRT-CY
npm run seed     # Seed with sample data
```

---

## More Ansvar MCPs

Full fleet at [ansvar.eu/gateway](https://ansvar.eu/gateway).
## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache License 2.0. See [LICENSE](./LICENSE) for details.

### Data Licenses

**License code:** `Cyprus-PSI` — statutory Cyprus public-sector information re-use regime.

**Statutory basis:** Cyprus Law 143(I)/2021 transposes [EU Directive 2019/1024](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32019L1024) on Open Data and the re-use of public sector information. Article 8 of the directive mandates commercial re-use of public-sector documents.

CSIRT-CY is part of the Digital Security Authority of Cyprus, a public-sector body within scope of Law 143(I)/2021. On-publisher acknowledgement at [csirt.cy/about-us/open-information](https://csirt.cy/about-us/open-information) cites Cyprus Law 184(I)/2017 (Right of Access to Public Sector Information) and the corresponding publication scheme; re-use rights flow from the companion statute Law 143(I)/2021.

Commercial reuse, derivatives, and redistribution are permitted with attribution. See `sources.yml` for the anchored URL pattern and full provenance metadata.

Attribution: "Source: National CSIRT-CY, Digital Security Authority, Republic of Cyprus. Reproduced under Cyprus public-sector information re-use regime (Law 143(I)/2021, transposing EU Directive 2019/1024)."

---

## About Ansvar Systems

We build AI-powered compliance and legal research tools for the European market. Our MCP fleet provides structured, verified regulatory data to AI assistants -- so compliance professionals can work with accurate sources instead of guessing.

**[ansvar.eu](https://ansvar.eu)** -- Stockholm, Sweden

---

<p align="center">
  <sub>Built with care in Stockholm, Sweden</sub>
</p>
