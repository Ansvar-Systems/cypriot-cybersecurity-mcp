# Data Coverage

This document describes the corpus covered by the Cypriot Cybersecurity MCP server.

## Sources

### CSIRT-CY — Cyprus Computer Security Incident Response Team

| Field | Value |
|-------|-------|
| **Authority** | CSIRT-CY / Digital Security Authority of Cyprus |
| **URL** | https://www.csirt.cy/ |
| **Scope** | Cybersecurity guidelines, national strategy documents, NIS2 implementation guidance, security advisories, and incident alerts |
| **License** | Public domain / government publication |
| **Language** | Greek and English |
| **Ingestion method** | Web crawler (`scripts/ingest-csirt-cy.ts`) |
| **Update frequency** | Monthly via GitHub Actions (`check-updates.yml`) |

## Document Types

| Type | Description |
|------|-------------|
| `directive` | EU directives as transposed into Cypriot law (e.g., NIS2) |
| `guideline` | CSIRT-CY technical guidelines and best practices |
| `standard` | Referenced cybersecurity standards |
| `recommendation` | CSIRT-CY recommendations for operators and citizens |

## Series

| Series ID | Description |
|-----------|-------------|
| `NIS2` | NIS2 Directive implementation guidance for Cyprus |
| `CSIRT-CY-guideline` | Official CSIRT-CY technical guidance documents |
| `national-strategy` | Cyprus National Cybersecurity Strategy documents |

## Known Limitations

- Coverage depends on the ingestion crawler's ability to access and parse CSIRT-CY publications
- Not all historical documents may be included
- Some documents may be available only in Greek
- This is a research tool — not a substitute for consulting primary sources directly at https://www.csirt.cy/

## Freshness

Use the `cy_cyber_check_data_freshness` tool to inspect record counts and latest ingestion dates at runtime.

See [data/coverage.json](data/coverage.json) for machine-readable coverage metadata.
