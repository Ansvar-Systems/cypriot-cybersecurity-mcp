# Tools Reference

This document describes every tool exposed by the Cypriot Cybersecurity MCP server.

All tools use the prefix `cy_cyber_` and return JSON-serialised structured data.

---

## cy_cyber_search_guidance

Full-text search across CSIRT-CY cybersecurity guidelines and technical recommendations. Covers NIS2 implementation guidance, national cybersecurity strategy documents, critical infrastructure protection guidelines, and incident response frameworks.

**Input parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `'NIS2 compliance'`, `'incident response'`, `'critical infrastructure'`) |
| `type` | string | no | Filter by document type: `directive`, `guideline`, `standard`, `recommendation` |
| `series` | string | no | Filter by series: `NIS2`, `CSIRT-CY-guideline`, `national-strategy` |
| `status` | string | no | Filter by status: `current`, `superseded`, `draft` |
| `limit` | number | no | Max results to return (default 20, max 100) |

**Returns:** Array of matching guidance documents with `reference`, `title`, `series`, `summary`, `status`, and `_meta`.

---

## cy_cyber_get_guidance

Get a specific CSIRT-CY guidance document by its reference identifier.

**Input parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | CSIRT-CY document reference (e.g., `'CSIRT-CY-GD-2024-01'`, `'CY-NIS2-2024'`) |

**Returns:** Full guidance document including `full_text`, or an error if not found.

---

## cy_cyber_search_advisories

Search CSIRT-CY security advisories and incident alerts. Returns advisories with severity ratings, affected products, and CVE references where available.

**Input parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `'critical vulnerability'`, `'ransomware'`, `'phishing'`) |
| `severity` | string | no | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | no | Max results to return (default 20, max 100) |

**Returns:** Array of matching advisories with `reference`, `title`, `severity`, `affected_products`, `cve_references`, and `_meta`.

---

## cy_cyber_get_advisory

Get a specific CSIRT-CY security advisory by its reference identifier.

**Input parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | CSIRT-CY advisory reference (e.g., `'CSIRT-CY-2024-001'`) |

**Returns:** Full advisory document including `full_text`, or an error if not found.

---

## cy_cyber_list_frameworks

List all CSIRT-CY cybersecurity frameworks covered in this MCP, including national cybersecurity strategy and NIS2 implementation framework.

**Input parameters:** None

**Returns:** Array of frameworks with `id`, `name`, `name_en`, `description`, and `document_count`.

---

## cy_cyber_about

Return metadata about this MCP server: version, data source, coverage summary, and full tool list.

**Input parameters:** None

**Returns:** Server metadata object including `name`, `version`, `description`, `data_source`, `coverage`, and `tools`.

---

## cy_cyber_list_sources

List all data sources used by this MCP server with provenance metadata: name, URL, scope, license, and known limitations.

**Input parameters:** None

**Returns:** Array of source metadata objects.

---

## cy_cyber_check_data_freshness

Check data freshness for each source. Reports record counts, latest ingested record date, and whether an update is recommended.

**Input parameters:** None

**Returns:** Array of freshness status objects per source, each including `record_count`, `latest_record_date`, and `update_recommended`.

---

## Response _meta block

Every successful tool response includes a `_meta` field:

```json
{
  "_meta": {
    "disclaimer": "This tool is not regulatory or legal advice. Verify all references against primary sources.",
    "source_url": "https://www.csirt.cy/",
    "data_age": "2024-01-15"   // only on single-document responses
  }
}
```
