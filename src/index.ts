#!/usr/bin/env node

/**
 * Cypriot Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying CSIRT-CY (Cyprus Computer Security Incident
 * Response Team) guidelines, security advisories, and national cybersecurity
 * framework documents.
 *
 * Tool prefix: cy_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
} from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "cypriot-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "cy_cyber_search_guidance",
    description:
      "Full-text search across CSIRT-CY cybersecurity guidelines and technical recommendations. Covers NIS2 implementation guidance, national cybersecurity strategy documents, critical infrastructure protection guidelines, and incident response frameworks. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'NIS2 compliance', 'incident response', 'critical infrastructure')",
        },
        type: {
          type: "string",
          enum: ["directive", "guideline", "standard", "recommendation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["NIS2", "CSIRT-CY-guideline", "national-strategy"],
          description: "Filter by series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "cy_cyber_get_guidance",
    description:
      "Get a specific CSIRT-CY guidance document by reference (e.g., 'CSIRT-CY-GD-2024-01', 'CY-NIS2-2024').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "CSIRT-CY document reference (e.g., 'CSIRT-CY-GD-2024-01')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "cy_cyber_search_advisories",
    description:
      "Search CSIRT-CY security advisories and incident alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'critical vulnerability', 'ransomware', 'phishing')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "cy_cyber_get_advisory",
    description:
      "Get a specific CSIRT-CY security advisory by reference (e.g., 'CSIRT-CY-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "CSIRT-CY advisory reference (e.g., 'CSIRT-CY-2024-001')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "cy_cyber_list_frameworks",
    description:
      "List all CSIRT-CY cybersecurity frameworks covered in this MCP, including national cybersecurity strategy and NIS2 implementation framework.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "cy_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["directive", "guideline", "standard", "recommendation"]).optional(),
  series: z.enum(["NIS2", "CSIRT-CY-guideline", "national-strategy"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Helper ------------------------------------------------------------------

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(data, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "cy_cyber_search_guidance": {
        const parsed = SearchGuidanceArgs.parse(args);
        const results = searchGuidance({
          query: parsed.query,
          type: parsed.type,
          series: parsed.series,
          status: parsed.status,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "cy_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        return textContent(doc);
      }

      case "cy_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "cy_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        return textContent(advisory);
      }

      case "cy_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }

      case "cy_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "CSIRT-CY (Cyprus Computer Security Incident Response Team) MCP server. Provides access to Cypriot national cybersecurity guidelines, NIS2 implementation documents, and CSIRT-CY security advisories.",
          data_source: "CSIRT-CY (https://www.csirt.cy/)",
          coverage: {
            guidance: "NIS2 implementation guidance, national cybersecurity strategy, critical infrastructure protection guidelines",
            advisories: "CSIRT-CY security advisories and incident alerts",
            frameworks: "NIS2 framework, national cybersecurity strategy, CSIRT-CY guidance series",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
