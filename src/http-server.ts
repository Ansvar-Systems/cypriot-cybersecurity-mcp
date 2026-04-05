#!/usr/bin/env node

/**
 * HTTP Server Entry Point for Docker Deployment
 *
 * Provides Streamable HTTP transport for remote MCP clients.
 * Use src/index.ts for local stdio-based usage.
 *
 * Endpoints:
 *   GET  /health  — liveness probe
 *   POST /mcp     — MCP Streamable HTTP (session-aware)
 */

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
  getDb,
} from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = parseInt(process.env["PORT"] ?? "3000", 10);
const SERVER_NAME = "cypriot-cybersecurity-mcp";

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback
}

// --- Tool definitions (shared with index.ts) ---------------------------------

const TOOLS = [
  {
    name: "cy_cyber_search_guidance",
    description:
      "Full-text search across CSIRT-CY cybersecurity guidelines and technical recommendations. Covers NIS2 implementation guidance, national cybersecurity strategy documents, critical infrastructure protection guidelines, and incident response frameworks. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'NIS2 compliance', 'incident response', 'critical infrastructure')" },
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
          description: "Filter by document status. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
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
        reference: { type: "string", description: "CSIRT-CY document reference (e.g., 'CSIRT-CY-GD-2024-01')" },
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
        query: { type: "string", description: "Search query (e.g., 'critical vulnerability', 'ransomware', 'phishing')" },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
      },
      required: ["query"],
    },
  },
  {
    name: "cy_cyber_get_advisory",
    description: "Get a specific CSIRT-CY security advisory by reference (e.g., 'CSIRT-CY-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "CSIRT-CY advisory reference (e.g., 'CSIRT-CY-2024-001')" },
      },
      required: ["reference"],
    },
  },
  {
    name: "cy_cyber_list_frameworks",
    description:
      "List all CSIRT-CY cybersecurity frameworks covered in this MCP, including national cybersecurity strategy and NIS2 implementation framework.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "cy_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "cy_cyber_list_sources",
    description: "List all data sources used by this MCP server with provenance metadata: name, URL, last ingestion date, scope, and known limitations.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "cy_cyber_check_data_freshness",
    description: "Check data freshness for each source. Reports the ingestion date, estimated staleness, and whether an update is recommended.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
];

// --- Zod schemas -------------------------------------------------------------

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

// --- MCP server factory ------------------------------------------------------

function createMcpServer(): Server {
  const server = new Server(
    { name: SERVER_NAME, version: pkgVersion },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    function textContent(data: unknown) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
      };
    }

    function errorContent(message: string) {
      return {
        content: [{ type: "text" as const, text: message }],
        isError: true as const,
      };
    }

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
          return textContent({
            results,
            count: results.length,
            _meta: {
              disclaimer: "This tool is not regulatory or legal advice. Verify all references against primary sources.",
              source_url: "https://www.csirt.cy/",
            },
          });
        }

        case "cy_cyber_get_guidance": {
          const parsed = GetGuidanceArgs.parse(args);
          const doc = getGuidance(parsed.reference);
          if (!doc) {
            return errorContent(`Guidance document not found: ${parsed.reference}`);
          }
          return textContent({
            ...doc,
            _meta: {
              disclaimer: "This tool is not regulatory or legal advice. Verify all references against primary sources.",
              source_url: "https://www.csirt.cy/",
              data_age: doc.date ?? "unknown",
            },
          });
        }

        case "cy_cyber_search_advisories": {
          const parsed = SearchAdvisoriesArgs.parse(args);
          const results = searchAdvisories({
            query: parsed.query,
            severity: parsed.severity,
            limit: parsed.limit,
          });
          return textContent({
            results,
            count: results.length,
            _meta: {
              disclaimer: "This tool is not regulatory or legal advice. Verify all references against primary sources.",
              source_url: "https://www.csirt.cy/",
            },
          });
        }

        case "cy_cyber_get_advisory": {
          const parsed = GetAdvisoryArgs.parse(args);
          const advisory = getAdvisory(parsed.reference);
          if (!advisory) {
            return errorContent(`Advisory not found: ${parsed.reference}`);
          }
          return textContent({
            ...advisory,
            _meta: {
              disclaimer: "This tool is not regulatory or legal advice. Verify all references against primary sources.",
              source_url: "https://www.csirt.cy/",
              data_age: advisory.date ?? "unknown",
            },
          });
        }

        case "cy_cyber_list_frameworks": {
          const frameworks = listFrameworks();
          return textContent({
            frameworks,
            count: frameworks.length,
            _meta: {
              disclaimer: "This tool is not regulatory or legal advice. Verify all references against primary sources.",
              source_url: "https://www.csirt.cy/",
            },
          });
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
            _meta: {
              disclaimer: "This tool is not regulatory or legal advice. Verify all references against primary sources.",
              source_url: "https://www.csirt.cy/",
            },
          });
        }

        case "cy_cyber_list_sources": {
          return textContent({
            sources: [
              {
                name: "CSIRT-CY — Cyprus Computer Security Incident Response Team",
                url: "https://www.csirt.cy/",
                scope: "Cybersecurity guidelines, national strategy, NIS2 implementation, security advisories",
                license: "Public domain / government publication",
                limitations: "Coverage depends on ingestion crawler; may not include all published documents",
              },
            ],
            _meta: {
              disclaimer: "This tool is not regulatory or legal advice. Verify all references against primary sources.",
              source_url: "https://www.csirt.cy/",
            },
          });
        }

        case "cy_cyber_check_data_freshness": {
          let guidanceCount = 0;
          let advisoryCount = 0;
          let latestGuidance: string | null = null;
          let latestAdvisory: string | null = null;
          try {
            const database = getDb();
            guidanceCount = (database.prepare("SELECT COUNT(*) as c FROM guidance").get() as { c: number }).c;
            advisoryCount = (database.prepare("SELECT COUNT(*) as c FROM advisories").get() as { c: number }).c;
            latestGuidance = (database.prepare("SELECT MAX(date) as d FROM guidance").get() as { d: string | null }).d;
            latestAdvisory = (database.prepare("SELECT MAX(date) as d FROM advisories").get() as { d: string | null }).d;
          } catch {
            // db may be empty or unavailable
          }
          return textContent({
            sources: [
              {
                name: "CSIRT-CY guidance",
                record_count: guidanceCount,
                latest_record_date: latestGuidance,
                update_recommended: guidanceCount === 0,
              },
              {
                name: "CSIRT-CY advisories",
                record_count: advisoryCount,
                latest_record_date: latestAdvisory,
                update_recommended: advisoryCount === 0,
              },
            ],
            _meta: {
              disclaimer: "This tool is not regulatory or legal advice. Verify all references against primary sources.",
              source_url: "https://www.csirt.cy/",
            },
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

  return server;
}

// --- HTTP server -------------------------------------------------------------

async function main(): Promise<void> {
  const sessions = new Map<
    string,
    { transport: StreamableHTTPServerTransport; server: Server }
  >();

  const httpServer = createServer((req, res) => {
    handleRequest(req, res, sessions).catch((err) => {
      console.error(`[${SERVER_NAME}] Unhandled error:`, err);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
    });
  });

  async function handleRequest(
    req: import("node:http").IncomingMessage,
    res: import("node:http").ServerResponse,
    activeSessions: Map<
      string,
      { transport: StreamableHTTPServerTransport; server: Server }
    >,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: SERVER_NAME, version: pkgVersion }));
      return;
    }

    if (url.pathname === "/mcp") {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (sessionId && activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId)!;
        await session.transport.handleRequest(req, res);
        return;
      }

      const mcpServer = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- SDK type mismatch with exactOptionalPropertyTypes
      await mcpServer.connect(transport as any);

      transport.onclose = () => {
        if (transport.sessionId) {
          activeSessions.delete(transport.sessionId);
        }
        mcpServer.close().catch(() => {});
      };

      await transport.handleRequest(req, res);

      if (transport.sessionId) {
        activeSessions.set(transport.sessionId, { transport, server: mcpServer });
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  }

  httpServer.listen(PORT, () => {
    console.error(`${SERVER_NAME} v${pkgVersion} (HTTP) listening on port ${PORT}`);
    console.error(`MCP endpoint:  http://localhost:${PORT}/mcp`);
    console.error(`Health check:  http://localhost:${PORT}/health`);
  });

  process.on("SIGTERM", () => {
    console.error("Received SIGTERM, shutting down...");
    httpServer.close(() => process.exit(0));
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
