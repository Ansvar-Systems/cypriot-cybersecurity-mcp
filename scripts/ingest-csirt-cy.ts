/**
 * CSIRT-CY / DSA Ingestion Crawler
 *
 * Scrapes the CSIRT-CY (csirt.cy) and Digital Security Authority (dsa.cy)
 * websites and populates the SQLite database with cybersecurity guidance,
 * security advisories (CVEs), and framework metadata.
 *
 * Data sources:
 *   1. CVE advisories       — csirt.cy/en/cve/{year} (paginated, per-year)
 *   2. Notifications/alerts — csirt.cy/en/alerts (paginated, 20 per page)
 *   3. DSA decisions         — dsa.cy/en/legislation/decisions (static list)
 *   4. DSA laws              — dsa.cy/en/legislation/laws (static list)
 *   5. DSA news              — dsa.cy/en/category/news (paginated)
 *
 * Usage:
 *   npx tsx scripts/ingest-csirt-cy.ts                   # full crawl
 *   npx tsx scripts/ingest-csirt-cy.ts --resume          # resume from last checkpoint
 *   npx tsx scripts/ingest-csirt-cy.ts --dry-run         # log what would be inserted
 *   npx tsx scripts/ingest-csirt-cy.ts --force           # drop and recreate DB first
 *   npx tsx scripts/ingest-csirt-cy.ts --advisories-only # only crawl CVE advisories
 *   npx tsx scripts/ingest-csirt-cy.ts --guidance-only   # only crawl guidance/notifications
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import type { AnyNode } from "domhandler";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["CSIRTCY_DB_PATH"] ?? "data/csirt-cy.db";
const PROGRESS_FILE = resolve(dirname(DB_PATH), "ingest-progress.json");

const CSIRT_BASE = "https://csirt.cy";
const DSA_BASE = "https://dsa.cy";

const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 2000;
const USER_AGENT =
  "AnsvarCSIRT-CYCrawler/1.0 (+https://ansvar.eu; compliance research)";

/** CVE year sections to crawl. CSIRT-CY groups CVEs by year. */
const CVE_YEARS = [2024, 2025, 2026];

// CLI flags
const args = process.argv.slice(2);
const force = args.includes("--force");
const dryRun = args.includes("--dry-run");
const resume = args.includes("--resume");
const advisoriesOnly = args.includes("--advisories-only");
const guidanceOnly = args.includes("--guidance-only");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string;
  full_text: string;
  cve_references: string | null;
}

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string | null;
  description: string;
  document_count: number;
}

interface Progress {
  completed_advisory_urls: string[];
  completed_guidance_urls: string[];
  completed_dsa_urls: string[];
  advisory_count: number;
  guidance_count: number;
  last_updated: string;
}

// ---------------------------------------------------------------------------
// Utility: rate-limited fetch with retry
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function rateLimitedFetch(
  url: string,
  opts?: RequestInit,
): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }

  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      lastRequestTime = Date.now();
      const resp = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
        },
        redirect: "follow",
        signal: AbortSignal.timeout(30_000),
        ...opts,
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      return resp;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      console.warn(
        `  [retry ${attempt}/${MAX_RETRIES}] ${url}: ${lastError.message}`,
      );
      if (attempt < MAX_RETRIES) {
        await sleep(RETRY_BACKOFF_MS * attempt);
      }
    }
  }
  throw lastError!;
}

async function fetchHtml(url: string): Promise<string> {
  const resp = await rateLimitedFetch(url);
  return resp.text();
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------

/**
 * Extract readable text from a cheerio element, preserving paragraph breaks.
 */
function extractText($el: cheerio.Cheerio<AnyNode>): string {
  // Replace <br> with newlines, </p> with double newlines
  const html = $el.html() ?? "";
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<\/h[1-6]>/gi, "\n\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#\d+;/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/**
 * Parse a date string from CSIRT-CY pages. Handles formats like:
 *   "13 February 2024", "30 September 2025", "04 April 2024"
 * Returns ISO date string (YYYY-MM-DD) or null.
 */
function parseDate(raw: string | undefined): string | null {
  if (!raw) return null;
  const cleaned = raw.trim();

  // Try "DD Month YYYY" format
  const match = cleaned.match(
    /(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/i,
  );
  if (match) {
    const months: Record<string, string> = {
      january: "01", february: "02", march: "03", april: "04",
      may: "05", june: "06", july: "07", august: "08",
      september: "09", october: "10", november: "11", december: "12",
    };
    const day = match[1]!.padStart(2, "0");
    const month = months[match[2]!.toLowerCase()]!;
    const year = match[3]!;
    return `${year}-${month}-${day}`;
  }

  // Try Greek month names
  const greekMonths: Record<string, string> = {
    "ιανουαρίου": "01", "φεβρουαρίου": "02", "μαρτίου": "03",
    "απριλίου": "04", "μαΐου": "05", "ιουνίου": "06",
    "ιουλίου": "07", "αυγούστου": "08", "σεπτεμβρίου": "09",
    "οκτωβρίου": "10", "νοεμβρίου": "11", "δεκεμβρίου": "12",
  };
  for (const [greekMonth, num] of Object.entries(greekMonths)) {
    const greekMatch = cleaned.match(
      new RegExp(`(\\d{1,2})\\s+${greekMonth}\\s+(\\d{4})`, "i"),
    );
    if (greekMatch) {
      const day = greekMatch[1]!.padStart(2, "0");
      return `${greekMatch[2]}-${num}-${day}`;
    }
  }

  // Fallback: try ISO format already
  if (/^\d{4}-\d{2}-\d{2}$/.test(cleaned)) return cleaned;

  return null;
}

/**
 * Extract CVE identifiers from text content.
 */
function extractCVEs(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,}/g);
  return matches ? [...new Set(matches)] : [];
}

/**
 * Derive a severity level from CVSS score or keywords in text.
 */
function deriveSeverity(text: string): string | null {
  // Check for explicit CVSS score
  const cvssMatch = text.match(/CVSS[:\s]*(\d+\.?\d*)/i);
  if (cvssMatch) {
    const score = parseFloat(cvssMatch[1]!);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }

  // Check for severity keywords
  const lower = text.toLowerCase();
  if (lower.includes("critical")) return "critical";
  if (lower.includes("high severity") || lower.includes("high risk")) return "high";
  if (lower.includes("medium severity") || lower.includes("moderate")) return "medium";
  if (lower.includes("low severity")) return "low";

  return null;
}

/**
 * Extract affected product names from advisory text.
 */
function extractAffectedProducts(title: string, text: string): string[] {
  const products: Set<string> = new Set();

  // Common product patterns in CSIRT-CY advisories
  const productPatterns = [
    /(?:in|affecting|targets?)\s+([\w\s]+(?:Server|Firewall|VPN|Browser|OS|Library|Framework|Platform|Suite|Desktop|Mobile))/gi,
    /(Microsoft\s+\w+)/gi,
    /(Google\s+Chrome)/gi,
    /(Mozilla\s+Firefox)/gi,
    /(Apple\s+(?:iOS|macOS|Safari|watchOS|tvOS))/gi,
    /(Fortinet\s+\w+)/gi,
    /(Cisco\s+\w+(?:\s+\w+)?)/gi,
    /(Ivanti\s+\w+(?:\s+\w+)?)/gi,
    /(Apache\s+\w+)/gi,
    /(WordPress(?:\s+Core)?)/gi,
    /(WinRAR)/gi,
    /(IBM\s+\w+(?:\s+\w+)?)/gi,
    /(FortiOS)/gi,
    /(WhatsApp)/gi,
    /(MongoDB)/gi,
    /(Argo\s*CD)/gi,
  ];

  const combined = `${title} ${text}`;
  for (const pattern of productPatterns) {
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(combined)) !== null) {
      const product = m[1]?.trim();
      if (product && product.length > 2) {
        products.add(product);
      }
    }
  }

  return [...products];
}

/**
 * Generate a stable reference ID from a URL slug.
 * e.g. "/en/cve/2025/cisco-asa-firewall-rce-vulnerability" -> "CSIRT-CY-CVE-2025-cisco-asa-firewall-rce"
 */
function referenceFromSlug(slug: string, prefix: string): string {
  const cleaned = slug
    .replace(/^\/+|\/+$/g, "")
    .split("/")
    .pop() ?? slug;
  // Truncate for readability
  const short = cleaned.slice(0, 60).replace(/-+$/, "");
  return `${prefix}-${short}`;
}

// ---------------------------------------------------------------------------
// Progress tracking
// ---------------------------------------------------------------------------

function loadProgress(): Progress {
  if (resume && existsSync(PROGRESS_FILE)) {
    try {
      const raw = readFileSync(PROGRESS_FILE, "utf-8");
      const p = JSON.parse(raw) as Progress;
      console.log(
        `Resuming from checkpoint (${p.last_updated}): ` +
          `${p.completed_advisory_urls.length} advisories, ` +
          `${p.completed_guidance_urls.length} guidance, ` +
          `${p.completed_dsa_urls.length} DSA docs`,
      );
      return p;
    } catch {
      console.warn("Could not parse progress file, starting fresh");
    }
  }
  return {
    completed_advisory_urls: [],
    completed_guidance_urls: [],
    completed_dsa_urls: [],
    advisory_count: 0,
    guidance_count: 0,
    last_updated: new Date().toISOString(),
  };
}

function saveProgress(progress: Progress): void {
  progress.last_updated = new Date().toISOString();
  writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2));
}

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

function initDatabase(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  if (force && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    console.log(`Deleted existing database at ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  console.log(`Database initialised at ${DB_PATH}`);
  return db;
}

// ---------------------------------------------------------------------------
// Framework definitions
// ---------------------------------------------------------------------------

const FRAMEWORKS: FrameworkRow[] = [
  {
    id: "nis2-cy",
    name: "NIS2 Implementation in Cyprus",
    name_en: "NIS2 Implementation in Cyprus",
    description:
      "Cyprus implementation of EU NIS2 Directive (2022/2555). Covers essential and " +
      "important entities, incident reporting within 24h/72h, minimum cybersecurity " +
      "measures, and CSIRT-CY supervisory role. Transposed via Law 89(I)/2020 as " +
      "amended by Law 60(I)/2025.",
    document_count: 0,
  },
  {
    id: "national-cyber-strategy",
    name: "Cyprus National Cybersecurity Strategy",
    name_en: "Cyprus National Cybersecurity Strategy",
    description:
      "Cyprus national cybersecurity strategy defining objectives for critical " +
      "infrastructure protection, cyber capacity building, public-private " +
      "cooperation, and international engagement.",
    document_count: 0,
  },
  {
    id: "csirt-cy-guidance",
    name: "CSIRT-CY Technical Guidance",
    name_en: "CSIRT-CY Technical Guidance",
    description:
      "CSIRT-CY guidance series covering incident response procedures, threat " +
      "intelligence, vulnerability disclosure, and cybersecurity best practices " +
      "for Cypriot organisations.",
    document_count: 0,
  },
  {
    id: "csirt-cy-cve",
    name: "CSIRT-CY CVE Advisories",
    name_en: "CSIRT-CY CVE Advisories",
    description:
      "Curated CVE vulnerability advisories published by CSIRT-CY, covering " +
      "critical vulnerabilities relevant to Cypriot critical infrastructure, " +
      "government systems, and the private sector.",
    document_count: 0,
  },
  {
    id: "dsa-legislation",
    name: "DSA Legislation and Decisions",
    name_en: "DSA Legislation and Decisions",
    description:
      "Legal instruments issued by the Digital Security Authority (DSA), including " +
      "laws (N.89(I)/2020), regulations, and binding decisions on security measures " +
      "for essential service operators, CII operators, and electronic communications " +
      "providers.",
    document_count: 0,
  },
];

// ---------------------------------------------------------------------------
// Crawl: CSIRT-CY CVE advisories
// ---------------------------------------------------------------------------

/**
 * Collect all CVE advisory listing links from csirt.cy/en/cve/{year}.
 * Each year page is paginated with ?start=N (10 items per page).
 */
async function collectCveListingUrls(year: number): Promise<Array<{ url: string; title: string; date: string | null }>> {
  const items: Array<{ url: string; title: string; date: string | null }> = [];
  let start = 0;
  let totalPages = 1;

  console.log(`\n--- Collecting CVE listing for ${year} ---`);

  while (true) {
    const pageUrl = `${CSIRT_BASE}/en/cve/${year}?start=${start}`;
    console.log(`  Fetching listing page: ${pageUrl}`);

    let html: string;
    try {
      html = await fetchHtml(pageUrl);
    } catch (err) {
      console.warn(`  Failed to fetch ${pageUrl}: ${err instanceof Error ? err.message : err}`);
      break;
    }

    const $ = cheerio.load(html);

    // Detect total pages from "Page X of Y" text
    const pageText = $("body").text();
    const pageMatch = pageText.match(/Page\s+\d+\s+of\s+(\d+)/i);
    if (pageMatch) {
      totalPages = parseInt(pageMatch[1]!, 10);
    }

    // Extract advisory links — each item has an h6 date + h3 title with a link
    // The links point to /en/cve/{year}/{slug}
    const cvePattern = new RegExp(`/en/cve/${year}/`);
    $("a").each((_, el) => {
      const href = $(el).attr("href");
      if (!href || !cvePattern.test(href)) return;

      const title = $(el).text().trim();
      if (!title || title.length < 5) return;

      const fullUrl = href.startsWith("http") ? href : `${CSIRT_BASE}${href}`;

      // Avoid duplicate URLs
      if (items.some((i) => i.url === fullUrl)) return;

      // Try to find the date in a preceding h6 element
      const parentEl = $(el).closest("h3, h4, div");
      const dateEl = parentEl.prev("h6").length > 0
        ? parentEl.prev("h6")
        : parentEl.prevAll("h6").first();
      const dateText = dateEl.text().trim();

      items.push({
        url: fullUrl,
        title,
        date: parseDate(dateText),
      });
    });

    const currentPage = Math.floor(start / 10) + 1;
    console.log(`  Page ${currentPage}/${totalPages}: found ${items.length} items so far`);

    if (currentPage >= totalPages) break;
    start += 10;
  }

  console.log(`  Total CVE items for ${year}: ${items.length}`);
  return items;
}

/**
 * Fetch a single CVE advisory detail page and extract content.
 */
async function fetchCveAdvisory(
  url: string,
  listTitle: string,
  listDate: string | null,
): Promise<AdvisoryRow | null> {
  let html: string;
  try {
    html = await fetchHtml(url);
  } catch (err) {
    console.warn(`  Failed to fetch advisory ${url}: ${err instanceof Error ? err.message : err}`);
    return null;
  }

  const $ = cheerio.load(html);

  // Extract title — prefer h1, fall back to h2, then listing title
  let title = $("h1").first().text().trim()
    || $("h2").first().text().trim()
    || listTitle;

  // Extract date from h6 on the page, or fall back to listing date
  let date = listDate;
  $("h6").each((_, el) => {
    const parsed = parseDate($(el).text());
    if (parsed) {
      date = parsed;
      return false; // break
    }
  });

  // Extract main content area
  const mainContent = $("main").length > 0
    ? $("main")
    : $("article").length > 0
      ? $("article")
      : $(".item-page").length > 0
        ? $(".item-page")
        : $("body");

  const fullText = extractText(mainContent);

  if (fullText.length < 50) {
    console.warn(`  Skipping ${url}: content too short (${fullText.length} chars)`);
    return null;
  }

  // Extract summary — first paragraph or first 300 chars
  const firstPara = mainContent.find("p").first().text().trim();
  const summary = firstPara && firstPara.length > 30
    ? firstPara.slice(0, 500)
    : fullText.slice(0, 300);

  // Extract CVEs, severity, affected products
  const cves = extractCVEs(fullText);
  const severity = deriveSeverity(fullText);
  const products = extractAffectedProducts(title, fullText);

  // Build reference from URL slug
  const slug = new URL(url).pathname;
  const reference = referenceFromSlug(slug, "CSIRT-CY-CVE");

  return {
    reference,
    title,
    date,
    severity,
    affected_products: products.length > 0 ? JSON.stringify(products) : null,
    summary,
    full_text: fullText,
    cve_references: cves.length > 0 ? JSON.stringify(cves) : null,
  };
}

async function crawlCveAdvisories(
  db: Database.Database,
  progress: Progress,
): Promise<number> {
  console.log("\n=== Crawling CSIRT-CY CVE Advisories ===");

  const insertStmt = db.prepare(
    `INSERT OR IGNORE INTO advisories
       (reference, title, date, severity, affected_products, summary, full_text, cve_references)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  let inserted = 0;

  for (const year of CVE_YEARS) {
    const listings = await collectCveListingUrls(year);

    for (const item of listings) {
      if (progress.completed_advisory_urls.includes(item.url)) {
        console.log(`  Skipping (already done): ${item.title}`);
        continue;
      }

      console.log(`  Fetching: ${item.title}`);

      if (dryRun) {
        console.log(`  [dry-run] Would fetch and insert: ${item.url}`);
        progress.completed_advisory_urls.push(item.url);
        continue;
      }

      const row = await fetchCveAdvisory(item.url, item.title, item.date);
      if (!row) continue;

      try {
        const result = insertStmt.run(
          row.reference, row.title, row.date, row.severity,
          row.affected_products, row.summary, row.full_text, row.cve_references,
        );
        if (result.changes > 0) {
          inserted++;
          console.log(`  Inserted: ${row.reference} — ${row.title}`);
        } else {
          console.log(`  Already exists: ${row.reference}`);
        }
      } catch (err) {
        console.warn(`  DB error for ${row.reference}: ${err instanceof Error ? err.message : err}`);
      }

      progress.completed_advisory_urls.push(item.url);
      progress.advisory_count = inserted;
      saveProgress(progress);
    }
  }

  console.log(`\nCVE advisories inserted: ${inserted}`);
  return inserted;
}

// ---------------------------------------------------------------------------
// Crawl: CSIRT-CY notifications/alerts (-> guidance table)
// ---------------------------------------------------------------------------

/**
 * Collect all notification listing links from csirt.cy/en/alerts.
 * Paginated with ?start=N (20 items per page, 19 pages).
 */
async function collectNotificationUrls(): Promise<Array<{ url: string; title: string; date: string | null }>> {
  const items: Array<{ url: string; title: string; date: string | null }> = [];
  let start = 0;
  let totalPages = 1;

  console.log("\n--- Collecting notification listings ---");

  while (true) {
    const pageUrl = `${CSIRT_BASE}/en/alerts?start=${start}`;
    console.log(`  Fetching listing page: ${pageUrl}`);

    let html: string;
    try {
      html = await fetchHtml(pageUrl);
    } catch (err) {
      console.warn(`  Failed to fetch ${pageUrl}: ${err instanceof Error ? err.message : err}`);
      break;
    }

    const $ = cheerio.load(html);

    // Detect total pages
    const pageText = $("body").text();
    const pageMatch = pageText.match(/Page\s+\d+\s+of\s+(\d+)/i);
    if (pageMatch) {
      totalPages = parseInt(pageMatch[1]!, 10);
    }

    // Extract notification links — they point to /en/notifications/{slug}
    // or /alerts/{slug} (individual alert pages, not the /en/alerts listing)
    let foundOnPage = 0;
    $("a").each((_, el) => {
      const href = $(el).attr("href");
      if (!href) return;
      // Match /en/notifications/{slug} or /alerts/{slug} individual pages
      const isNotification = href.includes("/notifications/");
      const isAlertDetail = /\/alerts\/[a-z]/.test(href) && !href.includes("/en/alerts");
      if (!isNotification && !isAlertDetail) return;
      // Skip non-article links (pagination, anchors)
      if (href.includes("?start=")) return;

      const title = $(el).text().trim();
      if (!title || title.length < 5) return;

      const fullUrl = href.startsWith("http") ? href : `${CSIRT_BASE}${href}`;
      if (items.some((i) => i.url === fullUrl)) return;

      // Find date from preceding h6
      const parentEl = $(el).closest("h3, h4, div");
      const dateEl = parentEl.prev("h6").length > 0
        ? parentEl.prev("h6")
        : parentEl.prevAll("h6").first();
      const dateText = dateEl.text().trim();

      items.push({
        url: fullUrl,
        title,
        date: parseDate(dateText),
      });
      foundOnPage++;
    });

    const currentPage = Math.floor(start / 20) + 1;
    console.log(`  Page ${currentPage}/${totalPages}: ${foundOnPage} new items (${items.length} total)`);

    if (currentPage >= totalPages) break;
    start += 20;
  }

  console.log(`  Total notifications: ${items.length}`);
  return items;
}

/**
 * Classify a notification's type and series based on its content.
 */
function classifyNotification(
  title: string,
  text: string,
): { type: string; series: string; topics: string[] } {
  const lower = (title + " " + text).toLowerCase();

  if (lower.includes("ransomware") || lower.includes("malware")) {
    return { type: "advisory", series: "csirt-cy-threat", topics: ["ransomware", "malware", "cybersecurity"] };
  }
  if (lower.includes("cve-") || lower.includes("vulnerability") || lower.includes("κενό ασφαλείας")) {
    return { type: "advisory", series: "csirt-cy-vulnerability", topics: ["vulnerability", "patch management", "cybersecurity"] };
  }
  if (lower.includes("phishing") || lower.includes("απάτ") || lower.includes("fraud") || lower.includes("bec")) {
    return { type: "advisory", series: "csirt-cy-threat", topics: ["phishing", "fraud", "social engineering"] };
  }
  if (lower.includes("nis2") || lower.includes("nis ") || lower.includes("directive") || lower.includes("οδηγία")) {
    return { type: "directive", series: "NIS2", topics: ["NIS2", "compliance", "regulation"] };
  }
  if (lower.includes("strategy") || lower.includes("στρατηγική")) {
    return { type: "standard", series: "national-strategy", topics: ["national strategy", "governance"] };
  }
  if (lower.includes("μνημόνιο") || lower.includes("cooperation") || lower.includes("memorandum")) {
    return { type: "announcement", series: "csirt-cy-cooperation", topics: ["international cooperation", "partnerships"] };
  }
  if (lower.includes("exercise") || lower.includes("drill") || lower.includes("conference") || lower.includes("συνέδριο")) {
    return { type: "announcement", series: "csirt-cy-activities", topics: ["exercises", "capacity building", "events"] };
  }
  if (lower.includes("awareness") || lower.includes("ασφάλεια") || lower.includes("safety") || lower.includes("tips")) {
    return { type: "guideline", series: "csirt-cy-awareness", topics: ["awareness", "cyber hygiene", "education"] };
  }

  return { type: "guideline", series: "csirt-cy-guideline", topics: ["cybersecurity"] };
}

/**
 * Fetch a single notification detail page and extract content.
 */
async function fetchNotification(
  url: string,
  listTitle: string,
  listDate: string | null,
): Promise<GuidanceRow | null> {
  let html: string;
  try {
    html = await fetchHtml(url);
  } catch (err) {
    console.warn(`  Failed to fetch notification ${url}: ${err instanceof Error ? err.message : err}`);
    return null;
  }

  const $ = cheerio.load(html);

  // Title
  let title = $("h1").first().text().trim()
    || $("h2").first().text().trim()
    || listTitle;

  // Date
  let date = listDate;
  $("h6").each((_, el) => {
    const parsed = parseDate($(el).text());
    if (parsed) {
      date = parsed;
      return false;
    }
  });

  // Content
  const mainContent = $("main").length > 0
    ? $("main")
    : $("article").length > 0
      ? $("article")
      : $(".item-page").length > 0
        ? $(".item-page")
        : $("body");

  const fullText = extractText(mainContent);

  if (fullText.length < 30) {
    console.warn(`  Skipping ${url}: content too short (${fullText.length} chars)`);
    return null;
  }

  // Summary
  const firstPara = mainContent.find("p").first().text().trim();
  const summary = firstPara && firstPara.length > 30
    ? firstPara.slice(0, 500)
    : fullText.slice(0, 300);

  // Classification
  const classification = classifyNotification(title, fullText);

  // Try to derive English title (CSIRT-CY sometimes has mixed Greek/English)
  const titleEn = /[a-zA-Z]{5,}/.test(title) ? title : null;

  // Reference
  const slug = new URL(url).pathname;
  const reference = referenceFromSlug(slug, "CSIRT-CY-NTF");

  return {
    reference,
    title,
    title_en: titleEn,
    date,
    type: classification.type,
    series: classification.series,
    summary,
    full_text: fullText,
    topics: JSON.stringify(classification.topics),
    status: "current",
  };
}

async function crawlNotifications(
  db: Database.Database,
  progress: Progress,
): Promise<number> {
  console.log("\n=== Crawling CSIRT-CY Notifications ===");

  const insertStmt = db.prepare(
    `INSERT OR IGNORE INTO guidance
       (reference, title, title_en, date, type, series, summary, full_text, topics, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  const listings = await collectNotificationUrls();
  let inserted = 0;

  for (const item of listings) {
    if (progress.completed_guidance_urls.includes(item.url)) {
      console.log(`  Skipping (already done): ${item.title}`);
      continue;
    }

    console.log(`  Fetching: ${item.title}`);

    if (dryRun) {
      console.log(`  [dry-run] Would fetch and insert: ${item.url}`);
      progress.completed_guidance_urls.push(item.url);
      continue;
    }

    const row = await fetchNotification(item.url, item.title, item.date);
    if (!row) continue;

    try {
      const result = insertStmt.run(
        row.reference, row.title, row.title_en, row.date, row.type,
        row.series, row.summary, row.full_text, row.topics, row.status,
      );
      if (result.changes > 0) {
        inserted++;
        console.log(`  Inserted: ${row.reference} — ${row.title}`);
      } else {
        console.log(`  Already exists: ${row.reference}`);
      }
    } catch (err) {
      console.warn(`  DB error for ${row.reference}: ${err instanceof Error ? err.message : err}`);
    }

    progress.completed_guidance_urls.push(item.url);
    progress.guidance_count = inserted;
    saveProgress(progress);
  }

  console.log(`\nNotifications inserted: ${inserted}`);
  return inserted;
}

// ---------------------------------------------------------------------------
// Crawl: DSA legislation & decisions (-> guidance table)
// ---------------------------------------------------------------------------

interface DsaDocument {
  title: string;
  reference: string;
  pdfUrl: string | null;
  type: string;
  series: string;
}

/**
 * Scrape DSA decisions page — static list, no pagination.
 */
async function collectDsaDecisions(): Promise<DsaDocument[]> {
  console.log("\n--- Collecting DSA decisions ---");
  const docs: DsaDocument[] = [];

  let html: string;
  try {
    html = await fetchHtml(`${DSA_BASE}/en/legislation/decisions`);
  } catch (err) {
    console.warn(`  Failed to fetch DSA decisions: ${err instanceof Error ? err.message : err}`);
    return docs;
  }

  const $ = cheerio.load(html);

  // Decisions are listed as text blocks with "Download File" links
  $("a").each((_, el) => {
    const href = $(el).attr("href");
    const linkText = $(el).text().trim();

    if (!href || !href.includes("/images/pdf-upload/")) return;
    if (!linkText.toLowerCase().includes("download")) return;

    // The title is in the preceding text before the download link
    const parentBlock = $(el).parent();
    const blockText = parentBlock.text().trim();

    // Extract the P.I. reference code
    const refMatch = blockText.match(/\(P\.I\.\s*([\d/]+)\)/);
    const reference = refMatch
      ? `DSA-DEC-PI-${refMatch[1]!.replace("/", "-")}`
      : `DSA-DEC-${docs.length + 1}`;

    // Title is everything before the reference code or download link
    let title = blockText
      .replace(/Download\s*File/i, "")
      .replace(/\(P\.I\.\s*[\d/]+\)/g, "")
      .replace(/\s+/g, " ")
      .trim();

    if (!title || title.length < 10) {
      // Try the preceding sibling or parent text
      title = parentBlock.prev().text().trim() || `DSA Decision ${reference}`;
    }

    const pdfUrl = href.startsWith("http") ? href : `${DSA_BASE}${href}`;

    docs.push({
      title: title.slice(0, 500),
      reference,
      pdfUrl,
      type: "decision",
      series: "dsa-decisions",
    });
  });

  console.log(`  Found ${docs.length} decisions`);
  return docs;
}

/**
 * Scrape DSA laws page — static list, no pagination.
 */
async function collectDsaLaws(): Promise<DsaDocument[]> {
  console.log("\n--- Collecting DSA laws ---");
  const docs: DsaDocument[] = [];

  let html: string;
  try {
    html = await fetchHtml(`${DSA_BASE}/en/legislation/laws`);
  } catch (err) {
    console.warn(`  Failed to fetch DSA laws: ${err instanceof Error ? err.message : err}`);
    return docs;
  }

  const $ = cheerio.load(html);

  $("a").each((_, el) => {
    const href = $(el).attr("href");
    const linkText = $(el).text().trim();

    if (!href || !href.includes("/images/pdf-upload/")) return;
    if (!linkText.toLowerCase().includes("download")) return;

    const parentBlock = $(el).parent();
    const blockText = parentBlock.text().trim();

    // Extract N.XX(I)/YYYY reference
    const refMatch = blockText.match(/N\.?\s*(\d+\([IV]+\)\/\d+)/);
    const reference = refMatch
      ? `DSA-LAW-${refMatch[1]!.replace(/[()\/]/g, "-")}`
      : `DSA-LAW-${docs.length + 1}`;

    let title = blockText
      .replace(/Download\s*File/i, "")
      .replace(/\s+/g, " ")
      .trim();

    if (!title || title.length < 10) {
      title = `DSA Law ${reference}`;
    }

    const pdfUrl = href.startsWith("http") ? href : `${DSA_BASE}${href}`;

    docs.push({
      title: title.slice(0, 500),
      reference,
      pdfUrl,
      type: "law",
      series: "dsa-laws",
    });
  });

  console.log(`  Found ${docs.length} laws`);
  return docs;
}

/**
 * Scrape DSA regulations page.
 */
async function collectDsaRegulations(): Promise<DsaDocument[]> {
  console.log("\n--- Collecting DSA regulations ---");
  const docs: DsaDocument[] = [];

  let html: string;
  try {
    html = await fetchHtml(`${DSA_BASE}/en/legislation/regulations`);
  } catch (err) {
    console.warn(`  Failed to fetch DSA regulations: ${err instanceof Error ? err.message : err}`);
    return docs;
  }

  const $ = cheerio.load(html);

  $("a").each((_, el) => {
    const href = $(el).attr("href");
    const linkText = $(el).text().trim();

    if (!href || !href.includes("/images/pdf-upload/")) return;
    if (!linkText.toLowerCase().includes("download")) return;

    const parentBlock = $(el).parent();
    const blockText = parentBlock.text().trim();

    const refMatch = blockText.match(/\(P\.I\.\s*([\d/]+)\)/);
    const reference = refMatch
      ? `DSA-REG-PI-${refMatch[1]!.replace("/", "-")}`
      : `DSA-REG-${docs.length + 1}`;

    let title = blockText
      .replace(/Download\s*File/i, "")
      .replace(/\(P\.I\.\s*[\d/]+\)/g, "")
      .replace(/\s+/g, " ")
      .trim();

    if (!title || title.length < 10) {
      title = `DSA Regulation ${reference}`;
    }

    const pdfUrl = href.startsWith("http") ? href : `${DSA_BASE}${href}`;

    docs.push({
      title: title.slice(0, 500),
      reference,
      pdfUrl,
      type: "regulation",
      series: "dsa-regulations",
    });
  });

  console.log(`  Found ${docs.length} regulations`);
  return docs;
}

/**
 * Scrape DSA news pages (paginated) for cybersecurity news/guidance.
 */
async function collectDsaNews(): Promise<Array<{ url: string; title: string; date: string | null }>> {
  const items: Array<{ url: string; title: string; date: string | null }> = [];
  let start = 0;
  let totalPages = 1;

  console.log("\n--- Collecting DSA news ---");

  while (true) {
    const pageUrl = `${DSA_BASE}/en/category/news?start=${start}`;
    console.log(`  Fetching listing page: ${pageUrl}`);

    let html: string;
    try {
      html = await fetchHtml(pageUrl);
    } catch (err) {
      console.warn(`  Failed to fetch ${pageUrl}: ${err instanceof Error ? err.message : err}`);
      break;
    }

    const $ = cheerio.load(html);

    const pageText = $("body").text();
    const pageMatch = pageText.match(/Page\s+\d+\s+of\s+(\d+)/i);
    if (pageMatch) {
      totalPages = parseInt(pageMatch[1]!, 10);
    }

    let foundOnPage = 0;
    $("a").each((_, el) => {
      const href = $(el).attr("href");
      if (!href || !href.includes("/category/news/")) return;
      if (href.includes("?start=")) return;
      // Skip the parent news page link itself
      if (href.endsWith("/category/news") || href.endsWith("/category/news/")) return;

      const title = $(el).text().trim();
      if (!title || title.length < 5) return;

      const fullUrl = href.startsWith("http") ? href : `${DSA_BASE}${href}`;
      if (items.some((i) => i.url === fullUrl)) return;

      // Try to extract date from surrounding context
      const parentEl = $(el).closest("div, li, article");
      const dateText = parentEl.find("time, .date, span").first().text().trim();

      items.push({
        url: fullUrl,
        title,
        date: parseDate(dateText),
      });
      foundOnPage++;
    });

    const currentPage = Math.floor(start / 20) + 1;
    console.log(`  Page ${currentPage}/${totalPages}: ${foundOnPage} new items (${items.length} total)`);

    if (currentPage >= totalPages) break;
    start += 20;
  }

  console.log(`  Total DSA news items: ${items.length}`);
  return items;
}

async function crawlDsaContent(
  db: Database.Database,
  progress: Progress,
): Promise<number> {
  console.log("\n=== Crawling DSA Legislation & News ===");

  const insertGuidance = db.prepare(
    `INSERT OR IGNORE INTO guidance
       (reference, title, title_en, date, type, series, summary, full_text, topics, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  let inserted = 0;

  // --- Legislation (decisions, laws, regulations) ---
  const decisions = await collectDsaDecisions();
  const laws = await collectDsaLaws();
  const regulations = await collectDsaRegulations();
  const allLegislation = [...decisions, ...laws, ...regulations];

  for (const doc of allLegislation) {
    if (progress.completed_dsa_urls.includes(doc.reference)) {
      console.log(`  Skipping (already done): ${doc.reference}`);
      continue;
    }

    console.log(`  Processing: ${doc.reference} — ${doc.title.slice(0, 80)}`);

    if (dryRun) {
      console.log(`  [dry-run] Would insert: ${doc.reference}`);
      progress.completed_dsa_urls.push(doc.reference);
      continue;
    }

    // For legislation, the title itself is the main content. PDF download URL
    // is stored in the full_text for reference since we cannot parse PDFs inline.
    const fullText = doc.pdfUrl
      ? `${doc.title}\n\nSource document available at: ${doc.pdfUrl}`
      : doc.title;

    const topics = doc.type === "law"
      ? JSON.stringify(["NIS", "cybersecurity", "legislation", "Cyprus"])
      : doc.type === "decision"
        ? JSON.stringify(["security measures", "compliance", "NIS", "Cyprus"])
        : JSON.stringify(["regulation", "cybersecurity", "Cyprus"]);

    try {
      const result = insertGuidance.run(
        doc.reference, doc.title, doc.title, null, doc.type,
        doc.series, doc.title, fullText, topics, "current",
      );
      if (result.changes > 0) {
        inserted++;
        console.log(`  Inserted: ${doc.reference}`);
      }
    } catch (err) {
      console.warn(`  DB error for ${doc.reference}: ${err instanceof Error ? err.message : err}`);
    }

    progress.completed_dsa_urls.push(doc.reference);
    saveProgress(progress);
  }

  // --- DSA News ---
  const newsItems = await collectDsaNews();

  for (const item of newsItems) {
    if (progress.completed_dsa_urls.includes(item.url)) {
      console.log(`  Skipping (already done): ${item.title}`);
      continue;
    }

    console.log(`  Fetching DSA news: ${item.title}`);

    if (dryRun) {
      console.log(`  [dry-run] Would fetch and insert: ${item.url}`);
      progress.completed_dsa_urls.push(item.url);
      continue;
    }

    let html: string;
    try {
      html = await fetchHtml(item.url);
    } catch (err) {
      console.warn(`  Failed to fetch ${item.url}: ${err instanceof Error ? err.message : err}`);
      progress.completed_dsa_urls.push(item.url);
      saveProgress(progress);
      continue;
    }

    const $ = cheerio.load(html);

    const title = $("h1").first().text().trim()
      || $("h2").first().text().trim()
      || item.title;

    // Try to extract date from the page
    let date = item.date;
    $("time, .date, h6").each((_, el) => {
      const parsed = parseDate($(el).text());
      if (parsed) {
        date = parsed;
        return false;
      }
    });

    const mainContent = $("main").length > 0
      ? $("main")
      : $("article").length > 0
        ? $("article")
        : $(".item-page").length > 0
          ? $(".item-page")
          : $("body");

    const fullText = extractText(mainContent);

    if (fullText.length < 30) {
      console.warn(`  Skipping ${item.url}: content too short`);
      progress.completed_dsa_urls.push(item.url);
      saveProgress(progress);
      continue;
    }

    const firstPara = mainContent.find("p").first().text().trim();
    const summary = firstPara && firstPara.length > 30
      ? firstPara.slice(0, 500)
      : fullText.slice(0, 300);

    const slug = new URL(item.url).pathname;
    const reference = referenceFromSlug(slug, "DSA-NEWS");
    const titleEn = /[a-zA-Z]{5,}/.test(title) ? title : null;

    try {
      const result = insertGuidance.run(
        reference, title, titleEn, date, "news",
        "dsa-news", summary, fullText,
        JSON.stringify(["DSA", "cybersecurity", "Cyprus"]), "current",
      );
      if (result.changes > 0) {
        inserted++;
        console.log(`  Inserted: ${reference} — ${title.slice(0, 60)}`);
      }
    } catch (err) {
      console.warn(`  DB error for ${reference}: ${err instanceof Error ? err.message : err}`);
    }

    progress.completed_dsa_urls.push(item.url);
    saveProgress(progress);
  }

  console.log(`\nDSA content inserted: ${inserted}`);
  return inserted;
}

// ---------------------------------------------------------------------------
// Framework document counts
// ---------------------------------------------------------------------------

function updateFrameworkCounts(db: Database.Database): void {
  console.log("\n--- Updating framework document counts ---");

  const countBySeries = db
    .prepare("SELECT series, count(*) as cnt FROM guidance GROUP BY series")
    .all() as Array<{ series: string; cnt: number }>;

  const advisoryCount = (
    db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }
  ).cnt;

  const seriesMap = new Map(countBySeries.map((r) => [r.series, r.cnt]));

  const updateStmt = db.prepare(
    "UPDATE frameworks SET document_count = ? WHERE id = ?",
  );

  // NIS2: legislation + NIS2-series guidance
  const nis2Count =
    (seriesMap.get("NIS2") ?? 0) +
    (seriesMap.get("dsa-decisions") ?? 0) +
    (seriesMap.get("dsa-laws") ?? 0) +
    (seriesMap.get("dsa-regulations") ?? 0);
  updateStmt.run(nis2Count, "nis2-cy");

  // National strategy
  updateStmt.run(seriesMap.get("national-strategy") ?? 0, "national-cyber-strategy");

  // CSIRT-CY guidance (all csirt-cy-* series)
  let csirtCount = 0;
  for (const [series, count] of seriesMap) {
    if (series.startsWith("csirt-cy-")) csirtCount += count;
  }
  updateStmt.run(csirtCount, "csirt-cy-guidance");

  // CVE advisories
  updateStmt.run(advisoryCount, "csirt-cy-cve");

  // DSA legislation
  const dsaLegCount =
    (seriesMap.get("dsa-decisions") ?? 0) +
    (seriesMap.get("dsa-laws") ?? 0) +
    (seriesMap.get("dsa-regulations") ?? 0);
  updateStmt.run(dsaLegCount, "dsa-legislation");

  console.log(
    `  Updated: nis2-cy=${nis2Count}, national-cyber-strategy=${seriesMap.get("national-strategy") ?? 0}, ` +
      `csirt-cy-guidance=${csirtCount}, csirt-cy-cve=${advisoryCount}, dsa-legislation=${dsaLegCount}`,
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("CSIRT-CY / DSA Ingestion Crawler");
  console.log("=".repeat(50));
  console.log(`Database: ${DB_PATH}`);
  console.log(`Mode: ${dryRun ? "DRY RUN" : force ? "FORCE (fresh DB)" : resume ? "RESUME" : "normal"}`);
  console.log(`Rate limit: ${RATE_LIMIT_MS}ms between requests`);
  console.log();

  const db = dryRun ? null : initDatabase();
  const progress = loadProgress();

  // Insert frameworks
  if (db && !advisoriesOnly) {
    const insF = db.prepare(
      "INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
    );
    for (const f of FRAMEWORKS) {
      insF.run(f.id, f.name, f.name_en, f.description, f.document_count);
    }
    console.log(`Inserted ${FRAMEWORKS.length} frameworks`);
  }

  let totalAdvisories = 0;
  let totalGuidance = 0;

  // Crawl CVE advisories
  if (!guidanceOnly) {
    if (db) {
      totalAdvisories = await crawlCveAdvisories(db, progress);
    } else {
      // dry-run mode — still collect URLs to show what would happen
      for (const year of CVE_YEARS) {
        const listings = await collectCveListingUrls(year);
        for (const item of listings) {
          console.log(`  [dry-run] Would fetch advisory: ${item.url}`);
        }
        totalAdvisories += listings.length;
      }
    }
  }

  // Crawl notifications and DSA content
  if (!advisoriesOnly) {
    if (db) {
      totalGuidance += await crawlNotifications(db, progress);
      totalGuidance += await crawlDsaContent(db, progress);

      // Update framework document counts
      updateFrameworkCounts(db);
    } else {
      // dry-run: collect listing URLs
      const notifications = await collectNotificationUrls();
      for (const item of notifications) {
        console.log(`  [dry-run] Would fetch notification: ${item.url}`);
      }
      totalGuidance += notifications.length;
    }
  }

  // Summary
  console.log("\n" + "=".repeat(50));
  console.log("Crawl complete");
  console.log(`  Advisories: ${totalAdvisories}`);
  console.log(`  Guidance:   ${totalGuidance}`);

  if (db) {
    const gCnt = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
    const aCnt = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
    const fCnt = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;
    console.log(`\nDatabase totals: ${fCnt} frameworks, ${gCnt} guidance, ${aCnt} advisories`);
    db.close();
  }

  // Clean up progress file on successful full run (not resume)
  if (!resume && !dryRun && existsSync(PROGRESS_FILE)) {
    unlinkSync(PROGRESS_FILE);
    console.log("Progress file cleaned up (full run complete)");
  }

  console.log(`Done. Database at ${DB_PATH}`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
