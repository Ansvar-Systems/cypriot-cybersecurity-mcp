/**
 * Seed the CSIRT-CY database with sample guidance and advisories.
 * Usage: npx tsx scripts/seed-sample.ts [--force]
 */
import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["CSIRTCY_DB_PATH"] ?? "data/csirt-cy.db";
const force = process.argv.includes("--force");
const dir = dirname(DB_PATH);
if (!existsSync(dir)) { mkdirSync(dir, { recursive: true }); }
if (force && existsSync(DB_PATH)) { unlinkSync(DB_PATH); console.log(`Deleted ${DB_PATH}`); }
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);
console.log(`Database initialised at ${DB_PATH}`);

// --- Frameworks ---
const frameworks = [
  { id: "nis2-cy", name: "NIS2 Implementation in Cyprus", name_en: "NIS2 Implementation in Cyprus", description: "Cyprus implementation of EU NIS2 Directive (2022/2555). Covers essential and important entities, incident reporting within 24h/72h, minimum cybersecurity measures, and CSIRT-CY supervisory role. Transposed via Law 89(I)/2023.", document_count: 3 },
  { id: "national-cyber-strategy", name: "Cyprus National Cybersecurity Strategy 2020-2024", name_en: "Cyprus National Cybersecurity Strategy 2020-2024", description: "Cyprus national cybersecurity strategy defining objectives for critical infrastructure protection, cyber capacity building, and public-private cooperation.", document_count: 2 },
  { id: "csirt-cy-guidance", name: "CSIRT-CY Technical Guidance", name_en: "CSIRT-CY Technical Guidance", description: "CSIRT-CY guidance series covering incident response procedures, threat intelligence, vulnerability disclosure, and cybersecurity best practices for Cypriot organisations.", document_count: 4 },
];
const insF = db.prepare("INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)");
for (const f of frameworks) insF.run(f.id, f.name, f.name_en, f.description, f.document_count);
console.log(`Inserted ${frameworks.length} frameworks`);

// --- Guidance ---
const guidance = [
  {
    reference: "CSIRT-CY-GD-2024-01", title: "NIS2 Implementation Guidance for Essential Entities in Cyprus", title_en: "NIS2 Implementation Guidance for Essential Entities in Cyprus",
    date: "2024-02-01", type: "directive", series: "NIS2",
    summary: "Practical guidance for Cypriot essential entities on NIS2 compliance obligations including risk management, incident reporting timelines, and supply chain security requirements.",
    full_text: "Cyprus transposed NIS2 Directive via Law 89(I)/2023, effective October 2024. Essential entities in Cyprus include energy, transport, banking, financial market infrastructure, health, drinking water, wastewater, digital infrastructure, ICT service management, public administration, and space sectors. Key obligations: (1) Risk management — entities must implement risk-based cybersecurity measures proportionate to risk; (2) Incident reporting — significant incidents reported to CSIRT-CY within 24 hours (early warning), detailed notification within 72 hours, final report within one month; (3) Supply chain security — entities must address ICT product and service supply chain risks; (4) Business continuity — backup management, disaster recovery, crisis management; (5) Governance — management bodies accountable for cybersecurity measures. Penalties: essential entities up to EUR 10 million or 2% of global annual turnover; important entities up to EUR 7 million or 1.4% of turnover. CSIRT-CY supervises essential entities.",
    topics: JSON.stringify(["NIS2", "essential entities", "incident reporting", "risk management"]), status: "current",
  },
  {
    reference: "CSIRT-CY-GD-2023-02", title: "Incident Response Best Practices for Cypriot Organisations", title_en: "Incident Response Best Practices for Cypriot Organisations",
    date: "2023-09-15", type: "guideline", series: "CSIRT-CY-guideline",
    summary: "CSIRT-CY practical guidance on building incident response capabilities, handling cybersecurity incidents, and coordinating with national authorities.",
    full_text: "CSIRT-CY provides free incident response assistance to public and private sector organisations in Cyprus. This guidance covers: (1) Preparation — establishing an IR team, defining roles, maintaining contact lists, deploying detection tools; (2) Detection and analysis — log monitoring, SIEM deployment, threat intelligence integration; (3) Containment — short-term containment to limit damage, long-term containment to prepare for recovery; (4) Eradication — removing malware, closing vulnerabilities, restoring from clean backups; (5) Recovery — restoring systems, monitoring for recurrence; (6) Post-incident — lessons learned, improving defences. Reporting to CSIRT-CY: call +357 22 80 90 00 or email csirt@csirt.cy for technical assistance. NIS2-regulated entities must also comply with mandatory reporting deadlines.",
    topics: JSON.stringify(["incident response", "CSIRT-CY", "cybersecurity", "reporting"]), status: "current",
  },
  {
    reference: "CY-NCSS-2020", title: "Cyprus National Cybersecurity Strategy 2020-2024", title_en: "Cyprus National Cybersecurity Strategy 2020-2024",
    date: "2020-07-01", type: "standard", series: "national-strategy",
    summary: "Cyprus five-year national cybersecurity strategy covering critical infrastructure protection, cyber capacity building, legal framework, and international cooperation.",
    full_text: "The Cyprus National Cybersecurity Strategy 2020-2024 sets out five strategic objectives: (1) Protecting critical infrastructure and government systems through risk assessments and baseline security standards; (2) Building cyber capacity through education, training, and certification programmes; (3) Developing a comprehensive legal and regulatory framework aligned with EU requirements including NIS Directive implementation; (4) Promoting public-private partnerships and information sharing; (5) Enhancing international cooperation through EU, NATO, and bilateral arrangements. The strategy established CSIRT-CY as the national CSIRT under OCECPR and designated the Ministry of Research, Innovation and Digital Policy as the competent authority.",
    topics: JSON.stringify(["national strategy", "critical infrastructure", "capacity building", "governance"]), status: "superseded",
  },
  {
    reference: "CSIRT-CY-GD-2024-03", title: "Ransomware Prevention and Recovery Guidance", title_en: "Ransomware Prevention and Recovery Guidance",
    date: "2024-04-10", type: "recommendation", series: "CSIRT-CY-guideline",
    summary: "CSIRT-CY recommendations for preventing ransomware attacks and recovering from incidents affecting Cypriot organisations.",
    full_text: "Ransomware remains a top cyber threat for Cypriot organisations. CSIRT-CY tracked a 35% increase in ransomware incidents in 2023. Prevention measures: (1) Offline backups — maintain immutable backups following 3-2-1 rule, test restoration procedures regularly; (2) Network segmentation — isolate critical systems, implement zero-trust architecture; (3) Patch management — apply security updates promptly, prioritise internet-facing systems; (4) Multi-factor authentication — enforce MFA for remote access, privileged accounts; (5) Email security — deploy anti-phishing controls, user awareness training. If ransomware strikes: do not pay ransom, isolate infected systems immediately, preserve evidence for forensic analysis, contact CSIRT-CY for technical support, report to Police Cybercrime Unit if criminal activity suspected.",
    topics: JSON.stringify(["ransomware", "backup", "incident response", "cybersecurity"]), status: "current",
  },
  {
    reference: "CSIRT-CY-GD-2023-04", title: "Cloud Security Guidelines for Cypriot Public Sector", title_en: "Cloud Security Guidelines for Cypriot Public Sector",
    date: "2023-03-01", type: "guideline", series: "CSIRT-CY-guideline",
    summary: "Guidance on securely adopting cloud services in the Cypriot public sector, aligned with ENISA cloud security recommendations and EU Cybersecurity Act.",
    full_text: "Cypriot public sector organisations increasingly adopt cloud services. This guidance aligns with ENISA Cloud Security for Smart Hospitals framework and EU cloud security recommendations. Key requirements: (1) Data classification — classify data before cloud migration, ensure personal data processing complies with GDPR; (2) Cloud provider assessment — evaluate providers' security certifications (ISO 27001, SOC 2, CSA STAR); (3) Shared responsibility model — understand what provider vs. customer is responsible for; (4) Access management — enforce MFA, privileged identity management, just-in-time access; (5) Monitoring — enable cloud provider logging, integrate with SIEM; (6) Exit strategy — ensure data portability and avoid vendor lock-in. Public sector entities handling classified information must use EU-approved cloud services or government cloud infrastructure.",
    topics: JSON.stringify(["cloud security", "public sector", "GDPR", "compliance"]), status: "current",
  },
];

const insG = db.prepare("INSERT OR IGNORE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
const insGAll = db.transaction(() => { for (const g of guidance) insG.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status); });
insGAll();
console.log(`Inserted ${guidance.length} guidance documents`);

// --- Advisories ---
const advisories = [
  {
    reference: "CSIRT-CY-2024-001", title: "Critical Vulnerability in Fortinet FortiOS SSL VPN",
    date: "2024-02-08", severity: "critical",
    affected_products: JSON.stringify(["Fortinet FortiOS", "FortiProxy"]),
    summary: "CSIRT-CY alerts on critical heap-based buffer overflow vulnerability in Fortinet FortiOS SSL VPN enabling remote code execution.",
    full_text: "CSIRT-CY issues critical alert for CVE-2024-21762, a heap-based buffer overflow in Fortinet FortiOS SSL VPN (CVSS 9.6). Unauthenticated remote attackers can execute arbitrary code via specially crafted HTTP requests. Affected versions: FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14. CSIRT-CY is aware of active exploitation targeting Cypriot organisations. Immediate actions: (1) Apply FortiOS patch 7.4.3, 7.2.7, 7.0.14, or 6.4.15; (2) If patching not immediately possible, disable SSL VPN; (3) Review authentication logs for anomalies; (4) Contact CSIRT-CY if compromise suspected.",
    cve_references: JSON.stringify(["CVE-2024-21762"]),
  },
  {
    reference: "CSIRT-CY-2023-012", title: "Business Email Compromise Targeting Cypriot Financial Sector",
    date: "2023-10-05", severity: "high",
    affected_products: JSON.stringify(["Microsoft 365", "Corporate email systems"]),
    summary: "CSIRT-CY warns of sophisticated BEC campaign targeting Cypriot financial institutions and professional services firms.",
    full_text: "CSIRT-CY has observed a surge in business email compromise (BEC) attacks targeting Cypriot financial institutions, law firms, and accountancy practices. Attackers compromise legitimate email accounts or use lookalike domains to redirect wire transfers. Tactics observed: (1) Account takeover via credential phishing followed by persistent mailbox access; (2) Thread hijacking — inserting fraudulent payment instructions into existing email conversations; (3) CEO fraud — impersonating executives to authorise urgent transfers; (4) Vendor invoice fraud — intercepting communications with suppliers. Reported losses exceed EUR 2.3 million across 8 confirmed incidents. Protective measures: enable MFA on all email accounts; verify payment changes via separate channel; implement DMARC, DKIM, SPF; train staff to recognise BEC indicators.",
    cve_references: null,
  },
  {
    reference: "CSIRT-CY-2024-005", title: "Critical Authentication Bypass in Ivanti Connect Secure",
    date: "2024-01-12", severity: "critical",
    affected_products: JSON.stringify(["Ivanti Connect Secure", "Ivanti Policy Secure"]),
    summary: "Authentication bypass chain in Ivanti Connect Secure actively exploited in the wild, enabling remote code execution without credentials.",
    full_text: "CSIRT-CY issues emergency advisory for critical vulnerability chain in Ivanti Connect Secure VPN. CVE-2023-46805 (authentication bypass) combined with CVE-2024-21887 (command injection) allows unauthenticated attackers to achieve remote code execution. Exploitation confirmed at multiple Cypriot organisations. The vulnerability has been weaponised by nation-state actors and criminal groups. Immediate actions required: (1) Apply Ivanti mitigation XML file immediately; (2) Run Ivanti Integrity Checker Tool to detect compromise; (3) If compromise detected, perform factory reset and rebuild; (4) Monitor for suspicious authentication and lateral movement; (5) Report findings to CSIRT-CY — available 24/7 at +357 22 80 90 00.",
    cve_references: JSON.stringify(["CVE-2023-46805", "CVE-2024-21887"]),
  },
];

const insA = db.prepare("INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
const insAAll = db.transaction(() => { for (const a of advisories) insA.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references); });
insAAll();
console.log(`Inserted ${advisories.length} advisories`);

const gCnt = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const aCnt = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const fCnt = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;
console.log(`\nSummary: ${fCnt} frameworks, ${gCnt} guidance, ${aCnt} advisories`);
console.log(`Done. Database ready at ${DB_PATH}`);
db.close();
