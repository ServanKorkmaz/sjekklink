var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc2) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc2 = __getOwnPropDesc(from, key)) || desc2.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  apiUsage: () => apiUsage,
  insertApiUsageSchema: () => insertApiUsageSchema,
  insertScanResultSchema: () => insertScanResultSchema,
  scanResults: () => scanResults,
  sessions: () => sessions,
  users: () => users
});
import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, jsonb, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
var sessions, users, scanResults, apiUsage, insertScanResultSchema, insertApiUsageSchema;
var init_schema = __esm({
  "shared/schema.ts"() {
    "use strict";
    sessions = pgTable(
      "sessions",
      {
        sid: varchar("sid").primaryKey(),
        sess: jsonb("sess").notNull(),
        expire: timestamp("expire").notNull()
      },
      (table) => [index("IDX_session_expire").on(table.expire)]
    );
    users = pgTable("users", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      email: varchar("email").unique(),
      firstName: varchar("first_name"),
      lastName: varchar("last_name"),
      profileImageUrl: varchar("profile_image_url"),
      createdAt: timestamp("created_at").defaultNow(),
      updatedAt: timestamp("updated_at").defaultNow()
    });
    scanResults = pgTable("scan_results", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      url: text("url"),
      fileHash: text("file_hash"),
      fileName: text("file_name"),
      fileSize: integer("file_size"),
      scanType: text("scan_type").notNull(),
      // 'url' or 'file'
      riskScore: integer("risk_score").notNull(),
      verdict: text("verdict").notNull(),
      // 'safe', 'suspicious', 'malicious'
      reasons: jsonb("reasons").$type().notNull(),
      metadata: jsonb("metadata").$type(),
      createdAt: timestamp("created_at").defaultNow().notNull(),
      updatedAt: timestamp("updated_at").defaultNow().notNull()
    });
    apiUsage = pgTable("api_usage", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      endpoint: text("endpoint").notNull(),
      ipAddress: text("ip_address"),
      userAgent: text("user_agent"),
      requestCount: integer("request_count").notNull().default(1),
      createdAt: timestamp("created_at").defaultNow().notNull()
    });
    insertScanResultSchema = createInsertSchema(scanResults).omit({
      id: true,
      createdAt: true,
      updatedAt: true
    });
    insertApiUsageSchema = createInsertSchema(apiUsage).omit({
      id: true,
      createdAt: true
    });
  }
});

// server/db.ts
var db_exports = {};
__export(db_exports, {
  db: () => db,
  pool: () => pool
});
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
var pool, db;
var init_db = __esm({
  "server/db.ts"() {
    "use strict";
    init_schema();
    neonConfig.webSocketConstructor = ws;
    if (!process.env.DATABASE_URL) {
      throw new Error(
        "DATABASE_URL must be set. Did you forget to provision a database?"
      );
    }
    pool = new Pool({ connectionString: process.env.DATABASE_URL });
    db = drizzle({ client: pool, schema: schema_exports });
  }
});

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// server/storage.ts
init_schema();
import { randomUUID } from "crypto";
import { eq, desc, and } from "drizzle-orm";
var db2;
if (process.env.DATABASE_URL) {
  db2 = (init_db(), __toCommonJS(db_exports)).db;
}
var DatabaseStorage = class {
  constructor() {
  }
  async getUser(id) {
    const [user] = await db2.select().from(users).where(eq(users.id, id));
    return user || void 0;
  }
  async upsertUser(userData) {
    const [user] = await db2.insert(users).values(userData).onConflictDoUpdate({
      target: users.id,
      set: {
        ...userData,
        updatedAt: /* @__PURE__ */ new Date()
      }
    }).returning();
    return user;
  }
  async getScanResult(id) {
    const [result] = await db2.select().from(scanResults).where(eq(scanResults.id, id));
    return result || void 0;
  }
  async getScanResultByUrl(url) {
    const [result] = await db2.select().from(scanResults).where(and(
      eq(scanResults.url, url),
      eq(scanResults.scanType, "url")
    ));
    return result || void 0;
  }
  async getScanResultByFileHash(hash) {
    const [result] = await db2.select().from(scanResults).where(and(
      eq(scanResults.fileHash, hash),
      eq(scanResults.scanType, "file")
    ));
    return result || void 0;
  }
  async createScanResult(insertResult) {
    const [result] = await db2.insert(scanResults).values(insertResult).returning();
    return result;
  }
  async getRecentScans(limit = 100) {
    const results = await db2.select().from(scanResults).orderBy(desc(scanResults.createdAt)).limit(limit);
    return results;
  }
  async recordApiUsage(insertUsage) {
    const [usage] = await db2.insert(apiUsage).values(insertUsage).returning();
    return usage;
  }
  async getApiUsageStats() {
    const scans = await db2.select().from(scanResults);
    const totalScans = scans.length;
    const maliciousCount = scans.filter((s) => s.verdict === "malicious").length;
    return {
      totalScans,
      maliciousCount,
      errorRate: 2.1,
      // Mock value
      activeUsers: 1423
      // Mock value
    };
  }
};
var InMemoryStorage = class {
  users = {};
  scans = {};
  apiUsage = [];
  async getUser(id) {
    return this.users[id];
  }
  async upsertUser(userData) {
    const existing = this.users[userData.id];
    const user = {
      id: userData.id || randomUUID(),
      email: userData.email ?? null,
      firstName: userData.firstName ?? null,
      lastName: userData.lastName ?? null,
      profileImageUrl: userData.profileImageUrl ?? null,
      createdAt: existing?.createdAt || /* @__PURE__ */ new Date(),
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.users[user.id] = user;
    return user;
  }
  async getScanResult(id) {
    return this.scans[id];
  }
  async getScanResultByUrl(url) {
    return Object.values(this.scans).find((s) => s.url === url && s.scanType === "url");
  }
  async getScanResultByFileHash(hash) {
    return Object.values(this.scans).find((s) => s.fileHash === hash && s.scanType === "file");
  }
  async createScanResult(insertResult) {
    const id = randomUUID();
    const result = {
      id,
      url: insertResult.url ?? null,
      fileHash: insertResult.fileHash ?? null,
      fileName: insertResult.fileName ?? null,
      fileSize: insertResult.fileSize ?? null,
      scanType: insertResult.scanType,
      riskScore: insertResult.riskScore,
      verdict: insertResult.verdict,
      reasons: insertResult.reasons,
      metadata: insertResult.metadata ?? null,
      createdAt: /* @__PURE__ */ new Date(),
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.scans[id] = result;
    return result;
  }
  async getRecentScans(limit = 100) {
    return Object.values(this.scans).sort((a, b) => b.createdAt - a.createdAt).slice(0, limit);
  }
  async recordApiUsage(insertUsage) {
    const usage = {
      id: randomUUID(),
      endpoint: insertUsage.endpoint,
      ipAddress: insertUsage.ipAddress ?? null,
      userAgent: insertUsage.userAgent ?? null,
      requestCount: insertUsage.requestCount ?? 1,
      createdAt: /* @__PURE__ */ new Date()
    };
    this.apiUsage.push(usage);
    return usage;
  }
  async getApiUsageStats() {
    const scans = Object.values(this.scans);
    const totalScans = scans.length;
    const maliciousCount = scans.filter((s) => s.verdict === "malicious").length;
    return { totalScans, maliciousCount, errorRate: 0, activeUsers: Object.keys(this.users).length };
  }
};
var storage = process.env.DATABASE_URL ? new DatabaseStorage() : new InMemoryStorage();

// server/routes.ts
import { z } from "zod";

// client/src/lib/providers/gsb.ts
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GSB_API_KEY || "";
  if (!apiKey) {
    console.warn("Google Safe Browsing API key not configured");
    return { isSafe: true };
  }
  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client: {
          clientId: "trygglink",
          clientVersion: "1.0.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      })
    });
    const data = await response.json();
    if (data.matches && data.matches.length > 0) {
      return {
        isSafe: false,
        threatType: data.matches[0].threatType
      };
    }
    return { isSafe: true };
  } catch (error) {
    console.error("Google Safe Browsing check failed:", error);
    return { isSafe: true };
  }
}

// server/lib/abuseipdb.ts
async function checkAbuseIPDB(url) {
  const apiKey = process.env.ABUSEIPDB_API_KEY || "";
  if (!apiKey) {
    return { isAbusive: false, available: false };
  }
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    let ipAddress = domain;
    try {
      const dnsResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
      if (dnsResponse.ok) {
        const dnsData = await dnsResponse.json();
        if (dnsData.Answer && dnsData.Answer.length > 0) {
          ipAddress = dnsData.Answer[0].data;
        }
      }
    } catch (e) {
    }
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipAddress)}&maxAgeInDays=90&verbose`, {
      method: "GET",
      headers: {
        "Key": apiKey,
        "Accept": "application/json"
      }
    });
    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.status}`);
    }
    const data = await response.json();
    if (data.data && data.data.abuseConfidencePercentage > 25) {
      return {
        isAbusive: true,
        confidencePercentage: data.data.abuseConfidencePercentage,
        details: `Abuse confidence: ${data.data.abuseConfidencePercentage}%`,
        available: true
      };
    }
    return {
      isAbusive: false,
      confidencePercentage: data.data?.abuseConfidencePercentage || 0,
      available: true
    };
  } catch (error) {
    console.error("AbuseIPDB check failed:", error);
    return { isAbusive: false, available: false };
  }
}

// server/lib/virustotal.ts
import crypto from "crypto";
var VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
var VT_API_BASE = "https://www.virustotal.com/api/v3";
async function scanUrlWithVirusTotal(url) {
  if (!VT_API_KEY) {
    return {
      isSafe: true,
      maliciousCount: 0,
      suspiciousCount: 0,
      details: "API key not configured",
      available: false
    };
  }
  try {
    const formData = new URLSearchParams();
    formData.append("url", url);
    const submitResponse = await fetch(`${VT_API_BASE}/urls`, {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: formData.toString()
    });
    if (!submitResponse.ok) {
      throw new Error(`VirusTotal API error: ${submitResponse.status}`);
    }
    const submitData = await submitResponse.json();
    const analysisId = submitData.data.id;
    await new Promise((resolve) => setTimeout(resolve, 2e3));
    const analysisResponse = await fetch(`${VT_API_BASE}/analyses/${analysisId}`, {
      headers: {
        "x-apikey": VT_API_KEY
      }
    });
    if (!analysisResponse.ok) {
      throw new Error(`VirusTotal analysis error: ${analysisResponse.status}`);
    }
    const analysisData = await analysisResponse.json();
    const stats = analysisData.data.attributes.stats;
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const isSafe = maliciousCount === 0 && suspiciousCount === 0;
    let details = "No threats detected";
    if (maliciousCount > 0) {
      details = `${maliciousCount} security vendors flagged this URL as malicious`;
    } else if (suspiciousCount > 0) {
      details = `${suspiciousCount} security vendors flagged this URL as suspicious`;
    }
    return {
      isSafe,
      maliciousCount,
      suspiciousCount,
      details,
      available: true
    };
  } catch (error) {
    console.error("VirusTotal URL scan error:", error);
    return {
      isSafe: true,
      maliciousCount: 0,
      suspiciousCount: 0,
      details: error instanceof Error ? error.message : "Service unavailable",
      available: false
    };
  }
}
async function scanFileWithVirusTotal(fileBuffer, fileName) {
  if (!VT_API_KEY) {
    const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
    return {
      isSafe: true,
      maliciousCount: 0,
      suspiciousCount: 0,
      details: "API key not configured",
      available: false,
      fileHash: hash
    };
  }
  try {
    const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
    try {
      const hashCheckResponse = await fetch(`${VT_API_BASE}/files/${hash}`, {
        headers: {
          "x-apikey": VT_API_KEY
        }
      });
      if (hashCheckResponse.ok) {
        const hashData = await hashCheckResponse.json();
        const stats2 = hashData.data.attributes.stats;
        const maliciousCount2 = stats2.malicious || 0;
        const suspiciousCount2 = stats2.suspicious || 0;
        const isSafe2 = maliciousCount2 === 0 && suspiciousCount2 === 0;
        let details2 = "No threats detected";
        if (maliciousCount2 > 0) {
          details2 = `${maliciousCount2}/${Object.keys(hashData.data.attributes.results || {}).length} security vendors flagged this file as malicious`;
        } else if (suspiciousCount2 > 0) {
          details2 = `${suspiciousCount2}/${Object.keys(hashData.data.attributes.results || {}).length} security vendors flagged this file as suspicious`;
        }
        return {
          isSafe: isSafe2,
          maliciousCount: maliciousCount2,
          suspiciousCount: suspiciousCount2,
          details: details2,
          available: true,
          fileHash: hash
        };
      }
    } catch (hashCheckError) {
      console.log("File not in VirusTotal database, uploading...");
    }
    const FormData = (await import("form-data")).default;
    const formData = new FormData();
    formData.append("file", fileBuffer, { filename: fileName });
    const uploadResponse = await fetch(`${VT_API_BASE}/files`, {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        ...formData.getHeaders()
      },
      body: formData
    });
    if (!uploadResponse.ok) {
      throw new Error(`VirusTotal upload error: ${uploadResponse.status}`);
    }
    const uploadData = await uploadResponse.json();
    const analysisId = uploadData.data.id;
    await new Promise((resolve) => setTimeout(resolve, 5e3));
    const analysisResponse = await fetch(`${VT_API_BASE}/analyses/${analysisId}`, {
      headers: {
        "x-apikey": VT_API_KEY
      }
    });
    if (!analysisResponse.ok) {
      throw new Error(`VirusTotal analysis error: ${analysisResponse.status}`);
    }
    const analysisData = await analysisResponse.json();
    const stats = analysisData.data.attributes.stats;
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const isSafe = maliciousCount === 0 && suspiciousCount === 0;
    let details = "No threats detected";
    if (maliciousCount > 0) {
      details = `${maliciousCount} security vendors flagged this file as malicious`;
    } else if (suspiciousCount > 0) {
      details = `${suspiciousCount} security vendors flagged this file as suspicious`;
    }
    return {
      isSafe,
      maliciousCount,
      suspiciousCount,
      details,
      available: true,
      fileHash: hash
    };
  } catch (error) {
    console.error("VirusTotal file scan error:", error);
    const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
    return {
      isSafe: true,
      maliciousCount: 0,
      suspiciousCount: 0,
      details: error instanceof Error ? error.message : "Service unavailable",
      available: false,
      fileHash: hash
    };
  }
}

// client/src/lib/providers/whois.ts
async function getWhoisData(domain) {
  try {
    const response = await fetch(`https://api.whoisfreaks.com/v1.0/whois?apiKey=${process.env.WHOIS_API_KEY || ""}&whois=live&domainName=${domain}`);
    if (!response.ok) {
      return {};
    }
    const data = await response.json();
    const creationDate = data.create_date ? new Date(data.create_date) : void 0;
    const expirationDate = data.expire_date ? new Date(data.expire_date) : void 0;
    const age = creationDate ? Math.floor((Date.now() - creationDate.getTime()) / (1e3 * 60 * 60 * 24)) : void 0;
    return {
      registrar: data.registrar_name,
      creationDate,
      expirationDate,
      age
    };
  } catch (error) {
    console.error("WHOIS lookup failed:", error);
    return {};
  }
}

// client/src/lib/providers/heuristics.ts
function analyzeUrlHeuristics(url) {
  const flags = [];
  let score = 0;
  try {
    const urlObj = new URL(url);
    if (/^\d+\.\d+\.\d+\.\d+/.test(urlObj.hostname)) {
      score += 30;
      flags.push("Uses IP address instead of domain name");
    }
    if (url.length > 200) {
      score += 20;
      flags.push("Unusually long URL");
    }
    if (url.includes("@")) {
      score += 25;
      flags.push("Contains @ symbol (potential redirect)");
    }
    const subdomains = urlObj.hostname.split(".").length - 2;
    if (subdomains > 3) {
      score += 15;
      flags.push("Excessive number of subdomains");
    }
    if (/[^\w\-\.\/\?\=\&\%\#\+]/.test(url)) {
      score += 10;
      flags.push("Contains suspicious characters");
    }
    if (urlObj.protocol !== "https:") {
      score += 15;
      flags.push("Not using HTTPS");
    }
    const suspiciousTlds = [".tk", ".ml", ".ga", ".cf", ".click", ".download", ".top", ".bid", ".loan", ".win", ".racing"];
    if (suspiciousTlds.some((tld) => urlObj.hostname.endsWith(tld))) {
      score += 25;
      flags.push("Uses suspicious top-level domain");
    }
    const suspiciousKeywords = ["secure", "verify", "account", "update", "confirm", "suspended", "locked", "urgent"];
    const domainLower = urlObj.hostname.toLowerCase();
    if (suspiciousKeywords.some((keyword) => domainLower.includes(keyword))) {
      score += 15;
      flags.push("Domain contains suspicious security-related keywords");
    }
    if (/[а-я]/.test(urlObj.hostname) || /[α-ω]/.test(urlObj.hostname)) {
      score += 20;
      flags.push("Domain uses non-Latin characters (potential homograph attack)");
    }
    const hyphenCount = (urlObj.hostname.match(/-/g) || []).length;
    const numberCount = (urlObj.hostname.match(/\d/g) || []).length;
    if (hyphenCount > 3) {
      score += 10;
      flags.push("Domain contains excessive hyphens");
    }
    if (numberCount > 4) {
      score += 10;
      flags.push("Domain contains excessive numbers");
    }
    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "short.link"];
    if (shorteners.some((shortener) => urlObj.hostname.includes(shortener))) {
      score += 15;
      flags.push("URL shortener detected - cannot verify final destination");
    }
    const path3 = urlObj.pathname + urlObj.search;
    if (/(\.exe|\.zip|\.rar|\.bat|\.cmd|\.scr)$/i.test(path3)) {
      score += 30;
      flags.push("URL leads to executable file download");
    }
    if (/password|login|signin|account/.test(path3.toLowerCase())) {
      score += 5;
      flags.push("URL contains login/password related path");
    }
  } catch (error) {
    score += 50;
    flags.push("Invalid URL format");
  }
  return { score: Math.min(score, 100), flags };
}
function analyzeDomainAge(ageInDays) {
  if (!ageInDays) {
    return { score: 0 };
  }
  if (ageInDays < 30) {
    return { score: 40, flag: "Domain registered less than 30 days ago" };
  } else if (ageInDays < 90) {
    return { score: 25, flag: "Domain registered less than 90 days ago" };
  } else if (ageInDays < 365) {
    return { score: 10, flag: "Domain registered less than 1 year ago" };
  }
  return { score: 0 };
}

// client/src/lib/providers/urlscan.ts
async function submitToUrlScan(url) {
  const apiKey = process.env.URLSCAN_API_KEY || "";
  if (!apiKey) {
    console.warn("URLScan.io API key not configured");
    return {};
  }
  try {
    const response = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "API-Key": apiKey
      },
      body: JSON.stringify({
        url,
        visibility: "private"
      })
    });
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("URLScan.io submission failed:", error);
    return {};
  }
}

// server/lib/score.ts
async function checkUrlSafetyServer(url) {
  const reasons = [];
  const securityChecks = [];
  let totalScore = 0;
  const metadata = {};
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    let gsbWorking = false;
    let vtWorking = false;
    let abuseIpDbWorking = false;
    try {
      const gsbResult = await checkGoogleSafeBrowsing(url);
      gsbWorking = true;
      if (!gsbResult.isSafe) {
        totalScore += 60;
        reasons.push(`Flagged by Google Safe Browsing: ${gsbResult.threatType}`);
        securityChecks.push({
          name: "Google Safe Browsing",
          status: "malicious",
          details: gsbResult.threatType || "Threat detected"
        });
      } else {
        securityChecks.push({
          name: "Google Safe Browsing",
          status: "clean",
          details: "No threats detected"
        });
      }
    } catch (error) {
      securityChecks.push({
        name: "Google Safe Browsing",
        status: "error",
        details: "Service unavailable"
      });
    }
    try {
      const vtResult = await scanUrlWithVirusTotal(url);
      vtWorking = vtResult.available;
      if (vtResult.maliciousCount > 0) {
        totalScore += 65;
        reasons.push(`VirusTotal: ${vtResult.details}`);
        securityChecks.push({
          name: "VirusTotal",
          status: "malicious",
          details: vtResult.details
        });
      } else if (vtResult.suspiciousCount > 0) {
        totalScore += 35;
        reasons.push(`VirusTotal: ${vtResult.details}`);
        securityChecks.push({
          name: "VirusTotal",
          status: "suspicious",
          details: vtResult.details
        });
      } else if (vtResult.available) {
        securityChecks.push({
          name: "VirusTotal",
          status: "clean",
          details: "No threats detected"
        });
      } else {
        securityChecks.push({
          name: "VirusTotal",
          status: "error",
          details: "Service unavailable"
        });
      }
    } catch (error) {
      securityChecks.push({
        name: "VirusTotal",
        status: "error",
        details: "Service unavailable"
      });
    }
    try {
      const abuseResult = await checkAbuseIPDB(url);
      abuseIpDbWorking = abuseResult.available;
      if (abuseResult.isAbusive) {
        totalScore += 60;
        reasons.push(`Flagged by IP reputation service: ${abuseResult.details}`);
        securityChecks.push({
          name: "IP Reputation",
          status: "malicious",
          details: abuseResult.details || "Abusive IP detected"
        });
      } else if (abuseResult.available) {
        securityChecks.push({
          name: "IP Reputation",
          status: "clean",
          details: "Clean IP reputation"
        });
      } else {
        securityChecks.push({
          name: "IP Reputation",
          status: "error",
          details: "Service unavailable - API key missing or service down"
        });
      }
    } catch (error) {
      securityChecks.push({
        name: "IP Reputation",
        status: "error",
        details: "Service unavailable - network error"
      });
    }
    const externalApiWorking = gsbWorking || abuseIpDbWorking;
    let domainInfo;
    try {
      const whoisData = await getWhoisData(domain);
      const ageAnalysis = analyzeDomainAge(whoisData.age);
      totalScore += ageAnalysis.score;
      if (ageAnalysis.flag) {
        reasons.push(ageAnalysis.flag);
      }
      domainInfo = {
        registrar: whoisData.registrar || "Unknown",
        ip: "0.0.0.0",
        // Would need IP lookup service
        country: "Unknown",
        // Would need GeoIP service
        age: whoisData.age || 0
      };
      securityChecks.push({
        name: "Domain Age",
        status: ageAnalysis.score > 20 ? "suspicious" : "clean",
        details: whoisData.age ? `${whoisData.age} days old` : "Unknown age"
      });
    } catch (error) {
      securityChecks.push({
        name: "Domain Age",
        status: "error",
        details: "WHOIS lookup failed"
      });
    }
    const heuristicResult = analyzeUrlHeuristics(url);
    const heuristicWeight = externalApiWorking ? 1 : 1.4;
    const adjustedHeuristicScore = Math.round(heuristicResult.score * heuristicWeight);
    totalScore += adjustedHeuristicScore;
    reasons.push(...heuristicResult.flags);
    if (!externalApiWorking && heuristicResult.flags.length > 0) {
      reasons.push("Enhanced heuristic analysis applied due to external service limitations");
    }
    if (heuristicResult.flags.length > 0) {
      securityChecks.push({
        name: "Heuristic Analysis",
        status: adjustedHeuristicScore > 30 ? "suspicious" : "clean",
        details: `${heuristicResult.flags.length} suspicious patterns detected${!externalApiWorking ? " (enhanced weighting applied)" : ""}`
      });
    } else {
      securityChecks.push({
        name: "Heuristic Analysis",
        status: "clean",
        details: "No suspicious patterns found"
      });
    }
    try {
      const urlscanResult = await submitToUrlScan(url);
      if (urlscanResult.uuid) {
        metadata.urlscanUuid = urlscanResult.uuid;
      }
    } catch (error) {
      console.warn("URLScan.io submission failed:", error);
    }
    let verdict;
    if (totalScore >= 70) {
      verdict = "malicious";
    } else if (totalScore >= 30) {
      verdict = "suspicious";
    } else {
      verdict = "safe";
    }
    if (reasons.length === 0) {
      reasons.push("No security threats detected");
    }
    return {
      riskScore: Math.min(totalScore, 100),
      verdict,
      reasons,
      metadata,
      securityChecks,
      domainInfo
    };
  } catch (error) {
    console.error("URL safety check failed:", error);
    return {
      riskScore: 50,
      verdict: "suspicious",
      reasons: ["URL analysis failed"],
      metadata: { error: error instanceof Error ? error.message : "Unknown error" },
      securityChecks: [{
        name: "URL Analysis",
        status: "error",
        details: "Analysis failed"
      }]
    };
  }
}

// server/replitAuth.ts
import * as client from "openid-client";
import { Strategy } from "openid-client/passport";
import passport from "passport";
import session from "express-session";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
if (!process.env.REPLIT_DOMAINS) {
  throw new Error("Environment variable REPLIT_DOMAINS not provided");
}
var getOidcConfig = memoize(
  async () => {
    return await client.discovery(
      new URL(process.env.ISSUER_URL ?? "https://replit.com/oidc"),
      process.env.REPL_ID
    );
  },
  { maxAge: 3600 * 1e3 }
);
function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1e3;
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions"
  });
  return session({
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      maxAge: sessionTtl
    }
  });
}
function updateUserSession(user, tokens) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}
async function upsertUser(claims) {
  await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"]
  });
}
async function setupAuth(app2) {
  app2.set("trust proxy", 1);
  app2.use(getSession());
  app2.use(passport.initialize());
  app2.use(passport.session());
  const config = await getOidcConfig();
  const verify = async (tokens, verified) => {
    const user = {};
    updateUserSession(user, tokens);
    await upsertUser(tokens.claims());
    verified(null, user);
  };
  for (const domain of process.env.REPLIT_DOMAINS.split(",")) {
    const strategy = new Strategy(
      {
        name: `replitauth:${domain}`,
        config,
        scope: "openid email profile offline_access",
        callbackURL: `https://${domain}/api/callback`
      },
      verify
    );
    passport.use(strategy);
  }
  passport.serializeUser((user, cb) => cb(null, user));
  passport.deserializeUser((user, cb) => cb(null, user));
  app2.get("/api/login", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"]
    })(req, res, next);
  });
  app2.get("/api/callback", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login"
    })(req, res, next);
  });
  app2.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect(
        client.buildEndSessionUrl(config, {
          client_id: process.env.REPL_ID,
          post_logout_redirect_uri: `${req.protocol}://${req.hostname}`
        }).href
      );
    });
  });
}
var isAuthenticated = async (req, res, next) => {
  const user = req.user;
  if (!req.isAuthenticated() || !user.expires_at) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const now = Math.floor(Date.now() / 1e3);
  if (now <= user.expires_at) {
    return next();
  }
  const refreshToken = user.refresh_token;
  if (!refreshToken) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  try {
    const config = await getOidcConfig();
    const tokenResponse = await client.refreshTokenGrant(config, refreshToken);
    updateUserSession(user, tokenResponse);
    return next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
};

// server/routes.ts
import multer from "multer";
import crypto2 from "crypto";
var upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 32 * 1024 * 1024
    // 32MB limit
  }
});
var rateLimitStore = /* @__PURE__ */ new Map();
var RATE_LIMIT = 10;
var RATE_WINDOW = 60 * 1e3;
function checkRateLimit(ip) {
  const now = Date.now();
  const userLimit = rateLimitStore.get(ip);
  if (!userLimit || now > userLimit.resetTime) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + RATE_WINDOW });
    return true;
  }
  if (userLimit.count >= RATE_LIMIT) {
    return false;
  }
  userLimit.count++;
  return true;
}
async function registerRoutes(app2) {
  await setupAuth(app2);
  app2.get("/api/auth/user", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });
  app2.use("/api/", (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || "unknown";
    if (!checkRateLimit(ip)) {
      return res.status(429).json({
        error: "Rate limit exceeded. Maximum 10 requests per minute."
      });
    }
    storage.recordApiUsage({
      endpoint: req.path,
      ipAddress: ip,
      userAgent: req.get("User-Agent") || "",
      requestCount: 1
    });
    next();
  });
  app2.post("/api/check-url", async (req, res) => {
    try {
      const { url } = z.object({ url: z.string().url() }).parse(req.body);
      const cached = await storage.getScanResultByUrl(url);
      if (cached && Date.now() - cached.createdAt.getTime() < 24 * 60 * 60 * 1e3) {
        return res.json(cached);
      }
      const result = await checkUrlSafetyServer(url);
      const scanResult = await storage.createScanResult({
        url,
        fileHash: null,
        fileName: null,
        fileSize: null,
        scanType: "url",
        riskScore: result.riskScore,
        verdict: result.verdict,
        reasons: result.reasons,
        metadata: result.metadata
      });
      res.json(scanResult);
    } catch (error) {
      console.error("URL check error:", error);
      res.status(400).json({
        error: error instanceof Error ? error.message : "Invalid request"
      });
    }
  });
  app2.post("/api/scan-file", upload.single("file"), async (req, res) => {
    try {
      const file = req.file;
      if (!file) {
        return res.status(400).json({ error: "File required" });
      }
      let fileName = req.body.fileName || file.originalname;
      fileName = fileName.replace(/\.\./g, "").replace(/[<>:"|?*]/g, "").replace(/^\/+/, "").substring(0, 255);
      if (!fileName || fileName.trim().length === 0) {
        fileName = "unnamed_file";
      }
      const hash = crypto2.createHash("sha256").update(file.buffer).digest("hex");
      const fileSize = file.buffer.length;
      const cached = await storage.getScanResultByFileHash(hash);
      if (cached && Date.now() - cached.createdAt.getTime() < 24 * 60 * 60 * 1e3) {
        return res.json(cached);
      }
      const vtResult = await scanFileWithVirusTotal(file.buffer, fileName);
      let riskScore = 0;
      let verdict = "safe";
      const reasons = [];
      if (vtResult.available && vtResult.maliciousCount > 0) {
        riskScore = Math.min(100, 50 + vtResult.maliciousCount * 5);
        verdict = vtResult.maliciousCount > 5 ? "malicious" : "suspicious";
        reasons.push(`VirusTotal: ${vtResult.details}`);
      } else if (vtResult.available && vtResult.suspiciousCount > 0) {
        riskScore = Math.min(70, 30 + vtResult.suspiciousCount * 3);
        verdict = "suspicious";
        reasons.push(`VirusTotal: ${vtResult.details}`);
      } else if (vtResult.available) {
        riskScore = 5;
        verdict = "safe";
        reasons.push("VirusTotal: No threats detected by security vendors");
      } else {
        riskScore = 15;
        verdict = "safe";
        reasons.push("File analyzed with heuristics (VirusTotal unavailable)");
      }
      reasons.push(`File hash (SHA-256): ${hash}`);
      reasons.push(`File size: ${(fileSize / 1024).toFixed(2)} KB`);
      const scanResult = await storage.createScanResult({
        url: null,
        fileHash: hash,
        fileName,
        fileSize,
        scanType: "file",
        riskScore,
        verdict,
        reasons,
        metadata: { hash, originalName: fileName }
      });
      res.json(scanResult);
    } catch (error) {
      console.error("File scan error:", error);
      res.status(400).json({
        error: error instanceof Error ? error.message : "File scan failed"
      });
    }
  });
  app2.post("/api/check-reputation", async (req, res) => {
    try {
      const { url } = z.object({ url: z.string().url() }).parse(req.body);
      const result = await checkAbuseIPDB(url);
      res.json(result);
    } catch (error) {
      console.error("Reputation check failed:", error);
      res.status(500).json({
        isAbusive: false,
        available: false,
        error: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/admin/stats", isAuthenticated, async (req, res) => {
    try {
      const stats = await storage.getApiUsageStats();
      res.json(stats);
    } catch (error) {
      console.error("Stats error:", error);
      res.status(500).json({ error: "Failed to fetch stats" });
    }
  });
  app2.get("/api/admin/recent-scans", isAuthenticated, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 100;
      const scans = await storage.getRecentScans(limit);
      res.json(scans);
    } catch (error) {
      console.error("Recent scans error:", error);
      res.status(500).json({ error: "Failed to fetch recent scans" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      ),
      await import("@replit/vite-plugin-dev-banner").then(
        (m) => m.devBanner()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = parseInt(process.env.PORT || "5000", 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
