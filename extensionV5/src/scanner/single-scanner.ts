// src/scanner/single-scanner.ts

// --- Environment Variable Access ---
const SCANNER_API_ENDPOINT: string = process.env.SCANNER_API_ENDPOINT as string;
const API_KEY: string = process.env.API_KEY as string;
// The two lines below were in your original file's ENV block. Keeping them for safety.
const VT_API_KEYS = (process.env.VT_API_KEYS || "").trim();
const VT_API_KEY = (process.env.VT_API_KEY || "").trim();
// --- End Environment Variable Access ---

// Debug flag and logger
// Note: process.argv is only available in Node.js, remove or replace if needed elsewhere.
const DEBUG = false; // process.argv.includes("--debug") removed for browser environment
function dlog(...args: any[]) {
  if (DEBUG) console.log("[debug]", ...args);
}

// Predicate to detect premium/forbidden errors
function isForbidden(err: any): boolean {
  const msg = String(err?.message || err || "");
  return msg.includes("403") || msg.toLowerCase().includes("forbidden");
}
// VirusTotal API Response Types
import { VTURLMetadata, VTDomainResponse, VTIPResponse } from "./type";

import { getDomain as tldGetDomain } from "tldts";

export interface ScanContext {
  order?: string;
  label?: string;
  rawUrl?: string;
  logId?: string;
  disableAutomaticWaitlist?: boolean;
}

export type ScanResult =
  | { status: "success"; data: Record<string, any> }
  | { status: "waitlist"; note?: string }
  | { status: "error"; error: string };

// Removed all CSV/File path constants:
// export const WAITLIST_CSV_PATH = "./outputs/waitlist.csv";
// export const ERROR_CSV_PATH = "./outputs/error.csv";
// const PROMPT_OUTPUT_PATH = "./outputs/prompt.txt";
// const FIELDS_OUTPUT_PATH = "./outputs/fields.json";

const ABSENT = null;

type OutputMask = Record<string, string | null>;

export const INSTRUCTION =
  "INSTRUCT: Cyber Security Analyst. Classify: 'phish' or 'legit'.::EXP: null=failed to read. isHttps=URL secure. entropy=avg randomness. similarity=avg text match. dnsRatio=age/count. faviconMatch=favicon URL match host. tlsSubjectMatch=TLS subject match host.::HINTS: Higher reputation: more % legit. maliciousVotes>0: 100% phish. domainValidDays<366: 75% phish. isHttps=false: 75% phish. suspiciousVotes>0: 75% phish. nullCount>=10: 75% phish";

const CUSTOMED_FIELDS_NAME = {
  url: "url",
  urlEntropy: "urlEntropy",
  hostname: "hostname",
  isHttps: "isHttps",
  contentInfoTitle: "title",
  contentInfoFaviconHostMatch: "faviconMatch",
  contentInfoCharset: "charset",
  contentInfoMimeType: "MIMEType",
  contentInfoMetaTagCount: "metaTagCount",
  reputation: "reputation",
  maliciousVotes: "maliciousVotes",
  suspiciousVotes: "suspiciousVotes",
  servicesKeyWords: "services",
  suspiciousFeatures: "features",
  redirectCount: "redirectCount",
  redirectEntropy: "redirectEntropy",
  redirectSimilarity: "redirectSimilarity",
  dnsRatio: "dnsRatio",
  domainAge: "domainAge",
  domainValidDays: "domainValidDays",
  networkAsOwner: "networkAsOwner",
  networkCountry: "networkCountry",
  httpInfoStatusCode: "statusCode",
  headerHttpServer: "serverName",
  headerContentSecurityPolicyCount: "contentSecurityPolicyCount",
  headerStrictTransportSecurity: "strictTransportSecurity",
  headerXFrameOptions: "xFrameOptions",
  headerXContentTypeOptions: "xContentTypeOptions",
  headerCacheControl: "cacheControl",
  tlsInfoSubjectMatch: "tlsSubjectMatch",
  tlsInfoValidDays: "tlsValidDays",
  tlsInfoSanEntriesCount: "tlsSANCount",
  tlsInfoSanEntriesEntropy: "tlsSANEntropy",
  tlsInfoSanEntriesSimilarity: "tlsSANSimilarity",
  externalResourcesEmbeddedUrlsCount: "embeddedURLCount",
  externalResourcesEmbeddedUrlsEntropy: "embeddedURLEntropy",
  externalResourcesEmbeddedUrlsSimilarity: "embeddedURLSimilarity",
  externalResourcesTrackersCount: "embeddedTrackersCount",
  nullCount: "nullCount",
};

const USELESS_WORDS = new Set([
  "and",
  "or",
  "a",
  "an",
  "the",
  "of",
  "for",
  "to",
  "in",
  "on",
  "at",
  "by",
  "with",
  "without",
  "from",
  "as",
  "is",
  "are",
  "be",
  "this",
  "that",
  "these",
  "those",
  "it",
  "its",
  "other",
  "others",
  "another",
  "&",
  "/",
  "-",
]);

function applyOutputMask(
  flattened: Record<string, any>,
  mask: OutputMask
): Record<string, any> {
  if (!mask || Object.keys(mask).length === 0) return flattened;

  const masked: Record<string, any> = {};
  const collisions: string[] = [];

  for (const [key, value] of Object.entries(flattened)) {
    const hasEntry = Object.prototype.hasOwnProperty.call(mask, key);
    const alias = hasEntry ? mask[key] : undefined;
    if (alias === null) continue; // explicit opt-out

    const targetKey = alias ?? key;
    if (
      Object.prototype.hasOwnProperty.call(masked, targetKey) &&
      targetKey !== key
    ) {
      collisions.push(`${key}->${targetKey}`);
    }
    masked[targetKey] = value;
  }

  if (collisions.length > 0) {
    dlog("Output mask collisions detected:", collisions.join(", "));
  }

  return masked;
}

function deepMarkAbsent(value: any): any {
  if (value === undefined || value === null) return ABSENT;
  if (Array.isArray(value)) return value.map((v) => deepMarkAbsent(v));
  if (typeof value === "object") {
    const out: any = {};
    for (const k of Object.keys(value)) {
      out[k] = deepMarkAbsent((value as any)[k]);
    }
    return out;
  }
  return value;
}

function capitalizeKeySegment(segment: string): string {
  if (!segment) return segment;
  return segment[0].toUpperCase() + segment.slice(1);
}

function isSubjectOverlap(hostname: string, subjectStr: string): boolean {
  const host = hostname.toLowerCase().replace(/^\*\./, "");
  const subj = subjectStr.toLowerCase().replace(/^\*\./, "");
  return host.endsWith(subj) || subj.endsWith(host);
}

function isPlainObject(value: any): value is Record<string, any> {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function flattenObject(
  value: Record<string, any>,
  parentKey = ""
): Record<string, any> {
  const flat: Record<string, any> = {};
  for (const [key, current] of Object.entries(value)) {
    const nextKey = parentKey
      ? `${parentKey}${capitalizeKeySegment(key)}`
      : key;
    if (isPlainObject(current)) {
      Object.assign(flat, flattenObject(current, nextKey));
    } else {
      flat[nextKey] = current;
    }
  }
  return flat;
}

function countNullValues(record: Record<string, any>): number {
  return Object.values(record).reduce(
    (total, value) => total + (value === null ? 1 : 0),
    0
  );
}

export function formatPrompt(
  flattened: Record<string, any>,
  instruction?: string
): string | null {
  if (!instruction || instruction.trim().length === 0) return null;

  const entries = Object.entries(flattened);
  const parts = entries.map(([key, value]) => {
    if (value === null) return `${key}=null`;
    if (typeof value === "string") return `${key}=${value}`;
    if (typeof value === "number" || typeof value === "boolean")
      return `${key}=${value}`;
    return `${key}=${JSON.stringify(value)}`;
  });

  const body = parts.join(" | ");
  return `${instruction}::DATA: ${body} CLASSIFICATION:`;
}

// Removed all CSV/File writing helpers: csvEscape, appendCsvRow

// Replaced appendToWaitlist and appendToErrorLog with simple console logs/no-ops
export function appendToWaitlist(
  url: string,
  note: string | undefined,
  context?: ScanContext
) {
  // In a browser extension, you would use chrome.storage or skip this entirely.
  // We'll log a warning instead of trying to write a file.
  console.warn(
    `[Waitlist] ${context?.order || ""} URL: ${url} Note: ${note || "N/A"}`
  );
}

function appendToErrorLog(url: string, error: string, context?: ScanContext) {
  console.error(
    `[Error Log] ${context?.order || ""} URL: ${url} Error: ${error}`
  );
}

// ====== API CONFIG ======
const BASE = "https://www.virustotal.com/api/v3";
const HARDCODED_URL = "https://www.apple.com/";

function parseApiKeys(): string[] {
  // Use environment variables injected by Parcel (VT_API_KEYS and VT_API_KEY)
  const rawList = VT_API_KEYS;
  let keys: string[] = [];
  if (rawList) {
    keys = rawList
      .split(/[,\s]+/)
      .map((k) => k.trim())
      .filter(Boolean);
  }
  if (keys.length === 0) {
    const single = VT_API_KEY;
    if (single) keys = [single];
  }
  return Array.from(new Set(keys));
}

const API_KEYS = parseApiKeys();

if (API_KEYS.length === 0 && !process.env.IS_EXTENSION) {
  // Added conditional check
  console.error(
    "Missing VT_API_KEY(S). Provide VT_API_KEY or VT_API_KEYS env vars."
  );
  // process.exit(1); // Removed: cannot exit a service worker
}

let activeApiKeyIndex = 0;

function getActiveApiKey(): string {
  return API_KEYS[activeApiKeyIndex];
}

function maskApiKey(key: string): string {
  if (key.length <= 8) return `${key.slice(0, 2)}***${key.slice(-2)}`;
  return `${key.slice(0, 4)}…${key.slice(-4)}`;
}

function tryRotateApiKey(reason: string): boolean {
  if (activeApiKeyIndex >= API_KEYS.length - 1) {
    console.warn(
      `VT API key rotation requested (${reason}) but no additional keys remain.`
    );
    return false;
  }

  const previous = maskApiKey(API_KEYS[activeApiKeyIndex]);
  activeApiKeyIndex += 1;
  const next = maskApiKey(API_KEYS[activeApiKeyIndex]);
  //console.warn(`Rotating VT API key (${reason}). ${previous} -> ${next}`);
  return true;
}

function isQuotaOrForbiddenStatus(status: number, body: string): boolean {
  if (status === 429) return true;
  const normalized = body.toLowerCase();
  const quotaIndicators = [
    "quota",
    "rate limit",
    "too many requests",
    "exceeded",
  ];
  if (quotaIndicators.some((token) => normalized.includes(token))) {
    return true;
  }
  if (status === 403) {
    return normalized.includes("quota");
  }
  return false;
}

// Encode plain URL → VT base64url (no padding)
function encodeVTUrl(u: string): string {
  // Use browser-native Buffer shim or TextEncoder/btoa for service worker compatibility
  const b64 = btoa(u);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ====== API CALL ======
async function performVTRequest(
  method: "GET" | "POST",
  path: string,
  init: RequestInit = {}
) {
  while (true) {
    const res = await fetch(`${BASE}${path}`, {
      ...init,
      method,
      headers: {
        ...(init.headers || {}),
        "x-apikey": getActiveApiKey(),
      },
    });

    if (res.ok) return res;

    const text = await res.text();
    if (isQuotaOrForbiddenStatus(res.status, text)) {
      const rotated = tryRotateApiKey(`${method} ${path} -> ${res.status}`);
      if (rotated) continue;
      throw new Error(
        `VirusTotal quota exhausted across all API keys. Last response ${method} ${path} -> ${res.status}: ${text}`
      );
    }

    throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  }
}

async function vtGet(path: string) {
  const res = await performVTRequest("GET", path);
  return res.json();
}

async function vtPost(path: string, body: URLSearchParams) {
  const res = await performVTRequest("POST", path, {
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  return res.json();
}

async function getUrlReport(url: string) {
  const id = encodeVTUrl(url);
  try {
    const data = await vtGet(`/urls/${id}`);
    return data; // full VT payload
  } catch (err: any) {
    // 404 or other errors bubble up — caller decides to submit
    throw err;
  }
}

async function submitUrl(url: string) {
  const form = new URLSearchParams();
  form.set("url", url);
  const data = await vtPost("/urls", form);
  // { data: { id: "<analysis-id>", type: "analysis" } }
  return data?.data?.id as string | undefined;
}

async function fetchDomainInfo(hostname: string) {
  try {
    const base = getRegistrableDomain(hostname) || hostname;
    const domainResp: VTDomainResponse = await vtGet(`/domains/${base}`);
    const attr = domainResp?.data?.attributes ?? {};
    const creationDate = formatUtcDateTime(attr.creation_date);
    const expirationDate = formatUtcDateTime(attr.expiration_date);

    const age = creationDate ? calculateDaysSince(creationDate) : undefined;
    const validDays =
      creationDate && expirationDate
        ? computeDaysBetween(creationDate, expirationDate)
        : undefined;

    const lastHttpsCert = (attr as any)?.last_https_certificate;
    // Capture the first A record (if present) to use as a network fallback
    let firstA: string | undefined;
    const lastDns = (attr as any)?.last_dns_records;
    if (Array.isArray(lastDns)) {
      const a = lastDns.find((r: any) => String(r?.type).toUpperCase() === "A");
      if (a?.value) firstA = String(a.value);
    }
    return {
      _queriedBase: base,
      creationDate,
      expirationDate,
      age,
      validDays,
      _lastHttpsCert: lastHttpsCert,
      _firstA: firstA,
    } as any;
  } catch {
    return {
      _queriedBase: getRegistrableDomain(hostname) || hostname,
      creationDate: ABSENT,
      expirationDate: ABSENT,
      domainAge: ABSENT,
      age: ABSENT,
      validDays: ABSENT,
      _lastHttpsCert: ABSENT,
      _firstA: ABSENT,
    } as any;
  }
}

async function fetchIPInfo(ip: string): Promise<VTURLMetadata["network"]> {
  try {
    const ipResp: VTIPResponse = await vtGet(`/ip_addresses/${ip}`);
    const attr = ipResp?.data?.attributes ?? {};
    let country: string | undefined = attr.country || undefined;
    const asOwner = attr.as_owner || undefined;
    const whoisText = typeof attr.whois === "string" ? attr.whois : undefined;

    // Extract country code/name from WHOIS if VT didn't provide it
    if (!country && whoisText) {
      const lines = whoisText
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      const kv = (key: RegExp) => lines.find((ln) => key.test(ln));
      const ctryLine =
        kv(/^country\s*:/i) ||
        kv(/^country-code\s*:/i) ||
        kv(/^country code\s*:/i);
      if (ctryLine) {
        const val = ctryLine.split(":").slice(1).join(":").trim();
        if (val) country = val.toUpperCase();
      }
    }

    return {
      asOwner,
      country,
    };
  } catch {
    return {
      asOwner: ABSENT as any,
      country: ABSENT as any,
    };
  }
}

// Helper: fetch a certificate from VT relationships as a fallback
async function fetchCertificateFromRelationships(
  hostname: string,
  ip?: string
) {
  // helper to resolve first cert from a relationships response
  const resolveFirst = async (rel: any) => {
    const first = rel?.data?.[0];
    if (!first) return undefined;
    if (first.attributes) return first.attributes; // attributes inlined
    if (first.id) {
      const cert = await vtGet(`/ssl_certificates/${first.id}`);
      return cert?.data?.attributes;
    }
    return undefined;
  };
  try {
    if (ip) {
      const rel = await vtGet(
        `/ip_addresses/${ip}/relationships/ssl_certificates?limit=1`
      );
      const attrs = await resolveFirst(rel);
      if (attrs) return attrs;
    }
  } catch {}
  try {
    const rel = await vtGet(
      `/domains/${hostname}/relationships/ssl_certificates?limit=1`
    );
    const attrs = await resolveFirst(rel);
    if (attrs) return attrs;
  } catch {}
  return undefined;
}

// Try to fetch a certificate by id or reference object
async function fetchCertificateById(ref: any) {
  try {
    const id =
      typeof ref === "string"
        ? ref
        : ref?.id || ref?.certificate_id || undefined;
    if (!id) return undefined;
    const cert = await vtGet(`/ssl_certificates/${id}`);
    return cert?.data?.attributes;
  } catch (e) {
    return undefined;
  }
}

function parseCNFromDN(dn: any): string | undefined {
  if (!dn) return undefined;
  if (typeof dn === "object") {
    return dn.CN || dn.cn || dn.commonName || dn.common_name || undefined;
  }
  if (typeof dn === "string") {
    const parts = dn.split(/,\s*/);
    for (const p of parts) {
      const m = p.match(/^CN\s*=\s*(.+)$/i);
      if (m) return m[1].trim();
    }
  }
  return undefined;
}

// Parse RFC5988 Link header to find rel=icon (favicon), resolving relative URLs as needed
function extractIconFromLinkHeader(
  linkHeader?: string,
  base?: string
): string | undefined {
  if (!linkHeader) return undefined;
  // split on commas not inside quotes
  const parts = linkHeader
    .split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/)
    .map((p) => p.trim());
  for (const p of parts) {
    const urlMatch = p.match(/<([^>]+)>/);
    if (!urlMatch) continue;
    const params = Object.fromEntries(
      p
        .slice(urlMatch.index! + urlMatch[0].length)
        .split(";")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((kv) => {
          const [k, v] = kv.split("=");
          return [
            k.toLowerCase(),
            v ? v.replace(/^"|"$/g, "").toLowerCase() : "",
          ];
        })
    );
    const rel = params["rel"] || "";
    if (rel.includes("icon") || rel.includes("shortcut icon")) {
      try {
        return base ? new URL(urlMatch[1], base).toString() : urlMatch[1];
      } catch {
        return urlMatch[1];
      }
    }
  }
  return undefined;
}

// Normalized Shannon entropy (bits per character), independent of length
function normalizedEntropy(source: string): number {
  if (!source || source.length <= 0) return -1;
  const freq: Record<string, number> = {};
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let H = 0;
  const n = source.length;
  for (const k in freq) {
    const p = freq[k] / n;
    H -= p * Math.log2(p);
  }
  return +H.toFixed(4); // bits/char
}

function avgEntropy(stringArray: string[]): number {
  if (!stringArray || !Array.isArray(stringArray) || stringArray.length <= 0)
    return -1;
  if (stringArray.length === 1) return normalizedEntropy(stringArray[0]);
  const avg =
    stringArray.reduce(
      (sum, v) => sum + normalizedEntropy(String(v).toLowerCase()),
      0
    ) / stringArray.length;
  return Number(avg.toFixed(4));
}

function avgSimilarity(stringArray: string[]): number {
  if (!stringArray || !Array.isArray(stringArray) || stringArray.length < 2)
    return -1;
  function levenshteinSim(a: string, b: string): number {
    const m = a.length,
      n = b.length;
    if (!m && !n) return 1;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + cost
        );
      }
    }
    const dist = dp[m][n];
    return 1 - dist / Math.max(m, n);
  }
  let sum = 0,
    pairs = 0;
  for (let i = 0; i < stringArray.length; i++) {
    for (let j = i + 1; j < stringArray.length; j++) {
      sum += levenshteinSim(stringArray[i], stringArray[j]);
      pairs++;
    }
  }
  return Number((sum / pairs).toFixed(4));
}

// Compute top-N tokens from an array of phrases, ignoring common stopwords
function top3Tokens(phrases: string[] | undefined, n: number = 3): string[] {
  if (!Array.isArray(phrases) || phrases.length === 0) return [];
  const freq: Record<string, number> = {};
  for (const p of phrases) {
    const parts = String(p)
      .split(/\s+/)
      .map((t) =>
        t.toLowerCase().replace(/^['"\(\[\{<]+|['"\)\]\}>,.;:!?]+$/g, "")
      )
      .filter(Boolean);
    for (const t of parts) {
      if (USELESS_WORDS.has(t)) continue;
      freq[t] = (freq[t] || 0) + 1;
    }
  }
  return Object.entries(freq)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, n)
    .map(([tok]) => tok);
}

// Case-insensitive header getter
function getHeaderCI(
  headers: Record<string, string | number | null> | undefined,
  name: string
): string | undefined {
  if (!headers) return undefined;
  const direct = (headers as any)[name];
  if (typeof direct === "string") return direct;
  const target = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === target) return (headers as any)[k];
  }
  return undefined;
}

function getHeaderValuesCI(
  headers: Record<string, unknown> | undefined,
  name: string
): string[] | null | undefined {
  if (!headers) return undefined;
  const target = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === target) {
      const value = (headers as any)[key];
      if (value == null) return value;
      if (Array.isArray(value)) return value.map((v) => String(v));
      return [String(value)];
    }
  }
  return undefined;
}

// Helper: fetch a certificate from VT URL relationships as a fallback
async function fetchCertificateFromUrlRelationships(urlId: string) {
  try {
    const rel = await vtGet(
      `/urls/${urlId}/relationships/ssl_certificates?limit=1`
    );
    const first = rel?.data?.[0];
    if (!first) return undefined;
    if (first.attributes) return first.attributes;
    if (first.id) {
      const cert = await vtGet(`/ssl_certificates/${first.id}`);
      return cert?.data?.attributes;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

// Fetch contacted IPs from URL relationships (to try IP->cert path)
async function fetchContactedIPsFromUrl(urlId: string): Promise<string[]> {
  try {
    const rel = await vtGet(
      `/urls/${urlId}/relationships/contacted_ips?limit=10`
    );
    const items = rel?.data || [];
    return items.map((x: any) => x?.id).filter(Boolean);
  } catch (e: any) {
    dlog("contacted_ips rel fetch failed:", e?.message || String(e));
    return [];
  }
}

// Fetch contacted domains from URL relationships
async function fetchContactedDomainsFromUrl(urlId: string): Promise<string[]> {
  try {
    const rel = await vtGet(
      `/urls/${urlId}/relationships/contacted_domains?limit=40`
    );
    const items = Array.isArray(rel?.data) ? rel.data : [];
    return items.map((x: any) => x?.id).filter(Boolean);
  } catch (e: any) {
    dlog("contacted_domains rel fetch failed:", e?.message || String(e));
    return [];
  }
}

// Try toggling www. variant of hostname to increase hit rate
function toggleWww(host: string): string {
  if (host.startsWith("www.")) return host.slice(4);
  return `www.${host}`;
}

function getRegistrableDomain(hostname: string): string {
  try {
    const base = tldGetDomain(hostname, { allowPrivateDomains: true });
    return base || hostname;
  } catch {
    return hostname;
  }
}

// ---- Passive DNS helpers ----
function formatUtcDateTime(value: any): string | undefined {
  if (value === null || value === undefined) return undefined;
  let date: Date;
  if (typeof value === "number") {
    const ms = value > 1e12 ? value : value * 1000;
    date = new Date(ms);
  } else if (value instanceof Date) {
    date = value;
  } else {
    const parsed = Date.parse(String(value));
    if (Number.isNaN(parsed)) return undefined;
    date = new Date(parsed);
  }
  if (Number.isNaN(date.getTime())) return undefined;
  const iso = date.toISOString();
  return iso.replace(/\.\d{3}Z$/, "Z");
}

function calculateDaysSince(
  value: string | number | undefined
): number | undefined {
  if (value === undefined || value === null) return undefined;
  let timestamp: number;
  if (typeof value === "number") {
    timestamp = value > 1e12 ? value : value * 1000;
  } else {
    const parsed = Date.parse(value);
    if (Number.isNaN(parsed)) return undefined;
    timestamp = parsed;
  }
  const diff = Date.now() - timestamp;
  if (!Number.isFinite(diff) || diff < 0) return undefined;
  return Math.floor(diff / (1000 * 60 * 60 * 24));
}

function computeDaysBetween(
  validFrom?: string,
  validTo?: string
): number | undefined {
  if (!validFrom || !validTo) return undefined;
  const from = Date.parse(validFrom);
  const to = Date.parse(validTo);
  if (Number.isNaN(from) || Number.isNaN(to) || to <= from) return undefined;
  const now = Date.now();
  const start = Math.max(from, now);
  const remainingMs = to - start;
  if (remainingMs <= 0) return 0;
  return Math.floor(remainingMs / (1000 * 60 * 60 * 24));
}

async function fetchPassiveDnsForDomain(hostname: string) {
  try {
    const resp = await vtGet(`/domains/${hostname}/resolutions?limit=40`);
    const rows = Array.isArray(resp?.data) ? resp.data : [];
    let first: number | undefined;

    for (const r of rows) {
      const a = r?.attributes || {};
      const when = a.date || a.last_resolved || a.first_seen || a.last_seen;
      if (typeof when === "number") {
        if (first === undefined || when < first) first = when;
      }
    }

    return {
      count: rows.length,
      firstSeen: formatUtcDateTime(first),
    } as VTURLMetadata["dns"];
  } catch (e) {
    dlog("dns fetch failed:", (e as any)?.message || String(e));
    return undefined;
  }
}

async function buildVTMetadata(
  targetUrl: string,
  vtUrlPayload: any
): Promise<VTURLMetadata> {
  const urlObj = new URL(targetUrl);
  const url = targetUrl;
  const urlEntropy = normalizedEntropy(url);
  const isHttps = url.trim().startsWith("https://");
  const hostname = urlObj.hostname;

  const attr = vtUrlPayload?.data?.attributes ?? {};
  dlog("attr keys:", Object.keys(attr));

  // HTTP Info (only top-8 selected headers kept in `headers`)
  const rawHeaders = attr.last_http_response_headers ?? {};
  const cspValues = getHeaderValuesCI(rawHeaders, "content-security-policy");

  const selectedMaybe: Record<string, string | undefined> = {
    server: getHeaderCI(rawHeaders, "server"),
    "content-security-policy":
      Array.isArray(cspValues) && cspValues.length > 0
        ? cspValues[0]
        : undefined,
    "strict-transport-security": getHeaderCI(
      rawHeaders,
      "strict-transport-security"
    ),
    "x-frame-options": getHeaderCI(rawHeaders, "x-frame-options"),
    "x-content-type-options": getHeaderCI(rawHeaders, "x-content-type-options"),
    "cache-control": getHeaderCI(rawHeaders, "cache-control"),
  };
  // Build headers map allowing string | number | null (temporary)
  const tempHeaders: Record<string, string | number | null> =
    Object.fromEntries(
      Object.entries(selectedMaybe).map(([k, v]) => [k, v ?? ABSENT])
    ) as Record<string, string | number | null>;

  let contentSecurityPolicyCount: number | null;
  if (cspValues == null) {
    contentSecurityPolicyCount = null;
  } else if (cspValues.length === 0) {
    contentSecurityPolicyCount = 0;
  } else {
    const tokens = cspValues.flatMap((value) =>
      String(value)
        .split(/[ ;]+/)
        .map((t) => t.trim())
        .filter(Boolean)
    );
    contentSecurityPolicyCount = tokens.length;
  }
  delete tempHeaders["content-security-policy"]; // remove raw CSP value

  const headers: Record<string, string | number | null> = {
    "content-security-policy-count": contentSecurityPolicyCount,
    ...tempHeaders,
  };

  const strictTransportHeader = headers["strict-transport-security"];
  if (typeof strictTransportHeader === "string") {
    headers["strict-transport-security"] = strictTransportHeader.replace(
      /;\s+/g,
      ";"
    );
  }

  const xFrameOptions = headers["x-frame-options"];
  if (typeof xFrameOptions === "string") {
    headers["x-frame-options"] = xFrameOptions.replace(/;\s+/g, ";");
  }

  const xContentTypeOptions = headers["x-content-type-options"];
  if (typeof xContentTypeOptions === "string") {
    headers["x-content-type-options"] = xContentTypeOptions.replace(
      /;\s+/g,
      ";"
    );
  }

  const cacheControlHeader = headers["cache-control"];
  if (typeof cacheControlHeader === "string") {
    headers["cache-control"] = cacheControlHeader.replace(/,\s+/g, ";");
  }

  const httpInfo = {
    headers,
    statusCode: attr.last_http_response_code ?? undefined,
  };

  // Favicon URL: VT sometimes stores a URL, otherwise try Link header, else heuristic /favicon.ico
  let favicon: string | undefined = attr.favicon ?? undefined;

  if (!favicon) {
    const linkHeader = (headers?.["link"] || headers?.["Link"]) as
      | string
      | undefined;
    const iconFromLink = extractIconFromLinkHeader(linkHeader, url);
    if (iconFromLink) favicon = iconFromLink;
  }

  if (!favicon) {
    try {
      // Heuristic only; does not fetch, just fills a reasonable default
      const base = new URL(url);
      favicon = `${base.protocol}//${base.host}/favicon.ico`;
    } catch {}
  }

  let faviconHostMatch = undefined;
  if (!!favicon) {
    faviconHostMatch = favicon.includes(hostname) ? true : false;
  }

  // Add charset, mimeType extraction
  const contentTypeHeader = getHeaderCI(rawHeaders, "content-type");
  const mimeType = contentTypeHeader?.split(";")[0]?.trim();
  let charset: string | undefined = undefined;
  if (contentTypeHeader) {
    const m = contentTypeHeader.match(/charset\s*=\s*([^;]+)/i);
    if (m) charset = m[1].trim();
  }

  const contentInfo = {
    title: attr.title ?? undefined,
    faviconHostMatch,
    charset,
    mimeType,
  };

  // Votes
  const lastStats = attr?.last_analysis_stats ?? null;
  const maliciousCount = lastStats?.malicious ?? null;
  const suspiciousCount = lastStats?.suspicious ?? null;

  // Redirect
  const redirectChainRaw = attr.redirection_chain;
  let redirectChain: string[] = [];
  let redirectCount: number | null = null;
  if (Array.isArray(redirectChainRaw)) {
    redirectChain = redirectChainRaw;
    redirectCount = redirectChainRaw.length; // 0 or positive
  } else if (redirectChainRaw === null || redirectChainRaw === undefined) {
    redirectCount = null; // no redirect data
  }

  const redirectEntropy = avgEntropy(redirectChain);
  const redirectSimilarityValue = avgSimilarity(redirectChain);

  const redirect = {
    count: redirectCount,
    entropy: redirectEntropy,
    similarity: redirectSimilarityValue,
  };

  // Fetch domain early so baseDomain is available for certificate fallbacks and network
  const domain = await fetchDomainInfo(hostname);
  dlog(
    "domain _lastHttpsCert present:",
    Boolean((domain as any)?._lastHttpsCert)
  );
  const baseDomain = (domain as any)?._queriedBase || hostname;

  // Certificate Info: multiple strategies
  let certAttributes: any | undefined = undefined;

  // 1) Directly from URL attributes (some keys carry inline attributes, others only an id)
  dlog("try direct last_https_certificate:", !!attr.last_https_certificate);
  if (attr.last_https_certificate) {
    if (attr.last_https_certificate.subject) {
      certAttributes = attr.last_https_certificate;
    } else {
      const deref = await fetchCertificateById(attr.last_https_certificate);
      if (deref) certAttributes = deref;
    }
  }

  // 2) Fallback: try relationships from IP, then domain
  dlog("try relationships: domain/ip", hostname, attr.last_serving_ip_address);
  if (!certAttributes) {
    const relAttr = await fetchCertificateFromRelationships(
      hostname,
      attr.last_serving_ip_address
    );
    if (relAttr) certAttributes = relAttr;
  }
  if (!certAttributes && baseDomain && baseDomain !== hostname) {
    try {
      const relBase = await fetchCertificateFromRelationships(
        baseDomain,
        undefined
      );
      if (relBase) certAttributes = relBase;
    } catch (e: any) {
      if (!isForbidden(e))
        dlog("baseDomain rel fetch failed:", e?.message || String(e));
    }
  }

  // 3) If final Url has a different hostname, try that too
  if (!certAttributes && attr.last_final_url) {
    try {
      const finalHost = new URL(attr.last_final_url).hostname;
      dlog("try relationships: finalHost", finalHost);
      if (finalHost && finalHost !== hostname) {
        const relAttr2 = await fetchCertificateFromRelationships(
          finalHost,
          undefined
        );
        if (relAttr2) certAttributes = relAttr2;
      }
    } catch {}
  }

  // 4) Additional fallback: try URL relationships
  if (!certAttributes) {
    try {
      dlog("try url relationships: ssl_certificates for urlId");
      const urlId = encodeVTUrl(targetUrl);
      const relAttr3 = await fetchCertificateFromUrlRelationships(urlId);
      if (relAttr3) certAttributes = relAttr3;
    } catch {}
  }

  // 5) Try contacted IPs from URL relationships then IP->cert
  if (!certAttributes) {
    try {
      const urlId = encodeVTUrl(targetUrl);
      const ips = await fetchContactedIPsFromUrl(urlId);
      dlog("contacted_ips from URL:", ips);
      for (const ip of ips) {
        const rel = await vtGet(
          `/ip_addresses/${ip}/relationships/ssl_certificates?limit=1`
        );
        const first = rel?.data?.[0]?.attributes;
        if (first) {
          certAttributes = first;
          break;
        }
      }
    } catch (e: any) {
      if (!isForbidden(e))
        dlog("contacted_ips->cert lookup failed:", e?.message || String(e));
    }
  }

  // 6) Try toggling www. variant of hostname
  if (!certAttributes) {
    const altHost = toggleWww(hostname);
    if (altHost !== hostname) {
      try {
        const relAlt = await fetchCertificateFromRelationships(
          altHost,
          undefined
        );
        if (relAlt) certAttributes = relAlt;
      } catch (e: any) {
        if (!isForbidden(e))
          dlog("alt host rel fetch failed:", e?.message || String(e));
      }
    }
  }

  dlog(
    "certAttributes present:",
    !!certAttributes,
    certAttributes && Object.keys(certAttributes)
  );

  // Threat info
  const scValues: string[] | undefined = attr.categories
    ? Object.values(attr.categories).map((v: unknown) => String(v))
    : undefined;

  const servicesKeyWordsRaw = top3Tokens(scValues, 3).filter(
    (s) => s.toLowerCase() !== "alphamountain.ai"
  );

  const servicesKeyWords =
    servicesKeyWordsRaw.length > 0 ? servicesKeyWordsRaw.join(";") : undefined;

  const suspiciousFeaturesList = Array.isArray(attr.tags)
    ? attr.tags.map((t: any) => String(t)).filter(Boolean)
    : attr.tags
    ? [String(attr.tags)]
    : [];
  const suspiciousFeatures =
    suspiciousFeaturesList.length > 0
      ? suspiciousFeaturesList.join(";")
      : undefined;

  const trackers = attr?.trackers;
  const trackersCount =
    trackers && typeof trackers === "object" && !Array.isArray(trackers)
      ? Object.keys(trackers).length
      : Array.isArray(trackers)
      ? trackers.filter((t) => typeof t === "string" && t.trim() !== "").length
      : null;

  // Normalize outgoing links to an array of strings
  const outgoingLinksRaw = Array.isArray(attr.outgoing_links)
    ? attr.outgoing_links
    : attr.outgoing_links === null
    ? null
    : [];

  const embeddedUrls: string[] =
    outgoingLinksRaw === undefined || null
      ? []
      : (outgoingLinksRaw as any[]).map((u) => String(u));

  const embeddedUrlsCount =
    outgoingLinksRaw === undefined || null ? null : embeddedUrls.length;

  const embeddedUrlsEntropy =
    outgoingLinksRaw === undefined || null ? null : avgEntropy(embeddedUrls);

  const embeddedUrlsSimilarity =
    outgoingLinksRaw === undefined || null ? null : avgSimilarity(embeddedUrls);

  const externalResources = {
    embeddedUrlsCount,
    embeddedUrlsEntropy,
    embeddedUrlsSimilarity,
    trackersCount,
  };

  const redirectHosts = redirectChain
    .map((u: string) => {
      try {
        return new URL(u).hostname.toLowerCase();
      } catch {
        return null;
      }
    })
    .filter((h: string | null): h is string => Boolean(h));
  const distinctRedirectHosts = new Set(redirectHosts).size;

  // Passive DNS
  let dns: VTURLMetadata["dns"] | undefined = undefined;

  try {
    const pdDomain = await fetchPassiveDnsForDomain(hostname);
    if (pdDomain && (pdDomain.firstSeen || pdDomain.count)) {
      dns = pdDomain;
    }
  } catch {}

  if (dns && dns?.firstSeen && dns.firstSeen !== ABSENT) {
    dns.age = calculateDaysSince(dns.firstSeen);
  }

  if (dns && dns.age && dns.count && dns.count !== 0) {
    const ratio = dns.age / Math.max(dns.count, 1);
    dns.ratio = Number(ratio.toFixed(4));
  }

  // Decide serving IP using multiple fallbacks
  let servingIp: string | undefined =
    attr.last_serving_ip_address ||
    headers?.["x-real-ip"] ||
    headers?.["cf-connecting-ip"];

  // Fallback 1: URL relationships → contacted_ips
  if (!servingIp) {
    try {
      const urlId = encodeVTUrl(targetUrl);
      const ips = await fetchContactedIPsFromUrl(urlId);
      if (Array.isArray(ips) && ips.length) servingIp = ips[0];
    } catch (e: any) {
      if (!isForbidden(e))
        dlog(
          "contacted_ips as network fallback failed:",
          e?.message || String(e)
        );
    }
  }

  // Fallback 3: domain first A record from last_dns_records
  if (!servingIp) {
    const firstA = (domain as any)?._firstA as string | undefined;
    if (firstA) servingIp = firstA;
  }

  // Build network object with all keys present so deepMarkAbsent won't leave `{}`
  let network: VTURLMetadata["network"] = {
    asOwner: undefined,
    country: undefined,
  };

  if (servingIp) {
    const ipInfo = await fetchIPInfo(servingIp);
    network = {
      asOwner: ipInfo?.asOwner,
      country: ipInfo?.country,
    };
  }

  // 0) Prefer VT domain attributes last_https_certificate when available (after domain is fetched)
  try {
    const domainLastCert = (domain as any)?._lastHttpsCert;
    if (!certAttributes && domainLastCert) {
      if (domainLastCert.subject) {
        certAttributes = domainLastCert;
      } else {
        const deref = await fetchCertificateById(domainLastCert);
        if (deref) certAttributes = deref;
      }
    }
  } catch {}

  // Build tlsInfo from certAttributes if available
  let tlsInfo: VTURLMetadata["tlsInfo"] | undefined = undefined;
  if (certAttributes) {
    const subjectObj =
      (certAttributes as any).subject ?? (certAttributes as any).subject_dn;

    const subjectCN =
      parseCNFromDN(subjectObj) ||
      (certAttributes as any).subject_cn ||
      undefined;

    // Prefer DN strings if available, else fall back to CNs, else JSON
    const subjectStr =
      typeof subjectObj === "string"
        ? subjectObj
        : subjectCN ?? (subjectObj ? JSON.stringify(subjectObj) : undefined);

    const subjectMatch =
      hostname && subjectStr
        ? isSubjectOverlap(hostname, subjectStr)
        : undefined;

    const nbRaw =
      (certAttributes as any).validity?.not_before ??
      (certAttributes as any).not_before ??
      (certAttributes as any).validity_not_before;
    const naRaw =
      (certAttributes as any).validity?.not_after ??
      (certAttributes as any).not_after ??
      (certAttributes as any).validity_not_after;

    // SAN extraction: VT may provide as string or array under different keys
    let sanEntries: string[] | null = null;
    const sanSrc =
      (certAttributes as any).extensions?.subject_alternative_name ??
      (certAttributes as any).subject_alternative_name ??
      (certAttributes as any).subject_alt_name ??
      (certAttributes as any).san;
    if (Array.isArray(sanSrc)) {
      sanEntries = sanSrc.map((s: any) => String(s)).filter(Boolean);
    } else if (typeof sanSrc === "string") {
      // Common format: "DNS:example.com, DNS:www.example.com"
      sanEntries = sanSrc
        .split(/,\s*/)
        .map((s: string) => s.replace(/^DNS:/i, "").trim())
        .filter(Boolean);
    } else if (sanSrc === null) {
      sanEntries = null;
    }

    const sanEntriesCount = Array.isArray(sanEntries)
      ? sanEntries.length
      : sanEntries === null
      ? null
      : undefined;
    const sanEntriesEntropy =
      Array.isArray(sanEntries) && sanEntries.length
        ? avgEntropy(sanEntries)
        : sanEntries === null
        ? null
        : undefined;
    const sanEntriesSimilarity = Array.isArray(sanEntries)
      ? avgSimilarity(sanEntries)
      : sanEntries === null
      ? null
      : undefined;

    const validFrom = formatUtcDateTime(nbRaw);
    const validTo = formatUtcDateTime(naRaw);

    let validDays;
    if (validFrom ?? validTo) {
      validDays = computeDaysBetween(validFrom, validTo);
    }

    if (subjectStr && validFrom && validTo) {
      tlsInfo = {
        subject: subjectStr,
        subjectMatch,
        validFrom,
        validTo,
        validDays,
        sanEntriesCount,
        sanEntriesEntropy,
        sanEntriesSimilarity,
      };
      dlog("tlsInfo:", tlsInfo);
    } else {
      dlog("tlsInfo not fully populated (missing one of subject/validity)");
    }
  }

  const selectedFields: any = {
    // Basic
    url,
    urlEntropy,
    hostname,
    isHttps,
    contentInfo: {
      title: contentInfo?.title,
      faviconHostMatch: contentInfo?.faviconHostMatch,
      charset: contentInfo?.charset,
      mimeType: contentInfo?.mimeType,
    },

    // Votes
    reputation: attr?.reputation ?? null,
    maliciousVotes: maliciousCount,
    suspiciousVotes: suspiciousCount,
    servicesKeyWords,
    suspiciousFeatures,

    // Redirect
    redirect: {
      count: redirect?.count,
      entropy: redirect?.entropy,
      similarity: redirect?.similarity,
    },

    // DNS
    dns: {
      ratio: dns?.ratio,
    },

    // Domain
    domain: {
      age: domain?.age,
      validDays: domain?.validDays,
    },

    // Network
    network: {
      asOwner: network?.asOwner,
      country: network?.country,
    },

    // HTTP
    httpInfo: {
      statusCode: httpInfo?.statusCode,
    },

    header: {
      httpServer: httpInfo?.headers["server"],
      contentSecurityPolicyCount: contentSecurityPolicyCount,
      strictTransportSecurity: httpInfo?.headers["strict-transport-security"],
      xFrameOptions: httpInfo?.headers["x-frame-options"],
      xContentTypeOptions: httpInfo?.headers["x-content-type-options"],
      cacheControl: httpInfo?.headers["cache-control"],
    },

    // TLS
    tlsInfo: {
      subjectMatch: tlsInfo?.subjectMatch,
      validDays: tlsInfo?.validDays,
      sanEntriesCount: tlsInfo?.sanEntriesCount,
      sanEntriesEntropy: tlsInfo?.sanEntriesEntropy,
      sanEntriesSimilarity: tlsInfo?.sanEntriesSimilarity,
    },

    // External Resources
    externalResources: {
      embeddedUrlsCount: externalResources?.embeddedUrlsCount,
      embeddedUrlsEntropy: externalResources?.embeddedUrlsEntropy,
      embeddedUrlsSimilarity: externalResources?.embeddedUrlsSimilarity,
      trackersCount: externalResources?.trackersCount,
    },
  };

  return selectedFields;
}

function finalizeOutput(selectedFields: any): Record<string, any> {
  const output = deepMarkAbsent(selectedFields);
  const flattenedOutput = flattenObject(output);
  const mask = CUSTOMED_FIELDS_NAME;

  const maskedOutput = applyOutputMask(flattenedOutput, mask);
  const nullCount = countNullValues(maskedOutput);
  const hasNullCountMask = Object.prototype.hasOwnProperty.call(
    mask,
    "nullCount"
  );
  const nullCountAlias = hasNullCountMask ? mask["nullCount"] : undefined;

  if (nullCountAlias !== null) {
    const targetKey = nullCountAlias ?? "nullCount";
    if (
      Object.prototype.hasOwnProperty.call(maskedOutput, targetKey) &&
      maskedOutput[targetKey] !== nullCount
    ) {
      dlog(`nullCount target key collision detected for ${targetKey}`);
    }
    maskedOutput[targetKey] = nullCount;
  }

  return maskedOutput;
}

function validateURL(url: string): string | null {
  if (typeof url !== "string") return null;

  const trimmed = url.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed.toLowerCase();
  } else return null;
}

function describeLogTarget(url: string, context?: ScanContext): string {
  if (context?.logId && context.logId.trim().length > 0) return context.logId;
  if (context?.order && context.order.trim().length > 0) return context.order;
  return url;
}

export async function scanUrl(
  target: string,
  context: ScanContext = {}
): Promise<ScanResult> {
  const url = validateURL(target);
  if (url === null) {
    return {
      status: "error",
      error: "Invalid URL. Please provide an URL starts with 'http' or 'https'",
    };
  }
  console.log(`VirusTotal is scanning: ${describeLogTarget(url, context)}`);

  try {
    let urlReport: any | null = null;
    try {
      urlReport = await getUrlReport(url);
    } catch (e: any) {
      const message = e?.message || String(e);
      const isNotFound = message.includes("404");
      if (isNotFound) {
        console.log(
          "No existing VirusTotal report — submitting to VT and waitlisting."
        );
        try {
          await submitUrl(url);
        } catch (_) {
          // ignore submission failures; still waitlist the URL
        }
        const waitlistUrl = context?.rawUrl ?? target;
        if (!context?.disableAutomaticWaitlist) {
          appendToWaitlist(waitlistUrl, "no VT report", context);
        }
        return { status: "waitlist", note: "no VT report" };
      }
      const errorUrl = context?.rawUrl ?? target;
      appendToErrorLog(errorUrl, message, context);
      return { status: "error", error: message };
    }

    const _attr = urlReport?.data?.attributes ?? {};
    if (!_attr || !_attr.last_analysis_stats) {
      console.log(
        "VirusTotal record exists but analysis not complete — adding to waitlist."
      );
      const waitlistUrl = context?.rawUrl ?? target;
      if (!context?.disableAutomaticWaitlist) {
        appendToWaitlist(waitlistUrl, "analysis not complete", context);
      }
      return { status: "waitlist", note: "analysis not complete" };
    }

    let selectedFields: any = await buildVTMetadata(url, urlReport);
    let flattened = finalizeOutput(selectedFields);

    return { status: "success", data: flattened };
  } catch (err: any) {
    const message = err?.message || String(err);
    const errorUrl = context?.rawUrl ?? target;
    appendToErrorLog(errorUrl, message, context);
    return { status: "error", error: message };
  }
}

export async function runScanner(urlArg?: string): Promise<string | null> {
  const target = urlArg ?? HARDCODED_URL;
  const result = await scanUrl(target, { rawUrl: target });

  if (result.status === "waitlist") {
    console.log("URL added to waitlist; no output generated yet.");
    return null;
  }
  if (result.status === "error") {
    console.error("Scan failed:", result.error);
    return null;
  }

  const flattenedOutput = result.data;
  const promptOutput = formatPrompt(flattenedOutput, INSTRUCTION || "");

  return promptOutput;
}
