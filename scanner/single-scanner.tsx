// Debug flag and logger
const DEBUG = process.argv.includes("--debug");
function dlog(...args: any[]) {
  if (DEBUG) console.log("[debug]", ...args);
}

// Predicate to detect premium/forbidden errors
function isForbidden(err: any): boolean {
  const msg = String(err?.message || err || "");
  return msg.includes("403") || msg.toLowerCase().includes("forbidden");
}
// Enhanced VirusTotal API Response Types with comprehensive metadata
export interface VTURLMetadata {
  // Basic URL info
  scanId?: string;
  reputation?: number;
  url: string;
  urlEntropy?: number;
  hostname: string;
  path: string;

  // Redirection
  redirect?: {
    count: number | null;
    entropy?: number | null;
    similarity?: number | null;
  };

  // Domain info
  domain: {
    registrar?: string;
    creationDate?: string;
    expirationDate?: string;
    domainAge?: number | string;
  };

  // Network and hosting info
  network: {
    asn?: string;
    asOwner?: string;
    country?: string;
  };

  // HTTP response info
  httpInfo: {
    headers?: Record<string, string | number | null>;
    statusCode?: number;
    contentType?: string;
    contentLength?: number;
    serverInfo?: string;
    hsts?: boolean;
  };

  // TLS/SSL Certificate info
  tlsInfo?: {
    issuer: string;
    subject: string;
    validFrom: string;
    validTo: string;
    serialNumber: string;
    fingerprint?: string;
    sanEntriesCount?: number | null;
    sanEntriesEntropy?: number | null;
    sanEntriesSimilarity?: number | null;
  };

  /** Certificate */
  certificateInfo?: {
    issuerCN?: string;
    subjectCN?: string;
    notBefore?: string;
    notAfter?: string;
    serialNumber?: string;
  };

  // Content Info
  contentInfo: {
    title?: string;
    favicon?: string;
    sha256?: string;
    charset?: string;
    mimeType?: string;
    metaTagCount?: number;
  };

  // Detection Vote
  detectionVotes: DetectionStats;
  servicesKeyWords?: string;
  suspiciousFeatures?: string;

  // External Resources
  externalResources: {
    linkedDomains?: string[];
    linkedDomainsCount?: number | null;
    linkedDomainsEntropy?: number | null;
    linkedDomainsSimilarity?: number | null;
    embeddedUrls?: string[];
    embeddedUrlsCount?: number | null;
    embeddedUrlsEntropy?: number | null;
    embeddedUrlsSimilarity?: number | null;
    trackers?: string;
  };

  // Passive DNS and historical data
  passiveDns?: {
    totalResolutions?: number;
    firstSeen?: string;
    lastSeen?: string;
  };
}

export interface DetectionStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}
export interface VTDomainResponse {
  data: {
    id: string;
    type: string;
    attributes: {
      registrar?: string;
      creation_date?: number;
      last_update_date?: number;
      expiration_date?: number;
    };
  };
}

export interface VTIPResponse {
  data: {
    id: string;
    type: string;
    attributes: {
      asn?: number;
      as_owner?: string;
      country?: string;
      whois?: string;
    };
  };
}

// ===== scanner.tsx (kept in full) =====
import fs from "fs";
import { getDomain as tldGetDomain } from "tldts";

const ABSENT = null;

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

// Helper: Append a failed URL to a waitlist file (best-effort)
function appendToWaitlist(url: string, note?: string) {
  try {
    const line = `${new Date().toISOString()}\t${url}${
      note ? `\t${note}` : ""
    }\n`;
    fs.appendFileSync("./outputs/waitlist.txt", line, { encoding: "utf-8" });
  } catch (e) {
    // best-effort; do not crash if we can't write the waitlist
  }
}

// ====== CONFIG ======
const API_KEY =
  "1d0b32a0630fc45fc0f7ef17c35421d2f56d961f97fcca7a9a135b4235268bf9";
const BASE = "https://www.virustotal.com/api/v3";
const HARDCODED_URL = "https://www.apple.com/";

if (!API_KEY) {
  console.error("Missing VT_API_KEY env var.");
  process.exit(1);
}

// Encode plain URL → VT base64url (no padding)
function encodeVTUrl(u: string): string {
  return Buffer.from(u)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function vtGet(path: string) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "x-apikey": API_KEY },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GET ${path} -> ${res.status}: ${text}`);
  }
  return res.json();
}

async function vtPost(path: string, body: URLSearchParams) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "x-apikey": API_KEY,
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`POST ${path} -> ${res.status}: ${text}`);
  }
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
    const registrar = attr.registrar;
    const creationDate = attr.creation_date
      ? new Date(attr.creation_date * 1000).toISOString()
      : undefined;
    const expirationDate = attr.expiration_date
      ? new Date(attr.expiration_date * 1000).toISOString()
      : undefined;
    let domainAge: number | undefined = undefined;
    if (attr.creation_date) {
      const now = Date.now();
      domainAge = Math.floor(
        (now - attr.creation_date * 1000) / (1000 * 60 * 60 * 24)
      );
    }
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
      registrar,
      creationDate,
      expirationDate,
      domainAge,
      _lastHttpsCert: lastHttpsCert,
      _firstA: firstA,
    } as any;
  } catch {
    return {
      _queriedBase: getRegistrableDomain(hostname) || hostname,
      registrar: ABSENT,
      creationDate: ABSENT,
      expirationDate: ABSENT,
      domainAge: ABSENT,
      _lastHttpsCert: undefined,
      _firstA: undefined,
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
      asn: attr.asn ? String(attr.asn) : undefined,
      asOwner,
      country,
    };
  } catch {
    return {
      asn: ABSENT as any,
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
        : ref?.id ||
          ref?.certificate_id ||
          ref?.sha256 ||
          ref?.sha1 ||
          undefined;
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

// ---- WHOIS city parsing helpers ----
function looksLikeStreetAddress(s: string): boolean {
  const str = s.toLowerCase();
  if (
    /(street|st\.?|road|rd\.?|avenue|ave\.?|blvd|boulevard|suite|ste\.?|floor|fl\.?|building|bldg)/i.test(
      str
    )
  ) {
    return true;
  }
  const digits = (str.match(/\d+/g) || []).join("");
  if (digits.length >= 3) return true;
  return false;
}

function cleanupCityToken(raw: string): string | undefined {
  if (!raw) return undefined;
  let s = raw.trim();
  // Remove surrounding quotes
  s = s.replace(/^"|"$/g, "");
  // Strip leading postal codes like "22177 Hamburg", "DE-22177 Hamburg", "W1A 1HQ London"
  const postalRe = /^(?:[A-Z]{1,3}[- ]?)?\d{3,6}\s+(.+)$/i;
  const m1 = s.match(postalRe);
  if (m1 && m1[1]) s = m1[1].trim();
  // Remove trailing country names/codes
  s = s
    .replace(
      /,?\s*(united states|usa|germany|de|france|fr|united kingdom|uk|italy|it|spain|es)$/i,
      ""
    )
    .trim();
  if (!s || looksLikeStreetAddress(s)) return undefined;
  const letters = (s.match(/[a-z]/gi) || []).length;
  const digits = (s.match(/\d/g) || []).length;
  if (letters < 3 || digits > 2) return undefined;
  return s;
}

function extractCityFromWhoisText(whoisText?: string): string | undefined {
  if (!whoisText) return undefined;
  const lines = whoisText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  // 1) Explicit keys
  const keys = [/^city\s*:/i, /^town\s*:/i, /^location\s*:/i];
  for (const ln of lines) {
    for (const re of keys) {
      if (re.test(ln)) {
        const val = ln.split(":").slice(1).join(":").trim();
        const cleaned = cleanupCityToken(val);
        if (cleaned) return cleaned;
      }
    }
  }
  // 2) Address line heuristic
  const addrLine = lines.find((l) => /^address\s*:/i.test(l));
  if (addrLine) {
    const v = addrLine.split(":").slice(1).join(":").trim();
    const parts = v
      .split(/,\s*/)
      .map((x) => x.trim())
      .filter(Boolean);
    const candidates = parts.map(cleanupCityToken).filter(Boolean) as string[];
    if (candidates.length) {
      candidates.sort(
        (a, b) =>
          a.replace(/[^a-z]/gi, "").length - b.replace(/[^a-z]/gi, "").length
      );
      return candidates[candidates.length - 1];
    }
  }
  return undefined;
}

// Normalized Shannon entropy (bits per character), independent of length
function normalizedEntropy(s: string): number {
  if (!s || !s.length) return 0;
  const freq: Record<string, number> = {};
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let H = 0;
  const n = s.length;
  for (const k in freq) {
    const p = freq[k] / n;
    H -= p * Math.log2(p);
  }
  return +H.toFixed(4); // bits/char
}

// Simple redirect similarity metric: average normalized Levenshtein similarity between all URLs
function avgSimilarity(urls: string[]): number {
  if (!Array.isArray(urls) || urls.length < 2) return -1;
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
  for (let i = 0; i < urls.length; i++) {
    for (let j = i + 1; j < urls.length; j++) {
      sum += levenshteinSim(urls[i], urls[j]);
      pairs++;
    }
  }
  return Number((sum / pairs).toFixed(4));
}

function avgEntropy(values: string[]): number {
  if (!Array.isArray(values) || values.length === 0) return -1;
  const avg =
    values.reduce(
      (sum, v) => sum + normalizedEntropy(String(v).toLowerCase()),
      0
    ) / values.length;
  return Number(avg.toFixed(4));
}

// Compute top-N tokens from an array of phrases, ignoring common stopwords
function top3Tokens(phrases: string[] | undefined, n: number = 3): string[] {
  if (!Array.isArray(phrases) || phrases.length === 0) return [];
  const STOP = new Set([
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
  const freq: Record<string, number> = {};
  for (const p of phrases) {
    const parts = String(p)
      .split(/\s+/)
      .map((t) =>
        t.toLowerCase().replace(/^['"\(\[\{<]+|['"\)\]\}>,.;:!?]+$/g, "")
      )
      .filter(Boolean);
    for (const t of parts) {
      if (STOP.has(t)) continue;
      freq[t] = (freq[t] || 0) + 1;
    }
  }
  return Object.entries(freq)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, n)
    .map(([tok]) => tok);
}

// Heuristic parser for response-time style headers (ms)
function parseDurationToMs(raw: string): number | undefined {
  if (!raw) return undefined;
  const s = String(raw).trim();
  // cases: "123ms", "0.123s", "123", "0.123"
  const msMatch = s.match(/^([0-9]*\.?[0-9]+)\s*ms$/i);
  if (msMatch) return Math.round(parseFloat(msMatch[1]));
  const sMatch = s.match(/^([0-9]*\.?[0-9]+)\s*s(ec|econds?)?$/i);
  if (sMatch) return Math.round(parseFloat(sMatch[1]) * 1000);
  // no unit: decide by magnitude — < 20 → seconds, else ms
  const num = parseFloat(s);
  if (!Number.isNaN(num)) {
    if (num < 20) return Math.round(num * 1000); // assume seconds
    return Math.round(num); // assume ms
  }
  return undefined;
}

function parseServerTiming(header: string | undefined): number | undefined {
  if (!header) return undefined;
  // Example: "cache;desc=HIT, edge;dur=1, origin;dur=45"
  // We pick the largest dur as a conservative page time (ms)
  const parts = header.split(/,(?![^\(]*\))/g).map((p) => p.trim());
  let best: number | undefined = undefined;
  for (const p of parts) {
    const m = p.match(/dur\s*=\s*([0-9]*\.?[0-9]+)/i);
    if (m) {
      const ms = Math.round(parseFloat(m[1]));
      if (!Number.isNaN(ms)) best = Math.max(best ?? 0, ms);
    }
  }
  return best;
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
function toISODate(value: any): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "number") {
    // VT usually returns seconds for these endpoints
    const ms = value > 1e12 ? value : value * 1000;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
  }
  if (typeof value === "string") {
    const t = Date.parse(value);
    if (!Number.isNaN(t)) return new Date(t).toISOString();
  }
  return undefined;
}

async function fetchPassiveDnsForDomain(hostname: string) {
  try {
    // Prefer the documented /resolutions resource; limit to a sane page
    const resp = await vtGet(`/domains/${hostname}/resolutions?limit=40`);
    const rows = Array.isArray(resp?.data) ? resp.data : [];
    let first: number | undefined;
    let last: number | undefined;

    for (const r of rows) {
      const a = r?.attributes || {};
      const when = a.date || a.last_resolved || a.first_seen || a.last_seen;
      if (typeof when === "number") {
        if (first === undefined || when < first) first = when;
        if (last === undefined || when > last) last = when;
      }
    }

    return {
      totalResolutions: rows.length,
      firstSeen: toISODate(first),
      lastSeen: toISODate(last),
    } as VTURLMetadata["passiveDns"];
  } catch (e) {
    dlog(
      "passive DNS (domain) fetch failed:",
      (e as any)?.message || String(e)
    );
    return undefined;
  }
}

async function fetchPassiveDnsForIP(ip: string) {
  try {
    const resp = await vtGet(`/ip_addresses/${ip}/resolutions?limit=40`);
    const rows = Array.isArray(resp?.data) ? resp.data : [];
    let first: number | undefined;
    let last: number | undefined;

    for (const r of rows) {
      const a = r?.attributes || {};
      const when = a.date || a.last_resolved || a.first_seen || a.last_seen;
      if (typeof when === "number") {
        if (first === undefined || when < first) first = when;
        if (last === undefined || when > last) last = when;
      }
    }

    return {
      totalResolutions: rows.length,
      firstSeen: toISODate(first),
      lastSeen: toISODate(last),
    } as VTURLMetadata["passiveDns"];
  } catch (e) {
    dlog("passive DNS (ip) fetch failed:", (e as any)?.message || String(e));
    return undefined;
  }
}

async function buildVTMetadata(
  targetUrl: string,
  vtUrlPayload: any
): Promise<VTURLMetadata> {
  const urlObj = new URL(targetUrl);
  const url = targetUrl;
  const hostname = urlObj.hostname;
  const path = urlObj.pathname + urlObj.search + urlObj.hash;

  const attr = vtUrlPayload?.data?.attributes ?? {};
  dlog("attr keys:", Object.keys(attr));

  // HTTP Info (only top-8 selected headers kept in `headers`)
  const rawHeaders = attr.last_http_response_headers ?? {};
  const cspValues = getHeaderValuesCI(rawHeaders, "content-security-policy");

  const selectedMaybe: Record<string, string | undefined> = {
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
    "referrer-policy": getHeaderCI(rawHeaders, "referrer-policy"),
    server: getHeaderCI(rawHeaders, "server"),
    "cache-control": getHeaderCI(rawHeaders, "cache-control"),
    "x-powered-by": getHeaderCI(rawHeaders, "x-powered-by"),
  };
  // Determine HSTS from the optional value BEFORE mapping to ABSENT
  const hsts = Boolean(selectedMaybe["strict-transport-security"]);
  // Build headers map allowing string | number | null (temporary)
  const tempHeaders: Record<string, string | number | null> =
    Object.fromEntries(
      Object.entries(selectedMaybe).map(([k, v]) => [k, v ?? ABSENT])
    ) as Record<string, string | number | null>;

  // Count tokens in Content-Security-Policy using delimiters: space and semicolon,
  // and ensure the count key appears FIRST in the final headers object.
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

  // Rebuild headers with CSP count first
  const headers: Record<string, string | number | null> = {
    "content-security-policy-count": contentSecurityPolicyCount,
    ...tempHeaders,
  };
  const cacheControlHeader = headers["cache-control"];
  if (typeof cacheControlHeader === "string") {
    headers["cache-control"] = cacheControlHeader.replace(/,\s+/g, ",");
  }
  const strictTransportHeader = headers["strict-transport-security"];
  if (typeof strictTransportHeader === "string") {
    headers["strict-transport-security"] = strictTransportHeader.replace(/;\s+/g, ";");
  }

  const httpInfo = {
    headers,
    statusCode: attr.last_http_response_code ?? undefined,
    contentLength: attr.last_http_response_content_length ?? undefined,
    serverInfo: (headers["server"] as string | null) || undefined,
    hsts,
  };

  // Redirect info (define early so contentInfo can use it)
  const redirectChainRaw = Array.isArray(attr.redirection_chain)
    ? attr.redirection_chain
    : attr.redirection_chain == null
    ? null
    : [];
  const redirectChain: string[] = redirectChainRaw ?? [];

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

  // Entropy features
  // urlEntropy: normalized entropy of the PROVIDED URL only
  const urlEntropy = normalizedEntropy(url);

  // redirectEntropy: average of individual URL entropies across the chain
  const redirectCount = redirectChainRaw === null ? null : redirectChain.length;
  const redirectEntropy =
    redirectChainRaw === null ? null : avgEntropy(redirectChain);
  const redirectSimilarityValue =
    redirectChainRaw === null ? null : avgSimilarity(redirectChain);
  const redirect = {
    count: redirectCount,
    entropy: redirectEntropy,
    similarity: redirectSimilarityValue,
  };

  // Add charset, mimeType, metaTagCount extraction
  const contentTypeHeader = getHeaderCI(rawHeaders, "content-type");
  const mimeType = contentTypeHeader?.split(";")[0]?.trim();
  let charset: string | undefined = undefined;
  if (contentTypeHeader) {
    const m = contentTypeHeader.match(/charset\s*=\s*([^;]+)/i);
    if (m) charset = m[1].trim();
  }
  const htmlMeta = (attr as any).html_meta || {};
  const metaTagCount =
    htmlMeta && typeof htmlMeta === "object"
      ? Object.keys(htmlMeta).length
      : undefined;

  const contentInfo = {
    title: attr.title ?? undefined,
    favicon,
    sha256: attr.last_http_response_content_sha256 ?? undefined,
    charset,
    mimeType,
    metaTagCount,
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
    if (
      attr.last_https_certificate.issuer ||
      attr.last_https_certificate.subject
    ) {
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

  // Detection Stats
  const lastStats = attr.last_analysis_stats ?? {};
  const malicious = lastStats.malicious ?? 0;
  const suspicious = lastStats.suspicious ?? 0;
  const harmless = lastStats.harmless ?? 0;
  const undetected = lastStats.undetected ?? 0;
  const total = malicious + suspicious + harmless + undetected;

  const detectionVotes: DetectionStats = {
    malicious,
    suspicious,
    harmless,
    undetected,
  };

  // Threat info
  const scValues: string[] | undefined = attr.categories
    ? Object.values(attr.categories).map((v: unknown) => String(v))
    : undefined;
  const servicesKeyWordsList = top3Tokens(scValues, 3);
  const servicesKeyWords =
    servicesKeyWordsList.length > 0
      ? servicesKeyWordsList.join(",")
      : undefined;
  const suspiciousFeaturesList = Array.isArray(attr.tags)
    ? attr.tags.map((t: any) => String(t)).filter(Boolean)
    : attr.tags
    ? [String(attr.tags)]
    : [];
  const suspiciousFeatures =
    suspiciousFeaturesList.length > 0
      ? suspiciousFeaturesList.join(",")
      : undefined;

  // Normalize trackers: VT may return an array of objects, a single object, or nothing
  let trackersList: string[] = [];
  if (Array.isArray(attr.trackers)) {
    trackersList = attr.trackers
      .flatMap((t: any) => (t && typeof t === "object" ? Object.keys(t) : []))
      .filter(Boolean);
  } else if (attr.trackers && typeof attr.trackers === "object") {
    trackersList = Object.keys(attr.trackers);
  }
  const trackers = trackersList.length > 0 ? trackersList.join(",") : undefined;

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

  // Build linked domains from multiple sources (relationships + outgoing_links + redirects)
  const linkedHostSet = new Set<string>();

  // a) Contacted domains via URL relationships (best signal)
  try {
    const urlId = encodeVTUrl(targetUrl);
    const relDomains = await fetchContactedDomainsFromUrl(urlId);
    for (const d of relDomains) {
      if (d && typeof d === "string") linkedHostSet.add(d.toLowerCase());
    }
  } catch {}

  // b) Hosts from outgoing_links
  for (const u of embeddedUrls) {
    try {
      const h = new URL(u).hostname.toLowerCase();
      if (h) linkedHostSet.add(h);
    } catch {}
  }

  // c) Hosts from redirect chain
  for (const u of redirectChain) {
    try {
      const h = new URL(u).hostname.toLowerCase();
      if (h) linkedHostSet.add(h);
    } catch {}
  }

  // Remove the page's own hostname from linked domains
  linkedHostSet.delete(hostname.toLowerCase());

  const linkedDomains = Array.from(linkedHostSet);
  const linkedDomainsCount =
    attr.linked_domains === undefined || null ? null : linkedDomains.length;
  const linkedDomainsEntropy =
    attr.linked_domains === undefined || null
      ? null
      : avgEntropy(linkedDomains);
  const linkedDomainsSimilarity =
    attr.linked_domains === undefined || null
      ? null
      : avgSimilarity(linkedDomains);

  const externalResources = {
    linkedDomainsCount,
    linkedDomainsEntropy,
    linkedDomainsSimilarity,
    embeddedUrlsCount,
    embeddedUrlsEntropy,
    embeddedUrlsSimilarity,
    trackers,
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
  let passiveDns: VTURLMetadata["passiveDns"] | undefined = undefined;
  try {
    const pdDomain = await fetchPassiveDnsForDomain(hostname);
    if (
      pdDomain &&
      (pdDomain.firstSeen || pdDomain.lastSeen || pdDomain.totalResolutions)
    ) {
      passiveDns = pdDomain;
    }
  } catch {}

  // Optionally complement with IP-side resolutions if we have the serving IP
  try {
    const ipForDns = attr.last_serving_ip_address;
    if (!passiveDns && ipForDns) {
      const pdIp = await fetchPassiveDnsForIP(ipForDns);
      if (pdIp && (pdIp.firstSeen || pdIp.lastSeen || pdIp.totalResolutions)) {
        passiveDns = pdIp;
      }
    }
  } catch {}

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
    asn: undefined,
    asOwner: undefined,
    country: undefined,
  };

  if (servingIp) {
    const ipInfo = await fetchIPInfo(servingIp);
    network = {
      asn: ipInfo.asn,
      asOwner: ipInfo.asOwner,
      country: ipInfo.country,
    };
  }

  // 0) Prefer VT domain attributes last_https_certificate when available (after domain is fetched)
  try {
    const domainLastCert = (domain as any)?._lastHttpsCert;
    if (!certAttributes && domainLastCert) {
      if (domainLastCert.issuer || domainLastCert.subject) {
        certAttributes = domainLastCert;
      } else {
        const deref = await fetchCertificateById(domainLastCert);
        if (deref) certAttributes = deref;
      }
    }
  } catch {}

  // Normalize to certificateInfo shape (after all attempts)
  let certificateInfo: VTURLMetadata["certificateInfo"] = undefined;
  if (certAttributes) {
    const issuerCN =
      parseCNFromDN(certAttributes.issuer) ||
      parseCNFromDN(certAttributes.issuer_dn) ||
      (certAttributes as any).issuer_cn;
    const subjectCN =
      parseCNFromDN(certAttributes.subject) ||
      parseCNFromDN(certAttributes.subject_dn) ||
      (certAttributes as any).subject_cn;

    const nbRaw =
      certAttributes.validity?.not_before ??
      (certAttributes as any).not_before ??
      (certAttributes as any).validity_not_before;
    const naRaw =
      certAttributes.validity?.not_after ??
      (certAttributes as any).not_after ??
      (certAttributes as any).validity_not_after;

    const toIso = (v: any) =>
      typeof v === "number" ? new Date(v * 1000).toISOString() : v;

    certificateInfo = {
      issuerCN: issuerCN,
      subjectCN: subjectCN,
      notBefore: toIso(nbRaw),
      notAfter: toIso(naRaw),
      serialNumber:
        (certAttributes as any).serial_number ||
        (certAttributes as any).serialNumber ||
        (certAttributes as any).serial ||
        undefined,
    };
    dlog("certificateInfo:", certificateInfo);
  }

  // Build tlsInfo (full certificate view) from certAttributes if available
  let tlsInfo: VTURLMetadata["tlsInfo"] | undefined = undefined;
  if (certAttributes) {
    const issuerObj =
      (certAttributes as any).issuer ?? (certAttributes as any).issuer_dn;
    const subjectObj =
      (certAttributes as any).subject ?? (certAttributes as any).subject_dn;

    const issuerCN =
      parseCNFromDN(issuerObj) ||
      (certAttributes as any).issuer_cn ||
      undefined;
    const subjectCN =
      parseCNFromDN(subjectObj) ||
      (certAttributes as any).subject_cn ||
      undefined;

    // Prefer DN strings if available, else fall back to CNs, else JSON
    const issuerStr =
      typeof issuerObj === "string"
        ? issuerObj
        : issuerCN ?? (issuerObj ? JSON.stringify(issuerObj) : undefined);

    const subjectStr =
      typeof subjectObj === "string"
        ? subjectObj
        : subjectCN ?? (subjectObj ? JSON.stringify(subjectObj) : undefined);

    const nbRaw =
      (certAttributes as any).validity?.not_before ??
      (certAttributes as any).not_before ??
      (certAttributes as any).validity_not_before;
    const naRaw =
      (certAttributes as any).validity?.not_after ??
      (certAttributes as any).not_after ??
      (certAttributes as any).validity_not_after;

    const toIso = (v: any) =>
      typeof v === "number" ? new Date(v * 1000).toISOString() : v;

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
      ? sanEntries.length > 1
        ? avgSimilarity(sanEntries)
        : 1
      : sanEntries === null
      ? null
      : undefined;

    const fingerprint =
      (certAttributes as any).thumbprint_sha256 ??
      (certAttributes as any).thumbprint ??
      (certAttributes as any).sha256 ??
      (certAttributes as any).fingerprint ??
      undefined;

    const serial =
      (certAttributes as any).serial_number ??
      (certAttributes as any).serialNumber ??
      (certAttributes as any).serial ??
      undefined;

    if (issuerStr && subjectStr && nbRaw && naRaw && serial) {
      tlsInfo = {
        issuer: issuerStr,
        subject: subjectStr,
        validFrom: toIso(nbRaw),
        validTo: toIso(naRaw),
        serialNumber: serial,
        fingerprint,
        sanEntriesCount,
        sanEntriesEntropy,
        sanEntriesSimilarity,
      };
      dlog("tlsInfo:", tlsInfo);
    } else {
      dlog(
        "tlsInfo not fully populated (missing one of issuer/subject/validity/serial)"
      );
    }
  }

  const metadata: VTURLMetadata = {
    scanId: vtUrlPayload?.data?.id,
    reputation: attr.reputation ?? undefined,
    url,
    urlEntropy,
    hostname,
    path,
    redirect,
    detectionVotes,
    domain: {
      registrar: domain.registrar,
      creationDate: domain.creationDate,
      expirationDate: domain.expirationDate,
      domainAge: domain.domainAge,
    },
    network,
    httpInfo,
    tlsInfo,
    certificateInfo,
    contentInfo,
    servicesKeyWords,
    suspiciousFeatures,
    externalResources,
    passiveDns,
  };

  return metadata;
}

async function run() {
  const cliArg = process.argv[2]; // optional CLI arg
  const target = cliArg || HARDCODED_URL;

  console.log(`VirusTotal URL scan for: ${target}`);

  let urlReport: any | null = null;

  // 1) Try to fetch an existing report (no retries, no submit)
  try {
    urlReport = await getUrlReport(target);
  } catch (e: any) {
    console.log(
      "No existing VirusTotal report — submitting to VT and waitlisting."
    );
    try {
      // Submit to VT so analysis can start, but do not poll.
      await submitUrl(target);
    } catch (_) {
      // ignore submission failures; still waitlist the URL
    }
    try {
      // Write ONLY the raw URL, one per line
      fs.appendFileSync("./outputs/waitlist.txt", `${target}\n`, {
        encoding: "utf-8",
      });
    } catch (_) {
      // best-effort; don't crash if write fails
    }
    return; // stop; no output.json
  }

  // If VT record exists but lacks analysis stats, also waitlist and exit
  const _attr = urlReport?.data?.attributes ?? {};
  if (!_attr || !_attr.last_analysis_stats) {
    console.log(
      "VirusTotal record exists but analysis not complete — adding to waitlist and exiting."
    );
    appendToWaitlist(target, "analysis not complete");
    return; // do nothing else
  }

  // 2) Extract a concise, useful summary from VT payload
  const metadata: VTURLMetadata = await buildVTMetadata(target, urlReport);

  const output = deepMarkAbsent(metadata);
  const flattenedOutput = flattenObject(output);

  // 4) Write JSON to output.json file
  fs.writeFileSync(
    "./outputs/output.json",
    JSON.stringify(flattenedOutput, null, 2),
    "utf-8"
  );
  console.log("Output written to output.json");
}

run().catch((err) => {
  console.error("Error:", err?.message || err);
  process.exit(1);
});
