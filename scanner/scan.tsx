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
  // Metadata
  scanId?: string;
  reputation?: number;

  // Basic URL info
  url: string;
  hostname: string;
  path: string;
  finalUrl?: string;
  urlEntropy?: number;
  redirectChain?: string[];
  redirectDepth: number;
  redirectEntropy?: number;

  // Domain info
  domain: {
    registrar?: string;
    creationDate?: string;
    expirationDate?: string;
    domainAge?: number | string;
  };

  // Network and hosting info
  network: {
    ipAddress?: string;
    asn?: string;
    asOwner?: string;
    country?: string;
    continent?: string;
    city?: string;
    isp?: string;
    hostingProvider?: string;
  };

  // HTTP response info
  httpInfo: {
    headers?: Record<string, string>;
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
    sanEntries?: string[];
    fingerprint?: string;
  };

  /** Parsed TLS certificate summary (from attributes.last_https_certificate) */
  certificateInfo?: {
    issuerCN?: string;
    subjectCN?: string;
    notBefore?: string; // ISO 8601
    notAfter?: string; // ISO 8601
    serialNumber?: string;
  };

  // Content and security analysis
  contentInfo: {
    title?: string;
    favicon?: string;
    sha256?: string;
    contentEntropy?: number;
  };

  // Detection and threat info
  detectionVotes: DetectionStats;
  threatCategories?: string[];
  malwareFamily?: string[];
  impersonatedBrand?: string;
  suspiciousFeatures?: string[];

  // External resources and links
  externalResources: {
    linkedDomains?: string[];
    embeddedUrls?: string[];
    externalScripts?: string[];
    trackers?: string[];
  };

  // Behavioral indicators
  behaviorInfo: {
    javascriptActivity?: boolean | null;
    dataUriUsage?: boolean;
    hiddenElements?: boolean;
  };

  // Passive DNS and historical data
  passiveDns?: {
    firstSeen?: string;
    lastSeen?: string;
    distinctIps?: string[];
    totalResolutions?: number;
  };
}

export interface DetectionStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

// VirusTotal API Response interfaces
export interface VTURLResponse {
  data: {
    id: string;
    type: string;
    attributes: VTURLAttributes;
    relationships?: {
      network_location?: { data: { id: string; type: string } };
      contacted_domains?: { data: Array<{ id: string; type: string }> };
      contacted_ips?: { data: Array<{ id: string; type: string }> };
    };
  };
}

export interface VTURLAttributes {
  // HTTP info
  last_http_response_code?: number;
  last_http_response_headers?: Record<string, string>;
  last_http_response_content_sha256?: string;
  last_http_response_content_length?: number;
  last_serving_ip_address?: string;

  // Redirect info
  last_final_url?: string;
  redirection_chain?: string[];

  // Content info
  title?: string;
  favicon?: string;

  // Categories and tags
  categories?: Record<string, string>;
  tags?: string[];

  // Trackers and external resources
  trackers?: Record<string, any>[];
  outgoing_links?: string[];

  // Timestamps
  first_submission_date?: number;
  last_analysis_date?: number;
  last_modification_date?: number;

  // Additional attributes
  threat_names?: string[];
  popular_threat_name?: string;
  targeted_brand?: string;

  total_votes?: {
    harmless: number;
    malicious: number;
  };

  last_https_certificate?: {
    issuer?: { CN?: string };
    subject?: { CN?: string };
    validity?: { not_before?: string; not_after?: string };
    serial_number?: string;
  };

  reputation?: number;
  times_submitted?: number;
  last_submission_date?: number;
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
      whois?: string;
      whois_date?: number;
      categories?: Record<string, string>;
      reputation?: number;
      last_analysis_stats?: {
        malicious: number;
        suspicious: number;
        harmless: number;
        undetected: number;
      };
      isp?: string;
      hosting_provider?: string;
      city?: string;
    };
  };
}

export interface VTIPResponse {
  data: {
    id: string;
    type: string;
    attributes: {
      ip_address?: string;
      network?: string;
      asn?: number;
      as_owner?: string;
      country?: string;
      continent?: string;
      city?: string;
      isp?: string;
      hosting_provider?: string;
      regional_internet_registry?: string;
      whois?: string;
      whois_date?: number;
      reputation?: number;
      last_analysis_stats?: {
        malicious: number;
        suspicious: number;
        harmless: number;
        undetected: number;
      };
    };
  };
}

export interface GeoIPResponse {
  ip?: string;
  country_code?: string;
  country_name?: string;
  region_code?: string;
  region_name?: string;
  city?: string;
  zip_code?: string;
  time_zone?: string;
  latitude?: number;
  longitude?: number;
  metro_code?: number;
  isp?: string;
  organization?: string;
  as?: string;
  asname?: string;
}

// ===== scanner.tsx (kept in full) =====
import fs from "fs";

const ABSENT = "absent";
const ERROR = "error";

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

// Helper: Append a failed URL to a waitlist file (best-effort)
function appendToWaitlist(url: string, note?: string) {
  try {
    const line = `${new Date().toISOString()}\t${url}${
      note ? `\t${note}` : ""
    }\n`;
    fs.appendFileSync("waitlist.txt", line, { encoding: "utf-8" });
  } catch (e) {
    // best-effort; do not crash if we can't write the waitlist
  }
}

// ====== CONFIG ======
const API_KEY =
  "1d0b32a0630fc45fc0f7ef17c35421d2f56d961f97fcca7a9a135b4235268bf9";
const BASE = "https://www.virustotal.com/api/v3";
const HARDCODED_URL = "https://www.apple.com/"; // <--- change to your target
const POLL_INTERVAL_MS = 1500; // VT is rate-limited; be gentle
const POLL_TIMEOUT_MS = 60_000; // stop after 60s

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
    const domainResp: VTDomainResponse = await vtGet(`/domains/${hostname}`);
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
      registrar,
      creationDate,
      expirationDate,
      domainAge,
      _lastHttpsCert: lastHttpsCert,
      _firstA: firstA,
    } as any;
  } catch {
    return {
      registrar: ERROR,
      creationDate: ERROR,
      expirationDate: ERROR,
      domainAge: ERROR,
      _lastHttpsCert: undefined,
      _firstA: undefined,
    } as any;
  }
}

async function fetchIPInfo(ip: string): Promise<VTURLMetadata["network"]> {
  try {
    const ipResp: VTIPResponse = await vtGet(`/ip_addresses/${ip}`);
    const attr = ipResp?.data?.attributes ?? {};

    // Start with VT-provided country; if missing, try to parse from WHOIS text
    let country: string | undefined = attr.country || undefined;
    let continent: string | undefined = attr.continent || undefined;

    // Derive ISP/hosting from VT fields with sensible fallbacks
    const asOwner = attr.as_owner || undefined;
    const isp = attr.isp || asOwner || undefined;
    const hostingProvider =
      attr.hosting_provider || isp || asOwner || undefined;

    // Best-effort city extraction from WHOIS text (VT-only, no external lookups)
    const whoisText = typeof attr.whois === "string" ? attr.whois : undefined;
    let city: string | undefined =
      attr.city || extractCityFromWhoisText(whoisText);

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

    // Derive continent from country code if needed
    if (!continent && country) {
      const cc = country.toUpperCase();
      const map: Record<string, string> = {
        US: "NA",
        CA: "NA",
        MX: "NA",
        BR: "SA",
        AR: "SA",
        CL: "SA",
        CO: "SA",
        PE: "SA",
        GB: "EU",
        UK: "EU",
        IE: "EU",
        FR: "EU",
        DE: "EU",
        ES: "EU",
        IT: "EU",
        NL: "EU",
        BE: "EU",
        SE: "EU",
        NO: "EU",
        DK: "EU",
        FI: "EU",
        PL: "EU",
        PT: "EU",
        CZ: "EU",
        AT: "EU",
        CH: "EU",
        RU: "EU",
        UA: "EU",
        RO: "EU",
        HU: "EU",
        GR: "EU",
        TR: "AS",
        SA: "AS",
        AE: "AS",
        IL: "AS",
        QA: "AS",
        KW: "AS",
        CN: "AS",
        JP: "AS",
        KR: "AS",
        IN: "AS",
        SG: "AS",
        HK: "AS",
        TW: "AS",
        TH: "AS",
        MY: "AS",
        ID: "AS",
        PH: "AS",
        VN: "AS",
        AU: "OC",
        NZ: "OC",
        ZA: "AF",
        NG: "AF",
        EG: "AF",
        KE: "AF",
        MA: "AF",
      };
      continent = map[cc] || undefined;
    }

    return {
      ipAddress: attr.ip_address || ip,
      asn: attr.asn ? String(attr.asn) : undefined,
      asOwner,
      country,
      continent,
      city,
      isp,
      hostingProvider,
    };
  } catch {
    return {
      ipAddress: ERROR as any,
      asn: ERROR as any,
      asOwner: ERROR as any,
      country: ERROR as any,
      continent: ERROR as any,
      city: ERROR as any,
      isp: ERROR as any,
      hostingProvider: ERROR as any,
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

// Try toggling www. variant of hostname to increase hit rate
function toggleWww(host: string): string {
  if (host.startsWith("www.")) return host.slice(4);
  return `www.${host}`;
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
    const ips: string[] = [];
    let first: number | undefined;
    let last: number | undefined;

    for (const r of rows) {
      const a = r?.attributes || {};
      const ip = a.ip_address || r?.id; // VT often places IP in attributes
      if (ip && !ips.includes(ip)) ips.push(ip);

      const when = a.date || a.last_resolved || a.first_seen || a.last_seen;
      if (typeof when === "number") {
        if (first === undefined || when < first) first = when;
        if (last === undefined || when > last) last = when;
      }
    }

    return {
      distinctIps: ips,
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
    const hosts: string[] = [];
    let first: number | undefined;
    let last: number | undefined;

    for (const r of rows) {
      const a = r?.attributes || {};
      const host = a.host_name || r?.id; // VT often places hostname in attributes
      if (host && !hosts.includes(host)) hosts.push(host);

      const when = a.date || a.last_resolved || a.first_seen || a.last_seen;
      if (typeof when === "number") {
        if (first === undefined || when < first) first = when;
        if (last === undefined || when > last) last = when;
      }
    }

    return {
      distinctIps: undefined, // this call returns hostnames, not IPs
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

  // HTTP Info
  const headers = attr.last_http_response_headers ?? {};
  const hsts =
    headers &&
    Object.keys(headers).some(
      (k) => k.toLowerCase() === "strict-transport-security"
    );

  const httpInfo = {
    headers: headers,
    statusCode: attr.last_http_response_code ?? undefined,
    contentLength: attr.last_http_response_content_length ?? undefined,
    serverInfo: headers
      ? headers["server"] ?? headers["Server"] ?? undefined
      : undefined,
    hsts: hsts || false,
  };

  // Redirect info (define early so contentInfo/behaviorInfo can use it)
  const finalUrl = attr.last_final_url ?? undefined;
  const redirectChain: string[] = Array.isArray(attr.redirection_chain)
    ? attr.redirection_chain
    : [];
  const redirectDepth = redirectChain.length;

  // Content Info (with fallbacks)
  // Best-effort content entropy without fetching body:
  // 1) last_http_response_content_sha256, 2) title, 3) ETag, 4) URL chain
  let entropySource: string | undefined = undefined;
  if (attr.last_http_response_content_sha256) {
    entropySource = attr.last_http_response_content_sha256;
  } else if (typeof attr.title === "string" && attr.title.trim()) {
    entropySource = attr.title.trim();
  } else if (typeof headers?.["etag"] === "string") {
    entropySource = String(headers["etag"]);
  } else if (typeof headers?.["ETag"] === "string") {
    entropySource = String(headers["ETag"]);
  } else {
    entropySource = [finalUrl || url, ...redirectChain].join("|");
  }
  const contentEntropy = normalizedEntropy(entropySource || "");

  // Favicon URL: VT sometimes stores a URL, otherwise try Link header, else heuristic /favicon.ico
  let favicon: string | undefined = attr.favicon ?? undefined;
  if (!favicon) {
    const linkHeader = (headers?.["link"] || headers?.["Link"]) as
      | string
      | undefined;
    const iconFromLink = extractIconFromLinkHeader(linkHeader, finalUrl || url);
    if (iconFromLink) favicon = iconFromLink;
  }
  if (!favicon) {
    try {
      // Heuristic only; does not fetch, just fills a reasonable default
      const base = new URL(finalUrl || url);
      favicon = `${base.protocol}//${base.host}/favicon.ico`;
    } catch {}
  }

  // Entropy features
  // urlEntropy: normalized entropy of the PROVIDED URL only
  const urlEntropy = normalizedEntropy(url);

  // redirectEntropy: normalized entropy of the concatenated redirection URLs only
  const redirectEntropy = normalizedEntropy(redirectChain.join("|"));

  const contentInfo = {
    title: attr.title ?? undefined,
    favicon,
    sha256: attr.last_http_response_content_sha256 ?? undefined,
    contentEntropy,
  };

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

  // 3) If finalUrl has a different hostname, try that too
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
  const threatCategories: string[] | undefined = attr.categories
    ? Object.values(attr.categories).map((v: unknown) => String(v))
    : undefined;
  const suspiciousFeatures = attr.tags ?? undefined;

  // Normalize trackers: VT may return an array of objects, a single object, or nothing
  let trackers: string[] = [];
  if (Array.isArray(attr.trackers)) {
    trackers = attr.trackers
      .flatMap((t: any) => (t && typeof t === "object" ? Object.keys(t) : []))
      .filter(Boolean);
  } else if (attr.trackers && typeof attr.trackers === "object") {
    trackers = Object.keys(attr.trackers);
  }

  // Normalize outgoing links to an array of strings
  const embeddedUrls: string[] = Array.isArray(attr.outgoing_links)
    ? (attr.outgoing_links as string[])
    : [];

  const externalResources = {
    linkedDomains: undefined,
    embeddedUrls,
    externalScripts: undefined,
    trackers,
  };

  // Behavior Info — derive basic booleans from VT attributes
  const ctLower = (
    headers?.["content-type"] ||
    headers?.["Content-Type"] ||
    ""
  ).toLowerCase();
  const javascriptActivity = Boolean(
    ctLower.includes("javascript") ||
      ctLower.includes("json") ||
      (Array.isArray(trackers) && trackers.length > 0)
  );

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
  const dataUriUsage = Array.isArray(embeddedUrls)
    ? embeddedUrls.some(
        (u: string) => typeof u === "string" && u.startsWith("data:")
      )
    : false;

  // "hiddenElements" cannot be observed from VT URL fetches (no DOM). Default to false.
  const hiddenElements = false;

  const behaviorInfo = {
    javascriptActivity,
    dataUriUsage,
    hiddenElements,
  };

  // Passive DNS
  let passiveDns: VTURLMetadata["passiveDns"] | undefined = undefined;
  try {
    const pdDomain = await fetchPassiveDnsForDomain(hostname);
    if (
      pdDomain &&
      (pdDomain.firstSeen ||
        pdDomain.lastSeen ||
        (pdDomain.distinctIps && pdDomain.distinctIps.length))
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

  // Domain info (moved earlier so we can use _firstA as a fallback for network)
  const domain = await fetchDomainInfo(hostname);
  dlog(
    "domain _lastHttpsCert present:",
    Boolean((domain as any)?._lastHttpsCert)
  );

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

  // Fallback 2: passive DNS distinct IPs (already fetched above)
  if (!servingIp && passiveDns?.distinctIps && passiveDns.distinctIps.length) {
    servingIp = passiveDns.distinctIps[0];
  }

  // Fallback 3: domain first A record from last_dns_records
  if (!servingIp) {
    const firstA = (domain as any)?._firstA as string | undefined;
    if (firstA) servingIp = firstA;
  }

  // Build network object with all keys present so deepMarkAbsent won't leave `{}`
  let network: VTURLMetadata["network"] = {
    ipAddress: undefined,
    asn: undefined,
    asOwner: undefined,
    country: undefined,
    continent: undefined,
    city: undefined,
    isp: undefined,
    hostingProvider: undefined,
  };

  if (servingIp) {
    const ipInfo = await fetchIPInfo(servingIp);
    network = {
      ipAddress: servingIp,
      asn: ipInfo.asn,
      asOwner: ipInfo.asOwner,
      country: ipInfo.country,
      continent: ipInfo.continent,
      city: ipInfo.city,
      isp: ipInfo.isp,
      hostingProvider: ipInfo.hostingProvider,
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
    let sanEntries: string[] | undefined = undefined;
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
    }

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
        sanEntries,
        fingerprint,
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
    hostname,
    path,
    finalUrl,
    urlEntropy,
    redirectChain,
    redirectDepth,
    redirectEntropy,

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

    detectionVotes,

    threatCategories,
    suspiciousFeatures,

    externalResources,

    behaviorInfo,

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
      fs.appendFileSync("waitlist.txt", `${target}\n`, { encoding: "utf-8" });
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

  // 4) Write JSON to output.json file
  fs.writeFileSync(
    "./outputs/output.json",
    JSON.stringify(output, null, 2),
    "utf-8"
  );
  console.log("Output written to output.json");
}

run().catch((err) => {
  console.error("Error:", err?.message || err);
  process.exit(1);
});
