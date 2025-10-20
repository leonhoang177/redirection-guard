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
  redirectChain?: string[];
  redirectDepth: number;

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
    statusCode?: number;
    responseTime?: number;
    headers?: Record<string, string>;
    contentType?: string;
    contentLength?: number;
    serverInfo?: string;
    /** Whether HSTS is present via the Strict-Transport-Security header */
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

  /** Vendor votes summary (VirusTotal attributes.total_votes) */
  votes?: {
    harmless: number;
    malicious: number;
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
    language?: string;
    favicon?: string;
    faviconHash?: string;
    sha256?: string;
    md5?: string;
    mimeType?: string;
    contentEntropy?: number;
  };

  // Detection and threat info
  detectionStats: DetectionStats;
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
    /** Whether JavaScript activity was detected (true/false), or null if undetermined */
    javascriptActivityDetected?: boolean | null;

    /** Status flag for JS activity (preferred for ML/export) */
    javascriptActivityStatus?: StatusFlag;
    suspiciousRedirects?: boolean;
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

export interface ContactInfo {
  name?: string;
  organization?: string;
  email?: string;
  country?: string;
}

export interface DetectionStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  total: number;
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
  // Analysis results
  last_analysis_stats: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    timeout: number;
  };
  last_analysis_results?: Record<
    string,
    {
      category: string;
      engine_name: string;
      engine_version: string;
      result: string;
      method: string;
    }
  >;

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
  html_meta?: {
    description?: string[];
    keywords?: string[];
    language?: string;
    author?: string[];
  };

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

// ===== Flat training row schema (value + status) =====
export type StatusFlag = "ok" | "not_present" | "unknown" | "error";

// Flat CSV-friendly row used for model training
export interface FlatScanRow {
  url: string;
  redirect_depth: number | null;

  javascript_activity_detected: 0 | 1 | null;
  javascript_activity_status: StatusFlag;

  hsts: 0 | 1 | null;
  hsts_status: StatusFlag;

  status_code: number | null;
  status_code_status: StatusFlag;

  vt_votes_harmless: number | null;
  vt_votes_malicious: number | null;
  vt_votes_status: StatusFlag;

  tls_valid_days: number | null;
  tls_valid_days_status: StatusFlag;

  reputation_score: number | null;
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

function analysisDone(status: string | undefined) {
  // status: queued | in-progress | completed (and maybe "failed")
  return status === "completed" || status === "failed";
}

async function pollAnalysis(
  analysisId: string,
  timeoutMs: number,
  intervalMs: number
) {
  const start = Date.now();
  while (true) {
    const data = await vtGet(`/analyses/${analysisId}`);
    const status = data?.data?.attributes?.status as string | undefined;

    if (analysisDone(status)) {
      return data;
    }

    if (Date.now() - start > timeoutMs) {
      throw new Error("Timed out waiting for analysis to complete.");
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
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
    return { registrar, creationDate, expirationDate, domainAge };
  } catch {
    return {
      registrar: ERROR,
      creationDate: ERROR,
      expirationDate: ERROR,
      domainAge: ERROR,
    };
  }
}

async function fetchIPInfo(ip: string): Promise<VTURLMetadata["network"]> {
  try {
    const ipResp: VTIPResponse = await vtGet(`/ip_addresses/${ip}`);
    const attr = ipResp?.data?.attributes ?? {};
    return {
      ipAddress: attr.ip_address,
      asn: attr.asn ? String(attr.asn) : undefined,
      asOwner: attr.as_owner,
      country: attr.country,
      continent: attr.continent,
      city: attr.city,
      isp: attr.isp,
      hostingProvider: attr.hosting_provider,
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

async function buildVTMetadata(
  targetUrl: string,
  vtUrlPayload: any
): Promise<VTURLMetadata> {
  const urlObj = new URL(targetUrl);
  const url = targetUrl;
  const hostname = urlObj.hostname;
  const path = urlObj.pathname + urlObj.search + urlObj.hash;

  const attr = vtUrlPayload?.data?.attributes ?? {};

  // HTTP Info
  const headers = attr.last_http_response_headers ?? {};
  const hsts =
    headers &&
    Object.keys(headers).some(
      (k) => k.toLowerCase() === "strict-transport-security"
    );

  const httpInfo = {
    statusCode: attr.last_http_response_code ?? undefined,
    responseTime: undefined,
    headers,
    contentType: headers
      ? headers["content-type"] ?? headers["Content-Type"] ?? undefined
      : undefined,
    contentLength: attr.last_http_response_content_length ?? undefined,
    serverInfo: headers
      ? headers["server"] ?? headers["Server"] ?? undefined
      : undefined,
    hsts: hsts || false,
  };

  // Content Info
  const contentInfo = {
    title: attr.title ?? undefined,
    language: attr.html_meta?.language ?? undefined,
    favicon: attr.favicon ?? undefined,
    faviconHash: undefined,
    sha256: attr.last_http_response_content_sha256 ?? undefined,
    md5: undefined,
    mimeType: httpInfo.contentType,
    contentEntropy: undefined,
  };

  // Votes
  const votes = attr.total_votes
    ? {
        harmless: attr.total_votes.harmless ?? 0,
        malicious: attr.total_votes.malicious ?? 0,
      }
    : undefined;

  // Certificate Info
  const cert = attr.last_https_certificate;
  const certificateInfo = cert
    ? {
        issuerCN: cert.issuer?.CN,
        subjectCN: cert.subject?.CN,
        notBefore: cert.validity?.not_before,
        notAfter: cert.validity?.not_after,
        serialNumber: cert.serial_number,
      }
    : undefined;

  // Detection Stats
  const lastStats = attr.last_analysis_stats ?? {};
  const malicious = lastStats.malicious ?? 0;
  const suspicious = lastStats.suspicious ?? 0;
  const harmless = lastStats.harmless ?? 0;
  const undetected = lastStats.undetected ?? 0;
  const total = malicious + suspicious + harmless + undetected;

  const detectionStats: DetectionStats = {
    malicious,
    suspicious,
    harmless,
    undetected,
    total,
  };

  // Threat info
  const threatCategories: string[] | undefined = attr.categories
    ? Object.values(attr.categories).map((v: unknown) => String(v))
    : undefined;
  const malwareFamily = attr.threat_names ?? undefined;
  const impersonatedBrand =
    attr.targeted_brand ?? attr.popular_threat_name ?? undefined;
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

  // Behavior Info - no live JS analysis in VT URL attributes
  const behaviorInfo = {
    javascriptActivityDetected: null,
    javascriptActivityStatus: "not_present" as StatusFlag,
    suspiciousRedirects: undefined,
    dataUriUsage: undefined,
    hiddenElements: undefined,
  };

  // Redirect info
  const finalUrl = attr.last_final_url ?? undefined;
  const redirectChain = attr.redirection_chain ?? undefined;
  const redirectDepth = redirectChain ? redirectChain.length : 0;

  // Network info
  let network: VTURLMetadata["network"] = {};
  if (attr.last_serving_ip_address) {
    network = await fetchIPInfo(attr.last_serving_ip_address);
  }

  // Domain info
  const domain = await fetchDomainInfo(hostname);

  const metadata: VTURLMetadata = {
    scanId: vtUrlPayload?.data?.id,
    reputation: attr.reputation ?? undefined,

    url,
    hostname,
    path,
    finalUrl,
    redirectChain,
    redirectDepth,

    domain: {
      registrar: domain.registrar,
      creationDate: domain.creationDate,
      expirationDate: domain.expirationDate,
      domainAge: domain.domainAge,
    },

    network,

    httpInfo,

    tlsInfo: undefined,

    votes,

    certificateInfo,

    contentInfo,

    detectionStats,

    threatCategories,
    malwareFamily,
    impersonatedBrand,
    suspiciousFeatures,

    externalResources,

    behaviorInfo,

    passiveDns: undefined,
  };

  return metadata;
}

async function run() {
  const cliArg = process.argv[2]; // optional CLI arg
  const target = cliArg || HARDCODED_URL;

  console.log(`VirusTotal URL scan for: ${target}`);

  let urlReport: any | null = null;

  // 1) Try to fetch an existing report
  try {
    urlReport = await getUrlReport(target);
  } catch (e: any) {
    // If no report exists, submit and poll
    console.log("No existing report found — submitting URL to VirusTotal…");
    const initialWaitMs = 10000; // 10s initial wait
    const analysisId = await submitUrl(target);
    if (!analysisId) throw new Error("No analysis id returned by VT.");

    console.log(`Polling analysis: ${analysisId}`);
    await pollAnalysis(analysisId, POLL_TIMEOUT_MS, POLL_INTERVAL_MS);

    // After completion, fetch the URL report again
    urlReport = await getUrlReport(target);
  }

  // 2) Extract a concise, useful summary from VT payload
  const metadata: VTURLMetadata = await buildVTMetadata(target, urlReport);

  const output = deepMarkAbsent(metadata);

  // 4) Write JSON to output.json file
  fs.writeFileSync("output.json", JSON.stringify(output, null, 2), "utf-8");
  console.log("Output written to output.json");
}

run().catch((err) => {
  console.error("Error:", err?.message || err);
  process.exit(1);
});
