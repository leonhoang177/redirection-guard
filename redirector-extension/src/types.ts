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

  // Domain and WHOIS info
  domain: {
    registrar?: string;
    creationDate?: string;
    expirationDate?: string;
    domainAge?: number;
    whoisData?: WhoisData;
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

export interface WhoisData {
  registrar?: string;
  registrarUrl?: string;
  creationDate?: string;
  expirationDate?: string;
  updatedDate?: string;
  nameServers?: string[];
  contacts?: {
    registrant?: ContactInfo;
    admin?: ContactInfo;
    tech?: ContactInfo;
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
  engines?: EngineResult[];
}

export interface EngineResult {
  engine: string;
  category: string;
  result: string;
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

// Additional API response types
export interface WhoisAPIResponse {
  domain?: string;
  registrar?: string;
  registrar_url?: string;
  creation_date?: string;
  expiration_date?: string;
  updated_date?: string;
  name_servers?: string[];
  contacts?: {
    registrant?: ContactInfo;
    admin?: ContactInfo;
    tech?: ContactInfo;
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
