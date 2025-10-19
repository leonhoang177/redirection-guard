import {
  VTURLMetadata,
  VTURLResponse,
  VTDomainResponse,
  VTIPResponse,
  DetectionStats,
  EngineResult,
  WhoisAPIResponse,
  GeoIPResponse,
  FlatScanRow,
  StatusFlag,
} from "./types.js";

export class VirusTotalService {
  private apiKey: string;
  private baseUrl = "https://www.virustotal.com/api/v3";

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  /**
   * Comprehensive URL analysis with enhanced metadata extraction
   */
  async scanURL(url: string): Promise<VTURLMetadata> {
    try {
      const urlId = btoa(url).replace(/=/g, "");
      let urlReport: VTURLResponse;

      try {
        // Try to get existing analysis first
        urlReport = await this.getURLReport(urlId);
      } catch (error) {
        // If no existing report, submit for new scan
        console.log("No existing report, submitting for new scan...");
        await this.submitURL(url);

        // Wait for scan to complete with exponential backoff
        await this.waitForScanCompletion(urlId);
        urlReport = await this.getURLReport(urlId);
      }

      // Extract comprehensive metadata
      const metadata = await this.extractComprehensiveMetadata(url, urlReport);
      return metadata;
    } catch (error) {
      console.error("Error scanning URL:", error);
      throw new Error(
        `Failed to scan URL: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  /**
   * Submit URL to VirusTotal for scanning
   */
  private async submitURL(url: string): Promise<string> {
    const formData = new FormData();
    formData.append("url", url);

    const response = await fetch(`${this.baseUrl}/urls`, {
      method: "POST",
      headers: { "x-apikey": this.apiKey },
      body: formData,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `VirusTotal API error: ${response.status} - ${errorText}`
      );
    }

    const data = await response.json();
    return data.data.id;
  }

  /**
   * Get URL analysis report
   */
  private async getURLReport(urlId: string): Promise<VTURLResponse> {
    const response = await fetch(`${this.baseUrl}/urls/${urlId}`, {
      headers: { "x-apikey": this.apiKey },
    });

    if (!response.ok) {
      throw new Error(`Failed to get URL report: ${response.status}`);
    }

    return await response.json();
  }

  /**
   * Get domain information
   */
  private async getDomainInfo(
    domain: string
  ): Promise<VTDomainResponse | null> {
    try {
      const response = await fetch(`${this.baseUrl}/domains/${domain}`, {
        headers: { "x-apikey": this.apiKey },
      });

      if (!response.ok) return null;
      return await response.json();
    } catch (error) {
      console.warn("Could not fetch domain info:", error);
      return null;
    }
  }

  /**
   * Get IP address from domain resolutions
   */
  private async getIPFromDomain(domain: string): Promise<string | null> {
    try {
      const response = await fetch(`${this.baseUrl}/domains/${domain}`, {
        headers: { "x-apikey": this.apiKey },
      });

      if (!response.ok) return null;

      const data = await response.json();

      // Get the most recent IP resolution
      if (data.data.attributes.last_dns_records) {
        const aRecords = data.data.attributes.last_dns_records.filter(
          (record: any) => record.type === "A"
        );
        if (aRecords.length > 0) {
          return aRecords[0].value; // Return the first A record (IP address)
        }
      }

      return null;
    } catch (error) {
      console.warn("Could not get IP from domain:", error);
      return null;
    }
  }

  /**
   * Get IP address information
   */
  private async getIPInfo(ip: string): Promise<VTIPResponse | null> {
    try {
      const response = await fetch(`${this.baseUrl}/ip_addresses/${ip}`, {
        headers: { "x-apikey": this.apiKey },
      });

      if (!response.ok) return null;
      return await response.json();
    } catch (error) {
      console.warn("Could not fetch IP info:", error);
      return null;
    }
  }

  /**
   * Get WHOIS data - Try multiple sources
   */
  private async getWhoisData(domain: string): Promise<WhoisAPIResponse | null> {
    // Skip WHOIS lookup - it's unreliable and times out frequently
    // The domain info from VirusTotal is usually sufficient
    console.warn("WHOIS lookup skipped - using VirusTotal domain data instead");
    return null;
  }

  /**
   * Get geographic IP information using ip-api.com (allows CORS for extensions)
   */
  private async getGeoIPData(ip: string): Promise<GeoIPResponse | null> {
    try {
      console.log("🌍 Fetching GeoIP data for:", ip);
      // Using ip-api.com free service (allows CORS, 45 requests/minute)
      const response = await fetch(
        `http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,isp,org,as,asname`
      );

      if (!response.ok) {
        console.warn("GeoIP API returned non-OK status:", response.status);
        return null;
      }

      const data = await response.json();
      console.log("🌍 GeoIP API response:", data);

      if (data.status === "fail") {
        console.warn("GeoIP API error:", data.message);
        return null;
      }

      return {
        ip: ip,
        country_code: data.countryCode,
        country_name: data.country,
        region_code: data.region,
        region_name: data.regionName,
        city: data.city,
        isp: data.isp,
        organization: data.org,
        as: data.as,
        asname: data.asname,
      };
    } catch (error) {
      console.warn("Could not fetch GeoIP data:", error);
      return null;
    }
  }
  /**
   * Calculate content entropy (for detecting obfuscated content)
   */
  private calculateEntropy(data: string): number {
    const freq: Record<string, number> = {};
    for (const char of data) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const length = data.length;
    for (const count of Object.values(freq)) {
      const p = count / length;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Wait for scan completion with exponential backoff
   */
  private async waitForScanCompletion(
    urlId: string,
    maxAttempts: number = 5
  ): Promise<void> {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await this.sleep(2000 * Math.pow(2, attempt)); // Exponential backoff

      try {
        const report = await this.getURLReport(urlId);
        if (report.data.attributes.last_analysis_stats) {
          return; // Analysis complete
        }
      } catch (error) {
        if (attempt === maxAttempts - 1) {
          throw new Error("Scan did not complete in time");
        }
      }
    }
  }

  /**
   * Extract comprehensive metadata from all sources
   */
  private async extractComprehensiveMetadata(
    url: string,
    urlReport: VTURLResponse
  ): Promise<VTURLMetadata> {
    const urlObj = new URL(url);
    const attrs = urlReport.data.attributes;
    // Cast to any for fields not declared in VTURLAttributes (e.g., total_votes)
    const attrsAny = attrs as any;

    // NEW: vendor votes (harmless/malicious) if present
    const totalVotes = attrsAny?.total_votes
      ? {
          harmless: attrsAny.total_votes.harmless ?? 0,
          malicious: attrsAny.total_votes.malicious ?? 0,
        }
      : undefined;

    // NEW: TLS certificate summary
    let certificateInfo: VTURLMetadata["certificateInfo"] = undefined;
    if (attrsAny?.last_https_certificate) {
      const cert = attrsAny.last_https_certificate;
      const issuerCN = cert?.issuer?.CN || cert?.issuer?.common_name;
      const subjectCN = cert?.subject?.CN || cert?.subject?.common_name;
      const notBefore = cert?.validity?.not_before
        ? new Date(cert.validity.not_before * 1000).toISOString()
        : undefined;
      const notAfter = cert?.validity?.not_after
        ? new Date(cert.validity.not_after * 1000).toISOString()
        : undefined;
      certificateInfo = {
        issuerCN,
        subjectCN,
        notBefore,
        notAfter,
        serialNumber: cert?.serial_number,
      };
    }

    if (!attrs.last_analysis_stats) {
      throw new Error(
        "Analysis not complete yet. Please try again in a few seconds."
      );
    }

    // Basic detection statistics
    const detectionStats: DetectionStats = {
      malicious: attrs.last_analysis_stats.malicious || 0,
      suspicious: attrs.last_analysis_stats.suspicious || 0,
      harmless: attrs.last_analysis_stats.harmless || 0,
      undetected: attrs.last_analysis_stats.undetected || 0,
      total: Object.keys(attrs.last_analysis_results || {}).length,
      engines: this.extractEngineResults(attrs.last_analysis_results || {}),
    };

    // Get IP address from multiple sources
    let ipAddress =
      attrs.last_serving_ip_address ||
      attrs.last_http_response_headers?.["x-real-ip"] ||
      attrs.last_http_response_headers?.["cf-connecting-ip"];

    // If still no IP, try contacted_ips
    if (!ipAddress && urlReport.data.relationships?.contacted_ips?.data?.[0]) {
      ipAddress = urlReport.data.relationships.contacted_ips.data[0].id;
    }

    // If STILL no IP, do a domain lookup
    if (!ipAddress) {
      console.log("🔍 No IP found, attempting domain resolution...");
      ipAddress = (await this.getIPFromDomain(urlObj.hostname)) || undefined;
    }

    console.log("=== IP DEBUG ===");
    console.log("last_serving_ip_address:", attrs.last_serving_ip_address);
    console.log("x-real-ip:", attrs.last_http_response_headers?.["x-real-ip"]);
    console.log(
      "cf-connecting-ip:",
      attrs.last_http_response_headers?.["cf-connecting-ip"]
    );
    console.log("Final Extracted IP Address:", ipAddress);
    console.log("===============");

    // Fetch additional data in parallel
    const [domainInfo, ipInfo, whoisData, geoData] = await Promise.all([
      this.getDomainInfo(urlObj.hostname),
      ipAddress ? this.getIPInfo(ipAddress) : null,
      this.getWhoisData(urlObj.hostname),
      ipAddress ? this.getGeoIPData(ipAddress) : null,
    ]);

    console.log("=== API RESULTS ===");
    console.log("domainInfo:", domainInfo);
    console.log("ipInfo:", ipInfo);
    console.log("geoData:", geoData);
    console.log("==================");

    // Calculate domain age
    let domainAge: number | undefined;
    if (domainInfo?.data.attributes.creation_date) {
      const creationDate = new Date(
        domainInfo.data.attributes.creation_date * 1000
      );
      domainAge = Math.floor(
        (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24)
      );
    } else if (whoisData?.creation_date) {
      const creationDate = new Date(whoisData.creation_date);
      domainAge = Math.floor(
        (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24)
      );
    }

    // Extract redirect information
    const redirectChain = attrs.redirection_chain || [];
    const redirectDepth = redirectChain.length - 1;

    // Extract content entropy if content available
    let contentEntropy: number | undefined;
    if (attrs.last_http_response_content_sha256) {
      contentEntropy = this.calculateEntropy(url);
    }

    // Extract external resources and linked domains
    const linkedDomains = this.extractLinkedDomains(urlReport);
    const embeddedUrls = attrs.outgoing_links || [];

    // Build comprehensive metadata object
    const metadata: VTURLMetadata = {
      // Basic URL info
      url: url,
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      finalUrl: attrs.last_final_url,
      redirectChain: redirectChain,
      redirectDepth: redirectDepth,

      // Domain information
      domain: {
        registrar:
          domainInfo?.data.attributes.registrar || whoisData?.registrar,
        creationDate: domainInfo?.data.attributes.creation_date
          ? new Date(
              domainInfo.data.attributes.creation_date * 1000
            ).toISOString()
          : whoisData?.creation_date,
        expirationDate: domainInfo?.data.attributes.expiration_date
          ? new Date(
              domainInfo.data.attributes.expiration_date * 1000
            ).toISOString()
          : whoisData?.expiration_date,
        domainAge: domainAge,
        whoisData: whoisData
          ? {
              registrar: whoisData.registrar,
              registrarUrl: whoisData.registrar_url,
              creationDate: whoisData.creation_date,
              expirationDate: whoisData.expiration_date,
              updatedDate: whoisData.updated_date,
              nameServers: whoisData.name_servers,
              contacts: whoisData.contacts,
            }
          : undefined,
      },

      // Network information
      network: {
        ipAddress: ipAddress,
        asn: ipInfo?.data.attributes.asn
          ? `AS${ipInfo.data.attributes.asn}`
          : geoData?.as,
        asOwner: ipInfo?.data.attributes.as_owner || geoData?.asname,
        country: ipInfo?.data.attributes.country || geoData?.country_name,
        continent: ipInfo?.data.attributes.continent,
        city: geoData?.city,
        isp: geoData?.isp,
        hostingProvider: geoData?.organization,
      },

      // HTTP response information
      httpInfo: {
        statusCode: attrs.last_http_response_code,
        headers: attrs.last_http_response_headers,
        contentType: attrs.last_http_response_headers?.["content-type"],
        contentLength: attrs.last_http_response_content_length,
        serverInfo: attrs.last_http_response_headers?.["server"],
        hsts: Boolean(
          attrs.last_http_response_headers?.["strict-transport-security"]
        ),
      },

      // Content information
      contentInfo: {
        title: attrs.title,
        language: attrs.html_meta?.language,
        favicon: attrs.favicon,
        sha256: attrs.last_http_response_content_sha256,
        mimeType:
          attrs.last_http_response_headers?.["content-type"]?.split(";")[0],
        contentEntropy: contentEntropy,
      },

      // Detection and threat information
      detectionStats: detectionStats,
      threatCategories: attrs.categories
        ? Object.values(attrs.categories)
        : undefined,
      malwareFamily: attrs.threat_names,
      impersonatedBrand: attrs.targeted_brand,
      suspiciousFeatures: this.extractSuspiciousFeatures(attrs),

      // External resources
      externalResources: {
        linkedDomains: linkedDomains,
        embeddedUrls: embeddedUrls,
        trackers: Array.isArray(attrs.trackers)
          ? attrs.trackers.map((t: any) => t.url || String(t)).filter(Boolean)
          : [],
      },

      // Behavioral indicators
      behaviorInfo: {
        javascriptActivity: this.detectJavaScriptActivity(attrs),
        suspiciousRedirects: redirectDepth > 3,
        dataUriUsage: embeddedUrls.some((url) => url.startsWith("data:")),
        hiddenElements: false, // Would need content analysis
      },

      // Passive DNS (limited without premium API)
      passiveDns: {
        firstSeen: attrs.first_submission_date
          ? new Date(attrs.first_submission_date * 1000).toISOString()
          : undefined,
        lastSeen: attrs.last_analysis_date
          ? new Date(attrs.last_analysis_date * 1000).toISOString()
          : undefined,
      },

      // Metadata
      scanDate: new Date().toISOString(),
      scanId: urlReport.data.id,
      reputation:
        domainInfo?.data.attributes.reputation ||
        ipInfo?.data.attributes.reputation,
      // NEW fields
      votes: totalVotes,
      certificateInfo,
    };

    return metadata;
  }

  /**
   * Extract engine results from analysis
   */
  private extractEngineResults(results: Record<string, any>): EngineResult[] {
    return Object.entries(results).map(([engine, result]) => ({
      engine: engine,
      category: result.category || "unknown",
      result: result.result || "clean",
    }));
  }

  /**
   * Extract linked domains from relationships
   */
  private extractLinkedDomains(urlReport: VTURLResponse): string[] {
    const domains: string[] = [];

    if (urlReport.data.relationships?.contacted_domains?.data) {
      domains.push(
        ...urlReport.data.relationships.contacted_domains.data.map((d) => d.id)
      );
    }

    return domains;
  }

  /**
   * Extract suspicious features based on various indicators
   */
  private extractSuspiciousFeatures(attrs: any): string[] {
    const features: string[] = [];

    if (attrs.redirection_chain && attrs.redirection_chain.length > 3) {
      features.push("Multiple redirects");
    }

    if (attrs.categories) {
      const categories = Object.values(attrs.categories) as string[];
      if (categories.some((cat) => cat.toLowerCase().includes("phishing"))) {
        features.push("Phishing category");
      }
      if (categories.some((cat) => cat.toLowerCase().includes("malware"))) {
        features.push("Malware category");
      }
    }

    if (attrs.targeted_brand) {
      features.push("Brand impersonation");
    }

    if (attrs.last_http_response_headers?.["set-cookie"]) {
      features.push("Sets cookies");
    }

    return features;
  }

  /**
   * Detect JavaScript activity indicators
   */
  private detectJavaScriptActivity(attrs: any): boolean {
    // Check for JavaScript-related headers or content types
    const contentType = attrs.last_http_response_headers?.["content-type"];
    return (
      contentType?.includes("javascript") ||
      contentType?.includes("json") ||
      Boolean(attrs.trackers && attrs.trackers.length > 0)
    );
  }

  /**
   * Helper function to wait
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Convert rich VTURLMetadata to a flat CSV-friendly row
   */
  public static toFlatRow(meta: VTURLMetadata): FlatScanRow {
    // redirect depth
    const redirect_depth =
      typeof meta.redirectDepth === "number" ? meta.redirectDepth : null;

    // JavaScript activity + status
    let javascript_activity: 0 | 1 | null = null;
    let javascript_activity_status: StatusFlag = "unknown";
    if (typeof meta.behaviorInfo?.javascriptActivity === "boolean") {
      javascript_activity = meta.behaviorInfo.javascriptActivity ? 1 : 0;
      javascript_activity_status = "ok";
    }

    // HSTS + status
    let hsts: 0 | 1 | null = null;
    let hsts_status: StatusFlag = "unknown";
    if (typeof meta.httpInfo?.hsts === "boolean") {
      hsts = meta.httpInfo.hsts ? 1 : 0;
      hsts_status = meta.httpInfo.hsts ? "ok" : "not_present";
    }

    // HTTP status code + status
    let status_code: number | null = null;
    let status_code_status: StatusFlag = "unknown";
    if (typeof meta.httpInfo?.statusCode === "number") {
      status_code = meta.httpInfo.statusCode;
      status_code_status = "ok";
    }

    // VT votes + status
    let vt_votes_harmless: number | null = null;
    let vt_votes_malicious: number | null = null;
    let vt_votes_status: StatusFlag = "unknown";
    if (meta.votes) {
      vt_votes_harmless =
        typeof meta.votes.harmless === "number" ? meta.votes.harmless : null;
      vt_votes_malicious =
        typeof meta.votes.malicious === "number" ? meta.votes.malicious : null;
      vt_votes_status = "ok";
    }

    // TLS valid days + status
    let tls_valid_days: number | null = null;
    let tls_valid_days_status: StatusFlag = "unknown";
    if (meta.certificateInfo?.notBefore && meta.certificateInfo?.notAfter) {
      const nb = Date.parse(meta.certificateInfo.notBefore);
      const na = Date.parse(meta.certificateInfo.notAfter);
      if (!Number.isNaN(nb) && !Number.isNaN(na) && na > nb) {
        tls_valid_days = Math.round((na - nb) / (1000 * 60 * 60 * 24));
        tls_valid_days_status = "ok";
      } else {
        tls_valid_days = null;
        tls_valid_days_status = "error";
      }
    }

    const reputation_score =
      typeof meta.reputation === "number" ? meta.reputation : null;

    return {
      url: meta.url,
      redirect_depth,
      javascript_activity,
      javascript_activity_status,
      hsts,
      hsts_status,
      status_code,
      status_code_status,
      vt_votes_harmless,
      vt_votes_malicious,
      vt_votes_status,
      tls_valid_days,
      tls_valid_days_status,
      reputation_score,
    };
  }
}

/**
 * Export comprehensive results to CSV format (flat schema)
 */
export function convertToCSV(results: VTURLMetadata[]): string {
  // Build flat rows using the static helper
  const rows: FlatScanRow[] = results.map((r) =>
    VirusTotalService.toFlatRow(r)
  );

  const headers = [
    "url",
    "javascript_activity",
    "javascript_activity_status",
    "hsts",
    "hsts_status",
    "status_code",
    "status_code_status",
    "vt_votes_harmless",
    "vt_votes_malicious",
    "vt_votes_status",
    "tls_valid_days",
    "tls_valid_days_status",
    "redirect_depth",
    "reputation_score",
  ];

  const lines: string[] = [headers.join(",")];

  for (const r of rows) {
    const cells = [
      r.url,
      r.javascript_activity ?? "",
      r.javascript_activity_status,
      r.hsts ?? "",
      r.hsts_status,
      r.status_code ?? "",
      r.status_code_status,
      r.vt_votes_harmless ?? "",
      r.vt_votes_malicious ?? "",
      r.vt_votes_status,
      r.tls_valid_days ?? "",
      r.tls_valid_days_status,
      r.redirect_depth ?? "",
      r.reputation_score ?? "",
    ];

    const line = cells
      .map((cell) => {
        const s = String(cell);
        return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      })
      .join(",");

    lines.push(line);
  }

  return lines.join("\n");
}

/**
 * Download CSV file
 */
export function downloadCSV(
  csv: string,
  filename: string = "comprehensive_url_scan.csv"
): void {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const link = document.createElement("a");
  const url = URL.createObjectURL(blob);

  link.setAttribute("href", url);
  link.setAttribute("download", filename);
  link.style.visibility = "hidden";

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
