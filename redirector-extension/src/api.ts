import { VTURLMetadata, VTURLResponse, DetectionStats } from "./types.js";

export class VirusTotalService {
  private apiKey: string;
  private baseUrl = "https://www.virustotal.com/api/v3";

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  /**
   * Quick URL analysis for redirect guard (simplified)
   */
  async scanURL(url: string): Promise<VTURLMetadata> {
    try {
      const urlId = btoa(url).replace(/=/g, "");
      const response = await fetch(`${this.baseUrl}/urls/${urlId}`, {
        headers: {
          "x-apikey": this.apiKey,
        },
      });

      if (!response.ok) {
        if (response.status === 404) {
          // Submit URL for analysis
          await this.submitURL(url);
          throw new Error("URL not found in database. Submitted for analysis.");
        }
        throw new Error(`API error: ${response.status}`);
      }

      const data: VTURLResponse = await response.json();
      return this.parseVTResponse(url, data);
    } catch (error: any) {
      console.error("VirusTotal scan error:", error);
      throw error;
    }
  }

  /**
   * Submit URL to VirusTotal for analysis
   */
  async submitURL(url: string): Promise<void> {
    try {
      const formData = new FormData();
      formData.append("url", url);

      await fetch(`${this.baseUrl}/urls`, {
        method: "POST",
        headers: {
          "x-apikey": this.apiKey,
        },
        body: formData,
      });
    } catch (error) {
      console.error("Error submitting URL:", error);
    }
  }

  /**
   * Parse VirusTotal response into simplified metadata
   */
  private parseVTResponse(url: string, data: VTURLResponse): VTURLMetadata {
    const attrs = data.data.attributes;
    const hostname = new URL(url).hostname;

    // Detection stats
    const stats = attrs.last_analysis_stats;
    const detectionStats: DetectionStats = {
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      harmless: stats.harmless,
      undetected: stats.undetected,
      total: stats.malicious + stats.suspicious + stats.harmless + stats.undetected,
    };

    // Basic metadata structure
    const metadata: VTURLMetadata = {
      scanId: data.data.id,
      reputation: this.calculateReputation(detectionStats),
      url: url,
      hostname: hostname,
      path: new URL(url).pathname,
      finalUrl: attrs.last_final_url || url,
      redirectChain: attrs.redirection_chain || [],
      redirectDepth: attrs.redirection_chain?.length || 0,

      domain: {
        registrar: "Unknown",
        domainAge: undefined,
      },

      network: {
        ipAddress: attrs.last_serving_ip_address,
        country: "Unknown",
        hostingProvider: "Unknown",
      },

      httpInfo: {
        statusCode: attrs.last_http_response_code,
        headers: attrs.last_http_response_headers || {},
        contentType: attrs.last_http_response_headers?.["content-type"],
        hsts: this.hasHSTS(attrs.last_http_response_headers),
      },

      contentInfo: {
        title: attrs.title,
        sha256: attrs.last_http_response_content_sha256,
      },

      detectionStats,
      threatCategories: attrs.categories ? Object.values(attrs.categories) : [],
      suspiciousFeatures: attrs.tags || [],

      externalResources: {
        linkedDomains: [],
        embeddedUrls: attrs.outgoing_links || [],
        externalScripts: [],
        trackers: attrs.trackers?.map(t => t.id) || [],
      },

      behaviorInfo: {
        suspiciousRedirects: (attrs.redirection_chain?.length || 0) > 2,
        dataUriUsage: false,
        hiddenElements: false,
      },
    };

    return metadata;
  }

  /**
   * Calculate simple reputation score
   */
  private calculateReputation(stats: DetectionStats): number {
    const total = stats.total;
    if (total === 0) return 0;

    const score = (stats.harmless - stats.malicious * 2 - stats.suspicious) / total;
    return Math.max(-100, Math.min(100, Math.round(score * 100)));
  }

  /**
   * Check if HSTS is present in headers
   */
  private hasHSTS(headers: Record<string, string> | undefined): boolean {
    if (!headers) return false;
    const hstsHeader = headers["strict-transport-security"] || headers["Strict-Transport-Security"];
    return !!hstsHeader;
  }

  /**
   * Get simple verdict for URL
   */
  getVerdict(metadata: VTURLMetadata): string {
    const { malicious, suspicious } = metadata.detectionStats;

    if (malicious > 0) {
      return "malicious";
    } else if (suspicious > 3) {
      return "suspicious";
    } else if (suspicious > 0 || metadata.suspiciousFeatures?.length) {
      return "unknown";
    } else {
      return "safe";
    }
  }
}

// Export utility functions for CSV and other features
export function convertToCSV(results: VTURLMetadata[]): string {
  const headers = [
    "URL",
    "Verdict",
    "Malicious",
    "Suspicious",
    "Harmless",
    "Domain",
    "Country",
    "Redirects",
    "Title"
  ].join(",");

  const rows = results.map(result => {
    const service = new VirusTotalService(""); // Dummy instance for verdict
    const verdict = service.getVerdict(result);
    
    return [
      `"${result.url}"`,
      verdict,
      result.detectionStats.malicious,
      result.detectionStats.suspicious,
      result.detectionStats.harmless,
      `"${result.hostname}"`,
      `"${result.network.country || 'Unknown'}"`,
      result.redirectDepth,
      `"${result.contentInfo.title || 'Unknown'}"`
    ].join(",");
  });

  return [headers, ...rows].join("\n");
}

export function downloadCSV(csv: string, filename: string): void {
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  
  URL.revokeObjectURL(url);
}
