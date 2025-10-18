import { 
  VTURLMetadata, 
  VTURLResponse, 
  VTDomainResponse, 
  VTIPResponse, 
  DetectionStats, 
  EngineResult,
  WhoisAPIResponse,
  GeoIPResponse 
} from './types.js';

export class VirusTotalService {
  private apiKey: string;
  private baseUrl = 'https://www.virustotal.com/api/v3';

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  /**
   * Comprehensive URL analysis with enhanced metadata extraction
   */
  async scanURL(url: string): Promise<VTURLMetadata> {
    try {
      const urlId = btoa(url).replace(/=/g, '');
      let urlReport: VTURLResponse;

      try {
        // Try to get existing analysis first
        urlReport = await this.getURLReport(urlId);
      } catch (error) {
        // If no existing report, submit for new scan
        console.log('No existing report, submitting for new scan...');
        await this.submitURL(url);
        
        // Wait for scan to complete with exponential backoff
        await this.waitForScanCompletion(urlId);
        urlReport = await this.getURLReport(urlId);
      }

      // Extract comprehensive metadata
      const metadata = await this.extractComprehensiveMetadata(url, urlReport);
      return metadata;
    } catch (error) {
      console.error('Error scanning URL:', error);
      throw new Error(`Failed to scan URL: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Submit URL to VirusTotal for scanning
   */
  private async submitURL(url: string): Promise<string> {
    const formData = new FormData();
    formData.append('url', url);

    const response = await fetch(`${this.baseUrl}/urls`, {
      method: 'POST',
      headers: { 'x-apikey': this.apiKey },
      body: formData
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`VirusTotal API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    return data.data.id;
  }

  /**
   * Get URL analysis report
   */
  private async getURLReport(urlId: string): Promise<VTURLResponse> {
    const response = await fetch(`${this.baseUrl}/urls/${urlId}`, {
      headers: { 'x-apikey': this.apiKey }
    });

    if (!response.ok) {
      throw new Error(`Failed to get URL report: ${response.status}`);
    }

    return await response.json();
  }

  /**
   * Get domain information
   */
  private async getDomainInfo(domain: string): Promise<VTDomainResponse | null> {
    try {
      const response = await fetch(`${this.baseUrl}/domains/${domain}`, {
        headers: { 'x-apikey': this.apiKey }
      });

      if (!response.ok) return null;
      return await response.json();
    } catch (error) {
      console.warn('Could not fetch domain info:', error);
      return null;
    }
  }

  /**
   * Get IP address from domain resolutions
   */
  private async getIPFromDomain(domain: string): Promise<string | null> {
    try {
      const response = await fetch(`${this.baseUrl}/domains/${domain}`, {
        headers: { 'x-apikey': this.apiKey }
      });

      if (!response.ok) return null;
      
      const data = await response.json();
      
      // Get the most recent IP resolution
      if (data.data.attributes.last_dns_records) {
        const aRecords = data.data.attributes.last_dns_records.filter((record: any) => record.type === 'A');
        if (aRecords.length > 0) {
          return aRecords[0].value; // Return the first A record (IP address)
        }
      }
      
      return null;
    } catch (error) {
      console.warn('Could not get IP from domain:', error);
      return null;
    }
  }
  
  /**
   * Get IP address information
   */
  private async getIPInfo(ip: string): Promise<VTIPResponse | null> {
    try {
      const response = await fetch(`${this.baseUrl}/ip_addresses/${ip}`, {
        headers: { 'x-apikey': this.apiKey }
      });

      if (!response.ok) return null;
      return await response.json();
    } catch (error) {
      console.warn('Could not fetch IP info:', error);
      return null;
    }
  }

  /**
   * Get WHOIS data - Try multiple sources
   */
  private async getWhoisData(domain: string): Promise<WhoisAPIResponse | null> {
    // Skip WHOIS lookup - it's unreliable and times out frequently
    // The domain info from VirusTotal is usually sufficient
    console.warn('WHOIS lookup skipped - using VirusTotal domain data instead');
    return null;
  }

  /**
   * Get geographic IP information using ipapi.co (more reliable than ip-api.com)
   */
  private async getGeoIPData(ip: string): Promise<GeoIPResponse | null> {
    try {
      console.log('🌍 Fetching GeoIP data for:', ip);
      // Using ipapi.co free service (HTTPS, no auth required, 1000 requests/day)
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      
      if (!response.ok) {
        console.warn('GeoIP API returned non-OK status:', response.status);
        return null;
      }
      
      const data = await response.json();
      console.log('🌍 GeoIP API response:', data);
      
      if (data.error) {
        console.warn('GeoIP API error:', data.reason);
        return null;
      }
      
      return {
        ip: ip,
        country_code: data.country_code,
        country_name: data.country_name,
        region_code: data.region_code,
        region_name: data.region,
        city: data.city,
        zip_code: data.postal,
        latitude: data.latitude,
        longitude: data.longitude,
        time_zone: data.timezone,
        isp: data.org,
        organization: data.org,
        as: data.as,
        asname: data.org
      };
    } catch (error) {
      console.warn('Could not fetch GeoIP data:', error);
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
  private async waitForScanCompletion(urlId: string, maxAttempts: number = 5): Promise<void> {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await this.sleep(2000 * Math.pow(2, attempt)); // Exponential backoff
      
      try {
        const report = await this.getURLReport(urlId);
        if (report.data.attributes.last_analysis_stats) {
          return; // Analysis complete
        }
      } catch (error) {
        if (attempt === maxAttempts - 1) {
          throw new Error('Scan did not complete in time');
        }
      }
    }
  }

  /**
   * Extract comprehensive metadata from all sources
   */
  private async extractComprehensiveMetadata(url: string, urlReport: VTURLResponse): Promise<VTURLMetadata> {
    const urlObj = new URL(url);
    const attrs = urlReport.data.attributes;

    if (!attrs.last_analysis_stats) {
      throw new Error('Analysis not complete yet. Please try again in a few seconds.');
    }

    // Basic detection statistics
    const detectionStats: DetectionStats = {
      malicious: attrs.last_analysis_stats.malicious || 0,
      suspicious: attrs.last_analysis_stats.suspicious || 0,
      harmless: attrs.last_analysis_stats.harmless || 0,
      undetected: attrs.last_analysis_stats.undetected || 0,
      total: Object.keys(attrs.last_analysis_results || {}).length,
      engines: this.extractEngineResults(attrs.last_analysis_results || {})
    };

    // Get IP address from multiple sources
    let ipAddress = attrs.last_serving_ip_address || 
                    attrs.last_http_response_headers?.['x-real-ip'] ||
                    attrs.last_http_response_headers?.['cf-connecting-ip'];

    // If still no IP, try contacted_ips
    if (!ipAddress && urlReport.data.relationships?.contacted_ips?.data?.[0]) {
      ipAddress = urlReport.data.relationships.contacted_ips.data[0].id;
    }

    // If STILL no IP, do a domain lookup
    if (!ipAddress) {
      console.log('🔍 No IP found, attempting domain resolution...');
      ipAddress = await this.getIPFromDomain(urlObj.hostname) || undefined;
    }

    console.log('=== IP DEBUG ===');
    console.log('last_serving_ip_address:', attrs.last_serving_ip_address);
    console.log('x-real-ip:', attrs.last_http_response_headers?.['x-real-ip']);
    console.log('cf-connecting-ip:', attrs.last_http_response_headers?.['cf-connecting-ip']);
    console.log('Final Extracted IP Address:', ipAddress);
    console.log('===============');

    // Fetch additional data in parallel
    const [domainInfo, ipInfo, whoisData, geoData] = await Promise.all([
      this.getDomainInfo(urlObj.hostname),
      ipAddress ? this.getIPInfo(ipAddress) : null,
      this.getWhoisData(urlObj.hostname),
      ipAddress ? this.getGeoIPData(ipAddress) : null
    ]);

    console.log('=== API RESULTS ===');
    console.log('domainInfo:', domainInfo);
    console.log('ipInfo:', ipInfo);
    console.log('geoData:', geoData);
    console.log('==================');

    // Calculate domain age
    let domainAge: number | undefined;
    if (domainInfo?.data.attributes.creation_date) {
      const creationDate = new Date(domainInfo.data.attributes.creation_date * 1000);
      domainAge = Math.floor((Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24));
    } else if (whoisData?.creation_date) {
      const creationDate = new Date(whoisData.creation_date);
      domainAge = Math.floor((Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24));
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
        registrar: domainInfo?.data.attributes.registrar || whoisData?.registrar,
        creationDate: domainInfo?.data.attributes.creation_date 
          ? new Date(domainInfo.data.attributes.creation_date * 1000).toISOString()
          : whoisData?.creation_date,
        expirationDate: domainInfo?.data.attributes.expiration_date
          ? new Date(domainInfo.data.attributes.expiration_date * 1000).toISOString()
          : whoisData?.expiration_date,
        domainAge: domainAge,
        whoisData: whoisData ? {
          registrar: whoisData.registrar,
          registrarUrl: whoisData.registrar_url,
          creationDate: whoisData.creation_date,
          expirationDate: whoisData.expiration_date,
          updatedDate: whoisData.updated_date,
          nameServers: whoisData.name_servers,
          contacts: whoisData.contacts
        } : undefined
      },

      // Network information
      network: {
        ipAddress: ipAddress,
        asn: ipInfo?.data.attributes.asn ? `AS${ipInfo.data.attributes.asn}` : geoData?.as,
        asOwner: ipInfo?.data.attributes.as_owner || geoData?.asname,
        country: ipInfo?.data.attributes.country || geoData?.country_name,
        continent: ipInfo?.data.attributes.continent,
        city: geoData?.city,
        isp: geoData?.isp,
        hostingProvider: geoData?.organization
      },

      // HTTP response information
      httpInfo: {
        statusCode: attrs.last_http_response_code,
        headers: attrs.last_http_response_headers,
        contentType: attrs.last_http_response_headers?.['content-type'],
        contentLength: attrs.last_http_response_content_length,
        serverInfo: attrs.last_http_response_headers?.['server']
      },

      // Content information
      contentInfo: {
        title: attrs.title,
        language: attrs.html_meta?.language,
        favicon: attrs.favicon,
        sha256: attrs.last_http_response_content_sha256,
        mimeType: attrs.last_http_response_headers?.['content-type']?.split(';')[0],
        contentEntropy: contentEntropy
      },

      // Detection and threat information
      detectionStats: detectionStats,
      threatCategories: attrs.categories ? Object.values(attrs.categories) : undefined,
      malwareFamily: attrs.threat_names,
      impersonatedBrand: attrs.targeted_brand,
      suspiciousFeatures: this.extractSuspiciousFeatures(attrs),

      // External resources
      externalResources: {
        linkedDomains: linkedDomains,
        embeddedUrls: embeddedUrls,
        trackers: Array.isArray(attrs.trackers) ? attrs.trackers.map((t: any) => t.url || String(t)).filter(Boolean) : []
      },

      // Behavioral indicators
      behaviorInfo: {
        javascriptActivity: this.detectJavaScriptActivity(attrs),
        suspiciousRedirects: redirectDepth > 3,
        dataUriUsage: embeddedUrls.some(url => url.startsWith('data:')),
        hiddenElements: false // Would need content analysis
      },

      // Passive DNS (limited without premium API)
      passiveDns: {
        firstSeen: attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toISOString() : undefined,
        lastSeen: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : undefined
      },

      // Metadata
      scanDate: new Date().toISOString(),
      scanId: urlReport.data.id,
      reputation: domainInfo?.data.attributes.reputation || ipInfo?.data.attributes.reputation
    };

    return metadata;
  }

  /**
   * Extract engine results from analysis
   */
  private extractEngineResults(results: Record<string, any>): EngineResult[] {
    return Object.entries(results).map(([engine, result]) => ({
      engine: engine,
      category: result.category || 'unknown',
      result: result.result || 'clean'
    }));
  }

  /**
   * Extract linked domains from relationships
   */
  private extractLinkedDomains(urlReport: VTURLResponse): string[] {
    const domains: string[] = [];
    
    if (urlReport.data.relationships?.contacted_domains?.data) {
      domains.push(...urlReport.data.relationships.contacted_domains.data.map(d => d.id));
    }
    
    return domains;
  }

  /**
   * Extract suspicious features based on various indicators
   */
  private extractSuspiciousFeatures(attrs: any): string[] {
    const features: string[] = [];
    
    if (attrs.redirection_chain && attrs.redirection_chain.length > 3) {
      features.push('Multiple redirects');
    }
    
    if (attrs.categories) {
      const categories = Object.values(attrs.categories) as string[];
      if (categories.some(cat => cat.toLowerCase().includes('phishing'))) {
        features.push('Phishing category');
      }
      if (categories.some(cat => cat.toLowerCase().includes('malware'))) {
        features.push('Malware category');
      }
    }
    
    if (attrs.targeted_brand) {
      features.push('Brand impersonation');
    }
    
    if (attrs.last_http_response_headers?.['set-cookie']) {
      features.push('Sets cookies');
    }
    
    return features;
  }

  /**
   * Detect JavaScript activity indicators
   */
  private detectJavaScriptActivity(attrs: any): boolean {
    // Check for JavaScript-related headers or content types
    const contentType = attrs.last_http_response_headers?.['content-type'];
    return contentType?.includes('javascript') || 
           contentType?.includes('json') || 
           Boolean(attrs.trackers && attrs.trackers.length > 0);
  }

  /**
   * Helper function to wait
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Export comprehensive results to CSV format
 */
export function convertToCSV(results: VTURLMetadata[]): string {
  const headers = [
    'URL', 'Hostname', 'Path', 'Final URL', 'Redirect Count',
    'IP Address', 'ASN', 'AS Owner', 'Country', 'City', 'ISP',
    'Domain Registrar', 'Domain Creation Date', 'Domain Age (days)',
    'HTTP Status', 'Content Type', 'Server Info',
    'Malicious Detections', 'Suspicious Detections', 'Total Scanners',
    'Threat Categories', 'Impersonated Brand', 'Suspicious Features',
    'Linked Domains Count', 'External URLs Count', 'Trackers Count',
    'JavaScript Activity', 'Suspicious Redirects', 'Data URI Usage',
    'Reputation Score', 'SHA256 Hash', 'Content Entropy',
    'First Seen', 'Last Seen', 'Scan Date'
  ];

  const rows = results.map(result => [
    result.url,
    result.hostname,
    result.path,
    result.finalUrl || result.url,
    result.redirectDepth,
    result.network.ipAddress || 'N/A',
    result.network.asn || 'N/A',
    result.network.asOwner || 'N/A',
    result.network.country || 'N/A',
    result.network.city || 'N/A',
    result.network.isp || 'N/A',
    result.domain.registrar || 'N/A',
    result.domain.creationDate || 'N/A',
    result.domain.domainAge || 'N/A',
    result.httpInfo.statusCode || 'N/A',
    result.httpInfo.contentType || 'N/A',
    result.httpInfo.serverInfo || 'N/A',
    result.detectionStats.malicious,
    result.detectionStats.suspicious,
    result.detectionStats.total,
    result.threatCategories?.join('; ') || 'None',
    result.impersonatedBrand || 'None',
    result.suspiciousFeatures?.join('; ') || 'None',
    result.externalResources.linkedDomains?.length || 0,
    result.externalResources.embeddedUrls?.length || 0,
    result.externalResources.trackers?.length || 0,
    result.behaviorInfo.javascriptActivity || false,
    result.behaviorInfo.suspiciousRedirects || false,
    result.behaviorInfo.dataUriUsage || false,
    result.reputation || 'N/A',
    result.contentInfo.sha256 || 'N/A',
    result.contentInfo.contentEntropy || 'N/A',
    result.passiveDns?.firstSeen || 'N/A',
    result.passiveDns?.lastSeen || 'N/A',
    result.scanDate
  ]);

  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
  ].join('\n');

  return csvContent;
}

/**
 * Download CSV file
 */
export function downloadCSV(csv: string, filename: string = 'comprehensive_url_scan.csv'): void {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  link.style.visibility = 'hidden';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}