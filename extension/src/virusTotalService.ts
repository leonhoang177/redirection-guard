import { VTURLMetadata, VTAPIResponse, NetworkLocationResponse, DetectionStats } from './types.js';

export class VirusTotalService {
  private apiKey: string;
  private baseUrl = 'https://www.virustotal.com/api/v3';

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  /**
   * Scan a URL and get comprehensive metadata
   */
  async scanURL(url: string): Promise<VTURLMetadata> {
    try {
      // First, try to get existing analysis
      const urlId = btoa(url).replace(/=/g, '');
      
      try {
        const existingReport = await this.getURLInfo(urlId);
        const metadata = await this.extractMetadata(url, existingReport);
        return metadata;
      } catch (error) {
        // If no existing report, submit for new scan
        console.log('No existing report, submitting for new scan...');
        await this.submitURL(url);
        
        // Wait longer for scan to complete
        await this.sleep(8000); // 8 seconds
        
        // Try to get the report
        const report = await this.getURLInfo(urlId);
        const metadata = await this.extractMetadata(url, report);
        return metadata;
      }
    } catch (error) {
      console.error('Error scanning URL:', error);
      throw new Error('Failed to scan URL. Please try again.');
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
      headers: {
        'x-apikey': this.apiKey
      },
      body: formData
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('VirusTotal API error:', errorText);
      throw new Error(`VirusTotal API error: ${response.status}`);
    }

    const data = await response.json();
    return data.data.id;
  }

  /**
   * Get detailed URL information
   */
  private async getURLInfo(urlId: string): Promise<VTAPIResponse> {
    const response = await fetch(`${this.baseUrl}/urls/${urlId}`, {
      headers: {
        'x-apikey': this.apiKey
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to get URL info: ${response.status}`);
    }

    return await response.json();
  }

  /**
   * Get network location details (IP, ASN, Country)
   */
  private async getNetworkLocation(locationId: string): Promise<NetworkLocationResponse> {
    const response = await fetch(`${this.baseUrl}/ip_addresses/${locationId}`, {
      headers: {
        'x-apikey': this.apiKey
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to get network location: ${response.status}`);
    }

    return await response.json();
  }

  /**
   * Extract all metadata from VirusTotal response
   */
  private async extractMetadata(url: string, report: VTAPIResponse): Promise<VTURLMetadata> {
    const urlObj = new URL(url);
    const attrs = report.data.attributes;

    // Check if analysis stats exist
    if (!attrs.last_analysis_stats) {
      throw new Error('Analysis not complete yet. Please try again in a few seconds.');
    }

    // Detection statistics
    const detectionStats: DetectionStats = {
      malicious: attrs.last_analysis_stats.malicious || 0,
      suspicious: attrs.last_analysis_stats.suspicious || 0,
      harmless: attrs.last_analysis_stats.harmless || 0,
      undetected: attrs.last_analysis_stats.undetected || 0,
      total: (attrs.last_analysis_stats.malicious || 0) + 
             (attrs.last_analysis_stats.suspicious || 0) + 
             (attrs.last_analysis_stats.harmless || 0) + 
             (attrs.last_analysis_stats.undetected || 0)
    };

    // Try to get additional URL info
    let ipAddress: string | undefined;
    let asn: string | undefined;
    let country: string | undefined;
    let impersonatedBrand: string | undefined;

    try {
      // Try multiple sources for IP address
      const lastServingIpAddress = attrs.last_serving_ip_address || 
                                   attrs.last_http_response_headers?.['x-real-ip'];
      
      // Also check if there's a network_location relationship
      const networkLocationId = report.data.relationships?.network_location?.data?.id;
      
      if (networkLocationId) {
        // We have a direct reference to network location
        try {
          const networkInfo = await this.getNetworkLocation(networkLocationId);
          ipAddress = networkInfo.data.attributes.ip_address;
          asn = `AS${networkInfo.data.attributes.asn}`;
          country = networkInfo.data.attributes.country;
        } catch (error) {
          console.warn('Could not fetch network location from relationship:', error);
        }
      } else if (lastServingIpAddress) {
        // Fallback: use the IP from attributes
        ipAddress = lastServingIpAddress;
        
        try {
          const networkInfo = await this.getNetworkLocation(lastServingIpAddress);
          asn = `AS${networkInfo.data.attributes.asn}`;
          country = networkInfo.data.attributes.country;
        } catch (error) {
          console.warn('Could not fetch network info for IP:', error);
        }
      }

      // Extract impersonated brand from categories
      if (attrs.categories) {
        const categories = Object.values(attrs.categories);
        impersonatedBrand = categories.find(cat => 
          typeof cat === 'string' && (
            cat.toLowerCase().includes('phishing') || 
            cat.toLowerCase().includes('impersonation')
          )
        ) as string | undefined;
      }
    } catch (error) {
      console.warn('Could not fetch additional URL info:', error);
    }

    const metadata: VTURLMetadata = {
      url: url,
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      language: attrs.html_meta?.language,
      ipAddress,
      asn,
      country,
      detectionStats,
      impersonatedBrand,
      scanDate: new Date().toISOString(),
      finalUrl: attrs.last_final_url,
      redirectChain: attrs.redirection_chain
    };

    return metadata;
  }

  /**
   * Helper function to wait
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Export results to CSV format
 */
export function convertToCSV(results: VTURLMetadata[]): string {
  const headers = [
    'URL',
    'Hostname',
    'Path',
    'IP Address',
    'ASN',
    'Country',
    'Language',
    'Final URL',
    'Malicious Detections',
    'Suspicious Detections',
    'Harmless Detections',
    'Total Scanners',
    'Impersonated Brand',
    'Redirects',
    'Scan Date'
  ];

  const rows = results.map(result => [
    result.url,
    result.hostname,
    result.path,
    result.ipAddress || 'N/A',
    result.asn || 'N/A',
    result.country || 'N/A',
    result.language || 'N/A',
    result.finalUrl || result.url,
    result.detectionStats.malicious,
    result.detectionStats.suspicious,
    result.detectionStats.harmless,
    result.detectionStats.total,
    result.impersonatedBrand || 'None',
    result.redirectChain?.join(' -> ') || 'None',
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
export function downloadCSV(csv: string, filename: string = 'virustotal_scan_results.csv'): void {
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

