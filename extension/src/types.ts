// VirusTotal API Response Types
export interface VTURLMetadata {
  url: string;
  hostname: string;
  path: string;
  language?: string;
  ipAddress?: string;
  asn?: string;
  country?: string;
  sslCertificate?: SSLCertInfo;
  detectionStats: DetectionStats;
  impersonatedBrand?: string;
  dropAccounts?: string[];
  scanDate: string;
  finalUrl?: string;
  redirectChain?: string[];
}

export interface SSLCertInfo {
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
}

export interface DetectionStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  total: number;
}

export interface VTAPIResponse {
  data: {
    id: string;
    type: string;
    attributes: {
      last_analysis_stats: {
        malicious: number;
        suspicious: number;
        harmless: number;
        undetected: number;
        timeout: number;
      };
      last_final_url?: string;
      redirection_chain?: string[];
      last_http_response_headers?: Record<string, string>;
      last_http_response_content_sha256?: string;
      last_serving_ip_address?: string;
      html_meta?: {
        description?: string[];
        language?: string;
      };
      categories?: Record<string, string>;
      tags?: string[];
      title?: string;
      trackers?: Record<string, any>[];
    };
    relationships?: {
      network_location?: {
        data: {
          id: string;
          type: string;
        };
      };
    };
  };
}

export interface NetworkLocationResponse {
  data: {
    attributes: {
      ip_address: string;
      network: string;
      asn: number;
      as_owner: string;
      country: string;
      continent: string;
    };
  };
}