export interface VTURLMetadata {
  // Basic
  url: string;
  urlEntropy: number;
  isHttps: boolean;
  hostname: string;
  contentInfo?: {
    title?: string;
    favicon?: string;
    faviconHostMatch?: boolean;
    charset?: string;
    mimeType?: string;
  };

  // Tools
  reputation: number;
  maliciousVotes: number;
  suspiciousVotes: number;
  servicesKeyWords?: string;
  suspiciousFeatures?: string;

  // Redirect
  redirect?: {
    count?: number | null;
    entropy?: number | null;
    similarity?: number | null;
  };

  // DNS
  dns?: {
    count?: number;
    firstSeen?: string;
    age?: number;
    ratio?: number;
  };

  // Domain
  domain?: {
    creationDate?: string;
    expirationDate?: string;
    age?: number;
    validDays?: number;
  };

  // Network
  network?: {
    asOwner?: string;
    country?: string;
  };

  // HTTP
  httpInfo?: {
    statusCode?: number;
    headers?: Record<string, string | number | null>;
  };

  // TLS
  tlsInfo?: {
    subject?: string;
    subjectMatch?: boolean;
    validFrom?: string;
    validTo?: string;
    validDays?: number;
    sanEntriesCount?: number | null;
    sanEntriesEntropy?: number | null;
    sanEntriesSimilarity?: number | null;
  };

  // External Resources
  externalResources: {
    embeddedUrls?: string[];
    embeddedUrlsCount?: number | null;
    embeddedUrlsEntropy?: number | null;
    embeddedUrlsSimilarity?: number | null;
    trackers?: object;
    trackersCount?: number;
  };
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
      as_owner?: string;
      country?: string;
      whois?: string;
    };
  };
}
