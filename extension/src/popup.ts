import { VirusTotalService, convertToCSV, downloadCSV } from "./api.js";
import { VTURLMetadata } from "./types.js";

// Storage for scan results
let scanResults: VTURLMetadata[] = [];
let vtService: VirusTotalService | null = null;

// DOM Elements
const apiKeyInput = document.getElementById("apiKey") as HTMLInputElement;
const saveApiKeyBtn = document.getElementById(
  "saveApiKey"
) as HTMLButtonElement;
const urlInput = document.getElementById("urlInput") as HTMLInputElement;
const scanBtn = document.getElementById("scanBtn") as HTMLButtonElement;
const scanCurrentBtn = document.getElementById(
  "scanCurrentBtn"
) as HTMLButtonElement;
const exportBtn = document.getElementById("exportBtn") as HTMLButtonElement;
const loader = document.getElementById("loader") as HTMLDivElement;
const status = document.getElementById("status") as HTMLDivElement;
const results = document.getElementById("results") as HTMLDivElement;

// Initialize
document.addEventListener("DOMContentLoaded", async () => {
  // Load saved API key
  const savedKey = await loadApiKey();
  if (savedKey) {
    apiKeyInput.value = savedKey;
    vtService = new VirusTotalService(savedKey);
    showStatus("API Key loaded successfully!", "success");
  }

  // Load saved results
  const savedResults = await loadResults();
  if (savedResults && savedResults.length > 0) {
    scanResults = savedResults;
    exportBtn.style.display = "block";
    showStatus(`${savedResults.length} previous scan(s) loaded`, "info");
  }

  // Enlarge popup, disable outer scroll, 2-column layout, keep values one line with ellipsis
  const style = document.createElement("style");
  style.textContent = `
    html, body {
      width: 780px;          /* keep within Chrome popup max */
      height: 600px;         /* fixed height to prevent outer scroll */
      margin: 0;
      overflow: hidden !important; /* remove outer scrollbars */
      font-size: 14px;
    }
    #results {
      max-height: none !important;
      overflow: hidden !important; /* no inner scroll */
    }
    .result-section {
      display: flex;
      flex-direction: column; /* single column layout */
      gap: 6px;
    }
    .result-item {
      display: flex;
      align-items: center;
      gap: 8px;
      line-height: 1.3;
      margin: 2px 0;
    }
    .result-label { flex: 0 0 auto; }
    .result-value {
      flex: 1 1 auto;
      white-space: nowrap;      /* single line */
      overflow: hidden;         /* clip overflow */
      text-overflow: ellipsis;  /* add … when too long */
    }
    .mono { font-family: monospace; }
    .threat-level { display: flex; align-items: center; justify-content: center; text-align: center; }
    .status-ok { color: #1a7f37; font-weight: 600; }        /* green */
    .status-unknown { color: #2563eb; font-weight: 600; }  /* blue */
    .status-error { color: #c2410c; font-weight: 600; }    /* orange */
  `;
  document.head.appendChild(style);
});

// Save API Key
saveApiKeyBtn.addEventListener("click", async () => {
  const apiKey = apiKeyInput.value.trim();

  if (!apiKey) {
    showStatus("Please enter an API key", "error");
    return;
  }

  if (apiKey.length !== 64) {
    showStatus("API key should be 64 characters long", "error");
    return;
  }

  await saveApiKey(apiKey);
  vtService = new VirusTotalService(apiKey);
  showStatus("API Key saved successfully!", "success");
});

// Scan URL
scanBtn.addEventListener("click", async () => {
  const url = urlInput.value.trim();

  if (!url) {
    showStatus("Please enter a URL", "error");
    return;
  }

  if (!vtService) {
    showStatus("Please save your API key first", "error");
    return;
  }

  if (!isValidUrl(url)) {
    showStatus(
      "Please enter a valid URL (include http:// or https://)",
      "error"
    );
    return;
  }

  await scanUrl(url);
});

// Scan Current Tab
scanCurrentBtn.addEventListener("click", async () => {
  if (!vtService) {
    showStatus("Please save your API key first", "error");
    return;
  }

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    if (!tab.url) {
      showStatus("Cannot access current tab URL", "error");
      return;
    }

    if (
      tab.url.startsWith("chrome://") ||
      tab.url.startsWith("chrome-extension://")
    ) {
      showStatus("Cannot scan Chrome internal pages", "error");
      return;
    }

    urlInput.value = tab.url;
    await scanUrl(tab.url);
  } catch (error) {
    showStatus("Error accessing current tab", "error");
    console.error(error);
  }
});

// Export to CSV
exportBtn.addEventListener("click", () => {
  if (scanResults.length === 0) {
    showStatus("No results to export", "error");
    return;
  }

  const csv = convertToCSV(scanResults);
  const timestamp = new Date()
    .toISOString()
    .replace(/[:.]/g, "-")
    .split("T")[0];
  downloadCSV(csv, `comprehensive_url_scan_${timestamp}.csv`);
  showStatus("CSV exported successfully!", "success");
});

// Scan URL Function
async function scanUrl(url: string): Promise<void> {
  showLoader(true);
  showStatus(
    "Performing comprehensive URL analysis... This may take 10-15 seconds.",
    "info"
  );
  results.style.display = "none";

  try {
    const metadata = await vtService!.scanURL(url);
    scanResults.push(metadata);

    // Save results
    await saveResults(scanResults);

    // Display results
    displayComprehensiveResults(metadata);
    showStatus("Comprehensive scan completed!", "success");
    exportBtn.style.display = "block";
  } catch (error: any) {
    const errorMessage = error.message.includes("quota")
      ? "API quota exceeded. Please wait or upgrade your VirusTotal account."
      : `Error: ${error.message}`;
    showStatus(errorMessage, "error");
    console.error("Scan error:", error);
  } finally {
    showLoader(false);
  }
}

// Display Comprehensive Results
function displayComprehensiveResults(metadata: VTURLMetadata): void {
  const threatLevel = getThreatLevel(metadata);
  const threatClass =
    threatLevel === "Low Risk"
      ? "threat-safe"
      : threatLevel === "Suspicious"
      ? "threat-warning"
      : "threat-danger";

  const domainAge = metadata.domain.domainAge
    ? `${metadata.domain.domainAge} days (${Math.floor(
        metadata.domain.domainAge / 365
      )} years)`
    : "N/A";

  // Derive nicer display strings for optional/missing fields
  const pageUrlForScheme = (() => {
    try {
      return new URL(metadata.finalUrl || metadata.url);
    } catch {
      return null;
    }
  })();

  const isHttps = pageUrlForScheme
    ? pageUrlForScheme.protocol === "https:"
    : undefined;

  const finalUrlDisplay = (() => {
    const fu = metadata.finalUrl || metadata.url;
    return fu; // if same as original, just print the URL again
  })();

  const certSummaryDisplay = (() => {
    if (metadata.certificateInfo) {
      const issuer = metadata.certificateInfo.issuerCN || "Unknown";
      const subject = metadata.certificateInfo.subjectCN || "Unknown";
      return `${issuer} → ${subject}`;
    }
    if (isHttps === false) return "Not applicable (HTTP)";
    if (metadata.httpInfo.hsts === true || isHttps === true)
      return "Unknown (not provided by VT)";
    return "Unknown";
  })();

  const certValidityDisplay = (() => {
    if (
      metadata.certificateInfo &&
      (metadata.certificateInfo.notBefore || metadata.certificateInfo.notAfter)
    ) {
      const nb = metadata.certificateInfo.notBefore
        ? formatDate(metadata.certificateInfo.notBefore)
        : "Unknown";
      const na = metadata.certificateInfo.notAfter
        ? formatDate(metadata.certificateInfo.notAfter)
        : "Unknown";
      return `${nb} → ${na}`;
    }
    if (isHttps === false) return "Not applicable (HTTP)";
    if (metadata.httpInfo.hsts === true || isHttps === true)
      return "Unknown (not provided by VT)";
    return "Unknown";
  })();

  const languageDisplay = metadata.contentInfo.language
    ? metadata.contentInfo.language
    : "Not declared";

  // Map HSTS to status: Ok (present), Unknown (URL does not provide it), Error (extraction failed)
  const hstsStatus = (() => {
    if (metadata.httpInfo.hsts === true) return "Ok"; // good
    if (metadata.httpInfo.hsts === false) return "Unknown"; // header not provided by URL
    return "Error"; // extractor failed / not available
  })();

  // JavaScript Activity display (value + status)
  const jsActivityStatus = (() => {
    const s = metadata.behaviorInfo.javascriptActivityStatus;
    if (s === "ok") return "Ok";
    if (s === "not_present") return "Unknown"; // URL does not provide it
    if (s === "error") return "Error";
    return "Unknown"; // default for undefined/unknown
  })();

  const jsActivityValue = (() => {
    if (typeof metadata.behaviorInfo.javascriptActivityDetected === "boolean") {
      return metadata.behaviorInfo.javascriptActivityDetected
        ? "Detected"
        : "None";
    }
    // If missing/unknown, prefer explicit label
    return "None";
  })();

  // Status to CSS class mapper
  const statusClass = (s: string) =>
    s === "Ok"
      ? "status-ok"
      : s === "Unknown"
      ? "status-unknown"
      : s === "Error"
      ? "status-error"
      : "";

  const items: { label: string; valueHtml: string }[] = [
    // ===== Metadata =====
    { label: "Scan ID", valueHtml: `${metadata.scanId || "N/A"}` },
    {
      label: "Reputation Score",
      valueHtml: `${
        metadata.reputation !== undefined ? metadata.reputation : "N/A"
      }`,
    },

    // ===== Basic URL info =====
    { label: "Original URL", valueHtml: `${metadata.url}` },
    { label: "Hostname", valueHtml: `${metadata.hostname || "N/A"}` },
    { label: "Path", valueHtml: `${metadata.path || "/"}` },
    { label: "Final URL", valueHtml: `${finalUrlDisplay}` },
    {
      label: "Redirect Chain",
      valueHtml: `${
        metadata.redirectChain?.length
          ? `${metadata.redirectChain.length} hops`
          : "0"
      }`,
    },
    { label: "Redirect Depth", valueHtml: `${metadata.redirectDepth || 0}` },

    // ===== Domain and WHOIS info =====
    { label: "Registrar", valueHtml: `${metadata.domain.registrar || "N/A"}` },
    {
      label: "Created",
      valueHtml: `${
        metadata.domain.creationDate
          ? formatDate(metadata.domain.creationDate)
          : "N/A"
      }`,
    },
    {
      label: "Expires",
      valueHtml: `${
        metadata.domain.expirationDate
          ? formatDate(metadata.domain.expirationDate)
          : "N/A"
      }`,
    },
    { label: "Domain Age", valueHtml: `${domainAge}` },
    {
      label: "WHOIS Registrar URL",
      valueHtml: `${metadata.domain.whoisData?.registrarUrl || "N/A"}`,
    },
    {
      label: "WHOIS Updated",
      valueHtml: `${
        metadata.domain.whoisData?.updatedDate
          ? formatDate(metadata.domain.whoisData.updatedDate)
          : "N/A"
      }`,
    },
    {
      label: "Name Servers",
      valueHtml: `${metadata.domain.whoisData?.nameServers?.length || 0}`,
    },
    {
      label: "WHOIS Contacts",
      valueHtml: `${(() => {
        const c = metadata.domain.whoisData?.contacts;
        if (!c) return "N/A";
        const parts: string[] = [];
        if (c.registrant) parts.push("registrant");
        if (c.admin) parts.push("admin");
        if (c.tech) parts.push("tech");
        return parts.length ? parts.join(", ") : "N/A";
      })()}`,
    },

    // ===== Network and hosting info =====
    {
      label: "IP Address",
      valueHtml: `${metadata.network.ipAddress || "N/A"}`,
    },
    { label: "ASN", valueHtml: `${metadata.network.asn || "N/A"}` },
    { label: "AS Owner", valueHtml: `${metadata.network.asOwner || "N/A"}` },
    { label: "Country", valueHtml: `${metadata.network.country || "N/A"}` },
    { label: "Continent", valueHtml: `${metadata.network.continent || "N/A"}` },
    { label: "City", valueHtml: `${metadata.network.city || "N/A"}` },
    { label: "ISP", valueHtml: `${metadata.network.isp || "N/A"}` },
    {
      label: "Hosting Provider",
      valueHtml: `${
        metadata.network.hostingProvider || metadata.network.asOwner || "N/A"
      }`,
    },

    // ===== HTTP response info =====
    {
      label: "Status Code",
      valueHtml: `${metadata.httpInfo.statusCode || "N/A"}`,
    },
    {
      label: "Response Time",
      valueHtml: `${
        metadata.httpInfo.responseTime !== undefined
          ? metadata.httpInfo.responseTime + " ms"
          : "N/A"
      }`,
    },
    {
      label: "Headers",
      valueHtml: `${
        metadata.httpInfo.headers
          ? Object.keys(metadata.httpInfo.headers).length + " headers"
          : "N/A"
      }`,
    },
    {
      label: "Content Type",
      valueHtml: `${metadata.httpInfo.contentType || "N/A"}`,
    },
    {
      label: "Content Length",
      valueHtml: `${
        metadata.httpInfo.contentLength
          ? formatBytes(metadata.httpInfo.contentLength)
          : "N/A"
      }`,
    },
    { label: "Server", valueHtml: `${metadata.httpInfo.serverInfo || "N/A"}` },
    {
      label: "HSTS",
      valueHtml: `<span class="${statusClass(
        hstsStatus
      )}">${hstsStatus}</span>`,
    },

    // ===== TLS/SSL Certificate info (tlsInfo) =====
    {
      label: "TLS Issuer (raw)",
      valueHtml: `${metadata.tlsInfo?.issuer || "N/A"}`,
    },
    {
      label: "TLS Subject (raw)",
      valueHtml: `${metadata.tlsInfo?.subject || "N/A"}`,
    },
    {
      label: "TLS Valid From",
      valueHtml: `${
        metadata.tlsInfo?.validFrom
          ? formatDate(metadata.tlsInfo.validFrom)
          : "N/A"
      }`,
    },
    {
      label: "TLS Valid To",
      valueHtml: `${
        metadata.tlsInfo?.validTo ? formatDate(metadata.tlsInfo.validTo) : "N/A"
      }`,
    },
    {
      label: "TLS Serial",
      valueHtml: `${metadata.tlsInfo?.serialNumber || "N/A"}`,
    },
    {
      label: "TLS SAN Count",
      valueHtml: `${metadata.tlsInfo?.sanEntries?.length ?? 0}`,
    },
    {
      label: "TLS Fingerprint",
      valueHtml: `${metadata.tlsInfo?.fingerprint || "N/A"}`,
    },

    // ===== Vendor votes summary =====
    {
      label: "VT Votes",
      valueHtml: `${
        metadata.votes
          ? `${metadata.votes.harmless ?? 0} harmless / ${
              metadata.votes.malicious ?? 0
            } malicious`
          : "N/A"
      }`,
    },

    // ===== Parsed TLS certificate summary (certificateInfo) =====
    {
      label: "Certificate (Issuer → Subject)",
      valueHtml: `${certSummaryDisplay}`,
    },
    { label: "Certificate Validity", valueHtml: `${certValidityDisplay}` },

    // ===== Content and security analysis =====
    {
      label: "Page Title",
      valueHtml: `${
        metadata.contentInfo.title ? metadata.contentInfo.title : "N/A"
      }`,
    },
    { label: "Language", valueHtml: `${languageDisplay}` },
    { label: "Favicon", valueHtml: `${metadata.contentInfo.favicon || "N/A"}` },
    {
      label: "Favicon Hash",
      valueHtml: `${metadata.contentInfo.faviconHash || "N/A"}`,
    },
    {
      label: "SHA256",
      valueHtml: `<span class="mono">${
        metadata.contentInfo.sha256 || "N/A"
      }</span>`,
    },
    {
      label: "MD5",
      valueHtml: `<span class="mono">${
        metadata.contentInfo.md5 || "N/A"
      }</span>`,
    },
    {
      label: "MIME Type",
      valueHtml: `${metadata.contentInfo.mimeType || "N/A"}`,
    },
    {
      label: "Content Entropy",
      valueHtml: `${
        metadata.contentInfo.contentEntropy
          ? metadata.contentInfo.contentEntropy.toFixed(2)
          : "N/A"
      }`,
    },

    // ===== Detection and threat info =====
    {
      label: "Malicious",
      valueHtml: `<span class="detection-count ${
        metadata.detectionStats.malicious > 0 ? "detection-danger" : ""
      }">${metadata.detectionStats.malicious}</span>/${
        metadata.detectionStats.total
      } engines`,
    },
    {
      label: "Suspicious",
      valueHtml: `<span class="detection-count ${
        metadata.detectionStats.suspicious > 2 ? "detection-warning" : ""
      }">${metadata.detectionStats.suspicious}</span>/${
        metadata.detectionStats.total
      } engines`,
    },
    {
      label: "Harmless",
      valueHtml: `${metadata.detectionStats.harmless}/${metadata.detectionStats.total} engines`,
    },
    {
      label: "Undetected",
      valueHtml: `${metadata.detectionStats.undetected}/${metadata.detectionStats.total} engines`,
    },
    {
      label: "Threat Categories",
      valueHtml: `${
        metadata.threatCategories?.length
          ? metadata.threatCategories.join(", ")
          : "N/A"
      }`,
    },
    {
      label: "Malware Families",
      valueHtml: `${
        metadata.malwareFamily?.length
          ? metadata.malwareFamily.join(", ")
          : "N/A"
      }`,
    },
    {
      label: "Impersonated Brand",
      valueHtml: `${metadata.impersonatedBrand || "N/A"}`,
    },
    {
      label: "Suspicious Features",
      valueHtml: `${
        metadata.suspiciousFeatures && metadata.suspiciousFeatures.length > 0
          ? metadata.suspiciousFeatures.join(", ")
          : "N/A"
      }`,
    },

    // ===== External resources and links =====
    {
      label: "Linked Domains",
      valueHtml: `${metadata.externalResources.linkedDomains?.length || 0}`,
    },
    {
      label: "Embedded URLs",
      valueHtml: `${metadata.externalResources.embeddedUrls?.length || 0}`,
    },
    {
      label: "External Scripts",
      valueHtml: `${metadata.externalResources.externalScripts?.length || 0}`,
    },
    {
      label: "Trackers",
      valueHtml: `${metadata.externalResources.trackers?.length || 0}`,
    },

    // ===== Behavioral indicators =====
    {
      label: "JavaScript Activity",
      valueHtml: `${jsActivityValue} <span class="${statusClass(
        jsActivityStatus
      )}">(${jsActivityStatus})</span>`,
    },
    { label: "JS Activity Status", valueHtml: `${jsActivityStatus}` },
    {
      label: "Suspicious Redirects",
      valueHtml: `${metadata.behaviorInfo.suspiciousRedirects ? "Yes" : "No"}`,
    },
    {
      label: "Data URI Usage",
      valueHtml: `${metadata.behaviorInfo.dataUriUsage ? "Detected" : "None"}`,
    },
    {
      label: "Hidden Elements",
      valueHtml: `${
        metadata.behaviorInfo.hiddenElements ? "Detected" : "None"
      }`,
    },

    // ===== Passive DNS and historical data =====
    {
      label: "First Seen",
      valueHtml: `${
        metadata.passiveDns?.firstSeen
          ? formatDate(metadata.passiveDns.firstSeen)
          : "N/A"
      }`,
    },
    {
      label: "Last Seen",
      valueHtml: `${
        metadata.passiveDns?.lastSeen
          ? formatDate(metadata.passiveDns.lastSeen)
          : "N/A"
      }`,
    },
    {
      label: "Distinct IPs",
      valueHtml: `${metadata.passiveDns?.distinctIps?.length ?? 0}`,
    },
    {
      label: "Total Resolutions",
      valueHtml: `${metadata.passiveDns?.totalResolutions ?? 0}`,
    },
  ];

  const itemsHtml = items
    .map(
      (it, idx) => `
      <div class="result-item">
        <span class="result-label">${idx + 1}. ${it.label}:</span>
        <span class="result-value">${it.valueHtml}</span>
      </div>`
    )
    .join("\n");

  results.innerHTML = `
    <div style="width: 800px; font-size: 15px;">
      <div style="margin-bottom: 12px;">
        <div class="threat-level ${threatClass}">
          ${threatLevel}
        </div>
      </div>

      <div class="result-item" style="margin: 6px 0 12px 0;">
        <span class="result-label">Status Legend:</span>
        <span class="result-value">Ok = good · Unknown = URL does not provide it · Error = extractor failed</span>
      </div>

      <div class="result-section">
        ${itemsHtml}
      </div>
    </div>
  `;

  results.style.display = "block";
}

// Helper Functions
function getThreatLevel(metadata: VTURLMetadata): string {
  const { malicious, suspicious } = metadata.detectionStats;

  if (malicious > 0) {
    return "Dangerous";
  } else if (suspicious > 0 || metadata.suspiciousFeatures?.length) {
    return "Suspicious";
  } else {
    return "Low Risk";
  }
}

function formatLocationInfo(metadata: VTURLMetadata): string {
  const parts = [];
  if (metadata.network.city) parts.push(metadata.network.city);
  if (metadata.network.country) parts.push(metadata.network.country);
  return parts.length > 0 ? parts.join(", ") : "N/A";
}

function formatDate(dateString: string): string {
  try {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return dateString;
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function showStatus(message: string, type: "success" | "error" | "info"): void {
  status.textContent = message;
  status.className = type;
  status.style.display = "block";

  if (type === "success") {
    setTimeout(() => {
      status.style.display = "none";
    }, 4000);
  }
}

function showLoader(show: boolean): void {
  loader.style.display = show ? "block" : "none";
  scanBtn.disabled = show;
  scanCurrentBtn.disabled = show;
  exportBtn.disabled = show;
}

function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

function truncateText(text: string, maxLength: number): string {
  return text.length > maxLength ? text.substring(0, maxLength) + "..." : text;
}

// Storage Functions
async function saveApiKey(apiKey: string): Promise<void> {
  await chrome.storage.local.set({ virusTotalApiKey: apiKey });
}

async function loadApiKey(): Promise<string | null> {
  const result = await chrome.storage.local.get("virusTotalApiKey");
  return result.virusTotalApiKey || null;
}

async function saveResults(results: VTURLMetadata[]): Promise<void> {
  // Keep only the last 50 results to avoid storage issues
  const trimmedResults = results.slice(-50);
  await chrome.storage.local.set({ scanResults: trimmedResults });
}

async function loadResults(): Promise<VTURLMetadata[]> {
  const result = await chrome.storage.local.get("scanResults");
  return result.scanResults || [];
}
