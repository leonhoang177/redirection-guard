import {
  VirusTotalService,
  convertToCSV,
  downloadCSV,
} from "./virusTotalService.js";
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
        <div class="result-item">
          <span class="result-label">1. Original URL:</span>
          <span class="result-value">${metadata.url}</span>
        </div>
        <div class="result-item">
          <span class="result-label">2. Final URL:</span>
          <span class="result-value">${finalUrlDisplay}</span>
        </div>
        <div class="result-item">
          <span class="result-label">3. Hostname:</span> ${
            metadata.hostname || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">4. Redirects:</span> ${
            metadata.redirectDepth || 0
          }
        </div>
        <div class="result-item">
          <span class="result-label">5. IP Address:</span> ${
            metadata.network.ipAddress || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">6. Country:</span> ${
            metadata.network.country || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">7. City:</span> ${
            metadata.network.city || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">8. ASN:</span> ${
            metadata.network.asn || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">9. AS Owner:</span> ${
            metadata.network.asOwner || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">10. ISP:</span> ${
            metadata.network.isp || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">11. Domain Age:</span> ${domainAge}
        </div>
        <div class="result-item">
          <span class="result-label">12. Registrar:</span> ${
            metadata.domain.registrar || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">13. Created:</span> ${
            metadata.domain.creationDate
              ? formatDate(metadata.domain.creationDate)
              : "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">14. Expires:</span> ${
            metadata.domain.expirationDate
              ? formatDate(metadata.domain.expirationDate)
              : "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">15. Certificate (Issuer → Subject):</span>
          <span class="result-value">${certSummaryDisplay}</span>
        </div>
        <div class="result-item">
          <span class="result-label">16. Certificate Validity:</span>
          <span class="result-value">${certValidityDisplay}</span>
        </div>
        <div class="result-item">
          <span class="result-label">17. Malicious:</span> 
          <span class="detection-count ${
            metadata.detectionStats.malicious > 0 ? "detection-danger" : ""
          }">${metadata.detectionStats.malicious}</span>
          /${metadata.detectionStats.total} engines
        </div>
        <div class="result-item">
          <span class="result-label">18. Suspicious:</span> 
          <span class="detection-count ${
            metadata.detectionStats.suspicious > 2 ? "detection-warning" : ""
          }">${metadata.detectionStats.suspicious}</span>
          /${metadata.detectionStats.total} engines
        </div>
        <div class="result-item">
          <span class="result-label">19. VT Votes:</span>
          ${
            metadata.votes
              ? `${metadata.votes.harmless ?? 0} harmless / ${
                  metadata.votes.malicious ?? 0
                } malicious`
              : "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">20. Impersonated Brand:</span> ${
            metadata.impersonatedBrand || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">21. Suspicious Features:</span>
          <span class="result-value">${
            metadata.suspiciousFeatures &&
            metadata.suspiciousFeatures.length > 0
              ? metadata.suspiciousFeatures.join(", ")
              : "N/A"
          }</span>
        </div>
        <div class="result-item">
          <span class="result-label">22. Reputation Score:</span> ${
            metadata.reputation !== undefined ? metadata.reputation : "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">23. Status Code:</span> ${
            metadata.httpInfo.statusCode || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">24. HSTS:</span>
          <span class="result-value"><span class="${statusClass(
            hstsStatus
          )}">${hstsStatus}</span></span>
        </div>
        <div class="result-item">
          <span class="result-label">25. Content Type:</span> ${
            metadata.httpInfo.contentType || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">26. Server:</span> ${
            metadata.httpInfo.serverInfo || "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">27. Content Length:</span> ${
            metadata.httpInfo.contentLength
              ? formatBytes(metadata.httpInfo.contentLength)
              : "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">28. Page Title:</span>
          <span class="result-value">${
            metadata.contentInfo.title ? metadata.contentInfo.title : "N/A"
          }</span>
        </div>
        <div class="result-item">
          <span class="result-label">29. Language:</span> ${languageDisplay}
        </div>
        <div class="result-item">
          <span class="result-label">30. SHA256:</span>
          <span class="result-value mono">${
            metadata.contentInfo.sha256 || "N/A"
          }</span>
        </div>
        <div class="result-item">
          <span class="result-label">31. Content Entropy:</span> ${
            metadata.contentInfo.contentEntropy
              ? metadata.contentInfo.contentEntropy.toFixed(2)
              : "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">32. Linked Domains:</span> ${
            metadata.externalResources.linkedDomains?.length || 0
          }
        </div>
        <div class="result-item">
          <span class="result-label">33. Embedded URLs:</span> ${
            metadata.externalResources.embeddedUrls?.length || 0
          }
        </div>
        <div class="result-item">
          <span class="result-label">34. Trackers:</span> ${
            metadata.externalResources.trackers?.length || 0
          }
        </div>
        <div class="result-item">
          <span class="result-label">35. JavaScript Activity:</span>
          <span class="result-value">${jsActivityValue} <span class="${statusClass(
    jsActivityStatus
  )}">(${jsActivityStatus})</span></span>
        </div>
        <div class="result-item">
          <span class="result-label">36. Suspicious Redirects:</span> ${
            metadata.behaviorInfo.suspiciousRedirects ? "Yes" : "No"
          }
        </div>
        <div class="result-item">
          <span class="result-label">37. Data URI Usage:</span> ${
            metadata.behaviorInfo.dataUriUsage ? "Detected" : "None"
          }
        </div>
        <div class="result-item">
          <span class="result-label">38. Scan Date:</span> ${formatDate(
            metadata.scanDate
          )}
        </div>
        <div class="result-item">
          <span class="result-label">39. First Seen:</span> ${
            metadata.passiveDns?.firstSeen
              ? formatDate(metadata.passiveDns.firstSeen)
              : "N/A"
          }
        </div>
        <div class="result-item">
          <span class="result-label">40. Scan ID:</span>
          <span class="result-value mono">${metadata.scanId || "N/A"}</span>
        </div>
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
