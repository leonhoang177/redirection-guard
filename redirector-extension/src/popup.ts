import { VirusTotalService } from "./api.js";
import { VTURLMetadata } from "./types.js";

// DOM Elements
const apiKeyInput = document.getElementById("apiKey") as HTMLInputElement;
const saveApiKeyBtn = document.getElementById("saveApiKey") as HTMLButtonElement;
const urlInput = document.getElementById("urlInput") as HTMLInputElement;
const scanBtn = document.getElementById("scanBtn") as HTMLButtonElement;
const scanCurrentBtn = document.getElementById("scanCurrentBtn") as HTMLButtonElement;
const exportBtn = document.getElementById("exportBtn") as HTMLButtonElement;
const loader = document.getElementById("loader") as HTMLDivElement;
const status = document.getElementById("status") as HTMLDivElement;
const results = document.getElementById("results") as HTMLDivElement;
const verdictDisplay = document.getElementById("verdictDisplay") as HTMLDivElement;
const detailedResults = document.getElementById("detailedResults") as HTMLDivElement;
const extensionStatus = document.getElementById("extensionStatus") as HTMLSpanElement;
const cachedCount = document.getElementById("cachedCount") as HTMLSpanElement;
const protectedCount = document.getElementById("protectedCount") as HTMLSpanElement;

let vtService: VirusTotalService | null = null;
let showDetailedResults = false;

// Initialize
document.addEventListener("DOMContentLoaded", async () => {
  // Load saved API key
  const savedKey = await loadApiKey();
  if (savedKey) {
    apiKeyInput.value = savedKey;
    vtService = new VirusTotalService(savedKey);
    showStatus("✅ API Key loaded successfully!", "success");
  } else {
    showStatus("⚠️ Please configure your VirusTotal API key", "info");
  }

  // Load extension stats
  await updateStats();

  // Test background script connection
  try {
    const response = await chrome.runtime.sendMessage("ping");
    if (response === "pong") {
      extensionStatus.textContent = "Active";
      extensionStatus.style.color = "#5cb85c";
    }
  } catch (error) {
    extensionStatus.textContent = "Error";
    extensionStatus.style.color = "#dc3545";
    showStatus("⚠️ Extension background script not responding", "error");
  }
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
  showStatus("✅ API Key saved successfully!", "success");
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
    showStatus("Please enter a valid URL (include http:// or https://)", "error");
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
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab.url) {
      showStatus("Cannot access current tab URL", "error");
      return;
    }

    if (tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://")) {
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

// Scan URL Function
async function scanUrl(url: string): Promise<void> {
  showLoader(true);
  showStatus("🔍 Scanning URL for security threats...", "info");
  results.style.display = "none";

  try {
    const metadata = await vtService!.scanURL(url);
    displayResults(metadata);
    showStatus("✅ Scan completed!", "success");
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

// Display Results with Simple Verdict
function displayResults(metadata: VTURLMetadata): void {
  const verdict = getSimpleVerdict(metadata);
  const verdictClass = getVerdictClass(verdict);
  
  // Show simple verdict prominently
  verdictDisplay.innerHTML = `
    <div class="verdict-icon">${getVerdictIcon(verdict)}</div>
    <div class="verdict-text">This URL is ${verdict}</div>
  `;
  verdictDisplay.className = `verdict-display ${verdictClass}`;
  verdictDisplay.style.display = "block";

  // Prepare detailed results (hidden by default)
  const detectionStats = metadata.detectionStats;
  const domainAge = metadata.domain.domainAge 
    ? `${Math.floor(metadata.domain.domainAge / 365)} years` 
    : "Unknown";

  detailedResults.innerHTML = `
    <div class="result-section">
      <h3>🔍 Security Analysis</h3>
      <div class="result-item">
        <span class="result-label">Malicious Detections:</span>
        <span class="result-value">${detectionStats.malicious}/${detectionStats.total} engines</span>
      </div>
      <div class="result-item">
        <span class="result-label">Suspicious Detections:</span>
        <span class="result-value">${detectionStats.suspicious}/${detectionStats.total} engines</span>
      </div>
      <div class="result-item">
        <span class="result-label">Harmless Detections:</span>
        <span class="result-value">${detectionStats.harmless}/${detectionStats.total} engines</span>
      </div>
    </div>

    <div class="result-section">
      <h3>🌐 Domain Information</h3>
      <div class="result-item">
        <span class="result-label">Domain:</span>
        <span class="result-value">${metadata.hostname}</span>
      </div>
      <div class="result-item">
        <span class="result-label">Domain Age:</span>
        <span class="result-value">${domainAge}</span>
      </div>
      <div class="result-item">
        <span class="result-label">Country:</span>
        <span class="result-value">${metadata.network.country || "Unknown"}</span>
      </div>
      <div class="result-item">
        <span class="result-label">Hosting Provider:</span>
        <span class="result-value">${metadata.network.hostingProvider || "Unknown"}</span>
      </div>
    </div>

    <div class="result-section">
      <h3>🔒 Security Features</h3>
      <div class="result-item">
        <span class="result-label">HTTPS:</span>
        <span class="result-value">${metadata.url.startsWith('https') ? 'Yes' : 'No'}</span>
      </div>
      <div class="result-item">
        <span class="result-label">HSTS:</span>
        <span class="result-value">${metadata.httpInfo.hsts ? 'Enabled' : 'Disabled'}</span>
      </div>
      <div class="result-item">
        <span class="result-label">Redirects:</span>
        <span class="result-value">${metadata.redirectDepth} level(s)</span>
      </div>
    </div>
  `;

  // Show/hide toggle for detailed results
  const toggleButton = document.createElement('button');
  toggleButton.textContent = showDetailedResults ? 'Hide Details' : 'Show Details';
  toggleButton.className = 'secondary-btn';
  toggleButton.onclick = () => {
    showDetailedResults = !showDetailedResults;
    detailedResults.style.display = showDetailedResults ? 'block' : 'none';
    toggleButton.textContent = showDetailedResults ? 'Hide Details' : 'Show Details';
  };

  results.innerHTML = '';
  results.appendChild(verdictDisplay);
  results.appendChild(toggleButton);
  results.appendChild(detailedResults);
  
  detailedResults.style.display = showDetailedResults ? 'block' : 'none';
  results.style.display = "block";

  // Update stats
  updateStats();
}

// Get Simple Verdict
function getSimpleVerdict(metadata: VTURLMetadata): string {
  const { malicious, suspicious } = metadata.detectionStats;

  if (malicious > 0) {
    return "MALICIOUS";
  } else if (suspicious > 3) {
    return "SUSPICIOUS";
  } else if (suspicious > 0 || metadata.suspiciousFeatures?.length) {
    return "UNKNOWN";
  } else {
    return "SAFE";
  }
}

// Get Verdict CSS Class
function getVerdictClass(verdict: string): string {
  switch (verdict) {
    case "SAFE":
      return "verdict-safe";
    case "SUSPICIOUS":
      return "verdict-suspicious";
    case "MALICIOUS":
      return "verdict-malicious";
    default:
      return "verdict-unknown";
  }
}

// Get Verdict Icon
function getVerdictIcon(verdict: string): string {
  switch (verdict) {
    case "SAFE":
      return "✅";
    case "SUSPICIOUS":
      return "⚠️";
    case "MALICIOUS":
      return "🚨";
    default:
      return "❓";
  }
}

// Update Extension Stats
async function updateStats(): Promise<void> {
  try {
    const stats = await chrome.runtime.sendMessage({ type: "getStats" });
    if (stats) {
      cachedCount.textContent = stats.cached || "0";
      protectedCount.textContent = stats.trusted || "0";
    }
  } catch (error) {
    console.log("Could not load stats:", error);
  }
}

// Helper Functions
function showStatus(message: string, type: "success" | "error" | "info"): void {
  status.innerHTML = message;
  status.className = type;
  status.style.display = "block";

  if (type === "success") {
    setTimeout(() => {
      status.style.display = "none";
    }, 3000);
  }
}

function showLoader(show: boolean): void {
  loader.style.display = show ? "block" : "none";
  scanBtn.disabled = show;
  scanCurrentBtn.disabled = show;
}

function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

// Storage Functions
async function saveApiKey(apiKey: string): Promise<void> {
  await chrome.storage.local.set({ virusTotalApiKey: apiKey });
}

async function loadApiKey(): Promise<string | null> {
  try {
    const result = await chrome.storage.local.get("virusTotalApiKey");
    return result.virusTotalApiKey || null;
  } catch {
    return null;
  }
}

// Add keyboard shortcut for current tab
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === 'Enter') {
    scanCurrentBtn.click();
  }
});
