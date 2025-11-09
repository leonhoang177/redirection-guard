// DOM Elements
const urlInput = document.getElementById("urlInput") as HTMLInputElement;
const scanBtn = document.getElementById("scanBtn") as HTMLButtonElement;
const scanCurrentBtn = document.getElementById("scanCurrentBtn") as HTMLButtonElement;
const loader = document.getElementById("loader") as HTMLDivElement;
const statusDiv = document.getElementById("status") as HTMLDivElement;
const results = document.getElementById("results") as HTMLDivElement;
const verdictDisplay = document.getElementById("verdictDisplay") as HTMLDivElement;
const detailedResults = document.getElementById("detailedResults") as HTMLDivElement;
const extensionStatus = document.getElementById("extensionStatus") as HTMLSpanElement;
const cachedCount = document.getElementById("cachedCount") as HTMLSpanElement;
const protectedCount = document.getElementById("protectedCount") as HTMLSpanElement;

let showDetailedResults = false;

// Initialize
document.addEventListener("DOMContentLoaded", async () => {
  showStatus("✅ Redirect Guard ready", "success");

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

// Scan URL
scanBtn.addEventListener("click", async () => {
  const url = urlInput.value.trim();

  if (!url) {
    showStatus("Please enter a URL", "error");
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

// Scan URL Function (using local heuristics)
async function scanUrl(url: string): Promise<void> {
  showLoader(true);
  showStatus("🔎 Analyzing URL for suspicious patterns...", "info");
  results.style.display = "none";

  try {
    // Get analysis from background script
    const analysis = await chrome.runtime.sendMessage({ type: "analyzeUrl", url });
    
    if (!analysis) {
      throw new Error("Failed to analyze URL");
    }

    displayResults(url, analysis);
    showStatus("✅ Scan completed!", "success");
  } catch (error: any) {
    showStatus(`Error: ${error.message}`, "error");
    console.error("Scan error:", error);
  } finally {
    showLoader(false);
  }
}

// Display Results
function displayResults(url: string, analysis: { verdict: string; reasons: string[] }): void {
  const { verdict, reasons } = analysis;
  const verdictClass = getVerdictClass(verdict.toUpperCase());
  
  // Show simple verdict prominently
  verdictDisplay.innerHTML = `
    <div class="verdict-icon">${getVerdictIcon(verdict.toUpperCase())}</div>
    <div class="verdict-text">This URL is ${verdict.toUpperCase()}</div>
  `;
  verdictDisplay.className = `verdict-display ${verdictClass}`;
  verdictDisplay.style.display = "block";

  // Parse URL for display
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch {
    urlObj = { hostname: "Invalid URL", protocol: "", pathname: "" };
  }

  // Prepare detailed results
  detailedResults.innerHTML = `
    <div class="result-section">
      <h3>🔍 Analysis Details</h3>
      ${reasons.map(reason => `
        <div class="result-item">
          • ${reason}
        </div>
      `).join('')}
    </div>

    <div class="result-section">
      <h3>🌐 URL Information</h3>
      <div class="result-item">
        <span class="result-label">Domain:</span>
        <span class="result-value">${urlObj.hostname}</span>
      </div>
      <div class="result-item">
        <span class="result-label">Protocol:</span>
        <span class="result-value">${urlObj.protocol}</span>
      </div>
      <div class="result-item">
        <span class="result-label">Path:</span>
        <span class="result-value">${urlObj.pathname || '/'}</span>
      </div>
    </div>

    <div class="result-section">
      <h3>🔒 Security Checks</h3>
      <div class="result-item">
        <span class="result-label">HTTPS:</span>
        <span class="result-value">${url.startsWith('https') ? '✅ Yes' : '❌ No'}</span>
      </div>
      <div class="result-item">
        <span class="result-label">IP Address:</span>
        <span class="result-value">${/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname) ? '⚠️ Yes' : '✅ No'}</span>
      </div>
      <div class="result-item">
        <span class="result-label">Analysis Method:</span>
        <span class="result-value">Heuristic Pattern Matching</span>
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
  statusDiv.innerHTML = message;
  statusDiv.className = type;
  statusDiv.style.display = "block";

  if (type === "success") {
    setTimeout(() => {
      statusDiv.style.display = "none";
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

// Add keyboard shortcut for current tab
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === 'Enter') {
    scanCurrentBtn.click();
  }
});