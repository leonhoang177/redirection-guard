interface BackgroundAnalysisResponse {
  success: boolean;
  verdict?: string;
  error?: string;
}

// DOM Elements
const urlInput = document.getElementById("urlInput") as HTMLInputElement;
const scanBtn = document.getElementById("scanBtn") as HTMLButtonElement;
const scanCurrentBtn = document.getElementById(
  "scanCurrentBtn"
) as HTMLButtonElement;
const loader = document.getElementById("loader") as HTMLDivElement;
const statusDiv = document.getElementById("status") as HTMLDivElement;
const results = document.getElementById("results") as HTMLDivElement;
const verdictDisplay = document.getElementById(
  "verdictDisplay"
) as HTMLDivElement;
const detailedResults = document.getElementById(
  "detailedResults"
) as HTMLDivElement;
const extensionStatus = document.getElementById(
  "extensionStatus"
) as HTMLSpanElement;

let showDetailedResults = false;
let statusHideTimeoutId: number | null = null;

// Initialize
document.addEventListener("DOMContentLoaded", async () => {
  showStatus("🚀 Redirect Guard is ready", "success");

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
    showStatus("👉 Please enter an URL", "error");
    return;
  }

  if (!isValidUrl(url)) {
    showStatus(
      "👉 Please enter a valid URL (starts with http:// or https://)",
      "error"
    );
    return;
  }

  await analyzeURL(url);
});

// Scan Current Tab
scanCurrentBtn.addEventListener("click", async () => {
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
      showStatus("🚨 Failed to scan Chrome internal pages", "error");
      return;
    }

    urlInput.value = tab.url;
    await analyzeURL(tab.url);
  } catch (error) {
    showStatus("🚩 Error accessing current tab", "error");
    console.error(error);
  }
});

// Scan URL Function (using local heuristics)
async function analyzeURL(url: string): Promise<void> {
  showLoader(true);
  showStatus("🔎 Analyzing URL for suspicious patterns...", "info");
  results.style.display = "none";

  try {
    // Get analysis from background script (handle waitlist retries)
    let analysis: BackgroundAnalysisResponse | null = null;
    let retryCount = 0;
    const maxRetries = 3;

    do {
      analysis = (await chrome.runtime.sendMessage({
        type: "analyzeUrl",
        url,
      })) as BackgroundAnalysisResponse;

      if (!analysis || !analysis.success || !analysis.verdict) {
        throw new Error(
          analysis?.error ?? "Failed to analyze URL: No verdict returned."
        );
      }

      if (analysis.verdict === "waitlist") {
        retryCount++;
        if (retryCount > maxRetries) {
          throw new Error("Analysis is still pending after multiple attempts.");
        }

        showStatus(
          "💡 Encounter a new URL: We need more time to scan...",
          "info",
          20_000
        );
        await delay(20_000);
      }
    } while (analysis?.verdict === "waitlist");

    displayResults(url, {
      verdict: analysis.verdict,
      reasons: [`Vertex AI final verdict: ${analysis.verdict.toUpperCase()}`],
    });
    showStatus(`✅ Scan completed!`, "success", 3_000);
  } catch (error: any) {
    showStatus(`Error: ${error.message}`, "error");
    console.error("Scan error:", error);
  } finally {
    showLoader(false);
  }
}

// Display Results
function displayResults(
  url: string,
  analysis: { verdict: string; reasons: string[] }
): void {
  const { verdict, reasons } = analysis;
  const verdictLower = verdict.toLowerCase();
  const verdictUpper = verdict.toUpperCase();
  const verdictClass = getVerdictClass(verdictLower);

  // Show simple verdict prominently
  verdictDisplay.innerHTML = `
    <div class="verdict-banner">
      <span class="verdict-text verdict-text-${verdictLower}">${verdictUpper}</span>
      <span class="verdict-icon">${getVerdictIcon(verdictLower)}</span>
    </div>
  `;
  verdictDisplay.className = `verdict-display ${verdictClass}`;
  verdictDisplay.style.display = "block";

  // Parse URL for display
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch {
    urlObj = { hostname: "Invalid URL" };
  }

  // Prepare detailed results
  detailedResults.innerHTML = `
    <div class="result-section">
      <h3>🔎 URL Information</h3>
      <div class="result-item">
        <span class="result-label">Domain:</span>
        <span class="result-value">${urlObj.hostname}</span>
      </div>
      <div class="result-item">
        <span class="result-label">HTTPS:</span>
        <span class="result-value">${
          url.startsWith("https") ? "✅ Yes" : "❌ No"
        }</span>
      </div>
      <div class="result-item">
        <span class="result-label">IP Address:</span>
        <span class="result-value">${
          /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname)
            ? "⚠️ Yes"
            : "✅ No"
        }</span>
      </div>
    </div>
  `;

  // Show/hide toggle for detailed results
  const toggleButton = document.createElement("button");
  toggleButton.textContent = showDetailedResults
    ? "Hide Details"
    : "Show Details";
  toggleButton.className = "secondary-btn";
  toggleButton.onclick = () => {
    showDetailedResults = !showDetailedResults;
    detailedResults.style.display = showDetailedResults ? "block" : "none";
    toggleButton.textContent = showDetailedResults
      ? "Hide Details"
      : "Show Details";
  };

  results.innerHTML = "";
  results.appendChild(verdictDisplay);
  results.appendChild(toggleButton);
  results.appendChild(detailedResults);

  detailedResults.style.display = showDetailedResults ? "block" : "none";
  results.style.display = "block";
}

// Get Verdict CSS Class
function getVerdictClass(verdict: string): string {
  switch (verdict) {
    case "legit":
      return "verdict-display-legit";
    case "phish":
      return "verdict-display-phish";
    default:
      return "verdict-display-unknown";
  }
}

// Get Verdict Icon
function getVerdictIcon(verdict: string): string {
  switch (verdict) {
    case "legit":
      return "✅";
    case "phish":
      return "⚠️";
    default:
      return "❓";
  }
}

function showStatus(
  message: string,
  type: "success" | "error" | "info",
  autoHideMs?: number
): void {
  if (statusHideTimeoutId !== null) {
    clearTimeout(statusHideTimeoutId);
    statusHideTimeoutId = null;
  }

  statusDiv.innerHTML = message;
  statusDiv.className = type;
  statusDiv.style.display = "block";

  if (autoHideMs && autoHideMs > 0) {
    statusHideTimeoutId = window.setTimeout(() => {
      statusDiv.style.display = "none";
      statusHideTimeoutId = null;
    }, autoHideMs);
  }
}

function showLoader(show: boolean): void {
  loader.style.display = show ? "block" : "none";
  scanBtn.disabled = show;
  scanCurrentBtn.disabled = show;
}

function isValidUrl(url: string): boolean {
  if (!(url.startsWith("http://") || url.startsWith("https://"))) {
    return false;
  }
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Add keyboard shortcut for current tab
document.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.key === "Enter") {
    scanCurrentBtn.click();
  }
});
