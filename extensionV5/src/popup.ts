interface BackgroundAnalysisResponse {
  success: boolean;
  verdict?: string;
  jsonOutput?: string;
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
          12000
        );
        await delay(12000);
      }
    } while (analysis?.verdict === "waitlist");

    displayResults(url, {
      verdict: analysis.verdict,
      jsonOutput: analysis.jsonOutput,
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
  analysis: { verdict: string; jsonOutput?: string }
): void {
  const { verdict, jsonOutput } = analysis;
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

  const detailRows = formatJsonDetails(jsonOutput, url);

  detailedResults.innerHTML = `
    <div class="result-section">
      <h3>📊 Scan Details</h3>
      ${detailRows}
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

function formatJsonDetails(
  jsonOutput: string | undefined,
  fallbackUrl: string
) {
  if (!jsonOutput) {
    return `
      <div class="result-item">
        <span class="result-label">Details:</span>
        <span class="result-value">No scanner data available for ${escapeHtml(
          fallbackUrl
        )}.</span>
      </div>
    `;
  }

  try {
    const parsed = JSON.parse(jsonOutput) as Record<string, unknown>;
    const prioritizedKeys = [
      "url",
      "hostname",
      "title",
      "isHttps",
      "reputation",
      "maliciousVotes",
      "suspiciousVotes",
      "services",
      "features",
      "redirectCount",
      "domainAge",
      "networkCountry",
      "serverName",
    ];
    const orderedKeys = [
      ...new Set([...prioritizedKeys, ...Object.keys(parsed)]),
    ];
    const rows = orderedKeys
      .filter((key) => Object.prototype.hasOwnProperty.call(parsed, key))
      .map((key) => {
        const value = parsed[key];
        return `
          <div class="result-item">
            <span class="result-label">${formatDetailKey(key)}:</span>
            <span class="result-value">${formatDetailValue(value)}</span>
          </div>
        `;
      });

    if (rows.length === 0) {
      return `
        <div class="result-item">
          <span class="result-label">Details:</span>
          <span class="result-value">Scanner returned an empty payload.</span>
        </div>
      `;
    }

    return rows.join("");
  } catch (error) {
    console.error("Failed to parse jsonOutput:", error);
    return `
      <div class="result-item">
        <span class="result-label">Raw JSON:</span>
        <span class="result-value code-block">${escapeHtml(jsonOutput)}</span>
      </div>
    `;
  }
}

function formatDetailKey(key: string): string {
  const base = key
    .replace(/([A-Z])/g, " $1")
    .replace(/_/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^./, (c) => c.toUpperCase());

  return base
    .replace(/M\s*I\s*M\s*E/gi, "MIME")
    .replace(/S\s*A\s*N/gi, "SAN")
    .replace(/U\s*R\s*L/gi, "URL");
}

function formatDetailValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "—";
  }

  if (typeof value === "boolean") {
    return value ? "✅ True" : "❌ False";
  }

  if (typeof value === "number") {
    return value.toString();
  }

  if (typeof value === "string") {
    return escapeHtml(value);
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return "—";
    return value.map((item) => formatDetailValue(item)).join(", ");
  }

  return escapeHtml(JSON.stringify(value));
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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
