/// <reference types="chrome"/>

import { runScanner } from "./scanner/single-scanner.js";
import { VERTEX_AI_CONFIG } from "./vertexConfig";

console.log("🟢 Redirect Guard: Background service worker initialized");

// Store for tracking navigation and redirects
interface NavigationInfo {
  currentUrl: string;
  timestamp: number;
  tabId: number;
  isRedirect: boolean;
  redirectCount: number;
}

const activeNavigations = new Map<number, NavigationInfo>();
const allowedUrls = new Set<string>(); // URLs user chose to proceed to
const safeOrigins = new Set<string>(); // Known safe domains to skip

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  //console.log("✅ Redirect Guard installed");
  chrome.alarms.create("keepAlive", { periodInMinutes: 4 });
});

// Keep service worker alive
chrome.alarms.onAlarm.addListener((alarm) => {
  /*
  if (alarm.name === "keepAlive") {
    console.log("Background heartbeat...");
  }
  */
});

// Helper functions
function extractDomain(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isTrustedDomain(url: string): boolean {
  const domain = extractDomain(url);
  return safeOrigins.has(domain) || safeOrigins.has(domain.replace("www.", ""));
}

function isSystemUrl(url: string): boolean {
  return (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:")
  );
}

function isSameDomain(url1: string, url2: string): boolean {
  const domain1 = extractDomain(url1);
  const domain2 = extractDomain(url2);
  return domain1 === domain2;
}

// Track initial navigation attempts
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame

  const { url, tabId } = details;

  // Skip system URLs
  if (isSystemUrl(url)) return;

  console.log(`🔍 Navigated to systemURL: ${url}`);

  // Store navigation info
  activeNavigations.set(tabId, {
    currentUrl: url,
    timestamp: Date.now(),
    tabId,
    isRedirect: false,
    redirectCount: 0,
  });
});

// Detect redirects and cross-domain navigation
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const { url, tabId, transitionType, transitionQualifiers } = details;

  // Skip system URLs
  if (isSystemUrl(url)) return;

  const navigation = activeNavigations.get(tabId);
  if (!navigation) {
    // This might be a direct navigation, track it
    activeNavigations.set(tabId, {
      currentUrl: url,
      timestamp: Date.now(),
      tabId,
      isRedirect: false,
      redirectCount: 0,
    });
    return;
  }

  // Check if this is a redirect
  const isServerRedirect =
    transitionType === "server_redirect" ||
    transitionQualifiers.includes("server_redirect");
  const isClientRedirect = transitionQualifiers.includes("client_redirect");
  const isCrossDomain = !isSameDomain(navigation.currentUrl, url);

  if (isServerRedirect || isClientRedirect || isCrossDomain) {
    console.log(
      `----- REDIRECTION DETECTED -----\nDestination: ${url}\nType: ${transitionQualifiers.join(
        ", "
      )}`
    );

    navigation.isRedirect = true;
    navigation.redirectCount++;
    navigation.currentUrl = url;

    // Skip if user already allowed this URL
    if (allowedUrls.has(url)) {
      console.log("✅ URL has been previously verified.");
      allowedUrls.delete(url);
      return;
    }

    // Skip redirects to trusted domains
    if (isTrustedDomain(url)) {
      console.log(`✅ Redirect to trusted domain: ${extractDomain(url)}`);
      return;
    }

    // PAUSE THE REDIRECT - Send to scanner analysis
    await pauseAndAnalyze(tabId, url);
  }
});

// Handle tab completion (final URL loaded)
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId === 0) {
    // Clean up navigation tracking
    activeNavigations.delete(details.tabId);
  }
});

async function wait(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getAuthToken(): Promise<string> {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: true }, (token) => {
      if (chrome.runtime.lastError) {
        reject(
          new Error(
            `Failed to get auth token: ${chrome.runtime.lastError.message}`
          )
        );
        return;
      }

      if (!token) {
        reject(
          new Error("Failed to get auth token: Token is null or undefined.")
        );
        return;
      }

      resolve(token);
    });
  });
}

async function requestVertexClassification(
  promptText: string
): Promise<string> {
  const token = await getAuthToken();
  const { PROJECT_ID, REGION, ENDPOINT_ID } = VERTEX_AI_CONFIG;
  const apiUrl = `https://${REGION}-aiplatform.googleapis.com/v1/projects/${PROJECT_ID}/locations/${REGION}/endpoints/${ENDPOINT_ID}:generateContent`;

  const requestBody = {
    contents: [
      {
        role: "user",
        parts: [
          {
            text: promptText,
          },
        ],
      },
    ],
  };

  const response = await fetch(apiUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const contentType = response.headers.get("content-type");
    let errorDetail = `Status: ${response.status}`;

    if (contentType && contentType.includes("application/json")) {
      const errorData = await response.json();
      errorDetail = `Status: ${response.status} - ${JSON.stringify(errorData)}`;
    } else {
      const errorText = await response.text();
      errorDetail = `Status: ${response.status} - Body: ${errorText.substring(
        0,
        200
      )}...`;
    }

    throw new Error(`Vertex AI API error: ${errorDetail}`);
  }

  const data = await response.json();
  const generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim();

  if (!generatedText) {
    throw new Error(
      "Gemini response was valid but contained no generated text."
    );
  }

  return generatedText;
}

function normalizeAiVerdict(rawText: string): "legit" | "phish" | "unknown" {
  const normalized = rawText.trim().toLowerCase();
  const legitSignals = ["legit", "legitimate"];
  const phishSignals = ["phish", "phishing"];

  const hasLegitSignal = legitSignals.some((signal) =>
    normalized.includes(signal)
  );
  const hasPhishSignal = phishSignals.some((signal) =>
    normalized.includes(signal)
  );

  if (hasLegitSignal && !hasPhishSignal) {
    return "legit";
  }

  if (hasPhishSignal && !hasLegitSignal) {
    return "phish";
  }

  return "unknown";
}

// Pause navigation and send to scanner analysis
async function pauseAndAnalyze(tabId: number, redirectURL: string) {
  console.log("----- REDIRECTION PAUSED -----");

  // Show loading page
  const loadingUrl =
    chrome.runtime.getURL("loading.html") +
    `?url=${encodeURIComponent(redirectURL)}`;

  await chrome.tabs.update(tabId, { url: loadingUrl });

  let promptText = null;

  promptText = await runScanner(redirectURL);

  /*if (promptText !== null) {
    console.log(`\n\n${promptText}\n\n`);
  }*/

  let verdict = "unknown";

  // AI CALL
  console.log("AI is analyzing...");

  if (!!promptText) {
    try {
      const aiResponse = await requestVertexClassification(promptText);
      verdict = normalizeAiVerdict(aiResponse);
      //console.log("Vertex AI raw response:", aiResponse);
    } catch (error) {
      console.error("Vertex AI call failed:", error);
    }
  } else {
    console.warn(
      "Scanner did not return prompt text; defaulting to phish verdict."
    );
  }

  console.log(`AI's final verdict: 🔥 ${verdict.toUpperCase()} 🔥`);

  // Send verdict to be handled
  await handleVerdict(tabId, redirectURL, verdict);
}

// Handle verdict from analysis
async function handleVerdict(tabId: number, url: string, verdict: string) {
  //console.log(`📊 VERDICT RECEIVED: ${url} → ${verdict}`);

  if (verdict === "phish") {
    console.log("Action: Blocked");
    await blockAndWarn(tabId, url, verdict);
  } else if (verdict === "legit") {
    console.log("Action: Allowed");
    allowedUrls.add(url);
    // Safe - allow the redirect to continue
    await chrome.tabs.update(tabId, { url: url });
  } else {
    //TODO Add some sorta shit here to handle errors
    console.log("UNKNOWN RETURN VALUE FROM THE AI");
    console.log("Attackers win by default I guess!");
    allowedUrls.add(url);
    await chrome.tabs.update(tabId, { url: url });
  }
}

// Block navigation and show warning page
async function blockAndWarn(tabId: number, url: string, verdict: string) {
  try {
    // 1. Construct the warning URL
    const warningUrl =
      chrome.runtime.getURL("warning.html") +
      `?url=${encodeURIComponent(url)}&verdict=${verdict}`;

    // 2. Update the tab to show the warning page
    await chrome.tabs.update(tabId, { url: warningUrl });

    // 3. Store blocked URL info for reference
    await chrome.storage.local.set({
      [`blocked_${tabId}_${Date.now()}`]: {
        url,
        verdict,
        timestamp: Date.now(),
      },
    });

    //console.log(`Blocked ${verdict} redirect and showed warning`);
  } catch (error) {
    console.error("Error blocking navigation:", error);
  }
}

// Message handler
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg === "ping") {
    console.log("Received ping from popup");
    sendResponse("pong");
  } else if (msg.type === "allowUrl") {
    // User chose to proceed to blocked URL
    const { url, tabId } = msg;
    console.log(`User allowing URL: ${url}`);
    allowedUrls.add(url);
    chrome.tabs.update(tabId, { url });
    sendResponse({ success: true });
  } else if (msg.type === "getStats") {
    // Return some stats for the popup
    sendResponse({
      active: activeNavigations.size,
      trusted: safeOrigins.size,
    });
  } else if (msg.type === "analysisResult") {
    // Manual analysis result from loading page buttons
    const { url, tabId, verdict } = msg;
    console.log(`🔥 Manual analysis result received for ${url}: ${verdict}`);
    handleVerdict(tabId, url, verdict);
    sendResponse({ success: true });
  } else if (msg.type === "requestAnalysis") {
    // EXTERNAL SCRIPT REQUESTING URL TO ANALYZE
    sendResponse({ success: true });
  }
  return true;
});

// Clean up on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  activeNavigations.delete(tabId);
});
