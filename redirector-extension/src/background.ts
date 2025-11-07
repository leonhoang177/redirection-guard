/// <reference types="chrome"/>

console.log("🟢 Redirect Guard: Background service worker initialized");

// Store for tracking navigation and redirects
interface NavigationInfo {
  initialUrl: string;
  currentUrl: string;
  timestamp: number;
  tabId: number;
  isRedirect: boolean;
  redirectCount: number;
}

const activeNavigations = new Map<number, NavigationInfo>();
const checkedUrls = new Map<string, { verdict: string; timestamp: number }>();
const allowedUrls = new Set<string>(); // URLs user chose to proceed to
const safeOrigins = new Set<string>(); // Known safe domains to skip

// Cache duration: 5 minutes
const CACHE_DURATION = 5 * 60 * 1000;

// Initialize safe domains (popular, trusted sites)
const TRUSTED_DOMAINS = [
  'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'twitter.com',
  'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com',
  'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'mozilla.org'
];

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log("✅ Redirect Guard installed");
  
  // Populate trusted domains
  TRUSTED_DOMAINS.forEach(domain => {
    safeOrigins.add(domain);
    safeOrigins.add(`www.${domain}`);
  });
  
  chrome.alarms.create("keepAlive", { periodInMinutes: 4 });
  chrome.alarms.create("cleanCache", { periodInMinutes: 10 });
});

// Keep service worker alive and clean cache
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "keepAlive") {
    console.log("💓 Background heartbeat");
  } else if (alarm.name === "cleanCache") {
    cleanExpiredCache();
  }
});

function cleanExpiredCache() {
  const now = Date.now();
  for (const [url, data] of checkedUrls.entries()) {
    if (now - data.timestamp > CACHE_DURATION) {
      checkedUrls.delete(url);
    }
  }
  console.log(`🧹 Cache cleaned. Entries remaining: ${checkedUrls.size}`);
}

// Helper functions
function extractDomain(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isTrustedDomain(url: string): boolean {
  const domain = extractDomain(url);
  return safeOrigins.has(domain) || 
         safeOrigins.has(domain.replace('www.', '')) ||
         TRUSTED_DOMAINS.some(trusted => domain.endsWith(trusted));
}

function isSystemUrl(url: string): boolean {
  return url.startsWith("chrome://") || 
         url.startsWith("chrome-extension://") ||
         url.startsWith("edge://") ||
         url.startsWith("about:");
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
  
  console.log(`📍 Navigation started: ${url}`);
  
  // Store navigation info
  activeNavigations.set(tabId, {
    initialUrl: url,
    currentUrl: url,
    timestamp: Date.now(),
    tabId,
    isRedirect: false,
    redirectCount: 0
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
      initialUrl: url,
      currentUrl: url,
      timestamp: Date.now(),
      tabId,
      isRedirect: false,
      redirectCount: 0
    });
    return;
  }
  
  // Check if this is a redirect
  const isServerRedirect = transitionType === "server_redirect" || 
                          transitionQualifiers.includes("server_redirect");
  const isClientRedirect = transitionQualifiers.includes("client_redirect");
  const isCrossDomain = !isSameDomain(navigation.currentUrl, url);
  
  if (isServerRedirect || isClientRedirect || isCrossDomain) {
    console.log(`🔀 REDIRECT DETECTED: ${navigation.currentUrl} → ${url}`);
    console.log(`   Type: ${transitionType}, Qualifiers: ${transitionQualifiers.join(', ')}`);
    
    navigation.isRedirect = true;
    navigation.redirectCount++;
    navigation.currentUrl = url;
    
    // Skip if user already allowed this URL
    if (allowedUrls.has(url)) {
      console.log("✅ User previously allowed this URL");
      allowedUrls.delete(url);
      return;
    }
    
    // Skip redirects to trusted domains
    if (isTrustedDomain(url)) {
      console.log(`✅ Redirect to trusted domain: ${extractDomain(url)}`);
      return;
    }
    
    // PAUSE AND SCAN THE REDIRECT
    console.log("⚠️ Suspicious redirect detected, pausing navigation");
    await pauseAndScan(tabId, url, navigation.initialUrl);
  }
});

// Handle tab completion (final URL loaded)
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId === 0) {
    // Clean up navigation tracking
    activeNavigations.delete(details.tabId);
  }
});

// Pause navigation and scan URL
async function pauseAndScan(tabId: number, redirectUrl: string, originalUrl: string) {
  try {
    // Show loading page immediately
    const loadingUrl = chrome.runtime.getURL("loading.html") + 
      `?url=${encodeURIComponent(redirectUrl)}&from=${encodeURIComponent(originalUrl)}`;
    
    await chrome.tabs.update(tabId, { url: loadingUrl });
    
    // Start scanning in background
    await handleUrlScan(tabId, redirectUrl, originalUrl);
  } catch (error) {
    console.error("Error pausing navigation:", error);
  }
}

// Handle URL scanning
async function handleUrlScan(tabId: number, url: string, originalUrl: string) {
  console.log(`🔍 Scanning redirect: ${url}`);
  
  // Check cache first
  const cached = checkedUrls.get(url);
  if (cached && (Date.now() - cached.timestamp < CACHE_DURATION)) {
    console.log(`⚡ Using cached verdict: ${cached.verdict}`);
    await handleVerdict(tabId, url, originalUrl, cached.verdict);
    return;
  }
  
  // Get API key
  const apiKey = await getApiKey();
  if (!apiKey) {
    console.log("⚠️ No API key configured");
    await handleVerdict(tabId, url, originalUrl, "unknown");
    return;
  }
  
  // Scan the URL
  const verdict = await quickScanUrl(url, apiKey);
  
  // Cache the result
  checkedUrls.set(url, { verdict, timestamp: Date.now() });
  
  // Handle based on verdict
  await handleVerdict(tabId, url, originalUrl, verdict);
}

// Handle verdict and take appropriate action
async function handleVerdict(tabId: number, url: string, originalUrl: string, verdict: string) {
  console.log(`📊 VERDICT: ${url} → ${verdict}`);
  
  if (verdict === "malicious") {
    console.log("🚨 BLOCKING malicious redirect");
    await blockAndWarn(tabId, url, originalUrl, verdict);
  } else if (verdict === "suspicious") {
    console.log("⚠️ WARNING about suspicious redirect");
    await blockAndWarn(tabId, url, originalUrl, verdict);
  } else if (verdict === "unknown") {
    console.log("❓ Unknown URL - showing caution warning");
    await blockAndWarn(tabId, url, originalUrl, verdict);
  } else {
    // Safe - allow the redirect to continue
    console.log("✅ Redirect is SAFE, allowing navigation");
    allowedUrls.add(url);
    await chrome.tabs.update(tabId, { url: url });
  }
}

// Quick URL scanning using VirusTotal
async function quickScanUrl(url: string, apiKey: string): Promise<string> {
  try {
    const urlId = btoa(url).replace(/=/g, "");
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": apiKey }
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        console.log("📤 URL not in VT database, submitting for scan");
        await submitUrlToVT(url, apiKey);
        return "unknown";
      }
      console.log(`❌ VT API error: ${response.status}`);
      return "unknown";
    }
    
    const data = await response.json();
    const stats = data.data?.attributes?.last_analysis_stats;
    
    if (!stats) {
      console.log("❌ No analysis stats available");
      return "unknown";
    }
    
    console.log(`📈 VT Stats: Malicious: ${stats.malicious}, Suspicious: ${stats.suspicious}, Harmless: ${stats.harmless}`);
    
    // Determine verdict based on detection stats
    if (stats.malicious > 0) {
      return "malicious";
    } else if (stats.suspicious > 3) {
      return "suspicious";
    } else if (stats.harmless >= 5 && stats.malicious === 0 && stats.suspicious <= 1) {
      return "safe";
    } else {
      return "unknown";
    }
    
  } catch (error) {
    console.error("❌ Error scanning URL:", error);
    return "unknown";
  }
}

// Submit URL to VirusTotal for analysis
async function submitUrlToVT(url: string, apiKey: string): Promise<void> {
  try {
    const formData = new FormData();
    formData.append("url", url);
    
    const response = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { "x-apikey": apiKey },
      body: formData
    });
    
    if (response.ok) {
      console.log("✅ URL submitted to VirusTotal for analysis");
    } else {
      console.log(`⚠️ Failed to submit URL: ${response.status}`);
    }
  } catch (error) {
    console.error("❌ Error submitting URL:", error);
  }
}

// Block navigation and show warning page
async function blockAndWarn(tabId: number, url: string, originalUrl: string, verdict: string) {
  try {
    const warningUrl = chrome.runtime.getURL("warning.html") + 
      `?url=${encodeURIComponent(url)}&verdict=${verdict}&from=${encodeURIComponent(originalUrl)}`;
    
    await chrome.tabs.update(tabId, { url: warningUrl });
    
    // Store blocked URL info for reference
    await chrome.storage.local.set({
      [`blocked_${tabId}_${Date.now()}`]: {
        url,
        originalUrl,
        verdict,
        timestamp: Date.now()
      }
    });
    
    console.log(`🛡️ Blocked ${verdict} redirect and showed warning`);
  } catch (error) {
    console.error("❌ Error blocking navigation:", error);
  }
}

// Get API key from storage
async function getApiKey(): Promise<string | null> {
  try {
    const result = await chrome.storage.local.get("virusTotalApiKey");
    return result.virusTotalApiKey || null;
  } catch {
    return null;
  }
}

// Message handler
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg === "ping") {
    console.log("📩 Received ping from popup");
    sendResponse("pong");
  } else if (msg.type === "allowUrl") {
    // User chose to proceed to blocked URL
    const { url, tabId } = msg;
    console.log(`🔓 User allowing URL: ${url}`);
    allowedUrls.add(url);
    chrome.tabs.update(tabId, { url });
    sendResponse({ success: true });
  } else if (msg.type === "getStats") {
    // Return some stats for the popup
    sendResponse({
      cached: checkedUrls.size,
      active: activeNavigations.size,
      trusted: safeOrigins.size
    });
  }
  return true;
});

// Clean up on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  activeNavigations.delete(tabId);
});