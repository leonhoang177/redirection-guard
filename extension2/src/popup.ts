import { VirusTotalService, convertToCSV, downloadCSV } from './virusTotalService.js';
import { VTURLMetadata } from './types.js';

// Storage for scan results
let scanResults: VTURLMetadata[] = [];
let vtService: VirusTotalService | null = null;

// DOM Elements
const apiKeyInput = document.getElementById('apiKey') as HTMLInputElement;
const saveApiKeyBtn = document.getElementById('saveApiKey') as HTMLButtonElement;
const urlInput = document.getElementById('urlInput') as HTMLInputElement;
const scanBtn = document.getElementById('scanBtn') as HTMLButtonElement;
const scanCurrentBtn = document.getElementById('scanCurrentBtn') as HTMLButtonElement;
const exportBtn = document.getElementById('exportBtn') as HTMLButtonElement;
const loader = document.getElementById('loader') as HTMLDivElement;
const status = document.getElementById('status') as HTMLDivElement;
const results = document.getElementById('results') as HTMLDivElement;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  // Load saved API key
  const savedKey = await loadApiKey();
  if (savedKey) {
    apiKeyInput.value = savedKey;
    vtService = new VirusTotalService(savedKey);
    showStatus('API Key loaded successfully!', 'success');
  }

  // Load saved results
  const savedResults = await loadResults();
  if (savedResults && savedResults.length > 0) {
    scanResults = savedResults;
    exportBtn.style.display = 'block';
    showStatus(`${savedResults.length} previous scan(s) loaded`, 'info');
  }
});

// Save API Key
saveApiKeyBtn.addEventListener('click', async () => {
  const apiKey = apiKeyInput.value.trim();
  
  if (!apiKey) {
    showStatus('Please enter an API key', 'error');
    return;
  }

  if (apiKey.length !== 64) {
    showStatus('API key should be 64 characters long', 'error');
    return;
  }

  await saveApiKey(apiKey);
  vtService = new VirusTotalService(apiKey);
  showStatus('API Key saved successfully!', 'success');
});

// Scan URL
scanBtn.addEventListener('click', async () => {
  const url = urlInput.value.trim();
  
  if (!url) {
    showStatus('Please enter a URL', 'error');
    return;
  }

  if (!vtService) {
    showStatus('Please save your API key first', 'error');
    return;
  }

  if (!isValidUrl(url)) {
    showStatus('Please enter a valid URL (include http:// or https://)', 'error');
    return;
  }

  await scanUrl(url);
});

// Scan Current Tab
scanCurrentBtn.addEventListener('click', async () => {
  if (!vtService) {
    showStatus('Please save your API key first', 'error');
    return;
  }

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab.url) {
      showStatus('Cannot access current tab URL', 'error');
      return;
    }

    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      showStatus('Cannot scan Chrome internal pages', 'error');
      return;
    }

    urlInput.value = tab.url;
    await scanUrl(tab.url);
  } catch (error) {
    showStatus('Error accessing current tab', 'error');
    console.error(error);
  }
});

// Export to CSV
exportBtn.addEventListener('click', () => {
  if (scanResults.length === 0) {
    showStatus('No results to export', 'error');
    return;
  }

  const csv = convertToCSV(scanResults);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
  downloadCSV(csv, `comprehensive_url_scan_${timestamp}.csv`);
  showStatus('CSV exported successfully!', 'success');
});

// Scan URL Function
async function scanUrl(url: string): Promise<void> {
  showLoader(true);
  showStatus('Performing comprehensive URL analysis... This may take 10-15 seconds.', 'info');
  results.style.display = 'none';

  try {
    const metadata = await vtService!.scanURL(url);
    scanResults.push(metadata);
    
    // Save results
    await saveResults(scanResults);
    
    // Display results
    displayComprehensiveResults(metadata);
    showStatus('Comprehensive scan completed!', 'success');
    exportBtn.style.display = 'block';
  } catch (error: any) {
    const errorMessage = error.message.includes('quota') 
      ? 'API quota exceeded. Please wait or upgrade your VirusTotal account.'
      : `Error: ${error.message}`;
    showStatus(errorMessage, 'error');
    console.error('Scan error:', error);
  } finally {
    showLoader(false);
  }
}

// Display Comprehensive Results
function displayComprehensiveResults(metadata: VTURLMetadata): void {
  const threatLevel = getThreatLevel(metadata);
  const threatClass = 
    threatLevel === 'Safe' ? 'threat-safe' :
    threatLevel === 'Suspicious' ? 'threat-warning' : 'threat-danger';

  const domainAge = metadata.domain.domainAge 
    ? `${metadata.domain.domainAge} days (${Math.floor(metadata.domain.domainAge / 365)} years)`
    : 'Unknown';

  results.innerHTML = `
    <div style="margin-bottom: 15px;">
      <div class="threat-level ${threatClass}">
        ${getThreatIcon(threatLevel)} ${threatLevel}
      </div>
    </div>

    <div class="result-section">
      <div class="result-item">
        <span class="result-label">Original URL:</span><br>
        <small>${truncateText(metadata.url, 50)}</small>
      </div>
      ${metadata.finalUrl && metadata.finalUrl !== metadata.url ? `
      <div class="result-item">
        <span class="result-label">Final URL:</span><br>
        <small>${truncateText(metadata.finalUrl, 50)}</small>
      </div>
      ` : ''}
      <div class="result-item">
        <span class="result-label">Hostname:</span> ${metadata.hostname}
      </div>
      ${metadata.redirectDepth > 0 ? `
      <div class="result-item">
        <span class="result-label">🔄 Redirects:</span> ${metadata.redirectDepth}
      </div>
      ` : ''}
      <div class="result-item">
        <span class="result-label">IP Address:</span> ${metadata.network.ipAddress || 'N/A'}
      </div>
      <div class="result-item">
        <span class="result-label">Country:</span> ${formatLocationInfo(metadata)}
      </div>
      <div class="result-item">
        <span class="result-label">ASN:</span> ${metadata.network.asn || 'N/A'}
      </div>
      ${metadata.network.asOwner ? `
      <div class="result-item">
        <span class="result-label">AS Owner:</span> ${metadata.network.asOwner}
      </div>
      ` : ''}
      ${metadata.network.isp ? `
      <div class="result-item">
        <span class="result-label">ISP:</span> ${metadata.network.isp}
      </div>
      ` : ''}
      <div class="result-item">
        <span class="result-label">Domain Age:</span> ${domainAge}
      </div>
      ${metadata.domain.registrar ? `
      <div class="result-item">
        <span class="result-label">Registrar:</span> ${metadata.domain.registrar}
      </div>
      ` : ''}
      ${metadata.domain.creationDate ? `
      <div class="result-item">
        <span class="result-label">Created:</span> ${formatDate(metadata.domain.creationDate)}
      </div>
      ` : ''}
      ${metadata.domain.expirationDate ? `
      <div class="result-item">
        <span class="result-label">Expires:</span> ${formatDate(metadata.domain.expirationDate)}
      </div>
      ` : ''}

      <div class="result-item">
        <span class="result-label">Malicious:</span> 
        <span class="detection-count ${metadata.detectionStats.malicious > 0 ? 'detection-danger' : ''}">${metadata.detectionStats.malicious}</span>
        /${metadata.detectionStats.total} engines
      </div>
      <div class="result-item">
        <span class="result-label">Suspicious:</span> 
        <span class="detection-count ${metadata.detectionStats.suspicious > 2 ? 'detection-warning' : ''}">${metadata.detectionStats.suspicious}</span>
        /${metadata.detectionStats.total} engines
      </div>
      ${metadata.impersonatedBrand ? `
      <div class="result-item">
        <span class="result-label">⚠️ Impersonated Brand:</span> ${metadata.impersonatedBrand}
      </div>
      ` : ''}
      ${metadata.suspiciousFeatures && metadata.suspiciousFeatures.length > 0 ? `
      <div class="result-item">
        <span class="result-label">⚠️ Suspicious Features:</span><br>
        <small>${metadata.suspiciousFeatures.join(', ')}</small>
      </div>
      ` : ''}
      ${metadata.reputation !== undefined ? `
      <div class="result-item">
        <span class="result-label">Reputation Score:</span> ${metadata.reputation}
      </div>
      ` : ''}

      ${metadata.httpInfo.statusCode || metadata.httpInfo.contentType || metadata.httpInfo.serverInfo ? `
      ${metadata.httpInfo.statusCode ? `
      <div class="result-item">
        <span class="result-label">Status Code:</span> ${metadata.httpInfo.statusCode}
      </div>
      ` : ''}
      ${metadata.httpInfo.contentType ? `
      <div class="result-item">
        <span class="result-label">Content Type:</span> ${metadata.httpInfo.contentType}
      </div>
      ` : ''}
      ${metadata.httpInfo.serverInfo ? `
      <div class="result-item">
        <span class="result-label">Server:</span> ${metadata.httpInfo.serverInfo}
      </div>
      ` : ''}
      ${metadata.httpInfo.contentLength ? `
      <div class="result-item">
        <span class="result-label">Content Length:</span> ${formatBytes(metadata.httpInfo.contentLength)}
      </div>
      ` : ''}
      ` : ''}

      ${metadata.contentInfo.title || metadata.contentInfo.language || metadata.contentInfo.sha256 ? `
      ${metadata.contentInfo.title ? `
      <div class="result-item">
        <span class="result-label">Page Title:</span><br>
        <small>${truncateText(metadata.contentInfo.title, 60)}</small>
      </div>
      ` : ''}
      ${metadata.contentInfo.language ? `
      <div class="result-item">
        <span class="result-label">Language:</span> ${metadata.contentInfo.language}
      </div>
      ` : ''}
      ${metadata.contentInfo.sha256 ? `
      <div class="result-item">
        <span class="result-label">SHA256:</span><br>
        <small style="font-family: monospace;">${metadata.contentInfo.sha256}</small>
      </div>
      ` : ''}
      ${metadata.contentInfo.contentEntropy ? `
      <div class="result-item">
        <span class="result-label">Content Entropy:</span> ${metadata.contentInfo.contentEntropy.toFixed(2)}
      </div>
      ` : ''}
      ` : ''}

      ${(metadata.externalResources.linkedDomains?.length || 0) > 0 || 
      (metadata.externalResources.embeddedUrls?.length || 0) > 0 || 
      (metadata.externalResources.trackers?.length || 0) > 0 ? `
      ${metadata.externalResources.linkedDomains?.length ? `
      <div class="result-item">
        <span class="result-label">Linked Domains:</span> ${metadata.externalResources.linkedDomains.length}
      </div>
      ` : ''}
      ${metadata.externalResources.embeddedUrls?.length ? `
      <div class="result-item">
        <span class="result-label">Embedded URLs:</span> ${metadata.externalResources.embeddedUrls.length}
      </div>
      ` : ''}
      ${metadata.externalResources.trackers?.length ? `
      <div class="result-item">
        <span class="result-label">Trackers:</span> ${metadata.externalResources.trackers.length}
      </div>
      ` : ''}
    
      ` : ''}

      <div class="result-item">
        <span class="result-label">JavaScript Activity:</span> ${metadata.behaviorInfo.javascriptActivity ? 'Detected' : 'None'}
      </div>
      <div class="result-item">
        <span class="result-label">Suspicious Redirects:</span> ${metadata.behaviorInfo.suspiciousRedirects ? '⚠️ Yes' : 'No'}
      </div>
      <div class="result-item">
        <span class="result-label">Data URI Usage:</span> ${metadata.behaviorInfo.dataUriUsage ? '⚠️ Detected' : 'None'}
      </div>

      <div class="result-item">
        <span class="result-label">Scan Date:</span> ${formatDate(metadata.scanDate)}
      </div>
      ${metadata.passiveDns?.firstSeen ? `
      <div class="result-item">
        <span class="result-label">First Seen:</span> ${formatDate(metadata.passiveDns.firstSeen)}
      </div>
      ` : ''}
      ${metadata.scanId ? `
      <div class="result-item">
        <span class="result-label">Scan ID:</span><br>
        <small style="font-family: monospace;">${metadata.scanId}</small>
      </div>
      ` : ''}
    </div>
  `;
  
  results.style.display = 'block';
}

// Helper Functions
function getThreatLevel(metadata: VTURLMetadata): string {
  const { malicious, suspicious } = metadata.detectionStats;
  
  if (malicious > 0) {
    return 'Dangerous';
  } else if (suspicious > 2) {
    return 'Suspicious';
  } else if (suspicious > 0 || metadata.suspiciousFeatures?.length) {
    return 'Low Risk';
  } else {
    return 'Safe';
  }
}

function getThreatIcon(threatLevel: string): string {
  switch (threatLevel) {
    case 'Dangerous': return '🚨';
    case 'Suspicious': return '⚠️';
    case 'Low Risk': return '⚡';
    case 'Safe': return '✅';
    default: return '❓';
  }
}

function formatLocationInfo(metadata: VTURLMetadata): string {
  const parts = [];
  if (metadata.network.city) parts.push(metadata.network.city);
  if (metadata.network.country) parts.push(metadata.network.country);
  return parts.length > 0 ? parts.join(', ') : 'N/A';
}

function formatDate(dateString: string): string {
  try {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  } catch {
    return dateString;
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showStatus(message: string, type: 'success' | 'error' | 'info'): void {
  status.textContent = message;
  status.className = type;
  status.style.display = 'block';
  
  if (type === 'success') {
    setTimeout(() => {
      status.style.display = 'none';
    }, 4000);
  }
}

function showLoader(show: boolean): void {
  loader.style.display = show ? 'block' : 'none';
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
  return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

// Storage Functions
async function saveApiKey(apiKey: string): Promise<void> {
  await chrome.storage.local.set({ virusTotalApiKey: apiKey });
}

async function loadApiKey(): Promise<string | null> {
  const result = await chrome.storage.local.get('virusTotalApiKey');
  return result.virusTotalApiKey || null;
}

async function saveResults(results: VTURLMetadata[]): Promise<void> {
  // Keep only the last 50 results to avoid storage issues
  const trimmedResults = results.slice(-50);
  await chrome.storage.local.set({ scanResults: trimmedResults });
}

async function loadResults(): Promise<VTURLMetadata[]> {
  const result = await chrome.storage.local.get('scanResults');
  return result.scanResults || [];
}