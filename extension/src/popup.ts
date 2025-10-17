import { VirusTotalService, convertToCSV, downloadCSV } from './virusTotalService.js';
import { VTURLMetadata } from './types';

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
    showStatus('API Key loaded!', 'success');
  }

  // Load saved results
  const savedResults = await loadResults();
  if (savedResults && savedResults.length > 0) {
    scanResults = savedResults;
    exportBtn.style.display = 'block';
  }
});

// Save API Key
saveApiKeyBtn.addEventListener('click', async () => {
  const apiKey = apiKeyInput.value.trim();
  
  if (!apiKey) {
    showStatus('Please enter an API key', 'error');
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
    showStatus('Please enter a valid URL', 'error');
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
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  downloadCSV(csv, `phishing_scan_${timestamp}.csv`);
  showStatus('CSV exported successfully!', 'success');
});

// Scan URL Function
async function scanUrl(url: string): Promise<void> {
  showLoader(true);
  showStatus('Scanning URL... This may take a few seconds.', 'info');
  results.style.display = 'none';

  try {
    const metadata = await vtService!.scanURL(url);
    scanResults.push(metadata);
    
    // Save results
    await saveResults(scanResults);
    
    // Display results
    displayResults(metadata);
    showStatus('Scan completed!', 'success');
    exportBtn.style.display = 'block';
  } catch (error: any) {
    showStatus(`Error: ${error.message}`, 'error');
    console.error('Scan error:', error);
  } finally {
    showLoader(false);
  }
}

// Display Results
function displayResults(metadata: VTURLMetadata): void {
  const threatLevel = getThreatLevel(metadata);
  const threatClass = 
    threatLevel === 'Safe' ? 'threat-safe' :
    threatLevel === 'Suspicious' ? 'threat-warning' : 'threat-danger';

  results.innerHTML = `
    <div class="result-item">
      <span class="result-label">URL:</span> ${truncateText(metadata.url, 40)}
    </div>
    <div class="result-item">
      <span class="result-label">Hostname:</span> ${metadata.hostname}
    </div>
    <div class="result-item">
      <span class="result-label">IP Address:</span> ${metadata.ipAddress || 'N/A'}
    </div>
    <div class="result-item">
      <span class="result-label">Country:</span> ${metadata.country || 'N/A'}
    </div>
    <div class="result-item">
      <span class="result-label">ASN:</span> ${metadata.asn || 'N/A'}
    </div>
    <div class="result-item">
      <span class="result-label">Malicious Detections:</span> ${metadata.detectionStats.malicious}/${metadata.detectionStats.total}
    </div>
    <div class="result-item">
      <span class="result-label">Suspicious Detections:</span> ${metadata.detectionStats.suspicious}/${metadata.detectionStats.total}
    </div>
    ${metadata.impersonatedBrand ? `
    <div class="result-item">
      <span class="result-label">⚠️ Impersonated Brand:</span> ${metadata.impersonatedBrand}
    </div>
    ` : ''}
    ${metadata.redirectChain && metadata.redirectChain.length > 1 ? `
    <div class="result-item">
      <span class="result-label">🔄 Redirects:</span> ${metadata.redirectChain.length - 1}
    </div>
    ` : ''}
    <div class="threat-level ${threatClass}">
      ${threatLevel}
    </div>
  `;
  
  results.style.display = 'block';
}

// Get Threat Level
function getThreatLevel(metadata: VTURLMetadata): string {
  const { malicious, suspicious } = metadata.detectionStats;
  
  if (malicious > 0) {
    return 'Dangerous';
  } else if (suspicious > 2) {
    return 'Suspicious';
  } else {
    return 'Safe';
  }
}

// Show Status
function showStatus(message: string, type: 'success' | 'error' | 'info'): void {
  status.textContent = message;
  status.className = type;
  status.style.display = 'block';
  
  if (type === 'success') {
    setTimeout(() => {
      status.style.display = 'none';
    }, 3000);
  }
}

// Show/Hide Loader
function showLoader(show: boolean): void {
  loader.style.display = show ? 'block' : 'none';
  scanBtn.disabled = show;
  scanCurrentBtn.disabled = show;
}

// Validate URL
function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

// Truncate Text
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
  await chrome.storage.local.set({ scanResults: results });
}

async function loadResults(): Promise<VTURLMetadata[]> {
  const result = await chrome.storage.local.get('scanResults');
  return result.scanResults || [];
}