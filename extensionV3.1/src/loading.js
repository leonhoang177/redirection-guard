// Parse URL parameters
const params = new URLSearchParams(window.location.search);
const scannedUrl = params.get('url') || 'Unknown URL';

// Display the URL being scanned
document.getElementById('urlDisplay').textContent = scannedUrl;

// Show redirect information if available
// if (originalUrl && originalUrl !== scannedUrl) {
//   const redirectInfo = document.getElementById('redirectInfo');
//   const redirectFrom = document.getElementById('redirectFrom');
//   const redirectTo = document.getElementById('redirectTo');
  
//   redirectTo.textContent = scannedUrl;
//   redirectInfo.style.display = 'block';
// }

// Add some dynamic status updates for better user experience
const statusMessages = [
  "Doing all of the hard stuff",
  "Asking Chat GPT what my name is",
  "There are seven 'R's in Strawberry", 
  "Watching Dr. Marz dance and break tables",
  "Asking Dr. Routi about buffer overflows",
  "Reading Dr. Kim's research papers"
];

let messageIndex = 0;
const statusText = document.querySelector('.status-text');

const statusInterval = setInterval(() => {
  messageIndex = (messageIndex + 1) % statusMessages.length;
  statusText.innerHTML = statusMessages[messageIndex] + '<span class="progress-dots"></span>';
}, 2000);

// Get current tab ID
let currentTabId;
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0]) {
    currentTabId = tabs[0].id;
  }
});

// Handle Safe button
document.getElementById('safeBtn').addEventListener('click', () => {
  console.log('✅ User marked redirect as SAFE');
  
  // Stop status updates
  clearInterval(statusInterval);
  
  // Send "safe" verdict to background script
  chrome.runtime.sendMessage({
    type: "analysisResult",
    url: scannedUrl,
    tabId: currentTabId,
    verdict: "safe"
  });

  // Update UI
  document.querySelector('.container').innerHTML = `
    <div class="icon">✅</div>
    <h1 style="color: #155724;">Proceeding Safely</h1>
    <div class="message">Redirecting to the destination now...</div>
    <div class="spinner"></div>
  `;
});

// Handle Unsafe button
document.getElementById('unsafeBtn').addEventListener('click', () => {
  console.log('🚨 User marked redirect as UNSAFE');
  
  // Stop status updates
  clearInterval(statusInterval);
  
  // Send "malicious" verdict to background script
  chrome.runtime.sendMessage({
    type: "analysisResult",
    url: scannedUrl,
    tabId: currentTabId,
    verdict: "malicious"
  });

  // Update UI
  document.querySelector('.container').innerHTML = `
    <div class="icon">🚨</div>
    <h1 style="color: #721c24;">Blocking Redirect</h1>
    <div class="message">Showing warning page...</div>
    <div class="spinner"></div>
  `;
});

// Listen for external analysis results
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "analysisComplete") {
    clearInterval(statusInterval);
    const verdict = message.verdict;
    
    if (verdict === "safe") {
      document.querySelector('.container').innerHTML = `
        <div class="icon">✅</div>
        <h1 style="color: #155724;">Safe to Proceed</h1>
        <div class="message">Redirecting now...</div>
        <div class="spinner"></div>
      `;
    } else {
      document.querySelector('.container').innerHTML = `
        <div class="icon">⚠️</div>
        <h1 style="color: #856404;">Suspicious Activity Detected</h1>
        <div class="message">Showing warning page...</div>
        <div class="spinner"></div>
      `;
    }
  }
});