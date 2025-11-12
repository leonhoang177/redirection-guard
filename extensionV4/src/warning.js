  // Parse URL parameters
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url') || 'Unknown URL';
  const verdict = params.get('verdict') || 'unknown';
  const originalUrl = params.get('from');

  // Display the blocked URL
  document.getElementById('urlDisplay').textContent = blockedUrl;

  // Show redirect information if available
  if (originalUrl && originalUrl !== blockedUrl) {
    const redirectInfo = document.getElementById('redirectInfo');
    const redirectChain = document.getElementById('redirectChain');
    
    redirectChain.innerHTML = `
      <div class="redirect-chain">
        ${originalUrl}
      </div>
      <div class="redirect-arrow">↓ REDIRECTED TO</div>
      <div class="redirect-chain">
        ${blockedUrl}
      </div>
    `;
    
    redirectInfo.style.display = 'block';
  }

  // Update verdict badge
  const verdictBadge = document.getElementById('verdictBadge');
  if (verdict === 'phish') {
    verdictBadge.textContent = '🚨 MALICIOUS';
    verdictBadge.className = 'verdict-badge verdict-phish';
  } else if (verdict === 'legit') {
    verdictBadge.textContent = ':3 legit';
    verdictBadge.className = 'verdict-badge verdict-legit';
  } else {
    verdictBadge.textContent = '❓ UNKNOWN';
    verdictBadge.className = 'verdict-badge verdict-unknown';
  }

  // Update warning reasons based on verdict
  const reasons = document.getElementById('warningReasons');
  reasons.innerHTML = `
    <li>Multiple security engines flagged this as MALICIOUS</li>
    <li>This site is known for phishing or malware distribution</li>
    <li>Proceeding will expose you to significant security risks</li>
  `;

  function goToGoogle() {
    window.location.href = 'https://www.google.com';
  }

  function goBack() {
    // Check if history is long enough to contain the Original Site (N-2), 
    // the Loading Page (N-1), and the Warning Page (N).
    // A length of 3 or more allows a safe jump back of 2.
    if (window.history.length > 3) {
      // Go back two steps to skip the loading.html page
      window.history.go(-3);
    } else {
      // If history is too short (length is 1 or 2), 
      // we cannot reliably go back 2 steps. Navigate to a safe default page instead.
      window.location.href = 'https://www.google.com';
    }
  }

async function proceedAnyway() {
  const confirmMessage = `⚠️ Security Warning ⚠️

Are you absolutely sure you want to visit this potentially dangerous site?

URL: ${blockedUrl}
Threat Level: ${verdict.toUpperCase()}

This action may expose you to:
• Phishing attacks
• Malware downloads  
• Identity theft
• Data compromise

Click "OK" to proceed or "Cancel" to go back to safety.`;

  const userConfirmed = confirm(confirmMessage);
  
  if (userConfirmed) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      chrome.runtime.sendMessage({
        type: 'allowUrl',
        url: blockedUrl,
        tabId: tab.id
      });
    } catch (error) {
      console.error('Error allowing URL:', error);

      // Fallback: direct navigation
      window.location.href = blockedUrl;
    }
  }
}


  document.addEventListener('DOMContentLoaded', () => {
    
    // 1. Attach the goBack function to the return button
    const returnButton = document.getElementById('returnButton');
    if (returnButton) {
      // Note: ensure your goBack function is the updated one that uses go(-2)
      returnButton.addEventListener('click', goBack); 
    } else {
      console.error("CSP Fix: Return button element (#returnButton) not found.");
    }

    // 2. Attach the proceedAnyway function to the continue button
    const continueButton = document.getElementById('continueButton');
    if (continueButton) {
      continueButton.addEventListener('click', proceedAnyway);
    } else {
      console.error("CSP Fix: Continue button element (#continueButton) not found.");
    }
    
    // 3. Attach the goToGoogle function to the new Google button
    const googleBtn = document.getElementById('googleBtn');
    if (googleBtn) {
      googleBtn.addEventListener('click', goToGoogle);
    } else {
      console.error("CSP Fix: Google button element (#googleBtn) not found.");
    }
  });