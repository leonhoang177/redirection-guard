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
  if (verdict === 'malicious') {
    verdictBadge.textContent = '🚨 MALICIOUS';
    verdictBadge.className = 'verdict-badge verdict-malicious';
  } else if (verdict === 'suspicious') {
    verdictBadge.textContent = '⚠️ SUSPICIOUS';
    verdictBadge.className = 'verdict-badge verdict-suspicious';
  } else {
    verdictBadge.textContent = '❓ UNKNOWN';
    verdictBadge.className = 'verdict-badge verdict-unknown';
  }

  // Update warning reasons based on verdict
  const reasons = document.getElementById('warningReasons');
  if (verdict === 'malicious') {
    reasons.innerHTML = `
      <li>Multiple security engines flagged this as MALICIOUS</li>
      <li>This site is known for phishing or malware distribution</li>
      <li>Proceeding will expose you to significant security risks</li>
    `;
  } else if (verdict === 'suspicious') {
    reasons.innerHTML = `
      <li>Some security engines flagged this as suspicious</li>
      <li>The redirect pattern exhibits unusual behavior</li>
      <li>Exercise extreme caution if you proceed</li>
    `;
  } else {
    reasons.innerHTML = `
      <li>This URL has not been analyzed yet</li>
      <li>We cannot verify if this redirect is safe</li>
      <li>The destination may pose unknown risks</li>
    `;
  }

  function goBack() {
    // Try to go back in history, or close tab if possible
    if (window.history.length > 1) {
      window.history.back();
    } else {
      // If no history, try to navigate to a safe page
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

Type "PROCEED" to confirm:`;

    const userConfirmation = prompt(confirmMessage);
    
    if (userConfirmation === "PROCEED") {
      try {
        // Get current tab ID
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        // Send message to background to allow the URL
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