import { ClassificationRequest, ClassificationResponse } from "./background";

const PROMPT: string =
  "INSTRUCT: Cyber Security Analyst. Classify: 'phish' or 'legit'.::EXP: null=failed to read. isHttps=URL secure. entropy=avg randomness. similarity=avg text match. dnsRatio=age/count. faviconMatch=favicon URL match host. tlsSubjectMatch=TLS subject match host.::HINTS: Higher reputation: more % legit. maliciousVotes>0: 100% phish. domainValidDays<366: 75% phish. isHttps=false: 75% phish. suspiciousVotes>0: 75% phish. nullCount>=10: 75% phish::DATA: url=https://www.apple.com/ | urlEntropy=3.6292 | hostname=www.apple.com | isHttps=true | title=Apple | faviconMatch=true | charset=utf-8 | MIMEType=text/html | reputation=119 | maliciousVotes=0 | suspiciousVotes=0 | services=information;technology;computersandsoftware | features=external-resources;iframes | redirectCount=1 | redirectEntropy=3.6292 | redirectSimilarity=-1 | dnsRatio=2.6 | domainAge=14142 | domainValidDays=103 | networkAsOwner=APPLE-ENGINEERING | networkCountry=US | statusCode=200 | serverName=Apple | contentSecurityPolicyCount=41 | strictTransportSecurity=max-age=31536000;includeSubdomains;preload | xFrameOptions=SAMEORIGIN | xContentTypeOptions=nosniff | cacheControl=max-age=0 | tlsSubjectMatch=true | tlsValidDays=39 | tlsSANCount=1 | tlsSANEntropy=2.9477 | tlsSANSimilarity=-1 | embeddedURLCount=1 | embeddedURLEntropy=3.7888 | embeddedURLSimilarity=-1 | embeddedTrackersCount=null | nullCount=1 CLASSIFICATION:";

const triggerButton = document.getElementById(
  "triggerButton"
) as HTMLButtonElement;
const statusDiv = document.getElementById("status") as HTMLDivElement;

triggerButton.addEventListener("click", () => {
  statusDiv.textContent = "Preparing hardcoded content for LLM...";
  triggerButton.disabled = true;

  chrome.runtime.sendMessage(
    {
      action: "process_file_content",
      prompt: PROMPT,
    },
    (response: ClassificationResponse) => {
      triggerButton.disabled = false;

      if (chrome.runtime.lastError) {
        statusDiv.textContent = `Error: ${chrome.runtime.lastError.message}`;
        return;
      }

      if (response && response.success) {
        statusDiv.textContent = "LLM Response:\n" + response.result;
      } else {
        statusDiv.textContent = `LLM Failure: ${
          response.error || "Unknown error"
        }`;
      }
    }
  );
});
