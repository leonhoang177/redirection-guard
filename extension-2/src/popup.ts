import { ClassificationRequest, ClassificationResponse } from "./background";

const PROMPT: string =
  "INSTRUCT: Cyber Security Analyst. Classify: 'phish' or 'legit'.::EXP: null=failed to read. isHttps=URL secure. entropy=avg randomness. similarity=avg text match. dnsRatio=age/count. faviconMatch=favicon URL match host. tlsSubjectMatch=TLS subject match host.::HINTS: Higher reputation: more % legit. maliciousVotes>0: 100% phish. domainValidDays<366: 75% phish. isHttps=false: 75% phish. suspiciousVotes>0: 75% phish. nullCount>=10: 75% phish::DATA: url=https://aide-fr-domicile.com/ | urlEntropy=4.0473 | hostname=aide-fr-domicile.com | isHttps=true | title=Just a moment... | faviconMatch=true | charset=UTF-8 | MIMEType=text/html | reputation=0 | maliciousVotes=0 | suspiciousVotes=1 | services=null | features=external-resources | redirectCount=1 | redirectEntropy=4.0473 | redirectSimilarity=-1 | dnsRatio=0.5 | domainAge=null | domainValidDays=null | networkAsOwner=CLOUDFLARENET | networkCountry=US | statusCode=403 | serverName=cloudflare | contentSecurityPolicyCount=null | strictTransportSecurity=null | xFrameOptions=SAMEORIGIN | xContentTypeOptions=nosniff | cacheControl=private;max-age=0;no-store;no-cache;must-revalidate;post-check=0;pre-check=0 | tlsSubjectMatch=true | tlsValidDays=89 | tlsSANCount=2 | tlsSANEntropy=3.5455 | tlsSANSimilarity=0.9091 | embeddedURLCount=0 | embeddedURLEntropy=-1 | embeddedURLSimilarity=-1 | embeddedTrackersCount=null | nullCount=6 CLASSIFICATION:";

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
