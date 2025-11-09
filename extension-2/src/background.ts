import { BEARER_TOKEN } from "../token";

export interface ClassificationRequest {
  action: "process_file_content";
  prompt: string;
}

export interface ClassificationResponse {
  success: boolean;
  result?: string;
  error?: string;
}

// Listen for messages from the extension's UI
chrome.runtime.onMessage.addListener(
  (
    request: ClassificationRequest,
    sender,
    sendResponse: (response: ClassificationResponse) => void
  ) => {
    if (request.action === "process_file_content") {
      const promptText = request.prompt;

      // Since fetch is async, we must return true to keep the channel open
      (async () => {
        try {
          // *** MODEL CONFIGURATION ***
          // Values extracted from your Vertex AI console screenshot
          const PROJECT_ID = "redirectguard-477115";
          const REGION = "us-central1";
          const MODEL_NAME = "gemini-2.5-flash";
          const apiUrl = `https://${REGION}-aiplatform.googleapis.com/v1/projects/${PROJECT_ID}/locations/${REGION}/publishers/google/models/${MODEL_NAME}:generateContent`;

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
              Authorization: `Bearer ${BEARER_TOKEN}`,
            },
            body: JSON.stringify(requestBody),
          });

          if (!response.ok) {
            // Check if content-type is JSON before parsing.
            const contentType = response.headers.get("content-type");
            let errorDetail = `Status: ${response.status}`;

            if (contentType && contentType.includes("application/json")) {
              // If it looks like JSON, attempt to parse it
              const errorData = await response.json();
              errorDetail = `Status: ${response.status} - ${JSON.stringify(
                errorData
              )}`;
            } else {
              // If it's not JSON, read it as plain text
              const errorText = await response.text();
              errorDetail = `Status: ${
                response.status
              } - Body: ${errorText.substring(0, 200)}...`; // Limit length for logs
            }

            throw new Error(`Vertex AI API error: ${errorDetail}`);
          }

          const data = await response.json();

          // The response typically returns content in data.candidates[0].content.parts[0].text
          const generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text;

          if (!generatedText) {
            throw new Error(
              "Gemini response was valid but contained no generated text."
            );
          }

          sendResponse({ success: true, result: generatedText.trim() });
        } catch (error) {
          console.error("Vertex AI Call failed:", error);
          sendResponse({
            success: false,
            error: error instanceof Error ? error.message : "Unknown error",
          });
        }
      })();

      return true; // Keep the message channel open
    }
  }
);
