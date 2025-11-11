chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "process_file_content") {
        const promptText = request.prompt;
        (async () => {
            try {
                const token = await new Promise((resolve, reject) => {
                    chrome.identity.getAuthToken({ interactive: true }, (tokenCallbackParam) => {
                        // Renamed parameter to avoid potential shadowing/clarity
                        if (chrome.runtime.lastError) {
                            reject(new Error(`Failed to get auth token: ${chrome.runtime.lastError.message}`));
                        }
                        else if (!tokenCallbackParam) {
                            // If token is null or undefined
                            reject(new Error("Failed to get auth token: Token is null or undefined."));
                        }
                        else {
                            // At this point, we've checked that tokenCallbackParam is not undefined.
                            // We use a type assertion to tell TypeScript it's a string.
                            resolve(tokenCallbackParam);
                        }
                    });
                });
                // *** MODEL CONFIGURATION ***
                const PROJECT_ID = "redirectguard-477115";
                const REGION = "us-central1";
                const ENDPOINT_ID = "1210737124530192384	";
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
                        Authorization: `Bearer ${token}`, // Use the dynamically obtained token
                    },
                    body: JSON.stringify(requestBody),
                });
                if (!response.ok) {
                    const contentType = response.headers.get("content-type");
                    let errorDetail = `Status: ${response.status}`;
                    if (contentType && contentType.includes("application/json")) {
                        const errorData = await response.json();
                        errorDetail = `Status: ${response.status} - ${JSON.stringify(errorData)}`;
                    }
                    else {
                        const errorText = await response.text();
                        errorDetail = `Status: ${response.status} - Body: ${errorText.substring(0, 200)}...`;
                    }
                    throw new Error(`Vertex AI API error: ${errorDetail}`);
                }
                const data = await response.json();
                const generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text;
                if (!generatedText) {
                    throw new Error("Gemini response was valid but contained no generated text.");
                }
                sendResponse({ success: true, result: generatedText.trim() });
            }
            catch (error) {
                console.error("Vertex AI Call failed:", error);
                sendResponse({
                    success: false,
                    error: error instanceof Error ? error.message : "Unknown error",
                });
            }
        })();
        return true;
    }
});
export {};
