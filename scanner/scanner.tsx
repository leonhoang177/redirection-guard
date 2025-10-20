// scanner.ts — Single-file CLI (submit-if-needed + fetch) for VirusTotal URLs
// Node 18+ (built-in fetch). If on Node 16, install node-fetch@3 and import it.
// Optional: import your own VT types from "./types" if you want to enforce your shape.

import fs from "fs";

// ====== CONFIG ======
const API_KEY =
  "1d0b32a0630fc45fc0f7ef17c35421d2f56d961f97fcca7a9a135b4235268bf9";
const BASE = "https://www.virustotal.com/api/v3";
const HARDCODED_URL = "https://www.apple.com/"; // <--- change to your target
const POLL_INTERVAL_MS = 1500; // VT is rate-limited; be gentle
const POLL_TIMEOUT_MS = 60_000; // stop after 60s

if (!API_KEY) {
  console.error("❌ Missing VT_API_KEY env var.");
  process.exit(1);
}

// Encode plain URL → VT base64url (no padding)
function encodeVTUrl(u: string): string {
  return Buffer.from(u)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function vtGet(path: string) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "x-apikey": API_KEY },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GET ${path} -> ${res.status}: ${text}`);
  }
  return res.json();
}

async function vtPost(path: string, body: URLSearchParams) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "x-apikey": API_KEY,
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`POST ${path} -> ${res.status}: ${text}`);
  }
  return res.json();
}

async function getUrlReport(url: string) {
  const id = encodeVTUrl(url);
  try {
    const data = await vtGet(`/urls/${id}`);
    return data; // full VT payload
  } catch (err: any) {
    // 404 or other errors bubble up — caller decides to submit
    throw err;
  }
}

async function submitUrl(url: string) {
  const form = new URLSearchParams();
  form.set("url", url);
  const data = await vtPost("/urls", form);
  // { data: { id: "<analysis-id>", type: "analysis" } }
  return data?.data?.id as string | undefined;
}

function analysisDone(status: string | undefined) {
  // status: queued | in-progress | completed (and maybe "failed")
  return status === "completed" || status === "failed";
}

async function pollAnalysis(
  analysisId: string,
  timeoutMs: number,
  intervalMs: number
) {
  const start = Date.now();
  while (true) {
    const data = await vtGet(`/analyses/${analysisId}`);
    const status = data?.data?.attributes?.status as string | undefined;

    if (analysisDone(status)) {
      return data;
    }

    if (Date.now() - start > timeoutMs) {
      throw new Error("Timed out waiting for analysis to complete.");
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

function summarizeLastAnalysisResults(results: any) {
  const byCategory: Record<string, number> = {};
  const byResult: Record<string, number> = {};
  const byMethod: Record<string, number> = {};
  let totalEngines = 0;

  if (results && typeof results === "object") {
    for (const engine of Object.keys(results)) {
      const r = results[engine] || {};
      totalEngines++;
      const cat = r.category ?? "unknown";
      const res = r.result ?? "unknown";
      const meth = r.method ?? "unknown";
      byCategory[cat] = (byCategory[cat] ?? 0) + 1;
      byResult[res] = (byResult[res] ?? 0) + 1;
      byMethod[meth] = (byMethod[meth] ?? 0) + 1;
    }
  }

  return { totalEngines, byCategory, byResult, byMethod };
}

function extractUsefulUrlAttributes(vtUrlPayload: any) {
  // This shape follows VT docs for /urls/{id}. Adapt to your types.ts if needed.
  const attr = vtUrlPayload?.data?.attributes ?? {};
  const analysisSummary = summarizeLastAnalysisResults(
    attr.last_analysis_results
  );

  return {
    // core URL identity
    url: attr.url ?? vtUrlPayload?.data?.id, // sometimes VT stores normalized URL here
    lastFinalUrl: attr.last_final_url ?? null,
    timesSubmitted: attr.times_submitted ?? null,
    lastSubmissionDate: attr.last_submission_date ?? null,
    lastHttpResponseCode: attr.last_http_response_code ?? null,

    // page content hints
    title: attr.title ?? null,
    htmlMeta: attr.html_meta ?? null,

    // categorization / reputation
    categories: attr.categories ?? {},
    reputation: attr.reputation ?? 0,
    totalVotes: attr.total_votes ?? null, // { harmless, malicious }
    maliciousVotes: attr.total_votes?.malicious ?? 0,
    harmlessVotes: attr.total_votes?.harmless ?? 0,

    // analysis stats from vendors
    lastAnalysisStats: attr.last_analysis_stats ?? {}, // { harmless, malicious, suspicious, undetected, timeout }
    lastAnalysisSummary: analysisSummary,

    // timing
    firstSubmissionDate: attr.first_submission_date ?? null,
    lastModificationDate: attr.last_modification_date ?? null,
  };
}

async function run() {
  const cliArg = process.argv[2]; // optional CLI arg
  const target = cliArg || HARDCODED_URL;

  console.log(`🔎 VirusTotal URL scan for: ${target}`);

  let urlReport: any | null = null;

  // 1) Try to fetch an existing report
  try {
    urlReport = await getUrlReport(target);
  } catch (e: any) {
    // If no report exists, submit and poll
    console.log("ℹ️ No existing report found — submitting URL to VirusTotal…");
    const analysisId = await submitUrl(target);
    if (!analysisId) throw new Error("No analysis id returned by VT.");

    console.log(`⏳ Polling analysis: ${analysisId}`);
    await pollAnalysis(analysisId, POLL_TIMEOUT_MS, POLL_INTERVAL_MS);

    // After completion, fetch the URL report again
    urlReport = await getUrlReport(target);
  }

  // 2) Extract a concise, useful summary from VT payload
  const extracted = extractUsefulUrlAttributes(urlReport);

  const sanitizedRaw = JSON.parse(JSON.stringify(urlReport));
  if (sanitizedRaw?.data?.attributes?.last_analysis_results) {
    delete sanitizedRaw.data.attributes.last_analysis_results;
  }

  const output = {
    summary: extracted,
    raw: sanitizedRaw, // last_analysis_results removed to keep file compact
  };

  // 4) Write JSON to output.json file
  fs.writeFileSync("output.json", JSON.stringify(output, null, 2), "utf-8");
  console.log("✅ Output written to output.json");
}

run().catch((err) => {
  console.error("❌ Error:", err?.message || err);
  process.exit(1);
});
