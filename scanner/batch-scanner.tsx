import fs from "fs";
import { pathToFileURL } from "url";
import { scanUrl } from "./single-scanner";

const INPUT_PATH = "./inputs/mixed_urls_10.csv";
const OUTPUT_PATH = "./outputs/output.jsonl";

function parseDelimitedLine(line: string): string[] {
  const cells: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (!inQuotes && (ch === "," || ch === "\t")) {
      cells.push(current.trim());
      current = "";
    } else {
      current += ch;
    }
  }
  cells.push(current.trim());
  return cells;
}

function formatInputText(flattened: Record<string, any>): string {
  const entries = Object.entries(flattened);
  const parts = entries.map(([key, value]) => {
    if (value === null) return `${key}=null`;
    if (typeof value === "string") return `${key}=${value}`;
    if (typeof value === "number" || typeof value === "boolean")
      return `${key}=${value}`;
    return `${key}=${JSON.stringify(value)}`;
  });
  return parts.join(" | ");
}

async function runBatch() {
  let input: string;
  try {
    input = fs.readFileSync(INPUT_PATH, "utf-8");
  } catch (err: any) {
    console.error(`Failed to read ${INPUT_PATH}:`, err?.message || String(err));
    process.exitCode = 1;
    return;
  }

  const lines = input
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length <= 1) {
    console.log("No data rows found in file.csv. Nothing to do.");
    return;
  }

  const header = parseDelimitedLine(lines[0]);
  const urlIndex = header.findIndex(
    (h) => h.toLowerCase() === "url" || h.toLowerCase() === "link"
  );
  const labelIndex = header.findIndex((h) => h.toLowerCase() === "label");
  if (urlIndex === -1 || labelIndex === -1) {
    console.error("Input CSV must contain 'Url' and 'Label' columns.");
    process.exitCode = 1;
    return;
  }

  fs.writeFileSync(OUTPUT_PATH, "", "utf-8");

  for (let i = 1; i < lines.length; i++) {
    const rawLine = lines[i];
    if (!rawLine.trim()) continue;
    const fields = parseDelimitedLine(rawLine);
    const url = fields[urlIndex];
    const label = fields[labelIndex];
    if (!url) continue;

    console.log(`\n=== Processing ${url} ===`);
    try {
      const result = await scanUrl(url);
      if (result) {
        const record = {
          input_text: formatInputText(result),
          output_text: label ?? "",
        };
        fs.appendFileSync(OUTPUT_PATH, `${JSON.stringify(record)}\n`, "utf-8");
        console.log(`Saved result for ${url}`);
      } else {
        console.log(`No result generated for ${url} (likely waitlisted).`);
      }
    } catch (err: any) {
      console.error(`Error scanning ${url}:`, err?.message || String(err));
    }
  }
}

const isMainModule =
  process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;

if (isMainModule) {
  runBatch().catch((err) => {
    console.error("Batch scanner failed:", err?.message || err);
    process.exit(1);
  });
}

export { runBatch };
