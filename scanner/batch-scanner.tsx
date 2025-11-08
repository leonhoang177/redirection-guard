import fs from "fs";
import { pathToFileURL } from "url";
import {
  scanUrl,
  ScanResult,
  WAITLIST_CSV_PATH,
  ERROR_CSV_PATH,
  appendToWaitlist,
  formatInstructionPrompt,
  readInstructionText,
  DEFAULT_INSTRUCTION_PATH,
} from "./single-scanner";

const INPUT_PATH = "./inputs/input.csv";
const OUTPUT_DIR = "./outputs";

type InputRecord = {
  order: string;
  url: string;
  label: string;
};

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

function sanitizeForFilename(value: string): string {
  const safe = value.replace(/[^a-zA-Z0-9-_]/g, "_");
  return safe.length > 0 ? safe : "unknown";
}

function buildOutputPath(firstOrder?: string, lastOrder?: string): string {
  if (!firstOrder || !lastOrder) {
    return `${OUTPUT_DIR}/unknown-unknown.jsonl`;
  }
  const first = sanitizeForFilename(firstOrder);
  const last = sanitizeForFilename(lastOrder);
  return `${OUTPUT_DIR}/${first}-${last}.jsonl`;
}

function resetOutputFiles(outputPath: string) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  fs.writeFileSync(outputPath, "", "utf-8");
  for (const logPath of [WAITLIST_CSV_PATH, ERROR_CSV_PATH]) {
    try {
      if (fs.existsSync(logPath)) {
        fs.unlinkSync(logPath);
      }
    } catch (err: any) {
      console.error(`Failed to reset ${logPath}:`, err?.message || String(err));
    }
  }
}

function getColumnIndex(header: string[], candidates: string[]): number {
  for (const candidate of candidates) {
    const idx = header.findIndex((cell) => cell === candidate);
    if (idx !== -1) return idx;
  }
  return -1;
}

function parseCsvRecords(raw: string, sourceLabel: string): InputRecord[] {
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length <= 1) return [];

  const header = parseDelimitedLine(lines[0].replace(/^\uFEFF/, ""));
  const normalized = header.map((cell) => cell.trim().toLowerCase());
  const urlIndex = getColumnIndex(normalized, ["url", "link"]);
  const labelIndex = getColumnIndex(normalized, ["label"]);
  if (urlIndex === -1 || labelIndex === -1) {
    throw new Error(
      `[${sourceLabel}] Input CSV must contain 'Url' and 'Label' columns.`
    );
  }
  const orderIndex = getColumnIndex(normalized, ["order", "id"]);

  const records: InputRecord[] = [];
  for (let lineIndex = 1; lineIndex < lines.length; lineIndex++) {
    const rawLine = lines[lineIndex];
    if (!rawLine || !rawLine.trim()) continue;
    const fields = parseDelimitedLine(rawLine);
    const url = (fields[urlIndex] ?? "").trim();
    if (!url) {
      console.error(`[${sourceLabel}] Skipping row ${lineIndex}: missing URL.`);
      continue;
    }
    const label = (fields[labelIndex] ?? "").trim();
    const fallbackOrder = String(records.length + 1);
    const orderValue =
      orderIndex !== -1 && fields[orderIndex]
        ? fields[orderIndex].trim() || fallbackOrder
        : fallbackOrder;

    records.push({
      order: orderValue,
      url,
      label,
    });
  }

  return records;
}

function readInputRecords(filePath: string): InputRecord[] {
  try {
    const input = fs.readFileSync(filePath, "utf-8");
    return parseCsvRecords(input, "input");
  } catch (err: any) {
    throw new Error(
      `Failed to read ${filePath}: ${err?.message || String(err)}`
    );
  }
}

function drainWaitlistRecords(): InputRecord[] {
  if (!fs.existsSync(WAITLIST_CSV_PATH)) return [];

  try {
    const raw = fs.readFileSync(WAITLIST_CSV_PATH, "utf-8");
    const records = parseCsvRecords(raw, "waitlist");
    try {
      fs.unlinkSync(WAITLIST_CSV_PATH);
    } catch (err: any) {
      console.error(
        `Failed to clear ${WAITLIST_CSV_PATH}:`,
        err?.message || String(err)
      );
    }
    return records;
  } catch (err: any) {
    console.error(
      `Failed to read ${WAITLIST_CSV_PATH}:`,
      err?.message || String(err)
    );
    return [];
  }
}

function appendRecordToWaitlist(record: InputRecord, note?: string) {
  appendToWaitlist(record.url, note, {
    order: record.order,
    label: record.label,
    rawUrl: record.url,
  });
}

function appendRemainingRecordsToWaitlist(
  records: InputRecord[],
  startIndex: number,
  note?: string
) {
  for (let i = startIndex; i < records.length; i++) {
    appendRecordToWaitlist(records[i], note);
  }
}

function isQuotaOrForbiddenError(message: string): boolean {
  if (!message) return false;
  const normalized = message.toLowerCase();
  return (
    normalized.includes("quota") ||
    normalized.includes("forbidden") ||
    normalized.includes("rate limit") ||
    normalized.includes("too many requests") ||
    normalized.includes("429")
  );
}

async function processRecords(
  records: InputRecord[],
  instruction: string,
  outputPath: string
): Promise<{ quotaHit: boolean }> {
  for (let index = 0; index < records.length; index++) {
    const record = records[index];
    console.log(`\n=== Processing ID ${record.order} ===`);

    try {
      const result: ScanResult = await scanUrl(record.url, {
        order: record.order,
        label: record.label,
        rawUrl: record.url,
        logId: `ID ${record.order}`,
        disableAutomaticWaitlist: true,
      });

      if (result.status === "success") {
        const inputText = formatInstructionPrompt(result.data, instruction);
        if (inputText === null) {
          console.log(
            `Skipped ID ${record.order}: no valid instruction provided.`
          );
          continue;
        }

        const outputRecord = {
          contents: [
            { role: "user", parts: [{ text: inputText }] },
            { role: "model", parts: [{ text: record.label ?? "" }] },
          ],
        };

        fs.appendFileSync(
          outputPath,
          `${JSON.stringify(outputRecord)}\n`,
          "utf-8"
        );
        console.log(`Saved result for ID ${record.order}`);
      } else if (result.status === "waitlist") {
        appendRecordToWaitlist(record, result.note);
        console.log(`ID ${record.order} added to waitlist.`);
      } else {
        console.error(`Error scanning ID ${record.order}: ${result.error}`);
        if (isQuotaOrForbiddenError(result.error)) {
          appendRecordToWaitlist(record, "pending (quota)");
          appendRemainingRecordsToWaitlist(
            records,
            index + 1,
            "pending (quota)"
          );
          return { quotaHit: true };
        }
      }
    } catch (err: any) {
      const message = err?.message || String(err);
      console.error(`Unexpected failure for ID ${record.order}: ${message}`);
      if (isQuotaOrForbiddenError(message)) {
        appendRecordToWaitlist(record, "pending (quota)");
        appendRemainingRecordsToWaitlist(records, index + 1, "pending (quota)");
        return { quotaHit: true };
      }
    }
  }

  return { quotaHit: false };
}

async function runBatch() {
  const instruction = readInstructionText();

  let currentRecords: InputRecord[];
  try {
    currentRecords = readInputRecords(INPUT_PATH);
  } catch (err: any) {
    console.error(err?.message || String(err));
    process.exitCode = 1;
    return;
  }

  if (currentRecords.length === 0) {
    console.log("No data rows found in CSV. Nothing to do.");
    return;
  }

  const firstOrder = currentRecords[0]?.order;
  const lastOrder = currentRecords[currentRecords.length - 1]?.order;
  const outputPath = buildOutputPath(firstOrder, lastOrder);
  resetOutputFiles(outputPath);

  let iteration = 1;
  while (currentRecords.length > 0) {
    console.log(
      `\n--- Batch iteration ${iteration} (${currentRecords.length} URLs) ---`
    );
    const { quotaHit } = await processRecords(
      currentRecords,
      instruction,
      outputPath
    );
    if (quotaHit) {
      console.warn(
        "Stopping batch scanning because of quota or unexpected error. Waitlist preserved for retry."
      );
      return;
    }

    const nextRecords = drainWaitlistRecords();
    if (nextRecords.length === 0) {
      console.log("Waitlist empty. Batch scanning complete.");
      break;
    }

    currentRecords = nextRecords;
    iteration++;
    console.log(
      `Waitlist contains ${currentRecords.length} URLs. Starting next pass.`
    );
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
