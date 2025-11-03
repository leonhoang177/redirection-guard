import fs from "fs";
import { pathToFileURL } from "url";
import { scanUrl } from "./single-scanner";

const INPUT_PATH = "./inputs/input.txt";
const OUTPUT_PATH = "./outputs/output.ndjson";

async function runBatch() {
  let input: string;
  try {
    input = fs.readFileSync(INPUT_PATH, "utf-8");
  } catch (err: any) {
    console.error(
      `Failed to read ${INPUT_PATH}:`,
      err?.message || String(err)
    );
    process.exitCode = 1;
    return;
  }

  const urls = input
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (urls.length === 0) {
    console.log("No URLs found in input.txt. Nothing to do.");
    return;
  }

  fs.writeFileSync(OUTPUT_PATH, "", "utf-8");

  for (const url of urls) {
    console.log(`\n=== Processing ${url} ===`);
    try {
      const result = await scanUrl(url);
      if (result) {
        fs.appendFileSync(
          OUTPUT_PATH,
          `${JSON.stringify(result)}\n`,
          "utf-8"
        );
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
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url;

if (isMainModule) {
  runBatch().catch((err) => {
    console.error("Batch scanner failed:", err?.message || err);
    process.exit(1);
  });
}

export { runBatch };
