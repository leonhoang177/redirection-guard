import fs from "fs";

const inputPath = "./inputs/test_05.jsonl"; // old format
const outputPath = "./outputs/test_05.jsonl"; // new Gemini format

const inputLines = fs
  .readFileSync(inputPath, "utf-8")
  .split(/\r?\n/)
  .filter(Boolean);

const outputLines = [];

for (const line of inputLines) {
  try {
    const data = JSON.parse(line);
    const { prompt, completion } = data;

    const formatted = {
      contents: [
        {
          role: "user",
          parts: [{ text: prompt.trim() }],
        },
        {
          role: "model",
          parts: [{ text: completion.trim() }],
        },
      ],
    };

    outputLines.push(JSON.stringify(formatted));
  } catch (err) {
    console.error("❌ Failed to parse line:", err.message);
  }
}

fs.writeFileSync(outputPath, outputLines.join("\n"), "utf-8");
console.log(`✅ Converted ${outputLines.length} entries → ${outputPath}`);
