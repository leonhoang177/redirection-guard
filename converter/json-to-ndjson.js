// convert.js (CommonJS)
const fs = require("fs");

const inputFile = "./inputs/openphish_30_days.json";
const outputFile = "./outputs/openphish_30_days.ndjson";

const data = JSON.parse(fs.readFileSync(inputFile, "utf8"));
const stream = fs.createWriteStream(outputFile, { flags: "w" });

for (const obj of data) {
  stream.write(JSON.stringify(obj) + "\n");
}

stream.end(() =>
  console.log(`✅ Converted ${data.length} objects to ${outputFile}`)
);
