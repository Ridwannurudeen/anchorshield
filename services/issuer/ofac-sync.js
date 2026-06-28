const fs = require("fs");
const path = require("path");
const { SDN_COLUMNS, parseLegacySdnCsv } = require("./lib/ofac");

const repo = path.resolve(__dirname, "..", "..");
const dataDir = path.join(__dirname, "data");
const sdnUrl = "https://www.treasury.gov/ofac/downloads/sdn.csv";
const sdnPath = path.join(dataDir, "sdn.csv");
const samplePath = path.join(dataDir, "sample-sdn.csv");

async function main() {
  fs.mkdirSync(dataDir, { recursive: true });

  const response = await fetch(sdnUrl);
  if (!response.ok) {
    throw new Error(`failed to fetch SDN.CSV: HTTP ${response.status}`);
  }

  const text = await response.text();
  const records = parseLegacySdnCsv(text);
  if (records.length === 0) {
    throw new Error("SDN.CSV contained no records");
  }

  const sample = text
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .slice(0, 6)
    .join("\n");

  fs.writeFileSync(sdnPath, text.endsWith("\n") ? text : `${text}\n`);
  fs.writeFileSync(samplePath, `${sample}\n`);

  console.log(
    JSON.stringify(
      {
        source: sdnUrl,
        records: records.length,
        columns: SDN_COLUMNS,
        wrote: path.relative(repo, sdnPath),
        sample: path.relative(repo, samplePath),
      },
      null,
      2,
    ),
  );
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
