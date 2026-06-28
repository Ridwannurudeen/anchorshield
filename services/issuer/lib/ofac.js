const SDN_COLUMNS = [
  "ent_num",
  "sdn_name",
  "sdn_type",
  "program",
  "title",
  "call_sign",
  "vess_type",
  "tonnage",
  "grt",
  "vess_flag",
  "vess_owner",
  "remarks",
];

const ALT_COLUMNS = ["ent_num", "alt_num", "alt_type", "alt_name", "remarks"];

function parseCsvLine(line) {
  const fields = [];
  let field = "";
  let quoted = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (quoted && line[i + 1] === '"') {
        field += '"';
        i += 1;
      } else {
        quoted = !quoted;
      }
    } else if (char === "," && !quoted) {
      fields.push(field);
      field = "";
    } else {
      field += char;
    }
  }

  fields.push(field);
  return fields;
}

function cleanOfacValue(value) {
  const trimmed = value.trim();
  return trimmed === "-0-" ? "" : trimmed;
}

function isRecordLine(line) {
  const trimmed = line.trim();
  return trimmed.length > 0 && trimmed !== "\u001a";
}

function parseLegacyCsv(text, columns, label) {
  return text
    .split(/\r?\n/)
    .filter(isRecordLine)
    .map((line, index) => {
      const fields = parseCsvLine(line).map(cleanOfacValue);
      if (fields.length !== columns.length) {
        throw new Error(
          `${label} row ${index + 1} has ${fields.length} columns; expected ${columns.length}`,
        );
      }
      return Object.fromEntries(
        columns.map((column, columnIndex) => [column, fields[columnIndex]]),
      );
    });
}

function parseLegacySdnCsv(text) {
  return parseLegacyCsv(text, SDN_COLUMNS, "SDN.CSV");
}

function parseLegacyAltCsv(text) {
  return parseLegacyCsv(text, ALT_COLUMNS, "ALT.CSV");
}

function normalizeName(name) {
  return name
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function buildScreeningIndex(sdnRecords, altRecords = []) {
  const names = new Map();

  for (const record of sdnRecords) {
    const normalized = normalizeName(record.sdn_name);
    if (normalized) {
      names.set(normalized, [
        ...(names.get(normalized) || []),
        {
          ent_num: record.ent_num,
          name: record.sdn_name,
          type: record.sdn_type,
          program: record.program,
          source: "SDN.CSV",
        },
      ]);
    }
  }

  for (const record of altRecords) {
    const normalized = normalizeName(record.alt_name);
    if (normalized) {
      names.set(normalized, [
        ...(names.get(normalized) || []),
        {
          ent_num: record.ent_num,
          name: record.alt_name,
          type: record.alt_type,
          program: "",
          source: "ALT.CSV",
        },
      ]);
    }
  }

  return names;
}

function screenRoster(users, sdnRecords, altRecords = []) {
  const index = buildScreeningIndex(sdnRecords, altRecords);
  return users.map((user) => {
    const normalized_name = normalizeName(user.legal_name);
    const matches = index.get(normalized_name) || [];
    return {
      user_id: user.id,
      legal_name: user.legal_name,
      normalized_name,
      matched: matches.length > 0,
      matches,
    };
  });
}

module.exports = {
  SDN_COLUMNS,
  ALT_COLUMNS,
  parseCsvLine,
  parseLegacySdnCsv,
  parseLegacyAltCsv,
  normalizeName,
  buildScreeningIndex,
  screenRoster,
};
