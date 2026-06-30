import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourcePath = path.join(
  repo,
  "circuits",
  "components",
  "poseidon255_constants.circom",
);
const outPath = path.join(repo, "apps", "web", "data", "poseidon255-t3.json");
const source = fs.readFileSync(sourcePath, "utf8");

function circomReturnExpression(functionName, t) {
  const functionStart = source.indexOf(`function ${functionName}`);
  const branchStart = source.indexOf(`t == ${t}`, functionStart);
  const returnStart = source.indexOf("return", branchStart);
  const arrayStart = source.indexOf("[", returnStart);
  let depth = 0;

  for (let i = arrayStart; i < source.length; i += 1) {
    const char = source[i];
    if (char === "[") {
      depth += 1;
    } else if (char === "]") {
      depth -= 1;
      if (depth === 0) {
        return source.slice(arrayStart, i + 1);
      }
    }
  }

  throw new Error(`could not parse ${functionName}(${t})`);
}

function circomArray(functionName, t) {
  const expression = circomReturnExpression(functionName, t).replace(
    /0x[0-9a-f]+/gi,
    (value) => `${value}n`,
  );
  return Function(`return ${expression};`)();
}

const constants = circomArray("CONSTANTS", 3);
const matrix = circomArray("MATRIX", 3);
const output = {
  schema: "anchorshield.poseidon255.t3.v1",
  source: "circuits/components/poseidon255_constants.circom",
  field_prime:
    "52435875175126190479447740508185965837690552500527637822603658699938581184513",
  t: 3,
  full_rounds: 8,
  partial_rounds: 56,
  constants: constants.map((value) => value.toString(10)),
  matrix: matrix.map((row) => row.map((value) => value.toString(10))),
};

fs.writeFileSync(outPath, `${JSON.stringify(output, null, 2)}\n`);
console.log(path.relative(repo, outPath));
