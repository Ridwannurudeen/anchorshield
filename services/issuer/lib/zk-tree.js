// Shared ZK tree/hash core for the AnchorShield issuer service.
//
// The hash primitives (poseidon255, foldHash, low248Hash, merkleRoot) are a
// faithful copy of the in-circuit reference in scripts/m1-circuit-smoke.js and
// read the SAME constants file (circuits/components/poseidon255_constants.circom),
// so they cannot drift from the deployed circuit. The tree builders below extend
// that core to POPULATED trees (the smoke test only ever builds empty ones):
//   - buildTree(leaves, depth): LeanIMT-style fixed-depth tree, empty node = 0,
//     internal node = Poseidon255(left, right), pair order = index-bit (matches
//     circuits/components/merkleProof.circom).
//   - buildExclusionTree(values, depth): indexed Merkle tree with a sorted
//     (value, next) linked list, producing non-membership witnesses (and refusing
//     to produce one for a member, which is exactly how a sanctioned key is blocked).

const fs = require("fs");
const path = require("path");

const repo = path.resolve(__dirname, "..", "..", "..");
const poseidonConstants = fs.readFileSync(
  path.join(repo, "circuits", "components", "poseidon255_constants.circom"),
  "utf8",
);

// BLS12-381 scalar field modulus r (public constant; decimal form of
// 0x73eda753...00000001) matching the circuit's --prime bls12381.
const FIELD_PRIME = BigInt(
  "52435875175126190479447740508185965837690552500527637822603658699938581184513",
);
const TWO_248 = 1n << 248n;
const partialRounds = [
  56, 56, 56, 56, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57,
];
const poseidonCache = new Map();

function decimal(value) {
  return value.toString(10);
}

function mod(value) {
  const reduced = value % FIELD_PRIME;
  return reduced >= 0n ? reduced : reduced + FIELD_PRIME;
}

function circomReturnExpression(functionName, t) {
  const functionStart = poseidonConstants.indexOf(`function ${functionName}`);
  const branchStart = poseidonConstants.indexOf(`t == ${t}`, functionStart);
  const returnStart = poseidonConstants.indexOf("return", branchStart);
  const arrayStart = poseidonConstants.indexOf("[", returnStart);
  let depth = 0;

  for (let i = arrayStart; i < poseidonConstants.length; i++) {
    const char = poseidonConstants[i];
    if (char === "[") {
      depth += 1;
    } else if (char === "]") {
      depth -= 1;
      if (depth === 0) {
        return poseidonConstants.slice(arrayStart, i + 1);
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

function poseidonParams(t) {
  if (!poseidonCache.has(t)) {
    poseidonCache.set(t, {
      constants: circomArray("CONSTANTS", t),
      matrix: circomArray("MATRIX", t),
    });
  }
  return poseidonCache.get(t);
}

function pow5(value) {
  const square = mod(value * value);
  return mod(square * square * value);
}

function poseidon255(inputs) {
  const values = inputs.map((value) => BigInt(value));
  const t = values.length + 1;
  const nPartial = partialRounds[values.length - 1];
  const nFull = 8;
  const { constants, matrix } = poseidonParams(t);
  let state = [0n, ...values];

  for (let round = 0; round < nFull + nPartial; round++) {
    const arked = state.map((value, index) =>
      mod(value + constants[round * t + index]),
    );
    const sbox =
      round < nFull / 2 || round >= nFull / 2 + nPartial
        ? arked.map(pow5)
        : [pow5(arked[0]), ...arked.slice(1)];

    state = matrix.map((row) =>
      mod(
        row.reduce(
          (sum, coefficient, index) => sum + coefficient * sbox[index],
          0n,
        ),
      ),
    );
  }

  return state[0];
}

function foldHash(values) {
  let current = poseidon255([values[0], values[1]]);
  for (let i = 2; i < values.length; i++) {
    current = poseidon255([current, values[i]]);
  }
  return current;
}

function low248Hash(values) {
  return poseidon255(values) % TWO_248;
}

function merkleRoot(leaf, index, siblings) {
  let node = BigInt(leaf);
  let pathIndex = BigInt(index);
  for (const sibling of siblings) {
    const siblingValue = BigInt(sibling);
    node =
      pathIndex & 1n
        ? poseidon255([siblingValue, node])
        : poseidon255([node, siblingValue]);
    pathIndex >>= 1n;
  }
  return node;
}

// Domain builders (field order matches circuits/eligibility.circom).
function credentialHash(input) {
  return foldHash([
    input.user_secret,
    input.issuer_id,
    input.kyc_passed,
    input.country,
    input.age,
    input.investor_type,
    input.tx_limit,
    input.issued_at,
    input.expires_at,
  ]);
}

function sanctionsKey(input) {
  return low248Hash([input.user_secret, input.issuer_id]);
}

function revocationKey(input) {
  return low248Hash([credentialHash(input)]);
}

// Fixed-depth LeanIMT-style tree. Empty subtree = 0; an internal node with at
// least one non-empty child = Poseidon255(left, right). Pair ordering is by
// index bit, matching MerkleProof in the circuit, so merkleRoot(leaf, index,
// siblings) reproduces buildTree(...).root for every occupied leaf.
function buildTree(leaves, depth) {
  const levels = [leaves.map((leaf) => BigInt(leaf))];
  if (levels[0].length === 0) {
    levels[0] = [0n];
  }
  for (let level = 0; level < depth; level++) {
    const current = levels[level];
    const next = [];
    for (let pos = 0; pos < Math.ceil(current.length / 2); pos++) {
      const left = current[2 * pos] ?? 0n;
      const right = current[2 * pos + 1] ?? 0n;
      next.push(left === 0n && right === 0n ? 0n : poseidon255([left, right]));
    }
    if (next.length === 0) {
      next.push(0n);
    }
    levels.push(next);
  }

  function siblings(index) {
    const result = [];
    let pos = Number(index);
    for (let level = 0; level < depth; level++) {
      const sibling = levels[level][pos ^ 1];
      result.push(decimal(sibling ?? 0n));
      pos = pos >> 1;
    }
    return result;
  }

  return { root: levels[depth][0], siblings, levels };
}

// Indexed Merkle tree for non-membership. Values are sorted; leaves are the
// linked-list nodes [(0, v1), (v1, v2), ..., (vm, 0)] hashed as Poseidon255(value, next).
// witnessFor(key) returns the low-leaf exclusion witness for a NON-member key and
// throws for a member (no low leaf brackets it) — the on-chain block for a listed key.
function buildExclusionTree(values, depth) {
  const sorted = [...new Set(values.map((value) => BigInt(value)))].sort(
    (a, b) => (a < b ? -1 : a > b ? 1 : 0),
  );
  const nodes = [{ value: 0n, next: sorted.length ? sorted[0] : 0n }];
  for (let i = 0; i < sorted.length; i++) {
    nodes.push({
      value: sorted[i],
      next: i + 1 < sorted.length ? sorted[i + 1] : 0n,
    });
  }

  const leaves = nodes.map((node) => poseidon255([node.value, node.next]));
  const tree = buildTree(leaves, depth);

  function lowLeafIndex(key) {
    const target = BigInt(key);
    for (let i = 0; i < nodes.length; i++) {
      const { value, next } = nodes[i];
      if (value < target && (target < next || next === 0n)) {
        return i;
      }
    }
    return -1;
  }

  function isMember(key) {
    const target = BigInt(key);
    return nodes.some((node) => node.value === target && target !== 0n);
  }

  function witnessFor(key) {
    if (isMember(key)) {
      throw new Error(
        `key ${key} is a member; no non-membership witness exists`,
      );
    }
    const index = lowLeafIndex(key);
    if (index < 0) {
      throw new Error(`no low leaf brackets key ${key}`);
    }
    return {
      low_value: decimal(nodes[index].value),
      low_next: decimal(nodes[index].next),
      low_index: decimal(BigInt(index)),
      low_siblings: tree.siblings(index),
      root: decimal(tree.root),
    };
  }

  return { root: tree.root, nodes, isMember, witnessFor };
}

module.exports = {
  FIELD_PRIME,
  decimal,
  poseidon255,
  foldHash,
  low248Hash,
  merkleRoot,
  credentialHash,
  sanctionsKey,
  revocationKey,
  buildTree,
  buildExclusionTree,
};
