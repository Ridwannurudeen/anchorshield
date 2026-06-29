import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const webDir = path.join(repo, "apps", "web");

function sha384(file) {
  return `sha384-${crypto.createHash("sha384").update(fs.readFileSync(file)).digest("base64")}`;
}

function fail(message) {
  throw new Error(message);
}

for (const name of fs
  .readdirSync(webDir)
  .filter((file) => file.endsWith(".html"))) {
  const file = path.join(webDir, name);
  const html = fs.readFileSync(file, "utf8");
  if (!html.includes('http-equiv="Content-Security-Policy"')) {
    fail(`${name}: missing CSP meta tag`);
  }

  const localRefs = [
    ...html.matchAll(/<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"[^>]*>/g),
    ...html.matchAll(/<script[^>]+src="([^"]+)"[^>]*><\/script>/g),
  ];
  for (const match of localRefs) {
    const tag = match[0];
    const src = match[1];
    if (!src.startsWith("./")) continue;
    const integrity = tag.match(/integrity="([^"]+)"/)?.[1];
    if (!integrity) fail(`${name}: ${src} missing integrity`);
    const target = path.join(webDir, src);
    const actual = sha384(target);
    if (integrity !== actual) {
      fail(`${name}: ${src} integrity mismatch`);
    }
  }
}

console.log("web CSP/SRI guard ok");
