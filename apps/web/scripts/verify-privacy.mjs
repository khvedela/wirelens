import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";

const appRoot = resolve(import.meta.dirname, "..");
const sourceRoot = join(appRoot, "src");
const forbidden = [
  ["fetch", /\bfetch\s*\(/u],
  ["XMLHttpRequest", /\bXMLHttpRequest\b/u],
  ["WebSocket", /\bWebSocket\b/u],
  ["EventSource", /\bEventSource\b/u],
  ["WebTransport", /\bWebTransport\b/u],
  ["sendBeacon", /\bsendBeacon\s*\(/u],
  ["service worker", /\bnavigator\s*\.\s*serviceWorker\b/u],
  ["IndexedDB", /\bindexedDB\b/u],
  ["Cache Storage", /\bcaches\s*\./u],
  ["local storage", /\blocalStorage\b/u],
  ["session storage", /\bsessionStorage\b/u],
];

function sourceFiles(directory) {
  return readdirSync(directory)
    .flatMap((entry) => {
      const path = join(directory, entry);
      if (statSync(path).isDirectory()) {
        return entry === "generated" ? [] : sourceFiles(path);
      }
      return [path];
    })
    .filter((path) => extname(path) === ".ts" || extname(path) === ".tsx");
}

const violations = [];
for (const path of sourceFiles(sourceRoot)) {
  const source = readFileSync(path, "utf8");
  for (const [label, expression] of forbidden) {
    if (expression.test(source)) {
      violations.push(`${relative(appRoot, path)} uses forbidden analysis-path API ${label}`);
    }
  }
}

if (violations.length > 0) {
  throw new Error(`Privacy boundary check failed:\n${violations.join("\n")}`);
}

process.stdout.write("Privacy boundary check passed: product sources contain no network APIs.\n");
