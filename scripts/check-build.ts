import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const collectFiles = (directory: string, extension: string): string[] => (
  readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const filePath = join(directory, entry.name);
    if (entry.isDirectory()) {
      return collectFiles(filePath, extension);
    }
    return entry.isFile() && entry.name.endsWith(extension) ? [filePath] : [];
  })
);
const requiredFiles = [
  "dist/index.html",
  "dist/_headers",
  "dist/theme.css",
  "dist/assets/favicon.svg",
  "functions/api/openai/refresh.ts",
  "functions/api/openai/whoami.ts",
  "wrangler.jsonc",
];
const missing = requiredFiles.filter((relativePath) => (
  !existsSync(join(root, relativePath))
));

if (missing.length) {
  console.error("Cloudflare Pages build is missing required files:");
  missing.forEach((file) => console.error(" - " + file));
  process.exit(1);
}

const assetFiles = readdirSync(join(root, "dist/assets"));
if (!assetFiles.some((file) => file.endsWith(".js"))) {
  console.error("Vite build did not emit a JavaScript bundle");
  process.exit(1);
}
if (!assetFiles.some((file) => file.endsWith(".css"))) {
  console.error("Vite build did not emit a CSS bundle");
  process.exit(1);
}

const runtimeFiles = [
  ...collectFiles(join(root, "src"), ".ts"),
  ...assetFiles
    .filter((file) => file.endsWith(".js"))
    .map((file) => join(root, "dist/assets", file)),
];
const source = runtimeFiles.map((filePath) => (
  readFileSync(filePath, "utf8")
)).join("\n");
const forbiddenRuntimeApis = [
  { label: "XMLHttpRequest", pattern: /\bXMLHttpRequest\b/u },
  { label: "sendBeacon", pattern: /\bsendBeacon\b/u },
  { label: "localStorage", pattern: /\blocalStorage\b/u },
  { label: "sessionStorage", pattern: /\bsessionStorage\b/u },
  { label: "IndexedDB", pattern: /\bindexedDB\b/u },
];
const violations = forbiddenRuntimeApis
  .filter((rule) => rule.pattern.test(source))
  .map((rule) => rule.label);

if (violations.length) {
  console.error("Client security boundary violated by: " + violations.join(", "));
  process.exit(1);
}

if (!source.includes("/api/openai/refresh")) {
  console.error("Browser bundle is missing the same-origin RT validation endpoint");
  process.exit(1);
}
if (!source.includes("/api/openai/whoami")) {
  console.error("Browser bundle is missing the same-origin AT validation endpoint");
  process.exit(1);
}

const browserBundle = assetFiles
  .filter((file) => file.endsWith(".js"))
  .map((file) => readFileSync(join(root, "dist/assets", file), "utf8"))
  .join("\n");
if (browserBundle.includes("https://auth.openai.com/oauth/token")) {
  console.error("Browser bundle must not call the OpenAI OAuth endpoint directly");
  process.exit(1);
}

const headers = readFileSync(join(root, "dist/_headers"), "utf8");
if (!headers.includes("connect-src 'self'")) {
  console.error("dist/_headers must restrict network requests to connect-src 'self'");
  process.exit(1);
}

interface WranglerConfig {
  pages_build_output_dir?: unknown;
  placement?: {
    region?: unknown;
  };
}

const wrangler = JSON.parse(
  readFileSync(join(root, "wrangler.jsonc"), "utf8"),
) as WranglerConfig;
if (wrangler.pages_build_output_dir !== "./dist") {
  console.error("wrangler.jsonc must target the Cloudflare Pages dist directory");
  process.exit(1);
}
if (wrangler.placement?.region !== "aws:us-east-1") {
  console.error("Pages Functions must run in an OpenAI-supported placement region");
  process.exit(1);
}

console.log("Cloudflare Pages build ready: dist/ + functions/");
