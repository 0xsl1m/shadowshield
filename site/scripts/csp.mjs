import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

// Externalize only recognized Next bootstrap scripts to content-addressed,
// same-origin files. Static JSON-LD and OG styles remain hash-authorized.
async function htmlFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  return (await Promise.all(entries.map(e => e.isDirectory() ? htmlFiles(join(dir,e.name)) : e.name.endsWith(".html") ? [join(dir,e.name)] : []))).flat();
}
const hashes = new Set(), styles = new Set();
const chunks = new Map();
const base = process.env.NEXT_PUBLIC_BASE_PATH || "";
if (base && !/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(base)) throw new Error("Invalid static export base path");
function isNextBootstrap(attrs, body) {
  if (/^\s*$/.test(attrs) && body === "(self.__next_f=self.__next_f||[]).push([0])") return true;
  const next = /^self\.__next_f\.push\((\[1,[\s\S]*\])\)$/.exec(body);
  if (/^\s*$/.test(attrs) && next) {
    try { const value = JSON.parse(next[1]); return Array.isArray(value) && value.length === 2 && value[0] === 1 && typeof value[1] === "string"; }
    catch { return false; }
  }
  const turbo = /^\(globalThis\["TURBOPACK"\] \|\| \(globalThis\["TURBOPACK"\] = \[\]\)\)\.push\((\{[\s\S]*\})\);$/.exec(body);
  if (/^\s+id="_R_"\s*$/.test(attrs) && turbo) {
    try {
      const value = JSON.parse(turbo[1]);
      return Object.keys(value).sort().join(",") === "otherChunks,runtimeModuleIds" &&
        Array.isArray(value.otherChunks) && value.otherChunks.every(x => typeof x === "string" && /^static\/chunks\/[a-z0-9._-]+\.js$/i.test(x)) &&
        Array.isArray(value.runtimeModuleIds) && value.runtimeModuleIds.every(Number.isSafeInteger);
    } catch { return false; }
  }
  return false;
}
for (const file of await htmlFiles("out")) {
  let html = await readFile(file,"utf8");
  const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "");
  if (/\sstyle\s*=/i.test(markup) || /\son[a-z]+\s*=/i.test(markup)) {
    throw new Error(`${file} contains a style attribute or handler forbidden by the CSP.`);
  }
  for (const match of markup.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) styles.add("'sha256-" + createHash("sha256").update(match[1].replace(/\r\n?/g,"\n")).digest("base64") + "'");
  html = html.replace(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi, (whole, attrs, body) => {
    if (/\bsrc\s*=/.test(attrs)) {
      if (body.trim()) throw new Error(`${file}: external script has inline content`);
      return whole;
    }
    if (/^\s+type="application\/ld\+json"\s*$/.test(attrs)) {
      const data = JSON.parse(body);
      if (data["@context"] !== "https://schema.org" || !Array.isArray(data["@graph"])) throw new Error(`${file}: unexpected JSON-LD`);
      hashes.add("'sha256-" + createHash("sha256").update(body.replace(/\r\n?/g,"\n")).digest("base64") + "'");
      return whole;
    }
    if (!isNextBootstrap(attrs,body)) throw new Error(`${file}: unrecognized inline script; refusing export`);
    const digest = createHash("sha256").update(body).digest("hex");
    chunks.set(digest, body);
    return `<script${attrs} src="${base}/_ss/bootstrap/${digest}.js"></script>`;
  });
  await writeFile(file,html);
}
if (!hashes.size || !chunks.size) throw new Error("Expected JSON-LD or bootstrap scripts missing from export.");
await mkdir("out/_ss/bootstrap", { recursive: true });
for (const [digest, body] of chunks) await writeFile(`out/_ss/bootstrap/${digest}.js`,body);
if (process.env.NEXT_PUBLIC_BASE_PATH) {
  console.log("Pages export checked; CSP headers are controlled by the host, not this artifact.");
  process.exit(0);
}
const path="vercel.json", config=JSON.parse(await readFile(path,"utf8"));
const headers=config.headers.find(rule=>rule.source==="/(.*)").headers;
const csp=headers.find(header=>header.key==="Content-Security-Policy");
const script="script-src 'self' " + [...hashes].sort().join(" ");
const style="style-src 'self' " + [...styles].sort().join(" ") + (styles.size ? " " : "") + "https://fonts.googleapis.com";
const desired=csp.value.replace(/script-src [^;]+/,script).replace(/style-src [^;]+/,style);
if (process.argv.includes("--write")) {
  csp.value=desired; await writeFile(path,JSON.stringify(config,null,2)+"\n");
  console.log(`Externalized ${chunks.size} bootstrap scripts; wrote ${hashes.size} static JSON-LD hashes.`);
} else if (csp.value !== desired) {
  throw new Error("Exported script hashes differ from vercel.json; run npm run build:update-csp and review the diff.");
} else console.log(`Externalized ${chunks.size} bootstrap scripts; verified ${hashes.size} static JSON-LD hashes.`);
