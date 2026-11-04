import type { NextConfig } from "next";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const files = ["app/page.tsx", "app/layout.tsx", "app/not-found.tsx", "app/style.css", "app/Atmosphere.tsx", "app/CopyInstall.tsx", "package.json", "package-lock.json", "next.config.ts"];
const hash = createHash("sha256");
for (const file of files) hash.update(readFileSync(file, "utf8").replace(/\r\n/g, "\n"));
hash.update(process.env.NEXT_PUBLIC_BASE_PATH || "");
const buildId = hash.digest("hex").slice(0, 20);

const config: NextConfig = {
  output: "export",
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || "",
  images: { unoptimized: true },
  generateBuildId: async () => buildId,
};
export default config;
