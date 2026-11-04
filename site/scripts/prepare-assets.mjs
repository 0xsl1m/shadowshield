import { copyFile, mkdir } from "node:fs/promises";
await mkdir("public", { recursive: true });
for (const file of ["og.html", "og.png", "robots.txt", "sitemap.xml", "llms.txt", "llms-full.txt"]) {
  await copyFile(file, `public/${file}`);
}
