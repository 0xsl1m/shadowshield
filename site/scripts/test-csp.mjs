import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

const root=await realpath(tmpdir());
const dir=await mkdtemp(join(root,"shadowshield-csp-"));
const target=await realpath(dir);
if (!target.startsWith(root+sep) || target===root) throw new Error("Unexpected temporary directory");
const script=resolve("scripts/csp.mjs");
const init="(self.__next_f=self.__next_f||[]).push([0])";
const rsc='self.__next_f.push([1,"escaped \\u003c/script>"])';
const turbo='(globalThis["TURBOPACK"] || (globalThis["TURBOPACK"] = [])).push({"otherChunks":["static/chunks/test.js"],"runtimeModuleIds":[3]});';
const schema=JSON.stringify({"@context":"https://schema.org","@graph":[]});
const csp="default-src 'self'; script-src 'self'; script-src-attr 'none'; style-src 'self' https://fonts.googleapis.com; style-src-attr 'none'";
const config={headers:[{source:"/(.*)",headers:[{key:"Content-Security-Policy",value:csp}]}]};
async function fixture(extra="",style="a{\ncolor:red\n}") {
  await mkdir(join(dir,"out"),{recursive:true});
  await writeFile(join(dir,"vercel.json"),JSON.stringify(config));
  await writeFile(join(dir,"out/index.html"),`<style>${style}</style><script type="application/ld+json">${schema}</script><script id="_R_">${turbo}</script><script>${init}</script><script>${rsc}</script>${extra}`);
}
function run(args,env={}) { return spawnSync(process.execPath,[script,...args],{cwd:dir,encoding:"utf8",env:{...process.env,...env}}); }
try {
  await fixture(); let result=run(["--write"]); assert.equal(result.status,0,result.stderr);
  const html=await readFile(join(dir,"out/index.html"),"utf8");
  const matches=[...html.matchAll(/<script([^>]*) src="([^"]+)"><\/script>/g)];
  assert.equal(matches.length,3); assert.match(matches[0][1],/id="_R_"/);
  assert.equal(await readFile(join(dir,"out",matches[2][2].slice(1)),"utf8"),rsc);
  const written=await readFile(join(dir,"vercel.json"),"utf8");
  await fixture("","a{\r\ncolor:red\r\n}"); await writeFile(join(dir,"vercel.json"),written);
  result=run(["--check"]); assert.equal(result.status,0,result.stderr);
  for (const bad of ['self.__next_f.push([1,alert(1)])', 'self.__next_f.push([1,"ok"]);alert(1)//']) {
    await fixture(`<script>${bad}</script>`); result=run(["--write"]); assert.notEqual(result.status,0,`accepted ${bad}`);
  }
  await fixture('<script nonce="bad">'+init+'</script>'); result=run(["--write"]); assert.notEqual(result.status,0,"accepted unexpected attributes");
  await fixture(); result=run(["--check"],{NEXT_PUBLIC_BASE_PATH:"/shadowshield"}); assert.equal(result.status,0,result.stderr);
  assert.match(await readFile(join(dir,"out/index.html"),"utf8"),/src="\/shadowshield\/_ss\/bootstrap\//);
  console.log("CSP externalization fixtures passed (ordering, escaped text, CRLF, hostile scripts, attributes, Pages base path).");
} finally {
  if (await realpath(dir) !== target || !target.startsWith(root+sep)) throw new Error("Temporary path changed; refusing cleanup");
  await rm(target,{recursive:true,force:true});
}
