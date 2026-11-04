"use client";
import { useState } from "react";
export default function CopyInstall() {
  const [label,setLabel]=useState("COPY");
  async function copy() {
    try { await navigator.clipboard.writeText("pip install shadowshield"); setLabel("COPIED"); }
    catch { setLabel("SELECT COMMAND"); }
  }
  return <button type="button" onClick={copy} aria-label="Copy pip install shadowshield" aria-live="polite">{label} <span aria-hidden="true">↗</span></button>;
}
