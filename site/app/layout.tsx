import type { Metadata } from "next";
import packageInfo from "../package.json";
import "./style.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://shadowshield.xyz"),
  title: "ShadowShield — security for agentic AI",
  description: "An open-source, defense-in-depth security shield for LLM apps and agents, with reproducible benchmarks and transparent limitations.",
  alternates: { canonical: "/" },
  icons: { icon: `${process.env.NEXT_PUBLIC_BASE_PATH || ""}/icon.svg` },
  openGraph: { title: "ShadowShield — security for agentic AI", description: "Protect the boundary between your agent and untrusted input.", url: "https://shadowshield.xyz/", images: ["/og.png"], type: "website" },
  twitter: { card: "summary_large_image", images: ["/og.png"] },
};
const structuredData = JSON.stringify({
  "@context": "https://schema.org",
  "@graph": [
    { "@type": "SoftwareApplication", "@id": "https://shadowshield.xyz/#software", name: "ShadowShield", applicationCategory: "SecurityApplication", operatingSystem: "Cross-platform (Python 3.10+)", description: "Open-source defense-in-depth security for LLM apps and agents.", url: "https://shadowshield.xyz/", downloadUrl: "https://pypi.org/project/shadowshield/", codeRepository: "https://github.com/0xsl1m/shadowshield", programmingLanguage: "Python", softwareVersion: packageInfo.version, license: "https://opensource.org/licenses/MIT", offers: { "@type": "Offer", price: "0", priceCurrency: "USD" }, author: { "@type": "Organization", name: "ShadowShield Contributors" }, publisher: { "@type": "Organization", name: "Archon Digital LLC", url: "https://archondigital.xyz" } },
    { "@type": "SoftwareSourceCode", "@id": "https://shadowshield.xyz/#sourcecode", name: "ShadowShield", codeRepository: "https://github.com/0xsl1m/shadowshield", programmingLanguage: "Python", license: "https://opensource.org/licenses/MIT", runtimePlatform: "Python 3.10+" },
  ],
}).replace(/</g, "\\u003c");
export default function Layout({ children }: Readonly<{children: React.ReactNode}>) {
  return <html lang="en"><body><script type="application/ld+json" dangerouslySetInnerHTML={{__html: structuredData}} />{children}</body></html>;
}
