import { exec } from "child_process";
import util from "util";

const execPromise = util.promisify(exec);

/**
 * Robustly detect platform and OS of a target URL
 */
export async function detectPlatform(url) {
  let platform = "Unknown";
  let os = "Unknown (Cloud/Proxy protected)";
  let server = "Unknown";
  let tech = [];

  try {
    // 1. Get Headers
    const { stdout: headers } = await execPromise(`curl -I -s -L --max-time 10 ${url}`);
    const h = headers.toLowerCase();

    // Server Header
    const serverMatch = headers.match(/Server:\s*(.+)/i);
    if (serverMatch) {
      server = serverMatch[1].trim();
    }

    // OS Detection based on Server/X-Powered-By
    if (h.includes("ubuntu")) os = "Ubuntu Linux";
    else if (h.includes("debian")) os = "Debian Linux";
    else if (h.includes("centos") || h.includes("redhat") || h.includes("rhel")) os = "RHEL/CentOS Linux";
    else if (h.includes("win32") || h.includes("iis") || h.includes("microsoft")) os = "Windows Server";
    else if (h.includes("alpine")) os = "Alpine Linux";
    else if (h.includes("amazonlinux")) os = "Amazon Linux";
    else if (h.includes("freebsd")) os = "FreeBSD";

    // Platform/Framework Detection
    if (h.includes("cloudflare")) platform = "Cloudflare Proxy";
    else if (h.includes("nginx")) platform = "Nginx Web Server";
    else if (h.includes("apache")) platform = "Apache HTTP Server";
    else if (h.includes("vercel")) platform = "Vercel Platform";
    else if (h.includes("netlify")) platform = "Netlify Platform";
    else if (h.includes("litespeed")) platform = "LiteSpeed Server";
    
    // Tech Stack
    if (h.includes("php")) tech.push("PHP");
    if (h.includes("asp.net") || h.includes("x-aspnet")) tech.push("ASP.NET");
    if (h.includes("express")) tech.push("Node.js/Express");
    if (h.includes("next.js") || h.includes("x-nextjs")) tech.push("Next.js");
    if (h.includes("wp-content") || h.includes("wordpress")) tech.push("WordPress");
    if (h.includes("drupal")) tech.push("Drupal");

    // 2. Extra probe for common tech indicators if needed (optional, keep it fast)
    if (tech.length === 0) {
        // Try to find common paths
        try {
            const { stdout: body } = await execPromise(`curl -s --max-time 5 ${url}`);
            if (body.includes("wp-content")) tech.push("WordPress");
            if (body.includes("_next/static")) tech.push("Next.js");
            if (body.includes("react")) tech.push("React");
        } catch(e) {}
    }

  } catch (error) {
    console.error("[PlatformDetector] Error:", error.message);
  }

  return {
    platform,
    os,
    server,
    tech: tech.length > 0 ? tech.join(", ") : "Not detected",
    detectedAt: new Date()
  };
}
