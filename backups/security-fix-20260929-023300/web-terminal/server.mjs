import { createServer } from "node:http";
import fs from "node:fs/promises";
import { chmodSync, copyFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(MODULE_DIR, "..");
const PORT = 6060;
const HOST = "127.0.0.1";
const ROOT_FS = "/";
const SESSION_COOKIE_NAME = "terminal_session";
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

let terminalServer = null;
const activeSockets = new Set();

// Cloudflare Quick Tunnel state variables (stored in memory only)
let cloudflareProcess = null;
let currentTunnelUrl = null;
let tunnelStarting = false;

// Rate limiting map: ip -> { count, firstAttempt }
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function getClientIp(req) {
  const cfIp = req.headers["cf-connecting-ip"];
  if (typeof cfIp === "string" && cfIp.trim()) return cfIp.trim();
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) return xff.split(",")[0].trim();
  return req.socket?.remoteAddress || "127.0.0.1";
}

function checkRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) return true;
  if (now - record.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.delete(ip);
    return true;
  }
  return record.count < MAX_LOGIN_ATTEMPTS;
}

function recordLoginAttempt(ip, success) {
  if (success) {
    loginAttempts.delete(ip);
    return;
  }
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, firstAttempt: now };
  if (now - record.firstAttempt > LOGIN_WINDOW_MS) {
    record.count = 1;
    record.firstAttempt = now;
  } else {
    record.count += 1;
  }
  loginAttempts.set(ip, record);
}

function getSecretKey() {
  return process.env.SESSION_SECRET || "hypersoft_terminal_secret_2026_secured_key";
}

function generateSessionToken(username) {
  const secret = getSecretKey();
  const payload = JSON.stringify({
    username,
    exp: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
  });
  const bodyB64 = Buffer.from(payload).toString("base64url");
  const signature = crypto.createHmac("sha256", secret).update(bodyB64).digest("base64url");
  return `${bodyB64}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [bodyB64, sigB64] = parts;
  const secret = getSecretKey();

  try {
    const expectedSig = crypto.createHmac("sha256", secret).update(bodyB64).digest("base64url");
    const sigBuf = Buffer.from(sigB64);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(bodyB64, "base64url").toString("utf8"));
    if (typeof payload.exp !== "number" || payload.exp < Date.now()) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  for (const cookie of cookieHeader.split(";")) {
    const parts = cookie.split("=");
    if (parts.length >= 2) {
      list[parts[0].trim()] = parts.slice(1).join("=").trim();
    }
  }
  return list;
}

function getAuthFromReq(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[SESSION_COOKIE_NAME];
  if (token) {
    const payload = verifySessionToken(token);
    if (payload) return payload;
  }

  const urlObj = new URL(req.url || "/", "http://127.0.0.1");
  const urlToken = urlObj.searchParams.get("token");
  if (urlToken) {
    const payload = verifySessionToken(urlToken);
    if (payload) return payload;
  }

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const payload = verifySessionToken(authHeader.substring(7));
    if (payload) return payload;
  }

  return null;
}

// Check cloudflared binary availability
export function getCloudflaredBinaryPath() {
  const candidates = [
    path.join(MODULE_DIR, "cloudflared"),
    path.join(PROJECT_ROOT, "web-terminal", "cloudflared"),
    path.join(PROJECT_ROOT, "cloudflared"),
    path.join(PROJECT_ROOT, ".tmp", "cloudflared"),
    "/web-terminal/cloudflared",
    "/.tmp/cloudflared",
    "/tmp/cloudflared",
    "/usr/local/bin/cloudflared",
    "/usr/bin/cloudflared",
  ];

  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;
    try {
      chmodSync(candidate, 0o755);
    } catch {}
    try {
      const check = spawnSync(candidate, ["--version"], { stdio: "ignore", timeout: 4000 });
      if (!check.error && check.status === 0) {
        return candidate;
      }
      // Fallback if current filesystem mount is noexec: copy to /tmp/cloudflared
      if (candidate !== "/tmp/cloudflared") {
        copyFileSync(candidate, "/tmp/cloudflared");
        chmodSync("/tmp/cloudflared", 0o755);
        const tmpCheck = spawnSync("/tmp/cloudflared", ["--version"], { stdio: "ignore", timeout: 4000 });
        if (!tmpCheck.error && tmpCheck.status === 0) {
          return "/tmp/cloudflared";
        }
      }
    } catch {}
  }

  return "cloudflared";
}

export function isCloudflaredAvailable() {
  try {
    const bin = getCloudflaredBinaryPath();
    const res = spawnSync(bin, ["--version"], { stdio: "ignore", timeout: 4000 });
    return !res.error && res.status === 0;
  } catch {
    return false;
  }
}

export function isCloudflareTunnelRunning() {
  return cloudflareProcess !== null && !cloudflareProcess.killed && cloudflareProcess.exitCode === null;
}

export function getCurrentTunnelUrl() {
  return isCloudflareTunnelRunning() ? currentTunnelUrl : null;
}

export function startCloudflareTunnelService() {
  if (isCloudflareTunnelRunning() && currentTunnelUrl) {
    return Promise.resolve(currentTunnelUrl);
  }

  if (tunnelStarting) {
    return new Promise((resolve) => {
      const interval = setInterval(() => {
        if (!tunnelStarting) {
          clearInterval(interval);
          resolve(currentTunnelUrl);
        }
      }, 500);
    });
  }

  if (!isCloudflaredAvailable()) {
    return Promise.resolve(null);
  }

  tunnelStarting = true;
  const binaryPath = getCloudflaredBinaryPath();

  return new Promise((resolve) => {
    try {
      cloudflareProcess = spawn(binaryPath, ["tunnel", "--no-autoupdate", "--url", `http://${HOST}:${PORT}`], {
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      tunnelStarting = false;
      cloudflareProcess = null;
      return resolve(null);
    }

    let resolved = false;

    const handleOutput = (data) => {
      const text = data.toString("utf8");
      const match = text.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
      if (match) {
        currentTunnelUrl = match[0];
        console.log(`[cloudflare] Quick Tunnel active -> http://${HOST}:${PORT}`);

        if (!resolved) {
          resolved = true;
          tunnelStarting = false;
          resolve(currentTunnelUrl);
        }
      }
    };

    cloudflareProcess.stdout.on("data", handleOutput);
    cloudflareProcess.stderr.on("data", handleOutput);

    cloudflareProcess.on("error", (err) => {
      console.error("[cloudflare] Tunnel error:", err.message);
      if (!resolved) {
        resolved = true;
        tunnelStarting = false;
        resolve(null);
      }
    });

    cloudflareProcess.on("exit", (code, signal) => {
      console.log(`[cloudflare] Tunnel exited with code=${code ?? "null"} signal=${signal ?? "none"}`);
      cloudflareProcess = null;
      currentTunnelUrl = null;
      tunnelStarting = false;
      if (!resolved) {
        resolved = true;
        resolve(null);
      }
    });

    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        tunnelStarting = false;
        resolve(currentTunnelUrl);
      }
    }, 15000);
  });
}

export function stopCloudflareTunnelService() {
  if (cloudflareProcess) {
    console.log("[cloudflare] Stopping Cloudflare Quick Tunnel...");
    try {
      cloudflareProcess.kill("SIGTERM");
    } catch {}
    cloudflareProcess = null;
  }
  currentTunnelUrl = null;
  tunnelStarting = false;
  return Promise.resolve();
}

export async function restartCloudflareTunnelService() {
  await stopCloudflareTunnelService();
  await new Promise((res) => setTimeout(res, 1000));
  return await startCloudflareTunnelService();
}

// Strictly restricted command set (no shell or child_process used for user commands)
const ALLOWED_COMMANDS = new Set([
  "pwd",
  "ls",
  "cd",
  "cat",
  "head",
  "tail",
  "mkdir",
  "touch",
  "clear",
  "whoami",
  "help",
]);

function resolveVirtualPath(currentVwd, targetPath) {
  const safeBase = typeof currentVwd === "string" && currentVwd.startsWith("/") ? currentVwd : ROOT_FS;
  if (!targetPath || targetPath === ".") {
    return path.posix.normalize(safeBase);
  }
  if (String(targetPath).includes("\0")) {
    throw new Error("Invalid path: null byte detected");
  }
  const normalizedTarget = String(targetPath).replace(/\\/g, "/");
  const resolvedVirtual = normalizedTarget.startsWith("/")
    ? path.posix.resolve(ROOT_FS, "." + normalizedTarget)
    : path.posix.resolve(safeBase, normalizedTarget);

  const rel = path.posix.relative(ROOT_FS, resolvedVirtual);
  if (rel.startsWith("..") || path.posix.isAbsolute(rel)) {
    return ROOT_FS;
  }
  return resolvedVirtual.startsWith("/") ? resolvedVirtual : "/" + resolvedVirtual;
}

function parseCommandLine(cmdString) {
  const args = [];
  let current = "";
  let inQuotes = false;
  let quoteChar = "";

  for (let i = 0; i < cmdString.length; i++) {
    const char = cmdString[i];
    if (inQuotes) {
      if (char === quoteChar) {
        inQuotes = false;
      } else {
        current += char;
      }
    } else {
      if (char === '"' || char === "'") {
        inQuotes = true;
        quoteChar = char;
      } else if (/\s/.test(char)) {
        if (current.length > 0) {
          args.push(current);
          current = "";
        }
      } else {
        current += char;
      }
    }
  }
  if (current.length > 0) {
    args.push(current);
  }
  return args;
}

export async function executeTerminalCommand(cmdString, state) {
  const trimmed = String(cmdString || "").trim();
  const currentVwd = resolveVirtualPath(state?.vwd || ROOT_FS, ".");
  if (!trimmed) {
    return { output: "", newVwd: currentVwd };
  }

  const args = parseCommandLine(trimmed);
  const command = (args[0] || "").toLowerCase();

  if (!ALLOWED_COMMANDS.has(command)) {
    return {
      output: `\x1b[31mCommand not allowed: '${command}'.\x1b[0m\r\nAllowed commands: pwd, ls, cd, cat, head, tail, mkdir, touch, clear, whoami, help\r\n`,
      newVwd: currentVwd,
    };
  }

  try {
    switch (command) {
      case "pwd": {
        return { output: `${currentVwd}\r\n`, newVwd: currentVwd };
      }

      case "whoami": {
        const username = state?.username || process.env.WEB_TERMINAL_USERNAME || "admin";
        return { output: `${username}\r\n`, newVwd: currentVwd };
      }

      case "clear": {
        return { output: "\x1bc", newVwd: currentVwd, clearScreen: true };
      }

      case "help": {
        const helpText = [
          "\x1b[1;36mHyperSoft Web Terminal - Allowed Commands:\x1b[0m",
          "  \x1b[1;32mpwd\x1b[0m              Print current working directory",
          "  \x1b[1;32mls [-l] [-a] [path]\x1b[0m List directory contents",
          "  \x1b[1;32mcd <path>\x1b[0m          Change working directory",
          "  \x1b[1;32mcat <file>\x1b[0m         Display contents of a file",
          "  \x1b[1;32mhead [-n N] <file>\x1b[0m Display first N lines of a file",
          "  \x1b[1;32mtail [-n N] <file>\x1b[0m Display last N lines of a file",
          "  \x1b[1;32mmkdir [-p] <dir>\x1b[0m   Create a directory",
          "  \x1b[1;32mtouch <file>\x1b[0m       Create an empty file or update timestamp",
          "  \x1b[1;32mclear\x1b[0m              Clear terminal screen",
          "  \x1b[1;32mwhoami\x1b[0m             Display logged in username",
          "  \x1b[1;32mhelp\x1b[0m               Display this help message",
        ].join("\r\n");
        return { output: helpText + "\r\n", newVwd: currentVwd };
      }

      case "cd": {
        const targetArg = args[1];
        if (!targetArg || targetArg === "~") {
          return { output: "", newVwd: ROOT_FS };
        }
        const targetVwd = resolveVirtualPath(currentVwd, targetArg);
        try {
          const st = await fs.stat(targetVwd);
          if (!st.isDirectory()) {
            return { output: `\x1b[31mcd: ${targetArg}: Not a directory\x1b[0m\r\n`, newVwd: currentVwd };
          }
          return { output: "", newVwd: targetVwd };
        } catch {
          return { output: `\x1b[31mcd: ${targetArg}: No such file or directory\x1b[0m\r\n`, newVwd: currentVwd };
        }
      }

      case "ls": {
        let showHidden = false;
        let longFormat = false;
        const paths = [];

        for (let i = 1; i < args.length; i++) {
          const arg = args[i];
          if (arg.startsWith("-")) {
            if (arg.includes("a")) showHidden = true;
            if (arg.includes("l")) longFormat = true;
          } else {
            paths.push(arg);
          }
        }

        const targetArg = paths[0] || ".";
        const targetPath = resolveVirtualPath(currentVwd, targetArg);

        try {
          const st = await fs.stat(targetPath);
          if (st.isFile()) {
            const fileName = path.posix.basename(targetPath);
            return { output: `${fileName}\r\n`, newVwd: currentVwd };
          }

          const entries = await fs.readdir(targetPath, { withFileTypes: true });
          const filtered = entries.filter((e) => showHidden || !e.name.startsWith("."));

          filtered.sort((a, b) => {
            if (a.isDirectory() && !b.isDirectory()) return -1;
            if (!a.isDirectory() && b.isDirectory()) return 1;
            return a.name.localeCompare(b.name);
          });

          if (longFormat) {
            const lines = [];
            for (const entry of filtered) {
              const itemPath = path.posix.join(targetPath, entry.name);
              let size = 0;
              let mtime = new Date();
              try {
                const itemStat = await fs.stat(itemPath);
                size = itemStat.size;
                mtime = itemStat.mtime;
              } catch {}

              const isDir = entry.isDirectory();
              const typeChar = isDir ? "d" : "-";
              const permissions = isDir ? "rwxr-xr-x" : "rw-r--r--";
              const formattedDate = mtime.toISOString().replace("T", " ").substring(0, 16);
              const colorName = isDir
                ? `\x1b[1;34m${entry.name}/\x1b[0m`
                : entry.name.endsWith(".js") || entry.name.endsWith(".mjs") || entry.name.endsWith(".sh")
                ? `\x1b[1;32m${entry.name}\x1b[0m`
                : entry.name;

              lines.push(`${typeChar}${permissions}  1 root root ${String(size).padStart(8)} ${formattedDate} ${colorName}`);
            }
            return { output: lines.join("\r\n") + (lines.length ? "\r\n" : ""), newVwd: currentVwd };
          } else {
            const formatted = filtered.map((e) => {
              if (e.isDirectory()) return `\x1b[1;34m${e.name}/\x1b[0m`;
              if (e.name.endsWith(".js") || e.name.endsWith(".mjs")) return `\x1b[1;32m${e.name}\x1b[0m`;
              return e.name;
            });
            return { output: formatted.join("  ") + (formatted.length ? "\r\n" : ""), newVwd: currentVwd };
          }
        } catch {
          return { output: `\x1b[31mls: cannot access '${targetArg}': No such file or directory\x1b[0m\r\n`, newVwd: currentVwd };
        }
      }

      case "cat": {
        const fileArg = args[1];
        if (!fileArg) {
          return { output: "\x1b[31mcat: missing file argument\x1b[0m\r\n", newVwd: currentVwd };
        }
        const targetPath = resolveVirtualPath(currentVwd, fileArg);
        try {
          const st = await fs.stat(targetPath);
          if (st.isDirectory()) {
            return { output: `\x1b[31mcat: ${fileArg}: Is a directory\x1b[0m\r\n`, newVwd: currentVwd };
          }
          if (st.size > 5 * 1024 * 1024) {
            return { output: `\x1b[31mcat: ${fileArg}: File too large (>5MB)\x1b[0m\r\n`, newVwd: currentVwd };
          }
          const content = await fs.readFile(targetPath, "utf8");
          const normalizedContent = content.replace(/\r?\n/g, "\r\n");
          return { output: normalizedContent + (normalizedContent.endsWith("\r\n") ? "" : "\r\n"), newVwd: currentVwd };
        } catch {
          return { output: `\x1b[31mcat: ${fileArg}: No such file or directory\x1b[0m\r\n`, newVwd: currentVwd };
        }
      }

      case "head":
      case "tail": {
        let numLines = 10;
        let fileArg = null;

        for (let i = 1; i < args.length; i++) {
          const arg = args[i];
          if (arg === "-n" && args[i + 1]) {
            numLines = Math.max(1, parseInt(args[i + 1], 10) || 10);
            i++;
          } else if (arg.startsWith("-n")) {
            numLines = Math.max(1, parseInt(arg.substring(2), 10) || 10);
          } else if (arg.startsWith("-") && /^\d+$/.test(arg.substring(1))) {
            numLines = Math.max(1, parseInt(arg.substring(1), 10) || 10);
          } else {
            fileArg = arg;
          }
        }

        if (!fileArg) {
          return { output: `\x1b[31m${command}: missing file argument\x1b[0m\r\n`, newVwd: currentVwd };
        }

        const targetPath = resolveVirtualPath(currentVwd, fileArg);
        try {
          const st = await fs.stat(targetPath);
          if (st.isDirectory()) {
            return { output: `\x1b[31m${command}: ${fileArg}: Is a directory\x1b[0m\r\n`, newVwd: currentVwd };
          }
          const content = await fs.readFile(targetPath, "utf8");
          const lines = content.split(/\r?\n/);
          const selectedLines = command === "head" ? lines.slice(0, numLines) : lines.slice(-numLines);
          return { output: selectedLines.join("\r\n") + "\r\n", newVwd: currentVwd };
        } catch {
          return { output: `\x1b[31m${command}: ${fileArg}: No such file or directory\x1b[0m\r\n`, newVwd: currentVwd };
        }
      }

      case "mkdir": {
        let recursive = false;
        let dirArg = null;
        for (let i = 1; i < args.length; i++) {
          if (args[i] === "-p") recursive = true;
          else if (!args[i].startsWith("-")) dirArg = args[i];
        }

        if (!dirArg) {
          return { output: "\x1b[31mmkdir: missing operand\x1b[0m\r\n", newVwd: currentVwd };
        }

        const targetPath = resolveVirtualPath(currentVwd, dirArg);
        try {
          await fs.mkdir(targetPath, { recursive });
          return { output: "", newVwd: currentVwd };
        } catch (err) {
          return { output: `\x1b[31mmkdir: cannot create directory '${dirArg}': ${err.message}\x1b[0m\r\n`, newVwd: currentVwd };
        }
      }

      case "touch": {
        const fileArg = args[1];
        if (!fileArg) {
          return { output: "\x1b[31mtouch: missing file operand\x1b[0m\r\n", newVwd: currentVwd };
        }
        const targetPath = resolveVirtualPath(currentVwd, fileArg);
        try {
          const handle = await fs.open(targetPath, "a");
          await handle.close();
          const now = new Date();
          await fs.utimes(targetPath, now, now).catch(() => {});
          return { output: "", newVwd: currentVwd };
        } catch (err) {
          return { output: `\x1b[31mtouch: cannot touch '${fileArg}': ${err.message}\x1b[0m\r\n`, newVwd: currentVwd };
        }
      }

      default:
        return {
          output: `\x1b[31mCommand not allowed: '${command}'.\x1b[0m\r\n`,
          newVwd: currentVwd,
        };
    }
  } catch (err) {
    return { output: `\x1b[31mError executing ${command}: ${err.message}\x1b[0m\r\n`, newVwd: currentVwd };
  }
}

// Native zero-dependency RFC 6455 WebSocket helpers
function createWsFrame(text) {
  const payload = Buffer.from(text, "utf8");
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81; // FIN + text frame
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

function createWsCloseFrame(code = 1000, reason = "") {
  const reasonBuf = Buffer.from(reason, "utf8");
  const payload = Buffer.alloc(2 + reasonBuf.length);
  payload.writeUInt16BE(code, 0);
  reasonBuf.copy(payload, 2);
  const header = Buffer.from([0x88, payload.length]);
  return Buffer.concat([header, payload]);
}

function decodeWsFrames(buffer) {
  const messages = [];
  let offset = 0;

  while (offset + 2 <= buffer.length) {
    const firstByte = buffer[offset];
    const secondByte = buffer[offset + 1];
    const opcode = firstByte & 0x0f;
    const isMasked = (secondByte & 0x80) !== 0;
    let payloadLen = secondByte & 0x7f;
    let headerLen = 2;

    if (payloadLen === 126) {
      if (offset + 4 > buffer.length) break;
      payloadLen = buffer.readUInt16BE(offset + 2);
      headerLen = 4;
    } else if (payloadLen === 127) {
      if (offset + 10 > buffer.length) break;
      payloadLen = Number(buffer.readBigUInt64BE(offset + 2));
      headerLen = 10;
    }

    const maskLen = isMasked ? 4 : 0;
    const totalFrameLen = headerLen + maskLen + payloadLen;
    if (offset + totalFrameLen > buffer.length) break;

    if (opcode === 0x08) {
      messages.push({ type: "close" });
      offset += totalFrameLen;
      break;
    }

    if (opcode === 0x09) {
      messages.push({ type: "ping" });
      offset += totalFrameLen;
      continue;
    }

    const payloadStart = offset + headerLen + maskLen;
    const payload = Buffer.from(buffer.subarray(payloadStart, payloadStart + payloadLen));

    if (isMasked) {
      const mask = buffer.subarray(offset + headerLen, offset + headerLen + 4);
      for (let i = 0; i < payload.length; i++) {
        payload[i] ^= mask[i & 3];
      }
    }

    if (opcode === 0x01 || opcode === 0x02) {
      messages.push({ type: "data", text: payload.toString("utf8") });
    }

    offset += totalFrameLen;
  }

  return { messages, remaining: buffer.subarray(offset) };
}

const HTML_INTERFACE = `<!DOCTYPE html>
<html lang="ar" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
  <title>HyperSoft Web Terminal (127.0.0.1:6060)</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css" />
  <script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js"></script>
  <style>
    body { font-family: 'Cairo', sans-serif; }
    .xterm-viewport::-webkit-scrollbar { width: 8px; }
    .xterm-viewport::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col antialiased selection:bg-blue-600 selection:text-white overflow-hidden">
  <header class="h-14 border-b border-slate-800/80 bg-slate-900/90 backdrop-blur-md px-4 flex items-center justify-between z-10 shrink-0">
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded-lg bg-blue-600/20 text-blue-400 border border-blue-500/30 flex items-center justify-center font-bold text-sm">
        💻
      </div>
      <div>
        <h1 class="text-sm font-bold text-white leading-none">HyperSoft Web Terminal</h1>
        <p class="text-[10px] text-slate-400 mt-0.5">127.0.0.1:6060 - Cloudflare Tunnel Only</p>
      </div>
    </div>
    <div class="flex items-center gap-2">
      <div class="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-950 border border-slate-800">
        <span id="status-indicator" class="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
        <span id="status-text" class="text-xs font-semibold text-slate-300">غير متصل</span>
      </div>
      <button id="btn-logout" class="hidden px-3 py-1 rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 text-xs font-bold transition">خروج</button>
    </div>
  </header>

  <div id="auth-modal" class="fixed inset-0 z-50 bg-slate-950/95 backdrop-blur-md flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-md w-full shadow-2xl">
      <div class="text-center mb-6">
        <div class="w-12 h-12 bg-blue-600/20 text-blue-400 rounded-xl mx-auto flex items-center justify-center font-black text-xl mb-3">
          🔒
        </div>
        <h2 class="text-xl font-bold text-white">مصادقة Web Terminal</h2>
        <p class="text-xs text-slate-400 mt-1">أدخل بيانات الاعتماد للوصول إلى Terminal</p>
      </div>
      <form id="auth-form" class="space-y-4">
        <div>
          <label class="block text-xs font-bold text-slate-300 mb-1">اسم المستخدم</label>
          <input type="text" id="auth-user" required class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-blue-500 font-mono" placeholder="Username" />
        </div>
        <div>
          <label class="block text-xs font-bold text-slate-300 mb-1">كلمة المرور</label>
          <input type="password" id="auth-pass" required class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-blue-500 font-mono" placeholder="••••••••" />
        </div>
        <div id="auth-error" class="hidden text-xs text-red-400 font-bold bg-red-950/40 p-3 rounded-xl border border-red-800/40"></div>
        <button type="submit" id="btn-submit-login" class="w-full py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm transition shadow-lg shadow-blue-600/20">
          تسجيل الدخول
        </button>
      </form>
    </div>
  </div>

  <div class="bg-slate-900/60 border-b border-slate-800/60 px-3 py-1.5 flex items-center gap-2 overflow-x-auto text-xs shrink-0">
    <button onclick="sendQuickCmd('pwd')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs">pwd</button>
    <button onclick="sendQuickCmd('ls -la')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs">ls -la</button>
    <button onclick="sendQuickCmd('cd /')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs">cd /</button>
    <button onclick="sendQuickCmd('whoami')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs">whoami</button>
    <button onclick="sendQuickCmd('help')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-400 font-mono text-xs font-bold">help</button>
    <button onclick="sendQuickCmd('clear')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs">clear</button>
  </div>

  <main class="flex-1 relative flex flex-col p-2 bg-slate-950">
    <div id="terminal-container" class="flex-1 rounded-xl border border-slate-800/80 overflow-hidden relative"></div>
  </main>

  <script>
    let term = null;
    let fitAddon = null;
    let socket = null;

    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const authModal = document.getElementById('auth-modal');
    const authForm = document.getElementById('auth-form');
    const authError = document.getElementById('auth-error');
    const btnLogout = document.getElementById('btn-logout');

    function initTerminal() {
      if (term) return;
      term = new Terminal({
        cursorBlink: true,
        cursorStyle: 'block',
        fontSize: 14,
        fontFamily: 'JetBrains Mono, monospace',
        theme: {
          background: '#090d16',
          foreground: '#e2e8f0',
          cursor: '#38bdf8',
          selectionBackground: '#0284c740',
          black: '#1e293b',
          red: '#f87171',
          green: '#4ade80',
          yellow: '#facc15',
          blue: '#60a5fa',
          magenta: '#c084fc',
          cyan: '#38bdf8',
          white: '#f1f5f9'
        }
      });

      fitAddon = new FitAddon.FitAddon();
      term.loadAddon(fitAddon);
      term.open(document.getElementById('terminal-container'));
      fitAddon.fit();

      window.addEventListener('resize', () => {
        if (fitAddon) fitAddon.fit();
      });

      term.onData((data) => {
        if (socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: 'input', data }));
        }
      });
    }

    function setStatus(state, text) {
      statusIndicator.className = 'w-2.5 h-2.5 rounded-full ' + (
        state === 'connected' ? 'bg-emerald-500 shadow-lg shadow-emerald-500/50 animate-pulse' :
        state === 'connecting' ? 'bg-amber-500 animate-pulse' : 'bg-rose-500'
      );
      statusText.textContent = text;
      if (state === 'connected') {
        btnLogout.classList.remove('hidden');
      } else {
        btnLogout.classList.add('hidden');
      }
    }

    function sendQuickCmd(cmd) {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'input', data: cmd + '\\r' }));
      }
    }

    async function checkSession() {
      try {
        const res = await fetch('/api/session');
        const data = await res.json();
        if (data.authenticated) {
          authModal.classList.add('hidden');
          connectWebSocket();
        } else {
          authModal.classList.remove('hidden');
        }
      } catch {
        authModal.classList.remove('hidden');
      }
    }

    function connectWebSocket() {
      if (socket) socket.close();

      initTerminal();
      setStatus('connecting', 'جاري الاتصال...');

      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = protocol + '//' + location.host + '/ws';

      socket = new WebSocket(wsUrl);

      socket.onopen = () => {
        setStatus('connected', 'متصل (بيئة محصنة)');
        authModal.classList.add('hidden');
        term.focus();
      };

      socket.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'output') {
            term.write(msg.data);
          }
        } catch {
          term.write(event.data);
        }
      };

      socket.onclose = (e) => {
        if (e.code === 4001) {
          setStatus('disconnected', 'يتطلب تسجيل الدخول');
          authModal.classList.remove('hidden');
          authError.textContent = 'انتهت الجلسة، يرجى إعادة تسجيل الدخول.';
          authError.classList.remove('hidden');
        } else {
          setStatus('disconnected', 'غير متصل');
        }
      };

      socket.onerror = () => {
        setStatus('disconnected', 'خطأ في الاتصال');
      };
    }

    authForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      authError.classList.add('hidden');
      const user = document.getElementById('auth-user').value;
      const pass = document.getElementById('auth-pass').value;

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: user, password: pass })
        });
        const data = await res.json();
        if (res.ok && data.ok) {
          authModal.classList.add('hidden');
          connectWebSocket();
        } else {
          authError.textContent = data.error || 'اسم المستخدم أو كلمة المرور غير صحيحة';
          authError.classList.remove('hidden');
        }
      } catch {
        authError.textContent = 'فشل الاتصال بخدمة المصادقة';
        authError.classList.remove('hidden');
      }
    });

    btnLogout.addEventListener('click', async () => {
      await fetch('/api/logout', { method: 'POST' });
      if (socket) socket.close();
      setStatus('disconnected', 'تم تسجيل الخروج');
      authModal.classList.remove('hidden');
    });

    checkSession();
  </script>
</body>
</html>`;

export function isWebTerminalRunning() {
  return terminalServer !== null && terminalServer.listening;
}

export function startWebTerminalService() {
  try {
    getCloudflaredBinaryPath();
  } catch {}
  if (isWebTerminalRunning()) {
    return Promise.resolve(terminalServer);
  }

  return new Promise((resolve, reject) => {
    terminalServer = createServer(async (req, res) => {
      const clientIp = getClientIp(req);
      const urlObj = new URL(req.url || "/", `http://${HOST}:${PORT}`);

      const sendJson = (status, data, extraHeaders = {}) => {
        res.writeHead(status, {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          ...extraHeaders,
        });
        res.end(JSON.stringify(data));
      };

      if (req.method === "GET" && urlObj.pathname === "/api/session") {
        const auth = getAuthFromReq(req);
        if (auth) {
          return sendJson(200, { authenticated: true, username: auth.username });
        }
        return sendJson(200, { authenticated: false });
      }

      if (req.method === "POST" && urlObj.pathname === "/api/login") {
        if (!checkRateLimit(clientIp)) {
          return sendJson(429, { error: "عدد المحاولات الخاطئة كبير جداً. حاول بعد 15 دقيقة." });
        }

        let body = "";
        req.on("data", (chunk) => {
          if (body.length < 16384) body += chunk;
        });
        req.on("end", () => {
          try {
            const parsed = JSON.parse(body || "{}");
            const inputUser = String(parsed.username || "").trim();
            const inputPass = String(parsed.password || "");

            const expectedUser = String(process.env.WEB_TERMINAL_USERNAME || "").trim();
            const expectedPass = String(process.env.WEB_TERMINAL_PASSWORD || "");

            if (!expectedUser || !expectedPass) {
              return sendJson(503, { error: "بيانات اعتماد Web Terminal غير مهيأة في الخادم" });
            }

            const userMatch =
              inputUser.length === expectedUser.length &&
              crypto.timingSafeEqual(Buffer.from(inputUser), Buffer.from(expectedUser));

            const passMatch =
              inputPass.length === expectedPass.length &&
              crypto.timingSafeEqual(Buffer.from(inputPass), Buffer.from(expectedPass));

            if (userMatch && passMatch) {
              recordLoginAttempt(clientIp, true);
              const token = generateSessionToken(inputUser);
              const isHttps = req.headers["x-forwarded-proto"] === "https";
              const cookieHeader = `${SESSION_COOKIE_NAME}=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400${isHttps ? "; Secure" : ""}`;
              return sendJson(200, { ok: true, username: inputUser }, { "Set-Cookie": cookieHeader });
            } else {
              recordLoginAttempt(clientIp, false);
              return sendJson(401, { error: "اسم المستخدم أو كلمة المرور غير صحيحة" });
            }
          } catch {
            return sendJson(400, { error: "صيغة الطلب غير صالحة" });
          }
        });
        return;
      }

      if (req.method === "POST" && urlObj.pathname === "/api/logout") {
        const cookieHeader = `${SESSION_COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0`;
        return sendJson(200, { ok: true }, { "Set-Cookie": cookieHeader });
      }

      if (req.method === "POST" && urlObj.pathname === "/api/exec") {
        const auth = getAuthFromReq(req);
        if (!auth) {
          return sendJson(401, { error: "غير مصرح به - يجب تسجيل الدخول أولاً" });
        }

        let body = "";
        req.on("data", (chunk) => {
          if (body.length < 32768) body += chunk;
        });
        req.on("end", async () => {
          try {
            const parsed = JSON.parse(body || "{}");
            const cmd = String(parsed.command || "");
            const currentVwd = String(parsed.vwd || ROOT_FS);

            const result = await executeTerminalCommand(cmd, {
              vwd: currentVwd,
              username: auth.username,
            });

            return sendJson(200, {
              output: result.output,
              vwd: result.newVwd,
              clearScreen: result.clearScreen || false,
            });
          } catch (err) {
            return sendJson(500, { error: err.message });
          }
        });
        return;
      }

      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      });
      res.end(HTML_INTERFACE);
    });

    terminalServer.on("upgrade", (req, socket) => {
      const urlObj = new URL(req.url || "/", `http://${HOST}:${PORT}`);
      if (urlObj.pathname !== "/ws") {
        socket.destroy();
        return;
      }

      const key = req.headers["sec-websocket-key"];
      if (!key) {
        socket.destroy();
        return;
      }

      const acceptKey = crypto
        .createHash("sha1")
        .update(key + WS_GUID)
        .digest("base64");

      socket.write(
        [
          "HTTP/1.1 101 Switching Protocols",
          "Upgrade: websocket",
          "Connection: Upgrade",
          `Sec-WebSocket-Accept: ${acceptKey}`,
          "\r\n",
        ].join("\r\n")
      );

      activeSockets.add(socket);
      socket.on("close", () => activeSockets.delete(socket));
      socket.on("error", () => activeSockets.delete(socket));

      const sendWsJson = (obj) => {
        if (!socket.destroyed) {
          socket.write(createWsFrame(JSON.stringify(obj)));
        }
      };

      const auth = getAuthFromReq(req);
      if (!auth) {
        sendWsJson({ type: "output", data: "\r\n\x1b[31m[Error]: Unauthorized. Please log in.\x1b[0m\r\n" });
        socket.write(createWsCloseFrame(4001, "Unauthorized"));
        socket.end();
        return;
      }

      const sessionState = {
        vwd: ROOT_FS,
        username: auth.username,
        inputBuffer: "",
        history: [],
        historyIndex: -1,
      };

      const prompt = () => `\r\n\x1b[1;32m${sessionState.username}@hypersoft\x1b[0m:\x1b[1;34m${sessionState.vwd}\x1b[0m$ `;

      sendWsJson({
        type: "output",
        data: `\x1b[1;36mWelcome to HyperSoft Standalone Web Terminal (Node.js Native Engine)\x1b[0m\r\nType '\x1b[1;33mhelp\x1b[0m' to list allowed commands.${prompt()}`,
      });

      let frameBuffer = Buffer.alloc(0);

      socket.on("data", async (chunk) => {
        frameBuffer = Buffer.concat([frameBuffer, chunk]);
        const decoded = decodeWsFrames(frameBuffer);
        frameBuffer = decoded.remaining;

        for (const msg of decoded.messages) {
          if (msg.type === "close") {
            socket.end();
            return;
          }
          if (msg.type === "ping") {
            socket.write(Buffer.from([0x8a, 0x00]));
            continue;
          }
          if (msg.type === "data") {
            let rawInput = "";
            try {
              const parsed = JSON.parse(msg.text);
              if (parsed.type === "input") rawInput = String(parsed.data || "");
            } catch {
              rawInput = msg.text;
            }

            for (let i = 0; i < rawInput.length; i++) {
              const char = rawInput[i];
              if (char === "\r" || char === "\n") {
                const cmdToExec = sessionState.inputBuffer.trim();
                sendWsJson({ type: "output", data: "\r\n" });

                if (cmdToExec) {
                  sessionState.history.push(cmdToExec);
                  sessionState.historyIndex = sessionState.history.length;

                  const res = await executeTerminalCommand(cmdToExec, sessionState);
                  sessionState.vwd = res.newVwd;

                  if (res.clearScreen) {
                    sendWsJson({ type: "output", data: "\x1bc" + prompt() });
                  } else {
                    sendWsJson({ type: "output", data: res.output + prompt() });
                  }
                } else {
                  sendWsJson({ type: "output", data: prompt() });
                }
                sessionState.inputBuffer = "";
              } else if (char === "\x7f" || char === "\b") {
                if (sessionState.inputBuffer.length > 0) {
                  sessionState.inputBuffer = sessionState.inputBuffer.slice(0, -1);
                  sendWsJson({ type: "output", data: "\b \b" });
                }
              } else if (char === "\x03") {
                sessionState.inputBuffer = "";
                sendWsJson({ type: "output", data: "^C" + prompt() });
              } else if (char >= " " && char <= "~") {
                sessionState.inputBuffer += char;
                sendWsJson({ type: "output", data: char });
              }
            }
          }
        }
      });
    });

    terminalServer
      .listen(PORT, HOST, () => {
        console.log(`[terminal 6060] Web Terminal listening on ${HOST}:${PORT}`);
        resolve(terminalServer);
      })
      .on("error", (err) => {
        console.error(`[terminal 6060] Failed to listen on ${HOST}:${PORT}:`, err.message);
        terminalServer = null;
        reject(err);
      });
  });
}

export function stopWebTerminalService() {
  if (!isWebTerminalRunning()) {
    return Promise.resolve();
  }

  stopCloudflareTunnelService();

  for (const sock of activeSockets) {
    try {
      sock.destroy();
    } catch {}
  }
  activeSockets.clear();

  return new Promise((resolve) => {
    if (terminalServer) {
      terminalServer.close(() => {
        console.log("[terminal 6060] Web Terminal stopped successfully.");
        terminalServer = null;
        resolve();
      });
    } else {
      resolve();
    }
  });
}
