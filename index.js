import { request as proxyRequest } from "node:http";
import { createServer } from "node:https";
import { chmodSync, createReadStream, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import {
  isWebTerminalRunning,
  isCloudflareTunnelRunning,
  getCurrentTunnelUrl,
  startWebTerminalService,
  stopWebTerminalService,
  startCloudflareTunnelService,
  stopCloudflareTunnelService,
  restartCloudflareTunnelService,
  isCloudflaredAvailable,
} from "./web-terminal/server.mjs";

const root = fileURLToPath(new URL(".", import.meta.url));
const publicDir = join(root, "public");
const apiEntry = join(root, "api", "index.mjs");

function loadDotEnv() {
  const envPath = join(root, ".env");
  if (!existsSync(envPath)) return;

  for (const line of readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator <= 0) continue;

    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = value;
  }
}

loadDotEnv();

const publicPort = Number(process.env.PORT || process.env.SERVER_PORT || 20137);
const apiPort = 3001;
const publicUrl = (process.env.PUBLIC_URL || "https://51.75.118.17:20137").trim();
const mainSiteUrl = "https://51.75.118.17:20137/";
const controlPortalUrl = "https://51.75.118.17:20137/control-9k2x-portal";
const dataDir = join(root, "data");
const tlsKeyPath = join(root, "tls", "server.key");
const tlsCertPath = join(root, "tls", "server.crt");
try {
  chmodSync(tlsKeyPath, 0o600);
} catch {}
const tlsOptions = {
  key: readFileSync(tlsKeyPath),
  cert: readFileSync(tlsCertPath),
};

mkdirSync(join(dataDir, "uploads"), { recursive: true });

const apiProcess = spawn(process.execPath, [apiEntry], {
  cwd: root,
  env: {
    ...process.env,
    NODE_ENV: "production",
    PORT: String(apiPort),
  },
  stdio: ["ignore", "pipe", "pipe"],
});

apiProcess.stdout.on("data", (chunk) => process.stdout.write(`[api] ${chunk}`));
apiProcess.stderr.on("data", (chunk) => process.stderr.write(`[api] ${chunk}`));
apiProcess.on("error", (error) => {
  console.error("[api] process error", error instanceof Error ? error.message : error);
});
apiProcess.on("exit", (code, signal) => {
  console.error(`[api] process exited with code=${code ?? "null"} signal=${signal ?? "none"}`);
});

let shuttingDown = false;

const telegramBotToken = process.env.Telegram_BOT_TOKEN?.trim();
const telegramOwnerId = process.env.Telegram_OWNER_ID?.trim();
let telegramStopped = false;
let telegramOffset = 0;

function isTelegramOwner(id) {
  return Boolean(telegramOwnerId) && String(id) === telegramOwnerId;
}

async function telegramRequest(method, payload) {
  const response = await fetch(`https://api.telegram.org/bot${telegramBotToken}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok || !data?.ok) {
    throw new Error(`Telegram ${method} failed with status ${response.status}`);
  }
  return data.result;
}

async function sendTelegramMessage(chatId, text, replyMarkup) {
  return telegramRequest("sendMessage", {
    chat_id: chatId,
    text,
    ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
  });
}

function visitorMessage() {
  return `مرحباً بكم في موقع HyperSoft\nالموقع الرسمي:\n${mainSiteUrl}`;
}

function ownerReplyKeyboard() {
  return {
    keyboard: [
      [{ text: "🌐 حالة Web Terminal" }, { text: "🔗 عرض رابط Web Terminal" }],
      [{ text: "▶️ تشغيل النفق" }, { text: "⏹ إيقاف النفق" }],
      [{ text: "🔄 إعادة تشغيل النفق" }, { text: "🌐 رابط الموقع الرئيسي" }],
      [{ text: "⚙️ لوحة التحكم" }, { text: "📊 حالة الخادم" }],
    ],
    resize_keyboard: true,
    is_persistent: true,
  };
}

function ownerMenuText() {
  const terminalOnline = isWebTerminalRunning();
  const tunnelOnline = isCloudflareTunnelRunning();
  const tunnelUrl = getCurrentTunnelUrl();

  return [
    "لوحة التحكم الخاصة بمالك HyperSoft",
    "",
    `🌐 الموقع الرئيسي: ${mainSiteUrl}`,
    `⚙️ لوحة التحكم: ${controlPortalUrl}`,
    `💻 Web Terminal (127.0.0.1:6060): ${terminalOnline ? "🟢 يعمل" : "🔴 متوقف"}`,
    `☁️ Cloudflare Quick Tunnel: ${tunnelOnline ? "🟢 متصل" : "🔴 متوقف"}`,
    `🔗 رابط Web Terminal: ${tunnelOnline && tunnelUrl ? tunnelUrl : "غير متاح (النفق متوقف)"}`,
  ].join("\n");
}

function webTerminalStatusText() {
  const terminalOnline = isWebTerminalRunning();
  const tunnelOnline = isCloudflareTunnelRunning();
  const tunnelUrl = getCurrentTunnelUrl();

  return [
    "🌐 حالة Web Terminal والنفق:",
    "",
    `💻 الخدمة الداخلية (127.0.0.1:6060): ${terminalOnline ? "🟢 نشطة" : "🔴 متوقفة"}`,
    `☁️ Cloudflare Quick Tunnel: ${tunnelOnline ? "🟢 متصل" : "🔴 متوقف"}`,
    `🔗 الرابط الحالي: ${tunnelOnline && tunnelUrl ? tunnelUrl : "غير متاح (النفق متوقف)"}`,
  ].join("\n");
}

function serverStatusText() {
  const terminalOnline = isWebTerminalRunning();
  const tunnelOnline = isCloudflareTunnelRunning();

  return [
    "📊 حالة الخادم - HyperSoft:",
    "",
    `🟢 الخادم العام: يعمل (Port ${publicPort})`,
    `🟢 الـ API الداخلي: يعمل (Port ${apiPort})`,
    `💻 Web Terminal (127.0.0.1:6060): ${terminalOnline ? "🟢 يعمل" : "🔴 متوقف"}`,
    `☁️ Cloudflare Tunnel: ${tunnelOnline ? "🟢 متصل" : "🔴 متوقف"}`,
    `🌐 الموقع الرئيسي: ${mainSiteUrl}`,
  ].join("\n");
}

async function sendOwnerMenu(chatId) {
  return telegramRequest("sendMessage", {
    chat_id: chatId,
    text: ownerMenuText(),
    reply_markup: ownerReplyKeyboard(),
  });
}

async function executeOwnerAction(chatId, action) {
  const keyboard = ownerReplyKeyboard();

  if (action === "terminal_status") {
    return sendTelegramMessage(chatId, webTerminalStatusText(), keyboard);
  }

  if (action === "get_terminal_url") {
    const url = getCurrentTunnelUrl();
    if (isCloudflareTunnelRunning() && url) {
      return sendTelegramMessage(
        chatId,
        `🔗 رابط Web Terminal الحالي:\n\n${url}`,
        keyboard
      );
    }
    return sendTelegramMessage(
      chatId,
      "⚠️ النفق متوقف حالياً ولا يوجد رابط نشط.\nاضغط على «▶️ تشغيل النفق» لتوليد رابط جديد.",
      keyboard
    );
  }

  if (action === "start_tunnel") {
    if (!isWebTerminalRunning()) {
      try {
        await startWebTerminalService();
      } catch (err) {
        return sendTelegramMessage(
          chatId,
          `❌ تعذر تشغيل خدمة Web Terminal الداخلية على 127.0.0.1:6060: ${err instanceof Error ? err.message : err}`,
          keyboard
        );
      }
    }

    if (isCloudflareTunnelRunning() && getCurrentTunnelUrl()) {
      return sendTelegramMessage(
        chatId,
        `✅ النفق يعمل بالفعل!\n\n🔗 رابط Web Terminal:\n${getCurrentTunnelUrl()}`,
        keyboard
      );
    }

    if (!isCloudflaredAvailable()) {
      return sendTelegramMessage(
        chatId,
        "⚠️ أداة cloudflared غير متوفرة حالياً على الخادم.",
        keyboard
      );
    }

    await sendTelegramMessage(chatId, "⏳ جاري تشغيل Cloudflare Quick Tunnel نحو http://127.0.0.1:6060 ...", keyboard);
    const url = await startCloudflareTunnelService();
    if (url) {
      return sendTelegramMessage(
        chatId,
        `✅ تم تشغيل النفق بنجاح!\n\n🔗 رابط Web Terminal:\n${url}`,
        keyboard
      );
    }
    return sendTelegramMessage(chatId, "❌ تعذر الحصول على رابط trycloudflare.com.", keyboard);
  }

  if (action === "stop_tunnel") {
    if (!isCloudflareTunnelRunning()) {
      return sendTelegramMessage(chatId, "ℹ️ النفق متوقف بالفعل.", keyboard);
    }
    await stopCloudflareTunnelService();
    return sendTelegramMessage(chatId, "⏹ تم إيقاف Cloudflare Quick Tunnel وإلغاء الرابط المؤقت.", keyboard);
  }

  if (action === "restart_tunnel") {
    if (!isWebTerminalRunning()) {
      try {
        await startWebTerminalService();
      } catch {}
    }
    if (!isCloudflaredAvailable()) {
      return sendTelegramMessage(
        chatId,
        "⚠️ أداة cloudflared غير متوفرة حالياً على الخادم.",
        keyboard
      );
    }
    await sendTelegramMessage(chatId, "⏳ جاري إعادة تشغيل Cloudflare Quick Tunnel...", keyboard);
    const url = await restartCloudflareTunnelService();
    if (url) {
      return sendTelegramMessage(
        chatId,
        `🔄 تم إعادة تشغيل النفق بنجاح!\n\n🔗 الرابط الجديد:\n${url}`,
        keyboard
      );
    }
    return sendTelegramMessage(chatId, "❌ فشل إعادة تشغيل Cloudflare Quick Tunnel.", keyboard);
  }

  if (action === "main_site_url") {
    return sendTelegramMessage(chatId, `🌐 رابط الموقع الرئيسي:\n${mainSiteUrl}`, keyboard);
  }

  if (action === "control_panel_url") {
    return sendTelegramMessage(chatId, `⚙️ رابط لوحة التحكم:\n${controlPortalUrl}`, keyboard);
  }

  if (action === "server_status") {
    return sendTelegramMessage(chatId, serverStatusText(), keyboard);
  }

  return sendOwnerMenu(chatId);
}

async function handleOwnerMessage(message) {
  const chatId = message.chat.id;
  const text = typeof message.text === "string" ? message.text.trim() : "";

  if (text === "/start" || text === "/menu" || text === "/help") {
    return sendOwnerMenu(chatId);
  }
  if (text === "🌐 حالة Web Terminal") {
    return executeOwnerAction(chatId, "terminal_status");
  }
  if (text === "🔗 عرض رابط Web Terminal") {
    return executeOwnerAction(chatId, "get_terminal_url");
  }
  if (text === "▶️ تشغيل النفق") {
    return executeOwnerAction(chatId, "start_tunnel");
  }
  if (text === "⏹ إيقاف النفق") {
    return executeOwnerAction(chatId, "stop_tunnel");
  }
  if (text === "🔄 إعادة تشغيل النفق") {
    return executeOwnerAction(chatId, "restart_tunnel");
  }
  if (text === "🌐 رابط الموقع الرئيسي" || text === "/url") {
    return executeOwnerAction(chatId, "main_site_url");
  }
  if (text === "⚙️ لوحة التحكم") {
    return executeOwnerAction(chatId, "control_panel_url");
  }
  if (text === "📊 حالة الخادم" || text === "/status" || text === "الحالة") {
    return executeOwnerAction(chatId, "server_status");
  }

  return sendOwnerMenu(chatId);
}

async function handleTelegramUpdate(update) {
  if (update.message) {
    const message = update.message;
    if (!isTelegramOwner(message.from?.id)) {
      return sendTelegramMessage(message.chat.id, visitorMessage());
    }
    return handleOwnerMessage(message);
  }

  if (update.callback_query) {
    const callback = update.callback_query;
    const owner = isTelegramOwner(callback.from?.id);
    await telegramRequest("answerCallbackQuery", { callback_query_id: callback.id });
    if (!owner) {
      if (callback.message?.chat?.id) {
        await sendTelegramMessage(callback.message.chat.id, visitorMessage());
      }
      return;
    }

    const chatId = callback.message?.chat?.id;
    if (!chatId) return;

    const action = callback.data;
    if (action === "get_url") return executeOwnerAction(chatId, "main_site_url");
    if (action === "get_status") return executeOwnerAction(chatId, "server_status");
    return executeOwnerAction(chatId, action);
  }
}

async function telegramPollingLoop() {
  while (!shuttingDown && !telegramStopped) {
    try {
      const updates = await telegramRequest("getUpdates", {
        offset: telegramOffset,
        timeout: 25,
        allowed_updates: ["message", "callback_query"],
      });
      for (const update of updates ?? []) {
        telegramOffset = update.update_id + 1;
        await handleTelegramUpdate(update);
      }
    } catch (error) {
      if (!shuttingDown && !telegramStopped) {
        console.error("[telegram] polling failed", error instanceof Error ? error.message : error);
        await new Promise((resolve) => setTimeout(resolve, 5000));
      }
    }
  }
}

let telegramPollingStarted = false;

async function startTelegramBot() {
  if (!telegramBotToken || !telegramOwnerId) {
    console.log("[telegram] bot disabled; Telegram_BOT_TOKEN or Telegram_OWNER_ID is missing");
    return;
  }

  const isPollingDisabled =
    process.env.DISABLE_TELEGRAM_POLLING === "true" ||
    process.env.DISABLE_TELEGRAM_POLLING === "1";
  if (isPollingDisabled) {
    console.log("[telegram] bot polling disabled by DISABLE_TELEGRAM_POLLING=true");
    return;
  }

  if (telegramPollingStarted) return;
  telegramPollingStarted = true;

  try {
    await telegramRequest("deleteWebhook", { drop_pending_updates: true });
    console.log("[telegram] Arabic control bot is running");
    telegramPollingLoop().catch((error) => {
      console.error("[telegram] polling stopped", error instanceof Error ? error.message : error);
    });
  } catch (error) {
    console.error("[telegram] startup failed", error instanceof Error ? error.message : error);
  }
}

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
};

function serveStatic(req, res) {
  const rawPath = new URL(req.url || "/", "http://localhost").pathname;
  const decodedPath = decodeURIComponent(rawPath);
  const rootAsset = decodedPath === "/Logo.png" ? join(root, "Logo.png") : null;
  const requested = normalize(join(publicDir, decodedPath));
  const safeRelative = relative(publicDir, requested);
  const isSafe =
    safeRelative &&
    !safeRelative.startsWith("..") &&
    !safeRelative.includes(`..${process.platform === "win32" ? "\\" : "/"}`);
  const candidate =
    (rootAsset && existsSync(rootAsset) && statSync(rootAsset).isFile() && rootAsset) ||
    (isSafe && existsSync(requested) && statSync(requested).isFile()
      ? requested
      : join(publicDir, "index.html"));

  if (!existsSync(candidate)) {
    res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Frontend build is missing.");
    return;
  }

  res.writeHead(200, {
    "Content-Type": contentTypes[extname(candidate).toLowerCase()] || "application/octet-stream",
    "Cache-Control": candidate.endsWith("index.html")
      ? "no-cache"
      : "public, max-age=31536000, immutable",
  });
  createReadStream(candidate).pipe(res);
}

const server = createServer(tlsOptions, (req, res) => {
  if ((req.url || "").startsWith("/api")) {
    const upstream = proxyRequest(
      {
        hostname: "127.0.0.1",
        port: apiPort,
        path: req.url,
        method: req.method,
        headers: {
          ...req.headers,
          host: `127.0.0.1:${apiPort}`,
          "x-internal-client-ip": (req.socket?.remoteAddress || "127.0.0.1").replace(/^::ffff:/, ""),
        },
      },
      (upstreamResponse) => {
        res.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
        upstreamResponse.pipe(res);
      }
    );
    upstream.on("error", (error) => {
      console.error("[proxy] API connection failed", error instanceof Error ? error.message : error);
      if (!res.headersSent) res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "API server is unavailable" }));
    });
    req.pipe(upstream);
    return;
  }

  try {
    serveStatic(req, res);
  } catch {
    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Bad request");
  }
});

server.listen(publicPort, "0.0.0.0", () => {
  console.log(`HyperSoft is listening on port ${publicPort}`);
  console.log(`API is proxied internally on port ${apiPort}`);
  console.log(`Official Domain: ${publicUrl}`);

  startWebTerminalService()
    .then(() => {
      console.log("Web Terminal internal service is ready on 127.0.0.1:6060");
    })
    .catch((error) => {
      console.error("Web Terminal startup failed", error instanceof Error ? error.message : error);
    });

  startTelegramBot().catch((error) => {
    console.error("Telegram startup failed", error);
  });
});

function shutdown(signal) {
  console.log(`Received ${signal}; stopping HyperSoft.`);
  shuttingDown = true;
  telegramStopped = true;
  stopCloudflareTunnelService().catch(() => {});
  stopWebTerminalService().catch(() => {});
  server.close();
  apiProcess.kill("SIGTERM");
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
