const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin"
};

const MAX_LEN = {
  name: 80,
  phone: 16,
  age: 20,
  program: 80,
  preferredTime: 60,
  paymentMethod: 60,
  message: 500,
  lang: 5,
  userAgent: 260,
  turnstileToken: 2048
};

function cleanText(value, maxLength = 200) {
  return String(value == null ? "" : value).replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function escapeHtml(value) {
  return String(value == null ? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function jsonResponse(status, payload, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders }
  });
}

function isAllowedOrigin(request, env) {
  const origin = request.headers.get("Origin");
  const allowedOrigin = cleanText(env.ALLOWED_ORIGIN || "", 200);
  if (!origin || !allowedOrigin) return true;
  return origin === allowedOrigin;
}

function getClientIp(request) {
  const cfIp = cleanText(request.headers.get("CF-Connecting-IP"), 64);
  if (cfIp) return cfIp;
  return cleanText(request.headers.get("X-Forwarded-For"), 128).split(",")[0].trim();
}

async function verifyTurnstile(turnstileToken, request, env) {
  const secret = cleanText(env.TURNSTILE_SECRET, 200);
  if (!secret) return false;

  const ip = getClientIp(request);
  const formData = new URLSearchParams();
  formData.set("secret", secret);
  formData.set("response", turnstileToken);
  if (ip) formData.set("remoteip", ip);

  const verification = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formData.toString()
  });

  if (!verification.ok) return false;
  const result = await verification.json();
  return Boolean(result && result.success);
}

async function sendToTelegram(payload, env) {
  const botToken = cleanText(env.TELEGRAM_BOT_TOKEN, 300);
  const chatId = cleanText(env.TELEGRAM_CHAT_ID, 100);
  if (!botToken || !chatId) return false;

  const message = `
<b>🔴 طلب اشتراك جديد (Secure Worker)</b>

<b>👤 الاسم:</b> ${escapeHtml(payload.name)}
<b>📞 الهاتف:</b> ${escapeHtml(payload.phone)}
<b>🎂 العمر:</b> ${escapeHtml(payload.age || "—")}
<b>🏋️ البرنامج:</b> ${escapeHtml(payload.program)}
<b>⏰ الوقت المفضل:</b> ${escapeHtml(payload.preferredTime || "—")}
<b>💳 طريقة الدفع:</b> ${escapeHtml(payload.paymentMethod || "—")}
<b>💬 الملاحظة:</b> ${escapeHtml(payload.message || "—")}
<b>🌐 اللغة:</b> ${escapeHtml(payload.lang || "ar")}
<b>🧭 User-Agent:</b> ${escapeHtml(payload.userAgent || "unknown")}
  `.trim();

  const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
  const telegramRes = await fetch(telegramUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text: message,
      parse_mode: "HTML",
      disable_web_page_preview: true
    })
  });

  return telegramRes.ok;
}

function validatePayload(raw) {
  const name = cleanText(raw.name, MAX_LEN.name);
  const phone = cleanText(raw.phone, MAX_LEN.phone).replace(/[^\d+]/g, "").slice(0, MAX_LEN.phone);
  const age = cleanText(raw.age, MAX_LEN.age);
  const program = cleanText(raw.program, MAX_LEN.program);
  const preferredTime = cleanText(raw.preferredTime, MAX_LEN.preferredTime);
  const paymentMethod = cleanText(raw.paymentMethod, MAX_LEN.paymentMethod);
  const message = cleanText(raw.message, MAX_LEN.message);
  const lang = cleanText(raw.lang, MAX_LEN.lang).toLowerCase();
  const userAgent = cleanText(raw.userAgent, MAX_LEN.userAgent);
  const turnstileToken = cleanText(raw.turnstileToken, MAX_LEN.turnstileToken);

  const isValidPhone = /^\+?\d{8,15}$/.test(phone);
  if (!name || !phone || !program || !isValidPhone || !turnstileToken) {
    return null;
  }

  return {
    name,
    phone,
    age,
    program,
    preferredTime,
    paymentMethod,
    message,
    lang: lang === "en" ? "en" : "ar",
    userAgent,
    turnstileToken
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== "/api/lead") {
      return jsonResponse(404, { ok: false, error: "not_found" });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: JSON_HEADERS });
    }

    if (request.method !== "POST") {
      return jsonResponse(405, { ok: false, error: "method_not_allowed" }, { Allow: "POST, OPTIONS" });
    }

    if (!isAllowedOrigin(request, env)) {
      return jsonResponse(403, { ok: false, error: "forbidden_origin" });
    }

    let body;
    try {
      body = await request.json();
    } catch (_) {
      return jsonResponse(400, { ok: false, error: "invalid_json" });
    }

    const payload = validatePayload(body || {});
    if (!payload) {
      return jsonResponse(400, { ok: false, error: "invalid_payload" });
    }

    const turnstileOk = await verifyTurnstile(payload.turnstileToken, request, env);
    if (!turnstileOk) {
      return jsonResponse(403, { ok: false, error: "turnstile_failed" });
    }

    const telegramOk = await sendToTelegram(payload, env);
    if (!telegramOk) {
      return jsonResponse(502, { ok: false, error: "telegram_failed" });
    }

    return jsonResponse(200, { ok: true });
  }
};
