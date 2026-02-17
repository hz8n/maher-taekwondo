const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Frame-Options": "DENY"
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
  turnstileToken: 2048,
  reviewLevel: 24,
  reviewProgram: 60,
  reviewComment: 450
};

const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 12;
const DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60;
const DEFAULT_MAX_BODY_BYTES = 8192;
const DEFAULT_REVIEWS_MAX_BODY_BYTES = 4096;
const DEFAULT_REVIEWS_MAX_ITEMS = 300;
const REVIEWS_KV_KEY = "maher_reviews_v1";
const REVIEW_ALLOWED_LEVELS = new Set(["beginner", "intermediate", "advanced"]);

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

function getPositiveInt(value, fallback) {
  const num = Number.parseInt(String(value == null ? "" : value), 10);
  if (!Number.isFinite(num) || num <= 0) return fallback;
  return num;
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

async function applyIpRateLimit(request, env, scope = "default") {
  const ip = getClientIp(request) || "unknown";
  const windowSeconds = getPositiveInt(env.RATE_LIMIT_WINDOW_SECONDS, DEFAULT_RATE_LIMIT_WINDOW_SECONDS);
  const maxRequests = getPositiveInt(env.RATE_LIMIT_MAX_REQUESTS, DEFAULT_RATE_LIMIT_MAX_REQUESTS);
  const now = Math.floor(Date.now() / 1000);

  const cache = caches.default;
  const cacheKey = new Request(
    `https://rate-limit.local/${encodeURIComponent(scope)}/${encodeURIComponent(ip)}`
  );
  let state = {
    count: 0,
    resetAt: now + windowSeconds
  };

  try {
    const cached = await cache.match(cacheKey);
    if (cached) {
      const parsed = await cached.json();
      const cachedCount = Number(parsed && parsed.count);
      const cachedResetAt = Number(parsed && parsed.resetAt);
      if (Number.isFinite(cachedCount) && Number.isFinite(cachedResetAt)) {
        state = { count: cachedCount, resetAt: cachedResetAt };
      }
    }
  } catch (_) {
    // Fail open if cache lookup fails.
    return { allowed: true, retryAfter: 0, limit: maxRequests, remaining: maxRequests };
  }

  if (state.resetAt <= now) {
    state = { count: 0, resetAt: now + windowSeconds };
  }

  state.count += 1;
  const retryAfter = Math.max(1, state.resetAt - now);
  const allowed = state.count <= maxRequests;
  const remaining = Math.max(0, maxRequests - state.count);

  try {
    await cache.put(
      cacheKey,
      new Response(JSON.stringify(state), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": `max-age=${retryAfter}`
        }
      })
    );
  } catch (_) {
    // Ignore cache write errors.
  }

  return { allowed, retryAfter, limit: maxRequests, remaining };
}

async function parseJsonBody(request, maxBodyBytes) {
  const contentType = cleanText(request.headers.get("Content-Type"), 120).toLowerCase();
  if (!contentType.includes("application/json")) {
    return { ok: false, status: 415, error: "unsupported_media_type" };
  }

  const contentLength = getPositiveInt(request.headers.get("Content-Length"), 0);
  if (contentLength > maxBodyBytes) {
    return { ok: false, status: 413, error: "payload_too_large" };
  }

  try {
    const raw = await request.text();
    if (raw.length > maxBodyBytes) {
      return { ok: false, status: 413, error: "payload_too_large" };
    }
    const body = JSON.parse(raw);
    return { ok: true, body };
  } catch (_) {
    return { ok: false, status: 400, error: "invalid_json" };
  }
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
<b>New Join Request (Secure Worker)</b>

<b>Name:</b> ${escapeHtml(payload.name)}
<b>Phone:</b> ${escapeHtml(payload.phone)}
<b>Age:</b> ${escapeHtml(payload.age || "-")}
<b>Program:</b> ${escapeHtml(payload.program)}
<b>Preferred Time:</b> ${escapeHtml(payload.preferredTime || "-")}
<b>Payment Method:</b> ${escapeHtml(payload.paymentMethod || "-")}
<b>Note:</b> ${escapeHtml(payload.message || "-")}
<b>Language:</b> ${escapeHtml(payload.lang || "ar")}
<b>User-Agent:</b> ${escapeHtml(payload.userAgent || "unknown")}
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

function normalizeReviewEntry(raw) {
  if (!raw || typeof raw !== "object") return null;

  const age = Math.round(Number(raw.age));
  const level = cleanText(raw.level, MAX_LEN.reviewLevel).toLowerCase();
  const programAr = cleanText(raw.programAr, MAX_LEN.reviewProgram);
  const programEn = cleanText(raw.programEn, MAX_LEN.reviewProgram);
  const commentAr = cleanText(raw.commentAr, MAX_LEN.reviewComment);
  const commentEn = cleanText(raw.commentEn, MAX_LEN.reviewComment);
  const createdAtRaw = cleanText(raw.createdAt, 40);
  const createdAt = Number.isNaN(Date.parse(createdAtRaw)) ? "" : new Date(createdAtRaw).toISOString();

  if (!Number.isFinite(age) || age < 6 || age > 40) return null;
  if (!REVIEW_ALLOWED_LEVELS.has(level)) return null;
  if (!programAr || !programEn) return null;
  if (!commentAr && !commentEn) return null;

  return {
    id: cleanText(raw.id, 80) || crypto.randomUUID(),
    age,
    level,
    programAr,
    programEn,
    commentAr: commentAr || commentEn,
    commentEn: commentEn || commentAr,
    createdAt: createdAt || new Date().toISOString()
  };
}

function validateReviewPayload(raw) {
  const age = Math.round(Number(raw && raw.age));
  const level = cleanText(raw && raw.level, MAX_LEN.reviewLevel).toLowerCase();
  const programAr = cleanText(raw && raw.programAr, MAX_LEN.reviewProgram);
  const programEn = cleanText(raw && raw.programEn, MAX_LEN.reviewProgram);
  const commentRaw = cleanText(raw && raw.comment, MAX_LEN.reviewComment);
  const commentAr = cleanText(raw && raw.commentAr, MAX_LEN.reviewComment) || commentRaw;
  const commentEn = cleanText(raw && raw.commentEn, MAX_LEN.reviewComment) || commentRaw || commentAr;

  if (!Number.isFinite(age) || age < 6 || age > 40) return null;
  if (!REVIEW_ALLOWED_LEVELS.has(level)) return null;
  if (!programAr || !programEn) return null;
  if (!commentAr && !commentEn) return null;

  return {
    id: crypto.randomUUID(),
    age,
    level,
    programAr,
    programEn,
    commentAr: commentAr || commentEn,
    commentEn: commentEn || commentAr,
    createdAt: new Date().toISOString()
  };
}

function getReviewsLimit(env) {
  const maxItems = getPositiveInt(env.REVIEWS_MAX_ITEMS, DEFAULT_REVIEWS_MAX_ITEMS);
  return Math.max(20, Math.min(1000, maxItems));
}

async function readReviewsFromKv(env) {
  if (!env || !env.REVIEWS_KV || typeof env.REVIEWS_KV.get !== "function") return null;

  try {
    const raw = await env.REVIEWS_KV.get(REVIEWS_KV_KEY, "json");
    if (!Array.isArray(raw)) return [];
    return raw.map(normalizeReviewEntry).filter(Boolean);
  } catch (_) {
    return [];
  }
}

async function writeReviewsToKv(env, reviews) {
  if (!env || !env.REVIEWS_KV || typeof env.REVIEWS_KV.put !== "function") return false;
  try {
    await env.REVIEWS_KV.put(REVIEWS_KV_KEY, JSON.stringify(reviews));
    return true;
  } catch (_) {
    return false;
  }
}

async function handleLeadRequest(request, env) {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: JSON_HEADERS });
  }

  if (request.method !== "POST") {
    return jsonResponse(405, { ok: false, error: "method_not_allowed" }, { Allow: "POST, OPTIONS" });
  }

  if (!isAllowedOrigin(request, env)) {
    return jsonResponse(403, { ok: false, error: "forbidden_origin" });
  }

  const rate = await applyIpRateLimit(request, env, "lead");
  if (!rate.allowed) {
    return jsonResponse(
      429,
      { ok: false, error: "rate_limited" },
      {
        "Retry-After": String(rate.retryAfter),
        "X-RateLimit-Limit": String(rate.limit),
        "X-RateLimit-Remaining": String(rate.remaining)
      }
    );
  }

  const maxBodyBytes = getPositiveInt(env.MAX_BODY_BYTES, DEFAULT_MAX_BODY_BYTES);
  const parsed = await parseJsonBody(request, maxBodyBytes);
  if (!parsed.ok) {
    return jsonResponse(parsed.status, { ok: false, error: parsed.error });
  }

  const payload = validatePayload(parsed.body || {});
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

async function handleReviewsRequest(request, env) {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: JSON_HEADERS });
  }

  if (request.method === "GET") {
    const reviews = await readReviewsFromKv(env);
    if (reviews === null) {
      return jsonResponse(200, { ok: true, reviews: [], configured: false });
    }

    reviews.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return jsonResponse(200, { ok: true, reviews: reviews.slice(0, getReviewsLimit(env)), configured: true });
  }

  if (request.method !== "POST") {
    return jsonResponse(405, { ok: false, error: "method_not_allowed" }, { Allow: "GET, POST, OPTIONS" });
  }

  if (!isAllowedOrigin(request, env)) {
    return jsonResponse(403, { ok: false, error: "forbidden_origin" });
  }

  if (!env || !env.REVIEWS_KV || typeof env.REVIEWS_KV.get !== "function") {
    return jsonResponse(503, { ok: false, error: "reviews_store_not_configured" });
  }

  const rate = await applyIpRateLimit(request, env, "reviews");
  if (!rate.allowed) {
    return jsonResponse(
      429,
      { ok: false, error: "rate_limited" },
      {
        "Retry-After": String(rate.retryAfter),
        "X-RateLimit-Limit": String(rate.limit),
        "X-RateLimit-Remaining": String(rate.remaining)
      }
    );
  }

  const maxBodyBytes = getPositiveInt(env.REVIEWS_MAX_BODY_BYTES, DEFAULT_REVIEWS_MAX_BODY_BYTES);
  const parsed = await parseJsonBody(request, maxBodyBytes);
  if (!parsed.ok) {
    return jsonResponse(parsed.status, { ok: false, error: parsed.error });
  }

  const payload = validateReviewPayload(parsed.body || {});
  if (!payload) {
    return jsonResponse(400, { ok: false, error: "invalid_payload" });
  }

  const existingReviews = await readReviewsFromKv(env);
  const merged = [payload, ...(Array.isArray(existingReviews) ? existingReviews : [])]
    .map(normalizeReviewEntry)
    .filter(Boolean)
    .slice(0, getReviewsLimit(env));

  const saved = await writeReviewsToKv(env, merged);
  if (!saved) {
    return jsonResponse(502, { ok: false, error: "reviews_store_write_failed" });
  }

  return jsonResponse(201, { ok: true, review: payload });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/lead") {
      return handleLeadRequest(request, env);
    }

    if (url.pathname === "/api/reviews") {
      return handleReviewsRequest(request, env);
    }

    return jsonResponse(404, { ok: false, error: "not_found" });
  }
};
