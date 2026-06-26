/**
 * The Grey Gym — SHRM Proxy
 * api/coach.js
 *
 * Secure proxy for Coach TGG AI requests.
 * Calls the Anthropic Messages API on behalf of the TGG app, keeping the
 * ANTHROPIC_API_KEY exclusively server-side in Vercel environment variables.
 *
 * Security measures:
 *   1. API key from environment only — never logged, never sent to client
 *   2. Origin restriction — only accepts requests from the TGG app domain
 *   3. Shared secret header (X-TGG-Auth) — must match TGG_PROXY_SECRET env var
 *   4. In-memory rate limiting — max 10 requests per minute per IP address
 */

// ── Constants ─────────────────────────────────────────────────────────────────

const ALLOWED_ORIGINS = new Set([
  'https://the-grey-gym-shrm-study-app.vercel.app',
  'https://shrm.thegreygym.com',
]);
const ANTHROPIC_URL   = 'https://api.anthropic.com/v1/messages';
const ANTHROPIC_MODEL_DEFAULT = 'claude-haiku-4-5-20251001';
const ANTHROPIC_MODELS_ALLOWED = new Set([
  'claude-haiku-4-5-20251001',
  'claude-sonnet-4-5',
  'claude-sonnet-4-6',
]);
const MAX_TOKENS_DEFAULT = 400;

// Rate limit: 10 requests per IP per rolling 60-second window
const RATE_LIMIT_MAX    = 10;
const RATE_LIMIT_WINDOW = 60 * 1000; // ms

// ── In-memory rate limit store ────────────────────────────────────────────────
// Map<ip: string, timestamps: number[]>
// Vercel serverless functions can share in-memory state across requests routed
// to the same instance, providing meaningful throttling at low traffic volumes.
// (Not a hard guarantee — a fresh instance starts with an empty map.)
const rateLimitStore = new Map();

/**
 * Returns true if the given IP has exceeded the rate limit.
 * Side-effect: prunes stale timestamps and records the current request.
 */
function isRateLimited(ip) {
  const now  = Date.now();
  const hits = rateLimitStore.get(ip) || [];

  // Drop timestamps outside the rolling window
  const recent = hits.filter(t => now - t < RATE_LIMIT_WINDOW);

  if (recent.length >= RATE_LIMIT_MAX) {
    // Update store with pruned list (don't record this blocked request)
    rateLimitStore.set(ip, recent);
    return true;
  }

  // Record this request and save
  recent.push(now);
  rateLimitStore.set(ip, recent);

  // Periodically clean up IPs with no recent activity to prevent memory growth
  if (rateLimitStore.size > 500) {
    for (const [key, timestamps] of rateLimitStore) {
      if (timestamps.every(t => now - t >= RATE_LIMIT_WINDOW)) {
        rateLimitStore.delete(key);
      }
    }
  }

  return false;
}

// ── CORS headers helper ───────────────────────────────────────────────────────
function setCorsHeaders(res, origin) {
  // Reflect the request origin only if it is in the allowlist
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-TGG-Auth');
  res.setHeader('Vary', 'Origin');
}

// ── Handler ───────────────────────────────────────────────────────────────────
export default async function handler(req, res) {
  // ── CORS preflight ─────────────────────────────────────────────────────────
  const origin = req.headers['origin'] || '';
  if (req.method === 'OPTIONS') {
    setCorsHeaders(res, origin);
    return res.status(204).end();
  }

  setCorsHeaders(res, origin);

  // ── Security 2: Origin check ───────────────────────────────────────────────
  if (!ALLOWED_ORIGINS.has(origin)) {
    console.warn('[coach] Rejected request from origin:', origin || '(none)');
    return res.status(403).json({ error: 'Forbidden' });
  }

  // ── Method guard ───────────────────────────────────────────────────────────
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ── Security 1: Check API key is configured ────────────────────────────────
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('[coach] ANTHROPIC_API_KEY environment variable is not set');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  // ── Security 3: Shared secret header ──────────────────────────────────────
  const proxySecret = process.env.TGG_PROXY_SECRET;
  const authHeader  = req.headers['x-tgg-auth'];
  if (!proxySecret || !authHeader || authHeader !== proxySecret) {
    console.warn('[coach] Unauthorized request — invalid or missing X-TGG-Auth header');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // ── Security 4: Rate limiting ──────────────────────────────────────────────
  // Prefer X-Forwarded-For (set by Vercel's edge) over req.socket.remoteAddress
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress
    || 'unknown';

  if (isRateLimited(ip)) {
    console.warn('[coach] Rate limit exceeded for IP:', ip);
    res.setHeader('Retry-After', '60');
    return res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
  }

  // ── Parse and validate request body ───────────────────────────────────────
  let body;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  const { messages, system, max_tokens, model } = body || {};

  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'messages array is required' });
  }
  if (typeof system !== 'string' || !system.trim()) {
    return res.status(400).json({ error: 'system prompt string is required' });
  }
  if (model !== undefined && !ANTHROPIC_MODELS_ALLOWED.has(model)) {
    return res.status(400).json({ error: 'Invalid model' });
  }

  const resolvedModel     = model || ANTHROPIC_MODEL_DEFAULT;
  const resolvedMaxTokens = (Number.isInteger(max_tokens) && max_tokens > 0 && max_tokens <= 2048)
    ? max_tokens
    : MAX_TOKENS_DEFAULT;

  // ── Call Anthropic Messages API ────────────────────────────────────────────
  try {
    const anthropicResp = await fetch(ANTHROPIC_URL, {
      method:  'POST',
      headers: {
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01',
        'content-type':      'application/json',
      },
      body: JSON.stringify({
        model:      resolvedModel,
        max_tokens: resolvedMaxTokens,
        system,
        messages,
      }),
    });

    if (!anthropicResp.ok) {
      // Log status server-side but never forward Anthropic's raw error to client
      console.error('[coach] Anthropic API returned status:', anthropicResp.status);
      return res.status(502).json({ error: 'AI service error. Please try again.' });
    }

    const data = await anthropicResp.json();
    return res.status(200).json(data);

  } catch (err) {
    console.error('[coach] Unexpected error calling Anthropic:', err?.message || err);
    return res.status(502).json({ error: 'AI service error. Please try again.' });
  }
}
