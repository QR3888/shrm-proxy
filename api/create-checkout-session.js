/**
 * The Grey Gym — SHRM Proxy
 * api/create-checkout-session.js
 *
 * Creates a Stripe Checkout Session for a subscription on behalf of the TGG app,
 * keeping STRIPE_SECRET_KEY exclusively server-side in Vercel environment
 * variables. The browser cannot call Stripe directly (that needs the secret
 * key), so it POSTs here and then redirects to the returned Checkout URL.
 *
 * Mirrors api/coach.js exactly for structure, env reading, CORS, shared-secret
 * auth, rate limiting, and non-leaking error handling.
 *
 * Security measures:
 *   1. Secret key from environment only — never logged, never sent to client
 *   2. Origin restriction — only accepts requests from the TGG app domain
 *   3. Shared secret header (X-TGG-Auth) — must match TGG_PROXY_SECRET env var
 *   4. In-memory rate limiting — max 10 requests per minute per IP address
 */

import Stripe from 'stripe';

// ── Constants ─────────────────────────────────────────────────────────────────

const ALLOWED_ORIGINS = new Set([
  'https://the-grey-gym-shrm-study-app.vercel.app',
  'https://shrm.thegreygym.com',
]);

// Stripe TEST-mode price IDs. plan -> price mapping (subscription).
const PRICE_IDS = {
  monthly: 'price_1TtVfuHRbRG3VPj5V4jVyvkM',
  annual:  'price_1TtVgcHRbRG3VPj5V7YeEWfB',
};

const SUCCESS_URL = 'https://shrm.thegreygym.com/?checkout=success';
const CANCEL_URL  = 'https://shrm.thegreygym.com/?checkout=cancelled';

// Rate limit: 10 requests per IP per rolling 60-second window
const RATE_LIMIT_MAX    = 10;
const RATE_LIMIT_WINDOW = 60 * 1000; // ms

// ── In-memory rate limit store ────────────────────────────────────────────────
// Map<ip: string, timestamps: number[]>
const rateLimitStore = new Map();

/**
 * Returns true if the given IP has exceeded the rate limit.
 * Side-effect: prunes stale timestamps and records the current request.
 */
function isRateLimited(ip) {
  const now  = Date.now();
  const hits = rateLimitStore.get(ip) || [];

  const recent = hits.filter(t => now - t < RATE_LIMIT_WINDOW);

  if (recent.length >= RATE_LIMIT_MAX) {
    rateLimitStore.set(ip, recent);
    return true;
  }

  recent.push(now);
  rateLimitStore.set(ip, recent);

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
    console.warn('[checkout] Rejected request from origin:', origin || '(none)');
    return res.status(403).json({ error: 'Forbidden' });
  }

  // ── Method guard ───────────────────────────────────────────────────────────
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ── Security 1: Check secret key is configured ─────────────────────────────
  const secretKey = process.env.STRIPE_SECRET_KEY;
  if (!secretKey) {
    console.error('[checkout] STRIPE_SECRET_KEY environment variable is not set');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  // ── Security 3: Shared secret header ──────────────────────────────────────
  const proxySecret = process.env.TGG_PROXY_SECRET;
  const authHeader  = req.headers['x-tgg-auth'];
  if (!proxySecret || !authHeader || authHeader !== proxySecret) {
    console.warn('[checkout] Unauthorized request — invalid or missing X-TGG-Auth header');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // ── Security 4: Rate limiting ──────────────────────────────────────────────
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress
    || 'unknown';

  if (isRateLimited(ip)) {
    console.warn('[checkout] Rate limit exceeded for IP:', ip);
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

  const { plan, userId, email } = body || {};

  const priceId = PRICE_IDS[plan];
  if (!priceId) {
    return res.status(400).json({ error: 'plan must be "monthly" or "annual"' });
  }
  if (typeof userId !== 'string' || !userId.trim()) {
    return res.status(400).json({ error: 'userId string is required' });
  }
  if (typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'A valid email is required' });
  }

  // ── Create the Stripe Checkout Session ─────────────────────────────────────
  try {
    const stripe = new Stripe(secretKey);

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      customer_email: email,
      client_reference_id: userId,
      metadata: { userId, plan },
      success_url: SUCCESS_URL,
      cancel_url:  CANCEL_URL,
    });

    // Return only the redirect URL — never the full session or anything sensitive
    return res.status(200).json({ url: session.url });

  } catch (err) {
    // Log server-side only; never forward Stripe internals or the key to client
    console.error('[checkout] Stripe error creating session:', err?.message || err);
    return res.status(502).json({ error: 'Could not start checkout. Please try again.' });
  }
}
