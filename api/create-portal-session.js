/**
 * The Grey Gym — SHRM Proxy
 * api/create-portal-session.js
 *
 * Creates a Stripe Billing (Customer) Portal session so a signed-in user can
 * manage or cancel their subscription. Mirrors api/create-checkout-session.js
 * exactly for CORS, the X-TGG-Auth check, rate limiting, and error handling.
 * The stripe_customer_id is looked up server-side from Supabase using the
 * service role key; all secrets come from environment variables only.
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

// Where Stripe returns the user after they finish in the portal.
const RETURN_URL = 'https://shrm.thegreygym.com';

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
    console.warn('[portal] Rejected request from origin:', origin || '(none)');
    return res.status(403).json({ error: 'Forbidden' });
  }

  // ── Method guard ───────────────────────────────────────────────────────────
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ── Security 1: Check secret key is configured ─────────────────────────────
  const secretKey = process.env.STRIPE_SECRET_KEY;
  if (!secretKey || !process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('[portal] Missing required environment configuration');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  // ── Security 3: Shared secret header ──────────────────────────────────────
  const proxySecret = process.env.TGG_PROXY_SECRET;
  const authHeader  = req.headers['x-tgg-auth'];
  if (!proxySecret || !authHeader || authHeader !== proxySecret) {
    console.warn('[portal] Unauthorized request — invalid or missing X-TGG-Auth header');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // ── Security 4: Rate limiting ──────────────────────────────────────────────
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress
    || 'unknown';

  if (isRateLimited(ip)) {
    console.warn('[portal] Rate limit exceeded for IP:', ip);
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

  const { userId } = body || {};
  if (typeof userId !== 'string' || !userId.trim()) {
    return res.status(400).json({ error: 'userId string is required' });
  }

  // ── Look up the Stripe customer id from Supabase (service role) ─────────────
  let customerId;
  try {
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const url = `${process.env.SUPABASE_URL}/rest/v1/users`
      + `?id=eq.${encodeURIComponent(userId)}&select=stripe_customer_id`;
    const lookup = await fetch(url, {
      headers: {
        'apikey':        key,
        'Authorization': `Bearer ${key}`,
      },
    });
    if (!lookup.ok) {
      console.error('[portal] Supabase lookup failed with status:', lookup.status);
      return res.status(500).json({ error: 'Could not open the billing portal. Please try again.' });
    }
    const rows = await lookup.json().catch(() => []);
    customerId = Array.isArray(rows) && rows[0] ? rows[0].stripe_customer_id : null;
  } catch (err) {
    console.error('[portal] Supabase lookup error:', err?.message || err);
    return res.status(500).json({ error: 'Could not open the billing portal. Please try again.' });
  }

  if (!customerId) {
    return res.status(400).json({ error: 'No billing account found for this user' });
  }

  // ── Create the Stripe Billing Portal session ───────────────────────────────
  try {
    const stripe = new Stripe(secretKey);

    const session = await stripe.billingPortal.sessions.create({
      customer:   customerId,
      return_url: RETURN_URL,
    });

    // Return only the redirect URL — never the full session or anything sensitive
    return res.status(200).json({ url: session.url });

  } catch (err) {
    // Log server-side only; never forward Stripe internals or the key to client
    console.error('[portal] Stripe error creating portal session:', err?.message || err);
    return res.status(500).json({ error: 'Could not open the billing portal. Please try again.' });
  }
}
