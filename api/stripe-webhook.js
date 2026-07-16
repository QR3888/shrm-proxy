/**
 * The Grey Gym — SHRM Proxy
 * api/stripe-webhook.js
 *
 * Receives Stripe webhook events and updates the user's subscription state in
 * Supabase. This is the ONLY thing that grants or revokes premium access.
 *
 * Security model (different from the other endpoints on purpose):
 *   - NO X-TGG-Auth header (Stripe cannot send it).
 *   - NO CORS allowlist (this is server-to-server, not browser traffic).
 *   - The ONLY trust check is Stripe's signature, verified against
 *     STRIPE_WEBHOOK_SECRET over the RAW request body.
 *
 * All secrets (STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, SUPABASE_URL,
 * SUPABASE_SERVICE_ROLE_KEY) come from environment variables only and are never
 * logged or returned. We log only the event type and the outcome.
 */

import Stripe from 'stripe';

// Disable Vercel's automatic body parsing so we can read the raw bytes that
// Stripe signed. Signature verification fails on a re-serialized JSON body.
export const config = {
  api: { bodyParser: false },
};

// ── Raw body reader ───────────────────────────────────────────────────────────
async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

// ── Supabase REST helper (service role, server-side only) ─────────────────────
// PATCHes the users table by the given PostgREST filter and returns the number
// of rows updated. Uses return=representation so we can tell if a row matched.
async function supabasePatchUsers(filter, patch) {
  const url = `${process.env.SUPABASE_URL}/rest/v1/users?${filter}`;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const resp = await fetch(url, {
    method: 'PATCH',
    headers: {
      'apikey':        key,
      'Authorization': `Bearer ${key}`,
      'Content-Type':  'application/json',
      'Prefer':        'return=representation',
    },
    body: JSON.stringify(patch),
  });
  if (!resp.ok) {
    // Log status only (never the key or full response); throw so the caller
    // returns 500 and Stripe retries.
    console.error('[webhook] Supabase PATCH failed with status:', resp.status);
    throw new Error('Supabase write failed');
  }
  const rows = await resp.json().catch(() => []);
  return Array.isArray(rows) ? rows.length : 0;
}

const toIso = (unixSeconds) =>
  (typeof unixSeconds === 'number' ? new Date(unixSeconds * 1000).toISOString() : null);

// Returns the subscription's current period end as an ISO timestamp, or null.
// Recent Stripe API versions moved current_period_end off the subscription root
// onto each subscription item, so we check the item first, then the root.
function subPeriodEndIso(sub) {
  if (!sub) return null;
  const itemEnd = sub.items?.data?.[0]?.current_period_end;
  return toIso(typeof itemEnd === 'number' ? itemEnd : sub.current_period_end);
}

// Returns true if the subscription is scheduled to cancel at period end.
// Stripe deprecated cancel_at_period_end: a Customer Portal "cancel at period
// end" is now expressed via cancel_at (a future timestamp) while the legacy
// boolean stays false. Read cancel_at first, then fall back to the legacy flag
// (same defensive pattern as subPeriodEndIso). Clicking "Don't cancel" sets
// cancel_at back to null, so this correctly returns false again.
function subCancelAtPeriodEnd(sub) {
  if (!sub) return false;
  return sub.cancel_at != null || sub.cancel_at_period_end === true;
}

const ACTIVE_STATUSES   = new Set(['active', 'trialing']);
const INACTIVE_STATUSES = new Set(['canceled', 'unpaid', 'incomplete_expired']);

// ── Handler ───────────────────────────────────────────────────────────────────
export default async function handler(req, res) {
  // Method guard — Stripe only ever POSTs.
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Required configuration (never hardcoded).
  const secretKey     = process.env.STRIPE_SECRET_KEY;
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secretKey || !webhookSecret || !process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('[webhook] Missing required environment configuration');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  const stripe = new Stripe(secretKey);

  // ── Signature verification over the RAW body ───────────────────────────────
  let event;
  try {
    const rawBody = await readRawBody(req);
    const sig     = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(rawBody, sig, webhookSecret);
  } catch (err) {
    // Never trust an unverified webhook.
    console.warn('[webhook] Signature verification failed:', err?.message || 'error');
    return res.status(400).json({ error: 'Invalid signature' });
  }

  // ── Event handling ─────────────────────────────────────────────────────────
  try {
    switch (event.type) {

      // ── User has paid: grant premium ───────────────────────────────────────
      case 'checkout.session.completed': {
        const session = event.data.object;
        const userId  = session.metadata?.userId || session.client_reference_id;
        const plan    = session.metadata?.plan || null;

        if (!userId) {
          console.warn('[webhook] checkout.session.completed with no userId — ignoring');
          return res.status(200).json({ received: true });
        }

        // The session only references the subscription by id, so retrieve the
        // full object to read its current period end. If this fails, periodEnd
        // stays null and we still grant premium with everything else below.
        let periodEnd = null;
        if (session.subscription) {
          try {
            const sub = await stripe.subscriptions.retrieve(session.subscription);
            periodEnd = subPeriodEndIso(sub);
          } catch (e) {
            console.warn('[webhook] could not retrieve subscription for period end:', e?.message || 'error');
          }
        }

        const updated = await supabasePatchUsers(`id=eq.${encodeURIComponent(userId)}`, {
          subscription_status:               'premium',
          stripe_customer_id:                session.customer || null,
          stripe_subscription_id:            session.subscription || null,
          subscription_plan:                 plan,
          subscription_period_end:           periodEnd,
          subscription_cancel_at_period_end: false,
        });

        if (updated === 0) {
          // Do not grant premium to a user we cannot identify; stop retries.
          console.warn('[webhook] checkout.session.completed: no user row matched userId');
          return res.status(200).json({ received: true });
        }
        console.log('[webhook] checkout.session.completed: premium granted');
        return res.status(200).json({ received: true });
      }

      // ── Subscription changed: sync period end / cancel flag / status ────────
      case 'customer.subscription.updated': {
        const sub   = event.data.object;
        const patch = {
          subscription_period_end:           subPeriodEndIso(sub),
          subscription_cancel_at_period_end: subCancelAtPeriodEnd(sub),
        };
        if (INACTIVE_STATUSES.has(sub.status))    patch.subscription_status = 'expired';
        else if (ACTIVE_STATUSES.has(sub.status)) patch.subscription_status = 'premium';
        // Other statuses (e.g. past_due) leave subscription_status unchanged —
        // access is only revoked on real cancellation/deletion.

        let updated = await supabasePatchUsers(`stripe_subscription_id=eq.${encodeURIComponent(sub.id)}`, patch);
        if (updated === 0 && sub.customer) {
          updated = await supabasePatchUsers(`stripe_customer_id=eq.${encodeURIComponent(sub.customer)}`, patch);
        }
        if (updated === 0) {
          console.warn('[webhook] customer.subscription.updated: no user row matched');
          return res.status(200).json({ received: true });
        }
        console.log('[webhook] customer.subscription.updated: synced,', 'status=' + sub.status + ', cancelAtPeriodEnd=' + patch.subscription_cancel_at_period_end);
        return res.status(200).json({ received: true });
      }

      // ── Subscription ended: revoke access ──────────────────────────────────
      case 'customer.subscription.deleted': {
        const sub   = event.data.object;
        const patch = {
          subscription_status:               'expired',
          subscription_cancel_at_period_end: false,
        };
        let updated = await supabasePatchUsers(`stripe_subscription_id=eq.${encodeURIComponent(sub.id)}`, patch);
        if (updated === 0 && sub.customer) {
          updated = await supabasePatchUsers(`stripe_customer_id=eq.${encodeURIComponent(sub.customer)}`, patch);
        }
        if (updated === 0) {
          console.warn('[webhook] customer.subscription.deleted: no user row matched');
          return res.status(200).json({ received: true });
        }
        console.log('[webhook] customer.subscription.deleted: access revoked');
        return res.status(200).json({ received: true });
      }

      // ── Payment failed: log only, do NOT revoke (Stripe retries) ───────────
      case 'invoice.payment_failed': {
        console.warn('[webhook] invoice.payment_failed — access retained; Stripe will retry billing');
        return res.status(200).json({ received: true });
      }

      // ── Everything else: acknowledge so Stripe does not retry ──────────────
      default: {
        console.log('[webhook] Ignoring event type:', event.type);
        return res.status(200).json({ received: true });
      }
    }
  } catch (err) {
    // A database (or other) failure: log and 500 so Stripe retries the event.
    console.error('[webhook] Handler error for', event.type + ':', err?.message || 'error');
    return res.status(500).json({ error: 'Webhook handler failed' });
  }
}
