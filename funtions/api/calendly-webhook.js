// functions/api/calendly-webhook.js
// Receives Calendly "invitee.created" and "invitee.canceled" messages,
// checks they are genuine, and saves them to the Supabase "orders" table.
//
// Secrets needed in Cloudflare (Settings > Variables and Secrets):
//   SUPABASE_URL          e.g. https://abcdxyz.supabase.co
//   SUPABASE_SERVICE_KEY  the service_role key (keep private)
//   CALENDLY_SIGNING_KEY  a long random string you make up (also used when creating the webhook)

const MAX_AGE_SECONDS = 300; // reject messages older than 5 minutes

function toHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function isGenuine(body, header, signingKey) {
  if (!header) return false;

  let t = "";
  let v1 = "";
  for (const piece of header.split(",")) {
    const i = piece.indexOf("=");
    const key = piece.slice(0, i).trim();
    const value = piece.slice(i + 1).trim();
    if (key === "t") t = value;
    if (key === "v1") v1 = value;
  }
  if (!t || !v1) return false;

  const age = Math.abs(Date.now() / 1000 - Number(t));
  if (!Number.isFinite(age) || age > MAX_AGE_SECONDS) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(signingKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${t}.${body}`)
  );
  return safeEqual(toHex(signature), v1);
}

export async function onRequestPost({ request, env }) {
  const body = await request.text();

  const ok = await isGenuine(
    body,
    request.headers.get("Calendly-Webhook-Signature"),
    env.CALENDLY_SIGNING_KEY
  );
  if (!ok) return new Response("Invalid signature", { status: 401 });

  let message;
  try {
    message = JSON.parse(body);
  } catch {
    return new Response("Bad JSON", { status: 400 });
  }

  const data = message.payload || {};
  const supabaseHeaders = {
    apikey: env.SUPABASE_SERVICE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_KEY}`,
    "Content-Type": "application/json",
  };

  // Someone booked and paid
  if (message.event === "invitee.created") {
    const scheduled = data.scheduled_event || {};
    const start = scheduled.start_time ? new Date(scheduled.start_time) : null;
    const end = scheduled.end_time ? new Date(scheduled.end_time) : null;
    const minutes =
      start && end ? Math.round((end - start) / 60000) : null;

    const row = {
      calendly_invitee_uri: data.uri,
      customer_name: data.name || null,
      customer_email: data.email || null,
      session_name: scheduled.name || null,
      session_minutes: minutes,
      session_start: scheduled.start_time || null,
      amount_paid: data.payment ? data.payment.amount : null,
      currency: data.payment ? data.payment.currency : null,
      status: "booked",
    };

    const res = await fetch(
      `${env.SUPABASE_URL}/rest/v1/orders?on_conflict=calendly_invitee_uri`,
      {
        method: "POST",
        headers: {
          ...supabaseHeaders,
          Prefer: "resolution=ignore-duplicates,return=minimal",
        },
        body: JSON.stringify(row),
      }
    );

    if (!res.ok) {
      // Returning an error makes Calendly retry later
      return new Response("Database write failed", { status: 500 });
    }
    return new Response("Saved", { status: 200 });
  }

  // Someone canceled
  if (message.event === "invitee.canceled") {
    const res = await fetch(
      `${env.SUPABASE_URL}/rest/v1/orders?calendly_invitee_uri=eq.${encodeURIComponent(
        data.uri
      )}`,
      {
        method: "PATCH",
        headers: { ...supabaseHeaders, Prefer: "return=minimal" },
        body: JSON.stringify({ status: "canceled" }),
      }
    );
    if (!res.ok) return new Response("Database update failed", { status: 500 });
    return new Response("Updated", { status: 200 });
  }

  // Any other message type: acknowledge and ignore
  return new Response("Ignored", { status: 200 });
}

