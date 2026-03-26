// netlify/functions/send-otp.js
import { ok, err, opts } from "../../lib/security.js";
import { requireApiKey } from "../../lib/middleware.js";
import { getUserByEmail } from "../../lib/firebase-admin.js";
import { randomBytes } from "crypto";

// Simple in‑memory session store (replace with Redis/Firestore for production)
const sessions = new Map();

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return opts();
  if (event.httpMethod !== "POST") return err("Method not allowed", 405);

  // Validate API key
  const apiKeyAuth = await requireApiKey(event);
  if (apiKeyAuth.statusCode) return apiKeyAuth;

  const { email } = JSON.parse(event.body);
  if (!email) return err("Email required", 400);

  // Find user
  const user = await getUserByEmail(email);
  if (!user) return err("User not found", 404);
  if (!user.isActive) return err("Account disabled", 403);

  // Create session token
  const sessionToken = randomBytes(24).toString('hex');
  sessions.set(sessionToken, {
    uid: user.uid,
    email: user.email,
    createdAt: Date.now(),
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
  });

  // Build the authenticator URL
  const authPageUrl = `https://thenux-auth.netlify.app/authenticator?session=${sessionToken}&email=${encodeURIComponent(user.email)}`;

  return ok({
    otpSessionToken: sessionToken,
    authenticatorUrl: authPageUrl,
    message: "Redirect the user to this URL to see the OTP code."
  });
};
