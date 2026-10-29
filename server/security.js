import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";

export const hashToken = (token) => createHash("sha256").update(token).digest("hex");
export const newToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const newId = () => randomUUID();

export async function hashPassword(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  });
}

export async function verifyPassword(hash, password) {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left ?? "");
  const rightBuffer = Buffer.from(right ?? "");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function validPassword(password) {
  return typeof password === "string" && password.length >= 12 && password.length <= 128;
}

export function publicUser(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    username: row.username,
    role: row.role,
    status: row.status,
    mustChangePassword: Boolean(row.must_change_password),
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at
  };
}

export function cookieOptions(production, maxAge) {
  return {
    httpOnly: true,
    secure: production,
    sameSite: "strict",
    path: "/",
    ...(maxAge ? { maxAge } : {})
  };
}

export function csrfCookieOptions(production, maxAge) {
  return {
    httpOnly: false,
    secure: production,
    sameSite: "strict",
    path: "/",
    ...(maxAge ? { maxAge } : {})
  };
}

export function readCookie(request, name) {
  const cookies = request.headers.cookie?.split(";") ?? [];
  for (const cookie of cookies) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
  return "";
}
