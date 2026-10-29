import { createDatabase, writeAudit } from "./db.js";
import { hashPassword, newId, validPassword } from "./security.js";

const { BOOTSTRAP_ADMIN_NAME: fullName, BOOTSTRAP_ADMIN_EMAIL: emailValue,
  BOOTSTRAP_ADMIN_USERNAME: usernameValue, BOOTSTRAP_ADMIN_PASSWORD: password } = process.env;
const email = emailValue?.trim().toLowerCase();
const username = usernameValue?.trim();

if (!fullName?.trim() || fullName.trim().length > 120 || !email ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 ||
    !username || !/^[a-zA-Z0-9._-]{3,32}$/.test(username) || !validPassword(password)) {
  console.error("Set BOOTSTRAP_ADMIN_NAME, BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_USERNAME, and a BOOTSTRAP_ADMIN_PASSWORD of at least 12 characters.");
  process.exitCode = 1;
} else {
  const db = createDatabase();
  try {
    const existing = db.prepare("SELECT id, role FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE")
      .get(email, username);
    if (existing) {
      if (existing.role !== "admin") {
        console.error("The bootstrap email or username belongs to a non-administrator account. No changes were made.");
        process.exitCode = 1;
      } else {
        console.log("Administrator already exists; no changes made.");
      }
    } else {
      const now = new Date().toISOString();
      const id = newId();
      db.prepare(`
        INSERT INTO users (id, full_name, email, username, password_hash, role, status, must_change_password, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'admin', 'active', 0, ?, ?)
      `).run(id, fullName.trim(), email, username, await hashPassword(password), now, now);
      writeAudit(db, id, "admin.bootstrapped", id);
      console.log("Initial administrator created.");
    }
  } catch (cause) {
    if (cause.code === "SQLITE_CONSTRAINT_UNIQUE") {
      console.error("The administrator email or username is already in use. No changes were made.");
      process.exitCode = 1;
    } else {
      throw cause;
    }
  } finally {
    db.close();
  }
}
