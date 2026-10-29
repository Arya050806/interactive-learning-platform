import { createDatabase, writeAudit } from "./db.js";
import { hashPassword, validPassword } from "./security.js";

const email = process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;

if (!email || !validPassword(password)) {
  console.error("Set BOOTSTRAP_ADMIN_EMAIL and a BOOTSTRAP_ADMIN_PASSWORD of at least 12 characters.");
  process.exitCode = 1;
} else {
  const db = createDatabase();
  try {
    const admin = db.prepare("SELECT id, status FROM users WHERE email = ? COLLATE NOCASE AND role = 'admin'").get(email);
    if (!admin || admin.status !== "active") {
      console.error("No active administrator matches that email. No account was changed.");
      process.exitCode = 1;
    } else {
      const now = new Date().toISOString();
      db.prepare("UPDATE users SET password_hash = ?, must_change_password = 1, updated_at = ? WHERE id = ?")
        .run(await hashPassword(password), now, admin.id);
      db.prepare("DELETE FROM sessions WHERE user_id = ?").run(admin.id);
      writeAudit(db, admin.id, "admin.password_recovered", admin.id);
      console.log("Administrator password updated. Existing sessions were revoked; change the password after sign-in.");
    }
  } catch (cause) {
    console.error("Administrator recovery failed.");
    throw cause;
  } finally {
    db.close();
  }
}
