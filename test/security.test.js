import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "../server/app.js";
import { courseModules } from "../server/course.js";
import { createDatabase } from "../server/db.js";
import { hashPassword, verifyPassword } from "../server/security.js";

let server;
let db;
let baseUrl;
let tempDirectory;
let adminId;
const adminPassword = "Admin test passphrase 482!";

function client() {
  const cookies = new Map();
  let csrfToken = "";
  const call = async (path, { method = "GET", body, headers = {} } = {}) => {
    const requestHeaders = { ...headers };
    if (cookies.size) requestHeaders.Cookie = [...cookies].map(([key, value]) => `${key}=${value}`).join("; ");
    if (body !== undefined) requestHeaders["Content-Type"] = "application/json";
    if (["POST", "PATCH", "DELETE"].includes(method) && csrfToken) requestHeaders["X-CSRF-Token"] = csrfToken;
    const response = await fetch(`${baseUrl}/api${path}`, {
      method,
      headers: requestHeaders,
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    for (const header of response.headers.getSetCookie()) {
      const [pair] = header.split(";");
      const splitAt = pair.indexOf("=");
      cookies.set(pair.slice(0, splitAt), pair.slice(splitAt + 1));
    }
    const payload = response.status === 204 ? null : await response.json();
    if (payload?.csrfToken) csrfToken = payload.csrfToken;
    return { response, payload };
  };
  return {
    call,
    async login(identifier, password) {
      const csrf = await call("/auth/csrf");
      csrfToken = csrf.payload.csrfToken;
      return call("/auth/login", { method: "POST", body: { identifier, password } });
    }
  };
}

async function addUser({ name, email, username, role, password }) {
  const now = new Date().toISOString();
  const id = randomUUID();
  db.prepare(`
    INSERT INTO users (id, full_name, email, username, password_hash, role, status, must_change_password, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, 'active', 0, ?, ?)
  `).run(id, name, email, username, await hashPassword(password), role, now, now);
  return id;
}

before(async () => {
  tempDirectory = mkdtempSync(join(tmpdir(), "medlearn-security-"));
  db = createDatabase(join(tempDirectory, "test.sqlite"));
  adminId = await addUser({
    name: "Test Administrator", email: "admin@example.test", username: "test.admin",
    role: "admin", password: adminPassword
  });
  server = createApp({ db, production: false }).listen(0, "127.0.0.1");
  await new Promise(resolve => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise(resolve => server.close(resolve));
  db?.close();
  if (tempDirectory) rmSync(tempDirectory, { recursive: true, force: true });
});

test("unauthenticated requests are denied and public registration does not exist", async () => {
  const visitor = client();
  const protectedPage = await visitor.call("/admin/users");
  assert.equal(protectedPage.response.status, 401);
  const csrfFailure = await visitor.call("/auth/login", { method: "POST", body: { identifier: "anyone", password: "wrong" } });
  assert.equal(csrfFailure.response.status, 403);
  const registration = await visitor.call("/auth/register", { method: "POST", body: { email: "anyone@example.test" } });
  assert.equal(registration.response.status, 404);
  const health = await visitor.call("/health");
  assert.equal(health.response.status, 200);
});

test("administrators create hashed student accounts; temporary passwords are one-time and must be changed", async () => {
  const administrator = client();
  await administrator.login("test.admin", adminPassword);
  const result = await administrator.call("/admin/users", {
    method: "POST",
    body: { fullName: "Taylor Student", email: "taylor@example.test", username: "taylor.student", role: "student" }
  });
  assert.equal(result.response.status, 201);
  assert.equal(result.payload.user.role, "student");
  assert.equal(result.payload.user.mustChangePassword, true);
  assert.equal(Object.hasOwn(result.payload.user, "password_hash"), false);
  const stored = db.prepare("SELECT password_hash, must_change_password FROM users WHERE id = ?").get(result.payload.user.id);
  assert.match(stored.password_hash, /^\$argon2id\$/);
  assert.notEqual(stored.password_hash, result.payload.temporaryPassword);
  const student = client();
  const loggedIn = await student.login("taylor.student", result.payload.temporaryPassword);
  assert.equal(loggedIn.response.status, 200);
  assert.equal(loggedIn.payload.user.mustChangePassword, true);
  const changed = await student.call("/auth/change-password", {
    method: "POST",
    body: { newPassword: "Taylor secure passphrase 928!" }
  });
  assert.equal(changed.response.status, 200);
  assert.equal(changed.payload.user.mustChangePassword, false);
  assert.equal(db.prepare("SELECT must_change_password FROM users WHERE id = ?").get(result.payload.user.id).must_change_password, 0);
});

test("students and instructors cannot create users, elevate roles, or access administrator records", async () => {
  const studentId = await addUser({
    name: "Other Student", email: "other@example.test", username: "other.student",
    role: "student", password: "Other student passphrase 325!"
  });
  const instructorId = await addUser({
    name: "Test Instructor", email: "instructor@example.test", username: "test.instructor",
    role: "instructor", password: "Instructor secure passphrase 825!"
  });
  const otherStudentId = await addUser({
    name: "Another Student", email: "another.student@example.test", username: "another.student",
    role: "student", password: "Another student passphrase 314!"
  });
  const privateSubmissionId = randomUUID();
  const now = new Date().toISOString();
  db.prepare("INSERT INTO submissions (id, user_id, module_id, response, submitted_at) VALUES (?, ?, 'foundations', ?, ?)")
    .run(privateSubmissionId, otherStudentId, "Private response", now);
  db.prepare("INSERT INTO progress (user_id, module_id, completed, updated_at) VALUES (?, 'foundations', 1, ?)")
    .run(otherStudentId, now);
  const student = client();
  await student.login("other.student", "Other student passphrase 325!");
  assert.equal((await student.call("/admin/users")).response.status, 403);
  assert.equal((await student.call("/admin/users", {
    method: "POST", body: { fullName: "Admin", email: "new@example.test", username: "newadmin", role: "admin" }
  })).response.status, 403);
  assert.equal((await student.call(`/admin/users/${studentId}`, {
    method: "PATCH", body: { role: "admin" }
  })).response.status, 403);
  const privateRecords = await student.call(`/me/records?userId=${otherStudentId}`);
  assert.equal(privateRecords.response.status, 200);
  assert.deepEqual(privateRecords.payload.submissions, []);
  assert.deepEqual(privateRecords.payload.quizzes, []);
  const ownProgress = await student.call("/me/progress");
  assert.deepEqual(ownProgress.payload.progress, []);
  const instructor = client();
  await instructor.login("test.instructor", "Instructor secure passphrase 825!");
  assert.equal((await instructor.call("/admin/users")).response.status, 403);
  assert.equal((await instructor.call("/admin/users", {
    method: "POST", body: { fullName: "Promoted", email: "promoted@example.test", username: "promoted", role: "admin" }
  })).response.status, 403);
  assert.equal(db.prepare("SELECT role FROM users WHERE id = ?").get(studentId).role, "student");
  assert.equal(db.prepare("SELECT role FROM users WHERE id = ?").get(instructorId).role, "instructor");
});

test("invalid credentials are generic and inactive accounts cannot authenticate", async () => {
  const visitor = client();
  const invalid = await visitor.login("missing@example.test", "some wrong password");
  assert.equal(invalid.response.status, 401);
  assert.match(invalid.payload.error, /Invalid username\/email or password/);
  const id = await addUser({
    name: "Disabled Student", email: "disabled@example.test", username: "disabled.student",
    role: "student", password: "Disabled account passphrase 46!"
  });
  db.prepare("UPDATE users SET status = 'inactive' WHERE id = ?").run(id);
  const disabled = await client().login("disabled.student", "Disabled account passphrase 46!");
  assert.equal(disabled.response.status, 401);
  assert.equal(disabled.payload.error, invalid.payload.error);
});

test("syllabus migration preserves user learning data and custom lessons", () => {
  const migrationPath = join(tempDirectory, "syllabus-migration.sqlite");
  const beforeMigration = createDatabase(migrationPath);
  const now = new Date().toISOString();
  const userId = randomUUID();
  beforeMigration.prepare(`
    INSERT INTO users (id, full_name, email, username, password_hash, role, created_at, updated_at)
    VALUES (?, 'Migration Student', ?, ?, 'test-hash', 'student', ?, ?)
  `).run(userId, `${userId}@example.test`, `migration.${userId.slice(0, 8)}`, now, now);
  beforeMigration.prepare("INSERT INTO progress (user_id, module_id, completed, updated_at) VALUES (?, 'foundations', 1, ?)")
    .run(userId, now);
  beforeMigration.prepare(`
    INSERT INTO lessons (id, module_id, title, content, position, created_at, updated_at)
    VALUES ('custom-preserved', 'foundations', 'Instructor addition', 'Keep this lesson', 99, ?, ?)
  `).run(now, now);
  beforeMigration.prepare("UPDATE lessons SET title = 'Outdated seeded lesson' WHERE id = 'seed-foundations-lesson-1'").run();
  beforeMigration.prepare("DELETE FROM schema_migrations WHERE version = 3").run();
  beforeMigration.prepare("DELETE FROM schema_migrations WHERE version = 4").run();
  beforeMigration.close();

  const migrated = createDatabase(migrationPath);
  assert.equal(migrated.prepare("SELECT COUNT(*) AS count FROM users WHERE id = ?").get(userId).count, 1);
  assert.equal(migrated.prepare("SELECT completed FROM progress WHERE user_id = ? AND module_id = 'foundations'").get(userId).completed, 1);
  assert.equal(migrated.prepare("SELECT title FROM lessons WHERE id = 'custom-preserved'").get().title, "Instructor addition");
  assert.equal(migrated.prepare("SELECT title FROM lessons WHERE id = 'seed-foundations-lesson-1'").get().title,
    courseModules[0].lessons[0].title);
  assert.equal(migrated.prepare("SELECT weeks FROM modules WHERE id = 'foundations'").get().weeks, "I");
  const storedModule = migrated.prepare("SELECT short_questions_json FROM modules WHERE id = 'foundations'").get();
  assert.equal(JSON.parse(storedModule.short_questions_json).length, 5);
  const storedLesson = migrated.prepare("SELECT lesson_details_json, video_json FROM lessons WHERE id = 'seed-foundations-lesson-1'").get();
  assert.ok(JSON.parse(storedLesson.lesson_details_json).objectives.length);
  assert.equal(JSON.parse(storedLesson.video_json).verified, false);
  migrated.close();
});

test("deactivation revokes active sessions and the last administrator cannot be disabled", async () => {
  const administrator = client();
  await administrator.login("admin@example.test", adminPassword);
  const created = await administrator.call("/admin/users", {
    method: "POST",
    body: { fullName: "Revocable User", email: "revoke@example.test", username: "revoke.user", role: "student" }
  });
  const student = client();
  await student.login("revoke.user", created.payload.temporaryPassword);
  assert.equal((await student.call("/auth/change-password", {
    method: "POST",
    body: { newPassword: "Revocable user passphrase 482!" }
  })).response.status, 200);
  assert.equal((await student.call("/course/modules")).response.status, 200);
  const deactivated = await administrator.call(`/admin/users/${created.payload.user.id}`, {
    method: "PATCH", body: { status: "inactive" }
  });
  assert.equal(deactivated.response.status, 200);
  assert.equal((await student.call("/course/modules")).response.status, 401);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?").get(created.payload.user.id).count, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE actor_id = ? AND action = 'user.deactivated' AND target_user_id = ?")
    .get(adminId, created.payload.user.id).count, 1);
  const lastAdmin = await administrator.call(`/admin/users/${adminId}`, { method: "PATCH", body: { status: "inactive" } });
  assert.equal(lastAdmin.response.status, 409);
  assert.equal(db.prepare("SELECT status FROM users WHERE id = ?").get(adminId).status, "active");
  assert.equal((await administrator.call("/auth/logout", { method: "POST" })).response.status, 204);
  assert.equal((await administrator.call("/auth/session")).response.status, 401);
});

test("quiz answers are scored server-side and responses never reveal answer keys", async () => {
  const administrator = client();
  await administrator.login("admin@example.test", adminPassword);
  const adminModules = await administrator.call("/admin/modules");
  assert.equal(adminModules.response.status, 200);
  assert.equal(adminModules.payload.modules[0].lessons.length, courseModules[0].lessons.length);
  assert.equal(adminModules.payload.modules[0].shortQuestions.length, 5);
  assert.equal(Object.hasOwn(adminModules.payload.modules[0].quiz[0], "answer"), true);
  const moduleEdit = await administrator.call("/admin/modules/foundations", {
    method: "PATCH",
    body: {
      assignmentDetails: {
        ...adminModules.payload.modules[0].assignmentDetails,
        overview: "Instructor-reviewed course assignment."
      }
    }
  });
  assert.equal(moduleEdit.response.status, 200);
  assert.equal(moduleEdit.payload.module.assignmentDetails.overview, "Instructor-reviewed course assignment.");
  const created = await administrator.call("/admin/users", {
    method: "POST",
    body: { fullName: "Quiz Student", email: "quiz@example.test", username: "quiz.student", role: "student" }
  });
  const student = client();
  await student.login("quiz.student", created.payload.temporaryPassword);
  assert.equal((await student.call("/course/modules")).response.status, 403);
  const passwordUpdated = await student.call("/auth/change-password", {
    method: "POST",
    body: { newPassword: "Quiz student secure passphrase 748!" }
  });
  assert.equal(passwordUpdated.response.status, 200);
  const modules = await student.call("/course/modules");
  assert.equal(modules.response.status, 200);
  assert.equal(modules.payload.modules.length, 6);
  assert.equal(modules.payload.schedule.length, 6);
  assert.equal(modules.payload.assessment.length, 3);
  assert.equal(modules.payload.modules.every((module, index) =>
    module.lessons.length === courseModules[index].lessons.length), true);
  assert.equal(modules.payload.modules.every(module => module.assignmentDetails.steps.length >= 5), true);
  assert.equal(modules.payload.modules.every(module => module.quiz.length === 10), true);
  assert.equal(modules.payload.modules.every(module => module.shortQuestions.length === 5), true);
  assert.deepEqual(modules.payload.modules.map(module => [module.title, module.durationHours]), courseModules.map(module =>
    [module.title, module.durationHours]));
  assert.deepEqual(modules.payload.modules.map(module => module.topics), courseModules.map(module => module.topics));
  assert.ok(modules.payload.modules.every(module => module.lessons.every(lesson =>
    lesson.objectives.length && lesson.limitations && lesson.video.verified === false)));
  assert.equal(modules.payload.modules.every(module =>
    module.lessons.every(lesson =>     lesson.videoUrl.startsWith("https://www.youtube.com/results?search_query="))), true);
  assert.equal(modules.payload.modules.find(module => module.id === "foundations").assignmentDetails.overview,
    "Instructor-reviewed course assignment.");
  assert.equal(Object.hasOwn(modules.payload.modules[0].quiz[0], "answer"), false);
  assert.equal(Object.hasOwn(modules.payload.modules[0].shortQuestions[0], "guidance"), false);
  const videoLibrary = await student.call("/course/videos?search=CT");
  assert.equal(videoLibrary.response.status, 200);
  assert.ok(videoLibrary.payload.videos.some(video => video.moduleId === "foundations"));
  const scored = await student.call("/me/quizzes/foundations/attempts", {
    method: "POST", body: { answers: adminModules.payload.modules[0].quiz.map(question => question.answer) }
  });
  assert.equal(scored.response.status, 200);
  assert.equal(scored.payload.score, 10);
  assert.equal(scored.payload.review.length, 10);
  assert.equal(scored.payload.review.every(item => item.isCorrect && item.explanation), true);
  const invalidAnswers = await student.call("/me/quizzes/foundations/attempts", {
    method: "POST", body: { answers: [99, ...Array(9).fill(0)] }
  });
  assert.equal(invalidAnswers.response.status, 400);
});

test("trusted bootstrap is idempotent and recovery only resets an existing administrator", async () => {
  const databasePath = join(tempDirectory, "bootstrap.sqlite");
  const bootstrapPath = fileURLToPath(new URL("../server/bootstrap-admin.js", import.meta.url));
  const recoverPath = fileURLToPath(new URL("../server/recover-admin.js", import.meta.url));
  const environment = {
    ...process.env,
    DATABASE_PATH: databasePath,
    BOOTSTRAP_ADMIN_NAME: "Bootstrap Administrator",
    BOOTSTRAP_ADMIN_EMAIL: "bootstrap@example.test",
    BOOTSTRAP_ADMIN_USERNAME: "bootstrap.admin",
    BOOTSTRAP_ADMIN_PASSWORD: "First secure bootstrap passphrase 284!"
  };
  const firstRun = spawnSync(process.execPath, [bootstrapPath], { env: environment, encoding: "utf8" });
  assert.equal(firstRun.status, 0, firstRun.stderr);
  const rerun = spawnSync(process.execPath, [bootstrapPath], { env: environment, encoding: "utf8" });
  assert.equal(rerun.status, 0, rerun.stderr);
  const provisionedDb = createDatabase(databasePath);
  const admin = provisionedDb.prepare("SELECT id, password_hash FROM users WHERE email = ?").get("bootstrap@example.test");
  assert.ok(admin);
  assert.equal(provisionedDb.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").get().count, 1);
  const sessionTokenHash = "bootstrap-session-hash";
  provisionedDb.prepare(`
    INSERT INTO sessions (token_hash, user_id, csrf_hash, expires_at, created_at, last_seen_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionTokenHash, admin.id, "csrf-hash", new Date(Date.now() + 3600000).toISOString(),
    new Date().toISOString(), new Date().toISOString());
  provisionedDb.close();
  const recovery = spawnSync(process.execPath, [recoverPath], {
    env: { ...environment, BOOTSTRAP_ADMIN_PASSWORD: "Recovered administrator passphrase 673!" },
    encoding: "utf8"
  });
  assert.equal(recovery.status, 0, recovery.stderr);
  const recoveredDb = createDatabase(databasePath);
  const recoveredAdmin = recoveredDb.prepare("SELECT password_hash, must_change_password FROM users WHERE email = ?")
    .get("bootstrap@example.test");
  assert.equal(recoveredAdmin.must_change_password, 1);
  assert.equal(await verifyPassword(recoveredAdmin.password_hash, "Recovered administrator passphrase 673!"), true);
  assert.equal(recoveredDb.prepare("SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?").get(admin.id).count, 0);
  recoveredDb.close();
});
