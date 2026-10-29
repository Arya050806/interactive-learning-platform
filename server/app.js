import express from "express";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import argon2 from "argon2";
import { courseAssessment, courseSchedule } from "./course.js";
import { writeAudit } from "./db.js";
import {
  cookieOptions,
  csrfCookieOptions,
  hashPassword,
  hashToken,
  newId,
  newToken,
  publicUser,
  readCookie,
  safeEqual,
  validPassword,
  verifyPassword
} from "./security.js";

const SESSION_COOKIE = "mtip_session";
const CSRF_COOKIE = "mtip_csrf";
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const usernamePattern = /^[a-zA-Z0-9._-]{3,32}$/;
const dummyPasswordHash = await argon2.hash(newToken(), { type: argon2.argon2id });

const error = (response, status, message) => response.status(status).json({ error: message });
const validText = (value, max) => typeof value === "string" && value.trim().length > 0 && value.trim().length <= max;
const parseJson = (value, fallback = []) => {
  try { return JSON.parse(value); } catch { return fallback; }
};

function moduleForClient(row, includeAnswers = false) {
  const questions = parseJson(row.quiz_json).map(({ question, options, answer, explanation, topic }) => ({
    question,
    options,
    ...(topic ? { topic } : {}),
    ...(includeAnswers ? { answer, explanation } : {})
  }));
  return {
    id: row.id,
    number: row.number,
    title: row.title,
    summary: row.summary,
    icon: row.icon,
    weeks: row.weeks,
    durationHours: row.duration_hours,
    prerequisites: row.prerequisites,
    topics: parseJson(row.topics_json),
    objectives: parseJson(row.objectives_json),
    shortQuestions: parseJson(row.short_questions_json).map(({ question, topic, guidance }) => ({
      question,
      topic,
      ...(includeAnswers ? { guidance } : {})
    })),
    lesson: row.lesson,
    quiz: questions,
    assignment: row.assignment_prompt,
    assignmentDetails: parseJson(row.assignment_details_json, {}),
    lessons: row.lessons ?? []
  };
}

function setSessionCookies(response, production, sessionToken, csrfToken, maxAge) {
  response.cookie(SESSION_COOKIE, sessionToken, cookieOptions(production, maxAge));
  response.cookie(CSRF_COOKIE, csrfToken, csrfCookieOptions(production, maxAge));
}

function clearSessionCookies(response, production) {
  response.clearCookie(SESSION_COOKIE, cookieOptions(production));
  response.clearCookie(CSRF_COOKIE, csrfCookieOptions(production));
}

export function createApp({ db, sessionTtlHours = Number(process.env.SESSION_TTL_HOURS ?? 12), production = process.env.NODE_ENV === "production" }) {
  const app = express();
  app.disable("x-powered-by");
  if (production) app.set("trust proxy", 1);
  app.use(helmet({
    contentSecurityPolicy: production ? undefined : false,
    crossOriginEmbedderPolicy: false
  }));
  app.use(express.json({ limit: "64kb" }));

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "Too many sign-in attempts. Try again later." }
  });

  const authenticate = (request, response, next) => {
    const rawToken = readCookie(request, SESSION_COOKIE);
    if (!rawToken) return error(response, 401, "Authentication required.");
    const session = db.prepare(`
      SELECT s.token_hash, s.csrf_hash, s.expires_at, u.*
      FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND u.status = 'active'
    `).get(hashToken(rawToken));
    if (!session || Date.parse(session.expires_at) <= Date.now()) {
      if (session) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(session.token_hash);
      clearSessionCookies(response, production);
      return error(response, 401, "Session expired. Please sign in again.");
    }
    if (session.must_change_password &&
        !["/api/auth/session", "/api/auth/logout", "/api/auth/change-password"].includes(request.path)) {
      return error(response, 403, "Set your password before accessing the learning platform.");
    }
    db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?")
      .run(new Date().toISOString(), session.token_hash);
    request.auth = { user: session, session };
    next();
  };

  const csrf = (request, response, next) => {
    const cookieToken = readCookie(request, CSRF_COOKIE);
    const headerToken = request.get("x-csrf-token");
    if (!cookieToken || !headerToken || !safeEqual(cookieToken, headerToken)) {
      return error(response, 403, "Invalid request token. Refresh and try again.");
    }
    if (request.auth && !safeEqual(hashToken(cookieToken), request.auth.session.csrf_hash)) {
      return error(response, 403, "Invalid request token. Refresh and try again.");
    }
    next();
  };

  const requireRole = (...roles) => (request, response, next) => {
    if (!roles.includes(request.auth.user.role)) return error(response, 403, "You do not have permission to perform this action.");
    next();
  };

  const adminOnly = [authenticate, requireRole("admin")];
  const teachingRoles = [authenticate, requireRole("admin", "instructor")];
  const mutable = (roles = null) => [
    authenticate,
    ...(roles ? [requireRole(...roles)] : []),
    csrf
  ];

  app.get("/api/health", (_request, response) => response.json({ status: "ok" }));

  app.get("/api/auth/csrf", (request, response) => {
    let token = readCookie(request, CSRF_COOKIE);
    if (!token || request.auth) token = newToken();
    const options = csrfCookieOptions(production, 60 * 60 * 1000);
    response.cookie(CSRF_COOKIE, token, options);
    response.set("Cache-Control", "no-store");
    response.json({ csrfToken: token });
  });

  app.post("/api/auth/login", csrf, authLimiter, async (request, response) => {
    const identifier = typeof request.body?.identifier === "string" ? request.body.identifier.trim() : "";
    const password = typeof request.body?.password === "string" ? request.body.password : "";
    if (!identifier || !password || identifier.length > 254 || password.length > 128) {
      await verifyPassword(dummyPasswordHash, "invalid-request-password");
      return error(response, 401, "Invalid username/email or password.");
    }
    const user = db.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE")
      .get(identifier, identifier);
    const matches = await verifyPassword(user?.password_hash ?? dummyPasswordHash, password);
    if (!user || !matches || user.status !== "active") {
      return error(response, 401, "Invalid username/email or password.");
    }
    const token = newToken();
    const csrfToken = newToken();
    const ttlMs = sessionTtlHours * 60 * 60 * 1000;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlMs).toISOString();
    db.prepare(`
      INSERT INTO sessions (token_hash, user_id, csrf_hash, expires_at, created_at, last_seen_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(hashToken(token), user.id, hashToken(csrfToken), expiresAt, now.toISOString(), now.toISOString());
    db.prepare("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?")
      .run(now.toISOString(), now.toISOString(), user.id);
    setSessionCookies(response, production, token, csrfToken, ttlMs);
    response.set("Cache-Control", "no-store");
    response.json({ user: publicUser({ ...user, last_login_at: now.toISOString() }), csrfToken });
  });

  app.get("/api/auth/session", authenticate, (request, response) => {
    response.set("Cache-Control", "no-store");
    response.json({ user: publicUser(request.auth.user) });
  });

  app.post("/api/auth/logout", ...mutable(), (request, response) => {
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(request.auth.session.token_hash);
    clearSessionCookies(response, production);
    response.status(204).end();
  });

  app.post("/api/auth/change-password", ...mutable(), async (request, response) => {
    const { currentPassword, newPassword } = request.body ?? {};
    if (!validPassword(newPassword)) return error(response, 400, "Choose a password between 12 and 128 characters.");
    const user = request.auth.user;
    if (!user.must_change_password && !(await verifyPassword(user.password_hash, currentPassword ?? ""))) {
      return error(response, 400, "Current password is incorrect.");
    }
    const passwordHash = await hashPassword(newPassword);
    const now = new Date().toISOString();
    db.prepare("UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = ? WHERE id = ?")
      .run(passwordHash, now, user.id);
    db.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?")
      .run(user.id, request.auth.session.token_hash);
    writeAudit(db, user.id, "password.changed", user.id);
    response.json({ user: publicUser({ ...user, must_change_password: 0 }) });
  });

  app.get("/api/course/modules", authenticate, (request, response) => {
    const lessonsForModule = db.prepare(`
      SELECT id, title, content, video_url AS videoUrl, lesson_details_json, video_json, position
      FROM lessons WHERE module_id = ? ORDER BY position, created_at
    `);
    const modules = db.prepare("SELECT * FROM modules ORDER BY number").all()
      .map(row => moduleForClient({
        ...row,
        lessons: lessonsForModule.all(row.id).map(item => ({
          id: item.id,
          title: item.title,
          content: item.content,
          videoUrl: item.videoUrl,
          position: item.position,
          ...parseJson(item.lesson_details_json, {}),
          video: parseJson(item.video_json, { sourceUrl: item.videoUrl, verified: false })
        }))
      }));
    response.json({ modules, schedule: courseSchedule, assessment: courseAssessment });
  });

  app.get("/api/course/videos", authenticate, (request, response) => {
    const moduleId = typeof request.query.moduleId === "string" ? request.query.moduleId.slice(0, 64) : "";
    const query = typeof request.query.search === "string" ? request.query.search.trim().slice(0, 100) : "";
    const videos = db.prepare(`
      SELECT l.id AS lessonId, l.title, l.video_json, l.video_url, l.module_id AS moduleId,
        m.number AS moduleNumber, m.title AS moduleTitle, l.lesson_details_json
      FROM lessons l JOIN modules m ON m.id = l.module_id
      WHERE (? = '' OR l.module_id = ?)
      ORDER BY m.number, l.position, l.created_at
    `).all(moduleId, moduleId).map(row => ({
      lessonId: row.lessonId,
      moduleId: row.moduleId,
      moduleNumber: row.moduleNumber,
      moduleTitle: row.moduleTitle,
      title: parseJson(row.video_json, {}).title ?? `Video resources: ${row.title}`,
      lessonTitle: row.title,
      description: parseJson(row.video_json, {}).description ?? "Search for instructor-approved learning resources on this topic.",
      source: parseJson(row.video_json, {}).source ?? "YouTube search",
      sourceUrl: row.video_url,
      embedUrl: parseJson(row.video_json, {}).embedUrl ?? null,
      duration: parseJson(row.video_json, {}).duration ?? null,
      verified: Boolean(parseJson(row.video_json, {}).verified),
      objectives: parseJson(row.lesson_details_json, {}).objectives ?? []
    })).filter(item => !query || `${item.title} ${item.lessonTitle} ${item.moduleTitle} ${item.description}`.toLowerCase().includes(query.toLowerCase()));
    response.json({ videos });
  });

  app.get("/api/me/progress", authenticate, (request, response) => {
    const rows = db.prepare("SELECT module_id, completed, updated_at FROM progress WHERE user_id = ?")
      .all(request.auth.user.id);
    response.json({ progress: rows.map(row => ({ moduleId: row.module_id, completed: Boolean(row.completed), updatedAt: row.updated_at })) });
  });

  app.post("/api/me/progress", ...mutable(), (request, response) => {
    const { moduleId, completed } = request.body ?? {};
    if (typeof moduleId !== "string" || typeof completed !== "boolean" ||
        !db.prepare("SELECT 1 FROM modules WHERE id = ?").get(moduleId)) {
      return error(response, 400, "A valid module and completion status are required.");
    }
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO progress (user_id, module_id, completed, updated_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id, module_id) DO UPDATE SET completed = excluded.completed, updated_at = excluded.updated_at
    `).run(request.auth.user.id, moduleId, Number(completed), now);
    response.json({ moduleId, completed, updatedAt: now });
  });

  app.post("/api/me/quizzes/:moduleId/attempts", ...mutable(), (request, response) => {
    const module = db.prepare("SELECT quiz_json FROM modules WHERE id = ?").get(request.params.moduleId);
    const answers = request.body?.answers;
    const questions = module ? parseJson(module.quiz_json) : null;
    if (!questions || !Array.isArray(answers) || answers.length !== questions.length ||
        answers.some((answer, index) => !Number.isInteger(answer) || answer < 0 || answer >= questions[index].options.length)) {
      return error(response, 400, "Submit one valid answer for each quiz question.");
    }
    const score = questions.reduce((total, question, index) => total + Number(question.answer === answers[index]), 0);
    const review = questions.map((question, index) => ({
      question: question.question,
      selectedAnswer: answers[index],
      correctAnswer: question.answer,
      explanation: question.explanation,
      isCorrect: answers[index] === question.answer
    }));
    const id = newId();
    const createdAt = new Date().toISOString();
    db.prepare(`
      INSERT INTO quiz_attempts (id, user_id, module_id, score, total, answers_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, request.auth.user.id, request.params.moduleId, score, questions.length, JSON.stringify(answers), createdAt);
    response.json({ id, score, total: questions.length, createdAt, review });
  });

  app.post("/api/me/assignments/:moduleId", ...mutable(), (request, response) => {
    const { response: answer } = request.body ?? {};
    if (!db.prepare("SELECT 1 FROM modules WHERE id = ?").get(request.params.moduleId) || !validText(answer, 10000)) {
      return error(response, 400, "A valid assignment response is required.");
    }
    const submittedAt = new Date().toISOString();
    const id = newId();
    db.prepare(`
      INSERT INTO submissions (id, user_id, module_id, response, submitted_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(user_id, module_id) DO UPDATE SET
        response = excluded.response, submitted_at = excluded.submitted_at,
        grade = NULL, feedback = NULL, reviewed_by = NULL, reviewed_at = NULL
    `).run(id, request.auth.user.id, request.params.moduleId, answer.trim(), submittedAt);
    const submission = db.prepare("SELECT id FROM submissions WHERE user_id = ? AND module_id = ?")
      .get(request.auth.user.id, request.params.moduleId);
    response.json({ id: submission.id, submittedAt });
  });

  app.get("/api/me/records", authenticate, (request, response) => {
    const userId = request.auth.user.id;
    const submissions = db.prepare(`
      SELECT s.id, s.module_id AS moduleId, m.title AS moduleTitle, s.response, s.submitted_at AS submittedAt,
        s.grade, s.feedback, s.reviewed_at AS reviewedAt
      FROM submissions s JOIN modules m ON m.id = s.module_id WHERE s.user_id = ? ORDER BY s.submitted_at DESC
    `).all(userId);
    const quizzes = db.prepare(`
      SELECT q.id, q.module_id AS moduleId, m.title AS moduleTitle, q.score, q.total, q.created_at AS createdAt
      FROM quiz_attempts q JOIN modules m ON m.id = q.module_id WHERE q.user_id = ? ORDER BY q.created_at DESC
    `).all(userId);
    response.json({ submissions, quizzes });
  });

  app.get("/api/admin/overview", ...adminOnly, (_request, response) => {
    const users = db.prepare(`
      SELECT COUNT(*) AS total,
        SUM(status = 'active') AS active,
        SUM(status = 'inactive') AS inactive,
        SUM(role = 'student') AS students,
        SUM(role = 'instructor') AS instructors
      FROM users
    `).get();
    const recent = db.prepare(`
      SELECT id, full_name AS fullName, email, role, created_at AS createdAt
      FROM users ORDER BY created_at DESC LIMIT 8
    `).all();
    const progress = db.prepare(`
      SELECT COUNT(*) AS assignments, SUM(grade IS NOT NULL) AS reviewed,
        (SELECT COUNT(*) FROM quiz_attempts) AS quizAttempts,
        (SELECT COUNT(*) FROM progress WHERE completed = 1) AS completedModules
      FROM submissions
    `).get();
    response.json({ users, recent, progress });
  });

  app.get("/api/admin/users", ...adminOnly, (request, response) => {
    const search = typeof request.query.search === "string" ? request.query.search.trim().slice(0, 100) : "";
    const role = ["student", "instructor", "admin"].includes(request.query.role) ? request.query.role : "";
    const status = ["active", "inactive"].includes(request.query.status) ? request.query.status : "";
    const rows = db.prepare(`
      SELECT id, full_name, email, username, role, status, must_change_password, created_at, last_login_at
      FROM users
      WHERE (? = '' OR full_name LIKE ? OR email LIKE ? OR username LIKE ?)
        AND (? = '' OR role = ?) AND (? = '' OR status = ?)
      ORDER BY created_at DESC LIMIT 500
    `).all(search, `%${search}%`, `%${search}%`, `%${search}%`, role, role, status, status);
    response.json({ users: rows.map(publicUser) });
  });

  app.post("/api/admin/users", ...mutable(["admin"]), async (request, response) => {
    const { fullName, email, username, role } = request.body ?? {};
    if (!validText(fullName, 120) || typeof email !== "string" || !emailPattern.test(email.trim()) ||
        email.trim().length > 254 || typeof username !== "string" || !usernamePattern.test(username.trim()) ||
        !["student", "instructor"].includes(role)) {
      return error(response, 400, "Enter a valid name, email, username, and student or instructor role.");
    }
    const id = newId();
    const temporaryPassword = newToken(24);
    const now = new Date().toISOString();
    try {
      db.prepare(`
        INSERT INTO users (id, full_name, email, username, password_hash, role, status, must_change_password, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'active', 1, ?, ?, ?)
      `).run(id, fullName.trim(), email.trim().toLowerCase(), username.trim(), await hashPassword(temporaryPassword),
        role, request.auth.user.id, now, now);
    } catch (cause) {
      if (cause.code === "SQLITE_CONSTRAINT_UNIQUE") return error(response, 409, "That email or username is already in use.");
      throw cause;
    }
    writeAudit(db, request.auth.user.id, "user.created", id, { role });
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
    response.status(201).json({ user: publicUser(user), temporaryPassword });
  });

  app.patch("/api/admin/users/:id", ...mutable(["admin"]), (request, response) => {
    const existing = db.prepare("SELECT * FROM users WHERE id = ?").get(request.params.id);
    if (!existing) return error(response, 404, "User not found.");
    const { fullName, email, username, role, status } = request.body ?? {};
    if (fullName !== undefined && !validText(fullName, 120)) return error(response, 400, "Name must be between 1 and 120 characters.");
    if (email !== undefined && (typeof email !== "string" || !emailPattern.test(email.trim()) || email.trim().length > 254)) {
      return error(response, 400, "Enter a valid email address.");
    }
    if (username !== undefined && (typeof username !== "string" || !usernamePattern.test(username.trim()))) {
      return error(response, 400, "Username must be 3–32 letters, numbers, dots, underscores, or hyphens.");
    }
    if (role !== undefined && !(existing.role === "admin" ? role === "admin" : ["student", "instructor"].includes(role))) {
      return error(response, 400, "Administrators cannot be assigned or removed through user management.");
    }
    if (status !== undefined && !["active", "inactive"].includes(status)) return error(response, 400, "Invalid account status.");
    if (existing.role === "admin" && status === "inactive") {
      const activeAdmins = db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND status = 'active'").get().count;
      if (activeAdmins <= 1) return error(response, 409, "The last active administrator cannot be deactivated.");
    }
    const updated = {
      fullName: fullName === undefined ? existing.full_name : fullName.trim(),
      email: email === undefined ? existing.email : email.trim().toLowerCase(),
      username: username === undefined ? existing.username : username.trim(),
      role: role ?? existing.role,
      status: status ?? existing.status
    };
    const now = new Date().toISOString();
    try {
      db.prepare(`
        UPDATE users SET full_name = ?, email = ?, username = ?, role = ?, status = ?, updated_at = ?
        WHERE id = ?
      `).run(updated.fullName, updated.email, updated.username, updated.role, updated.status, now, existing.id);
    } catch (cause) {
      if (cause.code === "SQLITE_CONSTRAINT_UNIQUE") return error(response, 409, "That email or username is already in use.");
      throw cause;
    }
    if (updated.status === "inactive") db.prepare("DELETE FROM sessions WHERE user_id = ?").run(existing.id);
    const action = updated.status !== existing.status
      ? `user.${updated.status === "active" ? "activated" : "deactivated"}`
      : updated.role !== existing.role ? "user.role_changed" : "user.updated";
    writeAudit(db, request.auth.user.id, action, existing.id, {
      role: updated.role,
      status: updated.status,
      fields: Object.keys(request.body ?? {}).filter(field => ["fullName", "email", "username", "role", "status"].includes(field))
    });
    response.json({ user: publicUser(db.prepare("SELECT * FROM users WHERE id = ?").get(existing.id)) });
  });

  app.post("/api/admin/users/:id/reset-password", ...mutable(["admin"]), async (request, response) => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(request.params.id);
    if (!user) return error(response, 404, "User not found.");
    if (user.role === "admin") return error(response, 400, "Administrator passwords are managed through the trusted recovery command.");
    const temporaryPassword = newToken(24);
    const now = new Date().toISOString();
    db.prepare("UPDATE users SET password_hash = ?, must_change_password = 1, updated_at = ? WHERE id = ?")
      .run(await hashPassword(temporaryPassword), now, user.id);
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(user.id);
    writeAudit(db, request.auth.user.id, "user.password_reset", user.id);
    response.json({ temporaryPassword, message: "Share this temporary password through a trusted channel. It will not be shown again." });
  });

  app.get("/api/admin/audit", ...adminOnly, (request, response) => {
    const rows = db.prepare(`
      SELECT a.id, a.action, a.details, a.created_at AS createdAt,
        actor.full_name AS actorName, actor.email AS actorEmail,
        target.full_name AS targetName, target.email AS targetEmail
      FROM audit_logs a
      LEFT JOIN users actor ON actor.id = a.actor_id
      LEFT JOIN users target ON target.id = a.target_user_id
      ORDER BY a.created_at DESC LIMIT 200
    `).all().map(row => ({ ...row, details: parseJson(row.details, {}) }));
    response.json({ entries: rows });
  });

  app.get("/api/admin/progress", ...adminOnly, (_request, response) => {
    const rows = db.prepare(`
      SELECT u.id, u.full_name AS fullName, u.email, u.role,
        (SELECT COUNT(*) FROM progress p WHERE p.user_id = u.id AND p.completed = 1) AS completedModules,
        (SELECT COUNT(*) FROM quiz_attempts q WHERE q.user_id = u.id) AS quizAttempts,
        (SELECT COUNT(*) FROM submissions s WHERE s.user_id = u.id) AS assignments,
        (SELECT AVG(s.grade) FROM submissions s WHERE s.user_id = u.id AND s.grade IS NOT NULL) AS averageGrade
      FROM users u WHERE u.role = 'student' ORDER BY u.full_name LIMIT 500
    `).all();
    response.json({ students: rows });
  });

  app.get("/api/admin/modules", ...adminOnly, (_request, response) => {
    const modules = db.prepare("SELECT * FROM modules ORDER BY number").all().map(row => {
      const lessons = db.prepare(`
        SELECT id, title, content, video_url AS videoUrl, lesson_details_json, video_json, position FROM lessons
        WHERE module_id = ? ORDER BY position, created_at
      `).all(row.id).map(item => ({
        id: item.id,
        title: item.title,
        content: item.content,
        videoUrl: item.videoUrl,
        position: item.position,
        ...parseJson(item.lesson_details_json, {}),
        video: parseJson(item.video_json, { sourceUrl: item.videoUrl, verified: false })
      }));
      return moduleForClient({ ...row, lessons }, true);
    });
    response.json({ modules });
  });

  app.patch("/api/admin/modules/:id", ...mutable(["admin"]), (request, response) => {
    const current = db.prepare("SELECT * FROM modules WHERE id = ?").get(request.params.id);
    if (!current) return error(response, 404, "Module not found.");
    const {
      title, summary, lesson, assignment, assignmentDetails, topics, objectives, shortQuestions, quiz
    } = request.body ?? {};
    if (title !== undefined && !validText(title, 160)) return error(response, 400, "Enter a valid module title.");
    if (summary !== undefined && !validText(summary, 500)) return error(response, 400, "Enter a valid module summary.");
    if (lesson !== undefined && !validText(lesson, 12000)) return error(response, 400, "Lesson text must be 1–12,000 characters.");
    if (assignment !== undefined && !validText(assignment, 2000)) return error(response, 400, "Assignment prompt must be 1–2,000 characters.");
    if (assignmentDetails !== undefined && (!assignmentDetails || typeof assignmentDetails !== "object" ||
        !Array.isArray(assignmentDetails.steps) || assignmentDetails.steps.length > 20 ||
        assignmentDetails.steps.some(item => !validText(item, 1000)) ||
        !Array.isArray(assignmentDetails.deliverables) || assignmentDetails.deliverables.length > 12 ||
        assignmentDetails.deliverables.some(item => !validText(item, 500)) ||
        !Array.isArray(assignmentDetails.rubric) || assignmentDetails.rubric.length > 12 ||
        assignmentDetails.rubric.some(item => !validText(item.criterion, 160) ||
          !Number.isInteger(item.points) || item.points < 0 || item.points > 100) ||
        !Number.isInteger(assignmentDetails.estimatedHours) ||
        assignmentDetails.estimatedHours < 1 || assignmentDetails.estimatedHours > 100)) {
      return error(response, 400, "Provide valid assignment steps, deliverables, rubric criteria, and estimated hours.");
    }
    if (topics !== undefined && (!Array.isArray(topics) || topics.length > 20 || topics.some(item => !validText(item, 120)))) {
      return error(response, 400, "Provide up to 20 valid topic labels.");
    }
    if (objectives !== undefined && (!Array.isArray(objectives) || objectives.length > 20 || objectives.some(item => !validText(item, 240)))) {
      return error(response, 400, "Provide up to 20 valid learning objectives.");
    }
    if (shortQuestions !== undefined && (!Array.isArray(shortQuestions) || shortQuestions.length > 20 ||
        shortQuestions.some(item => !validText(item.question, 1000) || !validText(item.topic, 200) ||
          (item.guidance !== undefined && (typeof item.guidance !== "string" || item.guidance.length > 2000))))) {
      return error(response, 400, "Provide valid short-answer questions.");
    }
    if (quiz !== undefined && (!Array.isArray(quiz) || quiz.length > 20 || quiz.some(item =>
      !validText(item.question, 500) || !Array.isArray(item.options) || item.options.length < 2 ||
      item.options.length > 8 || item.options.some(option => !validText(option, 240)) ||
      !Number.isInteger(item.answer) || item.answer < 0 || item.answer >= item.options.length))) {
      return error(response, 400, "Quiz questions need valid options and an answer index.");
    }
    db.prepare(`
      UPDATE modules SET title = ?, summary = ?, lesson = ?, assignment_prompt = ?,
        assignment_details_json = ?, topics_json = ?, objectives_json = ?, short_questions_json = ?,
        quiz_json = ?, updated_at = ? WHERE id = ?
    `).run(
      title?.trim() ?? current.title, summary?.trim() ?? current.summary, lesson?.trim() ?? current.lesson,
      assignment?.trim() ?? current.assignment_prompt,
      JSON.stringify(assignmentDetails ?? parseJson(current.assignment_details_json, {})),
      JSON.stringify(topics ?? parseJson(current.topics_json)),
      JSON.stringify(objectives ?? parseJson(current.objectives_json)),
      JSON.stringify(shortQuestions ?? parseJson(current.short_questions_json)),
      JSON.stringify(quiz ?? parseJson(current.quiz_json)),
      new Date().toISOString(), current.id
    );
    writeAudit(db, request.auth.user.id, "course.module_updated", null, { moduleId: current.id });
    response.json({ module: moduleForClient(db.prepare("SELECT * FROM modules WHERE id = ?").get(current.id)) });
  });

  app.post("/api/admin/modules/:id/lessons", ...mutable(["admin"]), (request, response) => {
    const { title, content, videoUrl = "", position = 0 } = request.body ?? {};
    if (!db.prepare("SELECT 1 FROM modules WHERE id = ?").get(request.params.id)) return error(response, 404, "Module not found.");
    if (!validText(title, 160) || !validText(content, 12000) ||
        (videoUrl && (typeof videoUrl !== "string" || videoUrl.length > 2048 || !/^https:\/\//i.test(videoUrl))) ||
        !Number.isInteger(position) || position < 0 || position > 999) {
      return error(response, 400, "Enter a valid lesson title, content, HTTPS video URL, and position.");
    }
    const id = newId();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO lessons (id, module_id, title, content, video_url, position, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, request.params.id, title.trim(), content.trim(), videoUrl || null, position, now, now);
    writeAudit(db, request.auth.user.id, "course.lesson_created", null, { moduleId: request.params.id, lessonId: id });
    response.status(201).json({ lesson: { id, moduleId: request.params.id, title: title.trim(), content: content.trim(), videoUrl: videoUrl || null, position } });
  });

  app.patch("/api/admin/lessons/:id", ...mutable(["admin"]), (request, response) => {
    const lesson = db.prepare("SELECT * FROM lessons WHERE id = ?").get(request.params.id);
    if (!lesson) return error(response, 404, "Lesson not found.");
    const { title, content, videoUrl, position } = request.body ?? {};
    if (title !== undefined && !validText(title, 160)) return error(response, 400, "Enter a valid lesson title.");
    if (content !== undefined && !validText(content, 12000)) return error(response, 400, "Lesson content must be 1–12,000 characters.");
    if (videoUrl !== undefined && videoUrl !== "" &&
        (typeof videoUrl !== "string" || videoUrl.length > 2048 || !/^https:\/\//i.test(videoUrl))) {
      return error(response, 400, "Video links must use HTTPS.");
    }
    if (position !== undefined && (!Number.isInteger(position) || position < 0 || position > 999)) {
      return error(response, 400, "Lesson position must be between 0 and 999.");
    }
    const updatedAt = new Date().toISOString();
    db.prepare(`
      UPDATE lessons SET title = ?, content = ?, video_url = ?, position = ?, updated_at = ? WHERE id = ?
    `).run(title?.trim() ?? lesson.title, content?.trim() ?? lesson.content,
      videoUrl === undefined ? lesson.video_url : (videoUrl || null),
      position ?? lesson.position, updatedAt, lesson.id);
    writeAudit(db, request.auth.user.id, "course.lesson_updated", null, { moduleId: lesson.module_id, lessonId: lesson.id });
    response.json({ lesson: db.prepare("SELECT id, module_id AS moduleId, title, content, video_url AS videoUrl, position FROM lessons WHERE id = ?").get(lesson.id) });
  });

  app.delete("/api/admin/lessons/:id", ...mutable(["admin"]), (request, response) => {
    const lesson = db.prepare("SELECT id, module_id FROM lessons WHERE id = ?").get(request.params.id);
    if (!lesson) return error(response, 404, "Lesson not found.");
    db.prepare("DELETE FROM lessons WHERE id = ?").run(lesson.id);
    writeAudit(db, request.auth.user.id, "course.lesson_deleted", null, { moduleId: lesson.module_id, lessonId: lesson.id });
    response.status(204).end();
  });

  app.get("/api/teaching/submissions", ...teachingRoles, (request, response) => {
    const rows = db.prepare(`
      SELECT s.id, s.module_id AS moduleId, m.title AS moduleTitle, s.response,
        s.submitted_at AS submittedAt, s.grade, s.feedback, s.reviewed_at AS reviewedAt,
        u.id AS studentId, u.full_name AS studentName, u.email AS studentEmail
      FROM submissions s JOIN users u ON u.id = s.user_id JOIN modules m ON m.id = s.module_id
      ORDER BY s.submitted_at DESC LIMIT 500
    `).all();
    response.json({ submissions: rows });
  });

  app.patch("/api/teaching/submissions/:id", ...mutable(["admin", "instructor"]), (request, response) => {
    const { grade, feedback } = request.body ?? {};
    if (typeof grade !== "number" || !Number.isFinite(grade) || grade < 0 || grade > 100 ||
        (feedback !== undefined && (typeof feedback !== "string" || feedback.length > 4000))) {
      return error(response, 400, "Enter a grade from 0 to 100 and feedback up to 4,000 characters.");
    }
    const submission = db.prepare("SELECT id, user_id FROM submissions WHERE id = ?").get(request.params.id);
    if (!submission) return error(response, 404, "Submission not found.");
    const reviewedAt = new Date().toISOString();
    db.prepare("UPDATE submissions SET grade = ?, feedback = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?")
      .run(grade, feedback?.trim() ?? "", request.auth.user.id, reviewedAt, submission.id);
    writeAudit(db, request.auth.user.id, "assignment.reviewed", submission.user_id, { submissionId: submission.id, grade });
    response.json({ id: submission.id, grade, feedback: feedback?.trim() ?? "", reviewedAt });
  });

  app.get("/api/teaching/progress", ...teachingRoles, (_request, response) => {
    const students = db.prepare(`
      SELECT u.id, u.full_name AS fullName, u.email,
        (SELECT COUNT(*) FROM progress p WHERE p.user_id = u.id AND p.completed = 1) AS completedModules,
        (SELECT COUNT(*) FROM quiz_attempts q WHERE q.user_id = u.id) AS quizAttempts,
        (SELECT COUNT(*) FROM submissions s WHERE s.user_id = u.id) AS assignments
      FROM users u WHERE u.role = 'student' AND u.status = 'active' ORDER BY u.full_name LIMIT 500
    `).all();
    response.json({ students });
  });

  app.use("/api", (_request, response) => error(response, 404, "API endpoint not found."));
  app.use((cause, _request, response, _next) => {
    if (response.headersSent) return;
    if (cause.type === "entity.parse.failed") return error(response, 400, "Request body must contain valid JSON.");
    if (cause.type === "entity.too.large") return error(response, 413, "Request body is too large.");
    console.error("Request failed:", cause);
    response.status(500).json({ error: "An unexpected server error occurred." });
  });

  return app;
}
