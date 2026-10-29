import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { courseModules } from "./course.js";

export function createDatabase(databasePath = process.env.DATABASE_PATH ?? "./data/platform.sqlite") {
  const resolvedPath = resolve(databasePath);
  mkdirSync(dirname(resolvedPath), { recursive: true });
  const db = new Database(resolvedPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      full_name TEXT NOT NULL CHECK(length(full_name) BETWEEN 1 AND 120),
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'instructor', 'student')),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'inactive')),
      must_change_password INTEGER NOT NULL DEFAULT 0 CHECK(must_change_password IN (0, 1)),
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      last_login_at TEXT
    );
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS users_role_status_idx ON users(role, status);
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      target_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      details TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_logs(created_at DESC);
    CREATE TABLE IF NOT EXISTS modules (
      id TEXT PRIMARY KEY,
      number INTEGER NOT NULL UNIQUE,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      icon TEXT NOT NULL,
      weeks TEXT NOT NULL DEFAULT '',
      duration_hours INTEGER NOT NULL DEFAULT 0,
      prerequisites TEXT NOT NULL DEFAULT '',
      topics_json TEXT NOT NULL,
      objectives_json TEXT NOT NULL,
      short_questions_json TEXT NOT NULL DEFAULT '[]',
      lesson TEXT NOT NULL,
      quiz_json TEXT NOT NULL,
      assignment_prompt TEXT NOT NULL,
      assignment_details_json TEXT NOT NULL DEFAULT '{}',
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS lessons (
      id TEXT PRIMARY KEY,
      module_id TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      video_url TEXT,
      lesson_details_json TEXT NOT NULL DEFAULT '{}',
      video_json TEXT NOT NULL DEFAULT '{}',
      position INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS lessons_module_position_idx ON lessons(module_id, position);
    CREATE TABLE IF NOT EXISTS progress (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      module_id TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
      completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
      updated_at TEXT NOT NULL,
      PRIMARY KEY(user_id, module_id)
    );
    CREATE TABLE IF NOT EXISTS quiz_attempts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      module_id TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
      score INTEGER NOT NULL,
      total INTEGER NOT NULL,
      answers_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS submissions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      module_id TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
      response TEXT NOT NULL,
      submitted_at TEXT NOT NULL,
      grade REAL CHECK(grade IS NULL OR (grade >= 0 AND grade <= 100)),
      feedback TEXT,
      reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TEXT,
      UNIQUE(user_id, module_id)
    );
    CREATE INDEX IF NOT EXISTS submissions_module_idx ON submissions(module_id, submitted_at DESC);
  `);
  const moduleColumns = new Set(db.pragma("table_info(modules)").map(column => column.name));
  for (const [name, definition] of [
    ["weeks", "TEXT NOT NULL DEFAULT ''"],
    ["duration_hours", "INTEGER NOT NULL DEFAULT 0"],
    ["prerequisites", "TEXT NOT NULL DEFAULT ''"],
    ["assignment_details_json", "TEXT NOT NULL DEFAULT '{}'"],
    ["short_questions_json", "TEXT NOT NULL DEFAULT '[]'"]
  ]) {
    if (!moduleColumns.has(name)) db.exec(`ALTER TABLE modules ADD COLUMN ${name} ${definition}`);
  }
  const lessonColumns = new Set(db.pragma("table_info(lessons)").map(column => column.name));
  for (const [name, definition] of [
    ["lesson_details_json", "TEXT NOT NULL DEFAULT '{}'"],
    ["video_json", "TEXT NOT NULL DEFAULT '{}'"]
  ]) {
    if (!lessonColumns.has(name)) db.exec(`ALTER TABLE lessons ADD COLUMN ${name} ${definition}`);
  }
  const now = new Date().toISOString();
  db.prepare("INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, ?)").run(now);
  const insertModule = db.prepare(`
    INSERT OR IGNORE INTO modules
      (id, number, title, summary, icon, weeks, duration_hours, prerequisites, topics_json, objectives_json,
       short_questions_json, lesson, quiz_json, assignment_prompt, assignment_details_json, updated_at)
    VALUES (@id, @number, @title, @summary, @icon, @weeks, @durationHours, @prerequisites, @topics, @objectives,
       @shortQuestions, @lesson, @quiz, @assignment, @assignmentDetails, @updatedAt)
  `);
  const insertLesson = db.prepare(`
    INSERT OR IGNORE INTO lessons
      (id, module_id, title, content, video_url, lesson_details_json, video_json, position, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const updateSeedLesson = db.prepare(`
    UPDATE lessons SET title = ?, content = ?, video_url = ?, lesson_details_json = ?, video_json = ?,
      position = ?, updated_at = ?
    WHERE id = ?
  `);
  const seed = db.transaction(() => {
    for (const module of courseModules) {
      insertModule.run({
        ...module,
        topics: JSON.stringify(module.topics),
        objectives: JSON.stringify(module.objectives),
        shortQuestions: JSON.stringify(module.shortAnswers),
        quiz: JSON.stringify(module.quiz),
        assignment: module.assignment,
        assignmentDetails: JSON.stringify(module.assignmentDetails),
        updatedAt: now
      });
    }
    const syllabusMigration = db.prepare("SELECT 1 FROM schema_migrations WHERE version = 3").get();
    if (!syllabusMigration) {
      const updateModule = db.prepare(`
        UPDATE modules SET weeks = ?, duration_hours = ?, prerequisites = ?, title = ?, summary = ?, icon = ?,
          topics_json = ?, objectives_json = ?, short_questions_json = ?, lesson = ?, quiz_json = ?,
          assignment_prompt = ?, assignment_details_json = ?, updated_at = ?
        WHERE id = ?
      `);
      for (const module of courseModules) {
        updateModule.run(
          module.weeks, module.durationHours, module.prerequisites, module.title, module.summary, module.icon,
          JSON.stringify(module.topics), JSON.stringify(module.objectives), JSON.stringify(module.shortAnswers),
          module.lesson, JSON.stringify(module.quiz), module.assignment, JSON.stringify(module.assignmentDetails),
          now, module.id
        );
        module.lessons.forEach((item, index) => {
          const id = `seed-${module.id}-lesson-${index + 1}`;
          const details = {
            estimatedMinutes: item.estimatedMinutes,
            objectives: item.objectives,
            definition: item.definition,
            importance: item.importance,
            principles: item.principles,
            steps: item.steps,
            formula: item.formula,
            application: item.application,
            example: item.example,
            advantages: item.advantages,
            limitations: item.limitations,
            comparison: item.comparison,
            misconceptions: item.misconceptions,
            keyTakeaways: item.keyTakeaways,
            revision: item.revision,
            questions: item.questions
          };
          const video = JSON.stringify(item.video);
          const lessonDetails = JSON.stringify(details);
          if (db.prepare("SELECT 1 FROM lessons WHERE id = ?").get(id)) {
            updateSeedLesson.run(
              item.title, item.content, item.videoUrl, lessonDetails, video, index + 1, now, id
            );
          } else {
            insertLesson.run(
              id, module.id, item.title, item.content, item.videoUrl, lessonDetails, video, index + 1, now, now
            );
          }
        });
        db.prepare("DELETE FROM lessons WHERE module_id = ? AND id LIKE 'seed-%-lesson-%' AND position > ?")
          .run(module.id, module.lessons.length);
      }
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (3, ?)").run(now);
    }
    const sequenceMigration = db.prepare("SELECT 1 FROM schema_migrations WHERE version = 4").get();
    if (!sequenceMigration) {
      const updateSequence = db.prepare("UPDATE modules SET weeks = ?, updated_at = ? WHERE id = ?");
      for (const module of courseModules) updateSequence.run(module.weeks, now, module.id);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (4, ?)").run(now);
    }
  });
  seed();
  return db;
}

export function writeAudit(db, actorId, action, targetUserId = null, details = {}) {
  db.prepare(`
    INSERT INTO audit_logs (id, actor_id, action, target_user_id, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(randomUUID(), actorId, action, targetUserId, JSON.stringify(details), new Date().toISOString());
}
