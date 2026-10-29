# MedLearn — Medical Text & Image Processing

MedLearn is a single integrated learning platform for a six-module university course. It includes a responsive student learning space, instructor assessment tools, and an administrator workspace backed by server-enforced roles and a persistent SQLite database.

## Requirements

- Node.js 20.19+ or 22.12+ (Node.js 24 LTS recommended)
- npm
- HTTPS termination in front of the application in production

## Local setup

```powershell
npm install
npm run dev
```

The Vite client runs at `http://127.0.0.1:5173` and proxies `/api` requests to the local API at `http://127.0.0.1:3000`. Data is stored in `data/platform.sqlite` by default. Override the database location with `DATABASE_PATH`.

No public signup route or default account exists. Create the first administrator from a trusted terminal. In PowerShell, the following prompts for the initial password instead of putting it in the command history:

```powershell
$env:BOOTSTRAP_ADMIN_NAME = "Course Administrator"
$env:BOOTSTRAP_ADMIN_EMAIL = "admin@your-university.edu"
$env:BOOTSTRAP_ADMIN_USERNAME = "course.admin"
$securePassword = Read-Host "Initial administrator password" -AsSecureString
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try {
  $env:BOOTSTRAP_ADMIN_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
  npm run bootstrap-admin
} finally {
  Remove-Item Env:BOOTSTRAP_ADMIN_PASSWORD -ErrorAction SilentlyContinue
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
}
Remove-Item Env:BOOTSTRAP_ADMIN_NAME, Env:BOOTSTRAP_ADMIN_EMAIL, Env:BOOTSTRAP_ADMIN_USERNAME -ErrorAction SilentlyContinue
```

The bootstrap command is local/CLI-only, creates an administrator only if the configured email and username are unused, and makes no changes when that administrator already exists. It will not promote an existing student or instructor. Keep bootstrap credentials out of source control and clear them from your deployment environment after provisioning.

If an active administrator loses access, use the same trusted-terminal password prompt with `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`, then run `npm run recover-admin`. Recovery only updates the password for an already existing active administrator; it cannot create or promote an account. It revokes that administrator’s sessions and requires a password change at next sign-in. These CLI commands require direct access to the application host and database.

## Roles and workflows

- **Administrator:** manage students and instructors, account status and temporary password resets, module notes and assignment prompts, course-wide progress, assessment reviews, and the audit log. Administrator accounts are created only by the controlled bootstrap/recovery commands.
- **Instructor:** view course-scoped student progress and review/grade assignment submissions. Instructors cannot manage accounts or access administrator endpoints.
- **Student:** access the six modules, lesson notes, interactive image-windowing demonstration, quizzes, assignment submission, and their own progress and results.

An administrator-created account receives a randomly generated temporary password. It is returned only once to the administrator and requires the new user to choose a password before accessing the course. Share temporary passwords through a trusted channel. Account recovery is administrator-initiated; no email provider or public password-reset flow is configured.

## Course syllabus and learning resources

The course map follows the supplied six-module syllabus: Medical Image Sources (8 hours); Image Processing in Clinical Practice (8); Image Representation (8); Operations in Intensity Space (7); Filtering, Transformations and Segmentation (7); and Spatial Transforms (7), for 45 stated study hours. Each module includes its syllabus topics, topic-aligned lesson notes, ten multiple-choice questions, five short-answer prompts, and an applied assignment with suggested steps, deliverables, and a 100-point rubric. The sequence labels are organizational and do not imply a calendar schedule. Topic video links open unverified external YouTube search results—not videos hosted or vetted by this application—so instructors should review and approve resources. Students can browse video resources separately and export module notes. Administrators can edit module content, quizzes, short-answer prompts, rubrics, supplementary lesson notes, and HTTPS video links in **Course content**.

## Production deployment

1. Set `NODE_ENV=production`, `PORT`, `DATABASE_PATH`, and a durable, access-controlled volume for the SQLite database.
2. Run `npm ci` and `npm run build`.
3. Provision the initial administrator using the bootstrap command on the host. Do not expose bootstrap or recovery credentials through a public web route.
4. Run `npm start` behind a TLS-terminating reverse proxy. The application binds to `127.0.0.1`; expose it only through the trusted proxy and restrict administrative access appropriately.
5. The production session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`; CSRF tokens are checked on state-changing requests and bound to authenticated sessions. Use HTTPS for the entire browser session.
6. Back up the SQLite database securely and test restores. Apply operating-system and dependency updates, monitor logs, and restrict access to database and audit records.

Sessions expire after 12 hours by default (`SESSION_TTL_HOURS` can tune the timeout). Active accounts and session records are checked on each protected request; deactivation and password reset revoke existing sessions. Authentication is rate-limited and invalid sign-in errors do not reveal whether an account exists. Password hashes use Argon2id.

The demo course content and imaging illustration are educational only and must not be used for diagnosis. Do not put protected health information into the learning platform.

## Verification

```powershell
npm test
npm run build
```

The automated security tests exercise unauthenticated access, disabled registration, role boundaries, initial/temporary password handling, session revocation, one-active-administrator protection, password hashing, safe login failures, audit records, student record scoping, and server-side quiz scoring.
