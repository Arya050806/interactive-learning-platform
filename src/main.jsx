import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

let csrfToken = "";

async function request(path, options = {}) {
  const headers = { ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers };
  if (["POST", "PATCH", "DELETE"].includes(options.method)) headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(`/api${path}`, {
    ...options,
    headers,
    credentials: "same-origin",
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && !path.includes("/auth/login")) {
      window.dispatchEvent(new Event("medlearn-session-expired"));
    }
    throw new Error(payload.error ?? "Something went wrong. Please try again.");
  }
  return payload;
}

const roleName = { admin: "Administrator", instructor: "Instructor", student: "Student" };
const navItems = {
  admin: [
    ["overview", "Overview", "⌂"],
    ["users", "User management", "♙"],
    ["content", "Course content", "▤"],
    ["review", "Assessments", "✓"],
    ["progress", "Student progress", "◔"],
    ["audit", "Audit log", "≋"],
    ["modules", "Course modules", "▦"]
  ],
  instructor: [
    ["overview", "Overview", "⌂"],
    ["review", "Assignment review", "✓"],
    ["progress", "Student progress", "◔"],
    ["modules", "Course modules", "▦"]
  ],
  student: [
    ["overview", "My learning", "⌂"],
    ["modules", "Course modules", "▦"],
    ["videos", "Video resources", "▷"],
    ["records", "My results", "◔"]
  ]
};

function Logo({ small = false }) {
  return <div className={`brand ${small ? "brand-small" : ""}`}>
    <span className="brand-mark">m<span>+</span></span>
    {!small && <span className="brand-copy"><strong>medlearn</strong><small>MEDICAL IMAGE & TEXT</small></span>}
  </div>;
}

function App() {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);
  const [page, setPage] = useState("overview");
  const [notice, setNotice] = useState(null);
  const [moduleId, setModuleId] = useState(null);
  const [mustChange, setMustChange] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);

  useEffect(() => {
    let active = true;
    const expireSession = () => {
      setUser(null);
      setMustChange(false);
    };
    window.addEventListener("medlearn-session-expired", expireSession);
    (async () => {
      try {
        const csrf = await request("/auth/csrf");
        csrfToken = csrf.csrfToken;
        const session = await request("/auth/session");
        if (active) {
          setUser(session.user);
          setMustChange(session.user.mustChangePassword);
        }
      } catch {
        if (active) setUser(null);
      } finally {
        if (active) setReady(true);
      }
    })();
    return () => {
      active = false;
      window.removeEventListener("medlearn-session-expired", expireSession);
    };
  }, []);

  const notify = (text, tone = "success") => {
    setNotice({ text, tone });
    window.setTimeout(() => setNotice(null), 4200);
  };

  const onLogin = (nextUser, nextCsrf) => {
    csrfToken = nextCsrf;
    setUser(nextUser);
    setMustChange(nextUser.mustChangePassword);
    setPage("overview");
  };

  const logout = async () => {
    try { await request("/auth/logout", { method: "POST" }); }
    catch (cause) { notify(cause.message, "error"); }
    setUser(null);
    setMustChange(false);
    setPage("overview");
  };

  if (!ready) return <div className="loading-screen"><Logo /><div className="spinner" /><span>Preparing your learning space</span></div>;
  if (!user) return <Login onLogin={onLogin} />;
  if (mustChange) return <PasswordSetup user={user} onChanged={setUser} notify={notify} />;

  return <div className="app-shell">
    <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
      <Logo />
      <div className="workspace-label">WORKSPACE</div>
      <nav className="side-nav">
        {navItems[user.role].map(([key, title, icon]) =>
          <button key={key} className={`nav-item ${page === key ? "active" : ""}`} onClick={() => { setPage(key); setModuleId(null); setMobileNav(false); }}>
            <span className="nav-icon">{icon}</span><span>{title}</span>
            {key === "users" && <span className="nav-dot" />}
          </button>
        )}
      </nav>
      <div className="sidebar-bottom">
        <div className="secure-note"><span className="secure-icon">◈</span><div><strong>Private learning</strong><small>Your account is protected</small></div></div>
        <button className="profile-button" onClick={logout}>
          <span className="avatar">{user.fullName?.slice(0, 1).toUpperCase()}</span>
          <span className="profile-meta"><strong>{user.fullName}</strong><small>{roleName[user.role]}</small></span>
          <span className="logout-glyph">↗</span>
        </button>
      </div>
    </aside>
    {mobileNav && <button className="nav-scrim" aria-label="Close menu" onClick={() => setMobileNav(false)} />}
    <main className="main-area">
      <header className="topbar">
        <button className="mobile-menu" aria-label="Open navigation" onClick={() => setMobileNav(true)}>☰</button>
        <div className="crumb">Learning space <span>/</span> <b>{navItems[user.role].find(item => item[0] === page)?.[1] ?? "Course"}</b></div>
        <div className="topbar-right"><span className="online-indicator" /> Secure session <span className="topbar-separator">·</span><span>{user.fullName}</span></div>
      </header>
      <div className="page-content">
        {notice && <div role="status" className={`toast ${notice.tone}`}>{notice.text}<button onClick={() => setNotice(null)}>×</button></div>}
        {moduleId
          ? <ModuleDetail moduleId={moduleId} onBack={() => setModuleId(null)} notify={notify} />
          : <Page page={page} user={user} setPage={setPage} openModule={setModuleId} notify={notify} />}
      </div>
      <footer className="footer"><span>MedLearn · Medical Text & Image Processing</span><span>Learn thoughtfully. Practice responsibly.</span></footer>
    </main>
  </div>;
}

function Login({ onLogin }) {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorText, setErrorText] = useState("");
  useEffect(() => {
    request("/auth/csrf").then(result => { csrfToken = result.csrfToken; })
      .catch(() => setErrorText("The sign-in service is unavailable. Please try again shortly."));
  }, []);
  const submit = async event => {
    event.preventDefault();
    setErrorText("");
    if (!identifier.trim() || !password) { setErrorText("Enter your username or email and password."); return; }
    setLoading(true);
    try {
      const result = await request("/auth/login", { method: "POST", body: { identifier: identifier.trim(), password } });
      onLogin(result.user, result.csrfToken);
    } catch (cause) {
      setErrorText(cause.message);
    } finally { setLoading(false); }
  };
  return <main className="login-page">
    <section className="login-panel">
      <div className="login-brand"><Logo /></div>
      <div className="login-content">
        <div className="eyebrow"><span className="eyebrow-line" /> YOUR CLINICAL LEARNING STUDIO</div>
        <h1>Welcome<br />back<span className="period">.</span></h1>
        <p className="login-intro">Sign in to continue your journey in medical text and image processing.</p>
        <form className="login-form" onSubmit={submit} noValidate>
          <label htmlFor="identifier">Email or username</label>
          <div className="input-wrap"><span className="input-icon">✉</span><input id="identifier" autoComplete="username" value={identifier} onChange={event => setIdentifier(event.target.value)} placeholder="you@university.edu" /></div>
          <div className="label-row"><label htmlFor="password">Password</label><span className="field-note">Secure sign in</span></div>
          <div className="input-wrap"><span className="input-icon">⌑</span><input id="password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} placeholder="Enter your password" /><button className="show-password" type="button" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? "Hide" : "Show"}</button></div>
          {errorText && <div role="alert" className="form-error"><span>!</span>{errorText}</div>}
          <button className="button button-primary login-submit" type="submit" disabled={loading}>{loading ? <><span className="button-spinner" />Signing in…</> : <>Sign in <span>→</span></>}</button>
        </form>
        <div className="login-help"><span className="lock-symbol">⌑</span><span>Accounts are provided by your administrator.<br /><b>Need help?</b> Contact your course administrator to reset your access.</span></div>
        <div className="login-foot">Protected learning environment <span>·</span> No public registration</div>
      </div>
    </section>
    <section className="login-art" aria-label="Medical imaging illustration">
      <div className="art-glow" />
      <div className="art-top"><span>FIELD NOTES <b>01 — 06</b></span><span className="art-status"><i /> COURSE ONLINE</span></div>
      <div className="scan-frame">
        <div className="scan-topline"><span>AXIAL VIEW · T1</span><span>R 07 / 24</span></div>
        <div className="scan-image">
          <div className="scan-ring ring-one" /><div className="scan-ring ring-two" /><div className="scan-core" />
          <div className="scan-structure structure-one" /><div className="scan-structure structure-two" /><div className="scan-structure structure-three" />
          <div className="scan-crosshair" /><span className="scan-measure">18.4 mm</span><span className="scan-corner corner-one" /><span className="scan-corner corner-two" />
          <div className="scan-scale"><i /><i /><i /><i /><i /><i /><i /></div>
        </div>
        <div className="scan-caption"><span><i className="caption-dot" /> IMAGE PROCESSING</span><span>LAT 04.12 · SERIES 08</span></div>
      </div>
      <div className="art-title"><span>01 / 06 — VISUALIZE</span><h2>See the<br /><em>signal</em> within.</h2><p>Six modules. One connected view of the clinical data landscape.</p></div>
      <div className="art-bottom"><span>MEDICAL TEXT & IMAGE PROCESSING</span><span>EST. FOR LEARNING <b>✳</b></span></div>
    </section>
  </main>;
}

function PasswordSetup({ user, onChanged, notify }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [errorText, setErrorText] = useState("");
  const submit = async event => {
    event.preventDefault();
    if (newPassword.length < 12) { setErrorText("Use at least 12 characters for your new password."); return; }
    if (newPassword !== confirm) { setErrorText("The passwords do not match."); return; }
    setBusy(true);
    try {
      const result = await request("/auth/change-password", { method: "POST", body: { currentPassword, newPassword } });
      onChanged(result.user);
      notify("Your password has been updated.");
    } catch (cause) { setErrorText(cause.message); }
    finally { setBusy(false); }
  };
  return <main className="setup-page"><section className="setup-card"><Logo /><div className="eyebrow">ONE-TIME ACCOUNT SETUP</div><h1>Create your password.</h1><p>Your administrator created this account. Choose a new password before continuing.</p>
    <form className="login-form" onSubmit={submit}>
      {!user.mustChangePassword && <><label htmlFor="currentPassword">Current password</label><input id="currentPassword" className="plain-input" type={show ? "text" : "password"} value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} /></>}
      <label htmlFor="newPassword">New password</label><input id="newPassword" className="plain-input" type={show ? "text" : "password"} autoComplete="new-password" value={newPassword} onChange={event => setNewPassword(event.target.value)} minLength={12} required />
      <label htmlFor="confirmPassword">Confirm password</label><input id="confirmPassword" className="plain-input" type={show ? "text" : "password"} autoComplete="new-password" value={confirm} onChange={event => setConfirm(event.target.value)} minLength={12} required />
      <label className="checkbox-row"><input type="checkbox" checked={show} onChange={event => setShow(event.target.checked)} /> Show passwords</label>
      {errorText && <div role="alert" className="form-error">{errorText}</div>}
      <button className="button button-primary login-submit" disabled={busy}>{busy ? "Updating…" : "Set password and continue →"}</button>
    </form>
  </section></main>;
}

function Page({ page, user, setPage, openModule, notify }) {
  if (page === "overview") return user.role === "admin"
    ? <AdminOverview setPage={setPage} notify={notify} />
    : <LearningOverview user={user} openModule={openModule} notify={notify} />;
  if (page === "users" && user.role === "admin") return <UsersPage notify={notify} />;
  if (page === "content" && user.role === "admin") return <ContentPage notify={notify} />;
  if (page === "audit" && user.role === "admin") return <AuditPage />;
  if (page === "review" && ["admin", "instructor"].includes(user.role)) return <ReviewPage notify={notify} />;
  if (page === "progress" && user.role !== "student") return <ProgressPage user={user} />;
  if (page === "records" && user.role === "student") return <RecordsPage />;
  if (page === "modules") return <ModulesPage openModule={openModule} />;
  if (page === "videos") return <VideoLibrary openModule={openModule} />;
  return <LearningOverview user={user} openModule={openModule} notify={notify} />;
}

function PageHeading({ eyebrow, title, description, action }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>;
}

function useLoad(path, dependencies = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [errorText, setErrorText] = useState("");
  const reload = async () => {
    setLoading(true);
    try { setData(await request(path)); setErrorText(""); }
    catch (cause) { setErrorText(cause.message); }
    finally { setLoading(false); }
  };
  useEffect(() => { reload(); }, dependencies);
  return { data, setData, loading, errorText, reload };
}

function LoadState({ loading, errorText, emptyText, children }) {
  if (loading) return <div className="panel-state"><span className="spinner" />Loading your data…</div>;
  if (errorText) return <div className="panel-state error-state">{errorText}</div>;
  if (emptyText && !children) return <div className="panel-state">{emptyText}</div>;
  return children;
}

function LearningOverview({ user, openModule, notify }) {
  const { data: moduleData, loading, errorText } = useLoad("/course/modules", []);
  const { data: progressData, reload: reloadProgress } = useLoad("/me/progress", []);
  const { data: records } = useLoad("/me/records", []);
  const modules = moduleData?.modules ?? [];
  const completed = new Set((progressData?.progress ?? []).filter(item => item.completed).map(item => item.moduleId));
  const done = modules.filter(module => completed.has(module.id)).length;
  const next = modules.find(module => !completed.has(module.id)) ?? modules[0];
  const latestGrade = records?.submissions?.find(item => item.grade !== null)?.grade;
  return <>
    <div className="welcome-band"><div className="welcome-content"><span className="welcome-kicker">YOUR LEARNING JOURNEY <i>✳</i></span><h1>Good to see you,<br /><em>{user.fullName.split(" ")[0]}.</em></h1><p>Small steps through complex signals. Pick up where your curiosity left off.</p><button className="button button-white" onClick={() => next && openModule(next.id)}>Continue learning <span>→</span></button></div><div className="welcome-graphic"><div className="graphic-orbit orbit-a" /><div className="graphic-orbit orbit-b" /><div className="graphic-hex">m<span>+</span></div><span className="graphic-label label-a">SIGNAL / 01</span><span className="graphic-label label-b">ANATOMY OF DATA</span></div><div className="welcome-index">STUDIO NOTE <b>01.06</b></div></div>
    <div className="section-title-row"><div><div className="eyebrow">YOUR OVERVIEW</div><h2>Learning at a glance</h2></div><button className="text-button" onClick={() => openModule(next?.id)}>Open course map <span>→</span></button></div>
    <div className="stat-grid student-stats">
      <StatCard label="Modules completed" value={`${done} / ${modules.length || 6}`} detail="Keep a steady pace" icon="◈" accent="mint" />
      <StatCard label="Quiz attempts" value={records?.quizzes?.length ?? 0} detail="Practice builds confidence" icon="⌗" accent="lavender" />
      <StatCard label="Assignments" value={records?.submissions?.length ?? 0} detail={latestGrade !== undefined ? `Latest grade · ${latestGrade}%` : "Ready when you are"} icon="▤" accent="peach" />
      <StatCard label="Your role" value="Student" detail="Personal learning space" icon="♙" accent="blue" />
    </div>
    <div className="section-title-row modules-heading"><div><div className="eyebrow">THE COURSE</div><h2>Six connected modules</h2></div><span className="muted-count">01 — 06</span></div>
    <LoadState loading={loading} errorText={errorText}><div className="module-grid">{modules.map(module => <ModuleCard key={module.id} module={module} complete={completed.has(module.id)} onClick={() => openModule(module.id)} />)}</div></LoadState>
  </>;
}

function StatCard({ label, value, detail, icon, accent }) {
  return <div className="stat-card"><div className={`stat-icon ${accent}`}>{icon}</div><div className="stat-label">{label}</div><div className="stat-value">{value}</div><div className="stat-detail">{detail}</div></div>;
}

function ModuleCard({ module, complete, onClick }) {
  return <button className={`module-card ${complete ? "module-complete" : ""}`} onClick={onClick}>
    <div className="module-card-top"><span className="module-number">MODULE {String(module.number).padStart(2, "0")}</span><span className="module-icon">{module.icon}</span></div>
    <h3>{module.title}</h3><p>{module.summary}</p>
    <div className="topic-list">{module.topics?.slice(0, 2).map(topic => <span key={topic}>{topic}</span>)}</div>
    <div className="module-card-bottom"><span>{complete ? <><i className="checkmark">✓</i> COMPLETED</> : "EXPLORE MODULE"}</span><span className="arrow-circle">↗</span></div>
  </button>;
}

function ModulesPage({ openModule }) {
  const { data, loading, errorText } = useLoad("/course/modules", []);
  return <><PageHeading eyebrow="THE CURRICULUM · 6 MODULES" title="Course modules" description="A guided path from image fundamentals to responsible clinical workflows." />
    {data?.schedule && <section className="surface-card syllabus-card"><div className="card-heading"><div><div className="eyebrow">SUPPLIED COURSE SYLLABUS</div><h2>Full syllabus at a glance</h2></div><span className="muted-count">6 MODULES · 45 STUDY HOURS</span></div><div className="syllabus-list">{data.schedule.map((item, index) => {
      const module = data.modules.find(entry => entry.id === item.moduleId);
      return <button className="syllabus-row" key={item.moduleId} onClick={() => openModule(item.moduleId)}><span className="syllabus-week">{item.weeks}<small>MODULE</small></span><span className="syllabus-unit">{String(index + 1).padStart(2, "0")}<small>UNIT</small></span><span className="syllabus-description"><strong>{module?.title}</strong><small>{item.focus}</small></span><span className="syllabus-milestone"><small>MODULE MILESTONE</small>{item.milestone}</span><span className="syllabus-arrow">↗</span></button>;
    })}</div><div className="syllabus-assessment"><div className="eyebrow">ASSESSMENT PLAN</div>{data.assessment.map(item => <div key={item.name}><strong>{item.name}</strong><b>{item.weighting}</b><span>{item.description}</span></div>)}</div></section>}
    <LoadState loading={loading} errorText={errorText}><div className="module-grid module-grid-large">{data?.modules?.map(module => <ModuleCard key={module.id} module={module} onClick={() => openModule(module.id)} />)}</div></LoadState>
  </>;
}

function VideoLibrary({ openModule }) {
  const { data, loading, errorText } = useLoad("/course/modules", []);
  const [search, setSearch] = useState("");
  const videos = (data?.modules ?? []).flatMap(module => module.lessons.map(lesson => ({
    ...lesson.video,
    sourceUrl: lesson.video?.sourceUrl ?? lesson.videoUrl,
    lessonTitle: lesson.title,
    moduleId: module.id,
    moduleTitle: module.title,
    moduleNumber: module.number,
    lessonId: lesson.id
  }))).filter(video => `${video.title ?? ""} ${video.lessonTitle} ${video.moduleTitle}`
    .toLowerCase().includes(search.trim().toLowerCase()));
  return <>
    <PageHeading eyebrow="COURSE MEDIA" title="Video resources" description="Topic-matched learning resources for the six syllabus modules. Search links are not verified endorsements or embedded lectures; review any resource with your instructor." />
    <label className="video-search-label">Search topics<input type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder="e.g. MRI, thresholding, DICOM" /></label>
    <LoadState loading={loading} errorText={errorText}>{videos.length ? <div className="video-library-grid">{videos.map((video, index) => <article className="video-resource-card" key={video.lessonId}><div className="video-resource-icon">▷</div><div className="eyebrow">MODULE {String(video.moduleNumber).padStart(2, "0")} · {video.moduleTitle}</div><h2>{video.title ?? `Explore ${video.lessonTitle}`}</h2><p>{video.description}</p><small>Topic: {video.lessonTitle} · {video.verified ? "Verified resource" : "Unverified search results"}</small><div className="video-library-actions">{video.sourceUrl && <a className="button button-outline" href={video.sourceUrl} target="_blank" rel="noreferrer">Browse resources ↗</a>}<button className="text-button" onClick={() => openModule(video.moduleId)}>Open lesson →</button></div></article>)}</div> : <div className="panel-state">No matching video resources were found.</div>}</LoadState>
  </>;
}

function exportModuleNotes(module) {
  const text = [
    module.title,
    "=".repeat(module.title.length),
    `Study time: ${module.durationHours} hours`,
    `Topics: ${module.topics.join(", ")}`,
    "",
    "Learning objectives",
    ...module.objectives.map(item => `• ${item}`),
    "",
    "Module notes",
    module.lesson,
    ...module.lessons.flatMap((item, index) => [
      "",
      `${index + 1}. ${item.title}`,
      item.content,
      item.formula ? `Formula: ${item.formula}` : "",
      item.revision ? `Revision: ${item.revision}` : "",
      ...(item.keyTakeaways ?? []).map(tip => `- ${tip}`)
    ])
  ].filter(Boolean).join("\n");
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `${module.id}-lecture-notes.txt`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function LessonDetail({ label, value }) {
  if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) return null;
  return <div className="lesson-detail"><h4>{label}</h4>{Array.isArray(value)
    ? <ul>{value.map((item, index) => <li key={`${label}-${index}`}>{item}</li>)}</ul>
    : <p>{value}</p>}</div>;
}

function ModuleDetail({ moduleId, onBack, notify }) {
  const { data, loading, errorText } = useLoad("/course/modules", [moduleId]);
  const { data: progressData, reload: reloadProgress } = useLoad("/me/progress", [moduleId]);
  const { data: records, reload: reloadRecords } = useLoad("/me/records", [moduleId]);
  const module = data?.modules?.find(item => item.id === moduleId);
  const [answers, setAnswers] = useState({});
  const [quizResult, setQuizResult] = useState(null);
  const [assignment, setAssignment] = useState("");
  const [brightness, setBrightness] = useState(100);
  const [contrast, setContrast] = useState(100);
  const completed = progressData?.progress?.some(item => item.moduleId === moduleId && item.completed);
  const priorSubmission = records?.submissions?.find(item => item.moduleId === moduleId);
  const quizSubmit = async () => {
    const selected = module.quiz.map((_question, index) => answers[index]);
    if (selected.some(answer => !Number.isInteger(answer))) { notify("Answer each question before submitting.", "error"); return; }
    try {
      const result = await request(`/me/quizzes/${module.id}/attempts`, { method: "POST", body: { answers: selected } });
      setQuizResult(result);
      reloadRecords();
    } catch (cause) { notify(cause.message, "error"); }
  };
  const assignmentSubmit = async event => {
    event.preventDefault();
    try {
      await request(`/me/assignments/${module.id}`, { method: "POST", body: { response: assignment } });
      setAssignment("");
      await reloadRecords();
      notify("Assignment submitted for review.");
    } catch (cause) { notify(cause.message, "error"); }
  };
  const toggleComplete = async () => {
    try {
      await request("/me/progress", { method: "POST", body: { moduleId: module.id, completed: !completed } });
      await reloadProgress();
      notify(completed ? "Module marked as in progress." : "Module marked complete. Nice work!");
    } catch (cause) { notify(cause.message, "error"); }
  };
  if (loading) return <div className="panel-state"><span className="spinner" />Loading module…</div>;
  if (errorText || !module) return <div className="panel-state error-state">{errorText || "Module not found."}<button className="text-button" onClick={onBack}>Go back</button></div>;
  return <div className="module-detail">
    <button className="back-link" onClick={onBack}>← <span>All modules</span></button>
    <div className="detail-hero"><div><span className="module-number">MODULE {String(module.number).padStart(2, "0")} <i>·</i> SEQUENCE {module.weeks} · {module.durationHours} STUDY HOURS</span><h1>{module.title}</h1><p>{module.summary}</p><div className="detail-topics">{module.topics?.map(topic => <span key={topic}>{topic}</span>)}</div><div className="module-prerequisite"><strong>Before you begin</strong> {module.prerequisites}</div></div><div className="detail-glyph">{module.icon}</div></div>
    <div className="detail-columns">
      <div className="detail-main">
        <section className="content-card"><div className="section-label"><span>01</span> LEARNING OBJECTIVES</div><h2>What you’ll explore</h2><ul className="objective-list">{module.objectives?.map(item => <li key={item}><span>✓</span>{item}</li>)}</ul></section>
        <section className="content-card lesson-card"><div className="section-label"><span>02</span> LECTURE NOTES</div><div className="section-title-row"><h2>Module overview</h2><button className="text-button" onClick={() => exportModuleNotes(module)}>Export notes ↓</button></div><p className="lesson-copy">{module.lesson}</p><div className="note-callout"><span>✳</span><p><strong>Practice responsibly</strong><br />Learning examples are for education, not clinical diagnosis. Preserve source data and verify every processing step.</p></div></section>
        <section className="content-card"><div className="section-label"><span>03</span> TOPIC-BY-TOPIC SYLLABUS</div><h2>{module.lessons?.length ?? 0} focused lessons</h2><p className="syllabus-intro">Lessons are organized around the specified syllabus topics and include objectives, explanations, examples, limitations, and revision prompts. Video links are unverified topic searches, not embedded or endorsed lectures.</p>{module.lessons?.map((lesson, index) => <article className="topic-lesson" key={lesson.id}><div className="topic-lesson-heading"><span>{String(index + 1).padStart(2, "0")}</span><h3>{lesson.title}</h3>{lesson.estimatedMinutes && <small>{lesson.estimatedMinutes} min</small>}</div>{lesson.objectives?.length > 0 && <LessonDetail label="Learning objectives" value={lesson.objectives} />}<p>{lesson.content}</p><LessonDetail label="Key principles" value={lesson.principles} /><LessonDetail label="Worked steps" value={lesson.steps} />{lesson.formula && <div className="formula-callout"><strong>Formula</strong><p>{lesson.formula}</p></div>}<LessonDetail label="Clinical and technical application" value={lesson.application} /><LessonDetail label="Example" value={lesson.example} /><LessonDetail label="Advantages" value={lesson.advantages} /><LessonDetail label="Limitations" value={lesson.limitations} /><LessonDetail label="Compare with" value={lesson.comparison} /><LessonDetail label="Common misconceptions" value={lesson.misconceptions} /><LessonDetail label="Key takeaways" value={lesson.keyTakeaways} /><LessonDetail label="Revision prompt" value={lesson.revision} /><LessonDetail label="Check your understanding" value={lesson.questions} />{lesson.videoUrl && <a className="video-resource-link" href={lesson.video?.sourceUrl ?? lesson.videoUrl} target="_blank" rel="noreferrer">▶ <span>Browse unverified video resources for this topic</span> ↗</a>}</article>)}</section>
        <section className="content-card lab-card"><div className="section-label"><span>04</span> INTERACTIVE DEMONSTRATION</div><h2>Image windowing lab</h2><p>Adjust display contrast and brightness to explore how intensity mapping changes visual emphasis.</p><div className="image-lab"><svg className="lab-scan" viewBox="0 0 360 220" role="img" aria-label="Illustrative medical scan with adjustable contrast"><defs><radialGradient id="tissue"><stop offset="0" stopColor="#edf5f2" /><stop offset=".4" stopColor="#929e9d" /><stop offset=".72" stopColor="#46575c" /><stop offset="1" stopColor="#17272e" /></radialGradient><filter id="soft"><feGaussianBlur stdDeviation="3" /></filter></defs><rect width="360" height="220" fill="#101d22" /><g style={{ filter: `contrast(${contrast}%) brightness(${brightness}%)` }}><ellipse cx="180" cy="111" rx="90" ry="97" fill="url(#tissue)" /><ellipse cx="180" cy="110" rx="63" ry="69" fill="#53646a" opacity=".8" /><ellipse cx="152" cy="100" rx="17" ry="31" fill="#c6d0ca" opacity=".9" filter="url(#soft)" /><ellipse cx="208" cy="100" rx="17" ry="31" fill="#c6d0ca" opacity=".9" filter="url(#soft)" /><path d="M162 130 Q180 150 198 130 Q188 170 180 171 Q172 170 162 130" fill="#26353b" /><ellipse cx="180" cy="60" rx="25" ry="12" fill="#eef2ed" opacity=".6" /></g><path d="M180 12v196M75 110h210" stroke="#90d5bb" strokeWidth=".7" strokeDasharray="3 5" opacity=".5" /><text x="15" y="20" fill="#90d5bb" fontSize="7">ILLUSTRATIVE · NOT A DIAGNOSTIC IMAGE</text></svg><div className="lab-controls"><label>Brightness <span>{brightness}%</span><input type="range" min="60" max="150" value={brightness} onChange={event => setBrightness(Number(event.target.value))} /></label><label>Contrast <span>{contrast}%</span><input type="range" min="60" max="180" value={contrast} onChange={event => setContrast(Number(event.target.value))} /></label><button className="text-button" onClick={() => { setBrightness(100); setContrast(100); }}>Reset adjustments ↺</button></div></div></section>
        <section className="content-card quiz-card"><div className="section-label"><span>05</span> KNOWLEDGE CHECK · {module.quiz.length} QUESTIONS</div><h2>Module quiz</h2>{module.quiz.map((question, index) => <div className="quiz-question" key={question.question}><h3><span>{String(index + 1).padStart(2, "0")}</span>{question.question}</h3><div className="quiz-options">{question.options.map((option, optionIndex) => <label key={option} className={`quiz-option ${answers[index] === optionIndex ? "selected" : ""}`}><input type="radio" name={`q-${index}`} checked={answers[index] === optionIndex} onChange={() => setAnswers(current => ({ ...current, [index]: optionIndex }))} /><span className="radio-custom" />{option}</label>)}</div></div>)}<button className="button button-dark" onClick={quizSubmit}>Submit quiz <span>→</span></button>{quizResult && <div className="quiz-result">You scored <strong>{quizResult.score} / {quizResult.total}</strong>. Results saved to your learning record.{quizResult.review?.map((item, index) => <div className={`quiz-feedback ${item.isCorrect ? "correct" : "incorrect"}`} key={index}><strong>{index + 1}. {item.isCorrect ? "Correct" : "Review this answer"}</strong><p>{item.explanation}</p></div>)}</div>}</section>
        <section className="content-card short-answer-card"><div className="section-label"><span>06</span> SHORT-ANSWER PRACTICE · {module.shortQuestions?.length ?? 0} QUESTIONS</div><h2>Apply your understanding</h2><p>Use these prompts to explain concepts in your own words. Discuss your responses with your instructor; this practice is not automatically graded.</p>{module.shortQuestions?.map((item, index) => <article className="short-answer-prompt" key={`${item.topic}-${index}`}><span>{String(index + 1).padStart(2, "0")} · {item.topic}</span><p>{item.question}</p></article>)}</section>
        <section className="content-card assignment-card"><div className="section-label"><span>07</span> MODULE ASSIGNMENT · {module.assignmentDetails?.estimatedHours ?? 3} HOURS</div><h2>Put it into practice</h2><p className="assignment-prompt">{module.assignment}</p>{module.assignmentDetails?.overview && <p className="assignment-overview">{module.assignmentDetails.overview}</p>}
          {module.assignmentDetails?.steps?.length > 0 && <div className="assignment-section"><h3>Suggested steps</h3><ol>{module.assignmentDetails.steps.map((step, index) => <li key={index}>{step}</li>)}</ol></div>}
          {module.assignmentDetails?.deliverables?.length > 0 && <div className="assignment-section"><h3>Submit these deliverables</h3><ul>{module.assignmentDetails.deliverables.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
          {module.assignmentDetails?.rubric?.length > 0 && <div className="assignment-rubric"><h3>Assessment rubric <span>100 points</span></h3>{module.assignmentDetails.rubric.map((criterion, index) => <div key={index}><span>{criterion.criterion}</span><b>{criterion.points} pts</b></div>)}</div>}
          {priorSubmission && <div className="submission-status"><span>Submitted {new Date(priorSubmission.submittedAt).toLocaleDateString()}</span>{priorSubmission.grade !== null ? <span className="grade-pill">{priorSubmission.grade}% · {priorSubmission.feedback || "Reviewed"}</span> : <span className="pending-pill">Awaiting review</span>}</div>}<form onSubmit={assignmentSubmit}><label className="form-label" htmlFor="assignment-response">Your response</label><textarea id="assignment-response" value={assignment} onChange={event => setAssignment(event.target.value)} placeholder="Share your reflection, plan, or analysis…" maxLength={10000} required /><div className="form-actions"><span>{assignment.length} / 10,000</span><button className="button button-primary" type="submit">Submit assignment →</button></div></form></section>
      </div>
      <aside className="detail-aside"><div className="aside-card progress-aside"><div className="section-label">YOUR PROGRESS</div><div className={`progress-ring ${completed ? "ring-done" : ""}`}><span>{completed ? "✓" : "01"}</span></div><h3>{completed ? "Module complete" : "One step at a time"}</h3><p>{completed ? "This module is in your completed learning record." : "Mark this module complete when you’re ready."}</p><button className={`button ${completed ? "button-soft" : "button-dark"} full-button`} onClick={toggleComplete}>{completed ? "Mark in progress" : "Mark complete"} <span>→</span></button></div><div className="aside-card"><div className="section-label">IN THIS MODULE</div><div className="aside-list"><span><i>01</i> Learning objectives</span><span><i>02</i> Lecture notes</span><span><i>03</i> Visual demonstration</span><span><i>04</i> Knowledge check</span><span><i>05</i> Assignment</span></div></div><div className="aside-note"><span>✳</span><p>Pause, reflect, and connect each method to its clinical context.</p></div></aside>
    </div>
  </div>;
}

function AdminOverview({ setPage }) {
  const { data, loading, errorText } = useLoad("/admin/overview", []);
  const stats = data?.users ?? {};
  return <><PageHeading eyebrow="ADMINISTRATOR WORKSPACE" title="Good morning." description="A clear view of your course community and learning activity." action={<button className="button button-primary" onClick={() => setPage("users")}>＋ Create user</button>} />
    <LoadState loading={loading} errorText={errorText}><div className="stat-grid admin-stats"><StatCard label="Total users" value={stats.total ?? 0} detail="Across this learning space" icon="♙" accent="blue" /><StatCard label="Active accounts" value={stats.active ?? 0} detail={`${stats.inactive ?? 0} inactive`} icon="◉" accent="mint" /><StatCard label="Students" value={stats.students ?? 0} detail="Enrolled learners" icon="⌗" accent="lavender" /><StatCard label="Instructors" value={stats.instructors ?? 0} detail="Teaching team" icon="▤" accent="peach" /></div>
      <div className="admin-overview-grid"><section className="surface-card"><div className="card-heading"><div><div className="eyebrow">COMMUNITY</div><h2>Recent accounts</h2></div><button className="text-button" onClick={() => setPage("users")}>Manage users →</button></div><div className="recent-list">{(data?.recent ?? []).map(person => <div className="recent-row" key={person.id}><span className="avatar small-avatar">{person.fullName.slice(0, 1)}</span><div className="recent-person"><strong>{person.fullName}</strong><small>{person.email}</small></div><span className={`role-chip ${person.role}`}>{roleName[person.role]}</span><span className="recent-date">{new Date(person.createdAt).toLocaleDateString()}</span></div>)}</div></section>
      <section className="surface-card activity-card"><div className="eyebrow">COURSE ACTIVITY</div><h2>Learning in motion</h2><div className="activity-visual"><span>{data?.progress?.completedModules ?? 0}</span><small>module completions recorded</small><div className="activity-bars">{[42, 66, 49, 80, 57, 91, 64].map((height, index) => <i key={index} style={{ height: `${height}%` }} />)}</div></div><div className="activity-summary"><span>Quiz attempts <b>{data?.progress?.quizAttempts ?? 0}</b></span><span>Assignments reviewed <b>{data?.progress?.reviewed ?? 0} / {data?.progress?.assignments ?? 0}</b></span></div><button className="button button-soft full-button" onClick={() => setPage("progress")}>View student progress →</button></section></div>
      <div className="admin-shortcuts"><button onClick={() => setPage("content")}><span>▤</span><strong>Course content</strong><small>Edit module notes and assignments</small><i>↗</i></button><button onClick={() => setPage("review")}><span>✓</span><strong>Assessments</strong><small>Review work and share feedback</small><i>↗</i></button><button onClick={() => setPage("audit")}><span>≋</span><strong>Audit log</strong><small>Review sensitive account actions</small><i>↗</i></button></div>
    </LoadState>
  </>;
}

function UsersPage({ notify }) {
  const [search, setSearch] = useState("");
  const [role, setRole] = useState("");
  const [status, setStatus] = useState("");
  const [modal, setModal] = useState(false);
  const [oneTimePassword, setOneTimePassword] = useState(null);
  const query = useMemo(() => `/admin/users?${new URLSearchParams({ search, role, status })}`, [search, role, status]);
  const { data, loading, errorText, reload } = useLoad(query, [query]);
  const toggleStatus = async user => {
    const nextStatus = user.status === "active" ? "inactive" : "active";
    if (!window.confirm(`${nextStatus === "inactive" ? "Deactivate" : "Activate"} ${user.fullName}? ${nextStatus === "inactive" ? "Their active sessions will be revoked immediately." : ""}`)) return;
    try { await request(`/admin/users/${user.id}`, { method: "PATCH", body: { status: nextStatus } }); notify(`Account ${nextStatus === "active" ? "activated" : "deactivated"}.`); reload(); }
    catch (cause) { notify(cause.message, "error"); }
  };
  const resetPassword = async user => {
    if (!window.confirm(`Issue a new temporary password for ${user.fullName}? Their active sessions will be revoked.`)) return;
    try {
      const result = await request(`/admin/users/${user.id}/reset-password`, { method: "POST", body: {} });
      setOneTimePassword({ name: user.fullName, password: result.temporaryPassword });
      reload();
    } catch (cause) { notify(cause.message, "error"); }
  };
  return <><PageHeading eyebrow="ADMINISTRATION · PEOPLE" title="User management" description="Create and manage the people in your learning community." action={<button className="button button-primary" onClick={() => setModal(true)}>＋ Create user</button>} />
    <div className="table-toolbar"><div className="search-field"><span>⌕</span><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search name, email or username" /></div><select aria-label="Filter by role" value={role} onChange={event => setRole(event.target.value)}><option value="">All roles</option><option value="student">Students</option><option value="instructor">Instructors</option><option value="admin">Administrators</option></select><select aria-label="Filter by status" value={status} onChange={event => setStatus(event.target.value)}><option value="">All statuses</option><option value="active">Active</option><option value="inactive">Inactive</option></select><span className="result-count">{data?.users?.length ?? "—"} accounts</span></div>
    <div className="table-card"><LoadState loading={loading} errorText={errorText} emptyText="No accounts match those filters.">{data?.users?.length ? <div className="table-scroll"><table><thead><tr><th>NAME</th><th>ROLE</th><th>STATUS</th><th>CREATED</th><th>LAST SIGN IN</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{data.users.map(account => <tr key={account.id}><td><div className="table-person"><span className="avatar small-avatar">{account.fullName.slice(0, 1)}</span><span><strong>{account.fullName}</strong><small>{account.email} · @{account.username}</small></span></div></td><td><span className={`role-chip ${account.role}`}>{roleName[account.role]}</span></td><td><span className={`status-chip ${account.status}`}><i />{account.status}</span></td><td>{new Date(account.createdAt).toLocaleDateString()}</td><td>{account.lastLoginAt ? new Date(account.lastLoginAt).toLocaleDateString() : <span className="muted">Never</span>}</td><td><div className="row-actions">{account.role !== "admin" && <button title="Issue a temporary password" aria-label={`Reset password for ${account.fullName}`} onClick={() => resetPassword(account)}>↻</button>}<button title={account.status === "active" ? "Deactivate account" : "Activate account"} aria-label={`${account.status === "active" ? "Deactivate" : "Activate"} ${account.fullName}`} onClick={() => toggleStatus(account)}>{account.status === "active" ? "⋯" : "✓"}</button></div></td></tr>)}</tbody></table></div> : <div className="panel-state">No accounts match those filters.</div>}</LoadState></div>
    <div className="inline-info"><span>◈</span> Temporary passwords are shown only once. Share them with users through a trusted channel; never send passwords in public or shared messages.</div>
    {modal && <CreateUserModal close={() => setModal(false)} created={async result => { setModal(false); setOneTimePassword({ name: result.user.fullName, password: result.temporaryPassword }); await reload(); notify("Account created. Share its temporary password securely."); }} />}
    {oneTimePassword && <OneTimePasswordModal entry={oneTimePassword} close={() => setOneTimePassword(null)} />}
  </>;
}

function CreateUserModal({ close, created }) {
  const [form, setForm] = useState({ fullName: "", email: "", username: "", role: "student" });
  const [busy, setBusy] = useState(false);
  const [errorText, setErrorText] = useState("");
  const update = event => setForm(current => ({ ...current, [event.target.name]: event.target.value }));
  const submit = async event => {
    event.preventDefault(); setBusy(true); setErrorText("");
    try { await created(await request("/admin/users", { method: "POST", body: form })); }
    catch (cause) { setErrorText(cause.message); }
    finally { setBusy(false); }
  };
  return <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) close(); }}><section className="modal-card" role="dialog" aria-modal="true" aria-labelledby="create-user-title"><div className="modal-heading"><div><div className="eyebrow">NEW ACCOUNT</div><h2 id="create-user-title">Create a user</h2></div><button className="modal-close" onClick={close} aria-label="Close">×</button></div><p className="modal-intro">Create a student or instructor account. They’ll set their own password on first sign in.</p>
    <form className="admin-form" onSubmit={submit}><label>Full name<input name="fullName" value={form.fullName} onChange={update} maxLength={120} required placeholder="e.g. Alex Morgan" /></label><label>Email address<input name="email" type="email" value={form.email} onChange={update} maxLength={254} required placeholder="alex@university.edu" /></label><label>Username<input name="username" value={form.username} onChange={update} minLength={3} maxLength={32} pattern="[a-zA-Z0-9._-]+" required placeholder="alex.morgan" /><small>3–32 letters, numbers, dots, underscores or hyphens</small></label><label>Account role<select name="role" value={form.role} onChange={update}><option value="student">Student</option><option value="instructor">Instructor</option></select></label>
      {errorText && <div role="alert" className="form-error">{errorText}</div>}<div className="modal-actions"><button type="button" className="button button-outline" onClick={close}>Cancel</button><button className="button button-primary" disabled={busy}>{busy ? "Creating…" : "Create account →"}</button></div>
    </form></section></div>;
}

function OneTimePasswordModal({ entry, close }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(entry.password); setCopied(true); }
    catch { setCopied(false); }
  };
  return <div className="modal-backdrop"><section className="modal-card password-modal" role="dialog" aria-modal="true"><div className="modal-heading"><div><div className="eyebrow">SHARE SECURELY · SHOWN ONCE</div><h2>Account is ready</h2></div><button className="modal-close" onClick={close} aria-label="Close">×</button></div><p className="modal-intro">Provide <strong>{entry.name}</strong> this temporary password through a trusted channel. They must set a new password at sign in.</p><div className="one-time-secret"><code>{entry.password}</code><button onClick={copy}>{copied ? "Copied ✓" : "Copy"}</button></div><div className="security-callout">This password cannot be viewed again after you close this window.</div><div className="modal-actions"><button className="button button-primary" onClick={close}>Done</button></div></section></div>;
}

function ContentPage({ notify }) {
  const { data, loading, errorText, reload } = useLoad("/admin/modules", []);
  const [selected, setSelected] = useState("");
  const [form, setForm] = useState(null);
  const [lessonDraft, setLessonDraft] = useState(null);
  const [savingLesson, setSavingLesson] = useState(false);
  useEffect(() => {
    const item = data?.modules?.find(module => module.id === selected) ?? data?.modules?.[0];
    if (item) {
      setSelected(item.id);
      setForm({
        title: item.title,
        summary: item.summary,
        lesson: item.lesson,
        assignment: item.assignment,
        assignmentDetails: item.assignmentDetails,
        topics: item.topics,
        objectives: item.objectives,
        quiz: item.quiz
      });
    }
  }, [data, selected]);
  useEffect(() => { setLessonDraft(null); }, [selected]);
  const save = async event => {
    event.preventDefault();
    try { await request(`/admin/modules/${selected}`, { method: "PATCH", body: form }); await reload(); notify("Course module updated."); }
    catch (cause) { notify(cause.message, "error"); }
  };
  const saveLesson = async event => {
    event.preventDefault();
    setSavingLesson(true);
    try {
      const path = lessonDraft.id
        ? `/admin/lessons/${lessonDraft.id}`
        : `/admin/modules/${selected}/lessons`;
      await request(path, {
        method: lessonDraft.id ? "PATCH" : "POST",
        body: { title: lessonDraft.title, content: lessonDraft.content, videoUrl: lessonDraft.videoUrl, position: Number(lessonDraft.position) }
      });
      setLessonDraft(null);
      await reload();
      notify(lessonDraft.id ? "Lesson updated." : "Lesson and video link added.");
    } catch (cause) { notify(cause.message, "error"); }
    finally { setSavingLesson(false); }
  };
  const deleteLesson = async lesson => {
    if (!window.confirm(`Delete “${lesson.title}” and its video link?`)) return;
    try {
      await request(`/admin/lessons/${lesson.id}`, { method: "DELETE" });
      await reload();
      notify("Lesson deleted.");
    } catch (cause) { notify(cause.message, "error"); }
  };
  const updateQuestion = (index, changes) => setForm(current => ({
    ...current,
    quiz: current.quiz.map((question, questionIndex) => questionIndex === index ? { ...question, ...changes } : question)
  }));
  const updateOption = (questionIndex, optionIndex, value) => setForm(current => ({
    ...current,
    quiz: current.quiz.map((question, index) => index === questionIndex
      ? { ...question, options: question.options.map((option, itemIndex) => itemIndex === optionIndex ? value : option) }
      : question)
  }));
  const updateAssignmentDetails = (changes) => setForm(current => ({
    ...current,
    assignmentDetails: { ...current.assignmentDetails, ...changes }
  }));
  const updateRubric = (value) => updateAssignmentDetails({
    rubric: value.split("\n").map(line => {
      const [criterion, points] = line.split("|");
      return { criterion: criterion?.trim() ?? "", points: Number(points?.trim()) };
    }).filter(item => item.criterion)
  });
  if (loading || errorText) return <><PageHeading eyebrow="COURSE DESIGN" title="Course content" description="Manage the six learning modules." /><LoadState loading={loading} errorText={errorText} /></>;
  const module = data?.modules?.find(item => item.id === selected);
  return <><PageHeading eyebrow="COURSE DESIGN · CONTENT MANAGEMENT" title="Course content" description="Edit lecture notes, assignment prompts, and module summaries." />
    <div className="content-workspace"><aside className="module-picker"><div className="eyebrow">MODULES</div>{data?.modules?.map(item => <button key={item.id} className={selected === item.id ? "selected" : ""} onClick={() => setSelected(item.id)}><span>{String(item.number).padStart(2, "0")}</span>{item.title}<i>↗</i></button>)}</aside>
      {module && form && <section className="content-editor">
        <form className="editor-form" onSubmit={save}>
          <div className="editor-header"><div><div className="eyebrow">EDITING MODULE {String(module.number).padStart(2, "0")}</div><h2>{module.title}</h2></div><button className="button button-primary">Save changes →</button></div>
          <label>Module title<input className="plain-input" value={form.title} maxLength={160} onChange={event => setForm({ ...form, title: event.target.value })} required /></label>
          <label>Summary<input className="plain-input" value={form.summary} maxLength={500} onChange={event => setForm({ ...form, summary: event.target.value })} required /></label>
          <label>Topics, one per line<textarea className="compact-textarea" value={form.topics.join("\n")} onChange={event => setForm({ ...form, topics: event.target.value.split("\n").map(item => item.trim()).filter(Boolean) })} /></label>
          <label>Learning objectives, one per line<textarea className="compact-textarea" value={form.objectives.join("\n")} onChange={event => setForm({ ...form, objectives: event.target.value.split("\n").map(item => item.trim()).filter(Boolean) })} /></label>
          <label>Lecture notes<textarea value={form.lesson} maxLength={12000} onChange={event => setForm({ ...form, lesson: event.target.value })} required /></label>
          <label>Assignment prompt<textarea value={form.assignment} maxLength={2000} onChange={event => setForm({ ...form, assignment: event.target.value })} required /></label>
          <div className="editor-subsection"><div className="subsection-heading"><div><div className="eyebrow">ASSIGNMENT DESIGN</div><h3>Instructions and marking guide</h3></div></div>
            <label>Assignment overview<textarea className="compact-textarea" value={form.assignmentDetails.overview ?? ""} maxLength={2000} onChange={event => updateAssignmentDetails({ overview: event.target.value })} /></label>
            <label>Estimated study hours<input className="plain-input" type="number" min="1" max="100" value={form.assignmentDetails.estimatedHours ?? 3} onChange={event => updateAssignmentDetails({ estimatedHours: Number(event.target.value) })} /></label>
            <label>Suggested steps, one per line<textarea className="compact-textarea" value={(form.assignmentDetails.steps ?? []).join("\n")} onChange={event => updateAssignmentDetails({ steps: event.target.value.split("\n").map(item => item.trim()).filter(Boolean) })} /></label>
            <label>Deliverables, one per line<textarea className="compact-textarea" value={(form.assignmentDetails.deliverables ?? []).join("\n")} onChange={event => updateAssignmentDetails({ deliverables: event.target.value.split("\n").map(item => item.trim()).filter(Boolean) })} /></label>
            <label>Rubric criteria — one per line, “criterion | points”<textarea className="compact-textarea" value={(form.assignmentDetails.rubric ?? []).map(item => `${item.criterion} | ${item.points}`).join("\n")} onChange={event => updateRubric(event.target.value)} /></label>
          </div>
          <div className="editor-subsection"><div className="subsection-heading"><div><div className="eyebrow">KNOWLEDGE CHECK</div><h3>Quiz questions</h3></div><button type="button" className="button button-soft" onClick={() => setForm({ ...form, quiz: [...form.quiz, { question: "", options: ["", ""], answer: 0 }] })}>＋ Add question</button></div>
            {form.quiz.map((question, index) => <div className="quiz-editor" key={index}><div className="quiz-editor-title"><strong>Question {index + 1}</strong><button type="button" className="remove-link" onClick={() => setForm({ ...form, quiz: form.quiz.filter((_item, itemIndex) => itemIndex !== index) })}>Remove</button></div><label>Question text<input className="plain-input" value={question.question} maxLength={500} onChange={event => updateQuestion(index, { question: event.target.value })} required /></label>
              {question.options.map((option, optionIndex) => <label key={optionIndex}>Option {optionIndex + 1}<div className="quiz-option-editor"><input className="plain-input" value={option} maxLength={240} onChange={event => updateOption(index, optionIndex, event.target.value)} required /><button type="button" className={`correct-option ${question.answer === optionIndex ? "is-correct" : ""}`} onClick={() => updateQuestion(index, { answer: optionIndex })} aria-label={`Set option ${optionIndex + 1} as correct`}>{question.answer === optionIndex ? "✓ Correct" : "Set correct"}</button>{question.options.length > 2 && <button type="button" className="remove-link" onClick={() => updateQuestion(index, { options: question.options.filter((_item, itemIndex) => itemIndex !== optionIndex), answer: question.answer === optionIndex ? 0 : question.answer > optionIndex ? question.answer - 1 : question.answer })}>×</button>}</div></label>)}
              {question.options.length < 8 && <button type="button" className="text-button" onClick={() => updateQuestion(index, { options: [...question.options, ""] })}>＋ Add option</button>}
            </div>)}
          </div>
          <button className="button button-primary editor-save-bottom">Save all module changes →</button>
        </form>
        <section className="lesson-manager"><div className="subsection-heading"><div><div className="eyebrow">LESSONS & VIDEO LINKS</div><h3>Supplementary lessons</h3></div><button type="button" className="button button-soft" onClick={() => setLessonDraft({ title: "", content: "", videoUrl: "", position: module.lessons?.length ?? 0 })}>＋ Add lesson</button></div>
          {lessonDraft && <form className="lesson-editor" onSubmit={saveLesson}><label>Lesson title<input className="plain-input" value={lessonDraft.title} maxLength={160} onChange={event => setLessonDraft({ ...lessonDraft, title: event.target.value })} required /></label><label>Lesson notes<textarea value={lessonDraft.content} maxLength={12000} onChange={event => setLessonDraft({ ...lessonDraft, content: event.target.value })} required /></label><label>Video URL (optional, HTTPS)<input className="plain-input" type="url" value={lessonDraft.videoUrl} onChange={event => setLessonDraft({ ...lessonDraft, videoUrl: event.target.value })} placeholder="https://…" /></label><div className="lesson-editor-actions"><button type="button" className="button button-outline" onClick={() => setLessonDraft(null)}>Cancel</button><button className="button button-primary" disabled={savingLesson}>{savingLesson ? "Saving…" : "Save lesson →"}</button></div></form>}
          {module.lessons?.length ? <div className="managed-lessons">{module.lessons.map(lesson => <div className="managed-lesson" key={lesson.id}><div><strong>{lesson.title}</strong><small>{lesson.videoUrl ? "Video link included" : "Notes only"} · Position {lesson.position}</small></div><button type="button" className="text-button" onClick={() => setLessonDraft({ ...lesson, videoUrl: lesson.videoUrl ?? "" })}>Edit</button><button type="button" className="remove-link" onClick={() => deleteLesson(lesson)}>Delete</button></div>)}</div> : <div className="panel-state">No supplementary lessons yet.</div>}
        </section>
        <div className="inline-info"><span>◈</span> Quiz answer keys are visible only to administrators; students receive question text and options, while the server scores attempts.</div>
      </section>}
    </div>
  </>;
}

function ReviewPage({ notify }) {
  const { data, loading, errorText, reload } = useLoad("/teaching/submissions", []);
  const [editing, setEditing] = useState(null);
  const save = async event => {
    event.preventDefault();
    try { await request(`/teaching/submissions/${editing.id}`, { method: "PATCH", body: { grade: Number(editing.grade), feedback: editing.feedback } }); setEditing(null); await reload(); notify("Grade and feedback saved."); }
    catch (cause) { notify(cause.message, "error"); }
  };
  return <><PageHeading eyebrow="ASSESSMENT WORKSPACE" title="Assignment review" description="Read student reflections, assign a mark, and provide actionable feedback." />
    <LoadState loading={loading} errorText={errorText} emptyText="No assignments have been submitted yet.">{data?.submissions?.length ? <div className="submission-list">{data.submissions.map(item => <article className="submission-card" key={item.id}><div className="submission-top"><div><span className="module-number">{item.moduleTitle}</span><h3>{item.studentName}</h3><small>{item.studentEmail} · Submitted {new Date(item.submittedAt).toLocaleString()}</small></div><span className={item.grade === null ? "pending-pill" : "grade-pill"}>{item.grade === null ? "Needs review" : `${item.grade}%`}</span></div><p className="student-response">{item.response}</p>{item.feedback && !editing?.id && <div className="feedback-preview"><strong>Previous feedback</strong><p>{item.feedback}</p></div>}{editing?.id === item.id ? <form className="review-form" onSubmit={save}><label>Grade (%)<input type="number" min="0" max="100" step="1" required value={editing.grade} onChange={event => setEditing({ ...editing, grade: event.target.value })} /></label><label>Feedback<textarea maxLength={4000} value={editing.feedback} onChange={event => setEditing({ ...editing, feedback: event.target.value })} placeholder="Share specific strengths and next steps…" /></label><div className="modal-actions"><button type="button" className="button button-outline" onClick={() => setEditing(null)}>Cancel</button><button className="button button-primary">Save review →</button></div></form> : <button className="button button-soft" onClick={() => setEditing({ id: item.id, grade: item.grade ?? 85, feedback: item.feedback ?? "" })}>{item.grade === null ? "Review submission →" : "Edit feedback →"}</button>}</article>)}</div> : <div className="panel-state">No assignments have been submitted yet.</div>}</LoadState>
  </>;
}

function ProgressPage({ user }) {
  const path = user.role === "admin" ? "/admin/progress" : "/teaching/progress";
  const { data, loading, errorText } = useLoad(path, []);
  const students = data?.students ?? [];
  return <><PageHeading eyebrow="LEARNING ANALYTICS" title="Student progress" description="Course activity and assessment progress for your learning community." />
    <div className="analytics-summary"><StatCard label="Students in view" value={students.length} detail="Current course roster" icon="♙" accent="blue" /><StatCard label="Module completions" value={students.reduce((sum, item) => sum + item.completedModules, 0)} detail="Across student accounts" icon="◈" accent="mint" /><StatCard label="Quiz attempts" value={students.reduce((sum, item) => sum + item.quizAttempts, 0)} detail="Practice activity" icon="⌗" accent="lavender" /></div>
    <div className="table-card"><div className="table-scroll"><LoadState loading={loading} errorText={errorText}>{students.length ? <table><thead><tr><th>STUDENT</th><th>MODULES COMPLETE</th><th>QUIZ ATTEMPTS</th><th>ASSIGNMENTS</th>{user.role === "admin" && <th>AVG. GRADE</th>}</tr></thead><tbody>{students.map(student => <tr key={student.id}><td><div className="table-person"><span className="avatar small-avatar">{student.fullName.slice(0, 1)}</span><span><strong>{student.fullName}</strong><small>{student.email}</small></span></div></td><td><span className="progress-value">{student.completedModules} <span>/ 6</span></span><div className="mini-progress"><i style={{ width: `${Math.min(100, student.completedModules / 6 * 100)}%` }} /></div></td><td>{student.quizAttempts}</td><td>{student.assignments}</td>{user.role === "admin" && <td>{student.averageGrade == null ? "—" : `${Math.round(student.averageGrade)}%`}</td>}</tr>)}</tbody></table> : <div className="panel-state">No students are available yet.</div>}</LoadState></div></div>
  </>;
}

function AuditPage() {
  const { data, loading, errorText } = useLoad("/admin/audit", []);
  return <><PageHeading eyebrow="ADMINISTRATION · SECURITY" title="Audit log" description="A chronological record of account and course-management actions." /><div className="table-card audit-card"><LoadState loading={loading} errorText={errorText}>{data?.entries?.length ? <div className="audit-list">{data.entries.map(entry => <div className="audit-row" key={entry.id}><span className="audit-mark">≋</span><div className="audit-text"><strong>{entry.action.replaceAll(".", " ")}</strong><span>{entry.actorName ?? "System"}{entry.targetName ? ` · ${entry.targetName}` : ""}{entry.details?.role ? ` · ${entry.details.role}` : ""}</span></div><time>{new Date(entry.createdAt).toLocaleString()}</time></div>)}</div> : <div className="panel-state">Sensitive administrative actions will appear here.</div>}</LoadState></div></>;
}

function RecordsPage() {
  const { data, loading, errorText } = useLoad("/me/records", []);
  return <><PageHeading eyebrow="YOUR LEARNING RECORD" title="My results" description="Your own quiz attempts, submissions, and instructor feedback." />
    <div className="records-columns"><section className="surface-card"><div className="card-heading"><div><div className="eyebrow">ASSESSMENTS</div><h2>Quiz attempts</h2></div></div><LoadState loading={loading} errorText={errorText}>{data?.quizzes?.length ? data.quizzes.map(item => <div className="record-row" key={item.id}><span className="record-icon lavender">⌗</span><div><strong>{item.moduleTitle}</strong><small>{new Date(item.createdAt).toLocaleDateString()}</small></div><b>{item.score} / {item.total}</b></div>) : <div className="panel-state">Complete a module quiz to see your results here.</div>}</LoadState></section>
      <section className="surface-card"><div className="card-heading"><div><div className="eyebrow">YOUR WORK</div><h2>Assignments</h2></div></div>{data?.submissions?.length ? data.submissions.map(item => <div className="record-row" key={item.id}><span className="record-icon peach">▤</span><div><strong>{item.moduleTitle}</strong><small>{item.grade === null ? "Awaiting review" : item.feedback || "Feedback available"}</small></div>{item.grade === null ? <span className="pending-pill">Pending</span> : <b>{item.grade}%</b>}</div>) : <div className="panel-state">Submit a module assignment to see it here.</div>}</section></div>
  </>;
}

function Main() { return <App />; }

createRoot(document.getElementById("root")).render(<React.StrictMode><Main /></React.StrictMode>);
