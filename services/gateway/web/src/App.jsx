import { useEffect, useMemo, useState } from "react";

const terminal = new Set(["completed", "failed", "queue_failed"]);

function messageFor(data, code) {
  if (typeof data?.error === "string") return data.error;
  if (typeof data?.detail === "string") return data.detail;
  if (Array.isArray(data?.detail)) return data.detail.map((x) => x.msg).join(" · ");
  return `Request failed (HTTP ${code})`;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(messageFor(data, response.status));
  return data;
}

function Scanner({ status = "ready" }) {
  const moving = ["queued", "running"].includes(status);
  return <div className={`scanner ${moving ? "moving" : ""}`}>
    <i className="ring r1" /><i className="ring r2" /><i className="beam" /><i className="core" />
    <b>{status}</b>
  </div>;
}

function Pipeline({ status }) {
  const active = status === "queued" ? 2 : status === "running" ? 4 : status === "completed" ? 6 : 0;
  return <div className="pipeline">{["Validate", "Analyze", "Queue", "Resolve DNS", "Inspect HTTP", "Verdict"].map((name, i) =>
    <div className={`stage ${i < active ? "done" : ""} ${i === active ? "active" : ""}`} key={name}>
      <span>{i < active ? "✓" : i + 1}</span><b>{name}</b>
    </div>
  )}</div>;
}

function Gauge({ title, data }) {
  const score = Math.min(100, Math.max(0, data?.risk_score || 0));
  return <div className="gauge">
    <div><span>{title}</span><b>{data?.verdict || "pending"}</b></div>
    <div className="track"><i style={{ width: `${score}%` }} /></div>
    <strong>{score}<small>/100 risk</small></strong>
  </div>;
}

function Auth({ enter }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      if (mode === "register") await api("/auth/register", { method: "POST", body: JSON.stringify({ email, password }) });
      const login = await api("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
      enter(login.access_token, email);
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  return <section className="auth-layout">
    <div className="hero">
      <p className="eyebrow">ZERO-TRUST URL INTELLIGENCE</p>
      <h1>See the risk<br/><em>before the click.</em></h1>
      <p>Controlled DNS, HTTP and suspicious-pattern analysis for untrusted destinations.</p>
      <div className="chips"><span>SSRF guarded</span><span>Isolated worker</span><span>Tenant scoped</span></div>
    </div>
    <div className="auth-card glass">
      <div className="tabs"><button className={mode === "login" ? "on" : ""} onClick={() => setMode("login")}>Sign in</button><button className={mode === "register" ? "on" : ""} onClick={() => setMode("register")}>Create account</button></div>
      <p className="eyebrow">{mode === "login" ? "SECURE SESSION" : "NEW IDENTITY"}</p>
      <h2>{mode === "login" ? "Welcome back" : "Create your workspace"}</h2>
      <form onSubmit={submit}>
        <label>Email address<input required type="email" autoComplete="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <label>Password<input required minLength="12" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} placeholder="Minimum 12 characters" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <button className="primary" disabled={busy}>{busy ? "Establishing session…" : mode === "login" ? "Enter dashboard" : "Create and continue"}</button>
      </form>
      {error && <p className="notice">{error}</p>}
      <small>JWT stays only in page memory and disappears on refresh or exit.</small>
    </div>
  </section>;
}

export default function App() {
  const [token, setToken] = useState("");
  const [identity, setIdentity] = useState("");
  const [url, setUrl] = useState("");
  const [scan, setScan] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const auth = (extra = {}) => ({ ...extra, headers: { ...(extra.headers || {}), Authorization: `Bearer ${token}` } });
  const flags = useMemo(() => [...new Set([...(scan?.static_analysis?.flags || []), ...(scan?.result?.flags || [])])], [scan]);

  async function start(event) {
  event.preventDefault();
  setBusy(true);
  setError("");
  setScan(null);

  const enteredURL = url.trim();
  const normalizedURL = /^https?:\/\//i.test(enteredURL)
    ? enteredURL
    : `https://${enteredURL}`;

  setUrl(normalizedURL);

  try {
    setScan(
      await api(
        "/scans",
        auth({
          method: "POST",
          body: JSON.stringify({ url: normalizedURL })
        })
      )
    );
  } catch (error) {
    setError(error.message);
  } finally {
    setBusy(false);
  }
}

  useEffect(() => {
    if (!token || !scan?.id || terminal.has(scan.status)) return;
    const timer = setTimeout(async () => {
      try { setScan(await api(`/scans/${scan.id}`, auth())); } catch (e) { setError(e.message); }
    }, 900);
    return () => clearTimeout(timer);
  }, [scan, token]);

  function exit() { setToken(""); setIdentity(""); setUrl(""); setScan(null); setError(""); }

  return <main>
    <div className="glow g1"/><div className="glow g2"/><div className="grid"/>
    <header><div className="brand"><i/><div><b>URL SENTINEL</b><span>Threat Intelligence Platform</span></div></div><div className="head-actions"><span className="online">● SYSTEM ONLINE</span>{token && <button className="ghost" onClick={exit}>Exit session</button>}</div></header>
    {!token ? <Auth enter={(t, e) => { setToken(t); setIdentity(e); }} /> : <section className="dashboard">
      <div className="title"><div><p className="eyebrow">ACTIVE WORKSPACE</p><h1>Threat analysis console</h1><p>Authenticated as {identity}</p></div><Scanner status={scan?.status}/></div>
      <div className="command glass"><div><p className="eyebrow">NEW INVESTIGATION</p><h2>Enter a public URL</h2><p>Validation, isolated resolution and controlled egress.</p></div><form onSubmit={start}><input required type="text" inputMode="url" placeholder="https://example.com/path" value={url} onChange={(e) => setUrl(e.target.value)}/><button className="primary" disabled={busy}>{busy ? "Validating…" : "Initiate scan"}</button></form></div>
      {scan && <>
        <div className="live glass"><div className="panel-head"><div><p className="eyebrow">LIVE EXECUTION</p><h2>{scan.url}</h2></div><span className={`status s-${scan.status}`}>{scan.status}</span></div><Pipeline status={scan.status}/></div>
        <div className="results">
          <article className="glass"><p className="eyebrow">RISK ASSESSMENT</p><Gauge title="Pattern intelligence" data={scan.static_analysis}/><Gauge title="Network inspection" data={scan.result}/></article>
          <article className="glass"><p className="eyebrow">NETWORK EVIDENCE</p><dl><div><dt>Connected address</dt><dd>{scan.result?.connected_address || "Awaiting worker"}</dd></div><div><dt>Resolved addresses</dt><dd>{scan.result?.resolved_addresses?.join(" · ") || "—"}</dd></div><div><dt>HTTP response</dt><dd>{scan.result?.status_code ?? "—"}</dd></div><div><dt>Worker attempts</dt><dd>{scan.worker_attempts ?? "—"}</dd></div><div><dt>Host intelligence</dt><dd className="pending">Provider not configured</dd></div></dl></article>
        </div>
        <div className="signals glass"><div><p className="eyebrow">DETECTION SIGNALS</p><h2>{flags.length ? `${flags.length} identified` : scan.status === "completed" ? "No elevated signals" : "Analysis in progress"}</h2></div><div>{flags.map((x) => <span key={x}>{x.replaceAll("_", " ")}</span>)}{!flags.length && scan.status === "completed" && <span className="clear">CLEAR</span>}</div></div>
      </>}
      {error && <p className="notice">{error}</p>}
    </section>}
    <footer>Gateway — Auth — Scanner — Redis — Worker — PostgreSQL</footer>
  </main>;
}
