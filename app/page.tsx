"use client";

import { useEffect, useMemo, useState } from "react";

type Host = { name: string; mark: string; status: "Connected" | "Ready" | "Not linked"; tone: string };

const initialHosts: Host[] = [
  { name: "Claude", mark: "A", status: "Connected", tone: "sand" },
  { name: "Cursor", mark: "C", status: "Connected", tone: "white" },
  { name: "Codex", mark: "O", status: "Ready", tone: "green" },
  { name: "GitHub", mark: "GH", status: "Not linked", tone: "white" },
  { name: "Grok", mark: "X", status: "Not linked", tone: "white" },
];

const capabilities = [
  { name: "GitHub", detail: "Repositories · Issues · Pull requests", mark: "GH", status: "Healthy", scopes: "Read & write" },
  { name: "Linear", detail: "Issues · Projects · Teams", mark: "LI", status: "Healthy", scopes: "Read & write" },
  { name: "Slack", detail: "Messages · Channels · Search", mark: "SL", status: "Healthy", scopes: "Read only" },
  { name: "Postgres", detail: "Local MCP · analytics-prod", mark: "PG", status: "Healthy", scopes: "Query only" },
  { name: "Browser", detail: "Local MCP · Chromium", mark: "BR", status: "Healthy", scopes: "Open & interact" },
  { name: "Notion", detail: "Pages · Databases · Search", mark: "NO", status: "Reauth", scopes: "Read only" },
];

export default function Home() {
  const [entered, setEntered] = useState(false);
  const [view, setView] = useState<"home" | "stack" | "memory" | "activity">("home");
  const [flow, setFlow] = useState<"closed" | "host" | "review" | "deploying" | "done">("closed");
  const [selectedHost, setSelectedHost] = useState("Codex");
  const [hosts, setHosts] = useState(initialHosts);
  const [selected, setSelected] = useState(capabilities.map((c) => c.name));
  const [toast, setToast] = useState("");

  const activeCount = useMemo(() => hosts.filter((h) => h.status === "Connected").length, [hosts]);

  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 2800);
    return () => clearTimeout(timer);
  }, [toast]);

  function toggleCapability(name: string) {
    setSelected((prev) => prev.includes(name) ? prev.filter((x) => x !== name) : [...prev, name]);
  }

  function deploy() {
    setFlow("deploying");
    setTimeout(() => {
      setHosts((prev) => prev.map((h) => h.name === selectedHost ? { ...h, status: "Connected" } : h));
      setFlow("done");
    }, 1700);
  }

  const title = view === "home" ? "Your AI stack, everywhere." : view === "stack" ? "Capability stack" : view === "memory" ? "Portable memory" : "Activity & security";

  if (!entered) return (
    <main className="landing">
      <header className="landing-nav">
        <button className="brand" aria-label="Home"><span className="brand-mark">R</span><span>RELAY</span><small>WORKING TITLE</small></button>
        <nav><a href="#product">Product</a><a href="#security">Security</a><a href="#platforms">Platforms</a></nav>
        <button className="launch-link" onClick={() => setEntered(true)}>Open prototype <span>→</span></button>
      </header>
      <section className="landing-hero">
        <div className="hero-kicker"><i /> THE PORTABLE AI CONNECTION LAYER</div>
        <h1>Every tool.<br />Every AI. <em>One link.</em></h1>
        <p>Bring your plugins, MCP servers, credentials, and workflows into any AI—without rebuilding your stack from scratch.</p>
        <div className="hero-actions"><button onClick={() => setEntered(true)}>Explore the control plane <span>→</span></button><a href="#product">See how it works</a></div>
        <div className="trust-strip"><span>Local-first controls</span><span>Encrypted credentials</span><span>Explicit consent</span><span>Instant rollback</span></div>
        <div className="hero-network" aria-hidden="true">
          <div className="network-core"><span className="brand-mark">R</span><small>YOUR LINK</small></div>
          {[["A","Claude"],["C","Cursor"],["O","Codex"],["GH","GitHub"],["X","Grok"]].map(([mark,name],i)=><div className={`network-node n${i+1}`} key={name}><b>{mark}</b><span>{name}</span></div>)}
          <i className="beam b1"/><i className="beam b2"/><i className="beam b3"/><i className="beam b4"/><i className="beam b5"/>
        </div>
      </section>
      <section className="landing-proof" id="product">
        <div><span>01 / IMPORT</span><h2>Your stack already exists.<br />We make it portable.</h2></div>
        <p>Relay discovers your existing plugins, MCP servers, skills, rules, and connected accounts—then turns them into one signed, portable manifest.</p>
        <div className="proof-flow"><article><b>01</b><strong>Discover</strong><small>Scan every AI client and local configuration.</small></article><i>→</i><article><b>02</b><strong>Normalize</strong><small>Resolve duplicates and map capabilities.</small></article><i>→</i><article className="accent"><b>03</b><strong>Secure</strong><small>Move secrets behind an encrypted broker.</small></article><i>→</i><article><b>04</b><strong>Deploy</strong><small>Generate safe, host-native configuration.</small></article></div>
      </section>
      <section className="landing-split" id="security">
        <div className="vault-visual"><span>RELAY VAULT</span><div className="vault-rings"><i/><i/><i/><b>✓</b></div><p>Credentials never move between AI hosts.</p></div>
        <div className="security-copy"><span>02 / TRUST LAYER</span><h2>The connection is the product.<br />Trust is the moat.</h2><p>Every installation is previewed. Every permission is explicit. Every mutation is signed, logged, and reversible.</p><ul><li><b>Credential isolation</b><span>Short-lived tokens, device-bound keys, zero plaintext sync.</span></li><li><b>Capability-level consent</b><span>Control exactly what each AI can read, write, and trigger.</span></li><li><b>Supply-chain verification</b><span>Publisher identity, package digest, provenance, and version checks.</span></li></ul></div>
      </section>
      <section className="platform-band" id="platforms"><p>ONE CONTROL PLANE / EVERY AI SURFACE</p><div>{["CLAUDE","CURSOR","CODEX","GITHUB","GROK","+ ANY MCP CLIENT"].map(x=><span key={x}>{x}</span>)}</div></section>
      <section className="landing-cta"><p>THE END OF INTEGRATION SPRAWL</p><h2>Your AI stack should follow you.</h2><button onClick={() => setEntered(true)}>Open the working prototype <span>→</span></button></section>
      <footer className="landing-footer"><span className="brand"><span className="brand-mark small">R</span><span>RELAY</span></span><p>Portable capability infrastructure for the AI era.</p><small>© 2026 · Working prototype</small></footer>
    </main>
  );

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <button className="brand" onClick={() => setView("home")} aria-label="Relay home"><span className="brand-mark">R</span><span>RELAY</span></button>
        <nav aria-label="Primary navigation">
          <button className={view === "home" ? "nav-item active" : "nav-item"} onClick={() => setView("home")}><span className="nav-glyph">⌂</span>Overview</button>
          <button className={view === "stack" ? "nav-item active" : "nav-item"} onClick={() => setView("stack")}><span className="nav-glyph">◇</span>My stack <span className="nav-count">{capabilities.length}</span></button>
          <button className={view === "memory" ? "nav-item active" : "nav-item"} onClick={() => setView("memory")}><span className="nav-glyph">◎</span>Memory <span className="nav-count">12</span></button>
          <button className={view === "activity" ? "nav-item active" : "nav-item"} onClick={() => setView("activity")}><span className="nav-glyph">↗</span>Activity</button>
        </nav>
        <div className="sidebar-label">AI HOSTS</div>
        <div className="host-nav">
          {hosts.map((host) => <button key={host.name} onClick={() => { setSelectedHost(host.name); setFlow("review"); }}><span className={`mini-mark ${host.tone}`}>{host.mark}</span><span>{host.name}</span><i className={host.status === "Connected" ? "online" : ""} /></button>)}
        </div>
        <div className="sidebar-bottom">
          <div className="security-note"><span className="shield">✓</span><div><strong>Vault secured</strong><small>End-to-end encrypted</small></div></div>
          <button className="profile"><span>Z</span><div><strong>Zertuche</strong><small>Personal workspace</small></div><b>•••</b></button>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div className="crumb"><span>Personal</span><b>/</b><span>{view === "home" ? "Overview" : view === "stack" ? "My stack" : view === "memory" ? "Memory" : "Activity"}</span></div>
          <div className="top-actions"><button className="icon-button" aria-label="Search">⌕</button><button className="icon-button" aria-label="Notifications">◌</button><button className="connect-button" onClick={() => setFlow("host")}><span>＋</span> Connect AI</button></div>
        </header>

        <div className="content">
          <div className="page-heading">
            <div><p className="eyebrow">CONTROL PLANE / LIVE</p><h1>{title}</h1><p>{view === "home" ? "One secure connection layer for every tool you use and every AI you trust." : view === "stack" ? "Your portable tools, permissions, and connection health in one place." : view === "memory" ? "A user-owned context vault that moves with you—shared selectively, never silently." : "A complete record of installs, access, configuration changes, and trust events."}</p></div>
            {view === "home" && <button className="quiet-action" onClick={() => { setView("stack"); setToast("Stack scan complete"); }}>↻ Scan this device</button>}
          </div>

          {view === "home" && <>
            <section className="signal-grid">
              <article className="hero-signal"><div className="signal-top"><span className="pulse"><i /></span><span>ALL SYSTEMS OPERATIONAL</span></div><div className="hero-number">{activeCount}<small> / 5</small></div><h2>AI hosts connected</h2><p>Your default Link is synchronized across every active host.</p><button onClick={() => setFlow("host")}>Extend your stack <span>→</span></button><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="core-dot" /></article>
              <article className="metric-card"><div className="metric-label">CAPABILITIES</div><strong>{capabilities.length}</strong><p>5 healthy · 1 needs attention</p><div className="meter"><i style={{ width: "84%" }} /></div><button onClick={() => setView("stack")}>Manage stack <span>↗</span></button></article>
              <article className="metric-card"><div className="metric-label">SECURITY SCORE</div><strong>98<span>%</span></strong><p>No critical permissions detected</p><div className="meter"><i style={{ width: "98%" }} /></div><button onClick={() => setView("activity")}>View audit log <span>↗</span></button></article>
            </section>

            <section className="section-block">
              <div className="section-title"><div><h2>Connected AI</h2><p>Your Link adapts to each host’s native capability format.</p></div><button onClick={() => setFlow("host")}>Manage hosts</button></div>
              <div className="host-cards">
                {hosts.map((host) => <button className="host-card" key={host.name} onClick={() => { setSelectedHost(host.name); setFlow(host.status === "Connected" ? "review" : "host"); }}><span className={`host-mark ${host.tone}`}>{host.mark}</span><div><strong>{host.name}</strong><small>{host.status === "Connected" ? "Synced 2m ago" : host.status === "Ready" ? "Ready to deploy" : "Available"}</small></div><span className={`status ${host.status === "Connected" ? "good" : ""}`}>{host.status}</span></button>)}
              </div>
            </section>

            <section className="section-block recent">
              <div className="section-title"><div><h2>Recent activity</h2><p>Verified changes across your connection layer.</p></div><button onClick={() => setView("activity")}>View all</button></div>
              <div className="activity-row"><span className="activity-icon good">✓</span><div><strong>Cursor synchronized</strong><small>6 capabilities verified · Default Link</small></div><time>2 min ago</time></div>
              <div className="activity-row"><span className="activity-icon">↻</span><div><strong>GitHub permission updated</strong><small>Pull requests: read → read & write</small></div><time>48 min ago</time></div>
              <div className="activity-row"><span className="activity-icon warn">!</span><div><strong>Notion authorization expires soon</strong><small>Reconnect to prevent interruption</small></div><time>3 hr ago</time></div>
            </section>
          </>}

          {view === "stack" && <section className="stack-panel">
            <div className="stack-toolbar"><div><strong>Default Link</strong><span className="version">v1.8</span><p>Portable across {activeCount} connected hosts</p></div><button onClick={() => { setSelected(capabilities.map((c) => c.name)); setToast("Device scan found 6 capabilities"); }}>＋ Import capability</button></div>
            <div className="cap-table-head"><span>CAPABILITY</span><span>ACCESS</span><span>HEALTH</span><span /></div>
            {capabilities.map((cap) => <div className="cap-row" key={cap.name}><span className="cap-id"><b>{cap.mark}</b><span><strong>{cap.name}</strong><small>{cap.detail}</small></span></span><span>{cap.scopes}</span><span className={cap.status === "Healthy" ? "health good" : "health warn"}><i />{cap.status}</span><button onClick={() => setToast(`${cap.name} settings opened`)}>•••</button></div>)}
          </section>}

          {view === "memory" && <section className="memory-layout">
            <div className="memory-main">
              <div className="memory-banner"><span className="shield large">✓</span><div><strong>You own this memory.</strong><p>Encrypted locally and synchronized as typed records. AI hosts receive only the fields you approve for that host and session.</p></div><button onClick={() => setToast("Memory export prepared")}>Export vault</button></div>
              <div className="memory-section-title"><div><strong>Identity & preferences</strong><small>4 verified records</small></div><button onClick={() => setToast("New memory editor opened")}>＋ Add memory</button></div>
              {[
                ["PROFILE", "About me", "Founder and operator focused on building durable, high-leverage businesses.", "All connected AI"],
                ["STYLE", "How I like to work", "Move quickly, verify deeply, communicate outcomes clearly, and avoid unnecessary friction.", "Coding AI only"],
                ["PREFERENCE", "Communication", "Concise by default. Surface risks early. Ask only when the choice materially changes the outcome.", "All connected AI"],
                ["CONTEXT", "Active product", "Building a portable capability and memory layer for moving seamlessly between AI platforms.", "Selected sessions"],
              ].map((m)=><article className="memory-card" key={m[1]}><div><span>{m[0]}</span><strong>{m[1]}</strong></div><p>{m[2]}</p><footer><span><i/> {m[3]}</span><button onClick={()=>setToast(`${m[1]} permissions opened`)}>Manage access</button></footer></article>)}
            </div>
            <aside className="memory-policy"><p className="modal-eyebrow">DISCLOSURE POLICY</p><h2>Context without oversharing.</h2><p>Memory is evaluated at request time against the AI host, workspace, purpose, and sensitivity.</p><div className="policy-stat"><span>Default posture</span><b>Ask first</b></div><div className="policy-stat"><span>Sensitive records</span><b>Local only</b></div><div className="policy-stat"><span>Provenance required</span><b>Always</b></div><div className="policy-stat"><span>Automatic expiry</span><b>90 days</b></div><button onClick={()=>setToast("Disclosure policy opened")}>Edit disclosure policy →</button></aside>
          </section>}

          {view === "activity" && <section className="audit-panel">
            <div className="audit-hero"><span className="shield large">✓</span><div><h2>Protected by Relay Vault</h2><p>Every configuration mutation is signed, logged, and reversible. Secrets never leave the encrypted broker.</p></div><span>ZERO CRITICAL EVENTS</span></div>
            {[
              ["Today, 7:42 PM", "Cursor synchronized", "relay-agent · macOS", "6 capabilities verified", "Success"],
              ["Today, 6:56 PM", "Permission changed", "GitHub · pull_requests", "Read → Read & write", "Verified"],
              ["Today, 4:11 PM", "Credential rotated", "Linear · OAuth 2.0", "Token replaced safely", "Success"],
              ["Yesterday, 9:20 PM", "Link deployed", "Claude · Default Link", "v1.7 → v1.8", "Success"],
            ].map((row) => <div className="audit-row" key={row[0] + row[1]}><time>{row[0]}</time><div><strong>{row[1]}</strong><small>{row[2]}</small></div><span>{row[3]}</span><b>✓ {row[4]}</b></div>)}
          </section>}
        </div>
      </section>

      {flow !== "closed" && <div className="modal-layer" role="dialog" aria-modal="true" aria-label="Connect an AI host">
        <button className="modal-backdrop" onClick={() => setFlow("closed")} aria-label="Close" />
        <section className="modal">
          <div className="modal-head"><div><span className="brand-mark small">R</span><div><strong>{flow === "done" ? "Connection complete" : "Connect an AI"}</strong><small>{flow === "host" ? "Choose where to deploy your Link" : `${selectedHost} · Default Link`}</small></div></div><button onClick={() => setFlow("closed")}>×</button></div>
          <div className="step-line"><i className="active" /><i className={flow !== "host" ? "active" : ""} /><i className={["deploying", "done"].includes(flow) ? "active" : ""} /></div>

          {flow === "host" && <div className="modal-body"><p className="modal-eyebrow">SELECT HOST</p><h2>Where should Relay connect?</h2><p className="modal-copy">We’ll detect the host’s supported features and generate a safe, native configuration.</p><div className="host-picker">{hosts.filter((h) => h.status !== "Connected").map((host) => <button key={host.name} className={selectedHost === host.name ? "selected" : ""} onClick={() => setSelectedHost(host.name)}><span className={`host-mark ${host.tone}`}>{host.mark}</span><div><strong>{host.name}</strong><small>{host.name === "Codex" ? "MCP · Skills · Plugins" : "MCP · Native tools"}</small></div><i>→</i></button>)}</div></div>}

          {flow === "review" && <div className="modal-body review"><p className="modal-eyebrow">REVIEW ACCESS</p><h2>Everything stays in your control.</h2><p className="modal-copy">Choose exactly what {selectedHost} can access. Relay will never share raw credentials.</p><div className="review-list">{capabilities.map((cap) => <label key={cap.name}><span className="cap-id"><b>{cap.mark}</b><span><strong>{cap.name}</strong><small>{cap.scopes}</small></span></span><input type="checkbox" checked={selected.includes(cap.name)} onChange={() => toggleCapability(cap.name)} /><i /></label>)}</div><div className="vault-line"><span className="shield">✓</span><p><strong>Credentials protected by Relay Vault</strong><small>{selected.length} capabilities · Tokens remain encrypted</small></p></div></div>}

          {flow === "deploying" && <div className="modal-body deploying"><div className="deploy-visual"><div className="deploy-ring"><span className="brand-mark">R</span></div><i className="scan-line" /></div><p className="modal-eyebrow">SECURELY DEPLOYING</p><h2>Connecting {selectedHost}</h2><p className="modal-copy">Generating native configuration, exchanging scoped tokens, and verifying {selected.length} capabilities.</p><div className="deploy-checks"><span>✓ Manifest signed</span><span>✓ Permissions verified</span><span className="pending">○ Running health checks</span></div></div>}

          {flow === "done" && <div className="modal-body deploying"><div className="success-mark">✓</div><p className="modal-eyebrow">LINK ACTIVE</p><h2>{selectedHost} is ready.</h2><p className="modal-copy">Your Default Link is connected and all {selected.length} selected capabilities passed their health checks.</p><div className="connection-receipt"><span>Deployment receipt</span><b>RLY-{Date.now().toString().slice(-6)}</b><span>Rollback available</span><b>30 days</b></div></div>}

          {!(["deploying", "done"] as string[]).includes(flow) && <div className="modal-footer"><button onClick={() => setFlow("closed")}>Cancel</button><button className="primary" onClick={() => flow === "host" ? setFlow("review") : deploy()}>{flow === "host" ? "Continue" : `Connect ${selectedHost}`} <span>→</span></button></div>}
          {flow === "done" && <div className="modal-footer single"><button className="primary" onClick={() => { setFlow("closed"); setToast(`${selectedHost} connected successfully`); }}>Done</button></div>}
        </section>
      </div>}
      {toast && <div className="toast"><span>✓</span>{toast}</div>}
    </main>
  );
}
