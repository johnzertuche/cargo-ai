import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type Profile = { id: string; display_name: string; created_at: string };
type Host = { host: string; path: string; exists: boolean; can_import: boolean; can_install: boolean; command_path: string | null; fingerprint: string | null };
type Connection = { id: string; name: string; transport: string; command: string | null; args: string[]; url: string | null; environment_keys: string[]; metadata: Record<string, string> };
type Deployment = { id: string; connection_id: string; host: string; server_name: string; config_path: string; state: "active" | "local_blocked" | "host_removed" | "conflict" | "failed"; installed_at: string };
type MemoryRecord = { id: string; title: string; body: string; sensitivity: "public" | "private" | "sensitive"; allowed_hosts: string[]; created_at: string };
type ImportResult = { connections_added: number; connections_skipped: number; memory_added: number; memory_skipped: number };
type ImportPreview = { import_id: string; source_profile: string; exported_at: string; connections: Connection[]; memory: MemoryRecord[]; warnings: string[] };
type Receipt = { id: string; action: string; target: string; outcome: string; record_hash: string; created_at: string };
type Plan = { plan_id: string; host: string; server_name: string; config_path: string; operation: string; creates_config: boolean; preimage_sha256: string | null; result_sha256: string; warnings: string[]; transport: string; command: string | null; args: string[]; url: string | null; secret_references: string[] };
type AppState = { profile: Profile | null; hosts: Host[]; connections: Connection[]; deployments: Deployment[]; memory: MemoryRecord[]; connection_count: number; memory_count: number; receipts: Receipt[]; receipt_chain_valid: boolean; vault_path: string };
type View = "home" | "connections" | "memory" | "activity" | "privacy";

const empty: AppState = { profile: null, hosts: [], connections: [], deployments: [], memory: [], connection_count: 0, memory_count: 0, receipts: [], receipt_chain_valid: true, vault_path: "" };

export default function App() {
  const [state, setState] = useState<AppState>(empty);
  const [locked, setLocked] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [openError, setOpenError] = useState("");
  const [notice, setNotice] = useState("");
  const [view, setView] = useState<View>("home");
  const [plan, setPlan] = useState<Plan | null>(null);
  const [exportMode, setExportMode] = useState<"plain" | "encrypted" | null>(null);
  const [selectedConnectionIds, setSelectedConnectionIds] = useState<string[]>([]);
  const [selectedMemoryIds, setSelectedMemoryIds] = useState<string[]>([]);
  const [backupOpen, setBackupOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [encryptedImportOpen, setEncryptedImportOpen] = useState(false);
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [passphraseAgain, setPassphraseAgain] = useState("");
  const [importPassphrase, setImportPassphrase] = useState("");
  const [deploymentToRemove, setDeploymentToRemove] = useState<Deployment | null>(null);

  const refresh = async () => {
    try {
      setError("");
      setOpenError("");
      setState(await invoke<AppState>("app_state"));
      setLocked(false);
    } catch (caught) {
      if (String(caught).includes("Vault is locked")) {
        setState(empty);
        setLocked(true);
        setError("");
      } else {
        setError(String(caught));
        setOpenError(String(caught));
      }
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { void refresh(); }, []);

  useEffect(() => {
    if (!state.profile || locked) return;
    let timer = window.setTimeout(() => void lock(), 15 * 60 * 1000);
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => void lock(), 15 * 60 * 1000);
    };
    window.addEventListener("keydown", reset);
    window.addEventListener("pointerdown", reset);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("keydown", reset);
      window.removeEventListener("pointerdown", reset);
    };
  }, [state.profile, locked]);

  const lock = async () => {
    try { await invoke("lock_vault"); } finally {
      setState(empty);
      setPlan(null);
      setImportPreview(null);
      setLocked(true);
      setBusy(false);
    }
  };

  const unlock = async () => {
    setBusy(true);
    setError("");
    try {
      await invoke("unlock_vault");
      setLocked(false);
      await refresh();
    } catch (caught) {
      setError(String(caught));
      setBusy(false);
    }
  };

  const create = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try {
      await invoke("create_local_profile", { displayName: name });
      await refresh();
    } catch (caught) {
      setError(String(caught));
      setBusy(false);
    }
  };

  const exportSafe = async () => {
    try {
      setError("");
      const exported = await invoke<boolean>("export_safe_pack", { connectionIds: selectedConnectionIds, memoryIds: selectedMemoryIds });
      if (exported) {
        setNotice("Portable pack exported. It contains connection definitions and memory, but no credentials or recovery data.");
        setExportMode(null);
        await refresh();
      }
    } catch (caught) { setError(String(caught)); }
  };

  const backup = async () => {
    if (passphrase.length < 12 || passphrase !== passphraseAgain) return;
    setBusy(true);
    try {
      const exported = await invoke<boolean>("export_encrypted_pack", { passphrase, connectionIds: selectedConnectionIds, memoryIds: selectedMemoryIds });
      if (exported) {
        setNotice("Encrypted portable pack exported. It transfers definitions and memory—not credentials or a full vault recovery.");
        closeBackup();
        await refresh();
      } else {
        setBusy(false);
      }
    } catch (caught) {
      setError(String(caught));
      setBusy(false);
    }
  };

  const closeBackup = () => {
    setBackupOpen(false);
    setPassphrase("");
    setPassphraseAgain("");
  };

  const beginExport = (mode: "plain" | "encrypted") => {
    setSelectedConnectionIds([]);
    setSelectedMemoryIds([]);
    setExportMode(mode);
  };

  const importSafe = async () => {
    try {
      setError("");
      setImportOpen(false);
      const preview = await invoke<ImportPreview | null>("prepare_safe_pack_import");
      if (preview) setImportPreview(preview);
    } catch (caught) { setError(String(caught)); }
  };

  const importEncrypted = async () => {
    if (!importPassphrase) return;
    setBusy(true);
    try {
      const preview = await invoke<ImportPreview | null>("prepare_encrypted_pack_import", { passphrase: importPassphrase });
      if (preview) {
        setEncryptedImportOpen(false);
        setImportPassphrase("");
        setImportPreview(preview);
        setBusy(false);
      } else {
        setBusy(false);
      }
    } catch (caught) {
      setError(String(caught));
      setBusy(false);
    }
  };

  const applyImport = async () => {
    if (!importPreview) return;
    setBusy(true);
    try {
      const result = await invoke<ImportResult>("apply_pack_import", { importId: importPreview.import_id });
      setNotice(importMessage(result, "Portable pack"));
      setImportPreview(null);
      await refresh();
    } catch (caught) {
      setError(String(caught));
      setImportPreview(null);
      setBusy(false);
    }
  };

  const addMemory = async (title: string, body: string, sensitivity: string, allowedHosts: string[]) => {
    setBusy(true);
    try {
      await invoke("add_memory_record", { title, body, sensitivity, allowedHosts });
      setNotice("Memory saved inside the encrypted local vault.");
      await refresh();
    } catch (caught) {
      setError(String(caught));
      setBusy(false);
      throw caught;
    }
  };

  const importHost = async (host: string) => {
    setBusy(true);
    try {
      const count = await invoke<number>("import_host_configuration", { host });
      setNotice(`Imported ${count} credential-free definition${count === 1 ? "" : "s"} from ${host}.`);
      await refresh();
    } catch (caught) {
      setError(String(caught));
      setBusy(false);
    }
  };

  const previewInstall = async (connectionId: string, host: string) => {
    try {
      setError("");
      setPlan(await invoke<Plan>("plan_connection_install", { connectionId, host }));
    } catch (caught) { setError(String(caught)); }
  };

  const applyInstall = async () => {
    if (!plan) return;
    setBusy(true);
    try {
      await invoke("apply_connection_install", { planId: plan.plan_id });
      setNotice(`${plan.server_name} was registered in ${plan.host}, its configuration presence was verified, and ownership was recorded. Restart the host if needed, then confirm tool availability there.`);
      setPlan(null);
      await refresh();
    } catch (caught) {
      setError(String(caught));
      setPlan(null);
      setBusy(false);
    }
  };

  const revoke = async () => {
    if (!deploymentToRemove) return;
    setBusy(true);
    try {
      await invoke("revoke_connection_deployment", { deploymentId: deploymentToRemove.id });
      setNotice(`${deploymentToRemove.server_name} was removed from ${deploymentToRemove.host}'s configuration. Existing sessions and provider credentials were not revoked.`);
      setDeploymentToRemove(null);
      await refresh();
    } catch (caught) {
      setError(String(caught));
      await refresh();
    }
  };

  if (locked) return <main className="lock-screen"><section><Mark /><span>LOCAL VAULT LOCKED</span><h1>Your private data is out of process memory.</h1><p>Unlock reads the existing vault key from this Mac's Keychain. Cargo still cannot recover the vault if that OS key is lost.</p><button onClick={() => void unlock()} disabled={busy}>{busy ? "Unlocking…" : "Unlock local vault"}</button>{error && <div className="error">{error}</div>}</section></main>;
  if (busy && state.profile === null) return <main className="loading">Opening your local vault…</main>;
  if (openError && state.profile === null) return <main className="lock-screen"><section><Mark /><span>VAULT RECOVERY REQUIRED</span><h1>Cargo refused to replace your encryption key.</h1><p>The existing vault could not be opened. No new key or database was created. Restore the missing Keychain entry or a supported recovery artifact before continuing.</p><div className="error">{openError}</div></section></main>;
  if (!state.profile) return <main className="onboarding">
    <section className="intro"><Mark /><p className="eyebrow">LOCAL-FIRST AI PORTABILITY</p><h1>Your AI life.<br /><em>Owned by you.</em></h1><p className="lead">Create a private profile and encrypted vault on this Mac. No email, cloud account, or hosted credential database.</p></section>
    <section className="create-card"><span>01 / CREATE LOCAL PROFILE</span><h2>What should we call you?</h2><label>Display name<input autoFocus value={name} onChange={event => setName(event.target.value)} onKeyDown={event => event.key === "Enter" && void create()} placeholder="Your name" /></label><button onClick={() => void create()} disabled={!name.trim() || busy}>Create encrypted vault <b>→</b></button><p>Protected by macOS Keychain. Your local profile never leaves this device.</p>{error && <div className="error">{error}</div>}</section>
  </main>;

  const connected = state.hosts.filter(host => host.exists).length;
  const activeDeployments = state.deployments.filter(item => item.state === "active");
  const overlayOpen = Boolean(plan || exportMode || importOpen || backupOpen || encryptedImportOpen || importPreview || deploymentToRemove);
  return <main className="shell">
    <aside inert={overlayOpen}><div className="wordmark"><Mark /><b>CARGO</b><small>PRIVATE PREVIEW</small></div><nav>{([ ["home", "⌂", "Overview"], ["connections", "◇", "Connections"], ["memory", "◫", "Memory"], ["activity", "↗", "Receipts"], ["privacy", "◎", "Privacy"] ] as const).map(([id, icon, label]) => <button key={id} className={view === id ? "active" : ""} onClick={() => setView(id)}><i>{icon}</i>{label}</button>)}</nav><div className="local"><i>✓</i><div><b>Local-only mode</b><span>Auto-locks after 15 minutes</span></div><button onClick={() => void lock()}>Lock</button></div></aside>
    <section className="workspace" inert={overlayOpen}><header><div><span>{state.profile.display_name}'s vault</span><b>/</b><strong>{view[0].toUpperCase() + view.slice(1)}</strong></div><div><button className="secondary" onClick={() => setImportOpen(true)}>Import</button><button className="secondary" onClick={() => beginExport("plain")}>Export portable pack</button><button onClick={() => beginExport("encrypted")}>Export encrypted pack</button></div></header>
      <div className="content">{error && <div className="error" role="alert">{error}</div>}{notice && <div className="notice" role="status" aria-live="polite">{notice}<button aria-label="Dismiss notice" onClick={() => setNotice("")}>×</button></div>}
        {view === "home" && <><div className="heading"><span>DEVICE CONTROL PLANE / LOCAL</span><h1>Everything that makes AI yours.</h1><p>Your configurations and memory are encrypted on this Mac. Nothing here depends on a hosted Cargo service.</p></div><section className="metrics"><article className="hero"><span>LOCAL VAULT HEALTHY</span><strong>{connected}<small> / {state.hosts.length}</small></strong><h2>AI clients discovered</h2><p>Read-only discovery. Configuration changes always require a preview and approval.</p></article><article><span>CONNECTIONS</span><strong>{state.connection_count}</strong><p>Encrypted definitions</p></article><article><span>ACTIVE INSTALLS</span><strong>{activeDeployments.length}</strong><p>Reversible deployments</p></article></section><HostList hosts={state.hosts} onImport={importHost} /></>}
        {view === "connections" && <Connections connections={state.connections} deployments={state.deployments} hosts={state.hosts} onImport={importHost} onPreview={previewInstall} onRevoke={setDeploymentToRemove} />}
        {view === "memory" && <MemoryView memory={state.memory} hosts={state.hosts} onAdd={addMemory} />}
        {view === "activity" && <><div className="heading"><span>HASH-CHAINED RECEIPTS</span><h1>Every local action, accounted for.</h1><p>Records present in this vault: <b className={state.receipt_chain_valid ? "good" : "bad"}>{state.receipt_chain_valid ? "Internally consistent" : "Chain invalid"}</b>. Tail deletion requires a future external checkpoint to detect.</p></div><section className="receipts">{state.receipts.map(receipt => <article key={receipt.id}><time>{new Date(receipt.created_at).toLocaleString()}</time><div><b>{receipt.action}</b><span>{receipt.target}</span></div><strong>✓ {receipt.outcome}</strong></article>)}</section></>}
        {view === "privacy" && <><div className="heading"><span>ZERO-CUSTODY BY DEFAULT</span><h1>Your device is the boundary.</h1><p>Cargo's website cannot inspect, reset, or recover this vault.</p></div><section className="privacy-grid"><article><b>Encrypted records</b><p>Profile, connection, memory, deployment, and receipt documents use authenticated per-record encryption.</p></article><article><b>OS-protected key</b><p>The vault master key lives in macOS Keychain—not in the database or exported portable packs.</p></article><article><b>Portable by choice</b><p>Portable packs contain definitions and memory, never credentials. Passphrase encryption protects a pack in transit.</p></article><article><b>Transparent limits</b><p>The current encrypted pack is not a full-vault recovery: deployments, receipts, and Keychain credentials are excluded.</p></article></section><div className="path">Vault location <code>{state.vault_path}</code></div></>}
      </div>
    </section>
    {plan && <PlanModal plan={plan} busy={busy} onClose={() => setPlan(null)} onApply={applyInstall} />}
    {exportMode && <ExportSelectionModal mode={exportMode} connections={state.connections} memory={state.memory} selectedConnections={selectedConnectionIds} selectedMemory={selectedMemoryIds} busy={busy} onConnections={setSelectedConnectionIds} onMemory={setSelectedMemoryIds} onClose={() => setExportMode(null)} onContinue={() => { if (exportMode === "plain") void exportSafe(); else { setExportMode(null); setBackupOpen(true); } }} />}
    {importOpen && <ImportChoiceModal busy={busy} onClose={() => setImportOpen(false)} onPlain={importSafe} onEncrypted={() => { setImportOpen(false); setEncryptedImportOpen(true); }} />}
    {backupOpen && <BackupModal passphrase={passphrase} passphraseAgain={passphraseAgain} busy={busy} onPassphrase={setPassphrase} onPassphraseAgain={setPassphraseAgain} onClose={closeBackup} onExport={backup} />}
    {encryptedImportOpen && <ImportModal passphrase={importPassphrase} busy={busy} onPassphrase={setImportPassphrase} onClose={() => { setEncryptedImportOpen(false); setImportPassphrase(""); }} onImport={importEncrypted} />}
    {importPreview && <ImportPreviewModal preview={importPreview} busy={busy} onClose={() => setImportPreview(null)} onImport={applyImport} />}
    {deploymentToRemove && <RemoveModal deployment={deploymentToRemove} busy={busy} onClose={() => setDeploymentToRemove(null)} onRemove={revoke} />}
  </main>;
}

function importMessage(result: ImportResult, label: string) {
  return `${label} imported: ${result.connections_added} connections and ${result.memory_added} memories added; ${result.connections_skipped + result.memory_skipped} duplicates skipped.`;
}

function Mark() { return <span className="mark"><i /><b /></span>; }

function HostList({ hosts, onImport }: { hosts: Host[]; onImport: (host: string) => Promise<void> }) {
  return <section className="hosts"><header><div><h2>AI clients on this Mac</h2><p>Supported documented configuration and official CLI surfaces</p></div><span>{hosts.filter(host => host.exists).length} discovered</span></header>{hosts.map(host => <article key={host.host}><div className="host-icon">{host.host[0]}</div><div><b>{host.host}</b><code>{host.path}</code></div>{host.can_import ? <button className="import" onClick={() => void onImport(host.host)}>Import definitions</button> : host.can_install ? <span className="found">✓ Official CLI ready</span> : <span className="not-found">○ Not found</span>}</article>)}</section>;
}

function Connections({ connections, deployments, hosts, onImport, onPreview, onRevoke }: { connections: Connection[]; deployments: Deployment[]; hosts: Host[]; onImport: (host: string) => Promise<void>; onPreview: (connectionId: string, host: string) => Promise<void>; onRevoke: (deployment: Deployment) => void }) {
  const destinations = hosts.filter(item => item.can_install);
  return <><div className="heading"><span>PORTABLE, REVERSIBLE CONNECTIONS</span><h1>Move definitions safely.</h1><p>Importing discards credential values. Installing previews one exact owned change; removal stops if that entry later drifts.</p></div>
    {connections.length === 0 ? <section className="empty-state"><h2>No definitions in your vault yet.</h2><p>Import from a discovered AI client to begin. Credentials remain in the source client's store.</p><div>{hosts.filter(host => host.can_import).map(host => <button key={host.host} onClick={() => void onImport(host.host)}>Import from {host.host}</button>)}</div></section> : <section className="connection-list">{connections.map(connection => <article key={connection.id}><div><span>{connection.transport.replace("_", " ")}</span><h2>{connection.name}</h2><p>{connection.command ?? connection.url}</p><small>Imported from {connection.metadata.source ?? "local pack"}</small></div><div className="connection-actions">{connection.environment_keys.length > 0 && <em>Authorization required: {connection.environment_keys.join(", ")}</em>}{destinations.map(host => { const nativeConnector = host.host === "Claude Desktop" && connection.transport !== "stdio"; return <button key={host.host} title={nativeConnector ? "Claude requires remote connectors to be added in its native Settings > Connectors interface." : undefined} disabled={connection.environment_keys.length > 0 || nativeConnector} onClick={() => void onPreview(connection.id, host.host)}>{nativeConnector ? "Use Claude Connectors" : `Install in ${host.host}`}</button>; })}</div></article>)}</section>}
    <div className="subheading"><span>MANAGED DEPLOYMENTS</span><h2>Registered installs and host removals</h2></div><section className="deployment-list">{deployments.length === 0 ? <p>No managed deployments yet.</p> : deployments.map(item => <article key={item.id}><div><b>{item.server_name}</b><span>{item.host}</span><code>{item.config_path}</code></div><strong className={`state ${item.state}`}>{item.state.replace("_", " ")}</strong>{(item.state === "active" || item.state === "local_blocked") && <button className="danger" onClick={() => void onRevoke(item)}>{item.state === "local_blocked" ? "Retry host removal" : "Remove from host"}</button>}</article>)}</section>
  </>;
}

function PlanModal({ plan, busy, onClose, onApply }: { plan: Plan; busy: boolean; onClose: () => void; onApply: () => Promise<void> }) {
  const [reviewed, setReviewed] = useState(false);
  return <div className="modal-backdrop" role="presentation"><section className="modal wide" role="dialog" aria-modal="true" aria-labelledby="plan-title"><span>UNTRUSTED EXECUTABLE DEFINITION</span><h2 id="plan-title">Review exactly what {plan.host} will run.</h2><p>Portable connection definitions are configuration—not trusted software. Cargo will register the following without executing it itself.</p><div className="execution-preview"><b>{plan.transport === "stdio" ? "Command" : "Remote endpoint"}</b>{plan.command && <code>{plan.command}</code>}{plan.url && <code>{plan.url}</code>}{plan.args.length > 0 && <><b>Arguments, in order</b><ol>{plan.args.map((argument, index) => <li key={`${index}-${argument}`}><code>{argument}</code></li>)}</ol></>}{plan.secret_references.length > 0 && <p>Credential references: {plan.secret_references.join(", ")}</p>}</div><p>Cargo will {plan.creates_config ? "create" : "rewrite"} this file after one final fingerprint check:</p><code>{plan.config_path}</code><dl><div><dt>Current file</dt><dd>{plan.preimage_sha256 ? `${plan.preimage_sha256.slice(0, 16)}…` : "Does not exist"}</dd></div><div><dt>Planned result</dt><dd>{plan.result_sha256.slice(0, 16)}…</dd></div></dl><ul>{plan.warnings.map(warning => <li key={warning}>{warning}</li>)}</ul><label className="confirm"><input type="checkbox" checked={reviewed} onChange={event => setReviewed(event.target.checked)} />I reviewed the executable or endpoint and every argument above.</label><div className="modal-actions"><button className="secondary" onClick={onClose} disabled={busy}>Cancel</button><button onClick={() => void onApply()} disabled={!reviewed || busy}>{busy ? "Applying…" : `Install in ${plan.host}`}</button></div></section></div>;
}

function MemoryView({ memory, hosts, onAdd }: { memory: MemoryRecord[]; hosts: Host[]; onAdd: (title: string, body: string, sensitivity: string, allowedHosts: string[]) => Promise<void> }) {
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [sensitivity, setSensitivity] = useState("private");
  const [allowedHosts, setAllowedHosts] = useState<string[]>([]);
  const submit = async () => {
    if (!title.trim() || !body.trim()) return;
    await onAdd(title, body, sensitivity, allowedHosts);
    setTitle(""); setBody(""); setSensitivity("private"); setAllowedHosts([]);
  };
  const toggle = (host: string) => setAllowedHosts(current => current.includes(host) ? current.filter(item => item !== host) : [...current, host]);
  return <><div className="heading"><span>PORTABLE CONTEXT / USER CONTROLLED</span><h1>Tell every AI once.</h1><p>Memory stays encrypted locally and is exported only when you select that record in a portable pack. Host policy is descriptive here and runtime injection is not enabled.</p></div><section className="memory-editor"><div><label>Title<input value={title} maxLength={200} onChange={event => setTitle(event.target.value)} placeholder="How I like to work" /></label><label>Memory<textarea value={body} onChange={event => setBody(event.target.value)} placeholder="Give me concise progress updates and surface security tradeoffs…" /></label></div><aside><label>Sensitivity<select value={sensitivity} onChange={event => setSensitivity(event.target.value)}><option value="public">Public</option><option value="private">Private</option><option value="sensitive">Sensitive</option></select></label><fieldset><legend>Allowed hosts</legend>{hosts.map(host => <label key={host.host}><input type="checkbox" checked={allowedHosts.includes(host.host)} onChange={() => toggle(host.host)} />{host.host}</label>)}</fieldset><button disabled={!title.trim() || !body.trim()} onClick={() => void submit()}>Save encrypted memory</button></aside></section><section className="memory-list">{memory.length === 0 ? <p>No memory records yet.</p> : memory.map(item => <article key={item.id}><div><span>{item.sensitivity}</span><h2>{item.title}</h2><p>{item.body}</p></div><small>{item.allowed_hosts.length ? `Allowed: ${item.allowed_hosts.join(", ")}` : "Not assigned to a host"}</small></article>)}</section></>;
}

function ImportChoiceModal({ busy, onClose, onPlain, onEncrypted }: { busy: boolean; onClose: () => void; onPlain: () => Promise<void>; onEncrypted: () => void }) {
  return <div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="import-choice-title"><span>IMPORT LOCAL FILE</span><h2 id="import-choice-title">Choose a portable pack.</h2><p>A pack can add connection definitions and memory. It never signs you into providers or restores deployment receipts.</p><div className="choice-grid"><button onClick={() => void onPlain()} disabled={busy}><b>Portable JSON</b><small>Readable, credential-free data</small></button><button onClick={onEncrypted} disabled={busy}><b>Encrypted pack</b><small>Passphrase-protected age file</small></button></div><div className="modal-actions"><button className="secondary" onClick={onClose} disabled={busy}>Cancel</button></div></section></div>;
}

function ExportSelectionModal({ mode, connections, memory, selectedConnections, selectedMemory, busy, onConnections, onMemory, onClose, onContinue }: { mode: "plain" | "encrypted"; connections: Connection[]; memory: MemoryRecord[]; selectedConnections: string[]; selectedMemory: string[]; busy: boolean; onConnections: (ids: string[]) => void; onMemory: (ids: string[]) => void; onClose: () => void; onContinue: () => void }) {
  const toggle = (items: string[], id: string) => items.includes(id) ? items.filter(item => item !== id) : [...items, id];
  return <div className="modal-backdrop" role="presentation"><section className="modal wide" role="dialog" aria-modal="true" aria-labelledby="export-title"><span>EXPLICIT EXPORT SELECTION</span><h2 id="export-title">Choose exactly what leaves this vault.</h2><p>{mode === "encrypted" ? "The selected records will be encrypted with age before the destination file is written." : "The JSON file is human-readable. Review the selected personal memory before sharing or committing it."}</p><div className="export-selection"><section><header><b>Connections</b><button onClick={() => onConnections(selectedConnections.length === connections.length ? [] : connections.map(item => item.id))}>{selectedConnections.length === connections.length ? "Clear" : "Select all"}</button></header>{connections.length === 0 ? <p>None available</p> : connections.map(connection => <label key={connection.id}><input type="checkbox" checked={selectedConnections.includes(connection.id)} onChange={() => onConnections(toggle(selectedConnections, connection.id))} /><span><b>{connection.name}</b><small>{connection.command ?? connection.url}</small></span></label>)}</section><section><header><b>Memory</b><button onClick={() => onMemory(selectedMemory.length === memory.length ? [] : memory.map(item => item.id))}>{selectedMemory.length === memory.length ? "Clear" : "Select all"}</button></header>{memory.length === 0 ? <p>None available</p> : memory.map(item => <details key={item.id}><summary><input type="checkbox" aria-label={`Export ${item.title}`} checked={selectedMemory.includes(item.id)} onChange={() => onMemory(toggle(selectedMemory, item.id))} onClick={event => event.stopPropagation()} />{item.title} · {item.sensitivity}</summary><p>{item.body}</p></details>)}</section></div><p className="selection-count">Selected: {selectedConnections.length} connections · {selectedMemory.length} memories</p><div className="modal-actions"><button className="secondary" onClick={onClose} disabled={busy}>Cancel</button><button onClick={onContinue} disabled={busy}>{mode === "encrypted" ? "Continue to encryption" : "Choose destination and export"}</button></div></section></div>;
}

function ImportPreviewModal({ preview, busy, onClose, onImport }: { preview: ImportPreview; busy: boolean; onClose: () => void; onImport: () => Promise<void> }) {
  const [confirmed, setConfirmed] = useState(false);
  return <div className="modal-backdrop" role="presentation"><section className="modal wide" role="dialog" aria-modal="true" aria-labelledby="import-preview-title"><span>EXACT LOCAL PREVIEW</span><h2 id="import-preview-title">Review before merging anything.</h2><p>Exported by {preview.source_profile} on {new Date(preview.exported_at).toLocaleString()}. Your current profile remains unchanged.</p>{preview.warnings.length > 0 && <ul>{preview.warnings.map(warning => <li key={warning}>{warning}</li>)}</ul>}<div className="import-preview"><section><b>{preview.connections.length} connection definitions</b>{preview.connections.length === 0 ? <p>None</p> : preview.connections.map(connection => <details key={connection.id}><summary>{connection.name} · {connection.transport.replace("_", " ")}</summary><div className="execution-preview">{connection.command && <><b>Command</b><code>{connection.command}</code></>}{connection.url && <><b>Endpoint</b><code>{connection.url}</code></>}{connection.args.length > 0 && <><b>Arguments</b><ol>{connection.args.map((argument, index) => <li key={`${index}-${argument}`}><code>{argument}</code></li>)}</ol></>}{connection.environment_keys.length > 0 && <p>Requires fresh authorization for: {connection.environment_keys.join(", ")}</p>}</div></details>)}</section><section><b>{preview.memory.length} memory records</b>{preview.memory.length === 0 ? <p>None</p> : preview.memory.map(memory => <details key={memory.id}><summary>{memory.title} · {memory.sensitivity}</summary><p className="memory-preview">{memory.body}</p><small>{memory.allowed_hosts.length ? `Allowed hosts: ${memory.allowed_hosts.join(", ")}` : "No allowed hosts assigned"}</small></details>)}</section></div><label className="confirm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />Merge these reviewed records transactionally. Matching records will be skipped.</label><div className="modal-actions"><button className="secondary" onClick={onClose} disabled={busy}>Cancel</button><button onClick={() => void onImport()} disabled={!confirmed || busy}>{busy ? "Merging…" : "Approve and merge"}</button></div></section></div>;
}

function ImportModal({ passphrase, busy, onPassphrase, onClose, onImport }: { passphrase: string; busy: boolean; onPassphrase: (value: string) => void; onClose: () => void; onImport: () => Promise<void> }) {
  return <div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="import-title"><span>ENCRYPTED PORTABLE PACK</span><h2 id="import-title">Unlock and choose the pack.</h2><p>The selected file is decrypted only in local application memory. Existing matching records are kept and duplicates are skipped.</p><label>Pack passphrase<input type="password" autoComplete="current-password" value={passphrase} onChange={event => onPassphrase(event.target.value)} autoFocus /></label><div className="modal-actions"><button className="secondary" onClick={onClose} disabled={busy}>Cancel</button><button onClick={() => void onImport()} disabled={!passphrase || busy}>{busy ? "Decrypting…" : "Choose file and import"}</button></div></section></div>;
}

function BackupModal({ passphrase, passphraseAgain, busy, onPassphrase, onPassphraseAgain, onClose, onExport }: { passphrase: string; passphraseAgain: string; busy: boolean; onPassphrase: (value: string) => void; onPassphraseAgain: (value: string) => void; onClose: () => void; onExport: () => Promise<void> }) {
  const valid = passphrase.length >= 12 && passphrase === passphraseAgain;
  return <div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="backup-title"><span>ENCRYPTED PORTABLE PACK</span><h2 id="backup-title">Protect definitions and memory.</h2><p>This is not a full vault backup. It excludes credentials, deployments, receipts, and the Keychain vault key. Cargo cannot recover the passphrase.</p><label>Passphrase<input type="password" autoComplete="new-password" value={passphrase} onChange={event => onPassphrase(event.target.value)} autoFocus /></label><label>Confirm passphrase<input type="password" autoComplete="new-password" value={passphraseAgain} onChange={event => onPassphraseAgain(event.target.value)} /></label>{passphraseAgain && passphrase !== passphraseAgain && <em className="field-error">Passphrases do not match.</em>}<div className="modal-actions"><button className="secondary" onClick={onClose} disabled={busy}>Cancel</button><button onClick={() => void onExport()} disabled={!valid || busy}>{busy ? "Encrypting…" : "Choose destination and export"}</button></div></section></div>;
}

function RemoveModal({ deployment, busy, onClose, onRemove }: { deployment: Deployment; busy: boolean; onClose: () => void; onRemove: () => Promise<void> }) {
  const [confirmed, setConfirmed] = useState(false);
  return <div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="remove-title"><span>HOST CONFIGURATION ONLY</span><h2 id="remove-title">Remove {deployment.server_name} from {deployment.host}?</h2><p>Cargo will remove only its managed entry from <code>{deployment.config_path}</code> and will stop if that entry changed.</p><ul><li>Already-running client sessions may remain active until the client restarts.</li><li>Local OAuth credentials and provider-side access are not revoked.</li><li>Unrelated host settings are preserved.</li></ul><label className="confirm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />I understand this is a host-config removal, not provider revocation.</label><div className="modal-actions"><button className="secondary" onClick={onClose} disabled={busy}>Cancel</button><button className="danger" onClick={() => void onRemove()} disabled={!confirmed || busy}>{busy ? "Removing…" : "Remove managed entry"}</button></div></section></div>;
}
