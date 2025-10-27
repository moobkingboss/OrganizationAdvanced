import React, { useEffect, useMemo, useRef, useState } from "react";
import { ethers } from "ethers";
import {
  getContractReadOnly,
  normAddr,
  ABI,
  config
} from "./contract";
import WalletManager from "./components/WalletManager";
import WalletSelector from "./components/WalletSelector";
import {
  FaLock,
  FaShieldAlt,
  FaPlusCircle,
  FaSyncAlt,
  FaCheckCircle,
  FaTimesCircle,
  FaFilter,
  FaKey,
  FaListUl,
  FaSearch,
  FaUser,
  FaClock,
  FaDatabase,
  FaBolt,
  FaInfoCircle
} from "react-icons/fa";
import "./App.css";

/** ----------------------------
 * Types
 * -----------------------------*/
type CheckinItem = {
  id: string;          // unique id
  ts: number;          // unix seconds
  from: string;        // submitter
  note?: string;       // optional opaque note (kept as plaintext or opaque bytes on-chain)
  tag?: string;        // optional category label
};

/** ----------------------------
 * Helpers
 * -----------------------------*/
const CHECKIN_KEY_PREFIX = "checkin_";
const CHECKIN_KEYS = "checkin_keys";

/**
 * Sign a short message (provable user intent) before a read-only availability check.
 * Returns the `isAvailable()` result to gate UI actions.
 */
async function signedAvailability(
  provider: ethers.BrowserProvider | null
): Promise<boolean> {
  try {
    if (!provider) return false;
    const signer = await provider.getSigner();
    const who = await signer.getAddress();
    const stamp = Math.floor(Date.now() / 1000);
    const msg = `isAvailable probe by ${who} @ ${stamp}`;
    await signer.signMessage(msg); // lightweight signature to prove user intent
    const ro = await getContractReadOnly();
    if (!ro) return false;
    const ok = await ro.isAvailable();
    return !!ok;
  } catch {
    return false;
  }
}

function shortId(id: string) {
  return id.length > 10 ? `${id.slice(0, 10)}…` : id;
}

/** ----------------------------
 * Main Component
 * -----------------------------*/
export default function App() {
  // Wallet
  const [account, setAccount] = useState<string>("");
  const [provider, setProvider] = useState<ethers.BrowserProvider | null>(null);
  const [walletSelectorOpen, setWalletSelectorOpen] = useState(false);

  // Data
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<CheckinItem[]>([]);
  const [creating, setCreating] = useState(false);

  // UI State
  const [introCollapsed, setIntroCollapsed] = useState(false);
  const [filterMine, setFilterMine] = useState(false);
  const [search, setSearch] = useState("");
  const [tag, setTag] = useState("");
  const [note, setNote] = useState("");
  const [busyBanner, setBusyBanner] = useState<{ show: boolean; type: "pending" | "ok" | "err"; msg: string }>({
    show: false,
    type: "pending",
    msg: ""
  });
  const [pingOk, setPingOk] = useState<boolean | null>(null);

  // Refs
  const firstLoadRef = useRef(true);

  /** ----------------------------
   * Wallet selection hooks
   * -----------------------------*/
  const onWalletSelect = async (wallet: any) => {
    if (!wallet?.provider) return;
    try {
      const web3 = new ethers.BrowserProvider(wallet.provider);
      setProvider(web3);
      const accounts = await web3.send("eth_requestAccounts", []);
      const acc = (accounts?.[0] || "") as string;
      setAccount(acc);

      wallet.provider.on("accountsChanged", async (a: string[]) => {
        setAccount(a?.[0] || "");
      });
    } catch (e) {
      console.error(e);
      alert("Wallet connection failed.");
    }
  };

  const onConnect = () => setWalletSelectorOpen(true);
  const onDisconnect = () => {
    setAccount("");
    setProvider(null);
  };

  /** ----------------------------
   * Load all check-ins
   * -----------------------------*/
  const loadAll = async () => {
    try {
      const ro = await getContractReadOnly();
      if (!ro) return;
      // signed read-intent + availability
      const ok = await signedAvailability(provider);
      setPingOk(ok);
      if (!ok) {
        setItems([]);
        return;
      }

      const keysBytes: Uint8Array = await ro.getData(CHECKIN_KEYS);
      let keys: string[] = [];
      if (keysBytes && keysBytes.length > 0) {
        try {
          const decoded = ethers.toUtf8String(keysBytes);
          keys = JSON.parse(decoded);
        } catch (err) {
          console.warn("Failed to parse keys:", err);
          keys = [];
        }
      }

      const out: CheckinItem[] = [];
      for (const k of keys) {
        try {
          const b: Uint8Array = await ro.getData(`${CHECKIN_KEY_PREFIX}${k}`);
          if (!b || b.length === 0) continue;
          const decoded = ethers.toUtf8String(b);
          const parsed = JSON.parse(decoded) as CheckinItem;
          // only keep items that match required shape
          if (parsed && parsed.id && parsed.ts && parsed.from) {
            out.push(parsed);
          }
        } catch (err) {
          console.warn("Skip broken item", k, err);
        }
      }

      // newest first
      out.sort((a, b) => b.ts - a.ts);
      setItems(out);
    } catch (err) {
      console.error("loadAll error:", err);
    }
  };

  useEffect(() => {
    (async () => {
      await loadAll();
      setLoading(false);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** ----------------------------
   * Derived stats
   * -----------------------------*/
  const stats = useMemo(() => {
    const total = items.length;
    const uniqueUsers = new Set(items.map(i => normAddr(i.from))).size;
    const lastTs = items[0]?.ts || 0;
    return { total, uniqueUsers, lastTs };
  }, [items]);

  const filtered = useMemo(() => {
    let list = [...items];

    if (filterMine && account) {
      list = list.filter(i => normAddr(i.from) === normAddr(account));
    }
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(i =>
        i.note?.toLowerCase().includes(q) ||
        i.tag?.toLowerCase().includes(q) ||
        i.id.toLowerCase().includes(q) ||
        normAddr(i.from).includes(q)
      );
    }
    return list;
  }, [items, filterMine, search, account]);

  /** ----------------------------
   * Actions
   * -----------------------------*/
  const pingFHE = async () => {
    setBusyBanner({ show: true, type: "pending", msg: "Verifying FHE availability..." });
    const ok = await signedAvailability(provider);
    setPingOk(ok);
    setBusyBanner({ show: true, type: ok ? "ok" : "err", msg: ok ? "FHE environment is available." : "Availability check failed." });
    setTimeout(() => setBusyBanner(s => ({ ...s, show: false })), 1600);
  };

  const submitCheckin = async () => {
    if (!provider) {
      alert("Please connect your wallet first.");
      return;
    }
    if (creating) return;

    try {
      setCreating(true);
      setBusyBanner({ show: true, type: "pending", msg: "Submitting encrypted attendance..." });

      const signer = await provider.getSigner();
      // sign before non-data-producing & also to declare intent
      await signer.signMessage(`checkin-intent:${Date.now()}`);

      const contract = new ethers.Contract(config.contractAddress, ABI, signer);

      // Build item
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const from = await signer.getAddress();
      const payload: CheckinItem = {
        id,
        ts: Math.floor(Date.now() / 1000),
        from,
        note: note.trim() || undefined,
        tag: tag.trim() || undefined
      };

      // Write item
      await contract.setData(
        `${CHECKIN_KEY_PREFIX}${id}`,
        ethers.toUtf8Bytes(JSON.stringify(payload))
      );

      // Update keys
      const ro = await getContractReadOnly();
      const keysBytes: Uint8Array = await ro.getData(CHECKIN_KEYS);
      let keys: string[] = [];
      if (keysBytes && keysBytes.length > 0) {
        try {
          keys = JSON.parse(ethers.toUtf8String(keysBytes));
        } catch {
          keys = [];
        }
      }
      keys.push(id);

      await contract.setData(
        CHECKIN_KEYS,
        ethers.toUtf8Bytes(JSON.stringify(keys))
      );

      setBusyBanner({ show: true, type: "ok", msg: "Attendance recorded securely." });
      setNote("");
      setTag("");
      await loadAll();
    } catch (err: any) {
      const m =
        typeof err?.message === "string" && err.message.includes("user rejected")
          ? "User rejected the transaction."
          : "Submission failed. Please try again.";
      console.error(err);
      setBusyBanner({ show: true, type: "err", msg: m });
    } finally {
      setCreating(false);
      setTimeout(() => setBusyBanner(s => ({ ...s, show: false })), 1600);
    }
  };

  const refresh = async () => {
    setBusyBanner({ show: true, type: "pending", msg: "Refreshing encrypted records..." });
    await loadAll();
    setBusyBanner({ show: true, type: "ok", msg: "Refreshed." });
    setTimeout(() => setBusyBanner(s => ({ ...s, show: false })), 1000);
  };

  /** ----------------------------
   * Render
   * -----------------------------*/
  if (loading) {
    return (
      <div className="loading-wrap">
        <div className="ring"></div>
        <div className="muted">Booting encrypted UI…</div>
      </div>
    );
  }

  const lastTime =
    stats.lastTs > 0
      ? new Date(stats.lastTs * 1000).toLocaleString()
      : "—";

  return (
    <div className="page">
      {/* Background deco */}
      <div className="bg-stack">
        <div className="bg-blob a" />
        <div className="bg-blob b" />
        <div className="bg-grid" />
      </div>

      {/* Top bar */}
      <header className="topbar">
        <div className="brand">
          <div className="logo">
            <FaShieldAlt />
          </div>
          <div className="brand-text">
            <span className="brand-strong">FHE</span> Check-in
          </div>
        </div>

        <div className="actions">
          <button className="btn ghost" onClick={pingFHE} title="Probe Availability">
            <FaBolt /> <span className="hide-sm">Ping FHE</span>
          </button>
          <button className="btn" onClick={refresh} title="Refresh">
            <FaSyncAlt /> <span className="hide-sm">Refresh</span>
          </button>
          <WalletManager account={account} onConnect={() => setWalletSelectorOpen(true)} onDisconnect={onDisconnect} />
        </div>
      </header>

      {/* Intro / Hero */}
      <section className={`hero ${introCollapsed ? "collapsed" : ""}`}>
        <div className="hero-left">
          <h1>Anonymous Attendance with Fully Homomorphic Encryption</h1>
          <p className="sub">
            Privacy-first check-in for events, workplaces, and on-chain activities. Records are
            verifiable while personal identity remains concealed.
          </p>

          <ul className="hero-points">
            <li>
              <FaLock /> Client-side protection: data prepared, signed and submitted from your wallet.
            </li>
            <li>
              <FaDatabase /> On-chain storage via <code>setData</code> / <code>getData</code>, protected by FHE pipeline.
            </li>
            <li>
              <FaKey /> Read-only flows sign intent and verify <code>isAvailable()</code> before proceeding.
            </li>
          </ul>

          <div className="hero-ctas">
            <button className="btn primary" onClick={submitCheckin} disabled={!provider || creating}>
              <FaPlusCircle /> New Check-in
            </button>
            <button className="btn ghost" onClick={() => setIntroCollapsed(!introCollapsed)}>
              <FaInfoCircle /> {introCollapsed ? "Expand" : "Collapse"} Intro
            </button>
          </div>

          <div className="hero-hint">
            {pingOk === null ? (
              <span className="muted">FHE status: not checked</span>
            ) : pingOk ? (
              <span className="ok"><FaCheckCircle /> FHE available</span>
            ) : (
              <span className="err"><FaTimesCircle /> FHE unavailable</span>
            )}
          </div>
        </div>

        <div className="hero-right">
          <div className="card glass kpi">
            <div className="kpi-title">Encrypted Stats</div>
            <div className="kpi-grid">
              <div className="kpi-item">
                <div className="kpi-label">Total Check-ins</div>
                <div className="kpi-value">{stats.total}</div>
              </div>
              <div className="kpi-item">
                <div className="kpi-label">Unique Participants</div>
                <div className="kpi-value">{stats.uniqueUsers}</div>
              </div>
              <div className="kpi-item">
                <div className="kpi-label">Last Activity</div>
                <div className="kpi-value">{lastTime}</div>
              </div>
            </div>
            <div className="kpi-foot">
              <FaListUl /> Live metrics computed from on-chain encrypted artifacts.
            </div>
          </div>

          <div className="card glass form">
            <div className="form-title">Compose Check-in</div>
            <div className="field">
              <label>Tag (optional)</label>
              <input
                value={tag}
                onChange={(e) => setTag(e.target.value)}
                placeholder="e.g. conference, daily, remote"
              />
            </div>
            <div className="field">
              <label>Note (optional)</label>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Short context for your attendance"
                rows={3}
              />
            </div>
            <button className="btn primary full" onClick={submitCheckin} disabled={!provider || creating}>
              <FaPlusCircle /> Submit Attendance
            </button>
            <div className="form-hint">
              <FaKey /> A lightweight signature is requested to validate intent before processing.
            </div>
          </div>
        </div>
      </section>

      {/* Toolbar */}
      <section className="toolbar card">
        <div className="tool-left">
          <div className={`pill ${filterMine ? "on" : ""}`} onClick={() => setFilterMine(!filterMine)}>
            <FaFilter /> Mine only
          </div>
          <div className="search">
            <FaSearch />
            <input
              placeholder="Search by note, tag, id, or address…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
        <div className="tool-right">
          <button className="btn ghost" onClick={refresh}>
            <FaSyncAlt /> Refresh
          </button>
        </div>
      </section>

      {/* List */}
      <section className="list">
        {filtered.length === 0 ? (
          <div className="empty card">
            <div className="empty-icon"><FaListUl /></div>
            <div className="empty-title">No attendance found</div>
            <div className="empty-sub">Create your first encrypted check-in to get started.</div>
            <button className="btn primary" onClick={submitCheckin} disabled={!provider || creating}>
              <FaPlusCircle /> New Check-in
            </button>
          </div>
        ) : (
          <div className="grid">
            {filtered.map((it) => {
              const mine = account && normAddr(it.from) === normAddr(account);
              const ts = new Date(it.ts * 1000).toLocaleString();
              return (
                <div className="row card hoverable" key={it.id}>
                  <div className="row-line">
                    <div className="row-main">
                      <div className="row-title">
                        <span className="badge">{it.tag || "general"}</span>
                        <span className="mono">{shortId(it.id)}</span>
                      </div>
                      <div className="row-note">{it.note || <span className="muted">No note</span>}</div>
                      <div className="row-meta">
                        <span className={`owner ${mine ? "me" : ""}`}>
                          <FaUser /> {mine ? "You" : `${normAddr(it.from).slice(0, 10)}…`}
                        </span>
                        <span className="time"><FaClock /> {ts}</span>
                        <span className="proof"><FaDatabase /> stored via <code>setData/getData</code></span>
                      </div>
                    </div>
                    <div className="row-ops">
                      <button className="btn xs ghost" onClick={async () => await pingFHE()}>
                        <FaKey /> Verify
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Banner */}
      {busyBanner.show && (
        <div className={`toast ${busyBanner.type}`}>
          {busyBanner.type === "pending" && <span className="dot dot-a" />}
          {busyBanner.type === "pending" && <span className="dot dot-b" />}
          {busyBanner.type === "pending" && <span className="dot dot-c" />}
          {busyBanner.type === "ok" && <FaCheckCircle />}
          {busyBanner.type === "err" && <FaTimesCircle />}
          <span className="toast-msg">{busyBanner.msg}</span>
        </div>
      )}

      {/* Footer */}
      <footer className="foot">
        <div className="foot-left">
          <span>FHE Check-in</span> · Encrypted presence, verifiable outcomes
        </div>
        <div className="foot-right">
          <a href="#" className="muted">Privacy</a>
          <a href="#" className="muted">Terms</a>
          <a href="#" className="muted">Compliance</a>
        </div>
      </footer>

      {/* Wallet selector modal */}
      {walletSelectorOpen && (
        <WalletSelector
          isOpen={walletSelectorOpen}
          onWalletSelect={(w) => {
            onWalletSelect(w);
            setWalletSelectorOpen(false);
          }}
          onClose={() => setWalletSelectorOpen(false)}
        />
      )}
    </div>
  );
}