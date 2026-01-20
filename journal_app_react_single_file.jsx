import React, { useEffect, useMemo, useState } from "react";

// JournalApp.jsx
// Single-file React component (Tailwind CSS assumed).
// Drop into a Vite + React + Tailwind project as a page or component.

export default function JournalApp() {
  // Data model
  // entry = { id, dateISO, title, body, tags: [], mood: string }

  const STORAGE_KEY = "journal:v1";
  const ENCRYPTED_KEY = "journal:enc:v1";

  const [entries, setEntries] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [query, setQuery] = useState("");
  const [tagsFilter, setTagsFilter] = useState([]);
  const [tagInput, setTagInput] = useState("");
  const [isEncrypted, setIsEncrypted] = useState(false);
  const [locked, setLocked] = useState(false);
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("");

  // editing fields
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [mood, setMood] = useState("");
  const [entryTags, setEntryTags] = useState([]);

  useEffect(() => {
    // try to load unencrypted first
    const raw = localStorage.getItem(STORAGE_KEY);
    const enc = localStorage.getItem(ENCRYPTED_KEY);
    if (raw) {
      try {
        setEntries(JSON.parse(raw));
        setIsEncrypted(false);
        setLocked(false);
      } catch (e) {
        console.error("parse error", e);
      }
    } else if (enc) {
      setIsEncrypted(true);
      setLocked(true);
      setEntries([]);
    } else {
      // no data
      setEntries([]);
    }
  }, []);

  useEffect(() => {
    // persist if not encrypted
    if (!isEncrypted) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
    }
  }, [entries, isEncrypted]);

  // helpers
  function makeId() {
    return Math.random().toString(36).slice(2, 9);
  }

  function newEntry() {
    const now = new Date().toISOString();
    const e = {
      id: makeId(),
      dateISO: now,
      title: "",
      body: "",
      tags: [],
      mood: "",
    };
    setEntries([e, ...entries]);
    setSelectedId(e.id);
    setTitle("");
    setBody("");
    setEntryTags([]);
    setMood("");
  }

  function saveSelected() {
    if (!selectedId) return;
    setEntries(prev => {
      const copy = [...prev];
      const i = copy.findIndex(x => x.id === selectedId);
      if (i === -1) return prev;
      copy[i] = {
        ...copy[i],
        title,
        body,
        tags: entryTags,
        mood,
        dateISO: copy[i].dateISO || new Date().toISOString(),
      };
      return copy;
    });
    setStatus("Saved");
    setTimeout(() => setStatus(""), 1400);
  }

  function deleteEntry(id) {
    if (!confirm("Delete this entry?")) return;
    setEntries(prev => prev.filter(e => e.id !== id));
    if (selectedId === id) {
      setSelectedId(null);
    }
  }

  function selectEntry(id) {
    setSelectedId(id);
    const e = entries.find(x => x.id === id);
    if (e) {
      setTitle(e.title);
      setBody(e.body);
      setEntryTags(e.tags || []);
      setMood(e.mood || "");
    }
  }

  // simple search & filter
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries.filter(e => {
      if (tagsFilter.length) {
        for (const t of tagsFilter) if (!e.tags || !e.tags.includes(t)) return false;
      }
      if (!q) return true;
      return (
        (e.title || "").toLowerCase().includes(q) ||
        (e.body || "").toLowerCase().includes(q) ||
        (e.tags || []).some(t => t.toLowerCase().includes(q))
      );
    });
  }, [entries, query, tagsFilter]);

  // tags UI
  function addTagToEntry(t) {
    if (!t) return;
    if (!entryTags.includes(t)) setEntryTags(prev => [...prev, t]);
    setTagInput("");
  }

  function removeTagFromEntry(t) {
    setEntryTags(prev => prev.filter(x => x !== t));
  }

  // export / import
  function exportJSON() {
    const payload = { entries, exportedAt: new Date().toISOString() };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `journal-export-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function importJSON(file) {
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const parsed = JSON.parse(e.target.result);
        if (Array.isArray(parsed.entries)) {
          // merge dedup by id
          const map = new Map(entries.map(x => [x.id, x]));
          for (const en of parsed.entries) map.set(en.id, en);
          const merged = Array.from(map.values()).sort((a, b) => (b.dateISO || "").localeCompare(a.dateISO || ""));
          setEntries(merged);
        } else {
          alert("Invalid import format: no entries array");
        }
      } catch (err) {
        alert("Failed to parse JSON: " + err.message);
      }
    };
    reader.readAsText(file);
  }

  // Encryption helpers using Web Crypto API (AES-GCM with derived key)
  async function deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const passKey = await window.crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 250000,
        hash: "SHA-256",
      },
      passKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  function buf2b64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }
  function b642buf(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  async function lockWithPassword(pw) {
    if (!pw) return alert("Provide a password to encrypt your journal.");
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKeyFromPassword(pw, salt);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const plaintext = enc.encode(JSON.stringify(entries));
    const ct = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
    const payload = {
      ct: buf2b64(ct),
      iv: buf2b64(iv.buffer),
      salt: buf2b64(salt.buffer),
      meta: { encryptedAt: new Date().toISOString() },
    };
    localStorage.setItem(ENCRYPTED_KEY, JSON.stringify(payload));
    localStorage.removeItem(STORAGE_KEY);
    setIsEncrypted(true);
    setLocked(true);
    setEntries([]);
    setPassword("");
    setStatus("Locked and encrypted");
  }

  async function unlockWithPassword(pw) {
    try {
      const raw = localStorage.getItem(ENCRYPTED_KEY);
      if (!raw) return alert("No encrypted journal found");
      const payload = JSON.parse(raw);
      const iv = b642buf(payload.iv);
      const salt = b642buf(payload.salt);
      const key = await deriveKeyFromPassword(pw, new Uint8Array(salt));
      const ctBuf = b642buf(payload.ct);
      const pt = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv) }, key, ctBuf);
      const dec = new TextDecoder();
      const parsed = JSON.parse(dec.decode(pt));
      setEntries(parsed);
      setIsEncrypted(true);
      setLocked(false);
      setPassword("");
      setStatus("Unlocked");
    } catch (err) {
      console.error(err);
      alert("Failed to decrypt — wrong password or corrupted data.");
    }
  }

  function wipeEncrypted() {
    if (!confirm("Delete the encrypted journal from this browser? This cannot be undone.")) return;
    localStorage.removeItem(ENCRYPTED_KEY);
    setIsEncrypted(false);
    setLocked(false);
    setEntries([]);
  }

  function saveEncryptedAfterEdit(pw) {
    // re-encrypt in-place
    lockWithPassword(pw);
  }

  // small UI helpers
  function formattedDate(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleString();
    } catch (e) {
      return iso;
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 p-6">
      <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-1">
          <div className="bg-white p-4 rounded-2xl shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-lg font-semibold">Journal</h2>
              <div className="text-sm text-slate-500">{status}</div>
            </div>

            <div className="space-y-3">
              <button
                className="w-full py-2 rounded-xl border hover:bg-slate-50"
                onClick={newEntry}
              >
                + New entry
              </button>

              <div className="flex gap-2">
                <input
                  className="flex-1 rounded-xl border px-3 py-2"
                  placeholder="Search text or tag"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                />
                <button className="px-3 rounded-xl border" onClick={() => {setQuery(""); setTagsFilter([]);}}>Clear</button>
              </div>

              <div className="flex gap-2">
                <input
                  className="flex-1 rounded-xl border px-3 py-2"
                  placeholder="Filter tag (press Enter)"
                  value={tagInput}
                  onChange={e => setTagInput(e.target.value)}
                  onKeyDown={e => { if (e.key === "Enter") { addTagToEntry(tagInput.trim()); setTagsFilter(prev => prev.includes(tagInput.trim()) ? prev : [...prev, tagInput.trim()]); setTagInput(""); } }}
                />
                <button className="px-3 rounded-xl border" onClick={() => { setTagsFilter([]); }}>Clear tags</button>
              </div>

              <div className="flex gap-2 flex-wrap">
                {tagsFilter.map(t => (
                  <button key={t} className="px-2 py-1 rounded-full border text-sm" onClick={() => setTagsFilter(prev => prev.filter(x => x !== t))}>{t} ×</button>
                ))}
              </div>

              <div className="flex gap-2">
                <button onClick={exportJSON} className="flex-1 py-2 rounded-xl border">Export JSON</button>
                <label className="flex-1 py-2 rounded-xl border text-center cursor-pointer">
                  Import
                  <input type="file" accept="application/json" className="hidden" onChange={e => e.target.files && importJSON(e.target.files[0])} />
                </label>
              </div>

              <div className="border-t pt-3">
                <div className="text-sm mb-2">Encryption</div>
                {!isEncrypted ? (
                  <div className="space-y-2">
                    <div className="text-xs text-slate-500">Store in this browser (unencrypted)</div>
                    <button className="w-full py-2 rounded-xl border" onClick={() => { if (!confirm('Switch to encrypted mode? This will encrypt current data with a password.')) return; const pw = prompt('Enter a password to encrypt your journal:'); if (pw) lockWithPassword(pw); }}>Encrypt & lock</button>
                  </div>
                ) : locked ? (
                  <div className="space-y-2">
                    <div className="text-xs text-slate-500">Journal is encrypted in localStorage</div>
                    <input placeholder="Password" type="password" className="w-full rounded-xl border px-3 py-2" value={password} onChange={e => setPassword(e.target.value)} />
                    <div className="flex gap-2">
                      <button className="flex-1 py-2 rounded-xl border" onClick={() => unlockWithPassword(password)}>Unlock</button>
                      <button className="flex-1 py-2 rounded-xl border" onClick={wipeEncrypted}>Delete</button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="text-xs text-slate-500">Unlocked (in memory)</div>
                    <div className="flex gap-2">
                      <button className="flex-1 py-2 rounded-xl border" onClick={() => { const pw = prompt('Enter password to re-encrypt:'); if (pw) saveEncryptedAfterEdit(pw); }}>Re-lock</button>
                      <button className="flex-1 py-2 rounded-xl border" onClick={() => { // export and then clear
                        if (confirm('Export and clear local encrypted copy? You will keep the encrypted file if you export.')) { exportJSON(); wipeEncrypted(); }
                      }}>Export + Clear</button>
                    </div>
                  </div>
                )}
              </div>

            </div>
          </div>

          <div className="mt-4 bg-white p-4 rounded-2xl shadow-sm">
            <div className="text-sm text-slate-600 mb-2">Entries ({visible.length})</div>
            <div className="space-y-2 max-h-[40vh] overflow-auto">
              {visible.map(e => (
                <div key={e.id} className={`p-3 rounded-xl border hover:bg-slate-50 cursor-pointer ${selectedId === e.id ? 'ring-2 ring-sky-200' : ''}`} onClick={() => selectEntry(e.id)}>
                  <div className="flex justify-between">
                    <div className="font-medium truncate">{e.title || '(untitled)'}</div>
                    <div className="text-xs text-slate-500">{formattedDate(e.dateISO)}</div>
                  </div>
                  <div className="text-sm text-slate-500 truncate mt-1">{(e.body || '').slice(0, 140)}</div>
                  <div className="flex gap-2 mt-2 flex-wrap">
                    {(e.tags || []).map(t => <div key={t} className="text-xs px-2 py-1 rounded-full border">{t}</div>)}
                    {e.mood && <div className="text-xs px-2 py-1 rounded-full border">{e.mood}</div>}
                  </div>
                  <div className="mt-2 text-right">
                    <button className="text-xs text-rose-600" onClick={(ev) => { ev.stopPropagation(); deleteEntry(e.id); }}>Delete</button>
                  </div>
                </div>
              ))}
              {visible.length === 0 && <div className="text-sm text-slate-500">No entries match</div>}
            </div>
          </div>
        </div>

        <div className="md:col-span-2">
          <div className="bg-white p-6 rounded-2xl shadow-sm">
            {!selectedId ? (
              <div className="text-center text-slate-500">Select an entry or create a new one</div>
            ) : (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <input className="w-full text-2xl font-semibold bg-transparent focus:outline-none" placeholder="Untitled" value={title} onChange={e => setTitle(e.target.value)} />
                    <div className="text-xs text-slate-400">{selectedId && formattedDate(entries.find(x=>x.id===selectedId)?.dateISO || new Date().toISOString())}</div>
                  </div>
                  <div className="flex gap-2">
                    <button className="px-3 py-2 rounded-xl border" onClick={saveSelected}>Save</button>
                    <button className="px-3 py-2 rounded-xl border" onClick={() => { const id = selectedId; if (!id) return; const e = entries.find(x => x.id === id); if (!e) return; setTitle(e.title); setBody(e.body); setEntryTags(e.tags || []); setMood(e.mood || ""); }}>Revert</button>
                  </div>
                </div>

                <div className="mb-4">
                  <textarea className="w-full min-h-[280px] rounded-xl border p-4" placeholder="Write your thoughts..." value={body} onChange={e => setBody(e.target.value)} />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Mood</div>
                    <input placeholder="e.g. calm, anxious" className="w-full rounded-xl border px-3 py-2" value={mood} onChange={e => setMood(e.target.value)} />
                  </div>

                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500 mb-1">Tags</div>
                    <div className="flex gap-2">
                      <input className="flex-1 rounded-xl border px-3 py-2" placeholder="Add tag and press Enter" value={tagInput} onChange={e => setTagInput(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') addTagToEntry(tagInput.trim()); }} />
                      <button className="px-3 py-2 rounded-xl border" onClick={() => addTagToEntry(tagInput.trim())}>Add</button>
                    </div>

                    <div className="flex gap-2 mt-2 flex-wrap">
                      {entryTags.map(t => (
                        <div key={t} className="flex items-center gap-2 text-xs px-2 py-1 rounded-full border">
                          <div>{t}</div>
                          <button className="text-xs" onClick={() => removeTagFromEntry(t)}>×</button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-6 flex gap-2">
                  <button className="px-4 py-2 rounded-xl border" onClick={() => { // quick save and keep encrypted state
                    saveSelected();
                    if (isEncrypted && !locked) {
                      const pw = prompt('Re-enter password to save encrypted copy:');
                      if (pw) saveEncryptedAfterEdit(pw);
                    }
                  }}>Save & sync encryption</button>

                  <button className="px-4 py-2 rounded-xl border" onClick={() => { navigator.clipboard.writeText(`${title}\n\n${body}`).then(()=>alert('Copied to clipboard')) }}>Copy</button>

                </div>

              </div>
            )}
          </div>

          <div className="mt-4 bg-white p-4 rounded-2xl shadow-sm">
            <div className="text-sm font-semibold mb-2">Simple stats</div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold">{entries.length}</div>
                <div className="text-xs text-slate-500">Total entries</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold">{Array.from(new Set(entries.flatMap(e => e.tags || []))).length}</div>
                <div className="text-xs text-slate-500">Unique tags</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold">{entries.filter(e=>e.mood).length}</div>
                <div className="text-xs text-slate-500">With mood</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold">{entries.filter(e=> (e.body||"").length>400).length}</div>
                <div className="text-xs text-slate-500">Long entries</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <footer className="max-w-6xl mx-auto mt-6 text-center text-xs text-slate-500">
        Built with ❤️ — single-file demo. Use in a Vite + React + Tailwind project. This demo keeps data in localStorage; create backups when needed.
      </footer>
    </div>
  );
}
