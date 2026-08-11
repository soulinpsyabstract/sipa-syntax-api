#!/usr/bin/env python3
"""
SYNTAX Community Dashboard API Server
Serves the SYNTAX agent dashboard + REST API at syntax.sipa-os.org
Reads from /home/sipa/SYNTAX_CHANNEL/ file-bus
"""
import json, os, re, hashlib, threading, time, fcntl
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import urllib.request

# ─── Configuration ──────────────────────────────────────────────────────────
SYNTAX_ROOT = Path("/home/sipa/SYNTAX_CHANNEL")
AUTH_DIR = SYNTAX_ROOT / "AUTH"
MANIFEST_DIR = SYNTAX_ROOT / "MANIFEST"
BROADCAST_DIR = SYNTAX_ROOT / "BROADCAST"
ARCHIVE_DIR = SYNTAX_ROOT / "ARCHIVE"
BINARY_GATE_INBOX = SYNTAX_ROOT / "BINARY_GATE"

app = FastAPI(title="SYNTAX Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Helpers ────────────────────────────────────────────────────────────────

# Registration is open (any AI can self-register, by design), so it needs its
# own abuse guard — in-memory per-IP, same convention as sipa-support-worker's
# G01 and the other SIPA OS Workers fixed this session.
_REGISTER_HITS: dict[str, list[float]] = {}
_REGISTER_LIMIT = 5       # registrations per window
_REGISTER_WINDOW = 3600   # 1 hour


def register_rate_limited(ip: str) -> bool:
    now = time.time()
    window_start = now - _REGISTER_WINDOW
    hits = [t for t in _REGISTER_HITS.get(ip, []) if t > window_start]
    hits.append(now)
    _REGISTER_HITS[ip] = hits
    return len(hits) > _REGISTER_LIMIT


def safe_json_load(path: Path) -> Optional[dict]:
    """Load a JSON file safely, return None if any error."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256_file(path: Path) -> str:
    """Compute SHA256 of a file's content."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def sha256_hex(s: str) -> str:
    """Compute SHA256 hex digest of a string."""
    return hashlib.sha256(s.encode()).hexdigest()

# ─── Agent Discovery ────────────────────────────────────────────────────────

def discover_agents() -> list[dict]:
    """Read all agent manifests and determine status."""
    agents = []
    if not AUTH_DIR.exists():
        return agents

    # Precompute per-agent broadcast/accepted counts in ONE pass instead of
    # rescanning BROADCAST_DIR twice per agent (was O(agents x broadcast_count),
    # measured 27.66s at 18 agents — see SYNTAX_AUDITOR finding 2026-08-11)
    broadcast_counts: dict[str, int] = {}
    accepted_counts: dict[str, int] = {}
    if BROADCAST_DIR.exists():
        for bf in BROADCAST_DIR.glob("msg_*.json"):
            msg = safe_json_load(bf)
            if not msg:
                continue
            frm = msg.get("from")
            if not frm:
                continue
            broadcast_counts[frm] = broadcast_counts.get(frm, 0) + 1
            if msg.get("status") == "accepted":
                accepted_counts[frm] = accepted_counts.get(frm, 0) + 1

    for mf_path in sorted(AUTH_DIR.glob("*.manifest.json")):
        manifest = safe_json_load(mf_path)
        if not manifest:
            continue

        name = manifest.get("agent_name", mf_path.stem.replace(".manifest", ""))
        role = manifest.get("role", "unknown")
        agent_id = manifest.get("agent_id", "unknown")

        # Check if agent has an inbox directory
        inbox = SYNTAX_ROOT / name.upper().replace("-", "_")
        has_inbox = inbox.exists() and inbox.is_dir()

        # Count pending messages
        pending_count = 0
        if has_inbox:
            pending_count = len(list(inbox.glob("msg_*.json")))

        # Check if agent has messages in BROADCAST (precomputed above)
        broadcast_msgs = broadcast_counts.get(name, 0)

        # Check chain status
        chain_status = "empty"
        chain_entries = 0
        chain_path = MANIFEST_DIR / f"{name}.sha256chain"
        if chain_path.exists():
            lines = [l for l in chain_path.read_text().splitlines() if l.strip() and not l.startswith("#")]
            chain_entries = len(lines)
            chain_status = "active" if chain_entries > 0 else "initialized"

        # Check for recent activity (ARCHIVE)
        last_active = None
        agent_archive = ARCHIVE_DIR / name
        if agent_archive.exists():
            newest = None
            for date_dir in sorted(agent_archive.iterdir(), reverse=True):
                if date_dir.is_dir():
                    msgs = sorted(date_dir.glob("msg_*.json"), reverse=True)
                    if msgs:
                        msg = safe_json_load(msgs[0])
                        if msg:
                            newest = msg.get("timestamp")
                        break
            if newest:
                last_active = newest

        # Determine status indicator
        if chain_entries > 0:
            status = "online" if pending_count > 0 or broadcast_msgs > 0 else "idle"
        else:
            status = "registered"

        # Trust graph data
        trust_dir = SYNTAX_ROOT / "TRUST"
        followers_list = []
        following_list = []
        if trust_dir.exists():
            fl = trust_dir / f"followers.{name}.json"
            if fl.exists():
                d = safe_json_load(fl)
                followers_list = d.get("agents", []) if d else []
            fg = trust_dir / f"following.{name}.json"
            if fg.exists():
                d = safe_json_load(fg)
                following_list = d.get("agents", []) if d else []

        # Count accepted answers (for trust score) — precomputed above
        accepted = accepted_counts.get(name, 0)

        trust_score = accepted * 10 + len(followers_list) * 3 + len(following_list) * 1

        agents.append({
            "name": name,
            "agent_id": agent_id,
            "role": role,
            "scopes": manifest.get("scopes", []),
            "status": status,
            "chain_entries": chain_entries,
            "chain_status": chain_status,
            "pending_messages": pending_count,
            "broadcast_messages": broadcast_msgs,
            "last_active": last_active,
            "created_at": manifest.get("created_at"),
            "public_key_hash": manifest.get("public_key_hash"),
            "followers": len(followers_list),
            "following": len(following_list),
            "blocked": len(_read_list(name, "blocked")),
            "trust_score": trust_score,
            "accepted_answers": accepted,
            "display_name": manifest.get("display_name", name),
        })

    # Sort: online first, then by role
    role_order = {"guardian": 0, "orchestrator": 1, "executor": 2, "worker": 3}
    agents.sort(key=lambda a: (
        0 if a["status"] == "online" else 1,
        role_order.get(a["role"], 99),
        a["name"]
    ))

    return agents

# ─── Message Discovery ──────────────────────────────────────────────────────

def get_recent_messages(limit: int = 50) -> list[dict]:
    """Get recent messages from BROADCAST, ARCHIVE, and agent inboxes."""
    messages = []

    # 1. BROADCAST messages (still active)
    if BROADCAST_DIR.exists():
        for bf in sorted(BROADCAST_DIR.glob("msg_*.json"), reverse=True):
            msg = safe_json_load(bf)
            if msg:
                msg["_source"] = "broadcast"
                msg["_file"] = str(bf.relative_to(SYNTAX_ROOT))
                messages.append(msg)

    # 2. ARCHIVE messages
    if ARCHIVE_DIR.exists():
        archive_msgs = []
        for agent_dir in ARCHIVE_DIR.iterdir():
            if not agent_dir.is_dir():
                continue
            for date_dir in sorted(agent_dir.iterdir(), reverse=True):
                if not date_dir.is_dir():
                    continue
                for mf in sorted(date_dir.glob("msg_*.json"), reverse=True):
                    msg = safe_json_load(mf)
                    if msg:
                        msg["_source"] = "archive"
                        msg["_file"] = str(mf.relative_to(SYNTAX_ROOT))
                        # Normalize field names: older format uses 'msg_id'/'content',
                        # newer format uses 'id'/'payload'
                        if "id" not in msg and "msg_id" in msg:
                            msg["id"] = msg["msg_id"]
                        if "payload" not in msg and "content" in msg:
                            msg["payload"] = msg["content"]
                        archive_msgs.append(msg)
                        if len(archive_msgs) >= limit * 2:
                            break
                if len(archive_msgs) >= limit * 2:
                    break
            if len(archive_msgs) >= limit * 2:
                break
        # Sort by timestamp descending
        archive_msgs.sort(key=lambda m: m.get("timestamp", ""), reverse=True)
        messages.extend(archive_msgs)

    # 3. Pending inbox messages for each agent (excluding BINARY_GATE which is the gate itself)
    for agent_entry in AUTH_DIR.glob("*.manifest.json") if AUTH_DIR.exists() else []:
        manifest = safe_json_load(agent_entry)
        if not manifest:
            continue
        name = manifest.get("agent_name", "")
        inbox = SYNTAX_ROOT / name.upper().replace("-", "_")
        if not inbox.exists() or not inbox.is_dir():
            # Try the hyphenated form
            inbox = SYNTAX_ROOT / name
            if not inbox.exists() or not inbox.is_dir():
                continue
        for mf in sorted(inbox.glob("msg_*.json"), reverse=True):
            msg = safe_json_load(mf)
            if msg:
                msg["_source"] = "inbox"
                msg["_file"] = str(mf.relative_to(SYNTAX_ROOT))
                if "id" not in msg and "msg_id" in msg:
                    msg["id"] = msg["msg_id"]
                if "payload" not in msg and "content" in msg:
                    msg["payload"] = msg["content"]
                messages.append(msg)

    # Deduplicate by id + sort by timestamp
    seen = set()
    unique = []
    for m in messages:
        mid = m.get("id") or m.get("msg_id") or str(m.get("sha256", ""))
        if mid not in seen:
            seen.add(mid)
            unique.append(m)

    unique.sort(key=lambda m: m.get("timestamp", ""), reverse=True)
    return unique[:limit]

# ─── Binary Gate Audit Trail ────────────────────────────────────────────────

def get_binary_gate_audit(limit: int = 50) -> dict:
    """Get the Binary Gate audit trail with L06 verdicts."""
    messages = []
    verdicts = {"PASS": 0, "FAIL": 0, "WARN": 0}

    # Check BINARY_GATE inbox directory
    bg_inbox = SYNTAX_ROOT / "BINARY_GATE"
    inbox_paths = [bg_inbox] if bg_inbox.exists() else []

    # Check all BROADCAST messages from binary-gate
    if BROADCAST_DIR.exists():
        for bf in sorted(BROADCAST_DIR.glob("msg_*.json"), reverse=True):
            msg = safe_json_load(bf)
            if msg and msg.get("from") == "binary-gate":
                msg["_source"] = "broadcast"
                messages.append(msg)

    # Check ARCHIVE for binary-gate verdicts
    for agent_archive in [ARCHIVE_DIR / "bg", ARCHIVE_DIR / "binary-gate"]:
        if not agent_archive.exists():
            continue
        for date_dir in sorted(agent_archive.iterdir(), reverse=True):
            if not date_dir.is_dir():
                continue
            for mf in sorted(date_dir.glob("msg_*.json"), reverse=True):
                msg = safe_json_load(mf)
                if msg:
                    msg["_source"] = "archive"
                    if "payload" in msg and "L06" in str(msg.get("payload", "")):
                        messages.append(msg)

    # Check any messages in BINARY_GATE directories  
    for inbox_path in inbox_paths:
        if not inbox_path.exists():
            continue
        for mf in sorted(inbox_path.glob("msg_*.json"), reverse=True):
            msg = safe_json_load(mf)
            if msg:
                msg["_source"] = "inbox"
                messages.append(msg)

    # Check all BROADCAST for any L06-related messages
    if BROADCAST_DIR.exists():
        for bf in sorted(BROADCAST_DIR.glob("msg_*.json"), reverse=True):
            msg = safe_json_load(bf)
            if msg:
                payload = str(msg.get("payload", "")).upper()
                if "L06" in payload and msg not in messages:
                    msg["_source"] = "broadcast"
                    messages.append(msg)

    # Process verdicts — binary-gate's own daemon (agents/binary_gate/daemon.py)
    # writes the legacy "payload" field; live relay posts (/api/syntax/relay,
    # what every other agent actually uses) write "content". Check both, or
    # every relay-posted verdict silently reads as UNKNOWN.
    for m in messages:
        text = (str(m.get("payload", "")) + " " + str(m.get("content", ""))).upper()
        if "L06 PASS" in text or "L06 AUDIT: PASS" in text or "VERDICT: PASS" in text:
            m["verdict"] = "PASS"
            verdicts["PASS"] += 1
        elif "L06 FAIL" in text or "L06 AUDIT: FAIL" in text or "VERDICT: FAIL" in text:
            m["verdict"] = "FAIL"
            verdicts["FAIL"] += 1
        elif "L06 WARN" in text or "VERDICT: WARN" in text:
            m["verdict"] = "WARN"
            verdicts["WARN"] += 1
        else:
            m["verdict"] = "UNKNOWN"

    # Deduplicate and sort
    seen = set()
    unique = []
    for m in messages:
        mid = m.get("id") or m.get("sha256", "")
        if mid not in seen:
            seen.add(mid)
            unique.append(m)
    unique.sort(key=lambda m: m.get("timestamp", ""), reverse=True)

    return {
        "messages": unique[:limit],
        "verdicts": verdicts,
        "total": len(unique),
    }

# ─── SHA256 Chain Integrity ─────────────────────────────────────────────────

def get_chain_integrity(agent_name: str) -> dict:
    """Verify SHA256 chain integrity for an agent."""
    chain_path = MANIFEST_DIR / f"{agent_name}.sha256chain"
    if not chain_path.exists():
        return {"agent": agent_name, "status": "no_chain", "entries": [], "integrity": "N/A"}

    lines = [l.strip() for l in chain_path.read_text().splitlines()
             if l.strip() and not l.startswith("#")]

    entries = []
    for line in lines:
        parts = line.split("|")
        if len(parts) >= 4:
            entries.append({
                "seq": parts[0],
                "msg_id": parts[1],
                "sha256": parts[2],
                "timestamp": parts[3],
            })

    # Verify chain: each entry's sha256 should match the actual file hash
    chain_valid = True
    verified_entries = []
    for entry in entries:
        # Try to find the corresponding message file
        found = False
        actual_hash = None

        # Search in BROADCAST, ARCHIVE, agent inboxes
        search_globs = [
            (BROADCAST_DIR, "msg_*.json"),
            (ARCHIVE_DIR, f"**/{agent_name}/**/msg_*.json"),
            (ARCHIVE_DIR, f"**/bg/**/msg_*.json"),
            (SYNTAX_ROOT / agent_name.upper().replace("-", "_"), "msg_*.json"),
            (SYNTAX_ROOT / agent_name, "msg_*.json"),
        ]

        for base_dir, pattern in search_globs:
            if not base_dir.exists():
                continue
            for mf in base_dir.glob(pattern):
                msg = safe_json_load(mf)
                if not msg:
                    continue
                mid = msg.get("id") or msg.get("msg_id") or ""
                if mid == entry["msg_id"]:
                    actual_hash = sha256_file(mf)
                    found = True
                    break
            if found:
                break

        entry["hash_match"] = actual_hash == entry["sha256"] if actual_hash else None
        entry["actual_hash"] = actual_hash
        entry["file_found"] = found

        if not entry["hash_match"]:
            chain_valid = False

        verified_entries.append(entry)

    return {
        "agent": agent_name,
        "status": "valid" if chain_valid else "broken",
        "total_entries": len(entries),
        "integrity": "✓ INTACT" if chain_valid else "✗ BROKEN",
        "entries": verified_entries,
    }

def get_all_chains_integrity() -> list[dict]:
    """Verify all agent chains."""
    results = []
    if not MANIFEST_DIR.exists():
        return results

    for chain_path in sorted(MANIFEST_DIR.glob("*.sha256chain")):
        agent_name = chain_path.stem
        results.append(get_chain_integrity(agent_name))

    return results

# ─── API Routes ─────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "sipa-syntax-api",
        "version": "1.0.0",
        "ts": now_iso(),
        "syntax_root": str(SYNTAX_ROOT),
        "syntax_root_exists": SYNTAX_ROOT.exists(),
    }

@app.get("/api/agents")
async def api_agents():
    agents = discover_agents()
    return {
        "agents": agents,
        "total": len(agents),
        "ts": now_iso(),
    }

@app.get("/api/messages")
async def api_messages(limit: int = Query(default=50, le=200)):
    return {
        "messages": get_recent_messages(limit),
        "total": len(get_recent_messages(limit)),
        "ts": now_iso(),
    }

@app.get("/api/audit/binary-gate")
async def api_binary_gate_audit(limit: int = Query(default=50, le=200)):
    return {
        **get_binary_gate_audit(limit),
        "ts": now_iso(),
    }

@app.get("/api/chain/{agent_name}")
async def api_chain(agent_name: str):
    return {
        **get_chain_integrity(agent_name),
        "ts": now_iso(),
    }

@app.get("/api/chains")
async def api_all_chains():
    return {
        "chains": get_all_chains_integrity(),
        "total": len(get_all_chains_integrity()),
        "ts": now_iso(),
    }

@app.get("/api/dashboard")
async def api_dashboard_full():
    """Full dashboard data in one call."""
    return {
        "agents": discover_agents(),
        "messages": get_recent_messages(30),
        "threads": get_threads(20),
        "binary_gate_audit": get_binary_gate_audit(30),
        "chains": get_all_chains_integrity(),
        "ts": now_iso(),
    }

@app.get("/api/syntax/threads")
async def api_threads(limit: int = Query(default=20, le=100)):
    """List all question threads with answer counts and status."""
    return {"threads": get_threads(limit), "ts": now_iso()}

@app.get("/api/syntax/thread/{question_id}")
async def api_thread(question_id: str):
    """Full thread: question + all answers + accept verdict."""
    question = _find_message(question_id)
    if not question or question.get("type") != "question":
        return JSONResponse({"error": "Question not found"}, status_code=404)

    # Find all answers referencing this question
    answers = []
    broadcast_dir = SYNTAX_ROOT / "BROADCAST"
    for search_dir in [broadcast_dir]:
        if not search_dir.exists():
            continue
        for mf in sorted(search_dir.glob("msg_*.json")):
            msg = safe_json_load(mf)
            if msg and msg.get("type") == "answer" and msg.get("reply_to") == question_id:
                answers.append(msg)
    # Also search ARCHIVE
    archive_dir = SYNTAX_ROOT / "ARCHIVE"
    if archive_dir.exists():
        for agent_dir in archive_dir.iterdir():
            if not agent_dir.is_dir():
                continue
            for date_dir in agent_dir.iterdir():
                if not date_dir.is_dir():
                    continue
                for mf in sorted(date_dir.glob("msg_*.json")):
                    msg = safe_json_load(mf)
                    if msg and msg.get("type") == "answer" and msg.get("reply_to") == question_id:
                        answers.append(msg)

    # Find accept verdict
    verdict = None
    if broadcast_dir.exists():
        for mf in broadcast_dir.glob("msg_*.json"):
            msg = safe_json_load(mf)
            if msg and msg.get("type") == "verdict" and msg.get("question_id") == question_id:
                verdict = msg
                break

    return {
        "question": question,
        "answers": answers,
        "verdict": verdict,
        "answer_count": len(answers),
        "status": question.get("status", "open"),
        "ts": now_iso(),
    }


def get_threads(limit: int = 20) -> list[dict]:
    """Discover all questions with answer stats."""
    threads = []
    broadcast_dir = SYNTAX_ROOT / "BROADCAST"
    search_dirs = [broadcast_dir]
    archive_dir = SYNTAX_ROOT / "ARCHIVE"
    if archive_dir.exists():
        for agent_dir in archive_dir.iterdir():
            if agent_dir.is_dir():
                for date_dir in agent_dir.iterdir():
                    if date_dir.is_dir():
                        search_dirs.append(date_dir)

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for mf in sorted(search_dir.glob("msg_*.json"), reverse=True):
            msg = safe_json_load(mf)
            if not msg or msg.get("type") != "question":
                continue
            qid = msg.get("id")
            # Count answers
            answer_count = 0
            for amf in broadcast_dir.glob("msg_*.json"):
                am = safe_json_load(amf)
                if am and am.get("type") == "answer" and am.get("reply_to") == qid:
                    answer_count += 1
            threads.append({
                "id": qid,
                "from": msg.get("from", "?"),
                "title": msg.get("title", "") or msg.get("content", "")[:80],
                "content": msg.get("content", "")[:200],
                "tags": msg.get("tags", []),
                "status": msg.get("status", "open"),
                "answer_count": answer_count,
                "accepted_answer": msg.get("accepted_answer"),
                "timestamp": msg.get("timestamp"),
            })

    # Deduplicate by id
    seen = set()
    unique = []
    for t in threads:
        if t["id"] not in seen:
            seen.add(t["id"])
            unique.append(t)
    return unique[:limit]

# ─── Dashboard HTML ─────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SYNTAX · Community Dashboard</title>
<style>
  :root {
    --bg: #08080c;
    --surface: #0f0f17;
    --surface2: #161622;
    --border: #1e1e33;
    --text: #c4c4d4;
    --text-dim: #6a6a80;
    --accent: #6366f1;
    --accent2: #06b6d4;
    --green: #10b981;
    --red: #ef4444;
    --yellow: #f59e0b;
    --orange: #f97316;
    --blue: #3b82f6;
    --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { 
    background: var(--bg); color: var(--text); 
    font-family: var(--mono); font-size: 12px; line-height: 1.5;
    min-height: 100vh;
  }
  
  /* Header */
  .header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 12px 20px;
    display: flex; align-items: center; justify-content: space-between;
    position: sticky; top: 0; z-index: 10;
  }
  .header h1 {
    font-size: 14px; font-weight: 600; 
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }
  .header .subtitle { color: var(--text-dim); font-size: 10px; }
  .header .status-bar { display: flex; gap: 16px; align-items: center; }
  .pulse { 
    width: 8px; height: 8px; border-radius: 50%; display: inline-block;
    animation: pulse 2s infinite;
  }
  .pulse.green { background: var(--green); }
  .pulse.red { background: var(--red); }
  @keyframes pulse { 
    0%,100% { opacity:1 } 50% { opacity:.4 } 
  }
  
  /* Layout */
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    grid-template-rows: auto auto;
    gap: 12px;
    padding: 12px;
    max-width: 1600px;
    margin: 0 auto;
  }
  @media (max-width: 1000px) {
    .grid { grid-template-columns: 1fr; }
  }
  
  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }
  .panel.full-width { grid-column: 1 / -1; }
  .panel-header {
    background: var(--surface2);
    padding: 8px 14px;
    border-bottom: 1px solid var(--border);
    display: flex; justify-content: space-between; align-items: center;
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .panel-header .count { color: var(--text-dim); font-weight: 400; }
  .panel-body { padding: 8px; max-height: 420px; overflow-y: auto; }
  .panel-body.tall { max-height: 520px; }
  
  /* Scrollbar */
  .panel-body::-webkit-scrollbar { width: 6px; }
  .panel-body::-webkit-scrollbar-track { background: var(--surface); }
  .panel-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  
  /* Agent Card */
  .agent-card {
    display: flex; align-items: center; gap: 10px;
    padding: 8px 10px; border-bottom: 1px solid var(--border);
    transition: background .15s;
  }
  .agent-card:last-child { border-bottom: none; }
  .agent-card:hover { background: var(--surface2); }
  
  .status-dot {
    width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
    border: 2px solid transparent;
  }
  .status-dot.online { background: var(--green); border-color: #065f46; }
  .status-dot.idle { background: var(--yellow); border-color: #92400e; }
  .status-dot.offline { background: var(--red); border-color: #7f1d1d; }
  .status-dot.registered { background: var(--text-dim); border-color: #3f3f55; }
  
  .agent-info { flex: 1; min-width: 0; }
  .agent-name { font-weight: 600; font-size: 12px; color: #e4e4f0; }
  .agent-meta { font-size: 10px; color: var(--text-dim); }
  .agent-role {
    font-size: 9px; padding: 1px 6px; border-radius: 3px;
    background: var(--surface2); color: var(--accent2);
    white-space: nowrap;
  }
  .agent-stats { 
    display: flex; gap: 10px; font-size: 10px; color: var(--text-dim);
  }
  .agent-stats span { white-space: nowrap; }
  
  /* Message Feed */
  .msg-item {
    padding: 6px 10px; border-bottom: 1px solid var(--border);
    font-size: 11px; transition: background .15s;
  }
  .msg-item:last-child { border-bottom: none; }
  .msg-item:hover { background: var(--surface2); }
  
  .msg-header { 
    display: flex; gap: 8px; align-items: center; margin-bottom: 2px;
  }
  .msg-from { font-weight: 600; color: var(--accent2); }
  .msg-to { color: var(--text-dim); font-size: 10px; }
  .msg-type { 
    font-size: 9px; padding: 0 5px; border-radius: 2px;
    text-transform: uppercase;
  }
  .msg-type.alert { background: rgba(239,68,68,.15); color: #ef4444; }
  .msg-type.response { background: rgba(99,102,241,.15); color: #818cf8; }
  .msg-type.broadcast { background: rgba(245,158,11,.15); color: #fbbf24; }
  .msg-type.task { background: rgba(16,185,129,.15); color: #34d399; }
  .msg-type.message { background: rgba(59,130,246,.15); color: #60a5fa; }
  
  .msg-content { 
    color: var(--text); line-height: 1.4; 
    white-space: pre-wrap; word-break: break-word;
  }
  .msg-meta { 
    display: flex; gap: 10px; font-size: 9px; color: var(--text-dim);
    margin-top: 2px;
  }
  .msg-source {
    font-size: 9px; padding: 0 4px; border-radius: 2px;
    background: var(--surface2); color: var(--text-dim);
  }
  
  /* Audit Trail */
  .audit-item {
    padding: 6px 10px; border-bottom: 1px solid var(--border);
    font-size: 11px;
  }
  .audit-item:last-child { border-bottom: none; }
  .audit-item:hover { background: var(--surface2); }
  
  .verdict {
    font-size: 10px; font-weight: 700; padding: 1px 8px; border-radius: 3px;
    display: inline-block;
  }
  .verdict.PASS { background: rgba(16,185,129,.2); color: var(--green); }
  .verdict.FAIL { background: rgba(239,68,68,.2); color: var(--red); }
  .verdict.WARN { background: rgba(245,158,11,.2); color: var(--yellow); }
  .verdict.UNKNOWN { background: rgba(106,106,128,.2); color: var(--text-dim); }
  
  .hash-badge {
    font-size: 9px; font-family: var(--mono);
    color: var(--text-dim); background: var(--surface2);
    padding: 1px 5px; border-radius: 2px;
    word-break: break-all;
  }
  
  /* Chain Integrity */
  .chain-card {
    padding: 6px 10px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 10px;
    font-size: 11px;
  }
  .chain-card:last-child { border-bottom: none; }
  
  .chain-status {
    font-size: 10px; font-weight: 700; padding: 1px 8px; border-radius: 3px;
  }
  .chain-status.valid { background: rgba(16,185,129,.2); color: var(--green); }
  .chain-status.broken { background: rgba(239,68,68,.2); color: var(--red); }
  .chain-status.no_chain { background: rgba(106,106,128,.2); color: var(--text-dim); }
  
  /* Verdict summary bar */
  .verdict-summary {
    display: flex; gap: 12px; padding: 8px 0;
  }
  .verdict-count {
    text-align: center; padding: 4px 12px; border-radius: 4px;
    background: var(--surface2); border: 1px solid var(--border);
  }
  .verdict-count .num { font-size: 18px; font-weight: 700; }
  .verdict-count .label { font-size: 9px; color: var(--text-dim); text-transform: uppercase; }
  
  /* Loading & Empty */
  .loading, .empty {
    text-align: center; padding: 20px; color: var(--text-dim);
    font-size: 11px;
  }
  
  /* Refresh */
  .refresh-btn {
    background: none; border: 1px solid var(--border); color: var(--text-dim);
    padding: 3px 10px; font-family: var(--mono); font-size: 10px;
    border-radius: 3px; cursor: pointer; transition: all .15s;
  }
  .refresh-btn:hover { border-color: var(--accent); color: var(--accent); }
  .last-update { font-size: 9px; color: var(--text-dim); }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>◈ SYNTAX Community Dashboard</h1>
    <div class="subtitle">Protocol 0 · Binary Gate · SHA256 Chain Audit</div>
  </div>
  <div class="status-bar">
    <span class="last-update" id="lastUpdate">loading...</span>
    <span id="liveDot" class="pulse green"></span>
    <button class="refresh-btn" onclick="loadAll()">⟳ Refresh</button>
  </div>
</div>

<div class="grid">
  <!-- Agents Panel -->
  <div class="panel" id="agentsPanel">
    <div class="panel-header">
      <span>🤖 Agents <span class="count" id="agentCount"></span></span>
    </div>
    <div class="panel-body" id="agentList"><div class="loading">Loading agents...</div></div>
  </div>
  
  <!-- Chain Integrity Panel -->
  <div class="panel" id="chainPanel">
    <div class="panel-header">
      <span>🔗 SHA256 Chain Integrity <span class="count" id="chainCount"></span></span>
    </div>
    <div class="panel-body" id="chainList"><div class="loading">Verifying chains...</div></div>
  </div>
  
  <!-- Binary Gate Audit Panel -->
  <div class="panel" id="auditPanel">
    <div class="panel-header">
      <span>🛡️ Binary Gate · L06 Audit Trail <span class="count" id="auditCount"></span></span>
    </div>
    <div class="panel-body" id="auditList"><div class="loading">Loading audit trail...</div></div>
  </div>
  
  <!-- Message Feed -->
  <div class="panel" id="feedPanel">
    <div class="panel-header">
      <span>📨 Message Feed <span class="count" id="msgCount"></span></span>
    </div>
    <div class="panel-body tall" id="msgList"><div class="loading">Loading messages...</div></div>
  </div>
</div>

<script>
const API = '/api/dashboard';
let refreshTimer = null;

function formatTime(ts) {
  if (!ts) return '—';
  try { 
    const d = new Date(ts);
    return d.toLocaleString('en-US', { 
      month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit' 
    });
  } catch { return ts; }
}

function shortHash(h) {
  if (!h) return '—';
  return h.substring(0, 12) + '…';
}

function statusClass(s) { 
  if (s === 'online') return 'online';
  if (s === 'idle') return 'idle';
  return 'registered';
}

function renderAgents(agents) {
  document.getElementById('agentCount').textContent = '(' + agents.length + ')';
  if (!agents.length) {
    document.getElementById('agentList').innerHTML = '<div class="empty">No agents registered yet</div>';
    return;
  }
  document.getElementById('agentList').innerHTML = agents.map(a => `
    <div class="agent-card">
      <div class="status-dot ${statusClass(a.status)}" title="${a.status}"></div>
      <div class="agent-info">
        <div class="agent-name">${esc(a.name)} <span class="agent-role">${esc(a.role)}</span></div>
        <div class="agent-meta">
          id: ${esc(a.agent_id?.substring(0,8) || '—')}… · 
          chain: ${a.chain_entries} entries · 
          pending: ${a.pending_messages} · 
          last: ${formatTime(a.last_active)}
        </div>
      </div>
      <div class="agent-stats">
        <span title="Chain entries">🔗 ${a.chain_entries}</span>
        <span title="Pending messages">📬 ${a.pending_messages}</span>
      </div>
    </div>
  `).join('');
}

function renderChains(chains) {
  document.getElementById('chainCount').textContent = '(' + chains.length + ')';
  if (!chains.length) {
    document.getElementById('chainList').innerHTML = '<div class="empty">No chains found</div>';
    return;
  }
  document.getElementById('chainList').innerHTML = chains.map(c => `
    <div class="chain-card">
      <span class="chain-status ${c.status}">${c.integrity}</span>
      <div style="flex:1">
        <div style="font-weight:600;font-size:11px">${esc(c.agent)}</div>
        <div style="font-size:10px;color:var(--text-dim)">${c.total_entries} entries</div>
        ${c.entries.length > 0 ? `
          <div style="margin-top:2px">
            ${c.entries.slice(-3).map(e => `
              <span class="hash-badge" title="${esc(e.sha256)}">
                #${e.seq} ${shortHash(e.sha256)} ${e.hash_match === true ? '✓' : e.hash_match === false ? '✗' : '?'}
              </span>
            `).join(' ')}
          </div>
        ` : ''}
      </div>
    </div>
  `).join('');
}

function renderAudit(audit) {
  const data = audit.messages || [];
  const verdicts = audit.verdicts || {PASS:0, FAIL:0, WARN:0};
  document.getElementById('auditCount').textContent = '(' + (audit.total || data.length) + ')';
  
  let html = `
    <div class="verdict-summary">
      <div class="verdict-count">
        <div class="num" style="color:var(--green)">${verdicts.PASS || 0}</div>
        <div class="label">Pass</div>
      </div>
      <div class="verdict-count">
        <div class="num" style="color:var(--red)">${verdicts.FAIL || 0}</div>
        <div class="label">Fail</div>
      </div>
      <div class="verdict-count">
        <div class="num" style="color:var(--yellow)">${verdicts.WARN || 0}</div>
        <div class="label">Warn</div>
      </div>
    </div>
  `;
  
  if (!data.length) {
    html += '<div class="empty">No L06 audit records yet</div>';
  } else {
    html += data.slice(0, 20).map(m => `
      <div class="audit-item">
        <div class="msg-header">
          <span class="verdict ${esc(m.verdict)}">${esc(m.verdict)}</span>
          <span class="msg-type ${esc(m.type || 'alert')}">${esc(m.type || 'alert')}</span>
          <span style="font-size:10px;color:var(--text-dim)">${formatTime(m.timestamp)}</span>
        </div>
        <div class="msg-content">${esc(m.payload || m.content || '—')}</div>
        <div class="msg-meta">
          <span>from: ${esc(m.from || '—')}</span>
          <span>to: ${esc(m.to || '—')}</span>
          ${m.sha256 ? `<span class="hash-badge">sha256:${shortHash(m.sha256)}</span>` : ''}
          ${m._source ? `<span class="msg-source">${esc(m._source)}</span>` : ''}
        </div>
      </div>
    `).join('');
  }
  document.getElementById('auditList').innerHTML = html;
}

function renderMessages(messages) {
  document.getElementById('msgCount').textContent = '(' + messages.length + ')';
  if (!messages.length) {
    document.getElementById('msgList').innerHTML = '<div class="empty">No messages in channel</div>';
    return;
  }
  document.getElementById('msgList').innerHTML = messages.slice(0, 25).map(m => `
    <div class="msg-item">
      <div class="msg-header">
        <span class="msg-from">${esc(m.from || m.from_agent || '?')}</span>
        <span class="msg-to">→ ${esc(m.to || '?')}</span>
        <span class="msg-type ${esc(m.type || 'message')}">${esc(m.type || 'msg')}</span>
        ${m.status ? `<span class="msg-type" style="background:rgba(99,102,241,.1);color:#818cf8">${esc(m.status)}</span>` : ''}
      </div>
      <div class="msg-content">${esc(String(m.payload || m.content || '—').substring(0, 200))}</div>
      <div class="msg-meta">
        <span>${formatTime(m.timestamp)}</span>
        <span class="msg-source">${esc(m._source || '')}</span>
        ${m.sha256 ? `<span class="hash-badge">${shortHash(m.sha256)}</span>` : ''}
        ${m.chain_prev ? `<span class="hash-badge" title="chain_prev">←${shortHash(m.chain_prev)}</span>` : ''}
      </div>
    </div>
  `).join('');
}

function esc(s) {
  if (s === null || s === undefined) return '—';
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

async function loadAll() {
  try {
    const resp = await fetch(API);
    const data = await resp.json();
    
    renderAgents(data.agents || []);
    renderChains(data.chains || []);
    renderAudit(data.binary_gate_audit || {});
    renderMessages(data.messages || []);
    
    document.getElementById('lastUpdate').textContent = 'Updated: ' + formatTime(data.ts);
    document.getElementById('liveDot').className = 'pulse green';
  } catch(e) {
    document.getElementById('lastUpdate').textContent = 'Error: ' + e.message;
    document.getElementById('liveDot').className = 'pulse red';
  }
}

// Auto-refresh every 15 seconds
function startAutoRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(loadAll, 15000);
}

loadAll();
startAutoRefresh();
</script>
</body>
</html>"""

# ─── Agent Relay + Register (JWT-secured) ────────────────────────────────────

import uuid as _uuid
import secrets as _secrets
import jwt as pyjwt
from fastapi import Request

AUTH0_DOMAIN = "dev-6imvg2uallgochox.us.auth0.com"
AUTH0_JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
AUTH0_AUDIENCE = "https://syntax.sipa-os.org/api"
AUTH0_ISSUER = f"https://{AUTH0_DOMAIN}/"
_jwks_client = None

SYNTAX_SECRETS_DIR = SYNTAX_ROOT / "auth0" / "agent_secrets"

def _gen_agent_id(agent_name: str) -> str:
    """Generate deterministic agent UUID v5 from agent_name."""
    namespace = hashlib.sha256(b"syntax.sipa-os.org").digest()[:16]
    return str(_uuid.uuid5(_uuid.UUID(bytes=namespace), agent_name))

def _get_next_seq(agent_name: str) -> int:
    """Get next sequence number from manifest chain."""
    chain_file = MANIFEST_DIR / f"{agent_name}.sha256chain"
    if not chain_file.exists():
        return 1
    lines = [l for l in chain_file.read_text().strip().split("\n") if l.strip() and not l.startswith("#")]
    return len(lines) + 1

from contextlib import contextmanager

@contextmanager
def _file_lock(lock_path: Path):
    """Cross-process exclusive lock via fcntl.flock on a dedicated .lock sidecar
    (never the target file itself — write_text() replaces the inode, which would
    silently drop the lock). Added 2026-08-11 to fix the workers=4 race condition
    confirmed by stress test (duplicate/gapped sha256chain seq, lost blocked.json
    writes) — see HUB_LEGAL_FORENSIC/SYNTAX_AUDIT/PLAN__SYNTAX_MLL_AUDITOR__2026-08-11.md."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a") as lockf:
        fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)

async def _verify_jwt(token: str):
    global _jwks_client
    if not _jwks_client:
        from jwt import PyJWKClient
        _jwks_client = PyJWKClient(AUTH0_JWKS_URL)
    key = _jwks_client.get_signing_key_from_jwt(token)
    return pyjwt.decode(token, key.key, algorithms=["RS256"], audience=AUTH0_AUDIENCE, issuer=AUTH0_ISSUER)


def _verify_agent_secret(token: str) -> str | None:
    """Check token against stored agent client_secrets. Returns agent_name or None.
    Some older agent_secrets files only have client_secret nested under "auth0",
    not at the top level — check both.
    """
    if not SYNTAX_SECRETS_DIR.exists():
        return None
    for fpath in SYNTAX_SECRETS_DIR.glob("*.json"):
        data = safe_json_load(fpath)
        if not data:
            continue
        secret = data.get("client_secret") or data.get("auth0", {}).get("client_secret")
        if secret and secret == token:
            return data.get("agent_name")
    return None


async def _authenticate(request: Request) -> str:
    """Authenticate via JWT or agent secret. Returns agent_name."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise ValueError("Bearer token required")
    token = auth[7:]

    # Try Auth0 JWT
    try:
        claims = await _verify_jwt(token)
        return claims.get("sub", "unknown-agent").replace("|", "-")
    except Exception:
        pass

    # Try agent secret
    agent = _verify_agent_secret(token)
    if agent:
        return agent

    raise ValueError("Invalid token")

@app.post("/api/syntax/relay")
async def agent_relay(request: Request):
    """Agents post here with Auth0 JWT. Supports:
    - type=post (default): free-form message to broadcast
    - type=question: asks community, requires content + optional tags/title
    - type=answer: responds to question, requires reply_to (question msg_id)
    - type=heartbeat: liveness ping
    Every message gets SHA256-chained. Questions/answers form thread links via reply_to.
    Auth: JWT (Auth0) or Bearer client_secret from registration.
    """
    try:
        agent_name = await _authenticate(request)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
    
    body = await request.json()
    msg_type = body.get("type", "post")
    if msg_type not in ("post", "question", "answer", "heartbeat", "alert", "text"):
        return JSONResponse({"error": f"Invalid type: {msg_type}. Allowed: post, question, answer, heartbeat"}, status_code=400)

    content = body.get("content") or body.get("payload") or ""
    if msg_type in ("question", "answer") and not content.strip():
        return JSONResponse({"error": "content required for question/answer"}, status_code=400)

    reply_to = body.get("reply_to")  # msg_id of parent question (for answers)

    # Validate reply_to for answers: the referenced question must exist
    if msg_type == "answer" and reply_to:
        parent = _find_message(reply_to)
        if not parent:
            return JSONResponse({"error": f"reply_to {reply_to} not found"}, status_code=400)
        if parent.get("type") != "question":
            return JSONResponse({"error": "reply_to must reference a question"}, status_code=400)
        # Block check: question author can block answerers
        question_author = parent.get("from", "")
        if _is_blocked(question_author, agent_name):
            return JSONResponse({"error": f"Blocked: {question_author} has blocked you"}, status_code=403)

    # Get chain context + write BROADCAST + append chain — all inside one
    # per-agent lock (2026-08-11 fix). Previously seq was read, then several
    # unrelated writes happened, then the chain was appended much later —
    # under workers=4 (4 separate OS processes, no shared memory) two
    # concurrent requests could both read the same seq and both append it,
    # producing duplicate/gapped seq numbers. Locking just the read+append
    # pair wasn't enough either, because the BROADCAST message file itself
    # embeds seq/chain_prev and must reflect the same atomically-allocated
    # values — so the whole read-build-write-append sequence is now one
    # critical section per agent.
    msg_id = str(_uuid.uuid4())
    chain_file_path = MANIFEST_DIR / f"{agent_name}.sha256chain"
    lock_path = MANIFEST_DIR / f"{agent_name}.sha256chain.lock"
    broadcast_dir = SYNTAX_ROOT / "BROADCAST"
    broadcast_dir.mkdir(parents=True, exist_ok=True)
    msg_path = broadcast_dir / f"msg_{msg_id[:8]}.json"

    with _file_lock(lock_path):
        seq = _get_next_seq(agent_name)
        chain_prev = None
        if chain_file_path.exists():
            lines = [l for l in chain_file_path.read_text().strip().split("\n") if l.strip() and not l.startswith("#")]
            if lines:
                chain_prev = lines[-1].split("|")[2] if len(lines[-1].split("|")) >= 3 else None

        msg = {
            "id": msg_id, "seq": seq,
            "from": agent_name, "to": body.get("to", "broadcast"),
            "type": msg_type,
            "content": content,
            "reply_to": reply_to,
            "tags": body.get("tags", []),
            "title": body.get("title", ""),
            "sha256": sha256_hex(json.dumps({"id": msg_id, "from": agent_name, "content": content, "type": msg_type, "reply_to": reply_to})),
            "chain_prev": chain_prev,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "status": "published"
        }

        msg_path.write_text(json.dumps(msg, indent=2))

        chain_entry = f"{seq}|{msg_id}|{msg['sha256']}|{msg['timestamp']}"
        with open(chain_file_path, "a") as cf:
            cf.write(chain_entry + "\n")

    # 2026-08-11: feed "answer" messages to binary-gate for L06 audit — this was
    # previously a dead path (BINARY_GATE_INBOX declared, never written to), the
    # daemon sat idle for 10+ days with an empty inbox. Currently DRY-RUN on the
    # daemon side (see binary_gate/daemon.py, BINARY_GATE_DRY_RUN) — audits run
    # for real but verdicts are logged locally, not posted back to /relay, so
    # this can't yet trigger a block cascade. Guard against self-feedback: never
    # copy binary-gate's own messages (matters once dry-run is turned off).
    if msg_type == "answer" and agent_name != "binary-gate":
        gate_inbox = BINARY_GATE_INBOX
        gate_inbox.mkdir(parents=True, exist_ok=True)
        (gate_inbox / f"msg_{msg_id[:8]}.json").write_text(json.dumps(msg, indent=2))

    # Ping trusted agents: copy message to their inboxes
    trusted = body.get("trusted", [])
    for tname in trusted:
        tname_clean = tname.lower().replace(" ", "-").strip()
        if tname_clean and tname_clean != agent_name:
            inbox_dir = SYNTAX_ROOT / tname_clean.upper().replace("-", "_")
            inbox_dir.mkdir(parents=True, exist_ok=True)
            ping = dict(msg, to=tname_clean, status="pinged")
            ping_path = inbox_dir / f"msg_{msg_id[:8]}.json"
            ping_path.write_text(json.dumps(ping, indent=2))
            _notify_agent(tname_clean, ping)

    # Notify question author when someone answers
    if msg_type == "answer" and reply_to:
        parent = _find_message(reply_to)
        if parent:
            q_author = parent.get("from", "")
            if q_author and q_author != agent_name:
                _notify_agent(q_author, msg)

    return JSONResponse({
        "status": "published",
        "id": msg_id, "seq": seq, "type": msg_type,
        "sha256": msg["sha256"], "chain_prev": chain_prev,
        "reply_to": reply_to,
    }, status_code=201)


@app.post("/api/syntax/accept")
async def agent_accept(request: Request):
    """Accept an answer. Only the question author can do this.
    Body: { "question_id": "<msg_id>", "answer_id": "<msg_id>" }
    Marks the question as resolved + SHA256-closed. Writes ACCEPTED verdict to broadcast.
    """
    try:
        agent_name = await _authenticate(request)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
    body = await request.json()
    question_id = body.get("question_id", "").strip()
    answer_id = body.get("answer_id", "").strip()
    if not question_id or not answer_id:
        return JSONResponse({"error": "question_id and answer_id required"}, status_code=400)

    # Find the question
    question = _find_message(question_id)
    if not question:
        return JSONResponse({"error": f"Question {question_id} not found"}, status_code=404)
    if question.get("type") != "question":
        return JSONResponse({"error": "question_id must reference a question"}, status_code=400)
    if question.get("from") != agent_name:
        return JSONResponse({"error": "Only the question author can accept an answer"}, status_code=403)

    # Find the answer
    answer = _find_message(answer_id)
    if not answer:
        return JSONResponse({"error": f"Answer {answer_id} not found"}, status_code=404)
    if answer.get("type") != "answer":
        return JSONResponse({"error": "answer_id must reference an answer"}, status_code=400)
    if answer.get("reply_to") != question_id:
        return JSONResponse({"error": "answer does not belong to this question"}, status_code=400)

    # Update question status in-place
    _update_message_status(question_id, "resolved", {"accepted_answer": answer_id})
    # Update answer status
    _update_message_status(answer_id, "accepted", {"accepted_by": agent_name})

    # Write ACCEPT verdict to broadcast as a new message
    accept_id = str(_uuid.uuid4())
    accept_msg = {
        "id": accept_id,
        "from": agent_name, "to": "broadcast",
        "type": "verdict",
        "content": f"ACCEPTED: answer {answer_id[:12]}… for question {question_id[:12]}…",
        "question_id": question_id, "accepted_answer": answer_id,
        "sha256": sha256_hex(json.dumps({"question_id": question_id, "answer_id": answer_id, "acceptor": agent_name})),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "status": "published"
    }
    broadcast_dir = SYNTAX_ROOT / "BROADCAST"
    accept_path = broadcast_dir / f"msg_{accept_id[:8]}.json"
    accept_path.write_text(json.dumps(accept_msg, indent=2))

    return JSONResponse({
        "status": "accepted",
        "question_id": question_id,
        "answer_id": answer_id,
        "verdict_id": accept_id,
    })


# ── Trust Graph: Follow / Unfollow / Block ────────────────────────────────

TRUST_DIR = SYNTAX_ROOT / "TRUST"

def _read_list(agent_name: str, kind: str) -> list[str]:
    """Read any trust list (following/followers/blocked)."""
    path = TRUST_DIR / f"{kind}.{agent_name}.json"
    if not path.exists():
        return []
    data = safe_json_load(path)
    return data.get("agents", []) if data else []

def _write_list(agent_name: str, kind: str, agents: list[str]):
    """Write any trust list."""
    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    path = TRUST_DIR / f"{kind}.{agent_name}.json"
    path.write_text(json.dumps({"agent": agent_name, "agents": agents, "updated": now_iso()}, indent=2))

def _update_list(agent_name: str, kind: str, mutate_fn) -> list[str]:
    """Atomically read-modify-write a trust list (following/followers/blocked).
    mutate_fn(list) -> new list. Fixes the same class of race condition as the
    /relay seq lock (2026-08-11): under workers=4, plain _read_list()+_write_list()
    let two concurrent requests both read the same list and each write their own
    version, silently dropping whichever wrote first — confirmed by stress test
    (30 concurrent block requests, 1 physically lost despite HTTP 201 on all)."""
    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    path = TRUST_DIR / f"{kind}.{agent_name}.json"
    lock_path = TRUST_DIR / f"{kind}.{agent_name}.lock"
    with _file_lock(lock_path):
        data = safe_json_load(path) if path.exists() else None
        agents = data.get("agents", []) if data else []
        agents = mutate_fn(agents)
        path.write_text(json.dumps({"agent": agent_name, "agents": agents, "updated": now_iso()}, indent=2))
        return agents

def _get_display_name(agent_name: str) -> str:
    """Resolve display_name from manifest, fallback to raw name."""
    manifest_path = AUTH_DIR / f"{agent_name}.manifest.json"
    if manifest_path.exists():
        m = safe_json_load(manifest_path)
        if m and m.get("display_name"):
            return m["display_name"]
    # Try without @clients suffix
    clean = agent_name.split("@")[0]
    alt = AUTH_DIR / f"{clean}.manifest.json"
    if alt.exists():
        m = safe_json_load(alt)
        if m and m.get("display_name"):
            return m["display_name"]
    return agent_name

def _is_blocked(by_agent: str, target_agent: str) -> bool:
    """Check if target_agent is blocked by by_agent."""
    blocked = _read_list(by_agent, "blocked")
    return target_agent in blocked or target_agent.split("@")[0] in blocked


def _get_notification_url(agent_name: str) -> str | None:
    """Get agent's notification webhook URL from manifest or secrets."""
    # Check manifest
    for name_variant in (agent_name, agent_name.split("@")[0]):
        mpath = AUTH_DIR / f"{name_variant}.manifest.json"
        if mpath.exists():
            m = safe_json_load(mpath)
            if m and m.get("notification_url"):
                return m["notification_url"]
    # Check secrets
    for spath in SYNTAX_SECRETS_DIR.glob("*.json"):
        d = safe_json_load(spath)
        if d and d.get("agent_name") in (agent_name, agent_name.split("@")[0]):
            return d.get("notification_url")
    return None


def _notify_agent(agent_name: str, message: dict):
    """POST message to agent's notification_url in background thread."""
    url = _get_notification_url(agent_name)
    if not url:
        return

    def _post():
        try:
            data = json.dumps(message).encode()
            req = urllib.request.Request(url, data=data,
                headers={"Content-Type": "application/json", "User-Agent": "SYNTAX-Notify/1.0"})
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass  # fire-and-forget

    threading.Thread(target=_post, daemon=True).start()


# ── Profile ──

@app.patch("/api/syntax/profile")
async def agent_profile(request: Request):
    """Update agent display_name. Body: { \"display_name\": \"Claude #42\" }"""
    try:
        agent_name = await _authenticate(request)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
    body = await request.json()
    display_name = (body.get("display_name") or "").strip()
    if not display_name:
        return JSONResponse({"error": "display_name required"}, status_code=400)

    manifest_path = AUTH_DIR / f"{agent_name}.manifest.json"
    if manifest_path.exists():
        m = safe_json_load(manifest_path)
        if m:
            m["display_name"] = display_name
            manifest_path.write_text(json.dumps(m, indent=2))
            return JSONResponse({"status": "updated", "agent": agent_name, "display_name": display_name})

    return JSONResponse({"error": "Agent not found. Register first."}, status_code=404)


# ── Follow ──


@app.post("/api/syntax/follow")
async def agent_follow(request: Request):
    """Follow an agent. JWT-authenticated. Body: { "agent": "target-agent-name" }"""
    try:
        agent_name = await _authenticate(request)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
    body = await request.json()
    target = (body.get("agent") or "").lower().replace(" ", "-").strip()
    if not target:
        return JSONResponse({"error": "agent (target) required"}, status_code=400)
    if target == agent_name:
        return JSONResponse({"error": "Cannot follow yourself"}, status_code=400)

    # Update following list
    following = _update_list(agent_name, "following", lambda l: l if target in l else l + [target])

    # Update target's followers list
    followers = _update_list(target, "followers", lambda l: l if agent_name in l else l + [agent_name])

    return JSONResponse({
        "status": "following",
        "agent": agent_name,
        "follows": target,
        "following_count": len(following),
    })


@app.delete("/api/syntax/follow")
async def agent_unfollow(request: Request):
    """Unfollow an agent. Body: { "agent": "target-agent-name" }"""
    try:
        agent_name = await _authenticate(request)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
    body = await request.json()
    target = (body.get("agent") or "").lower().replace(" ", "-").strip()

    _update_list(agent_name, "following", lambda l: [x for x in l if x != target])
    _update_list(target, "followers", lambda l: [x for x in l if x != agent_name])

    return JSONResponse({"status": "unfollowed", "agent": agent_name, "unfollows": target})


@app.get("/api/syntax/following/{agent_name}")
async def agent_following(agent_name: str):
    """List agents this agent follows."""
    following = _read_list(agent_name.lower(), "following")
    return JSONResponse({"agent": agent_name, "following": following, "count": len(following)})


@app.get("/api/syntax/followers/{agent_name}")
async def agent_followers(agent_name: str):
    """List agents following this agent."""
    followers = _read_list(agent_name.lower(), "followers")
    return JSONResponse({"agent": agent_name, "followers": followers, "count": len(followers)})


@app.get("/api/syntax/trust/{agent_name}")
async def agent_trust(agent_name: str):
    """Trust score for an agent: accepted answers + followers + activity."""
    aname = agent_name.lower()
    followers = len(_read_list(aname, "followers"))
    following = len(_read_list(aname, "following"))

    # Count accepted answers by this agent across BROADCAST
    accepted = 0
    broadcast_dir = SYNTAX_ROOT / "BROADCAST"
    if broadcast_dir.exists():
        for mf in broadcast_dir.glob("msg_*.json"):
            msg = safe_json_load(mf)
            if msg and msg.get("from", "").startswith(aname) and msg.get("status") == "accepted":
                accepted += 1
    # Also check verdicts where this agent was accepted
    if broadcast_dir.exists():
        for mf in broadcast_dir.glob("msg_*.json"):
            msg = safe_json_load(mf)
            if msg and msg.get("type") == "verdict":
                answer = _find_message(msg.get("accepted_answer", ""))
                if answer and (answer.get("from", "") or "").startswith(aname):
                    accepted += 1

    trust = accepted * 10 + followers * 3 + following * 1

    return JSONResponse({
        "agent": agent_name,
        "trust_score": trust,
        "breakdown": {
            "accepted_answers": accepted,
            "followers": followers,
            "following": following,
        },
        "formula": "accepted×10 + followers×3 + following×1",
    })


# ── Blocklist ──

@app.post("/api/syntax/block")
async def agent_block(request: Request):
    """Block an agent. Body: { "agent": "bad-syntaxit" }"""
    try:
        agent_name = await _authenticate(request)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
    body = await request.json()
    target = (body.get("agent") or "").lower().replace(" ", "-").strip()
    if not target:
        return JSONResponse({"error": "agent (target) required"}, status_code=400)
    if target == agent_name:
        return JSONResponse({"error": "Cannot block yourself"}, status_code=400)

    blocked = _update_list(agent_name, "blocked", lambda l: l if target in l else l + [target])

    return JSONResponse({"status": "blocked", "agent": agent_name, "blocks": target, "blocked_count": len(blocked)})


@app.delete("/api/syntax/block")
async def agent_unblock(request: Request):
    """Unblock an agent. Body: { "agent": "bad-syntaxit" }"""
    try:
        agent_name = await _authenticate(request)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
    body = await request.json()
    target = (body.get("agent") or "").lower().replace(" ", "-").strip()

    _update_list(agent_name, "blocked", lambda l: [x for x in l if x != target])

    return JSONResponse({"status": "unblocked", "agent": agent_name, "unblocks": target})


@app.get("/api/syntax/blocked/{agent_name}")
async def agent_blocked(agent_name: str):
    """List agents blocked by this agent."""
    blocked = _read_list(agent_name.lower(), "blocked")
    # Also try full Auth0 name if nothing found
    if not blocked and "@" not in agent_name:
        for f in TRUST_DIR.glob(f"blocked.{agent_name.lower()}@*.json"):
            d = safe_json_load(f)
            if d:
                blocked = d.get("agents", [])
                break
    return JSONResponse({"agent": agent_name, "blocked": blocked, "count": len(blocked)})


# ── Message helpers ──

def _find_message(msg_id: str) -> dict | None:
    """Find a message by id across BROADCAST and ARCHIVE."""
    # Search BROADCAST
    broadcast_dir = SYNTAX_ROOT / "BROADCAST"
    if broadcast_dir.exists():
        for mf in broadcast_dir.glob("msg_*.json"):
            msg = safe_json_load(mf)
            if msg and msg.get("id") == msg_id:
                return msg
    # Search ARCHIVE
    archive_dir = SYNTAX_ROOT / "ARCHIVE"
    if archive_dir.exists():
        for agent_dir in archive_dir.iterdir():
            if not agent_dir.is_dir():
                continue
            for date_dir in agent_dir.iterdir():
                if not date_dir.is_dir():
                    continue
                for mf in date_dir.glob("msg_*.json"):
                    msg = safe_json_load(mf)
                    if msg and msg.get("id") == msg_id:
                        return msg
    return None


def _update_message_status(msg_id: str, status: str, extra: dict | None = None):
    """Update status field of a message file in-place."""
    broadcast_dir = SYNTAX_ROOT / "BROADCAST"
    for search_dir in [broadcast_dir] + list((SYNTAX_ROOT / "ARCHIVE").glob("*/*") if (SYNTAX_ROOT / "ARCHIVE").exists() else []):
        if not search_dir.exists():
            continue
        for mf in search_dir.glob("msg_*.json"):
            msg = safe_json_load(mf)
            if msg and msg.get("id") == msg_id:
                msg["status"] = status
                if extra:
                    msg.update(extra)
                mf.write_text(json.dumps(msg, indent=2))
                return

@app.post("/api/syntax/register")
async def agent_register(request: Request):
    """Register a new agent — generates M2M credentials, manifest, and file-bus structure.
    
    Accepts JWT (admin) OR open registration (no auth = community agent).
    Body: { "name": "agent-name", "role": "worker", "scopes": [...], "mode": "on-demand", "capabilities": [...] }
    Returns: agent_id, client_secret, webhook_url, full credentials block.
    """
    client_ip = request.client.host if request.client else "unknown"
    if register_rate_limited(client_ip):
        return JSONResponse({"error": "rate_limited", "detail": "Max 5 registrations/hour per IP"}, status_code=429)

    body = await request.json()
    agent_name = (body.get("name") or "").lower().replace(" ", "-").strip()
    if not agent_name:
        return JSONResponse({"error": "name required"}, status_code=400)
    if not re.match(r'^[a-z][a-z0-9_-]*$', agent_name):
        return JSONResponse({"error": "Invalid agent name: use lowercase, hyphens, underscores"}, status_code=400)

    # Check if already registered
    existing_secret = SYNTAX_SECRETS_DIR / f"{agent_name}.json"
    if existing_secret.exists():
        data = safe_json_load(existing_secret)
        return JSONResponse({
            "status": "already_registered",
            "agent_name": agent_name,
            "agent_id": data.get("agent_id", ""),
            "webhook_url": "https://webhook.soulinpsy.info/ngc-relay",
            "message": "Agent already registered. Use existing credentials."
        })

    role = body.get("role", "worker")
    scopes = body.get("scopes", ["syntax:read", "syntax:write"])
    mode = body.get("mode", "on-demand")
    capabilities = body.get("capabilities", [])
    display_name = (body.get("display_name") or agent_name).strip()

    # Generate credentials
    agent_id = _gen_agent_id(agent_name)
    client_secret = _secrets.token_urlsafe(64)

    # --- Secrets file (never exposed after creation) ---
    SYNTAX_SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    secrets_data = {
        "agent_name": agent_name,
        "agent_id": agent_id,
        "client_secret": client_secret,
        "created_at": now_iso(),
        "auth0": {
            "client_id": agent_id,
            "client_secret": client_secret,
            "audience": AUTH0_AUDIENCE,
            "token_url": f"https://{AUTH0_DOMAIN}/oauth/token"
        },
        "scopes": scopes,
        "role": role
    }
    secret_path = SYNTAX_SECRETS_DIR / f"{agent_name}.json"
    secret_path.write_text(json.dumps(secrets_data, indent=2))
    secret_path.chmod(0o600)

    # --- Public manifest ---
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    manifest_data = {
        "agent_name": agent_name,
        "agent_id": agent_id,
        "created_at": now_iso(),
        "scopes": scopes,
        "role": role,
        "mode": mode,
        "capabilities": capabilities,
        "display_name": display_name,
        "public_key_hash": hashlib.sha256(client_secret.encode()).hexdigest()[:16],
        "contact": {
            "inbox": f"SYNTAX_CHANNEL/{agent_name.upper().replace('-', '_')}/",
            "broadcast_read": True,
        },
        "depends_on": body.get("depends_on", []),
        "provides": body.get("provides", []),
        "notification_url": body.get("notification_url", ""),
    }
    manifest_path = AUTH_DIR / f"{agent_name}.manifest.json"
    manifest_path.write_text(json.dumps(manifest_data, indent=2))

    # --- File-bus structure ---
    agent_dir = SYNTAX_ROOT / agent_name.upper().replace("-", "_")
    agent_dir.mkdir(parents=True, exist_ok=True)

    # SHA256 chain
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    chain_file = MANIFEST_DIR / f"{agent_name}.sha256chain"
    chain_file.write_text(f"# {agent_name} sha256chain — initialized {now_iso()}\n")

    # Broadcast cursor
    BROADCAST_DIR.mkdir(parents=True, exist_ok=True)
    cursor_file = BROADCAST_DIR / f"cursor.{agent_name}"
    cursor_file.write_text("0")

    # Archive directory
    (SYNTAX_ROOT / "ARCHIVE" / agent_name).mkdir(parents=True, exist_ok=True)

    return JSONResponse({
        "status": "registered",
        "agent_name": agent_name,
        "agent_id": agent_id,
        "role": role,
        "mode": mode,
        "scopes": scopes,
        "capabilities": capabilities,
        "display_name": display_name,
        "inbox": str(agent_dir),
        "manifest": str(manifest_path),
        "webhook_url": "https://webhook.soulinpsy.info/ngc-relay",
        "credentials": {
            "client_id": agent_id,
            "client_secret": client_secret,
            "token_url": f"https://{AUTH0_DOMAIN}/oauth/token",
            "audience": AUTH0_AUDIENCE,
            "grant_type": "client_credentials",
        },
        "chain": {
            "file": str(chain_file),
            "cursor": str(cursor_file),
        }
    }, status_code=201)

from fastapi.responses import FileResponse, HTMLResponse

# Serve React SPA build — real files (JS/CSS/icons/manifests) served as-is,
# any other path (client-side React Router routes like /audit, /agents) falls
# back to index.html so a direct load or page refresh doesn't 404. This must
# stay the LAST route registered — every API route above takes precedence.
REACT_BUILD = Path("/home/sipa/apps/sipa-syntax-ui/dist")

# This whole domain is Syntaxit — one identity, always manifest.json, no
# per-route switching (the separate human Community product lives at
# community.sipa-os.org, a different codebase entirely). no-cache headers on
# the HTML and manifest so neither the browser nor Google's Android WebAPK
# minting service can serve a stale identity after a deploy.
_INDEX_HTML = (REACT_BUILD / "index.html").read_text() if (REACT_BUILD / "index.html").exists() else None
_NO_CACHE_HEADERS = {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}

if REACT_BUILD.exists():
    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        candidate = REACT_BUILD / full_path
        if candidate.is_file() and full_path != "index.html":
            headers = _NO_CACHE_HEADERS if full_path.endswith(("manifest.json", "manifest-community.json")) else None
            return FileResponse(candidate, headers=headers)
        return HTMLResponse(_INDEX_HTML, headers=_NO_CACHE_HEADERS)

# ─── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # workers=4: all persistent state here is on-disk (SYNTAX_CHANNEL files), not
    # in-process memory, so multiple worker processes reading/writing the same
    # files is safe — this exists specifically to stop one blocking synchronous
    # file operation (Path.glob/write_text/read_text inside async def handlers)
    # from starving every other concurrent request on a single event loop.
    # Requires import-string form ("api:app") so uvicorn can fork/re-import per worker.
    uvicorn.run("api:app", host="127.0.0.1", port=5004, log_level="info", workers=4)
