#!/usr/bin/env python3
"""
Session manager for bounty-hunter-toolkit.
Manages engagement state for save/resume across Claude Code sessions.
"""

import json
import os
import sys
import time

HOME = os.path.expanduser("~")
SESSIONS_DIR = os.path.join(HOME, ".bounty-hunter-data", "sessions")


def create_session(target, output_dir, scope_json=None):
    """Create a new hunting session."""
    session_id = f"hunt-{target}-{time.strftime('%Y%m%d-%H%M%S')}"
    session = {
        "id": session_id,
        "target": target,
        "output_dir": output_dir,
        "scope_json": scope_json,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "active",
        "current_phase": "scope_parsing",
        "phases_completed": [],
        "findings_count": 0,
        "reports_generated": 0,
        "notes": ""
    }
    save_session(session)
    print(f"Session created: {session_id}")
    return session


def save_session(session):
    """Save session state to disk."""
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    filepath = os.path.join(SESSIONS_DIR, f"{session['id']}.json")
    session["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(filepath, "w") as f:
        json.dump(session, f, indent=2)
    # Also save to the engagement directory
    if session.get("output_dir"):
        session_copy = os.path.join(session["output_dir"], "session.json")
        os.makedirs(os.path.dirname(session_copy) or ".", exist_ok=True)
        with open(session_copy, "w") as f:
            json.dump(session, f, indent=2)


def load_session(session_id):
    """Load a session by ID."""
    filepath = os.path.join(SESSIONS_DIR, f"{session_id}.json")
    if not os.path.isfile(filepath):
        # Try partial match
        for fname in os.listdir(SESSIONS_DIR):
            if session_id in fname:
                filepath = os.path.join(SESSIONS_DIR, fname)
                break
    if not os.path.isfile(filepath):
        print(f"Session not found: {session_id}", file=sys.stderr)
        return None
    with open(filepath) as f:
        return json.load(f)


def list_sessions():
    """List all sessions."""
    if not os.path.isdir(SESSIONS_DIR):
        print("No sessions found.")
        return []
    sessions = []
    for fname in sorted(os.listdir(SESSIONS_DIR)):
        if fname.endswith(".json"):
            filepath = os.path.join(SESSIONS_DIR, fname)
            with open(filepath) as f:
                session = json.load(f)
            sessions.append(session)
            status = session.get("status", "unknown")
            target = session.get("target", "unknown")
            phase = session.get("current_phase", "unknown")
            findings = session.get("findings_count", 0)
            created = session.get("created", "")[:10]
            print(f"  [{status}] {session['id']} | target={target} | phase={phase} | findings={findings} | {created}")
    if not sessions:
        print("  No sessions found.")
    return sessions


def update_phase(session_id, phase, completed=False):
    """Update the current phase of a session."""
    session = load_session(session_id)
    if not session:
        return None
    if completed and phase not in session["phases_completed"]:
        session["phases_completed"].append(phase)
    session["current_phase"] = phase
    save_session(session)
    return session


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  session_manager.py create <target> <output_dir> [scope.json]")
        print("  session_manager.py load <session_id>")
        print("  session_manager.py list")
        print("  session_manager.py update <session_id> <phase> [--completed]")
        sys.exit(1)

    action = sys.argv[1]

    if action == "create":
        target = sys.argv[2] if len(sys.argv) > 2 else "unknown"
        output_dir = sys.argv[3] if len(sys.argv) > 3 else "."
        scope = sys.argv[4] if len(sys.argv) > 4 else None
        session = create_session(target, output_dir, scope)
        print(json.dumps(session, indent=2))

    elif action == "load":
        session_id = sys.argv[2] if len(sys.argv) > 2 else ""
        session = load_session(session_id)
        if session:
            print(json.dumps(session, indent=2))

    elif action == "list":
        list_sessions()

    elif action == "update":
        session_id = sys.argv[2] if len(sys.argv) > 2 else ""
        phase = sys.argv[3] if len(sys.argv) > 3 else ""
        completed = "--completed" in sys.argv
        session = update_phase(session_id, phase, completed)
        if session:
            print(f"Updated: phase={phase}, completed={completed}")

    else:
        print(f"Unknown action: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()
