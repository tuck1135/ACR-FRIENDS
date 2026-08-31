"""
Friend presence websocket service — deploy this SEPARATELY, on Render (or
wherever you end up), NOT on PythonAnywhere. PythonAnywhere's free tier
has no websocket support at all, which is the entire reason this exists
as its own thing.

What this does and doesn't own:
- Owns ONLY the real-time layer: who's currently connected right now, and
  pushing live presence/notification events to the right people.
- Owns NOTHING persistent. Your main backend (PythonAnywhere) stays the
  one source of truth for friends lists, tokens, bans — everything that
  needs to survive a restart. This service calls back to it over HTTP
  whenever it needs that kind of data, and forgets everything the moment
  it restarts (which Render's free tier will do on every idle spin-down).

Protocol notes (this part matters — get it wrong and the real client just
silently ignores every message):
- Nakama's Unity SDK only acts on a small allowlist of top-level envelope
  keys — status_presence_event, notifications, match_presence_event, etc.
  A made-up shape like {"event": "presence", ...} is parsed and discarded
  without any error, confirmed directly from a friend's own real,
  previously-broken version of this exact thing. Every message below uses
  the real envelope shapes.
- Token verification here is BYTE-EXACT to the main backend's own
  make_token/decode_verified_token, confirmed by decoding one of your
  actual real, captured tokens with this exact code. TOKEN_SECRET below
  MUST be set to the identical value your main backend uses, or every
  verification will fail.
- Deliberately does NOT re-check ban status here (that would mean a
  network call back to the main backend on every single connection).
  Worst case a banned account's still-valid token can see presence
  events through this service alone — it can't do anything
  state-changing through it, since this only ever pushes read-only
  presence/notification pushes.
"""
import os
import json
import time
import uuid
import hmac
import hashlib
import base64
import threading
import requests
from flask import Flask, request, jsonify
from flask_sock import Sock

app = Flask(__name__)
sock = Sock(app)

# MUST match the main backend's TOKEN_SECRET exactly — HMAC verification is
# stateless, so this works correctly with no network call, as long as this
# value is identical on both sides.
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "ukBVC2MsENIX8XY7fE3dHpSI1Hq9CHI5PXjqk2OmCeM")

# Your real PythonAnywhere backend — this service calls back here for the
# one piece of persistent data it needs (a connecting player's friends list).
MAIN_BACKEND_URL = os.environ.get("MAIN_BACKEND_URL", "https://tuck1135.pythonanywhere.com")

# Protects POST /internal/notify — only the main backend, which is given
# this same value, can trigger a push to a connected user. Without this,
# anyone who found this service's URL could fake a notification to anyone.
INTERNAL_NOTIFY_SECRET = os.environ.get("INTERNAL_NOTIFY_SECRET", "SuZijRyEfDVaBe7Hwj2gv2M1IUkd4n8k3nkmaNQaKgI")

_UID_NAMESPACE = uuid.UUID("7cdc1fa7-5d90-4575-a6a3-47f0748da898")


def generate_deterministic_uid(username):
    """MUST match the main backend's own generate_deterministic_uid exactly
    — same namespace UUID, same normalization — so a uid computed here
    always agrees with the uid the main backend computed for that same
    username."""
    uname_norm = str(username or "").lower().strip()
    return str(uuid.uuid5(_UID_NAMESPACE, uname_norm))


def decode_verified_token(raw_token):
    """Byte-exact port of the main backend's own decode_verified_token —
    verified directly against one of your real, captured tokens before
    this was written. Does not re-check ban status (see module docstring)."""
    if not raw_token:
        return None
    parts = raw_token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature = parts
    msg = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(TOKEN_SECRET.encode(), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)).decode())
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("exp", 0) < time.time():
        return None
    return payload


# ── In-memory connection + follow state — none of this is persistent ──────
_lock = threading.Lock()
_online_users = {}       # uid -> ws connection
_status_following = {}   # uid -> set of uids whose presence this uid wants pushed to it
_status_followers = {}   # uid -> set of uids following THIS uid's presence


def _user_presence_obj(uid, username):
    """Real Nakama UserPresence shape — matches what a friend's own working
    version of this sends."""
    return {
        "persistence": False,
        "session_id": uid,
        "status": "",
        "username": username or "",
        "user_id": uid,
    }


def _send_status_presence(to_uid, joins=None, leaves=None):
    """Real status_presence_event envelope — the one shape confirmed (from
    a friend's own working implementation) to actually get parsed by the
    real client's Socket.cs, rather than silently discarded."""
    ws = _online_users.get(to_uid)
    if not ws:
        return
    envelope = {
        "status_presence_event": {
            "joins": [_user_presence_obj(u, n) for u, n in (joins or [])],
            "leaves": [_user_presence_obj(u, n) for u, n in (leaves or [])],
        }
    }
    try:
        ws.send(json.dumps(envelope))
    except Exception:
        with _lock:
            _online_users.pop(to_uid, None)


def _push_notification_envelope(to_uid, code, sender_uid, subject, content="{}"):
    """Real notifications envelope shape — same reasoning as above."""
    ws = _online_users.get(to_uid)
    if not ws:
        return False
    try:
        envelope = {
            "notifications": {
                "notifications": [{
                    "id": str(uuid.uuid4()),
                    "subject": subject,
                    "content": content,
                    "code": code,
                    "sender_id": sender_uid,
                    "persistent": False,
                    "create_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }]
            }
        }
        ws.send(json.dumps(envelope))
        return True
    except Exception:
        with _lock:
            _online_users.pop(to_uid, None)
        return False


def _fetch_friend_uids(token):
    """Calls back to the main backend's own GET /v2/friend to get this
    user's actual friends list — this service has no persistent data of
    its own. Returns [(uid, username), ...] for accepted friends only
    (state 0), not pending requests."""
    try:
        resp = requests.get(
            f"{MAIN_BACKEND_URL}/v2/friend",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        out = []
        for entry in data.get("friends", []):
            if entry.get("state") == 0:
                u = entry.get("user", {})
                if u.get("id"):
                    out.append((u["id"], u.get("username", "")))
        return out
    except Exception:
        return []


def _broadcast_presence(uid, username, online):
    """Tell everyone following this uid (explicitly, or implicitly via
    being friends) that their online state changed."""
    targets = set(_status_followers.get(uid, set()))
    for fid in targets:
        if fid == uid:
            continue
        if online:
            _send_status_presence(fid, joins=[(uid, username)])
        else:
            _send_status_presence(fid, leaves=[(uid, username)])


@sock.route("/ws")
def ws_handler(ws):
    token = request.args.get("token", "")
    payload = decode_verified_token(token)
    if not payload:
        ws.close()
        return
    usn = payload.get("usn", "")
    uid = generate_deterministic_uid(usn) if usn else payload.get("uid", "")
    if not uid:
        ws.close()
        return

    with _lock:
        _online_users[uid] = ws

    # Auto-follow friends (matches how the reference treats friendship as
    # an implicit mutual follow, even without an explicit status_follow
    # message from the client) and push back who's already online.
    friend_uids = []
    try:
        friends = _fetch_friend_uids(token)
        friend_uids = [fid for fid, _ in friends]
        online_now = [(fid, fname) for fid, fname in friends if fid in _online_users]
        with _lock:
            _status_following.setdefault(uid, set()).update(friend_uids)
            for fid in friend_uids:
                _status_followers.setdefault(fid, set()).add(uid)
        if online_now:
            _send_status_presence(uid, joins=online_now)
    except Exception:
        pass

    _broadcast_presence(uid, usn, online=True)

    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            try:
                data = json.loads(msg)
            except Exception:
                continue
            if "status_follow" in data and isinstance(data["status_follow"], dict):
                follow_ids = list(data["status_follow"].get("user_ids") or [])
                follow_ids = [x for x in follow_ids if x and x != uid]
                online_now = []
                with _lock:
                    my_set = _status_following.setdefault(uid, set())
                    for tid in follow_ids:
                        my_set.add(tid)
                        _status_followers.setdefault(tid, set()).add(uid)
                        if tid in _online_users:
                            online_now.append((tid, ""))
                if online_now:
                    _send_status_presence(uid, joins=online_now)
            elif "status_unfollow" in data and isinstance(data["status_unfollow"], dict):
                unsub_ids = list(data["status_unfollow"].get("user_ids") or [])
                with _lock:
                    my_set = _status_following.get(uid, set())
                    for tid in unsub_ids:
                        my_set.discard(tid)
                        _status_followers.get(tid, set()).discard(uid)
    except Exception:
        pass
    finally:
        with _lock:
            if _online_users.get(uid) is ws:
                _online_users.pop(uid, None)
            for fid in list(_status_following.get(uid, set())):
                _status_followers.get(fid, set()).discard(uid)
            _status_following.pop(uid, None)
        _broadcast_presence(uid, usn, online=False)


@app.route("/internal/notify", methods=["POST"])
def internal_notify():
    """Called BY the main backend (never by a game client) when something
    happens that a connected player should hear about right now — a new
    friend request, an accepted one. Silently does nothing if that player
    isn't currently connected; the main backend already saved the real
    state regardless, so there's nothing to lose by a missed push."""
    if not hmac.compare_digest(request.headers.get("X-Internal-Secret", ""), INTERNAL_NOTIFY_SECRET):
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    target_uid = data.get("uid", "")
    code = data.get("code", 0)
    sender_uid = data.get("sender_uid", "")
    subject = data.get("subject", "")
    content = data.get("content", "{}")
    delivered = _push_notification_envelope(target_uid, code, sender_uid, subject, content)
    return jsonify({"delivered": delivered}), 200


@app.route("/internal/online-count", methods=["GET"])
def internal_online_count():
    """Simple health/debug check — how many sockets this instance currently
    has open. Not secret-protected since it reveals nothing sensitive."""
    with _lock:
        return jsonify({"online": len(_online_users)}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
