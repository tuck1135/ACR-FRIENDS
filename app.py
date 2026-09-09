import random
import os
import hmac
import hashlib
import re
import base64
import uuid
import time
import json
import secrets
import string
import threading
import requests
from flask import Flask, jsonify, request, session, redirect
from flask_sockets import Sockets
from gevent import pywsgi
from geventwebsocket.handler import WebSocketHandler
from datetime import datetime, timezone
import ssl
localusername = ""
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dih3 = os.path.join(BASE_DIR, "wowie", "R.A.M")
dih2 = os.path.join(BASE_DIR, "wowie", "R.A.M")
ApiKey = ""

# The current server key is now admin-editable (see /admin/<token>/server-key)
# instead of a hardcoded constant — rotating it no longer needs a code
# change. Falls back to the existing, already-deployed value the very
# first time this runs, so nothing breaks for anyone already using it.
#
# Deliberately reads the file fresh on every single call instead of
# caching in memory. If PythonAnywhere runs this app across more than one
# worker process, each keeps its own separate memory — a cached value
# here means whichever worker didn't happen to handle the admin-panel
# rotation click would keep silently checking logins against the old,
# stale key indefinitely. That's exactly the kind of bug that's easy to
# ship without noticing and genuinely locks people out. Reading a tiny
# JSON file on every request has no meaningful cost, and it makes this
# completely immune to that class of bug regardless of how many workers
# are actually running.
SERVER_KEY_FILE = os.path.join(BASE_DIR, "server_key_config.json")
_DEFAULT_SERVER_KEY = "Basic WllpaVJNOGh1T2htRTR4cjo="

def load_server_key():
    try:
        if os.path.exists(SERVER_KEY_FILE):
            with open(SERVER_KEY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                key = data.get("server_key") if isinstance(data, dict) else None
                if key:
                    return key
    except Exception as e:
        write_log(f"[server key] load error: {e}")
    return _DEFAULT_SERVER_KEY

def save_server_key(new_key):
    try:
        with open(SERVER_KEY_FILE, "w", encoding="utf-8") as f:
            json.dump({"server_key": new_key}, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[server key] save error: {e}")
        return False

# The original, pre-patch key — not accepted from everyone, only from
# specific usernames on OLD_KEY_USERS below.
ORIGINAL_SERVER_KEY = "Basic NlVSdVRTbERLS2ZZYnVEVzo="

nichepeople = ["skibb.ok", "exploding_car"]
app: Flask = Flask(__name__)
LOG_FILE = os.path.join(BASE_DIR, "request_log.txt")

def write_log(line):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(str(line) + "\n")
    except Exception:
        pass
LOG_FILE = os.path.join(BASE_DIR, "request_log.txt")

def write_log(line):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

@app.before_request
def debug_log_request():
    _track_presence()
    write_log(f"REQ {request.method} {request.path}")
    if request.path == "/v2/storage":
        try:
            write_log(f"STORAGE JSON: {request.get_json(silent=True)}")
            write_log(f"STORAGE RAW: {request.data.decode(errors='ignore')}")
        except Exception as e:
            write_log(f"STORAGE LOG ERROR: {e}")

@app.after_request
def debug_log_response(response):
    write_log(f"RES {request.method} {request.path} -> {response.status_code}")
    return response
# Needed for the admin password login below — Flask signs the session
# cookie with this. Same rules as your other secrets: private, don't post
# it anywhere public.
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", "DJGi6PLGg-AfbYJK-PwwtCv_ZSlRc4F5hL4hP2_JvbQ")
#sockets = Sockets(app)
sockets = Sockets(app)

def b64decode_json(obj):
    return json.loads(base64.urlsafe_b64decode(obj + '=' * (-len(obj) % 4)).decode())

def b64encode_json(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')

# --- real token signing ------------------------------------------------------
# Tokens used to end with a random signature that was never actually checked
# against anything — meaning anyone could hand-craft a "header.payload.junk"
# string with any username in it and every endpoint would trust it. This
# secret is what makes a signature impossible to forge without it: only
# tokens minted by THIS server (BearerGeneration / SessionRefresh / the
# refresh route) will verify. CHANGE THIS to your own long random string
# before relying on it — anyone who has this exact value can still forge
# tokens, same idea as ADMIN_PANEL_TOKEN below.
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "ukBVC2MsENIX8XY7fE3dHpSI1Hq9CHI5PXjqk2OmCeM")

def _sign_token_parts(header_b64, payload_b64):
    msg = f"{header_b64}.{payload_b64}".encode()
    return hmac.new(TOKEN_SECRET.encode(), msg, hashlib.sha256).hexdigest()

def make_token(payload):
    """Mints a signed token for this payload. Use this instead of hand-building
    header.payload.signature strings."""
    header = {'alg': 'HS256', 'typ': 'JWT'}
    header_b64 = b64encode_json(header)
    payload_b64 = b64encode_json(payload)
    signature = _sign_token_parts(header_b64, payload_b64)
    return f"{header_b64}.{payload_b64}.{signature}"

def decode_verified_token(raw_token):
    """Returns the token's payload dict if its signature is valid, else None.
    This is what actually stops a stolen/repackaged client (or someone just
    poking the API with curl) from impersonating a player — without
    TOKEN_SECRET they can't produce a signature that matches, so any token
    they invent by hand is rejected here before any endpoint sees a username."""
    if not raw_token:
        return None
    parts = raw_token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature = parts
    expected = _sign_token_parts(header_b64, payload_b64)
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = b64decode_json(payload_b64)
    except Exception:
        return None
    # A banned player's ALREADY-ISSUED tokens stop working immediately, not
    # just their next login attempt — checked centrally here so it applies
    # everywhere this function is used, not just the login endpoint.
    if isinstance(payload, dict) and _ban_reason(payload.get("usn")) is not None:
        return None
    return payload

# username (lowercased) -> ban reason. Checked above (blocks already-issued
# tokens immediately) and at login (shows the reason as an in-game error).
BANS_FILE = os.path.join(BASE_DIR, "bans.json")
_bans_cache = None

def _load_bans():
    global _bans_cache
    if _bans_cache is None:
        try:
            if os.path.exists(BANS_FILE):
                with open(BANS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _bans_cache = data if isinstance(data, dict) else {}
            else:
                _bans_cache = {}
        except Exception as e:
            write_log(f"[bans] load error: {e}")
            _bans_cache = {}
    return _bans_cache

def _save_bans(bans):
    global _bans_cache
    _bans_cache = bans
    try:
        with open(BANS_FILE, "w", encoding="utf-8") as f:
            json.dump(bans, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[bans] save error: {e}")
        return False

def _ban_reason(username):
    """The ban reason string if this username is banned, else None."""
    return _load_bans().get(str(username or "").strip().lower())

# ── Daily missions ─────────────────────────────────────────────────────────
# Ported from a reference backend. Two things are confirmed reliable there:
# the exact wire shape for missions.json entries, and the delivery mechanism
# (fetched via the SAME generic /v2/storage object_ids POST every other
# collection already uses, from a collection called "econ_daily_missions" —
# no user_id needed, the server derives the player from the auth token).
# The RPC route names (dailyMissions.getData etc.) are NOT confirmed — the
# reference author's own comment says the exact strings aren't knowable from
# the client dump and are their best guess. Ported anyway since they're
# harmless if unused, with real Discord visibility added if the client calls
# something else entirely (see the catch-all RPC route below).
MISSIONS_FILE = os.path.join(BASE_DIR, "missions.json")
MISSIONS_SEED_MIGRATION_MARKER = os.path.join(BASE_DIR, "missions_seed_migrated.json")
MISSION_PROGRESS_FILE = os.path.join(BASE_DIR, "mission_progress.json")
_missions_cache = None
_mission_progress_cache = None

# Full ApiDailyMissionTaskType enum, from a friend's dump.cs research — args
# conventions are explicitly unverified beyond the general shape, but the
# enum values themselves are real (not guessed). Shown as dropdown options
# in the mission editor so args can be filled in correctly without needing
# to remember this table.
TASK_TYPES = [
    ("None", "No task — probably unused for real missions.", "[]"),
    ("DailyReward", "Just open the terminal / log in.", "[]"),
    ("SellItem", "Sell N items.", '["<count>"]'),
    ("BatchSellItemsTotallingX", "Sell items worth a total of X currency in one batch.", '["<totalValue>"]'),
    ("KillMonsterXTimes", "Kill a specific monster N times.", '["<monsterID>", "<count>"]'),
    ("KillMonsters", "Kill any N monsters.", '["<count>"]'),
    ("KillMonster", "Kill one specific monster (once).", '["<monsterID>"]'),
    ("KillMonsterWithItem", "Kill a monster using a specific item/weapon.", '["<monsterID>", "<itemID>"]'),
    ("KillMonsterWithItemInArea", "Same, restricted to an area.", '["<monsterID>", "<itemID>", "<area>"]'),
    ("KillMonsterInArea", "Kill a monster within a specific area.", '["<monsterID>", "<area>"]'),
    ("KillXMonstersWithoutDying", "Kill N monsters in one life.", '["<count>"]'),
    ("SpendSoftCurrency", "Spend N soft currency (nuts).", '["<amount>"]'),
    ("FindItem", "Find/pick up a specific item.", '["<itemID>"]'),
    ("ExploreArea", 'Visit an area (known: "Foundation", "DarkForest").', '["<areaName>"]'),
    ("TakeTeleporterInArea", "Use a teleporter in a specific area.", '["<area>"]'),
    ("TakeTeleporterXTimes", "Use any teleporter N times.", '["<count>"]'),
    ("UseItem", "Use any item N times.", '["<count>"]'),
    ("UseItemInArea", "Use an item within a specific area.", '["<itemID>", "<area>"]'),
    ("RecoverBackpackFromArea", "Recover a lost backpack from an area.", '["<area>"]'),
    ("MakeAFriend", "Add a friend.", "[]"),
    ("FlyForXSeconds", "Fly (jetpack/etc) for N seconds cumulative.", '["<seconds>"]'),
    ("TakePhotoOfMonsters", "Photograph monsters (photohook feature).", '["<count>"]'),
    ("ChangeAppearance", "Change avatar appearance.", "[]"),
]

DEFAULT_MISSIONS_SEED = [
    {
        "id": "daily_mission_login",
        "name": "Daily Check-In",
        "description": "Log in and claim your daily reward.",
        "taskType": "DailyReward",
        "rewardHard": 100,
        "rewardResearchPoints": 5,
        "dailyReset": True,
        "args": [],
    },
]

# Confirmed real missions currently live on a friend's working backend
# (pulled directly from their server logs, not guessed) — added here as a
# migration below so anyone who already has a missions.json gets these too,
# not just fresh installs.
_CONFIRMED_REAL_MISSIONS = [
    {
        "id": "daily_mission_appearance",
        "name": "the appearance one",
        "description": "Change your avatar appearance.",
        "taskType": "ChangeAppearance",
        "rewardHard": 100,
        "rewardResearchPoints": 5,
        "dailyReset": True,
        "args": [],
    },
    {
        "id": "daily_mission_teleporter_cave",
        "name": "Not a trap probably",
        "description": "Use the teleporter in mimic caves.",
        "taskType": "TakeTeleporterInArea",
        "rewardHard": 100,
        "rewardResearchPoints": 5,
        "dailyReset": True,
        "args": ["mimic caves"],
    },
    {
        "id": "daily_mission_recover_backpack_sewer",
        "name": "Dumpster diving",
        "description": "Recover a lost backpack from sewers.",
        "taskType": "RecoverBackpackFromArea",
        "rewardHard": 100,
        "rewardResearchPoints": 5,
        "dailyReset": True,
        "args": ["sewers"],
    },
]

def load_missions():
    global _missions_cache
    if _missions_cache is None:
        try:
            if os.path.exists(MISSIONS_FILE):
                with open(MISSIONS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _missions_cache = data if isinstance(data, list) else []
            else:
                _missions_cache = list(DEFAULT_MISSIONS_SEED)
        except Exception as e:
            write_log(f"[missions] load error: {e}")
            _missions_cache = list(DEFAULT_MISSIONS_SEED)

        # Self-healing migration: taskType "login" was this backend's own
        # placeholder before the real enum was known — it was replaced with
        # the confirmed-real "DailyReward" in code, but anything already
        # persisted to missions.json before that change never got updated,
        # since load_missions() only applies the code's default when the
        # file doesn't exist yet. Silently upgrading any stragglers here so
        # this can't cause the same "auto-complete stopped matching" bug
        # again for anyone who saved a mission before this fix landed.
        _migrated = False
        for _m in _missions_cache:
            if isinstance(_m, dict) and _m.get("taskType") == "login":
                _m["taskType"] = "DailyReward"
                _migrated = True

        # Adds the confirmed-real missions above if missing — but only the
        # FIRST time this ever runs after being deployed, tracked via a
        # small marker file. Confirmed real bug without that marker: this
        # ran on every single load_missions() call with no memory of
        # having already run, so deliberately deleting one of these via
        # the admin page had it silently reappear on the very next
        # request that needed mission data — making these three
        # effectively undeletable. The one-time intent (quoted in the
        # comment below) was real; the missing "have I already done this"
        # check was the bug.
        if not os.path.exists(MISSIONS_SEED_MIGRATION_MARKER):
            _existing_ids = {_m.get("id") for _m in _missions_cache if isinstance(_m, dict)}
            for _cm in _CONFIRMED_REAL_MISSIONS:
                if _cm["id"] not in _existing_ids:
                    _missions_cache.append(dict(_cm))
                    _migrated = True
            try:
                with open(MISSIONS_SEED_MIGRATION_MARKER, "w", encoding="utf-8") as f:
                    json.dump({"done": True}, f)
            except Exception as e:
                write_log(f"[missions] marker write error: {e}")

        if _migrated:
            write_log("[missions] migrated missions.json (taskType fix and/or confirmed-real missions added)")
            save_missions(_missions_cache)
    return _missions_cache

def save_missions(missions):
    global _missions_cache
    _missions_cache = missions
    try:
        with open(MISSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(missions, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[missions] save error: {e}")
        return False

def load_mission_progress():
    global _mission_progress_cache
    if _mission_progress_cache is None:
        try:
            if os.path.exists(MISSION_PROGRESS_FILE):
                with open(MISSION_PROGRESS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _mission_progress_cache = data if isinstance(data, dict) else {}
            else:
                _mission_progress_cache = {}
        except Exception as e:
            write_log(f"[missions] progress load error: {e}")
            _mission_progress_cache = {}
    return _mission_progress_cache

def save_mission_progress(progress):
    global _mission_progress_cache
    _mission_progress_cache = progress
    try:
        with open(MISSION_PROGRESS_FILE, "w", encoding="utf-8") as f:
            json.dump(progress, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[missions] progress save error: {e}")
        return False

def _mission_def_by_id(mission_id):
    for m in load_missions():
        if isinstance(m, dict) and m.get("id") == mission_id:
            return m
    return {}

def _today_utc_key():
    return time.strftime("%Y-%m-%d", time.gmtime())

def _apply_daily_reset(mp, mission, today):
    """If mission has dailyReset:true and the player's lastClaimDate isn't
    today UTC, wipe collected/completed so it can be claimed again. Returns
    True when reset happened (caller should persist)."""
    if not mp.get("completed") and not mp.get("collected"):
        return False
    if not (isinstance(mission, dict) and mission.get("dailyReset")):
        return False
    if mp.get("lastClaimDate") == today:
        return False
    mp["completed"] = False
    mp["collected"] = False
    return True

def _user_mission_progress(uid, mission_id):
    today = _today_utc_key()
    mission = _mission_def_by_id(mission_id)
    progress = load_mission_progress()
    user_progress = progress.get(uid) if isinstance(progress.get(uid), dict) else {}
    mp = user_progress.get(mission_id) if isinstance(user_progress, dict) else None
    if not isinstance(mp, dict):
        mp = {"id": mission_id, "progress": "", "completed": False, "collected": False}
    if _apply_daily_reset(mp, mission, today):
        if not isinstance(user_progress, dict):
            user_progress = {}
        user_progress[mission_id] = mp
        progress[uid] = user_progress
        save_mission_progress(progress)
    return {
        "id": mission_id,
        "progress": str(mp.get("progress", "") or ""),
        "completed": bool(mp.get("completed", False)),
        "collected": bool(mp.get("collected", False)),
    }

def _persist_user_mission(uid, mission_id, updates):
    progress = load_mission_progress()
    user_progress = progress.setdefault(uid, {})
    if not isinstance(user_progress, dict):
        user_progress = {}
        progress[uid] = user_progress
    mp = user_progress.setdefault(mission_id, {"id": mission_id, "progress": "", "completed": False, "collected": False})
    if not isinstance(mp, dict):
        mp = {"id": mission_id, "progress": "", "completed": False, "collected": False}
        user_progress[mission_id] = mp
    mp.update(updates)
    mp["id"] = mission_id
    # lastClaimDate is what _apply_daily_reset checks to know "already
    # handled today, don't wipe it yet" — without setting it here, a
    # dailyReset:true mission gets reset back to incomplete on the very
    # next progress check, same day, before it can ever be collected.
    if updates.get("completed"):
        mp["lastClaimDate"] = _today_utc_key()
    save_mission_progress(progress)
    return mp

# The daily check-in is pinned to always lead the schedule; the rest rotate
# in fixed-size chunks that advance one chunk per UTC day (matching exactly
# when the client's countdown hits zero) and wrap at the end.
DAILY_MISSION_SLOTS = int(os.environ.get("DAILY_MISSION_SLOTS", "3"))
DAILY_MISSION_PINNED = os.environ.get("DAILY_MISSION_PINNED", "daily_mission_login")

def _daily_mission_schedule_ids(day_number):
    ids = [m.get("id") for m in load_missions() if isinstance(m, dict) and m.get("id")]
    pinned = [i for i in ids if i == DAILY_MISSION_PINNED]
    rest = [i for i in ids if i not in pinned]
    slots = max(1, DAILY_MISSION_SLOTS)
    if len(rest) <= slots:
        return pinned + rest
    num_chunks = (len(rest) + slots - 1) // slots
    g = day_number % num_chunks
    return pinned + rest[g * slots:(g + 1) * slots]

# ── Scavenger hunts ─────────────────────────────────────────────────────────
# Ported after a REAL confirmed RPC call (scavengerHunt.progress) showed up
# in the catch-all logger — the reference's own route registration for this
# exact name matches it, and its hunt config confirmed "v1.1"/"v1.2"-style
# IDs are real, version-specific hunt identifiers.
SCAV_HUNTS_FILE = os.path.join(BASE_DIR, "scavenger_hunt_progress.json")
_scav_lock = threading.Lock()
_scav_cache = None

# Keyed by the scavengerHuntID the client requests (confirmed real: "v1.1").
# count = total items needed before "completed"; rewards granted on collect.
# Persisted + admin-editable now (was a hardcoded dict) — see /admin/<token>/scavhunts.
SCAV_CONFIG_FILE = os.path.join(BASE_DIR, "scav_hunt_config.json")
_scav_config_cache = None
DEFAULT_SCAV_HUNT_CONFIG = {
    "v1.1": {"count": 10, "rewardHard": 500, "rewardResearchPoints": 100},
    "v1.2": {"count": 10, "rewardHard": 500, "rewardResearchPoints": 100},
}

def load_scav_config():
    global _scav_config_cache
    if _scav_config_cache is None:
        try:
            if os.path.exists(SCAV_CONFIG_FILE):
                with open(SCAV_CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _scav_config_cache = data if isinstance(data, dict) else {}
            else:
                _scav_config_cache = dict(DEFAULT_SCAV_HUNT_CONFIG)
        except Exception as e:
            write_log(f"[scav config] load error: {e}")
            _scav_config_cache = dict(DEFAULT_SCAV_HUNT_CONFIG)
    return _scav_config_cache

def save_scav_config(config):
    global _scav_config_cache
    _scav_config_cache = config
    try:
        with open(SCAV_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[scav config] save error: {e}")
        return False

def _load_scav_progress():
    global _scav_cache
    if _scav_cache is None:
        try:
            if os.path.exists(SCAV_HUNTS_FILE):
                with open(SCAV_HUNTS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _scav_cache = data if isinstance(data, dict) else {}
            else:
                _scav_cache = {}
        except Exception as e:
            write_log(f"[scav] load error: {e}")
            _scav_cache = {}
    return _scav_cache

def _save_scav_progress(data):
    global _scav_cache
    _scav_cache = data
    try:
        with open(SCAV_HUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[scav] save error: {e}")
        return False

def _user_scav_for(uid, hunt_id):
    """Returns {itemIDs, completed, collected} for a (uid, huntID) pair."""
    all_progress = _load_scav_progress()
    user_block = all_progress.get(uid, {}) if isinstance(all_progress.get(uid), dict) else {}
    entry = user_block.get(hunt_id) if isinstance(user_block, dict) else None
    if not isinstance(entry, dict):
        entry = {}
    raw_items = entry.get("itemIDs", [])
    item_ids = [str(x) for x in raw_items if isinstance(x, (str, int))] if isinstance(raw_items, list) else []
    cfg = load_scav_config().get(hunt_id, {})
    total = int(cfg.get("count", 0) or 0)
    completed = total > 0 and len(item_ids) >= total
    return {
        "itemIDs": item_ids,
        "completed": completed,
        "collected": bool(entry.get("collected", False)),
    }

# ── Client integrity checks (package name, libraries, version anomalies) ──
# Ported from a confirmed-real mechanism found in a friend's live server logs
# (/v2/sync, internally logged as "smali") — not guessed. Alert-only by
# explicit choice: bans/blocks nothing on its own, just notifies so you can
# decide. Genuinely uncertain part, flagged honestly: the library baseline
# below is seeded from the FRIEND'S game's confirmed library list, minus
# their game-specific lib (libXeraCompany.so) — this game's own main library
# name isn't confirmed, so it will very likely show up as "unauthorized" on
# the very first real login. That's expected, not a bug — check the
# alert, confirm it's really your own game's lib, then add it via the admin
# page below so it stops alerting on every login.
EXPECTED_APP_ID = "tuck1135.animalCompanyrebirth1135"
SYNC_PROTOCOL_VERSION = 3  # confirmed real value ("pv":3) from captured traffic

DEFAULT_LIBS_FILE = os.path.join(BASE_DIR, "default_libs.json")
_default_libs_cache = None
_CONFIRMED_COMMON_LIBS = [
    "libOculusXRPlugin.so", "libcrypto.so", "libssl.so", "lib_burst_generated.so",
    "libovrplatformloader.so", "libwebrtc-audio.so", "libcurl.so", "libnanosockets.so",
    "libc++_shared.so", "libfvad.so", "libopus_egpv.so", "libil2cpp.so", "libopusenc.so",
    "libOVRPlugin.so", "libopus.so", "libunity.so", "libopenxr_loader.so", "libmain.so", "libtox.so",
]

def load_default_libs():
    global _default_libs_cache
    if _default_libs_cache is None:
        try:
            if os.path.exists(DEFAULT_LIBS_FILE):
                with open(DEFAULT_LIBS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _default_libs_cache = data if isinstance(data, list) else []
            else:
                _default_libs_cache = list(_CONFIRMED_COMMON_LIBS)
        except Exception as e:
            write_log(f"[libs] load error: {e}")
            _default_libs_cache = list(_CONFIRMED_COMMON_LIBS)
    return _default_libs_cache

def save_default_libs(libs):
    global _default_libs_cache
    _default_libs_cache = libs
    try:
        with open(DEFAULT_LIBS_FILE, "w", encoding="utf-8") as f:
            json.dump(libs, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[libs] save error: {e}")
        return False

KNOWN_VERSIONS_FILE = os.path.join(BASE_DIR, "known_client_versions.json")
_known_versions_cache = None

def _load_known_versions():
    global _known_versions_cache
    if _known_versions_cache is None:
        try:
            if os.path.exists(KNOWN_VERSIONS_FILE):
                with open(KNOWN_VERSIONS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and isinstance(data.get("seen"), list):
                        _known_versions_cache = data
                    else:
                        _known_versions_cache = {"seen": [], "max": None}
            else:
                _known_versions_cache = {"seen": [], "max": None}
        except Exception as e:
            write_log(f"[versions] load error: {e}")
            _known_versions_cache = {"seen": [], "max": None}
    return _known_versions_cache

def _save_known_versions(data):
    global _known_versions_cache
    _known_versions_cache = data
    try:
        with open(KNOWN_VERSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        write_log(f"[versions] save error: {e}")

def _check_version_anomaly(client_ua, username):
    """Alerts if this (major, minor) hasn't been seen before, and/or is
    higher than anything seen before. Updates the known-versions record
    either way. No-op if the version can't be parsed at all."""
    cv = _parse_version_tuple(client_ua) if client_ua else None
    if cv is None:
        return
    ver_str = f"{cv[0]}.{cv[1]}"
    data = _load_known_versions()
    seen = data.get("seen", [])
    prev_max = tuple(data["max"]) if data.get("max") else None

    is_new = ver_str not in seen
    is_higher = prev_max is None or cv > prev_max

    if is_new:
        seen.append(ver_str)
        data["seen"] = seen
    if is_higher:
        data["max"] = list(cv)
    if is_new or is_higher:
        _save_known_versions(data)

    if is_new and is_higher:
        log_to_package_alert_discord(
            f"🚨 **Unreleased version in use — possible unauthorized backend access**\n"
            f"👤 User: `{username}`\n"
            f"📦 Version: `{ver_str}` (raw: `{client_ua}`)\n"
            f"_(never seen before, and higher than anything you've released — worth checking if this is really you/a beta tester)_"
        )
    elif is_new:
        log_to_package_alert_discord(
            f"❔ **Unrecognized client version**\n"
            f"👤 User: `{username}`\n"
            f"📦 Version: `{ver_str}` (raw: `{client_ua}`)\n"
            f"_(first time seeing this version — not higher than the max on record)_"
        )
    elif is_higher:
        log_to_package_alert_discord(
            f"⬆️ **Client version higher than anything seen before**\n"
            f"👤 User: `{username}`\n"
            f"📦 Version: `{ver_str}` (raw: `{client_ua}`)"
        )

# Usernames allowed to connect even without the correct Serverkey header —
# see the honesty note where this is checked (afhjkfh) for what this
# actually verifies vs. what it doesn't.
BYPASS_FILE = os.path.join(BASE_DIR, "bypass_list.json")
_bypass_cache = None

def _load_bypass_list():
    global _bypass_cache
    if _bypass_cache is None:
        try:
            if os.path.exists(BYPASS_FILE):
                with open(BYPASS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _bypass_cache = data if isinstance(data, list) else []
            else:
                # Seeded with your own username so your own testing (curl,
                # browser checks, etc.) doesn't get caught by this. Remove
                # yourself from the Manage Bypass List page if you don't want this.
                _bypass_cache = ["tuck1135"]
        except Exception as e:
            write_log(f"[bypass] load error: {e}")
            _bypass_cache = []
    return _bypass_cache

def _save_bypass_list(names):
    global _bypass_cache
    _bypass_cache = names
    try:
        with open(BYPASS_FILE, "w", encoding="utf-8") as f:
            json.dump(names, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[bypass] save error: {e}")
        return False

def _is_bypassed(username):
    return str(username or "").strip().lower() in _load_bypass_list()

# Usernames specifically allowed to authenticate using the ORIGINAL,
# pre-patch server key — not open to everyone, only these. Separate from
# the general bypass list above (that one skips the key check entirely;
# this one still requires A key, just accepts the old one specifically for
# people on this list).
OLD_KEY_USERS_FILE = os.path.join(BASE_DIR, "old_key_users.json")
_old_key_users_cache = None

def load_old_key_users():
    global _old_key_users_cache
    if _old_key_users_cache is None:
        try:
            if os.path.exists(OLD_KEY_USERS_FILE):
                with open(OLD_KEY_USERS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _old_key_users_cache = data if isinstance(data, list) else []
            else:
                _old_key_users_cache = []
        except Exception as e:
            write_log(f"[old key users] load error: {e}")
            _old_key_users_cache = []
    return _old_key_users_cache

def save_old_key_users(names):
    global _old_key_users_cache
    _old_key_users_cache = names
    try:
        with open(OLD_KEY_USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(names, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[old key users] save error: {e}")
        return False

def _can_use_old_key(username):
    return str(username or "") in load_old_key_users()

# ── Promo codes ─────────────────────────────────────────────────────────────
# Confirmed real from your catch-all RPC logger: promo.redeem, body shape
# {"code": "..."}. The old implementation here crashed on every call (called
# .get() on a decoded string instead of a parsed dict) and only worked for
# one hardcoded code and two hardcoded usernames — full rebuild.
PROMO_CODES_FILE = os.path.join(BASE_DIR, "promo_codes.json")
_promo_codes_cache = None

def load_promo_codes():
    global _promo_codes_cache
    if _promo_codes_cache is None:
        try:
            if os.path.exists(PROMO_CODES_FILE):
                with open(PROMO_CODES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _promo_codes_cache = data if isinstance(data, dict) else {}
            else:
                _promo_codes_cache = {}
        except Exception as e:
            write_log(f"[promo codes] load error: {e}")
            _promo_codes_cache = {}
    return _promo_codes_cache

def save_promo_codes(data):
    global _promo_codes_cache
    _promo_codes_cache = data
    try:
        with open(PROMO_CODES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[promo codes] save error: {e}")
        return False

PROMO_REDEMPTIONS_FILE = os.path.join(BASE_DIR, "promo_redemptions.json")
_promo_redemptions_cache = None

def load_promo_redemptions():
    global _promo_redemptions_cache
    if _promo_redemptions_cache is None:
        try:
            if os.path.exists(PROMO_REDEMPTIONS_FILE):
                with open(PROMO_REDEMPTIONS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _promo_redemptions_cache = data if isinstance(data, dict) else {}
            else:
                _promo_redemptions_cache = {}
        except Exception as e:
            write_log(f"[promo redemptions] load error: {e}")
            _promo_redemptions_cache = {}
    return _promo_redemptions_cache

def save_promo_redemptions(data):
    global _promo_redemptions_cache
    _promo_redemptions_cache = data
    try:
        with open(PROMO_REDEMPTIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[promo redemptions] save error: {e}")
        return False

# ── Custom display names & developer flag — now decoupled ─────────────────
# Previously one hardcoded dict controlled both a styled display name AND
# isDeveloper together — anyone with a custom name automatically became a
# "developer" too, with no way to separate the two. Custom names are purely
# cosmetic (color/size rich-text tags); isDeveloper is a separate, more
# sensitive flag that should be opted into explicitly per person.
CUSTOM_NAMES_FILE = os.path.join(BASE_DIR, "custom_names.json")
_custom_names_cache = None
_DEFAULT_CUSTOM_NAMES = {
    "robozeke5":            {"display_username": "<color=yellow>gamertag202</color>", "display_name": "<color=yellow>gamertag202</color>", "custom_id": "24968022896116226"},
    "tuck1135":              {"display_username": "<size=5><color=#800080>Tuck</color>", "display_name": "<color=#800080>Tuck</color>", "custom_id": ""},
    "reese.s.pieces.lover": {"display_username": "<color=#FFA500>Reeses</color>:Reeses", "display_name": "<color=#FFA500>Reeses</color>reese.s.pieces.lover", "custom_id": "24968022896116226"},
    "Zizzyplays":           {"display_username": "<color=#800080>Ender</color>", "display_name": "<color=#800080>Ender</color>", "custom_id": ""},
    "I_like_breadalot":     {"display_username": "<color=yellow>Gay</color>", "display_name": "<color=yellow>Gay</color>", "custom_id": ""},
    "massive.dude.vr":      {"display_username": "<size=5><color=green>massive</color></size>", "display_name": "<size=5><color=green>massive</color></size>", "custom_id": ""},
    "SD_WatchOD":           {"display_username": "<color=blue>Watch</color>", "display_name": "<color=blue>Watch</color>", "custom_id": ""},
    "kris_kovidov":         {"display_username": "<color=purple>kris_kovidov</color>", "display_name": "<color=purple>kris_kovidov</color>", "custom_id": ""},
}

def load_custom_names():
    global _custom_names_cache
    if _custom_names_cache is None:
        try:
            if os.path.exists(CUSTOM_NAMES_FILE):
                with open(CUSTOM_NAMES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _custom_names_cache = data if isinstance(data, dict) else {}
            else:
                _custom_names_cache = dict(_DEFAULT_CUSTOM_NAMES)
        except Exception as e:
            write_log(f"[custom names] load error: {e}")
            _custom_names_cache = dict(_DEFAULT_CUSTOM_NAMES)
    return _custom_names_cache

def _get_custom_name_entry(username):
    """Case-insensitive lookup. Confirmed real bug: entries get saved with
    whatever capitalization the admin happened to type (e.g. "Zizzyplays"),
    but every other part of this system normalizes usernames to lowercase
    (see generate_deterministic_uid) — so a plain, case-sensitive .get()
    here silently failed for any entry that wasn't already all-lowercase,
    exactly the entries with any capital letter in them. Normalizes both
    sides before comparing rather than assuming they already match."""
    if not username:
        return None
    target = str(username).lower()
    for key, entry in load_custom_names().items():
        if str(key).lower() == target:
            return entry
    return None

def save_custom_names(names):
    global _custom_names_cache
    _custom_names_cache = names
    try:
        with open(CUSTOM_NAMES_FILE, "w", encoding="utf-8") as f:
            json.dump(names, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[custom names] save error: {e}")
        return False

# Separate, persisted, admin-editable — who actually gets isDeveloper: true.
# Defaults to just you; add anyone else explicitly via /admin/<token>/devs.
DEV_USERS_FILE = os.path.join(BASE_DIR, "dev_users.json")
_dev_users_cache = None

def load_dev_users():
    global _dev_users_cache
    if _dev_users_cache is None:
        try:
            if os.path.exists(DEV_USERS_FILE):
                with open(DEV_USERS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _dev_users_cache = data if isinstance(data, list) else []
            else:
                _dev_users_cache = ["tuck1135"]
        except Exception as e:
            write_log(f"[dev users] load error: {e}")
            _dev_users_cache = ["tuck1135"]
    return _dev_users_cache

def save_dev_users(names):
    global _dev_users_cache
    _dev_users_cache = names
    try:
        with open(DEV_USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(names, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[dev users] save error: {e}")
        return False

def _is_dev_user(username):
    return str(username or "") in load_dev_users()

# ── Gameplay/cosmetic unlock-everything lists ──────────────────────────────
# Previously every account started with ~90 research nodes (nearly the whole
# tree) and every cosmetic already owned — a hardcoded, static default with
# no way to differentiate accounts. Now: normal players start with none of
# that (leaving only the handful of ungated, always-purchasable items like
# item_treestick/item_flashlight available by default); these two lists are
# the explicit exception, admin-editable, same pattern as dev_users.
GAMEPLAY_UNLOCK_ALL_FILE = os.path.join(BASE_DIR, "gameplay_unlock_all.json")
_gameplay_unlock_all_cache = None

def load_gameplay_unlock_all():
    global _gameplay_unlock_all_cache
    if _gameplay_unlock_all_cache is None:
        try:
            if os.path.exists(GAMEPLAY_UNLOCK_ALL_FILE):
                with open(GAMEPLAY_UNLOCK_ALL_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _gameplay_unlock_all_cache = data if isinstance(data, list) else []
            else:
                _gameplay_unlock_all_cache = ["tuck1135"]
        except Exception as e:
            write_log(f"[gameplay unlock-all] load error: {e}")
            _gameplay_unlock_all_cache = ["tuck1135"]
    return _gameplay_unlock_all_cache

def save_gameplay_unlock_all(names):
    global _gameplay_unlock_all_cache
    _gameplay_unlock_all_cache = names
    try:
        with open(GAMEPLAY_UNLOCK_ALL_FILE, "w", encoding="utf-8") as f:
            json.dump(names, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[gameplay unlock-all] save error: {e}")
        return False

def _has_all_gameplay(username):
    return str(username or "") in load_gameplay_unlock_all()

COSMETICS_UNLOCK_ALL_FILE = os.path.join(BASE_DIR, "cosmetics_unlock_all.json")
_cosmetics_unlock_all_cache = None

def load_cosmetics_unlock_all():
    global _cosmetics_unlock_all_cache
    if _cosmetics_unlock_all_cache is None:
        try:
            if os.path.exists(COSMETICS_UNLOCK_ALL_FILE):
                with open(COSMETICS_UNLOCK_ALL_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _cosmetics_unlock_all_cache = data if isinstance(data, list) else []
            else:
                _cosmetics_unlock_all_cache = ["tuck1135"]
        except Exception as e:
            write_log(f"[cosmetics unlock-all] load error: {e}")
            _cosmetics_unlock_all_cache = ["tuck1135"]
    return _cosmetics_unlock_all_cache

def save_cosmetics_unlock_all(names):
    global _cosmetics_unlock_all_cache
    _cosmetics_unlock_all_cache = names
    try:
        with open(COSMETICS_UNLOCK_ALL_FILE, "w", encoding="utf-8") as f:
            json.dump(names, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[cosmetics unlock-all] save error: {e}")
        return False

def _has_all_cosmetics(username):
    return str(username or "") in load_cosmetics_unlock_all()

# Cosmetics: back to everyone-owns-everything by default (per your call to
# scrap the buy system) — refined with two new controls instead of the
# purchase-based restriction.
#
# 1. Excluded cosmetics — admin-editable, removes specific items from the
# everyone-owns-everything default. Reversible: taking something off this
# list restores it to the default grant for everyone again. Doesn't apply
# to accounts on the cosmetics unlock-all list (they bypass exclusions
# entirely, same as before).
EXCLUDED_COSMETICS_FILE = os.path.join(BASE_DIR, "excluded_cosmetics.json")
_excluded_cosmetics_cache = None

def load_excluded_cosmetics():
    global _excluded_cosmetics_cache
    if _excluded_cosmetics_cache is None:
        try:
            if os.path.exists(EXCLUDED_COSMETICS_FILE):
                with open(EXCLUDED_COSMETICS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _excluded_cosmetics_cache = data if isinstance(data, list) else []
            else:
                _excluded_cosmetics_cache = []
        except Exception as e:
            write_log(f"[excluded cosmetics] load error: {e}")
            _excluded_cosmetics_cache = []
    return _excluded_cosmetics_cache

def save_excluded_cosmetics(ids):
    global _excluded_cosmetics_cache
    _excluded_cosmetics_cache = ids
    try:
        with open(EXCLUDED_COSMETICS_FILE, "w", encoding="utf-8") as f:
            json.dump(ids, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[excluded cosmetics] save error: {e}")
        return False

# 2. Per-person cosmetic grants — admin-editable, gives a SPECIFIC item to a
# SPECIFIC username regardless of exclusions or unlock-all status. Keyed by
# username -> list of item ids. This bypasses exclusion for that exact
# (person, item) pair even if the item is globally excluded.
PER_PERSON_COSMETICS_FILE = os.path.join(BASE_DIR, "per_person_cosmetics.json")
_per_person_cosmetics_cache = None

def load_per_person_cosmetics():
    global _per_person_cosmetics_cache
    if _per_person_cosmetics_cache is None:
        try:
            if os.path.exists(PER_PERSON_COSMETICS_FILE):
                with open(PER_PERSON_COSMETICS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _per_person_cosmetics_cache = data if isinstance(data, dict) else {}
            else:
                _per_person_cosmetics_cache = {}
        except Exception as e:
            write_log(f"[per-person cosmetics] load error: {e}")
            _per_person_cosmetics_cache = {}
    return _per_person_cosmetics_cache

def save_per_person_cosmetics(data):
    global _per_person_cosmetics_cache
    _per_person_cosmetics_cache = data
    try:
        with open(PER_PERSON_COSMETICS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[per-person cosmetics] save error: {e}")
        return False

def _default_cosmetics_for(username, client_version=None):
    """DEPRECATED under the new purchase-based economy — kept only for
    unlock-all accounts, who still just get the full eligible catalog
    outright, bypassing purchase entirely."""
    all_ids = _all_avatar_item_ids(client_version)
    if _has_all_cosmetics(username):
        return all_ids
    return []

# ── Cosmetics economy: ported from a friend's real, working implementation ──
# Full switch per your call: nothing is owned by default anymore (except
# unlock-all accounts) — every cosmetic must be explicitly purchased with
# cc, tracked in its own dedicated file, completely separate from the old
# exclusion-list default. Two things explicitly preserved per your
# requirement: (1) every catalog item stays buyable regardless of its own
# showInShop flag — their own purchase RPC never checks that field at all,
# it only validates the item exists — and (2) anyone who already redeemed
# a cosmetic via a promo code keeps it, since per-person grants are
# checked as an additional, independent source of ownership on top of
# purchases, not replaced by them.
PURCHASED_AVATAR_ITEMS_FILE = os.path.join(BASE_DIR, "purchased_avatar_items.json")
_purchased_avatar_items_cache = None

def _load_purchased_avatar_items():
    global _purchased_avatar_items_cache
    if _purchased_avatar_items_cache is None:
        try:
            if os.path.exists(PURCHASED_AVATAR_ITEMS_FILE):
                with open(PURCHASED_AVATAR_ITEMS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _purchased_avatar_items_cache = data if isinstance(data, dict) else {}
            else:
                _purchased_avatar_items_cache = {}
        except Exception as e:
            write_log(f"[purchased avatar items] load error: {e}")
            _purchased_avatar_items_cache = {}
    return _purchased_avatar_items_cache

def _save_purchased_avatar_items(data):
    global _purchased_avatar_items_cache
    _purchased_avatar_items_cache = data
    try:
        with open(PURCHASED_AVATAR_ITEMS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[purchased avatar items] save error: {e}")
        return False

def get_purchased_avatar_items(username):
    """Case-insensitive lookup — the exact same class of bug we already
    found and fixed for custom names, so built case-insensitively from
    the start here rather than repeating it."""
    key = str(username or "").strip().lower()
    purchased = _load_purchased_avatar_items()
    user_data = purchased.get(key)
    if user_data is None:
        for k, v in purchased.items():
            if isinstance(k, str) and k.lower() == key:
                user_data = v
                break
    if isinstance(user_data, dict):
        items = user_data.get("items", [])
        if isinstance(items, list):
            return items
    return []

def add_purchased_avatar_items(username, items):
    key = str(username or "").strip().lower()
    if not isinstance(items, list):
        items = [items] if items else []
    purchased = _load_purchased_avatar_items()
    if not isinstance(purchased.get(key), dict):
        purchased[key] = {"items": []}
    current = purchased[key].get("items", [])
    if not isinstance(current, list):
        current = []
    for item in items:
        if item not in current:
            current.append(item)
    purchased[key]["items"] = current
    return _save_purchased_avatar_items(purchased)

def _get_owned_cosmetics(username, client_version=None):
    """Single source of truth for cosmetics ownership under the new
    purchase-based economy. An item is owned if: this account has
    unlock-all (bypasses purchase entirely), OR it's been explicitly
    purchased (plus that purchase's bundle sub-items), OR it's been
    granted per-person (e.g. via a redeemed promo code — checked
    independently, so redemptions from before this switch are never
    lost). Used everywhere ownership needs reporting (/v2/account,
    avatar.update GET, /v2/storage, purchase.avatarItems)."""
    if _has_all_cosmetics(username):
        return _all_avatar_item_ids(client_version)

    catalog_by_id = {i.get("id"): i for i in _load_avatar_catalog() if isinstance(i, dict)}
    owned = set()

    for iid in get_purchased_avatar_items(username):
        owned.add(iid)
        subs = catalog_by_id.get(iid, {}).get("subItemsFlat", [])
        if isinstance(subs, list):
            owned.update(s for s in subs if isinstance(s, str))

    for iid in load_per_person_cosmetics().get(username, []):
        owned.add(iid)
        subs = catalog_by_id.get(iid, {}).get("subItemsFlat", [])
        if isinstance(subs, list):
            owned.update(s for s in subs if isinstance(s, str))

    return list(owned)

# The full ~90-node research tree, preserved exactly as it was — this is now
# ONLY handed to accounts on the gameplay unlock-all list, not everyone.
_FULL_RESEARCH_NODES = ["node_dynamite", "node_teleport_grenade", "node_glowsticks", "node_skill_backpack_cap_1", "node_skill_health_1", "node_crowbar", "node_flaregun", "node_ogre_hands", "node_revolver", "node_skill_gundamage_1", "node_skill_explosive_1", "node_rpg", "node_skill_selling_1", "node_revolver_ammo", "node_rpg_ammo", "node_flashbang", "node_impact_grenade", "node_cluster_grenade", "node_jetpack", "node_shotgun", "node_tripwire_explosive", "node_crossbow", "node_tablet", "node_plunger", "node_umbrella", "node_backpack", "node_flashlight_mega", "node_lance", "node_balloon", "node_saddle", "node_skill_right_hip_attachment", "node_skill_left_hip_attachment", "node_sticky_dynamite", "node_rpg_cny", "node_zipline_gun", "node_zipline_rope", "node_company_ration", "node_balloon_heart", "node_crossbow_heart", "node_arrow", "node_arrow_heart", "node_hoverpad", "node_quiver", "node_backpack_large", "node_shield", "node_shield_police", "node_hookshot", "node_baseball_bat", "node_police_baton", "node_heart_gun", "node_pogostick", "node_boxfan", "node_mega_broccoli", "node_mini_broccoli", "node_dynamite_cube", "node_skill_backpack_cap_2", "node_whoopie", "node_disposable_camera", "node_sticker_dispenser", "node_impulse_grenade", "node_stash_grenade", "node_cardboardbox", "node_rpg_easter", "node_rpg_ammo_egg", "node_pinata_bat", "node_hawaiian_drum", "node_ukulele", "node_anti_gravity_grenade", "node_antigrav_grenade", "node_football", "node_skill_backpack_cap_3", "node_item_nut_shredder", "node_hookshot_sword", "node_rpg_spear", "node_rpg_ammo_spear", "node_skill_health_2", "node_skill_selling_2", "node_skill_selling_3", "node_frying_pan", "node_skill_melee_1", "node_skill_melee_2", "node_skill_melee_3", "node_viking_hammer", "node_viking_hammer_twilight", "node_mega_broccoli_bomb", "node_micro_broccoli_bomb", "node_teleport_gun", "node_arrow_bomb", "node_robo_monke", "node_friend_launcher", "node_grenade_launcher"]

def noncevalidation(nonce, oculus_id):
    response = requests.post(
        url=f'https://graph.oculus.com/user_nonce_validate?nonce={nonce}&user_id={oculus_id}&access_token={""}',
        headers={"content-type": "application/json"}
    )
    return response.json().get("is_valid")

def SessionRefresh(token):
    changetoken = decode_verified_token(token)
    if changetoken is None:
        return jsonify({"error": "invalid token"}), 403
    now = int(time.time())
    changetoken['exp'] = now + 3600
    Bearer = make_token(changetoken)
    return jsonify({
        "token": Bearer
    }), 200

def skidatoken(clankersfuckassid, diddyid, metaupdate):
    data = f"{clankersfuckassid}|{diddyid}|{metaupdate}"
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + data.encode()).digest()
    token = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    mid = len(token) // 2
    token = token[:mid] + "-" + token[mid:]

    return token

def ilowkeydontknowwhy():
    efsfdfsdsdf = int(time.time())
    gfshrtfhfghjfgd = efsfdfsdsdf + 86400
    return "gfshrtfhfghjfgd"

# --- persistence + stable identity (ported from XeraCompany_3.py) ----------
# Local JSON file, keyed by lowercased username. No GH-repo push (kept minimal).
USER_DATA_FILE = os.path.join(BASE_DIR, "user_data.json")
_items_lock = threading.Lock()
# Serializes the whole read-check-charge-save sequence in
# purchase_avatar_items, same reasoning as the reference's own version —
# without this, two concurrent purchase requests could both read the same
# starting balance, both pass the funds check, and one's deduction could
# overwrite the other's.
_avatar_purchase_lock = threading.Lock()

# uid -> username reverse lookup, needed because generate_deterministic_uid
# below is a one-way hash. Kept in its own small file rather than folded
# into currency.json/user_data.json since it's looked up by uid, not username.
_UID_LOOKUP_FILE = os.path.join(BASE_DIR, "uid_lookup.json")
_uid_lookup_cache = None
_uid_lookup_lock = threading.Lock()

def _load_uid_lookup():
    global _uid_lookup_cache
    if _uid_lookup_cache is None:
        try:
            if os.path.exists(_UID_LOOKUP_FILE):
                with open(_UID_LOOKUP_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _uid_lookup_cache = data if isinstance(data, dict) else {}
            else:
                _uid_lookup_cache = {}
        except Exception as e:
            write_log(f"[uid lookup] load error: {e}")
            _uid_lookup_cache = {}
    return _uid_lookup_cache

def generate_deterministic_uid(username):
    """Same username -> same UUID, always. This is the key everything else
    (account id, token uid, storage user_id) hangs off of. This is a one-way
    hash (uuid5) — there's no way to recover a username from a uid without
    a stored reverse lookup, so this also opportunistically records that
    mapping. Needed by /v2/user: when player B's client asks "who is this
    uid I'm seeing", we have to be able to answer with an actual username."""
    namespace = uuid.UUID("7cdc1fa7-5d90-4575-a6a3-47f0748da898")
    uname_norm = str(username or "").lower().strip()
    uid = str(uuid.uuid5(namespace, uname_norm))
    lookup = _load_uid_lookup()
    if lookup.get(uid) != uname_norm:
        with _uid_lookup_lock:
            lookup[uid] = uname_norm
            try:
                with open(_UID_LOOKUP_FILE, "w", encoding="utf-8") as f:
                    json.dump(lookup, f)
            except Exception as e:
                write_log(f"[uid lookup] save error: {e}")
    return uid

# ── Friends system — ported from a friend's real, working implementation ──
# Replaces the old /v2/friends stub, which was a hardcoded single fake
# entry with your own comment on it saying it didn't work. This is a
# faithful port of the reference's actual add/accept/reject/block flow —
# including its fix for a real Nakama Unity SDK quirk (the accept action
# sends DELETE then POST in quick succession, which without special
# handling looks identical to "reject, then immediately send a new
# request the other direction").
FRIENDS_FILE = os.path.join(BASE_DIR, "friends_state.json")
_friends_cache = None

def _load_friends_file():
    global _friends_cache
    if _friends_cache is None:
        try:
            if os.path.exists(FRIENDS_FILE):
                with open(FRIENDS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _friends_cache = data if isinstance(data, dict) else {}
            else:
                _friends_cache = {}
        except Exception as e:
            write_log(f"[friends] load error: {e}")
            _friends_cache = {}
    return _friends_cache

def _save_friends_file(data):
    global _friends_cache
    _friends_cache = data
    try:
        with open(FRIENDS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[friends] save error: {e}")
        return False

def _friends_key(uid):
    return f"uid_{uid}"

def _load_friends_for(uid):
    fd = _load_friends_file()
    data = fd.get(_friends_key(uid), {})
    if not isinstance(data, dict):
        data = {}
    def _to_list(v):
        return v if isinstance(v, list) else []
    data["friends"] = _to_list(data.get("friends"))
    data["pending_sent"] = _to_list(data.get("pending_sent"))
    data["pending_incoming"] = _to_list(data.get("pending_incoming"))
    data["blocked"] = _to_list(data.get("blocked"))
    return data

def _save_friends_for(uid, data):
    fd = _load_friends_file()
    fd[_friends_key(uid)] = data
    _save_friends_file(fd)

def _is_online(uid):
    """No websocket layer yet — this uses the same HTTP last-seen tracking
    the leaderboard already relies on, same idea as the reference's own
    fallback path for client versions that predate its websocket support.
    Once the planned separate real-time service exists, this is the spot
    to make online-ness authoritative instead of last-seen-based."""
    uname = _load_uid_lookup().get(uid)
    if not uname:
        return False
    with _presence_lock:
        ts = _last_seen.get(uname)
    return ts is not None and (time.time() - ts) < PRESENCE_TIMEOUT_SECONDS

def _user_status(uid):
    if not _is_online(uid):
        return "Offline"
    uname = _load_uid_lookup().get(uid)
    with _presence_lock:
        room = _player_room.get(uname) if uname else None
    return "In Game" if room else "Online"

# Recent DELETE-of-a-pending-incoming-request, per (my uid -> their uid) —
# a same-request POST that follows within the window is treated as an
# accept rather than a brand new outgoing request. See the docstring above.
_recent_dismissed_incoming = {}
_DISMISS_ACCEPT_WINDOW = 60

def _parse_ids_param():
    """Accepts ids from a JSON body (ids/user_ids/user_id/id, string or
    list) or query string, comma-separated or repeated — matches what the
    real Nakama Unity SDK actually sends across these different calls."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        body = {}
    ids = []
    def add_val(val):
        if isinstance(val, list):
            for i in val:
                if i is not None:
                    s = str(i).strip()
                    if s:
                        ids.append(s)
        elif isinstance(val, str):
            for part in val.split(","):
                part = part.strip()
                if part:
                    ids.append(part)
        elif val is not None:
            s = str(val).strip()
            if s:
                ids.append(s)
    for key in ("ids", "user_ids", "user_id", "id"):
        if key in body:
            add_val(body[key])
    for key in ("ids", "user_ids", "user_id", "id"):
        for entry in request.args.getlist(key):
            add_val(entry)
    if not ids:
        raw = (request.args.get("ids", "") or request.args.get("user_ids", "")
               or request.args.get("user_id", "") or request.args.get("id", ""))
        add_val(raw)
    return list(dict.fromkeys(ids))

def _usernames_to_uids(usernames):
    return [generate_deterministic_uid(u.strip()) for u in usernames if u.strip()]

def _resolve_friend_user(fid):
    """Same shape /v2/user already returns for a known uid, so a friend
    list entry's "user" object stays consistent with what /v2/user says
    about that same person elsewhere."""
    uname = _load_uid_lookup().get(fid)
    if not uname:
        return {
            "id": fid, "username": f"Friend_{fid[:8]}", "display_name": f"Friend_{fid[:8]}",
            "lang_tag": "en", "metadata": json.dumps({"isDeveloper": False}),
            "edge_count": 0, "create_time": "2024-08-24T04:20:56Z", "update_time": "2025-01-01T00:00:00Z",
        }
    name_entry = _get_custom_name_entry(uname)
    display = (name_entry.get("display_name") or uname) if name_entry else uname
    return {
        "id": fid, "username": display, "display_name": display,
        "lang_tag": "en", "metadata": json.dumps({"isDeveloper": _is_dev_user(uname)}),
        "edge_count": 0, "create_time": "2024-08-24T04:20:56Z", "update_time": "2025-01-01T00:00:00Z",
    }

@app.route("/v2/friend", methods=["GET", "POST", "DELETE"])
@app.route("/3/v2/friend", methods=["GET", "POST", "DELETE"])
@app.route("/nnnnaakamacloud.c/v2/friends", methods=["GET", "POST", "DELETE"])
def friends_v2():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "authentication required"}), 401
    usn = payload["usn"]
    uid = generate_deterministic_uid(usn)

    if request.method == "GET":
        my_data = _load_friends_for(uid)
        friends_list = []
        for fid in my_data["friends"]:
            u = _resolve_friend_user(fid)
            friends_list.append({"user": u, "state": 0, "update_time": u["update_time"],
                                  "online": _is_online(fid), "status": _user_status(fid)})
        for fid in my_data["pending_sent"]:
            u = _resolve_friend_user(fid)
            friends_list.append({"user": u, "state": 1, "update_time": u["update_time"],
                                  "online": _is_online(fid), "status": _user_status(fid)})
        for fid in my_data["pending_incoming"]:
            u = _resolve_friend_user(fid)
            friends_list.append({"user": u, "state": 2, "update_time": u["update_time"],
                                  "online": _is_online(fid), "status": _user_status(fid)})
        return jsonify({"friends": friends_list, "cursor": ""}), 200

    if request.method == "POST":
        target_ids = _parse_ids_param()
        raw_usernames = []
        for key in ("usernames", "username"):
            for entry in request.args.getlist(key):
                raw_usernames.extend(entry.split(","))
            body = request.get_json(silent=True)
            if isinstance(body, dict) and key in body:
                val = body[key]
                if isinstance(val, list):
                    raw_usernames.extend(val)
                elif isinstance(val, str):
                    raw_usernames.extend(val.split(","))
        if raw_usernames:
            target_ids = list(dict.fromkeys(target_ids + _usernames_to_uids(raw_usernames)))
        if not target_ids:
            return jsonify({"error": "ids required"}), 400

        my_data = _load_friends_for(uid)
        results = []
        for tid in target_ids:
            if tid == uid:
                continue
            if tid in my_data["blocked"]:
                results.append({"id": tid, "status": "blocked"})
                continue

            their_data = _load_friends_for(tid)
            dismissed_at = _recent_dismissed_incoming.get(uid, {}).get(tid, 0)
            within_window = (time.time() - dismissed_at) < _DISMISS_ACCEPT_WINDOW

            if tid in my_data["pending_incoming"] or within_window:
                if tid not in my_data["friends"]:
                    my_data["friends"].append(tid)
                if uid not in their_data["friends"]:
                    their_data["friends"].append(uid)
                my_data["pending_incoming"] = [x for x in my_data["pending_incoming"] if x != tid]
                their_data["pending_sent"] = [x for x in their_data["pending_sent"] if x != uid]
                _recent_dismissed_incoming.get(uid, {}).pop(tid, None)
                _save_friends_for(tid, their_data)
                results.append({"id": tid, "status": "accepted"})
                _notify_presence_service(tid, -3, uid, "friend_accepted")  # -3 = FriendRequestAccepted
            elif tid in my_data["friends"]:
                results.append({"id": tid, "status": "already_friends"})
            elif tid in my_data["pending_sent"]:
                results.append({"id": tid, "status": "request_pending"})
            else:
                if tid not in my_data["pending_sent"]:
                    my_data["pending_sent"].append(tid)
                if uid not in their_data["pending_incoming"]:
                    their_data["pending_incoming"].append(uid)
                _save_friends_for(tid, their_data)
                results.append({"id": tid, "status": "request_sent"})
                _notify_presence_service(tid, -2, uid, "friend_request")  # -2 = FriendRequestReceived

        _save_friends_for(uid, my_data)
        return jsonify({"success": True, "results": results}), 200

    if request.method == "DELETE":
        target_ids = _parse_ids_param()
        raw_usernames = []
        for key in ("usernames", "username"):
            for entry in request.args.getlist(key):
                raw_usernames.extend(entry.split(","))
            body = request.get_json(silent=True)
            if isinstance(body, dict) and key in body:
                val = body[key]
                if isinstance(val, list):
                    raw_usernames.extend(val)
                elif isinstance(val, str):
                    raw_usernames.extend(val.split(","))
        if raw_usernames:
            target_ids = list(dict.fromkeys(target_ids + _usernames_to_uids(raw_usernames)))
        if not target_ids:
            return jsonify({"error": "ids required"}), 400

        my_data = _load_friends_for(uid)
        now = time.time()
        for tid in target_ids:
            if tid in my_data["pending_incoming"]:
                _recent_dismissed_incoming.setdefault(uid, {})[tid] = now
            my_data["friends"] = [f for f in my_data["friends"] if f != tid]
            my_data["pending_sent"] = [f for f in my_data["pending_sent"] if f != tid]
            my_data["pending_incoming"] = [f for f in my_data["pending_incoming"] if f != tid]
            their_data = _load_friends_for(tid)
            their_data["friends"] = [f for f in their_data["friends"] if f != uid]
            their_data["pending_sent"] = [f for f in their_data["pending_sent"] if f != uid]
            their_data["pending_incoming"] = [f for f in their_data["pending_incoming"] if f != uid]
            _save_friends_for(tid, their_data)
        _save_friends_for(uid, my_data)

        cutoff = now - _DISMISS_ACCEPT_WINDOW
        for _u, _m in list(_recent_dismissed_incoming.items()):
            for _t, _ts in list(_m.items()):
                if _ts < cutoff:
                    _m.pop(_t, None)
            if not _m:
                _recent_dismissed_incoming.pop(_u, None)
        return jsonify({"success": True}), 200

@app.route("/v2/friend/block", methods=["POST", "GET"])
@app.route("/3/v2/friend/block", methods=["POST", "GET"])
def friend_block():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "authentication required"}), 401
    uid = generate_deterministic_uid(payload["usn"])

    target_ids = _parse_ids_param()
    if not target_ids:
        return jsonify({"error": "ids required"}), 400
    my_data = _load_friends_for(uid)
    for tid in target_ids:
        if tid not in my_data["blocked"]:
            my_data["blocked"].append(tid)
        my_data["friends"] = [f for f in my_data["friends"] if f != tid]
        my_data["pending_sent"] = [f for f in my_data["pending_sent"] if f != tid]
        my_data["pending_incoming"] = [f for f in my_data["pending_incoming"] if f != tid]
        their_data = _load_friends_for(tid)
        their_data["friends"] = [f for f in their_data["friends"] if f != uid]
        their_data["pending_sent"] = [f for f in their_data["pending_sent"] if f != uid]
        their_data["pending_incoming"] = [f for f in their_data["pending_incoming"] if f != uid]
        _save_friends_for(tid, their_data)
    _save_friends_for(uid, my_data)
    return jsonify({"success": True}), 200

@app.route("/v2/friend/unblock", methods=["POST", "GET"])
@app.route("/3/v2/friend/unblock", methods=["POST", "GET"])
def friend_unblock():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "authentication required"}), 401
    uid = generate_deterministic_uid(payload["usn"])

    target_ids = _parse_ids_param()
    if not target_ids:
        return jsonify({"error": "ids required"}), 400
    my_data = _load_friends_for(uid)
    my_data["blocked"] = [f for f in my_data["blocked"] if f not in target_ids]
    _save_friends_for(uid, my_data)
    return jsonify({"success": True}), 200

@app.route("/v2/friend/blocked", methods=["GET"])
@app.route("/3/v2/friend/blocked", methods=["GET"])
def friend_blocked_list():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "authentication required"}), 401
    uid = generate_deterministic_uid(payload["usn"])

    my_data = _load_friends_for(uid)
    blocked_list = [_resolve_friend_user(fid) for fid in my_data["blocked"]]
    return jsonify({"blocked": blocked_list}), 200

# Same idea as the currency cache above — user_data.json holds everyone's
# inventory and gets read on nearly every storage/avatar RPC.
_items_cache = None

def _load_items():
    global _items_cache
    if _items_cache is None:
        try:
            if os.path.exists(USER_DATA_FILE):
                with open(USER_DATA_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _items_cache = data if isinstance(data, dict) else {}
            else:
                _items_cache = {}
        except Exception as e:
            write_log(f"[items] load error: {e}")
            _items_cache = {}
    return _items_cache

def _save_items(items):
    global _items_cache
    _items_cache = items
    try:
        with open(USER_DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[items] save error: {e}")
        return False

def save_user_items(username, item_data, collection="user_inventory", key="avatar"):
    name_key = str(username or "").strip().lower()
    if not name_key:
        return False
    with _items_lock:
        items = _load_items()
        if not isinstance(items, dict):
            items = {}
        if not isinstance(items.get(name_key), dict):
            items[name_key] = {"collections": {}}
        if "collections" not in items[name_key]:
            items[name_key]["collections"] = {}
        items[name_key]["collections"][f"{collection}:{key}"] = item_data
        return _save_items(items)

def get_user_items(username, collection="user_inventory", key="avatar"):
    name_key = str(username or "").strip().lower()
    if not name_key:
        return None
    items = _load_items()
    if not isinstance(items, dict):
        return None
    user_data = items.get(name_key)
    if isinstance(user_data, dict):
        return user_data.get("collections", {}).get(f"{collection}:{key}", None)
    return None

def _storage_defaults(path, username=None):
    # autism()/storage166() are defined further down; called at request time so
    # the forward reference is fine.
    if path.startswith("/nnnnaakamacloud.c"):
        return storage166(username).get("objects", [])
    return autism(username).get("objects", [])

def _overlay_user_objects(username, base_objects, client_version=None):
    """Default objects with this user's stable user_id stamped in, and any
    value they've saved overlaid on top of the default. If client_version is
    given, both the owned-cosmetics list (user_inventory/avatar) AND the
    equipped-appearance state (user_avatar/0 — head/torso/accessories/etc)
    are stripped of anything that client build can't handle — matching the
    catalog endpoint's filtering, so a legacy client never receives a
    reference to an item it has no catalog entry for at all, whether that's
    something it owns or something it's currently wearing."""
    uid = generate_deterministic_uid(username)
    out = []
    for obj in base_objects:
        o = dict(obj)
        o["user_id"] = uid
        saved = get_user_items(username, o.get("collection", ""), o.get("key", ""))
        if isinstance(saved, dict) and saved.get("value") is not None:
            o["value"] = saved["value"]
            if saved.get("update_time"):
                o["update_time"] = saved["update_time"]
            if saved.get("version"):
                o["version"] = saved["version"]
        if client_version is not None and o.get("collection") in ("user_avatar", "user_inventory"):
            try:
                parsed = json.loads(o["value"])
                if isinstance(parsed, dict):
                    o["value"] = json.dumps(_strip_unknown_avatar_items(parsed, client_version))
            except Exception:
                pass
        # Cosmetics ownership is always the fresh current default for normal
        # accounts (see _get_owned_cosmetics' docstring for why relying on
        # whatever's saved here was the actual bug — it could only ever
        # subtract newly-excluded items, never resurrect one that's no
        # longer excluded but simply isn't present in an old save).
        # Replaces the saved "items" list outright rather than subtracting
        # from it, so un-excluding something takes effect immediately.
        if o.get("collection") == "user_inventory" and o.get("key") == "avatar":
            try:
                parsed = json.loads(o["value"])
                if isinstance(parsed, dict):
                    parsed["items"] = _get_owned_cosmetics(username, client_version)
                    o["value"] = json.dumps(parsed)
            except Exception:
                pass
        out.append(o)
    return out

def _save_storage_objects(username, objects):
    saved_any = False
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for obj in objects or []:
        if not isinstance(obj, dict):
            continue
        collection = obj.get("collection")
        if not collection:
            continue
        key = obj.get("key", "0")
        item_data = {
            "value": obj.get("value"),
            "update_time": obj.get("update_time") or now,
            "version": obj.get("version") or secrets.token_hex(8),
        }
        if save_user_items(username, item_data, collection, key):
            saved_any = True
    return saved_any

# Diagnostic only — targets exactly the storage slots cosmetics/appearance
# live in. Since color changes already work in-game, whatever gets logged
# here when you change color IS the correct, working format — use it as
# the reference for how cosmetics equips should look once we see one.
_AVATAR_RELATED_COLLECTIONS = {"user_avatar", "user_inventory"}
_AVATAR_RELATED_KEYS = {"avatar", "gameplay_loadout", "0"}

def _log_avatar_storage_write(username, objects):
    for obj in objects or []:
        if not isinstance(obj, dict):
            continue
        if obj.get("collection") in _AVATAR_RELATED_COLLECTIONS and obj.get("key") in _AVATAR_RELATED_KEYS:
            log_to_avatar_discord(
                f"🎨 **Avatar/cosmetic storage write**\n"
                f"👤 User: `{username}`\n"
                f"📁 Collection: `{obj.get('collection')}` | Key: `{obj.get('key')}`\n"
                f"📦 Value: ```json\n{obj.get('value')}\n```"
            )

# --- currency / wallet persistence -----------------------------------------
# Mapping to the wire format: softCurrency=nuts, hardCurrency=cc, researchPoints=rp
CURRENCY_FILE = os.path.join(BASE_DIR, "currency.json")
_currency_lock = threading.Lock()
_research_unlock_lock = threading.Lock()
# New normal users start with tuck.py's historical default account wallet.
_DEFAULT_CURRENCY = {"nuts": 100, "cc": 435686, "rp": 1135}

# In-memory mirror of currency.json. Previously every wallet read re-opened
# and re-parsed the whole file from disk — and get_user_currency() runs on
# almost every RPC call (mining, wallet, avatar, storage...), so that adds
# up fast. Now we read the file once and keep it in memory; writes still hit
# disk immediately so nothing is lost on a reload/crash.
_currency_cache = None

def _load_currencies():
    global _currency_cache
    if _currency_cache is None:
        try:
            if os.path.exists(CURRENCY_FILE):
                with open(CURRENCY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _currency_cache = data if isinstance(data, dict) else {}
            else:
                _currency_cache = {}
        except Exception as e:
            write_log(f"[currency] load error: {e}")
            _currency_cache = {}
    return _currency_cache

def _save_currencies(currencies):
    global _currency_cache
    _currency_cache = currencies
    try:
        with open(CURRENCY_FILE, "w", encoding="utf-8") as f:
            json.dump(currencies, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[currency] save error: {e}")
        return False

def get_user_currency(username):
    key = str(username or "").strip().lower()
    if not key:
        return dict(_DEFAULT_CURRENCY)
    with _currency_lock:
        currencies = _load_currencies()
        if not isinstance(currencies, dict):
            currencies = {}
        if not isinstance(currencies.get(key), dict):
            currencies[key] = dict(_DEFAULT_CURRENCY)
            _save_currencies(currencies)
        return currencies[key]

def update_user_currency(username, rp=None, nuts=None, cc=None):
    key = str(username or "").strip().lower()
    if not key:
        return dict(_DEFAULT_CURRENCY)
    with _currency_lock:
        currencies = _load_currencies()
        if not isinstance(currencies, dict):
            currencies = {}
        if not isinstance(currencies.get(key), dict):
            currencies[key] = dict(_DEFAULT_CURRENCY)
        if rp is not None:
            currencies[key]["rp"] = int(rp)
        if nuts is not None:
            currencies[key]["nuts"] = int(nuts)
        if cc is not None:
            currencies[key]["cc"] = int(cc)
        _save_currencies(currencies)
        return currencies[key]

def _wallet_rpc(username):
    """ApiUserWallet shape used by mining/research RPC responses."""
    cur = get_user_currency(username)
    return {
        "softCurrency":   int(cur.get("nuts", 0)),
        "hardCurrency":   int(cur.get("cc", 0)),
        "researchPoints": int(cur.get("rp", 0)),
    }
def reset_all_nuts_to_100():
    """Sets softCurrency (nuts) to 100 for every saved account. Returns the
    number of accounts touched."""
    with _currency_lock:
        currencies = _load_currencies()
        if not isinstance(currencies, dict):
            currencies = {}
        count = 0
        for uname, wallet in currencies.items():
            if isinstance(wallet, dict):
                wallet["nuts"] = 100
                count += 1
        _save_currencies(currencies)
        return count

def reset_all_tech_trees():
    """Deletes every saved account's user_inventory:research entry, so it
    falls back to the dynamic default (empty for normal accounts, the full
    tree for anyone on the gameplay unlock-all list) rather than forcing
    everyone to literally empty regardless of that list. Returns the number
    of accounts that actually had a saved record to clear."""
    with _items_lock:
        items = _load_items()
        if not isinstance(items, dict):
            items = {}
        count = 0
        for uname, udata in items.items():
            if isinstance(udata, dict) and "user_inventory:research" in udata.get("collections", {}):
                del udata["collections"]["user_inventory:research"]
                count += 1
        _save_items(items)
        return count

def reset_all_cosmetics():
    """Deletes every saved account's owned-cosmetics list AND equipped
    appearance state, so both fall back to the dynamic default (empty
    ownership for normal accounts, everything for anyone on the cosmetics
    unlock-all list) — clearing both together so nobody's left with an
    equipped item they no longer technically own. Returns the number of
    accounts that had at least one of the two records cleared."""
    with _items_lock:
        items = _load_items()
        if not isinstance(items, dict):
            items = {}
        count = 0
        for uname, udata in items.items():
            if not isinstance(udata, dict):
                continue
            cols = udata.get("collections", {})
            touched = False
            if "user_inventory:avatar" in cols:
                del cols["user_inventory:avatar"]
                touched = True
            if "user_avatar:0" in cols:
                del cols["user_avatar:0"]
                touched = True
            if touched:
                count += 1
        _save_items(items)
        return count

# This is a "security by obscurity" token: the page only exists at
# /admin/<ADMIN_PANEL_TOKEN>, it isn't linked anywhere. Now admin-editable
# (see /admin/<token>/change-url) instead of a hardcoded constant, so
# rotating it doesn't need a code change — falls back to the existing,
# already-deployed value the first time this runs.
#
# Same reasoning as load_server_key above for reading fresh every call
# rather than caching: a stale copy of THIS specific value on even one
# worker process means that worker keeps accepting the OLD admin URL
# and rejecting the new one, or vice versa, depending on which process
# happens to handle which request — this is exactly the kind of thing
# that must never be allowed to drift out of sync with what's on disk.
ADMIN_PANEL_TOKEN_FILE = os.path.join(BASE_DIR, "admin_panel_token_config.json")
_DEFAULT_ADMIN_PANEL_TOKEN = "GDmbSrcCgVtL0J1pS1e4gSZdmaDSTLtF"

def load_admin_panel_token():
    try:
        if os.path.exists(ADMIN_PANEL_TOKEN_FILE):
            with open(ADMIN_PANEL_TOKEN_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                token = data.get("token") if isinstance(data, dict) else None
                if token:
                    return token
    except Exception as e:
        write_log(f"[admin panel token] load error: {e}")
    return _DEFAULT_ADMIN_PANEL_TOKEN

def save_admin_panel_token(new_token):
    try:
        with open(ADMIN_PANEL_TOKEN_FILE, "w", encoding="utf-8") as f:
            json.dump({"token": new_token}, f, indent=2)
        return True
    except Exception as e:
        write_log(f"[admin panel token] save error: {e}")
        return False

def _check_admin_token(token):
    return hmac.compare_digest(str(token or ""), load_admin_panel_token())

# Second layer on top of the URL token above: a real password, so the
# admin panel isn't fully exposed to anyone who happens to see the URL once
# (browser history, a screenshot, someone glancing at your screen). CHANGE
# THIS to your own password before relying on it.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "tuck7")

# Third layer, specific to the nuts-reset button only. Someone could log
# into the admin panel with ADMIN_PASSWORD (e.g. a co-moderator you trust
# with bans/leaderboard) without being able to wipe everyone's currency —
# that action needs this separate password too. CHANGE THIS to your own.
RESET_NUTS_PASSWORD = os.environ.get("RESET_NUTS_PASSWORD", "tuck1135$")

# Same pattern, separate passwords — resetting everyone's tech tree or
# cosmetics is just as irreversible as wiping currency, so each gets its
# own gate rather than sharing RESET_NUTS_PASSWORD. CHANGE THESE too.
RESET_TECH_PASSWORD = os.environ.get("RESET_TECH_PASSWORD", "tuck1135$")
RESET_COSMETICS_PASSWORD = os.environ.get("RESET_COSMETICS_PASSWORD", "tuck1135$")

def _admin_authed():
    return session.get("admin_authed") is True

def _require_admin_login(token):
    """For pages the browser navigates to directly. Returns None if fully
    authorized (token + password), otherwise the response to return early —
    a 404 for a wrong/missing token, or a redirect to the password page."""
    if not _check_admin_token(token):
        return ("Not found", 404)
    if not _admin_authed():
        return redirect(f"/admin/{token}/login")
    return None

def _require_admin_login_json(token):
    """Same as above, for endpoints called via fetch() rather than direct
    navigation — returns JSON errors instead of a redirect, since a redirect
    response isn't useful to a fetch() caller. The frontend JS checks for a
    401 and redirects the page itself."""
    if not _check_admin_token(token):
        return jsonify({"error": "not found"}), 404
    if not _admin_authed():
        return jsonify({"error": "not authenticated"}), 401
    return None

# ── Separate, lower-trust mod panel — bans + leaderboard only ─────────────
# The full admin panel is now the OWNER panel (everything: currency/tech/
# cosmetics resets, missions, custom names, dev grants, etc). This is a
# completely separate token + session + password, deliberately not sharing
# any auth state with the owner panel, so it's safe to hand out to a
# co-moderator without giving them anything beyond banning and viewing
# who's online.
MOD_PANEL_TOKEN = "_CiMXNrkfdYux0f8_ScLAD580LbYZXTX"

def _check_mod_token(token):
    return hmac.compare_digest(str(token or ""), MOD_PANEL_TOKEN)

MOD_PANEL_PASSWORD = os.environ.get("MOD_PANEL_PASSWORD", "modpass123")

def _mod_authed():
    return session.get("mod_authed") is True

def _require_mod_login(token):
    if not _check_mod_token(token):
        return ("Not found", 404)
    if not _mod_authed():
        return redirect(f"/modpanel/{token}/login")
    return None

def _require_mod_login_json(token):
    if not _check_mod_token(token):
        return jsonify({"error": "not found"}), 404
    if not _mod_authed():
        return jsonify({"error": "not authenticated"}), 401
    return None

def _auth_username():
    """Username from the request's Bearer/JWT, or None if missing/invalid/forged."""
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    return payload.get("usn") if payload else None
# --- live presence tracking (for the connected-players leaderboard) --------
# There's no real socket-level identity (the /ws handler never learns who
# connected), so "currently connected" is approximated as "made an
# authenticated request in the last PRESENCE_TIMEOUT_SECONDS". The game
# client hits currency/storage/mining endpoints constantly while running,
# so this stays accurate to within about a minute.
#
# There's no field we know for certain the client reports as "APK/app
# version" — but your Discord dev-log webhook dumps full headers + body on
# every request, so if you spot the real field name there, add it to
# _VERSION_HEADER_CANDIDATES / _VERSION_BODY_KEY_CANDIDATES below and it'll
# start showing up correctly. Until then this tries a handful of common
# names and falls back to the raw User-Agent header.
_presence_lock = threading.Lock()
_last_seen = {}      # username -> unix timestamp of last authenticated request
_client_agent = {}   # username -> best-guess client version string

_player_room = {}    # username -> current Photon room code. Populated by the
                      # /game/* webhooks below (the real, working mechanism —
                      # confirmed against a reference backend) and, if you
                      # ever move to WebSocket-capable hosting, also by /ws.
PRESENCE_TIMEOUT_SECONDS = 90

_VERSION_HEADER_CANDIDATES = ("X-Ac-User-Agent", "X-App-Version", "X-Client-Version", "X-Game-Version", "X-Build-Version", "X-Version")
_VERSION_BODY_KEY_CANDIDATES = ("clientVersion", "appVersion", "buildVersion", "gameVersion", "version")

def _guess_client_version():
    for h in _VERSION_HEADER_CANDIDATES:
        v = request.headers.get(h)
        if v:
            return v
    body = request.get_json(silent=True)
    if isinstance(body, dict):
        for k in _VERSION_BODY_KEY_CANDIDATES:
            v = body.get(k)
            if v:
                return str(v)
    return request.headers.get("User-Agent") or "unknown"

def _track_presence():
    username = _auth_username()
    if username:
        key = str(username).strip().lower()
        with _presence_lock:
            _last_seen[key] = time.time()
            _client_agent[key] = _guess_client_version()
_RESEARCH_NODES_PATH = os.path.join(BASE_DIR, "data", "econ_research_nodes.json")

def _research_nodes_map():
    try:
        with open(_RESEARCH_NODES_PATH, "r", encoding="utf-8") as f:
            nodes = json.load(f)
        return {n["id"]: n for n in nodes if isinstance(n, dict) and "id" in n}
    except Exception as e:
        write_log(f"[research] nodes load error: {e}")
        return {}

# @socketIO.on("ws")
def handleconnect():
    socketio.emit({{
        "status_presence_event": {
            "joins": [
                {
                    "user_id": uuid.uuid4().hex,
                    "session_id": uuid.uuid4().hex,
                    "username": "OWNER: THUNDA",
                    "status": "{\"roomCode\":\"67\",\"gameMode\":0,\"appearOffline\":false,\"clientVersion\":\"1.38.0.1672\",\"photonVersion\":\"release\"}"
                }
           ]
       }
    }})
dihhcord = "https://discord.com/api/webhooks/1537307074357231646/oKRNPJ5ZnG0XIiX0s1FoeEl9NI98bnzZYxq_Lr8SltQTOX0m6hTlYsiDOEVwjKi6y7aN"

# Separate webhook just for admin panel actions (keeps this out of your dev-log channel)
ADMIN_WEBHOOK_URL = os.environ.get("ADMIN_WEBHOOK_URL", "https://discord.com/api/webhooks/1537580334416265246/TtniRH0Iyatz2gKKVySIbPNsRexoWYWGRX5x9XNpDVxlXbAjtZf5qZ7OSmD9Ypyr2fsR")

def log_to_admin_discord(message: str):
    try:
        requests.post(ADMIN_WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"[Admin Webhook Error] {e}")

# Separate again from the admin webhook above — just for login/auth activity
# (the login debug snapshot + blocked-login alerts), so it can sit in its
# own private channel instead of wherever ADMIN_WEBHOOK_URL posts.
AUTH_LOG_WEBHOOK_URL = os.environ.get("AUTH_LOG_WEBHOOK_URL", "https://discord.com/api/webhooks/1538263853073436792/KNHS1A9S9feNBAI2kWXeK65dAPMzkquMkUzEhzkrF3-i-Dbh0ze9W2EcTuY6nSohZe27")

def log_to_auth_discord(message: str):
    try:
        requests.post(AUTH_LOG_WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"[Auth Webhook Error] {e}")

# Dedicated channel for ban/unban actions.
BANS_WEBHOOK_URL = os.environ.get("BANS_WEBHOOK_URL", "https://discord.com/api/webhooks/1539029889636896878/E-nXNnscuRNEX-A5bjIpIS2lQHkX3ZYl4mdhoZrDTpAMDPf8hmPIN6BoNRjzFlPSAdd1")

def log_to_bans_discord(message: str):
    try:
        requests.post(BANS_WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"[Bans Webhook Error] {e}")

# Dedicated channel for avatar/cosmetic update activity (storage writes,
# avatar.update saves, purchase.avatarItems).
AVATAR_WEBHOOK_URL = os.environ.get("AVATAR_WEBHOOK_URL", "https://discord.com/api/webhooks/1539030689536548944/C7QshIkaJi0D8CGRLVwBy1a_tPfU_RsVf1HNz4JFf4MQ_PPlnXzLmPEevBdxfk5kP3Yb")

def log_to_avatar_discord(message: str):
    try:
        requests.post(AVATAR_WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"[Avatar Webhook Error] {e}")

PROMO_WEBHOOK_URL = os.environ.get("PROMO_WEBHOOK_URL", "https://discord.com/api/webhooks/1541598571894411346/ypj7Az2_lSWxvvZbycj5J6K5Nr372XUdU91BgCLZhnxBY5a1_F4RL0EPlgyJuiZJVNdS")

def log_to_promo_discord(message: str):
    try:
        requests.post(PROMO_WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"[Promo Webhook Error] {e}")

# The separate real-time presence service (deployed on Render, not here —
# PythonAnywhere has no websocket support). This is a best-effort push:
# if that service isn't deployed yet, is asleep (Render's free tier spins
# down after 15 min idle), or is just slow, the friend request/accept
# ITSELF still succeeds and is saved correctly here regardless — a failed
# push just means the other player finds out next time their own client
# happens to check, not that anything was lost. Short timeout so a slow or
# sleeping instance never makes a friend request feel like it hung.
PRESENCE_SERVICE_URL = os.environ.get("wss://acr-friends.onrender.com", "")
INTERNAL_NOTIFY_SECRET = os.environ.get("INTERNAL_NOTIFY_SECRET", "SuZijRyEfDVaBe7Hwj2gv2M1IUkd4n8k3nkmaNQaKgI")

def _notify_presence_service(target_uid, code, sender_uid, subject, content="{}"):
    if not PRESENCE_SERVICE_URL:
        return
    try:
        requests.post(
            f"{PRESENCE_SERVICE_URL}/internal/notify",
            json={"uid": target_uid, "code": code, "sender_uid": sender_uid, "subject": subject, "content": content},
            headers={"X-Internal-Secret": INTERNAL_NOTIFY_SECRET},
            timeout=2,
        )
    except Exception:
        pass

# Live leaderboard broadcast — pushes to the same presence service used for
# friend notifications above, but this is a completely separate concern:
# no player identity or token involved, just periodically handing the
# render service a fresh snapshot of the connected-players leaderboard so
# it can relay it to whichever browsers are currently watching a
# leaderboard page. Two channels, not one, since the public leaderboard
# deliberately never includes room codes ("reveals exactly where a player
# currently is") while the admin/mod ones do — that distinction has to
# survive all the way through, not get flattened into one payload.
LEADERBOARD_BROADCAST_INTERVAL_SECONDS = 3

def _push_leaderboard_channel(channel, include_room):
    if not PRESENCE_SERVICE_URL:
        return
    try:
        players = _leaderboard_players(include_room=include_room)
        requests.post(
            f"{PRESENCE_SERVICE_URL}/internal/broadcast-leaderboard",
            json={"channel": channel, "players": players},
            headers={"X-Internal-Secret": INTERNAL_NOTIFY_SECRET},
            timeout=2,
        )
    except Exception as e:
        write_log(f"[leaderboard broadcast] {channel} error: {e}")

def _leaderboard_broadcast_loop():
    while True:
        _push_leaderboard_channel("public", include_room=False)
        _push_leaderboard_channel("full", include_room=True)
        time.sleep(LEADERBOARD_BROADCAST_INTERVAL_SECONDS)

if PRESENCE_SERVICE_URL:
    threading.Thread(target=_leaderboard_broadcast_loop, daemon=True).start()

# Dedicated channel for unrecognized-client alerts (server-key mismatch —
# see afhjkfh for the honesty note on what this does/doesn't actually verify).
PACKAGE_ALERT_WEBHOOK_URL = os.environ.get("PACKAGE_ALERT_WEBHOOK_URL", "https://discord.com/api/webhooks/1539034197707071568/Rs60imxZgYRXvL8_vEIZnmDfLsGjhg3O_C1QTU5OcfkDGyCPZhwVdeA9ickXurxV5Xj5")

def log_to_package_alert_discord(message: str):
    try:
        requests.post(PACKAGE_ALERT_WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"[Package Alert Webhook Error] {e}")

def log_to_discord(message: str):
    try:
        requests.post(dihhcord, json={"content": message})
    except Exception as e:
        print(f"[Webhook Error] {e}")

@app.before_request
def log_request():
    try:
        headers = dict(request.headers)
        path = request.path
        queries = request.args.to_dict()
        body = request.get_json(silent=True)
        if body is None and request.form:
            body = request.form.to_dict()
        if body is None:
            body = request.data.decode(errors="ignore") or "(empty)"
        else:
            body = json.dumps(body, indent=2)

        message = (
            f"📨 **{request.method} {path}**\n"
            f"🔍 Query: ```json\n{json.dumps(queries, indent=2)}\n```\n"
            f"🧾 Headers: ```json\n{json.dumps(headers, indent=2)}\n```\n"
            f"📦 Body: ```json\n{body}\n```"
        )

        log_to_discord(message)

    except Exception as e:
        print(f"[Log Error] {e}")

@app.after_request
def log_response(response):
    try:
        resp_data = response.get_data(as_text=True)
        headers = dict(response.headers)

        message = (
            f"📤 **Response {response.status}**\n"
            f"🧾 Headers: ```json\n{json.dumps(headers, indent=2)}\n```\n"
            f"📦 Body: ```json\n{resp_data[:1500]}\n```"  # limit length
        )

        log_to_discord(message)

    except Exception as e:
        print(f"[Response Log Error] {e}")

    return response

@app.route("/3/v2/rpc/research.unlock", methods=["POST"])
@app.route("/v2/rpc/research.unlock", methods=["POST"])
@app.route("/nnnnaakamacloud.c/v2/rpc/research.unlock", methods=["POST"])
def cavaedataavataRRRRRRrpurchase():
    username = _auth_username()
    if not username:
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": "InvalidToken"})}), 403

    raw = request.get_data(as_text=True) or "{}"
    try:
        data = json.loads(raw)
        if isinstance(data, str):
            data = json.loads(data)
    except Exception:
        data = {}
    node_id = None
    if isinstance(data, dict):
        node_id = data.get("nodeID") or data.get("node_id") or data.get("id")
    elif isinstance(data, str):
        node_id = data.strip()
    if not node_id:
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": "ResearchNodeNotFound"})}), 400

    node_def = _research_nodes_map().get(node_id, {})

    with _research_unlock_lock:
        saved = get_user_items(username, "user_inventory", "research")
        if saved is None:
            # Seed from the default storage research list so unlocking one node
            # doesn't wipe the player's preset nodes.
            base = _storage_defaults(request.path, username)
            dr = next((o for o in base
                       if o.get("collection") == "user_inventory" and o.get("key") == "research"), None)
            try:
                current_nodes = set(json.loads(dr["value"]).get("nodes", [])) if dr else set()
            except Exception:
                current_nodes = set()
        else:
            try:
                val = saved.get("value") if isinstance(saved, dict) else saved
                if isinstance(val, str):
                    val = json.loads(val)
                current_nodes = set((val or {}).get("nodes", []))
            except Exception:
                current_nodes = set()

        if node_id in current_nodes:
            return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": "AlreadyUnlocked",
                                                   "wallet": _wallet_rpc(username),
                                                   "inventoryResearchNodes": list(current_nodes)})}), 200

        price = int(node_def.get("price", 0) or 0)
        cur = get_user_currency(username)
        rp = int(cur.get("rp", 0))
        if rp < price:
            return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": "InsufficientFunds",
                                                   "wallet": _wallet_rpc(username),
                                                   "inventoryResearchNodes": list(current_nodes)})}), 200

        update_user_currency(username, rp=rp - price)
        current_nodes.add(node_id)
        save_user_items(username, {"value": json.dumps({"nodes": list(current_nodes)})},
                        "user_inventory", "research")

    return jsonify({"payload": json.dumps({"succeeded": True, "errorCode": "",
                                           "wallet": _wallet_rpc(username),
                                           "inventoryResearchNodes": list(current_nodes)})}), 200

@app.route("/", methods=["GET", "POST"])
@app.route("/nnnnaakamacloud.c/", methods=["GET", "POST"])
def fawhjfajkfhkj():
    return jsonify({"token": "bb"}), 200

@app.route("/Halloween/authenticEate/Redo/Sigma", methods=['GET', 'POST'])
def tesssssssst():
    userid = secrets.token_hex(16)
    sessionid = secrets.token_hex(16)
    return jsonify({
        "Authenticated": "true",
        "ResultCode": 1,
        "UserId": userid,
        "SessionID": sessionid,
        "Message": "Authenticated successfully"
    })

def BearerGeneration(ussername, client_user_agent=None):
    now = int(time.time())
    id = generate_deterministic_uid(ussername)
    id2 = uuid.uuid4().hex
    refreshpayload = {
        'tid': id2,
        'uid': id,
        'usn': ussername,
        'vrs': {
            'authID': secrets.token_hex(16),
            # Real client version, captured from the login request's
            # X-Ac-User-Agent header — this used to be a hardcoded fake
            # value, which meant every token claimed the same fake build
            # regardless of who actually logged in. Embedding the real one
            # here is what lets later requests (like the avatar catalog)
            # know which client they're really talking to.
            'clientUserAgent': client_user_agent or "unknown",
            'loginType': "meta_quest"
        },
        'exp': now + 3600,
        'iat': now
    }
    token = make_token(refreshpayload)
    return jsonify({"token": token}), 200

# Toggle for the server-key gate below. RE-ENABLED with a freshly-generated
# secret — the previous one was never confirmed to have actually been
# patched into the client (you were searching for the raw decoded key in
# the metadata, but that was a long time and many other changes ago). Same
# fundamental limitation as before: this is a single static string sent by
# every install, extractable by anyone willing to pull it from the APK or
# sniff their own traffic. It raises the bar (the WIDELY-KNOWN original key
# no longer works) but isn't unbeatable — if this one leaks too, generate a
# new one and patch it in again, same process. The bypass-list feature
# (seeded with your own username) is still here as a safety net.
REQUIRE_SERVER_KEY_ON_AUTH = True

@app.route("/3/v2/account/authenticate/custom", methods=["POST", "GET"])
@app.route("/v2/account/authenticate/custom", methods=["POST", "GET"])
@app.route("/nnnnaakamacloud.c/v2/account/authenticate/custom", methods=["POST", "GET"])
def afhjkfh():
    # One-time debug snapshot of THIS call only, sent to the auth webhook
    # (its own private channel) so it's easy to find — your dev-log webhook
    # logs every single RPC, which makes hunting for one login call tedious.
    body_for_debug = request.get_json(silent=True)
    if body_for_debug is None:
        # Not valid/labeled JSON — fall back to the raw bytes so nothing
        # gets silently dropped from the debug view (this is what was
        # happening: Content-Length showed data but Body showed empty).
        raw = request.data.decode("utf-8", errors="ignore")
        body_debug_str = raw if raw else "(empty)"
    else:
        body_debug_str = json.dumps(body_for_debug, indent=2)
    log_to_auth_discord(
        f"🔍 **Login attempt debug**\n"
        f"🌐 IP: `{request.remote_addr}`\n"
        f"🔗 Query args: ```json\n{json.dumps(request.args.to_dict(), indent=2)}\n```\n"
        f"🧾 Headers: ```json\n{json.dumps(dict(request.headers), indent=2)}\n```\n"
        f"📦 Body: ```\n{body_debug_str}\n```"
    )

    username = request.args.get("username", "MAGICMAN69420")

    if REQUIRE_SERVER_KEY_ON_AUTH:
        auth_header = request.headers.get("Authorization", "")
        write_log(f"[auth] authenticate/custom Authorization header seen: {auth_header!r}")
        if auth_header != load_server_key():
            if auth_header == ORIGINAL_SERVER_KEY and _can_use_old_key(username):
                write_log(f"[auth] original server key accepted for allowlisted username {username!r}")
            elif _is_bypassed(username):
                write_log(f"[auth] server-key mismatch bypassed for allowlisted username {username!r}")
            else:
                # Heads up in the code, not just the chat: this checks the
                # app's server key, not the literal Android package name —
                # that's never transmitted over HTTP unless the client code
                # explicitly sends it, which this one doesn't. This is the
                # closest reliable signal actually available.
                log_to_package_alert_discord(
                    f"🚨 **Unrecognized client connection attempt**\n"
                    f"🌐 IP: `{request.remote_addr}`\n"
                    f"👤 Claimed username: `{username or '(none)'}`\n"
                    f"🧾 Authorization sent: `{auth_header or '(none)'}`\n"
                    f"🧾 User-Agent: `{request.headers.get('X-Ac-User-Agent', '(none)')}`"
                )
                return jsonify({"error": "Authorization Incorrect"}), 401
    if username == "MAGICMAN69420":
        return jsonify ({"error": "banned for 48 hours REASON: You have been banned."}), 403

    ban_reason = _ban_reason(username)
    if ban_reason is not None:
        # Real Nakama server source (heroiclabs/nakama, core_authenticate.go)
        # returns exactly this for a banned user: grpc code 7 (PermissionDenied)
        # with the literal message "User account banned." — confirmed from the
        # official open-source server code, and matches the real error envelope
        # shape {"error", "message", "code"} confirmed from Nakama's own
        # api_rpc.go. Your custom reason rides along in an extra "reason" field
        # in case anything downstream reads it, but per your friend's test
        # (banned themselves, saw only the generic message, no hardcoded
        # reason-display anywhere in their code), the client's ban screen very
        # likely shows its own fixed string regardless of what's here — this
        # should get the CORRECT dedicated ban screen to trigger, which the
        # exact wrong shape was probably preventing, but likely won't surface
        # the reason text itself.
        return jsonify({
            "error": "User account banned.",
            "message": "User account banned.",
            "code": 7,
            "reason": ban_reason
        }), 403

    # Newer clients send this as the X-Ac-User-Agent header. At least one
    # older client build (1.1.2) doesn't — confirmed it sends "ua" as a
    # query param on its /auth/photon call, but that alone didn't fix it,
    # meaning the LOGIN call itself apparently doesn't send that either.
    # Adding the one other confirmed-real pattern from this session: 0.11.x
    # clients send it as vars.clientUserAgent in the request BODY. Trying
    # header, then query param, then body field — whichever's actually there.
    # body_for_debug can be None even when the body IS valid JSON — Flask's
    # get_json() refuses to parse without a Content-Type: application/json
    # header, which this client doesn't send. Confirmed directly: the real
    # request body had clientUserAgent right there in vars, but this exact
    # gap meant it was never actually read. Falling back to the raw bytes
    # (same pattern already used elsewhere in this file, e.g. Storage())
    # instead of trusting get_json() alone.
    body_json = body_for_debug
    if body_json is None:
        try:
            body_json = json.loads(request.data.decode("utf-8", errors="ignore") or "{}")
        except Exception:
            body_json = {}
    body_vars = body_json.get("vars") if isinstance(body_json, dict) else None
    body_client_ua = body_vars.get("clientUserAgent") if isinstance(body_vars, dict) else None
    client_ua = request.headers.get("X-Ac-User-Agent") or request.args.get("ua") or body_client_ua
    _check_version_anomaly(client_ua, username)

    skid = BearerGeneration(username, client_ua)
    return skid

@app.route("/3/v2/rpc/mining.balance", methods=["POST", "GET"])
@app.route("/v2/rpc/mining.balance", methods=["POST", "GET"])
@app.route("/nnnnaakamacloud.c/v2/rpc/mining.balance", methods=["POST", "GET"])
def CaveDatamnnnniniangbalance():
    username = _auth_username()
    if not username:
        return jsonify({"payload": json.dumps({"hardCurrency": 30000, "researchPoints": 40000})}), 200
    cur = get_user_currency(username)
    return jsonify({"payload": json.dumps({
        "hardCurrency": int(cur.get("cc", 0)),
        "researchPoints": int(cur.get("rp", 0)),
    })}), 200

@app.route("/3/v2/rpc/mining.collect", methods=["POST"])
@app.route("/v2/rpc/mining.collect", methods=["POST"])
@app.route("/nnnnaakamacloud.c/v2/rpc/mining.collect", methods=["POST"])
def mining_collect():
    """Credit mined currency and return the CollectMiningRewardResponseInternal
    shape. Returning succeeded=true is what stops the client's retry loop
    (the old catch-all reply had no `succeeded`, so it re-fired forever)."""
    username = _auth_username()

    def _ok():
        wallet = _wallet_rpc(username) if username else {"softCurrency": 0, "hardCurrency": 0, "researchPoints": 0}
        return jsonify({"payload": json.dumps({
            "succeeded": True,
            "errorCode": "None",
            "balance": {"hardCurrency": 0, "researchPoints": 0},
            "wallet": wallet,
        })}), 200

    if not username:
        return _ok()

    try:
        body = request.get_json(force=True, silent=True) or {}
        if isinstance(body, str):
            body = json.loads(body) if body else {}
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    try:
        hc = max(0, int(body.get("hardCurrency") or 0))
    except Exception:
        hc = 0
    try:
        rp = max(0, int(body.get("researchPoints") or 0))
    except Exception:
        rp = 0

    if hc or rp:
        cur = get_user_currency(username)
        update_user_currency(username, cc=int(cur.get("cc", 0)) + hc, rp=int(cur.get("rp", 0)) + rp)

    return _ok()

@app.route("/3/v2/rpc/updateWalletSoftCurrency", methods=["POST", "GET"])
@app.route("/v2/rpc/updateWalletSoftCurrency", methods=["POST", "GET"])
@app.route("/nnnnaakamacloud.c/v2/rpc/updateWalletSoftCurrency", methods=["POST", "GET"])
def wowie():
    username = _auth_username()
    if not username:
        return jsonify({"error": "No username found"}), 401
    try:
        data = request.get_json(force=True, silent=True)
        if isinstance(data, str):
            data = json.loads(data)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    try:
        amount = int(data.get("amount", 0) or 0)
    except Exception:
        amount = 0
    cur = get_user_currency(username)
    new_nuts = max(0, int(cur.get("nuts", 0)) + amount)
    update_user_currency(username, nuts=new_nuts)
    return jsonify({"success": True, "new_balance": new_nuts}), 200

@app.route("/3/v2/account/link/device", methods=["POST", "GET"])
@app.route("/v2/account/link/device", methods=["POST", "GET"])
@app.route("/nnnnaakamacloud.c/v2/account/link/device", methods=["POST", "GET"])
def fsaf():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "invalid token"}), 403
    try:
        us1erid = payload["uid"]
    except Exception:
        return jsonify({"error": "invalid token"}), 403
    return jsonify({
        "id": uuid.uuid4().hex,
        "user_id": us1erid,
        "linked": "true",
        "create_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    }), 200


@app.route("/3/v2/account/session/refresh", methods=["POST", "GET"])
@app.route("/v2/account/session/refresh", methods=["POST", "GET"])
@app.route("/nnnnaakamacloud.c/v2/account/session/refresh", methods=["POST", "GET"])
def a():
    now = int(time.time())
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]

    try:
        parts = token.split(".")
        if len(parts) < 2:
            return jsonify({"error": "invalid token"}), 403

        payload = b64decode_json(parts[1])
        payload["exp"] = now + 3600
        payload["iat"] = now

        header = {'alg': 'HS256', 'typ': 'JWT'}
        signature = secrets.token_urlsafe(32)
        new_token = f"{b64encode_json(header)}.{b64encode_json(payload)}.{signature}"
    except Exception:
        return jsonify({"error": "invalid token"}), 403

    return jsonify({"token": new_token}), 200



def CaveDatarefresh():
    Authorization = request.headers.get("Authorization")
    data = request.get_json()
    token = data.get("token")
    if Authorization != "Basic NlVSdVRTbERLS2ZZYnVEVzo=":
        return jsonify({
            "Authenticated": "false",
            "message": "Authorization Incorrect",
            "error": "Authorization Header Incorrect"
        }), 401
    bearer = SessionRefresh(token)
    return jsonify(bearer), 200

@app.route("/nnnnaakamacloud/api/v1/preauth", methods=["POST"])
def preauth():
    playershit = request.get_json()
    CurrentPlayerVersion = "Skidding"
    AttestID = str(uuid.uuid4())
    PUI = playershit.get("platformUserID")
    DeviceID = request.headers.get("X-Device-Id")
    FBItypeshit = request.headers.get("User-Agent")
    expiration = ilowkeydontknowwhy()
    attestNonce = skidatoken(PUI, DeviceID, FBItypeshit)
    return jsonify ({"time": expiration, "updateType": CurrentPlayerVersion, "attestID": AttestID, "attestNonce": attestNonce})

@app.route("/3/v2/rpc/avatar.update", methods=["POST", "GET"])
@app.route("/v2/rpc/avatar.update", methods=["GET", "POST", "PUT"])
@app.route("/nnnnaakamacloud.c/v2/rpc/avatar.update", methods=["POST"])
def avataruaannnnaaaaaapdate():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "invalid token"}), 403
    username = payload["usn"]
    client_version = _client_version_from_token(payload)

    if request.method == "GET":
        # Read back whatever was last saved, so a fresh login (or the client
        # re-checking) sees the actual equipped appearance instead of nothing.
        saved = get_user_items(username, "user_avatar", "0")
        if isinstance(saved, dict) and saved.get("value") is not None:
            try:
                state = json.loads(saved["value"])
                if not isinstance(state, dict):
                    state = {}
            except Exception:
                state = {}
        else:
            state = {"primaryColor": "FFFFFF", "accessories": []}
        state = _strip_unknown_avatar_items(state, client_version)
        # Also include the owned-items list under the same field name your
        # promo.redeem endpoint already uses elsewhere in this codebase — a
        # sign this exact field name is meaningful to the real client somewhere.
        state["inventoryAvatarItems"] = _get_owned_cosmetics(username, client_version)
        return jsonify({"payload": json.dumps(state)}), 200

    # WRITE (POST/PUT): confirmed from real traffic that the raw HTTP body is
    # itself a JSON-encoded STRING (e.g. "{\"primaryColor\":...}" — a quoted
    # string, not a bare object), matching the same "payload" convention this
    # backend already uses for every RPC response. Handle that plus a plain
    # object body defensively, in case a different client build sends it
    # un-wrapped.
    parsed = request.get_json(silent=True)
    state = None
    if isinstance(parsed, dict):
        state = parsed
    elif isinstance(parsed, str):
        try:
            inner = json.loads(parsed)
            if isinstance(inner, dict):
                state = inner
        except Exception:
            state = None
    if state is None:
        try:
            raw = request.data.decode("utf-8", errors="ignore")
            inner = json.loads(raw)
            if isinstance(inner, str):
                inner = json.loads(inner)
            if isinstance(inner, dict):
                state = inner
        except Exception:
            state = None

    if state is not None:
        # Merge onto the existing saved state rather than overwriting, so a
        # partial update (e.g. only primaryColor) can't wipe out accessories
        # that were set in an earlier call.
        existing = get_user_items(username, "user_avatar", "0")
        merged = {}
        if isinstance(existing, dict) and isinstance(existing.get("value"), str):
            try:
                loaded = json.loads(existing["value"])
                if isinstance(loaded, dict):
                    merged = loaded
            except Exception:
                merged = {}
        # A legacy client that just READ this state got it stripped (see
        # _strip_unknown_avatar_items) — slots it can't see come back as
        # null, lists come back pruned. If it then sends an update (e.g.
        # just changing color) and blindly echoes that stripped view back,
        # a naive merge would commit those nulls/prunes as real edits and
        # permanently delete a modern player's loadout. So for a legacy
        # client: a falsy slot value is treated as our own truncation
        # echoing back, not a deliberate clear; list fields get the new
        # values merged with whatever was previously hidden rather than
        # overwritten outright.
        legacy = _allowed_avatar_types_for(client_version) is not None
        for k, v in state.items():
            if legacy and k in _AVATAR_SLOTS and not v:
                continue
            if legacy and k in ("accessories", "items") and isinstance(v, list):
                prev = merged.get(k) if isinstance(merged.get(k), list) else []
                allowed_now = _allowed_avatar_ids(client_version)
                hidden = [i for i in prev if i not in allowed_now]
                merged[k] = list(v) + [i for i in hidden if i not in v]
                continue
            merged[k] = v
        save_user_items(
            username,
            {
                "value": json.dumps(merged),
                "update_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "version": secrets.token_hex(8),
            },
            "user_avatar",
            "0"
        )
        log_to_avatar_discord(
            f"🎭 **avatar.update saved**\n"
            f"👤 User: `{username}`\n"
            f"📦 Now: ```json\n{json.dumps(merged, indent=2)}\n```"
        )
    else:
        raw = request.data.decode("utf-8", errors="ignore")
        log_to_avatar_discord(
            f"⚠️ **avatar.update — could not parse body**\n"
            f"👤 User: `{username}`\n"
            f"📦 Raw: ```\n{raw or '(empty)'}\n```"
        )

    return {
        "payload": "{\"succeeded\":true,\"errorCode\":\"\"}"
    }
# ids=5ceae17b8521cc25d57c8cde09af7d24
@app.route("/v2/user", methods=["POST", "GET"])
@app.route("/nnnnaakamacloud.c/v2/user", methods=["POST", "GET"])
def sssss():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "invalid token"}), 403

    # Real Nakama account-lookup convention allows repeated ?ids=&ids=... for
    # batch lookup. This previously ignored whatever was requested entirely
    # and just returned the CALLER's own username — meaning when another
    # player's client asked "who is this uid I'm seeing", it got back
    # nonsense that didn't describe that player at all. That's the leading
    # suspect for "cosmetics only show client-side".
    requested_ids = request.args.getlist("ids")
    requester_version = _client_version_from_token(payload)
    lookup = _load_uid_lookup()

    if not requested_ids:
        # No ids requested — preserve old behavior (self-lookup) in case
        # something else relies on that shape.
        return jsonify({"username": payload["usn"], "id": None})

    users = []
    for uid in requested_ids:
        uname = lookup.get(uid)
        if not uname:
            continue
        cur = get_user_currency(uname)
        wallet = {"hardCurrency": int(cur.get("cc", 0)), "softCurrency": int(cur.get("nuts", 0)), "researchPoints": int(cur.get("rp", 0))}
        avatar_saved = get_user_items(uname, "user_avatar", "0")
        appearance = {}
        if isinstance(avatar_saved, dict) and isinstance(avatar_saved.get("value"), str):
            try:
                loaded = json.loads(avatar_saved["value"])
                if isinstance(loaded, dict):
                    appearance = loaded
            except Exception:
                appearance = {}
        appearance = _strip_unknown_avatar_items(appearance, requester_version)
        # Confirmed real from the reference's own working version of this
        # same lookup-by-id mechanism (_lookup_users_by_ids there) — this is
        # what actually powers the leaderboard's display names, not the
        # leaderboard entry's own username field. This endpoint had the
        # same raw-username bug the leaderboard entries did.
        name_entry = _get_custom_name_entry(uname)
        display = (name_entry.get("display_name") or uname) if name_entry else uname
        users.append({
            "id": uid,
            "username": display,
            "display_name": display,
            # Modeled on /v2/account's own convention (isDeveloper already
            # lives in "metadata" there) — best-reasoned guess, not
            # confirmed against real traffic yet, since no other player has
            # been observed calling this endpoint so far.
            "metadata": json.dumps({**wallet, **appearance}),
        })

    log_to_auth_discord(
        f"👥 **/v2/user lookup**\n"
        f"🔎 Requested ids: `{requested_ids}`\n"
        f"✅ Resolved: `{[u['username'] for u in users]}`\n"
        f"❓ Unresolved: `{[i for i in requested_ids if i not in lookup]}`"
    )

    return jsonify({"users": users})

@app.route("/3/v2/rpc/promo.redeem", methods=["POST", "GET"])
@app.route("/v2/rpc/promo.redeem", methods=["POST", "GET"])
def autisticpersonality():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "invalid token"}), 403
    username = payload["usn"]

    # Same "may be a JSON-encoded string" RPC convention used elsewhere in
    # this file (e.g. avatar.update) — get_json() alone isn't reliable here.
    parsed = request.get_json(silent=True)
    body = None
    if isinstance(parsed, dict):
        body = parsed
    elif isinstance(parsed, str):
        try:
            inner = json.loads(parsed)
            if isinstance(inner, dict):
                body = inner
        except Exception:
            body = None
    if body is None:
        try:
            raw = request.data.decode("utf-8", errors="ignore")
            inner = json.loads(raw)
            if isinstance(inner, str):
                inner = json.loads(inner)
            if isinstance(inner, dict):
                body = inner
        except Exception:
            body = {}
    if not isinstance(body, dict):
        body = {}

    raw_code = str(body.get("code", "") or "").strip()
    code_key = raw_code.upper()

    def _fail(error_code):
        log_to_promo_discord(
            f"❌ **Promo redeem failed**\n"
            f"👤 User: `{username}`\n"
            f"🎟️ Code entered: `{raw_code}`\n"
            f"⚠️ Reason: `{error_code}`"
        )
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": error_code})}), 200

    if not code_key:
        return _fail("MissingCode")

    codes = load_promo_codes()
    code_def = codes.get(code_key)
    if code_def is None:
        return _fail("InvalidCode")

    expires = code_def.get("expires")
    if expires:
        try:
            expiry_date = datetime.strptime(expires, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
            if datetime.now(timezone.utc) > expiry_date:
                return _fail("Expired")
        except Exception:
            pass  # malformed date on our end shouldn't block a real redemption

    redemptions = load_promo_redemptions()
    already = redemptions.get(username, [])
    if code_key in already:
        return _fail("AlreadyRedeemed")

    nuts_reward = int(code_def.get("nuts", 0) or 0)
    cc_reward = int(code_def.get("cc", 0) or 0)
    rp_reward = int(code_def.get("rp", 0) or 0)
    cosmetic_rewards = code_def.get("cosmetics", [])
    if not isinstance(cosmetic_rewards, list):
        cosmetic_rewards = []

    cur = get_user_currency(username)
    new_nuts = int(cur.get("nuts", 0)) + nuts_reward
    new_cc = int(cur.get("cc", 0)) + cc_reward
    new_rp = int(cur.get("rp", 0)) + rp_reward
    update_user_currency(username, nuts=new_nuts, cc=new_cc, rp=new_rp)

    # Cosmetics go through the same per-person grant list the exclusion
    # system already checks — NOT a direct save write. Under the current
    # "everyone owns everything except exclusions" design, a normal item is
    # already owned by default, so this only actually matters for items
    # that are currently excluded; this grant makes it show up for this
    # specific player regardless.
    if cosmetic_rewards:
        grants = load_per_person_cosmetics()
        player_grants = grants.setdefault(username, [])
        for item_id in cosmetic_rewards:
            if item_id not in player_grants:
                player_grants.append(item_id)
        save_per_person_cosmetics(grants)

    already.append(code_key)
    redemptions[username] = already
    save_promo_redemptions(redemptions)

    log_to_promo_discord(
        f"🎁 **Promo code redeemed**\n"
        f"👤 User: `{username}`\n"
        f"🎟️ Code: `{code_key}`\n"
        f"💰 Reward: `{nuts_reward}` nuts, `{cc_reward}` cc, `{rp_reward}` rp\n"
        + (f"🎽 Cosmetics: `{', '.join(cosmetic_rewards)}`\n" if cosmetic_rewards else "")
        + f"📊 New balance: `{new_nuts}` nuts, `{new_cc}` cc, `{new_rp}` rp"
    )

    return jsonify({
        "payload": json.dumps({
            "succeeded": True,
            "errorCode": "",
            "wallet": {"softCurrency": new_nuts, "hardCurrency": new_cc, "researchPoints": new_rp},
        })
    }), 200

@app.route("/3/v2/account", methods=["POST", "GET"])
@app.route("/v2/account", methods=["GET", "POST", "PUT"])
@app.route("/nnnnaakamacloud.c/v2/account", methods=["GET", "POST", "PUT"])
def CaaveDataccount():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "invalid token"}), 403
    username = payload["usn"]
    client_version = _client_version_from_token(payload)

    # The account id MUST equal the storage user_id (both derived from the
    # username) or nothing the player saves can be tied back to them.
    uid = generate_deterministic_uid(username)
    custom_id = secrets.token_hex(8)

    cur = get_user_currency(username)
    wallet = {"hardCurrency": int(cur.get("cc", 0)), "softCurrency": int(cur.get("nuts", 0)), "researchPoints": int(cur.get("rp", 0))}

    # Custom display name (cosmetic — color/size rich-text tags) and
    # isDeveloper (a real privilege flag) are now separate, admin-editable
    # lists — see /admin/<token>/names and /admin/<token>/devs. Having a
    # styled name no longer implies developer status on its own.
    entry = _get_custom_name_entry(username)
    if entry:
        disp_user = entry.get("display_username") or username
        disp_name = entry.get("display_name") or username
        cid = entry.get("custom_id") or custom_id  # empty string in the file means "use a fresh random one"
    else:
        disp_user, disp_name, cid = username, username, custom_id
    is_dev = _is_dev_user(username)

    # Nakama's IApiAccount.Wallet and user.metadata are STRING fields — the
    # client JSON-parses them into ApiUserWallet / ApiUserMetadata. Sending them
    # as objects leaves the string null, the wallet parse fails, and soft
    # currency falls back to the -1 sentinel. They must be json.dumps strings.
    #
    # inventoryAvatarItems added here as our leading theory for why cosmetics
    # never appear on some older clients: this field name is already used
    # elsewhere in this codebase (promo.redeem), suggesting the real client
    # reads owned cosmetics from account-fetch itself rather than a separate
    # call — which would also explain why opening the outfit changer makes no
    # network request of its own (it's already cached from login).
    return jsonify({
        "user": {
            "id": uid,
            "username": disp_user,
            "display_name": disp_name,
            "lang_tag": "en",
            "metadata": json.dumps({"isDeveloper": is_dev}),
            "edge_count": 240,
            "create_time": "2024-08-24T04:20:56Z",
            "update_time": "2025-07-25T18:41:17Z"
        },
        "wallet": json.dumps({"stashCols": 8, "stashRows": 8, **wallet, "inventoryAvatarItems": _get_owned_cosmetics(username, client_version)}),
        "custom_id": cid
    })


def wip():
    return jsonify({"error": "small issue in the backend. working on a fix."})

def CaaveDataccount():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if username == "the_idiot12":
        return jsonify({
        "user": {
            "id": uuid.uuid4().hex,
            "username": "<color=purple>Tuck</color>: the_idiot12",
            "display_name": "<color=purple>Tuck</color> Tuck",
            "lang_tag": "en",
            "metadata": {'isDeveloper': True},
            "edge_count": 240,
            "create_time": "2024-08-24T04:20:56Z",
            "update_time": "2025-07-25T18:41:17Z"
        },
        "wallet": {
            'stashCols': 8, 'stashRows': 8,
            'hardCurrency': 1000000,
            'softCurrency': 1000000,
            'researchPoints': 1000000
        },
        "custom_id": custom_id
    })
    else:
        return jsonify({
        "user": {
            "id": uuid.uuid4().hex,
            "username": username,
            "display_name": username,
            "lang_tag": "en",
            "metadata": {'isDeveloper': False},
            "edge_count": 240,
            "create_time": "2024-08-24T04:20:56Z",
            "update_time": "2025-07-25T18:41:17Z"
        },
        "wallet": {
            'stashCols': 8, 'stashRows': 8,
            'hardCurrency': 1000000,
            'softCurrency': 1000000,
            'researchPoints': 1000000
        },
        "custom_id": "4938276150923746"
    })


@app.route("/3/v2/storage/econ_avatar_items", methods=["GET", "POST", "PUT"])
@app.route("/v2/storage/econ_avatar_items", methods=["GET", "POST", "PUT"])
@app.route("/nnnnaakamacloud.c/v2/storage/econ_avatar_items", methods=["GET", "POST", "PUT"])
def CavennnnDataaeconavataritems():
    # Filter the catalog to what this specific client version can actually
    # handle — confirmed from a working reference backend that this is
    # required: it sends old clients a reduced catalog (674 of 754 items for
    # a 1.8-era client), not the full list. No token / unparseable version
    # falls back to "show everything" rather than guessing wrong.
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    client_version = None
    if token:
        token_payload = decode_verified_token(token)
        if token_payload:
            client_version = _client_version_from_token(token_payload)

    data = _load_econ_catalog_file("econ_avatar_items.json") or []
    newdata = {"objects": []}
    for e in data:
        if not _avatar_item_allowed(e, client_version):
            continue
        newdata["objects"].append({
            "collection": "econ_avatar_items",
            "key": e["id"],
            "user_id": "00000000-0000-0000-0000-000000000000",
            "value": json.dumps(e),
            "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
            "permission_read": 2,
            "create_time": "2025-05-28T16:03:59Z",
            "update_time": "2025-06-11T16:16:56Z"
        })

    return jsonify(newdata)

@app.route('/3/v2/rpc/attest.start', methods=['POST'])
@app.route('/v2/rpc/attest.start', methods=['POST'])
@app.route('/nnnnaakamacloud.c/v2/rpc/attest.start', methods=['POST'])
def CaveaDatannnnatteststart():
    return jsonify({
        'payload': json.dumps({
            'status': 'success',
            'attestResult': 'Valid',
            'message': 'Attestation validated'
        })
    })

@app.route("/3/v2/storage/econ_gameplay_items", methods=["GET", "POST", "PUT"])
@app.route("/v2/storage/econ_gameplay_items", methods=["GET", "POST", "PUT"])
@app.route("/nnnnaakamacloud.c/v2/storage/econ_gameplay_items", methods=["GET", "POST", "PUT"])
def CaveDatannnngaameplayitems():
    data = _load_econ_catalog_file("econ_gameplay_items.json") or []
    newdata = {"objects": []}
    for e in data:
        newdata["objects"].append({
            "collection": "econ_gameplay_items",
            "key": e["id"],
            "user_id": "00000000-0000-0000-0000-000000000000",
            "value": json.dumps(e),
            "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
            "permission_read": 2,
            "create_time": "2025-05-28T16:03:59Z",
            "update_time": "2025-06-11T16:16:56Z"
        })

    return jsonify(newdata)

@app.route("/3/v2/storage/econ_research_nodes", methods=["GET", "POST", "PUT"])
@app.route("/v2/storage/econ_research_nodes", methods=["GET", "POST", "PUT"])
@app.route("/nnnnaakamacloud.c/v2/storage/econ_research_nodes", methods=["GET", "POST", "PUT"])
def CaveaDatannnnresearchnodes():
    data = _load_econ_catalog_file("econ_research_nodes.json") or []
    newdata = {"objects": []}
    for e in data:
        newdata["objects"].append({
            "collection": "econ_research_nodes",
            "key": e["id"],
            "user_id": "00000000-0000-0000-0000-000000000000",
            "value": json.dumps(e),
            "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
            "permission_read": 2,
            "create_time": "2025-05-28T16:03:59Z",
            "update_time": "2025-06-11T16:16:56Z"
        })

    return jsonify(newdata)

@app.route("/3/v2/storage/econ_products", methods=["GET", "POST", "PUT"])
@app.route("/v2/storage/econ_products", methods=["GET", "POST", "PUT"])
@app.route("/nnnnaakamacloud.c/v2/storage/econ_products", methods=["GET", "POST", "PUT"])
def CaaveDannnntaeconproducts():
    data = _load_econ_catalog_file("econ_products.json") or []

    if not isinstance(data, list):
        write_log(f"[econ catalog] econ_products.json loaded but not a list: {type(data)}")
        data = []

    newdata = {"objects": []}

    for e in data:
        if not isinstance(e, dict):
            continue

        item_id = e.get("id")
        if not item_id:
            continue

        newdata["objects"].append({
            "collection": "econ_products",
            "key": item_id,
            "user_id": "00000000-0000-0000-0000-000000000000",
            "value": json.dumps(e),
            "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
            "permission_read": 2,
            "create_time": "2025-05-28T16:03:59Z",
            "update_time": "2025-06-11T16:16:56Z"
        })

    return jsonify(newdata)

@app.route("/3/v2/storage/econ_mining_ores", methods=["GET", "POST", "PUT"])
@app.route("/v2/storage/econ_mining_ores", methods=["GET", "POST", "PUT"])
@app.route("/nnnnaakamacloud.c/v2/storage/econ_mining_ores", methods=["GET", "POST", "PUT"])
def CaveDataeconminingores():
    data = _load_econ_catalog_file("econ_mining_ores.json") or {}
    if not isinstance(data, dict):
        data = {}

    newdata = {"objects": []}

    ores = data.get("ores", [])
    for e in ores:
        newdata["objects"].append({
            "collection": "econ_mining_ores",
            "key": e.get("id", ""),
            "user_id": "00000000-0000-0000-0000-000000000000",
            "value": json.dumps(e),
            "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
            "permission_read": 2,
            "create_time": "2025-05-28T16:03:59Z",
            "update_time": "2025-06-11T16:16:56Z"
        })

    return jsonify(newdata)

@app.route("/v2/storage/econ_stash_upgrades", methods=["GET", "POST", "PUT"])
@app.route("/3/v2/storage/econ_stash_upgrades", methods=["GET", "POST", "PUT"])
@app.route("/nnnnaakamacloud.c/v2/storage/econ_stash_upgrades", methods=["GET", "POST", "PUT"])
def CavaeDatnnnnaeconstashupgrades():
    data = _load_econ_catalog_file("econ_stash_upgrades.json") or {}
    if not isinstance(data, dict):
        data = {}

    newdata = {"objects": []}

    upgrades = data.get("upgrades", [])
    for e in upgrades:
        newdata["objects"].append({
            "collection": "econ_stash_upgrades",
            "key": e.get("id", ""),
            "user_id": "00000000-0000-0000-0000-000000000000",
            "value": json.dumps(e),
            "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
            "permission_read": 2,
            "create_time": "2025-05-28T16:03:59Z",
            "update_time": "2025-06-11T16:16:56Z"
        })

    return jsonify(newdata)

# Confirmed from real traffic: the client fetches catalogs via a DIFFERENT
# URL shape than the bare routes above — GET /v2/storage/<collection>/<uuid>
# ?limit=N (the real Nakama REST convention for "list objects in a
# collection", with the all-zeros uuid meaning system/public-owned objects).
# None of the six bare routes above ever matched this pattern, so every one
# of these calls was 404ing — explaining why the catalog never reached the
# client at all, regardless of what filtering logic ran server-side.
# Dispatches to the exact same handlers as the bare routes so both forms
# always agree.
_ECON_COLLECTION_HANDLERS = {
    "econ_avatar_items": CavennnnDataaeconavataritems,
    "econ_gameplay_items": CaveDatannnngaameplayitems,
    "econ_research_nodes": CaveaDatannnnresearchnodes,
    "econ_products": CaaveDannnntaeconproducts,
    "econ_mining_ores": CaveDataeconminingores,
    "econ_stash_upgrades": CavaeDatnnnnaeconstashupgrades,
}

def _paginate_objects(objects, limit_param, cursor_param):
    """Simple offset-based pagination matching the real Nakama contract for
    GET /v2/storage/{collection}/{user_id}?limit=N&cursor=.... The cursor is
    just our own opaque offset string — the client only ever needs to pass
    back whatever we hand it, never parse it itself. Confirmed the real
    client sends ?limit=50 and we were ignoring it entirely, returning all
    674+ items in one response — worth fixing on protocol-compliance grounds
    alone, whether or not it's the actual reason the outfit changer is
    still empty."""
    try:
        limit = int(limit_param) if limit_param else len(objects)
    except (TypeError, ValueError):
        limit = len(objects)
    try:
        offset = int(cursor_param) if cursor_param else 0
    except (TypeError, ValueError):
        offset = 0
    page = objects[offset:offset + limit]
    next_offset = offset + limit
    next_cursor = str(next_offset) if next_offset < len(objects) else None
    return page, next_cursor

@app.route("/3/v2/storage/<collection>/<owner_uid>", methods=["GET"])
@app.route("/v2/storage/<collection>/<owner_uid>", methods=["GET"])
@app.route("/nnnnaakamacloud.c/v2/storage/<collection>/<owner_uid>", methods=["GET"])
def storage_collection_list(collection, owner_uid):
    handler = _ECON_COLLECTION_HANDLERS.get(collection)
    if handler:
        full_response = handler()
        try:
            full_data = full_response.get_json()
        except Exception:
            return full_response
        objects = full_data.get("objects", []) if isinstance(full_data, dict) else []
        page, next_cursor = _paginate_objects(
            objects, request.args.get("limit"), request.args.get("cursor")
        )
        result = {"objects": page}
        if next_cursor:
            result["cursor"] = next_cursor
        return jsonify(result), 200

    if collection.startswith("user_"):
        # Confirmed real bug: this route previously fell through to an empty
        # list for ANY collection not in the static catalog dict above —
        # including user_inventory/user_avatar. For an older client using
        # this same path-based convention for its OWN ownership query (not
        # just the catalog), that meant it always saw nothing as owned,
        # regardless of what Storage()'s correct, exclusion-aware logic
        # would have said — Storage() never even ran for these requests.
        # Same auth + default-building Storage() itself uses, filtered to
        # just this one collection since the path form is collection-specific.
        token = request.args.get("token", "") or request.headers.get("Authorization", "")
        if token.startswith("Bearer "):
            token = token.split(" ", 1)[1]
        if token:
            payload = decode_verified_token(token)
            if payload is None:
                return jsonify({"error": "invalid token"}), 403
            username = payload.get("usn", "unknown")
            client_version = _client_version_from_token(payload)
        else:
            username = "unknown"
            client_version = None

        base = _storage_defaults(request.path, username)
        overlaid = _overlay_user_objects(username, base, client_version)
        objects = [o for o in overlaid if o.get("collection") == collection]
        page, next_cursor = _paginate_objects(
            objects, request.args.get("limit"), request.args.get("cursor")
        )
        result = {"objects": page}
        if next_cursor:
            result["cursor"] = next_cursor
        return jsonify(result), 200

    # Not one of our known catalogs or user collections — respond with a
    # valid empty list rather than a 404, since a real Nakama server would
    # just report no matching objects instead of failing the whole request.
    return jsonify({"objects": []}), 200

app.route("/v2/storage/econ_loot_table_bindings", methods=["GET", "POST", "PUT"])
app.route("/nnnnaakamacloud/v2/storage/econ_loot_table_bindings", methods=["GET", "POST", "PUT"])
def CavaeDnnnnataeconloottablebindings():
    ballsjr = os.path.join(dih2, "econ_loot_table_bindings.json")
    with open(ballsjr, 'r', encoding='utf-8') as f:
        data = json.load(f) or []
    newdata = {"objects": []}
    for e in data:
        newdata["objects"].append({
            "collection": "econ_loot_table_bindings",
            "key": e["id"],
            "user_id": "00000000-0000-0000-0000-000000000000",
            "value": json.dumps(e),
            "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
            "permission_read": 2,
            "create_time": "2025-05-28T16:03:59Z",
            "update_time": "2025-06-11T16:16:56Z"
        })

    return jsonify(newdata)

app.route("/v2/storage/econ_loot_table", methods=["GET", "POST", "PUT"])
app.route("/nnnnaakamacloud.c/v2/storage/econ_loot_table", methods=["GET", "POST", "PUT"])
def CavaeDaannnntaeconloottable():
    ballsjr = os.path.join(dih2, "econ_loot_table.json")
    with open(ballsjr, 'r', encoding='utf-8') as f:
        data = json.load(f) or []
    newdata = {"objects": []}
    for e in data:
        newdata["objects"].append({
            "collection": "econ_loot_table",
            "key": e["id"],
            "user_id": "00000000-0000-0000-0000-000000000000",
            "value": json.dumps(e),
            "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
            "permission_read": 2,
            "create_time": "2025-05-28T16:03:59Z",
            "update_time": "2025-06-11T16:16:56Z"
        })

    return jsonify(newdata)

app.route("/v2/storage/econ_crafting_materials", methods=["GET", "POST", "PUT"])
app.route("/nnnnaakamacloud.c/v2/storage/econ_crafting_materials", methods=["GET", "POST", "PUT"])
def CavaeDataennnnconcraftingmaterials():
    ballsjr = os.path.join(dih2, "econ_crafting_materials.json")
    with open(ballsjr, 'r', encoding='utf-8') as f:
        data = json.load(f) or []
    newdata = {"objects": []}
    for e in data:
        newdata["objects"].append({
            "collection": "econ_crafting_materials",
            "key": e["id"],
            "user_id": "00000000-0000-0000-0000-000000000000",
            "value": json.dumps(e),
            "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
            "permission_read": 2,
            "create_time": "2025-05-28T16:03:59Z",
            "update_time": "2025-06-11T16:16:56Z"
        })

    return jsonify(newdata)

@app.route("/3/v2/storage", methods=["GET", "POST", "PUT"])
@app.route("/v2/storage", methods=["GET", "POST", "PUT"])
@app.route("/nnnnaakamacloud.c/v2/storage", methods=["GET", "POST", "PUT"])
def Storage():
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]

    if token:
        payload = decode_verified_token(token)
        if payload is None:
            return jsonify({"error": "invalid token"}), 403
        username = payload.get("usn", "unknown")
        client_version = _client_version_from_token(payload)
    else:
        username = "unknown"
        client_version = None

    uid = generate_deterministic_uid(username)
    base = _storage_defaults(request.path, username)

    # WRITE: the game PUTs (some clients POST) the objects it wants persisted.
    if request.method == "PUT" or (request.method == "POST" and isinstance(request.get_json(silent=True), dict) and request.get_json(silent=True).get("objects")):
        body = request.get_json(silent=True)
        if body is None:
            try:
                body = json.loads(request.data.decode("utf-8", errors="ignore") or "{}")
            except Exception:
                body = {}
        objects = body.get("objects", []) if isinstance(body, dict) else []
        _log_avatar_storage_write(username, objects)
        _save_storage_objects(username, objects)
        # echo the saved objects back with the stable user_id stamped in
        echoed = []
        for obj in objects:
            if isinstance(obj, dict):
                o = dict(obj)
                o["user_id"] = uid
                echoed.append(o)
        return jsonify({"objects": echoed}), 200

    # READ (list everything) — defaults with saved values overlaid
    if request.method == "GET":
        return jsonify({"objects": _overlay_user_objects(username, base, client_version)})

    if request.method == "POST":
        body = request.get_json(silent=True)
        if body is None:
            try:
                body = json.loads(request.data.decode("utf-8", errors="ignore") or "{}")
            except Exception:
                body = {}

        object_ids = body.get("object_ids", []) if isinstance(body, dict) else []

        # Mission/scavenger-hunt collections don't carry user_id — derive the
        # player from the auth token instead, and handle them before the
        # general loop (matches the reference exactly, confirmed as the real
        # delivery path — scavenger hunt confirmed via a real captured RPC).
        _mission_cols = {"econ_daily_missions", "user_daily_missions_progress", "user_scavenger_hunts_progress"}
        if object_ids and any(oid.get("collection") in _mission_cols for oid in object_ids if isinstance(oid, dict)):
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            mission_results = []
            for oid in object_ids:
                if not isinstance(oid, dict):
                    continue
                col = oid.get("collection", "")
                key = oid.get("key", "")
                if col == "econ_daily_missions":
                    # Client historically stringified whole mission objects
                    # into what should've been a bare ID (a bug the
                    # reference backend documents fixing) — tolerate that
                    # shape defensively rather than repeat it.
                    try:
                        mission_id = json.loads(key).get("id", key)
                    except Exception:
                        mission_id = key
                    mission = _mission_def_by_id(mission_id)
                    if mission:
                        mission_results.append({
                            "collection": col, "key": key, "user_id": uid,
                            "value": json.dumps(mission), "version": "1",
                            "create_time": now_iso, "update_time": now_iso,
                            "permission_read": 2, "permission_write": 0,
                        })
                elif col == "user_daily_missions_progress":
                    ids = [m.get("id") for m in load_missions() if isinstance(m, dict) and m.get("id")]
                    prog_list = [_user_mission_progress(uid, mid) for mid in ids]
                    mission_results.append({
                        "collection": col, "key": key, "user_id": uid,
                        "value": json.dumps({"progress": prog_list}), "version": "1",
                        "create_time": now_iso, "update_time": now_iso,
                        "permission_read": 1, "permission_write": 1,
                    })
                elif col == "user_scavenger_hunts_progress":
                    # key IS the hunt ID (e.g. "v1.1") — matches real captured traffic.
                    scav = _user_scav_for(uid, key)
                    mission_results.append({
                        "collection": col, "key": key, "user_id": uid,
                        "value": json.dumps(scav), "version": "1",
                        "create_time": now_iso, "update_time": now_iso,
                        "permission_read": 1, "permission_write": 1,
                    })
            return jsonify({"objects": mission_results})

        overlaid = _overlay_user_objects(username, base, client_version)
        if not object_ids:
            return jsonify({"objects": overlaid})

        response_objects = []

        for obj in object_ids:
            collection = obj.get("collection", "")
            key = obj.get("key", "")
            requested_uid = obj.get("user_id", "")

            if requested_uid and requested_uid != uid:
                # Cross-player lookup — confirmed from a real reference
                # backend's traffic handling: the client batches multiple
                # object_ids in ONE POST, one entry per nearby player, each
                # carrying THAT player's own user_id. This field was
                # previously ignored entirely, so a request for someone
                # else's data silently came back as the CALLER's own
                # instead — wrong data, not a missing mechanism. Scoped to
                # just the two collections the reference itself allows
                # cross-player reads for; anything else gets a harmless
                # empty placeholder rather than ever leaking other data
                # (currency, inventory, etc.) across accounts.
                placeholder = {
                    "collection": collection, "key": key, "user_id": requested_uid,
                    "value": "{}", "version": secrets.token_hex(8), "permission_read": 1,
                    "permission_write": 0, "create_time": "2024-08-24T00:00:00Z",
                    "update_time": "2025-08-07T18:09:40Z"
                }
                # Matches the reference's exact scoping: collection AND key
                # together, not the collection alone — user_inventory also
                # holds things like unlocked research nodes, which is
                # progress data that shouldn't cross accounts the way
                # appearance data reasonably can.
                cross_player_allowed = (collection == "user_avatar" and key == "0") or \
                                       (collection == "user_inventory" and key == "avatar")
                if cross_player_allowed:
                    other_username = _load_uid_lookup().get(requested_uid)
                    other_saved = get_user_items(other_username, collection, key) if other_username else None
                    if isinstance(other_saved, dict) and other_saved.get("value") is not None:
                        other_value = other_saved["value"]
                        if client_version is not None:
                            try:
                                parsed = json.loads(other_value)
                                if isinstance(parsed, dict):
                                    other_value = json.dumps(_strip_unknown_avatar_items(parsed, client_version))
                            except Exception:
                                pass
                        placeholder["value"] = other_value
                        placeholder["version"] = other_saved.get("version", placeholder["version"])
                        placeholder["update_time"] = other_saved.get("update_time", placeholder["update_time"])
                response_objects.append(placeholder)
                continue

            # match a default object (already carries this user's saved value)
            matched = next((o for o in overlaid
                            if o.get("collection") == collection and o.get("key") == key), None)
            if matched:
                response_objects.append(matched)
                continue

            # something the user saved that isn't one of the defaults
            saved = get_user_items(username, collection, key)
            if isinstance(saved, dict) and saved.get("value") is not None:
                response_objects.append({
                    "collection": collection,
                    "key": key,
                    "user_id": uid,
                    "value": saved["value"],
                    "version": saved.get("version", secrets.token_hex(8)),
                    "permission_read": 1,
                    "permission_write": 1,
                    "create_time": "2024-08-24T04:20:56Z",
                    "update_time": saved.get("update_time", "2025-08-07T18:09:40Z")
                })
                continue

            # special case for econ_* config requests
            if collection.startswith("econ_") and key == "config":
                if request.path.startswith("/nnnnaakamacloud.c"):
                    filepath = os.path.join(dih3, f"{collection}.json")
                else:
                    filepath = os.path.join(dih2, f"{collection}.json")

                if os.path.exists(filepath):
                    with open(filepath, "r", encoding="utf-8") as f:
                        file_data = json.load(f)

                    response_objects.append({
                        "collection": collection,
                        "key": "config",
                        "user_id": "00000000-0000-0000-0000-000000000000",
                        "value": json.dumps(file_data),
                        "version": "5c8518bd84cdb43a4e057cb62ca8d5b1",
                        "permission_read": 2,
                        "create_time": "2025-05-28T16:03:59Z",
                        "update_time": "2025-06-11T16:16:56Z"
                    })

        return jsonify({"objects": response_objects})


# ── Photon Fusion room webhooks ───────────────────────────────────────────
# Confirmed via a reference backend: Photon calls these via plain HTTP POST
# whenever a room is created/joined/left/closed — NOT a persistent socket,
# so this works fine on PythonAnywhere unlike /ws. This is what actually
# populates _player_room, replacing the dead-end /ws approach.
#
# IMPORTANT — this only starts firing once these URLs are registered as
# webhooks in the Photon Dashboard for whatever photonAppID clientBootstrap
# hands out below. If you don't have access to that dashboard for this
# specific App ID, these routes will just sit here unused. Worth checking
# with your friend whether the app ID is one you can access, or whether
# you'd need your own Photon account + App ID (Photon has a free tier) and
# to update photonAppID below to match.
PHOTON_SECRET = os.environ.get("PHOTON_SECRET", "45UdTI2FAPpmcP4Kt5TO3EXJEGTlMhRM")  # matches the X-SecretKey value set in Photon's CustomHttpHeaders

def _photon_auth_ok():
    if not PHOTON_SECRET:
        return True
    return request.headers.get("X-SecretKey", "") == PHOTON_SECRET

@app.route("/auth", methods=["GET", "POST"])
@app.route("/auth/photon", methods=["POST", "GET"])
def photon_custom_auth_webhook():
    """Photon Custom Authentication webhook — Photon calls THIS to validate a
    player's token before letting them connect at all, separately from the
    room-lifecycle webhooks below. Missing this entirely is very likely why
    switching to a fresh Photon App ID broke connectivity outright: the old
    App ID was presumably already configured (by whoever set it up
    originally) with a working Custom Authentication URL; a brand-new App ID
    has nothing telling Photon how to validate incoming connections at all.
    Security here comes from verifying the token's HMAC signature (only this
    server could have produced it) — same mechanism as everywhere else in
    this backend, not a separate secret check like the room webhooks below."""
    auth_token = request.args.get("auth_token") or request.args.get("token") or ""
    if not auth_token:
        data = request.get_json(silent=True) or {}
        auth_token = data.get("auth_token") or data.get("token") or ""
    if not auth_token:
        return jsonify({"ResultCode": 2, "Message": "auth token required"}), 200
    if auth_token.startswith("Bearer "):
        auth_token = auth_token.split(" ", 1)[1]

    payload = decode_verified_token(auth_token)
    if payload is None:
        return jsonify({"ResultCode": 2, "Message": "invalid token"}), 200
    if time.time() > payload.get("exp", 0):
        return jsonify({"ResultCode": 2, "Message": "token expired"}), 200

    uid = payload.get("uid", "")
    login_type = (payload.get("vrs") or {}).get("loginType", "")
    # Matches the "_companion" convention _photon_uid_to_username (below)
    # already strips back off — a paired companion app authenticates as the
    # same Nakama account as the headset, so it needs a distinct Photon
    # UserId or Photon (which only allows one connection per UserId per
    # room) would evict the headset's session when the companion joins.
    photon_user_id = uid
    if login_type == "mobile_device":
        photon_user_id = uid + "_companion"

    return jsonify({
        "ResultCode": 1,
        "Message": "Authentication successful",
        "UserId": photon_user_id,
        "Authenticated": True
    }), 200

def _photon_room_from_body(body):
    """Extract the short room code from a Photon webhook body."""
    room = body.get("RoomName", "") or ""
    if not room:
        game_id = body.get("GameId", "") or ""
        # GameId format is like "0:eu:roomname" — take the last segment.
        room = game_id.rsplit(":", 1)[-1] if ":" in game_id else game_id
    return room.strip()

def _photon_uid_to_username(photon_user_id):
    """Photon's UserId is the same as our Nakama uid (set in the custom-auth
    webhook) — except a paired mobile companion app connects with '_companion'
    appended so it doesn't evict the VR headset's session. Strip that back off
    to resolve to the same underlying account either way."""
    uid = photon_user_id
    if uid.endswith("_companion"):
        uid = uid[: -len("_companion")]
    return _load_uid_lookup().get(uid)

@app.route("/game/create", methods=["POST"])
def photon_game_create():
    if not _photon_auth_ok():
        return jsonify({"Status": 400, "Error": "Unauthorized", "Message": "Bad secret"}), 400
    body = request.get_json(force=True, silent=True) or {}
    uid = body.get("UserId", "")
    room = _photon_room_from_body(body)
    username = _photon_uid_to_username(uid)
    if username and room:
        with _presence_lock:
            _player_room[username] = room
        write_log(f"[photon] create: {username} created room {room!r}")
    return jsonify({}), 200

@app.route("/game/beforejoin", methods=["POST"])
def photon_game_before_join():
    """Fires before a join completes — Photon's newer webhook version
    (v1.2) requires this path be configured even if you don't need to
    reject anyone. Always allowing here; if you want per-room bans later,
    this is where that check would go (reject by returning a non-200/
    an ErrorMessage rather than the plain {} used for approval)."""
    if not _photon_auth_ok():
        return jsonify({"Status": 400, "Error": "Unauthorized", "Message": "Bad secret"}), 400
    body = request.get_json(force=True, silent=True) or {}
    uid = body.get("UserId", "")
    room = _photon_room_from_body(body)
    username = _photon_uid_to_username(uid)
    write_log(f"[photon] beforejoin: {username or uid} attempting room {room!r}")
    return jsonify({}), 200

@app.route("/game/join", methods=["POST"])
def photon_game_join():
    if not _photon_auth_ok():
        return jsonify({"Status": 400, "Error": "Unauthorized", "Message": "Bad secret"}), 400
    body = request.get_json(force=True, silent=True) or {}
    uid = body.get("UserId", "")
    room = _photon_room_from_body(body)
    username = _photon_uid_to_username(uid)
    if username and room:
        with _presence_lock:
            _player_room[username] = room
        write_log(f"[photon] join: {username} joined room {room!r}")
    return jsonify({}), 200

@app.route("/game/leave", methods=["POST"])
def photon_game_leave():
    if not _photon_auth_ok():
        return jsonify({"Status": 400, "Error": "Unauthorized", "Message": "Bad secret"}), 400
    body = request.get_json(force=True, silent=True) or {}
    uid = body.get("UserId", "")
    username = _photon_uid_to_username(uid)
    is_inactive = body.get("IsInactive", False)
    if username and not is_inactive:
        with _presence_lock:
            _player_room.pop(username, None)
        write_log(f"[photon] leave: {username} left their room")
    return jsonify({}), 200

@app.route("/game/close", methods=["POST"])
def photon_game_close():
    if not _photon_auth_ok():
        return jsonify({"Status": 400, "Error": "Unauthorized", "Message": "Bad secret"}), 400
    body = request.get_json(force=True, silent=True) or {}
    room = _photon_room_from_body(body)
    with _presence_lock:
        for uname, rc in list(_player_room.items()):
            if rc == room:
                _player_room.pop(uname, None)
    write_log(f"[photon] close: room {room!r} closed")
    return jsonify({}), 200

import json
#photon server stuff
@app.route('/3/v2/rpc/clientBootstrap', methods=['GET', 'POST'])
@app.route('/v2/rpc/clientBootstrap', methods=['GET', 'POST'])
@app.route('/nnnnaakamacloud.c/v2/rpc/clientBootstrap', methods=['GET', 'POST'])
def nakamacloudccaaCaveDatabootstrap():

    _now = time.time()
    _t = time.gmtime(_now)
    _next_reset = int(_now) + (86400 - (_t.tm_hour * 3600 + _t.tm_min * 60 + _t.tm_sec))
    _date_key = time.strftime("%Y-%m-%d", time.gmtime(_now))
    _day_number = int(_now // 86400)
    _mission_ids = _daily_mission_schedule_ids(_day_number)

    # "DailyReward" tasks (real enum value, confirmed) have no in-game action
    # to report progress on — logging in (this exact call, which only fires
    # at boot) IS the task, so it's marked completed here directly rather
    # than waiting for a client report that was never going to come.
    _username = _auth_username()
    if _username:
        _uid = generate_deterministic_uid(_username)
        for _m in load_missions():
            if isinstance(_m, dict) and _m.get("taskType") == "DailyReward" and _m.get("id") in _mission_ids:
                _mp = _user_mission_progress(_uid, _m["id"])
                if not _mp.get("completed"):
                    _persist_user_mission(_uid, _m["id"], {"completed": True})

    payload = {
        "updateType": "None",
        "attestResult": "Valid",
        "attestTokenExpiresAt": 1786139899,

        "photonAppID": "f2da88c4-c60c-43b3-9bbe-b55e398b57dd",
        "photonVoiceAppID": "be90bc96-1982-4a06-8a76-a6a4c3786c30",
        "photonVersion": "UkqqufU7dTP1FgbMqS39",
        "photonRegion": "us",

        "metadataHash": "7eb4cdd9",

        "termsAcceptanceNeeded": [],
        "dailyMissionDateKey": _date_key,
        "dailyMissions": _mission_ids,
        "dailyMissionResetTime": _next_reset,

        "serverTimeUnix": int(_now),

        "gameDataURL": "https://tuck1135.pythonanywhere.com/gamedata/RAM.zip"
    }

    return jsonify({
        "payload": json.dumps(payload)
    })
    return json.dumps({"payload": json.dumps(payload)}), 200, {'Content-Type': 'application/json'}

def _parse_version_tuple(version_string):
    """Extracts a (major, minor) tuple from a version-ish string. Handles both
    client build strings ('MetaQuest 1.8.1.858_f23df3c4' -> (1, 8)) and
    catalog clientVer strings ('1.24.0' -> (1, 24)) — same logic, since both
    just need the first two dot-separated numbers found anywhere in the
    string. Returns None if nothing parseable is found."""
    if not version_string:
        return None
    match = re.search(r'(\d+)\.(\d+)', str(version_string))
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))

def _client_version_from_token(payload):
    """Pulls the requesting client's version out of an already-decoded token
    payload's vrs.clientUserAgent field. None if missing/unparseable — callers
    treat that as 'don't filter' rather than guessing."""
    if not isinstance(payload, dict):
        return None
    vrs = payload.get("vrs")
    if not isinstance(vrs, dict):
        return None
    return _parse_version_tuple(vrs.get("clientUserAgent"))

# Two DIFFERENT failure modes live here, per a working reference backend
# (Xera) a friend compared this file against directly:
#   - clientVer wrong: one cosmetic is missing its model. Contained.
#   - type unrecognized: the client's enum deserializer throws on that ONE
#     item and takes the whole ~750-item catalog parse down with it — empty
#     shop, skinless ragdoll, even for basic items the client otherwise
#     supports fine. This is why clientVer-only filtering (674/674 by count,
#     but the WRONG 1 item) still left the outfit changer empty: the count
#     matching was a coincidence of this catalog, not evidence the mechanism
#     was right.
# Verified against the real econ_avatar_items.json: every item has a type,
# and these exact strings match what's actually in the data (confirmed via
# collections.Counter) — no naming mismatch to correct here.
_AVATAR_TYPES_113 = frozenset({
    "None", "Animal", "Character", "Outfit",
    "BodyPart_Head", "BodyPart_Eye", "BodyPart_Torso",
    "BodyPart_ArmLeft", "BodyPart_ArmRight", "BodyPart_Butt", "BodyPart_Tail",
    "Clothing_Top",
    "Accessory_Head", "Accessory_Face",
    "Accessory_Neck", "Accessory_Shoulder", "Accessory_Hand",
})
_AVATAR_TYPES_116 = _AVATAR_TYPES_113 | frozenset({"Accessory_Ear"})

def _allowed_avatar_types_for(client_version):
    """None == modern client, no type filter."""
    if client_version is None:
        return None
    if client_version <= (1, 13):
        return _AVATAR_TYPES_113
    if client_version < (1, 17):
        return _AVATAR_TYPES_116
    return None

def _avatar_item_allowed(item, client_version):
    """True if this catalog item should be visible to a client at this
    (major, minor) version. Checks BOTH the type-enum allowlist (what that
    client's deserializer can safely parse without throwing) and the
    clientVer threshold (per-item release gating). No client_version
    (couldn't determine it) means don't filter — safer to show everything
    than wrongly hide it."""
    if client_version is None:
        return True
    if not isinstance(item, dict):
        return False
    allowed_types = _allowed_avatar_types_for(client_version)
    if allowed_types is not None and item.get("type") not in allowed_types:
        return False  # note: a MISSING type now fails too, unlike clientVer-only
    item_ver = _parse_version_tuple(item.get("clientVer"))
    if item_ver is not None and client_version < item_ver:
        return False
    return True

# Real avatar/cosmetic item catalog — the same file /v2/storage/econ_avatar_items
# already reads from disk. Cached in memory after first read (same reasoning
# as the currency/items caches above): ~750 items, no need to re-read the
# file from disk on every single account/storage fetch.
_avatar_catalog_cache = None

def _load_avatar_catalog():
    global _avatar_catalog_cache
    if _avatar_catalog_cache is None:
        # Matches _load_econ_catalog_file's path branch, per your friend's
        # note: dih2 and dih3 are the same folder today so this is dormant,
        # but if they ever diverge, this cache is filled on FIRST CALL only
        # (whichever request happens to trigger it) — not fully safe against
        # a future split, just consistent with the other loader for now.
        base_dir = dih3 if request.path.startswith("/nnnnaakamacloud.c") else dih2
        path = os.path.join(base_dir, "econ_avatar_items.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            _avatar_catalog_cache = data if isinstance(data, list) else []
            if not _avatar_catalog_cache:
                write_log(f"[avatar catalog] {path} loaded but empty/unexpected shape")
        except Exception as e:
            write_log(f"[avatar catalog] could not load {path}: {e}")
            _avatar_catalog_cache = []
    return _avatar_catalog_cache

def _all_avatar_item_ids(client_version=None):
    """Every cosmetic id in the real catalog that this client version is
    allowed to see — used to grant every player every ELIGIBLE cosmetic by
    default, per your call that everyone should own them all. Pass the
    requesting client's (major, minor) tuple (see _client_version_from_token)
    to filter out items that client build can't render; omit it to get the
    full catalog unfiltered."""
    return [
        item["id"] for item in _load_avatar_catalog()
        if isinstance(item, dict) and item.get("id") and _avatar_item_allowed(item, client_version)
    ]

_AVATAR_SLOTS = ("head", "eyeLeft", "eyeRight", "torso",
                 "armLeft", "armRight", "butt", "tail")

# _all_avatar_item_ids re-filters all ~750 items (one re.search each) on
# every call, and it's called on every /v2/account, avatar.update GET, and
# storage overlay. Caching per version tuple avoids repeating that work for
# what's really a handful of distinct client versions ever connecting.
_allowed_ids_cache = {}

def _allowed_avatar_ids(client_version):
    if client_version in _allowed_ids_cache:
        return _allowed_ids_cache[client_version]
    ids = set(_all_avatar_item_ids(client_version))
    _allowed_ids_cache[client_version] = ids
    return ids

def _strip_unknown_avatar_items(state, client_version):
    """Read-side only — never persist the result of this. Clears any of the
    eight body-part/accessory slots that reference an item this client
    version can't handle, and prunes any of the three list-shaped fields
    (accessories, items, inventoryAvatarItems) the same way."""
    if not isinstance(state, dict):
        return state
    if _allowed_avatar_types_for(client_version) is None:
        return state  # modern client — nothing to strip
    allowed = _allowed_avatar_ids(client_version)
    if not allowed:
        return state  # catalog failed to load — don't wipe everything out
    out = dict(state)
    for slot in _AVATAR_SLOTS:
        if out.get(slot) and out[slot] not in allowed:
            out[slot] = None
    for k in ("accessories", "items", "inventoryAvatarItems"):
        if isinstance(out.get(k), list):
            out[k] = [i for i in out[k] if i in allowed]
    return out

def _load_econ_catalog_file(filename):
    """Reads one of the econ_*.json catalog files from the wowie/R.A.M
    folder (same folder /v2/storage/econ_avatar_items already reads from).
    Returns None instead of raising if the file is missing/unreadable, so a
    missing catalog file degrades to an empty catalog instead of a 500 that
    breaks the whole endpoint for every player."""
    path = os.path.join(dih3 if request.path.startswith("/nnnnaakamacloud.c") else dih2, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        write_log(f"[econ catalog] could not load {path}: {e}")
        return None

def autism(username=None):
    return {
        "objects": [
        {
        "collection": "user_avatar",
        "key": "0",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": json.dumps({"primaryColor": "FFFFFF", "accessories": []}),
        "version": "e897bbeb9a5d4364d73dee44c2d4e6e4",
        "permission_read": 2,
        "create_time": "2024-09-20T21:26:18Z",
        "update_time": "2025-08-08T09:22:23Z"
        },
        {
        "collection": "user_inventory",
        "key": "avatar",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": json.dumps({"items": _default_cosmetics_for(username)}),
        "version": "277a87beb4905dbe2333d5cd55a7e5be",
        "permission_read": 1,
        "create_time": "2024-09-20T21:26:18Z",
        "update_time": "2025-08-07T01:22:02Z"
        },
        {
        "collection": "user_inventory",
        "key": "research",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": json.dumps({"nodes": list(_FULL_RESEARCH_NODES) if _has_all_gameplay(username) else []}),
        "version": "58c1d1c4ade0e8e205939be8a07ce49b",
        "permission_read": 1,
        "create_time": "2024-11-25T17:55:33Z",
        "update_time": "2025-07-14T21:34:27Z"
        },
        {
        "collection": "user_inventory",
        "key": "stash",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"items\": []}",
        "version": "d1315c03b540bef68ce4742d46e77cc0",
        "permission_read": 1,
        "permission_write": 1,
        "create_time": "2025-02-11T22:35:00Z",
        "update_time": "2025-08-07T17:14:27Z"
        },
        {
        "collection": "user_inventory",
        "key": "stash_upgrades",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"upgrades\": [\"col_1\", \"col_2\", \"col_3\", \"col_4\", \"col_5\", \"col_6\", \"col_7\", \"col_8\", \"row_1\", \"row_2\", \"row_3\", \"row_4\", \"row_5\", \"row_6\", \"row_7\", \"row_8\", \"mtl_1\", \"mtl_2\", \"mtl_3\", \"mtl_4\", \"mtl_5\", \"mtl_6\", \"mtl_7\", \"mtl_8\"]}",
        "version": "af1feb89bd8c849f5f16a4754577be04",
        "permission_read": 1,
        "create_time": "2025-07-23T23:32:02Z",
        "update_time": "2025-08-07T17:05:15Z"
        },
        {
        "collection": "user_inventory",
        "key": "gameplay_loadout",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"version\": 1}",
        "version": "3846efa925d304495efbfed41eaafe74",
        "permission_read": 1,
        "permission_write": 1,
        "create_time": "2024-10-30T01:21:34Z",
        "update_time": "2025-08-08T20:34:56Z"
        },
        {
        "collection": "user_preferences",
        "key": "gameplay_items",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"recents\": []}",
        "version": "fe9acf47fd31aeb3ea1aa209e6485ce3",
        "permission_read": 1,
        "permission_write": 1,
        "create_time": "2024-12-10T20:44:21Z",
        "update_time": "2025-08-09T07:39:43Z"
        },
        {
        "collection": "user_preferences",
        "key": "common",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"appearOffline\": false}",
        "version": "d56295314bb7a4c43e13da9c446a77a8",
        "permission_read": 1,
        "permission_write": 1,
        "create_time": "2025-06-11T03:57:33Z",
        "update_time": "2025-08-07T18:09:40Z"
        }
    ]
    }

@app.route("/3/v2/rpc/user.getActiveSanctions", methods=["GET"])
@app.route("/v2/rpc/user.getActiveSanctions", methods=["GET"])
@app.route("/nnnnaakamacloud.c/v2/rpc/user.getActiveSanctions", methods=["GET"])
def getactivesanctions():
    return {
        "payload": "[]"
    }

def storage166(username=None):
    return {
        "objects": [
        {
        "collection": "user_avatar",
        "key": "0",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": json.dumps({"primaryColor": "FFFFFF", "accessories": []}),
        "version": "e897bbeb9a5d4364d73dee44c2d4e6e4",
        "permission_read": 2,
        "create_time": "2024-09-20T21:26:18Z",
        "update_time": "2025-08-08T09:22:23Z"
        },
        {
        "collection": "user_inventory",
        "key": "avatar",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": json.dumps({"items": _default_cosmetics_for(username)}),
        "version": "277a87beb4905dbe2333d5cd55a7e5be",
        "permission_read": 1,
        "create_time": "2024-09-20T21:26:18Z",
        "update_time": "2025-08-07T01:22:02Z"
        },
        {
        "collection": "user_inventory",
        "key": "research",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": json.dumps({"nodes": list(_FULL_RESEARCH_NODES) if _has_all_gameplay(username) else []}),
        "version": "58c1d1c4ade0e8e205939be8a07ce49b",
        "permission_read": 1,
        "create_time": "2024-11-25T17:55:33Z",
        "update_time": "2025-07-14T21:34:27Z"
        },
        {
        "collection": "user_inventory",
        "key": "stash",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"items\": []}",
        "version": "d1315c03b540bef68ce4742d46e77cc0",
        "permission_read": 1,
        "permission_write": 1,
        "create_time": "2025-02-11T22:35:00Z",
        "update_time": "2025-08-07T17:14:27Z"
        },
        {
        "collection": "user_inventory",
        "key": "stash_upgrades",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"upgrades\": [\"col_1\", \"col_2\", \"col_3\", \"col_4\", \"col_5\", \"col_6\", \"col_7\", \"col_8\", \"row_1\", \"row_2\", \"row_3\", \"row_4\", \"row_5\", \"row_6\", \"row_7\", \"row_8\", \"mtl_1\", \"mtl_2\", \"mtl_3\", \"mtl_4\", \"mtl_5\", \"mtl_6\", \"mtl_7\", \"mtl_8\"]}",
        "version": "af1feb89bd8c849f5f16a4754577be04",
        "permission_read": 1,
        "create_time": "2025-07-23T23:32:02Z",
        "update_time": "2025-08-07T17:05:15Z"
        },
        {
        "collection": "user_inventory",
        "key": "gameplay_loadout",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"version\": 1}",
        "version": "3846efa925d304495efbfed41eaafe74",
        "permission_read": 1,
        "permission_write": 1,
        "create_time": "2024-10-30T01:21:34Z",
        "update_time": "2025-08-08T20:34:56Z"
        },
        {
        "collection": "user_preferences",
        "key": "gameplay_items",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"recents\": []}",
        "version": "fe9acf47fd31aeb3ea1aa209e6485ce3",
        "permission_read": 1,
        "permission_write": 1,
        "create_time": "2024-12-10T20:44:21Z",
        "update_time": "2025-08-09T07:39:43Z"
        },
        {
        "collection": "user_preferences",
        "key": "common",
        "user_id": "3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236",
        "value": "{\"appearOffline\": false}",
        "version": "d56295314bb7a4c43e13da9c446a77a8",
        "permission_read": 1,
        "permission_write": 1,
        "create_time": "2025-06-11T03:57:33Z",
        "update_time": "2025-08-07T18:09:40Z"
        }
    ]
    }

@app.route('/3/v2/rpc/purchase.list', methods=['GET'])
@app.route('/v2/rpc/purchase.list', methods=['GET'])
@app.route('/nnnnaakamacloud.c/v2/rpc/purchase.list', methods=['GET'])
def purchaselist():
    return {
        "payload": "{\"purchases\":[{\"user_id\":\"3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236\",\"product_id\":\"KPOP_GOLD\",\"transaction_id\":\"716802304855579\",\"store\":3,\"purchase_time\":{\"seconds\":1754458259},\"create_time\":{\"seconds\":1754458305,\"nanos\":154543000},\"update_time\":{\"seconds\":1754458305,\"nanos\":154543000},\"refund_time\":{},\"provider_response\":\"{\\\"success\\\": true, \\\"grant_time\\\": 1754458259}\",\"environment\":2},{\"user_id\":\"3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236\",\"product_id\":\"CHAMELEON_BUNDLE\",\"transaction_id\":\"642819158920561\",\"store\":3,\"purchase_time\":{\"seconds\":1748315321},\"create_time\":{\"seconds\":1748315350,\"nanos\":615822000},\"update_time\":{\"seconds\":1748315350,\"nanos\":615822000},\"refund_time\":{},\"provider_response\":\"{\\\"success\\\": true, \\\"grant_time\\\": 1748315321}\",\"environment\":2},{\"user_id\":\"3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236\",\"product_id\":\"SHELLLONG_BUNDLE\",\"transaction_id\":\"583001341569010\",\"store\":3,\"purchase_time\":{\"seconds\":1742932724},\"create_time\":{\"seconds\":1742932880,\"nanos\":773282000},\"update_time\":{\"seconds\":1742932880,\"nanos\":773282000},\"refund_time\":{},\"provider_response\":\"{\\\"success\\\": true}\",\"environment\":2},{\"user_id\":\"3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236\",\"product_id\":\"G.O.A.T_BUNDLE\",\"transaction_id\":\"556928314176313\",\"store\":3,\"purchase_time\":{\"seconds\":1740523561},\"create_time\":{\"seconds\":1740523626,\"nanos\":858485000},\"update_time\":{\"seconds\":1741616276,\"nanos\":636221000},\"refund_time\":{},\"provider_response\":\"{\\\"success\\\": true}\",\"environment\":2},{\"user_id\":\"3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236\",\"product_id\":\"CURRENCY_SMALL\",\"transaction_id\":\"520077871194691\",\"store\":3,\"purchase_time\":{\"seconds\":1737165591},\"create_time\":{\"seconds\":1737165616,\"nanos\":219758000},\"update_time\":{\"seconds\":1737165616,\"nanos\":219758000},\"refund_time\":{},\"provider_response\":\"{\\\"success\\\": true}\",\"environment\":2},{\"user_id\":\"3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236\",\"product_id\":\"POLAR_PAWS_BUNDLE\",\"transaction_id\":\"498846086651203\",\"store\":3,\"purchase_time\":{\"seconds\":1735139449},\"create_time\":{\"seconds\":1735155215,\"nanos\":988535000},\"update_time\":{\"seconds\":1735155215,\"nanos\":988535000},\"refund_time\":{},\"provider_response\":\"{\\\"success\\\": true}\",\"environment\":2},{\"user_id\":\"3560fe2e-015c-4d2b-b2a6-6eb9f8d6a236\",\"product_id\":\"FROG_BUNDLE\",\"transaction_id\":\"411070858762060\",\"store\":3,\"purchase_time\":{\"seconds\":1726952768},\"create_time\":{\"seconds\":1726953016,\"nanos\":937191000},\"update_time\":{\"seconds\":1726953016,\"nanos\":937191000},\"refund_time\":{},\"provider_response\":\"{\\\"success\\\": true}\",\"environment\":2}]}"
    }
@app.route('/3/v2/rpc/purchase.avatarItems', methods=['POST'])
@app.route('/v2/rpc/purchase.avatarItems', methods=['POST'])
@app.route('/nnnnaakamacloud.c/v2/rpc/purchase.avatarItems', methods=['POST'])
def purchase_avatar_items():
    """Ported from a friend's real, working purchase.avatarItems — full
    switch to their economy model: nothing owned by default (except
    unlock-all), every cosmetic explicitly purchased with cc at its real
    catalog hardPrice. Every catalog item stays buyable regardless of its
    own showInShop value — their own implementation never checks that
    field at all, only that the item genuinely exists — and per-person
    promo-code grants are checked as an independent, additional source of
    ownership in _get_owned_cosmetics, so anyone who already redeemed a
    cosmetic keeps it untouched by this switch."""
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is None:
        return jsonify({"error": "invalid token"}), 403
    username = payload["usn"]
    client_version = _client_version_from_token(payload)

    # Same "payload may be a JSON-encoded string" RPC convention as avatar.update.
    parsed = request.get_json(silent=True)
    body = None
    if isinstance(parsed, dict):
        body = parsed
    elif isinstance(parsed, str):
        try:
            inner = json.loads(parsed)
            if isinstance(inner, dict):
                body = inner
        except Exception:
            body = None
    if body is None:
        try:
            raw = request.data.decode("utf-8", errors="ignore")
            inner = json.loads(raw)
            if isinstance(inner, str):
                inner = json.loads(inner)
            if isinstance(inner, dict):
                body = inner
        except Exception:
            body = {}
    if not isinstance(body, dict):
        body = {}

    item_ids = body.get("itemIDs", [])
    if not isinstance(item_ids, list):
        item_ids = []

    catalog_by_id = {i.get("id"): i for i in _load_avatar_catalog() if isinstance(i, dict)}

    def _fail(error_code, wallet=None):
        payload_out = {"succeeded": False, "errorCode": error_code}
        if wallet is not None:
            payload_out["wallet"] = wallet
        log_to_avatar_discord(
            f"🛒 **purchase.avatarItems failed**\n"
            f"👤 User: `{username}`\n"
            f"🎁 Requested: `{item_ids}`\n"
            f"⚠️ Reason: `{error_code}`"
        )
        return jsonify({"payload": json.dumps(payload_out)}), 200

    for iid in item_ids:
        if iid not in catalog_by_id:
            return _fail("ItemNotFound")

    with _avatar_purchase_lock:
        already_owned = set(_get_owned_cosmetics(username, client_version))
        to_charge = [i for i in item_ids if i not in already_owned]

        cur = get_user_currency(username)
        wallet_now = {
            "softCurrency": int(cur.get("nuts", 0)),
            "hardCurrency": int(cur.get("cc", 0)),
            "researchPoints": int(cur.get("rp", 0)),
        }

        if not to_charge:
            return _fail("AlreadyOwned", wallet_now)

        total_cost = sum(int(catalog_by_id[i].get("hardPrice", 0) or 0) for i in to_charge)
        current_cc = wallet_now["hardCurrency"]

        if current_cc < total_cost:
            return _fail("InsufficientFunds", wallet_now)

        if not add_purchased_avatar_items(username, item_ids):
            return _fail("UnexpectedClientError", wallet_now)

        update_user_currency(username, cc=current_cc - total_cost)

    final_cur = get_user_currency(username)
    wallet = {
        "softCurrency": int(final_cur.get("nuts", 0)),
        "hardCurrency": int(final_cur.get("cc", 0)),
        "researchPoints": int(final_cur.get("rp", 0)),
    }

    log_to_avatar_discord(
        f"🛒 **purchase.avatarItems**\n"
        f"👤 User: `{username}`\n"
        f"🎁 Requested: `{item_ids}`\n"
        f"💰 Charged: `{total_cost}cc` for: `{to_charge}`\n"
        f"📊 New balance: `{wallet['hardCurrency']}cc`"
    )

    return jsonify({
        "payload": json.dumps({
            "succeeded": True,
            "errorCode": "",
            "itemIDs": item_ids,
            "cost": total_cost,
            "wallet": wallet,
            "inventoryAvatarItems": _get_owned_cosmetics(username, client_version),
        })
    }), 200

@app.route("/v2/rpc/matchmake", methods=["POST"])
@app.route("/3/v2/rpc/matchmake", methods=["POST"])
def matchmake():
    response = {
        "matchId": "test_room",
        "region": "us",
        "maxPlayers": 10,
        "playerCount": 1
    }
    return json.dumps({"payload": json.dumps(response)})


@app.route("/v2/rpc/lobby", methods=["POST"])
@app.route("/v2/rpc/findMatch", methods=["POST"])
def lobby():
    response = {
        "matchId": "test_room",
        "region": "us"
    }
    return json.dumps({"payload": json.dumps(response)})

# ── Daily missions RPCs ────────────────────────────────────────────────────
# Best-effort guessed names (see the honesty note where these are defined,
# near the data layer) — registered defensively under several plausible
# spellings. The real, confirmed delivery path is econ_daily_missions via
# /v2/storage (see Storage() above); these exist in case the client also
# calls dedicated RPCs for reporting/collecting.
def _daily_missions_payload():
    return {"missions": load_missions()}

def _daily_progress_payload(uid):
    ids = [m.get("id") for m in load_missions() if isinstance(m, dict) and m.get("id")]
    return {"progress": [_user_mission_progress(uid, mid) for mid in ids]}

@app.route("/v2/rpc/dailyMissions.getData", methods=["GET", "POST"])
@app.route("/3/v2/rpc/dailyMissions.getData", methods=["GET", "POST"])
@app.route("/v2/rpc/getDailyMissionsData", methods=["GET", "POST"])
@app.route("/3/v2/rpc/getDailyMissionsData", methods=["GET", "POST"])
def daily_missions_get_data():
    return jsonify({"payload": json.dumps(_daily_missions_payload())}), 200

@app.route("/v2/rpc/dailyMissions.getProgress", methods=["GET", "POST"])
@app.route("/3/v2/rpc/dailyMissions.getProgress", methods=["GET", "POST"])
@app.route("/v2/rpc/getDailyMissionsProgress", methods=["GET", "POST"])
@app.route("/3/v2/rpc/getDailyMissionsProgress", methods=["GET", "POST"])
def daily_missions_get_progress():
    username = _auth_username()
    uid = generate_deterministic_uid(username) if username else ""
    return jsonify({"payload": json.dumps(_daily_progress_payload(uid))}), 200

def _extract_rpc_body():
    """Client sends RPC bodies as a JSON-encoded string (the same "payload"
    convention used everywhere else in this backend), so get_json() often
    returns a str that needs one more json.loads()."""
    try:
        body = request.get_json(force=True, silent=True)
        if isinstance(body, str):
            body = json.loads(body) if body else {}
        if isinstance(body, dict) and isinstance(body.get("payload"), str):
            body = json.loads(body["payload"]) or {}
    except Exception:
        body = {}
    return body if isinstance(body, dict) else {}

@app.route("/v2/rpc/dailyMissions.reportProgress", methods=["POST"])
@app.route("/3/v2/rpc/dailyMissions.reportProgress", methods=["POST"])
@app.route("/v2/rpc/reportDailyMissionProgress", methods=["POST"])
@app.route("/3/v2/rpc/reportDailyMissionProgress", methods=["POST"])
@app.route("/v2/rpc/dailyMission.progress", methods=["POST"])
@app.route("/3/v2/rpc/dailyMission.progress", methods=["POST"])
def daily_missions_report_progress():
    username = _auth_username()
    if not username:
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 2})}), 200
    uid = generate_deterministic_uid(username)
    body = _extract_rpc_body()
    mission_id = body.get("missionID") or body.get("missionId") or body.get("id", "")
    if not mission_id or not _mission_def_by_id(mission_id):
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 4})}), 200
    updates = {}
    if "progress" in body:
        updates["progress"] = str(body.get("progress", ""))
    if "completed" in body:
        updates["completed"] = bool(body.get("completed"))
    _persist_user_mission(uid, mission_id, updates)
    log_to_avatar_discord(f"🎯 **mission progress**\n👤 User: `{username}`\n📋 Mission: `{mission_id}`\n📦 {updates}")
    return jsonify({"payload": json.dumps({"succeeded": True, "errorCode": 0})}), 200

@app.route("/v2/rpc/dailyMissions.collectReward", methods=["POST"])
@app.route("/3/v2/rpc/dailyMissions.collectReward", methods=["POST"])
@app.route("/v2/rpc/collectDailyMissionReward", methods=["POST"])
@app.route("/3/v2/rpc/collectDailyMissionReward", methods=["POST"])
@app.route("/v2/rpc/dailyMission.collect", methods=["POST"])
@app.route("/3/v2/rpc/dailyMission.collect", methods=["POST"])
def daily_missions_collect_reward():
    username = _auth_username()
    if not username:
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 2})}), 200
    uid = generate_deterministic_uid(username)
    body = _extract_rpc_body()
    mission_id = body.get("missionID") or body.get("missionId") or body.get("id", "")
    mission = _mission_def_by_id(mission_id)
    if not mission_id or not mission:
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 4})}), 200
    mp = _user_mission_progress(uid, mission_id)
    if mp.get("collected"):
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 6})}), 200
    if not mp.get("completed"):
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 5})}), 200
    reward_hard = int(mission.get("rewardHard", 0) or 0)
    reward_rp = int(mission.get("rewardResearchPoints", 0) or 0)
    cur = get_user_currency(username)
    if reward_hard:
        update_user_currency(username, cc=int(cur.get("cc", 0)) + reward_hard)
    if reward_rp:
        update_user_currency(username, rp=int(cur.get("rp", 0)) + reward_rp)
    _persist_user_mission(uid, mission_id, {"collected": True})
    log_to_avatar_discord(f"🎁 **mission collected**\n👤 User: `{username}`\n📋 Mission: `{mission_id}`\n💰 +{reward_hard}cc +{reward_rp}rp")
    return jsonify({"payload": json.dumps({"succeeded": True, "errorCode": 0})}), 200

# ── Scavenger hunt RPCs ────────────────────────────────────────────────────
# Real, confirmed RPC name (scavengerHunt.progress) — this one isn't a guess.
@app.route("/v2/rpc/scavengerHunt.getProgress", methods=["GET", "POST"])
@app.route("/3/v2/rpc/scavengerHunt.getProgress", methods=["GET", "POST"])
@app.route("/v2/rpc/getScavengerHuntProgress", methods=["GET", "POST"])
@app.route("/3/v2/rpc/getScavengerHuntProgress", methods=["GET", "POST"])
def scavenger_hunt_get_progress():
    username = _auth_username()
    if not username:
        return jsonify({"payload": json.dumps({"itemIDs": [], "completed": False, "collected": False})}), 200
    uid = generate_deterministic_uid(username)
    body = _extract_rpc_body()
    hunt_id = body.get("scavengerHuntID") or body.get("huntID") or body.get("id", "")
    prog = _user_scav_for(uid, hunt_id) if hunt_id else {"itemIDs": [], "completed": False, "collected": False}
    return jsonify({"payload": json.dumps(prog)}), 200

@app.route("/v2/rpc/scavengerHunt.progress", methods=["POST"])
@app.route("/3/v2/rpc/scavengerHunt.progress", methods=["POST"])
@app.route("/v2/rpc/reportScavengerHuntProgress", methods=["POST"])
@app.route("/3/v2/rpc/reportScavengerHuntProgress", methods=["POST"])
def scavenger_hunt_report_progress():
    """Adds scavengerHuntItemID to the player's collected set for the hunt.
    Returns {succeeded, completed, errorCode}."""
    username = _auth_username()
    if not username:
        return jsonify({"payload": json.dumps({"succeeded": False, "completed": False, "errorCode": 2})}), 200
    uid = generate_deterministic_uid(username)
    body = _extract_rpc_body()
    hunt_id = body.get("scavengerHuntID") or body.get("huntID") or body.get("id", "")
    item_id = body.get("scavengerHuntItemID") or body.get("itemID", "")
    if not hunt_id or not item_id:
        return jsonify({"payload": json.dumps({"succeeded": False, "completed": False, "errorCode": 4})}), 200
    cfg = load_scav_config().get(hunt_id)
    if not cfg:
        return jsonify({"payload": json.dumps({"succeeded": False, "completed": False, "errorCode": 4})}), 200
    with _scav_lock:
        data = _load_scav_progress()
        user_block = data.setdefault(uid, {})
        if not isinstance(user_block, dict):
            user_block = {}
            data[uid] = user_block
        entry = user_block.setdefault(hunt_id, {"itemIDs": [], "collected": False})
        if not isinstance(entry, dict):
            entry = {"itemIDs": [], "collected": False}
            user_block[hunt_id] = entry
        items = entry.setdefault("itemIDs", [])
        if not isinstance(items, list):
            items = []
            entry["itemIDs"] = items
        total = int(cfg.get("count", 0) or 0)
        if item_id in items:
            return jsonify({"payload": json.dumps({"succeeded": False, "completed": len(items) >= total, "errorCode": 6})}), 200
        items.append(item_id)
        completed = total > 0 and len(items) >= total
        _save_scav_progress(data)
    log_to_avatar_discord(f"🔍 **scavenger hunt progress**\n👤 User: `{username}`\n🗺️ Hunt: `{hunt_id}`\n📦 Item: `{item_id}` ({len(items)}/{total}) completed={completed}")
    return jsonify({"payload": json.dumps({"succeeded": True, "completed": completed, "errorCode": 0})}), 200

@app.route("/v2/rpc/scavengerHunt.collectReward", methods=["POST"])
@app.route("/3/v2/rpc/scavengerHunt.collectReward", methods=["POST"])
@app.route("/v2/rpc/collectScavengerHuntReward", methods=["POST"])
@app.route("/3/v2/rpc/collectScavengerHuntReward", methods=["POST"])
def scavenger_hunt_collect_reward():
    username = _auth_username()
    if not username:
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 2})}), 200
    uid = generate_deterministic_uid(username)
    body = _extract_rpc_body()
    hunt_id = body.get("scavengerHuntID") or body.get("huntID") or body.get("id", "")
    cfg = load_scav_config().get(hunt_id)
    if not cfg:
        return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 4})}), 200
    with _scav_lock:
        data = _load_scav_progress()
        user_block = data.setdefault(uid, {})
        if not isinstance(user_block, dict):
            user_block = {}
            data[uid] = user_block
        entry = user_block.setdefault(hunt_id, {"itemIDs": [], "collected": False})
        if not isinstance(entry, dict):
            entry = {"itemIDs": [], "collected": False}
            user_block[hunt_id] = entry
        items = entry.get("itemIDs", [])
        if not isinstance(items, list):
            items = []
        total = int(cfg.get("count", 0) or 0)
        if total <= 0 or len(items) < total:
            return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 5})}), 200
        if entry.get("collected"):
            return jsonify({"payload": json.dumps({"succeeded": False, "errorCode": 6})}), 200
        reward_hard = int(cfg.get("rewardHard", 0) or 0)
        reward_rp = int(cfg.get("rewardResearchPoints", 0) or 0)
        cur = get_user_currency(username)
        if reward_hard:
            update_user_currency(username, cc=int(cur.get("cc", 0)) + reward_hard)
        if reward_rp:
            update_user_currency(username, rp=int(cur.get("rp", 0)) + reward_rp)
        entry["collected"] = True
        _save_scav_progress(data)
    log_to_avatar_discord(f"🎁 **scavenger hunt collected**\n👤 User: `{username}`\n🗺️ Hunt: `{hunt_id}`\n💰 +{reward_hard}cc +{reward_rp}rp")
    return jsonify({"payload": json.dumps({"succeeded": True, "errorCode": 0})}), 200

@app.route("/v2/sync", methods=["POST"])
@app.route("/smali", methods=["POST"])
def client_sync_check():
    """Package name + library check — confirmed real (not guessed), pulled
    from a friend's live server logs. Now also checks native_mods, from
    your friend's own version of this same check — a Battery/Sync smali
    pair that scans /sdcard/Android/data/<pkg>/nativemods for .so files and
    reports it here. Alert-only by explicit choice: never blocks or bans
    on its own, just notifies. See the honesty note above load_default_libs()
    for why the very first real login will likely alert on this game's own
    main library — that's expected, confirm it and add it via
    /admin/<token>/libs so it stops."""
    # Same gap already found and fixed once in the login flow: get_json()
    # silently returns None without an exact application/json Content-Type
    # header, even when the body IS valid JSON — so pkg/libs/pv all read as
    # empty and every check below silently no-ops. Falling back to raw
    # bytes, matching the pattern used everywhere else in this file.
    body = request.get_json(silent=True)
    if body is None:
        try:
            body = json.loads(request.data.decode("utf-8", errors="ignore") or "{}")
        except Exception:
            body = {}
    pkg = body.get("pkg", "")
    incoming_libs = body.get("libs", [])
    device_id = body.get("device_id", "unknown")
    pv = body.get("pv")
    username = _auth_username() or request.args.get("username", "")

    if pkg != EXPECTED_APP_ID:
        log_to_package_alert_discord(
            f"🚨 **Wrong package name on /v2/sync**\n"
            f"👤 User: `{username or '(unknown)'}`\n"
            f"📦 Got: `{pkg}` (expected `{EXPECTED_APP_ID}`)\n"
            f"🌐 IP: `{request.remote_addr}`"
        )

    if pv is not None and pv != SYNC_PROTOCOL_VERSION:
        log_to_package_alert_discord(
            f"⚠️ **Unexpected sync protocol version**\n"
            f"👤 User: `{username or '(unknown)'}`\n"
            f"🔢 Got: `{pv}` (expected `{SYNC_PROTOCOL_VERSION}`)"
        )

    incoming_set = {str(l).strip() for l in incoming_libs if l}
    unauthorized = incoming_set - set(load_default_libs())
    if unauthorized:
        log_to_package_alert_discord(
            f"📚 **Unrecognized libraries on /v2/sync**\n"
            f"👤 User: `{username or '(unknown)'}`\n"
            f"🌐 IP: `{request.remote_addr}`\n"
            f"📦 Device: `{device_id}`\n"
            f"🧩 Unrecognized: `{', '.join(sorted(unauthorized))}`\n"
            f"_(alert only — nothing blocked. If this is really this game's own library, add it at /admin/<token>/libs)_"
        )

    # native_mods: confirmed from your friend's own version of this same
    # check — specifically scans /sdcard/Android/data/<pkg>/nativemods for
    # .so files. A non-empty list here is a much stronger signal than an
    # unrecognized library above (there's no legitimate reason a normal
    # install would ever have files in that specific folder), but keeping
    # this alert-only too, matching this route's existing, consistent
    # policy rather than introducing an auto-ban path with no username
    # attached to act on yet.
    native_mods = body.get("native_mods", [])
    native_mods_set = {str(m).strip() for m in native_mods if m}
    if native_mods_set:
        log_to_package_alert_discord(
            f"🚨 **Native mod libraries detected on /v2/sync**\n"
            f"👤 User: `{username or '(unknown)'}`\n"
            f"🌐 IP: `{request.remote_addr}`\n"
            f"📦 Device: `{device_id}`\n"
            f"🧨 Detected: `{', '.join(sorted(native_mods_set))}`\n"
            f"_(alert only — nothing blocked automatically)_"
        )

    return jsonify({"status": "ok"}), 200

@app.route("/v2/rpc/<path:subpath>", methods=["POST"])
@app.route("/3/v2/rpc/<path:subpath>", methods=["POST"])
def catch_all_rpc(subpath):
    # Was a bare print() — invisible unless someone's watching the raw
    # PythonAnywhere console. Any RPC name that lands here has no specific
    # route above, which is exactly how you'd discover the daily-mission RPC
    # guesses above are wrong, if they are — so this needs to be somewhere
    # you'll actually see it.
    try:
        body_preview = request.get_data(as_text=True)[:300]
    except Exception:
        body_preview = ""
    write_log(f"[rpc:unknown] {request.method} id={subpath} user={_auth_username()} body={body_preview!r}")
    log_to_auth_discord(f"❓ **Unknown RPC called**\n🆔 `{subpath}`\n👤 User: `{_auth_username()}`\n📦 Body: ```\n{body_preview}\n```")

    response = {
        "matchId": "test_room",
        "region": "us"
    }

    return json.dumps({"payload": json.dumps(response)})


@sockets.route("/ws")
def ws_route(ws):
    # Nakama's real socket auth convention: token as a query param on the
    # connection URL itself, not a header (harder to set on a raw WebSocket
    # handshake). A present-but-invalid/banned token closes the connection
    # immediately, same as any other endpoint would reject it.
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token) if token else None
    username = payload.get("usn") if payload else None
    if token and payload is None:
        ws.close()
        return

    logged_first_message = False
    while not ws.closed:
        msg = ws.receive()
        if msg:
            if not logged_first_message:
                logged_first_message = True
                log_to_auth_discord(
                    f"🔌 **WS status message** (first on this connection)\n"
                    f"👤 User: `{username or 'unknown'}`\n"
                    f"📦 Raw: ```\n{str(msg)[:1500]}\n```"
                )

            # Best-effort parse — the client previously got a hardcoded
            # empty roomCode back regardless of what it sent, so this is a
            # reasoned guess (matching the shape of the response this same
            # code already sends) rather than confirmed from real traffic.
            # Handles the status either being a JSON-encoded string (the
            # RPC "payload" convention used everywhere else in this backend)
            # or a plain nested object.
            room_code = None
            try:
                parsed = json.loads(msg)
                if isinstance(parsed, dict):
                    status_update = parsed.get("status_update", parsed)
                    if isinstance(status_update, dict):
                        status_val = status_update.get("status", status_update)
                        if isinstance(status_val, str):
                            status_val = json.loads(status_val)
                        if isinstance(status_val, dict) and "roomCode" in status_val:
                            room_code = status_val.get("roomCode")
            except Exception:
                pass

            if username and room_code is not None:
                with _presence_lock:
                    _player_room[username] = room_code

            ws.send(json.dumps({
                "cid": "29",
                "status_update": {
                    "status": json.dumps({
                        "roomCode": room_code or "",
                        "gameMode": 0,
                        "appearOffline": True,
                        "clientVersion": "1.27.0.1415_c6aabe18",
                        "photonVersion": "UkqqufU7dTP1FgbMqS39"
                    })
                }
            }))
@app.route("/admin/<token>", methods=["GET"])
def admin_panel(token):
    early = _require_admin_login(token)
    if early:
        return early

    with _currency_lock:
        currencies = _load_currencies()
    account_count = len(currencies) if isinstance(currencies, dict) else 0

    missions = load_missions()
    if missions:
        missions_rows = "".join(
            f'<tr><td><code>{_escape_html(m.get("id",""))}</code></td>'
            f'<td>{_escape_html(m.get("name", ""))}</td>'
            f'<td>{m.get("rewardHard",0)} cc / {m.get("rewardResearchPoints",0)} rp</td>'
            f'<td>{"Daily" if m.get("dailyReset") else "One-time"}</td></tr>'
            for m in missions
        )
    else:
        missions_rows = '<tr><td colspan="4" style="color:#aaa;">None yet.</td></tr>'

    scav_config = load_scav_config()
    if scav_config:
        scav_rows = "".join(
            f'<tr><td>{_escape_html(hid)}</td><td>{cfg.get("count",0)} items</td>'
            f'<td>{cfg.get("rewardHard",0)} cc / {cfg.get("rewardResearchPoints",0)} rp</td></tr>'
            for hid, cfg in scav_config.items()
        )
    else:
        scav_rows = '<tr><td colspan="3" style="color:#aaa;">None configured.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Animal Company Rebirth Made by tuck1135.</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    h2 {{ font-size:15px; margin:24px 0 4px; color:#ddd; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:12px 18px; border-radius:6px;
              font-size:15px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    #result {{ margin-top:16px; font-size:14px; white-space:pre-wrap; }}
    table {{ width:100%; border-collapse:collapse; margin-top:6px; }}
    th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    code {{ font-family:monospace; background:#1b1b22; padding:2px 5px; border-radius:4px; font-size:12px; }}
    th {{ color:#aaa; font-weight:600; }}
    .note {{ color:#aaa; font-size:12px; margin-top:4px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Animal Company Rebirth&mdash; Admin Panel by Tuck</h1>
    <p>Accounts: <strong>{account_count}</strong> &middot; <a href="/admin/{token}/leaderboard" style="color:#8F00FF;">View live leaderboard</a> &middot; <a href="/admin/{token}/bans" style="color:#8F00FF;">Manage bans</a> &middot; <a href="/admin/{token}/bypass" style="color:#8F00FF;">Manage bypass list</a> &middot; <a href="/admin/{token}/old-key-users" style="color:#8F00FF;">Old server key users</a> &middot; <a href="/admin/{token}/server-key" style="color:#8F00FF;">Server key</a> &middot; <a href="/admin/{token}/missions" style="color:#8F00FF;">Manage daily missions</a> &middot; <a href="/admin/{token}/libs" style="color:#8F00FF;">Manage known libraries</a> &middot; <a href="/admin/{token}/names" style="color:#8F00FF;">Manage custom names</a> &middot; <a href="/admin/{token}/devs" style="color:#8F00FF;">Manage developers</a> &middot; <a href="/admin/{token}/unlock-gameplay" style="color:#8F00FF;">Full gameplay unlock</a> &middot; <a href="/admin/{token}/unlock-cosmetics" style="color:#8F00FF;">Full cosmetics unlock</a> &middot; <a href="/admin/{token}/excluded-cosmetics" style="color:#8F00FF;">Exclude cosmetics</a> &middot; <a href="/admin/{token}/person-cosmetics" style="color:#8F00FF;">Per-person cosmetics</a> &middot; <a href="/admin/{token}/promo-codes" style="color:#8F00FF;">Manage promo codes</a> &middot; <a href="/admin/{token}/migrate-player" style="color:#8F00FF;">Migrate player data</a></p>
    <p><form method="POST" action="/admin/{token}/change-url" onsubmit="return confirm('This immediately changes your panel URL and redirects you to the new one. The old link stops working right away. Continue?')" style="display:inline;"><button type="submit" style="background:#c0392b; color:#fff; border:none; padding:8px 14px; border-radius:6px; font-size:13px; cursor:pointer;">Change Owner Panel URL</button></form></p>
    <p>This resets <strong>every</strong> player's soft currency (nuts) to 100. This cannot be undone.</p>
    <button id="resetBtn">Reset all nuts to 100</button>
    <div id="result"></div>

    <p style="margin-top:20px;">This resets <strong>every</strong> player's unlocked research/tech tree back to default (nothing unlocked, unless they're on the gameplay unlock-all list). This cannot be undone.</p>
    <button id="resetTechBtn">Reset all tech trees</button>
    <div id="resultTech"></div>

    <p style="margin-top:20px;">This resets <strong>every</strong> player's owned cosmetics and equipped appearance back to default (nothing owned, unless they're on the cosmetics unlock-all list). This cannot be undone.</p>
    <button id="resetCosmeticsBtn">Reset all cosmetics</button>
    <div id="resultCosmetics"></div>

    <h2>Daily Missions ({len(missions)})</h2>
    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Reward</th><th>Type</th></tr></thead>
      <tbody>{missions_rows}</tbody>
    </table>
    <p class="note"><a href="/admin/{token}/missions" style="color:#8F00FF;">Edit missions &rarr;</a></p>

    <h2>Scavenger Hunts ({len(scav_config)})</h2>
    <table>
      <thead><tr><th>Hunt ID</th><th>Items needed</th><th>Reward</th></tr></thead>
      <tbody>{scav_rows}</tbody>
    </table>
    <p class="note"><a href="/admin/{token}/scavhunts" style="color:#8F00FF;">Edit scavenger hunts &rarr;</a></p>
  </div>
  <script>
    function setupResetButton(btnId, resultId, endpoint, confirmMsg, successText) {{
      document.getElementById(btnId).addEventListener('click', async () => {{
        const pw = prompt(confirmMsg);
        if (pw === null) return;
        const btn = document.getElementById(btnId);
        const result = document.getElementById(resultId);
        btn.disabled = true;
        result.textContent = 'Working...';
        try {{
          const res = await fetch(window.location.pathname + endpoint, {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ password: pw }})
          }});
          if (res.status === 401) {{ window.location.href = '/admin/{token}/login'; return; }}
          const data = await res.json();
          result.textContent = res.ok
            ? `Done. ${{successText}} for ${{data.accounts_reset}} account(s).`
            : `Error: ${{data.error || res.status}}`;
        }} catch (e) {{
          result.textContent = 'Request failed: ' + e;
        }} finally {{
          btn.disabled = false;
        }}
      }});
    }}
    setupResetButton('resetBtn', 'result', '/reset-nuts',
      'This resets EVERY player\\'s nuts to 100 and cannot be undone.\\nEnter the reset password to confirm:',
      'Reset to 100 nuts');
    setupResetButton('resetTechBtn', 'resultTech', '/reset-tech',
      'This resets EVERY player\\'s tech tree back to default and cannot be undone.\\nEnter the reset password to confirm:',
      'Tech tree reset');
    setupResetButton('resetCosmeticsBtn', 'resultCosmetics', '/reset-cosmetics',
      'This resets EVERY player\\'s cosmetics back to default and cannot be undone.\\nEnter the reset password to confirm:',
      'Cosmetics reset');
  </script>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/login", methods=["GET"])
def admin_login_page(token):
    if not _check_admin_token(token):
        return "Not found", 404
    if _admin_authed():
        return redirect(f"/admin/{token}")

    show_error = request.args.get("error") == "1"
    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Admin Login</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:360px; margin:80px auto 0; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    input {{ width:100%; box-sizing:border-box; padding:10px; margin:10px 0; border-radius:6px; border:none; }}
    button {{ width:100%; background:#8F00FF; color:#fff; border:none; padding:12px 18px; border-radius:6px;
              font-size:15px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    .err {{ color:#ff6b6b; font-size:14px; margin-top:8px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Admin Login</h1>
    <form method="POST" action="/admin/{token}/login">
      <input type="password" name="password" placeholder="Password" autofocus required>
      <button type="submit">Log in</button>
    </form>
    {'<p class="err">Wrong password.</p>' if show_error else ''}
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/login", methods=["POST"])
def admin_login_submit(token):
    if not _check_admin_token(token):
        return "Not found", 404
    submitted = request.form.get("password", "")
    if hmac.compare_digest(submitted, ADMIN_PASSWORD):
        session["admin_authed"] = True
        session.permanent = True
        return redirect(f"/admin/{token}")
    return redirect(f"/admin/{token}/login?error=1")

@app.route("/admin/<token>/server-key", methods=["GET"])
def admin_server_key(token):
    early = _require_admin_login(token)
    if early:
        return early

    current_key = load_server_key()
    raw_key = "(unable to decode)"
    try:
        b64_part = current_key.split(" ", 1)[1]
        raw_key = base64.b64decode(b64_part).decode().rstrip(":")
    except Exception:
        pass

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Server Key</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; margin-top:12px; }}
    button:hover {{ background:#e74c3c; }}
    code {{ font-family:monospace; background:#1b1b22; padding:8px 10px; border-radius:6px; font-size:13px;
            display:block; margin-top:8px; word-break:break-all; }}
    p.note {{ color:#aaa; font-size:13px; }}
    p.warn {{ color:#ff6b6b; font-size:13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Server Key</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a></p>

    <p class="note">Raw key to patch into the client (this is what the APK's Authorization header decodes to):</p>
    <code>{_escape_html(raw_key)}</code>

    <p class="note" style="margin-top:16px;">Full header value this backend actually checks against:</p>
    <code>{_escape_html(current_key)}</code>

    <p class="warn" style="margin-top:20px;">Rotating generates a brand new key immediately — anyone not already patched to it (or not on your bypass/old-key-users lists) gets locked out the instant you do this. Patch the new raw key into your client FIRST, confirm it works, THEN come back and rotate — same order as every previous key rotation.</p>
    <form method="POST" action="/admin/{token}/server-key/rotate" onsubmit="return confirm('This immediately locks out anyone not already patched to the new key. Have you already prepared the new client patch? Only continue if yes.')">
      <button type="submit">Rotate Server Key</button>
    </form>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/server-key/rotate", methods=["POST"])
def admin_server_key_rotate(token):
    early = _require_admin_login(token)
    if early:
        return early

    alphabet = string.ascii_letters + string.digits
    new_raw_key = "".join(secrets.choice(alphabet) for _ in range(16))
    new_full_key = "Basic " + base64.b64encode((new_raw_key + ":").encode()).decode()
    save_server_key(new_full_key)

    log_to_admin_discord(
        f"🔑 **Server key rotated**\n"
        f"🌐 IP: `{request.remote_addr}`\n"
        f"_(via owner panel)_"
    )
    return redirect(f"/admin/{token}/server-key")

@app.route("/admin/<token>/change-url", methods=["POST"])
def admin_change_url(token):
    early = _require_admin_login(token)
    if early:
        return early

    new_token = secrets.token_urlsafe(24)
    save_admin_panel_token(new_token)

    log_to_admin_discord(
        f"🔗 **Owner panel URL changed**\n"
        f"🌐 IP: `{request.remote_addr}`\n"
        f"_(bookmark the new one — the old link no longer works)_"
    )
    # Redirects straight to the new URL so this can never lock you out of
    # your own panel — your browser follows this automatically.
    return redirect(f"/admin/{new_token}")

@app.route("/admin/<token>/reset-nuts", methods=["POST"])
def admin_reset_nuts(token):
    early = _require_admin_login_json(token)
    if early:
        return early

    body = request.get_json(silent=True) or {}
    submitted_pw = body.get("password", "") if isinstance(body, dict) else ""
    if not hmac.compare_digest(str(submitted_pw), RESET_NUTS_PASSWORD):
        log_to_admin_discord(
            f"🚫 **Blocked nuts-reset attempt** — wrong reset password\n"
            f"🌐 IP: `{request.remote_addr}`"
        )
        return jsonify({"error": "wrong password"}), 403

    count = reset_all_nuts_to_100()

    log_to_admin_discord(
        f"🔄 ** all player nuts reset to **100**!\n"
        f"👥 Accounts affected: **{count}**\n"
        f"hi @here"
    )

    return jsonify({"success": True, "accounts_reset": count}), 200

@app.route("/admin/<token>/reset-tech", methods=["POST"])
def admin_reset_tech(token):
    early = _require_admin_login_json(token)
    if early:
        return early

    body = request.get_json(silent=True) or {}
    submitted_pw = body.get("password", "") if isinstance(body, dict) else ""
    if not hmac.compare_digest(str(submitted_pw), RESET_TECH_PASSWORD):
        log_to_admin_discord(
            f"🚫 **Blocked tech-tree-reset attempt** — wrong reset password\n"
            f"🌐 IP: `{request.remote_addr}`"
        )
        return jsonify({"error": "wrong password"}), 403

    count = reset_all_tech_trees()

    log_to_admin_discord(
        f"🔄 **All player tech trees reset**\n"
        f"👥 Accounts affected: **{count}**\n"
        f"hi @here"
    )

    return jsonify({"success": True, "accounts_reset": count}), 200

@app.route("/admin/<token>/reset-cosmetics", methods=["POST"])
def admin_reset_cosmetics(token):
    early = _require_admin_login_json(token)
    if early:
        return early

    body = request.get_json(silent=True) or {}
    submitted_pw = body.get("password", "") if isinstance(body, dict) else ""
    if not hmac.compare_digest(str(submitted_pw), RESET_COSMETICS_PASSWORD):
        log_to_admin_discord(
            f"🚫 **Blocked cosmetics-reset attempt** — wrong reset password\n"
            f"🌐 IP: `{request.remote_addr}`"
        )
        return jsonify({"error": "wrong password"}), 403

    count = reset_all_cosmetics()

    log_to_admin_discord(
        f"🔄 **All player cosmetics reset**\n"
        f"👥 Accounts affected: **{count}**\n"
        f"hi @here"
    )

    return jsonify({"success": True, "accounts_reset": count}), 200

def _leaderboard_players(include_room=False):
    """Shared by both the admin and public leaderboard endpoints. Room code
    is admin-only — not included for the public leaderboard, since it
    reveals exactly where a player currently is, unlike currency stats."""
    now = time.time()
    with _presence_lock:
        seen_copy = dict(_last_seen)
        agents_copy = dict(_client_agent)
        room_copy = dict(_player_room) if include_room else {}

    currencies = _load_currencies()  # in-memory now, so this is effectively free
    players = []
    for uname, ts in seen_copy.items():
        if now - ts > PRESENCE_TIMEOUT_SECONDS:
            continue
        cur = currencies.get(uname, _DEFAULT_CURRENCY)
        entry = {
            "username": uname,
            "nuts": int(cur.get("nuts", 0)),
            "cc": int(cur.get("cc", 0)),
            "rp": int(cur.get("rp", 0)),
            "seconds_ago": int(now - ts),
            "client_version": agents_copy.get(uname, "unknown"),
        }
        if include_room:
            entry["room_code"] = room_copy.get(uname) or ""
        players.append(entry)
    players.sort(key=lambda p: p["nuts"], reverse=True)
    return players

def _render_leaderboard_html(data_url, back_link_html="", show_room=False):
    room_header = "<th>Room</th>" if show_room else ""
    room_cell_js = "<td>${p.room_code || \"—\"}</td>" if show_room else ""
    channel = "full" if show_room else "public"
    # wss:// derived from the same PRESENCE_SERVICE_URL the backend already
    # uses for friend presence — empty if that's not configured, in which
    # case this just falls back to polling below with no live layer at all.
    ws_url = ""
    if PRESENCE_SERVICE_URL:
        ws_url = PRESENCE_SERVICE_URL.replace("https://", "wss://").replace("http://", "ws://") + f"/leaderboard-ws?channel={channel}"
    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Animal Company Rebirth - Leaderboard</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:720px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; font-weight:600; }}
    #empty {{ color:#aaa; margin-top:12px; }}
    #live-dot {{ display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; background:#666; }}
    #live-dot.connected {{ background:#2ecc71; }}
    #live-label {{ font-size:12px; color:#aaa; }}
    a {{ color:#8F00FF; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Currently Connected Players</h1>
    <p>{back_link_html}</p>
    <p><span id="live-dot"></span><span id="live-label">Connecting...</span></p>
    <table id="board">
      <thead><tr><th>#</th><th>Player</th><th>Nuts</th><th>CC</th><th>RP</th><th>Client</th>{room_header}<th>Last seen</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div id="empty" style="display:none;">Nobody's connected right now.</div>
  </div>
  <script>
    const wsUrl = {json.dumps(ws_url)};
    const dot = document.getElementById('live-dot');
    const label = document.getElementById('live-label');
    let pollTimer = null;
    let socket = null;

    function renderPlayers(players) {{
      const rows = document.getElementById('rows');
      const empty = document.getElementById('empty');
      rows.innerHTML = '';
      if (!players.length) {{
        empty.style.display = 'block';
      }} else {{
        empty.style.display = 'none';
        players.forEach((p, i) => {{
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${{i + 1}}</td><td>${{p.username}}</td><td>${{p.nuts}}</td><td>${{p.cc}}</td><td>${{p.rp}}</td><td>${{p.client_version}}</td>{room_cell_js}<td>${{p.seconds_ago}}s ago</td>`;
          rows.appendChild(tr);
        }});
      }}
    }}

    async function pollOnce() {{
      try {{
        const res = await fetch('{data_url}');
        const data = await res.json();
        renderPlayers(data.players);
      }} catch (e) {{
        console.error(e);
      }}
    }}

    function startPolling() {{
      if (pollTimer) return;
      label.textContent = 'Live (polling)';
      dot.classList.remove('connected');
      pollOnce();
      pollTimer = setInterval(pollOnce, 5000);
    }}

    function stopPolling() {{
      if (pollTimer) {{
        clearInterval(pollTimer);
        pollTimer = null;
      }}
    }}

    function connectSocket() {{
      if (!wsUrl) {{
        startPolling();
        return;
      }}
      try {{
        socket = new WebSocket(wsUrl);
      }} catch (e) {{
        startPolling();
        return;
      }}
      socket.onopen = () => {{
        stopPolling();
        dot.classList.add('connected');
        label.textContent = 'Live';
      }};
      socket.onmessage = (event) => {{
        try {{
          const data = JSON.parse(event.data);
          renderPlayers(data.players || []);
        }} catch (e) {{}}
      }};
      socket.onerror = () => {{
        startPolling();
      }};
      socket.onclose = () => {{
        dot.classList.remove('connected');
        startPolling();
        setTimeout(connectSocket, 5000);
      }};
    }}

    connectSocket();
  </script>
</body>
</html>
"""

@app.route("/admin/<token>/leaderboard", methods=["GET"])
def admin_leaderboard(token):
    early = _require_admin_login(token)
    if early:
        return early
    back = f'<a href="/admin/{token}">&larr; back to admin panel</a>'
    return _render_leaderboard_html(f"/admin/{token}/leaderboard-data", back, show_room=True), 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/leaderboard-data", methods=["GET"])
def admin_leaderboard_data(token):
    early = _require_admin_login_json(token)
    if early:
        return early
    return jsonify({"players": _leaderboard_players(include_room=True)}), 200

@app.route("/leaderboard", methods=["GET"])
def public_leaderboard():
    return _render_leaderboard_html("/leaderboard-data"), 200, {"Content-Type": "text/html"}

@app.route("/leaderboard-data", methods=["GET"])
def public_leaderboard_data():
    return jsonify({"players": _leaderboard_players()}), 200

def _escape_html(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))

@app.route("/admin/<token>/bans", methods=["GET"])
def admin_bans(token):
    early = _require_admin_login(token)
    if early:
        return early

    bans = _load_bans()
    if bans:
        rows = "".join(
            f'<tr><td>{_escape_html(u)}</td><td>{_escape_html(r)}</td>'
            f'<td><form method="POST" action="/admin/{token}/bans/remove" onsubmit="return confirm(\'Unban {_escape_html(u)}?\')">'
            f'<input type="hidden" name="username" value="{_escape_html(u)}">'
            f'<button type="submit">Unban</button></form></td></tr>'
            for u, r in bans.items()
        )
    else:
        rows = '<tr><td colspan="3" style="color:#aaa;">No one is banned.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Bans</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    input {{ padding:10px; border-radius:6px; border:none; margin-right:8px; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:14px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Manage Bans</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a></p>
    <form method="POST" action="/admin/{token}/bans/add">
      <input type="text" name="username" placeholder="Username" required>
      <input type="text" name="reason" placeholder="Reason (shown to the player)" required>
      <button type="submit">Ban</button>
    </form>
    <table>
      <thead><tr><th>Username</th><th>Reason</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/bans/add", methods=["POST"])
def admin_bans_add(token):
    early = _require_admin_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip()
    reason = request.form.get("reason", "").strip() or "No reason given."
    if username:
        bans = _load_bans()
        bans[username.lower()] = reason
        _save_bans(bans)
        log_to_bans_discord(
            f"🔨 **Player banned**\n"
            f"👤 User: `{username}`\n"
            f"📝 Reason: {reason}"
        )
    return redirect(f"/admin/{token}/bans")

@app.route("/admin/<token>/bans/remove", methods=["POST"])
def admin_bans_remove(token):
    early = _require_admin_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip().lower()
    bans = _load_bans()
    if username in bans:
        del bans[username]
        _save_bans(bans)
        log_to_bans_discord(f"✅ **Player unbanned**\n👤 User: `{username}`")
    return redirect(f"/admin/{token}/bans")

@app.route("/admin/<token>/bypass", methods=["GET"])
def admin_bypass(token):
    early = _require_admin_login(token)
    if early:
        return early

    names = _load_bypass_list()
    if names:
        rows = "".join(
            f'<tr><td>{_escape_html(n)}</td>'
            f'<td><form method="POST" action="/admin/{token}/bypass/remove" onsubmit="return confirm(\'Remove {_escape_html(n)} from the bypass list?\')">'
            f'<input type="hidden" name="username" value="{_escape_html(n)}">'
            f'<button type="submit">Remove</button></form></td></tr>'
            for n in names
        )
    else:
        rows = '<tr><td colspan="2" style="color:#aaa;">Nobody is on the bypass list.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Bypass List</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    input {{ padding:10px; border-radius:6px; border:none; margin-right:8px; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:14px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
    p.note {{ color:#aaa; font-size:13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Manage Bypass List</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a></p>
    <p class="note">Usernames here can connect even if the app's server key doesn't match — no password backs this, so treat these names themselves as semi-sensitive.</p>
    <form method="POST" action="/admin/{token}/bypass/add">
      <input type="text" name="username" placeholder="Username" required>
      <button type="submit">Add</button>
    </form>
    <table>
      <thead><tr><th>Username</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/bypass/add", methods=["POST"])
def admin_bypass_add(token):
    early = _require_admin_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip().lower()
    if username:
        names = _load_bypass_list()
        if username not in names:
            names.append(username)
            _save_bypass_list(names)
    return redirect(f"/admin/{token}/bypass")

@app.route("/admin/<token>/bypass/remove", methods=["POST"])
def admin_bypass_remove(token):
    early = _require_admin_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip().lower()
    names = _load_bypass_list()
    if username in names:
        names.remove(username)
        _save_bypass_list(names)
    return redirect(f"/admin/{token}/bypass")

@app.route("/admin/<token>/old-key-users", methods=["GET"])
def admin_old_key_users(token):
    early = _require_admin_login(token)
    if early:
        return early

    names = load_old_key_users()
    if names:
        rows = "".join(
            f'<tr><td>{_escape_html(n)}</td>'
            f'<td><form method="POST" action="/admin/{token}/old-key-users/remove" onsubmit="return confirm(\'Remove {_escape_html(n)}?\')">'
            f'<input type="hidden" name="username" value="{_escape_html(n)}">'
            f'<button type="submit">Remove</button></form></td></tr>'
            for n in names
        )
    else:
        rows = '<tr><td colspan="2" style="color:#aaa;">Nobody on this list.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Old Server Key Users</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    input {{ padding:10px; border-radius:6px; border:none; margin-right:8px; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:14px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
    p.note {{ color:#aaa; font-size:13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Old Server Key Users</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a></p>
    <p class="note">Usernames here can still authenticate using the original, pre-patch server key — everyone else must use the current one. Not open to everyone; add people individually as needed while they update.</p>
    <form method="POST" action="/admin/{token}/old-key-users/add">
      <input type="text" name="username" placeholder="Username" required>
      <button type="submit">Add</button>
    </form>
    <table>
      <thead><tr><th>Username</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/old-key-users/add", methods=["POST"])
def admin_old_key_users_add(token):
    early = _require_admin_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip()
    if username:
        names = load_old_key_users()
        if username not in names:
            names.append(username)
            save_old_key_users(names)
    return redirect(f"/admin/{token}/old-key-users")

@app.route("/admin/<token>/old-key-users/remove", methods=["POST"])
def admin_old_key_users_remove(token):
    early = _require_admin_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip()
    names = load_old_key_users()
    if username in names:
        names.remove(username)
        save_old_key_users(names)
    return redirect(f"/admin/{token}/old-key-users")

@app.route("/admin/<token>/promo-codes", methods=["GET"])
def admin_promo_codes(token):
    early = _require_admin_login(token)
    if early:
        return early

    codes = load_promo_codes()
    catalog = _load_avatar_catalog()
    by_id = {i.get("id"): i for i in catalog if isinstance(i, dict)}

    if codes:
        rows = "".join(
            f'<tr><td><code>{_escape_html(code)}</code></td>'
            f'<td>{int(d.get("nuts",0))}</td><td>{int(d.get("cc",0))}</td><td>{int(d.get("rp",0))}</td>'
            f'<td>{", ".join(_escape_html(by_id.get(i, {}).get("name", i)) for i in d.get("cosmetics", [])) or "&mdash;"}</td>'
            f'<td>{_escape_html(d.get("expires") or "Never")}</td>'
            f'<td><form method="POST" action="/admin/{token}/promo-codes/remove" onsubmit="return confirm(\'Remove code {_escape_html(code)}?\')">'
            f'<input type="hidden" name="code" value="{_escape_html(code)}">'
            f'<button type="submit">Remove</button></form></td></tr>'
            for code, d in sorted(codes.items())
        )
    else:
        rows = '<tr><td colspan="7" style="color:#aaa;">No promo codes yet.</td></tr>'

    catalog_rows = "".join(
        f'<tr><td><input type="checkbox" name="cosmetics" value="{_escape_html(i.get("id",""))}"></td>'
        f'<td><code>{_escape_html(i.get("id",""))}</code></td>'
        f'<td>{_escape_html(i.get("name",""))}</td></tr>'
        for i in sorted(catalog, key=lambda x: x.get("name","")) if isinstance(i, dict)
    )

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Promo Codes</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:720px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    h2 {{ font-size:15px; margin:20px 0 4px; color:#ddd; }}
    a {{ color:#8F00FF; }}
    label {{ display:block; margin-top:12px; font-size:13px; color:#aaa; }}
    input[type=text], input[type=number], input[type=date] {{
      width:100%; box-sizing:border-box; padding:10px; margin-top:4px; border-radius:6px; border:none; font-family:inherit;
    }}
    button {{ margin-top:16px; background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
    code {{ font-family:monospace; background:#1b1b22; padding:2px 5px; border-radius:4px; font-size:12px; }}
    p.note {{ color:#aaa; font-size:13px; }}
    #catalogPicker {{ max-height:260px; overflow-y:auto; border:1px solid #3a3a42; border-radius:6px; margin-top:6px; }}
    #catalogPicker table {{ margin-top:0; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Manage Promo Codes</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a></p>
    <p class="note">Codes are matched case-insensitively. Each account can redeem a given code once. Currency rewards are added on top of the player's current balance. Cosmetic rewards go through the per-person grant list — under the current "everyone owns everything except exclusions" design, this only actually matters for items that are currently excluded; otherwise the player already owns it by default. Leave expiry blank for a code that never expires.</p>
    <form method="POST" action="/admin/{token}/promo-codes/add">
      <label>Code</label>
      <input type="text" name="code" placeholder="e.g. WELCOME2026" required>
      <label>Nuts reward</label>
      <input type="number" name="nuts" value="0">
      <label>CC reward</label>
      <input type="number" name="cc" value="0">
      <label>RP reward</label>
      <input type="number" name="rp" value="0">
      <label>Expires (leave blank for never)</label>
      <input type="date" name="expires">

      <label>Cosmetic rewards (optional, select any number)</label>
      <input type="text" id="catalogSearch" placeholder="Search catalog...">
      <div id="catalogPicker">
        <table id="catalogTable">
          <thead><tr><th></th><th>ID</th><th>Name</th></tr></thead>
          <tbody>{catalog_rows}</tbody>
        </table>
      </div>
      <button type="submit">Add Code</button>
    </form>
    <table>
      <thead><tr><th>Code</th><th>Nuts</th><th>CC</th><th>RP</th><th>Cosmetics</th><th>Expires</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <script>
    document.getElementById('catalogSearch').addEventListener('input', function() {{
      const q = this.value.toLowerCase();
      document.querySelectorAll('#catalogTable tbody tr').forEach(row => {{
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      }});
    }});
  </script>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/promo-codes/add", methods=["POST"])
def admin_promo_codes_add(token):
    early = _require_admin_login(token)
    if early:
        return early

    code = request.form.get("code", "").strip().upper()
    if code:
        def _int_field(name):
            try:
                return int(request.form.get(name, "0") or "0")
            except Exception:
                return 0
        cosmetics = [c.strip() for c in request.form.getlist("cosmetics") if c.strip()]
        expires = request.form.get("expires", "").strip() or None
        codes = load_promo_codes()
        codes[code] = {
            "nuts": _int_field("nuts"),
            "cc": _int_field("cc"),
            "rp": _int_field("rp"),
            "cosmetics": cosmetics,
            "expires": expires,
        }
        save_promo_codes(codes)
    return redirect(f"/admin/{token}/promo-codes")

@app.route("/admin/<token>/promo-codes/remove", methods=["POST"])
def admin_promo_codes_remove(token):
    early = _require_admin_login(token)
    if early:
        return early

    code = request.form.get("code", "").strip().upper()
    codes = load_promo_codes()
    if code in codes:
        del codes[code]
        save_promo_codes(codes)
    return redirect(f"/admin/{token}/promo-codes")

# ── Player data migration ────────────────────────────────────────────────
# A player changing their Meta/Oculus username is indistinguishable from a
# brand-new player to this backend — every data file is keyed by the exact
# username string (or a uid deterministically derived from it), and there's
# no other stable identifier this client sends (confirmed much earlier:
# authID is backend-generated, deviceID is never sent at all). A username
# change means every key changes at once, so all their data is still here,
# just filed under a key the game no longer asks for. This can't be
# detected or fixed automatically — only a human who knows "this is the
# same person" can trigger the right migration, which is what this is for.
def _get_case_insensitive(d, key):
    """Looks up key in dict d, trying exact match first, then a
    case-insensitive fallback — different files in this codebase have
    turned out to use different casing conventions historically (e.g. the
    custom-names bug from earlier), so this is safer than assuming any one
    convention here specifically."""
    if key in d:
        return key, d[key]
    lower_key = key.strip().lower()
    for k in d:
        if isinstance(k, str) and k.strip().lower() == lower_key:
            return k, d[k]
    return None, None

def _migrate_username_keyed_file(filepath, old_username, new_username, force=False):
    """Returns (status, detail) where status is one of:
    'migrated', 'no_data', 'conflict', 'overwritten', 'error'.
    force=True makes the old username's data replace whatever's at the new
    username outright, for when you're already certain both names belong
    to the same person — otherwise a conflict is left untouched, since
    this backend has no way to verify that itself."""
    try:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = {}
        if not isinstance(data, dict):
            return "error", "file did not contain a JSON object"

        old_key, old_value = _get_case_insensitive(data, old_username)
        if old_key is None:
            return "no_data", None

        new_key, new_value = _get_case_insensitive(data, new_username)
        if new_key is not None and not force:
            return "conflict", f"'{new_username}' already has its own data in this file"

        if new_key is not None and new_key != new_username:
            del data[new_key]  # different casing of the same destination key
        data[new_username] = old_value
        del data[old_key]
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return ("overwritten" if new_key is not None else "migrated"), None
    except Exception as e:
        return "error", str(e)

@app.route("/admin/<token>/migrate-player", methods=["GET"])
def admin_migrate_player(token):
    early = _require_admin_login(token)
    if early:
        return early

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Migrate Player Data</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    label {{ display:block; margin-top:14px; font-size:13px; color:#ccc; }}
    input[type=text] {{ width:100%; box-sizing:border-box; padding:8px; border-radius:6px; border:none; margin-top:4px; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; margin-top:18px; }}
    button:hover {{ background:#e74c3c; }}
    p.note {{ color:#aaa; font-size:13px; }}
    p.warn {{ color:#ff6b6b; font-size:13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Migrate Player Data</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a></p>
    <p class="note">For a player whose Meta/Oculus username changed and lost access to their data — this copies their currency, cosmetics, purchases, mission/scavenger progress, friends, and promo-code history from their old username to their new one.</p>
    <p class="warn">Only use this when you're confident both usernames genuinely belong to the same person — there's no way for this backend to verify that on its own.</p>
    <form method="POST" action="/admin/{token}/migrate-player">
      <label>Old username (what they used to be)</label>
      <input type="text" name="old_username" required>
      <label>New username (what they are now)</label>
      <input type="text" name="new_username" required>
      <label style="display:flex; align-items:center; gap:8px; margin-top:16px;">
        <input type="checkbox" name="force" value="1" style="width:auto; margin:0;">
        Overwrite — old data replaces anything already saved under the new username (e.g. from them already having logged in once with it). Only check this once you're sure the old data should win.
      </label>
      <button type="submit">Migrate</button>
    </form>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/migrate-player", methods=["POST"])
def admin_migrate_player_submit(token):
    early = _require_admin_login(token)
    if early:
        return early

    old_username = request.form.get("old_username", "").strip()
    new_username = request.form.get("new_username", "").strip()
    if not old_username or not new_username:
        return redirect(f"/admin/{token}/migrate-player")
    force = request.form.get("force") == "1"

    old_uid = generate_deterministic_uid(old_username)
    new_uid = generate_deterministic_uid(new_username)

    results = {}
    for label, path, old_key, new_key in [
        ("Currency", CURRENCY_FILE, old_username, new_username),
        ("Account data", USER_DATA_FILE, old_username, new_username),
        ("Purchased cosmetics", PURCHASED_AVATAR_ITEMS_FILE, old_username, new_username),
        ("Per-person cosmetic grants", PER_PERSON_COSMETICS_FILE, old_username, new_username),
        ("Promo code redemptions", PROMO_REDEMPTIONS_FILE, old_username, new_username),
        ("Custom display name", CUSTOM_NAMES_FILE, old_username, new_username),
        ("Mission progress", MISSION_PROGRESS_FILE, old_uid, new_uid),
        ("Scavenger hunt progress", SCAV_HUNTS_FILE, old_uid, new_uid),
        ("Friends list", FRIENDS_FILE, old_uid, new_uid),
    ]:
        status, detail = _migrate_username_keyed_file(path, old_key, new_key, force=force)
        results[label] = (status, detail)

    # uid_lookup.json maps uid -> username directly, and is already kept
    # correctly up to date as a side effect of generate_deterministic_uid
    # itself (called above for new_uid) — no separate save step needed here.
    results["uid lookup"] = ("migrated", f"{new_uid} -> {new_username}")

    rows = "".join(
        f'<tr><td>{_escape_html(label)}</td>'
        f'<td>{_escape_html(status)}</td>'
        f'<td style="color:#aaa;">{_escape_html(detail or "")}</td></tr>'
        for label, (status, detail) in results.items()
    )

    log_to_admin_discord(
        f"🔀 **Player data migrated**\n"
        f"👤 `{old_username}` → `{new_username}`\n"
        f"📊 " + ", ".join(f"{k}: {v[0]}" for k, v in results.items())
    )

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Migration Result</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Migrated: {_escape_html(old_username)} &rarr; {_escape_html(new_username)}</h1>
    <p><a href="/admin/{token}/migrate-player">&larr; migrate another</a> &middot; <a href="/admin/{token}">back to panel</a></p>
    <table>
      <thead><tr><th>Data</th><th>Result</th><th>Detail</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    <p style="color:#aaa; font-size:13px; margin-top:16px;">"conflict" means the new username already had its own data there and it was left untouched (check "Overwrite" and migrate again to replace it). "overwritten" means it did have data, and the old username's data replaced it since Overwrite was checked. "no_data" means the old username had nothing in that file to migrate, which is normal for a newer player.</p>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/names", methods=["GET"])
def admin_names(token):
    early = _require_admin_login(token)
    if early:
        return early

    names = load_custom_names()
    dev_users = load_dev_users()
    if names:
        rows = "".join(
            f'<tr>'
            f'<td>{_escape_html(uname)}</td>'
            f'<td>{entry.get("display_name","")}</td>'
            f'<td>{"Yes" if uname in dev_users else "No"}</td>'
            f'<td>'
            f'<a href="/admin/{token}/names/edit/{_escape_html(uname)}" style="color:#8F00FF;">Edit</a> '
            f'<form method="POST" action="/admin/{token}/names/delete" onsubmit="return confirm(\'Remove custom name for {_escape_html(uname)}?\')">'
            f'<input type="hidden" name="username" value="{_escape_html(uname)}">'
            f'<button type="submit">Delete</button></form>'
            f'</td></tr>'
            for uname, entry in names.items()
        )
    else:
        rows = '<tr><td colspan="4" style="color:#aaa;">No custom names yet.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Custom Names</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:680px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:6px 12px; border-radius:6px;
              font-size:13px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
    p.note {{ color:#aaa; font-size:13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Manage Custom Names</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a> &middot; <a href="/admin/{token}/names/edit/">Add new</a> &middot; <a href="/admin/{token}/devs" style="color:#8F00FF;">Manage developers &rarr;</a></p>
    <p class="note">Custom names are cosmetic only (rich-text color/size tags) — they no longer grant developer status on their own. Manage that separately on the developers page.</p>
    <table>
      <thead><tr><th>Username</th><th>Display Name</th><th>Is Developer</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/names/edit/", methods=["GET"], defaults={"username": ""})
@app.route("/admin/<token>/names/edit/<username>", methods=["GET"])
def admin_names_edit(token, username):
    early = _require_admin_login(token)
    if early:
        return early

    names = load_custom_names()
    entry = names.get(username, {}) if username else {}

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{"Edit" if username else "New"} Custom Name</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:600px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    label {{ display:block; margin-top:14px; font-size:13px; color:#aaa; }}
    input[type=text] {{
      width:100%; box-sizing:border-box; padding:10px; margin-top:4px; border-radius:6px; border:none; font-family:inherit;
    }}
    button {{ margin-top:20px; background:#8F00FF; color:#fff; border:none; padding:12px 18px; border-radius:6px;
              font-size:15px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    p.note {{ color:#aaa; font-size:12px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{"Edit" if username else "New"} Custom Name</h1>
    <p><a href="/admin/{token}/names">&larr; back to custom names</a></p>
    <form method="POST" action="/admin/{token}/names/save">
      <input type="hidden" name="original_username" value="{_escape_html(username)}">
      <label>Username (exact match, case-sensitive)</label>
      <input type="text" name="username" value="{_escape_html(username)}" required>
      <label>Display Username (rich-text tags allowed, e.g. &lt;color=#800080&gt;Name&lt;/color&gt;)</label>
      <input type="text" name="display_username" value="{_escape_html(entry.get('display_username',''))}" required>
      <label>Display Name</label>
      <input type="text" name="display_name" value="{_escape_html(entry.get('display_name',''))}" required>
      <label>Custom ID (leave blank for a random one each login)</label>
      <input type="text" name="custom_id" value="{_escape_html(entry.get('custom_id',''))}">
      <p class="note">Grant developer status separately on the Manage Developers page — this only sets the cosmetic name.</p>
      <button type="submit">Save</button>
    </form>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/names/save", methods=["POST"])
def admin_names_save(token):
    early = _require_admin_login(token)
    if early:
        return early

    original_username = request.form.get("original_username", "").strip()
    new_username = request.form.get("username", "").strip()
    if not new_username:
        return redirect(f"/admin/{token}/names")

    entry = {
        "display_username": request.form.get("display_username", "").strip(),
        "display_name": request.form.get("display_name", "").strip(),
        "custom_id": request.form.get("custom_id", "").strip(),
    }

    names = load_custom_names()
    if original_username and original_username != new_username and original_username in names:
        del names[original_username]
    names[new_username] = entry
    save_custom_names(names)
    log_to_avatar_discord(f"🎨 **Custom name saved**\n👤 `{new_username}`\n📝 {entry['display_name']}")
    return redirect(f"/admin/{token}/names")

@app.route("/admin/<token>/names/delete", methods=["POST"])
def admin_names_delete(token):
    early = _require_admin_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip()
    names = load_custom_names()
    if username in names:
        del names[username]
        save_custom_names(names)
        log_to_avatar_discord(f"🗑️ **Custom name removed**\n👤 `{username}`")
    return redirect(f"/admin/{token}/names")

@app.route("/admin/<token>/devs", methods=["GET"])
def admin_devs(token):
    early = _require_admin_login(token)
    if early:
        return early

    devs = load_dev_users()
    if devs:
        rows = "".join(
            f'<tr><td>{_escape_html(d)}</td>'
            f'<td><form method="POST" action="/admin/{token}/devs/remove" onsubmit="return confirm(\'Remove developer status from {_escape_html(d)}?\')">'
            f'<input type="hidden" name="username" value="{_escape_html(d)}">'
            f'<button type="submit">Remove</button></form></td></tr>'
            for d in devs
        )
    else:
        rows = '<tr><td colspan="2" style="color:#aaa;">Nobody is a developer.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Developers</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    input {{ padding:10px; border-radius:6px; border:none; margin-right:8px; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:14px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
    p.note {{ color:#aaa; font-size:13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Manage Developers</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a> &middot; <a href="/admin/{token}/names" style="color:#8F00FF;">&larr; Manage custom names</a></p>
    <p class="note">Grants isDeveloper: true in account metadata — a real privilege flag, separate from cosmetic name styling.</p>
    <form method="POST" action="/admin/{token}/devs/add">
      <input type="text" name="username" placeholder="Username" required>
      <button type="submit">Add</button>
    </form>
    <table>
      <thead><tr><th>Username</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/devs/add", methods=["POST"])
def admin_devs_add(token):
    early = _require_admin_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip()
    if username:
        devs = load_dev_users()
        if username not in devs:
            devs.append(username)
            save_dev_users(devs)
    return redirect(f"/admin/{token}/devs")

@app.route("/admin/<token>/devs/remove", methods=["POST"])
def admin_devs_remove(token):
    early = _require_admin_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip()
    devs = load_dev_users()
    if username in devs:
        devs.remove(username)
        save_dev_users(devs)
    return redirect(f"/admin/{token}/devs")

def _render_simple_username_list_page(token, title, back_links, note, list_fn, add_action, remove_action):
    """Shared renderer for the two unlock-all list pages — identical shape
    to the developers page, just parameterized so it isn't duplicated twice."""
    names = list_fn()
    if names:
        rows = "".join(
            f'<tr><td>{_escape_html(n)}</td>'
            f'<td><form method="POST" action="{remove_action}" onsubmit="return confirm(\'Remove {_escape_html(n)}?\')">'
            f'<input type="hidden" name="username" value="{_escape_html(n)}">'
            f'<button type="submit">Remove</button></form></td></tr>'
            for n in names
        )
    else:
        rows = '<tr><td colspan="2" style="color:#aaa;">Nobody on this list.</td></tr>'

    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    input {{ padding:10px; border-radius:6px; border:none; margin-right:8px; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:14px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
    p.note {{ color:#aaa; font-size:13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{title}</h1>
    <p>{back_links}</p>
    <p class="note">{note}</p>
    <form method="POST" action="{add_action}">
      <input type="text" name="username" placeholder="Username" required>
      <button type="submit">Add</button>
    </form>
    <table>
      <thead><tr><th>Username</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
""", 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/unlock-gameplay", methods=["GET"])
def admin_unlock_gameplay(token):
    early = _require_admin_login(token)
    if early:
        return early
    return _render_simple_username_list_page(
        token, "Full Gameplay Unlock",
        f'<a href="/admin/{token}">&larr; back to admin panel</a> &middot; <a href="/admin/{token}/unlock-cosmetics" style="color:#8F00FF;">Full cosmetics unlock &rarr;</a>',
        "Everyone else starts with only the handful of ungated starter items (e.g. flashlight, small backpack, tree stick) — no research nodes unlocked. Usernames here get the entire research tree from account creation.",
        load_gameplay_unlock_all, f"/admin/{token}/unlock-gameplay/add", f"/admin/{token}/unlock-gameplay/remove"
    )

@app.route("/admin/<token>/unlock-gameplay/add", methods=["POST"])
def admin_unlock_gameplay_add(token):
    early = _require_admin_login(token)
    if early:
        return early
    username = request.form.get("username", "").strip()
    if username:
        names = load_gameplay_unlock_all()
        if username not in names:
            names.append(username)
            save_gameplay_unlock_all(names)
    return redirect(f"/admin/{token}/unlock-gameplay")

@app.route("/admin/<token>/unlock-gameplay/remove", methods=["POST"])
def admin_unlock_gameplay_remove(token):
    early = _require_admin_login(token)
    if early:
        return early
    username = request.form.get("username", "").strip()
    names = load_gameplay_unlock_all()
    if username in names:
        names.remove(username)
        save_gameplay_unlock_all(names)
    return redirect(f"/admin/{token}/unlock-gameplay")

@app.route("/admin/<token>/unlock-cosmetics", methods=["GET"])
def admin_unlock_cosmetics(token):
    early = _require_admin_login(token)
    if early:
        return early
    return _render_simple_username_list_page(
        token, "Full Cosmetics Unlock",
        f'<a href="/admin/{token}">&larr; back to admin panel</a> &middot; <a href="/admin/{token}/unlock-gameplay" style="color:#8F00FF;">&larr; Full gameplay unlock</a>',
        "Everyone else starts owning no cosmetics and has to buy each one (real hardPrice, actually charged now). Usernames here own every cosmetic for free from account creation, and purchase.avatarItems never charges them.",
        load_cosmetics_unlock_all, f"/admin/{token}/unlock-cosmetics/add", f"/admin/{token}/unlock-cosmetics/remove"
    )

@app.route("/admin/<token>/unlock-cosmetics/add", methods=["POST"])
def admin_unlock_cosmetics_add(token):
    early = _require_admin_login(token)
    if early:
        return early
    username = request.form.get("username", "").strip()
    if username:
        names = load_cosmetics_unlock_all()
        if username not in names:
            names.append(username)
            save_cosmetics_unlock_all(names)
    return redirect(f"/admin/{token}/unlock-cosmetics")

@app.route("/admin/<token>/unlock-cosmetics/remove", methods=["POST"])
def admin_unlock_cosmetics_remove(token):
    early = _require_admin_login(token)
    if early:
        return early
    username = request.form.get("username", "").strip()
    names = load_cosmetics_unlock_all()
    if username in names:
        names.remove(username)
        save_cosmetics_unlock_all(names)
    return redirect(f"/admin/{token}/unlock-cosmetics")

@app.route("/admin/<token>/excluded-cosmetics", methods=["GET"])
def admin_excluded_cosmetics(token):
    early = _require_admin_login(token)
    if early:
        return early

    excluded = set(load_excluded_cosmetics())
    catalog = _load_avatar_catalog()
    by_id = {i.get("id"): i for i in catalog if isinstance(i, dict)}

    if excluded:
        rows = "".join(
            f'<tr><td><input type="checkbox" name="item_ids" value="{_escape_html(iid)}"></td>'
            f'<td><code>{_escape_html(iid)}</code></td>'
            f'<td>{_escape_html(by_id.get(iid, {}).get("name", "(not in catalog)"))}</td></tr>'
            for iid in sorted(excluded)
        )
    else:
        rows = '<tr><td colspan="3" style="color:#aaa;">Nothing excluded — everyone owns everything.</td></tr>'

    catalog_rows = "".join(
        f'<tr><td><input type="checkbox" name="item_ids" value="{_escape_html(i.get("id",""))}"></td>'
        f'<td><code>{_escape_html(i.get("id",""))}</code></td>'
        f'<td>{_escape_html(i.get("name",""))}</td></tr>'
        for i in sorted(catalog, key=lambda x: x.get("name","")) if isinstance(i, dict) and i.get("id") not in excluded
    )

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Exclude Cosmetics</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:720px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    h2 {{ font-size:15px; margin:24px 0 4px; color:#ddd; }}
    a {{ color:#8F00FF; }}
    input[type=text] {{ width:100%; box-sizing:border-box; padding:8px; border-radius:6px; border:none; margin-top:6px; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:8px 14px; border-radius:6px;
              font-size:13px; cursor:pointer; margin-top:8px; }}
    button:hover {{ background:#e74c3c; }}
    button:disabled {{ opacity:0.4; cursor:not-allowed; }}
    table {{ width:100%; border-collapse:collapse; margin-top:8px; }}
    th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; font-weight:600; }}
    th:first-child, td:first-child {{ width:28px; }}
    code {{ font-family:monospace; background:#1b1b22; padding:2px 5px; border-radius:4px; font-size:12px; }}
    p.note {{ color:#aaa; font-size:13px; }}
    .toolbar {{ display:flex; align-items:center; gap:10px; margin-top:8px; }}
    .toolbar label {{ font-size:13px; color:#ddd; display:flex; align-items:center; gap:5px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Exclude Cosmetics</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a></p>
    <p class="note">Everyone owns every cosmetic by default (except accounts with an individual exclusion here). Excluding something removes it from that default for everyone — "Add Back" restores it. Doesn't affect the full-unlock list or per-person grants, which bypass exclusions entirely.</p>

    <h2>Currently Excluded ({len(excluded)})</h2>
    <form method="POST" action="/admin/{token}/excluded-cosmetics/remove" id="excludedForm">
      <table>
        <thead><tr><th><input type="checkbox" class="selectAll" data-target="excludedForm"></th><th>ID</th><th>Name</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <button type="submit" class="bulkBtn" disabled>Add Selected Back</button>
    </form>

    <h2>Exclude From Catalog</h2>
    <input type="text" id="catalogSearch" placeholder="Search catalog...">
    <form method="POST" action="/admin/{token}/excluded-cosmetics/add" id="catalogForm">
      <table id="catalogTable">
        <thead><tr><th><input type="checkbox" class="selectAll" data-target="catalogForm"></th><th>ID</th><th>Name</th></tr></thead>
        <tbody>{catalog_rows}</tbody>
      </table>
      <button type="submit" class="bulkBtn" disabled>Exclude Selected</button>
    </form>
  </div>
  <script>
    document.getElementById('catalogSearch').addEventListener('input', function() {{
      const q = this.value.toLowerCase();
      document.querySelectorAll('#catalogTable tbody tr').forEach(row => {{
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      }});
    }});

    // "Select all" only selects currently-visible rows (respects search filter),
    // and the bulk button stays disabled until at least one box is checked.
    document.querySelectorAll('.selectAll').forEach(function(master) {{
      const formId = master.getAttribute('data-target');
      const form = document.getElementById(formId);
      const btn = form.querySelector('.bulkBtn');
      const boxes = () => Array.from(form.querySelectorAll('input[name="item_ids"]'));

      function refreshBtn() {{
        btn.disabled = !boxes().some(b => b.checked);
      }}
      master.addEventListener('change', function() {{
        boxes().forEach(b => {{
          if (b.closest('tr').style.display !== 'none') b.checked = master.checked;
        }});
        refreshBtn();
      }});
      form.addEventListener('change', function(e) {{
        if (e.target.name === 'item_ids') refreshBtn();
      }});
    }});
  </script>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/excluded-cosmetics/add", methods=["POST"])
def admin_excluded_cosmetics_add(token):
    early = _require_admin_login(token)
    if early:
        return early
    selected = [i.strip() for i in request.form.getlist("item_ids") if i.strip()]
    if selected:
        ids = load_excluded_cosmetics()
        changed = False
        for item_id in selected:
            if item_id not in ids:
                ids.append(item_id)
                changed = True
        if changed:
            save_excluded_cosmetics(ids)
    return redirect(f"/admin/{token}/excluded-cosmetics")

@app.route("/admin/<token>/excluded-cosmetics/remove", methods=["POST"])
def admin_excluded_cosmetics_remove(token):
    early = _require_admin_login(token)
    if early:
        return early
    selected = set(i.strip() for i in request.form.getlist("item_ids") if i.strip())
    if selected:
        ids = load_excluded_cosmetics()
        new_ids = [i for i in ids if i not in selected]
        if len(new_ids) != len(ids):
            save_excluded_cosmetics(new_ids)
    return redirect(f"/admin/{token}/excluded-cosmetics")

@app.route("/admin/<token>/person-cosmetics", methods=["GET"])
def admin_person_cosmetics(token):
    early = _require_admin_login(token)
    if early:
        return early

    grants = load_per_person_cosmetics()
    by_id = {i.get("id"): i for i in _load_avatar_catalog() if isinstance(i, dict)}

    if grants:
        rows = "".join(
            f'<tr><td>{_escape_html(uname)}</td>'
            f'<td><code>{_escape_html(iid)}</code> — {_escape_html(by_id.get(iid, {}).get("name", "(not in catalog)"))}</td>'
            f'<td><form method="POST" action="/admin/{token}/person-cosmetics/remove" onsubmit="return confirm(\'Remove this grant?\')">'
            f'<input type="hidden" name="username" value="{_escape_html(uname)}">'
            f'<input type="hidden" name="item_id" value="{_escape_html(iid)}">'
            f'<button type="submit">Remove</button></form></td></tr>'
            for uname, item_list in grants.items() for iid in item_list
        )
    else:
        rows = '<tr><td colspan="3" style="color:#aaa;">No individual grants yet.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Per-Person Cosmetics</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:680px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    label {{ display:block; margin-top:14px; font-size:13px; color:#aaa; }}
    input[type=text] {{ width:100%; box-sizing:border-box; padding:10px; margin-top:4px; border-radius:6px; border:none; font-family:inherit; }}
    button {{ margin-top:16px; background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
    code {{ font-family:monospace; background:#1b1b22; padding:2px 5px; border-radius:4px; font-size:12px; }}
    p.note {{ color:#aaa; font-size:13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Per-Person Cosmetics</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a></p>
    <p class="note">Grants a specific item to a specific username, even if that item is on the excluded list — bypasses exclusion for just this (person, item) pair.</p>
    <form method="POST" action="/admin/{token}/person-cosmetics/add">
      <label>Username</label>
      <input type="text" name="username" placeholder="Username" required>
      <label>Item ID (exact, e.g. acc_head_black_1984_headphones)</label>
      <input type="text" name="item_id" placeholder="Item ID" required>
      <button type="submit">Grant</button>
    </form>
    <table>
      <thead><tr><th>Username</th><th>Item</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/person-cosmetics/add", methods=["POST"])
def admin_person_cosmetics_add(token):
    early = _require_admin_login(token)
    if early:
        return early
    username = request.form.get("username", "").strip()
    item_id = request.form.get("item_id", "").strip()
    if username and item_id:
        grants = load_per_person_cosmetics()
        items = grants.setdefault(username, [])
        if item_id not in items:
            items.append(item_id)
            save_per_person_cosmetics(grants)
    return redirect(f"/admin/{token}/person-cosmetics")

@app.route("/admin/<token>/person-cosmetics/remove", methods=["POST"])
def admin_person_cosmetics_remove(token):
    early = _require_admin_login(token)
    if early:
        return early
    username = request.form.get("username", "").strip()
    item_id = request.form.get("item_id", "").strip()
    grants = load_per_person_cosmetics()
    if username in grants and item_id in grants[username]:
        grants[username].remove(item_id)
        if not grants[username]:
            del grants[username]
        save_per_person_cosmetics(grants)
    return redirect(f"/admin/{token}/person-cosmetics")

@app.route("/admin/<token>/libs", methods=["GET"])
def admin_libs(token):
    early = _require_admin_login(token)
    if early:
        return early

    libs = load_default_libs()
    if libs:
        rows = "".join(
            f'<tr><td><code>{_escape_html(l)}</code></td>'
            f'<td><form method="POST" action="/admin/{token}/libs/remove" onsubmit="return confirm(\'Remove {_escape_html(l)}?\')">'
            f'<input type="hidden" name="lib" value="{_escape_html(l)}">'
            f'<button type="submit">Remove</button></form></td></tr>'
            for l in sorted(libs)
        )
    else:
        rows = '<tr><td colspan="2" style="color:#aaa;">No libraries configured.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Known Libraries</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    input {{ padding:10px; border-radius:6px; border:none; margin-right:8px; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
    code {{ font-family:monospace; background:#1b1b22; padding:2px 5px; border-radius:4px; font-size:12px; }}
    p.note {{ color:#aaa; font-size:13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Manage Known Libraries</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a></p>
    <p class="note">Libraries here are treated as known-good on /v2/sync — anything else on a real login triggers an alert (not a block). If a real player's login flags one of your own game's own libraries, confirm it's legitimate, then add it here.</p>
    <form method="POST" action="/admin/{token}/libs/add">
      <input type="text" name="lib" placeholder="e.g. libYourGame.so" required>
      <button type="submit">Add</button>
    </form>
    <table>
      <thead><tr><th>Library</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/libs/add", methods=["POST"])
def admin_libs_add(token):
    early = _require_admin_login(token)
    if early:
        return early

    lib = request.form.get("lib", "").strip()
    if lib:
        libs = load_default_libs()
        if lib not in libs:
            libs.append(lib)
            save_default_libs(libs)
    return redirect(f"/admin/{token}/libs")

@app.route("/admin/<token>/libs/remove", methods=["POST"])
def admin_libs_remove(token):
    early = _require_admin_login(token)
    if early:
        return early

    lib = request.form.get("lib", "").strip()
    libs = load_default_libs()
    if lib in libs:
        libs.remove(lib)
        save_default_libs(libs)
    return redirect(f"/admin/{token}/libs")

@app.route("/admin/<token>/missions", methods=["GET"])
def admin_missions(token):
    early = _require_admin_login(token)
    if early:
        return early

    missions = load_missions()
    if missions:
        rows = "".join(
            f'<tr>'
            f'<td>{_escape_html(m.get("id",""))}</td>'
            f'<td>{_escape_html(m.get("name",""))}</td>'
            f'<td>{_escape_html(m.get("taskType",""))}</td>'
            f'<td>{m.get("rewardHard",0)} cc / {m.get("rewardResearchPoints",0)} rp</td>'
            f'<td>{"Yes" if m.get("dailyReset") else "No"}</td>'
            f'<td>'
            f'<a href="/admin/{token}/missions/edit/{_escape_html(m.get("id",""))}" style="color:#8F00FF;">Edit</a> '
            f'<form method="POST" action="/admin/{token}/missions/delete" onsubmit="return confirm(\'Delete mission {_escape_html(m.get("id",""))}?\')">'
            f'<input type="hidden" name="id" value="{_escape_html(m.get("id",""))}">'
            f'<button type="submit">Delete</button></form>'
            f'</td></tr>'
            for m in missions
        )
    else:
        rows = '<tr><td colspan="6" style="color:#aaa;">No missions yet.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Daily Missions</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:820px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:6px 12px; border-radius:6px;
              font-size:13px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Manage Daily Missions</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a> &middot; <a href="/admin/{token}/missions/edit/">Add new mission</a></p>
    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Task Type</th><th>Reward</th><th>Daily Reset</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/missions/edit/", methods=["GET"], defaults={"mission_id": ""})
@app.route("/admin/<token>/missions/edit/<mission_id>", methods=["GET"])
def admin_missions_edit(token, mission_id):
    early = _require_admin_login(token)
    if early:
        return early

    mission = _mission_def_by_id(mission_id) if mission_id else {}
    args_json = json.dumps(mission.get("args", []))
    current_task_type = mission.get("taskType", "")

    task_type_options = "".join(
        f'<option value="{_escape_html(val)}" data-args-hint="{_escape_html(args_hint)}" {"selected" if val == current_task_type else ""}>'
        f'{_escape_html(val)} — {_escape_html(desc)} (args: {_escape_html(args_hint)})'
        f'</option>'
        for val, desc, args_hint in TASK_TYPES
    )

    # Real item catalog, for taskTypes needing an itemID in args (FindItem,
    # UseItemInArea, KillMonsterWithItem, etc.) — same source file the game
    # itself reads from, so these IDs are confirmed real, not guessed.
    gameplay_items = _load_econ_catalog_file("econ_gameplay_items.json") or []
    item_rows = "".join(
        f'<tr><td><code>{_escape_html(i.get("id",""))}</code></td><td>{_escape_html(i.get("name",""))}</td></tr>'
        for i in sorted(gameplay_items, key=lambda x: x.get("name", "")) if isinstance(i, dict)
    )

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{"Edit" if mission_id else "New"} Mission</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    label {{ display:block; margin-top:14px; font-size:13px; color:#aaa; }}
    input[type=text], input[type=number], textarea, select {{
      width:100%; box-sizing:border-box; padding:10px; margin-top:4px; border-radius:6px; border:none; font-family:inherit;
    }}
    select {{ font-size:13px; }}
    textarea {{ min-height:80px; font-family:monospace; }}
    h2 {{ font-size:15px; color:#ddd; }}
    .note {{ color:#aaa; font-size:12px; }}
    table {{ width:100%; border-collapse:collapse; margin-top:8px; max-height:300px; }}
    th, td {{ text-align:left; padding:5px 8px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; font-weight:600; }}
    code {{ font-family:monospace; background:#1b1b22; padding:2px 5px; border-radius:4px; font-size:12px; }}
    .checkbox-row {{ margin-top:14px; }}
    .checkbox-row label {{ display:inline; margin-left:6px; color:#eee; }}
    button {{ margin-top:20px; background:#8F00FF; color:#fff; border:none; padding:12px 18px; border-radius:6px;
              font-size:15px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{"Edit" if mission_id else "New"} Mission</h1>
    <p><a href="/admin/{token}/missions">&larr; back to missions</a></p>
    <form method="POST" action="/admin/{token}/missions/save">
      <input type="hidden" name="original_id" value="{_escape_html(mission_id)}">
      <label>ID (unique, no spaces — this is just a label you choose, the client doesn't require a specific string)</label>
      <input type="text" name="id" value="{_escape_html(mission.get('id',''))}" required>
      <label>Name</label>
      <input type="text" name="name" value="{_escape_html(mission.get('name',''))}" required>
      <label>Description</label>
      <input type="text" name="description" value="{_escape_html(mission.get('description',''))}">
      <label>Task Type (real enum from the client — the args hint shown is unverified, double-check before relying on it)</label>
      <select name="taskType">
        <option value="">-- choose a task type --</option>
        {task_type_options}
      </select>
      <label>Reward — Hard Currency (cc)</label>
      <input type="number" name="rewardHard" value="{int(mission.get('rewardHard', 0) or 0)}">
      <label>Reward — Research Points</label>
      <input type="number" name="rewardResearchPoints" value="{int(mission.get('rewardResearchPoints', 0) or 0)}">
      <div class="checkbox-row">
        <input type="checkbox" id="dailyReset" name="dailyReset" {"checked" if mission.get("dailyReset") else ""}>
        <label for="dailyReset">Resets daily (can be re-claimed every UTC day)</label>
      </div>
      <label>Args (JSON array — match the shape shown for your chosen Task Type above)</label>
      <textarea name="args" id="argsField">{_escape_html(args_json)}</textarea>
      <button type="submit">Save Mission</button>
    </form>

    <h2 style="margin-top:28px;">Item ID Reference ({len(gameplay_items)})</h2>
    <p class="note">For Task Types that need an itemID (FindItem, UseItemInArea, KillMonsterWithItem, etc.) — copy the ID into your args array. Pulled from the real catalog, not guessed.</p>
    <input type="text" id="itemSearch" placeholder="Search items..." style="width:100%; box-sizing:border-box; padding:8px; border-radius:6px; border:none; margin-top:6px;">
    <table id="itemTable">
      <thead><tr><th>ID</th><th>Name</th></tr></thead>
      <tbody>{item_rows}</tbody>
    </table>
  </div>
  <script>
    // Fills the args template in automatically when a task type is picked,
    // so the correct shape lands in the field itself instead of only being
    // visible in the dropdown text (which is exactly how the last mission
    // ended up with empty args when UseItem needed a count). Only touches
    // the field while it's still at the untouched default ([] or empty) —
    // never overwrites args you've actually filled in yourself.
    document.querySelector('select[name="taskType"]').addEventListener('change', function() {{
      const argsField = document.getElementById('argsField');
      const current = argsField.value.trim();
      if (current === '' || current === '[]') {{
        const hint = this.options[this.selectedIndex].getAttribute('data-args-hint') || '[]';
        argsField.value = hint;
      }}
    }});
    // Simple client-side filter for the item reference table.
    document.getElementById('itemSearch').addEventListener('input', function() {{
      const q = this.value.toLowerCase();
      document.querySelectorAll('#itemTable tbody tr').forEach(row => {{
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      }});
    }});
  </script>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/missions/save", methods=["POST"])
def admin_missions_save(token):
    early = _require_admin_login(token)
    if early:
        return early

    original_id = request.form.get("original_id", "").strip()
    new_id = request.form.get("id", "").strip()
    if not new_id:
        return redirect(f"/admin/{token}/missions")

    try:
        args = json.loads(request.form.get("args", "[]") or "[]")
    except Exception:
        args = []

    mission = {
        "id": new_id,
        "name": request.form.get("name", "").strip(),
        "description": request.form.get("description", "").strip(),
        "taskType": request.form.get("taskType", "").strip(),
        "rewardHard": int(request.form.get("rewardHard", "0") or 0),
        "rewardResearchPoints": int(request.form.get("rewardResearchPoints", "0") or 0),
        "dailyReset": request.form.get("dailyReset") == "on",
        "args": args,
    }

    missions = load_missions()
    if original_id:
        missions = [m for m in missions if not (isinstance(m, dict) and m.get("id") == original_id)]
    missions = [m for m in missions if not (isinstance(m, dict) and m.get("id") == new_id)]
    missions.append(mission)
    save_missions(missions)
    log_to_avatar_discord(f"🎯 **Mission saved**\n🆔 `{new_id}`\n📝 {mission['name']}")
    return redirect(f"/admin/{token}/missions")

@app.route("/admin/<token>/missions/delete", methods=["POST"])
def admin_missions_delete(token):
    early = _require_admin_login(token)
    if early:
        return early

    mission_id = request.form.get("id", "").strip()
    missions = [m for m in load_missions() if not (isinstance(m, dict) and m.get("id") == mission_id)]
    save_missions(missions)
    log_to_avatar_discord(f"🗑️ **Mission deleted**\n🆔 `{mission_id}`")
    return redirect(f"/admin/{token}/missions")

@app.route("/admin/<token>/scavhunts", methods=["GET"])
def admin_scavhunts(token):
    early = _require_admin_login(token)
    if early:
        return early

    config = load_scav_config()
    if config:
        rows = "".join(
            f'<tr>'
            f'<td>{_escape_html(hid)}</td>'
            f'<td>{cfg.get("count",0)}</td>'
            f'<td>{cfg.get("rewardHard",0)} cc / {cfg.get("rewardResearchPoints",0)} rp</td>'
            f'<td>'
            f'<a href="/admin/{token}/scavhunts/edit/{_escape_html(hid)}" style="color:#8F00FF;">Edit</a> '
            f'<form method="POST" action="/admin/{token}/scavhunts/delete" onsubmit="return confirm(\'Delete scavenger hunt {_escape_html(hid)}?\')">'
            f'<input type="hidden" name="hunt_id" value="{_escape_html(hid)}">'
            f'<button type="submit">Delete</button></form>'
            f'</td></tr>'
            for hid, cfg in config.items()
        )
    else:
        rows = '<tr><td colspan="4" style="color:#aaa;">No scavenger hunts yet.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Scavenger Hunts</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:6px 12px; border-radius:6px;
              font-size:13px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:13px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Manage Scavenger Hunts</h1>
    <p><a href="/admin/{token}">&larr; back to admin panel</a> &middot; <a href="/admin/{token}/scavhunts/edit/">Add new hunt</a></p>
    <table>
      <thead><tr><th>Hunt ID</th><th>Items needed</th><th>Reward</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/scavhunts/edit/", methods=["GET"], defaults={"hunt_id": ""})
@app.route("/admin/<token>/scavhunts/edit/<hunt_id>", methods=["GET"])
def admin_scavhunts_edit(token, hunt_id):
    early = _require_admin_login(token)
    if early:
        return early

    cfg = load_scav_config().get(hunt_id, {}) if hunt_id else {}

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{"Edit" if hunt_id else "New"} Scavenger Hunt</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:600px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    label {{ display:block; margin-top:14px; font-size:13px; color:#aaa; }}
    input[type=text], input[type=number] {{
      width:100%; box-sizing:border-box; padding:10px; margin-top:4px; border-radius:6px; border:none; font-family:inherit;
    }}
    button {{ margin-top:20px; background:#8F00FF; color:#fff; border:none; padding:12px 18px; border-radius:6px;
              font-size:15px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{"Edit" if hunt_id else "New"} Scavenger Hunt</h1>
    <p><a href="/admin/{token}/scavhunts">&larr; back to scavenger hunts</a></p>
    <form method="POST" action="/admin/{token}/scavhunts/save">
      <input type="hidden" name="original_hunt_id" value="{_escape_html(hunt_id)}">
      <label>Hunt ID (matches what the client requests, e.g. "v1.1")</label>
      <input type="text" name="hunt_id" value="{_escape_html(hunt_id)}" required>
      <label>Items needed to complete</label>
      <input type="number" name="count" value="{int(cfg.get('count', 10) or 0)}" required>
      <label>Reward — Hard Currency (cc)</label>
      <input type="number" name="rewardHard" value="{int(cfg.get('rewardHard', 0) or 0)}">
      <label>Reward — Research Points</label>
      <input type="number" name="rewardResearchPoints" value="{int(cfg.get('rewardResearchPoints', 0) or 0)}">
      <button type="submit">Save Scavenger Hunt</button>
    </form>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/admin/<token>/scavhunts/save", methods=["POST"])
def admin_scavhunts_save(token):
    early = _require_admin_login(token)
    if early:
        return early

    original_hunt_id = request.form.get("original_hunt_id", "").strip()
    new_hunt_id = request.form.get("hunt_id", "").strip()
    if not new_hunt_id:
        return redirect(f"/admin/{token}/scavhunts")

    entry = {
        "count": int(request.form.get("count", "0") or 0),
        "rewardHard": int(request.form.get("rewardHard", "0") or 0),
        "rewardResearchPoints": int(request.form.get("rewardResearchPoints", "0") or 0),
    }

    config = load_scav_config()
    if original_hunt_id and original_hunt_id != new_hunt_id and original_hunt_id in config:
        del config[original_hunt_id]
    config[new_hunt_id] = entry
    save_scav_config(config)
    log_to_avatar_discord(f"🔍 **Scavenger hunt saved**\n🆔 `{new_hunt_id}`\n📦 {entry}")
    return redirect(f"/admin/{token}/scavhunts")

@app.route("/admin/<token>/scavhunts/delete", methods=["POST"])
def admin_scavhunts_delete(token):
    early = _require_admin_login(token)
    if early:
        return early

    hunt_id = request.form.get("hunt_id", "").strip()
    config = load_scav_config()
    if hunt_id in config:
        del config[hunt_id]
        save_scav_config(config)
        log_to_avatar_discord(f"🗑️ **Scavenger hunt deleted**\n🆔 `{hunt_id}`")
    return redirect(f"/admin/{token}/scavhunts")

# ── Nakama's real in-game leaderboard API ─────────────────────────────────
# Confirmed missing entirely (checked — no route for this existed anywhere
# in this file), so any client call here was a flat 404. Adapted from a
# reference backend, using presence/room tracking already built for the
# admin leaderboard (_last_seen / _player_room / uid_lookup) instead of
# rebuilding separate tracking. Same honest caveat the reference itself
# carries: unverified against real client behavior beyond the response
# shape matching Nakama's ApiLeaderboardRecord fields — confirm the actual
# in-game join flow works as expected once deployed.
def _build_leaderboard_entries(leaderboard_id):
    now = time.time()
    with _presence_lock:
        seen_copy = dict(_last_seen)
        room_copy = dict(_player_room)
    lookup = _load_uid_lookup()
    uid_by_username = {v: k for k, v in lookup.items()}

    currencies = _load_currencies()
    entries = []
    for username, ts in seen_copy.items():
        if now - ts > PRESENCE_TIMEOUT_SECONDS:
            continue
        room = room_copy.get(username)
        if not room:
            continue  # matches the reference: only currently-in-a-room players are listed
        uid = uid_by_username.get(username) or generate_deterministic_uid(username)
        cur = currencies.get(username, _DEFAULT_CURRENCY)
        # Confirmed real bug: this previously always sent the raw login
        # username, never the styled display name. The owning player's own
        # client already knows its own display name from its own account
        # response and substitutes it locally, which is exactly why only
        # they ever saw it colored — everyone else's client just showed
        # whatever this endpoint actually sent, which was the plain name.
        name_entry = _get_custom_name_entry(username)
        display = (name_entry.get("display_name") or username) if name_entry else username
        entries.append({
            "leaderboard_id": leaderboard_id,
            "owner_id": uid,
            "username": display,
            "score": str(int(cur.get("rp", 0))),
            "subscore": "0",
            "num_score": 1,
            "max_num_score": 1,
            "metadata": json.dumps({"roomCode": room}),
            "rank": "0",
            "create_time": "",
            "update_time": "",
            "expiry_time": "0",
        })
    entries.sort(key=lambda e: int(e["score"]), reverse=True)
    for i, e in enumerate(entries, start=1):
        e["rank"] = str(i)
    return entries

@app.route("/v2/leaderboard/<leaderboard_id>", methods=["GET", "POST"])
def A0_leaderboard(leaderboard_id):
    entries = _build_leaderboard_entries(leaderboard_id)

    # Confirmed real bug: this never authenticated the requester at all, so
    # it couldn't filter anything per-viewer — blocking worked correctly
    # server-side (confirmed via /v2/friend/block's own real response) but
    # had no way to reach this endpoint, since it didn't know who was
    # asking. Reciprocal: hides a blocked entry from you AND hides your
    # own entry from someone who blocked you, matching how blocking
    # already removes friend/pending state in both directions.
    token = request.args.get("token", "") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    payload = decode_verified_token(token)
    if payload is not None:
        my_uid = generate_deterministic_uid(payload["usn"])
        my_blocked = set(_load_friends_for(my_uid)["blocked"])
        entries = [
            e for e in entries
            if e["owner_id"] not in my_blocked
            and my_uid not in _load_friends_for(e["owner_id"])["blocked"]
        ]

    return jsonify({"payload": json.dumps({"leaderboardId": leaderboard_id, "entries": entries, "status": "success"})})

@app.route("/v2/leaderboard/<leaderboard_id>/owner/<owner_id>", methods=["GET", "POST"])
def A0_leaderboard_owner(leaderboard_id, owner_id):
    entries = [e for e in _build_leaderboard_entries(leaderboard_id) if e["owner_id"] == owner_id]
    return jsonify({"payload": json.dumps({"leaderboardId": leaderboard_id, "ownerId": owner_id, "entries": entries, "status": "success"})})

# ── Mod panel routes ────────────────────────────────────────────────────────
@app.route("/modpanel/<token>", methods=["GET"])
def mod_panel(token):
    early = _require_mod_login(token)
    if early:
        return early
    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Animal Company Rebirth - Mod Panel</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:480px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; display:block; margin-top:10px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Mod Panel</h1>
    <a href="/modpanel/{token}/bans">Manage bans &rarr;</a>
    <a href="/modpanel/{token}/leaderboard">View live leaderboard &rarr;</a>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/modpanel/<token>/login", methods=["GET"])
def mod_login_page(token):
    if not _check_mod_token(token):
        return "Not found", 404
    if _mod_authed():
        return redirect(f"/modpanel/{token}")

    show_error = request.args.get("error") == "1"
    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Mod Login</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:360px; margin:80px auto 0; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    input {{ width:100%; box-sizing:border-box; padding:10px; margin:10px 0; border-radius:6px; border:none; }}
    button {{ width:100%; background:#8F00FF; color:#fff; border:none; padding:12px 18px; border-radius:6px;
              font-size:15px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    .err {{ color:#ff6b6b; font-size:14px; margin-top:8px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Mod Login</h1>
    <form method="POST" action="/modpanel/{token}/login">
      <input type="password" name="password" placeholder="Password" autofocus required>
      <button type="submit">Log in</button>
    </form>
    {'<p class="err">Wrong password.</p>' if show_error else ''}
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/modpanel/<token>/login", methods=["POST"])
def mod_login_submit(token):
    if not _check_mod_token(token):
        return "Not found", 404
    submitted = request.form.get("password", "")
    if hmac.compare_digest(submitted, MOD_PANEL_PASSWORD):
        session["mod_authed"] = True
        session.permanent = True
        return redirect(f"/modpanel/{token}")
    return redirect(f"/modpanel/{token}/login?error=1")

@app.route("/modpanel/<token>/bans", methods=["GET"])
def mod_bans(token):
    early = _require_mod_login(token)
    if early:
        return early

    bans = _load_bans()
    if bans:
        rows = "".join(
            f'<tr><td>{_escape_html(u)}</td><td>{_escape_html(r)}</td>'
            f'<td><form method="POST" action="/modpanel/{token}/bans/remove" onsubmit="return confirm(\'Unban {_escape_html(u)}?\')">'
            f'<input type="hidden" name="username" value="{_escape_html(u)}">'
            f'<button type="submit">Unban</button></form></td></tr>'
            for u, r in bans.items()
        )
    else:
        rows = '<tr><td colspan="3" style="color:#aaa;">No one is banned.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Bans</title>
  <style>
    body {{ font-family: sans-serif; background:#0000FF; color:#eee; padding:40px; }}
    .card {{ max-width:640px; margin:0 auto; background:#25252b; padding:24px 28px; border-radius:10px; }}
    h1 {{ font-size:20px; margin-top:0; }}
    a {{ color:#8F00FF; }}
    input {{ padding:10px; border-radius:6px; border:none; margin-right:8px; }}
    button {{ background:#8F00FF; color:#fff; border:none; padding:10px 16px; border-radius:6px;
              font-size:14px; cursor:pointer; }}
    button:hover {{ background:#e74c3c; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #3a3a42; font-size:14px; }}
    th {{ color:#aaa; font-weight:600; }}
    form {{ display:inline; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Manage Bans</h1>
    <p><a href="/modpanel/{token}">&larr; back to mod panel</a></p>
    <form method="POST" action="/modpanel/{token}/bans/add">
      <input type="text" name="username" placeholder="Username" required>
      <input type="text" name="reason" placeholder="Reason (shown to the player)" required>
      <button type="submit">Ban</button>
    </form>
    <table>
      <thead><tr><th>Username</th><th>Reason</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/modpanel/<token>/bans/add", methods=["POST"])
def mod_bans_add(token):
    early = _require_mod_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip().lower()
    reason = request.form.get("reason", "").strip()
    if username and reason:
        bans = _load_bans()
        bans[username] = reason
        _save_bans(bans)
        log_to_bans_discord(
            f"🔨 **Player banned**\n"
            f"👤 User: `{username}`\n"
            f"📝 Reason: {reason}\n"
            f"_(via mod panel)_"
        )
    return redirect(f"/modpanel/{token}/bans")

@app.route("/modpanel/<token>/bans/remove", methods=["POST"])
def mod_bans_remove(token):
    early = _require_mod_login(token)
    if early:
        return early

    username = request.form.get("username", "").strip().lower()
    bans = _load_bans()
    if username in bans:
        del bans[username]
        _save_bans(bans)
        log_to_bans_discord(f"✅ **Player unbanned**\n👤 User: `{username}`\n_(via mod panel)_")
    return redirect(f"/modpanel/{token}/bans")

@app.route("/modpanel/<token>/leaderboard", methods=["GET"])
def mod_leaderboard(token):
    early = _require_mod_login(token)
    if early:
        return early
    back = f'<a href="/modpanel/{token}">&larr; back to mod panel</a>'
    return _render_leaderboard_html(f"/modpanel/{token}/leaderboard-data", back, show_room=True), 200, {"Content-Type": "text/html"}

@app.route("/modpanel/<token>/leaderboard-data", methods=["GET"])
def mod_leaderboard_data(token):
    early = _require_mod_login_json(token)
    if early:
        return early
    return jsonify({"players": _leaderboard_players(include_room=True)}), 200

PRIVACY_POLICY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy Policy — Animal Company Rebirth</title>
<style>
  :root {
    --bg: #f7f7f9;
    --surface: #ffffff;
    --text: #1c1c1f;
    --text-muted: #55555c;
    --border: #e2e2e7;
    --accent: #6b4fbb;
    --link: #4b3a94;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #16161a;
      --surface: #1f1f24;
      --text: #ececef;
      --text-muted: #a8a8b3;
      --border: #313138;
      --accent: #a68cff;
      --link: #b9a4ff;
    }
  }
  :root[data-theme="dark"] {
    --bg: #16161a;
    --surface: #1f1f24;
    --text: #ececef;
    --text-muted: #a8a8b3;
    --border: #313138;
    --accent: #a68cff;
    --link: #b9a4ff;
  }

  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    line-height: 1.65;
  }
  .wrap {
    max-width: 720px;
    margin: 0 auto;
    padding: 64px 24px 96px;
  }
  header {
    margin-bottom: 40px;
    padding-bottom: 32px;
    border-bottom: 1px solid var(--border);
  }
  h1 {
    font-size: 28px;
    font-weight: 650;
    margin: 0 0 8px;
    letter-spacing: -0.01em;
  }
  .meta {
    color: var(--text-muted);
    font-size: 14px;
  }
  h2 {
    font-size: 18px;
    font-weight: 650;
    margin: 40px 0 12px;
    letter-spacing: -0.01em;
  }
  p, li {
    font-size: 15.5px;
    color: var(--text);
    max-width: 66ch;
  }
  p.muted {
    color: var(--text-muted);
    font-size: 14px;
  }
  ul {
    padding-left: 22px;
    margin: 12px 0;
  }
  li { margin-bottom: 8px; }
  a { color: var(--link); }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 22px;
    margin: 16px 0;
  }
  .card p:last-child { margin-bottom: 0; }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
    font-size: 14.5px;
  }
  th, td {
    text-align: left;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  th {
    color: var(--text-muted);
    font-weight: 600;
    font-size: 13px;
    text-transform: none;
  }
  .container-scroll {
    overflow-x: auto;
  }
  footer {
    margin-top: 56px;
    padding-top: 24px;
    border-top: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 13px;
  }
</style>
</head>
<body>
<div class="wrap">

  <header>
    <h1>Privacy Policy</h1>
    <div class="meta">Animal Company Rebirth &nbsp;·&nbsp; Last updated September 3, 2026</div>
  </header>

  <p>Animal Company Rebirth is an independently run, private multiplayer server for a VR game. It is not affiliated with or endorsed by the original game's developer or publisher. This page explains what information the server collects from players, why, and how it's handled.</p>

  <h2>Information collected</h2>
  <p>When you connect and play, the server receives and stores:</p>
  <div class="container-scroll">
  <table>
    <tr><th>Category</th><th>What's included</th></tr>
    <tr><td>Account identifier</td><td>The username your client sends when connecting.</td></tr>
    <tr><td>Connection information</td><td>Your IP address and basic client details (app version, headset type), used for account security and to keep the game compatible with your client version.</td></tr>
    <tr><td>Gameplay data</td><td>In-game currency balances, unlocked or owned cosmetic items, research/gameplay progress, mission and scavenger hunt progress.</td></tr>
    <tr><td>Social data</td><td>Friends lists, blocked users, and any custom display name assigned to your account.</td></tr>
    <tr><td>Moderation records</td><td>Ban records (username and reason), kept if enforcement action is taken against an account.</td></tr>
  </table>
  </div>
  <p class="muted">No real-world payment or financial information is collected. In-game currency has no monetary value and cannot be purchased with real money through this server.</p>

  <h2>How this information is used</h2>
  <ul>
    <li>To operate core gameplay: saving your progress, currency, and cosmetics between sessions.</li>
    <li>To support social features: friend requests, friend status, and blocking.</li>
    <li>To maintain a fair environment: detecting cheating or abuse and enforcing bans.</li>
    <li>To keep the game working correctly across different client versions.</li>
  </ul>

  <h2>Third-party services</h2>
  <p>Parts of the game rely on other services to function:</p>
  <div class="card">
    <p><strong>Discord.</strong> Certain server events (such as moderation actions or error alerts) are sent to private Discord channels for the server's own operators. This is for the server's internal monitoring — it isn't a public or player-facing feature.</p>
  </div>
  <div class="card">
    <p><strong>Photon.</strong> Real-time multiplayer positioning and voice chat during gameplay are handled by Photon's networking infrastructure, which is standard for this game engine.</p>
  </div>
  <div class="card">
    <p><strong>Hosting providers.</strong> Server infrastructure runs on third-party hosting providers, which may log standard connection information (like IP addresses) as part of normal infrastructure operation.</p>
  </div>

  <h2>Data retention and deletion</h2>
  <p>Account and gameplay data is kept for as long as an account is active, so that progress persists between sessions. If you'd like your data removed, contact the server operator using the details below and it will be deleted on request.</p>

  <h2>Children's privacy</h2>
  <p>This server is not directed at children under 13, and it does not knowingly collect personal information from anyone under 13.</p>

  <h2>Changes to this policy</h2>
  <p>This policy may be updated as the server's features change. The "last updated" date at the top of this page reflects the most recent revision.</p>

  <h2>Contact</h2>
  <p>Questions about this policy or requests regarding your data can be directed to the server operator via Discord.</p>

  <footer>
    Animal Company Rebirth is an independent, fan-run project and is not affiliated with the original game's developer or publisher.
  </footer>

</div>
</body>
</html>
"""

@app.route("/privacy", methods=["GET"])
def privacy_policy():
    return PRIVACY_POLICY_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}

if __name__ == "__main__":
    app.run(debug=True)
