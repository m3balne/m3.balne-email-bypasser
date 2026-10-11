import json
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

BASE  = "https://accountsettings.roblox.com"
USERS = "https://users.roblox.com"
TIMEOUT = 15


def _session(cookie: str) -> requests.Session:
    s = requests.Session()
    s.cookies.set(".ROBLOSECURITY", cookie, domain=".roblox.com")
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/json",
    })
    return s


def whoami(s):
    r = s.get(f"{USERS}/v1/users/authenticated", timeout=TIMEOUT)
    return r.json() if r.status_code == 200 else None


def current_email(s):
    r = s.get(f"{BASE}/v1/email", timeout=TIMEOUT)
    return r.json().get("emailAddress") if r.status_code == 200 else None


def get_csrf(s):
    r = s.post(f"{BASE}/v1/email", json={}, timeout=TIMEOUT)
    return r.headers.get("x-csrf-token")


def unlink_email(s, csrf, password, pin=None):
    h = {"x-csrf-token": csrf, "Content-Type": "application/json"}
    body = {"password": password}
    if pin:
        body["pin"] = pin

    r = s.delete(f"{BASE}/v1/email", headers=h,
                 data=json.dumps(body), timeout=TIMEOUT)
    if r.status_code == 200:
        return True, "unlinked via DELETE"

    r2 = s.post(f"{BASE}/v1/email", headers=h,
                data=json.dumps({**body, "emailAddress": ""}), timeout=TIMEOUT)
    if r2.status_code == 200:
        return True, "unlinked via POST"

    r3 = s.post(f"{BASE}/v1/email/remove", headers=h,
                data=json.dumps(body), timeout=TIMEOUT)
    if r3.status_code == 200:
        return True, "unlinked via /remove"

    return False, (
        f"delete={r.status_code} {r.text[:120]} | "
        f"post={r2.status_code} {r2.text[:120]} | "
        f"remove={r3.status_code} {r3.text[:120]}"
    )


@app.route("/api", methods=["POST"])
def run():
    data = request.get_json(force=True) or {}
    cookie   = (data.get("cookie")   or "").strip()
    password = (data.get("password") or "").strip()
    pin      = (data.get("pin")      or "").strip() or None

    if not cookie or not password:
        return jsonify(ok=False, stage="input",
                       msg="cookie and password required"), 400

    s = _session(cookie)

    me = whoami(s)
    if not me:
        return jsonify(ok=False, stage="auth",
                       msg="cookie rejected"), 401

    before = current_email(s)
    csrf = get_csrf(s)
    if not csrf:
        return jsonify(ok=False, stage="csrf",
                       msg="no x-csrf-token returned"), 502

    ok, msg = unlink_email(s, csrf, password, pin)
    after = current_email(s) if ok else before

    return jsonify(
        ok=ok,
        user=me.get("name"),
        uid=me.get("id"),
        before=before,
        after=after,
        msg=msg,
    )
