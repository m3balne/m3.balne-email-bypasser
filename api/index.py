import json
import base64
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

BASE  = "https://accountsettings.roblox.com"
USERS = "https://users.roblox.com"
TSV   = "https://twostepverification.roblox.com"
TIMEOUT = 20


def _session(cookie):
    s = requests.Session()
    s.cookies.set(".ROBLOSECURITY", cookie, domain=".roblox.com")
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/122.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Origin": "https://www.roblox.com",
        "Referer": "https://www.roblox.com/",
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


def _extract_challenge(r):
    """Pull challenge headers off a 403 response."""
    return {
        "id":       r.headers.get("rblx-challenge-id"),
        "type":     r.headers.get("rblx-challenge-type"),
        "metadata": r.headers.get("rblx-challenge-metadata"),
        "body":     r.text[:300],
    }


def _verify_2fa(s, challenge_id, code):
    """Send the 2FA code, return verificationToken or (None, err)."""
    url = f"{TSV}/v1/challenges/{challenge_id}/verify"
    h = {"Content-Type": "application/json"}
    body = {"actionType": "Generic", "code": code}
    r = s.post(url, headers=h, data=json.dumps(body), timeout=TIMEOUT)
    if r.status_code != 200:
        return None, f"2fa verify {r.status_code}: {r.text[:200]}"
    return r.json().get("verificationToken"), None


def _challenge_headers(challenge_id, token):
    meta = base64.b64encode(
        json.dumps({"verificationToken": token}).encode()
    ).decode()
    return {
        "rblx-challenge-id": challenge_id,
        "rblx-challenge-metadata": meta,
    }


def _attempt_unlink(s, csrf, body, challenge_headers=None):
    h = {
        "x-csrf-token": csrf,
        "Content-Type": "application/json",
    }
    if challenge_headers:
        h.update(challenge_headers)

    r = s.post(f"{BASE}/v1/email",
               headers=h,
               data=json.dumps({**body, "emailAddress": ""}),
               timeout=TIMEOUT)
    return r


@app.route("/api", methods=["POST"])
def run():
    data = request.get_json(force=True) or {}
    cookie   = (data.get("cookie")   or "").strip()
    password = (data.get("password") or "").strip()
    pin      = (data.get("pin")      or "").strip() or None
    code     = (data.get("code")     or "").strip() or None

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

    body = {"password": password}
    if pin:
        body["pin"] = pin

    # first attempt
    r = _attempt_unlink(s, csrf, body)
    if r.status_code == 200:
        return jsonify(ok=True, user=me.get("name"), uid=me.get("id"),
                       before=before, after=current_email(s),
                       msg="unlinked (no challenge)")

    # challenge path
    ch = _extract_challenge(r)
    if not ch["id"]:
        return jsonify(ok=False, user=me.get("name"), uid=me.get("id"),
                       before=before, after=before,
                       msg=f"unlink failed {r.status_code}: {r.text[:200]}")

    # no code supplied — tell the caller to send one
    if not code:
        return jsonify(
            ok=False, stage="challenge",
            user=me.get("name"), uid=me.get("id"),
            before=before, after=before,
            challenge_type=ch["type"],
            challenge_id=ch["id"],
            msg=f"challenge required: {ch['type']} — send 2FA code",
        ), 428

    # verify 2FA
    token, err = _verify_2fa(s, ch["id"], code)
    if err:
        return jsonify(ok=False, stage="2fa", user=me.get("name"),
                       uid=me.get("id"), before=before, after=before,
                       msg=err), 401

    # retry with challenge headers
    r2 = _attempt_unlink(s, csrf, body, _challenge_headers(ch["id"], token))
    ok = r2.status_code == 200
    return jsonify(
        ok=ok, user=me.get("name"), uid=me.get("id"),
        before=before, after=current_email(s) if ok else before,
        msg="unlinked with 2FA" if ok else
            f"retry {r2.status_code}: {r2.text[:200]}"
    )


# Vercel entrypoint alias
handler = app
