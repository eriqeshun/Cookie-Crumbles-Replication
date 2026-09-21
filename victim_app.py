"""
Victim application ("The Bank"): a minimal Flask app implementing a
textbook synchronizer-token CSRF defense.

  GET  /          serves a page with a money-transfer form. It issues a
                   fresh random CSRF token, stored BOTH in a cookie
                   (csrf_token, host-only -- no Domain attribute) and
                   embedded in the page as a hidden form field.

  POST /transfer   accepts the form submission. The defense: the token
                   submitted in the form body must match the token
                   found in the incoming request's csrf_token cookie.
                   If they match, the transfer is "approved".

This mirrors the synchronizer-token CSRF defense discussed in
Squarcina, Adao, Veronese & Maffei, "Cookie Crumbles: Breaking and
Fixing Web Session Integrity" (USENIX Security 2023) -- specifically
the case where the secrecy of the token depends on the cookie jar
being a trustworthy, exclusive channel between this app and the
browser, an assumption the paper shows does not always hold.

Runs only on localhost. Part of the educational replication in this
repository -- not intended to demonstrate anything against real,
third-party systems.
"""
import secrets
from flask import Flask, request, make_response

app = Flask(__name__)

STATE = {"balance": 1000, "approved_transfers": []}


@app.route("/", methods=["GET"])
def home():
    token = secrets.token_hex(16)  # 128 bits of randomness
    html = f"""<html><body>
      <h1>The Bank</h1>
      <p>Balance: ${STATE['balance']}</p>
      <form action="/transfer" method="POST">
        <input type="hidden" name="csrf_token" value="{token}">
        Amount: <input type="text" name="amount">
        <button type="submit">Transfer</button>
      </form>
    </body></html>"""
    resp = make_response(html)
    # Host-only cookie: no Domain attribute, so a spec-compliant browser
    # should only ever send this back to this exact host. This is the
    # trust assumption the demo's attack goes on to break.
    resp.set_cookie("csrf_token", token, httponly=True, path="/")
    return resp


@app.route("/transfer", methods=["POST"])
def transfer():
    submitted_token = request.form.get("csrf_token", "")
    cookie_token = request.cookies.get("csrf_token", "")

    if not cookie_token or submitted_token != cookie_token:
        return {"status": "rejected", "reason": "csrf token mismatch",
                "submitted_token": submitted_token, "cookie_token": cookie_token}, 403

    amount = request.form.get("amount", "0")
    STATE["approved_transfers"].append(amount)
    return {"status": "approved", "amount": amount, "cookie_token_used": cookie_token}


@app.route("/reset", methods=["POST"])
def reset():
    STATE["approved_transfers"] = []
    return {"status": "reset"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
