"""
Test suite covering:
  1. The RFC 6265 cookie jar simulator's domain-matching, path-matching,
     and creation-time ordering logic.
  2. The victim app's basic security logic in isolation (using Flask's
     test client, so this does not require the live servers or the
     hosts file entries to be set up).
"""
from cookiejar_sim import CookieJarSim
import victim_app


def test_host_only_cookie_scoping():
    jar = CookieJarSim()
    jar.set_cookie("csrf_token", "REAL", request_host="victim.cc-demo.test")

    # Host-only cookie should NOT be sent to a sibling subdomain.
    assert jar.cookies_for("attacker.cc-demo.test", "/") == []
    # ...but should be sent back to the exact host that set it.
    sent = jar.cookies_for("victim.cc-demo.test", "/")
    assert len(sent) == 1 and sent[0].value == "REAL"
    print("OK: host-only cookies are scoped to their exact host")


def test_domain_cookie_reaches_siblings():
    jar = CookieJarSim()
    jar.set_cookie("csrf_token", "TOSSED", request_host="attacker.cc-demo.test",
                    domain_attr="cc-demo.test")

    sent_to_victim = jar.cookies_for("victim.cc-demo.test", "/")
    sent_to_unrelated = jar.cookies_for("unrelated.other.test", "/")

    assert len(sent_to_victim) == 1 and sent_to_victim[0].value == "TOSSED"
    assert sent_to_unrelated == []
    print("OK: domain-scoped cookies reach sibling subdomains but not unrelated domains")


def test_creation_time_ordering():
    jar = CookieJarSim()
    jar.set_cookie("csrf_token", "FIRST", request_host="victim.cc-demo.test")
    jar.set_cookie("csrf_token", "SECOND", request_host="attacker.cc-demo.test",
                    domain_attr="cc-demo.test")

    header = jar.cookie_header_for("victim.cc-demo.test", "/")
    assert header == "csrf_token=FIRST; csrf_token=SECOND", header
    print("OK: cookies are ordered oldest-first, per RFC 6265")


def test_victim_app_accepts_matching_token():
    client = victim_app.app.test_client()
    home = client.get("/")
    cookie_value = home.headers.get("Set-Cookie").split("csrf_token=")[1].split(";")[0]

    resp = client.post("/transfer", data={"csrf_token": cookie_value, "amount": "50"})
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "approved"
    print("OK: victim app approves a request whose form token matches its cookie")


def test_victim_app_rejects_mismatched_token():
    client = victim_app.app.test_client()
    client.get("/")  # sets a real cookie in the test client's jar

    resp = client.post("/transfer", data={"csrf_token": "not-the-real-token", "amount": "50"})
    assert resp.status_code == 403
    assert resp.get_json()["status"] == "rejected"
    print("OK: victim app rejects a request whose form token does not match its cookie")


if __name__ == "__main__":
    test_host_only_cookie_scoping()
    test_domain_cookie_reaches_siblings()
    test_creation_time_ordering()
    test_victim_app_accepts_matching_token()
    test_victim_app_rejects_mismatched_token()
    print("\nAll tests passed.")
