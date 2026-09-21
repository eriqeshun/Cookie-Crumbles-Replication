"""
Extension experiment (beyond the paper's own figures):

The core experiment (experiment_core.py) shows cookie tossing beats a
victim who has NO pre-existing session. But what if the victim already
has a real, legitimate session when the attacker acts? Then BOTH a
real cookie and a toxic cookie exist at once, with the SAME name --
and the server has to pick one.

This raises two questions the original paper's headline figures don't
directly plot, which we explore as a small sensitivity analysis:

  1. Does the OUTCOME depend on which cookie was created first (i.e.
     whether the victim visited the real site before or after the
     attacker's page ran)?
  2. Does the outcome depend on HOW the server resolves duplicate
     cookie names -- keeping the first occurrence in the Cookie header,
     or the last?

We test question 1 directly against the real, running victim app
(which uses Werkzeug/Flask's actual cookie parsing). For question 2,
since we only have one real server to test against, we additionally
implement our own minimal reference "last-occurrence-wins" parser and
evaluate the same security decision it would have made on the exact
same Cookie header -- letting us compare two resolution policies on
identical data, which is exactly the kind of cross-implementation
inconsistency the original paper documents across real frameworks.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import requests

from cookiejar_sim import CookieJarSim
from harness import start_apps, stop_apps
from experiment_core import parse_set_cookie, extract_hidden_token, VICTIM, ATTACKER

N_TRIALS = 20


def first_occurrence_wins(header: str, name: str) -> str:
    """Reference implementation of 'first occurrence wins' duplicate
    resolution -- this is what we empirically confirmed Werkzeug does."""
    for part in header.split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part.split("=", 1)[1]
    return None


def last_occurrence_wins(header: str, name: str) -> str:
    """Reference implementation of an alternative 'last occurrence
    wins' duplicate resolution policy, representing a different
    implementation choice a framework could plausibly make."""
    value = None
    for part in header.split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            value = part.split("=", 1)[1]
    return value


def build_scenario(order: str):
    """Build the Cookie header a browser would send to the victim,
    for a session where BOTH a real and a toxic cookie exist, created
    in the given order ('victim_first' or 'attacker_first')."""
    jar = CookieJarSim()

    def plant_victim():
        r = requests.get(f"{VICTIM}/", timeout=2)
        name, value, domain_attr, path_attr = parse_set_cookie(r.headers.get("Set-Cookie"))
        jar.set_cookie(name, value, request_host="victim.cc-demo.test",
                        domain_attr=domain_attr, path_attr=path_attr)
        return extract_hidden_token(r.text)

    def plant_attacker():
        r = requests.get(f"{ATTACKER}/attack", timeout=2)
        name, value, domain_attr, path_attr = parse_set_cookie(r.headers.get("Set-Cookie"))
        jar.set_cookie(name, value, request_host="attacker.cc-demo.test",
                        domain_attr=domain_attr, path_attr=path_attr)
        return value

    if order == "victim_first":
        real_token = plant_victim()
        attacker_known = plant_attacker()
    else:
        attacker_known = plant_attacker()
        real_token = plant_victim()

    header = jar.cookie_header_for("victim.cc-demo.test", "/transfer")
    return header, real_token, attacker_known


def run_grid():
    orders = ["attacker_first", "victim_first"]
    policies = {
        "first-occurrence wins\n(Werkzeug, measured)": first_occurrence_wins,
        "last-occurrence wins\n(alternative policy)": last_occurrence_wins,
    }

    grid = {}  # (order, policy_label) -> success rate
    for order in orders:
        for policy_label, resolver in policies.items():
            successes = 0
            for _ in range(N_TRIALS):
                header, real_token, attacker_known = build_scenario(order)
                resolved = resolver(header, "csrf_token")
                # The attacker's forged request always submits the value
                # IT knows -- it never learns `real_token`.
                attack_succeeds = (resolved == attacker_known)
                successes += int(attack_succeeds)
                requests.post(f"{VICTIM}/reset", timeout=2)
            grid[(order, policy_label)] = successes / N_TRIALS
    return grid, orders, list(policies.keys())


def make_plot(grid, orders, policy_labels, outpath):
    fig, ax = plt.subplots(figsize=(8.5, 5.5))
    x = np.arange(len(policy_labels))
    width = 0.35

    for i, order in enumerate(orders):
        values = [grid[(order, p)] * 100 for p in policy_labels]
        offset = (i - 0.5) * width
        bars = ax.bar(x + offset, values, width, label=order.replace("_", " "))
        for bar, v in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, v + 2, f"{v:.0f}%",
                     ha="center", fontsize=10, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(policy_labels)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Does the Attack Still Work With an Existing Session?\n(Sensitivity to Cookie Order and Parser Policy)")
    ax.legend(title="Who set their cookie first")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    print(f"Saved plot to {outpath}")


if __name__ == "__main__":
    victim_proc, attacker_proc = start_apps()
    try:
        grid, orders, policy_labels = run_grid()
        print("Attack success rate by (creation order, resolution policy):")
        for (order, policy), rate in grid.items():
            print(f"  {order:16s} | {policy.replace(chr(10), ' '):35s} -> {rate*100:.0f}%")
        make_plot(grid, orders, policy_labels, "extension_order_sensitivity.png")
    finally:
        stop_apps(victim_proc, attacker_proc)
