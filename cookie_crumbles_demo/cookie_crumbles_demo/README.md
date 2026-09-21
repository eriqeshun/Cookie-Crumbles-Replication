# Cookie Tossing Replication — COE 576 End of Semester Assessment

Replication of the central mechanism of:

> M. Squarcina, P. Adao, L. Veronese, and M. Maffei, "Cookie Crumbles:
> Breaking and Fixing Web Session Integrity," *32nd USENIX Security
> Symposium (USENIX Security '23)*, pp. 5539-5556.

**Central claim being tested:** a synchronizer-token CSRF defense that
stores its secret token in a cookie is only as secure as the
assumption that nobody else can write to that cookie's namespace. A
**related subdomain** of the same registrable domain can violate that
assumption ("cookie tossing") by setting a cookie of the same name via
the `Domain` attribute — letting it get a forged request approved
**without ever learning the real secret**, something a genuinely
unrelated attacker cannot do.

## Scope and ethics note

Everything in this repository runs **entirely on `localhost`**,
against two toy applications this project also provides. No real,
third-party website, domain, or service is contacted, scanned, or
targeted at any point. The vulnerability class demonstrated here is
already public and peer-reviewed (see the paper above); this project
reproduces the *mechanism* for educational purposes on synthetic
`*.cc-demo.test` hostnames that only resolve to `127.0.0.1` on your
own machine.

## Repository Contents

- `victim_app.py` — "The Bank": a minimal Flask app implementing a
  textbook synchronizer-token CSRF defense (secret token in a cookie,
  checked against a hidden form field).
- `attacker_app.py` — "The Trickster": a minimal Flask app that plants
  ("tosses") a cookie scoped to the shared parent domain.
- `cookiejar_sim.py` — a small, RFC 6265-faithful cookie jar simulator
  written from scratch for this project, so the replication scripts
  can show *exactly* what a spec-compliant browser would store and
  send, rather than relying on a third-party HTTP client's internal
  cookie handling.
- `harness.py` — shared helper for starting/stopping the two local
  Flask apps from the experiment scripts.
- `experiment_core.py` — **Core replication.** Runs three scenarios
  (legitimate user, unrelated outsider, cookie-tossing sibling
  subdomain) for 20 trials each and plots the CSRF defense's approval
  rate under each. Produces `core_result_cookie_tossing.png`.
- `experiment_extension.py` — **Extension (beyond the paper).** Tests
  whether the attack still works when the victim already has a
  legitimate session, as a function of (a) which cookie was created
  first and (b) how the server resolves duplicate cookie names (the
  real, measured Werkzeug behavior vs. an alternative reference
  policy implemented from scratch). Produces
  `extension_order_sensitivity.png`.
- `test_demo.py` — Unit tests for the cookie jar simulator and the
  victim app's core accept/reject logic (does not require the live
  servers or hosts file setup).

## Setup

### 1. Point the demo hostnames at localhost

Add these two lines to your hosts file (`/etc/hosts` on Mac/Linux,
`C:\Windows\System32\drivers\etc\hosts` on Windows — editing it
requires administrator privileges):

```
127.0.0.1 victim.cc-demo.test
127.0.0.1 attacker.cc-demo.test
```

### 2. Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate       # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running

Run the unit tests first (fast, no servers required):

```bash
python3 test_demo.py
```

Run the core replication (starts both apps itself, runs the
experiment, shuts them down):

```bash
python3 experiment_core.py
```

Run the extension experiment:

```bash
python3 experiment_extension.py
```

### Running the apps manually (optional)

If you want to click through the demo yourself in a browser:

```bash
python3 victim_app.py      # in one terminal
python3 attacker_app.py    # in another terminal
```

Then visit `http://victim.cc-demo.test:5000/` to see the real form,
and `http://attacker.cc-demo.test:5001/attack` to see the attacker's
page plant its cookie (check your browser's dev tools → Application →
Cookies to see both `csrf_token` cookies coexisting).

## Notes on Results

- The core experiment shows a clean 100% / 0% / 100% split: the
  legitimate flow works, an unrelated outsider is correctly rejected,
  and the cookie-tossing sibling-subdomain attacker is approved every
  time — confirming the paper's central claim that relatedness, not
  cross-site-ness, is what actually matters for this class of bypass.
- The extension shows the attack's success against an *already
  logged-in* victim flips entirely based on (a) whether the attacker's
  cookie was planted before or after the victim's real one, and (b)
  which duplicate-cookie resolution policy the server implements. This
  mirrors the original paper's finding that different real-world
  frameworks disagree on this resolution, making the practical impact
  of cookie tossing implementation-dependent rather than universal.

## Reproducibility

The core experiment's "legit" scenario uses a fresh random 128-bit
token per trial (via `secrets.token_hex`), by design — this is
intentional, since the whole point is to show the attack works
regardless of what the real secret happens to be. All other logic is
deterministic given the scenario.
