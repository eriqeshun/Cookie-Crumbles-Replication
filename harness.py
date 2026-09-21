"""
Shared helper for starting/stopping the two local Flask apps used by
the replication scripts. Both apps are bound to 127.0.0.1 only.
"""
import subprocess
import time
import sys
import requests


def wait_until_up(url, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            requests.get(url, timeout=0.5)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)
    return False


def start_apps():
    victim = subprocess.Popen(
        [sys.executable, "victim_app.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    attacker = subprocess.Popen(
        [sys.executable, "attacker_app.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    ok_v = wait_until_up("http://victim.cc-demo.test:5000/")
    ok_a = wait_until_up("http://attacker.cc-demo.test:5001/attack")
    if not (ok_v and ok_a):
        stop_apps(victim, attacker)
        raise RuntimeError(
            "Could not start local demo apps. Check that victim.cc-demo.test and "
            "attacker.cc-demo.test resolve to 127.0.0.1 in your hosts file, and "
            "that ports 5000/5001 are free."
        )
    return victim, attacker


def stop_apps(victim, attacker):
    for p in (victim, attacker):
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
