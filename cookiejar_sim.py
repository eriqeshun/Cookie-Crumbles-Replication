"""
A minimal, RFC 6265-faithful cookie jar simulator.

This exists so the replication scripts can show *exactly* what a
spec-compliant browser would store and send, rather than hiding that
behavior inside a third-party HTTP client's internals. It implements
just the subset of RFC 6265 needed for this demo:

  - the Domain attribute, and the host-only vs. domain-cookie distinction
  - the Path attribute and basic path-matching
  - domain-matching (host-only cookies match only their exact host;
    domain cookies match their domain and any subdomain of it)
  - the creation-time-based ordering RFC 6265 specifies for the
    outgoing Cookie header: longer paths first, then earlier
    creation-time first, among cookies with equal path length

This is NOT a general-purpose or production cookie jar. It exists
purely to make the "cookie tossing" mechanism from Squarcina et al.'s
"Cookie Crumbles" paper transparent and testable for this replication.
"""
from dataclasses import dataclass


@dataclass
class StoredCookie:
    name: str
    value: str
    domain: str       # e.g. "cc-demo.test" (domain cookie) or "victim.cc-demo.test" (host-only)
    path: str
    host_only: bool
    created_at: int

    def domain_matches(self, request_host: str) -> bool:
        if self.host_only:
            return request_host == self.domain
        return request_host == self.domain or request_host.endswith("." + self.domain)

    def path_matches(self, request_path: str) -> bool:
        return request_path.startswith(self.path)


class CookieJarSim:
    """A tiny, inspectable simulation of a browser's cookie jar."""

    def __init__(self):
        self._cookies: list[StoredCookie] = []
        self._clock = 0

    def _tick(self) -> int:
        self._clock += 1
        return self._clock

    def set_cookie(self, name: str, value: str, request_host: str,
                    domain_attr: str = None, path_attr: str = "/") -> None:
        """Simulate the browser processing a Set-Cookie response header
        received while visiting `request_host`."""
        if domain_attr:
            domain = domain_attr.lstrip(".")
            host_only = False
        else:
            domain = request_host
            host_only = True

        # A new Set-Cookie for the same (name, domain, path, host_only)
        # replaces the old one, per RFC 6265.
        self._cookies = [
            c for c in self._cookies
            if not (c.name == name and c.domain == domain and c.path == path_attr and c.host_only == host_only)
        ]
        self._cookies.append(StoredCookie(name, value, domain, path_attr, host_only, self._tick()))

    def cookies_for(self, request_host: str, request_path: str) -> list:
        matches = [
            c for c in self._cookies
            if c.domain_matches(request_host) and c.path_matches(request_path)
        ]
        # RFC 6265 S5.4: longer paths first; among equal path lengths,
        # earlier creation-time first.
        matches.sort(key=lambda c: (-len(c.path), c.created_at))
        return matches

    def cookie_header_for(self, request_host: str, request_path: str) -> str:
        matches = self.cookies_for(request_host, request_path)
        return "; ".join(f"{c.name}={c.value}" for c in matches)

    def reset(self) -> None:
        self._cookies = []
        self._clock = 0
