"""HTTPS awareness behind the Cloudflare tunnel (F-22).

The site is reached two ways (deploy/listen.conf.example):

* through the tunnel, which connects to 127.0.0.1:5000 and says ``X-Forwarded-Proto: https``;
* on the LAN, over plain HTTP, straight to the server's address.

A ``Secure`` cookie is never sent over plain HTTP, so marking every cookie Secure would stop
anyone signing in on the LAN address. Instead a request counts as HTTPS when it really is, or
when it comes from loopback (the tunnel) saying so, and only then do its cookies get
``Secure``. A LAN client sending the header itself is ignored: it isn't on loopback.

In production waitress decides the scheme: the unit file passes ``--trusted-proxy=127.0.0.1
--trusted-proxy-headers=x-forwarded-proto``, and waitress 3 drops the header from anyone else
before the app sees it. The loopback check below does the same job under any other server
(the development server, the test client), so the rule doesn't depend on how the app is run.

This sits at the WSGI layer because Flask writes the session cookie after every
``after_request`` hook has run, and Flask-Login sets the remember cookie in a hook of its own;
rewriting ``Set-Cookie`` on the way out catches both, whatever order they run in.
"""
from __future__ import annotations

LOOPBACK = frozenset({"127.0.0.1", "::1"})


class HttpsAware:
    """WSGI middleware: trust the tunnel's scheme, and mark cookies Secure over HTTPS."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        forwarded = environ.get("HTTP_X_FORWARDED_PROTO", "").split(",")[0].strip().lower()
        if environ.get("REMOTE_ADDR") in LOOPBACK and forwarded == "https":
            environ["wsgi.url_scheme"] = "https"
        if environ.get("wsgi.url_scheme") != "https":
            return self.app(environ, start_response)

        def secure_cookies(status, headers, exc_info=None):
            headers = [(name, secure(value) if name.lower() == "set-cookie" else value)
                       for name, value in headers]
            return start_response(status, headers, exc_info)

        return self.app(environ, secure_cookies)


def secure(cookie: str) -> str:
    """Add the Secure attribute to one Set-Cookie value, once."""
    attributes = [part.strip().lower() for part in cookie.split(";")[1:]]
    return cookie if "secure" in attributes else cookie + "; Secure"
