"""Every API route needs a session, except the health probe.

Four skeeball GET routes were reachable without logging in -- /api/lanes,
/api/lanes/<id>/status, /api/lanes/<id>/stats and /api/health -- on a site
published to the internet through a Cloudflare tunnel. The first three now
require a session. /api/health stays open deliberately: deploy/deploy.sh polls it
to decide whether a deployment succeeded, before any session exists.

This test reads the route table rather than a hand-written list, so a new
unauthenticated route fails here instead of being noticed in production.
"""
from __future__ import annotations

import re

# Routes authorised by something that is not a session, with what authorises them. These do
# not redirect to /login -- they refuse in their own way -- so a check that only knows about
# sessions reads them as leaks. They still have to refuse.
TOKEN_AUTHORISED = {
    "/api/v1/roster": (
        "a GATBOX device bearer token. requires_device answers its own JSON 401 and is "
        "deliberately not stacked on @login_required, which would 302 a machine."
    ),
    "/api/v1/machines/<slug>/orders": "the same device bearer token",
    "/report/<token>": (
        "Phase 2.5: the coin-door capability token *is* the URL. Someone who opened the door "
        "read it off a QR, and an unknown token is a 404 -- there is no session to have."
    ),
}

# Routes that are allowed to answer without any credential at all, with the reason.
PUBLIC = {
    "/skeeball/api/health": "a subsystem health probe; deploy/deploy.sh reports it",
    "/login": "you cannot require a session to reach the login page",
    "/logout": "handled by flask_login",
    "/static/<path:filename>": "static assets",
    "/setup": "first-run admin creation, guarded by there being no users",
    "/api/v1/health": (
        "GATBOX reads it to choose between the LAN address and the tunnel, and needs the "
        "answer before it can commit to a request. It reveals only that the app is up."
    ),
}


def _api_rules(app):
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/static"):
            continue
        yield rule


# A value for every converter, so a parameterised route is checked rather than skipped.
# What the value is does not matter: @login_required runs before the view, so a protected
# route redirects whatever the parameter says. A route that answers 200 here either has no
# session check or has its decorators in the wrong order, and both are the point.
CONVERTER = re.compile(r"<(?:(int|float|path|string|uuid|any)(?:\([^)]*\))?:)?([^>]+)>")
FILLER = {"int": "1", "float": "1.0", "path": "x", "uuid": "0" * 32}


def _fill(rule: str) -> str:
    return CONVERTER.sub(lambda m: FILLER.get(m.group(1) or "", "x"), rule)


def test_every_parameterised_route_is_filled_in(app):
    """The guard below is only worth anything if it actually reaches these routes.

    Until Phase 2.5 it substituted <lane_id> and skipped anything still containing a
    converter, so /g/<code> -- the one route GATBOX's printed labels resolve through -- had
    never been checked, and neither would /report/<token> have been. A filler that silently
    stops working would put the whole check back to sleep, which is what this asserts.
    """
    unfilled = [r.rule for r in _api_rules(app) if "<" in _fill(r.rule)]
    assert not unfilled, "no filler for:\n  " + "\n  ".join(unfilled)


def test_every_route_not_listed_as_public_sends_an_anonymous_caller_to_the_login_page(
        app, client):
    """A redirect to /login, specifically -- not merely "did not return 200".

    Checking for 200 is what let the previous version of this pass while saying nothing. A
    route whose parameter is a lookup key answers 404 to a made-up value, so an endpoint that
    requires no session at all looked identical to one that requires one. The redirect is the
    signature of @login_required, so demanding it is what actually distinguishes them -- and
    it catches a route whose decorators are in the wrong order, where the view runs and
    aborts before the session is ever checked.
    """
    wrong = []
    for rule in _api_rules(app):
        if rule.rule in PUBLIC or rule.rule in TOKEN_AUTHORISED:
            continue
        if "GET" not in (rule.methods or set()):
            continue
        response = client.get(_fill(rule.rule), follow_redirects=False)
        location = response.headers.get("Location", "")
        if response.status_code != 302 or "/login" not in location:
            wrong.append(f"{rule.rule} -> {response.status_code} {location}".rstrip())
    assert not wrong, (
        "these did not send an anonymous caller to the login page; each is either missing a "
        "session check or belongs in PUBLIC with a reason:\n  " + "\n  ".join(wrong)
    )


def test_a_route_is_listed_in_one_category_at_most(app):
    """PUBLIC means "no credential". TOKEN_AUTHORISED means "a credential that is not a
    session". A route in both would be a claim that nobody has read."""
    both = set(PUBLIC) & set(TOKEN_AUTHORISED)
    assert not both, f"listed as both public and token-authorised: {sorted(both)}"


def test_both_lists_name_routes_that_exist(app):
    """A stale entry is worse than a missing one: it silently exempts nothing while reading
    like it exempts something, and the route it was written for is checked by nobody."""
    rules = {r.rule for r in app.url_map.iter_rules()}
    for name, listed in (("PUBLIC", PUBLIC), ("TOKEN_AUTHORISED", TOKEN_AUTHORISED)):
        missing = sorted(set(listed) - rules)
        assert not missing, f"{name} names routes that no longer exist: {missing}"


def test_a_token_authorised_route_still_refuses_an_anonymous_caller(app, client):
    """Being outside the session check is not permission to answer. Each of these has to
    refuse a caller with no credential -- 401 for the device API, 404 for a coin-door token
    nobody holds -- and the one thing none of them may do is serve content."""
    served = []
    for path in TOKEN_AUTHORISED:
        rule = next(r for r in app.url_map.iter_rules() if r.rule == path)
        if "GET" not in (rule.methods or set()):
            continue
        response = client.get(_fill(path), follow_redirects=False)
        if response.status_code not in (401, 403, 404):
            served.append(f"{path} -> {response.status_code}")
    assert not served, "these answered an anonymous caller:\n  " + "\n  ".join(served)


def test_the_health_probe_stays_open(client):
    # deploy/deploy.sh probes this after its liveness gate and reports the result,
    # so it has to answer without a session. It also exercises the skeeball lane
    # manager, which is how a missing gpiozero shows up as a test failure here
    # rather than as a 500 in production.
    response = client.get("/skeeball/api/health", follow_redirects=False)
    assert response.status_code == 200, (
        f"the health probe must answer anonymously, got {response.status_code}"
    )
