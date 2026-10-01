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

# Routes that are allowed to answer without a session, with the reason.
PUBLIC = {
    "/skeeball/api/health": "a subsystem health probe; deploy/deploy.sh reports it",
    "/login": "you cannot require a session to reach the login page",
    "/logout": "handled by flask_login",
    "/static/<path:filename>": "static assets",
    "/setup": "first-run admin creation, guarded by there being no users",
}


def _api_rules(app):
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/static"):
            continue
        yield rule


def test_no_api_route_answers_without_a_session(app, client):
    leaked = []
    for rule in _api_rules(app):
        if rule.rule in PUBLIC or "GET" not in (rule.methods or set()):
            continue
        path = rule.rule
        if "<" in path:
            # Substitute something harmless for each converter.
            path = path.replace("<lane_id>", "lane_1")
            if "<" in path:
                continue        # a converter we cannot fill in blind
        response = client.get(path, follow_redirects=False)
        # 200 means it served real content to an anonymous caller.
        if response.status_code == 200:
            leaked.append(f"{rule.rule} -> 200")
    assert not leaked, "these answered 200 without a session:\n  " + "\n  ".join(leaked)


def test_the_health_probe_stays_open(client):
    # deploy/deploy.sh probes this after its liveness gate and reports the result,
    # so it has to answer without a session. It also exercises the skeeball lane
    # manager, which is how a missing gpiozero shows up as a test failure here
    # rather than as a 500 in production.
    response = client.get("/skeeball/api/health", follow_redirects=False)
    assert response.status_code == 200, (
        f"the health probe must answer anonymously, got {response.status_code}"
    )
