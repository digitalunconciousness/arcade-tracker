"""Domain logic, kept out of the route functions.

A route parses the request, calls a service, and renders or redirects. A service queries,
decides and computes, and never touches ``request``, ``flash`` or templates, so it can be
tested without a client and reused by more than one page.
"""
