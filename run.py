#!/usr/bin/env python3
"""Arcade Tracker — application entry point.

Usage::

    python run.py          # development server on 0.0.0.0:5000
    python run.py --port 8080
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Arcade Tracker")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app.run(host=args.host, port=args.port, debug=args.debug)
