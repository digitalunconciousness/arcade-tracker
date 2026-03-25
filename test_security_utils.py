#!/usr/bin/env python3
"""Focused regression tests for security utility helpers."""

import unittest

from flask import Flask
from security_utils import get_client_ip, is_safe_redirect_url, safe_path_join

app = Flask(__name__)


class SecurityUtilsTestCase(unittest.TestCase):
    """Validate safety checks used across authentication and file handling."""

    def test_safe_path_join_rejects_prefix_traversal(self):
        """Ensure prefix-matching bypasses are blocked."""
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.7"}):
            result = safe_path_join("/tmp/app", "../app_evil/secret.txt")
            self.assertIsNone(result)

    def test_safe_path_join_accepts_child_path(self):
        """Ensure valid child paths still work."""
        result = safe_path_join("/tmp/app", "images/photo.jpg")
        self.assertTrue(result.endswith("/tmp/app/images/photo.jpg"))

    def test_get_client_ip_validates_header_value(self):
        """Fallback to remote_addr when forwarded value is invalid."""
        with app.test_request_context(
            "/",
            headers={"X-Forwarded-For": "not-an-ip"},
            environ_base={"REMOTE_ADDR": "10.0.0.7"},
        ):
            self.assertEqual(get_client_ip(), "10.0.0.7")

    def test_get_client_ip_accepts_valid_forwarded_ip(self):
        """Use forwarded address when present and valid."""
        with app.test_request_context(
            "/",
            headers={"X-Forwarded-For": "203.0.113.8, 10.0.0.1"},
            environ_base={"REMOTE_ADDR": "10.0.0.7"},
        ):
            self.assertEqual(get_client_ip(), "203.0.113.8")

    def test_safe_redirect_rejects_protocol_relative(self):
        """Prevent open redirects via protocol-relative targets."""
        self.assertFalse(is_safe_redirect_url("//evil.example"))
        self.assertTrue(is_safe_redirect_url("/dashboard"))


if __name__ == "__main__":
    unittest.main()
