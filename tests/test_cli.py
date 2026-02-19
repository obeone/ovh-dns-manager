"""
Tests for the cli module.

Covers: logging configuration.

Copyright (c) 2026 Snapp'
Author: Yannis Duvignau (yduvignau@snapp.fr)
"""

from ovh_dns_manager.cli import setup_logging


class TestSetupLogging:
    """Tests for logging configuration."""

    def test_default_level(self):
        setup_logging(verbose=False)

    def test_verbose_level(self):
        setup_logging(verbose=True)
