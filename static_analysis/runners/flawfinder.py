"""Flawfinder runner."""

from __future__ import annotations

from static_analysis.runners.sarif import SarifRunner


class FlawfinderRunner(SarifRunner):
    tool_name = "flawfinder"

