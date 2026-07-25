"""Firmware parser backends with backward-compatible public exports."""

from ai_firmware_agent.parsers.binwalk import parse_binwalk_result
from ai_firmware_agent.parsers.mock import (
    components_from_manifest,
    make_demo_firmware,
    parse_firmware,
    parse_firmware_file,
)

__all__ = [
    "components_from_manifest",
    "make_demo_firmware",
    "parse_binwalk_result",
    "parse_firmware",
    "parse_firmware_file",
]
