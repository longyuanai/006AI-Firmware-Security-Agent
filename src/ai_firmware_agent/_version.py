"""Single source of the product version.

Kept in its own module so low-level code (HTTP clients, the SBOM exporter)
can read it without importing the package root, which pulls in the LLM layer.
"""

from __future__ import annotations

__version__ = "0.1.0"

#: Sent on every outbound request this product makes.
USER_AGENT = f"ai-firmware-security-agent/{__version__}"
