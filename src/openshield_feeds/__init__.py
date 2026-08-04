"""openshield-feeds — deterministic threat-intelligence feed builder.

Fetches threat feeds from configs/sources.json, normalizes/validates/
de-duplicates them, and publishes format-pure per-category lists under
feeds/ plus machine-readable metadata under metadata/.

Design notes: docs/ARCHITECTURE.md.
"""

__version__ = "1.0.0"
