# Contributing

## Ground rules

- **Sources and categories change via `configs/` only.** No feed logic in
  PRs that add a source; no source edits in PRs that change logic.
- Generated directories (`feeds/`, `metadata/`, `raw/`, `processed/`) are
  produced by the pipeline — never hand-edit them.
- All checks must pass: config validation, unit tests, integration tests.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
```

The project is stdlib-only; the dev environment adds nothing but the
package itself.

## Useful commands

```bash
openshield-feeds validate-config        # check configs/*.json
openshield-feeds list-sources           # print the registry
openshield-feeds build --no-network     # rebuild from committed caches (offline)
openshield-feeds build --only feodo_tracker_full,botvrij_c2 --force
openshield-feeds verify                 # offline integrity check of feeds/
```

## Testing

- `tests/test_parser.py`, `test_validator.py`, `test_pipeline.py`,
  `test_metadata.py`, `test_config.py` — unit tests.
- `tests/test_integration.py` — full pipeline against `tests/fixtures/`
  via `file://` sources: outputs, metadata, idempotency, cross-checkout
  determinism, verify.
- Add tests for every parser/validator behavior change.

## Style

- Modern stdlib Python (≥ 3.10), type hints, dataclasses, `logging`.
- No new runtime dependencies — the builder must stay install-anywhere.
- Keep the determinism contract: no wall-clock time, randomness, or
  environment-dependent ordering in `feeds/` outputs.
