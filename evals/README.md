# Firmware-analysis LLM evaluation fixtures

- Native baseline recorded: 2026-08-13
- EMBA-import baseline recorded: 2026-08-17
- Model identifier: `synthetic-replay-v1`
- Mode: deterministic replay only in CI

`native-*` fixtures are the six reviewed native-pipeline baselines recorded on
2026-08-13; this change only renamed those files and did not alter their bytes.

`emba-*` fixtures are synthetic recordings for the EMBA-import path. They were
not produced by running EMBA and are not claimed to represent a captured EMBA
execution. They exercise the source-specific evaluation boundary only.

All fixtures contain reviewed structured findings for synthetic firmware
components. No firmware path, host address, customer identifier, or credential
is recorded.
