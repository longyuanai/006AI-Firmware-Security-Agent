# Importing an existing EMBA report

`firmware-agent` can read one machine-readable artifact produced by an existing
EMBA installation. It does not install, invoke, embed, or distribute EMBA.

## Supported artifact

The importer accepts the JSON file written by EMBA's official F15 CycloneDX
SBOM module when all of these markers are present:

- CycloneDX schema `http://cyclonedx.org/schema/bom-1.5.schema.json`
- `bomFormat` `CycloneDX`, `specVersion` `1.5`, document `version` `1`
- `metadata.tools.components` identifies
  `EMBA binary analysis environment`, authored by `EMBA community`
- `components`, `dependencies`, and the F15 `vulnerabilities: []` field

This is the only format implemented and tested. The tests use a synthetic
recording of that documented shape, not output captured from a real EMBA run.
HTML reports, module CSV files, loose per-module JSON logs, XML, protobuf, SPDX,
other CycloneDX versions, and non-empty vulnerability arrays are rejected.

The current official F15 generator leaves `vulnerabilities` empty. Imported
components therefore pass through this product's existing CVE matcher; the
importer does not guess vulnerability fields that EMBA did not emit.

## Usage

If you already have that EMBA report:

```powershell
firmware-agent scan --emba-report EMBA_cyclonedx_sbom.json --json
```

Omit `--json` to pass the imported component inventory through the normal CVE
matching and LLM report pipeline. `--emba-report` is mutually exclusive with
`--input`, `--demo`, and `--sbom`.

Malformed JSON, missing required fields, unsupported versions, and unknown
schema shapes produce distinct error types and fail closed. Component
properties and firmware paths from the imported document are not copied into
the internal model.

## License boundary

EMBA is GPL-3.0. This MIT-licensed product does not include or distribute EMBA,
does not depend on it, and does not execute it. Import is limited to reading an
output file that a user already possesses.
