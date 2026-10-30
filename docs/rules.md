# Rules

Six rules, each answering one question a reviewer would ask before merging a PoC.
The default gate blocks at `high`, so `critical` and `high` need a deliberate
waiver to run.

| ID | Question it answers | Default |
| --- | --- | --- |
| [PG-001](#pg-001-metadata-contract) | Can this template be owned, triaged and maintained? | high |
| [PG-002](#pg-002-identity-and-cve-consistency) | Is its identity unique and consistent with its CVE claims? | high |
| [PG-003](#pg-003-dangerous-capabilities) | Can it hurt the scanner host or escape the target? | critical |
| [PG-004](#pg-004-destructive-or-invasive-payload) | Can it hurt the target? | high |
| [PG-005](#pg-005-weak-matchers) | Will it actually detect the vulnerability, or just produce noise? | high |
| [PG-006](#pg-006-cross-file-duplicates) | Is it a copy of a template we already have? | high |

Severity weights drive the score: `critical` −25, `high` −10, `medium` −4,
`low` −1, `warning` 0. A template starts at 100.

## PG-001 metadata contract

Required: `id`, `info.name`, `info.author`, `info.severity`, `info.description`,
`info.reference`. Also validated:

* `severity` is one of `critical`, `high`, `medium`, `low`, `info`, `unknown`;
* every reference is an absolute `http(s)` URL;
* `cvss-score` is a number between 0.0 and 10.0;
* `tags` is present (low);
* the description is at least 20 characters (low otherwise).

Native templates may use the flat v1 fields (`name`, `severity`, ...); they are
normalized before the rule runs.

## PG-002 identity and CVE consistency

* `id` matches `[a-z0-9][a-z0-9._-]{1,79}` (medium);
* the file name equals the id, so `grep` and SARIF locations agree (medium);
* ids are unique across the whole scan (high on every copy after the first);
* if the id contains `CVE-YYYY-NNNN`, `info.classification.cve-id` must agree
  (high on mismatch, medium when one side is missing);
* a declared CVE without a `cveYYYY` tag is low;
* duplicate YAML keys are high — PyYAML silently keeps the last value.

## PG-003 dangerous capabilities

Nuclei's `code`, `javascript`, `file` and `headless` blocks execute logic on the
machine that scans (critical). `network`, `tcp`, `whois` and `websocket` speak
raw traffic and bypass HTTP scope checks (high).

For any dialect:

* CR/LF in a header name or value — request splitting (high);
* non latin-1 header characters that the runner cannot send (medium);
* a header name that is not an HTTP token (medium);
* a path that is an absolute URL escaping the target (high);
* `unsafe: true` on a request (high);
* a raw request with an absolute request target (high).

## PG-004 destructive or invasive payload

Only *request* values are scanned (paths, payloads, headers, body, raw), never
descriptions or matchers — those legitimately mention destructive strings when
documenting a vulnerability.

High: `DROP TABLE/DATABASE`, `TRUNCATE TABLE`, `DELETE` without `WHERE`,
`xp_cmdshell`, `rm -r[f]`, `mkfs`, `dd if=`, `shutdown`, fork bombs,
`--os-shell`, `--dump-all`, `INTO OUTFILE`, `LOAD_FILE()`, `ALTER TABLE ... DROP`,
`chmod 777`, download-and-execute pipelines.

Medium: time-based probes (`SLEEP`, `BENCHMARK`, `pg_sleep`, `WAITFOR DELAY`,
`DBMS_LOCK.SLEEP`), request fields above 4 KB, and opaque base64 blobs (warning).

A template that *detects* SQL injection does not need to drop a table. If a
payload really is required, waive PG-004 with a reason and scope it to a
disposable target.

## PG-005 weak matchers

* no matchers at all (high);
* status-only, especially `[200]` (high; other codes are medium);
* a regex with fewer than 3 literal characters, such as `.*` (high);
* a word shorter than 3 characters or a ubiquitous word like `error` (medium);
* every matcher negative (high);
* an `and` condition over mutually exclusive status codes (high);
* matcher types the runner cannot evaluate (`xpath`, `binary`, ...) (high);
* a DSL expression that only checks `status_code == 200` (high);
* a size-only matcher (low).

The runner treats unverifiable matchers as errors, not as passes, so a template
that cannot be checked cannot silently look clean.

## PG-006 cross-file duplicates

The fingerprint is `sha256(method + normalized paths + matcher signatures +
condition)` per request:

* identical fingerprint (high) — two copies of the same check;
* same endpoint, different matchers (medium) — likely a fork;
* same CVE in several templates (low) — consolidate on the strongest matcher.

Paths are normalized so a native `/admin` and a Nuclei `{{BaseURL}}/admin`
collide, and raw request targets are parsed for the same comparison.

## Scoring and gates

```text
score = max(0, 100 - 25*critical - 10*high - 4*medium - 1*low)
```

* `--fail-on high` fails `lint` when a non-waived finding is at or above high.
* `--fail-under 80` fails when any single template scores below 80.
* `run` refuses templates with a finding at or above `--block-on` (default high)
  unless `--allow-unsafe` is passed.
* Waived findings stay visible in reports and SARIF (as suppressions) but do not
  affect the score or the gate.
