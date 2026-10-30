# Architecture

## The pipeline

```text
templates/*.yaml
      │
      ▼
 loader.py ── dialect detection ── normalization ── line index
      │            native / nuclei / legacy v1        (YAML path → line)
      ▼
 lint/engine.py ── 6 rules ── waivers ── score
      │
      ▼
 gate.py ── block on severity ── --allow-unsafe
      │
      ├──────────────► report (Markdown / SARIF / JSON)
      ▼
 runner/http.py ── scoped URL ── HTTP ── matcher evaluation ── evidence
```

`lint` stops after the linter. `run` goes through the gate and only then sends
requests. The gate is the link that makes this one tool instead of two: a
template that fails lint is refused by the runner unless a human explicitly
overrides it.

## Module map

| Module | Responsibility |
| --- | --- |
| `schema.py` | `Template`, `Request`, `Matcher`, `Finding`, `Severity`, rule metadata, scoring weights |
| `loader.py` | YAML parsing, node-tree line index, dialect detection, normalization, discovery |
| `config.py` | `.pocverify.yaml`, glob waivers with mandatory reasons, thresholds |
| `lint/engine.py` | rule execution, waiver application, per-template scores, unused waivers |
| `lint/rules/*` | PG-001 … PG-006 |
| `gate.py` | which templates may run |
| `runner/http.py` | URL construction, payload expansion, redirect policy, HTTP, evidence |
| `runner/matchers.py` | status/word/regex/size/dsl matchers and evidence extraction |
| `runner/dsl.py` | the supported Nuclei DSL subset, with explicit failures |
| `report/*` | Markdown bundle, SARIF 2.1.0, JSON |
| `cli.py` | `lint`, `run`, `rules`; exit codes |

Nothing downstream of the loader branches on the source dialect. That is the
main design constraint: one model, one rule set, two input formats.

## Trust boundary

A PoC is executable content written by a stranger. The tool assumes:

1. **The template is hostile.** It may contain `code`, `javascript` or `file`
   blocks, or a payload that destroys the target.
2. **The target is authorized but not disposable.** Sending a `DROP TABLE` to
   prove a SQL injection is worse than not proving it.
3. **The collection is duplicated.** The same CVE arrives in several variants,
   each one multiplying requests and alerts.

Therefore:

* lint never executes a template, resolves no code, and sends no request;
* run refuses what the gate blocks, and only accepts a *same-origin* absolute URL
  even with `--allow-unsafe` off; a different origin requires the explicit flag;
* redirects that change scheme/host/port are not followed;
* `Host` in raw requests is always replaced by the target;
* response bodies are capped, credentials in previews are masked, and reports
  are written as untrusted Markdown.

## Line mapping

`yaml.compose` returns a node tree with `start_mark.line` for every key and list
item. The loader walks it once and stores `YAML path → 1-based line`, so a rule
can say "this finding is at `pocs/x.yaml:12`" without regexing the source. When
a key is absent, `Template.line_at` walks up to the nearest parent, which is why
"missing author" points at the `info:` block rather than line 1.

## Failure modes and their handling

| Failure | Behaviour |
| --- | --- |
| YAML syntax error | collected as a load error; exit code 2 |
| duplicate YAML key | PG-002 high (values would silently override) |
| unsupported matcher | PG-005 high; the runner reports ERROR instead of PASS |
| unknown DSL function | lint medium; runner ERROR |
| network failure | retried, then reported as ERROR, never as FAIL |
| rule exception | converted to a `PG-000` warning; other rules still run |
| unused waiver | reported; fails with `--strict-waivers` |

## Deliberate limitations

* No concurrency or rate limiter beyond `--delay` between templates.
* No authentication flow: cookies are copied into the template.
* Nuclei DSL support is a documented subset (flat `&&` / `||`, no parentheses).
* Nuclei `payloads` expand up to 50 combinations, then the request is refused.
* Only the first matching request of a template is kept as evidence.
* No template execution, sandboxing or dynamic analysis of `code` blocks — by
  design, that is a different tool.
