# Security policy

## Scope

PoCVerify is a defensive tool for people who maintain or review PoC templates.
It performs **static analysis** and, for templates that pass the gate, sends
HTTP requests **only to the target you pass on the command line**.

It is not a scanner-as-a-service, and it does not decide whether you are allowed
to test a target. That is your responsibility.

## Authorization

Use it only against systems you own, systems you have written permission to
test, or local labs such as the bundled `mock/dvwa_mock.py`. Unauthorized
scanning is illegal in most jurisdictions. The maintainers cannot grant
permission and accept no liability for misuse.

## Design guarantees

- `pocverify lint` never executes template code and never opens a network
  connection.
- `pocverify run` refuses any template with a non-waived finding at or above the
  gate threshold unless `--allow-unsafe` is given.
- Request URLs are restricted to the configured target; an absolute URL of a
  different origin is refused, and redirects that change scheme, host or port are
  not followed.
- Response bodies are read with a hard cap (`--max-response-size`, 2 MB default).
- Credentials in request previews (`Cookie`, `Authorization`, ...) are masked.
- Reports contain response bodies and are therefore sensitive; treat
  `reports/` as untrusted input and do not publish evidence from real targets.

## Template execution

`code`, `javascript`, `file` and `headless` templates are **never executed** by
this tool. They are flagged critical and blocked. If you need dynamic execution
of such templates, use the engine they were written for, in an isolated
environment.

## Reporting a vulnerability

Open a private security advisory on GitHub, or email the maintainer listed in
the repository profile. Please include a minimal reproduction (template + command)
and the version. Do not open a public issue for a vulnerability in the tool.

Supported versions: the latest 2.x release receives fixes.
