# Security Policy

PromptGuard is a security **tool**, but it is also software, and software has bugs. This policy covers vulnerabilities **in PromptGuard itself** — not prompts it fails to catch (those are ordinary bug reports; see [CONTRIBUTING.md](CONTRIBUTING.md#reporting-a-bypass)).

## Supported versions

Only the latest release line receives security fixes.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email **Kushagra Dubey** at `kushagra.23b1531207@abes.ac.in` with:

- a description of the issue and its impact,
- a minimal repro (input, command, or request),
- the PromptGuard version and your Python / scikit-learn versions,
- any suggested fix.

You should get an acknowledgement within a few days. Please allow reasonable time to triage and fix before any public disclosure.

## Scope

**In scope:** a way to make PromptGuard mishandle input such that it creates a real risk for a system relying on it — for example a sanitization bypass that lets an injection through when the caller relied on `sanitize` / `build_defense`, or a crash in the server.

**Out of scope here** (but welcome as a normal issue): a prompt-injection string the detector *scores too low*. That is a detection miss, not a vulnerability in the tool — report it so the corpus can grow.

## Hardening you can do regardless

PromptGuard is one layer, not a wall. Combine it with model alignment, output filtering, least-privilege tool access, and human review. The defenses are mitigations — see the README's "What this is not" section.
