# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Describe the problem, how to reproduce it, and its impact.

GitHub keeps the report private between you and the maintainer:
https://github.com/Sebastian197/skill-preinstall-review/security/advisories/new

You can expect an acknowledgement within 7 days. Confirmed problems are
fixed in a new release, and the advisory is published once the fix is out.
Reporters are credited unless they ask otherwise.

## What counts as a vulnerability here

This tool runs untrusted code inside a Docker container, so these are in
scope and especially welcome:

- a reviewed package escaping the container, reaching the network, or
  reading or writing files on the host;
- a reviewed package tampering with the evidence (traces, sinkhole log,
  filesystem diffs) so the report misses what it did;
- anything in the host-side scripts that executes, follows symlinks into or
  writes outside the reviewed package or the report directory;
- a report that states a package is safe or hides a finding it recorded.

A package that behaves well only inside the sandbox, or waits for a trigger
the review does not provide, is a documented limit rather than a
vulnerability (see the Limits section of the README), but reports that show
a practical way to close such a gap are welcome as ordinary issues.

## Supported versions

Only the latest release receives fixes.
