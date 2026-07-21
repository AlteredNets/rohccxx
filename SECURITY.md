<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# Security Policy

`rohccxx` handles network packet parsing and compression, so malformed input handling, memory safety, and concurrency safety are security-relevant.

## Reporting A Vulnerability

Please report suspected vulnerabilities privately through [AlteredNets.com](https://AlteredNets.com).

Include:

- A concise description of the issue.
- A reproducer or packet corpus if available.
- The affected commit, branch, or release.
- Whether the issue affects parsing, compression, decompression, ROHCoIPsec, threading, or build/test infrastructure.

## Supported Versions

Until public releases are tagged, security review applies to the current `master` branch.
