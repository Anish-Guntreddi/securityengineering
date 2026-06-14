# Security Policy & Authorized-Use Notice

This repository contains **defensive and educational** security tooling. Every tool
here is built to protect, audit, or teach about code and infrastructure that **you own
or are explicitly authorized to test.**

## Authorized use only

- **SecretHawk** scans Git repositories. Only scan repositories you own or maintain.
- **WebShield** inspects the security configuration of a website. Only point it at
  hosts you own or have **written authorization** to test. It is read-only and
  non-destructive by design, and it refuses to run without an explicit
  authorized-target confirmation flag.
- **AuthLab** is an educational playground. Its "insecure" demonstrations are
  sandboxed, clearly labeled, and never target real users or real credentials.

These tools do **not** include offensive exploitation capabilities: no auto-revocation,
no live key abuse, no weaponized payloads, no fuzzing, and no detection evasion.

## Reporting a vulnerability

If you find a security issue in this project, please open a GitHub issue describing the
problem and steps to reproduce. Do not include real secrets or live credentials in
reports — redact them first.
