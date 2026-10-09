---
name: threat-modeling
description: >-
  Maps a component's entry points, trust boundaries, and sensitive data paths
  and writes or updates a threat_model.md artifact at the workspace root
  (entry points, trust-boundary checks, threat matrix) that
  test-driven-development turns into security tests. Use when starting a
  security review or audit of a component or endpoint, when asked whether a
  design is safe, what could go wrong, or how an attacker could abuse it, for
  an attack surface analysis, when a new or changed endpoint accepts untrusted
  input or crosses an authentication or privilege boundary, or when scoping a
  reported vulnerability before any code changes. Don't use for writing the
  tests or code (use test-driven-development, which calls this skill in its
  PLAN step), for checking specific code against secure coding rules (use
  secure-coding), or for dependency vulnerability scanning (use
  secure-coding).
---

# Security Threat Model Skill

## Overview
Use this skill at the start of a security review or component planning to map entry points, trust boundaries, and sensitive data paths.

The primary output of this skill is a **Threat Model Artifact** (`threat_model.md` located at the root of the workspace). This artifact is directly consumed by the **test-driven-development skill** to guide the creation of security-hardening tests.

## Steps
1. **Identify Purpose**: Understand what the component does and what assets it protects.
2. **Map Entry Points**: Document all user inputs and interfaces (HTTP endpoints, CLI parameters, config files, environment variables).
3. **Identify Trust Boundaries**: Map authentication barriers, access control levels, and privilege transitions (e.g., user vs. admin, public internet vs. internal service).
4. **Map Sensitive Data Paths**: Trace where credentials, keys, PII, and critical application state flow and are stored.
5. **Generate Threat Model Artifact**: Write a `threat_model.md` file at the root of the workspace listing the identified risks, entry points, and trust boundaries.

## Target Output Structure (`threat_model.md`)
Your generated threat model should be stored at the root of the workspace and include:
- **Entry Points**: A list of inputs and endpoints that must be validated.
- **Trust Boundaries**: A list of checks required to enforce authentication and authorization.
- **Threat Matrix**: A mapping of potential vulnerabilities (e.g., SQL Injection at `/user`, Path Traversal at `/read_file`).
