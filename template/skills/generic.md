---
id: generic-setup
title: Generic Integration
description: Fallback setup instructions for any detected project
---

# Generic Integration Guide

1. Inspect the project manifest (`package.json`, `pyproject.toml`, `go.mod`, or `Cargo.toml`).
2. Install the matching SDK for the detected ecosystem.
3. Ask the user for any required API key via `ask_user` (with `secret: true`) and store it using `set_env_values`.
4. Add a minimal initialization module following the codebase's existing conventions.
5. Verify the project still builds or passes typechecks.
