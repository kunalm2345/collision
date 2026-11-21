---
id: nextjs-setup
title: Next.js Integration
description: Install and initialize Your Product in a Next.js App Router or Pages Router project
frameworks: [nextjs]
---

# Next.js Integration Guide

1. Install the SDK using the detected package manager (`npm`, `pnpm`, `yarn`, or `bun`).
2. Add the public API key via the `set_env_values` tool (never read `.env*` files directly).
3. Initialize the client in the App Router (`app/providers.tsx`) or Pages Router (`pages/_app.tsx`).
4. Run the project's typecheck or build script to confirm zero errors.
