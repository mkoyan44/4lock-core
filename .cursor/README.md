# 4lock-core Cursor setup

Cursor rules and docs are instantiated from 4lock-agent patterns and adapted for 4lock-core (Linux-only Rust workspace: blob, container, vappc).

## Structure

- **`.cursor/docs/`** – Architecture and development documentation
  - `00-overview.md` – System purpose, layout, design
  - `01-crate-architecture.md` – blob, container, vappc modules
  - `05-development-guide.md` – Build, run, test, Makefile
  - `README.md` – Doc index

- **`.cursor/rules/`** – Cursor rules (alwaysApply where set)
  - `00-context-inclusion.mdc` – Mandatory: load docs and rules before tasks
  - `00-os-specific-rules.mdc` – Linux-only; containerized build/run
  - `01-core-project.mdc` – Project layout, what to be careful with
  - `02-rust-workspace.mdc` – Rust/Cargo and crate guidelines
  - `04-cursor-workflow.mdc` – Build/run/test workflow
  - `05-architecture-usage.mdc` – When to consult which doc

## Context loading

**MANDATORY**: Consult `.cursor/docs/` and `.cursor/rules/` before making changes. See `00-context-inclusion.mdc` for the full rule.

## Quick links

- Overview: `.cursor/docs/00-overview.md`
- Crate layout: `.cursor/docs/01-crate-architecture.md`
- Build/run: `.cursor/docs/05-development-guide.md`
- Rules: `.cursor/rules/01-core-project.mdc`, `.cursor/rules/05-architecture-usage.mdc`
