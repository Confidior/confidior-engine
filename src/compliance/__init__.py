"""Compliance framework mapping, kept separate from the assurance engine.

This package is **not part of grading**. The engine's output is an evidence
bundle; mapping that evidence onto a framework's checklist is a downstream
reading of it, and this package is where that reading lives. Nothing in
``src/core``, ``src/export``, ``src/cli`` or ``src/web`` imports it, so the
engine can be built, tested and shipped without it.

Why it is separate
------------------

- **The checklist is not the product.** Most of a framework's criteria are
  organizational: whether a policy document exists, whether an auditor
  interviewed staff. A quote cannot speak to them, so a mapping derived from
  attestation evidence is mostly "GAP" for reasons that say nothing about the
  workload.
- **Licensing.** The C5:2026 catalogue is BSI's, CC BY-ND 4.0, non-commercial.
  The engine is Apache 2.0. Bundling a mapping that requires BSI's terms would
  put the engine's licence in tension with its data, so the data is not
  shipped and this package is opt-in.
- **Someone else maintains the frameworks.** Rego control libraries now cover
  the frameworks most users ask for, including C5. See
  ``docs/COMPLIANCE.md`` for how to use those instead of this module.

What consumes it
----------------

Nothing, by default. ``confidior compliance`` renders a mapping on request, and
the web UI exposes it behind its own route. The verification path
(``confidior verify``) does not call it.
"""
