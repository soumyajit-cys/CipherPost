"""Standalone capture agent (Phase 3 Task 3): `cipherpost-agent`.

Captures, reassembles, and parses locally (only `app.parsing` +
`app.live.{reassembly,packets}` — never redis/fastapi/sqlalchemy), then ships
SESSION METADATA ONLY to the server ingest endpoint. Raw payload bytes and
mail content never leave the sensor; see PRIVACY_ALLOW_LIST in meta.py.
"""
from __future__ import annotations
