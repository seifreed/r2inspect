#!/usr/bin/env python3
"""Hashing-related display sections."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from .display_sections_common import Results, _get_console
from . import display_sections_hashing_fuzzy_views as _fuzzy_views
from . import display_sections_hashing_symbol_views as _symbol_views
from . import display_sections_hashing_views as _hashing_views


def _bind_console_getter() -> None:
    _hashing_views._get_console = _get_console
    _fuzzy_views._get_console = _get_console
    _symbol_views._get_console = _get_console


def _display_ssdeep(results: Results) -> None:
    _bind_console_getter()
    _hashing_views.display_ssdeep(results)


def _display_tlsh(results: Results) -> None:
    _bind_console_getter()
    _hashing_views.display_tlsh(results)


def _add_tlsh_entries(table: Table, tlsh_info: dict[str, Any]) -> None:
    _hashing_views.add_tlsh_entries(table, tlsh_info)


def _display_telfhash(results: Results) -> None:
    _bind_console_getter()
    _hashing_views.display_telfhash(results)


def _add_telfhash_entries(table: Table, telfhash_info: dict[str, Any]) -> None:
    _hashing_views.add_telfhash_entries(table, telfhash_info)


def _display_impfuzzy(results: Results) -> None:
    _bind_console_getter()
    _hashing_views.display_impfuzzy(results)


def _add_impfuzzy_entries(table: Table, impfuzzy_info: dict[str, Any]) -> None:
    _hashing_views.add_impfuzzy_entries(table, impfuzzy_info)


def _display_ccbhash(results: Results) -> None:
    _bind_console_getter()
    _hashing_views.display_ccbhash(results)


def _add_ccbhash_entries(table: Table, ccbhash_info: dict[str, Any]) -> None:
    _hashing_views.add_ccbhash_entries(table, ccbhash_info)
