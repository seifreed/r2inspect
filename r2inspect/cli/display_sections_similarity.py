#!/usr/bin/env python3
"""Similarity and analysis-related display sections."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from .display_sections_common import Results, _get_console
from . import display_sections_similarity_binlex as _sim_binlex_ops
from . import display_sections_similarity_binbloom as _sim_binbloom_ops
from . import display_sections_similarity_misc as _sim_misc_ops


def _sync_console_hooks() -> None:
    _sim_binlex_ops._get_console = _get_console
    _sim_binbloom_ops._get_console = _get_console
    _sim_misc_ops._get_console = _get_console


def _display_binlex(results: Results) -> None:
    _sync_console_hooks()
    _sim_binlex_ops._display_binlex(results)


def _add_binlex_entries(table: Table, binlex_info: dict[str, Any]) -> None:
    _sim_binlex_ops._add_binlex_entries(table, binlex_info)


def _add_binlex_basic_stats(table: Table, binlex_info: dict[str, Any]) -> list[Any]:
    return _sim_binlex_ops._add_binlex_basic_stats(table, binlex_info)


def _add_binlex_unique_signatures(
    table: Table, ngram_sizes: list[Any], unique_signatures: dict[str, Any]
) -> None:
    _sim_binlex_ops._add_binlex_unique_signatures(table, ngram_sizes, unique_signatures)


def _add_binlex_similarity_groups(
    table: Table, ngram_sizes: list[Any], similar_functions: dict[str, Any]
) -> None:
    _sim_binlex_ops._add_binlex_similarity_groups(table, ngram_sizes, similar_functions)


def _add_binlex_binary_signatures(
    table: Table, ngram_sizes: list[Any], binary_signature: dict[str, Any]
) -> None:
    _sim_binlex_ops._add_binlex_binary_signatures(table, ngram_sizes, binary_signature)


def _add_binlex_top_ngrams(
    table: Table, ngram_sizes: list[Any], top_ngrams: dict[str, Any]
) -> None:
    _sim_binlex_ops._add_binlex_top_ngrams(table, ngram_sizes, top_ngrams)


def _display_binbloom(results: Results) -> None:
    _sync_console_hooks()
    _sim_binbloom_ops._display_binbloom(results)


def _add_binbloom_stats(table: Table, binbloom_info: dict[str, Any]) -> None:
    _sim_binbloom_ops._add_binbloom_stats(table, binbloom_info)


def _add_binbloom_similar_groups(table: Table, binbloom_info: dict[str, Any]) -> None:
    _sim_binbloom_ops._add_binbloom_similar_groups(table, binbloom_info)


def _add_binbloom_group(table: Table, index: int, group: dict[str, Any]) -> None:
    _sim_binbloom_ops._add_binbloom_group(table, index, group)


def _add_binbloom_binary_signature(table: Table, binbloom_info: dict[str, Any]) -> None:
    _sim_binbloom_ops._add_binbloom_binary_signature(table, binbloom_info)


def _add_binbloom_bloom_stats(table: Table, binbloom_info: dict[str, Any]) -> None:
    _sim_binbloom_ops._add_binbloom_bloom_stats(table, binbloom_info)


def _display_binbloom_signature_details(binbloom_info: dict[str, Any]) -> None:
    _sync_console_hooks()
    _sim_binbloom_ops._display_binbloom_signature_details(binbloom_info)


def _display_simhash(results: Results) -> None:
    _sync_console_hooks()
    _sim_misc_ops._display_simhash(results)


def _display_bindiff(results: Results) -> None:
    _sync_console_hooks()
    _sim_misc_ops._display_bindiff(results)


def _display_machoc_functions(results: Results) -> None:
    _sync_console_hooks()
    _sim_misc_ops._display_machoc_functions(results)
