"""Shared validation helpers for simple policy/config rules."""

from __future__ import annotations


def validate_non_negative(value: int | float, *, name: str) -> None:
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def validate_positive(value: int | float, *, name: str) -> None:
    if value < 1:
        raise ValueError(f"{name} must be positive")


def validate_minimum(value: int | float, *, name: str, minimum: int | float) -> None:
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
