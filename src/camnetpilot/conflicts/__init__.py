"""Conflits : détection et résolution d'adresses IP."""

from .detect import detect_conflicts
from .resolve import resolve_conflict

__all__ = ["detect_conflicts", "resolve_conflict"]