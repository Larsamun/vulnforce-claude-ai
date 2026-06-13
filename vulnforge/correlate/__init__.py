"""Correlation engine - fuse SAST + DAST evidence into combined findings."""
from .engine import correlate

__all__ = ["correlate"]
