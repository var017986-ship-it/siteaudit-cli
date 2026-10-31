"""Shared request and findings context for scan modules."""

from .http_client import ScanContext, ScanResponse

__all__ = ["ScanContext", "ScanResponse"]
