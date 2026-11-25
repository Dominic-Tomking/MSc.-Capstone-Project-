"""Aggregation / fusion engine."""
from .fusion import (
    FusionEngine, AggregationReport, Cluster, deduplicate,
)

__all__ = ["FusionEngine", "AggregationReport", "Cluster", "deduplicate"]
