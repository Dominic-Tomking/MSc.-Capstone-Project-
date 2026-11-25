"""Common vulnerability schema, taxonomy and severity mapping."""
from .finding import Finding, Location, Source
from .severity import Severity, baseline
from .taxonomy import (
    VulnType, TaxonomyEntry, TAXONOMY, entry, are_related, from_string,
)

__all__ = [
    "Finding", "Location", "Source",
    "Severity", "baseline",
    "VulnType", "TaxonomyEntry", "TAXONOMY", "entry", "are_related", "from_string",
]
