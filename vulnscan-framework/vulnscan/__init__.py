"""vulnscan — reference implementation of the automated vulnerability-scanning
framework for Ethereum smart contracts and DeFi applications.

This package implements the non-NLP segments of the framework described in the
capstone proposal:

* ``vulnscan.schema``          — the common vulnerability schema, canonical
                                 taxonomy (SWC/CWE/OWASP) and severity mapping.
* ``vulnscan.static_analysis`` — Slither and SmartCheck adapters + normaliser.
* ``vulnscan.aggregation``     — the fusion engine (dedup / correlate / consensus).
* ``vulnscan.evaluation``      — ground-truth matching + evaluation metrics.
* ``vulnscan.testnet``         — Hardhat/Anvil dynamic validation runner.

The CodeBERT / NLP detection service is delivered separately; its findings are
consumed here through the same :class:`~vulnscan.schema.finding.Finding` schema.
"""

__version__ = "0.1.0"
