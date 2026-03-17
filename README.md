# PAPI: Provenance-Aware Parse Insertion for LangSec Mediation

The initial release is a proof-of-concept taint analyzer which demonstrates provenance-aware parsing; pass-through parameters in a routine do not need to be parsed, only those that changed.


## PAPI Taint Analyzer

This tool implements multi-layer taint tracking to identify where parsing is needed before untrusted data reaches security-sensitive operations (sinks). Unlike simple binary tainted/untainted tracking, this analyzer recognizes multiple validation layers:

| Layer | Description | Example |
|-------|-------------|---------|
| RAW | Unparsed, untrusted input | Data from `fgets()`, `getenv()` |
| SYNTACTIC | Structure validated | Well-formed date string (MM-DD-YYYY) |
| SEMANTIC | Domain meaning validated | Valid calendar date (not Feb 30) |
| CONTEXTUAL | Use-specific constraints | Birthdate must be in the past |
| CLEAN | Not tainted | Literals, computed values |

More information on the analyzer is located in [ANALYZER.md](ANALYZER.md).

## STRATUM Annotations

PAPI supports `__attribute__((annotate(...)))` annotations using the `stratum:` prefix.
These annotations let you communicate information to the analyzer that it cannot infer
from source alone — most importantly, the taint behaviour of library functions whose source is not available to PAPI.

More information on this is located in [STRATUM.md](STRATUM.md).

Updated: 16 Mar 2026

