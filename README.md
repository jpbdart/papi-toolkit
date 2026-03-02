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

**Note:** We currently are testing the analyzer before we move it to the "production" branch, and here. As soon as we complete testing, we will finish uploading code to the repository.

Updated: 01 Mar 2026
