# PAPI Taint Analyzer: How It Works

The PAPI taint analyzer is a static analysis tool built on the Clang/LLVM toolchain. It reads C source files through Clang's AST (Abstract Syntax Tree) infrastructure and walks every function definition looking for untrusted data that flows into security-sensitive operations without first passing through a parser. The core idea comes from language security (LangSec) research: untrusted input must be explicitly recognized and validated before it is acted upon, and different operations require different levels of validation.

## Taint Layers

Rather than tracking a simple tainted/untainted boolean, the analyzer assigns each variable one of five ordered layers:

| Layer | Meaning |
|-------|---------|
| RAW | Unparsed, untrusted input (e.g., data from `fgets`, `getenv`) |
| SYNTACTIC | Structure has been verified (e.g., a well-formed date string) |
| SEMANTIC | Domain meaning has been validated (e.g., the date is a real calendar date) |
| CONTEXTUAL | Use-specific constraints have been applied (e.g., the date is in the past) |
| CLEAN | Not tainted; literals and computed constants start here |

A variable's layer can only increase. Once a parser elevates a value from RAW to SYNTACTIC, subsequent operations that require only SYNTACTIC validation no longer generate a warning for that variable. Variables not explicitly seen as input sources default to CLEAN.

## Provenance Tracking

The analyzer's central insight is provenance: not every parameter of every function needs to be parsed. A parameter that passes straight through a function unchanged carries whatever taint level it already had, so parsing it again at each call site would be redundant. The `ProvenanceTracker` class identifies this distinction by walking each function's AST body and marking parameters as either MODIFIED or PASS_THROUGH.

Modification detection covers direct assignment, increment/decrement operators,
dereference writes, array subscript writes, member assignments, and parameters passed to
known output-writing library functions such as `memcpy`, `fgets`, `recv`, and `sscanf`.
Only parameters that are actually modified inside a function are candidates for a parse
point recommendation.

## Interprocedural Analysis

The `InterproceduralPropagator` class extends the single-function analysis across call chains. It maintains a map of (function, parameter-index) pairs and their current taint levels, then iterates over all call sites until no further changes occur (up to 100
passes). When a caller passes a PASS_THROUGH parameter directly to a callee, the callee's corresponding parameter inherits the caller's taint level. This propagation lets the analyzer avoid flagging a parameter at every intermediate function in a call chain; it only flags the point where the data is first modified and then used in a sink.

## Validation Pattern Detection

The analyzer also performs lightweight flow-sensitive analysis to recognize common C validation idioms and elevate taint levels accordingly. `ValidationPatterns.cpp` identifies several patterns:

- **Error-checked calls**: `rc = parse_func(..., &out); if (rc != 0) return rc;` after the error check, `out` is elevated to at least SYNTACTIC.
- **Bounds checks**: `if (x >= 0 && x < MAX)` inside the branch, `x` is elevated to SEMANTIC.
- **Equality checks**: `if (type == TYPE_A)` inside the branch, `type` is elevated to SEMANTIC.
- **Non-null checks**: `if (ptr != NULL)` recognized but the pointed-to content remains RAW; the pointer itself is safe to dereference.
- **Bitmask extraction**: `val = (header & MASK) >> SHIFT` detected as a range-constraining operation.

Parser function heuristics supplement the pattern detection. Functions whose names match patterns such as `parse_*`, `decode_*`, `str_to_*`, `strtol`, or `validate_*` are recognized as likely parsers and their output is tentatively elevated to SYNTACTIC or SEMANTIC based on the name.

## Parser Registry

The `ParserRegistry` class maintains a built-in catalog of known LangSec-compatible parsers drawn from a hypothetical `langsec/` library. Each entry records the function name, the include header, the taint layer it produces, a confidence level, and three matching criteria: C type, sink function name, and variable name substrings. When the analyzer identifies a violation, such as a modified RAW parameter flowing into a sink, it consults the registry to suggest an appropriate parser. Suggestions are ranked by priority: type match first, then sink match, then variable name heuristic.

## STRATUM Annotations

Because the analyzer operates only on the source files given to it, it cannot infer the taint behavior of library functions whose source is absent. STRATUM annotations, written as `__attribute__((annotate("stratum:...")))`, bridge this gap.

More information on annotations is located in [STRATUM.md](STRATUM.md).

## Output

Results are written to YAML files selected by command-line flags.

- `--emit-provenance` records the full per-function analysis: parameter modification status, call site bindings,
and computed parse points.
- `--emit-fixes` contains parser suggestions keyed by violation location, suitable for consumption by `papi-annotate`.
- `--emit-raw` reports every use of a RAW-tainted variable. `papi-annotate` can also read these files.
- `--emit-summary` writes the function database entries generated during analysis.
- `--emit-report` writes the human-readable violation summary to a file in addition to standard error.

Some of these flags may be deprecated in the future.

Updated: 16 Mar 2026
