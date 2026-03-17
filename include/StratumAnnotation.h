/*----------------------------------------------------------------------
 *
 * Filename: StratumAnnotation.h
 * Description: Parsing and representation of __attribute__((annotate(...)))
 *              annotations using the "stratum:" prefix convention.
 *
 *   Two annotation forms are supported:
 *
 *   stratum:validates(N,LEVEL)
 *     Placed on a function parameter or on the function declaration itself.
 *     Declares that, upon return from this function, parameter N (0-based)
 *     has been elevated to at least LEVEL.  This injects a synthetic
 *     function-summary entry so PAPI's taint propagation treats the
 *     function as a known validator without needing to see its source.
 *
 *     Example:
 *       void sanitize_id(
 *           __attribute__((annotate("stratum:validates(0,SEMANTIC)")))
 *           const char *id);
 *
 *   stratum:suppress(REASON)
 *     Placed on a parameter declaration.  Suppresses a parse-point finding
 *     at that location and emits it with suppressed:true in the YAML output
 *     instead of omitting it, preserving auditability.
 *
 *     Example:
 *       void write_log(
 *           __attribute__((annotate("stratum:suppress(OUT_PARAM)")))
 *           char *buf, size_t len);
 *
 * Date       Pgm  Comment
 * 11 Mar 26  jpb  Creation.
 *
 */
#ifndef STRATUM_ANNOTATION_H
#define STRATUM_ANNOTATION_H

#include "TaintAnalyzer.h"
#include "clang/AST/Decl.h"

#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace taint
{

//
// Parsed annotation variants
//

/// stratum:validates(paramIndex, TaintLevel)
struct ValidatesAnnotation
{
    unsigned   paramIndex; ///< 0-based parameter position
    TaintLayer level;      ///< Minimum level after function returns
};

/// stratum:suppress(reason)
struct SuppressAnnotation
{
    std::string reason; ///< Free-text reason stored in YAML output
};

/// Union of all recognised annotation types; monostate = not a stratum annotation
using StratumAnnotation = std::variant<std::monostate,
                                       ValidatesAnnotation,
                                       SuppressAnnotation>;

//
// Parsing helpers
//

/// Parse a single annotation string such as "stratum:validates(0,SEMANTIC)".
/// Returns std::monostate if the string does not begin with "stratum:".
StratumAnnotation parseStratumAnnotation(const std::string &annotationText);

/// Collect all stratum: annotations attached to a clang FunctionDecl
/// (searching the declaration's attribute list and all parameter attribute
/// lists).  Results are returned in declaration order.
struct FuncAnnotationResult
{
    std::vector<ValidatesAnnotation> validates; ///< from any param or the func
    // suppress annotations are per-parameter; keyed by param index
    std::vector<std::pair<unsigned, SuppressAnnotation>> suppressions;
};

FuncAnnotationResult collectFunctionAnnotations(const clang::FunctionDecl *func);

/// Convert a TaintLayer enum value to the canonical string used in
/// annotation syntax ("RAW", "SYNTACTIC", etc.).  Inverse of
/// parseTaintLevel.
const char *taintLevelToAnnotationString(TaintLayer layer);

/// Parse a taint-level token from annotation text.
/// Returns std::nullopt for unrecognised tokens.
std::optional<TaintLayer> parseTaintLevel(const std::string &token);

} // namespace taint

#endif // STRATUM_ANNOTATION_H
