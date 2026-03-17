/*----------------------------------------------------------------------
 *
 * Filename: ParserRegistry.h
 * Description: Registry of known LangSec parsers and their properties.
 *
 * The ParserRegistry is the single source of truth for parser metadata.
 * Both FunctionDatabase (which needs parser names and output taint levels
 * for analysis) and FixEmitter (which needs full parser details for fix
 * suggestions) consult this registry rather than maintaining separate
 * hardcoded tables.
 *
 * Each ParserEntry describes one parser function: what taint level it
 * produces, what type names trigger it, what sink functions call for it,
 * and what variable name patterns suggest it. This maps directly to a
 * future SQLite schema where each field becomes a column or child table.
 *
 * Date       Pgm  Comment
 * 09 Mar 26  jpb  Creation.
 *
 */

#ifndef PARSER_REGISTRY_H
#define PARSER_REGISTRY_H

#include "TaintAnalyzer.h"
#include "TaintFixEmitter.h"
#include <map>
#include <string>
#include <vector>

namespace taint
{

//
// A single parser entry in the registry.
//
// matchTypes    - C type names that strongly suggest this parser
//                 e.g. {"int32_t", "int"} for langsec_parse_int32
// matchSinks    - sink function names that call for this parser
//                 e.g. {"system", "popen"} for langsec_parse_string_enum
// matchVarNames - variable name substrings (lowercased) that suggest this
//                 parser via naming convention
//                 e.g. {"port"} for langsec_parse_uint16
//
// A parser may have entries in any combination of the three match lists.
// The registry searches them in priority order: type > sink > varname.
//
struct ParserEntry
{
    std::string name;           // e.g. "langsec_parse_int32"
    std::string header;         // e.g. "langsec/primitive.h"
    TaintLayer outputLayer;     // Taint level produced on success
    FixConfidence confidence;   // How certain the suggestion is
    std::string reason;         // Human-readable rationale

    std::vector<std::string> matchTypes;    // C type triggers
    std::vector<std::string> matchSinks;    // Sink function triggers
    std::vector<std::string> matchVarNames; // Variable name triggers
};

//
// ParserRegistry
//
// Owns the canonical list of known parsers and provides lookup methods
// used by both FunctionDatabase and FixEmitter.
//
class ParserRegistry
{
  public:
    ParserRegistry ();

    // Populate the registry with built-in parser entries.
    // Called once at startup, analogous to FunctionDatabase::loadBuiltins().
    void loadBuiltinParsers ();

    // Register a single parser entry (for user-defined parsers).
    void registerParser (const ParserEntry &entry);

    //
    // Lookups used by FunctionDatabase
    //
    // Returns true if name is a known parser function.
    bool isKnownParser (const std::string &name) const;

    // Returns the output taint layer for a named parser, or CLEAN if
    // the parser is unknown (unknown parsers should not elevate taint).
    TaintLayer getOutputLayer (const std::string &name) const;

    // Populate a FunctionDatabase's parser map from this registry.
    // Called by FunctionDatabase::loadBuiltins() to avoid duplication.
    void registerWithFuncDb (FunctionDatabase &db) const;

    //
    // Lookups used by FixEmitter
    //
    // Find the best parser for a given C type name.
    // Returns an empty ParserEntry (name == "") if none found.
    ParserEntry findForType (const std::string &cType) const;

    // Find all parsers appropriate for a given sink function.
    std::vector<ParserEntry> findForSink (const std::string &sinkName) const;

    // Find the best parser by variable name heuristic.
    // Returns an empty ParserEntry if no name pattern matches.
    ParserEntry findForVarName (const std::string &varName) const;

    // Convenience: given a variable name and optional sink, return an
    // ordered list of suggestions (deduped, type > sink > varname).
    std::vector<ParserEntry> suggestForViolation (
        const std::string &varName,
        const std::string &sinkName,
        const std::string &cType = "") const;

  private:
    // Primary storage: name -> entry (for fast isKnownParser / getOutputLayer)
    std::map<std::string, ParserEntry> byName_;

    // Inverted indexes for suggestion lookups
    std::map<std::string, std::string> byType_;    // cType    -> parser name
    std::map<std::string, std::vector<std::string>> bySink_;  // sink -> [names]
    std::map<std::string, std::string> byVarName_; // substring -> parser name

    // Internal helper: rebuild inverted indexes after a registration
    void indexEntry (const ParserEntry &entry);
};

} // namespace taint

#endif // PARSER_REGISTRY_H
