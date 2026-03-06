/*----------------------------------------------------------------------
 *
 * Filename: TaintFixEmitter.h
 * Description:
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */
#ifndef TAINT_FIX_EMITTER_H
#define TAINT_FIX_EMITTER_H

#include "ProvenanceTracker.h"
#include "TaintAnalyzer.h"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace taint
{

//
// Fix Types
// Only used for non-provenance emitter
//
enum class FixConfidence
{
    HIGH,   // Strong match, can auto-insert
    MEDIUM, // Reasonable guess, needs review
    LOW,    // Placeholder only
    UNKNOWN // No suggestion available
};

struct SuggestedParser
{
    std::string name;       // e.g., "langsec_parse_int32"
    std::string header;     // e.g., "langsec/primitive.h"
    TaintLayer outputLayer; // What layer it produces
    FixConfidence confidence;
    std::string reason; // Why this parser was suggested
};

enum class InsertionPosition { Before, After, Replace };

struct InsertionPoint {
    std::string file;
    unsigned line;
    unsigned column;
    InsertionPosition position;
    std::string scope;  // "function", "block", "statement"
};

struct VariableInfo
{
    std::string name;
    std::string type; // Declared C type
    std::string file;
    unsigned declLine;
    unsigned declColumn;
    std::string inferredGrammar; // If detectable
};

struct Fix
{
    std::string id; // Unique identifier (e.g., "v001")

    // Location of the violation
    std::string file;
    unsigned line;
    unsigned column;

    // What's wrong
    std::string variable;
    TaintLayer actualLayer;
    TaintLayer requiredLayer;
    std::string sinkFunction;
    std::string context;

    // Remediation info
    InsertionPoint insertionPoint;
    VariableInfo variableInfo;
    std::vector<SuggestedParser> suggestedParsers;

    // Generated code
    std::string placeholderCode;
    std::string autoFixCode; // Only if confidence is HIGH

    // Status
    bool canAutoFix;
    bool isProvenance;
    std::string notes;
};

//
// Fix Emitter
//

class FixEmitter
{
  public:
    FixEmitter ();

    // Generate fixes from violations
    std::vector<Fix>
    generateFixes (const std::vector<TaintViolation> &violations,
                   const FunctionDatabase &funcDb);

    // Generate fixes from provenance-based parse points
    std::vector<Fix>
    generateFixesFromParsePoints (const std::set<ParsePoint> &parsePoints,
                                  const FunctionDatabase &funcDb);

    // Output formats
    bool emitYAML (const std::vector<Fix> &fixes, const std::string &filename);
    bool emitJSON (const std::vector<Fix> &fixes, const std::string &filename);
    void emitToStdout (const std::vector<Fix> &fixes);

    // Generate placeholder code
    std::string generatePlaceholder (const Fix &fix);

    // Generate auto-fix code (if possible)
    std::string generateAutoFix (const Fix &fix);

  private:
    unsigned nextFixId_ = 1;

    // Parser suggestion based on context
    std::vector<SuggestedParser>
    suggestParsers (const TaintViolation &violation,
                    const FunctionDatabase &funcDb);

    // Infer type from variable name patterns
    std::string inferTypeFromName (const std::string &varName);

    // Determine insertion point
    InsertionPoint findInsertionPoint (const TaintViolation &violation);

    // Look up parser for a type
    SuggestedParser findParserForType (const std::string &type);

    // Look up parser for a sink
    std::vector<SuggestedParser>
    findParsersForSink (const std::string &sinkName);
};

//
// Code Generator
//

class CodeGenerator
{
  public:
    // Generate langsec parsing code
    static std::string
    generateParseCall (const std::string &parser, const std::string &inputVar,
                       const std::string &outputVar,
                       const std::string &errorHandling = "return -1");

    // Generate placeholder with warning
    static std::string generatePlaceholder (const std::string &variable,
                                            TaintLayer requiredLayer,
                                            const std::string &hint);

    // Generate #include if needed
    static std::string generateInclude (const std::string &header);

    // Indent code
    static std::string indent (const std::string &code, int spaces = 4);
};

} // namespace taint

#endif // TAINT_FIX_EMITTER_H
