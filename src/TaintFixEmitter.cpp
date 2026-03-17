/*----------------------------------------------------------------------
 *
 * Filename: TaintFixEmitter.cpp
 * Description: Fix emission implementation
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 * 08 Mar 26  jpb  Change inferTypeFrom Name to use a map.
 * 10 Mar 26  jpb  Refactoring
 *
 */

#include "TaintFixEmitter.h"
#include "ParserRegistry.h"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>

namespace taint
{

//
// FixEmitter Implementation
//

FixEmitter::FixEmitter () : nextFixId_ (1) {}

std::vector<Fix> FixEmitter::generateFixes (const std::vector<TaintViolation> &violations,
                 const FunctionDatabase &funcDb)
{

    std::vector<Fix> fixes;

    // Deduplicate violations by location + variable
    std::set<std::string> seen;
    std::vector<TaintViolation> uniqueViolations;
    for (const auto &v : violations)
        {
            std::string key = v.location + "|" + v.variable;
            if (seen.find (key) == seen.end ())
                {
                    seen.insert (key);
                    uniqueViolations.push_back (v);
                }
        }

    for (const auto &v : uniqueViolations)
        {
            Fix fix;

            // Generate ID
            std::stringstream idss;
            idss << "v" << std::setfill ('0') << std::setw (3) << nextFixId_++;
            fix.id = idss.str ();
            fix.isProvenance = false;

            // Parse location string (format: "file:line:col")
            size_t firstColon = v.location.find (':');
            size_t secondColon = v.location.find (':', firstColon + 1);
            if (firstColon != std::string::npos
                && secondColon != std::string::npos)
                {
                    fix.file = v.location.substr (0, firstColon);
                    fix.line = std::stoul (v.location.substr (
                        firstColon + 1, secondColon - firstColon - 1));
                    fix.column
                        = std::stoul (v.location.substr (secondColon + 1));
                }
            else
                {
                    fix.file = v.location;
                    fix.line = 0;
                    fix.column = 0;
                }

            // Copy violation info
            fix.variable = v.variable;
            fix.actualLayer = v.actualLayer;
            fix.requiredLayer = v.requiredLayer;
            fix.context = v.context;

            // Extract sink function from context
            if (v.context.find ("passed to sink function '")
                != std::string::npos)
                {
                    size_t start = v.context.find ("'") + 1;
                    size_t end = v.context.find ("'", start);
                    if (end != std::string::npos)
                        {
                            fix.sinkFunction
                                = v.context.substr (start, end - start);
                        }
                }

            // Find insertion point
            fix.insertionPoint = findInsertionPoint (v);

            // Variable info
            fix.variableInfo.name = v.variable;
            fix.variableInfo.type = inferTypeFromName (v.variable);

            // Suggest parsers
            fix.suggestedParsers = suggestParsers (v, funcDb);

            // Generate placeholder code
            fix.placeholderCode = generatePlaceholder (fix);

            // Check if we can auto-fix
            fix.canAutoFix = !fix.suggestedParsers.empty ()
                             && fix.suggestedParsers[0].confidence == FixConfidence::HIGH;

            if (fix.canAutoFix)
                {
                    fix.autoFixCode = generateAutoFix (fix);
                }

            fixes.push_back (fix);
        }

    return fixes;
}

std::vector<Fix>
FixEmitter::generateFixesFromParsePoints (
    const std::set<ParsePoint> &parsePoints, const FunctionDatabase &funcDb)
{

    std::vector<Fix> fixes;

    for (const auto &pp : parsePoints)
        {
            // Suppressed parse points are handled separately by
            // generateSuppressedFromParsePoints — skip them here so they
            // do not appear in the actionable fix list.
            if (pp.suppressed)
                continue;

            Fix fix;

            // Generate ID
            std::stringstream idss;
            idss << "p" << std::setfill ('0') << std::setw (3) << nextFixId_++;
            fix.id = idss.str ();

            // Parse location if available
            if (!pp.location.empty ())
                {
                    size_t firstColon = pp.location.find (':');
                    size_t secondColon = pp.location.find (':', firstColon + 1);
                    if (firstColon != std::string::npos
                        && secondColon != std::string::npos)
                        {
                            fix.file = pp.location.substr (0, firstColon);
                            fix.line = std::stoul (pp.location.substr (
                                firstColon + 1, secondColon - firstColon - 1));
                            fix.column = std::stoul (
                                pp.location.substr (secondColon + 1));
                        }
                    else
                        {
                            fix.file = pp.location;
                            fix.line = 0;
                            fix.column = 0;
                        }
                }
            else
                {
                    fix.file = "<unknown>";
                    fix.line = 0;
                    fix.column = 0;
                }

            // Fill in details from parse point
            fix.variable = pp.paramName;
            fix.actualLayer = pp.currentLevel;
            fix.requiredLayer = pp.requiredLevel;
            fix.context = pp.reason + " in function " + pp.functionName;
            fix.sinkFunction = "";
            fix.isProvenance = true;

            // Set insertion point
            fix.insertionPoint.file = fix.file;
            fix.insertionPoint.line = fix.line;
            fix.insertionPoint.column = fix.column;
            fix.insertionPoint.position = InsertionPosition::Before;
            fix.insertionPoint.scope = "statement";

            // Variable info
            fix.variableInfo.name = pp.paramName;
            fix.variableInfo.type = inferTypeFromName (pp.paramName);

            // Suggest parsers based on variable name
            TaintViolation fakeViolation;
            fakeViolation.variable = pp.paramName;
            fakeViolation.requiredLayer = pp.requiredLevel;
            fakeViolation.context = pp.reason;
            fix.suggestedParsers = suggestParsers (fakeViolation, funcDb);

            // Generate placeholder
            fix.placeholderCode = generatePlaceholder (fix);

            // Check if we can auto-fix
            fix.canAutoFix = !fix.suggestedParsers.empty ()
                  && fix.suggestedParsers[0].confidence == FixConfidence::HIGH;

            if (fix.canAutoFix)
                {
                    fix.autoFixCode = generateAutoFix (fix);
                }

            // Clear notes for non-suppressed actionable fixes.
            fix.notes = "";

            fixes.push_back (fix);
        }

    return fixes;
}

// Companion to generateFixesFromParsePoints: returns lightweight Fix records
// for parse points suppressed via stratum:suppress(...).  These are emitted
// in a separate YAML section for auditability — they are not actionable.
std::vector<Fix>
FixEmitter::generateSuppressedFromParsePoints (
    const std::set<ParsePoint> &parsePoints)
{
    std::vector<Fix> suppressed;

    for (const auto &pp : parsePoints)
        {
            if (!pp.suppressed)
                continue;

            Fix fix;
            std::stringstream idss;
            idss << "s" << std::setfill ('0') << std::setw (3) << nextFixId_++;
            fix.id = idss.str ();

            if (!pp.location.empty ())
                {
                    size_t firstColon  = pp.location.find (':');
                    size_t secondColon = pp.location.find (':', firstColon + 1);
                    if (firstColon != std::string::npos
                        && secondColon != std::string::npos)
                        {
                            fix.file   = pp.location.substr (0, firstColon);
                            fix.line   = std::stoul (pp.location.substr (
                                firstColon + 1, secondColon - firstColon - 1));
                            fix.column = std::stoul (
                                pp.location.substr (secondColon + 1));
                        }
                    else
                        {
                            fix.file   = pp.location;
                            fix.line   = 0;
                            fix.column = 0;
                        }
                }
            else
                {
                    fix.file   = "<unknown>";
                    fix.line   = 0;
                    fix.column = 0;
                }

            fix.variable      = pp.paramName;
            fix.actualLayer   = pp.currentLevel;
            fix.requiredLayer = pp.requiredLevel;
            fix.context       = pp.reason + " in function " + pp.functionName;
            fix.isProvenance  = true;
            fix.canAutoFix    = false;
            // Encode reason and index for the YAML emitter
            fix.notes = pp.suppressReason + "|" + std::to_string (pp.paramIndex);

            suppressed.push_back (fix);
        }

    return suppressed;
}

// it passes back a custom solution is needed. Future versions should
// suggestParsers - delegate entirely to ParserRegistry.
// The registry searches in priority order: type > sink > variable name.
// If nothing matches, fall back to CUSTOM_PARSER so the output is never
// empty and the developer always gets an actionable placeholder.
std::vector<SuggestedParser>
FixEmitter::suggestParsers (const TaintViolation &violation,
                            const FunctionDatabase &funcDb)
{
    (void)funcDb;

    // Extract sink name from violation context if present
    std::string sinkName;
    if (violation.context.find ("passed to sink function '")
        != std::string::npos)
        {
            size_t start = violation.context.find ("'") + 1;
            size_t end   = violation.context.find ("'", start);
            if (end != std::string::npos)
                sinkName = violation.context.substr (start, end - start);
        }

    ParserRegistry registry;
    auto entries = registry.suggestForViolation (violation.variable,
                                                 sinkName);

    std::vector<SuggestedParser> suggestions;
    for (const auto &e : entries)
        {
            SuggestedParser p;
            p.name        = e.name;
            p.header      = e.header;
            p.outputLayer = e.outputLayer;
            p.confidence  = e.confidence;
            p.reason      = e.reason;
            suggestions.push_back (p);
        }

    // Fallback: no registry match — developer must provide a custom parser
    if (suggestions.empty ())
        {
            SuggestedParser p;
            p.name        = "CUSTOM_PARSER";
            p.header      = "";
            p.outputLayer = violation.requiredLayer;
            p.confidence  = FixConfidence::UNKNOWN;
            p.reason      = "No built-in parser matched — custom implementation needed";
            suggestions.push_back (p);
        }

    return suggestions;
}

// inferTypeFromName is retained as a private helper for callers that
// want to resolve a C type string from a variable name before querying
// the registry by type. The registry's matchVarNames entries cover the
// same heuristics, so this is only needed if a type-exact lookup is
// preferred over a name-substring lookup.
std::string
FixEmitter::inferTypeFromName (const std::string &varName)
{
    std::string lower = varName;
    std::transform (lower.begin (), lower.end (), lower.begin (), ::tolower);

    static const std::pair<std::string_view, std::string_view> rules[] = {
        {"port",  "uint16_t"},
        {"ip",    "ip_address"},
        {"email", "email"},
        {"url",   "url"},
        {"id",    "int32_t"},
        {"num",   "int32_t"},
        {"count", "int32_t"},
        {"size",  "size_t"},
        {"flag",  "bool"},
    };

    for (auto &[keyword, type] : rules)
        if (lower.find (keyword) != std::string::npos)
            return std::string (type);

    return "";
}

InsertionPoint FixEmitter::findInsertionPoint (const TaintViolation &v)
{
    InsertionPoint ip;
    size_t firstColon  = v.location.find (':');
    size_t secondColon = v.location.find (':', firstColon + 1);

    if (firstColon != std::string::npos && secondColon != std::string::npos)
        {
            ip.file   = v.location.substr (0, firstColon);
            ip.line   = std::stoul (v.location.substr (
                firstColon + 1, secondColon - firstColon - 1));
            ip.column = std::stoul (v.location.substr (secondColon + 1));
        }
    ip.position = InsertionPosition::Before;
    ip.scope    = "statement";
    return ip;
}

// findParserForType and findParsersForSink are thin wrappers kept for
// any callers outside suggestParsers that may use them directly. They
// now delegate to the registry rather than maintaining their own tables.
SuggestedParser
FixEmitter::findParserForType (const std::string &type)
{
    ParserRegistry registry;
    ParserEntry e = registry.findForType (type);
    if (e.name.empty ())
        return {};
    SuggestedParser p;
    p.name        = e.name;
    p.header      = e.header;
    p.outputLayer = e.outputLayer;
    p.confidence  = e.confidence;
    p.reason      = e.reason;
    return p;
}

std::vector<SuggestedParser>
FixEmitter::findParsersForSink (const std::string &sinkName)
{
    ParserRegistry registry;
    std::vector<SuggestedParser> results;
    for (const auto &e : registry.findForSink (sinkName))
        {
            SuggestedParser p;
            p.name        = e.name;
            p.header      = e.header;
            p.outputLayer = e.outputLayer;
            p.confidence  = e.confidence;
            p.reason      = e.reason;
            results.push_back (p);
        }
    return results;
}

std::string FixEmitter::generatePlaceholder (const Fix &fix)
{
    return CodeGenerator::generatePlaceholder (
        fix.variable, fix.requiredLayer,
        fix.suggestedParsers.empty () ? "implement parser"
                                      : fix.suggestedParsers[0].name);
}

std::string FixEmitter::generateAutoFix (const Fix &fix)
{
    if (fix.suggestedParsers.empty ())
        return "";
    const auto &parser = fix.suggestedParsers[0];
    std::string code;
    if (!parser.header.empty ())
        code += CodeGenerator::generateInclude (parser.header);
    code += CodeGenerator::generateParseCall (
        parser.name, fix.variable, fix.variable + "_parsed", "return -1");
    return code;
}

// Output methods - see TaintFixEmitter_output.cpp

} // namespace taint
