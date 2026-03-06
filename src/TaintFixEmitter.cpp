/*----------------------------------------------------------------------
 *
 * Filename: TaintFixEmitter.cpp
 * Description: Fix emission implementation
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */

#include "TaintFixEmitter.h"
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

std::vector<Fix>
FixEmitter::generateFixes (const std::vector<TaintViolation> &violations,
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
            fix.canAutoFix
                = !fix.suggestedParsers.empty ()
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
            fix.canAutoFix
                = !fix.suggestedParsers.empty ()
                  && fix.suggestedParsers[0].confidence == FixConfidence::HIGH;

            if (fix.canAutoFix)
                {
                    fix.autoFixCode = generateAutoFix (fix);
                }

            // Add note about provenance
            fix.notes = "Identified via provenance analysis (parameter index: "
                        + std::to_string (pp.paramIndex) + ")";

            fixes.push_back (fix);
        }

    return fixes;
}

std::vector<SuggestedParser>
FixEmitter::suggestParsers (const TaintViolation &violation,
                            const FunctionDatabase &funcDb)
{

    (void)funcDb;
    std::vector<SuggestedParser> suggestions;

    // Infer type from variable name
    std::string inferredType = inferTypeFromName (violation.variable);

    if (!inferredType.empty ())
        {
            SuggestedParser p = findParserForType (inferredType);
            if (!p.name.empty ())
                {
                    suggestions.push_back (p);
                }
        }

    // Look for sink-specific parsers
    std::string sinkName;
    if (violation.context.find ("passed to sink function '")
        != std::string::npos)
        {
            size_t start = violation.context.find ("'") + 1;
            size_t end = violation.context.find ("'", start);
            if (end != std::string::npos)
                {
                    sinkName = violation.context.substr (start, end - start);
                }
        }

    if (!sinkName.empty ())
        {
            auto sinkParsers = findParsersForSink (sinkName);
            for (const auto &p : sinkParsers)
                {
                    bool found = false;
                    for (const auto &existing : suggestions)
                        {
                            if (existing.name == p.name)
                                {
                                    found = true;
                                    break;
                                }
                        }
                    if (!found)
                        suggestions.push_back (p);
                }
        }

    if (suggestions.empty ())
        {
            SuggestedParser p;
            p.name = "CUSTOM_PARSER";
            p.outputLayer = violation.requiredLayer;
            p.confidence = FixConfidence::UNKNOWN;
            p.reason = "No built-in parser - custom implementation needed";
            suggestions.push_back (p);
        }

    return suggestions;
}

std::string
FixEmitter::inferTypeFromName (const std::string &varName)
{
    std::string lower = varName;
    std::transform (lower.begin (), lower.end (), lower.begin (), ::tolower);

    if (lower.find ("port") != std::string::npos)
        return "uint16_t";
    if (lower.find ("ip") != std::string::npos)
        return "ip_address";
    if (lower.find ("email") != std::string::npos)
        return "email";
    if (lower.find ("url") != std::string::npos)
        return "url";
    if (lower.find ("id") != std::string::npos)
        return "int32_t";
    if (lower.find ("num") != std::string::npos)
        return "int32_t";
    if (lower.find ("count") != std::string::npos)
        return "int32_t";
    if (lower.find ("size") != std::string::npos)
        return "size_t";
    if (lower.find ("flag") != std::string::npos)
        return "bool";

    return "";
}

InsertionPoint FixEmitter::findInsertionPoint (const TaintViolation &v)
{
    InsertionPoint ip;
    size_t firstColon = v.location.find (':');
    size_t secondColon = v.location.find (':', firstColon + 1);

    if (firstColon != std::string::npos && secondColon != std::string::npos)
        {
            ip.file = v.location.substr (0, firstColon);
            ip.line = std::stoul (v.location.substr (
                firstColon + 1, secondColon - firstColon - 1));
            ip.column = std::stoul (v.location.substr (secondColon + 1));
        }
    ip.position = InsertionPosition::Before;
    ip.scope = "statement";
    return ip;
}

SuggestedParser FixEmitter::findParserForType (const std::string &type)
{
    SuggestedParser p;

    if (type == "int32_t" || type == "int")
        {
            p.name = "langsec_parse_int32";
            p.header = "langsec/primitive.h";
            p.outputLayer = TaintLayer::SYNTACTIC;
            p.confidence = FixConfidence::HIGH;
            p.reason = "Type match: int32_t";
        }
    else if (type == "uint16_t")
        {
            p.name = "langsec_parse_uint16";
            p.header = "langsec/primitive.h";
            p.outputLayer = TaintLayer::SYNTACTIC;
            p.confidence = FixConfidence::HIGH;
            p.reason = "Type match: uint16_t";
        }
    else if (type == "size_t")
        {
            p.name = "langsec_parse_size";
            p.header = "langsec/primitive.h";
            p.outputLayer = TaintLayer::SYNTACTIC;
            p.confidence = FixConfidence::HIGH;
            p.reason = "Type match: size_t";
        }
    else if (type == "bool")
        {
            p.name = "langsec_parse_bool";
            p.header = "langsec/primitive.h";
            p.outputLayer = TaintLayer::SEMANTIC;
            p.confidence = FixConfidence::HIGH;
            p.reason = "Type match: bool";
        }
    else if (type == "ip_address")
        {
            p.name = "langsec_parse_ipv4";
            p.header = "langsec/net.h";
            p.outputLayer = TaintLayer::SEMANTIC;
            p.confidence = FixConfidence::MEDIUM;
            p.reason = "Inferred: IP address";
        }
    else if (type == "email")
        {
            p.name = "langsec_parse_email";
            p.header = "langsec/net.h";
            p.outputLayer = TaintLayer::SYNTACTIC;
            p.confidence = FixConfidence::MEDIUM;
            p.reason = "Inferred: email";
        }
    else if (type == "url")
        {
            p.name = "langsec_parse_url";
            p.header = "langsec/net.h";
            p.outputLayer = TaintLayer::SYNTACTIC;
            p.confidence = FixConfidence::MEDIUM;
            p.reason = "Inferred: URL";
        }
    return p;
}

std::vector<SuggestedParser> FixEmitter::findParsersForSink (const std::string &sinkName)
{
    std::vector<SuggestedParser> parsers;

    if (sinkName == "system" || sinkName == "popen" || sinkName == "execve")
        {
            SuggestedParser p;
            p.name = "langsec_parse_string_enum";
            p.header = "langsec/primitive.h";
            p.outputLayer = TaintLayer::CONTEXTUAL;
            p.confidence = FixConfidence::LOW;
            p.reason = "Shell commands should use whitelist";
            parsers.push_back (p);
        }
    return parsers;
}

std::string FixEmitter::generatePlaceholder (const Fix &fix)
{
    return CodeGenerator::generatePlaceholder (
        fix.variable, fix.requiredLayer,
        fix.suggestedParsers.empty () ? "implement parser"
                                      : fix.suggestedParsers[0].name);
}

std::string
FixEmitter::generateAutoFix (const Fix &fix)
{
    if (fix.suggestedParsers.empty ())
        return "";
    const auto &parser = fix.suggestedParsers[0];
    std::string code;
    if (!parser.header.empty ())
        {
            code += CodeGenerator::generateInclude (parser.header);
        }
    code += CodeGenerator::generateParseCall (
        parser.name, fix.variable, fix.variable + "_parsed", "return -1");
    return code;
}

// Output methods - see TaintFixEmitter_output.cpp

} // namespace taint
