/*----------------------------------------------------------------------
 *
 * Filename: TaintFixEmitter_output.cpp 
 * Description: Output and code generation methods
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 * 12 Mar 26  jpb  Annotation changes and refactoring
 *
 */

#include "TaintFixEmitter.h"
#include <fstream>
#include <sstream>

namespace taint
{

//
// Output Methods
//

bool
FixEmitter::emitYAML (const std::vector<Fix> &fixes,
                      const std::string &filename,
                      const std::vector<Fix> &suppressed)
{
    std::ofstream out (filename);
    if (!out)
        return false;

    out << "# PAPI Taint Analyzer - Fix Suggestions\n";
    out << "---\n";
    out << "version: 1.0\n";
    out << "fix_count: " << fixes.size () << "\n";
    out << "fixes:\n";

    for (const auto &fix : fixes)
        {
            out << "  - id: " << fix.id << "\n";
            out << "    file: \"" << fix.file << "\"\n";
            out << "    line: " << fix.line << "\n";
            out << "    variable: " << fix.variable << "\n";
            out << "    actual_layer: " << layerToString (fix.actualLayer) << "\n";
            out << "    required_layer: " << layerToString (fix.requiredLayer) << "\n";
            out << "    can_auto_fix: " << (fix.canAutoFix ? "true" : "false") << "\n";
            out << "    provenance: " << (fix.isProvenance ? "true" : "false") << "\n";

            out << "    suggested_parsers:\n";
            for (const auto &p : fix.suggestedParsers)
                {
                    out << "      - name: " << p.name << "\n";
                    out << "        header: " << p.header << "\n";
                    out << "        reason: \"" << p.reason << "\"\n";
                }
            out << "\n";
        }

    // Suppressed entries — emitted for auditability, not actionable
    if (!suppressed.empty ())
        {
            out << "suppressed_count: " << suppressed.size () << "\n";
            out << "suppressed_fixes:\n";
            for (const auto &fix : suppressed)
                {
                    // Decode "reason|paramIndex" from notes
                    std::string suppressReason = fix.notes;
                    std::string paramIndexStr;
                    auto sep = fix.notes.rfind ('|');
                    if (sep != std::string::npos)
                        {
                            suppressReason = fix.notes.substr (0, sep);
                            paramIndexStr  = fix.notes.substr (sep + 1);
                        }

                    out << "  - id: " << fix.id << "\n";
                    out << "    file: \"" << fix.file << "\"\n";
                    out << "    line: " << fix.line << "\n";
                    out << "    variable: " << fix.variable << "\n";
                    out << "    actual_layer: "
                        << layerToString (fix.actualLayer) << "\n";
                    out << "    required_layer: "
                        << layerToString (fix.requiredLayer) << "\n";
                    out << "    suppressed: true\n";
                    out << "    suppress_reason: \"" << suppressReason << "\"\n";
                    if (!paramIndexStr.empty ())
                        out << "    parameter_index: " << paramIndexStr << "\n";
                    out << "\n";
                }
        }

    out << "...\n";
    return true;
}

bool
FixEmitter::emitJSON (const std::vector<Fix> &fixes,
                      const std::string &filename)
{
    std::ofstream out (filename);
    if (!out)
        return false;

    out << "{\n  \"version\": 1,\n  \"fixes\": [\n";
    for (size_t i = 0; i < fixes.size (); i++)
        {
            const auto &fix = fixes[i];
            out << "    {\"id\": \"" << fix.id << "\", ";
            out << "\"variable\": \"" << fix.variable << "\", ";
            out << "\"line\": " << fix.line << "}";
            if (i < fixes.size () - 1)
                out << ",";
            out << "\n";
        }
    out << "  ]\n}\n";
    return true;
}

void
FixEmitter::emitToStdout (const std::vector<Fix> &fixes)
{
    llvm::errs () << "\n======================================================="
                     "=========\n";
    llvm::errs ()
        << "                    FIX SUGGESTIONS                             \n";
    llvm::errs () << "========================================================="
                     "=======\n\n";

    for (const auto &fix : fixes)
        {
            llvm::errs () << "Fix " << fix.id << ":\n";
            llvm::errs () << "  Location:  " << fix.file << ":" << fix.line
                          << "\n";
            llvm::errs () << "  Variable:  " << fix.variable << "\n";
            llvm::errs () << "  Current:   " << layerToString (fix.actualLayer)
                          << "\n";
            llvm::errs () << "  Required:  "
                          << layerToString (fix.requiredLayer) << "\n";

            llvm::errs () << "  Suggested Parsers:\n";
            for (const auto &p : fix.suggestedParsers)
                {
                    llvm::errs ()
                        << "    - " << p.name << " (" << p.reason << ")\n";
                }

            llvm::errs () << "  Placeholder:\n";
            std::istringstream iss (fix.placeholderCode);
            std::string line;
            while (std::getline (iss, line))
                {
                    llvm::errs () << "    " << line << "\n";
                }
            llvm::errs () << "\n";
        }
}

//
// CodeGenerator Implementation
//

std::string
CodeGenerator::generateParseCall (const std::string &parser,
                                  const std::string &inputVar,
                                  const std::string &outputVar,
                                  const std::string &errorHandling)
{

    std::string outputType = "int32_t"; // Default
    if (parser.find ("uint16") != std::string::npos)
        outputType = "uint16_t";
    else if (parser.find ("uint32") != std::string::npos)
        outputType = "uint32_t";
    else if (parser.find ("int64") != std::string::npos)
        outputType = "int64_t";
    else if (parser.find ("bool") != std::string::npos)
        outputType = "bool";
    else if (parser.find ("size") != std::string::npos)
        outputType = "size_t";
    else if (parser.find ("ipv4") != std::string::npos)
        outputType = "langsec_ipv4_t";

    std::stringstream ss;
    ss << "/* LANGSEC_GENERATED_BEGIN */\n";
    ss << outputType << " " << outputVar << ";\n";
    ss << "langsec_result_t __res = " << parser << "(" << inputVar
       << ", strlen(" << inputVar << "), &" << outputVar << ", NULL);\n";
    ss << "if (!__res.ok) { " << errorHandling << "; }\n";
    ss << "/* LANGSEC_GENERATED_END */\n";
    return ss.str ();
}

std::string
CodeGenerator::generatePlaceholder (const std::string &variable,
                                    TaintLayer requiredLayer,
                                    const std::string &hint)
{

    std::stringstream ss;
    ss << "/* LANGSEC_PARSE_REQUIRED\n";
    ss << " * Variable: " << variable << "\n";
    ss << " * Required: " << layerToString (requiredLayer) << "\n";
    ss << " * Hint: " << hint << "\n";
    ss << " */\n";
    ss << "#warning \"LANGSEC: " << variable << " requires parsing to "
       << layerToString (requiredLayer) << "\"\n";
    ss << "/* TODO: Insert parser for " << variable << " */\n";
    return ss.str ();
}

std::string
CodeGenerator::generateInclude (const std::string &header)
{
    return "#include <" + header + ">\n";
}

std::string
CodeGenerator::indent (const std::string &code, int spaces)
{
    std::string prefix (spaces, ' ');
    std::stringstream ss;
    std::istringstream iss (code);
    std::string line;
    while (std::getline (iss, line))
        {
            ss << prefix << line << "\n";
        }
    return ss.str ();
}

bool
FixEmitter::emitRawUsageYAML (const std::vector<RawUsage> &usages,
                               const std::string &filename)
{
    std::ofstream out (filename);
    if (!out)
        return false;

    out << "# PAPI Taint Analyzer - RAW Usage Report\n";
    out << "---\n";
    out << "version: 1.0\n";
    out << "usage_count: " << usages.size () << "\n";
    out << "raw_usages:\n";

    for (const auto &r : usages)
        {
            out << "  - variable: \"" << r.variable << "\"\n";
            out << "    location: \"" << r.location << "\"\n";
            out << "    function: \"" << r.function << "\"\n";
            out << "    usage_type: " << rawUsageTypeToString (r.usageType) << "\n";
            out << "    context: \"" << r.usageContext << "\"\n";
            if (!r.suggestedParser.empty ())
                out << "    suggested_parser: \"" << r.suggestedParser << "\"\n";
            if (!r.suggestedType.empty ())
                out << "    suggested_type: \"" << r.suggestedType << "\"\n";
            out << "\n";
        }

    out << "...\n";
    return true;
}

} // namespace taint
