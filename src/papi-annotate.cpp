/*----------------------------------------------------------------------
 *
 * Filename: papi-annotate - Insert parser suggestion comments into source files
 * Description: Reads a LangSec fix suggestions YAML file (produced by the taint analyzer
 *              with --provenance enabled) and inserts commented parser suggestions into
 *              the source code at the appropriate locations.
 *
 * Date       Pgm  Comment
 * 01 Mar 26  jpb  Rebuilt from old test program to work with provenance-enabled files
 *
 * Supported YAML format (taint analyzer fix suggestions):
 *   version: 1
 *   fix_count: N
 *   fixes:
 *     - id: p001
 *       file: "/path/to/file.c"
 *       line: 72
 *       variable: buf
 *       actual_layer: RAW
 *       required_layer: CLEAN
 *       can_auto_fix: false
 *       provenance: true
 *       suggested_parsers:
 *         - name: CUSTOM_PARSER
 *           header: ""
 *           reason: "No built-in parser - custom implementation needed"
 *
 * Usage:
 *   papi-annotate <fix_suggestions.yaml> [options]
 *
 * Options:
 *   --dry-run           Show what would be changed without modifying files
 *   --backup            Create .bak backup files before modifying
 *   --output-dir=<dir>  Write annotated files to a different directory
 *   --verbose           Show detailed progress
 */

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

//
// Data Structures
//

struct SuggestedParser
{
    std::string name;
    std::string header;
    std::string reason;
};

struct Fix
{
    std::string id;
    std::string file;
    unsigned line = 0;
    std::string variable;
    std::string actualLayer;
    std::string requiredLayer;
    bool canAutoFix = false;
    bool provenance = false;
    std::vector<SuggestedParser> suggestedParsers;
};

struct ReportMetadata
{
    int version = 0;
    int fixCount = 0;
    bool hasProvenance = false; // true if any fix has provenance: true
};

//
// YAML Parser for fix suggestions format
//

class FixYAMLParser
{
  public:
    struct ParseResult
    {
        ReportMetadata metadata;
        std::vector<Fix> fixes;
    };

    ParseResult
    parse (const std::string &filename)
    {
        ParseResult result;
        std::ifstream in (filename);
        if (!in)
            {
                std::cerr << "Error: Cannot open " << filename << "\n";
                return result;
            }

        std::string line;
        Fix current;
        SuggestedParser currentParser;
        bool inFixes = false;
        bool inFix = false;
        bool inSuggestedParsers = false;
        bool inParser = false;

        while (std::getline (in, line))
            {
                // Skip comments and empty lines
                if (line.empty () || line[0] == '#')
                    continue;
                if (trim (line) == "---" || trim (line) == "...")
                    continue;

                size_t indent = line.find_first_not_of(' ');
                if (indent == std::string::npos)    // no non-space character found
                    std::cerr << "Warning: did not find spaces in file\n";

                std::string t = trim (line);

                // Top-level fields
                if (indent == 0)
                    {
                        if (t.find ("version:") == 0)
                            {
                                result.metadata.version
                                    = std::stoi (extractValue (t, "version:"));
                            }
                        else if (t.find ("fix_count:") == 0)
                            {
                                result.metadata.fixCount
                                    = std::stoi (extractValue (t, "fix_count:"));
                            }
                        else if (t == "fixes:")
                            {
                                inFixes = true;
                            }
                        continue;
                    }

                if (!inFixes)
                    continue;

                // New fix entry (2-space indent with leading dash)
                if (indent == 2 && t.find ("- id:") == 0)
                    {
                        // Save previous fix
                        if (inFix)
                            {
                                if (inParser && !currentParser.name.empty ())
                                    {
                                        current.suggestedParsers.push_back (currentParser);
                                        currentParser = SuggestedParser ();
                                    }
                                if (current.provenance)
                                    result.metadata.hasProvenance = true;
                                result.fixes.push_back (current);
                            }
                        current = Fix ();
                        current.id = extractValue (t, "- id:");
                        inFix = true;
                        inSuggestedParsers = false;
                        inParser = false;
                        continue;
                    }

                if (!inFix)
                    continue;

                // Fix-level fields (4-space indent)
                if (indent == 4 && !inSuggestedParsers)
                    {
                        if (t.find ("file:") == 0)
                            {
                                current.file
                                    = extractValue (t, "file:"); //quoted
                            }
                        else if (t.find ("line:") == 0)
                            {
                                current.line
                                    = std::stoul (extractValue (t, "line:"));
                            }
                        else if (t.find ("variable:") == 0)
                            {
                                current.variable
                                    = extractValue (t, "variable:");
                            }
                        else if (t.find ("actual_layer:") == 0)
                            {
                                current.actualLayer
                                    = extractValue (t, "actual_layer:");
                            }
                        else if (t.find ("required_layer:") == 0)
                            {
                                current.requiredLayer
                                    = extractValue (t, "required_layer:");
                            }
                        else if (t.find ("can_auto_fix:") == 0)
                            {
                                std::string val
                                    = extractValue (t, "can_auto_fix:");
                                current.canAutoFix
                                    = (val == "true" || val == "yes");
                            }
                        else if (t.find ("provenance:") == 0)
                            {
                                std::string val
                                    = extractValue (t, "provenance:");
                                current.provenance
                                    = (val == "true" || val == "yes");
                            }
                        else if (t == "suggested_parsers:")
                            {
                                inSuggestedParsers = true;
                                inParser = false;
                            }
                        continue;
                    }

                // Inside suggested_parsers list
                if (inSuggestedParsers)
                    {
                        // New parser entry (6-space indent with dash)
                        if (indent == 6 && t.find ("- name:") == 0)
                            {
                                if (inParser && !currentParser.name.empty ())
                                    {
                                        current.suggestedParsers.push_back (
                                            currentParser);
                                    }
                                currentParser = SuggestedParser ();
                                currentParser.name
                                    = extractValue (t, "- name:");
                                inParser = true;
                                continue;
                            }

                        // Parser sub-fields (8-space indent)
                        if (indent == 8 && inParser)
                            {
                                if (t.find ("header:") == 0)
                                    {
                                        currentParser.header = extractValue (t, "header:"); //quoted
                                    }
                                else if (t.find ("reason:") == 0)
                                    {
                                        currentParser.reason = extractValue (t, "reason:"); //quoted
                                    }
                                continue;
                            }

                        // Returning to fix-level means end of parsers
                        if (indent == 4)
                            {
                                inSuggestedParsers = false;
                                // fall through to fix-level handling
                            }
                    }
            }

        // Don't forget the last fix
        if (inFix)
            {
                if (inParser && !currentParser.name.empty ())
                    {
                        current.suggestedParsers.push_back (currentParser);
                    }
                if (current.provenance)
                    result.metadata.hasProvenance = true;
                result.fixes.push_back (current);
            }

        return result;
    }

  private:
    std::string trim (const std::string &s)
    {
        size_t start = s.find_first_not_of (" \t\r\n");
        size_t end = s.find_last_not_of (" \t\r\n");
        if (start == std::string::npos)
            return "";
        return s.substr (start, end - start + 1);
    }

    std::string extractValue(const std::string& line, const std::string& key)
    {
        size_t pos = line.find(key);
        if (pos == std::string::npos) // blank line if we didn't find anything
            return "";
    
        std::string value = trim(line.substr(pos + key.length()));
    
        // If the value is quoted, remove the quotes
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
            return value.substr(1, value.size() - 2);
    
        return value;
    }
};

/*
 * AnnotationGenerator Class
 *
 * Generates the comment file to be inserted into the target source file.
 */

class AnnotationGenerator
{
  public:
    std::string generate (const Fix &fix, const std::string &indent, bool provenanceFiltered)
    {
        std::stringstream ss;

        ss << indent << "/* TODO [LANGSEC]: Parse '" << fix.variable << "' before use\n";
        ss << indent << " *   Fix ID:         " << fix.id << "\n";
        ss << indent << " *   Current layer:  " << fix.actualLayer << "\n";
        ss << indent << " *   Required layer: " << fix.requiredLayer << "\n";

        if (provenanceFiltered)
            {
                ss << indent << " *   Provenance:    "; 
                if (fix.provenance)
                    {
                        ss << indent << "flagged after provenance filtering\n";
                        ss << indent << " *                   (not inherited from caller - requires validation here)\n";
                    }
                else
                    ss << indent << "provenance status unknown for this fix\n";
            }

        if (!fix.suggestedParsers.empty ())
            {
                ss << indent << " *\n";
                ss << indent << " *   Suggested parser\n";
                ss << indent << ((fix.suggestedParsers.size () == 1) ? ":" : "s:") << "\n";

                for (const auto &parser : fix.suggestedParsers)
                    {
                        ss << indent << " *     - " << parser.name << "\n";
                        if (!parser.header.empty ())
                            {
                                ss << indent << " *       Header:  " << parser.header << "\n";
                            }
                        if (!parser.reason.empty ())
                            {
                                ss << indent << " *       Reason:  " << parser.reason << "\n";
                            }

                        // Generate example code if it's a known parser
                        std::string example = generateExample (fix.variable, parser);
                        if (!example.empty ())
                            {
                                ss << indent << " *\n";
                                ss << indent << " *       Example:\n";
                                for (const auto &exLine : splitLines (example))
                                    {
                                        ss << indent << " *         " << exLine << "\n";
                                    }
                            }
                    }
            }

        if (fix.canAutoFix)
            {
                ss << indent << " *\n";
                ss << indent << " *   Note: auto-fix available (run with --auto-fix)\n";
            }

        ss << indent << " */";
        return ss.str ();
    }

  private:
    /*
     * We created examples of how to repair/add certain types of parsing
     * depending on the type. If we don't know the type, nothing is emitted
     * from this routine.
     */
    std::string generateExample (const std::string &var, const SuggestedParser &parser)
    {
        const std::string &name = parser.name;

        if (name == "langsec_parse_int32" || name == "langsec_parse_int64"
            || name == "langsec_parse_int8" || name == "langsec_parse_int16")
            {
                std::string type = "int32_t";
                if (name == "langsec_parse_int64")
                    type = "int64_t";
                if (name == "langsec_parse_int8")
                    type = "int8_t";
                if (name == "langsec_parse_int16")
                    type = "int16_t";
                return type + " parsed_" + var + ";\n"
                       + "if (" + name + "(" + var
                       + ", strlen(" + var + "), &parsed_" + var
                       + ", NULL) != LANGSEC_OK) {\n"
                         "    /* Handle parse error */\n"
                         "    return -1;\n"
                         "}\n"
                         "/* Use parsed_"
                       + var + " instead of " + var + " */";
            }

        if (name == "langsec_parse_uint32" || name == "langsec_parse_uint64"
            || name == "langsec_parse_uint8"
            || name == "langsec_parse_uint16")
            {
                std::string type = "uint32_t";
                if (name == "langsec_parse_uint64")
                    type = "uint64_t";
                if (name == "langsec_parse_uint8")
                    type = "uint8_t";
                if (name == "langsec_parse_uint16")
                    type = "uint16_t";
                return type + " parsed_" + var + ";\n"
                       + "if (" + name + "(" + var
                       + ", strlen(" + var + "), &parsed_" + var
                       + ", NULL) != LANGSEC_OK) {\n"
                         "    /* Handle parse error */\n"
                         "    return -1;\n"
                         "}\n"
                         "/* Use parsed_"
                       + var + " instead of " + var + " */";
            }

        if (name == "langsec_parse_string")
            {
                return "char parsed_" + var + "[256]; /* adjust size */\n"
                       + "size_t parsed_" + var + "_len;\n"
                       + "langsec_string_out_t out_" + var
                       + " = {\n"
                         "    .buffer = parsed_"
                       + var + ",\n" + "    .buffer_size = sizeof(parsed_" + var
                       + "),\n" + "    .length_out = &parsed_" + var
                       + "_len\n"
                         "};\n"
                         "if (langsec_parse_string("
                       + var + ", strlen(" + var + "), &out_" + var
                       + ", NULL) != LANGSEC_OK) {\n"
                         "    /* Handle parse error */\n"
                         "    return -1;\n"
                         "}";
            }

        if (name == "langsec_parse_double" || name == "langsec_parse_float")
            {
                std::string type = (name == "langsec_parse_float") ? "float"
                                                                    : "double";
                return type + " parsed_" + var + ";\n"
                       + "if (" + name + "(" + var
                       + ", strlen(" + var + "), &parsed_" + var
                       + ", NULL) != LANGSEC_OK) {\n"
                         "    /* Handle parse error */\n"
                         "    return -1;\n"
                         "}";
            }

        if (name == "langsec_parse_ipv4")
            {
                return "langsec_ipv4_t parsed_" + var + ";\n"
                       + "if (langsec_parse_ipv4(" + var + ", strlen(" + var
                       + "), &parsed_" + var
                       + ", NULL) != LANGSEC_OK) {\n"
                         "    /* Handle invalid IPv4 address */\n"
                         "    return -1;\n"
                         "}";
            }

        if (name == "langsec_parse_port")
            {
                return "uint16_t parsed_" + var + ";\n"
                       + "if (langsec_parse_port(" + var + ", strlen(" + var
                       + "), &parsed_" + var
                       + ", NULL) != LANGSEC_OK) {\n"
                         "    /* Handle invalid port */\n"
                         "    return -1;\n"
                         "}";
            }

        // CUSTOM_PARSER or unknown - no example, reason is sufficient
        return "";
    }

    std::vector<std::string> splitLines (const std::string &text)
    {
        std::vector<std::string> lines;
        std::istringstream stream (text);
        std::string line;
        while (std::getline (stream, line))
            {
                lines.push_back (line);
            }
        return lines;
    }
};

//
// Source File Annotator
//

class SourceAnnotator
{
  public:
    struct Options
    {
        bool dryRun = false;
        bool backup = false;
        bool verbose = false;
        std::string outputDir;
    };

    struct Stats
    {
        int filesProcessed = 0;
        int annotationsInserted = 0;
        int skipped = 0;
    };

    SourceAnnotator (const Options &opts) : opts_ (opts) {}

    Stats
    annotateFiles (const std::vector<Fix> &fixes,
                   const ReportMetadata &metadata)
    {
        Stats stats;

        // Group fixes by file
        std::map<std::string, std::vector<Fix>> byFile;
        for (const auto &fix : fixes)
            {
                if (!fix.file.empty () && fix.line > 0)
                    {
                        byFile[fix.file].push_back (fix);
                    }
                else
                    {
                        if (opts_.verbose)
                            {
                                std::cerr << "  Warning: Fix " << fix.id
                                          << " has no file/line, skipping\n";
                            }
                        stats.skipped++;
                    }
            }

        if (byFile.empty ())
            {
                std::cout << "No fixes with valid file locations found.\n";
                return stats;
            }

        std::cout << "Processing " << byFile.size () << " file(s)...\n\n";

        for (auto &[file, fileFixes] : byFile)
            {
                // Sort descending by line so we insert bottom-up
                std::sort (fileFixes.begin (), fileFixes.end (),
                           [] (const Fix &a, const Fix &b) {
                               return a.line > b.line;
                           });

                Stats fileStats = annotateFile (file, fileFixes, metadata);
                stats.filesProcessed++;
                stats.annotationsInserted += fileStats.annotationsInserted;
                stats.skipped += fileStats.skipped;
            }

        return stats;
    }

  private:
    Options opts_;
    AnnotationGenerator generator_;

    Stats
    annotateFile (const std::string &filename, const std::vector<Fix> &fixes,
                  const ReportMetadata &metadata)
    {
        Stats stats;

        if (opts_.verbose)
            {
                std::cout << "Processing: " << filename << "\n";
            }

        // Read source file
        std::ifstream in (filename);
        if (!in)
            {
                std::cerr << "Error: Cannot read " << filename << "\n";
                stats.skipped += fixes.size ();
                return stats;
            }

        std::vector<std::string> lines;
        std::string line;
        while (std::getline (in, line))
            {
                lines.push_back (line);
            }
        in.close ();

        // Track lines already annotated to avoid duplicates
        std::set<unsigned> annotatedLines;

        for (const auto &fix : fixes)
            {
                if (fix.line == 0 || fix.line > lines.size ())
                    {
                        if (opts_.verbose)
                            {
                                std::cerr << "  Warning: Fix " << fix.id
                                          << " line " << fix.line
                                          << " out of range\n";
                            }
                        stats.skipped++;
                        continue;
                    }

                if (annotatedLines.count (fix.line))
                    {
                        if (opts_.verbose)
                            {
                                std::cout << "  Line " << fix.line
                                          << ": already annotated, skipping\n";
                            }
                        stats.skipped++;
                        continue;
                    }

                // Check if a LANGSEC annotation for this variable already
                // exists near the target line
                if (alreadyAnnotated (lines, fix))
                    {
                        if (opts_.verbose)
                            {
                                std::cout << "  Line " << fix.line << " ["
                                          << fix.id << "]: '" << fix.variable
                                          << "' already annotated, skipping\n";
                            }
                        stats.skipped++;
                        continue;
                    }

                annotatedLines.insert (fix.line);

                // Detect indentation from target line
                std::string indent;
                const std::string &targetLine = lines[fix.line - 1];
                for (char c : targetLine)
                    {
                        if (c == ' ' || c == '\t')
                            indent += c;
                        else
                            break;
                    }

                // Generate annotation
                std::string annotation
                    = generator_.generate (fix, indent, metadata.hasProvenance);

                // Insert before target line
                lines.insert (lines.begin () + fix.line - 1, annotation);
                stats.annotationsInserted++;

                if (opts_.verbose)
                    {
                        std::cout << "  Line " << fix.line << " [" << fix.id
                                  << "]: '" << fix.variable << "' ("
                                  << fix.actualLayer << " -> "
                                  << fix.requiredLayer << ")\n";
                    }
            }

        if (stats.annotationsInserted == 0)
            {
                std::cout << "  " << filename << ": No new annotations\n";
                return stats;
            }

        // Determine output path
        std::string outputPath = filename;
        if (!opts_.outputDir.empty ())
            {
                fs::path outDir (opts_.outputDir);
                fs::path srcPath (filename);
                outputPath = (outDir / srcPath.filename ()).string ();
            }

        if (opts_.dryRun)
            {
                std::cout << "  " << filename << ": Would insert "
                          << stats.annotationsInserted << " annotation(s)\n";
                return stats;
            }

        // Backup if requested
        if (opts_.backup && outputPath == filename)
            {
                std::string backupPath = filename + ".bak";
                if (opts_.verbose)
                    std::cout << "  Creating backup: " << backupPath << "\n";
                fs::copy_file (filename, backupPath,
                               fs::copy_options::overwrite_existing);
            }

        // Write output
        std::ofstream out (outputPath);
        if (!out)
            {
                std::cerr << "Error: Cannot write " << outputPath << "\n";
                return stats;
            }

        for (const auto &l : lines)
            out << l << "\n";
        out.close ();

        std::cout << "  " << outputPath << ": Inserted "
                  << stats.annotationsInserted << " annotation(s)\n";
        return stats;
    }

    bool alreadyAnnotated (const std::vector<std::string> &lines, const Fix &fix)
    {
        // Check a window around the target line for existing LANGSEC comments
        // mentioning this fix id or variable
        int startLine = std::max (0, static_cast<int> (fix.line) - 10);
        int endLine   = std::min (static_cast<int> (lines.size ()),
                                  static_cast<int> (fix.line) + 5);

        std::string varMarker = "'" + fix.variable + "'";
        std::string idMarker  = fix.id;

        for (auto i = startLine; i < endLine; ++i)
            {
                const std::string &l = lines[i];
                if (l.find ("LANGSEC") != std::string::npos)
                    {
                        if (l.find (varMarker) != std::string::npos
                            || l.find (idMarker) != std::string::npos)
                            {
                                return true;
                            }
                    }
            }
        return false;
    }
};

//
// Print the program usage. This is quite the tome and probably should be
// mostly moved to a man page.
//
void printUsage (const char *progName)
{
    std::cout << "Usage: " << progName << " <fix_suggestions.yaml> [options]\n\n";
    std::cout << "Insert LangSec parser suggestion comments into C source files.\n";
    std::cout << "Reads fix suggestions produced by the PAPI taint analyzer (--provenance mode).\n\n";
    std::cout << "Options:\n";
    std::cout << "  --dry-run           Show what would be changed without modifying files\n";
    std::cout << "  --backup            Create .bak backup files before modifying\n";
    std::cout << "  --output-dir=<dir>  Write annotated files to a different directory\n";
    std::cout << "  --verbose           Show detailed progress\n";
    std::cout << "  --help              Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << progName << " fix_suggestions.yaml --dry-run\n";
    std::cout << "  " << progName << " fix_suggestions.yaml --backup --verbose\n";
    std::cout << "  " << progName << " fix_suggestions.yaml --output-dir=./annotated\n";
}

//
// Command Line Interface
//
int main (int argc, char *argv[])
{
    if (argc < 2)
        {
            printUsage (argv[0]);
            return 1;
        }

    std::string yamlFile;
    SourceAnnotator::Options opts;

    for (auto i = 1; i < argc; ++i)
        {
            std::string arg = argv[i];

            if (arg == "--help" || arg == "-h")
                {
                    printUsage (argv[0]);
                    return 0;
                }
            else if (arg == "--dry-run")
                opts.dryRun = true;
            else if (arg == "--backup")
                opts.backup = true;
            else if (arg == "--verbose" || arg == "-v")
                opts.verbose = true;
            else if (arg.find ("--output-dir=") == 0)
                opts.outputDir = arg.substr (13);
            else if (arg[0] != '-')
                yamlFile = arg;
            else
                {
                    std::cerr << "Unknown option: " << arg << "\n";
                    return 1;
                }
        }

    if (yamlFile.empty ())
        {
            std::cerr << "Error: No YAML file specified\n";
            printUsage (argv[0]);
            return 1;
        }

    if (!opts.outputDir.empty ())
        fs::create_directories (opts.outputDir);

    std::cout << "LangSec Annotate - Insert parser suggestion comments\n";
    std::cout << "====================================================\n\n";

    // Parse the YAML
    FixYAMLParser parser;
    auto result = parser.parse (yamlFile);

    if (result.fixes.empty ())
        {
            std::cout << "No fixes found in " << yamlFile << "\n";
            return 0;
        }

    // Report what we found
    std::cout << "Report version:     " << result.metadata.version << "\n";
    std::cout << "Fixes in report:    " << result.metadata.fixCount << "\n";
    std::cout << "Fixes parsed:       " << result.fixes.size () << "\n";
    std::cout << "Provenance filtered: " << (result.metadata.hasProvenance ? "yes" : "no") << "\n\n";

    // Mark whether provenance is on. In the future, the analyzer will default to
    // provenance-enabled reports.
    if (result.metadata.hasProvenance)
        {
            std::cout
                << "Note: Provenance filtering was applied. Flagged locations\n"
                   "are modified or locally-introduced parameters that cannot\n"
                   "inherit validation from callers.\n\n";
        }
    else
        {
            std::cout
                << "Warning: No provenance information detected in this report.\n"
                   "Results may include pass-through parameters that do not\n"
                   "require validation at this location. Consider re-running\n"
                   "the taint analyzer with --provenance enabled.\n\n";
        }

    // Annotate files
    SourceAnnotator annotator (opts);
    auto stats = annotator.annotateFiles (result.fixes, result.metadata);

    std::cout << "\n====================================================\n";
    std::cout << "Summary:\n";
    std::cout << "  Files processed:      " << stats.filesProcessed << "\n";
    std::cout << "  Annotations inserted: " << stats.annotationsInserted << "\n";
    std::cout << "  Skipped:              " << stats.skipped << "\n";
    std::cout << "\nDone.\n";

    return 0;
}
