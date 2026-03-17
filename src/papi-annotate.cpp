/*----------------------------------------------------------------------
 *
 * Filename: papi-annotate.cpp
 * Description: Insert PAPI annotation comments into C source files.
 *              Reads a PAPI YAML output file, auto-detects the format,
 *              and inserts structured comment annotations immediately
 *              before the target source line in each affected file.
 *
 * Date       Pgm  Comment
 * 01 Mar 26  jpb  Rebuilt from old test program to work with provenance-enabled files
 * 15 Mar 26  jpb  Merged papi-recommendations.c and unified annotation format.
 *
 * Usage:
 *   papi-annotate <papi.yaml> [--srcdir <dir>] [--dry-run] [--verbose]
 *
 * The YAML format is auto-detected from the top-level key:
 *
 *   raw_usages:       Raw taint observations.  Inserts:
 *                       @papi: var=X, suggested_parser=Y, context=Z
 *
 *   fixes:            Parse-point fix suggestions.  Inserts:
 *                       @papi: var=X, suggested_parser=Y,
 *                              actual_layer=A, required_layer=B
 *
 *   suppressed_fixes: (no fixes are present) Prints message, exits cleanly.
 *
 * Options:
 *   --srcdir <dir>   Resolve relative source paths under <dir> (default: .)
 *   --dry-run        Print changes without modifying files
 *   --verbose        Print per-annotation progress
 *
 * Notes:
 *   - Annotation insertion is idempotent: an existing @papi annotation for
 *     the same variable immediately preceding the target line is replaced
 *     rather than duplicated (two-pass rewrite).
 *   - PARSER_REVIEW_NEEDED is substituted when no parser is suggested.
 *
 */

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

// YAML format detected in the input file
enum class YamlFormat
{
    RawUsages,
    Fixes,
    SuppressedOnly,
    Unknown
};

// Unified annotation entry covering both YAML formats
struct AnnotEntry
{
    std::string srcFile;
    int         srcLine = -1;       // 1-based; -1 if unresolved
    std::string variable;
    std::string suggestedParser;
    std::string context;            // raw_usages: context field
    std::string actualLayer;        // fixes: actual_layer field
    std::string requiredLayer;      // fixes: required_layer field
    std::string location;           // raw_usages: raw "path:line:col" string
};

// String helpers
static std::string trim(const std::string &s)
{
    auto start = s.find_first_not_of(" \t\r\n");
    auto end   = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

static void unquote(std::string &s)
{
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        s = s.substr(1, s.size() - 2);
}

static bool startsWith(const std::string &s, const std::string &prefix)
{
    return s.size() >= prefix.size()
           && s.compare(0, prefix.size(), prefix) == 0;
}

// Return value after key at the start of t, trimmed and unquoted.
// Returns empty string if t does not start with key.
static std::string fieldValue(const std::string &t, const std::string &key)
{
    if (!startsWith(t, key)) return "";
    std::string val = trim(t.substr(key.size()));
    unquote(val);
    return val;
}

static int countIndent(const std::string &line)
{
    int n = 0;
    for (char c : line)
    {
        if (c == ' ') n++;
        else break;
    }
    return n;
}

// Format detection
// Figure out if this is a raw vs. fixes file
static YamlFormat detectFormat(const std::string &path, const std::string &appName)
{
    std::ifstream in(path);
    if (!in)
    {
        std::cerr << appName << ": cannot open '" << path << "': " << std::strerror(errno) << "\n";
        return YamlFormat::Unknown;
    }

    bool hasRaw = false, hasFixes = false, hasSuppressed = false;
    std::string line;

    while (std::getline(in, line))
    {
        // Top-level YAML keys have no leading whitespace.
        if (line.empty() || line[0] == ' ' || line[0] == '\t') continue;
        std::string t = trim(line);
        if      (t == "raw_usages:")                 hasRaw = true;
        else if (t == "fixes:")                      hasFixes = true;
        else if (startsWith(t, "suppressed_fixes:")) hasSuppressed = true;
    }

    if (hasRaw)        return YamlFormat::RawUsages;
    if (hasFixes)      return YamlFormat::Fixes;
    if (hasSuppressed) return YamlFormat::SuppressedOnly;
    return YamlFormat::Unknown;
}

/* Location parser (raw_usages mode)
 * Split "path/to/file.c:line:col" into file path and line number.
 *  The path may contain colons, so we split from the right.
 */
static bool parseLocation(const std::string &loc, std::string &fileOut, int &lineOut)
{
    auto last = loc.rfind(':');
    if (last == std::string::npos || last == 0) return false;

    auto second = loc.rfind(':', last - 1);
    if (second == std::string::npos) return false;

    std::string lineStr = loc.substr(second + 1, last - second - 1);
    for (char c : lineStr)
    {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }

    lineOut = std::stoi(lineStr);
    fileOut = loc.substr(0, second);
    return true;
}

// Source path resolver
static bool resolvePath(const std::string &srcFile, const std::string &srcDir,
            std::string &resolved)
{
    // Try as-is (absolute or relative to cwd).
    if (std::ifstream(srcFile)) { resolved = srcFile; return true; }

    // Try basename under srcDir.
    auto sep  = srcFile.rfind('/');
    std::string base = (sep == std::string::npos) ? srcFile
                                                   : srcFile.substr(sep + 1);
    resolved = srcDir + "/" + base;
    if (std::ifstream(resolved)) return true;

    // Try full relative path under srcDir.
    resolved = srcDir + "/" + srcFile;
    if (std::ifstream(resolved)) return true;

    return false;
}

// YAML parser: raw_usages format
static std::vector<AnnotEntry> parseRawUsages(const std::string &path, const std::string &appName)
{
    std::vector<AnnotEntry> entries;
    std::ifstream in(path);
    if (!in)
    {
        std::cerr << appName << ": cannot open '" << path << "': " << std::strerror(errno) << "\n";
        return entries;
    }

    int curIdx = -1;
    std::string line;

    while (std::getline(in, line))
    {
        std::string t = trim(line);

        if (startsWith(t, "- "))
        {
            entries.emplace_back();
            curIdx = static_cast<int>(entries.size()) - 1;
            t = t.substr(2);
        }

        if (curIdx < 0) continue;
        AnnotEntry &cur = entries[curIdx];

        std::string val;
        if      (!(val = fieldValue(t, "variable: ")).empty())         cur.variable        = val;
        else if (!(val = fieldValue(t, "location: ")).empty())         cur.location        = val;
        else if (!(val = fieldValue(t, "context: ")).empty())          cur.context         = val;
        else if (!(val = fieldValue(t, "suggested_parser: ")).empty()) cur.suggestedParser = val;
    }

    // Post-process: parse location strings into srcFile + srcLine.
    for (auto &e : entries)
    {
        if (e.location.empty()) continue;
        if (!parseLocation(e.location, e.srcFile, e.srcLine))
        {
            std::cerr << appName << ": warning: cannot parse location '" << e.location << "' (skipping)\n";
            e.srcLine = -1;
        }
    }

    return entries;
}

// YAML parser: fixes format
static std::vector<AnnotEntry> parseFixes(const std::string &path, const std::string &appName)
{
    std::vector<AnnotEntry> entries;
    std::ifstream in(path);
    if (!in)
    {
        std::cerr << appName << ": cannot open '" << path << "': " << std::strerror(errno) << "\n";
        return entries;
    }

    int         curIdx    = -1;
    bool        inFixes   = false;
    bool        inParsers = false;
    bool        gotParser = false;
    std::string line;

    while (std::getline(in, line))
    {
        int         indent = countIndent(line);
        std::string t      = trim(line);

        if (t.empty() || t[0] == '#') continue;

        // Top-level keys (indent == 0)
        if (indent == 0)
        {
            if (t == "fixes:") inFixes = true;
            else if (startsWith(t, "suppressed_fixes:")) inFixes = false;
            continue;
        }

        if (!inFixes) continue;

        // New fix entry at indent 2: "  - id: ..."
        if (indent == 2 && startsWith(t, "- id:"))
        {
            entries.emplace_back();
            curIdx    = static_cast<int>(entries.size()) - 1;
            inParsers = false;
            gotParser = false;
            continue;
        }

        if (curIdx < 0) continue;
        AnnotEntry &cur = entries[curIdx];

        // Handle suggested_parsers content; watch for first "- name:" at
        // indent 6, or a return to indent 4 which ends the list.
        if (inParsers)
        {
            if (indent == 6 && startsWith(t, "- name:") && !gotParser)
            {
                cur.suggestedParser = fieldValue(t, "- name:");
                gotParser = true;
            }
            if (indent <= 4) inParsers = false;
            else             continue;
        }

        // Fix-level fields at indent 4
        if (indent == 4)
        {
            std::string val;
            if      (!(val = fieldValue(t, "file:")).empty())            cur.srcFile       = val;
            else if (!(val = fieldValue(t, "line:")).empty())            cur.srcLine       = std::stoi(val);
            else if (!(val = fieldValue(t, "variable:")).empty())        cur.variable      = val;
            else if (!(val = fieldValue(t, "actual_layer:")).empty())    cur.actualLayer   = val;
            else if (!(val = fieldValue(t, "required_layer:")).empty())  cur.requiredLayer = val;
            else if (t == "suggested_parsers:")                          { inParsers = true; gotParser = false; }
        }
    }

    return entries;
}

// Annotation builder
static std::string buildAnnotation(const AnnotEntry &e, YamlFormat fmt)
{
    const std::string &parser = e.suggestedParser.empty()
                                ? "PARSER_REVIEW_NEEDED"
                                : e.suggestedParser;

    std::ostringstream ss;
    ss << "/* @papi: var=" << e.variable
       << ", suggested_parser=" << parser << ",\n";

    if (fmt == YamlFormat::RawUsages)
    {
        ss << " *         context=" << (e.context.empty() ? "unknown" : e.context) << " */";
    }
    else
    {
        ss << " *         actual_layer=" << (e.actualLayer.empty() ? "unknown" : e.actualLayer)
           << ", required_layer=" << (e.requiredLayer.empty() ? "unknown" : e.requiredLayer) << " */";
    }

    return ss.str();
}

// Annotation check
static bool isPapiFor(const std::string &line, const std::string &varname)
{
    if (line.find("@papi:") == std::string::npos) return false;
    return line.find("var=" + varname) != std::string::npos;
}

// File annotator
//
// Two-pass strategy:
//   Pass 1: blank out any existing @papi block immediately preceding each
//           target line (for the same variable) so updates are clean.
//   Pass 2: emit lines, injecting fresh annotations before target lines.
static int annotateFile(const std::string &srcPath,
             const std::vector<std::pair<int, const AnnotEntry *>> &anns,
             YamlFormat fmt, bool dryRun, bool verbose, const std::string &appName)
{
    std::ifstream in(srcPath);
    if (!in)
    {
        std::cerr << appName << ": cannot open '" << srcPath << "': " << std::strerror(errno) << "\n";
        return -1;
    }

    // Read all lines, preserving newlines so empty string means "suppressed".
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line))
        lines.push_back(line + "\n");
    in.close();

    // Pass 1: blank out existing @papi blocks for the same variable.
    for (const auto &ann : anns)
    {
        int li                     = ann.first;
        const std::string &varname = ann.second->variable;

        for (int bk = li - 1; bk >= 0; bk--)
        {
            const std::string &prev = lines[bk];
            std::string t           = trim(prev);

            if (t.empty()) break;
            if (prev.find("@papi") == std::string::npos
                && t[0] != '*'
                && !(t.size() >= 2 && t[0] == '/' && t[1] == '*')) break;

            if (isPapiFor(prev, varname) ||
                prev.find("@papi") != std::string::npos)
                lines[bk] = "";
            else
                break;
        }
    }

    std::string tmpPath = srcPath + ".papi_tmp";
    std::ofstream out;
    if (!dryRun)
    {
        out.open(tmpPath);
        if (!out)
        {
            std::cerr << appName << ": cannot write '" << tmpPath << "': " << std::strerror(errno) << "\n";
            return -1;
        }
    }

    int changes = 0;

    // Pass 2: emit lines, injecting annotations before target lines.
    for (int li = 0; li < static_cast<int>(lines.size()); li++)
    {
        const std::string &l = lines[li];
        if (l.empty()) continue;   // suppressed in pass 1

        for (const auto &ann : anns)
        {
            if (ann.first != li) continue;

            std::string annotation = buildAnnotation(*ann.second, fmt);

            if (verbose || dryRun)
                std::cout << (dryRun ? "[dry-run] " : "") << "  +annotation at " << srcPath << ":"
                          << li + 1 << " for var '" << ann.second->variable << "'\n";

            if (!dryRun) out << annotation << "\n";
            changes++;
        }

        if (!dryRun) out << l;
    }

    if (!dryRun)
    {
        out.close();
        if (changes > 0)
        {
            if (std::rename(tmpPath.c_str(), srcPath.c_str()) != 0)
            {
                std::cerr << appName << ": rename '" << tmpPath << "' -> '" << srcPath << "': " << std::strerror(errno) << "\n";
                std::remove(tmpPath.c_str());
                return -1;
            }
            if (verbose)
                std::cout << "  wrote " << changes << " annotation(s) to " << srcPath << "\n";
        }
        else
        {
            std::remove(tmpPath.c_str());
        }
    }

    return changes;
}

// Annotate all entries grouped by source file
static int annotateAll(std::vector<AnnotEntry> &entries, const std::string &srcDir,
            YamlFormat fmt, bool dryRun, bool verbose, const std::string &appName)
{
    // Group valid entries by resolved source path.
    std::map<std::string, std::vector<const AnnotEntry *>> byFile;

    for (const auto &e : entries)
    {
        if (e.srcLine < 1) continue;

        std::string resolved;
        if (!resolvePath(e.srcFile, srcDir, resolved))
        {
            std::cerr << appName << ": warning: cannot find source file '" << e.srcFile << "' (skipping)\n";
            continue;
        }

        byFile[resolved].push_back(&e);
    }

    int total = 0;

    for (const auto &kv : byFile)
    {
        const std::string &srcPath = kv.first;
        const std::vector<const AnnotEntry *> &fileEntries = kv.second;

        if (verbose)
            std::cout << appName << ": processing " << srcPath << "\n";

        std::vector<std::pair<int, const AnnotEntry *>> anns;
        for (const auto *e : fileEntries)
            anns.emplace_back(e->srcLine - 1, e);

        int n = annotateFile(srcPath, anns, fmt, dryRun, verbose, appName);
        if (n > 0) total += n;
    }

    return total;
}

// Print usage/help information 
static void printUsage(const std::string &appName)
{
    std::cerr << "Usage: " << appName
              << " <papi.yaml> [--srcdir <dir>] [--dry-run] [--verbose]\n\n"
              << "  <papi.yaml>     PAPI YAML file (raw_usages or fixes format)\n"
              << "  --srcdir <dir>  Directory to resolve relative source paths "
                 "(default: .)\n"
              << "  --dry-run       Show changes without modifying files\n"
              << "  --verbose       Print progress\n";
}

// main entry point
int main(int argc, char *argv[])
{
    std::string yamlPath;
    std::string srcDir  = ".";
    std::string appName;
    bool        dryRun  = false;
    bool        verbose = false;

    for (int i = 1; i < argc; i++)  // grab the cmd line arguments
    {
        std::string arg = argv[i];

        if (arg == "--srcdir" && i + 1 < argc)
            srcDir = argv[++i];
        else if (arg == "--dry-run")
            dryRun = true;
        else if (arg == "--verbose")
            verbose = true;
        else if (arg[0] != '-')
            yamlPath = arg;
        else
        {
            std::cerr << argv[0] << ": unknown option '" << arg << "'\n";
            printUsage(argv[0]);
            return 1;
        }
    }

    appName = argv[0];  // set the app name for printing info

    // Forgot the YAML file? Here's some help.
    if (yamlPath.empty()) { printUsage(appName); return 1; }

    YamlFormat fmt = detectFormat(yamlPath, appName);

    switch (fmt)
    {
        case YamlFormat::Unknown:
            std::cerr << appName << ": '" << yamlPath << "': unrecognized YAML format (expected raw_usages: or fixes: top-level key)\n";
            return 1;

        case YamlFormat::SuppressedOnly:
            std::cout << appName << ": all fixes were suppressed; nothing to annotate.\n";
            return 0;

        case YamlFormat::RawUsages:
        case YamlFormat::Fixes:
            break;
    }

    std::vector<AnnotEntry> entries = (fmt == YamlFormat::RawUsages) ? parseRawUsages(yamlPath, appName) : parseFixes(yamlPath, appName);

    if (verbose)
        std::cout << appName << ": loaded " << entries.size() << " entry/entries from " << yamlPath << "\n";

    if (entries.empty())
    {
        std::cout << appName << ": no entries found; nothing to do.\n";
        return 0;
    }

    int total = annotateAll(entries, srcDir, fmt, dryRun, verbose, appName);

    if (dryRun)
        std::cout << "[dry-run] " << total << " annotation(s) would be written.\n";
    else
        std::cout << appName << ": " << total << " annotation(s) written.\n";

    return 0;
}
