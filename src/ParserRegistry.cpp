/*----------------------------------------------------------------------
 *
 * Filename: ParserRegistry.cpp
 * Description: Registry of known LangSec parsers and their properties.
 *
 * loadBuiltinParsers() is the canonical list. Each entry states:
 *   - The parser function name and its include header
 *   - The taint layer it elevates input to on success
 *   - How confident the suggestion is (HIGH/MEDIUM/LOW)
 *   - Which C types, sink functions, and variable name substrings
 *     trigger this parser as a suggestion
 *
 * A future version may move this into SQLite to separate the parser
 * registry from the analyzer code. When moving to SQLite,
 * loadBuiltinParsers() becomes a schema population script and the
 * three match vectors become child tables:
 *   parser_type_triggers  (parser_name, c_type)
 *   parser_sink_triggers  (parser_name, sink_name)
 *   parser_name_triggers  (parser_name, var_substring)
 *
 * Date       Pgm  Comment
 * 09 Mar 26  jpb  Creation.
 * 12 Mar 26  jpb  Refactored parser entry/selection
 *
 */

#include "ParserRegistry.h"
#include "TaintAnalyzer.h"

#include <algorithm>
#include <cctype>

namespace taint
{

ParserRegistry::ParserRegistry ()
{
    loadBuiltinParsers ();
}

//
// loadBuiltinParsers
//
// Table-driven catalog.  Each row is one ParserEntry.  Group by header.
// To add a new parser, append a row to the table below.
//
void ParserRegistry::loadBuiltinParsers ()
{
    struct ParserSpec
    {
        const char              *name;
        const char              *header;
        TaintLayer               outputLayer;
        FixConfidence            confidence;
        const char              *reason;
        std::vector<std::string> matchTypes;
        std::vector<std::string> matchSinks;
        std::vector<std::string> matchVarNames;
    };

    const ParserSpec table[] =
    {
        // langsec/primitive.h
        // 32-bit signed integer. Replaces atoi/atol which propagate taint.
        { "langsec_parse_int32", "langsec/primitive.h",
          TaintLayer::SYNTACTIC, FixConfidence::HIGH,
          "Safe integer parse with overflow and format checking",
          {"int32_t", "int"}, {},
          {"id", "num", "count", "index", "len", "length",
           "val", "value", "code", "result"} },

        // Unsigned 16-bit integer. Natural fit for port numbers.
        { "langsec_parse_uint16", "langsec/primitive.h",
          TaintLayer::SYNTACTIC, FixConfidence::HIGH,
          "Unsigned 16-bit integer; bounds enforced by type",
          {"uint16_t"}, {}, {"port"} },

        // size_t. Requires SEMANTIC: valid size can still be dangerously large.
        { "langsec_parse_size", "langsec/primitive.h",
          TaintLayer::SEMANTIC, FixConfidence::HIGH,
          "Bounded size_t; rejects negative and oversized values",
          {"size_t"},
          {"malloc", "calloc", "realloc", "memcpy", "memmove", "memset"},
          {"size", "sz", "len", "length", "nbytes", "buflen"} },

        // Boolean. Accepts "0"/"1", "true"/"false", "yes"/"no".
        { "langsec_parse_bool", "langsec/primitive.h",
          TaintLayer::SEMANTIC, FixConfidence::HIGH,
          "Strict boolean; rejects all non-boolean strings",
          {"bool", "_Bool"}, {},
          {"flag", "enable", "enabled", "active", "toggle"} },

        // Length-bounded string. Most widely applicable parser.
        { "langsec_parse_string", "langsec/primitive.h",
          TaintLayer::SYNTACTIC, FixConfidence::HIGH,
          "Length-bounded string; verifies null termination",
          {"char *", "const char *", "char*", "const char*"},
          {"strlen", "strcpy", "strncpy", "strcat", "strncat",
           "strcmp", "printf", "fprintf", "sprintf", "snprintf"},
          {"str", "string", "buf", "buffer", "msg", "message",
           "text", "name", "username", "input", "data"} },

        // Whitelist enum. Required before passing strings to shell commands.
        { "langsec_parse_string_enum", "langsec/primitive.h",
          TaintLayer::CONTEXTUAL, FixConfidence::LOW,
          "Shell input must be whitelisted; provide allowed values",
          {},
          {"system", "popen", "execve", "execvp", "execv", "execl", "execlp"},
          {"cmd", "command", "arg", "argv", "shell"} },

        // langsec/net.h
        // IPv4 address via inet_pton; structurally and domain-valid.
        { "langsec_parse_ipv4", "langsec/net.h",
          TaintLayer::SEMANTIC, FixConfidence::MEDIUM,
          "IPv4 address validation via inet_pton",
          {"struct in_addr", "in_addr_t"},
          {"connect", "bind", "sendto"},
          {"ip", "addr", "address", "host", "ipaddr",
           "ipv4", "src_ip", "dst_ip", "peer"} },

        // Hostname / FQDN per RFC 1123. Does not perform DNS lookup.
        { "langsec_parse_hostname", "langsec/net.h",
          TaintLayer::SYNTACTIC, FixConfidence::MEDIUM,
          "Hostname syntax per RFC 1123; no DNS resolution",
          {},
          {"getaddrinfo", "gethostbyname", "connect"},
          {"host", "hostname", "server", "fqdn", "domain"} },

        // URL - validates scheme, authority, and path structure.
        { "langsec_parse_url", "langsec/net.h",
          TaintLayer::SYNTACTIC, FixConfidence::MEDIUM,
          "URL syntax validation (scheme, authority, path)",
          {},
          {"fopen", "open", "curl_easy_setopt"},
          {"url", "uri", "endpoint", "link", "href"} },

        // Email address per RFC 5321.
        { "langsec_parse_email", "langsec/net.h",
          TaintLayer::SYNTACTIC, FixConfidence::MEDIUM,
          "Email address syntax per RFC 5321",
          {}, {},
          {"email", "mail", "address", "recipient", "sender"} },

        // langsec/path.h
        // Filesystem path. Rejects traversal and null bytes. Callers must
        // still check permissions and canonicalize before use.
        { "langsec_parse_path", "langsec/path.h",
          TaintLayer::SEMANTIC, FixConfidence::HIGH,
          "Path traversal prevention; rejects ../ and null bytes",
          {},
          {"open", "fopen", "opendir", "unlink", "rename",
           "stat", "chmod", "chown", "mkdir"},
          {"path", "filename", "file", "dir", "directory",
           "filepath", "fname", "dirname"} },
    };

    for (const auto &spec : table)
        {
            ParserEntry e;
            e.name         = spec.name;
            e.header       = spec.header;
            e.outputLayer  = spec.outputLayer;
            e.confidence   = spec.confidence;
            e.reason       = spec.reason;
            e.matchTypes   = spec.matchTypes;
            e.matchSinks   = spec.matchSinks;
            e.matchVarNames = spec.matchVarNames;
            registerParser (e);
        }
}

//
// registerParser
//
void ParserRegistry::registerParser (const ParserEntry &entry)
{
    byName_[entry.name] = entry;
    indexEntry (entry);
}

//
// indexEntry - rebuild inverted indexes for one entry
//
void ParserRegistry::indexEntry (const ParserEntry &entry)
{
    for (const auto &t : entry.matchTypes)
        byType_[t] = entry.name;

    for (const auto &s : entry.matchSinks)
        bySink_[s].push_back (entry.name);

    for (const auto &v : entry.matchVarNames)
        byVarName_[v] = entry.name;
}

//
// FunctionDatabase integration
//
void ParserRegistry::registerWithFuncDb (FunctionDatabase &db) const
{
    for (const auto &pair : byName_)
        db.registerParser (pair.second.name, pair.second.outputLayer);
}

//
// isKnownParser / getOutputLayer
//
bool ParserRegistry::isKnownParser (const std::string &name) const
{
    return byName_.count (name) > 0;
}

TaintLayer ParserRegistry::getOutputLayer (const std::string &name) const
{
    auto it = byName_.find (name);
    if (it != byName_.end ())
        return it->second.outputLayer;
    return TaintLayer::CLEAN;
}

//
// findForType
//
ParserEntry ParserRegistry::findForType (const std::string &cType) const
{
    auto it = byType_.find (cType);
    if (it != byType_.end ())
        {
            auto pit = byName_.find (it->second);
            if (pit != byName_.end ())
                return pit->second;
        }
    return {}; // empty entry: name == ""
}

//
// findForSink
//
std::vector<ParserEntry> ParserRegistry::findForSink (const std::string &sinkName) const
{
    std::vector<ParserEntry> results;
    auto it = bySink_.find (sinkName);
    if (it != bySink_.end ())
        {
            for (const auto &name : it->second)
                {
                    auto pit = byName_.find (name);
                    if (pit != byName_.end ())
                        results.push_back (pit->second);
                }
        }
    return results;
}

//
// findForVarName
// Lowercase the incoming name and scan all registered substrings.
// Returns the first match found; longer substrings are not prioritized
// here — entries are inserted in registration order.
//
ParserEntry ParserRegistry::findForVarName (const std::string &varName) const
{
    std::string lower = varName;
    std::transform (lower.begin (), lower.end (), lower.begin (), ::tolower);

    for (const auto &pair : byVarName_)
        {
            if (lower.find (pair.first) != std::string::npos)
                {
                    auto pit = byName_.find (pair.second);
                    if (pit != byName_.end ())
                        return pit->second;
                }
        }
    return {}; // no match
}

//
// suggestForViolation
// Priority: type match > sink match > variable name match.
// Results are deduped by parser name.
//
std::vector<ParserEntry>
ParserRegistry::suggestForViolation (const std::string &varName,
                                     const std::string &sinkName,
                                     const std::string &cType) const
{
    std::vector<ParserEntry> results;
    std::set<std::string> seen;

    auto addIfNew = [&] (const ParserEntry &e) {
        if (!e.name.empty () && seen.find (e.name) == seen.end ())
            {
                seen.insert (e.name);
                results.push_back (e);
            }
    };

    // 1. Type match (highest confidence)
    if (!cType.empty ())
        addIfNew (findForType (cType));

    // 2. Sink match
    if (!sinkName.empty ())
        for (const auto &e : findForSink (sinkName))
            addIfNew (e);

    // 3. Variable name heuristic
    if (!varName.empty ())
        addIfNew (findForVarName (varName));

    return results;
}

} // namespace taint
