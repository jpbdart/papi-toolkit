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

// -----------------------------------------------------------------------
// loadBuiltinParsers
//
// Add one block per parser. Group by header to make the catalog readable.
// -----------------------------------------------------------------------
void
ParserRegistry::loadBuiltinParsers ()
{
    // ---- langsec/primitive.h ------------------------------------------

    // 32-bit signed integer. The most common numeric type.
    // Replaces atoi/atol which propagate taint without validation.
    {
        ParserEntry e;
        e.name         = "langsec_parse_int32";
        e.header       = "langsec/primitive.h";
        e.outputLayer  = TaintLayer::SYNTACTIC;
        e.confidence   = FixConfidence::HIGH;
        e.reason       = "Safe integer parse with overflow and format checking";
        e.matchTypes    = {"int32_t", "int"};
        e.matchSinks    = {};
        e.matchVarNames = {"id", "num", "count", "index", "len", "length",
                           "val", "value", "code", "result"};
        registerParser (e);
    }

    // Unsigned 16-bit integer. Natural fit for port numbers and small counts.
    {
        ParserEntry e;
        e.name         = "langsec_parse_uint16";
        e.header       = "langsec/primitive.h";
        e.outputLayer  = TaintLayer::SYNTACTIC;
        e.confidence   = FixConfidence::HIGH;
        e.reason       = "Unsigned 16-bit integer; bounds enforced by type";
        e.matchTypes    = {"uint16_t"};
        e.matchSinks    = {};
        e.matchVarNames = {"port"};
        registerParser (e);
    }

    // size_t. Used for buffer sizes and allocation lengths.
    // Requires SEMANTIC because a syntactically valid size can still be
    // dangerously large; callers must also bounds-check after parsing.
    {
        ParserEntry e;
        e.name         = "langsec_parse_size";
        e.header       = "langsec/primitive.h";
        e.outputLayer  = TaintLayer::SEMANTIC;
        e.confidence   = FixConfidence::HIGH;
        e.reason       = "Bounded size_t; rejects negative and oversized values";
        e.matchTypes    = {"size_t"};
        e.matchSinks    = {"malloc", "calloc", "realloc", "memcpy",
                           "memmove", "memset"};
        e.matchVarNames = {"size", "sz", "len", "length", "nbytes", "buflen"};
        registerParser (e);
    }

    // Boolean. Accepts "0"/"1", "true"/"false", "yes"/"no".
    {
        ParserEntry e;
        e.name         = "langsec_parse_bool";
        e.header       = "langsec/primitive.h";
        e.outputLayer  = TaintLayer::SEMANTIC;
        e.confidence   = FixConfidence::HIGH;
        e.reason       = "Strict boolean; rejects all non-boolean strings";
        e.matchTypes    = {"bool", "_Bool"};
        e.matchSinks    = {};
        e.matchVarNames = {"flag", "enable", "enabled", "active", "toggle"};
        registerParser (e);
    }

    // Length-bounded string. Verifies null termination within max_len.
    // Elevates to SYNTACTIC: the string is well-formed but not yet
    // domain-validated. The most widely applicable parser.
    {
        ParserEntry e;
        e.name         = "langsec_parse_string";
        e.header       = "langsec/primitive.h";
        e.outputLayer  = TaintLayer::SYNTACTIC;
        e.confidence   = FixConfidence::HIGH;
        e.reason       = "Length-bounded string; verifies null termination";
        e.matchTypes    = {"char *", "const char *", "char*", "const char*"};
        e.matchSinks    = {"strlen", "strcpy", "strncpy", "strcat", "strncat",
                           "strcmp", "printf", "fprintf", "sprintf", "snprintf"};
        e.matchVarNames = {"str", "string", "buf", "buffer", "msg", "message",
                           "text", "name", "username", "input", "data"};
        registerParser (e);
    }

    // Whitelist-based string enum. Used when a value must be one of a
    // fixed set. Elevates to CONTEXTUAL because the whitelist check is
    // use-specific. Required before passing strings to shell commands.
    {
        ParserEntry e;
        e.name         = "langsec_parse_string_enum";
        e.header       = "langsec/primitive.h";
        e.outputLayer  = TaintLayer::CONTEXTUAL;
        e.confidence   = FixConfidence::LOW;
        e.reason       = "Shell input must be whitelisted; provide allowed values";
        e.matchTypes    = {};
        e.matchSinks    = {"system", "popen", "execve", "execvp", "execv",
                           "execl", "execlp"};
        e.matchVarNames = {"cmd", "command", "arg", "argv", "shell"};
        registerParser (e);
    }

    // ---- langsec/net.h ------------------------------------------------

    // IPv4 address. Uses inet_pton internally; elevates to SEMANTIC
    // because the value is structurally and domain-valid as an address.
    {
        ParserEntry e;
        e.name         = "langsec_parse_ipv4";
        e.header       = "langsec/net.h";
        e.outputLayer  = TaintLayer::SEMANTIC;
        e.confidence   = FixConfidence::MEDIUM;
        e.reason       = "IPv4 address validation via inet_pton";
        e.matchTypes    = {"struct in_addr", "in_addr_t"};
        e.matchSinks    = {"connect", "bind", "sendto"};
        e.matchVarNames = {"ip", "addr", "address", "host", "ipaddr",
                           "ipv4", "src_ip", "dst_ip", "peer"};
        registerParser (e);
    }

    // Hostname or FQDN. Validates label structure and length limits
    // per RFC 1123. Does not perform DNS lookup.
    {
        ParserEntry e;
        e.name         = "langsec_parse_hostname";
        e.header       = "langsec/net.h";
        e.outputLayer  = TaintLayer::SYNTACTIC;
        e.confidence   = FixConfidence::MEDIUM;
        e.reason       = "Hostname syntax per RFC 1123; no DNS resolution";
        e.matchTypes    = {};
        e.matchSinks    = {"getaddrinfo", "gethostbyname", "connect"};
        e.matchVarNames = {"host", "hostname", "server", "fqdn", "domain"};
        registerParser (e);
    }

    // URL. Validates scheme, authority, and path structure.
    {
        ParserEntry e;
        e.name         = "langsec_parse_url";
        e.header       = "langsec/net.h";
        e.outputLayer  = TaintLayer::SYNTACTIC;
        e.confidence   = FixConfidence::MEDIUM;
        e.reason       = "URL syntax validation (scheme, authority, path)";
        e.matchTypes    = {};
        e.matchSinks    = {"fopen", "open", "curl_easy_setopt"};
        e.matchVarNames = {"url", "uri", "endpoint", "link", "href"};
        registerParser (e);
    }

    // Email address. RFC 5321 syntax check.
    {
        ParserEntry e;
        e.name         = "langsec_parse_email";
        e.header       = "langsec/net.h";
        e.outputLayer  = TaintLayer::SYNTACTIC;
        e.confidence   = FixConfidence::MEDIUM;
        e.reason       = "Email address syntax per RFC 5321";
        e.matchTypes    = {};
        e.matchSinks    = {};
        e.matchVarNames = {"email", "mail", "address", "recipient", "sender"};
        registerParser (e);
    }

    // ---- langsec/path.h -----------------------------------------------

    // Filesystem path. Rejects traversal sequences (../) and null bytes.
    // Elevates to SEMANTIC: structurally safe, but callers must still
    // check permissions and canonicalize before use.
    {
        ParserEntry e;
        e.name         = "langsec_parse_path";
        e.header       = "langsec/path.h";
        e.outputLayer  = TaintLayer::SEMANTIC;
        e.confidence   = FixConfidence::HIGH;
        e.reason       = "Path traversal prevention; rejects ../ and null bytes";
        e.matchTypes    = {};
        e.matchSinks    = {"open", "fopen", "opendir", "unlink", "rename",
                           "stat", "chmod", "chown", "mkdir"};
        e.matchVarNames = {"path", "filename", "file", "dir", "directory",
                           "filepath", "fname", "dirname"};
        registerParser (e);
    }
}

// -----------------------------------------------------------------------
// registerParser
// -----------------------------------------------------------------------
void
ParserRegistry::registerParser (const ParserEntry &entry)
{
    byName_[entry.name] = entry;
    indexEntry (entry);
}

// -----------------------------------------------------------------------
// indexEntry - rebuild inverted indexes for one entry
// -----------------------------------------------------------------------
void
ParserRegistry::indexEntry (const ParserEntry &entry)
{
    for (const auto &t : entry.matchTypes)
        byType_[t] = entry.name;

    for (const auto &s : entry.matchSinks)
        bySink_[s].push_back (entry.name);

    for (const auto &v : entry.matchVarNames)
        byVarName_[v] = entry.name;
}

// -----------------------------------------------------------------------
// FunctionDatabase integration
// -----------------------------------------------------------------------
void
ParserRegistry::registerWithFuncDb (FunctionDatabase &db) const
{
    for (const auto &pair : byName_)
        db.registerParser (pair.second.name, pair.second.outputLayer);
}

// -----------------------------------------------------------------------
// isKnownParser / getOutputLayer
// -----------------------------------------------------------------------
bool
ParserRegistry::isKnownParser (const std::string &name) const
{
    return byName_.count (name) > 0;
}

TaintLayer
ParserRegistry::getOutputLayer (const std::string &name) const
{
    auto it = byName_.find (name);
    if (it != byName_.end ())
        return it->second.outputLayer;
    return TaintLayer::CLEAN;
}

// -----------------------------------------------------------------------
// findForType
// -----------------------------------------------------------------------
ParserEntry
ParserRegistry::findForType (const std::string &cType) const
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

// -----------------------------------------------------------------------
// findForSink
// -----------------------------------------------------------------------
std::vector<ParserEntry>
ParserRegistry::findForSink (const std::string &sinkName) const
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

// -----------------------------------------------------------------------
// findForVarName
// Lowercase the incoming name and scan all registered substrings.
// Returns the first match found; longer substrings are not prioritized
// here — entries are inserted in registration order.
// -----------------------------------------------------------------------
ParserEntry
ParserRegistry::findForVarName (const std::string &varName) const
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

// -----------------------------------------------------------------------
// suggestForViolation
// Priority: type match > sink match > variable name match.
// Results are deduped by parser name.
// -----------------------------------------------------------------------
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
