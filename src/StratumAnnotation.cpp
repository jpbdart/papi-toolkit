/*----------------------------------------------------------------------
 *
 * Filename: StratumAnnotation.cpp
 * Description: Implementation of STRATUM annotation parsing.
 *              See StratumAnnotation.h for the public interface.
 *
 * Date       Pgm  Comment
 * 11 Mar 26  jpb  Creation.
 *
 */
#include "StratumAnnotation.h"
#include "clang/AST/Attr.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace taint
{

//
// Internal helpers
//

// Trim leading and trailing ASCII whitespace from s.
static std::string
trim(const std::string &s)
{
    auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
        return {};
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

//
// Public: parseTaintLevel
//

std::optional<TaintLayer>
parseTaintLevel(const std::string &token)
{
    std::string t = trim(token);
    // Use a case-insensitive comparison
    std::string upper;
    upper.resize(t.size());
    std::transform(t.begin(), t.end(), upper.begin(),
                   [](unsigned char c) { return std::toupper(c); });

    if (upper == "RAW")         return TaintLayer::RAW;
    if (upper == "SYNTACTIC")   return TaintLayer::SYNTACTIC;
    if (upper == "SEMANTIC")    return TaintLayer::SEMANTIC;
    if (upper == "CONTEXTUAL")  return TaintLayer::CONTEXTUAL;
    if (upper == "CLEAN")       return TaintLayer::CLEAN;
    return std::nullopt;
}

const char *
taintLevelToAnnotationString(TaintLayer layer)
{
    // Re-use the existing layerToString but return uppercase tokens suitable
    // for annotation syntax (they are identical in this implementation).
    return layerToString(layer);
}

//
// Public: parseStratumAnnotation
//

StratumAnnotation
parseStratumAnnotation(const std::string &annotationText)
{
    const std::string prefix = "stratum:";
    if (annotationText.compare(0, prefix.size(), prefix) != 0)
        return std::monostate{};

    // Extract the verb and the parenthesised argument list.
    // Grammar: stratum:<verb>(<args>)
    std::string rest = annotationText.substr(prefix.size());

    auto parenOpen  = rest.find('(');
    auto parenClose = rest.rfind(')');

    if (parenOpen == std::string::npos || parenClose == std::string::npos
        || parenClose < parenOpen)
    {
        llvm::errs() << "[StratumAnnotation] Warning: malformed annotation '"
                     << annotationText << "' (missing parentheses)\n";
        return std::monostate{};
    }

    std::string verb = trim(rest.substr(0, parenOpen));
    std::string args = trim(rest.substr(parenOpen + 1,
                                        parenClose - parenOpen - 1));

    // stratum:validates(N,LEVEL)
    // N is argument, LEVEL is taint validation level
    if (verb == "validates")
    {
        auto comma = args.find(',');
        if (comma == std::string::npos)
        {
            llvm::errs() << "[StratumAnnotation] Warning: validates() "
                            "requires two arguments in '"
                         << annotationText << "'\n";
            return std::monostate{};
        }

        std::string indexStr = trim(args.substr(0, comma));
        std::string levelStr = trim(args.substr(comma + 1));

        // Parse parameter index
        try
        {
            size_t pos = 0;
            long idx = std::stol(indexStr, &pos);
            if (pos != indexStr.size() || idx < 0)
            {
                llvm::errs() << "[StratumAnnotation] Warning: invalid parameter "
                                "index '" << indexStr << "' in '"
                             << annotationText << "'\n";
                return std::monostate{};
            }

            // Parse taint level
            auto level = parseTaintLevel(levelStr);
            if (!level)
            {
                llvm::errs() << "[StratumAnnotation] Warning: unknown taint "
                                "level '" << levelStr << "' in '"
                             << annotationText << "'\n";
                return std::monostate{};
            }

            ValidatesAnnotation va;
            va.paramIndex = static_cast<unsigned>(idx);
            va.level      = *level;
            return va;
        }
        catch (const std::exception &)
        {
            llvm::errs() << "[StratumAnnotation] Warning: could not parse "
                            "validates() arguments in '"
                         << annotationText << "'\n";
            return std::monostate{};
        }
    }

    // stratum:suppress(REASON)
    if (verb == "suppress")
    {
        SuppressAnnotation sa;
        sa.reason = args.empty() ? "suppressed" : args;
        return sa;
    }

    llvm::errs() << "[StratumAnnotation] Warning: unknown stratum verb '"
                 << verb << "' in '" << annotationText << "'\n";
    return std::monostate{};
}

//
// Public: collectFunctionAnnotations
//

FuncAnnotationResult
collectFunctionAnnotations(const clang::FunctionDecl *func)
{
    FuncAnnotationResult result;

    if (!func)
        return result;

    // Annotations on the function declaration itself
    for (const clang::Attr *attr : func->attrs())
    {
        if (const auto *annotate = llvm::dyn_cast<clang::AnnotateAttr>(attr))
        {
            auto parsed = parseStratumAnnotation(
                annotate->getAnnotation().str());

            if (std::holds_alternative<ValidatesAnnotation>(parsed))
            {
                result.validates.push_back(
                    std::get<ValidatesAnnotation>(parsed));
            }
            else if (std::holds_alternative<SuppressAnnotation>(parsed))
            {
                // suppress on the function declaration applies to all
                // parameters — the author is saying "this function as a
                // whole does not consume untrusted input that needs
                // validation" (e.g. an init/teardown function).
                const SuppressAnnotation &sa
                    = std::get<SuppressAnnotation>(parsed);
                for (unsigned i = 0; i < func->getNumParams(); ++i)
                {
                    result.suppressions.emplace_back(i, sa);
                }
            }
        }
    }

    // Annotations on individual parameters
    for (unsigned i = 0; i < func->getNumParams(); ++i)
    {
        const clang::ParmVarDecl *param = func->getParamDecl(i);
        for (const clang::Attr *attr : param->attrs())
        {
            if (const auto *annotate
                    = llvm::dyn_cast<clang::AnnotateAttr>(attr))
            {
                auto parsed = parseStratumAnnotation(
                    annotate->getAnnotation().str());

                if (std::holds_alternative<ValidatesAnnotation>(parsed))
                {
                    // A validates() on a specific parameter: treat the
                    // paramIndex field as relative to this parameter — i.e.,
                    // override the index with i so the author can simply write
                    //   __attribute__((annotate("stratum:validates(0,SEMANTIC)")))
                    // on the parameter declaration and not worry about its
                    // position in the signature.
                    ValidatesAnnotation va
                        = std::get<ValidatesAnnotation>(parsed);
                    va.paramIndex = i;
                    result.validates.push_back(va);
                }
                else if (std::holds_alternative<SuppressAnnotation>(parsed))
                {
                    result.suppressions.emplace_back(
                        i, std::get<SuppressAnnotation>(parsed));
                }
            }
        }
    }

    return result;
}

} // namespace taint
