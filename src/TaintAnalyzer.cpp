/*----------------------------------------------------------------------
 *
 * Filename: TaintAnalyzer.cpp
 * Description:
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 * 08 Mar 26  jpb  A few more comments and cleanup.
 * 09 Mar 26  jpb  Refactoring
 * 10 Mar 26  jpb  Added annotation.
 * 22 Mar 26  jpb  Updating with more C++20 constructs.
 * 05 Apr 26  jpb  Coding mistake; change IgnoreParenCasts -> IgnoreParenImpCasts
 *
 */
#include "TaintAnalyzer.h"
#include "ParserRegistry.h"
#include "StratumAnnotation.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

namespace taint
{

//
// TaintTracker Implementation
//

void TaintTracker::setTaint (const std::string &varName, TaintState state)
{
    taintMap_[varName] = state;
}

TaintState TaintTracker::getTaint (const std::string &varName) const
{
    auto it = taintMap_.find (varName);
    if (it != taintMap_.end ())
        {
            return it->second;
        }
    // Unknown variables are assumed CLEAN (could be conservative: RAW)
    return TaintState (TaintLayer::CLEAN);
}

bool TaintTracker::hasTaint (const std::string &varName) const
{
    return taintMap_.find (varName) != taintMap_.end ();
}

void TaintTracker::propagate (const std::string &dest, const std::string &src)
{
    TaintState srcState = getTaint (src);
    taintMap_[dest] = srcState;
}

void TaintTracker::elevate (const std::string &varName, TaintLayer newLayer,
                            const std::string &parser)
{
    auto it = taintMap_.find (varName);
    if (it != taintMap_.end ())
        {
            if (newLayer > it->second.layer)
                {
                    it->second.layer = newLayer;
                    it->second.lastParser = parser;
                }
        }
    else
        {
            TaintState state (newLayer);
            state.lastParser = parser;
            taintMap_[varName] = state;
        }
}

void TaintTracker::dump () const
{
    llvm::errs () << "=== Taint State ===\n";
    for (const auto &pair : taintMap_)
        {
            llvm::errs () << "  " << pair.first << ": "
                          << layerToString (pair.second.layer);
            if (!pair.second.source.empty ())
                {
                    llvm::errs () << " (source: " << pair.second.source << ")";
                }
            if (!pair.second.lastParser.empty ())
                {
                    llvm::errs ()
                        << " [parsed by: " << pair.second.lastParser << "]";
                }
            llvm::errs () << "\n";
        }
}

void TaintTracker::clear ()
{
    taintMap_.clear ();
}

void TaintTracker::merge (const TaintTracker &other)
{
    // Meet operation: for each variable, take the minimum (most conservative)
    // layer
    for (const auto &pair : other.taintMap_)
        {
            auto it = taintMap_.find (pair.first);
            if (it == taintMap_.end ())
                {
                    // Variable not in this state, add it
                    taintMap_[pair.first] = pair.second;
                }
            else
                {
                    // Take minimum layer (most tainted)
                    if (pair.second.layer < it->second.layer)
                        {
                            it->second = pair.second;
                        }
                }
        }
}

bool TaintTracker::equals (const TaintTracker &other) const
{
    if (taintMap_.size () != other.taintMap_.size ())
        return false;
    for (const auto &pair : taintMap_)
        {
            auto it = other.taintMap_.find (pair.first);
            if (it == other.taintMap_.end ())
                return false;
            if (pair.second.layer != it->second.layer)
                return false;
        }
    return true;
}

//
// FunctionDatabase Implementation
//

FunctionDatabase::FunctionDatabase () { loadBuiltins (); }

void FunctionDatabase::addSummary (const FunctionSummary &summary)
{
    summaries_[summary.name] = summary;
    if (summary.isTaintSource)
        {
            sources_.insert (summary.name);
        }
    if (summary.isTaintSink)
        {
            sinks_.insert (summary.name);
        }
}

std::optional<FunctionSummary>
FunctionDatabase::lookup (const std::string &name) const
{
    auto it = summaries_.find (name);
    if (it != summaries_.end ())
        {
            return it->second;
        }
    return std::nullopt;
}

bool FunctionDatabase::isKnownSource (const std::string &name) const
{
    return sources_.contains (name);
}

bool FunctionDatabase::isKnownSink (const std::string &name) const
{
    return sinks_.contains (name);
}

bool FunctionDatabase::isKnownParser (const std::string &name) const
{
    return parsers_.contains (name);
}

TaintLayer FunctionDatabase::getParserOutputLayer (const std::string &name) const
{
    auto it = parsers_.find (name);
    if (it != parsers_.end ())
        {
            return it->second;
        }
    return TaintLayer::RAW;
}

// Register a parser directly by name and output layer.
// Called by ParserRegistry::registerWithFuncDb().
void FunctionDatabase::registerParser (const std::string &name,
                                       TaintLayer outputLayer)
{
    parsers_[name] = outputLayer;
}

// Builtin catalog helpers
// Construct standard FunctionSummary / ParamSummary records for the most
// common patterns in loadBuiltins().  Each helper fills only the fields
// that differ from the struct defaults so the per-entry code stays compact.
//
// OUT param: index idx becomes RAW after the call (taint source buffer).
static ParamSummary makeOutParam (unsigned idx)
{
    ParamSummary p;
    p.index         = idx;
    p.direction     = ParamDirection::OUT;
    p.requiredLayer = TaintLayer::CLEAN;
    p.outputLayer   = TaintLayer::RAW;
    return p;
}

// IN param for a sink: index idx must meet minReq; treated as consumed.
static ParamSummary makeInParam (unsigned idx, TaintLayer minReq)
{
    ParamSummary p;
    p.index         = idx;
    p.direction     = ParamDirection::IN;
    p.requiredLayer = minReq;
    p.outputLayer   = TaintLayer::CLEAN;
    return p;
}

// IN param for a propagator: index idx passes through unchanged (stays RAW).
static ParamSummary
makePropParam (unsigned idx)
{
    ParamSummary p;
    p.index         = idx;
    p.direction     = ParamDirection::IN;
    p.requiredLayer = TaintLayer::RAW;
    p.outputLayer   = TaintLayer::RAW;
    return p;
}

// Source without an explicit OUT param (return value is the tainted data).
static FunctionSummary
makeSimpleSource (const std::string &name, TaintLayer ret)
{
    FunctionSummary s;
    s.name          = name;
    s.isTaintSource = true;
    s.returnLayer   = ret;
    return s;
}

// Sink without explicit IN params (all args checked by sink-level rule).
static FunctionSummary
makeSimpleSink (const std::string &name, TaintLayer req)
{
    FunctionSummary s;
    s.name            = name;
    s.isTaintSink     = true;
    s.sinkRequirement = req;
    return s;
}

// Propagator: return value inherits taint from param <from>.
static FunctionSummary
makePropagator (const std::string &name, unsigned from = 0)
{
    FunctionSummary s;
    s.name                = name;
    s.returnInherits      = true;
    s.returnInheritSource = from;
    return s;
}
// End helpers

// Load all our built-in sources and sinks.
void FunctionDatabase::loadBuiltins ()
{
    // Taint Sources
    // Sources where an OUT buffer (param N) becomes RAW on return.

    // fread - reads from file into buffer; buffer (param 0) becomes RAW
    {
        FunctionSummary s = makeSimpleSource ("fread", TaintLayer::CLEAN);
        s.params.push_back (makeOutParam (0));
        addSummary (s);
    }

    // fgets - reads line from file; buffer (param 0) becomes RAW
    {
        FunctionSummary s = makeSimpleSource ("fgets", TaintLayer::RAW);
        s.params.push_back (makeOutParam (0));
        addSummary (s);
    }

    // gets - legacy unsafe line read; buffer (param 0) becomes RAW
    {
        FunctionSummary s = makeSimpleSource ("gets", TaintLayer::RAW);
        s.params.push_back (makeOutParam (0));
        addSummary (s);
    }

    // getline - POSIX line read; buffer (param 0) becomes RAW
    {
        FunctionSummary s = makeSimpleSource ("getline", TaintLayer::CLEAN);
        s.params.push_back (makeOutParam (0));
        addSummary (s);
    }

    // read/pread/recv/recvfrom/recvmsg/msgrcv/mq_receive - buffer (param 1) becomes RAW
    for (const char *name : {"read", "pread", "recv", "recvfrom", "recvmsg",
                             "msgrcv", "mq_receive"})
        {
            FunctionSummary s = makeSimpleSource (name, TaintLayer::CLEAN);
            s.params.push_back (makeOutParam (1));
            addSummary (s);
        }

    // getenv/readline - return value is RAW
    { addSummary (makeSimpleSource ("getenv",   TaintLayer::RAW)); }
    { addSummary (makeSimpleSource ("readline", TaintLayer::RAW)); }

    // scanf/fscanf - variadic output args become RAW; return value is count
    { addSummary (makeSimpleSource ("scanf",  TaintLayer::CLEAN)); }
    { addSummary (makeSimpleSource ("fscanf", TaintLayer::CLEAN)); }

    // dlopen/dlsym - dynamic loading; path/symbol is source AND sink requiring SEMANTIC
    {
        FunctionSummary s = makeSimpleSource ("dlopen", TaintLayer::RAW);
        s.isTaintSink     = true;
        s.sinkRequirement = TaintLayer::SEMANTIC;
        s.params.push_back (makeInParam (0, TaintLayer::SEMANTIC));
        addSummary (s);
    }
    {
        FunctionSummary s = makeSimpleSource ("dlsym", TaintLayer::RAW);
        s.isTaintSink     = true;
        s.sinkRequirement = TaintLayer::SEMANTIC;
        s.params.push_back (makeInParam (1, TaintLayer::SEMANTIC));
        addSummary (s);
    }

    // Taint Sinks
    // Sinks require some validation level before data can safely flow in.

    // exec family - all args should be CONTEXTUAL (command execution)
    for (const char *name : {"execve", "execvp", "execv", "execl", "execlp"})
        { addSummary (makeSimpleSink (name, TaintLayer::CONTEXTUAL)); }

    // system/popen - shell execution; command arg (param 0) requires CONTEXTUAL
    {
        FunctionSummary s = makeSimpleSink ("system", TaintLayer::CONTEXTUAL);
        s.params.push_back (makeInParam (0, TaintLayer::CONTEXTUAL));
        addSummary (s);
    }
    {
        FunctionSummary s = makeSimpleSink ("popen", TaintLayer::CONTEXTUAL);
        s.params.push_back (makeInParam (0, TaintLayer::CONTEXTUAL));
        addSummary (s);
    }

    // printf - format string sink; format arg (param 0) must be CONTEXTUAL
    {
        FunctionSummary s = makeSimpleSink ("printf", TaintLayer::CONTEXTUAL);
        s.params.push_back (makeInParam (0, TaintLayer::CONTEXTUAL));
        addSummary (s);
    }

    // fprintf - format string sink; format arg is param 1 (param 0 is FILE*)
    {
        FunctionSummary s = makeSimpleSink ("fprintf", TaintLayer::CONTEXTUAL);
        s.params.push_back (makeInParam (1, TaintLayer::CONTEXTUAL));
        addSummary (s);
    }

    // open/fopen - path injection; path arg (param 0) must be SEMANTIC
    {
        FunctionSummary s = makeSimpleSink ("open", TaintLayer::SEMANTIC);
        s.params.push_back (makeInParam (0, TaintLayer::SEMANTIC));
        addSummary (s);
    }
    {
        FunctionSummary s = makeSimpleSink ("fopen", TaintLayer::SEMANTIC);
        s.params.push_back (makeInParam (0, TaintLayer::SEMANTIC));
        addSummary (s);
    }

    // EVP_DecryptUpdate - inl (param 4) controls buffer writes; requires SEMANTIC
    {
        FunctionSummary s = makeSimpleSink ("EVP_DecryptUpdate", TaintLayer::SEMANTIC);
        s.params.push_back (makeInParam (4, TaintLayer::SEMANTIC));
        addSummary (s);
    }

    // RSA_public_decrypt - flen (param 0) controls input length; requires SEMANTIC
    {
        FunctionSummary s = makeSimpleSink ("RSA_public_decrypt", TaintLayer::SEMANTIC);
        s.params.push_back (makeInParam (0, TaintLayer::SEMANTIC));
        addSummary (s);
    }

    // memset - size (param 2) may be attacker-controlled causing oversized write;
    //          param 0 is not flagged to avoid false positives on normal zeroing.
    {
        FunctionSummary s = makeSimpleSink ("memset", TaintLayer::SEMANTIC);
        s.params.push_back (makeInParam (2, TaintLayer::SEMANTIC));
        addSummary (s);
    }

    // sprintf - format into buffer; format arg (param 1) must be CONTEXTUAL;
    //           dest (param 0) inherits taint from the format string.
    {
        FunctionSummary s = makeSimpleSink ("sprintf", TaintLayer::CONTEXTUAL);
        s.returnLayer = TaintLayer::CLEAN;
        ParamSummary p0 = makeOutParam (0);
        p0.inheritsFromParam = true;
        p0.inheritSource     = 1; // inherits from format string
        s.params.push_back (p0);
        s.params.push_back (makeInParam (1, TaintLayer::CONTEXTUAL));
        addSummary (s);
    }

    // snprintf - bounded format into buffer; same semantics as sprintf.
    //            param 0=dest, param 1=size, param 2=format.
    {
        FunctionSummary s = makeSimpleSink ("snprintf", TaintLayer::CONTEXTUAL);
        s.returnLayer = TaintLayer::CLEAN;
        ParamSummary p0 = makeOutParam (0);
        p0.inheritsFromParam = true;
        p0.inheritSource     = 2; // inherits from format string
        s.params.push_back (p0);
        s.params.push_back (makeInParam (2, TaintLayer::CONTEXTUAL));
        addSummary (s);
    }

    // Propagators (preserve taint, no elevation)
    // memcpy/memmove/strcpy/strncpy/strcat/strncat - propagate src (param 1) -> dest
    for (const char *name : {"memcpy", "memmove", "strcpy", "strncpy",
                             "strcat", "strncat"})
        {
            FunctionSummary s = makePropagator (name);
            s.params.push_back (makePropParam (1));
            addSummary (s);
        }

    // atoi - does NOT validate; propagates taint from param 0 to return value
    { addSummary (makePropagator ("atoi")); }

    // strlen - returns CLEAN (just a count, not the string content)
    {
        FunctionSummary s;
        s.name        = "strlen";
        s.returnLayer = TaintLayer::CLEAN;
        addSummary (s);
    }

    // Sanitizers (elevate taint level)

    // strtol/strtoul/strtoll/sscanf - elevate to SYNTACTIC via type conversion
    for (const char *name : {"strtol", "strtoul", "strtoll", "sscanf"})
        {
            FunctionSummary s;
            s.name        = name;
            s.returnLayer = TaintLayer::SYNTACTIC;
            addSummary (s);
        }

    // inet_pton/inet_aton - IP address validation; elevates to SEMANTIC
    for (const char *name : {"inet_pton", "inet_aton"})
        {
            FunctionSummary s;
            s.name        = name;
            s.returnLayer = TaintLayer::SEMANTIC;
            addSummary (s);
        }

    // Parsers (via ParserRegistry)
    // Add new parsers in ParserRegistry::loadBuiltinParsers(), not here.
    {
        ParserRegistry registry;
        registry.registerWithFuncDb (*this);
    }
}

//
// TaintAnalysisVisitor Implementation
//

TaintAnalysisVisitor::TaintAnalysisVisitor (clang::ASTContext *context,
                                            FunctionDatabase &funcDb)
    : context_ (context), funcDb_ (funcDb)
{
}

std::string TaintAnalysisVisitor::getLocation (clang::SourceLocation loc)
{
    if (loc.isInvalid ())
        return "<unknown>";

    clang::SourceManager &sm = context_->getSourceManager ();
    clang::PresumedLoc ploc = sm.getPresumedLoc (loc);
    if (ploc.isInvalid ())
        return "<unknown>";

    return std::string (ploc.getFilename ()) + ":"
           + std::to_string (ploc.getLine ()) + ":"
           + std::to_string (ploc.getColumn ());
}

std::string TaintAnalysisVisitor::getFilePath (clang::SourceLocation loc)
{
    if (loc.isInvalid ())
        return "<unknown>";

    clang::SourceManager &sm = context_->getSourceManager ();
    clang::PresumedLoc ploc = sm.getPresumedLoc (loc);
    if (ploc.isInvalid ())
        return "<unknown>";

    return std::string (ploc.getFilename ());
}

std::string TaintAnalysisVisitor::getExprAsString (const clang::Expr *expr)
{
    if (!expr)
        return "<null>";

    clang::SourceManager &sm = context_->getSourceManager ();
    clang::SourceRange range = expr->getSourceRange ();

    if (range.isInvalid ())
        return "<invalid>";

    clang::CharSourceRange charRange
        = clang::CharSourceRange::getTokenRange (range);

    return clang::Lexer::getSourceText (charRange, sm, context_->getLangOpts ())
        .str ();
}

bool TaintAnalysisVisitor::VisitFunctionDecl (clang::FunctionDecl *func)
{
    // Forward-declaration hook for stratum: annotations
    //
    // A function declared but not defined in this TU (e.g. a library function)
    // can still carry stratum:validates or stratum:suppress annotations.
    // When we see such a declaration, inject a synthetic FunctionSummary into
    // funcDb_ so the interprocedural propagator treats the function as a known
    // validator without needing its source.
    if (!func->hasBody () || !func->isThisDeclarationADefinition ())
        {
            // Only act if there are stratum: annotations present
            FuncAnnotationResult annots = collectFunctionAnnotations (func);
            if (!annots.validates.empty () || !annots.suppressions.empty ())
                {
                    // Avoid injecting the same declaration twice
                    std::string fname = func->getNameAsString ();
                    if (!funcDb_.lookup (fname))
                        {
                            FunctionSummary synth;
                            synth.name          = fname;
                            synth.qualifiedName = func->getQualifiedNameAsString ();

                            for (auto i = 0u; i < func->getNumParams (); ++i)
                                {
                                    ParamSummary ps;
                                    ps.index          = i;
                                    ps.direction      = ParamDirection::IN;
                                    ps.requiredLayer  = TaintLayer::RAW;
                                    ps.outputLayer    = TaintLayer::RAW;
                                    ps.modStatus      = ParamModStatus::PASS_THROUGH;
                                    synth.params.push_back (ps);
                                }

                            for (const ValidatesAnnotation &va : annots.validates)
                                {
                                    if (va.paramIndex < synth.params.size ())
                                        {
                                            synth.params[va.paramIndex].outputLayer
                                                = va.level;
                                            synth.validatesOverrides[va.paramIndex]
                                                = va.level;
                                            llvm::errs ()
                                                << "[stratum] Synthetic summary "
                                                   "for extern '"
                                                << fname << "' param "
                                                << va.paramIndex << " -> "
                                                << layerToString (va.level)
                                                << "\n";
                                        }
                                }

                            for (const auto &[idx, sa] : annots.suppressions)
                                {
                                    synth.suppressedParams[idx] = sa.reason;
                                }

                            funcDb_.addSummary (synth);
                        }
                }
            return true;
        }

    if (!func->hasBody ())
        return true;
    if (!func->isThisDeclarationADefinition ())
        return true;

    // Skip system headers
    clang::SourceManager &sm = context_->getSourceManager ();
    if (sm.isInSystemHeader (func->getLocation ()))
        return true;

    // Finalize previous function's summary (if any)
    if (currentFunction_ != nullptr)
        {
            finalizeFunctionSummary ();
        }

    currentFunction_ = func;

    // Reset tracking for this function
    paramsFlowingToSinks_.clear ();
    currentSinkRequirement_ = TaintLayer::RAW;
    paramNameToIndex_.clear ();

    llvm::errs () << "\nAnalyzing function: " << func->getNameAsString () << "\n";

    // Mark parameters as RAW (they come from outside) and track their indices
    for (auto i = 0u; i < func->getNumParams (); ++i)
        {
            clang::ParmVarDecl *param = func->getParamDecl (i);
            std::string paramName = param->getNameAsString ();

            // For this proof of concept, treat all params as potentially
            // tainted. A future version will look into check calling context
            TaintState state (TaintLayer::RAW, "parameter");
            tracker_.setTaint (paramName, state);

            // Track param name to index mapping
            paramNameToIndex_[paramName] = i;

            llvm::errs () << "  Parameter '" << paramName << "' marked as RAW\n";
        }

    // Generate initial summary for this function
    FunctionSummary summary;
    summary.name = func->getNameAsString ();
    summary.qualifiedName = func->getQualifiedNameAsString ();
    summary.sourceFile = getFilePath (func->getLocation ());

    for (auto i = 0u; i < func->getNumParams (); ++i)
        {
            ParamSummary ps;
            ps.index = i;
            ps.direction = ParamDirection::IN;  // Default, could be refined
            ps.requiredLayer = TaintLayer::RAW; // Accepts any
            ps.outputLayer = TaintLayer::RAW;
            ps.inheritsFromParam = false;
            summary.params.push_back (ps);
        }

    // Collect stratum: annotations and apply them
    {
        FuncAnnotationResult annots = collectFunctionAnnotations (func);

        // validates: elevate the param's output layer in the summary and
        // update its initial taint in the tracker (treat the param as already
        // validated to the declared level).
        for (const ValidatesAnnotation &va : annots.validates)
            {
                if (va.paramIndex < summary.params.size ())
                    {
                        summary.params[va.paramIndex].outputLayer = va.level;
                        summary.validatesOverrides[va.paramIndex] = va.level;

                        // Elevate the param's current taint so downstream
                        // analysis within this TU sees it as already validated.
                        if (va.paramIndex < func->getNumParams ())
                            {
                                std::string pname = func->getParamDecl (va.paramIndex)
                                                        ->getNameAsString ();
                                tracker_.elevate (pname, va.level,
                                                  "stratum:validates");
                                llvm::errs ()
                                    << "  [stratum] validates: param '"
                                    << pname << "' elevated to "
                                    << layerToString (va.level) << "\n";
                            }
                    }
                else
                    {
                        llvm::errs ()
                            << "  [stratum] Warning: validates() index "
                            << va.paramIndex << " out of range for '"
                            << func->getNameAsString () << "'\n";
                    }
            }

        // suppress: record in the summary so the provenance tracker can
        // mark the parse point rather than silently drop it.
        for (const auto &[idx, sa] : annots.suppressions)
            {
                summary.suppressedParams[idx] = sa.reason;
                llvm::errs () << "  [stratum] suppress: param "
                              << idx << " reason='" << sa.reason << "'\n";
            }
    }

    // Check if this is a parser function (by naming convention for PoC)
    std::string fname = func->getNameAsString ();
    if (fname.find ("parse_") == 0)
        {
            summary.returnLayer = TaintLayer::SYNTACTIC;
        }
    else if (fname.find ("validate_") == 0)
        {
            summary.returnLayer = TaintLayer::SEMANTIC;
        }
    else
        {
            summary.returnLayer = TaintLayer::RAW; // Conservative
            summary.returnInherits = true;
            if (func->getNumParams () > 0)
                {
                    summary.returnInheritSource = 0;
                }
        }

    generatedSummaries_.push_back (summary);

    return true;
}

// Called after function body is fully traversed
void TaintAnalysisVisitor::finalizeFunctionSummary ()
{
    if (generatedSummaries_.empty ())
        return;

    FunctionSummary &summary = generatedSummaries_.back ();

    // Update summary with params that flow to sinks
    for (unsigned idx : paramsFlowingToSinks_)
        {
            summary.paramsFlowToSink.push_back (idx);
        }
    summary.paramSinkRequirement = currentSinkRequirement_;

    if (!paramsFlowingToSinks_.empty ())
        {
            llvm::errs () << "  [Summary] Function '" << summary.name
                          << "' has " << paramsFlowingToSinks_.size ()
                          << " param(s) flowing to sinks\n";
        }
}

void TaintAnalysisVisitor::recordParamFlowsToSink (const std::string &paramName,
                                              TaintLayer required)
{
    auto it = paramNameToIndex_.find (paramName);
    if (it != paramNameToIndex_.end ())
        {
            paramsFlowingToSinks_.insert (it->second);
            // Track the highest requirement
            if (required > currentSinkRequirement_)
                {
                    currentSinkRequirement_ = required;
                }
        }
}

bool TaintAnalysisVisitor::VisitVarDecl (clang::VarDecl *var)
{
    // Skip parameters (handled in VisitFunctionDecl)
    if (llvm::isa<clang::ParmVarDecl> (var))
        return true;

    // Skip if in system header
    clang::SourceManager &sm = context_->getSourceManager ();
    if (sm.isInSystemHeader (var->getLocation ()))
        return true;

    std::string varName = var->getNameAsString ();

    if (var->hasInit ())
        {
            const clang::Expr *init = var->getInit ();
            TaintState initState = analyzeExpr (init);
            tracker_.setTaint (varName, initState);

            llvm::errs () << "  Variable '" << varName << "' initialized with "
                          << layerToString (initState.layer) << " data\n";
        }
    else
        {
            // Uninitialized local - CLEAN until assigned
            tracker_.setTaint (varName, TaintState (TaintLayer::CLEAN));
        }

    return true;
}

TaintState TaintAnalysisVisitor::analyzeExpr (const clang::Expr *expr)
{
    if (!expr)
        return TaintState (TaintLayer::CLEAN);

    expr = expr->IgnoreParenImpCasts ();

    // Literal values are CLEAN
    if (llvm::isa<clang::IntegerLiteral> (expr)
        || llvm::isa<clang::FloatingLiteral> (expr)
        || llvm::isa<clang::StringLiteral> (expr)
        || llvm::isa<clang::CharacterLiteral> (expr))
        {
            return TaintState (TaintLayer::CLEAN, "literal");
        }

    // Variable reference - look up its taint
    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (expr))
        {
            if (const auto *vd
                = llvm::dyn_cast<clang::VarDecl> (dre->getDecl ()))
                {
                    return tracker_.getTaint (vd->getNameAsString ());
                }
        }

    // Function call - check for sources/parsers
    if (const auto *call = llvm::dyn_cast<clang::CallExpr> (expr))
        {
            if (const auto *callee = call->getDirectCallee ())
                {
                    std::string funcName = callee->getNameAsString ();

                    // Check if it's a known source
                    if (funcDb_.isKnownSource (funcName))
                        {
                            return TaintState (TaintLayer::RAW, funcName);
                        }

                    // Check if it's a known parser
                    if (funcDb_.isKnownParser (funcName))
                        {
                            TaintLayer outputLayer
                                = funcDb_.getParserOutputLayer (funcName);
                            return TaintState (outputLayer, funcName);
                        }

                    // Check naming convention for parsers
                    // Prefix patterns: parse_*, validate_*, read_*, decode_*
                    if (funcName.find ("parse_") == 0
                        || funcName.find ("parse") == 0
                        || funcName.find ("read_") == 0
                        || funcName.find ("decode_") == 0
                        || funcName.find ("deserialize_") == 0)
                        {
                            return TaintState (TaintLayer::SYNTACTIC, funcName);
                        }
                    if (funcName.find ("validate_") == 0
                        || funcName.find ("validate") == 0
                        || funcName.find ("check_") == 0
                        || funcName.find ("verify_") == 0)
                        {
                            return TaintState (TaintLayer::SEMANTIC, funcName);
                        }

                    // Infix patterns: *__read*, *__parse*, *_read_*, *_parse_*
                    // Common in projects like mosquitto (packet__read_string)
                    if (funcName.find ("__read") != std::string::npos
                        || funcName.find ("_read_") != std::string::npos
                        || funcName.find ("__parse") != std::string::npos
                        || funcName.find ("_parse_") != std::string::npos
                        || funcName.find ("__decode") != std::string::npos
                        || funcName.find ("_decode_") != std::string::npos)
                        {
                            return TaintState (TaintLayer::SYNTACTIC, funcName);
                        }
                    if (funcName.find ("__validate") != std::string::npos
                        || funcName.find ("_validate_") != std::string::npos
                        || funcName.find ("__check") != std::string::npos
                        || funcName.find ("_check_") != std::string::npos)
                        {
                            return TaintState (TaintLayer::SEMANTIC, funcName);
                        }

                    // Check for summary
                    auto summary = funcDb_.lookup (funcName);
                    if (summary)
                        {
                            if (summary->returnInherits
                                && call->getNumArgs () > 0)
                                {
                                    // Return inherits from argument
                                    unsigned srcIdx
                                        = summary->returnInheritSource;
                                    if (srcIdx < call->getNumArgs ())
                                        {
                                            return analyzeExpr (
                                                call->getArg (srcIdx));
                                        }
                                }
                            return TaintState (summary->returnLayer, funcName);
                        }

                    // Unknown function - conservative: check arguments
                    TaintLayer minLevel = TaintLayer::CLEAN;
                    for (auto i = 0u; i < call->getNumArgs (); ++i)
                        {
                            TaintState argState = analyzeExpr (call->getArg (i));
                            minLevel = minLayer (minLevel, argState.layer);
                        }
                    return TaintState (minLevel, funcName + " (inferred)");
                }
        }

    // Binary operator - combine operand taints
    if (const auto *binOp = llvm::dyn_cast<clang::BinaryOperator> (expr))
        {
            TaintState lhs = analyzeExpr (binOp->getLHS ());
            TaintState rhs = analyzeExpr (binOp->getRHS ());
            TaintLayer combined = minLayer (lhs.layer, rhs.layer);
            return TaintState (combined, "binary operation");
        }

    // Array subscript - combine array and index
    if (const auto *arrSub = llvm::dyn_cast<clang::ArraySubscriptExpr> (expr))
        {
            TaintState base = analyzeExpr (arrSub->getBase ());
            TaintState idx = analyzeExpr (arrSub->getIdx ());

            // Track if RAW data is used as array index (dangerous!)
            if (idx.layer == TaintLayer::RAW && trackRawUsage_)
                {
                    std::string idxStr = getExprAsString (arrSub->getIdx ());
                    std::string loc = getLocation (arrSub->getBeginLoc ());
                    recordRawUsage (idxStr, loc, RawUsageType::ARRAY_INDEX,
                                    "used as array index");
                }

            // Index taint doesn't affect data taint, but base does
            return base;
        }

    // Member access
    if (const auto *member = llvm::dyn_cast<clang::MemberExpr> (expr))
        {
            return analyzeExpr (member->getBase ());
        }

    // sizeof, alignof, __typeof__ - always compile-time constants, always CLEAN
    // regardless of the type or expression operand. This prevents false positives
    // where sizeof(untrusted_ptr) inherits taint from the pointer.
    if (llvm::isa<clang::UnaryExprOrTypeTraitExpr> (expr))
        return TaintState (TaintLayer::CLEAN, "sizeof/alignof");


    // Unary operator
    if (const auto *unOp = llvm::dyn_cast<clang::UnaryOperator> (expr))
        {
            return analyzeExpr (unOp->getSubExpr ());
        }

    // Default: CLEAN (conservative for unknown expressions)
    return TaintState (TaintLayer::CLEAN);
}

bool TaintAnalysisVisitor::VisitBinaryOperator (clang::BinaryOperator *op)
{
    if (!op->isAssignmentOp ())
        return true;

    // Skip system headers
    clang::SourceManager &sm = context_->getSourceManager ();
    if (sm.isInSystemHeader (op->getBeginLoc ()))
        return true;

    const clang::Expr *lhs = op->getLHS ()->IgnoreParenImpCasts ();
    const clang::Expr *rhs = op->getRHS ();

    // Get LHS variable name
    std::string lhsName;
    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (lhs))
        {
            if (const auto *vd
                = llvm::dyn_cast<clang::VarDecl> (dre->getDecl ()))
                {
                    lhsName = vd->getNameAsString ();
                }
        }

    if (lhsName.empty ())
        return true; // Complex LHS, skip for now

    // Analyze RHS
    TaintState rhsState = analyzeExpr (rhs);

    // Simple assignment: propagate taint
    if (op->getOpcode () == clang::BO_Assign)
        {
            tracker_.setTaint (lhsName, rhsState);
            llvm::errs () << "  Assignment: " << lhsName << " = "
                          << getExprAsString (rhs) << " -> "
                          << layerToString (rhsState.layer) << "\n";
        }
    else
        {
            // Compound assignment (+=, etc.): combine with existing
            TaintState lhsState = tracker_.getTaint (lhsName);
            TaintLayer combined = minLayer (lhsState.layer, rhsState.layer);
            tracker_.setTaint (lhsName,
                               TaintState (combined, "compound assignment"));
        }

    return true;
}

bool TaintAnalysisVisitor::VisitCallExpr (clang::CallExpr *call)
{
    // Skip system headers
    clang::SourceManager &sm = context_->getSourceManager ();
    if (sm.isInSystemHeader (call->getBeginLoc ()))
        return true;

    handleFunctionCall (call);
    return true;
}

void TaintAnalysisVisitor::handleFunctionCall (clang::CallExpr *call)
{
    const clang::FunctionDecl *callee = call->getDirectCallee ();
    if (!callee)
        return;

    std::string funcName = callee->getNameAsString ();
    std::string loc = getLocation (call->getBeginLoc ());

    llvm::errs () << "  Call to " << funcName << " at " << loc << "\n";

    // Check if this looks like a parser function (by name heuristics)
    bool isLikelyParser = funcName.find ("__read") != std::string::npos
                          || funcName.find ("_read_") != std::string::npos
                          || funcName.find ("read_") == 0
                          || funcName.find ("__parse") != std::string::npos
                          || funcName.find ("_parse_") != std::string::npos
                          || funcName.find ("parse_") == 0
                          || funcName.find ("__decode") != std::string::npos
                          || funcName.find ("decode_") == 0;

    bool isLikelyValidator
        = funcName.find ("__validate") != std::string::npos
          || funcName.find ("_validate_") != std::string::npos
          || funcName.find ("validate_") == 0
          || funcName.find ("__check") != std::string::npos
          || funcName.find ("check_") == 0 || funcName.find ("verify_") == 0;

    // First, handle OUT/INOUT parameters that get tainted by the call
    auto summary = funcDb_.lookup (funcName);
    if (summary)
        {
            for (const auto &param : summary->params)
                {
                    if ((param.direction == ParamDirection::OUT
                         || param.direction == ParamDirection::INOUT)
                        && param.index < call->getNumArgs ())
                        {

                            // Get the argument expression
                            const clang::Expr *arg = call->getArg (param.index);

                            // Try to get variable name from argument
                            std::string varName;
                            if (const auto *dre
                                = llvm::dyn_cast<clang::DeclRefExpr> (arg->IgnoreParenImpCasts ()))
                                {
                                    if (const auto *vd
                                        = llvm::dyn_cast<clang::VarDecl> (
                                            dre->getDecl ()))
                                        {
                                            varName = vd->getNameAsString ();
                                        }
                                }

                            if (!varName.empty ())
                                {
                                    // Taint the output variable
                                    TaintState newState (param.outputLayer,
                                                         funcName);
                                    tracker_.setTaint (varName, newState);
                                }
                        }
                }
        }
    // Heuristic: For parser-like functions without summaries,
    // detect OUT params by looking for &var or pointer-to-pointer args
    else if (isLikelyParser || isLikelyValidator)
        {
            TaintLayer outputLayer = isLikelyValidator ? TaintLayer::SEMANTIC
                                                       : TaintLayer::SYNTACTIC;

            for (auto i = 0u; i < call->getNumArgs (); ++i)
                {
                    const clang::Expr *arg = call->getArg (i)->IgnoreParenImpCasts ();
                    std::string varName;

                    // Check for &var (address-of operator)
                    if (const auto *unOp
                        = llvm::dyn_cast<clang::UnaryOperator> (arg))
                        {
                            if (unOp->getOpcode () == clang::UO_AddrOf)
                                {
                                    const clang::Expr *sub
                                        = unOp->getSubExpr ()
                                              ->IgnoreParenImpCasts ();
                                    if (const auto *dre
                                        = llvm::dyn_cast<clang::DeclRefExpr> (
                                            sub))
                                        {
                                            if (const auto *vd = llvm::dyn_cast<
                                                    clang::VarDecl> (
                                                    dre->getDecl ()))
                                                {
                                                    varName
                                                        = vd->getNameAsString ();
                                                }
                                        }
                                }
                        }

                    // Check for pointer-to-pointer (like char** for strings)
                    // The variable itself might be passed
                    if (varName.empty ())
                        {
                            if (const auto *dre
                                = llvm::dyn_cast<clang::DeclRefExpr> (arg))
                                {
                                    if (const auto *vd
                                        = llvm::dyn_cast<clang::VarDecl> (
                                            dre->getDecl ()))
                                        {
                                            clang::QualType type
                                                = vd->getType ();
                                            // Check if it's a pointer to
                                            // pointer
                                            if (type->isPointerType ())
                                                {
                                                    clang::QualType pointee
                                                        = type->getPointeeType ();
                                                    if (pointee
                                                            ->isPointerType ())
                                                        {
                                                            varName
                                                                = vd->getNameAsString ();
                                                        }
                                                }
                                        }
                                }
                        }

                    if (!varName.empty ())
                        {
                            llvm::errs ()
                                << "    [Heuristic] OUT param detected: "
                                << varName << " -> "
                                << layerToString (outputLayer) << "\n";
                            tracker_.setTaint (
                                varName,
                                TaintState (outputLayer,
                                            funcName + " (heuristic OUT)"));
                        }
                }
        }

    // Check if it's a sink
    if (funcDb_.isKnownSink (funcName))
        {
            auto sinkSummary = funcDb_.lookup (funcName);
            TaintLayer required = sinkSummary ? sinkSummary->sinkRequirement
                                              : TaintLayer::CONTEXTUAL;

            // Check each argument
            for (auto i = 0u; i < call->getNumArgs (); ++i)
                {
                    TaintState argState = analyzeExpr (call->getArg (i));

                    if (argState.layer < required)
                        {
                            std::string argStr = getExprAsString (call->getArg (i));
                            recordViolation ( loc, argStr, argState.layer, required,
                                "passed to sink function '" + funcName + "'");
                        }
                }
        }

    // Check parameter requirements from summary (reuse the lookup from above)
    if (summary)
        {
            // Check explicit parameter requirements
            for (const auto &param : summary->params)
                {
                    if (param.index < call->getNumArgs ())
                        {
                            TaintState argState
                                = analyzeExpr (call->getArg (param.index));

                            if (param.direction == ParamDirection::IN
                                || param.direction == ParamDirection::INOUT)
                                {
                                    if (argState.layer < param.requiredLayer)
                                        {
                                            std::string argStr
                                                = getExprAsString (
                                                    call->getArg (param.index));
                                            recordViolation (
                                                loc, argStr, argState.layer,
                                                param.requiredLayer,
                                                "passed to '" + funcName
                                                    + "' parameter "
                                                    + std::to_string (
                                                        param.index));
                                        }
                                }
                        }
                }

            // Check if any parameters flow to sinks (cross-file tracking)
            if (!summary->paramsFlowToSink.empty ())
                {
                    TaintLayer required = summary->paramSinkRequirement;
                    for (unsigned paramIdx : summary->paramsFlowToSink)
                        {
                            if (paramIdx < call->getNumArgs ())
                                {
                                    TaintState argState
                                        = analyzeExpr (call->getArg (paramIdx));

                                    if (argState.layer < required)
                                        {
                                            std::string argStr
                                                = getExprAsString (
                                                    call->getArg (paramIdx));
                                            recordViolation (
                                                loc, argStr, argState.layer,
                                                required,
                                                "passed to '" + funcName
                                                    + "' which flows to sink");
                                        }
                                }
                        }
                }
        }

    // Track RAW arguments passed to any function (for --report-raw)
    if (trackRawUsage_)
        {
            for (auto i = 0u; i < call->getNumArgs (); ++i)
                {
                    TaintState argState = analyzeExpr (call->getArg (i));
                    if (argState.layer == TaintLayer::RAW)
                        {
                            std::string argStr = getExprAsString (call->getArg (i));
                            recordRawUsage (argStr, loc, RawUsageType::FUNCTION_ARG,
                                            "passed to '" + funcName + "'");
                        }
                }
        }
}

void TaintAnalysisVisitor::recordViolation (const std::string &loc,
                                       const std::string &var,
                                       TaintLayer actual, TaintLayer required,
                                       const std::string &context)
{
    TaintViolation v;
    v.location = loc;
    v.variable = var;
    v.actualLayer = actual;
    v.requiredLayer = required;
    v.context = context;

    // Generate suggestion based on the gap
    if (actual == TaintLayer::RAW)
        {
            if (required >= TaintLayer::SYNTACTIC)
                {
                    v.suggestion = "Insert syntactic parser before this point";
                }
        }
    else if (actual == TaintLayer::SYNTACTIC)
        {
            if (required >= TaintLayer::SEMANTIC)
                {
                    v.suggestion
                        = "Insert semantic validator before this point";
                }
        }
    else if (actual == TaintLayer::SEMANTIC)
        {
            if (required >= TaintLayer::CONTEXTUAL)
                {
                    v.suggestion
                        = "Insert contextual validator before this point";
                }
        }

    violations_.push_back (v);

    // Also track if this variable is a parameter flowing to a sink
    // This is used for cross-file analysis
    recordParamFlowsToSink (var, required);

    llvm::errs () << "\n*** TAINT VIOLATION ***\n"
                  << "  Location: " << loc << "\n"
                  << "  Variable: " << var << "\n"
                  << "  Actual layer: " << layerToString (actual) << "\n"
                  << "  Required layer: " << layerToString (required) << "\n"
                  << "  Context: " << context << "\n"
                  << "  Suggestion: " << v.suggestion << "\n\n";
}

void TaintAnalysisVisitor::recordRawUsage (const std::string &var,
                                      const std::string &loc, RawUsageType type,
                                      const std::string &context)
{
    if (!trackRawUsage_)
        return;

    // Check if this variable is actually RAW
    TaintState state = tracker_.getTaint (var);
    if (state.layer != TaintLayer::RAW)
        return;

    // Deduplicate by location + variable + type
    for (const auto &existing : rawUsages_)
        {
            if (existing.location == loc && existing.variable == var
                && existing.usageType == type)
                {
                    return; // Already recorded
                }
        }

    RawUsage usage;
    usage.variable = var;
    usage.location = loc;
    usage.function
        = currentFunction_ ? currentFunction_->getNameAsString () : "<unknown>";
    usage.usageType = type;
    usage.usageContext = context;
    usage.suggestedParser = suggestParserForUsage (type, context);

    // Infer type from usage
    switch (type)
        {
        case RawUsageType::ARRAY_INDEX:
            usage.suggestedType = "size_t or bounded integer";
            break;
        case RawUsageType::ARITHMETIC:
            usage.suggestedType = "numeric type";
            break;
        case RawUsageType::STRING_OP:
            usage.suggestedType = "validated string";
            break;
        default:
            usage.suggestedType = "";
            break;
        }

    rawUsages_.push_back (usage);
}

std::string TaintAnalysisVisitor::suggestParserForUsage (RawUsageType type,
                                             const std::string &context)
{
    // Delegate to the registry where possible, using the sink name extracted
    // from context as the lookup key. Fall back to usage-type heuristics for
    // cases the registry does not cover (pointer deref, bare comparison, etc.)
    ParserRegistry registry;

    // Extract a sink name from context if present (e.g. "passed to strlen")
    std::string sinkName;
    for (const auto &candidate : {"atoi", "strtol", "strlen", "strcpy",
                                   "strcat", "printf", "fprintf", "system",
                                   "execve", "malloc", "memcpy"})
        {
            if (context.find (candidate) != std::string::npos)
                {
                    sinkName = candidate;
                    break;
                }
        }

    if (!sinkName.empty ())
        {
            auto entries = registry.findForSink (sinkName);
            if (!entries.empty ())
                return entries[0].name;
        }

    // Usage-type fallbacks for cases without a sink match
    switch (type)
        {
        case RawUsageType::ARRAY_INDEX:
            return registry.findForType ("size_t").name.empty ()
                       ? "langsec_parse_size"
                       : registry.findForType ("size_t").name;
        case RawUsageType::ARITHMETIC:
            if (context.find ("float") != std::string::npos
                || context.find ("double") != std::string::npos)
                return "langsec_parse_double";
            return registry.findForType ("int32_t").name.empty ()
                       ? "langsec_parse_int32"
                       : registry.findForType ("int32_t").name;
        case RawUsageType::STRING_OP:
            return registry.findForType ("const char *").name.empty ()
                       ? "langsec_parse_string"
                       : registry.findForType ("const char *").name;
        case RawUsageType::POINTER_DEREF:
            return "validate pointer/ensure non-null";
        case RawUsageType::COMPARISON:
            return "type-appropriate parser based on comparison";
        default:
            return "";
        }
}

void TaintAnalysisVisitor::dumpState () const
{
    tracker_.dump ();
}

//
// CFG-Based Flow-Sensitive Analysis
//
void TaintAnalysisVisitor::analyzeWithCFG (clang::FunctionDecl *func)
{
    if (!func->hasBody ())
        return;

    // Build CFG for this function
    clang::CFG::BuildOptions buildOpts;
    std::unique_ptr<clang::CFG> cfg
        = clang::CFG::buildCFG (func, func->getBody (), context_, buildOpts);

    if (!cfg)
        {
            llvm::errs () << "  [Warning: Could not build CFG for "
                          << func->getNameAsString () << "]\n";
            return;
        }

    llvm::errs () << "  [CFG Analysis: " << cfg->size () << " blocks]\n";

    // Initialize state for each block
    std::map<const clang::CFGBlock *, TaintTracker> blockInStates;
    std::map<const clang::CFGBlock *, TaintTracker> blockOutStates;

    // Initialize entry block with parameter taint
    const clang::CFGBlock &entry = cfg->getEntry ();
    TaintTracker entryState;
    for (auto i = 0u; i < func->getNumParams (); ++i)
        {
            clang::ParmVarDecl *param = func->getParamDecl (i);
            entryState.setTaint (param->getNameAsString (),
                                 TaintState (TaintLayer::RAW, "parameter"));
        }
    blockOutStates[&entry] = entryState;

    // Worklist-based dataflow analysis
    std::vector<const clang::CFGBlock *> worklist;
    for (const clang::CFGBlock *block : *cfg)
        {
            if (block != &entry)
                {
                    worklist.push_back (block);
                }
        }

    int iterations = 0;
    const int maxIterations = 100; // Prevent infinite loops

    while (!worklist.empty () && iterations < maxIterations)
        {
            iterations++;
            const clang::CFGBlock *block = worklist.back ();
            worklist.pop_back ();

            // Compute IN state by merging OUT states of predecessors
            TaintTracker inState;
            bool first = true;
            for (auto it = block->pred_begin (); it != block->pred_end (); ++it)
                {
                    const clang::CFGBlock *pred = *it;
                    if (pred)
                        {
                            auto outIt = blockOutStates.find (pred);
                            if (outIt != blockOutStates.end ())
                                {
                                    if (first)
                                        {
                                            inState = outIt->second;
                                            first = false;
                                        }
                                    else
                                        {
                                            inState.merge (outIt->second);
                                        }
                                }
                        }
                }

            blockInStates[block] = inState;

            // Compute OUT state by analyzing block statements
            TaintTracker outState = inState;
            analyzeBlock (block, blockOutStates);

            // Check if OUT state changed
            auto oldOutIt = blockOutStates.find (block);
            bool changed = (oldOutIt == blockOutStates.end ())
                           || !outState.equals (oldOutIt->second);

            if (changed)
                {
                    blockOutStates[block] = outState;

                    // Add successors to worklist
                    for (auto it = block->succ_begin ();
                         it != block->succ_end (); ++it)
                        {
                            const clang::CFGBlock *succ = *it;
                            if (succ)
                                {
                                    // Only add if not already in worklist
                                    if (std::find (worklist.begin (),
                                                   worklist.end (), succ)
                                        == worklist.end ())
                                        {
                                            worklist.push_back (succ);
                                        }
                                }
                        }
                }
        }

    if (iterations >= maxIterations)
        {
            llvm::errs () << "  [Warning: CFG analysis did not converge]\n";
        }
    else
        {
            llvm::errs () << "  [CFG Analysis converged in " << iterations
                          << " iterations]\n";
        }

    // Update the tracker with exit state
    const clang::CFGBlock &exit = cfg->getExit ();
    auto exitIt = blockInStates.find (&exit);
    if (exitIt != blockInStates.end ())
        {
            tracker_ = exitIt->second;
        }
}

void TaintAnalysisVisitor::analyzeBlock (
    const clang::CFGBlock *block,
    std::map<const clang::CFGBlock *, TaintTracker> &blockStates)
{

    // Process each element in the block
    for (const clang::CFGElement &elem : *block)
        {
            if (auto stmtElem = elem.getAs<clang::CFGStmt> ())
                {
                    const clang::Stmt *stmt = stmtElem->getStmt ();

                    // Handle assignments
                    if (const auto *binOp
                        = llvm::dyn_cast<clang::BinaryOperator> (stmt))
                        {
                            if (binOp->isAssignmentOp ())
                                {
                                    const clang::Expr *lhs
                                        = binOp->getLHS ()
                                              ->IgnoreParenImpCasts ();
                                    const clang::Expr *rhs = binOp->getRHS ();

                                    if (const auto *dre
                                        = llvm::dyn_cast<clang::DeclRefExpr> (
                                            lhs))
                                        {
                                            if (const auto *vd = llvm::dyn_cast<
                                                    clang::VarDecl> (
                                                    dre->getDecl ()))
                                                {
                                                    TaintState rhsState
                                                        = analyzeExpr (rhs);
                                                    tracker_.setTaint (
                                                        vd->getNameAsString (),
                                                        rhsState);
                                                }
                                        }
                                }
                        }

                    // Handle declarations with initializers
                    if (const auto *ds = llvm::dyn_cast<clang::DeclStmt> (stmt))
                        {
                            for (const clang::Decl *d : ds->decls ())
                                {
                                    if (const auto *vd
                                        = llvm::dyn_cast<clang::VarDecl> (d))
                                        {
                                            if (vd->hasInit ())
                                                {
                                                    TaintState initState
                                                        = analyzeExpr (
                                                            vd->getInit ());
                                                    tracker_.setTaint (
                                                        vd->getNameAsString (),
                                                        initState);
                                                }
                                        }
                                }
                        }

                    // Handle function calls (for sink checking)
                    if (const auto *call
                        = llvm::dyn_cast<clang::CallExpr> (stmt))
                        {
                            handleFunctionCall (
                                const_cast<clang::CallExpr *> (call));
                        }
                }
        }
}

} // namespace taint
