/*----------------------------------------------------------------------
 *
 * Filename: TaintAnalyzer.cpp
 * Description:
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */
#include "TaintAnalyzer.h"
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
            if (static_cast<int> (newLayer)
                > static_cast<int> (it->second.layer))
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
                    if (static_cast<int> (pair.second.layer)
                        < static_cast<int> (it->second.layer))
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

TaintTracker TaintTracker::copy () const
{
    TaintTracker result;
    result.taintMap_ = taintMap_;
    return result;
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
    return sources_.count (name) > 0;
}

bool FunctionDatabase::isKnownSink (const std::string &name) const
{
    return sinks_.count (name) > 0;
}

bool FunctionDatabase::isKnownParser (const std::string &name) const
{
    return parsers_.count (name) > 0;
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

void FunctionDatabase::loadBuiltins ()
{
    // ---- Taint Sources ----

    // fread - reads from file into buffer
    {
        FunctionSummary s;
        s.name = "fread";
        s.isTaintSource = true;
        s.returnLayer = TaintLayer::CLEAN; // returns count
        // The buffer (param 0) becomes RAW
        ParamSummary p0;
        p0.index = 0;
        p0.direction = ParamDirection::OUT;
        p0.requiredLayer = TaintLayer::CLEAN;
        p0.outputLayer = TaintLayer::RAW;
        p0.inheritsFromParam = false;
        p0.inheritSource = 0;
        s.params.push_back (p0);
        addSummary (s);
    }

    // fgets - reads line from file
    {
        FunctionSummary s;
        s.name = "fgets";
        s.isTaintSource = true;
        s.returnLayer = TaintLayer::RAW; // returns the buffer or NULL
        ParamSummary p0;
        p0.index = 0;
        p0.direction = ParamDirection::OUT;
        p0.requiredLayer = TaintLayer::CLEAN;
        p0.outputLayer = TaintLayer::RAW;
        p0.inheritsFromParam = false;
        p0.inheritSource = 0;
        s.params.push_back (p0);
        addSummary (s);
    }

    // getenv - environment variable
    {
        FunctionSummary s;
        s.name = "getenv";
        s.isTaintSource = true;
        s.returnLayer = TaintLayer::RAW;
        addSummary (s);
    }

    // read - POSIX read
    {
        FunctionSummary s;
        s.name = "read";
        s.isTaintSource = true;
        s.returnLayer = TaintLayer::CLEAN; // returns byte count
        ParamSummary p1;
        p1.index = 1;
        p1.direction = ParamDirection::OUT;
        p1.requiredLayer = TaintLayer::CLEAN;
        p1.outputLayer = TaintLayer::RAW;
        p1.inheritsFromParam = false;
        p1.inheritSource = 0;
        s.params.push_back (p1);
        addSummary (s);
    }

    // recv - network receive
    {
        FunctionSummary s;
        s.name = "recv";
        s.isTaintSource = true;
        s.returnLayer = TaintLayer::CLEAN;
        ParamSummary p1;
        p1.index = 1;
        p1.direction = ParamDirection::OUT;
        p1.requiredLayer = TaintLayer::CLEAN;
        p1.outputLayer = TaintLayer::RAW;
        p1.inheritsFromParam = false;
        p1.inheritSource = 0;
        s.params.push_back (p1);
        addSummary (s);
    }

    // ---- Taint Sinks ----

    // system - command execution
    {
        FunctionSummary s;
        s.name = "system";
        s.isTaintSink = true;
        s.sinkRequirement = TaintLayer::CONTEXTUAL;
        ParamSummary p0;
        p0.index = 0;
        p0.direction = ParamDirection::IN;
        p0.requiredLayer = TaintLayer::CONTEXTUAL;
        p0.outputLayer = TaintLayer::CLEAN;
        p0.inheritsFromParam = false;
        p0.inheritSource = 0;
        s.params.push_back (p0);
        addSummary (s);
    }

    // execve - exec family
    {
        FunctionSummary s;
        s.name = "execve";
        s.isTaintSink = true;
        s.sinkRequirement = TaintLayer::CONTEXTUAL;
        addSummary (s);
    }

    // ---- Propagation (no elevation) ----

    // memcpy - propagates taint from src to dest
    {
        FunctionSummary s;
        s.name = "memcpy";
        s.returnInherits = true;
        s.returnInheritSource = 0; // returns dest
        ParamSummary p0;
        p0.index = 0;
        p0.direction = ParamDirection::OUT;
        p0.requiredLayer = TaintLayer::CLEAN;
        p0.outputLayer = TaintLayer::RAW;
        p0.inheritsFromParam = true;
        p0.inheritSource = 1; // inherits from src
        ParamSummary p1;
        p1.index = 1;
        p1.direction = ParamDirection::IN;
        p1.requiredLayer = TaintLayer::RAW;
        p1.outputLayer = TaintLayer::RAW;
        p1.inheritsFromParam = false;
        p1.inheritSource = 0;
        s.params.push_back (p0);
        s.params.push_back (p1);
        addSummary (s);
    }

    // strcpy - propagates taint
    {
        FunctionSummary s;
        s.name = "strcpy";
        s.returnInherits = true;
        s.returnInheritSource = 0;
        ParamSummary p0;
        p0.index = 0;
        p0.direction = ParamDirection::OUT;
        p0.requiredLayer = TaintLayer::CLEAN;
        p0.outputLayer = TaintLayer::RAW;
        p0.inheritsFromParam = true;
        p0.inheritSource = 1;
        ParamSummary p1;
        p1.index = 1;
        p1.direction = ParamDirection::IN;
        p1.requiredLayer = TaintLayer::RAW;
        p1.outputLayer = TaintLayer::RAW;
        p1.inheritsFromParam = false;
        p1.inheritSource = 0;
        s.params.push_back (p0);
        s.params.push_back (p1);
        addSummary (s);
    }

    // strlen - returns CLEAN (just a number)
    {
        FunctionSummary s;
        s.name = "strlen";
        s.returnLayer = TaintLayer::CLEAN;
        addSummary (s);
    }

    // atoi - does NOT validate, propagates taint
    {
        FunctionSummary s;
        s.name = "atoi";
        s.returnInherits = true;
        s.returnInheritSource = 0;
        addSummary (s);
    }

    // ---- Example Parsers (users would add their own) ----

    // For demonstration: functions named parse_* elevate to SYNTACTIC
    // In real use, this would be configured
    parsers_["parse_int"] = TaintLayer::SYNTACTIC;
    parsers_["parse_date"] = TaintLayer::SYNTACTIC;
    parsers_["validate_date"] = TaintLayer::SEMANTIC;
    parsers_["validate_birthdate"] = TaintLayer::CONTEXTUAL;
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
            if (static_cast<int> (required)
                > static_cast<int> (currentSinkRequirement_))
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
                                = llvm::dyn_cast<clang::DeclRefExpr> (
                                    arg->IgnoreParenCasts ()))
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

                    if (static_cast<int> (argState.layer)
                        < static_cast<int> (required))
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
                                    if (static_cast<int> (argState.layer)
                                        < static_cast<int> (
                                            param.requiredLayer))
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

                                    if (static_cast<int> (argState.layer)
                                        < static_cast<int> (required))
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
    switch (type)
        {
        case RawUsageType::ARRAY_INDEX:
            return "langsec_parse_bounded_size (bounds check required)";
        case RawUsageType::ARITHMETIC:
            if (context.find ("float") != std::string::npos
                || context.find ("double") != std::string::npos)
                {
                    return "langsec_parse_double";
                }
            return "langsec_parse_int32 or appropriate integer parser";
        case RawUsageType::POINTER_DEREF:
            return "validate pointer/ensure non-null";
        case RawUsageType::STRING_OP:
            return "langsec_parse_string (length-bounded)";
        case RawUsageType::COMPARISON:
            return "type-appropriate parser based on comparison";
        case RawUsageType::FUNCTION_ARG:
            // Context might tell us more
            if (context.find ("atoi") != std::string::npos
                || context.find ("strtol") != std::string::npos)
                {
                    return "langsec_parse_int32 (replaces unsafe conversion)";
                }
            if (context.find ("strlen") != std::string::npos
                || context.find ("strcpy") != std::string::npos
                || context.find ("strcat") != std::string::npos)
                {
                    return "langsec_parse_string (length-bounded)";
                }
            return ""; // Can't infer
        default:
            return "";
        }
}

void TaintAnalysisVisitor::dumpState () const
{
    tracker_.dump ();
}

//
// TaintAnalysisConsumer Implementation
//

TaintAnalysisConsumer::TaintAnalysisConsumer (clang::ASTContext *context,
                                              FunctionDatabase &funcDb)
    : visitor_ (context, funcDb)
{
}

void TaintAnalysisConsumer::HandleTranslationUnit (clang::ASTContext &context)
{
    visitor_.TraverseDecl (context.getTranslationUnitDecl ());

    // Finalize the last function's summary
    visitor_.finalizeFunctionSummary ();

    llvm::errs () << "\n=== Analysis Complete ===\n";
    visitor_.dumpState ();
}

const std::vector<TaintViolation> &
TaintAnalysisConsumer::getViolations () const
{
    return visitor_.getViolations ();
}

const std::vector<FunctionSummary> &
TaintAnalysisConsumer::getGeneratedSummaries () const
{
    return visitor_.getGeneratedSummaries ();
}

const std::vector<RawUsage> &
TaintAnalysisConsumer::getRawUsages () const
{
    return visitor_.getRawUsages ();
}

void TaintAnalysisConsumer::setTrackRawUsage (bool enabled)
{
    visitor_.setTrackRawUsage (enabled);
}

//
// TaintAnalysisAction Implementation
//

TaintAnalysisAction::TaintAnalysisAction (FunctionDatabase &funcDb)
    : funcDb_ (funcDb)
{
}

std::unique_ptr<clang::ASTConsumer>
TaintAnalysisAction::CreateASTConsumer (clang::CompilerInstance &ci,
                                        llvm::StringRef file)
{
    llvm::errs () << "Analyzing file: " << file << "\n";
    auto consumer = std::make_unique<TaintAnalysisConsumer> (
        &ci.getASTContext (), funcDb_);
    consumer_ = consumer.get ();
    return consumer;
}

void TaintAnalysisAction::EndSourceFileAction ()
{
    if (consumer_)
        {
            violations_ = consumer_->getViolations ();
            generatedSummaries_ = consumer_->getGeneratedSummaries ();
        }
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
                                            inState = outIt->second.copy ();
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
            TaintTracker outState = inState.copy ();
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

//
// TaintAnalysisActionFactory Implementation
//

TaintAnalysisActionFactory::TaintAnalysisActionFactory (
    FunctionDatabase &funcDb)
    : funcDb_ (funcDb)
{
}

std::unique_ptr<clang::FrontendAction>
TaintAnalysisActionFactory::create ()
{
    return std::make_unique<TaintAnalysisAction> (funcDb_);
}

void TaintAnalysisActionFactory::collectResults (TaintAnalysisAction *action)
{
    const auto &violations = action->getViolations ();
    allViolations_.insert (allViolations_.end (), violations.begin (),
                           violations.end ());

    const auto &summaries = action->getGeneratedSummaries ();
    allSummaries_.insert (allSummaries_.end (), summaries.begin (),
                          summaries.end ());
}

} // namespace taint
