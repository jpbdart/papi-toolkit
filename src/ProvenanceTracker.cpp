/*----------------------------------------------------------------------
 *
 * Filename: ProvenanceTracker.cpp
 * Description:
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */
#include "ProvenanceTracker.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

#include <algorithm>
#include <fstream>
#include <functional>
#include <queue>

namespace taint
{

//
// ProvenanceTracker Implementation
//

ProvenanceTracker::ProvenanceTracker (FunctionDatabase &funcDb)
    : funcDb_ (funcDb)
{
}

void
ProvenanceTracker::analyzeFunction (clang::FunctionDecl *func,
                                    clang::ASTContext *context,
                                    FunctionSummary &summary)
{
    if (!func->hasBody ())
        return;

    currentFunc_ = func;
    currentContext_ = context;
    currentModifiedParams_.clear ();
    paramNameToIndex_.clear ();
    varToParamDerivation_.clear ();

    for (auto i = 0u; i < func->getNumParams (); ++i)
        {
            clang::ParmVarDecl *param = func->getParamDecl (i);
            std::string paramName = param->getNameAsString ();
            paramNameToIndex_[paramName] = i;
            varToParamDerivation_[paramName].insert (i);

            if (i < summary.params.size ())
                {
                    summary.params[i].name = paramName;
                }
        }

    llvm::errs () << "[Provenance] Analyzing: " << summary.name << "\n";

    analyzeParameterModifications (summary);
    analyzeCallSites (summary);
    summary.rebuildParamSets ();

    for (auto i = 0u; i < summary.params.size (); ++i)
        {
            llvm::errs () << "  Param " << i;
            if (!summary.params[i].name.empty ())
                {
                    llvm::errs () << " (" << summary.params[i].name << ")";
                }
            llvm::errs () << ": "
                          << modStatusToString (summary.params[i].modStatus)
                          << "\n";
        }
}

void ProvenanceTracker::analyzeParameterModifications (FunctionSummary &summary)
{
    visitStmtForModifications (currentFunc_->getBody ());

    for (auto i = 0u; i < summary.params.size (); ++i)
        {
            if (currentModifiedParams_.count (i))
                {
                    summary.params[i].modStatus = ParamModStatus::MODIFIED;
                }
            else
                {
                    summary.params[i].modStatus = ParamModStatus::PASS_THROUGH;
                }
        }
}

void ProvenanceTracker::visitStmtForModifications (const clang::Stmt *stmt)
{
    if (!stmt)
        return;

    if (const auto *compound = llvm::dyn_cast<clang::CompoundStmt> (stmt))
        {
            for (const clang::Stmt *child : compound->body ())
                {
                    visitStmtForModifications (child);
                }
        }
    else if (const auto *ifStmt = llvm::dyn_cast<clang::IfStmt> (stmt))
        {
            visitStmtForModifications (ifStmt->getThen ());
            if (ifStmt->getElse ())
                visitStmtForModifications (ifStmt->getElse ());
        }
    else if (const auto *whileStmt = llvm::dyn_cast<clang::WhileStmt> (stmt))
        {
            visitStmtForModifications (whileStmt->getBody ());
        }
    else if (const auto *forStmt = llvm::dyn_cast<clang::ForStmt> (stmt))
        {
            visitStmtForModifications (forStmt->getBody ());
        }
    else if (const auto *doStmt = llvm::dyn_cast<clang::DoStmt> (stmt))
        {
            visitStmtForModifications (doStmt->getBody ());
        }
    else if (const auto *switchStmt = llvm::dyn_cast<clang::SwitchStmt> (stmt))
        {
            visitStmtForModifications (switchStmt->getBody ());
        }
    else if (const auto *binOp = llvm::dyn_cast<clang::BinaryOperator> (stmt))
        {
            if (binOp->isAssignmentOp () || binOp->isCompoundAssignmentOp ())
                {
                    checkAssignmentTarget (binOp->getLHS ());
                }
        }
    else if (const auto *unOp = llvm::dyn_cast<clang::UnaryOperator> (stmt))
        {
            if (unOp->isIncrementDecrementOp ())
                {
                    checkAssignmentTarget (unOp->getSubExpr ());
                }
        }
    else if (const auto *call = llvm::dyn_cast<clang::CallExpr> (stmt))
        {
            checkCallArguments (call);
        }
    else if (const auto *exprStmt = llvm::dyn_cast<clang::Expr> (stmt))
        {
            for (auto it = exprStmt->child_begin ();
                 it != exprStmt->child_end (); ++it)
                {
                    if (*it)
                        visitStmtForModifications (*it);
                }
        }
}

void ProvenanceTracker::checkAssignmentTarget (const clang::Expr *lhs)
{
    if (!lhs)
        return;
    lhs = lhs->IgnoreParenImpCasts ();

    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (lhs))
        {
            if (const auto *vd
                = llvm::dyn_cast<clang::VarDecl> (dre->getDecl ()))
                {
                    auto it = paramNameToIndex_.find (vd->getNameAsString ());
                    if (it != paramNameToIndex_.end ())
                        {
                            currentModifiedParams_.insert (it->second);
                        }
                }
        }

    if (const auto *unOp = llvm::dyn_cast<clang::UnaryOperator> (lhs))
        {
            if (unOp->getOpcode () == clang::UO_Deref)
                {
                    unsigned paramIdx;
                    if (isExprFromParam (
                            unOp->getSubExpr ()->IgnoreParenImpCasts (),
                            paramIdx))
                        {
                            currentModifiedParams_.insert (paramIdx);
                        }
                }
        }

    if (const auto *arrSub = llvm::dyn_cast<clang::ArraySubscriptExpr> (lhs))
        {
            unsigned paramIdx;
            if (isExprFromParam (arrSub->getBase ()->IgnoreParenImpCasts (),
                                 paramIdx))
                {
                    currentModifiedParams_.insert (paramIdx);
                }
        }

    if (const auto *member = llvm::dyn_cast<clang::MemberExpr> (lhs))
        {
            unsigned paramIdx;
            if (isExprFromParam (member->getBase ()->IgnoreParenImpCasts (),
                                 paramIdx))
                {
                    currentModifiedParams_.insert (paramIdx);
                }
        }
}

void ProvenanceTracker::checkCallArguments (const clang::CallExpr *call)
{
    if (!call)
        return;
    const clang::FunctionDecl *callee = call->getDirectCallee ();
    if (!callee)
        return;

    std::string calleeName = callee->getNameAsString ();

    auto summary = funcDb_.lookup (calleeName);
    if (summary)
        {
            for (const auto &param : summary->params)
                {
                    if ((param.direction == ParamDirection::OUT
                         || param.direction == ParamDirection::INOUT)
                        && param.index < call->getNumArgs ())
                        {

                            const clang::Expr *arg = call->getArg (param.index);
                            unsigned paramIdx;

                            if (isExprFromParam (arg->IgnoreParenImpCasts (),
                                                 paramIdx))
                                {
                                    currentModifiedParams_.insert (paramIdx);
                                }

                            if (const auto *unOp
                                = llvm::dyn_cast<clang::UnaryOperator> (
                                    arg->IgnoreParenImpCasts ()))
                                {
                                    if (unOp->getOpcode () == clang::UO_AddrOf)
                                        {
                                            if (isExprFromParam (
                                                    unOp->getSubExpr (),
                                                    paramIdx))
                                                {
                                                    currentModifiedParams_
                                                        .insert (paramIdx);
                                                }
                                        }
                                }
                        }
                }
        }

    static const std::set<std::string> modifyingFuncs
        = { "memcpy",  "strcpy",   "strncpy", "memmove", "memset",
            "sprintf", "snprintf", "sscanf",  "fgets",   "fread",
            "gets",    "read",     "recv",    "recvfrom" };

    if (modifyingFuncs.count (calleeName) && call->getNumArgs () > 0)
        {
            unsigned paramIdx;
            if (isExprFromParam (call->getArg (0)->IgnoreParenImpCasts (),
                                 paramIdx))
                {
                    currentModifiedParams_.insert (paramIdx);
                }
        }
}

void ProvenanceTracker::analyzeCallSites (FunctionSummary &summary)
{
    std::function<void (const clang::Stmt *)> findCalls =
        [&] (const clang::Stmt *stmt) {
            if (!stmt)
                return;

            if (const auto *call = llvm::dyn_cast<clang::CallExpr> (stmt))
                {
                    if (const clang::FunctionDecl *callee
                        = call->getDirectCallee ())
                        {
                            CallSiteRecord csRecord;
                            csRecord.calleeName = callee->getNameAsString ();
                            csRecord.location
                                = getLocation (call->getBeginLoc ());

                            for (unsigned i = 0; i < call->getNumArgs (); ++i)
                                {
                                    CallSiteBinding binding
                                        = analyzeArgumentSource (
                                            call->getArg (i), summary);
                                    binding.argIndex = i;
                                    csRecord.bindings.push_back (binding);
                                }

                            summary.callSites.push_back (csRecord);
                        }
                }

            for (auto it = stmt->child_begin (); it != stmt->child_end (); ++it)
                {
                    findCalls (*it);
                }
        };

    findCalls (currentFunc_->getBody ());
}

CallSiteBinding ProvenanceTracker::analyzeArgumentSource (const clang::Expr *arg,
                                          const FunctionSummary &summary)
{

    CallSiteBinding binding;
    if (!arg)
        return binding;
    arg = arg->IgnoreParenImpCasts ();

    unsigned paramIdx;
    if (isDirectParamRef (arg, paramIdx))
        {
            binding.fromCallerParam = true;
            binding.callerParamIndex = paramIdx;
            binding.isDirectPassThrough
                = (currentModifiedParams_.count (paramIdx) == 0);
            if (paramIdx < summary.params.size ())
                {
                    binding.sourceName = summary.params[paramIdx].name;
                }
            return binding;
        }

    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (arg))
        {
            if (const auto *vd
                = llvm::dyn_cast<clang::VarDecl> (dre->getDecl ()))
                {
                    binding.sourceName = vd->getNameAsString ();
                }
        }

    return binding;
}

bool ProvenanceTracker::isExprFromParam (const clang::Expr *expr, unsigned &paramIdx)
{
    if (!expr)
        return false;
    expr = expr->IgnoreParenImpCasts ();

    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (expr))
        {
            if (const auto *vd
                = llvm::dyn_cast<clang::VarDecl> (dre->getDecl ()))
                {
                    auto it = paramNameToIndex_.find (vd->getNameAsString ());
                    if (it != paramNameToIndex_.end ())
                        {
                            paramIdx = it->second;
                            return true;
                        }
                    auto derivIt
                        = varToParamDerivation_.find (vd->getNameAsString ());
                    if (derivIt != varToParamDerivation_.end ()
                        && !derivIt->second.empty ())
                        {
                            paramIdx = *derivIt->second.begin ();
                            return true;
                        }
                }
        }
    return false;
}

bool ProvenanceTracker::isDirectParamRef (const clang::Expr *expr,
                                     unsigned &paramIdx)
{
    if (!expr)
        return false;
    expr = expr->IgnoreParenImpCasts ();

    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (expr))
        {
            if (const auto *pd
                = llvm::dyn_cast<clang::ParmVarDecl> (dre->getDecl ()))
                {
                    auto it = paramNameToIndex_.find (pd->getNameAsString ());
                    if (it != paramNameToIndex_.end ())
                        {
                            paramIdx = it->second;
                            return true;
                        }
                }
        }
    return false;
}

std::set<ParsePoint> ProvenanceTracker::computeMinimalParsePoints (
    const std::vector<FunctionSummary> &summaries)
{

    std::set<ParsePoint> parsePoints;
    llvm::errs () << "\n[Provenance] Computing minimal parse points...\n";

    for (const FunctionSummary &summary : summaries)
        {
            for (const CallSiteRecord &cs : summary.callSites)
                {
                    auto calleeSummary = funcDb_.lookup (cs.calleeName);
                    if (!calleeSummary)
                        continue;

                    for (unsigned i = 0; i < cs.bindings.size (); ++i)
                        {
                            const CallSiteBinding &binding = cs.bindings[i];

                            TaintLayer requiredLevel = TaintLayer::RAW;
                            if (calleeSummary->isTaintSink)
                                {
                                    requiredLevel
                                        = calleeSummary->sinkRequirement;
                                }
                            else if (i < calleeSummary->params.size ())
                                {
                                    requiredLevel = calleeSummary->params[i]
                                                        .requiredLayer;
                                }

                            if (requiredLevel <= TaintLayer::RAW)
                                continue;

                            if (binding.fromCallerParam
                                && !binding.isDirectPassThrough)
                                {
                                    ParsePoint pp;
                                    pp.functionName = summary.name;
                                    pp.paramIndex = binding.callerParamIndex;
                                    pp.paramName = binding.sourceName;
                                    pp.currentLevel = TaintLayer::RAW;
                                    pp.requiredLevel = requiredLevel;
                                    pp.reason = "Modified before passing to "
                                                + cs.calleeName;
                                    pp.location = cs.location;
                                    parsePoints.insert (pp);
                                }
                        }
                }

            for (unsigned paramIdx : summary.paramsFlowToSink)
                {
                    if (summary.modifiedParams.count (paramIdx))
                        {
                            ParsePoint pp;
                            pp.functionName = summary.name;
                            pp.paramIndex = paramIdx;
                            if (paramIdx < summary.params.size ())
                                pp.paramName = summary.params[paramIdx].name;
                            pp.currentLevel = TaintLayer::RAW;
                            pp.requiredLevel = summary.paramSinkRequirement;
                            pp.reason = "Modified parameter flows to sink";
                            parsePoints.insert (pp);
                        }
                }
        }

    llvm::errs () << "[Provenance] Found " << parsePoints.size () << " parse point(s)\n";
    return parsePoints;
}

bool
ProvenanceTracker::isPassThrough (const FunctionSummary &summary,
                                  unsigned paramIdx)
{
    return summary.passThroughParams.count (paramIdx) > 0;
}

void
ProvenanceTracker::dumpSummary (const FunctionSummary &summary)
{
    llvm::errs () << "\nFunction: " << summary.name << "\n  Parameters:\n";
    for (const auto &param : summary.params)
        {
            llvm::errs () << "    [" << param.index << "] ";
            if (!param.name.empty ())
                llvm::errs () << param.name << ": ";
            llvm::errs () << modStatusToString (param.modStatus);
            if (summary.passThroughParams.count (param.index))
                llvm::errs () << " (PASS-THROUGH)";
            llvm::errs () << "\n";
        }
    if (!summary.callSites.empty ())
        {
            llvm::errs () << "  Call Sites:\n";
            for (const auto &cs : summary.callSites)
                {
                    llvm::errs () << "    -> " << cs.calleeName << " at "
                                  << cs.location << "\n";
                    for (const auto &b : cs.bindings)
                        {
                            llvm::errs ()
                                << "       Arg " << b.argIndex << ": ";
                            if (b.fromCallerParam)
                                {
                                    llvm::errs ()
                                        << "from param " << b.callerParamIndex;
                                    if (b.isDirectPassThrough)
                                        llvm::errs ()
                                            << " (direct pass-through)";
                                }
                            else if (!b.sourceName.empty ())
                                {
                                    llvm::errs () << "from local '"
                                                  << b.sourceName << "'";
                                }
                            else
                                {
                                    llvm::errs () << "expression";
                                }
                            llvm::errs () << "\n";
                        }
                }
        }
}

std::string
ProvenanceTracker::getLocation (clang::SourceLocation loc)
{
    if (!currentContext_)
        return "<unknown>";
    clang::SourceManager &sm = currentContext_->getSourceManager ();
    clang::PresumedLoc ploc = sm.getPresumedLoc (loc);
    if (ploc.isInvalid ())
        return "<invalid>";
    return std::string (ploc.getFilename ()) + ":"
           + std::to_string (ploc.getLine ()) + ":"
           + std::to_string (ploc.getColumn ());
}

std::string
ProvenanceTracker::getExprAsString (const clang::Expr *expr)
{
    if (!expr || !currentContext_)
        return "<null>";
    clang::SourceManager &sm = currentContext_->getSourceManager ();
    clang::SourceRange range = expr->getSourceRange ();
    if (range.isInvalid ())
        return "<invalid>";
    return clang::Lexer::getSourceText (
               clang::CharSourceRange::getTokenRange (range), sm,
               currentContext_->getLangOpts ())
        .str ();
}

//
// ProvenanceVisitor Implementation
//

ProvenanceVisitor::ProvenanceVisitor (clang::ASTContext *context,
                                      ProvenanceTracker &tracker,
                                      std::vector<FunctionSummary> &summaries)
    : context_ (context), tracker_ (tracker), summaries_ (summaries)
{
}

bool
ProvenanceVisitor::VisitFunctionDecl (clang::FunctionDecl *func)
{
    if (!func->hasBody () || !func->isThisDeclarationADefinition ())
        return true;
    clang::SourceManager &sm = context_->getSourceManager ();
    if (sm.isInSystemHeader (func->getLocation ()))
        return true;

    std::string funcName = func->getNameAsString ();
    for (FunctionSummary &summary : summaries_)
        {
            if (summary.name == funcName)
                {
                    tracker_.analyzeFunction (func, context_, summary);
                    break;
                }
        }
    return true;
}

//
// InterproceduralPropagator Implementation
//

InterproceduralPropagator::InterproceduralPropagator (
    FunctionDatabase &funcDb, std::vector<FunctionSummary> &summaries)
    : funcDb_ (funcDb), summaries_ (summaries)
{
    buildSummaryMap ();
}

void
InterproceduralPropagator::buildSummaryMap ()
{
    for (FunctionSummary &s : summaries_)
        {
            summaryMap_[s.name] = &s;
        }
}

std::set<ParsePoint>
InterproceduralPropagator::propagateAndComputeParsePoints ()
{
    std::set<ParsePoint> parsePoints;
    initializeLevels ();

    int iterations = 0;
    while (iterations < 100 && iterateOnce ())
        iterations++;
    llvm::errs () << "[Interprocedural] Converged in " << iterations
                  << " iterations\n";

    for (FunctionSummary &summary : summaries_)
        {
            for (unsigned paramIdx : summary.paramsFlowToSink)
                {
                    auto key = std::make_pair (summary.name, paramIdx);
                    TaintLayer currentLevel = TaintLayer::RAW;
                    auto it = propagatedLevels_.find (key);
                    if (it != propagatedLevels_.end ())
                        currentLevel = it->second;

                    if (static_cast<int> (currentLevel)
                        < static_cast<int> (summary.paramSinkRequirement))
                        {
                            if (summary.modifiedParams.count (paramIdx))
                                {
                                    ParsePoint pp;
                                    pp.functionName = summary.name;
                                    pp.paramIndex = paramIdx;
                                    if (paramIdx < summary.params.size ())
                                        pp.paramName
                                            = summary.params[paramIdx].name;
                                    pp.currentLevel = currentLevel;
                                    pp.requiredLevel
                                        = summary.paramSinkRequirement;
                                    pp.reason = "Parameter flows to sink and "
                                                "is modified";
                                    parsePoints.insert (pp);
                                }
                        }
                }
        }
    return parsePoints;
}

void
InterproceduralPropagator::initializeLevels ()
{
    for (const FunctionSummary &summary : summaries_)
        {
            for (unsigned i = 0; i < summary.params.size (); ++i)
                {
                    propagatedLevels_[{ summary.name, i }] = TaintLayer::RAW;
                }
        }
}

bool
InterproceduralPropagator::iterateOnce ()
{
    bool changed = false;
    for (const FunctionSummary &summary : summaries_)
        {
            for (const CallSiteRecord &cs : summary.callSites)
                {
                    for (const CallSiteBinding &binding : cs.bindings)
                        {
                            if (binding.fromCallerParam
                                && binding.isDirectPassThrough)
                                {
                                    auto callerKey = std::make_pair (
                                        summary.name, binding.callerParamIndex);
                                    auto calleeKey = std::make_pair (
                                        cs.calleeName, binding.argIndex);

                                    auto callerIt
                                        = propagatedLevels_.find (callerKey);
                                    if (callerIt != propagatedLevels_.end ())
                                        {
                                            auto calleeIt
                                                = propagatedLevels_.find (
                                                    calleeKey);
                                            if (calleeIt
                                                != propagatedLevels_.end ())
                                                {
                                                    if (static_cast<int> (
                                                            callerIt->second)
                                                        > static_cast<int> (
                                                            calleeIt->second))
                                                        {
                                                            calleeIt->second
                                                                = callerIt
                                                                      ->second;
                                                            changed = true;
                                                        }
                                                }
                                        }
                                }
                        }
                }
        }
    return changed;
}

} // namespace taint
