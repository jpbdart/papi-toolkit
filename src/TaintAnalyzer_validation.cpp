/*----------------------------------------------------------------------
 *
 * Filename: TaintAnalyzer_validation.cpp
 * Description: Enhanced analysis with validation pattern detection
 *
 * This file contains the additions to TaintAnalyzer.cpp to support
 * branch-sensitive taint elevation based on validation patterns.
 *
 * Add this to the TaintAnalysisVisitor class and integrate with existing code.
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */

#include "TaintAnalyzer.h"
#include "ValidationPatterns.h"
#include <stack>

namespace taint
{

//
// Additional State for Branch-Sensitive Analysis
//

// Stack of conditional contexts for branch tracking
struct ConditionalContext
{
    std::vector<ValidationInfo> validations;
    bool inTrueBranch;
    const clang::Stmt *scope; // The if/while/for statement
};

// This would be added to TaintAnalysisVisitor as a member:
// std::stack<ConditionalContext> conditionalStack_;

//
// VisitIfStmt - Detect validation patterns
//

bool
TaintAnalysisVisitor_VisitIfStmt (clang::IfStmt *ifStmt,
                                  clang::ASTContext *context,
                                  TaintTracker &tracker, bool trackRawUsage,
                                  std::vector<RawUsage> &rawUsages)
{

    // Skip system headers
    clang::SourceManager &sm = context->getSourceManager ();
    if (sm.isInSystemHeader (ifStmt->getBeginLoc ()))
        return true;

    // Analyze condition for validation patterns
    std::vector<ValidationInfo> validations
        = analyzeIfForValidation (ifStmt, *context);

    if (!validations.empty ())
        {
            llvm::errs () << "  [Validation] Detected " << validations.size ()
                          << " validation pattern(s) at "
                          << ifStmt->getBeginLoc ().printToString (sm) << ":\n";

            for (const auto &v : validations)
                {
                    llvm::errs ()
                        << "    - " << v.variable << " -> "
                        << layerToString (v.elevatedLevel) << " (" << v.reason
                        << ")"
                        << " [valid in: " << (v.validInTrueBranch ? "then" : "")
                        << (v.validInTrueBranch && v.validInFalseBranch ? "/"
                                                                        : "")
                        << (v.validInFalseBranch ? "else" : "") << "]\n";
                }
        }

    // For flow-sensitive analysis, we would push context and pop after branches
    // For now, we'll use a simpler approach: if the error branch returns,
    // elevate the variable for the rest of the function

    const clang::Stmt *thenStmt = ifStmt->getThen ();
    bool thenReturns = false;

    // Check if 'then' branch returns/exits
    if (const auto *compound = llvm::dyn_cast<clang::CompoundStmt> (thenStmt))
        {
            for (const clang::Stmt *s : compound->body ())
                {
                    if (llvm::isa<clang::ReturnStmt> (s))
                        {
                            thenReturns = true;
                            break;
                        }
                }
        }
    else if (llvm::isa<clang::ReturnStmt> (thenStmt))
        {
            thenReturns = true;
        }

    // If 'then' returns and validation is valid in 'false' branch,
    // we can elevate for rest of function (simplified model)
    for (const auto &v : validations)
        {
            if (thenReturns && v.validInFalseBranch)
                {
                    // Error-check pattern: rc checked, error returns
                    // Variable is valid after the if
                    TaintState current = tracker.getTaint (v.variable);
                    if (static_cast<int> (v.elevatedLevel)
                        > static_cast<int> (current.layer))
                        {
                            tracker.elevate (v.variable, v.elevatedLevel,
                                             v.reason);
                            llvm::errs ()
                                << "    -> Elevated '" << v.variable << "' to "
                                << layerToString (v.elevatedLevel) << "\n";
                        }
                }
        }

    return true;
}

//
// Enhanced analyzeExpr with parser heuristics
//

TaintState
analyzeExprWithHeuristics (const clang::Expr *expr, clang::ASTContext *context,
                           TaintTracker &tracker, FunctionDatabase &funcDb)
{

    if (!expr)
        return TaintState (TaintLayer::CLEAN);

    expr = expr->IgnoreParenImpCasts ();

    // Function call - check for parser patterns
    if (const auto *call = llvm::dyn_cast<clang::CallExpr> (expr))
        {
            if (const auto *callee = call->getDirectCallee ())
                {
                    std::string funcName = callee->getNameAsString ();

                    // Check if it looks like a parser function
                    if (isLikelyParserFunction (funcName))
                        {
                            TaintLayer outputLayer
                                = inferParserOutputLayer (funcName);

                            llvm::errs ()
                                << "  [Heuristic] '" << funcName
                                << "' looks like a parser -> "
                                << layerToString (outputLayer) << "\n";

                            return TaintState (outputLayer,
                                               funcName + " (heuristic)");
                        }
                }
        }

    // Bitmask extraction pattern
    if (const auto *binOp = llvm::dyn_cast<clang::BinaryOperator> (expr))
        {
            // Check for (x & MASK) >> SHIFT pattern
            if (binOp->getOpcode () == clang::BO_Shr)
                {
                    const clang::Expr *lhs
                        = binOp->getLHS ()->IgnoreParenImpCasts ();
                    if (const auto *andOp
                        = llvm::dyn_cast<clang::BinaryOperator> (lhs))
                        {
                            if (andOp->getOpcode () == clang::BO_And)
                                {
                                    // This is a bitmask extraction - result has
                                    // bounded range The layer depends on
                                    // whether the source was validated For now,
                                    // just note this pattern exists
                                    llvm::errs () << "  [Pattern] Bitmask "
                                                     "extraction detected\n";
                                }
                        }
                }
        }

    // Fall through to normal analysis
    return TaintState (TaintLayer::CLEAN); // Placeholder
}

//
// Track assignments preceding error checks
//

struct RecentAssignment
{
    std::string destVar;
    std::string callName;
    std::vector<std::string> outParams; // Variables passed as OUT params
    clang::SourceLocation loc;
};

// This tracks the most recent assignment to catch error-check patterns
// Would be a member of TaintAnalysisVisitor:
// std::optional<RecentAssignment> lastAssignment_;

void
trackAssignmentForErrorCheck (clang::BinaryOperator *op,
                              clang::ASTContext *context,
                              std::optional<RecentAssignment> &lastAssignment)
{

    if (op->getOpcode () != clang::BO_Assign)
        return;

    const clang::Expr *lhs = op->getLHS ()->IgnoreParenImpCasts ();
    const clang::Expr *rhs = op->getRHS ()->IgnoreParenImpCasts ();

    // Get destination variable
    std::string destVar = extractVarName (lhs);
    if (destVar.empty ())
        return;

    // Check if RHS is a function call
    if (const auto *call = llvm::dyn_cast<clang::CallExpr> (rhs))
        {
            if (const auto *callee = call->getDirectCallee ())
                {
                    RecentAssignment ra;
                    ra.destVar = destVar;
                    ra.callName = callee->getNameAsString ();
                    ra.loc = op->getBeginLoc ();

                    // Extract OUT parameter variables
                    for (unsigned i = 0; i < call->getNumArgs (); ++i)
                        {
                            const clang::Expr *arg
                                = call->getArg (i)->IgnoreParenImpCasts ();

                            // Look for &var pattern (address-of, indicating OUT
                            // param)
                            if (const auto *unOp
                                = llvm::dyn_cast<clang::UnaryOperator> (arg))
                                {
                                    if (unOp->getOpcode () == clang::UO_AddrOf)
                                        {
                                            std::string outVar
                                                = extractVarName (
                                                    unOp->getSubExpr ());
                                            if (!outVar.empty ())
                                                {
                                                    ra.outParams.push_back (
                                                        outVar);
                                                }
                                        }
                                }
                        }

                    lastAssignment = ra;

                    llvm::errs () << "  [Track] Assignment: " << destVar
                                  << " = " << ra.callName << "()";
                    if (!ra.outParams.empty ())
                        {
                            llvm::errs () << " [OUT: ";
                            for (size_t i = 0; i < ra.outParams.size (); ++i)
                                {
                                    if (i > 0)
                                        llvm::errs () << ", ";
                                    llvm::errs () << ra.outParams[i];
                                }
                            llvm::errs () << "]";
                        }
                    llvm::errs () << "\n";
                }
        }
}

// When we see an if that checks the return code, elevate the OUT params
void
checkForErrorCheckPattern (
    clang::IfStmt *ifStmt, clang::ASTContext *context, TaintTracker &tracker,
    const std::optional<RecentAssignment> &lastAssignment)
{

    if (!lastAssignment)
        return;

    const clang::Expr *cond = ifStmt->getCond ()->IgnoreParenImpCasts ();

    // Check if condition references the return variable
    std::string condVar;

    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (cond))
        {
            condVar = dre->getDecl ()->getNameAsString ();
        }
    else if (const auto *binOp = llvm::dyn_cast<clang::BinaryOperator> (cond))
        {
            // Handle rc != 0 or rc == 0
            if (binOp->getOpcode () == clang::BO_NE
                || binOp->getOpcode () == clang::BO_EQ)
                {
                    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (
                            binOp->getLHS ()->IgnoreParenImpCasts ()))
                        {
                            condVar = dre->getDecl ()->getNameAsString ();
                        }
                }
        }

    if (condVar != lastAssignment->destVar)
        return;

    // Check if 'then' branch returns (error handling)
    const clang::Stmt *thenStmt = ifStmt->getThen ();
    bool thenReturns = false;

    if (const auto *compound = llvm::dyn_cast<clang::CompoundStmt> (thenStmt))
        {
            for (const clang::Stmt *s : compound->body ())
                {
                    if (llvm::isa<clang::ReturnStmt> (s))
                        {
                            thenReturns = true;
                            break;
                        }
                }
        }
    else if (llvm::isa<clang::ReturnStmt> (thenStmt))
        {
            thenReturns = true;
        }

    if (!thenReturns)
        return;

    // Pattern matched! Elevate OUT params to SYNTACTIC
    llvm::errs () << "  [Pattern] Error-check detected for "
                  << lastAssignment->callName << "()\n";

    // Check if function looks like a parser
    TaintLayer elevation = TaintLayer::SYNTACTIC;
    if (isLikelyParserFunction (lastAssignment->callName))
        {
            elevation = inferParserOutputLayer (lastAssignment->callName);
        }

    for (const auto &outVar : lastAssignment->outParams)
        {
            TaintState current = tracker.getTaint (outVar);
            if (static_cast<int> (elevation) > static_cast<int> (current.layer))
                {
                    tracker.elevate (outVar, elevation,
                                     lastAssignment->callName
                                         + " (error-checked)");
                    llvm::errs () << "    -> Elevated '" << outVar << "' to "
                                  << layerToString (elevation) << "\n";
                }
        }
}

//
// Integration Notes
//

/*
To integrate this into TaintAnalyzer.cpp:

1. Add to TaintAnalysisVisitor class:
   - std::stack<ConditionalContext> conditionalStack_;
   - std::optional<RecentAssignment> lastAssignment_;

2. Add visitor method:
   bool VisitIfStmt(clang::IfStmt* ifStmt) {
       return TaintAnalysisVisitor_VisitIfStmt(
           ifStmt, context_, tracker_, trackRawUsage_, rawUsages_);
   }

3. Modify VisitBinaryOperator to call trackAssignmentForErrorCheck()

4. Call checkForErrorCheckPattern() from VisitIfStmt

5. Update analyzeExpr to use analyzeExprWithHeuristics for function calls

6. Add to TaintAnalyzer.h:
   bool VisitIfStmt(clang::IfStmt* ifStmt);
*/

} // namespace taint
