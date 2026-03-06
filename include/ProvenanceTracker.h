/*----------------------------------------------------------------------
 *
 * Filename: ProvenanceTracker.h
 * Description:
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */
#ifndef PROVENANCE_TRACKER_H
#define PROVENANCE_TRACKER_H

#include "TaintAnalyzer.h"
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace taint
{

//
// Parse Point - Where to Insert Validation
//

struct ParsePoint
{
    std::string functionName;
    unsigned paramIndex;
    std::string paramName;
    TaintLayer currentLevel;  // Current taint level at this point
    TaintLayer requiredLevel; // Required taint level
    std::string reason;       // Why this parse point is needed
    std::string location;     // Source location for insertion

    bool
    operator< (const ParsePoint &other) const
    {
        if (functionName != other.functionName)
            return functionName < other.functionName;
        return paramIndex < other.paramIndex;
    }

    bool
    operator== (const ParsePoint &other) const
    {
        return functionName == other.functionName
               && paramIndex == other.paramIndex;
    }
};

//
// Provenance Tracker - Main Analysis Class
//
//
// This class performs provenance analysis and populates the
// FunctionSummary structures with pass-through/modified info
// and call site bindings.
//

class ProvenanceTracker
{
  public:
    explicit ProvenanceTracker (FunctionDatabase &funcDb);

    // Analyze a function and update its summary with provenance info
    // Returns a FunctionSummary enriched with provenance data
    void analyzeFunction (clang::FunctionDecl *func, clang::ASTContext *context,
                          FunctionSummary &summary);

    // Compute minimal parse points from all analyzed summaries
    std::set<ParsePoint> computeMinimalParsePoints (const std::vector<FunctionSummary> &summaries);

    // Check if a parameter is pass-through (unmodified)
    static bool isPassThrough (const FunctionSummary &summary,
                               unsigned paramIdx);

    // Dump analysis results for a summary
    static void dumpSummary (const FunctionSummary &summary);

  private:
    FunctionDatabase &funcDb_;

    // Current function context during analysis
    clang::FunctionDecl *currentFunc_ = nullptr;
    clang::ASTContext *currentContext_ = nullptr;
    std::map<std::string, unsigned> paramNameToIndex_;
    std::set<unsigned> currentModifiedParams_;

    // Track variable definitions within current function
    std::map<std::string, std::set<unsigned>> varToParamDerivation_;

    // Phase 1: Detect parameter modifications
    void analyzeParameterModifications (FunctionSummary &summary);
    void visitStmtForModifications (const clang::Stmt *stmt);
    void checkAssignmentTarget (const clang::Expr *lhs);
    void checkCallArguments (const clang::CallExpr *call);

    // Phase 2: Analyze call sites and bindings
    void analyzeCallSites (FunctionSummary &summary);
    CallSiteBinding analyzeArgumentSource (const clang::Expr *arg,
                                           const FunctionSummary &summary);

    // Helpers
    bool isExprFromParam (const clang::Expr *expr, unsigned &paramIdx);
    bool isDirectParamRef (const clang::Expr *expr, unsigned &paramIdx);
    std::string getLocation (clang::SourceLocation loc);
    std::string getExprAsString (const clang::Expr *expr);
};

//
// AST Visitor for Provenance Analysis
//

class ProvenanceVisitor : public clang::RecursiveASTVisitor<ProvenanceVisitor>
{
  public:
    explicit ProvenanceVisitor (clang::ASTContext *context,
                                ProvenanceTracker &tracker,
                                std::vector<FunctionSummary> &summaries);

    bool VisitFunctionDecl (clang::FunctionDecl *func);

  private:
    clang::ASTContext *context_;
    ProvenanceTracker &tracker_;
    std::vector<FunctionSummary> &summaries_;
};

//
// Interprocedural Taint Propagator
//

class InterproceduralPropagator
{
  public:
    InterproceduralPropagator (FunctionDatabase &funcDb,
                               std::vector<FunctionSummary> &summaries);

    // Propagate taint levels using provenance information
    // Updates summaries in place with propagated information
    // Returns the set of minimal parse points needed
    std::set<ParsePoint> propagateAndComputeParsePoints ();

  private:
    FunctionDatabase &funcDb_;
    std::vector<FunctionSummary> &summaries_;

    // Taint levels after propagation: (funcName, paramIdx) -> level
    std::map<std::pair<std::string, unsigned>, TaintLayer> propagatedLevels_;

    // Build a map for quick lookup
    std::map<std::string, FunctionSummary *> summaryMap_;

    void buildSummaryMap ();
    void initializeLevels ();
    bool iterateOnce ();
};

} // namespace taint

#endif // PROVENANCE_TRACKER_H
