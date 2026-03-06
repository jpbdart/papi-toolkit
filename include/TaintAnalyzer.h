/*----------------------------------------------------------------------
 *
 * Filename: TaintAnalyzer.h
 * Description:
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */
#ifndef TAINT_ANALYZER_H
#define TAINT_ANALYZER_H

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/CFG.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/raw_ostream.h"

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace taint
{

//
// Taint Layer Definitions
//

enum class TaintLayer
{
    RAW = 0,        // Unparsed, untrusted input
    SYNTACTIC = 1,  // Structure validated
    SEMANTIC = 2,   // Domain meaning validated
    CONTEXTUAL = 3, // Use-specific constraints validated
    CLEAN = 4       // Not tainted (e.g., literals, computed lengths)
};

inline const char *
layerToString (TaintLayer layer)
{
    switch (layer)
        {
        case TaintLayer::RAW:
            return "RAW";
        case TaintLayer::SYNTACTIC:
            return "SYNTACTIC";
        case TaintLayer::SEMANTIC:
            return "SEMANTIC";
        case TaintLayer::CONTEXTUAL:
            return "CONTEXTUAL";
        case TaintLayer::CLEAN:
            return "CLEAN";
        }
    return "UNKNOWN";
}

inline TaintLayer
minLayer (TaintLayer a, TaintLayer b)
{
    return static_cast<TaintLayer> (
        std::min (static_cast<int> (a), static_cast<int> (b)));
}

//
// Taint State for Variables
//

struct TaintState
{
    TaintLayer layer = TaintLayer::CLEAN;
    std::string source;     // Where the taint originated
    std::string lastParser; // Last parser applied (if any)

    //TaintState () {}
    //TaintState (TaintLayer l, const std::string &src = "")
    //    : layer (l), source (src), lastParser ("")
    TaintState() = default;
    TaintState (TaintLayer l, const std::string &src = "")
        : layer (l), source (src)
    {
    }
};

//
// Function Summary for Cross-File Analysis
//

enum class ParamDirection
{
    IN,
    OUT,
    INOUT
};

// Provenance: how a parameter is used in a function
enum class ParamModStatus
{
    UNKNOWN,      // Not yet analyzed
    PASS_THROUGH, // Parameter is not modified; inherits caller's taint
    MODIFIED      // Parameter is modified; needs fresh validation
};

inline const char *
modStatusToString (ParamModStatus status)
{
    switch (status)
        {
        case ParamModStatus::UNKNOWN:
            return "UNKNOWN";
        case ParamModStatus::PASS_THROUGH:
            return "PASS_THROUGH";
        case ParamModStatus::MODIFIED:
            return "MODIFIED";
        }
    return "UNKNOWN";
}

struct ParamSummary
{
    unsigned index;
    std::string name; // Parameter name (for diagnostics)
    ParamDirection direction;
    TaintLayer requiredLayer; // Minimum layer required for input
    TaintLayer outputLayer;   // Layer after function returns (for OUT/INOUT)
    bool inheritsFromParam;   // If true, outputLayer comes from another param
    unsigned inheritSource;   // Which param to inherit from

    // Provenance tracking
    ParamModStatus modStatus; // Whether param is modified in function body

    ParamSummary ()
        : index (0), direction (ParamDirection::IN),
          requiredLayer (TaintLayer::RAW), outputLayer (TaintLayer::RAW),
          inheritsFromParam (false), inheritSource (0),
          modStatus (ParamModStatus::UNKNOWN)
    {
    }
};

// Call site argument binding - tracks data flow at call sites
struct CallSiteBinding
{
    unsigned argIndex;         // Which argument position
    bool fromCallerParam;      // Is this from a caller parameter?
    unsigned callerParamIndex; // If so, which one?
    bool isDirectPassThrough;  // Passed without modification?
    std::string sourceName;    // Name for diagnostics

    CallSiteBinding ()
        : argIndex (0), fromCallerParam (false), callerParamIndex (0),
          isDirectPassThrough (false)
    {
    }
};

// Call site within a function
struct CallSiteRecord
{
    std::string calleeName;
    std::string location;
    std::vector<CallSiteBinding> bindings;
};

struct FunctionSummary
{
    std::string name;
    std::string qualifiedName;
    std::vector<ParamSummary> params;
    TaintLayer returnLayer;
    bool returnInherits; // Return layer inherits from a param
    unsigned returnInheritSource;
    bool isTaintSource;         // Function introduces RAW data (e.g., fread)
    bool isTaintSink;           // Function is security-sensitive
    TaintLayer sinkRequirement; // Required layer at sink
    std::string sourceFile;

    // Cross-file tracking: which params flow to sinks
    std::vector<unsigned>
        paramsFlowToSink;            // Indices of params that reach sinks
    TaintLayer paramSinkRequirement; // Required layer for those params

    // Provenance: call sites within this function
    std::vector<CallSiteRecord> callSites;

    // Quick lookup sets (populated from params)
    std::set<unsigned> passThroughParams; // Params that are pass-through
    std::set<unsigned> modifiedParams;    // Params that are modified

    FunctionSummary ()
        : returnLayer (TaintLayer::CLEAN), returnInherits (false),
          returnInheritSource (0), isTaintSource (false), isTaintSink (false),
          sinkRequirement (TaintLayer::RAW),
          paramSinkRequirement (TaintLayer::RAW)
    {
    }

    // Helper to rebuild lookup sets from params
    void
    rebuildParamSets ()
    {
        passThroughParams.clear ();
        modifiedParams.clear ();
        for (const auto &p : params)
            {
                if (p.modStatus == ParamModStatus::PASS_THROUGH)
                    {
                        passThroughParams.insert (p.index);
                    }
                else if (p.modStatus == ParamModStatus::MODIFIED)
                    {
                        modifiedParams.insert (p.index);
                    }
            }
    }
};

//
// Taint Violation Report
//

struct TaintViolation
{
    std::string location;
    std::string variable;
    TaintLayer actualLayer;
    TaintLayer requiredLayer;
    std::string context;    // e.g., "passed to sink function X"
    std::string suggestion; // e.g., "insert parser Y before this point"
};

//
// RAW Usage Tracking (for --report-raw)
//

enum class RawUsageType
{
    ARRAY_INDEX,   // Used as array subscript
    POINTER_DEREF, // Dereferenced
    ARITHMETIC,    // Used in arithmetic operation
    COMPARISON,    // Used in comparison
    FUNCTION_ARG,  // Passed to function
    STRING_OP,     // Used in string operation
    CONTROL_FLOW,  // Used in if/while/for condition
    ASSIGNMENT,    // Assigned to another variable
    RETURN_VALUE,  // Returned from function
    OTHER          // Other usage
};

struct RawUsage
{
    std::string variable;
    std::string location;
    std::string function; // Function where usage occurs
    RawUsageType usageType;
    std::string usageContext;    // Human-readable context
    std::string suggestedParser; // Parser suggestion if we can infer one
    std::string suggestedType;   // Inferred type if known
};

inline const char *
rawUsageTypeToString (RawUsageType type)
{
    switch (type)
        {
        case RawUsageType::ARRAY_INDEX:
            return "array index";
        case RawUsageType::POINTER_DEREF:
            return "pointer dereference";
        case RawUsageType::ARITHMETIC:
            return "arithmetic";
        case RawUsageType::COMPARISON:
            return "comparison";
        case RawUsageType::FUNCTION_ARG:
            return "function argument";
        case RawUsageType::STRING_OP:
            return "string operation";
        case RawUsageType::CONTROL_FLOW:
            return "control flow";
        case RawUsageType::ASSIGNMENT:
            return "assignment";
        case RawUsageType::RETURN_VALUE:
            return "return value";
        default:
            return "other";
        }
}

//
// Variable Taint Tracker
//

class TaintTracker
{
  public:
    void setTaint (const std::string &varName, TaintState state);
    TaintState getTaint (const std::string &varName) const;
    bool hasTaint (const std::string &varName) const;
    void propagate (const std::string &dest, const std::string &src);
    void elevate (const std::string &varName, TaintLayer newLayer,
                  const std::string &parser);
    void dump () const;

    // For flow-sensitive analysis
    void clear ();
    void merge (const TaintTracker &other); // Meet operation for dataflow
    bool equals (const TaintTracker &other) const;
    TaintTracker copy () const;

  private:
    std::map<std::string, TaintState> taintMap_;
};

//
// Known Function Database
//

class FunctionDatabase
{
  public:
    FunctionDatabase ();

    void addSummary (const FunctionSummary &summary);
    std::optional<FunctionSummary> lookup (const std::string &name) const;
    bool isKnownSource (const std::string &name) const;
    bool isKnownSink (const std::string &name) const;
    bool isKnownParser (const std::string &name) const;
    TaintLayer getParserOutputLayer (const std::string &name) const;

    void loadBuiltins (); // Load standard library summaries

  private:
    std::map<std::string, FunctionSummary> summaries_;
    std::set<std::string> sources_;
    std::set<std::string> sinks_;
    std::map<std::string, TaintLayer> parsers_; // parser name -> output layer
};

//
// AST Visitor for Taint Analysis
//

class TaintAnalysisVisitor
    : public clang::RecursiveASTVisitor<TaintAnalysisVisitor>
{
  public:
    explicit TaintAnalysisVisitor (clang::ASTContext *context,
                                   FunctionDatabase &funcDb);

    // Visit function definitions
    bool VisitFunctionDecl (clang::FunctionDecl *func);

    // Visit variable declarations
    bool VisitVarDecl (clang::VarDecl *var);

    // Visit assignments
    bool VisitBinaryOperator (clang::BinaryOperator *op);

    // Visit function calls
    bool VisitCallExpr (clang::CallExpr *call);

    // Get analysis results
    const std::vector<TaintViolation> &
    getViolations () const
    {
        return violations_;
    }
    const std::vector<FunctionSummary> &
    getGeneratedSummaries () const
    {
        return generatedSummaries_;
    }
    const std::vector<RawUsage> &
    getRawUsages () const
    {
        return rawUsages_;
    }

    void dumpState () const;

    // Enable/disable flow-sensitive mode
    void
    setFlowSensitive (bool enabled)
    {
        flowSensitive_ = enabled;
    }

    // Enable/disable RAW usage tracking
    void
    setTrackRawUsage (bool enabled)
    {
        trackRawUsage_ = enabled;
    }

    // Finalize current function summary (for cross-file analysis)
    void finalizeFunctionSummary ();

  private:
    clang::ASTContext *context_;
    FunctionDatabase &funcDb_;
    TaintTracker tracker_;
    std::vector<TaintViolation> violations_;
    std::vector<FunctionSummary> generatedSummaries_;
    std::vector<RawUsage> rawUsages_;
    clang::FunctionDecl *currentFunction_ = nullptr;
    bool flowSensitive_ = false;
    bool trackRawUsage_ = false;

    // Track which parameters flow to sinks in current function
    std::set<unsigned> paramsFlowingToSinks_;
    TaintLayer currentSinkRequirement_ = TaintLayer::RAW;
    std::map<std::string, unsigned> paramNameToIndex_;

    std::string getLocation (clang::SourceLocation loc);
    std::string getFilePath (clang::SourceLocation loc);
    std::string getExprAsString (const clang::Expr *expr);
    TaintState analyzeExpr (const clang::Expr *expr);
    void handleFunctionCall (clang::CallExpr *call);
    void recordViolation (const std::string &loc, const std::string &var,
                          TaintLayer actual, TaintLayer required,
                          const std::string &context);
    void recordParamFlowsToSink (const std::string &paramName,
                                 TaintLayer required);
    void recordRawUsage (const std::string &var, const std::string &loc,
                         RawUsageType type, const std::string &context);
    std::string suggestParserForUsage (RawUsageType type,
                                       const std::string &context);

    // Flow-sensitive analysis using CFG
    void analyzeWithCFG (clang::FunctionDecl *func);
    void
    analyzeBlock (const clang::CFGBlock *block,
                  std::map<const clang::CFGBlock *, TaintTracker> &blockStates);
};

//
// AST Consumer
//

class TaintAnalysisConsumer : public clang::ASTConsumer
{
  public:
    explicit TaintAnalysisConsumer (clang::ASTContext *context,
                                    FunctionDatabase &funcDb);

    void HandleTranslationUnit (clang::ASTContext &context) override;

    const std::vector<TaintViolation> &getViolations () const;
    const std::vector<FunctionSummary> &getGeneratedSummaries () const;
    const std::vector<RawUsage> &getRawUsages () const;

    void setTrackRawUsage (bool enabled);

  private:
    TaintAnalysisVisitor visitor_;
};

//
// Frontend Action
//

class TaintAnalysisAction : public clang::ASTFrontendAction
{
  public:
    explicit TaintAnalysisAction (FunctionDatabase &funcDb);

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer (clang::CompilerInstance &ci,
                       llvm::StringRef file) override;

    void EndSourceFileAction () override;

    const std::vector<TaintViolation> &
    getViolations () const
    {
        return violations_;
    }
    const std::vector<FunctionSummary> &
    getGeneratedSummaries () const
    {
        return generatedSummaries_;
    }

  private:
    FunctionDatabase &funcDb_;
    std::vector<TaintViolation> violations_;
    std::vector<FunctionSummary> generatedSummaries_;
    TaintAnalysisConsumer *consumer_ = nullptr;
};

//
// Action Factory
//

class TaintAnalysisActionFactory : public clang::tooling::FrontendActionFactory
{
  public:
    explicit TaintAnalysisActionFactory (FunctionDatabase &funcDb);

    std::unique_ptr<clang::FrontendAction> create () override;

    const std::vector<TaintViolation> &
    getAllViolations () const
    {
        return allViolations_;
    }
    const std::vector<FunctionSummary> &
    getAllSummaries () const
    {
        return allSummaries_;
    }

    void collectResults (TaintAnalysisAction *action);

  private:
    FunctionDatabase &funcDb_;
    std::vector<TaintViolation> allViolations_;
    std::vector<FunctionSummary> allSummaries_;
};

} // namespace taint

#endif // TAINT_ANALYZER_H
