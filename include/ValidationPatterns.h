/*----------------------------------------------------------------------
 *
 * Filename: ValidationPatterns.h 
 * Description: Detect validation patterns that elevate taint
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */

#ifndef VALIDATION_PATTERNS_H
#define VALIDATION_PATTERNS_H

#include "TaintAnalyzer.h"
#include "clang/AST/Stmt.h"
#include <optional>
#include <vector>

namespace taint
{

//
// Validation Pattern Results
//

struct ValidationInfo
{
    std::string variable;
    TaintLayer elevatedLevel;
    std::string reason;
    bool validInTrueBranch;  // Validation holds in 'then' branch
    bool validInFalseBranch; // Validation holds in 'else' branch
};

struct BoundsCheckInfo
{
    std::string variable;
    bool hasLowerBound;
    bool hasUpperBound;
    int64_t lowerBound;
    int64_t upperBound;
};

struct BitmaskInfo
{
    std::string variable;
    uint64_t possibleValues; // Bitmask of bits that can be set
    uint64_t maxValue;       // Maximum possible value
};

struct ErrorCheckPattern
{
    std::string functionName;
    std::string returnVar;
    std::vector<std::string> outParams;
};

//
// Pattern Detection Functions
//

// Analyze an if statement for validation patterns
std::vector<ValidationInfo> analyzeIfForValidation (const clang::IfStmt *ifStmt,
                                                    clang::ASTContext &context);

// Detect bounds checking: if (x >= 0 && x < MAX)
std::optional<BoundsCheckInfo>
detectBoundsCheck (const clang::BinaryOperator *binOp);

// Detect equality check: if (x == CONSTANT)
std::optional<ValidationInfo>
detectEqualityCheck (const clang::BinaryOperator *binOp);

// Detect non-null check: if (ptr != NULL)
std::optional<ValidationInfo> detectNonNullCheck (const clang::Expr *cond);

// Detect error-checked function call pattern
std::optional<ErrorCheckPattern>
detectErrorCheckPattern (const clang::IfStmt *ifStmt,
                         clang::ASTContext &context);

// Detect bitmask extraction: val = (x & MASK) >> SHIFT
std::optional<BitmaskInfo>
detectBitmaskExtraction (const clang::BinaryOperator *assignment);

//
// Parser Function Heuristics
//

// Check if function name suggests it's a parser
bool isLikelyParserFunction (const std::string &funcName);

// Infer output taint layer for a parser function
TaintLayer inferParserOutputLayer (const std::string &funcName);

//
// Helper Functions
//

// Extract variable name from expression
std::string extractVarName (const clang::Expr *expr);

// Check if expression is a constant
bool isConstant (const clang::Expr *expr);

// Check if expression is NULL
bool isNullExpr (const clang::Expr *expr);

} // namespace taint

#endif // VALIDATION_PATTERNS_H
