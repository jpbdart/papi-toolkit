/*----------------------------------------------------------------------
 *
 * Filename: ValidationPatterns.cpp
 * Description: Detect validation patterns that elevate taint
 *
 * This module detects common C validation patterns and elevates taint
 * levels accordingly:
 *
 * 1. Error-checked function calls:
 *    rc = parse_func(..., &out);
 *    if (rc != 0) return rc;
 *    // After: out is SYNTACTIC
 *
 * 2. Bounds checking:
 *    if (val >= 0 && val < MAX) { ... }
 *    // Inside: val is SEMANTIC
 *
 * 3. Enum/constant validation:
 *    if (type == TYPE_A || type == TYPE_B) { ... }
 *    // Inside: type is SEMANTIC
 *
 * 4. Non-null checks:
 *    if (ptr != NULL) { ... }
 *    // Inside: ptr is safe to deref (but still RAW content)
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */

#include "TaintAnalyzer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Stmt.h"
#include <regex>
#include <set>

namespace taint
{

//
// Pattern Detection Structures
//

struct ValidationInfo
{
    std::string variable;
    TaintLayer elevatedLevel;
    std::string reason;
    bool validInTrueBranch;  // Valid in 'then' branch of if
    bool validInFalseBranch; // Valid in 'else' branch of if
};

//
// Helper Functions
//

// Extract variable name from an expression (handles DeclRefExpr, MemberExpr)
static std::string
extractVarName (const clang::Expr *expr)
{
    expr = expr->IgnoreParenImpCasts ();

    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (expr))
        {
            return dre->getDecl ()->getNameAsString ();
        }

    if (const auto *me = llvm::dyn_cast<clang::MemberExpr> (expr))
        {
            // Get the full member access path
            std::string base;
            if (const auto *baseExpr = me->getBase ())
                {
                    base = extractVarName (baseExpr);
                }
            if (!base.empty ())
                {
                    return base + "."
                           + me->getMemberDecl ()->getNameAsString ();
                }
            return me->getMemberDecl ()->getNameAsString ();
        }

    if (const auto *ase = llvm::dyn_cast<clang::ArraySubscriptExpr> (expr))
        {
            return extractVarName (ase->getBase ());
        }

    return "";
}

// Check if expression is a constant/literal
static bool
isConstant (const clang::Expr *expr)
{
    expr = expr->IgnoreParenImpCasts ();
    return llvm::isa<clang::IntegerLiteral> (expr)
           || llvm::isa<clang::FloatingLiteral> (expr)
           || llvm::isa<clang::CharacterLiteral> (expr)
           || llvm::isa<clang::StringLiteral> (expr)
           || (llvm::isa<clang::DeclRefExpr> (expr)
               && llvm::cast<clang::DeclRefExpr> (expr)->getDecl ()->getKind ()
                      == clang::Decl::EnumConstant);
}

// Check if expression is NULL
static bool
isNullExpr (const clang::Expr *expr)
{
    expr = expr->IgnoreParenImpCasts ();

    // Integer literal 0
    if (const auto *il = llvm::dyn_cast<clang::IntegerLiteral> (expr))
        {
            return il->getValue () == 0;
        }

    // GNU __null
    if (llvm::isa<clang::GNUNullExpr> (expr))
        {
            return true;
        }

    return false;
}

//
// Pattern: Error-Checked Function Call
//
// Detect: rc = func(&out); if(rc) return;
// Result: 'out' is elevated to SYNTACTIC

struct ErrorCheckPattern
{
    std::string functionName;
    std::string returnVar;
    std::vector<std::string> outParams; // Parameters that receive parsed data
};

// Detect error-checked function call pattern
static std::optional<ErrorCheckPattern>
detectErrorCheckPattern (const clang::IfStmt *ifStmt,
                         clang::ASTContext &context)
{

    ErrorCheckPattern pattern;

    // The condition should check a variable (the return code)
    const clang::Expr *cond = ifStmt->getCond ()->IgnoreParenImpCasts ();

    // Handle: if(rc) or if(rc != 0) or if(rc != MOSQ_ERR_SUCCESS)
    std::string rcVar;

    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (cond))
        {
            rcVar = dre->getDecl ()->getNameAsString ();
        }
    else if (const auto *binOp = llvm::dyn_cast<clang::BinaryOperator> (cond))
        {
            if (binOp->getOpcode () == clang::BO_NE
                || binOp->getOpcode () == clang::BO_EQ)
                {

                    const clang::Expr *lhs
                        = binOp->getLHS ()->IgnoreParenImpCasts ();
                    const clang::Expr *rhs
                        = binOp->getRHS ()->IgnoreParenImpCasts ();

                    if (const auto *dre
                        = llvm::dyn_cast<clang::DeclRefExpr> (lhs))
                        {
                            if (isConstant (rhs))
                                {
                                    rcVar = dre->getDecl ()->getNameAsString ();
                                }
                        }
                    else if (const auto *dre
                             = llvm::dyn_cast<clang::DeclRefExpr> (rhs))
                        {
                            if (isConstant (lhs))
                                {
                                    rcVar = dre->getDecl ()->getNameAsString ();
                                }
                        }
                }
        }

    if (rcVar.empty ())
        {
            return std::nullopt;
        }

    pattern.returnVar = rcVar;

    // The 'then' branch should be error handling (return, cleanup, etc.)
    const clang::Stmt *thenStmt = ifStmt->getThen ();
    bool isErrorBranch = false;

    if (const auto *compound = llvm::dyn_cast<clang::CompoundStmt> (thenStmt))
        {
            for (const clang::Stmt *s : compound->body ())
                {
                    if (llvm::isa<clang::ReturnStmt> (s))
                        {
                            isErrorBranch = true;
                            break;
                        }
                }
        }
    else if (llvm::isa<clang::ReturnStmt> (thenStmt))
        {
            isErrorBranch = true;
        }

    if (!isErrorBranch)
        {
            return std::nullopt;
        }

    // Now we need to find the assignment to rcVar before this if
    // This requires looking at the previous statement
    // For now, we'll return the pattern and let the caller handle lookback

    return pattern;
}

//
// Pattern: Bounds Check
//
// Detect: if (x >= 0 && x < MAX) or if (x < MAX)
// Result: Inside the branch, x is SEMANTIC

struct BoundsCheckInfo
{
    std::string variable;
    bool hasLowerBound;
    bool hasUpperBound;
    int64_t lowerBound;
    int64_t upperBound;
};

static std::optional<BoundsCheckInfo>
detectBoundsCheck (const clang::BinaryOperator *binOp)
{

    BoundsCheckInfo info;
    info.hasLowerBound = false;
    info.hasUpperBound = false;

    // Handle compound conditions: x >= 0 && x < MAX
    if (binOp->getOpcode () == clang::BO_LAnd)
        {
            auto left
                = detectBoundsCheck (llvm::dyn_cast<clang::BinaryOperator> (
                    binOp->getLHS ()->IgnoreParenImpCasts ()));
            auto right
                = detectBoundsCheck (llvm::dyn_cast<clang::BinaryOperator> (
                    binOp->getRHS ()->IgnoreParenImpCasts ()));

            if (left && right && left->variable == right->variable)
                {
                    info.variable = left->variable;
                    info.hasLowerBound
                        = left->hasLowerBound || right->hasLowerBound;
                    info.hasUpperBound
                        = left->hasUpperBound || right->hasUpperBound;
                    if (left->hasLowerBound)
                        info.lowerBound = left->lowerBound;
                    if (right->hasLowerBound)
                        info.lowerBound = right->lowerBound;
                    if (left->hasUpperBound)
                        info.upperBound = left->upperBound;
                    if (right->hasUpperBound)
                        info.upperBound = right->upperBound;
                    return info;
                }

            // Return whichever one matched
            if (left)
                return left;
            if (right)
                return right;
            return std::nullopt;
        }

    // Handle simple comparisons: x < MAX, x >= 0, etc.
    clang::BinaryOperatorKind op = binOp->getOpcode ();
    if (op != clang::BO_LT && op != clang::BO_LE && op != clang::BO_GT
        && op != clang::BO_GE)
        {
            return std::nullopt;
        }

    const clang::Expr *lhs = binOp->getLHS ()->IgnoreParenImpCasts ();
    const clang::Expr *rhs = binOp->getRHS ()->IgnoreParenImpCasts ();

    std::string varName;
    const clang::Expr *constExpr = nullptr;
    bool varOnLeft = false;

    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (lhs))
        {
            if (isConstant (rhs) || llvm::isa<clang::DeclRefExpr> (rhs))
                {
                    varName = dre->getDecl ()->getNameAsString ();
                    constExpr = rhs;
                    varOnLeft = true;
                }
        }
    if (varName.empty ())
        {
            if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (rhs))
                {
                    if (isConstant (lhs) || llvm::isa<clang::DeclRefExpr> (lhs))
                        {
                            varName = dre->getDecl ()->getNameAsString ();
                            constExpr = lhs;
                            varOnLeft = false;
                        }
                }
        }

    if (varName.empty ())
        {
            return std::nullopt;
        }

    info.variable = varName;

    // Determine if this is upper or lower bound
    // x < MAX  -> upper bound (var on left, LT)
    // x >= 0   -> lower bound (var on left, GE)
    // MAX > x  -> upper bound (var on right, GT)
    // 0 <= x   -> lower bound (var on right, LE)

    if (varOnLeft)
        {
            if (op == clang::BO_LT || op == clang::BO_LE)
                {
                    info.hasUpperBound = true;
                }
            else
                {
                    info.hasLowerBound = true;
                }
        }
    else
        {
            if (op == clang::BO_GT || op == clang::BO_GE)
                {
                    info.hasUpperBound = true;
                }
            else
                {
                    info.hasLowerBound = true;
                }
        }

    // Try to get actual bound value
    if (const auto *il = llvm::dyn_cast<clang::IntegerLiteral> (constExpr))
        {
            int64_t val = il->getValue ().getSExtValue ();
            if (info.hasUpperBound)
                info.upperBound = val;
            if (info.hasLowerBound)
                info.lowerBound = val;
        }

    return info;
}

//
// Pattern: Value Equality Check
//
// Detect: if (type == TYPE_A) or switch(type)
// Result: Inside matching branch, type is SEMANTIC

static std::optional<ValidationInfo>
detectEqualityCheck (const clang::BinaryOperator *binOp)
{

    if (binOp->getOpcode () != clang::BO_EQ)
        {
            return std::nullopt;
        }

    const clang::Expr *lhs = binOp->getLHS ()->IgnoreParenImpCasts ();
    const clang::Expr *rhs = binOp->getRHS ()->IgnoreParenImpCasts ();

    std::string varName;

    if (isConstant (rhs))
        {
            varName = extractVarName (lhs);
        }
    else if (isConstant (lhs))
        {
            varName = extractVarName (rhs);
        }

    if (varName.empty ())
        {
            return std::nullopt;
        }

    ValidationInfo info;
    info.variable = varName;
    info.elevatedLevel = TaintLayer::SEMANTIC;
    info.reason = "equality check against constant";
    info.validInTrueBranch = true;
    info.validInFalseBranch = false;

    return info;
}

//
// Pattern: Non-null Check
//
// Detect: if (ptr != NULL) or if (ptr)
// Result: Inside branch, ptr is safe to dereference

static std::optional<ValidationInfo>
detectNonNullCheck (const clang::Expr *cond)
{

    cond = cond->IgnoreParenImpCasts ();

    std::string varName;
    bool validInTrue = true;

    // Direct: if (ptr)
    if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr> (cond))
        {
            if (dre->getType ()->isPointerType ())
                {
                    varName = dre->getDecl ()->getNameAsString ();
                }
        }

    // Comparison: if (ptr != NULL) or if (ptr == NULL)
    if (const auto *binOp = llvm::dyn_cast<clang::BinaryOperator> (cond))
        {
            if (binOp->getOpcode () == clang::BO_NE
                || binOp->getOpcode () == clang::BO_EQ)
                {

                    const clang::Expr *lhs
                        = binOp->getLHS ()->IgnoreParenImpCasts ();
                    const clang::Expr *rhs
                        = binOp->getRHS ()->IgnoreParenImpCasts ();

                    if (isNullExpr (rhs))
                        {
                            varName = extractVarName (lhs);
                        }
                    else if (isNullExpr (lhs))
                        {
                            varName = extractVarName (rhs);
                        }

                    if (!varName.empty ())
                        {
                            // ptr != NULL -> valid in true branch
                            // ptr == NULL -> valid in false branch
                            validInTrue = (binOp->getOpcode () == clang::BO_NE);
                        }
                }
        }

    // Negation: if (!ptr)
    if (const auto *unOp = llvm::dyn_cast<clang::UnaryOperator> (cond))
        {
            if (unOp->getOpcode () == clang::UO_LNot)
                {
                    varName = extractVarName (unOp->getSubExpr ());
                    validInTrue = false; // !ptr means null in true branch
                }
        }

    if (varName.empty ())
        {
            return std::nullopt;
        }

    ValidationInfo info;
    info.variable = varName;
    info.elevatedLevel = TaintLayer::RAW; // Still RAW, but safe to deref
    info.reason = "non-null check";
    info.validInTrueBranch = validInTrue;
    info.validInFalseBranch = !validInTrue;

    return info;
}

//
// Pattern: Parser Function Heuristics
//
// Detect functions that look like parsers based on name/signature

bool
isLikelyParserFunction (const std::string &funcName)
{
    // Common parser function name patterns
    static const std::vector<std::regex> parserPatterns = {
        std::regex (".*parse.*", std::regex::icase),
        std::regex (".*read.*", std::regex::icase),
        std::regex (".*decode.*", std::regex::icase),
        std::regex (".*deserialize.*", std::regex::icase),
        std::regex (".*from_.*", std::regex::icase),
        std::regex (".*_to_.*", std::regex::icase), // e.g., str_to_int
        std::regex (".*validate.*", std::regex::icase),
        std::regex ("str(n)?to.*", std::regex::icase), // strtol, strtoul, etc.
        std::regex ("ato.*"),                          // atoi, atol, atof
        std::regex ("sscanf"),
    };

    for (const auto &pattern : parserPatterns)
        {
            if (std::regex_match (funcName, pattern))
                {
                    return true;
                }
        }

    return false;
}

// Determine likely output layer for a parser based on what it does
TaintLayer
inferParserOutputLayer (const std::string &funcName)
{
    // Functions that do semantic validation
    static const std::vector<std::regex> semanticPatterns = {
        std::regex (".*validate.*", std::regex::icase),
        std::regex (".*check.*", std::regex::icase),
        std::regex (".*verify.*", std::regex::icase),
    };

    for (const auto &pattern : semanticPatterns)
        {
            if (std::regex_match (funcName, pattern))
                {
                    return TaintLayer::SEMANTIC;
                }
        }

    // Default to SYNTACTIC for other parsers
    return TaintLayer::SYNTACTIC;
}

//
// Integration with TaintAnalyzer
//

// Analyze an if statement for validation patterns
std::vector<ValidationInfo>
analyzeIfForValidation (const clang::IfStmt *ifStmt, clang::ASTContext &context)
{

    std::vector<ValidationInfo> validations;

    const clang::Expr *cond = ifStmt->getCond ();
    if (!cond)
        return validations;

    cond = cond->IgnoreParenImpCasts ();

    // Check for non-null
    if (auto info = detectNonNullCheck (cond))
        {
            validations.push_back (*info);
        }

    // Check for bounds and equality
    if (const auto *binOp = llvm::dyn_cast<clang::BinaryOperator> (cond))
        {
            // Bounds check
            if (auto bounds = detectBoundsCheck (binOp))
                {
                    ValidationInfo info;
                    info.variable = bounds->variable;
                    info.elevatedLevel = TaintLayer::SEMANTIC;
                    info.reason = "bounds check";
                    if (bounds->hasLowerBound && bounds->hasUpperBound)
                        {
                            info.reason
                                = "range check ["
                                  + std::to_string (bounds->lowerBound) + ", "
                                  + std::to_string (bounds->upperBound) + "]";
                        }
                    info.validInTrueBranch = true;
                    info.validInFalseBranch = false;
                    validations.push_back (info);
                }

            // Equality check
            if (auto info = detectEqualityCheck (binOp))
                {
                    validations.push_back (*info);
                }
        }

    // Check for error-handling pattern
    if (auto pattern = detectErrorCheckPattern (ifStmt, context))
        {
            // This needs more context to be useful - the caller should
            // look back for the assignment
            ValidationInfo info;
            info.variable = pattern->returnVar;
            info.elevatedLevel = TaintLayer::SYNTACTIC;
            info.reason = "error-checked return value";
            info.validInTrueBranch = false; // Error in true branch
            info.validInFalseBranch = true;
            validations.push_back (info);
        }

    return validations;
}

/*
 * Bitmask Analysis
 *
 * Detect: val = (header & 0x06) >> 1;
 * Result: val has constrained range based on mask
 */
struct BitmaskInfo
{
    std::string variable;
    uint64_t possibleValues; // Bitmask of possible values
    uint64_t maxValue;
};

std::optional<BitmaskInfo>
detectBitmaskExtraction (const clang::BinaryOperator *assignment)
{

    if (!assignment->isAssignmentOp ())
        {
            return std::nullopt;
        }

    std::string destVar = extractVarName (assignment->getLHS ());
    if (destVar.empty ())
        {
            return std::nullopt;
        }

    // Look for pattern: (expr & MASK) >> SHIFT
    const clang::Expr *rhs = assignment->getRHS ()->IgnoreParenImpCasts ();

    uint64_t mask = UINT64_MAX;
    int shift = 0;

    // Check for shift
    if (const auto *shiftOp = llvm::dyn_cast<clang::BinaryOperator> (rhs))
        {
            if (shiftOp->getOpcode () == clang::BO_Shr)
                {
                    if (const auto *shiftAmt
                        = llvm::dyn_cast<clang::IntegerLiteral> (
                            shiftOp->getRHS ()->IgnoreParenImpCasts ()))
                        {
                            shift = shiftAmt->getValue ().getZExtValue ();
                            rhs = shiftOp->getLHS ()->IgnoreParenImpCasts ();
                        }
                }
        }

    // Check for mask
    if (const auto *maskOp = llvm::dyn_cast<clang::BinaryOperator> (rhs))
        {
            if (maskOp->getOpcode () == clang::BO_And)
                {
                    const clang::Expr *lhs
                        = maskOp->getLHS ()->IgnoreParenImpCasts ();
                    const clang::Expr *rhsMask
                        = maskOp->getRHS ()->IgnoreParenImpCasts ();

                    if (const auto *maskLit
                        = llvm::dyn_cast<clang::IntegerLiteral> (rhsMask))
                        {
                            mask = maskLit->getValue ().getZExtValue ();
                        }
                    else if (const auto *maskLit
                             = llvm::dyn_cast<clang::IntegerLiteral> (lhs))
                        {
                            mask = maskLit->getValue ().getZExtValue ();
                        }
                }
        }

    if (mask == UINT64_MAX)
        {
            return std::nullopt; // No mask found
        }

    BitmaskInfo info;
    info.variable = destVar;
    info.possibleValues = mask >> shift;

    // Calculate max value from mask
    uint64_t maxVal = 0;
    uint64_t temp = info.possibleValues;
    while (temp)
        {
            if (temp & 1)
                {
                    maxVal = (maxVal << 1) | 1;
                }
            else
                {
                    maxVal <<= 1;
                }
            temp >>= 1;
        }
    info.maxValue = maxVal;

    return info;
}

} // namespace taint
