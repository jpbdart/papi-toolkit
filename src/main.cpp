/*----------------------------------------------------------------------
 *
 * Filename: main.cpp
 * Description:
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 * 02 Mar 26  jpb  Removed some old, unused methods. Enable provenance
 *                 flag by default.
 * 04 Mar 26  jpb  Removed unused older cmd line options.
 *
 */
#include "ProvenanceTracker.h"
#include "TaintAnalyzer.h"
#include "TaintFixEmitter.h"
#include "TaintSummaryFile.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include <fstream>
#include <map>
#include <unistd.h>

using namespace clang::tooling;
using namespace llvm;

/* 
 * Handle command line options using clang's CommonOptionsParser
 */
static cl::OptionCategory TaintCategory ("Taint Analyzer Options");

static cl::opt<std::string> EmitProvenance (
    "emit-provenance",
    cl::desc ("Emit provenance analysis results to specified YAML file"),
    cl::value_desc ("filename"), cl::cat (TaintCategory));

static cl::opt<std::string> EmitFixes (
    "emit-fixes",
    cl::desc ("Emit fix suggestions to specified YAML file"),
    cl::value_desc ("filename"), cl::cat (TaintCategory));

static cl::opt<std::string> EmitSummary (
    "emit-summary",
    cl::desc ("Emit generated function summaries to specified file"),
    cl::value_desc ("filename"), cl::cat (TaintCategory));

static cl::extrahelp CommonHelp (CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp (
    "\nPAPI Taint Analyzer - LangSec-inspired taint tracking for C programs\n"
    "\n"
    "This tool analyzes C source files to track taint propagation and\n"
    "identify where parsing is needed before data reaches security-sensitive\n"
    "operations (sinks).\n"
    "\n"
    "Examples:\n"
    "  taint-analyzer test.c --\n"
    "  taint-analyzer file1.c file2.c -- -I/usr/include\n"
    "  taint-analyzer test.c --emit-provenance=provenance.yaml --\n"
    "  taint-analyzer test.c --emit-fixes=fixes.yaml --\n"
    "  taint-analyzer test.c --emit-summary=summary.yaml --\n");

// Analysis results collection
class AnalysisContext
{
  public:
    std::vector<taint::TaintViolation> violations;
    std::vector<taint::FunctionSummary> summaries;
    std::vector<taint::RawUsage> rawUsages;
    taint::FunctionDatabase funcDb;
    std::unique_ptr<taint::ProvenanceTracker> provenanceTracker;
    bool flowSensitive = false;
    bool trackRawUsage = false;
};

// Provenance-aware consumer that performs pass-through analysis
class ProvenanceTaintConsumer : public clang::ASTConsumer
{
  public:
    ProvenanceTaintConsumer (clang::ASTContext *context,
                             AnalysisContext &ctx)
        : context_ (context), ctx_ (ctx),
          visitor_ (context, ctx_.funcDb)
    {
        visitor_.setFlowSensitive (ctx_.flowSensitive);
        visitor_.setTrackRawUsage (ctx_.trackRawUsage);
    }

    void HandleTranslationUnit (clang::ASTContext &context) override
    {
        // Run standard taint analysis to generate summaries
        visitor_.TraverseDecl (context.getTranslationUnitDecl ());
        visitor_.finalizeFunctionSummary ();

        for (const auto &s : visitor_.getGeneratedSummaries ()) // Copy summaries to globals
            {
                ctx_.summaries.push_back (s);
                ctx_.funcDb.addSummary (s);
            }

        // Run provenance analysis to add summaries with pass-through
        // info ProvenanceVisitor will update ctx.summaries in place
        taint::ProvenanceVisitor provenanceVisitor (&context, *ctx_.provenanceTracker, ctx_.summaries);
        provenanceVisitor.TraverseDecl (context.getTranslationUnitDecl ());

        llvm::errs () << "\nAnalysis Complete\n";
        visitor_.dumpState ();

        // Copy violations and raw usages
        for (const auto &v : visitor_.getViolations ())
                ctx_.violations.push_back (v);
        for (const auto &r : visitor_.getRawUsages ())
                ctx_.rawUsages.push_back (r);
    }

  private:
    clang::ASTContext *context_;
    AnalysisContext &ctx_;
    taint::TaintAnalysisVisitor visitor_;
};

class ProvenanceTaintAction : public clang::ASTFrontendAction
{
  public:
    explicit ProvenanceTaintAction (AnalysisContext &ctx) : ctx_ (ctx) {}

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer (clang::CompilerInstance &ci,
                       llvm::StringRef file) override
    {
        llvm::errs () << "Analyzing file (with provenance): " << file << "\n";
        return std::make_unique<ProvenanceTaintConsumer> (&ci.getASTContext (), ctx_);
    }

  private:
    AnalysisContext &ctx_;
};

class ProvenanceTaintActionFactory : public FrontendActionFactory
{
  public:
    explicit ProvenanceTaintActionFactory (AnalysisContext &ctx) : ctx_ (ctx) {}

    std::unique_ptr<clang::FrontendAction>
    create () override
    {
        return std::make_unique<ProvenanceTaintAction> (ctx_);
    }

  private:
    AnalysisContext &ctx_;
};

// Emit RAW usage report to YAML file
bool emitRawUsageYAML (const std::vector<taint::RawUsage> &usages,
                  const std::string &filename)
{
    std::ofstream out (filename);
    if (!out)
        return false;

    out << "# PAPI Taint Analyzer - RAW Usage Report\n";
    out << "---\n";
    out << "version: 1\n";
    out << "usage_count: " << usages.size () << "\n";
    out << "raw_usages:\n";

    for (const auto &r : usages)
        {
            out << "  - variable: \"" << r.variable << "\"\n";
            out << "    location: \"" << r.location << "\"\n";
            out << "    function: \"" << r.function << "\"\n";
            out << "    usage_type: "
                << taint::rawUsageTypeToString (r.usageType) << "\n";
            out << "    context: \"" << r.usageContext << "\"\n";
            if (!r.suggestedParser.empty ())
                {
                    out << "    suggested_parser: \"" << r.suggestedParser
                        << "\"\n";
                }
            if (!r.suggestedType.empty ())
                {
                    out << "    suggested_type: \"" << r.suggestedType
                        << "\"\n";
                }
            out << "\n";
        }
    out << "...\n";
    return true;
}

void
printReport (AnalysisContext *ctx)
{
    llvm::errs () << "\n";
    llvm::errs ()
        << "================================================================\n";
    llvm::errs ()
        << "                    TAINT ANALYSIS REPORT                       \n";
    llvm::errs () << "========================================================="
                     "=======\n\n";

    if (ctx->violations.empty ())
        {
            llvm::errs () << "No taint violations detected.\n\n";
        }
    else
        {
            llvm::errs () << "Found " << ctx->violations.size ()
                          << " taint violation(s):\n\n";

            int i = 1;
            for (const auto &v : ctx->violations)
                {
                    llvm::errs () << "-----------------------------------------"
                                     "-----------------------\n";
                    llvm::errs () << "Violation #" << i++ << "\n";
                    llvm::errs () << "  Location:  " << v.location << "\n";
                    llvm::errs () << "  Variable:  " << v.variable << "\n";
                    llvm::errs ()
                        << "  Current:   "
                        << taint::layerToString (v.actualLayer) << "\n";
                    llvm::errs ()
                        << "  Required:  "
                        << taint::layerToString (v.requiredLayer) << "\n";
                    llvm::errs () << "  Context:   " << v.context << "\n";
                    if (!v.suggestion.empty ())
                        {
                            llvm::errs ()
                                << "  Suggest:   " << v.suggestion << "\n";
                        }
                }
            llvm::errs () << "-------------------------------------------------"
                             "---------------\n\n";
        }

    if (!EmitSummary.empty () && !ctx->summaries.empty ())
        {
            llvm::errs () << "Generated Function Summaries:\n";
            llvm::errs () << "-------------------------------------------------"
                             "---------------\n";

            for (const auto &s : ctx->summaries)
                {
                    llvm::errs () << "  " << s.name << ":\n";
                    llvm::errs () << "    Source: " << s.sourceFile << "\n";
                    llvm::errs () << "    Params: " << s.params.size () << "\n";
                    llvm::errs () << "    Return: "
                                  << taint::layerToString (s.returnLayer);
                    if (s.returnInherits)
                        {
                            llvm::errs () << " (inherits from param "
                                          << s.returnInheritSource << ")";
                        }
                    llvm::errs () << "\n";
                    if (s.isTaintSource)
                        {
                            llvm::errs () << "    [TAINT SOURCE]\n";
                        }
                    if (s.isTaintSink)
                        {
                            llvm::errs ()
                                << "    [TAINT SINK - requires "
                                << taint::layerToString (s.sinkRequirement)
                                << "]\n";
                        }
                    llvm::errs () << "\n";
                }
        }
}

// Search for compile_commands.json in common locations
std::string findCompilationDatabase (const std::string &startPath)
{
    std::vector<std::string> searchPaths;

    // Get absolute path of start directory
    llvm::SmallString<256> absPath;
    if (startPath.empty ())
        {
            llvm::sys::fs::current_path (absPath);
        }
    else
        {
            absPath = startPath;
            llvm::sys::fs::make_absolute (absPath);
        }

    // Add current directory
    searchPaths.push_back (std::string (absPath.str ()));

    // Add 'build' subdirectory
    llvm::SmallString<256> buildDir = absPath;
    llvm::sys::path::append (buildDir, "build");
    searchPaths.push_back (std::string (buildDir.str ()));

    // Add parent directories (up to 3 levels)
    llvm::SmallString<256> parentDir = absPath;
    for (auto i = 0u; i < 3u; ++i)
        {
            llvm::sys::path::remove_filename (parentDir);
            if (parentDir.empty ())
                break;
            searchPaths.push_back (std::string (parentDir.str ()));

            // Also check build/ in parent
            llvm::SmallString<256> parentBuild = parentDir;
            llvm::sys::path::append (parentBuild, "build");
            searchPaths.push_back (std::string (parentBuild.str ()));
        }

    // Search for compile_commands.json
    for (const auto &dir : searchPaths)
        {
            llvm::SmallString<256> dbPath (dir);
            llvm::sys::path::append (dbPath, "compile_commands.json");

            if (llvm::sys::fs::exists (dbPath))
                {
                    return dir;
                }
        }

    return "";
}

// Main line entry point
int main (int argc, const char **argv)
{
    // Parse command line options
    auto ExpectedParser = CommonOptionsParser::create (
        argc, argv, TaintCategory, cl::OneOrMore,
        "Taint Analyzer - Track data flow and identify missing parsers");

    if (!ExpectedParser)
        {
            llvm::errs () << ExpectedParser.takeError ();
            return 1;
        }

    CommonOptionsParser &OptionsParser = ExpectedParser.get ();

    // Create function database with built-in knowledge
    AnalysisContext ctx;

    taint::FunctionDatabase funcDb;
    ctx.funcDb = funcDb;

    // Clear any previous results
    ctx.violations.clear ();
    ctx.summaries.clear ();
    ctx.rawUsages.clear ();
    ctx.flowSensitive = false;
    ctx.trackRawUsage = false;

    // Create provenance tracker
    //std::unique_ptr<taint::ProvenanceTracker> provenanceTracker;
    ctx.provenanceTracker = std::make_unique<taint::ProvenanceTracker>(ctx.funcDb);
    //ctx.provenanceTracker = provenanceTracker.get ();
    llvm::errs () << "Provenance-aware analysis enabled\n";

    // Track which source files we're analyzing (for saving summaries)
    std::vector<std::string> sourceFiles = OptionsParser.getSourcePathList ();

    // Try to find a compilation database
    std::string compDbPath;
    std::unique_ptr<CompilationDatabase> customCompDb;

    // First check if source file directory has one
    if (!sourceFiles.empty ())
        {
            llvm::SmallString<256> sourceDir (sourceFiles[0]);
            llvm::sys::path::remove_filename (sourceDir);
            compDbPath
                = findCompilationDatabase (std::string (sourceDir.str ()));
        }

    // Fall back to current directory
    if (compDbPath.empty ())
        {
            compDbPath = findCompilationDatabase ("");
        }

    // Load custom compilation database if found
    CompilationDatabase *compDb = &OptionsParser.getCompilations ();
    if (!compDbPath.empty ())
        {
            std::string errMsg;
            customCompDb
                = CompilationDatabase::loadFromDirectory (compDbPath, errMsg);
            if (customCompDb)
                {
                    compDb = customCompDb.get ();
                    llvm::errs ()
                        << "Using compile_commands.json from: " << compDbPath
                        << "\n";
                }
            else if (!errMsg.empty ())
                {
                    llvm::errs () << "Warning: Found compile_commands.json but "
                                     "failed to load: "
                                  << errMsg << "\n";
                }
        }

    // Multi-file analysis: do two passes if we have multiple files
    bool multiFile = sourceFiles.size () > 1;

    llvm::errs ()
        << "================================================================\n";
    llvm::errs ()
        << "              PAPI Taint Analyzer                     \n";
    llvm::errs () << "========================================================="
                     "=======\n\n";

    int result = 0;

    if (multiFile)
        {
            // PASS 1: Build function summaries from all files
            llvm::errs () << "=== Pass 1: Building function summaries ===\n\n";

            {
                ClangTool Tool (*compDb, sourceFiles);
                ProvenanceTaintActionFactory factory(ctx);
                result = Tool.run (&factory);

llvm::errs() << "Pass 1 Tool result: " << result << "\n";
llvm::errs() << "Summaries collected: " << ctx.summaries.size() << "\n";
llvm::errs() << "Violations collected: " << ctx.violations.size() << "\n";

                if (result)
                    llvm::errs () << "Error " << result << " running FrontEndAction in ClangTool\n";
            }

            llvm::errs () << "\n=== Pass 1 complete: " << ctx.summaries.size ()
                          << " function summaries collected ===\n\n";

            // Add all collected summaries to the database for pass 2
            // (They were already added during pass 1, but let's be explicit)

            // Clear violations from pass 1 - we'll re-detect them in pass 2
            // but keep the summaries
            ctx.violations.clear ();

            // PASS 2: Re-analyze with full function knowledge
            llvm::errs () << "=== Pass 2: Full analysis with cross-file "
                             "knowledge ===\n\n";

            {
                ClangTool Tool (*compDb, sourceFiles);
                ProvenanceTaintActionFactory factory(ctx);
                result = Tool.run (&factory);
                llvm::errs() << "Pass 2 Tool result: " << result << "\n";
llvm::errs() << "Summaries collected: " << ctx.summaries.size() << "\n";
llvm::errs() << "Violations collected: " << ctx.violations.size() << "\n";
            }

            llvm::errs () << "\n=== Pass 2 complete ===\n";
        }
    else
        {
            // Single file: one pass is sufficient
            {
                ClangTool Tool (*compDb, sourceFiles);
                ProvenanceTaintActionFactory factory(ctx);
                result = Tool.run (&factory);
                llvm::errs() << "Final Pass Tool result: " << result << "\n";
llvm::errs() << "Summaries collected: " << ctx.summaries.size() << "\n";
llvm::errs() << "Violations collected: " << ctx.violations.size() << "\n";
            }
        }
    // ClangTool is now destroyed, safe to access our copied results

    // Print the report
    printReport (&ctx);

    // Provenance analysis output
    {
        llvm::errs () << "\n================================================================\n";
        llvm::errs () << "              PROVENANCE ANALYSIS RESULTS\n";
        llvm::errs () << "================================================================\n";

        // Dump each summary with provenance info
        for (const auto &summary : ctx.summaries)
            {
                taint::ProvenanceTracker::dumpSummary (summary);
            }

        // Compute minimal parse points
        std::set<taint::ParsePoint> parsePoints
            = ctx.provenanceTracker->computeMinimalParsePoints (ctx.summaries);

        // Generate and emit fixes from parse points
        if (!parsePoints.empty () && !EmitFixes.empty ())
            {
                taint::FixEmitter emitter;
                std::vector<taint::Fix> provenanceFixes
                    = emitter.generateFixesFromParsePoints (parsePoints, funcDb);
                if (emitter.emitYAML (provenanceFixes, EmitFixes))
                    {
                        llvm::errs () << "\nProvenance-based fixes written to: " << EmitFixes << "\n";
                    }
                else
                    {
                        llvm::errs () << "\nError: Could not write fixes to " << EmitFixes << "\n";
                    }
            }

        // Emit provenance YAML if requested
        if (!EmitProvenance.empty ())
            {
                if (taint::SummaryFileWriter::write (EmitProvenance, ctx.summaries, "provenance-analysis"))
                    {
                        llvm::errs () << "\nProvenance summaries written to: " << EmitProvenance << "\n";
                    }
                else
                    {
                        llvm::errs () << "\nError: Could not write provenance to " << EmitProvenance << "\n";
                    }
            }

        // Emit summary file if requested
        if (!EmitSummary.empty () && !ctx.summaries.empty ())
            {
                if (taint::SummaryFileWriter::write (EmitSummary, ctx.summaries, "function-summaries"))
                    {
                        llvm::errs () << "\nFunction summaries written to: " << EmitSummary << "\n";
                    }
                else
                    {
                        llvm::errs () << "\nError: Could not write summaries to " << EmitSummary << "\n";
                    }
            }
    }

    // Determine exit code: 1 if violations found, otherwise tool result
    int exitCode = ctx.violations.empty () ? result : 1;

    // LLVM has a destructor ordering bug in its static initializers. StringMap is freed by 
    // __run_exit_handlers then __cxa_finalize attempts a second free of the same block.
    // _exit() bypasses this by skipping destructor processing entirely.
    // See: double-free in llvm::StringMap destructor during __cxa_finalize.
    llvm::errs().flush();
    _exit(exitCode);

    return exitCode; // Not reached, but prevents compiler warnings
}
