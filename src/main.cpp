/*----------------------------------------------------------------------
 *
 * Filename: main.cpp
 * Description: The main entry point for the PAPI taint analyzer.
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 * 02 Mar 26  jpb  Removed some old, unused methods. Enable provenance
 *                 flag by default.
 * 04 Mar 26  jpb  Removed unused older cmd line options.
 * 06 Mar 26  jpb  Finished refactoring. Added DEBUG around some output.
 * 07 Mar 26  jpb  Fixed versioning. Sorted out which files to allow to output.
 * 22 Mar 26  jpb  More updates to C++20.
 * 05 Apr 26  jpb  Change in call to calculate parse points.
 * 06 Apr 26  jpb  Add response file. Make explicit path optional.
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
#include <map>
#include <fstream>
#include <unistd.h>
#include "version.h"

using namespace clang::tooling;
using namespace llvm;

/* 
 * Handle command line options using clang's CommonOptionsParser
 */
static cl::OptionCategory TaintCategory ("PAPI Taint Analyzer Options");

static cl::opt<std::string> EmitProvenance (
    "emit-provenance",
    cl::desc ("Emit provenance analysis results to specified YAML file"),
    cl::value_desc ("filename"), cl::cat (TaintCategory));

static cl::opt<std::string> EmitFixes (
    "emit-fixes",
    cl::desc ("Emit fix suggestions to specified YAML file"),
    cl::value_desc ("filename"), cl::cat (TaintCategory));

static cl::opt<std::string> EmitRaw (
    "emit-raw",
    cl::desc ("Emit raw usage report to specified YAML file"),
    cl::value_desc ("filename"), cl::cat (TaintCategory));

static cl::opt<std::string> EmitSummary (
    "emit-summary",
    cl::desc ("Emit generated function summaries to specified file"),
    cl::value_desc ("filename"), cl::cat (TaintCategory));

static cl::opt<std::string> EmitReport (
    "emit-report",
    cl::desc ("Emit taint violations report to specified file (in addition to stderr)"),
    cl::value_desc ("filename"), cl::cat (TaintCategory));

static cl::opt<std::string> FileList (
    "file-list",
    cl::desc ("Read list of source files from specified file (one path per line)"),
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
    void resetContext (void)
    {
        violations.clear ();
        summaries.clear ();
        rawUsages.clear ();
        flowSensitive = false;
        trackRawUsage = !EmitRaw.empty();
    }

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

// Begin non class-related routines. Most are for printing and output,
// as well as the main entry point.

void printReport (AnalysisContext *ctx, llvm::raw_ostream &out)
{
    out << "\n";
    out << "================================================================\n";
    out << "                    TAINT ANALYSIS REPORT                       \n";
    out << "================================================================\n\n";

    if (ctx->violations.empty ())
        {
            out << "No taint violations detected.\n\n";
        }
    else
        {
            out << "Found " << ctx->violations.size ()
                << " taint violation(s):\n\n";

            int i = 1;
            for (const auto &v : ctx->violations)
                {
                    out << "------------------------------------------------------------\n";
                    out << "Violation #" << i++ << "\n";
                    out << "  Location:  " << v.location << "\n";
                    out << "  Variable:  " << v.variable << "\n";
                    out << "  Current:   "
                        << taint::layerToString (v.actualLayer) << "\n";
                    out << "  Required:  "
                        << taint::layerToString (v.requiredLayer) << "\n";
                    out << "  Context:   " << v.context << "\n";
                    if (!v.suggestion.empty ())
                        out << "  Suggest:   " << v.suggestion << "\n";
                }
            out << "------------------------------------------------------------\n\n";
        }

    if (!EmitSummary.empty () && !ctx->summaries.empty ())
        {
            out << "Generated Function Summaries:\n";
            out << "------------------------------------------------------------\n";

            for (const auto &s : ctx->summaries)
                {
                    out << "  " << s.name << ":\n";
                    out << "    Source: " << s.sourceFile << "\n";
                    out << "    Params: " << s.params.size () << "\n";
                    out << "    Return: " << taint::layerToString (s.returnLayer);
                    if (s.returnInherits)
                        out << " (inherits from param " << s.returnInheritSource << ")";
                    out << "\n";
                    if (s.isTaintSource)
                        out << "    [TAINT SOURCE]\n";
                    if (s.isTaintSink)
                        out << "    [TAINT SINK - requires "
                            << taint::layerToString (s.sinkRequirement)
                            << "]\n";
                    out << "\n";
                }
        }
}

// Maximum number of parent directory levels searched for compile_commands.json.
static constexpr unsigned kMaxParentSearchDepth = 3;

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

    // Add parent directories (up to kMaxParentSearchDepth levels)
    llvm::SmallString<256> parentDir = absPath;
    for (auto i = 0u; i < kMaxParentSearchDepth; ++i)
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

// Run one ClangTool pass over all source files and return the tool exit code.
static int
runTool (CompilationDatabase &compDb,
         const std::vector<std::string> &sourceFiles,
         AnalysisContext &ctx)
{
    ClangTool Tool (compDb, sourceFiles);
    ProvenanceTaintActionFactory factory (ctx);
    int r = Tool.run (&factory);
#ifdef DEBUG
    llvm::errs () << std::format("Tool result: {}\nSummaries collected: {}\nViolations collected: {}\n",
        r, ctx.summaries.size(), ctx.violations.size());
#endif
    return r;
}

// Taps into the LLVM version stream to display our version.
void printVersion(llvm::raw_ostream &OS) {
    OS << std::format("taint-analyzer {} (LLVM {})\n", VERSION_STRING, LLVM_VERSION_STRING);
}

// Main line entry point
int main (int argc, const char **argv)
{
    // Create function database with built-in knowledge
    AnalysisContext ctx;

    // This goes ahead of the command line parsing, as LLVM may end the program
    // e.g., someone uses "--help", which causes a segfault because LLVM is not
    // unwinding properly due to a destructor ordering issue. 
    // This stops that problem.
    atexit([]() { _exit(0); });

    llvm::cl::SetVersionPrinter(printVersion); // set our version in place

    // Parse command line options
    auto ExpectedParser = CommonOptionsParser::create (
        argc, argv, TaintCategory, cl::ZeroOrMore,
        "PAPI Taint Analyzer - Track data flow and identify missing parsers");

    if (!ExpectedParser)
        {
            llvm::errs () << ExpectedParser.takeError ();
            return 1;
        }

    CommonOptionsParser &OptionsParser = ExpectedParser.get ();

    // Clear any previous results
    ctx.resetContext();

    // Create provenance tracker
    ctx.provenanceTracker = std::make_unique<taint::ProvenanceTracker>(ctx.funcDb);
    //llvm::errs () << "Provenance-aware analysis enabled\n";

    // Track which source files we're analyzing (for saving summaries)
    std::vector<std::string> sourceFiles = OptionsParser.getSourcePathList ();

    // If --file-list was specified, read additional source files from it
    if (!FileList.empty ())
        {
            std::ifstream listFile (FileList);
            if (!listFile.is_open ())
                {
                    llvm::errs () << std::format("Error: cannot open file list {}\n ", FileList.getValue());
                    return 1;
                }
            std::string line;
            while (std::getline (listFile, line))
                {
                    // Skip blank lines and comments
                    if (line.empty () || line[0] == '#')
                        continue;
                    sourceFiles.push_back (line);
                }
            llvm::errs () << std::format("Loaded {} source file(s) from {}\n", sourceFiles.size (), FileList.getValue());
        }

    if (sourceFiles.empty ())
    {
        llvm::errs () << "Error: no source files specified. Provide files on the command line or use --file-list.\n";
        return 1;
    }

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
                    llvm::errs () << "Using compile_commands.json from: " << compDbPath << "\n";
                }
            else if (!errMsg.empty ())
                {
                    llvm::errs () << "Warning: Found compile_commands.json but failed to load: " << errMsg << "\n";
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

            result = runTool (*compDb, sourceFiles, ctx);
            if (result)
                llvm::errs () << std::format("Error {} running FrontEndAction in ClangTool\n", result);

            llvm::errs () << std::format("\n=== Pass 1 complete: {} function summaries collected ===\n\n", ctx.summaries.size());

            // Clear violations from pass 1 - re-detected in pass 2 with full
            // cross-file knowledge; keep the summaries.
            ctx.violations.clear ();

            // PASS 2: Re-analyze with full function knowledge
            llvm::errs () << "=== Pass 2: Full analysis with cross-file knowledge ===\n\n";

            result = runTool (*compDb, sourceFiles, ctx);

            llvm::errs () << "\n=== Pass 2 complete ===\n";
        }
    else
        {
            // Single file: one pass is sufficient
            result = runTool (*compDb, sourceFiles, ctx);
        }
    // ClangTool is now destroyed, safe to access our copied results

    // Print the report to stderr as before
    printReport (&ctx, llvm::errs ());

    // Mirror report to file if --emit-report was specified
    if (!EmitReport.empty ())
        {
            std::error_code ec;
            llvm::raw_fd_ostream reportFile (EmitReport, ec);
            if (ec)
                {
                    llvm::errs () << "\nError: Could not open report file '" << EmitReport << "': " << ec.message () << "\n";
                }
            else
                {
                    printReport (&ctx, reportFile);
                    llvm::errs () << "\nReport written to: " << EmitReport << "\n";
                }
        }

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
            = ctx.provenanceTracker->computeMinimalParsePoints (ctx.summaries, ctx.violations);

        // Emit RAW usage report to YAML if requested
        if (!EmitRaw.empty () && !ctx.rawUsages.empty ())
            {
                if (taint::FixEmitter::emitRawUsageYAML (ctx.rawUsages, EmitRaw))
                    llvm::errs () << "\nRAW usage report written to: " << EmitRaw << "\n";
                else
                    llvm::errs () << "\nError: Could not write RAW report to " << EmitRaw << "\n";
            }

        // Generate and emit fixes from parse points
        if (!parsePoints.empty () && !EmitFixes.empty ())
            {
                taint::FixEmitter emitter;
                std::vector<taint::Fix> provenanceFixes
                    = emitter.generateFixesFromParsePoints (parsePoints, ctx.funcDb);
                std::vector<taint::Fix> suppressedFixes
                    = emitter.generateSuppressedFromParsePoints (parsePoints);
                if (emitter.emitYAML (provenanceFixes, EmitFixes, suppressedFixes))
                    {
                        llvm::errs () << "\nProvenance-based fixes written to: " << EmitFixes << "\n";
                        if (!suppressedFixes.empty ())
                            llvm::errs () << "  (" << suppressedFixes.size ()
                                          << " suppressed entr"
                                          << (suppressedFixes.size () == 1 ? "y" : "ies")
                                          << " included for auditability)\n";
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
    // 07 Mar 26 commented the _exit out as we handle it at the top of main() with
    // the atexit call. This is left here for history,
    llvm::errs().flush();
//    _exit(exitCode);

    return exitCode; // Not reached, but prevents compiler warnings
}
