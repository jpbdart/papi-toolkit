/*----------------------------------------------------------------------
 *
 * Filename: TaintSummaryFile.h
 * Description:
 *
 * Date       Pgm  Comment
 * 18 Jan 26  jpb  Creation.
 *
 */
#ifndef TAINT_SUMMARY_FILE_H
#define TAINT_SUMMARY_FILE_H

#include "TaintAnalyzer.h"
#include <filesystem>
#include <string>
#include <vector>

namespace taint
{

//
// Summary File Format (YAML-like)
//
// File format:
// ---
// version: 1
// source_file: /path/to/source.c
// functions:
//   - name: function_name
//     qualified_name: function_name
//     return_layer: SYNTACTIC
//     return_inherits: false
//     return_inherit_source: 0
//     is_taint_source: false
//     is_taint_sink: false
//     sink_requirement: RAW
//     params:
//       - index: 0
//         direction: IN
//         required_layer: RAW
//         output_layer: RAW
//         inherits_from_param: false
//         inherit_source: 0
// ...
//

class SummaryFileWriter
{
  public:
    static bool write (const std::string &filename,
                       const std::vector<FunctionSummary> &summaries,
                       const std::string &sourceFile);

    static bool writeDatabase (const std::string &filename,
                               const FunctionDatabase &db);

  private:
    static std::string layerToYaml (TaintLayer layer);
    static std::string directionToYaml (ParamDirection dir);
    static std::string indent (int level);
};

class SummaryFileReader
{
  public:
    static bool read (const std::string &filename,
                      std::vector<FunctionSummary> &summaries);

    static bool loadIntoDatabase (const std::string &filename,
                                  FunctionDatabase &db);

    // Load all .taint files from a directory
    static bool loadDirectory (const std::string &directory,
                               FunctionDatabase &db);

  private:
    static TaintLayer parseLayer (const std::string &str);
    static ParamDirection parseDirection (const std::string &str);
    static std::string trim (const std::string &str);
    static std::string getValue (const std::string &line);
    //static bool startsWith (const std::string &str, const std::string &prefix);
};

//
// Summary Database Manager
//

class SummaryManager
{
  public:
    SummaryManager (FunctionDatabase &db);

    // Save summaries for a single source file
    bool saveSummaries (const std::string &sourceFile,
                        const std::vector<FunctionSummary> &summaries);

    // Load all summaries from a directory
    bool loadSummaries (const std::string &directory);

    // Get the summary file path for a source file
    static std::string getSummaryPath (const std::string &sourceFile);

    // Get summary directory (default: .taint-summaries)
    void
    setSummaryDirectory (const std::string &dir)
    {
        summaryDir_ = dir;
    }
    const std::string &
    getSummaryDirectory () const
    {
        return summaryDir_;
    }

  private:
    FunctionDatabase &db_;
    std::string summaryDir_ = ".taint-summaries";
};

} // namespace taint

#endif // TAINT_SUMMARY_FILE_H
