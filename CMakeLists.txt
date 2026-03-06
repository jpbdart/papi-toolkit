#######################################################################
#
# Filename: CMakeLists.txt
# Description:
#
# Date       Pgm  Comment
# 18 Jan 26  jpb  Creation.
# 02 Mar 26  jpb  Updated for papi-annotate.
#
#
cmake_minimum_required(VERSION 3.16)
project(TaintAnalyzer VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find LLVM and Clang
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Using ClangConfig.cmake in: ${Clang_DIR}")

# Add LLVM definitions and include directories
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${CLANG_INCLUDE_DIRS})

# Link directories
link_directories(${LLVM_LIBRARY_DIRS})

# Our include directory
include_directories(${CMAKE_SOURCE_DIR}/include)

# Get required LLVM components
llvm_map_components_to_libnames(LLVM_LIBS
    core
    support
    option
)

# Clang libraries we need
set(CLANG_LIBS
    clangTooling
    clangFrontend
    clangSerialization
    clangDriver
    clangParse
    clangSema
    clangAnalysis
    clangAST
    clangASTMatchers
    clangBasic
    clangEdit
    clangLex
    clangRewrite
)

# Build the analyzer
add_executable(taint-analyzer
    src/main.cpp
    src/TaintAnalyzer.cpp
    src/TaintSummaryFile.cpp
    src/TaintFixEmitter.cpp
    src/TaintFixEmitter_output.cpp
    src/ProvenanceTracker.cpp
)

target_link_libraries(taint-analyzer
    ${CLANG_LIBS}
    ${LLVM_LIBS}
)

# Build the annotator tool (standalone, no LLVM deps)
add_executable(papi-annotate src/papi-annotate.cpp
)


# Installation
install(TARGETS taint-analyzer papi-annotate DESTINATION bin)
