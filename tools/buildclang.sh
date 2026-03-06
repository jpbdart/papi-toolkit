#!/bin/bash

#----------------------------------------------------------------------
#
# Filename: buildclang.sh
# Description: Convenience for building clang version from cmake
#
# Date       Pgm  Comment
# 02 Mar 26  jpb  Creation.
#

cmake .. -DCMAKE_PREFIX_PATH="/usr/lib/llvm-20;/usr/lib/llvm-20/lib/cmake/clang" -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang

