#!/bin/bash

#----------------------------------------------------------------------
#
# Filename: buildclang.sh
# Description: Convenience for building clang version from cmake
#
# Date       Pgm  Comment
# 02 Mar 26  jpb  Creation.
# 06 Mar 26  jpb  Added -d option to create debug version
#

CMAKE_ARGS="-DCMAKE_PREFIX_PATH=\"/usr/lib/llvm-20;/usr/lib/llvm-20/lib/cmake/clang\" -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang"

# Add -d to the script start for DEBUG in build
while getopts "d" opt; do
    case $opt in
        d) CMAKE_ARGS="$CMAKE_ARGS -DDEBUG_BUILD=ON" ;;
        *) echo "Usage: $0 [-d]"; exit 1 ;;
    esac
done

# Run cmake
eval cmake .. $CMAKE_ARGS
