# Building the PAPI applications

## Requirements
While LLVM >= 17 should work with PAPI, we have moved `cmake` up to LLVM 20. The following packages should be installed prior to building PAPI:

clang-20
libclang-20-dev
llvm-20-dev

## Running a build
PAPI uses `cmake`; do the following to build PAPI:

```
mkdir build && cd build
cmake ..
../tools/buildclang.sh

```
`papi-annotate` and `taint-analyzer` are in the build directory.

## Installing

```
cd build
sudo make install
```

