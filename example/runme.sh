#!/bin/sh

export LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH

echo "== building"
make

echo "== ldd output"
ldd ./main

echo "== symfind facto"
../symfind facto ./main

echo "== symtrace output"
../symtrace -r facto -- ./main

echo "== symhijack output"
../symhijack -r good.so facto -- ./main

