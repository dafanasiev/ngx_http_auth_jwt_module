#!/usr/bin/env bash

set -xe

git clone https://github.com/json-parser/json-parser.git
cd json-parser
git checkout 60fd8a7
git am --3way --ignore-space-change --keep-cr ../json-parser.patches/0001-fix-support-Werror-unused-parameter.patch
rm -rf .git
