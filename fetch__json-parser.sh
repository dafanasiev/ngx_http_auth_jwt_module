#!/usr/bin/env bash

set -xe

git clone https://github.com/json-parser/json-parser.git
cd json-parser
git checkout 936f799
rm -rf .git
