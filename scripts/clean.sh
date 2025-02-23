#!/bin/bash

if [ -z "$ROOT" ]; then
    make clean
else
    cd $ROOT && make clean
fi