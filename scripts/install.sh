#!/bin/bash

if [ -z "$ROOT" ]; then
    make install
else
    cd $ROOT && make install
fi