#!/bin/bash

STATIC="$1"

if [ -z "$STATIC" ]; then
    STATIC=1
fi

if [ -n "$ROOT" ]; then
    cd $ROOT
fi

LIBXDP_STATIC=$STATIC make