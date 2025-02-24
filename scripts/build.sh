#!/bin/bash

STATIC="$1"

if [ -z "$STATIC" ]; then
    STATIC=1
fi

if [ -z "$ROOT" ]; then
    LIBXDP_STATIC=$STATIC make
else
    cd $ROOT && LIBXDP_STATIC=$STATIC make
fi