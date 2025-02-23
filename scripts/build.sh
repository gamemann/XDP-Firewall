#!/bin/bash

STATIC="$1"

if [ -z "$STATIC" ]; then
    STATIC=0
fi

if [ -z "$ROOT" ]; then
    LIBBPF_LIBXDP_STATIC=$STATIC make
else
    cd $ROOT && LIBBPF_LIBXDP_STATIC=$STATIC make
fi