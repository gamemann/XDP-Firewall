#!/bin/bash

if [ -z "$ROOT" ]; then
    make libxdp_clean
else
    cd $ROOT && make libxdp_clean
fi