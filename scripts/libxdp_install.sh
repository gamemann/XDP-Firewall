#!/bin/bash

if [ -z "$ROOT" ]; then
    make libxdp_install
else
    cd $ROOT && make libxdp_install
fi