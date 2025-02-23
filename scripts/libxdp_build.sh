#!/bin/bash

if [ -z "$ROOT" ]; then
    make libxdp
else
    cd $ROOT && make libxdp
fi