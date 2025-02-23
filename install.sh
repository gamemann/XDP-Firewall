#!/bin/bash
WITH_LIBXDP=0
INSTALL=1
CLEAN=0
STATIC=0

while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        --libxdp)
            WITH_LIBXDP=1

            shift
            ;;

        --no-install)
            INSTALL=0

            shift
            ;;

        --clean)
            CLEAN=1

            shift
            ;;

        --static)
            STATIC=1
            
            shift
            ;;

        --help)
            echo "Usage: install.sh [OPTIONS]"
            echo
            echo "Options:"
            echo "  --libxdp       Build and install LibXDP before building the tool."
            echo "  --no-install   Build the tool and/or LibXDP without installing them."
            echo "  --clean        Remove build files for the tool and LibXDP."
            echo "  --static       Statically link LibXDP and LibBPF object files when building the tool."
            echo "  --help         Display this help message."

            exit 0

            shift
            ;;
        *)

            shift
            ;;
        esac
done

if [ "$CLEAN" -gt 0 ]; then
    if [ "$WITH_LIBXDP" -gt 0 ]; then
        echo "Cleaning LibXDP..."

        ./scripts/libxdp_clean.sh
    fi

    echo "Cleaning up tool..."

    ./scripts/clean.sh

    exit 0
fi

if [ "$WITH_LIBXDP" -gt 0 ]; then
    echo "Building LibXDP..."

    ./scripts/libxdp_build.sh

    if [ "$INSTALL" -gt 0 ]; then
        echo "Installing LibXDP..."

        sudo ./scripts/libxdp_install.sh
    fi
fi

echo "Building tool..."

./scripts/build.sh $STATIC

if [ "$INSTALL" -gt 0 ]; then
    echo "Installing tool..."

    sudo ./scripts/install.sh
fi