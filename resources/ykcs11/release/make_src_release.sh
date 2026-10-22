#!/bin/bash
# Script to produce the source distribution package

if [ "$#" -lt 1 ]; then
    echo "This script produces a source distribution package"
    echo ""
    echo "      Usage: ./resources/ykcs11/release/make_src_release.sh <version>"
    echo "";
    exit 0
fi

VERSION=$1 # Full ykcs11 version, tex 2.1.0

set +e
set -x

tar --exclude .git        \
    --exclude .github     \
    --exclude .gitignore  \
    --exclude resources/ykcs11/release   \
    --exclude crates/yubihsm-pkcs11 \
    --exclude Cargo.lock \
    --transform="s/^\./ykcs11-$VERSION/" -czf ../ykcs11-$VERSION.tar.gz .


exitcode=$?
if [ "$exitcode" != "1" ] && [ "$exitcode" != "0" ]; then
    exit $exitcode
fi

set -e