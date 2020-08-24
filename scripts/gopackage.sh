#!/usr/bin/env bash

set -e

source $(dirname $0)/version.sh

VERSION_NO_V=$(echo $VERSION | sed "s/^[v|V]//")

echo "==> Packaging binaries version ${VERSION_NO_V} ..."

DIST=$(pwd)/dist/artifacts

mkdir -p $DIST/${VERSION}

for i in build/bin/*; do
    if [ ! -e $i ]; then
        continue
    fi

    BASE=build/archive
    DIR=${BASE}/${VERSION}

    rm -rf $BASE
    mkdir -p $BASE $DIR

    EXT=
    if [[ $i =~ .*windows.* ]]; then
        EXT=.exe
    fi

    cp $i ${DIR}/ssh-client_${VERSION}${EXT}

    (
        cd $DIR
        NAME=$(basename $i | cut -f1 -d_)
        ARCH=$(basename $i | cut -f2,3 -d_ | cut -f1 -d.)
        ARCHIVE=${NAME}_${VERSION_NO_V}_${ARCH}.zip
        echo "Packaging dist/artifacts/${VERSION}/${ARCHIVE} ..."
        zip -q $DIST/${VERSION}/${ARCHIVE} *
    )
done

(
    cd $DIST/${VERSION}/
    shasum -a 256 * > ssh-client_${VERSION_NO_V}_SHA256SUMS
)