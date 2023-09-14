#!/bin/bash

set -x

VERSION=$3
if [ -z "$VERSION" ]; then
    echo "need specify version number !"
    echo "such as: ./t-storage-overlaybd-tcmu-build.sh 0 1 1.0.0"
    exit 1;
fi
RELEASE=$4
if [ -z "$RELEASE" ]; then
    RELEASE=`git log --pretty=format:%h -1`
else
    RELEASE="$RELEASE.`git log --pretty=format:%h -1`"
fi
CUR_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$CUR_DIR/../
cd $ROOT

# arch
uname -a | grep x86_64
if [ $? -eq 0 ]; then
    GOARCH=amd64
    GO_PACKAGE=go1.21.1.linux-amd64.tar.gz
else
    GOARCH=arm64
    GO_PACKAGE=go1.21.1.linux-arm64.tar.gz
fi

BUILD_DIR=${ROOT}/build/src/overlaybd-snapshotter
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}
ln -sf ${ROOT}/* ${BUILD_DIR}

# download go
if ! go version; then
    mkdir -p ${ROOT}/_golang
    if [[ ! -f ${GO_PACKAGE} ]]; then
        wget --no-check-certificate -q -O ${GO_PACKAGE} https://qianchen-public.oss-cn-hangzhou.aliyuncs.com/golang/${GO_PACKAGE}
        if [[ $? != 0 ]]; then
            echo "ERROR: download go failed."
            exit 1
        fi
    fi
    tar -C ${ROOT}/_golang/ -xzf ${GO_PACKAGE}
    export GOPATH="${ROOT}/build"
    export GOROOT="${ROOT}/_golang/go"
    export PATH="${PATH}:${GOROOT}/bin"
    export GO_EXE="${GOROOT}/bin/go"
    ${GO_EXE} env -w GO111MODULE=on
    ${GO_EXE} env -w GOPROXY=https://goproxy.cn,direct
else
    GO_EXE=go
fi

# build
BIN=${ROOT}/bin
rm -rf ${BIN}
mkdir -p ${BIN}
target_snapshotter="overlaybd-snapshotter"
target_ctr="ctr"

cd ${BUILD_DIR}
GOOS='linux'
GOOS=${GOOS} GOARCH=${GOARCH} ${GO_EXE} build -o ${BIN}/${target_snapshotter} ./cmd/${target_snapshotter}
GOOS=${GOOS} GOARCH=${GOARCH} ${GO_EXE} build -o ${BIN}/${target_ctr} ./cmd/${target_ctr}
cp script/{config.json,overlaybd-snapshotter.service} ${BIN}/

# package
TOP_DIR=/tmp/${target_snapshotter}/
if [[ -d $TOP_DIR ]]; then
    rm -r $TOP_DIR || {
        echo "Failed to rm -r $TOP_DIR"
        exit 1
    }
fi
mkdir -p $TOP_DIR || {
    echo "Failed to mkdir $TOP_DIR"
    exit 1
}
cd $ROOT
rpmbuild -bb --define "_topdir ${TOP_DIR}" --define "_rpm_version ${VERSION}" --define "_rpm_release ${RELEASE}"  rpm/overlaybd-snapshotter.spec

cd $CUR_DIR
for rpm in `find $TOP_DIR/RPMS -name "*${RELEASE}*.rpm"`; do
    mv $rpm .
done
