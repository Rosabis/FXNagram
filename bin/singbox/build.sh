#!/bin/bash

set -e

SINGBOX_VERSION="1.12.24"
SINGBOX_REPO="https://github.com/SagerNet/sing-box"
OUTPUT_DIR="TMessagesProj/libs"

echo ">> Building sing-box v${SINGBOX_VERSION} for Android"

mkdir -p "${OUTPUT_DIR}"

TMPDIR=$(mktemp -d)
OLDDIR="$(pwd)"
cd "${TMPDIR}"

echo ">> Downloading sing-box source"
git clone --depth 1 --branch "v${SINGBOX_VERSION}" "${SINGBOX_REPO}" sing-box
cd sing-box

echo ">> Installing custom gomobile (SagerNet fork)"
go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.7
go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.7
gomobile init

echo ">> Building sing-box AAR (arm64-v8a, armeabi-v7a)"
go run ./cmd/internal/build_libbox -target android

echo ">> Copying AAR to project"
cp libbox.aar "${OLDDIR}/${OUTPUT_DIR}/sing-box.aar"

cd "${OLDDIR}"
rm -rf "${TMPDIR}"

echo ">> sing-box AAR built successfully at ${OUTPUT_DIR}/sing-box.aar"
