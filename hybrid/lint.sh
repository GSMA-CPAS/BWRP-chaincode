#!/bin/bash
# SPDX-FileCopyrightText: 2021 the BWRP-chaincode contributors.
#
# SPDX-License-Identifier: Apache-2.0
#
echo "> will run gofmt to fix formatting. will fix the following files:"
gofmt -l .
gofmt -w .
echo "> done."

echo "> will run golangci-lint ..."
LINTER=$(go env GOPATH)/bin/golangci-lint
if [ ! -x $LINTER ]; then
    echo "ERROR: linter not found ($LINTER)"
    echo "       please install golangci-lint via:"
    echo "       curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.35.2"
    echo ""
    exit
fi

$LINTER run || echo "--> please fix all errors above and re-run this test!"
