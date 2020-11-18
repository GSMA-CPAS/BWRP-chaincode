#!/bin/bash
echo "> will run gofmt to fix formatting. will fix the following files:"
gofmt -l .
gofmt -w .
echo "> done."

echo "> will run go lint ..."
golint ./... | grep -v "test/mocks/"
echo "> please fix all errors above (if any)."

