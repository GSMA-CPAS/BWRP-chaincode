#!/bin/bash
echo "> will run gofmt to fix formatting. will fix the following files:"
gofmt -l .
gofmt -w .
echo "> done."

echo "> will run golangci-lint ..."
go run github.com/golangci/golangci-lint/cmd/golangci-lint run || echo "--> please fix all errors above!"

