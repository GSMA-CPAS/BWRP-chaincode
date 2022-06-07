#!/bin/bash
# SPDX-FileCopyrightText: 2021 GSMA and all contributors.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "> will generate mock files"
go generate ./...

echo "> will run go tests now..."
go test

