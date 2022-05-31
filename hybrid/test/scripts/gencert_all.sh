#!/bin/bash
# SPDX-FileCopyrightText: 2021 GSMA and all contributors.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

RUNDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";

cat << EOF 
// SPDX-FileCopyrightText: 2021 GSMA and all contributors.
// SPDX-License-Identifier: Apache-2.0
package data

// ### certificates generated by:
// test/scripts/gencert.sh ORG1 1 0
// test/scripts/gencert.sh ORG2 1 0
// test/scripts/gencert.sh ORG3 0 0
// test/scripts/gencert.sh ORG3 1 1
// ###
//
// Organization handles some dummy definitions for testing
type Organization struct {
	Name                    string
	RootCertificate         string
	IntermediateCertificate string
	UserCertificate         string
	RootPrivateKey          string
	IntermediatePrivateKey  string
	UserPrivateKey          string
	OffchainDBConfigURI     string
}

EOF

add_org () {
cat << EOF
// ORG$1 is dummy organization $1
var ORG$1 = Organization{
	Name: "ORG$1",
EOF

$RUNDIR/gencert.sh ORG$1 $2 $3 2> /dev/null

cat << EOF
    OffchainDBConfigURI: "localhost:300$1"}

EOF
}

add_org 1 1 0
add_org 2 1 0
add_org 3 0 0
add_org 4 1 1
