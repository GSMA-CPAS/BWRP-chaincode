#!/bin/bash
# SPDX-FileCopyrightText: 2021 GSMA and all contributors.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

if [ $# -lt 2 ]; then
    echo "> usage: $0 <ORGNAME> <CANSIGN 0,1>"
    exit 0
fi

ORG=$1
CANSIGN=$2

DIR=$(mktemp -d)
cd $DIR
echo $DIR 

cat <<EOF > ca.ext
[ default ]
basicConstraints = critical,CA:true
keyUsage         = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

if [ "$CANSIGN" -eq "1" ]; then
    echo "adding CanSignDocument"
    attr_hex=$(echo -n '{"attrs":{"CanSignDocument":"yes"}}' | xxd -ps -c 200 | tr -d '\n')
    echo -ne "[default]\n1.2.3.4.5.6.7.8.1=DER:$attr_hex\n" > user.ext
else
    echo "NOT adding CanSignDocument"
    echo -ne "[default]\n" > user.ext
fi

# create ca 
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -out root.csr -keyout root.key  -subj "/CN=ROOT@$ORG/C=DE/ST=NRW/L=Bielefeld/O=$ORG/OU=${ORG}OU" 
openssl x509 -signkey root.key -days 365 -req -in root.csr -out root.pem  --extfile ca.ext
openssl x509 -in root.pem > root.crt

# create signing request
openssl req -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -keyout user.key -out user.csr  -subj "/CN=user@$ORG/C=DE/ST=NRW/L=Bielefeld/O=$ORG/OU=${ORG}OU"

# use ca to sign it
openssl x509 -CA root.crt -CAkey root.key -CAcreateserial -req -in  user.csr -out user.pem -extfile user.ext -days 365
openssl x509 -in user.pem > user.crt

# verify chain
openssl verify -x509_strict -CAfile root.pem user.crt

# export for golang
echo "#################################################################"
echo ""
echo -ne '    RootCertificate: `'
cat root.crt | head -c -1
echo -e '`,'
echo -ne '    RootPrivateKey: `'
cat root.key | head -c -1
echo -e '`,'
echo -ne '    UserCertificate: `'
cat user.crt | head -c -1
echo -e '`,'
echo -ne '    UserPrivateKey: `'
cat user.key | head -c -1
echo -e '`,'
echo ""
echo "#################################################################"

echo $DIR
