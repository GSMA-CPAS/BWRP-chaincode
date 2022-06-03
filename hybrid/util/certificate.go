// SPDX-FileCopyrightText: 2014 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
)

// CertificateBlockType is a possible value for pem.Block.Type.
const CertificateBlockType = "CERTIFICATE"

// EncodeCertificates returns the PEM-encoded byte array that represents by the specified certs.
func EncodeCertificates(certs ...*x509.Certificate) ([]byte, error) {
	b := bytes.Buffer{}

	for _, cert := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: CertificateBlockType, Bytes: cert.Raw}); err != nil {
			return []byte{}, err
		}
	}

	return b.Bytes(), nil
}
