package certificate

import (
	"crypto"
	"crypto/x509"

	"hybrid/errorcode"
)

// Strings reflect the x509 standard and are distinct from golang's x509 library string
var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	name       string
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.DSAWithSHA256, "dsaWithSha256", x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA256, "ecdsaWithSha256", x509.ECDSA, crypto.SHA256},
	{x509.SHA256WithRSA, "sha256WithRsaEncryption", x509.RSA, crypto.SHA256},
}

func GetSignatureAlgorithmFromString(name string) (x509.SignatureAlgorithm, error) {
	for _, details := range signatureAlgorithmDetails {
		if details.name == name {
			return details.algo, nil
		}
	}
	return -1, errorcode.SignatureInvalid.WithMessage("signature algorithm not supported").LogReturn()
}

func GetStringFromSignatureAlgorithm(algo x509.SignatureAlgorithm) (string, error) {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			return details.name, nil
		}
	}
	return "", errorcode.SignatureInvalid.WithMessage("signature algorithm not supported").LogReturn()
}

func GetHashAlgorithmFromSignatureAlgortithm(algo x509.SignatureAlgorithm) (*crypto.Hash, error) {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			return &details.hash, nil
		}
	}
	return nil, errorcode.SignatureInvalid.WithMessage("signature algorithm not supported").LogReturn()
}

func GetPubKeyAlgorithmFromSignatureAlgortithm(algo x509.SignatureAlgorithm) (*x509.PublicKeyAlgorithm, error) {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			return &details.pubKeyAlgo, nil
		}
	}
	return nil, errorcode.SignatureInvalid.WithMessage("signature algorithm not supported").LogReturn()
}
