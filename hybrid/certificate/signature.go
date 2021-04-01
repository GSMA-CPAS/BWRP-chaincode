package certificate

import (
	"crypto"
	"crypto/x509"

	"hybrid/errorcode"
)

// largely taken from crypto/x509, unfortunately it isn't exported
var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	name       string
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, "MD2-RSA", x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, "MD5-RSA", x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, "SHA1-RSA", x509.RSA, crypto.SHA1},
	{x509.SHA1WithRSA, "SHA1-RSA", x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, "SHA256-RSA", x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, "SHA384-RSA", x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, "SHA512-RSA", x509.RSA, crypto.SHA512},
	{x509.SHA256WithRSAPSS, "SHA256-RSAPSS", x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSAPSS, "SHA384-RSAPSS", x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSAPSS, "SHA512-RSAPSS", x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, "DSA-SHA1", x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, "DSA-SHA256", x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, "ECDSA-SHA1", x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, "ECDSA-SHA256", x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, "ECDSA-SHA384", x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, "ECDSA-SHA512", x509.ECDSA, crypto.SHA512},
	{x509.PureEd25519, "Ed25519", x509.Ed25519, crypto.Hash(0) /* no pre-hashing */},
}

func GetSignatureAlgorithmFromString(name string) (x509.SignatureAlgorithm, error) {
	for _, details := range signatureAlgorithmDetails {
		if details.name == name {
			return details.algo, nil
		}
	}
	return -1, errorcode.SignatureInvalid.WithMessage("signature algorithm not supported").LogReturn()
}
