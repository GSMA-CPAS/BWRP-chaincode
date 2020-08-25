package offchain

// ### generated by:
// openssl req -x509 -newkey ec:<(openssl ecparam -name secp384r1) -nodes -keyout example.key -out example.crt -subj "/CN=user@ORG1/C=DE/ST=NRW/L=Bielefeld/O=ORG1/OU=ORG1OU" -addext keyUsage=digitalSignature
// openssl req -x509 -newkey ec:<(openssl ecparam -name secp384r1) -nodes -keyout example.key -out example.crt -subj "/CN=user@ORG2/C=DE/ST=NRW/L=Bielefeld/O=ORG2/OU=ORG2OU" -addext keyUsage=digitalSignature

// Organization handles some dummy definitions for testing
type Organization struct {
	Name        string
	Certificate []byte
	PrivateKey  []byte
}

// ORG1 is dummy organization 1
var ORG1 = Organization{
	Name: "ORG1",
	Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIICZjCCAeugAwIBAgIUGqvDgrUdANVyayPeRCgi1GuRnDcwCgYIKoZIzj0EAwIw
YzESMBAGA1UEAwwJdXNlckBPUkcxMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJX
MRIwEAYDVQQHDAlCaWVsZWZlbGQxDTALBgNVBAoMBE9SRzExDzANBgNVBAsMBk9S
RzFPVTAeFw0yMDA4MjUxMjQ1MzBaFw0yMDA5MjQxMjQ1MzBaMGMxEjAQBgNVBAMM
CXVzZXJAT1JHMTELMAkGA1UEBhMCREUxDDAKBgNVBAgMA05SVzESMBAGA1UEBwwJ
QmllbGVmZWxkMQ0wCwYDVQQKDARPUkcxMQ8wDQYDVQQLDAZPUkcxT1UwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAATZ4BKcxPAj0txG1CStZZYr5QA/C1DmrBrTofor+bx9
Tr6HYEfehE4zjzAzWAl0W6v+WGtgXBKUk83ZHME5dlXD0gW9dqkRsNqp5dKBJZ3k
Qg041OYEqkbXbBOjAKa2AQGjYDBeMB0GA1UdDgQWBBQZIh+sxlppbyUUzus1ubW8
8iM84jAfBgNVHSMEGDAWgBQZIh+sxlppbyUUzus1ubW88iM84jAPBgNVHRMBAf8E
BTADAQH/MAsGA1UdDwQEAwIHgDAKBggqhkjOPQQDAgNpADBmAjEAgIzDQo5xsHES
tYs7Z5RzOiSQisKRwvP9mjCdctCwkoQXOwVqsDBEo03rdNXEJ32VAjEAhENi6j5V
d7J3Um7g9u7OgRo8NM0am7ewrybFSJDlPgi6x3qlhuOfWWK1Yc4Yv652
-----END CERTIFICATE-----`),
	PrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAIuLa/WeJczj+au9V6
EGHHf6ONlRFKDqvcZOOFxBd9X/S/Fr4GMOuhpzA6WEaLMSehZANiAATZ4BKcxPAj
0txG1CStZZYr5QA/C1DmrBrTofor+bx9Tr6HYEfehE4zjzAzWAl0W6v+WGtgXBKU
k83ZHME5dlXD0gW9dqkRsNqp5dKBJZ3kQg041OYEqkbXbBOjAKa2AQE=
-----END PRIVATE KEY-----`)}

// ORG2 is dummy organization 2
var ORG2 = Organization{
	Name: "ORG2",
	Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIICZTCCAeugAwIBAgIUeCytEOhRGJi5dqxR2Kbo1phVMj4wCgYIKoZIzj0EAwIw
YzESMBAGA1UEAwwJdXNlckBPUkcyMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJX
MRIwEAYDVQQHDAlCaWVsZWZlbGQxDTALBgNVBAoMBE9SRzIxDzANBgNVBAsMBk9S
RzJPVTAeFw0yMDA4MjUxMjQ3NDhaFw0yMDA5MjQxMjQ3NDhaMGMxEjAQBgNVBAMM
CXVzZXJAT1JHMjELMAkGA1UEBhMCREUxDDAKBgNVBAgMA05SVzESMBAGA1UEBwwJ
QmllbGVmZWxkMQ0wCwYDVQQKDARPUkcyMQ8wDQYDVQQLDAZPUkcyT1UwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAAQ5sYj1rC4JUqLsKq+Fn156LPiBYS/uTC01NatLjJoG
r/WTAC2iObEeqb26PMttefKVUHNZ55VCz7s4g3LAwGjDAOiaHv418VRsbDrd7Z+m
zLfpTkvVTT6IDofYoNp8CUmjYDBeMB0GA1UdDgQWBBQrOSz8rWDOe1mRHTJb7TsJ
1hjV6zAfBgNVHSMEGDAWgBQrOSz8rWDOe1mRHTJb7TsJ1hjV6zAPBgNVHRMBAf8E
BTADAQH/MAsGA1UdDwQEAwIHgDAKBggqhkjOPQQDAgNoADBlAjA5vUSqh9WPkhhj
jTxHeTEYEz0JBCactYl2Gs2KaIMqAZ2xepAlTbN5vEpv/6b8MNMCMQCfmTOXu8jH
5mitVEVlSvG+uG/3nKsBZfmhEohzfOSIT/5PJABUFfbwdQylLpMvKio=
-----END CERTIFICATE-----`),
	PrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDREKNtlcGv4pFBA8KQ
8gCqmRG7mgOkNKWAyo2Lo56y/WUrQpbxjVMeEKHxxvHD3VChZANiAAQ5sYj1rC4J
UqLsKq+Fn156LPiBYS/uTC01NatLjJoGr/WTAC2iObEeqb26PMttefKVUHNZ55VC
z7s4g3LAwGjDAOiaHv418VRsbDrd7Z+mzLfpTkvVTT6IDofYoNp8CUk=
-----END PRIVATE KEY-----`)}
