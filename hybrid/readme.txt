# changelog #
- changed composite key structure
 - as per recent discussion signing identity is NOT the hyperledger identity any more
 - use txid as composite key in order to allow multiple updates
- changed return type of GetSignatures as fabric-sdk-node seems to have problems with []byte return values
- ...

-- Prerequisites --

counterfeiter is installed, if not:
GO111MODULE=off go get -u github.com/maxbrunsfeld/counterfeiter

then:
- export PATH=$PATH:$GOPATH/bin
- go generate ./... 
- go test
