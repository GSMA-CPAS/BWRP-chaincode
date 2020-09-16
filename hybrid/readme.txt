# changelog #
- switch to document id as identifier and secret for the hidden communication key
- CreateStorageKey is now based on documentID, dropped CreateStorageKeyFromHash
- added FetchPrivateDocument to allow the blockchain-adapter to query data
- added CreateStorageKeyFromHash as the rest api needs to call it
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
