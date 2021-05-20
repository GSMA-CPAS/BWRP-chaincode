// SPDX-FileCopyrightText: 2021 GSMA and all contributors.
// SPDX-License-Identifier: Apache-2.0
package stubs

import (
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -o ../mocks/chaincodestub.go -fake-name ChaincodeStub . chaincodeStub
type chaincodeStub interface {
	shim.ChaincodeStubInterface
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -o ../mocks/transaction.go -fake-name TransactionContext . transactionContext
type transactionContext interface {
	contractapi.TransactionContextInterface
}
