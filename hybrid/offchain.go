// SPDX-FileCopyrightText: 2021 GSMA and all contributors.
// SPDX-License-Identifier: Apache-2.0
//
// Chaincode POC
//	- hybrid approach
//	- offchain data storage
//	- hidden communication on chain (only partners can derive storage location)
//	- hlf composite keys for storage
//
//  Please see offchain_test.go for an example workflow with mocked rest interface.
//
package main

import (
	"hybrid/contract"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

const enableDebug = true

func main() {
	if enableDebug {
		// set loglevel
		log.SetLevel(log.DebugLevel)
	}

	// instantiate chaincode
	roamingChaincode := contract.InitRoamingSmartContract()

	chaincode, err := contractapi.NewChaincode(roamingChaincode)
	if err != nil {
		log.Panicf("failed to create chaincode: %v", err)
		return
	}

	// run chaincode
	err = chaincode.Start()
	if err != nil {
		log.Panicf("failed to start chaincode: %v", err)
	}
}
