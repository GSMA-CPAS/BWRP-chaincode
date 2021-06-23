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
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

const enableDebug = true

func main() {
	if enableDebug {
		// set loglevel
		log.SetLevel(log.DebugLevel)
	}
	roamingChaincode := contract.InitRoamingSmartContract()

	// instantiate chaincode
	chaincode, err := contractapi.NewChaincode(roamingChaincode)
	if err != nil {
		log.Panicf("failed to create chaincode: %v", err)
		return
	}

	// try to detect if we should start in external chaincode mode
	ccid, ccidPresent := os.LookupEnv("CHAINCODE_CCID")
	address, addressPresent := os.LookupEnv("CHAINCODE_ADDRESS")

	if ccidPresent || addressPresent {
		// chaincode will run as external service

		// make sure both variables are set up properly
		if !addressPresent || !ccidPresent {
			log.Panicf("please make sure to export CHAINCODE_CCID and CHAINCODE_ADDRESS for external chaincode mode")
			return
		}

		// create local server
		server := &shim.ChaincodeServer{
			CCID:    ccid,
			Address: address,
			CC:      chaincode,
			TLSProps: shim.TLSProperties{
				Disabled: true,
			},
		}

		// run server
		err := server.Start()

		if err != nil {
			log.Panicf("failed to start external chaincode: %v", err)
		}

	} else {
		// use the default way (dind)

		// run chaincode
		err = chaincode.Start()

		if err != nil {
			log.Panicf("failed to start chaincode: %v", err)
		}
	}
}
