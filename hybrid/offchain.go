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
	"io/ioutil"
	"os"
	"strconv"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	log "github.com/sirupsen/logrus"
)

const enableDebug = true

func loadTLSFile(filePth string) ([]byte, error) {
	f, err := os.Open(filePth)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(f)
}

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
	tlsDisable, tlsDisablePresent := os.LookupEnv("CORE_CHAINCODE_TLS_DISABLED")

	if ccidPresent || addressPresent || tlsDisablePresent {
		// chaincode will run as external service
		//
		// make sure both variables are set up properly
		if !addressPresent || !ccidPresent || !tlsDisablePresent {
			log.Panicf("please make sure to export CORE_CHAINCODE_TLS_DISABLED, CHAINCODE_CCID and CHAINCODE_ADDRESS for external chaincode mode")
			return
		}

		CorePeerTLSKeyFile, err := loadTLSFile(os.Getenv("CORE_CHAINCODE_TLS_KEY_FILE")) //nolint:govet // ignore err shadow declaration
		if err != nil {
			log.Panicf("Error loadTLSFile : %s", err)
		}

		CorePeerTLSCertFile, err := loadTLSFile(os.Getenv("CORE_CHAINCODE_TLS_CERT_FILE"))

		if err != nil {
			log.Panicf("Error loadTLSFile : %s", err)
		}

		CorePeerTLSRootCertFile, err := loadTLSFile(os.Getenv("CORE_CHAINCODE_TLS_CLIENT_CACERT_FILE"))

		if err != nil {
			log.Panicf("Error loadTLSFile : %s", err)
		}

		tlsDisableParsed, err := strconv.ParseBool(tlsDisable)
		if err != nil {
			log.Panicf("invalid value for tlsDisable")
			return
		}

		// create local server
		server := &shim.ChaincodeServer{
			CCID:    ccid,
			Address: address,
			CC:      chaincode,
			TLSProps: shim.TLSProperties{
				Disabled:      tlsDisableParsed,
				Key:           CorePeerTLSKeyFile,
				Cert:          CorePeerTLSCertFile,
				ClientCACerts: CorePeerTLSRootCertFile,
			},
		}

		// run server
		err = server.Start()

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
