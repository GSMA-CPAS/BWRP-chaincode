# BWRP-chaincode

The chaincode is executed by each orgnaization on at least one Hyperledger Fabric peer.

It is responsible for:
* Writing information on the ledger (public transactions)
  * Document Signatures
  * Document Hashes
* Sharing private information between organizations (private queries)
  * Document details
  * Private data is stored in a private database (no ledger interaction)
