# changelog #
- rename documentID to referenceID
- expose FetchPrivateDocuments
- better testing api scheme, more tests added
- added StoreDocumentHash(): this will store a document hash on the ledger and sends an STORE:DOCUMENTHASH event
  this can be used as an additional proof by ORG2 in order to verify that ORG1 is the author of the document
- switch to documentID as identifier and secret for the hidden communication key
- CreateStorageKey is now based on documentID, dropped CreateStorageKeyFromHash
- added FetchPrivateDocument to allow the blockchain-adapter to query data
- added CreateStorageKeyFromHash as the rest api needs to call it
- changed composite key structure
 - as per recent discussion signing identity is NOT the hyperledger identity any more
 - use txid as composite key in order to allow multiple updates
- changed return type of GetSignatures as fabric-sdk-node seems to have problems with []byte return values
- ...


# notes #
- why 32 byte referenceID instead of sha256(doc)?
  - as gal pointed out, template based documents migth allow bruteforce attacks
  - even worse, as martin pointed out, a sucessfully guessed document reveals the full contract details
- why no uuid4 instead of 32 byte referenceID?
  - uuid4 is 2^128, referenceID is 2^256
  - RFC4122: "...Do not assume that UUIDs are hard to guess; they should not be used as security capabilities..."

# testing #

run:
go test
