<!--
 SPDX-FileCopyrightText: 2021 GSMA and all contributors.

 SPDX-License-Identifier: Apache-2.0
-->
# BWRP-chaincode

The chaincode is executed by each orgnaization on at least one Hyperledger Fabric peer.

It is responsible for:
* Writing information on the ledger (public transactions)
  * Document Signatures
  * Document Hashes
* Sharing private information between organizations (private queries)
  * Document details
  * Private data is stored in a private database (no ledger interaction)

## Code of Conduct

This project has adopted the [Contributor Covenant](https://www.contributor-covenant.org/) in version 2.0 as our code of conduct. Please see the details in our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). All contributors must abide by the code of conduct.

## How to Contribute

Contribution and feedback is encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](./docs/CONTRIBUTING.md). By participating in this project, you agree to abide by its [Code of Conduct](./docs/CODE_OF_CONDUCT.md) at all times.

## Contributors

Our commitment to open source means that we are enabling -in fact encouraging- all interested parties to contribute and become part of its developer community.

## Licensing

Copyright (c) 2021 GSMA and its licensors.

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License.
