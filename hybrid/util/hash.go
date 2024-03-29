// SPDX-FileCopyrightText: 2021 GSMA and all contributors.
// SPDX-License-Identifier: Apache-2.0
package util

import (
	"crypto/sha256"
	"encoding/hex"
)

// concatenate n strings
// e.g. HashConcat("a", "b", "c") => "a:b:c"
func HashConcat(s ...string) string {
	result := ""

	for index, value := range s {
		if index == 0 {
			result = value
		} else {
			result = result + ":" + value
		}
	}

	return result
}

func CalculateHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}
