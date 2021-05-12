// SPDX-FileCopyrightText: 2021 GSMA and all contributors.
// SPDX-License-Identifier: Apache-2.0
package util

import (
	"runtime"
)

// FunctionName returns the name of the callee function
func FunctionName(stackpos int) string {
	// pc, file, line, ..
	programCounter, _, _, _ := runtime.Caller(stackpos)
	fn := runtime.FuncForPC(programCounter)
	//return fmt.Sprintf("%s():%d ", fn.Name(), line)
	return fn.Name()
}
