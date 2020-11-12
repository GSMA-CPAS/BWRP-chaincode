package util

import (
	"runtime"
)

func FunctionName() string {
	// pc, file, line, ..
	programCounter, _, _, _ := runtime.Caller(1)
	fn := runtime.FuncForPC(programCounter)
	//return fmt.Sprintf("%s():%d ", fn.Name(), line)
	return fn.Name()
}
