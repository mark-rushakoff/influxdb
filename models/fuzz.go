// +build gofuzz
package models

// Fuzzing definitions to detect edge/corner cases via https://github.com/dvyukov/go-fuzz.
//
// Currently, go-fuzz doesn't offer a way to automatically detect one of multiple Fuzz functions,
// so you will need to specify which function to use.
// First, build the instrumented package:
//
//     go-fuzz-build -func FuzzParsePoints -o /tmp/FuzzParsePoints.zip github.com/influxdata/influxdb/models
//
// Then, run the tests:
//
//     go-fuzz -bin=/tmp/FuzzParsePoints.zip -workdir=$GOPATH/src/github.com/influxdata/influxdb/models/fuzz-data/ParsePoints

// The return value of the fuzz functions affects how the fuzzer finds new cases.
const (
	// "Correct" input that was correctly parsed.
	fuzzInteresting = 1

	// Not really interesting input.
	fuzzBoring = 0

	// Do not use this input, even if it results in new coverage.
	// (When would you use this?)
	fuzzIgnore = -1
)

func FuzzParsePoints(data []byte) int {
	_, err := ParsePoints(data)
	if err != nil {
		// There are practically infinite parser error conditions.
		// Don't ever add parsing errors to the corpus.
		return fuzzIgnore
	}

	// Practically infinite valid parseable lines.
	return fuzzBoring
}
