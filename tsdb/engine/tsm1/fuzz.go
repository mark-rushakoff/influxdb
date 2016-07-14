// +build gofuzz
package tsm1

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/influxdata/influxdb/tsdb"
)

// Fuzzing definitions to detect edge/corner cases via https://github.com/dvyukov/go-fuzz.
//
// Currently, go-fuzz doesn't offer a way to automatically detect one of multiple Fuzz functions,
// so you will need to specify which function to use.
// First, build the instrumented package:
//
//     go-fuzz-build -func FuzzCacheLoader -o /tmp/FuzzCacheLoader.zip github.com/influxdata/influxdb/tsdb/engine/tsm1
//
// Then, run the tests:
//
//     go-fuzz -bin=/tmp/FuzzCacheLoader.zip -workdir=$GOPATH/src/github.com/influxdata/influxdb/tsdb/engine/tsm1/fuzz-data/CacheLoader

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

func FuzzCacheLoader(data []byte) int {
	// Write the data to a file since CacheLoader expects to load a collection of files.
	f, err := ioutil.TempFile("", "cacheloader-fuzz")
	if err != nil {
		// Should never happen. Has nothing to do with input data.
		return fuzzBoring
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(data); err != nil {
		// Should never happen. Has nothing to do with input data.
		return fuzzBoring
	}
	if err := f.Close(); err != nil {
		// Should never happen. Has nothing to do with input data.
		return fuzzBoring
	}

	cl := NewCacheLoader([]string{f.Name()})
	cl.Logger.SetOutput(ioutil.Discard)

	// CacheLoader populates a cache struct.
	// TODO: remove path argument?
	c := NewCache(tsdb.DefaultCacheMaxMemorySize, "")

	if err := cl.Load(c); err != nil {
		return fuzzBoring
	}

	return fuzzInteresting
}

func FuzzTSMReader(data []byte) int {
	dir, err := ioutil.TempDir("", "tsmreader-fuzz")
	if err != nil {
		// Should never happen. Has nothing to do with input data.
		return fuzzBoring
	}

	filename := filepath.Join(dir, "x.tsm")
	if err := ioutil.WriteFile(filename, data, 0600); err != nil {
		return fuzzBoring
	}
	defer os.RemoveAll(dir)

	f, err := os.Open(filename)
	if err != nil {
		return fuzzBoring
	}
	defer f.Close()

	r, err := NewTSMReader(f)
	if err != nil {
		return fuzzBoring
	}
	defer r.Close()

	iter := r.BlockIterator()
	for iter.Next() {
		key, _, _, _, _, err := iter.Read()
		if err != nil {
			return fuzzBoring
		}

		_, _ = r.Type(key)

		if _, err = r.ReadAll(key); err != nil {
			return fuzzBoring
		}
	}

	return fuzzInteresting
}
