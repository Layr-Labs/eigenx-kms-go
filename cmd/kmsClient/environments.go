package main

import (
	"fmt"
	"sort"
	"strings"
)

// environment holds the non-secret connection defaults for a named network.
// The RPC URL is intentionally excluded — production RPC URLs embed API-key
// credentials and must not be committed. Users still supply --rpc-url.
type environment struct {
	AVSAddress    string
	OperatorSetID uint32
}

// environments is the registry of known connection presets, selected via
// --environment. Values are sourced from the operator deployment charts.
var environments = map[string]environment{
	"sepolia": {
		AVSAddress:    "0x47c9806e7DC4e6fE9a0a2399831F32d06DaE5730",
		OperatorSetID: 0,
	},
}

// supportedEnvironmentsString returns the known environment names as a sorted,
// comma-separated string for error and usage messages.
func supportedEnvironmentsString() string {
	names := make([]string, 0, len(environments))
	for name := range environments {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// resolveConnection determines the effective AVS address and operator-set id
// from the --environment preset and any explicitly-set flags. Explicitly-set
// flags always win over the preset; the preset wins over the built-in default.
// avsSet/setIDSet report whether the corresponding flag was passed on the
// command line (cli.Context.IsSet).
//
// Resolution:
//   - avs-address: explicit flag → preset → else error.
//   - operator-set-id: explicit flag → preset → else 0.
func resolveConnection(envName, avsFlag string, avsSet bool, setIDFlag uint32, setIDSet bool) (string, uint32, error) {
	var preset environment
	havePreset := false
	if envName != "" {
		p, ok := environments[envName]
		if !ok {
			return "", 0, fmt.Errorf("unknown environment %q: supported environments are: %s", envName, supportedEnvironmentsString())
		}
		preset = p
		havePreset = true
	}

	// Resolve AVS address: explicit flag wins, then preset, else error.
	avsAddress := ""
	switch {
	case avsSet:
		avsAddress = avsFlag
	case havePreset:
		avsAddress = preset.AVSAddress
	default:
		return "", 0, fmt.Errorf("avs-address is required (provide --avs-address or --environment)")
	}

	// Resolve operator-set id: explicit flag wins, then preset, else 0.
	var operatorSetID uint32
	switch {
	case setIDSet:
		operatorSetID = setIDFlag
	case havePreset:
		operatorSetID = preset.OperatorSetID
	default:
		operatorSetID = 0
	}

	return avsAddress, operatorSetID, nil
}
