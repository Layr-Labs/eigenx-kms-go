// Package registrarabi embeds the concrete EigenKMSRegistrar contract ABI so
// the KMS node can register the registrar with the chain-indexer poller and
// decode its emitted events (notably AvsConfigSet) without depending on the
// gitignored contracts/out build artifacts at build time.
package registrarabi

import _ "embed"

//go:embed eigenkmsregistrar.abi.json
var EigenKMSRegistrarABI string

// AvsConfigSetEventName is the event the node listens for to pick up platform config changes.
const AvsConfigSetEventName = "AvsConfigSet"
