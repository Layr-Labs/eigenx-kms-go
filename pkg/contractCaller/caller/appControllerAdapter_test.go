package caller

// Compile-time assertions that the adapters satisfy the interfaces the
// contract caller / KMS handler depend on.
var (
	_ AppControllerInterface = (*appControllerAdapter)(nil)
	_ AppUpgradedIterator    = (*appUpgradedIteratorAdapter)(nil)
)
