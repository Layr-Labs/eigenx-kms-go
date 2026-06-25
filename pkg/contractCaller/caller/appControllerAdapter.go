package caller

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	iappctl "github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/IAppController"
)

// appControllerAdapter wraps the generated IAppController binding so it satisfies
// AppControllerInterface. The binding's caller methods match the interface 1:1; the
// only adaptation needed is FilterAppUpgraded, whose generated iterator exposes Event
// as a field and uses a binding-specific event type — we bridge those to the
// interface's AppUpgradedIterator (Event() method) and AppUpgradedEvent.
//
// The AppController lives on L1 (Ethereum), so construct this with the L1 contract
// backend. See NewAppControllerAdapter.
type appControllerAdapter struct {
	caller   *iappctl.IAppControllerCaller
	filterer *iappctl.IAppControllerFilterer
}

// NewAppControllerAdapter builds an AppControllerInterface bound to the AppController
// contract at the given address on the supplied (L1) backend.
func NewAppControllerAdapter(address common.Address, backend bind.ContractBackend) (AppControllerInterface, error) {
	c, err := iappctl.NewIAppControllerCaller(address, backend)
	if err != nil {
		return nil, err
	}
	f, err := iappctl.NewIAppControllerFilterer(address, backend)
	if err != nil {
		return nil, err
	}
	return &appControllerAdapter{caller: c, filterer: f}, nil
}

func (a *appControllerAdapter) GetAppCreator(opts *bind.CallOpts, app common.Address) (common.Address, error) {
	return a.caller.GetAppCreator(opts, app)
}

func (a *appControllerAdapter) GetAppOperatorSetId(opts *bind.CallOpts, app common.Address) (uint32, error) {
	return a.caller.GetAppOperatorSetId(opts, app)
}

func (a *appControllerAdapter) GetAppLatestReleaseBlockNumber(opts *bind.CallOpts, app common.Address) (uint32, error) {
	return a.caller.GetAppLatestReleaseBlockNumber(opts, app)
}

func (a *appControllerAdapter) GetAppStatus(opts *bind.CallOpts, app common.Address) (uint8, error) {
	return a.caller.GetAppStatus(opts, app)
}

func (a *appControllerAdapter) FilterAppUpgraded(opts *bind.FilterOpts, apps []common.Address) (AppUpgradedIterator, error) {
	it, err := a.filterer.FilterAppUpgraded(opts, apps)
	if err != nil {
		return nil, err
	}
	return &appUpgradedIteratorAdapter{it: it}, nil
}

// appUpgradedIteratorAdapter bridges the generated iterator (Event field) to the
// AppUpgradedIterator interface (Event() method returning *AppUpgradedEvent).
type appUpgradedIteratorAdapter struct {
	it *iappctl.IAppControllerAppUpgradedIterator
}

func (i *appUpgradedIteratorAdapter) Next() bool   { return i.it.Next() }
func (i *appUpgradedIteratorAdapter) Error() error { return i.it.Error() }
func (i *appUpgradedIteratorAdapter) Close() error { return i.it.Close() }

func (i *appUpgradedIteratorAdapter) Event() *AppUpgradedEvent {
	e := i.it.Event
	if e == nil {
		return nil
	}
	// AppRelease is a type alias for iappctl.IAppControllerAppRelease, so e.Release
	// already has the right type — no field-by-field copy needed.
	return &AppUpgradedEvent{
		App:          e.App,
		RmsReleaseId: e.RmsReleaseId,
		Release:      e.Release,
		Raw:          e.Raw,
	}
}
