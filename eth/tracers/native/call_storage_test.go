// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package native_test

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/tests"
	"github.com/stretchr/testify/require"
)

// Addresses of the accounts used by the generated test contracts.
var (
	storageRoot  = common.Address{0x01}
	storageChild = common.Address{0x02}
	storageLib   = common.Address{0x03}
	storageBad   = common.Address{0x04}
)

// traceStorageChange mirrors the storageChanges JSON entry of callFrame.
type traceStorageChange struct {
	Address common.Address `json:"address"`
	Slot    common.Hash    `json:"slot"`
	Before  common.Hash    `json:"before"`
	After   common.Hash    `json:"after"`
}

// traceFrame is the JSON subset of the callTracer result used in the tests.
type traceFrame struct {
	Type           string               `json:"type"`
	To             *common.Address      `json:"to"`
	Error          string               `json:"error"`
	Calls          []traceFrame         `json:"calls"`
	Logs           []json.RawMessage    `json:"logs"`
	StorageChanges []traceStorageChange `json:"storageChanges"`
}

// uhash turns a single-byte scalar into a right-aligned 32-byte hash,
// matching how PUSH1 places the value on the EVM stack.
func uhash(v byte) common.Hash { return common.Hash{31: v} }

// sstoreCode returns PUSH1 val; PUSH1 slot; SSTORE.
func sstoreCode(slot, val byte) []byte {
	return []byte{
		byte(vm.PUSH1), val,
		byte(vm.PUSH1), slot,
		byte(vm.SSTORE),
	}
}

// callCode invokes the contract at addr with zero value and no arguments.
func callCode(addr common.Address) []byte {
	code := []byte{
		byte(vm.PUSH1), 0, // retSize
		byte(vm.PUSH1), 0, // retOffset
		byte(vm.PUSH1), 0, // argsSize
		byte(vm.PUSH1), 0, // argsOffset
		byte(vm.PUSH1), 0, // value
		byte(vm.PUSH20),
	}
	code = append(code, addr[:]...) // addresses are left-aligned in a word
	return append(code, byte(vm.GAS), byte(vm.CALL), byte(vm.POP))
}

// delegateCallCode invokes the contract at addr through DELEGATECALL with no
// arguments.
func delegateCallCode(addr common.Address) []byte {
	code := []byte{
		byte(vm.PUSH1), 0, // retSize
		byte(vm.PUSH1), 0, // retOffset
		byte(vm.PUSH1), 0, // argsSize
		byte(vm.PUSH1), 0, // argsOffset
		byte(vm.PUSH20),
	}
	code = append(code, addr[:]...)
	return append(code, byte(vm.GAS), byte(vm.DELEGATECALL), byte(vm.POP))
}

func stopCode() []byte { return []byte{byte(vm.STOP)} }

func revertCode() []byte {
	return []byte{byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.REVERT)}
}

func logCode() []byte {
	return []byte{byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.LOG0)}
}

// runStorageTrace assembles a genesis with the given root and callee code,
// sends a transaction to the root contract with a callTracer configured by
// cfg and returns the decoded top frame together with the raw JSON result.
func runStorageTrace(t *testing.T, rootCode []byte, codes map[common.Address][]byte, preset map[common.Address]map[byte]byte, cfg string) (traceFrame, json.RawMessage) {
	t.Helper()

	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)

	alloc := core.GenesisAlloc{
		from:        {Balance: big.NewInt(1_000_000_000_000_000_000)},
		storageRoot: {Code: rootCode},
	}
	for addr, code := range codes {
		alloc[addr] = core.GenesisAccount{Code: code}
	}
	for addr, slots := range preset {
		account := alloc[addr]
		account.Storage = make(map[common.Hash]common.Hash, len(slots))
		for slot, val := range slots {
			account.Storage[uhash(slot)] = uhash(val)
		}
		alloc[addr] = account
	}
	genesis := &core.Genesis{
		Config: params.AllEthashProtocolChanges,
		Alloc:  alloc,
	}
	st := tests.MakePreState(rawdb.NewMemoryDatabase(), genesis.Alloc, false, rawdb.HashScheme)
	defer st.Close()

	tracer, err := tracers.DefaultDirectory.New("callTracer", new(tracers.Context), json.RawMessage(cfg), genesis.Config)
	require.NoError(t, err)

	context := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		BlockNumber: big.NewInt(1),
		Time:        1,
		GasLimit:    30_000_000,
		BaseFee:     common.Big0,
	}
	hookedState := state.NewHookedState(st.StateDB, tracer.Hooks)
	evm := vm.NewEVM(context, hookedState, genesis.Config, vm.Config{Tracer: tracer.Hooks})

	const gas = uint64(20_000_000)
	tx := types.MustSignNewTx(key, types.NewLondonSigner(genesis.Config.ChainID), &types.DynamicFeeTx{
		ChainID:   genesis.Config.ChainID,
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       gas,
		To:        &storageRoot,
	})
	msg, err := core.TransactionToMessage(tx, types.NewLondonSigner(genesis.Config.ChainID), context.BaseFee)
	require.NoError(t, err)

	tracer.OnTxStart(evm.GetVMContext(), tx, msg.From)
	vmRet, err := core.ApplyMessage(evm, msg, nil)
	require.NoError(t, err)
	tracer.OnTxEnd(&types.Receipt{GasUsed: vmRet.UsedGas}, nil)

	raw, err := tracer.GetResult()
	require.NoError(t, err)

	var frame traceFrame
	require.NoError(t, json.Unmarshal(raw, &frame))
	return frame, raw
}

// TestCallTracerStorageChanges verifies per-frame net storage changes:
//   - SSTOREs of the frame and successful subcalls are aggregated, one entry
//     per (address, slot), sorted by address and slot
//   - writes restored to the value at frame entry are not reported
//   - the reported "before" value is the actual slot value at frame entry
func TestCallTracerStorageChanges(t *testing.T) {
	root := append(sstoreCode(1, 0x0A), sstoreCode(2, 0x0B)...)
	root = append(root, sstoreCode(2, 0x00)...) // restore slot 2 to its entry value
	root = append(root, sstoreCode(7, 0x88)...) // slot 7 already holds 0x77
	root = append(root, callCode(storageChild)...)
	root = append(root, stopCode()...)

	frame, _ := runStorageTrace(t, root,
		map[common.Address][]byte{
			storageChild: append(sstoreCode(3, 0x0C), stopCode()...),
		},
		map[common.Address]map[byte]byte{
			storageRoot: {7: 0x77},
		},
		`{"withStorageChanges":true}`,
	)

	require.Equal(t, "CALL", frame.Type)
	require.Equal(t, []traceStorageChange{
		{Address: storageRoot, Slot: uhash(1), Before: common.Hash{}, After: uhash(0x0A)},
		{Address: storageRoot, Slot: uhash(7), Before: uhash(0x77), After: uhash(0x88)},
		{Address: storageChild, Slot: uhash(3), Before: common.Hash{}, After: uhash(0x0C)},
	}, frame.StorageChanges)

	require.Len(t, frame.Calls, 1)
	require.Equal(t, "CALL", frame.Calls[0].Type)
	require.Equal(t, storageChild, *frame.Calls[0].To)
	require.Equal(t, []traceStorageChange{
		{Address: storageChild, Slot: uhash(3), Before: common.Hash{}, After: uhash(0x0C)},
	}, frame.Calls[0].StorageChanges)
}

// TestCallTracerStorageChangesAggregation writes the same slot in the root
// frame and in a DELEGATECALL. The write must be aggregated into a single
// entry and attributed to the account owning the storage (the root contract),
// not the delegatee.
func TestCallTracerStorageChangesAggregation(t *testing.T) {
	root := append(sstoreCode(1, 0x0A), delegateCallCode(storageLib)...)
	root = append(root, stopCode()...)

	frame, _ := runStorageTrace(t, root,
		map[common.Address][]byte{
			storageLib: append(sstoreCode(1, 0x0B), stopCode()...),
		}, nil,
		`{"withStorageChanges":true}`,
	)

	// Root frame sees the aggregated 0x00 -> 0x0B change.
	require.Equal(t, []traceStorageChange{
		{Address: storageRoot, Slot: uhash(1), Before: common.Hash{}, After: uhash(0x0B)},
	}, frame.StorageChanges)

	require.Len(t, frame.Calls, 1)
	require.Equal(t, "DELEGATECALL", frame.Calls[0].Type)
	require.Equal(t, storageLib, *frame.Calls[0].To)
	// The delegate frame reports the root address and its own entry value.
	require.Equal(t, []traceStorageChange{
		{Address: storageRoot, Slot: uhash(1), Before: uhash(0x0A), After: uhash(0x0B)},
	}, frame.Calls[0].StorageChanges)
}

// TestCallTracerStorageChangesRestoredAcrossCalls covers a slot which the
// root frame writes and a successful subcall restores: the root frame does
// not report the slot, while the subcall keeps its own change.
func TestCallTracerStorageChangesRestoredAcrossCalls(t *testing.T) {
	root := append(sstoreCode(1, 0x0A), delegateCallCode(storageLib)...)
	root = append(root, stopCode()...)

	frame, _ := runStorageTrace(t, root,
		map[common.Address][]byte{
			storageLib: append(sstoreCode(1, 0x00), stopCode()...),
		}, nil,
		`{"withStorageChanges":true}`,
	)

	require.Nil(t, frame.StorageChanges)
	require.Len(t, frame.Calls, 1)
	require.Equal(t, []traceStorageChange{
		{Address: storageRoot, Slot: uhash(1), Before: uhash(0x0A), After: common.Hash{}},
	}, frame.Calls[0].StorageChanges)
}

// TestCallTracerStorageChangesRevertedCall ensures that a reverted subcall
// drops its own storage writes and does not leak them into the parent frame.
func TestCallTracerStorageChangesRevertedCall(t *testing.T) {
	root := append(sstoreCode(1, 0x0A), callCode(storageBad)...)
	root = append(root, stopCode()...)

	frame, _ := runStorageTrace(t, root,
		map[common.Address][]byte{
			storageBad: append(sstoreCode(4, 0xDD), revertCode()...),
		}, nil,
		`{"withStorageChanges":true}`,
	)

	require.Equal(t, []traceStorageChange{
		{Address: storageRoot, Slot: uhash(1), Before: common.Hash{}, After: uhash(0x0A)},
	}, frame.StorageChanges)

	require.Len(t, frame.Calls, 1)
	require.NotEmpty(t, frame.Calls[0].Error)
	require.Nil(t, frame.Calls[0].StorageChanges)
}

// TestCallTracerStorageChangesAncestorRevert ensures that when an ancestor
// frame reverts, the storage changes already attached to a successful
// subcall are removed as well.
func TestCallTracerStorageChangesAncestorRevert(t *testing.T) {
	root := append(callCode(storageChild), sstoreCode(1, 0x0A)...)
	root = append(root, revertCode()...)

	frame, _ := runStorageTrace(t, root,
		map[common.Address][]byte{
			storageChild: append(sstoreCode(3, 0x0C), stopCode()...),
		}, nil,
		`{"withStorageChanges":true}`,
	)

	require.NotEmpty(t, frame.Error)
	require.Nil(t, frame.StorageChanges)
	require.Len(t, frame.Calls, 1)
	require.Empty(t, frame.Calls[0].Error)
	require.Nil(t, frame.Calls[0].StorageChanges)
}

// TestCallTracerStorageChangesOnlyTopCall keeps only the top-level frame but
// still aggregates the storage writes of non-reverted subcalls.
func TestCallTracerStorageChangesOnlyTopCall(t *testing.T) {
	root := append(sstoreCode(1, 0x0A), callCode(storageChild)...)
	root = append(root, callCode(storageBad)...) // reverts, its writes must be dropped
	root = append(root, stopCode()...)

	frame, _ := runStorageTrace(t, root,
		map[common.Address][]byte{
			storageChild: append(sstoreCode(3, 0x0C), stopCode()...),
			storageBad:   append(sstoreCode(4, 0xDD), revertCode()...),
		}, nil,
		`{"withStorageChanges":true,"onlyTopCall":true}`,
	)

	require.Nil(t, frame.Calls)
	require.Equal(t, []traceStorageChange{
		{Address: storageRoot, Slot: uhash(1), Before: common.Hash{}, After: uhash(0x0A)},
		{Address: storageChild, Slot: uhash(3), Before: common.Hash{}, After: uhash(0x0C)},
	}, frame.StorageChanges)
}

// TestCallTracerStorageChangesDisabled verifies that the option is off by
// default and the trace output contains no storageChanges information.
func TestCallTracerStorageChangesDisabled(t *testing.T) {
	root := append(sstoreCode(1, 0x0A), callCode(storageChild)...)
	root = append(root, stopCode()...)

	frame, raw := runStorageTrace(t, root,
		map[common.Address][]byte{
			storageChild: append(sstoreCode(3, 0x0C), stopCode()...),
		}, nil,
		`{}`,
	)

	require.NotContains(t, string(raw), "storageChanges")
	require.Len(t, frame.Calls, 1)
	require.Nil(t, frame.StorageChanges)
	require.Nil(t, frame.Calls[0].StorageChanges)
}

// TestCallTracerStorageChangesWithLog checks that withLog and
// withStorageChanges work independently in the same subcall frame.
func TestCallTracerStorageChangesWithLog(t *testing.T) {
	root := append(callCode(storageChild), stopCode()...)

	frame, _ := runStorageTrace(t, root,
		map[common.Address][]byte{
			storageChild: append(sstoreCode(3, 0x0C), logCode()...),
		}, nil,
		`{"withStorageChanges":true,"withLog":true}`,
	)

	require.Len(t, frame.Calls, 1)
	require.Len(t, frame.Calls[0].Logs, 1)
	require.Equal(t, []traceStorageChange{
		{Address: storageChild, Slot: uhash(3), Before: common.Hash{}, After: uhash(0x0C)},
	}, frame.Calls[0].StorageChanges)
}
