// Copyright 2021 The go-ethereum Authors
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

package native

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/params"
)

//go:generate go run github.com/fjl/gencodec -type callFrame -field-override callFrameMarshaling -out gen_callframe_json.go

func init() {
	tracers.DefaultDirectory.Register("callTracer", newCallTracer, false)
}

type callLog struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    hexutil.Bytes  `json:"data"`
	Index   hexutil.Uint   `json:"index"`
	// Position of the log relative to subcalls within the same trace
	// See https://github.com/ethereum/go-ethereum/pull/28389 for details
	Position hexutil.Uint `json:"position"`
}

// callStorageChange is the net SSTORE change recorded for a call frame,
// aggregated over the frame itself and all of its non-reverted subcalls.
// Address is the account whose storage was modified (which differs from the
// callee for DELEGATECALL), Slot the storage key, Before the slot value at
// frame entry and After the slot value at frame exit.
type callStorageChange struct {
	Address common.Address `json:"address"`
	Slot    common.Hash    `json:"slot"`
	Before  common.Hash    `json:"before"`
	After   common.Hash    `json:"after"`
}

type callFrame struct {
	Type         vm.OpCode       `json:"-"`
	From         common.Address  `json:"from"`
	Gas          uint64          `json:"gas"`
	GasUsed      uint64          `json:"gasUsed"`
	To           *common.Address `json:"to,omitempty" rlp:"optional"`
	Input        []byte          `json:"input" rlp:"optional"`
	Output       []byte          `json:"output,omitempty" rlp:"optional"`
	Error        string          `json:"error,omitempty" rlp:"optional"`
	RevertReason string          `json:"revertReason,omitempty"`
	Calls        []callFrame     `json:"calls,omitempty" rlp:"optional"`
	Logs         []callLog       `json:"logs,omitempty" rlp:"optional"`
	// StorageChanges contains the net storage writes of the frame, including
	// the aggregated effect of non-reverted subcalls. Only populated when
	// the tracer is configured with withStorageChanges.
	StorageChanges []callStorageChange `json:"storageChanges,omitempty" rlp:"optional"`
	// Placed at end on purpose. The RLP will be decoded to 0 instead of
	// nil if there are non-empty elements after in the struct.
	Value            *big.Int `json:"value,omitempty" rlp:"optional"`
	revertedSnapshot bool
}

func (f callFrame) TypeString() string {
	return f.Type.String()
}

func (f callFrame) failed() bool {
	return len(f.Error) > 0 && f.revertedSnapshot
}

func (f *callFrame) processOutput(output []byte, err error, reverted bool) {
	output = common.CopyBytes(output)
	// Clear error if tx wasn't reverted. This happened
	// for pre-homestead contract storage OOG.
	if err != nil && !reverted {
		err = nil
	}
	if err == nil {
		f.Output = output
		return
	}
	f.Error = err.Error()
	f.revertedSnapshot = reverted
	if f.Type == vm.CREATE || f.Type == vm.CREATE2 {
		f.To = nil
	}
	if !errors.Is(err, vm.ErrExecutionReverted) || len(output) == 0 {
		return
	}
	f.Output = output
	if len(output) < 4 {
		return
	}
	if unpacked, err := abi.UnpackRevert(output); err == nil {
		f.RevertReason = unpacked
	}
}

type callFrameMarshaling struct {
	TypeString string `json:"type"`
	Gas        hexutil.Uint64
	GasUsed    hexutil.Uint64
	Value      *hexutil.Big
	Input      hexutil.Bytes
	Output     hexutil.Bytes
}

type callTracer struct {
	callstack []callFrame
	config    callTracerConfig
	gasLimit  uint64
	depth     int
	// storageChanges holds the net storage writes tracked per open call frame,
	// in lockstep with callstack. It is only populated when WithStorageChanges
	// is enabled.
	storageChanges []map[storageSlot]*storageDelta
	interrupt      atomic.Bool           // Atomic flag to signal execution interruption
	reason         atomic.Pointer[error] // Reason for the interruption, populated by Stop
}

// storageSlot identifies a storage slot of an account.
type storageSlot struct {
	address common.Address
	slot    common.Hash
}

// storageDelta tracks the value of a slot at frame entry (before) and its
// latest value (after).
type storageDelta struct {
	before common.Hash
	after  common.Hash
}

type callTracerConfig struct {
	OnlyTopCall        bool `json:"onlyTopCall"`        // If true, call tracer won't collect any subcalls
	WithLog            bool `json:"withLog"`            // If true, call tracer will collect event logs
	WithStorageChanges bool `json:"withStorageChanges"` // If true, call tracer will collect net storage changes
}

// newCallTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func newCallTracer(ctx *tracers.Context, cfg json.RawMessage, chainConfig *params.ChainConfig) (*tracers.Tracer, error) {
	t, err := newCallTracerObject(ctx, cfg)
	if err != nil {
		return nil, err
	}
	hooks := &tracing.Hooks{
		OnTxStart: t.OnTxStart,
		OnTxEnd:   t.OnTxEnd,
		OnEnter:   t.OnEnter,
		OnExit:    t.OnExit,
		OnLog:     t.OnLog,
	}
	if t.config.WithStorageChanges {
		hooks.OnStorageChange = t.OnStorageChange
		// Wrap the hooks with a journal so that storage writes of reverted
		// frames are replayed with their reverse values before the frame exits.
		if hooks, err = tracing.WrapWithJournal(hooks); err != nil {
			return nil, err
		}
	}
	return &tracers.Tracer{
		Hooks:     hooks,
		GetResult: t.GetResult,
		Stop:      t.Stop,
	}, nil
}

func newCallTracerObject(ctx *tracers.Context, cfg json.RawMessage) (*callTracer, error) {
	var config callTracerConfig
	if err := json.Unmarshal(cfg, &config); err != nil {
		return nil, err
	}
	// First callframe contains tx context info
	// and is populated on start and end.
	return &callTracer{callstack: make([]callFrame, 0, 1), config: config}, nil
}

// OnEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *callTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	t.depth = depth
	if t.config.OnlyTopCall && depth > 0 {
		return
	}
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}

	toCopy := to
	call := callFrame{
		Type:  vm.OpCode(typ),
		From:  from,
		To:    &toCopy,
		Input: common.CopyBytes(input),
		Gas:   gas,
		Value: value,
	}
	if depth == 0 {
		call.Gas = t.gasLimit
	}
	t.callstack = append(t.callstack, call)
	if t.config.WithStorageChanges {
		t.storageChanges = append(t.storageChanges, nil)
	}
}

// OnExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *callTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if depth == 0 {
		t.captureEnd(output, gasUsed, err, reverted)
		return
	}

	t.depth = depth - 1
	if t.config.OnlyTopCall {
		return
	}

	size := len(t.callstack)
	if size <= 1 {
		return
	}
	// Pop call.
	call := t.callstack[size-1]
	t.callstack = t.callstack[:size-1]
	size -= 1

	call.GasUsed = gasUsed
	call.processOutput(output, err, reverted)
	if t.config.WithStorageChanges {
		t.finishStorageChanges(&call, reverted)
	}
	// Nest call into parent.
	t.callstack[size-1].Calls = append(t.callstack[size-1].Calls, call)
}

func (t *callTracer) captureEnd(output []byte, gasUsed uint64, err error, reverted bool) {
	if len(t.callstack) != 1 {
		return
	}
	t.callstack[0].processOutput(output, err, reverted)
	if t.config.WithStorageChanges && len(t.storageChanges) == 1 {
		if reverted {
			// The top-level frame reverted, so no storage write survives,
			// not even ones made by subcalls which had already succeeded.
			clearStorageChanges(&t.callstack[0])
		} else {
			t.callstack[0].StorageChanges = sortedStorageChanges(t.storageChanges[0])
		}
		t.storageChanges = t.storageChanges[:0]
	}
}

// OnStorageChange is invoked for every storage slot write. The tracer hooks
// are wrapped with a tracing journal, which replays the writes with reverse
// values when a frame reverts before OnExit is called.
func (t *callTracer) OnStorageChange(addr common.Address, slot, prev, new common.Hash) {
	if t.interrupt.Load() || len(t.storageChanges) == 0 {
		return
	}
	idx := len(t.storageChanges) - 1
	changes := t.storageChanges[idx]
	if changes == nil {
		changes = make(map[storageSlot]*storageDelta)
		t.storageChanges[idx] = changes
	}
	key := storageSlot{address: addr, slot: slot}
	if delta, ok := changes[key]; ok {
		// A subsequent write (or a journal replay on revert) only updates
		// the latest value, keeping the slot value at frame entry.
		delta.after = new
		return
	}
	changes[key] = &storageDelta{before: prev, after: new}
}

// finishStorageChanges consumes the storage deltas of the frame that is about
// to be nested into its parent call frame.
func (t *callTracer) finishStorageChanges(call *callFrame, reverted bool) {
	if len(t.storageChanges) == 0 {
		return
	}
	idx := len(t.storageChanges) - 1
	changes := t.storageChanges[idx]
	t.storageChanges = t.storageChanges[:idx]

	if reverted {
		// The frame reverted: none of its (or its descendants') storage
		// writes survive. Discard the deltas and clear any change that was
		// already attached to a nested non-reverted subcall.
		clearStorageChanges(call)
		return
	}
	call.StorageChanges = sortedStorageChanges(changes)
	// Aggregate this frame's net effect into the parent frame.
	if len(changes) == 0 || idx == 0 {
		return
	}
	parent := t.storageChanges[idx-1]
	if parent == nil {
		parent = make(map[storageSlot]*storageDelta, len(changes))
		t.storageChanges[idx-1] = parent
	}
	for key, delta := range changes {
		if p, ok := parent[key]; ok {
			p.after = delta.after
		} else {
			parent[key] = &storageDelta{before: delta.before, after: delta.after}
		}
	}
}

// sortedStorageChanges turns the tracked deltas into a deterministically
// ordered list, dropping slots whose final value equals their value at frame
// entry.
func sortedStorageChanges(changes map[storageSlot]*storageDelta) []callStorageChange {
	if len(changes) == 0 {
		return nil
	}
	res := make([]callStorageChange, 0, len(changes))
	for key, delta := range changes {
		if delta.before == delta.after {
			continue
		}
		res = append(res, callStorageChange{
			Address: key.address,
			Slot:    key.slot,
			Before:  delta.before,
			After:   delta.after,
		})
	}
	sort.Slice(res, func(i, j int) bool {
		if cmp := bytes.Compare(res[i].Address[:], res[j].Address[:]); cmp != 0 {
			return cmp < 0
		}
		return bytes.Compare(res[i].Slot[:], res[j].Slot[:]) < 0
	})
	return res
}

// clearStorageChanges drops the recorded storage changes of a frame and all of
// its nested subcalls. It is used when the frame itself or one of its
// ancestors reverted.
func clearStorageChanges(cf *callFrame) {
	cf.StorageChanges = nil
	for i := range cf.Calls {
		clearStorageChanges(&cf.Calls[i])
	}
}

func (t *callTracer) OnTxStart(env *tracing.VMContext, tx *types.Transaction, from common.Address) {
	t.gasLimit = tx.Gas()
}

func (t *callTracer) OnTxEnd(receipt *types.Receipt, err error) {
	// Error happened during tx validation.
	if err != nil {
		return
	}
	if receipt != nil {
		t.callstack[0].GasUsed = receipt.GasUsed
	}
	if t.config.WithLog {
		// Logs are not emitted when the call fails
		clearFailedLogs(&t.callstack[0], false)
	}
}

func (t *callTracer) OnLog(log *types.Log) {
	// Only logs need to be captured via opcode processing
	if !t.config.WithLog {
		return
	}
	// Avoid processing nested calls when only caring about top call
	if t.config.OnlyTopCall && t.depth > 0 {
		return
	}
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}
	l := callLog{
		Address:  log.Address,
		Topics:   log.Topics,
		Data:     log.Data,
		Index:    hexutil.Uint(log.Index),
		Position: hexutil.Uint(len(t.callstack[len(t.callstack)-1].Calls)),
	}
	t.callstack[len(t.callstack)-1].Logs = append(t.callstack[len(t.callstack)-1].Logs, l)
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *callTracer) GetResult() (json.RawMessage, error) {
	if len(t.callstack) != 1 {
		return nil, errors.New("incorrect number of top-level calls")
	}

	res, err := json.Marshal(t.callstack[0])
	if err != nil {
		return nil, err
	}
	if p := t.reason.Load(); p != nil {
		return res, *p
	}
	return res, nil
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *callTracer) Stop(err error) {
	t.reason.Store(&err)
	t.interrupt.Store(true)
}

// clearFailedLogs clears the logs of a callframe and all its children
// in case of execution failure.
func clearFailedLogs(cf *callFrame, parentFailed bool) {
	failed := cf.failed() || parentFailed
	// Clear own logs
	if failed {
		cf.Logs = nil
	}
	for i := range cf.Calls {
		clearFailedLogs(&cf.Calls[i], failed)
	}
}
