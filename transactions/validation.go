// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package transactions

import (
	"fmt"

	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
)

// OutputView is the minimal view of a referenced UTXO needed for validation.
type OutputView struct {
	Value      uint64
	PubKeyHash cryptography.Hash160
}

// SpendView provides UTXO lookups to the validator. The BlockDAG engine
// implements this interface; the mempool uses a snapshot.
type SpendView interface {
	// Lookup returns the referenced output if it exists and is spendable at
	// the current canonical tip (coinbase maturity applied).
	Lookup(prev cryptography.Hash, index uint32) (OutputView, bool)
}

// ValidateSpendable validates a transaction against a UTXO view:
//
//   - structural checks (CheckStructure) including signatures
//   - every input must reference an existing, mature, unspent output
//   - the input pubkey must hash to the referenced output's pubkey hash
//     (pay-to-public-key-hash binding)
//   - the relay fee must meet MinRelayFee
//
// Conflicts with concurrent transactions in other DAG blocks are resolved at
// canonical application time by the BlockDAG engine, not here.
func ValidateSpendable(t *Tx, p *consensus.Params, chainTag [4]byte, view SpendView) error {
	if t.IsCoinbase() {
		return fmt.Errorf("tx: coinbase transactions are block-only")
	}
	if err := CheckStructure(t, p, chainTag); err != nil {
		return err
	}
	values := make([]uint64, len(t.Inputs))
	for i := range t.Inputs {
		in := &t.Inputs[i]
		out, ok := view.Lookup(in.PrevTx, in.PrevIndex)
		if !ok {
			return fmt.Errorf("tx: input %d references unknown or spent output", i)
		}
		if cryptography.Hash160Of(in.PubKey[:]) != out.PubKeyHash {
			return fmt.Errorf("tx: input %d pubkey does not match locked hash", i)
		}
		values[i] = out.Value
	}
	fee, err := t.Fee(values)
	if err != nil {
		return err
	}
	if fee < p.MinRelayFee {
		return fmt.Errorf("tx: fee %d below relay minimum %d", fee, p.MinRelayFee)
	}
	return nil
}
