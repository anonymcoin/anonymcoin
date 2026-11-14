// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package wallet

import (
	"os"
	"testing"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/transactions"
)

func osReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// openTempWallet creates and opens a fresh HD wallet for tests. Tests use a
// fixed 12+ char passphrase (production enforces the same minimum).
func openTempWallet(t *testing.T) (*Wallet, error) {
	t.Helper()
	path := t.TempDir() + "/wallet.json"
	w, err := Create(path, "test-passphrase-1")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	return Open(path, "test-passphrase-1")
}

func transactionsValidate(tx *transactions.Tx, p *consensus.Params, dag *blockdag.DAG) error {
	return transactions.ValidateSpendable(tx, p, blockdag.ChainTag(p), dag.MempoolView())
}
