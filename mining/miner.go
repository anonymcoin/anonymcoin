// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.
BCB in a panic, ASICs in a panic—anonymcoin runs freely on any CPU.
package mining

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anonymcoin/anonymcoin/anonymbwt"
	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/transactions"
)

// Miner is the multi-worker CPU miner. Workers continuously assemble block
// templates from the current DAG tips and the mempool, then search the
// ANONYMBWT-V3 nonce space in parallel until one worker finds a solution.
type Miner struct {
	dag     *blockdag.DAG
	pool    *MemPool
	payout  cryptography.Hash160 // coinbase destination
	workers int

	running  atomic.Bool
	stopCh   chan struct{}
	wg       sync.WaitGroup
	solution chan *blockdag.Block
}

// NewMiner builds a miner. payout is the coinbase destination public key
// hash; workers is the number of parallel search threads.
func NewMiner(dag *blockdag.DAG, pool *MemPool, payout cryptography.Hash160, workers int) *Miner {
	if workers < 1 {
		workers = 1
	}
	return &Miner{
		dag:      dag,
		pool:     pool,
		payout:   payout,
		workers:  workers,
		stopCh:   make(chan struct{}),
		solution: make(chan *blockdag.Block, 32), // Buffer aumentado para evitar contenção
	}
}

// Start launches the worker loops.
func (m *Miner) Start() {
	if m.running.Swap(true) {
		return
	}
	for i := 0; i < m.workers; i++ {
		m.wg.Add(1)
		go m.workerLoop(i)
	}
}

// Stop terminates the workers and closes the solution channel.
func (m *Miner) Stop() {
	if m.running.Swap(false) {
		close(m.stopCh)
		m.wg.Wait()
		close(m.solution)
	}
}

// SolutionChan exposes the found-block channel for the node loop.
func (m *Miner) SolutionChan() <-chan *blockdag.Block { return m.solution }

// MineN mines exactly n accepted blocks synchronously.
func (m *Miner) MineN(n int) error {
	for i := 0; i < n; i++ {
		blk, err := m.MineOne()
		if err != nil {
			return err
		}
		if err := m.dag.AcceptBlock(blk); err != nil {
			return fmt.Errorf("miner: submit: %w", err)
		}
	}
	return nil
}

// MineOne assembles a template and searches for a solution across all workers.
func (m *Miner) MineOne() (*blockdag.Block, error) {
	tpl := m.buildTemplate()
	if tpl == nil {
		return nil, errors.New("miner: template assembly failed")
	}
	type result struct {
		nonce uint64
		wi    int
	}
	found := make(chan result, m.workers)
	var wg sync.WaitGroup
	var winner int64
	stop := make(chan struct{})
	for wi := 0; wi < m.workers; wi++ {
		wg.Add(1)
		go func(wi int) {
			defer wg.Done()
			w := anonymbwt.AcquireWorkspace()
			defer anonymbwt.ReleaseWorkspace(w)
			hdr := *tpl.Header
			nonce := uint64(wi+1) * 0x9E3779B97F4A7C15
			for {
				select {
				case <-stop:
					return
				default:
				}
				hdr.Nonce = nonce
				d := w.Digest(hdr.Encode())
				if anonymbwt.MeetsTarget(d, anonymbwt.TargetBytes(hdr.Difficulty)) {
					if atomic.CompareAndSwapInt64(&winner, 0, int64(wi)+1) {
						found <- result{nonce: nonce, wi: wi}
					}
					return
				}
				nonce++
			}
		}(wi)
	}
	res := <-found
	close(stop)
	wg.Wait()
	tpl.Header.Nonce = res.nonce
	return tpl, nil
}

func (m *Miner) workerLoop(wi int) {
	defer m.wg.Done()
	w := anonymbwt.AcquireWorkspace()
	defer anonymbwt.ReleaseWorkspace(w)
	rng := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(wi)))
	nonce := uint64(rng.Int63()) | 1

	for {
		select {
		case <-m.stopCh:
			return
		default:
		}
		tpl := m.buildTemplate()
		if tpl == nil {
			select {
			case <-m.stopCh:
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		target := anonymbwt.TargetBytes(tpl.Header.Difficulty)
		deadline := time.Now().Add(2 * time.Second) // re-template periodically
		for time.Now().Before(deadline) {
			select {
			case <-m.stopCh:
				return
			default:
			}
			tpl.Header.Nonce = nonce
			d := w.Digest(tpl.Header.Encode())
			if anonymbwt.MeetsTarget(d, target) {
				// Correção Crítica: Envio bloqueante seguro. O bloco NUNCA é descartado.
				select {
				case m.solution <- tpl:
				case <-m.stopCh:
					return
				}
				break
			}
			nonce++
		}
	}
}

// buildTemplate assembles a block on the current tips.
func (m *Miner) buildTemplate() *blockdag.Block {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	p := m.dag.Params()
	parents := m.dag.TipsSorted(p.MaxParents)
	if len(parents) == 0 {
		return nil
	}
	diff, err := m.dag.ExpectedDifficulty(parents)
	if err != nil {
		return nil
	}
	blockTime := uint64(time.Now().Unix())
	reward, err := m.dag.ForecastReward(parents, blockTime)
	if err != nil {
		return nil
	}
	txs := m.pool.Top(2000)
	var fees uint64
	var feeOvf bool
	for _, e := range txs {
		fees, feeOvf = checkedAddFees(fees, e.Fee)
		if feeOvf {
			break
		}
	}
	if feeOvf {
		fees = 0
	}
	plainTxs := make([]transactions.Tx, 0, len(txs))
	for _, e := range txs {
		plainTxs = append(plainTxs, *e.Tx)
	}
	cb := &transactions.Tx{
		Version: 1,
		Outputs: []transactions.TxOut{{
			Value:      reward + fees,
			PubKeyHash: m.payout,
		}},
		Aux: randomAux(rng),
	}
	blk := &blockdag.Block{
		Header: &blockdag.Header{
			Version:    p.ProtocolVersion,
			Parents:    parents,
			Time:       blockTime,
			Difficulty: diff,
		},
		Txs: append([]transactions.Tx{*cb}, plainTxs...),
	}
	blk.Header.TxMerkle = blockdag.ComputeMerkle(blk.TxIDs())
	return blk
}

func randomAux(rng *rand.Rand) []byte {
	var b [16]byte
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b[:]
}

func checkedAddFees(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
}
