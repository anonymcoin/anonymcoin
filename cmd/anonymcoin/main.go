// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.
//
// ANONYMCOIN — THE BLOCKDAG IS THE HEART OF ANONYMCOIN.
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee

package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/anonymcoin/anonymcoin/consensus"

	"github.com/anonymcoin/anonymcoin/anonymbwt"
	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/config"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/mining"
	"github.com/anonymcoin/anonymcoin/network"
	"github.com/anonymcoin/anonymcoin/storage"
	"github.com/anonymcoin/anonymcoin/wallet"
)

const versionString = "ANONYMCOIN 1.0.0 — THE BLOCKDAG IS THE HEART — Iury Lee © 2026"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "node":
		err = cmdNode(os.Args[2:])
	case "wallet":
		err = cmdWallet(os.Args[2:])
	case "send":
		err = cmdSend(os.Args[2:])
	case "balance":
		err = cmdBalance(os.Args[2:])
	case "bench":
		err = cmdBench(os.Args[2:])
	case "version", "--version":
		fmt.Println(versionString)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`ANONYMCOIN — private BlockDAG cryptocurrency (Iury Lee © 2026)

Usage:
  anonymcoin node    [--config FILE] [--datadir DIR] [--mine] [--workers N]
                     [--payout ADDRESS] [--listen ADDR]
  anonymcoin wallet  --datadir DIR create|restore|newaddress|newaccount
                              |addresses|keycount|show-mnemonic|watch|export
  anonymcoin send    --datadir DIR --to ADDRESS --amount COIN [--fee COIN]
  anonymcoin balance --datadir DIR ADDRESS
  anonymcoin bench   [--iters N]
  anonymcoin version

Wallet commands:
  create         generate a new 24-word recovery phrase (printed ONCE)
  restore        recover from an existing 24-word phrase (read from stdin)
  show-mnemonic  print the stored recovery phrase again (passphrase needed)
  newaddress     derive the next address of account 0
  newaccount     create account N with its first address
  addresses      list controlled addresses (--account N optional)
  keycount       number of signing keys
  watch          register a watch-only address (cannot sign)
  export         write an encrypted backup under a NEW passphrase

SECURITY: the 24-word phrase IS the wallet. Anyone holding it holds the
funds. Print it once, write it on paper, store it offline. See SECURITY.md.

THE BLOCKDAG IS THE HEART OF ANONYMCOIN.
ANONYMCOIN RODA LIVRE EM QUALQUER CPU.
`)
}

// ---------------------------------------------------------------------------
// node
// ---------------------------------------------------------------------------

func cmdNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config.json")
	dataDir := fs.String("datadir", "", "override data_dir")
	mine := fs.Bool("mine", false, "enable CPU mining")
	workers := fs.Int("workers", runtime.NumCPU(), "miner worker threads")
	payout := fs.String("payout", "", "mining payout address override")
	listen := fs.String("listen", "", "P2P listen address override")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *listen != "" {
		cfg.P2P.ListenAddr = *listen
	}
	if cfg.Mining.PayoutAddress != "" {
		*payout = cfg.Mining.PayoutAddress
	}
	if cfg.Mining.Enabled {
		*mine = true
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}

	logf := func(format string, args ...interface{}) {
		fmt.Printf(time.Now().UTC().Format("2006-01-02T15:04:05Z")+" "+format+"\n", args...)
	}

	p := cfg.Consensus
	genesis := blockdag.GenesisHash(&p)
	logf("ANONYMCOIN node starting — %s — genesis %x", versionString, genesis[:8])
	logf("BCB in a panic, Asics in a panic—Anonymcoin runs on any CPU.")

	// Storage.
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	store, err := storage.Open(filepath.Join(cfg.DataDir, "blocks.dat"), &p, true)
	if err != nil {
		return err
	}
	defer store.Close()

	// DAG with hooks that persist accepted blocks and rebase the mempool.
	var pool *mining.MemPool
	hooks := blockdag.Hooks{
		OnAccepted: func(b *blockdag.Block, idx int64) {
			if err := store.Append(b); err != nil {
				logf("storage append failed: %v", err)
			}
		},
	}
	dag, err := blockdag.New(&p, hooks)
	if err != nil {
		return err
	}
	pool = mining.NewMemPool(&p)
	hooks.OnReorg = nil
	dagRebase := func() { pool.Rebase(dag.MempoolView()) }
	hooks.OnReorg = dagRebase
	prev := hooks.OnAccepted
	hooks.OnAccepted = func(b *blockdag.Block, idx int64) {
		prev(b, idx)
		dagRebase()
	}

	if n := store.Count(); n > 0 {
		logf("replaying %d stored blocks...", n)
		start := time.Now()
		if err := store.ForEach(&p, func(b *blockdag.Block) error {
			bh := b.BlockHash()
			if err := dag.AcceptBlock(b); err != nil {
				return fmt.Errorf("replay of %x: %w", bh[:6], err)
			}
			return nil
		}); err != nil {
			return err
		}
		logf("replay done in %s: canonical=%d supply=%s", time.Since(start).Round(time.Millisecond),
			dag.CanonicalCount(), p.CoinString(dag.CirculatingSupply()))
	}

	// Networking.
	identity, err := network.LoadOrCreateIdentity(cfg.DataDir)
	if err != nil {
		return err
	}
	logf("node identity: cert=%s falcon=%s", identity.CertFingerprint(), identity.FalconFingerprint())
	srv, err := network.NewServer(identity, dag, pool, cfg.P2P, true, logf)
	if err != nil {
		return err
	}
	if cfg.P2P.Enabled {
		if err := srv.Start(); err != nil {
			return err
		}
	}

	// Miner.
	var miner *mining.Miner
	if *mine {
		payoutAddr := *payout
		if payoutAddr == "" {
			return errors.New("node: mining enabled but no payout address configured")
		}
		pkh, err := cryptography.AddressToPubKeyHash(payoutAddr)
		if err != nil {
			return err
		}
		miner = mining.NewMiner(dag, pool, pkh, *workers)
		miner.Start()
		logf("mining with %d CPU workers -> %s", *workers, payoutAddr)
		go func() {
			for blk := range miner.SolutionChan() {
				bh := blk.BlockHash()
				if err := dag.AcceptBlock(blk); err != nil {
					if errors.Is(err, blockdag.ErrDuplicate) {
						continue
					}
					logf("mined block rejected: %v", err)
					continue
				}
				logf("mined block %x (canonical=%d supply=%s)", bh[:6], dag.CanonicalCount(), p.CoinString(dag.CirculatingSupply()))
			}
		}()
	}

	logf("node ready. THE BLOCKDAG IS THE HEART.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logf("shutting down...")
	if miner != nil {
		miner.Stop()
	}
	srv.Stop()
	return nil
}

// ---------------------------------------------------------------------------
// wallet
// ---------------------------------------------------------------------------

var valueFlags = map[string]bool{
	"datadir": true, "account": true, "address": true, "label": true, "out": true,
}

func extractSubcommand(args []string) (sub string, rest []string) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			return
		}
		if strings.HasPrefix(a, "-") {
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") && valueFlags[name] && i+1 < len(args) {
				rest = append(rest, a, args[i+1])
				i++
				continue
			}
			rest = append(rest, a)
			continue
		}
		if sub == "" {
			sub = a
			continue
		}
		rest = append(rest, a)
	}
	return sub, rest
}

func cmdWallet(args []string) error {
	sub, rest := extractSubcommand(args)
	fs := flag.NewFlagSet("wallet", flag.ContinueOnError)
	dataDir := fs.String("datadir", "./data", "data directory holding wallet.json")
	account := fs.Int("account", 0, "account index (addresses)")
	watchAddr := fs.String("address", "", "watch: address to register")
	watchLabel := fs.String("label", "", "watch: label for the address")
	out := fs.String("out", "", "export: backup file path")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if sub == "" {
		return errors.New("wallet: need a subcommand: create|restore|show-mnemonic|newaddress|newaccount|addresses|keycount|watch|export")
	}
	path := filepath.Join(*dataDir, "wallet.json")

	switch sub {
	case "create":
		pass, err := readPassphraseTwice()
		if err != nil {
			return err
		}
		if fileExists(path) {
			return errors.New("wallet: wallet.json already exists")
		}
		w, err := wallet.Create(path, pass)
		if err != nil {
			return err
		}
		defer w.Close()
		phrase, err := w.MnemonicWords()
		if err != nil {
			return err
		}
		words := strings.Fields(phrase)
		fmt.Println("=== ANONYMCOIN RECOVERY PHRASE (24 words) — WRITE IT DOWN NOW ===")
		for i := 0; i < len(words); i += 4 {
			fmt.Printf("  %2d. %s\n", i+1, strings.Join(words[i:min(i+4, len(words))], " "))
		}
		fmt.Println("=== END — anyone holding this phrase holds your funds. ===")
		addr, err := w.Address(0)
		if err != nil {
			return err
		}
		fmt.Println("wallet created. first address:", addr)

	case "restore":
		fmt.Fprint(os.Stderr, "recovery phrase (24 words): ")
		line, err := stdinReader.ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		pass, err := readPassphraseTwice()
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, "optional BIP-39 passphrase (empty if none): ")
		b39, _ := stdinReader.ReadString('\n')
		w, err := wallet.Restore(path, pass, strings.TrimSpace(line), strings.TrimSpace(b39))
		if err != nil {
			return err
		}
		defer w.Close()
		addr, err := w.Address(0)
		if err != nil {
			return err
		}
		fmt.Println("wallet restored. first address:", addr)

	case "show-mnemonic":
		pass, err := readPassphrase()
		if err != nil {
			return err
		}
		w, err := wallet.Open(path, pass)
		if err != nil {
			return err
		}
		defer w.Close()
		phrase, err := w.MnemonicWords()
		if err != nil {
			return err
		}
		fmt.Println(phrase)

	case "newaddress":
		pass, err := readPassphrase()
		if err != nil {
			return err
		}
		w, err := wallet.Open(path, pass)
		if err != nil {
			return err
		}
		defer w.Close()
		addr, err := w.NewAddressIn(pass, *account)
		if err != nil {
			return err
		}
		fmt.Println(addr)

	case "newaccount":
		pass, err := readPassphrase()
		if err != nil {
			return err
		}
		w, err := wallet.Open(path, pass)
		if err != nil {
			return err
		}
		defer w.Close()
		acct, err := w.NewAccount(pass)
		if err != nil {
			return err
		}
		addrs, err := w.AccountAddresses(acct)
		if err != nil {
			return err
		}
		fmt.Printf("account %d created. first address: %s\n", acct, addrs[0])

	case "addresses":
		pass, err := readPassphrase()
		if err != nil {
			return err
		}
		w, err := wallet.Open(path, pass)
		if err != nil {
			return err
		}
		defer w.Close()
		acctSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "account" {
				acctSet = true
			}
		})
		if acctSet {
			addrs, err := w.AccountAddresses(*account)
			if err != nil {
				return err
			}
			for _, a := range addrs {
				fmt.Println(a)
			}
			return nil
		}
		for _, a := range w.Addresses() {
			fmt.Println(a)
		}

	case "keycount":
		pass, err := readPassphrase()
		if err != nil {
			return err
		}
		w, err := wallet.Open(path, pass)
		if err != nil {
			return err
		}
		defer w.Close()
		fmt.Println(w.KeyCount())

	case "watch":
		if *watchAddr == "" {
			return errors.New("wallet: watch needs --address ADDRESS")
		}
		pass, err := readPassphrase()
		if err != nil {
			return err
		}
		w, err := wallet.Open(path, pass)
		if err != nil {
			return err
		}
		defer w.Close()
		if err := w.AddWatchAddress(pass, *watchAddr, *watchLabel); err != nil {
			return err
		}
		fmt.Println("watch-only address registered:", *watchAddr)

	case "export":
		if *out == "" {
			return errors.New("wallet: export needs --out FILE")
		}
		fmt.Fprint(os.Stderr, "wallet passphrase: ")
		pass, err := readPassphrase()
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, "NEW backup passphrase (min 12 chars): ")
		pass2, err := readPassphrase()
		if err != nil {
			return err
		}
		if pass == pass2 {
			return errors.New("wallet: backup passphrase must differ")
		}
		if err := wallet.Export(*out, path, pass, pass2); err != nil {
			return err
		}
		fmt.Println("encrypted backup written:", *out)

	default:
		return fmt.Errorf("wallet: unknown subcommand %q", sub)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

var stdinReader = bufio.NewReader(os.Stdin)

func readPassphrase() (string, error) {
	fmt.Fprint(os.Stderr, "passphrase: ")
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func readPassphraseTwice() (string, error) {
	s, err := readPassphrase()
	if err != nil {
		return "", err
	}
	if len(s) < 12 {
		return "", errors.New("passphrase must be at least 12 characters")
	}
	fmt.Fprint(os.Stderr, "confirm passphrase: ")
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	if strings.TrimSpace(line) != s {
		return "", errors.New("passphrases do not match")
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	dataDir := fs.String("datadir", "./data", "data directory holding wallet.json")
	to := fs.String("to", "", "recipient address")
	amount := fs.String("amount", "", "amount in Coin (decimal)")
	fee := fs.String("fee", "0.00001", "fee in Coin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" || *amount == "" {
		return errors.New("send: --to and --amount are required")
	}
	pass, err := readPassphrase()
	if err != nil {
		return err
	}
	w, err := wallet.Open(filepath.Join(*dataDir, "wallet.json"), pass)
	if err != nil {
		return err
	}
	amountAtoms, err := parseAmount(*amount)
	if err != nil {
		return err
	}
	feeAtoms, err := parseAmount(*fee)
	if err != nil {
		return err
	}
	dag, err := loadDAGForWallet(*dataDir)
	if err != nil {
		return err
	}
	tx, err := w.BuildTx(dag, *to, amountAtoms, feeAtoms)
	if err != nil {
		return err
	}
	raw := tx.Encode()
	fmt.Printf("tx built and signed successfully (%d bytes). Hex:\n%s\n", len(raw), hex.EncodeToString(raw))
	return nil
}

// ---------------------------------------------------------------------------
// balance (Direto, sem RPC/Sockets)
// ---------------------------------------------------------------------------

func cmdBalance(args []string) error {
	fs := flag.NewFlagSet("balance", flag.ContinueOnError)
	dataDir := fs.String("datadir", "./data", "data directory holding blocks.dat")
	if err := fs.Parse(args); err != nil {
		return err
	}
	addr := fs.Arg(0)
	if addr == "" {
		return errors.New("balance: provide an address as argument")
	}

	pkh, err := cryptography.AddressToPubKeyHash(addr)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	dag, err := loadDAGForWallet(*dataDir)
	if err != nil {
		return fmt.Errorf("failed to load block store from %s: %w", *dataDir, err)
	}

	total, _, _ := dag.Balance(pkh)
	fmt.Printf("Address: %s\nBalance: %s (%d atoms)\n", addr, dag.Params().CoinString(total), total)
	return nil
}

func loadDAGForWallet(dataDir string) (*blockdag.DAG, error) {
	p := consensus.Defaults()
	store, err := storage.Open(filepath.Join(dataDir, "blocks.dat"), &p, false)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	dag, err := blockdag.New(&p, blockdag.Hooks{})
	if err != nil {
		return nil, err
	}
	err = store.ForEach(&p, func(b *blockdag.Block) error {
		return dag.AcceptBlock(b)
	})
	if err != nil {
		return nil, err
	}
	return dag, nil
}

func parseAmount(s string) (uint64, error) {
	parts := strings.SplitN(s, ".", 2)
	var whole, frac uint64
	var err error
	if len(parts) > 0 && parts[0] != "" {
		_, err = fmt.Sscanf(parts[0], "%d", &whole)
		if err != nil {
			return 0, err
		}
	}
	if len(parts) > 1 && parts[1] != "" {
		fStr := parts[1]
		if len(fStr) > 8 {
			fStr = fStr[:8]
		}
		for len(fStr) < 8 {
			fStr += "0"
		}
		_, err = fmt.Sscanf(fStr, "%d", &frac)
		if err != nil {
			return 0, err
		}
	}
	return whole*100000000 + frac, nil
}

// ---------------------------------------------------------------------------
// bench
// ---------------------------------------------------------------------------

func cmdBench(args []string) error {
	iters := 200
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.IntVar(&iters, "iters", iters, "hash iterations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	w := anonymbwt.AcquireWorkspace()
	defer anonymbwt.ReleaseWorkspace(w)
	data := make([]byte, 128)
	for i := range data {
		data[i] = byte(i)
	}
	start := time.Now()
	for i := 0; i < iters; i++ {
		data[0] = byte(i)
		w.Digest(data)
	}
	elapsed := time.Since(start)
	perHash := elapsed / time.Duration(iters)
	fmt.Printf("ANONYMBWT: %d hashes in %s => %s/hash (~%.1f H/s per core)\n",
		iters, elapsed.Round(time.Millisecond), perHash.Round(time.Microsecond),
		float64(time.Second)/float64(perHash))
	return nil
}
