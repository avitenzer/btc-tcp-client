package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

/*
Pure TCP Bitcoin P2P client (regtest) that:
- Handshakes (version/verack), sends sendheaders + mempool
- Receives inv (tx + block), getdata, tx, headers, block
- Tracks headers/blocks in a tiny chain index (height + tip)
- Parses transactions (legacy + segwit), prints inputs & outputs (addresses + amounts)
- Computes and prints confirmations when a seen tx is mined

Network magics:
mainnet: 0xD9B4BEF9
testnet3:0x0709110B
signet:  0x0A03CF40
regtest: 0xDAB5BFFA
*/

const (
	UserAgent    = "/go-listener:0.3/"
	ProtoVersion = int32(70016)
	MagicRegtest = 0xD9B4BEF9

	InvTypeTx    = 1
	InvTypeBlock = 2
)

// Bitcoin mainnet node to connect to
var BitcoinNode = "71.254.210.237:8333"

// ---------- wire header ----------
type msgHeader struct {
	Magic    uint32
	Command  [12]byte
	Length   uint32
	Checksum [4]byte
}

// ---------- production-ready chain index ----------
type BlockNode struct {
	Hash      [32]byte // LE internal
	Prev      [32]byte // LE internal
	Height    int
	Work      *big.Int // Cumulative chain work
	Timestamp uint32   // Block timestamp
	Bits      uint32   // Difficulty target
}

type Chain struct {
	nodes map[[32]byte]*BlockNode
	tip   *BlockNode
	// Reorg tracking
	lastReorgHeight int
	reorgCount      int
}

func NewChain() *Chain {
	return &Chain{nodes: make(map[[32]byte]*BlockNode)}
}

func (c *Chain) addHeader(leHash, lePrev [32]byte, timestamp, bits uint32) *BlockNode {
	// height: parent height + 1 if known, else 0 (fixed when parent appears)
	h := 0
	var parentWork *big.Int
	if p, ok := c.nodes[lePrev]; ok {
		h = p.Height + 1
		parentWork = p.Work
	} else {
		parentWork = big.NewInt(0)
	}

	// Calculate block work (2^256 / (target + 1))
	target := difficultyToTarget(bits)
	blockWork := new(big.Int).Div(new(big.Int).Lsh(big.NewInt(1), 256), new(big.Int).Add(target, big.NewInt(1)))

	// Cumulative work
	cumulativeWork := new(big.Int).Add(parentWork, blockWork)

	n := &BlockNode{
		Hash:      leHash,
		Prev:      lePrev,
		Height:    h,
		Work:      cumulativeWork,
		Timestamp: timestamp,
		Bits:      bits,
	}

	if exist, ok := c.nodes[leHash]; ok {
		// upgrade height and work if parent known later
		if n.Height > exist.Height {
			exist.Height = n.Height
			exist.Work = n.Work
			exist.Timestamp = n.Timestamp
			exist.Bits = n.Bits
		}
		n = exist
	} else {
		c.nodes[leHash] = n
	}

	// try to fix orphan children heights and work
	for _, child := range c.nodes {
		if child.Prev == leHash && child.Height < n.Height+1 {
			child.Height = n.Height + 1
			// Recalculate child's work based on new parent
			childTarget := difficultyToTarget(child.Bits)
			childBlockWork := new(big.Int).Div(new(big.Int).Lsh(big.NewInt(1), 256), new(big.Int).Add(childTarget, big.NewInt(1)))
			child.Work = new(big.Int).Add(n.Work, childBlockWork)
		}
	}

	// Update tip based on chain work (production-ready)
	oldTip := c.tip
	if c.tip == nil || n.Work.Cmp(c.tip.Work) > 0 {
		c.tip = n

		// Detect and handle reorg
		if oldTip != nil && oldTip != n {
			c.handleReorg(oldTip, n)
		}
	}

	return n
}

func (c *Chain) handleReorg(oldTip, newTip *BlockNode) {
	// Find the fork point
	forkPoint := c.findForkPoint(oldTip, newTip)

	// Calculate reorg depth
	reorgDepth := oldTip.Height - forkPoint.Height

	log.Printf("REORG DETECTED: Chain tip changed from %s@%d to %s@%d (depth: %d blocks)",
		leHashToHex(oldTip.Hash), oldTip.Height,
		leHashToHex(newTip.Hash), newTip.Height,
		reorgDepth)

	// Update transaction statuses for affected transactions
	c.updateTransactionStatuses(forkPoint.Height)

	c.lastReorgHeight = newTip.Height
	c.reorgCount++

	log.Printf("Reorg stats: count=%d, last at height=%d", c.reorgCount, c.lastReorgHeight)
}

func (c *Chain) findForkPoint(chain1, chain2 *BlockNode) *BlockNode {
	// Find common ancestor by walking back both chains
	node1, node2 := chain1, chain2

	// Align heights
	for node1.Height > node2.Height {
		if parent, ok := c.nodes[node1.Prev]; ok {
			node1 = parent
		} else {
			break
		}
	}
	for node2.Height > node1.Height {
		if parent, ok := c.nodes[node2.Prev]; ok {
			node2 = parent
		} else {
			break
		}
	}

	// Walk back until we find common ancestor
	for node1 != node2 && node1 != nil && node2 != nil {
		if parent, ok := c.nodes[node1.Prev]; ok {
			node1 = parent
		} else {
			break
		}
		if parent, ok := c.nodes[node2.Prev]; ok {
			node2 = parent
		} else {
			break
		}
	}

	return node1
}

func (c *Chain) updateTransactionStatuses(forkHeight int) {
	// Update transaction statuses for transactions in orphaned blocks
	for txid, status := range txSeen {
		if status.IncludedHeight > forkHeight {
			// Transaction was in an orphaned block, reset it
			status.IncludedHeight = 0
			log.Printf("Transaction %s unconfirmed due to reorg (was at height %d)",
				txid, status.IncludedHeight)
		}
	}
}

func difficultyToTarget(bits uint32) *big.Int {
	// Convert compact difficulty to target
	exp := bits >> 24
	mantissa := bits & 0xffffff

	target := new(big.Int).Lsh(big.NewInt(int64(mantissa)), uint(8*(exp-3)))
	return target
}

func (c *Chain) addBlockHeaderFrom80(hdr80 []byte) *BlockNode {
	var prevLE [32]byte
	copy(prevLE[:], hdr80[4:36]) // prev hash in header is LE on the wire

	// Extract timestamp (bytes 68-71)
	var timestamp uint32
	binary.Read(bytes.NewReader(hdr80[68:72]), binary.LittleEndian, &timestamp)

	// Extract bits (bytes 72-75)
	var bits uint32
	binary.Read(bytes.NewReader(hdr80[72:76]), binary.LittleEndian, &bits)

	leHash := bytesToLEHash(doubleSHA256(hdr80))
	return c.addHeader(leHash, prevLE, timestamp, bits)
}

func (c *Chain) confirmationsForHeight(h int) int {
	if c.tip == nil || h <= 0 {
		return 0
	}
	return c.tip.Height - h + 1
}

func bytesToLEHash(b []byte) [32]byte {
	var le [32]byte
	for i := 0; i < 32; i++ {
		le[i] = b[31-i]
	}
	return le
}

func leHashToHex(le [32]byte) string {
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[i] = le[31-i]
	}
	return hex.EncodeToString(be)
}

// ---------- tx seen map ----------
type TxStatus struct {
	FirstSeen      time.Time
	IncludedHeight int // 0 if unmined
}

var (
	chain  = NewChain()
	txSeen = make(map[string]*TxStatus) // txid (hex) -> status
)

// ---------- tx parsing ----------
// JSON-serializable transaction structures
type TxJSON struct {
	TxID          string      `json:"txid"`
	WTxID         string      `json:"wtxid"`
	Version       uint32      `json:"version"`
	LockTime      uint32      `json:"locktime"`
	SegWit        bool        `json:"segwit"`
	Size          int         `json:"size"`
	Inputs        []TxInJSON  `json:"inputs"`
	Outputs       []TxOutJSON `json:"outputs"`
	Timestamp     time.Time   `json:"timestamp"`
	Confirmations int         `json:"confirmations,omitempty"`
	BlockHeight   int         `json:"block_height,omitempty"`
}

type TxInJSON struct {
	PrevTxID     string   `json:"prev_txid"`
	PrevIndex    uint32   `json:"prev_index"`
	ScriptSig    string   `json:"script_sig"`
	ScriptSigLen int      `json:"script_sig_len"`
	Sequence     uint32   `json:"sequence"`
	Witness      []string `json:"witness"`
}

type TxOutJSON struct {
	Index        int        `json:"index"`
	Value        int64      `json:"value_satoshis"`
	ValueBTC     float64    `json:"value_btc"`
	ScriptPubKey string     `json:"script_pubkey"`
	ScriptLen    int        `json:"script_len"`
	Address      string     `json:"address"`
	ScriptType   ScriptType `json:"script_type"`
	Description  string     `json:"description,omitempty"`
	ScriptData   []string   `json:"script_data,omitempty"` // For multisig keys, OP_RETURN data, etc.
}

// Original internal transaction structures
type Tx struct {
	Version  uint32
	Vins     []TxIn
	Vouts    []TxOut
	LockTime uint32
	SegWit   bool
}

type TxIn struct {
	PrevTxID  []byte // 32 LE
	PrevIndex uint32
	ScriptSig []byte
	Sequence  uint32
	Witness   [][]byte
}

type TxOut struct {
	Value        int64
	ScriptPubKey []byte
}

// ---------- main ----------
func main() {
	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown on interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received shutdown signal, closing connections...")
		cancel()
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			return
		default:
			log.Printf("Attempting to connect to %s", BitcoinNode)

			if err := connectAndListen(ctx, BitcoinNode); err != nil {
				if ctx.Err() != nil {
					log.Println("Context cancelled, exiting...")
					return
				}
				log.Printf("Connection error: %v", err)
				log.Printf("Retrying in 3 seconds...")

				// Wait with context cancellation check
				select {
				case <-time.After(3 * time.Second):
				case <-ctx.Done():
					log.Println("Shutting down...")
					return
				}
				continue
			}

			// Connection successful, exit the retry loop
			return
		}
	}
}

func connectAndListen(ctx context.Context, nodeAddr string) error {
	// Create dialer with context
	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", nodeAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	log.Printf("Connected to %s", nodeAddr)

	if err := handshake(ctx, conn); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	log.Println("Handshake complete")

	// Send initial messages to appear as a normal Bitcoin node
	if err := writeMessage(conn, "sendheaders", nil); err != nil {
		return fmt.Errorf("sendheaders: %w", err)
	}

	// Send getaddr to request peer addresses (normal node behavior)
	if err := writeMessage(conn, "getaddr", nil); err != nil {
		log.Printf("getaddr failed: %v", err) // Don't fail on this
	}

	log.Println("Initial messages sent, listening for transactions...")

	// Start ping ticker for keep-alive with shorter interval
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	// Channel to handle ping ticker in select
	go func() {
		for {
			select {
			case <-pingTicker.C:
				nonce := make([]byte, 8)
				_, _ = rand.Read(nonce)
				if err := writeMessage(conn, "ping", nonce); err != nil {
					log.Printf("Failed to send ping: %v", err)
					return
				}
				log.Println("Sent keep-alive ping")
			case <-ctx.Done():
				log.Println("Ping ticker stopped due to context cancellation")
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping message processing")
			return ctx.Err()
		default:
			// Set read timeout for each message - longer to avoid false timeouts
			if err := conn.SetReadDeadline(time.Now().Add(120 * time.Second)); err != nil {
				return fmt.Errorf("set read deadline: %w", err)
			}

			cmd, payload, err := readMessage(conn)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Println("Read timeout, connection might be stale")
					return fmt.Errorf("read timeout: %w", err)
				}
				return fmt.Errorf("read message: %w", err)
			}

			// Clear read deadline after successful read
			if err := conn.SetReadDeadline(time.Time{}); err != nil {
				return fmt.Errorf("clear read deadline: %w", err)
			}

			log.Printf("Received message: %s (payload: %d bytes)", cmd, len(payload))

			switch cmd {
			case "inv":
				reqTx, reqBlk := parseInv(payload)
				// Request all announced transactions (no rate limiting)
				if len(reqTx) > 0 {
					log.Printf("INV: Requesting all %d announced transactions", len(reqTx))

					// Log the transaction hashes we're requesting
					for i, hash := range reqTx {
						log.Printf("Requesting TX #%d: %x", i, hash)
					}

					if err := sendGetData(conn, InvTypeTx, reqTx); err != nil {
						log.Printf("getdata(tx) err: %v", err)
					} else {
						log.Printf("Successfully sent getdata request for %d transactions", len(reqTx))
					}
				}
				if len(reqBlk) > 0 {
					// Request all blocks (usually fewer)
					if err := sendGetData(conn, InvTypeBlock, reqBlk); err != nil {
						log.Printf("getdata(block) err: %v", err)
					}
				}
			case "headers":
				parseHeaders(payload)
			case "block":
				parseBlock(payload)
			case "tx":
				parseAndPrintTx(payload)
			case "ping":
				if err := writeMessage(conn, "pong", payload); err != nil {
					log.Printf("Failed to send pong: %v", err)
					return fmt.Errorf("pong: %w", err)
				}
				log.Println("Responded to ping with pong")
			case "pong":
				log.Println("Received pong response")
			case "addr", "addrv2":
				log.Printf("Received %s message with %d peers", cmd, len(payload))
			case "sendheaders", "sendcmpct", "feefilter":
				log.Printf("Received %s message", cmd)
			case "reject":
				log.Printf("Received reject message - peer rejected our request")
			default:
				log.Printf("Received unhandled message: %s", cmd)
			}
		}
	}
}

// ---------- handshake ----------
func handshake(ctx context.Context, conn net.Conn) error {
	vPayload := buildVersionPayload()
	if err := writeMessage(conn, "version", vPayload); err != nil {
		return fmt.Errorf("send version: %w", err)
	}
	gotVer, gotAck := false, false

	// Set a timeout for the handshake
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for !(gotVer && gotAck) {
		select {
		case <-handshakeCtx.Done():
			return fmt.Errorf("handshake timeout: %w", handshakeCtx.Err())
		default:
			// Set read deadline for this iteration
			if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
				return fmt.Errorf("set read deadline: %w", err)
			}

			cmd, payload, err := readMessage(conn)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Check if context was cancelled during timeout
				select {
				case <-handshakeCtx.Done():
					return fmt.Errorf("handshake cancelled: %w", handshakeCtx.Err())
				default:
					continue // Retry on timeout
				}
			}
			if err != nil {
				return err
			}

			switch cmd {
			case "version":
				gotVer = true
				if err := writeMessage(conn, "verack", nil); err != nil {
					return err
				}
			case "verack":
				gotAck = true
			case "ping":
				_ = writeMessage(conn, "pong", payload)
			}
		}
	}

	// Clear read deadline after successful handshake
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear read deadline: %w", err)
	}

	return nil
}

func buildVersionPayload() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, ProtoVersion)
	binary.Write(&b, binary.LittleEndian, uint64(0))
	binary.Write(&b, binary.LittleEndian, time.Now().Unix())
	writeNetAddr(&b, 0, "0.0.0.0", 0)
	writeNetAddr(&b, 0, "0.0.0.0", 0)
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	b.Write(nonce[:])
	writeVarStr(&b, []byte(UserAgent))
	binary.Write(&b, binary.LittleEndian, int32(0))
	b.WriteByte(1)
	return b.Bytes()
}

func writeNetAddr(b *bytes.Buffer, services uint64, ip string, port uint16) {
	binary.Write(b, binary.LittleEndian, services)
	b.Write(make([]byte, 16))
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	b.Write(p[:])
}

// ---------- wire framing ----------
func writeMessage(conn net.Conn, cmd string, payload []byte) error {
	var hdr msgHeader
	hdr.Magic = MagicRegtest
	copy(hdr.Command[:], []byte(cmd))
	hdr.Length = uint32(len(payload))
	sum := checksum(payload)
	copy(hdr.Checksum[:], sum[:])
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, hdr.Magic)
	buf.Write(hdr.Command[:])
	binary.Write(&buf, binary.LittleEndian, hdr.Length)
	buf.Write(hdr.Checksum[:])
	if len(payload) > 0 {
		buf.Write(payload)
	}
	_, err := conn.Write(buf.Bytes())
	return err
}

func readMessage(conn net.Conn) (string, []byte, error) {
	h := make([]byte, 24)
	if _, err := io.ReadFull(conn, h); err != nil {
		return "", nil, err
	}
	magic := binary.LittleEndian.Uint32(h[0:4])
	if magic != MagicRegtest {
		return "", nil, fmt.Errorf("magic mismatch: got 0x%08x", magic)
	}
	cmd := strings.TrimRight(string(h[4:16]), "\x00")
	length := binary.LittleEndian.Uint32(h[16:20])
	var ck [4]byte
	copy(ck[:], h[20:24])
	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return "", nil, err
		}
		expectedChecksum := checksum(payload)
		if !bytes.Equal(expectedChecksum[:], ck[:]) {
			return "", nil, fmt.Errorf("checksum mismatch on %s", cmd)
		}
	}
	return cmd, payload, nil
}

func checksum(b []byte) [4]byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	var out [4]byte
	copy(out[:], h2[:4])
	return out
}

// ---------- varint/varstr ----------
func writeVarInt(b *bytes.Buffer, v uint64) {
	switch {
	case v < 0xFD:
		b.WriteByte(byte(v))
	case v <= 0xFFFF:
		b.WriteByte(0xFD)
		tmp := make([]byte, 2)
		binary.LittleEndian.PutUint16(tmp, uint16(v))
		b.Write(tmp)
	case v <= 0xFFFFFFFF:
		b.WriteByte(0xFE)
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(v))
		b.Write(tmp)
	default:
		b.WriteByte(0xFF)
		tmp := make([]byte, 8)
		binary.LittleEndian.PutUint64(tmp, v)
		b.Write(tmp)
	}
}

func readVarInt(r *bytes.Reader) (uint64, error) {
	p, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch p {
	case 0xFF:
		var v uint64
		err = binary.Read(r, binary.LittleEndian, &v)
		return v, err
	case 0xFE:
		var v uint32
		err = binary.Read(r, binary.LittleEndian, &v)
		return uint64(v), err
	case 0xFD:
		var v uint16
		err = binary.Read(r, binary.LittleEndian, &v)
		return uint64(v), err
	default:
		return uint64(p), nil
	}
}

func writeVarStr(b *bytes.Buffer, s []byte) {
	writeVarInt(b, uint64(len(s)))
	b.Write(s)
}

func readVarStr(r *bytes.Reader) ([]byte, error) {
	l, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	return buf, err
}

// ---------- inv/getdata ----------
func parseInv(payload []byte) (txHashes [][]byte, blkHashes [][]byte) {
	r := bytes.NewReader(payload)
	n, err := readVarInt(r)
	if err != nil {
		log.Printf("inv varint: %v", err)
		return
	}
	for i := uint64(0); i < n; i++ {
		var typ uint32
		if err := binary.Read(r, binary.LittleEndian, &typ); err != nil {
			log.Printf("inv type: %v", err)
			return
		}
		h := make([]byte, 32)
		if _, err := io.ReadFull(r, h); err != nil {
			log.Printf("inv hash: %v", err)
			return
		}
		switch typ {
		case InvTypeTx:
			txHashes = append(txHashes, h)
		case InvTypeBlock:
			blkHashes = append(blkHashes, h)
		}
	}
	if len(txHashes) > 0 {
		log.Printf("INV: %d tx(s) announced", len(txHashes))
	}
	if len(blkHashes) > 0 {
		log.Printf("INV: %d block(s) announced", len(blkHashes))
	}
	return
}

func sendGetData(conn net.Conn, invType uint32, hashes [][]byte) error {
	var b bytes.Buffer
	writeVarInt(&b, uint64(len(hashes)))
	for _, h := range hashes {
		binary.Write(&b, binary.LittleEndian, invType)
		b.Write(h) // LE byte order, as received
	}
	return writeMessage(conn, "getdata", b.Bytes())
}

// ---------- headers/block ----------
func parseHeaders(payload []byte) {
	r := bytes.NewReader(payload)
	n, err := readVarInt(r)
	if err != nil {
		log.Printf("headers varint: %v", err)
		return
	}
	for i := uint64(0); i < n; i++ {
		hdr := make([]byte, 80)
		if _, err := io.ReadFull(r, hdr); err != nil {
			log.Printf("header read: %v", err)
			return
		}
		// txn_count (must be 0 in headers msg)
		if _, err := readVarInt(r); err != nil {
			log.Printf("headers txn_count: %v", err)
			return
		}
		node := chain.addBlockHeaderFrom80(hdr)
		log.Printf("HEADER: %s height=%d tip=%s@%d",
			leHashToHex(node.Hash), node.Height,
			func() string {
				if chain.tip != nil {
					return leHashToHex(chain.tip.Hash)
				}
				return "-"
			}(),
			func() int {
				if chain.tip != nil {
					return chain.tip.Height
				}
				return -1
			}(),
		)
	}
}

func parseBlock(payload []byte) {
	r := bytes.NewReader(payload)
	hdr := make([]byte, 80)
	if _, err := io.ReadFull(r, hdr); err != nil {
		log.Printf("block header: %v", err)
		return
	}
	node := chain.addBlockHeaderFrom80(hdr)
	txCount, err := readVarInt(r)
	if err != nil {
		log.Printf("block txcount: %v", err)
		return
	}
	log.Printf("BLOCK: %s height=%d txs=%d (tip=%s@%d)",
		leHashToHex(node.Hash), node.Height, txCount,
		func() string {
			if chain.tip != nil {
				return leHashToHex(chain.tip.Hash)
			}
			return "-"
		}(),
		func() int {
			if chain.tip != nil {
				return chain.tip.Height
			}
			return -1
		}(),
	)

	for i := uint64(0); i < txCount; i++ {
		tx, rawNoWit, rawWithWit, err := readTx(r)
		if err != nil {
			log.Printf("block tx parse #%d: %v", i, err)
			return
		}
		txid := hashToHex(doubleSHA256(rawNoWit))
		wtxid := hashToHex(doubleSHA256(rawWithWit))

		// Convert block transaction to JSON
		txJSON := txToJSON(tx, txid, wtxid, len(rawWithWit))
		txJSON.BlockHeight = node.Height
		txJSON.Confirmations = chain.confirmationsForHeight(node.Height)

		jsonData, err := json.MarshalIndent(txJSON, "", "  ")
		if err != nil {
			log.Printf("JSON marshal error: %v", err)
			continue
		}
		fmt.Printf("Block TX #%d:\n%s\n", i, string(jsonData))

		// mark confirmations
		st, ok := txSeen[txid]
		if !ok {
			st = &TxStatus{FirstSeen: time.Now()}
			txSeen[txid] = st
		}
		if st.IncludedHeight == 0 {
			st.IncludedHeight = node.Height
		}
	}
}

// Convert internal transaction to JSON format
func txToJSON(tx *Tx, txid, wtxid string, rawSize int) *TxJSON {
	now := time.Now()

	// Convert inputs
	inputs := make([]TxInJSON, len(tx.Vins))
	for i, vin := range tx.Vins {
		// Convert previous txid from LE bytes to hex
		prevTxID := make([]byte, 32)
		for j := 0; j < 32; j++ {
			prevTxID[j] = vin.PrevTxID[31-j]
		}

		// Convert witness data
		witness := make([]string, len(vin.Witness))
		for j, w := range vin.Witness {
			witness[j] = hex.EncodeToString(w)
		}

		inputs[i] = TxInJSON{
			PrevTxID:     hex.EncodeToString(prevTxID),
			PrevIndex:    vin.PrevIndex,
			ScriptSig:    hex.EncodeToString(vin.ScriptSig),
			ScriptSigLen: len(vin.ScriptSig),
			Sequence:     vin.Sequence,
			Witness:      witness,
		}
	}

	// Convert outputs
	outputs := make([]TxOutJSON, len(tx.Vouts))
	for i, vout := range tx.Vouts {
		scriptInfo := parseScript(vout.ScriptPubKey)

		outputs[i] = TxOutJSON{
			Index:        i,
			Value:        vout.Value,
			ValueBTC:     float64(vout.Value) / 1e8,
			ScriptPubKey: hex.EncodeToString(vout.ScriptPubKey),
			ScriptLen:    len(vout.ScriptPubKey),
			Address:      scriptInfo.Address,
			ScriptType:   scriptInfo.Type,
			Description:  scriptInfo.Description,
		}

		// Add script-specific data
		switch scriptInfo.Type {
		case ScriptTypeMultisig:
			outputs[i].ScriptData = scriptInfo.Keys
		case ScriptTypeOpReturn:
			if len(scriptInfo.Data) > 0 {
				outputs[i].ScriptData = []string{fmt.Sprintf("%x", scriptInfo.Data)}
			}
		case ScriptTypeP2PK:
			if len(scriptInfo.Data) > 0 {
				outputs[i].ScriptData = []string{fmt.Sprintf("%x", scriptInfo.Data)}
			}
		}
	}

	// Check for confirmations if transaction is known
	var confirmations int
	var blockHeight int
	if st, ok := txSeen[txid]; ok {
		if st.IncludedHeight > 0 {
			confirmations = chain.confirmationsForHeight(st.IncludedHeight)
			blockHeight = st.IncludedHeight
		}
	}

	return &TxJSON{
		TxID:          txid,
		WTxID:         wtxid,
		Version:       tx.Version,
		LockTime:      tx.LockTime,
		SegWit:        tx.SegWit,
		Size:          rawSize,
		Inputs:        inputs,
		Outputs:       outputs,
		Timestamp:     now,
		Confirmations: confirmations,
		BlockHeight:   blockHeight,
	}
}

func parseAndPrintTx(payload []byte) {
	r := bytes.NewReader(payload)
	tx, rawNoWit, rawWithWit, err := readTx(r)
	if err != nil {
		log.Printf("tx parse: %v", err)
		return
	}

	txid := hashToHex(doubleSHA256(rawNoWit))
	wtxid := hashToHex(doubleSHA256(rawWithWit))

	// Update transaction status
	if _, ok := txSeen[txid]; !ok {
		txSeen[txid] = &TxStatus{FirstSeen: time.Now()}
	}

	// Convert to JSON and print
	txJSON := txToJSON(tx, txid, wtxid, len(payload))
	jsonData, err := json.MarshalIndent(txJSON, "", "  ")
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		return
	}

	fmt.Println(string(jsonData))
}

func readTx(r *bytes.Reader) (*Tx, []byte, []byte, error) {
	startPos := r.Size() - int64(r.Len())

	var version uint32
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, nil, nil, err
	}
	// check segwit marker/flag
	marker, _ := r.ReadByte()
	flag, _ := r.ReadByte()
	segwit := marker == 0x00 && flag != 0x00
	if !segwit {
		r.UnreadByte()
		r.UnreadByte()
	}

	vinCount, err := readVarInt(r)
	if err != nil {
		return nil, nil, nil, err
	}
	vins := make([]TxIn, 0, vinCount)
	for i := uint64(0); i < vinCount; i++ {
		var in TxIn
		in.PrevTxID = make([]byte, 32)
		if _, err := io.ReadFull(r, in.PrevTxID); err != nil {
			return nil, nil, nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &in.PrevIndex); err != nil {
			return nil, nil, nil, err
		}
		sig, err := readVarStr(r)
		if err != nil {
			return nil, nil, nil, err
		}
		in.ScriptSig = sig
		if err := binary.Read(r, binary.LittleEndian, &in.Sequence); err != nil {
			return nil, nil, nil, err
		}
		vins = append(vins, in)
	}

	voutCount, err := readVarInt(r)
	if err != nil {
		return nil, nil, nil, err
	}
	vouts := make([]TxOut, 0, voutCount)
	for i := uint64(0); i < voutCount; i++ {
		var out TxOut
		if err := binary.Read(r, binary.LittleEndian, &out.Value); err != nil {
			return nil, nil, nil, err
		}
		pk, err := readVarStr(r)
		if err != nil {
			return nil, nil, nil, err
		}
		out.ScriptPubKey = pk
		vouts = append(vouts, out)
	}

	if segwit {
		for i := range vins {
			cnt, err := readVarInt(r)
			if err != nil {
				return nil, nil, nil, err
			}
			w := make([][]byte, cnt)
			for j := uint64(0); j < cnt; j++ {
				val, err := readVarStr(r)
				if err != nil {
					return nil, nil, nil, err
				}
				w[j] = val
			}
			vins[i].Witness = w
		}
	}

	var locktime uint32
	if err := binary.Read(r, binary.LittleEndian, &locktime); err != nil {
		return nil, nil, nil, err
	}

	endPos := r.Size() - int64(r.Len())
	rawWithWit := make([]byte, endPos-startPos)
	// We can't easily slice from bytes.Reader; rebuild the raw with witness:
	rawWithWit = rebuildRawWithWitness(&Tx{
		Version: version, Vins: append([]TxIn(nil), vins...),
		Vouts: vouts, LockTime: locktime, SegWit: segwit,
	})

	// Re-encode NO-WITNESS for txid
	var noW bytes.Buffer
	binary.Write(&noW, binary.LittleEndian, version)
	writeVarInt(&noW, vinCount)
	for _, in := range vins {
		noW.Write(in.PrevTxID)
		binary.Write(&noW, binary.LittleEndian, in.PrevIndex)
		writeVarStr(&noW, in.ScriptSig)
		binary.Write(&noW, binary.LittleEndian, in.Sequence)
	}
	writeVarInt(&noW, voutCount)
	for _, out := range vouts {
		binary.Write(&noW, binary.LittleEndian, out.Value)
		writeVarStr(&noW, out.ScriptPubKey)
	}
	binary.Write(&noW, binary.LittleEndian, locktime)

	tx := &Tx{Version: version, Vins: vins, Vouts: vouts, LockTime: locktime, SegWit: segwit}
	return tx, noW.Bytes(), rawWithWit, nil
}

func rebuildRawWithWitness(tx *Tx) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, tx.Version)
	if tx.SegWit {
		b.WriteByte(0x00)
		b.WriteByte(0x01)
	}
	writeVarInt(&b, uint64(len(tx.Vins)))
	for _, in := range tx.Vins {
		b.Write(in.PrevTxID)
		binary.Write(&b, binary.LittleEndian, in.PrevIndex)
		writeVarStr(&b, in.ScriptSig)
		binary.Write(&b, binary.LittleEndian, in.Sequence)
	}
	writeVarInt(&b, uint64(len(tx.Vouts)))
	for _, out := range tx.Vouts {
		binary.Write(&b, binary.LittleEndian, out.Value)
		writeVarStr(&b, out.ScriptPubKey)
	}
	if tx.SegWit {
		for _, in := range tx.Vins {
			writeVarInt(&b, uint64(len(in.Witness)))
			for _, w := range in.Witness {
				writeVarStr(&b, w)
			}
		}
	}
	binary.Write(&b, binary.LittleEndian, tx.LockTime)
	return b.Bytes()
}

// ---------- hashing helpers ----------
func doubleSHA256(b []byte) []byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

func hashToHex(h []byte) string {
	rev := make([]byte, len(h))
	for i := 0; i < len(h); i++ {
		rev[i] = h[len(h)-1-i]
	}
	return hex.EncodeToString(rev)
}

// ---------- address decoding (regtest/testnet prefixes) ----------
const (
	p2pkhVerTestnet = 0x6f
	p2shVerTestnet  = 0xc4
	bech32HRP       = "bcrt"
)

// ScriptType represents the type of scriptPubKey
type ScriptType string

const (
	ScriptTypeP2PKH    ScriptType = "P2PKH"
	ScriptTypeP2SH     ScriptType = "P2SH"
	ScriptTypeP2WPKH   ScriptType = "P2WPKH"
	ScriptTypeP2WSH    ScriptType = "P2WSH"
	ScriptTypeP2TR     ScriptType = "P2TR"
	ScriptTypeMultisig ScriptType = "MULTISIG"
	ScriptTypeOpReturn ScriptType = "OP_RETURN"
	ScriptTypeP2PK     ScriptType = "P2PK"
	ScriptTypeUnknown  ScriptType = "UNKNOWN"
)

// ScriptInfo contains parsed script information
type ScriptInfo struct {
	Type        ScriptType
	Address     string
	Description string
	Data        []byte
	Keys        []string // For multisig
	Required    int      // For multisig
	Total       int      // For multisig
}

func decodeAddress(script []byte) string {
	info := parseScript(script)
	return info.Address
}

func parseScript(script []byte) ScriptInfo {
	if len(script) == 0 {
		return ScriptInfo{Type: ScriptTypeUnknown, Address: "empty", Description: "Empty script"}
	}

	// OP_RETURN: OP_RETURN <data>
	if len(script) >= 2 && script[0] == 0x6a {
		dataLen := int(script[1])
		if len(script) >= 2+dataLen {
			data := script[2 : 2+dataLen]
			description := "OP_RETURN data"
			if len(data) <= 80 {
				// Try to decode as UTF-8 text
				if utf8.Valid(data) {
					description = fmt.Sprintf("OP_RETURN text: %q", string(data))
				} else {
					description = fmt.Sprintf("OP_RETURN data: %x", data)
				}
			} else {
				description = fmt.Sprintf("OP_RETURN data: %x...", data[:80])
			}
			return ScriptInfo{
				Type:        ScriptTypeOpReturn,
				Address:     fmt.Sprintf("OP_RETURN:%x", data),
				Description: description,
				Data:        data,
			}
		}
	}

	// P2PKH: OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG
	if len(script) == 25 &&
		script[0] == 0x76 && script[1] == 0xa9 &&
		script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac {
		h160 := script[3:23]
		address := base58Check(append([]byte{p2pkhVerTestnet}, h160...))
		return ScriptInfo{
			Type:        ScriptTypeP2PKH,
			Address:     address,
			Description: "Pay to Public Key Hash",
		}
	}

	// P2SH: OP_HASH160 0x14 <20> OP_EQUAL
	if len(script) == 23 &&
		script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
		h160 := script[2:22]
		address := base58Check(append([]byte{p2shVerTestnet}, h160...))
		return ScriptInfo{
			Type:        ScriptTypeP2SH,
			Address:     address,
			Description: "Pay to Script Hash",
		}
	}

	// P2WPKH: OP_0 0x14 <20>
	if len(script) == 22 && script[0] == 0x00 && script[1] == 0x14 {
		address := bech32Encode(bech32HRP, 0, script[2:])
		return ScriptInfo{
			Type:        ScriptTypeP2WPKH,
			Address:     address,
			Description: "Pay to Witness Public Key Hash",
		}
	}

	// P2WSH: OP_0 0x20 <32>
	if len(script) == 34 && script[0] == 0x00 && script[1] == 0x20 {
		address := bech32Encode(bech32HRP, 0, script[2:])
		return ScriptInfo{
			Type:        ScriptTypeP2WSH,
			Address:     address,
			Description: "Pay to Witness Script Hash",
		}
	}

	// P2TR (taproot): OP_1 0x20 <32>
	if len(script) == 34 && script[0] == 0x51 && script[1] == 0x20 {
		address := bech32mEncode(bech32HRP, 1, script[2:])
		return ScriptInfo{
			Type:        ScriptTypeP2TR,
			Address:     address,
			Description: "Pay to Taproot",
		}
	}

	// P2PK: <pubkey> OP_CHECKSIG
	if len(script) == 67 && script[0] == 0x41 && script[66] == 0xac {
		// Compressed public key
		pubkey := script[1:66]
		address := fmt.Sprintf("P2PK:%x", pubkey)
		return ScriptInfo{
			Type:        ScriptTypeP2PK,
			Address:     address,
			Description: "Pay to Public Key (compressed)",
			Data:        pubkey,
		}
	}
	if len(script) == 35 && script[0] == 0x21 && script[34] == 0xac {
		// Uncompressed public key
		pubkey := script[1:34]
		address := fmt.Sprintf("P2PK:%x", pubkey)
		return ScriptInfo{
			Type:        ScriptTypeP2PK,
			Address:     address,
			Description: "Pay to Public Key (uncompressed)",
			Data:        pubkey,
		}
	}

	// Multisig: OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG
	multisigInfo := parseMultisig(script)
	if multisigInfo.Type == ScriptTypeMultisig {
		return multisigInfo
	}

	// Unknown script
	return ScriptInfo{
		Type:        ScriptTypeUnknown,
		Address:     fmt.Sprintf("script:%x", script),
		Description: fmt.Sprintf("Unknown script (%d bytes)", len(script)),
		Data:        script,
	}
}

func parseMultisig(script []byte) ScriptInfo {
	if len(script) < 4 {
		return ScriptInfo{Type: ScriptTypeUnknown}
	}

	// Check if it starts with a valid M value (OP_1 to OP_16)
	m := int(script[0])
	if m < 0x51 || m > 0x60 {
		return ScriptInfo{Type: ScriptTypeUnknown}
	}
	required := m - 0x50

	// Check if it ends with OP_N OP_CHECKMULTISIG
	if len(script) < 3 {
		return ScriptInfo{Type: ScriptTypeUnknown}
	}

	n := int(script[len(script)-2])
	if n < 0x51 || n > 0x60 {
		return ScriptInfo{Type: ScriptTypeUnknown}
	}
	total := n - 0x50

	if script[len(script)-1] != 0xae { // OP_CHECKMULTISIG
		return ScriptInfo{Type: ScriptTypeUnknown}
	}

	// Parse public keys
	var keys []string
	pos := 1
	for i := 0; i < total && pos < len(script)-2; i++ {
		if pos >= len(script)-2 {
			break
		}

		keyLen := int(script[pos])
		if keyLen == 0x21 || keyLen == 0x41 { // Compressed or uncompressed
			if pos+1+keyLen <= len(script)-2 {
				pubkey := script[pos+1 : pos+1+keyLen]
				keys = append(keys, fmt.Sprintf("%x", pubkey))
				pos += 1 + keyLen
			} else {
				break
			}
		} else {
			break
		}
	}

	if len(keys) == total {
		address := fmt.Sprintf("MULTISIG:%d-of-%d", required, total)
		description := fmt.Sprintf("%d-of-%d Multisig", required, total)
		return ScriptInfo{
			Type:        ScriptTypeMultisig,
			Address:     address,
			Description: description,
			Keys:        keys,
			Required:    required,
			Total:       total,
		}
	}

	return ScriptInfo{Type: ScriptTypeUnknown}
}

// ---------- base58check ----------
var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func base58Check(payload []byte) string {
	cs := doubleSHA256(payload)[:4]
	full := append(payload, cs...)
	zeros := 0
	for zeros < len(full) && full[zeros] == 0 {
		zeros++
	}
	num := new(big.Int).SetBytes(full)
	var out []byte
	mod := new(big.Int)
	base := big.NewInt(58)
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, b58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// ---------- bech32/bech32m (minimal) ----------
func bech32Polymod(values []int) int {
	GEN := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := (chk >> 25) & 0xff
		chk = ((chk & 0x1ffffff) << 5) ^ v
		for i := 0; i < 5; i++ {
			if ((b >> i) & 1) == 1 {
				chk ^= GEN[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []int {
	r := []int{}
	for _, c := range hrp {
		r = append(r, int(c>>5))
	}
	r = append(r, 0)
	for _, c := range hrp {
		r = append(r, int(c&31))
	}
	return r
}

var bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]int, bool) {
	var ret []int
	acc := 0
	bits := uint(0)
	maxv := (1 << toBits) - 1
	for _, value := range data {
		if (value >> fromBits) > 0 {
			return nil, false
		}
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, (acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, (acc<<(toBits-bits))&maxv)
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, false
	}
	return ret, true
}

func bech32CreateChecksum(hrp string, data []int, constM int) []int {
	values := append(bech32HrpExpand(hrp), data...)
	values = append(values, []int{0, 0, 0, 0, 0, 0}...)
	mod := bech32Polymod(values) ^ constM
	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (mod >> uint(5*(5-i))) & 31
	}
	return checksum
}

func bech32Encode(hrp string, witVer int, prog []byte) string {
	data := []int{witVer}
	cv, ok := convertBits(prog, 8, 5, true)
	if !ok {
		return ""
	}
	data = append(data, cv...)
	constM := 1
	checksum := bech32CreateChecksum(hrp, data, constM)
	combined := append(data, checksum...)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range combined {
		sb.WriteByte(bech32Charset[v])
	}
	return sb.String()
}

func bech32mEncode(hrp string, witVer int, prog []byte) string {
	data := []int{witVer}
	cv, ok := convertBits(prog, 8, 5, true)
	if !ok {
		return ""
	}
	data = append(data, cv...)
	constM := 0x2bc830a3
	checksum := bech32CreateChecksum(hrp, data, constM)
	combined := append(data, checksum...)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range combined {
		sb.WriteByte(bech32Charset[v])
	}
	return sb.String()
}
