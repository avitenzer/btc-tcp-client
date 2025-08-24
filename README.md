# BTC TCP Client

A production-ready pure TCP Bitcoin P2P client that connects to Bitcoin mainnet nodes and listens for transactions. Designed for reliable relay operations to downstream systems.

## Usage:
```bash
# Run directly
go run main.go

# For production: separate logs from JSON output
go run main.go 2>btc-relay.log | your-downstream-processor

# With systemd or process manager for automatic restarts
./btc-client
```

## Features:
- Handshakes (version/verack), sends sendheaders + mempool
- Receives inv (tx + block), getdata, tx, headers, block
- **Dynamic network magic selection**:
  - Automatically detects network based on port number
  - 8333 → mainnet (0xD9B4BEF9)
  - 18333 → testnet (0x0709110B)
  - 38333 → signet (0x0A03CF40)
  - 18444 → regtest (0xDAB5BFFA)
- **Production-ready chain management**:
  - Chain work validation (not just longest chain)
  - Automatic reorg detection and handling
  - Transaction status updates during reorgs
  - Fork point detection and orphaned block handling
  - Reorg statistics and logging
- **Memory management**:
  - Transaction cache cleared on each reconnection
  - Prevents unbounded memory growth across reconnects
  - Logs cache cleanup statistics
- **Non-blocking JSON processing**:
  - Asynchronous JSON output to downstream systems
  - Prevents slow JSON processing from blocking Bitcoin network reads
  - Buffered output channel with overflow protection
  - Optimized for high-throughput relay operations
- Parses transactions (legacy + segwit), prints inputs & outputs (addresses + amounts)
- **Enhanced script parsing** supporting:
  - Standard outputs: P2PKH, P2SH, P2WPKH, P2WSH, P2TR (Taproot)
  - Multisig outputs: M-of-N multisignature scripts
  - OP_RETURN outputs: Data embedding with UTF-8 text detection
  - P2PK outputs: Pay-to-public-key scripts
  - Unknown scripts: Hex representation for unrecognized patterns
- Computes and prints confirmations when a seen tx is mined
- Graceful shutdown with context management
- **Reliability features**:
  - Panic recovery in all goroutines
  - Structured logging to stderr (separate from JSON data output)
  - Message size validation to prevent OOM attacks
  - Optimized connection timeouts for production use
  - Graceful degradation when downstream systems are slow
  - Periodic health monitoring and metrics reporting

## Building:
```bash
# Build the Bitcoin P2P client
go build -o btc-client main.go

# Run the binary
./btc-client
```

## Enhanced Script Parsing

The client now includes comprehensive scriptPubKey parsing that identifies and describes various Bitcoin output types:

### Supported Script Types:

1. **Standard Outputs**:
   - **P2PKH**: Pay to Public Key Hash (legacy addresses)
   - **P2SH**: Pay to Script Hash (wrapped SegWit)
   - **P2WPKH**: Pay to Witness Public Key Hash (native SegWit)
   - **P2WSH**: Pay to Witness Script Hash (native SegWit)
   - **P2TR**: Pay to Taproot (Taproot addresses)

2. **Multisig Outputs**:
   - **M-of-N Multisig**: Parses multisignature scripts with M required signatures from N total public keys
   - Shows the required and total number of signatures
   - Lists all public keys involved in the multisig

3. **OP_RETURN Outputs**:
   - **Data Embedding**: Identifies OP_RETURN scripts used for data storage
   - **UTF-8 Detection**: Automatically detects and displays UTF-8 text data
   - **Hex Fallback**: Shows hex representation for binary data

4. **P2PK Outputs**:
   - **Pay to Public Key**: Direct public key scripts (compressed and uncompressed)
   - Shows the public key in hex format

5. **Unknown Scripts**:
   - **Hex Representation**: For unrecognized script patterns, shows the full hex
   - **Size Information**: Includes script length for analysis

### JSON Output Format:

Each transaction output now includes enhanced information:
```json
{
  "index": 0,
  "value_satoshis": 1000000,
  "value_btc": 0.01,
  "script_pubkey": "76a914...",
  "script_len": 25,
  "address": "mzBc4XEFSdzCDcTxagfizbU7VXV4kqT3L3",
  "script_type": "P2PKH",
  "description": "Pay to Public Key Hash",
  "script_data": [] // Additional data for multisig, OP_RETURN, etc.
}
```

## Production-Ready Chain Management

The client now includes robust chain management suitable for mainnet production use:

### Chain Work Validation:
- **Proof-of-Work Based**: Uses cumulative chain work instead of simple height comparison
- **Difficulty Calculation**: Properly calculates block work from difficulty bits
- **Best Chain Selection**: Always follows the chain with the most cumulative work

### Reorg Detection and Handling:
- **Automatic Detection**: Detects when a new chain becomes the best chain
- **Fork Point Detection**: Finds the common ancestor of competing chains
- **Transaction Updates**: Automatically updates transaction statuses during reorgs
- **Orphaned Block Handling**: Properly handles blocks that are no longer in the best chain

### Reorg Logging:
- **Detailed Logs**: Logs reorg depth, affected blocks, and transaction changes
- **Statistics Tracking**: Maintains reorg count and last reorg height
- **Transaction Status**: Shows when transactions become unconfirmed due to reorgs

### Example Reorg Log:
```
REORG DETECTED: Chain tip changed from abc123@1000 to def456@999 (depth: 1 blocks)
Transaction 123456... unconfirmed due to reorg (was at height 1000)
Reorg stats: count=1, last at height=999
```

## Network Configuration:
The client connects to Bitcoin mainnet nodes and automatically retries connections if they fail. It includes a list of seed nodes and implements connection resilience with exponential backoff.

## Message Types and Protocol Flow

### Supported Message Types

The client implements the Bitcoin P2P protocol and supports the following message types:

#### 1. Handshake Messages
- **`version`**: Initial connection message containing protocol version, user agent, and network information
- **`verack`**: Acknowledgment of version message to complete handshake
- **`ping`/`pong`**: Keep-alive messages sent every 30 seconds to maintain connection

#### 2. Data Announcement Messages
- **`inv`** (Inventory): Announces available transactions and blocks
  - Can contain up to 50,000 items
  - Types: `InvTypeTx` (1) for transactions, `InvTypeBlock` (2) for blocks
- **`getdata`**: Requests full data for items announced in `inv` messages

#### 3. Data Transfer Messages
- **`tx`**: Full transaction data (both legacy and SegWit transactions)
- **`block`**: Complete block data including all transactions
- **`headers`**: Block headers without transaction data (up to 2,000 per message)

#### 4. Configuration Messages
- **`sendheaders`**: Tells peer to send new blocks as headers instead of inv
- **`getaddr`**: Requests list of known peer addresses
- **`addr`/`addrv2`**: Provides peer addresses
- **`sendcmpct`**, **`feefilter`**: Other configuration messages (acknowledged but not actively used)

### Message Flow

#### 1. Connection Establishment
```
Client → Node: TCP connection to port (8333 for mainnet)
Client → Node: version message
Node → Client: version message  
Client → Node: verack
Node → Client: verack
[Handshake complete]
```

#### 2. Initial Setup
```
Client → Node: sendheaders (request headers instead of inv)
Client → Node: getaddr (request peer list)
```

#### 3. Transaction Flow
```
Node → Client: inv (announces new transactions)
Client → Node: getdata (requests full tx data)
Node → Client: tx (sends transaction data)
Client: Parses tx, outputs JSON, tracks in cache
```

#### 4. Block Flow
```
Node → Client: inv (announces new block)
Client → Node: getdata (requests block)
Node → Client: block (sends full block data)
Client: 
  - Updates chain index with proof-of-work validation
  - Detects reorgs if necessary
  - Updates transaction confirmations
  - Outputs JSON for each transaction
```

#### 5. Keep-Alive Flow
```
Every 30 seconds:
Client → Node: ping (with random nonce)
Node → Client: pong (echoes nonce)
```

### Key Protocol Features

1. **Non-blocking JSON Output**: Messages are parsed and converted to JSON, then sent through a buffered channel (1000 messages) to prevent blocking network reads

2. **Chain Management**: 
   - Maintains chain index with proof-of-work validation
   - Detects and handles reorganizations
   - Tracks cumulative chain work, not just height

3. **Transaction Tracking**:
   - Caches seen transactions
   - Updates confirmation count when included in blocks
   - Handles status changes during reorgs
   - Cache cleared on reconnection to prevent memory leaks

4. **Message Size Limits**:
   - Max message size: 32MB
   - Max inventory items: 50,000
   - Max headers per message: 2,000

5. **Network Auto-Detection**:
   - Port 8333 → Mainnet (magic: 0xD9B4BEF9)
   - Port 18333 → Testnet (magic: 0x0709110B)
   - Port 38333 → Signet (magic: 0x0A03CF40)
   - Port 18444 → Regtest (magic: 0xDAB5BFFA)

The application operates as a passive listener, receiving transaction and block announcements from the Bitcoin network and outputting structured JSON data for downstream processing.

## Production Deployment

### Running with systemd

Create `/etc/systemd/system/btc-relay.service`:
```ini
[Unit]
Description=Bitcoin TCP Relay Client
After=network.target

[Service]
Type=simple
User=btcrelay
ExecStart=/usr/local/bin/btc-client
Restart=always
RestartSec=5
StandardOutput=append:/var/log/btc-relay/output.json
StandardError=append:/var/log/btc-relay/error.log

[Install]
WantedBy=multi-user.target
```

### Health Monitoring

The client logs health metrics every 60 seconds to stderr:
```
[BTC-RELAY] 2024/01/01 12:00:00.123456 HEALTH: Queue 45/1000 (4.5%), Dropped: 0, TxCache: 1523 entries, Chain height: 812456
```

Monitor for:
- **Queue utilization** > 80% indicates downstream is lagging
- **Dropped messages** > 0 means data loss is occurring
- **TxCache size** growing too large (resets on reconnect)

### Production Best Practices

1. **Separate logs from data**: Always redirect stderr to a log file
2. **Use a process manager**: systemd, supervisor, or container orchestration
3. **Monitor health logs**: Set up alerts for dropped messages or high queue usage
4. **Pipe to a buffer**: Consider using a message queue between this client and your processor
5. **Configure node address**: Set `BitcoinNode` variable or modify in code

### Resource Requirements

- **Memory**: ~100-500MB typical, depends on transaction volume
- **CPU**: Minimal, mostly I/O bound
- **Network**: Reliable connection to Bitcoin node required
- **Disk**: Only for logs (JSON output should be piped)
