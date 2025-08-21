# BTC TCP Client

A pure TCP Bitcoin P2P client that connects to Bitcoin mainnet nodes and listens for transactions.

## Usage:
```bash
go run main.go
```

## Features:
- Handshakes (version/verack), sends sendheaders + mempool
- Receives inv (tx + block), getdata, tx, headers, block
- **Production-ready chain management**:
  - Chain work validation (not just longest chain)
  - Automatic reorg detection and handling
  - Transaction status updates during reorgs
  - Fork point detection and orphaned block handling
  - Reorg statistics and logging
- Parses transactions (legacy + segwit), prints inputs & outputs (addresses + amounts)
- **Enhanced script parsing** supporting:
  - Standard outputs: P2PKH, P2SH, P2WPKH, P2WSH, P2TR (Taproot)
  - Multisig outputs: M-of-N multisignature scripts
  - OP_RETURN outputs: Data embedding with UTF-8 text detection
  - P2PK outputs: Pay-to-public-key scripts
  - Unknown scripts: Hex representation for unrecognized patterns
- Computes and prints confirmations when a seen tx is mined
- Graceful shutdown with context management

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
