# Myco: A Metadata-Private Messaging System

Myco is an implementation of a metadata-private messaging system that achieves polylogarithmic read and write efficiency while maintaining strong cryptographic guarantees. It uses a distributed-trust model with two non-colluding servers and a novel tree-based oblivious data structure that enables private communication between clients.

## Project Structure

### Source Files (`src/`)
- `client.rs` - Implements client-side functionality including message encryption, PRF computation, and path reading/writing
- `constants.rs` - Defines system-wide constants like bucket size, tree depth, and protocol parameters
- `crypto.rs` - Contains cryptographic primitives and operations including PRF, KDF, and authenticated encryption
- `dtypes.rs` - Defines core data types and structures used throughout the system
- `error.rs` - Custom error types and error handling functionality
- `lib.rs` - Main library entry point and module declarations
- `logging.rs` - Performance logging and metrics collection utilities
- `network.rs` - Network communication layer between clients and servers
- `rpc_types.rs` - RPC message types and serialization
- `server1.rs` - Server1 implementation handling client writes and batch evictions
- `server2.rs` - Server2 implementation managing the message tree and client reads
- `tree.rs` - Binary tree data structure implementation with bucket management
- `utils.rs` - Utility functions and helpers

### Binary Files (`bin/`)
- `rpc_client.rs` - Client binary for network deployment
- `rpc_server1.rs` - Server1 binary for network deployment
- `rpc_server1_tput.rs` - Server1 throughput testing binary
- `rpc_server2.rs` - Server2 binary for network deployment
- `rpc_server2_tput.rs` - Server2 throughput testing binary
- `simulation.rs` - Local simulation binary for testing and benchmarking

## Running Simulations

### Basic Simulation
```bash
cargo run --bin simulation --release
```

### No-Encryption Mode
```bash
cargo run --release --bin simulation --features no-enc benchmark
```

### Standard Encryption Mode
```bash
cargo run --release --bin simulation benchmark
```

## Running Client-Server Setup

### Start Server1
```bash
cargo run --release --bin rpc_server1 --features perf-logging
```

### Start Server2
```bash
cargo run --release --bin rpc_server2 --features perf-logging
```

### Run Client
```bash
cargo run --release --bin rpc_client --features perf-logging <server1_addr> <server2_addr>
```

Default addresses if not specified:
- Server1: http://127.0.0.1:3001
- Server2: http://127.0.0.1:3002

### Performance Logging
When `perf-logging` is enabled, metrics will be saved to the `logs` directory with filenames containing the current configuration parameters (BLOCK_SIZE, Z, D, BATCH_SIZE).

### Command Flags
- `--release`: Builds and runs in release mode for better performance
- `--features perf-logging`: Enables performance logging metrics
- `--features no-enc`: Disables encryption for testing/benchmarking
- `--bin <name>`: Specifies which binary to run (simulation, rpc_server2, or rpc_client)

## Testing
Run the test suite with:
```bash
cargo test --release
```