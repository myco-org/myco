# Myco

## Running Simulations

### Basic Simulation
To run the basic simulation:
```bash
cargo run --bin simulation --release
```

### No-Encryption Mode
To run the simulation without encryption:
```bash
cargo run --release --bin simulation --features no-enc benchmark
```

### Standard Encryption Mode
To run the simulation with standard encryption:
```bash
cargo run --release --bin simulation benchmark
```

## Running Client-Server Setup

### Start Server2
First, start Server2 in a terminal:
```bash
cargo run --release --bin rpc_server2 --features perf-logging
```

### Run Client
Then in a separate terminal, run the client:
```bash
cargo run --release --bin rpc_client --features perf-logging <server1_addr> <server2_addr>
```
Default addresses if not specified:
- Server1: http://127.0.0.1:3001
- Server2: http://127.0.0.1:3002

### Performance Logging
When `perf-logging` is enabled, metrics will be saved to the `logs` directory with filenames containing the current configuration parameters (BLOCK_SIZE, Z, D, BATCH_SIZE).

### Command Flags Explained
- `--release`: Builds and runs in release mode for better performance
- `--features perf-logging`: Enables performance logging metrics
- `--features no-enc`: Disables encryption for testing/benchmarking
- `--bin <name>`: Specifies which binary to run (simulation, rpc_server2, or rpc_client)

### Optional Client Parameters
You can specify custom server addresses:
