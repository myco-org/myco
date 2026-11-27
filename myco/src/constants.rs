//! Constants used in the Myco protocol.
/// Parameter controlling number of paths sampled per client write.
/// Set to 1 since each client writes exactly one message per epoch.
pub const NU: usize = 1;

/// Size of each bucket in the binary tree.
/// Set to 53 from simulation at 2^26 messages (2,684,354 clients): the chance that some bucket
/// exceeds Z in an epoch is about NUM_CLIENTS / 2^(Z+1), about 2^-32.6 here.
pub const Z: usize = 53;


/// Size of each bucket for Matrix-Myco (notification buckets). Each write adds one notification,
/// so an epoch puts NUM_CLIENTS notifications into Q * NUM_CLIENTS buckets. The capacity analysis
/// (and matrix_simulation.rs) conservatively assumes Q * NUM_CLIENTS notifications, under which
/// the chance that some bucket exceeds Z_M in an epoch is about Q * NUM_CLIENTS * e^-1 / (Z_M + 1)!,
/// about 2^-39.5 at 2,684,354 clients; with the actual load it is far smaller.
pub const Z_M: usize = 20;

/// Size of each bucket in bytes, calculated as bucket capacity * block size + size of digital signature.
pub const BUCKET_SIZE_BYTES: usize = Z * BLOCK_SIZE + 32;

/// Size of each notification bucket in bytes, calculated as bucket capacity * block size
pub const NOTIFICATION_BUCKET_SIZE_BYTES: usize = Z_M * LAMBDA_BYTES;

/// Number of iterations for latency benchmarking
pub const LATENCY_BENCH_COUNT: usize = 10;

/// Number of iterations for throughput testing
pub const THROUGHPUT_ITERATIONS: usize = 10;

/// Total block size including encrypted message and metadata
pub const BLOCK_SIZE: usize = INNER_BLOCK_SIZE + NONCE_SIZE + TAG_SIZE;

/// Size of inner encrypted block including message and metadata
pub const INNER_BLOCK_SIZE: usize = MESSAGE_SIZE + NONCE_SIZE + TAG_SIZE;

/// Maximum bytes per request for gRPC messages
pub const MAX_REQUEST_SIZE: usize = 4 * 1024 * 1024 - (32 * 1024);

/// Number of buckets that can be written in one batch chunk
pub const NUM_BUCKETS_PER_BATCH_WRITE_CHUNK: usize = 
    MAX_REQUEST_SIZE / BUCKET_SIZE_BYTES; // Leave 32KB for protobuf overhead


/// Number of buckets that can be written in one notification chunk
pub const NUM_BUCKETS_PER_NOTIFICATION_CHUNK: usize = 
    MAX_REQUEST_SIZE / (NOTIFICATION_BUCKET_SIZE_BYTES * 12); // Make chunks much smaller


/// Fixed seed for throughput benchmark RNG to ensure reproducible results
pub const FIXED_SEED_TPUT_RNG: [u8; 32] = [1u8; 32];

/// Number of conversations
pub const Q: usize = 64;

pub const LAMBDA_BYTES: usize = 16;

/// Size of the nonce used in authenticated encryption (AES-GCM)
pub const NONCE_SIZE: usize = 12;

/// Size of the authentication tag for AES-GCM
pub const TAG_SIZE: usize = 16;

/// Number of epochs a message persists before expiring and being deleted.
/// Set to 100 to ensure messages remain available long enough for clients 
/// who may temporarily go offline.
pub const DELTA: usize = 25;

/// Number of warmup iterations
pub const WARMUP_COUNT: usize = DELTA;

/// Depth of the binary tree used to store messages.
/// With D=18, supports a database size of 2^18 = 262,144 messages.
pub const D: usize = 18;

/// Security parameter for cryptographic operations in bits.
/// Standard 128-bit security level for keys and PRFs.
pub const LAMBDA: usize = 128;

/// Number of active clients in the system, calculated as database size / message lifetime.
/// This matches Talek's approach to message time-to-live.
pub const NUM_CLIENTS: usize = DB_SIZE / DELTA;

/// Total size of the message database, calculated as 2^D.
pub const DB_SIZE: usize = 1 << D;

/// Size of plaintext message payload in bytes.
/// Set to 228 bytes to match block sizes used in prior PIR systems.
pub const MESSAGE_SIZE: usize = 228;

/// Deterministic seed for server signing key pair (Ed25519).
pub const SERVER_SIGNING_SEED: [u8; 32] = [42u8; 32];

/// Maximum number of read indices to process in a single request
/// This takes into account that each read index returns D buckets
/// Each bucket is Z * BLOCK_SIZE bytes
pub const MAX_READ_INDICES_PER_CHUNK: usize = MAX_REQUEST_SIZE / (D * BUCKET_SIZE_BYTES);

/// Maximum number of read indices to process in a single request.
pub const MAX_READ_INDICES_PER_CHUNK_SERVER_2: usize = MAX_REQUEST_SIZE / BUCKET_SIZE_BYTES;

/// Maximum number of notification indices to process in a single request
/// This takes into account that each notification index returns D buckets
/// Each bucket is Z_M * LAMBDA_BYTES bytes
pub const MAX_NOTIF_INDICES_PER_CHUNK: usize = MAX_REQUEST_SIZE / (NOTIFICATION_BUCKET_SIZE_BYTES);

/// Maximum number of clients to request PRF keys for in a single chunk
/// Each client has up to DELTA PRF keys and each key is LAMBDA_BYTES bytes
/// This ensures we stay under the gRPC message size limit
pub const MAX_CLIENTS_PER_PRF_KEY_CHUNK: usize = 
    MAX_REQUEST_SIZE / (DELTA * LAMBDA_BYTES * 2); // Leave 32KB for protobuf overhead

/// Number of bits in the PRF
pub const D_BYTES: usize = (D + 7) / 8;

/// Number of bytes in the notification location. Eight bytes, reduced mod Q * N by
/// `utils::l_to_u64`, so that every notification bucket is reachable and the bias of the
/// reduction is below 2^-35 at every supported size.
pub const NOTIF_LOC_BYTES: usize = 8;

/// With the `short-reads` feature, readers skip the top levels of the tree for as long as each
/// bucket of the first level they do read is expected to lie on at least this many of the
/// paths Server1 samples per epoch (see `utils::read_skipped_levels`).
pub const MIN_PATHS_PER_BUCKET: usize = 64;

/// Number of vCPUs on Server1
pub const SERVER1_VCPU_COUNT: usize = 64;

/// Number of vCPUs on Server2
pub const SERVER2_VCPU_COUNT: usize = 64;

/// Number of connections to establish between Server1 and Server2
/// Using a reasonable fraction of available cores for network connections
pub const S1_S2_CONNECTION_COUNT: usize = 32;


/// Maximum number of notification indices to send in a single request
/// This is based on the size of the indices themselves, not the response size
/// Each index is NOTIF_LOC_BYTES bytes
pub const MAX_NOTIFICATION_INDICES_PER_REQUEST: usize = 
    MAX_REQUEST_SIZE / NOTIF_LOC_BYTES; // Leave 32KB for protobuf overhead

// Calculate log2 of NUM_CLIENTS using integer operations
pub const LOG_2_NUM_CLIENTS: usize = (NUM_CLIENTS as usize).ilog2() as usize;

// ct, ct_ntf, f, f_ntf (LAMBDA_BYTES each: the client's values are full-length PRF outputs), k_renc_t, c_s
pub const WRITE_DATA_CHUNK_SIZE: usize = INNER_BLOCK_SIZE + 4 * LAMBDA_BYTES + LOG_2_NUM_CLIENTS;

pub const NUM_CLIENT_WRITES_PER_CHUNK: usize = MAX_REQUEST_SIZE / WRITE_DATA_CHUNK_SIZE;

/// Number of buckets that can be sent in a single gRPC message
pub const NUM_BUCKETS_PER_GRPC_MESSAGE: usize = MAX_REQUEST_SIZE / BUCKET_SIZE_BYTES;