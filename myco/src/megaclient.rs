use crate::constants::{INNER_BLOCK_SIZE, LAMBDA_BYTES, NUM_CLIENTS, Q, NUM_CLIENT_WRITES_PER_CHUNK};
use crate::dtypes::{Key, TreeMycoKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tonic::{Response, Status};

/// MegaClient generates test data for throughput testing
/// It pre-generates all data for all clients and provides
/// methods to access this data efficiently
pub struct MegaClient {
    rng: ChaCha20Rng,
}

impl MegaClient {
    /// Create a new MegaClient with pre-generated data for all clients
    pub fn new() -> Self {
        let rng = ChaCha20Rng::from_entropy();
        
        Self {
            rng,
        }
    }
    

    pub fn generate_writes_chunk(&mut self, chunk_index: usize, chunk_size: usize) -> (
        Vec<Vec<u8>>,     // cts
        Vec<Vec<u8>>,     // ct_ntfs
        Vec<Vec<u8>>,     // fs
        Vec<Vec<u8>>,     // f_ntfs
        Vec<Key<TreeMycoKey>>, // k_renc_ts
        Vec<Vec<u8>>,     // c_ss
    ) {
        // Calculate start and end indices for this chunk
        let start = chunk_index * chunk_size;
        let end = std::cmp::min(start + chunk_size, NUM_CLIENTS);
        
        if start >= NUM_CLIENTS {
            // Return empty vectors if we're past the end
            return (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        }
        
        // Pre-generate write data for this chunk
        let mut cts = Vec::with_capacity(end - start);
        let mut ct_ntfs = Vec::with_capacity(end - start);
        let mut fs = Vec::with_capacity(end - start);
        let mut f_ntfs = Vec::with_capacity(end - start);
        let mut k_renc_ts = Vec::with_capacity(end - start);
        let mut c_ss = Vec::with_capacity(end - start);
        
        // Generate fake data for clients in this chunk
        for i in start..end {
            // Generate fake write data
            let ct = Self::generate_fake_data(&mut self.rng, INNER_BLOCK_SIZE);
            let ct_ntf = Self::generate_fake_data(&mut self.rng, LAMBDA_BYTES);
            let f = Self::generate_fake_data(&mut self.rng, LAMBDA_BYTES);
            let f_ntf = Self::generate_fake_data(&mut self.rng, LAMBDA_BYTES);
            let k_renc_t = Key::random(&mut self.rng);
            let c_s = i.to_string().into_bytes();
            
            cts.push(ct);
            ct_ntfs.push(ct_ntf);
            fs.push(f);
            f_ntfs.push(f_ntf);
            k_renc_ts.push(k_renc_t);
            c_ss.push(c_s);
        }
        
        return (cts, ct_ntfs, fs, f_ntfs, k_renc_ts, c_ss);
    }
    
    // Keep the original method but implement it using chunks
    pub fn generate_writes(&mut self) -> (
        Vec<Vec<u8>>,     // cts
        Vec<Vec<u8>>,     // ct_ntfs
        Vec<Vec<u8>>,     // fs
        Vec<Vec<u8>>,     // f_ntfs
        Vec<Key<TreeMycoKey>>, // k_renc_ts
        Vec<Vec<u8>>,     // c_ss
    ) {
        // Calculate how many chunks we need
        let chunk_size = NUM_CLIENT_WRITES_PER_CHUNK;
        let num_chunks = (NUM_CLIENTS + chunk_size - 1) / chunk_size;
        
        // Pre-allocate vectors for all clients
        let mut cts = Vec::with_capacity(NUM_CLIENTS);
        let mut ct_ntfs = Vec::with_capacity(NUM_CLIENTS);
        let mut fs = Vec::with_capacity(NUM_CLIENTS);
        let mut f_ntfs = Vec::with_capacity(NUM_CLIENTS);
        let mut k_renc_ts = Vec::with_capacity(NUM_CLIENTS);
        let mut c_ss = Vec::with_capacity(NUM_CLIENTS);
        
        // Process each chunk
        for chunk_index in 0..num_chunks {
            let (chunk_cts, chunk_ct_ntfs, chunk_fs, chunk_f_ntfs, chunk_k_renc_ts, chunk_c_ss) = 
                self.generate_writes_chunk(chunk_index, chunk_size);
            
            cts.extend(chunk_cts);
            ct_ntfs.extend(chunk_ct_ntfs);
            fs.extend(chunk_fs);
            f_ntfs.extend(chunk_f_ntfs);
            k_renc_ts.extend(chunk_k_renc_ts);
            c_ss.extend(chunk_c_ss);
        }
        
        return (cts, ct_ntfs, fs, f_ntfs, k_renc_ts, c_ss);
    }


    pub fn generate_read_notifs(&mut self) -> Vec<Vec<Vec<u8>>> {
        let mut read_notif_indices = Vec::with_capacity(NUM_CLIENTS);
        // Generate Q fake read notification indices per client
        for _ in 0..NUM_CLIENTS {
            let mut client_notif_indices = Vec::with_capacity(Q);
            for _ in 0..Q {
                let notif_index = Self::generate_fake_data(&mut self.rng, LAMBDA_BYTES);
                client_notif_indices.push(notif_index);
            }
            read_notif_indices.push(client_notif_indices);
        }
        read_notif_indices
    }

    pub fn generate_reads(&mut self) -> Vec<Vec<u8>> {
        let mut read_indices = Vec::with_capacity(NUM_CLIENTS);
        for _ in 0..NUM_CLIENTS {
            let random_index = Self::generate_fake_data(&mut self.rng, LAMBDA_BYTES);
            read_indices.push(random_index);
        }
        read_indices
    }
    
    /// Generate random data of specified length
    fn generate_fake_data(rng: &mut ChaCha20Rng, length: usize) -> Vec<u8> {
        let mut data = vec![0u8; length];
        for i in 0..length {
            data[i] = rng.gen();
        }
        data
    }
}

#[tonic::async_trait]
pub trait MegaClientService {
    async fn get_megaclient_writes(&self) -> Result<Response<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Key<TreeMycoKey>>, Vec<Vec<u8>>)>, Status>;
} 