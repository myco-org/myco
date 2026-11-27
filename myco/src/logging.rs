//! Logging utilities for tracking latency and bytes metrics.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    /// Global log for storing latency metrics with operation name, duration in ms, and timestamps
    static ref LATENCY_LOG: Mutex<Vec<(String, f64, u64, u64)>> = Mutex::new(Vec::new());
    /// Global log for storing bytes metrics with operation name and byte count
    static ref BYTES_LOG: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());
    /// Track ongoing batch operations
    static ref BATCH_OPERATIONS: Mutex<HashMap<String, (Instant, u64)>> = Mutex::new(HashMap::new());
}

/// Tracks latency metrics for an operation, with support for pausing/resuming timing
pub struct LatencyMetric {
    /// Name of the operation being timed
    operation: String,
    /// Start time of the operation
    start_time: Instant,
    /// Unix timestamp in microseconds when operation started
    start_timestamp: u64,
    /// Total duration accumulated when paused
    accumulated_duration: Duration,
    /// Whether timing is currently paused
    is_paused: bool,
}

/// Tracks bytes metrics for an operation
pub struct BytesMetric {
    /// Name of the operation being measured
    operation: String,
    /// Number of bytes processed
    bytes: usize,
}

impl LatencyMetric {
    /// Creates a new LatencyMetric for the given operation name.
    /// Starts timing immediately.
    pub fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            start_time: Instant::now(),
            start_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64,
            accumulated_duration: Duration::from_secs(0),
            is_paused: false,
        }
    }

    /// Pauses timing of the operation.
    /// Accumulated duration is preserved.
    pub fn pause(&mut self) {
        if !self.is_paused {
            self.accumulated_duration += self.start_time.elapsed();
            self.is_paused = true;
        }
    }

    /// Resumes timing of the operation.
    /// Continues from accumulated duration.
    pub fn resume(&mut self) {
        if self.is_paused {
            self.start_time = Instant::now();
            self.is_paused = false;
        }
    }

    /// Finishes timing and logs the final duration.
    pub fn finish(self) {
        {
            let final_duration = if self.is_paused {
                self.accumulated_duration
            } else {
                self.accumulated_duration + self.start_time.elapsed()
            };

            let milliseconds = final_duration.as_secs_f64() * 1000.0;
            let end_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;

            log_latency(&format!(
                "{},{:.5},{},{}\n",
                self.operation,
                milliseconds,
                self.start_timestamp,
                end_timestamp,
            ));
        }
    }

    /// Logs the operation name and start timestamp.
    pub fn log_operation(&self) {
        println!("Operation: {}", self.operation);
        println!("Start Timestamp: {}", self.start_timestamp);
    }
}

impl BytesMetric {
    /// Creates a new BytesMetric for the given operation and byte count
    pub fn new(operation: &str, bytes: usize) -> Self {
        Self {
            operation: operation.to_string(),
            bytes,
        }
    }

    /// Logs the bytes metric.
    pub fn log(self) {
        {
            log_bytes(&format!(
                "{},{}\n",
                self.operation,
                self.bytes,
            ));
        }
    }

    /// Logs the operation name and byte count.
    pub fn log_operation(&self) {
        println!("Operation: {}", self.operation);
        println!("Bytes: {}", self.bytes);
    }
}

/// Internal helper to parse and log a latency metric
fn log_latency(message: &str) {
    let parts: Vec<&str> = message.trim().split(',').collect();
    if parts.len() >= 4 {
        if let (Ok(value), Ok(start), Ok(end)) = (
            parts[1].parse::<f64>(),
            parts[2].parse::<u64>(),
            parts[3].parse::<u64>(),
        ) {
            LATENCY_LOG.lock().unwrap().push((
                parts[0].to_string(),
                value,
                start,
                end,
            ));
        }
    }
}

/// Records under `operation` a duration that was measured elsewhere.
pub fn log_duration_ms(operation: &str, milliseconds: f64) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
    LATENCY_LOG.lock().unwrap().push((operation.to_string(), milliseconds, now, now));
}

/// Internal helper to parse and log a bytes metric
fn log_bytes(message: &str) {
    let parts: Vec<&str> = message.trim().split(',').collect();
    if parts.len() >= 2 {
        if let Ok(value) = parts[1].parse::<usize>() {
            BYTES_LOG.lock().unwrap().push((parts[0].to_string(), value));
        }
    }
}

/// Calculates averages from logged metrics and writes them to CSV files.
/// 
/// # Arguments
/// * `latency_filename` - Name of file to write latency metrics to
/// * `bytes_filename` - Name of file to write bytes metrics to
///
/// Files are written to a "logs" directory with a prefix containing block size,
/// Z, D and batch size constants.
pub fn calculate_and_append_averages(latency_filename: &str, bytes_filename: &str) {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::collections::HashMap;

    {
        // Create logs directory if it doesn't exist
        std::fs::create_dir_all("logs").unwrap();
        
        let constants_prefix = format!("B{}_Z{}_D{}", 
            crate::constants::BLOCK_SIZE,
            crate::constants::Z,
            crate::constants::D,
        );

        let latency_path = format!("logs/{}{}", constants_prefix, latency_filename);
        let bytes_path = format!("logs/{}{}", constants_prefix, bytes_filename);

        // Process latency data
        let mut latency_sums: HashMap<String, (f64, usize)> = HashMap::new();
        let mut recent_latency_sums: HashMap<String, Vec<f64>> = HashMap::new();
        let mut epoch_stats: HashMap<String, HashMap<u64, Vec<(u64, u64)>>> = HashMap::new();
        let mut epoch_max_durations: HashMap<String, HashMap<u64, f64>> = HashMap::new();
        {
            let latency_data = LATENCY_LOG.lock().unwrap();
            
            // Write all latency data to file
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&latency_path) 
            {
                writeln!(file, "operation,milliseconds,start_timestamp_us,end_timestamp_us").unwrap();
                for (operation, value, start, end) in latency_data.iter() {
                    writeln!(file, "{},{:.5},{},{}", operation, value, start, end).unwrap();
                    
                    let entry = latency_sums.entry(operation.clone()).or_insert((0.0, 0));
                    entry.0 += value;
                    entry.1 += 1;

                    // Also track recent values for each operation
                    recent_latency_sums.entry(operation.clone())
                        .or_default()
                        .push(*value);

                    // Track epoch-based statistics for batch operations
                    if operation.contains("_epoch_") {
                        let parts: Vec<&str> = operation.split('_').collect();
                        if parts.len() >= 3 {
                            let base_op = parts[0..parts.len()-2].join("_");
                            if let Ok(epoch) = parts[parts.len()-1].parse::<u64>() {
                                epoch_stats.entry(base_op.clone())
                                    .or_default()
                                    .entry(epoch)
                                    .or_default()
                                    .push((*start, *end));
                                    
                                // Store the maximum chunk duration for this epoch
                                epoch_max_durations.entry(base_op)
                                    .or_default()
                                    .insert(epoch, *value);
                            }
                        }
                    }
                }
            }
        }

        // Process bytes data
        let mut bytes_sums: HashMap<String, (usize, usize)> = HashMap::new();
        {
            let bytes_data = BYTES_LOG.lock().unwrap();
            
            // Write all bytes data to file
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&bytes_path) 
            {
                writeln!(file, "operation,bytes").unwrap();
                for (operation, value) in bytes_data.iter() {
                    writeln!(file, "{},{}", operation, value).unwrap();
                    
                    let entry = bytes_sums.entry(operation.clone()).or_insert((0, 0));
                    entry.0 += value;
                    entry.1 += 1;
                }
            }
        }

        // Append averages to both files
        if let Ok(mut file) = OpenOptions::new().append(true).open(&latency_path) {
            writeln!(file, "\nAVERAGES (all iterations):").unwrap();
            for (operation, (sum, count)) in latency_sums {
                // Skip epoch-specific entries in the regular averages section
                if operation.contains("_epoch_") {
                    continue;
                }
                
                let average = sum / count as f64;
                writeln!(file, "{},{:.5}", operation, average).unwrap();

                // Add recent averages if we have enough data
                if let Some(recent_values) = recent_latency_sums.get(&operation) {
                    if recent_values.len() >= crate::constants::LATENCY_BENCH_COUNT {
                        let recent_slice = &recent_values[recent_values.len() - crate::constants::LATENCY_BENCH_COUNT..];
                        let recent_avg = recent_slice.iter().sum::<f64>() / recent_slice.len() as f64;
                        writeln!(file, "{} (last {} iterations),{:.5}", 
                            operation,
                            crate::constants::LATENCY_BENCH_COUNT,
                            recent_avg
                        ).unwrap();
                    }
                }
            }

            // Add epoch-based statistics
            writeln!(file, "\nEPOCH-BASED STATISTICS:").unwrap();
            for (operation, epoch_data) in epoch_max_durations {
                let mut durations: Vec<(u64, f64)> = epoch_data.into_iter().collect();
                durations.sort_by_key(|&(epoch, _)| epoch);
                
                // Calculate and write average of maximum chunk durations over last 10 epochs
                if durations.len() >= 10 {
                    let last_10_durations: Vec<f64> = durations.iter()
                        .rev()
                        .take(10)
                        .map(|&(_, duration)| duration)
                        .collect();
                    let avg_duration = last_10_durations.iter().sum::<f64>() / last_10_durations.len() as f64;
                    writeln!(file, "{}_avg_max_chunk_duration_last_10,{:.5}", operation, avg_duration).unwrap();
                }
            }
        }

        if let Ok(mut file) = OpenOptions::new().append(true).open(&bytes_path) {
            writeln!(file, "\nAVERAGES:").unwrap();
            for (operation, (sum, count)) in bytes_sums {
                let average = sum as f64 / count as f64;
                writeln!(file, "{},{}", operation, average).unwrap();
            }
        }

        // Clear the in-memory logs
        LATENCY_LOG.lock().unwrap().clear();
        BYTES_LOG.lock().unwrap().clear();
    }
}
