use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::io::BufReader;
use std::io::BufRead;

lazy_static! {
    static ref LATENCY_LOG: Mutex<Vec<(String, f64, u64, u64)>> = Mutex::new(Vec::new());
    static ref BYTES_LOG: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());
}

pub struct LatencyMetric {
    operation: String,
    start_time: Instant,
    start_timestamp: u64,
    accumulated_duration: Duration,
    is_paused: bool,
}

pub struct BytesMetric {
    operation: String,
    bytes: usize,
}
impl LatencyMetric {
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

    pub fn pause(&mut self) {
        if !self.is_paused {
            self.accumulated_duration += self.start_time.elapsed();
            self.is_paused = true;
        }
    }

    pub fn resume(&mut self) {
        if self.is_paused {
            self.start_time = Instant::now();
            self.is_paused = false;
        }
    }

    pub fn finish(self) {
        #[cfg(feature = "perf-logging")]
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
}

impl BytesMetric {
    pub fn new(operation: &str, bytes: usize) -> Self {
        Self {
            operation: operation.to_string(),
            bytes,
        }
    }

    pub fn log(self) {
        #[cfg(feature = "perf-logging")]
        {
            log_bytes(&format!(
                "{},{}\n",
                self.operation,
                self.bytes,
            ));
        }
    }
}

fn log_latency(message: &str) {
    #[cfg(feature = "perf-logging")]
    {
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
}

fn log_bytes(message: &str) {
    #[cfg(feature = "perf-logging")]
    {
        let parts: Vec<&str> = message.trim().split(',').collect();
        if parts.len() >= 2 {
            if let Ok(value) = parts[1].parse::<usize>() {
                BYTES_LOG.lock().unwrap().push((parts[0].to_string(), value));
            }
        }
    }
}

pub fn calculate_and_append_averages(latency_filename: &str, bytes_filename: &str) {
    #[cfg(feature = "perf-logging")]
    {
        // Create logs directory if it doesn't exist
        std::fs::create_dir_all("logs").map_err(|e| format!("Failed to create logs directory: {}", e))?;
        
        let constants_prefix = format!("B{}_Z{}_D{}_BATCH{}_", 
            crate::constants::BLOCK_SIZE,
            crate::constants::Z,
            crate::constants::D,
            crate::constants::BATCH_SIZE);
        
        let latency_path = format!("logs/{}{}", constants_prefix, latency_filename);
        let bytes_path = format!("logs/{}{}", constants_prefix, bytes_filename);

        // Process latency data
        let mut latency_sums: HashMap<String, (f64, usize)> = HashMap::new();
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
            writeln!(file, "\nAVERAGES:").unwrap();
            for (operation, (sum, count)) in latency_sums {
                let average = sum / count as f64;
                writeln!(file, "{},{:.5}", operation, average).unwrap();
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
