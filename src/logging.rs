use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::io::BufReader;
use std::io::BufRead;

lazy_static! {
    static ref LATENCY_LOG: Mutex<Option<File>> = Mutex::new(None);
    static ref BYTES_LOG: Mutex<Option<File>> = Mutex::new(None);
}

pub struct LatencyMetric {
    operation: String,
    start_time: Instant,
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

            log_latency(&format!(
                "{},{:.5}\n",
                self.operation,
                milliseconds,
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

pub fn initialize_logging(latency_path: &str, bytes_path: &str) {
    #[cfg(feature = "perf-logging")]
    {
        // Create logs directory if it doesn't exist
        std::fs::create_dir_all("logs").expect("Failed to create logs directory");
        
        // Create filename prefix with constants
        let constants_prefix = format!("B{}_Z{}_D{}_BATCH{}_", 
            crate::constants::BLOCK_SIZE,
            crate::constants::Z,
            crate::constants::D,
            crate::constants::BATCH_SIZE);
        
        // Initialize latency log with directory prefix and constants
        let latency_file_path = format!("logs/{}{}", constants_prefix, latency_path);
        let mut latency_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&latency_file_path)
            .expect("Failed to open latency log file");
        
        // Write CSV header if file is empty
        if latency_file.metadata().unwrap().len() == 0 {
            writeln!(latency_file, "operation,microseconds,milliseconds").unwrap();
        }
        *LATENCY_LOG.lock().unwrap() = Some(latency_file);

        // Initialize bytes log with directory prefix and constants
        let bytes_file_path = format!("logs/{}{}", constants_prefix, bytes_path);
        let mut bytes_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&bytes_file_path)
            .expect("Failed to open bytes log file");
        
        // Write CSV header if file is empty
        if bytes_file.metadata().unwrap().len() == 0 {
            writeln!(bytes_file, "operation,bytes").unwrap();
        }
        *BYTES_LOG.lock().unwrap() = Some(bytes_file);
    }
}

fn log_latency(message: &str) {
    #[cfg(feature = "perf-logging")]
    {
        if let Some(file) = &mut *LATENCY_LOG.lock().unwrap() {
            file.write_all(message.as_bytes()).expect("Failed to write to latency log");
            file.flush().expect("Failed to flush latency log");
        }
    }
}

fn log_bytes(message: &str) {
    #[cfg(feature = "perf-logging")]
    {
        if let Some(file) = &mut *BYTES_LOG.lock().unwrap() {
            file.write_all(message.as_bytes()).expect("Failed to write to bytes log");
            file.flush().expect("Failed to flush bytes log");
        }
    }
}

pub fn calculate_and_append_averages(latency_filename: &str, bytes_filename: &str) {
    #[cfg(feature = "perf-logging")]
    {
        // Close the current file handles
        {
            let mut latency_guard = LATENCY_LOG.lock().unwrap();
            let mut bytes_guard = BYTES_LOG.lock().unwrap();
            *latency_guard = None;
            *bytes_guard = None;
        }

        // Process latency file
        let constants_prefix = format!("B{}_Z{}_D{}_BATCH{}_", 
            crate::constants::BLOCK_SIZE,
            crate::constants::Z,
            crate::constants::D,
            crate::constants::BATCH_SIZE);
        
        let latency_path = format!("logs/{}{}", constants_prefix, latency_filename);
        let bytes_path = format!("logs/{}{}", constants_prefix, bytes_filename);

        // Calculate averages for latency file
        let mut latency_sums: HashMap<String, (f64, usize)> = HashMap::new();
        if let Ok(file) = File::open(&latency_path) {
            let reader = BufReader::new(file);
            let mut is_header = true;
            
            for line in reader.lines() {
                if let Ok(line) = line {
                    if is_header {
                        is_header = false;
                        continue;
                    }
                    
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 2 {
                        let operation = parts[0].to_string();
                        if let Ok(value) = parts[1].parse::<f64>() {
                            let entry = latency_sums.entry(operation).or_insert((0.0, 0));
                            entry.0 += value;
                            entry.1 += 1;
                        }
                    }
                }
            }
        }

        // Append averages to latency file
        if let Ok(mut file) = OpenOptions::new().append(true).open(&latency_path) {
            writeln!(file, "\nAVERAGES:").unwrap();
            for (operation, (sum, count)) in latency_sums {
                let average = sum / count as f64;
                writeln!(file, "{},{:.5}", operation, average).unwrap();
            }
        }

        // Calculate averages for bytes file
        let mut bytes_sums: HashMap<String, (usize, usize)> = HashMap::new();
        if let Ok(file) = File::open(&bytes_path) {
            let reader = BufReader::new(file);
            let mut is_header = true;
            
            for line in reader.lines() {
                if let Ok(line) = line {
                    if is_header {
                        is_header = false;
                        continue;
                    }
                    
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 2 {
                        let operation = parts[0].to_string();
                        if let Ok(value) = parts[1].parse::<usize>() {
                            let entry = bytes_sums.entry(operation).or_insert((0, 0));
                            entry.0 += value;
                            entry.1 += 1;
                        }
                    }
                }
            }
        }

        // Append averages to bytes file
        if let Ok(mut file) = OpenOptions::new().append(true).open(&bytes_path) {
            writeln!(file, "\nAVERAGES:").unwrap();
            for (operation, (sum, count)) in bytes_sums {
                let average = sum as f64 / count as f64;
                writeln!(file, "{},{}", operation, average).unwrap();
            }
        }

        // Reinitialize the log files with the same filenames
        initialize_logging(latency_filename, bytes_filename);
    }
}
