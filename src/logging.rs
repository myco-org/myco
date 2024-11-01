use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use lazy_static::lazy_static;

lazy_static! {
    static ref LATENCY_LOG: Mutex<Option<File>> = Mutex::new(None);
    static ref BYTES_LOG: Mutex<Option<File>> = Mutex::new(None);
}

pub struct LatencyMetric {
    operation: String,
    start_time: Instant,
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
        }
    }

    pub fn finish(self) {
        #[cfg(feature = "perf-logging")]
        {
            let duration = self.start_time.elapsed();
            log_latency(&format!(
                "{},{},{}\n",
                self.operation,
                duration.as_micros(),
                duration.as_millis(),
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
        std::fs::create_dir_all("latency_logs").expect("Failed to create logs directory");
        
        // Initialize latency log with directory prefix
        let latency_file_path = format!("latency_logs/{}", latency_path);
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

        // Initialize bytes log with directory prefix
        let bytes_file_path = format!("latency_logs/{}", bytes_path);
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