use bazel_remote_apis_rs::build::bazel::remote::execution::v2::digest_function;
use clap::{Parser, ValueEnum};


#[derive(Debug, ValueEnum, Clone, PartialEq)]
#[clap(rename_all = "snake_case")]
pub enum SupportedDigestFunction {
    Sha256,
    Blake3
}

impl From<SupportedDigestFunction> for digest_function::Value {
    fn from(digest: SupportedDigestFunction) -> Self {
        match digest {
            SupportedDigestFunction::Sha256 => digest_function::Value::Sha256,
            SupportedDigestFunction::Blake3 => digest_function::Value::Blake3,
        }
    }
}

impl From<SupportedDigestFunction> for i32 {
    fn from(digest_fn: SupportedDigestFunction) -> Self {
        let digest_fn_re: digest_function::Value = digest_fn.into();
        digest_fn_re.into()
    }
}

#[derive(Debug, Clone, Parser)]
#[command(version, about, long_about = None)]
#[clap(rename_all = "snake_case")]
pub struct BenchmarkConfig {
    /// The optional auth header to be included in request metadata to authenticate requests against
    /// a secure backend
    #[arg(long, env = "AUTH_HEADER")]
    pub auth_header: Option<String>,

    /// The reAPI gRPC endpoint under test; Note it is required to use http:// and https:// schemes
    /// even while this is gRPC only.
    #[arg(long, env = "TARGET_ENDPOINT")]
    pub target_endpoint: String,

    /// The instance_name field passed to the RE API calls
    #[arg(long, env = "REMOTE_INSTANCE_NAME", default_value = "main")]
    pub remote_instance_name: String,

    /// The size in bytes to use for the randomly generated blobs used to test the backend
    #[arg(long, env = "BLOB_SIZE_BYTES", default_value_t = 32768)]
    pub blob_size_bytes: usize,

    /// The port on which prometheus metrics are made available for scraping at /metrics by
    /// prometheus
    #[arg(long, env = "PROMETHEUS_PORT", default_value_t = 9091)]
    pub prometheus_port: u16,

    /// The port on which this program will respond to HTTP requests regarding its health and
    /// readiness status, useful if running in kubernetes
    #[arg(long, env = "UTILITY_PORT", default_value_t = 3001)]
    pub utility_port: u16,

    /// The number of concurrent benchmark tasks to spawn. Note these are Tokio tasks spawned into
    /// the tokio default runtime's threadpool (thread-per-core and work-stealing).
    ///
    /// - Going beyond ~2x physical core count will harm performance
    /// - For each num_thread, a new connection is made to the backend
    /// - Within each "iteration" running on a "thread" additional tasks are spawned;
    ///   - A task to call get_capabilities
    ///   - A task to call bs_write, then N tasks to call bs_read up to read_amplification
    ///   - A task to call ac_write, then ac_read; note this task also has a configurable sleep on
    ///     it to work around a race condition present in some cache backends
    #[arg(long, env = "NUM_THREADS", default_value_t = 20)]
    pub num_threads: usize,

    /// Only generate and write data with Bytestream.Write() RPC
    #[arg(long, env = "WRITE_ONLY", default_value_t = false)]
    pub write_only: bool,

    /// For each iteration of requests, how many additional read requests to send; allows for
    /// simulation of a more realistic read-heavy workload with a single client
    #[arg(long, env = "READ_AMPLIFICATION", default_value_t = 20)]
    pub read_amplification: usize,

    /// The size in which chunks should be created and sent up to the backend. Bigger generally is
    /// better for speed on a good network, but bazel defaults this to quite small at 16k, so that
    /// is the default here.
    #[arg(long, env = "CHUNK_SIZE", default_value_t = 16384)]
    pub chunk_size: usize,

    /// A mechanism by which to increase write performance (less RNG) and also test data
    /// deduplication, by replacing the specified percentage of each blob by 0s, and also verify
    /// compression is working as expected, as the repeating 0s should compress well. Note that after
    /// use of fast_rng, enabled by default, 0 padding offers quite little, so it defaults to 0 (off)
    #[arg(long, env = "ZERO_PAD_BLOB_PCT", default_value_t = 0)]
    pub zero_pad_blob_pct: usize,

    /// Some caches will return not-found to requests coming too soon after an AC entry is written.
    /// This delay offsets that, but in a single threaded mode it will significantly affect RPS.
    /// Set as close to 0 as possible while minimizing ac_read error rates in the Grafana dashboard.
    #[arg(long, env = "AC_READ_SLEEP_MS", default_value_t = 20)]
    pub ac_read_sleep_ms: u64,

    /// The reAPI digest function to use to generate hashes; blake3 is preferred but not supported in
    /// bazel-remote, so the default is sha256. If the cache under test supports blake3, be sure to use
    /// this to remove the CPU-bound nature of large write benchmarks caused by sha256 hashing
    #[arg(long, env = "DIGEST_FUNCTION", default_value = "sha256")]
    pub digest_function: SupportedDigestFunction,

    /// The label to associate with metrics reported into prometheus, so that separate lines can be
    /// shown for each cache backend under test; comes in as a value on the "cache_backend" label
    #[arg(long, env = "LABEL", default_value = "default")]
    pub label: String,

    /// Whether to allow use of CUDA devices if present
    #[arg(long, env = "ALLOW_GPU", default_value_t = true, num_args = 1)]
    pub allow_gpu: bool,

    /// When running in flamegraph mode, the program will exit after the first iteration
    #[arg(long, env = "FLAMEGRAPH", default_value_t = false)]
    pub flamegraph: bool,

    /// The number of slices to create when shuffling pre-generated random blob data
    #[arg(long, env = "PSEUDORANDOM_CHUNK_COUNT", default_value_t = 1000)]
    pub pseudorandom_chunk_count: usize,

    /// Whether to use fast RNG by accepting lots of duplicated chunks within the blobs.
    /// Also, an ideal way to test data deduplication
    #[arg(long, env = "FAST_RNG", default_value_t = true, num_args = 1)]
    pub fast_rng: bool,

    /// Verify blob contents match expected hash
    #[arg(long, env = "VERIFY", default_value_t = false)]
    pub verify: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            auth_header: None,
            target_endpoint: "default".to_string(),
            remote_instance_name: "default".to_string(),
            blob_size_bytes: 1048576,
            prometheus_port: 9091,
            utility_port: 3001,
            num_threads: 1,
            write_only: false,
            read_amplification: 20,
            chunk_size: 16384,
            zero_pad_blob_pct: 50,
            ac_read_sleep_ms: 6,
            digest_function: SupportedDigestFunction::Blake3,
            label: "default".to_string(),
            allow_gpu: true,
            flamegraph: false,
            pseudorandom_chunk_count: 1000,
            fast_rng: true,
            verify: false,
        }
    }
}

impl BenchmarkConfig {
    pub fn default_large() -> Self {
        Self {
            auth_header: None,
            target_endpoint: "default_large".to_string(),
            remote_instance_name: "default_large".to_string(),
            blob_size_bytes: 10485760,
            prometheus_port: 9091,
            utility_port: 3001,
            num_threads: 1,
            write_only: false,
            read_amplification: 20,
            chunk_size: 1048576,
            zero_pad_blob_pct: 50,
            ac_read_sleep_ms: 6,
            digest_function: SupportedDigestFunction::Blake3,
            label: "default_large".to_string(),
            allow_gpu: true,
            flamegraph: false,
            pseudorandom_chunk_count: 1000,
            fast_rng: true,
            verify: false,
        }
    }
}
