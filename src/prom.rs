use std::time::Instant;

use anyhow::anyhow;
use lazy_static::lazy_static;
use prometheus::{self, Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};
use prometheus::core::Collector;

lazy_static! {
    pub static ref CONNECT_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("connect", "Number of connect calls"),
        &["success", "cache_backend"]
    )
    .expect("metric can be created");

    pub static ref GET_CAPS_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("get_capabilities", "Number of GetCapabilities calls"),
        &["success", "cache_backend"]
    )
    .expect("metric can be created");

    pub static ref INTERNAL_ERR_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("internal", "Number of Internal Errors"),
        &["success", "cache_backend"]
    )
    .expect("metric can be created");

    pub static ref AC_WRITE_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("ac_write", "Number of AC Write calls"),
        &["success", "cache_backend"]
    )
    .expect("metric can be created");

    pub static ref AC_READ_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("ac_read", "Number of AC Read calls"),
        &["success", "cache_backend"]
    )
    .expect("metric can be created");

    pub static ref BS_WRITE_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("bs_write", "Number of BS Write calls"),
        &["success", "cache_backend"]
    )
    .expect("metric can be created");

    pub static ref BS_BYTES_WRITTEN_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("bs_bytes_written_count", "Number of BS bytes written"),
        &["cache_backend"]
    )
    .expect("metric can be created");

    pub static ref BS_BYTES_READ_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("bs_bytes_read_count", "Number of BS bytes read"),
        &["cache_backend"]
    )
    .expect("metric can be created");

    pub static ref BS_READ_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("bs_read", "Number of BS Read calls"),
        &["success", "cache_backend"]
    )
    .expect("metric can be created");

    pub static ref CAS_FIND_MISSING_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("cas_find_missing", "Number of FindMissingBlobs calls"),
        &["success", "cache_backend"]
    )
    .expect("metric can be created");

    pub static ref RESPONSE_TIME_COLLECTOR: HistogramVec = HistogramVec::new(
        HistogramOpts::new("response_time", "Response Times"),
        &["method", "cache_backend"]
    )
    .expect("metric can be created");

    pub static ref REGISTRY: Registry = Registry::new();
}

pub fn track_rpc_success(metric: &IntCounterVec, started: Instant, cache_backend_label: &str) {
    let elapsed = started.elapsed();
    let label = metric.desc().first().unwrap().fq_name.as_str();
    RESPONSE_TIME_COLLECTOR
        .with_label_values(&[label, cache_backend_label])
        .observe(elapsed.as_secs_f64());
    metric
        .with_label_values(&["true", cache_backend_label])
        .inc();
}

pub fn register() {
    REGISTRY
        .register(Box::new(CONNECT_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(GET_CAPS_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(INTERNAL_ERR_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(AC_READ_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(AC_WRITE_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(BS_READ_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(BS_BYTES_READ_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(BS_WRITE_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(BS_BYTES_WRITTEN_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(CAS_FIND_MISSING_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(RESPONSE_TIME_COLLECTOR.clone()))
        .expect("collector can be registered");
}

pub(crate) async fn metrics_handler() -> Result<impl warp::Reply, warp::Rejection> {
    let encoder = prometheus::TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        eprintln!("could not encode custom metrics: {}", e);
    };
    let mut res = String::from_utf8(buffer.clone()).unwrap_or_else(|e| {
        eprintln!("custom metrics could not be from_utf8'd: {}", e);
        String::default()
    });
    buffer.clear();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        eprintln!("could not encode prometheus metrics: {}", e);
    };
    let res_custom = String::from_utf8(buffer.clone()).unwrap_or_else(|e| {
        eprintln!("prometheus metrics could not be from_utf8'd: {}", e);
        String::default()
    });
    buffer.clear();

    res.push_str(&res_custom);
    Ok(res)
}

pub trait TrackedResult<T, E = anyhow::Error> {
    fn track_err(self, metric: &IntCounterVec, cache_backend_label: &str) -> anyhow::Result<T, E>;
}

impl<T> TrackedResult<T> for anyhow::Result<T, anyhow::Error> {
    fn track_err(self, metric: &IntCounterVec, cache_backend_label: &str) -> anyhow::Result<T, anyhow::Error> {
        match self {
            Ok(s) => Ok(s),
            Err(_e) => {
                let labeled = metric
                    .with_label_values(&[
                        "false", // success
                       cache_backend_label,
                    ]);
                labeled.inc();
                let msg = format!("{}", metric.desc().first().unwrap().fq_name);
                println!("[track_err]: name: \"{}\", count: {} cause: \"{}\"", msg, labeled.get(), _e);
                Err(anyhow!(msg))
            }
        }
    }
}