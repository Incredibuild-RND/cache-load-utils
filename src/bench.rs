use std::process::exit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
#[allow(unused_imports)] use anyhow::Context;

use bazel_remote_apis_rs::build::bazel::remote::execution::v2::OutputFile;
use clap::Parser;
use dotenv::dotenv;
use fastrand::Rng;
use rand::{RngCore};
#[allow(unused_imports)] use rand::rngs::StdRng;
#[allow(unused_imports)] use rand_core::SeedableRng;
use tokio::sync::Mutex;
use tokio::task;
use warp::Filter;

use crate::{blob, prom};
use crate::bench_config::BenchmarkConfig;
use crate::grpc_client::RemoteClient;
use crate::prom::{AC_READ_COLLECTOR, TrackedResult};
use crate::prom::AC_WRITE_COLLECTOR;
use crate::prom::BS_READ_COLLECTOR;
use crate::prom::BS_WRITE_COLLECTOR;
use crate::prom::CAS_FIND_MISSING_COLLECTOR;
use crate::prom::CONNECT_COLLECTOR;
use crate::prom::GET_CAPS_COLLECTOR;
use crate::prom::INTERNAL_ERR_COLLECTOR;

static ITERATIONS: AtomicU64 = AtomicU64::new(0);

fn increment_iterations() {
    ITERATIONS.fetch_add(1, Ordering::Relaxed);
}

fn get_iterations() -> u64 {
    ITERATIONS.load(Ordering::Relaxed)
}

impl BenchmarkConfig {
    pub fn parse_with_dotenv() -> anyhow::Result<BenchmarkConfig> {
        dotenv().ok();
        Ok(BenchmarkConfig::parse())
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkRunner {
    cfg: BenchmarkConfig,
}

async fn create_client(cfg: BenchmarkConfig) -> anyhow::Result<RemoteClient> {
    let now = Instant::now();
    let r = RemoteClient::connect(&cfg).await?;
    prom::track_rpc_success(&CONNECT_COLLECTOR, now, cfg.label.as_str());
    return Ok(r);
}

#[cfg(feature = "cuda")]
fn new_gpu_rng(cfg: &BenchmarkConfig) -> anyhow::Result<Option<Box<dyn RngCore + Send>>> {
    let num_cuda_devices = cust::device::Device::num_devices().context("failed to query CUDA")?;
    if !cfg.allow_gpu || num_cuda_devices == 0 {
        return Ok(None)
    }
    Ok(Some(Box::new(gpu_rand::DefaultRand::from_entropy())))
}

#[cfg(not(feature = "cuda"))]
fn new_gpu_rng(_cfg: &BenchmarkConfig) -> anyhow::Result<Option<Box<dyn RngCore + Send>>> {
    Ok(None)
}

#[cfg(feature = "cuda")]
fn print_cuda_status(cfg: &BenchmarkConfig) -> anyhow::Result<()> {
    cust::init(cust::CudaFlags::empty())?;
    let num_cuda_devices = cust::device::Device::num_devices()
        .context("failed to query CUDA")? as i32;
    println!("CUDA support is present. CUDA devices: {num_cuda_devices}. CUDA enabled: {}", cfg.allow_gpu);
    Ok(())
}

#[cfg(not(feature = "cuda"))]
fn print_cuda_status(_cfg: &BenchmarkConfig) -> anyhow::Result<()> {
    println!("CUDA support not present.");
    Ok(())
}

impl BenchmarkRunner {
    pub fn new(c: BenchmarkConfig) -> Self {
        Self {
            cfg: c.clone(),
        }
    }

    /// The runners main loop; runs forever, or until an error is received.
    pub async fn run(self) -> anyhow::Result<()> {
        println!("benchmarking {} with config:\n{:?}", self.cfg.target_endpoint, self.cfg);
        print_cuda_status(&self.cfg)?;

        let cfg = self.cfg.clone();
        task::spawn(async move {
            let _ = warp::serve(warp::path!("metrics")
                .and_then(prom::metrics_handler))
                .run(([0, 0, 0, 0], cfg.prometheus_port)).await;
        });

        // spawn a task to respond to healthcheck endpoints,
        // useful if this binary if it's running as k8s service, modeled after
        // https://kubernetes.io/docs/reference/using-api/health-checks/
        task::spawn(async move {
            let _ = warp::serve(
                warp::path!("readyz").map(||"OK")
                    .or( warp::path!("livez").map(||"OK"))
                    .or( warp::path!("healthz").map(||"OK"))
            ).run(([0, 0, 0, 0], cfg.utility_port)).await;
        });

        // spawn a task to update iter/sec
        task::spawn(async move {
            let mut last_time = Instant::now();
            let mut last_iterations = get_iterations();

            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let current_iterations = get_iterations();
                let iterations_since_last = current_iterations - last_iterations;
                let elapsed = last_time.elapsed().as_secs_f64();
                let iterations_per_second = iterations_since_last as f64 / elapsed;

                println!("ITER/SEC: {}", iterations_per_second);

                last_time = Instant::now();
                last_iterations = current_iterations;
            }
        });

        // spawn infinite tasks for each configured benchmark thread
        let mut handles = Vec::with_capacity(cfg.num_threads);
        for _ in 0..cfg.num_threads {
            // to rate limit, if that is ever impl'd, just await the interval tick() within the loop
            // let mut interval = time::interval(Duration::from_millis(100));

            let mut cache_client = create_client(cfg.clone()).await?;
            let s = self.clone();
            let mut rng_gen = fastrand::Rng::new();
            let gpu_rng_gen = Mutex::new(new_gpu_rng(&cfg)?);

            let forever = task::spawn({
                let cfg = cfg.clone();

                async move {
                    let mut gpu_rng_gen = gpu_rng_gen.lock().await;
                    let mut iterations = 1;
                    loop {
                        // interval.tick().await;
                        if cfg.write_only {
                            match s.call_bs_write(&mut cache_client, &mut rng_gen, &mut gpu_rng_gen).await {
                                Ok(_) => increment_iterations(),
                                Err(e) => {
                                    eprintln!("\x07FAIL at: {}", e)
                                }
                            }
                        } else {
                            match s.call_rpcs(&mut cache_client, &mut rng_gen, &mut gpu_rng_gen).await {
                                Ok(_) => increment_iterations(),
                                Err(e) => {
                                    eprintln!("\x07FAIL at: {}", e)
                                }
                            }
                        }
                        if cfg.flamegraph && iterations == 10 {
                            println!("flamegraph=true, exiting after 10 iterations");
                            exit(0);
                        }
                        iterations += 1;
                    }
                    #[allow(unreachable_code)] anyhow::Ok(())
                }
            });
            handles.push(forever);
        }

        // this is just unwrapping the results to bubble out errors, but these handles don't
        // actually return
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await?);
        }
        Ok(())
    }

    /// runs a benchmark iteration, ideally called per tick
    pub(crate) async fn call_rpcs(&self, cache_client: &mut RemoteClient, rng_gen: &mut Rng, gpu_rng_gen: &mut Option<Box<dyn RngCore + Send>>) -> anyhow::Result<()> {
        let mut handles = Vec::new();

        let mut cache_client_clone = cache_client.clone();
        let lbl = self.cfg.label.clone();
        handles.push(task::spawn(async move {
            // check capabilities
            cache_client_clone.call_capabilities()
                .await
                .track_err(&GET_CAPS_COLLECTOR, lbl.as_str())?;

            anyhow::Ok(())
        }));

        // Generate fake data, since we need to reuse this in a few calls.
        let file_tups = blob::generate_outputs(
            1,
            &self.cfg,
            rng_gen,
            gpu_rng_gen,
        )
            .track_err(&INTERNAL_ERR_COLLECTOR, self.cfg.label.as_str())?;
        let output_files = file_tups
            .iter()
            .map(|(f,_)|f.clone())
            .collect::<Vec<OutputFile>>();

        let mut cache_client_clone = cache_client.clone();
        let output_files_clone = output_files.clone();
        let ac_read_sleep_ms = self.cfg.ac_read_sleep_ms;

        let lbl = self.cfg.label.clone();
        handles.push(task::spawn(async move {
            // AC write
            let (_digest, _action_result) = cache_client_clone.call_ac_write(&output_files_clone)
                .await
                .track_err(&AC_WRITE_COLLECTOR, lbl.as_str())?;

            // seems we need this for bazel-remote, as there's some race condition internally there.
            // under load, the wait needed for the writes sync grows almost linearly
            tokio::time::sleep(Duration::from_millis(ac_read_sleep_ms)).await;

            // AC Read
            cache_client_clone.call_ac_read(_digest, &output_files_clone)
                .await
                .track_err(&AC_READ_COLLECTOR, lbl.as_str())?;

            anyhow::Ok(())
        }));

        let mut cache_client_clone = cache_client.clone();
        let read_amp = self.cfg.read_amplification;

        let output_files_clone = output_files.clone();
        let lbl = self.cfg.label.clone();
        let verify = self.cfg.verify;

        handles.push(task::spawn(async move {
            let lbl = lbl.clone();
            let mut handles = Vec::new();

            // BS write
            cache_client_clone.call_write(file_tups)
                .await
                .track_err(&BS_WRITE_COLLECTOR, lbl.as_str())?;

            // BS Read
            for _ in 0 ..read_amp {
                let mut cache_client_clone2 = cache_client_clone.clone();
                let output_files_clone2 = output_files_clone.clone();
                let lbl = lbl.clone();
                handles.push(task::spawn(async move {
                    cache_client_clone2.call_read(output_files_clone2, verify)
                        .await
                        .track_err(&BS_READ_COLLECTOR, lbl.as_str())?;
                    anyhow::Ok(())
                }));
            }

            let mut cache_client_clone = cache_client_clone.clone();
            handles.push(task::spawn(async move {
                // CAS FindMissing
                cache_client_clone.call_find_missing(&output_files_clone)
                    .await
                    .track_err(&CAS_FIND_MISSING_COLLECTOR, lbl.as_str())?;
                anyhow::Ok(())
            }));

            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(handle.await?);
            }

            anyhow::Ok(())
        }));

        // consider other remote asset ops

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await?);
        }

        Ok(())
    }

    /// calls a benchmark iteration of just bytestream write
    pub(crate) async fn call_bs_write(&self, cache_client: &mut RemoteClient, rng_gen: &mut Rng, gpu_rng_gen: &mut Option<Box<dyn RngCore + Send>>) -> anyhow::Result<()> {
        let file_tups = blob::generate_outputs(
            1,
            &self.cfg,
            rng_gen,
            gpu_rng_gen,
        )
            .track_err(&INTERNAL_ERR_COLLECTOR, self.cfg.label.as_str())?;

        cache_client.call_write(file_tups)
            .await
            .track_err(&BS_WRITE_COLLECTOR, self.cfg.label.as_str())?;

        Ok(())
    }
}
