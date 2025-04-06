


use std::process::exit;
use bazelbench::bench_config::BenchmarkConfig;
use bazelbench::bench::BenchmarkRunner;
use tokio::{signal};
use tokio::signal::unix::{signal, SignalKind};
use bazelbench::prom;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = BenchmarkConfig::parse_with_dotenv()?;
    let main = BenchmarkRunner::new(cfg.clone());
    let mut stream = signal(SignalKind::terminate())?;
    prom::register();
    tokio::select! {
        res = main.run() => res,
        _ = stream.recv() => {
            println!("\nSIGTERM, exiting");
            exit(0);
        },
        _ = signal::ctrl_c() => {
            println!("\nctrl-c, exiting");
            exit(0);
        },
    }
}
