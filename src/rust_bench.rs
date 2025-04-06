use criterion::{black_box, criterion_group, criterion_main, Criterion};
use bazelbench::bench_config::BenchmarkConfig;
use bazelbench::blob::{generate_blob};


fn benchmark_generate_blob_cpu(c: &mut Criterion) {
    let mut cfg = BenchmarkConfig::default();
    fastrand::seed(42);
    let mut rng_gen = fastrand::Rng::new();
    let mut gpu_rng_gen: Option<_> = None;

    cfg.blob_size_bytes = 1048576;
    cfg.zero_pad_blob_pct = 50;
    cfg.fast_rng = false;
    c.bench_function("generate_blob 1mib cpu 50%", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    cfg.blob_size_bytes = 1048576;
    cfg.zero_pad_blob_pct = 0;
    c.bench_function("generate_blob 1mib cpu 100%", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    cfg.blob_size_bytes = 10485760;
    cfg.zero_pad_blob_pct = 0;
    c.bench_function("generate_blob 10mib cpu 100%", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    // fast
    cfg.blob_size_bytes = 1048576;
    cfg.zero_pad_blob_pct = 50;
    cfg.fast_rng = true;
    c.bench_function("generate_blob 1mib cpu 50% fast", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    cfg.zero_pad_blob_pct = 0;
    c.bench_function("generate_blob 1mib cpu 100% fast", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    cfg.blob_size_bytes = 10485760;
    cfg.zero_pad_blob_pct = 0;
    c.bench_function("generate_blob 10mib cpu 100% fast", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });
}


#[cfg(feature = "cuda")] use gpu_rand::xoroshiro::rand_core::SeedableRng;
#[cfg(feature = "cuda")] use cust::CudaFlags;
use rand_core::RngCore;

#[cfg(feature = "cuda")]
fn benchmark_generate_blob_gpu(c: &mut Criterion) {
    cust::init(CudaFlags::empty()).unwrap();
    let num_cuda_devices = cust::device::Device::num_devices().unwrap();
    if num_cuda_devices == 0 {
        eprint!("no CUDA devices were available, GPU benchmark aborted");
        return
    }
    let mut cfg = BenchmarkConfig::default();
    fastrand::seed(42);
    let mut rng_gen = fastrand::Rng::new();
    let mut gpu_rng_gen: Option<Box<dyn RngCore + Send>> = Some(Box::new(gpu_rand::DefaultRand::from_entropy()));

    cfg.blob_size_bytes = 1048576;
    cfg.zero_pad_blob_pct = 50;
    cfg.fast_rng = false;
    c.bench_function("generate_blob 1mib gpu 50%", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    cfg.blob_size_bytes = 1048576;
    cfg.zero_pad_blob_pct = 0;
    c.bench_function("generate_blob 1mib gpu 100%", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    cfg.blob_size_bytes = 10485760;
    cfg.zero_pad_blob_pct = 0;
    c.bench_function("generate_blob 10mib gpu 100%", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    // fast
    cfg.blob_size_bytes = 1048576;
    cfg.zero_pad_blob_pct = 50;
    cfg.fast_rng = true;
    c.bench_function("generate_blob 1mib gpu 50% fast", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    cfg.zero_pad_blob_pct = 0;
    c.bench_function("generate_blob 1mib gpu 100% fast", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });

    cfg.blob_size_bytes = 10485760;
    cfg.zero_pad_blob_pct = 0;
    c.bench_function("generate_blob 10mib gpu 100% fast", |b| {
        b.iter(|| {
            let _output = generate_blob(black_box(&cfg), black_box(&mut rng_gen), black_box(&mut gpu_rng_gen)).unwrap();
        })
    });
}

#[cfg(not(feature = "cuda"))] criterion_group!(benches_cpu, benchmark_generate_blob_cpu);
#[cfg(not(feature = "cuda"))] criterion_main!(benches_cpu);

#[cfg(feature = "cuda")] criterion_group!(benches_all, benchmark_generate_blob_cpu, benchmark_generate_blob_gpu);
#[cfg(feature = "cuda")] criterion_main!(benches_all);
