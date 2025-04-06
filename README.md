# bazelbench-rs

A Bazel reAPI benchmarking and load-testing tool.

## Overview

- Random files are generated with `fastrng` on the CPU; if GPU is available, blobs are generated via `CUDA`, allowing for more load to be generated
- There are 2 modes: write-only, and the default write-read mode
- Only gRPC backends are supported, as this tool is built on top of `tonic` and `tokio`
- This tool makes heavy use of `prometheus` metrics to expose performance information, which are just exposed as counters on the binary via `http`
  - As such, `prometheus` and `grafana` are needed to scrape and display this information, see definitions in the `Makefile`

## Dashboard Example

![dash.png](images%2Fdash.png)

## Usage

### Makefile

- Test `bazel-remote` with `make bench_bazelremote`
- Test `nativelink` with `make bench_nativelink`

### CLI Invocation

See the definition of the `Makefile` tasks for a complete example of how `bazel-remote` and `nativelink` are benchmarked and compared to one another.

Run `bazelbench-rs --help` or `make help` to see options:

```text
Usage: bazelbench-rs [OPTIONS] --target_endpoint <TARGET_ENDPOINT>

Options:
      --auth_header <AUTH_HEADER>
          The optional auth header to be included in request metadata to authenticate requests against a secure backend
          
          [env: AUTH_HEADER=]

      --target_endpoint <TARGET_ENDPOINT>
          The reAPI gRPC endpoint under test; Note it is required to use http:// and https:// schemes even while this is gRPC only
          
          [env: TARGET_ENDPOINT=http://localhost:9092]

      --remote_instance_name <REMOTE_INSTANCE_NAME>
          The instance_name field passed to the RE API calls
          
          [env: REMOTE_INSTANCE_NAME=]
          [default: main]

      --blob_size_bytes <BLOB_SIZE_BYTES>
          The size in bytes to use for the randomly generated blobs used to test the backend
          
          [env: BLOB_SIZE_BYTES=1048576]
          [default: 32768]

      --prometheus_port <PROMETHEUS_PORT>
          The port on which prometheus metrics are made available for scraping at /metrics by prometheus
          
          [env: PROMETHEUS_PORT=9091]
          [default: 9091]

      --container_port <CONTAINER_PORT>
          The port on which this program will respond to HTTP requests regarding its health and readiness status, useful if running in kubernetes
          
          [env: UTILITY_PORT=3001]
          [default: 3001]

      --num_threads <NUM_THREADS>
          The number of concurrent benchmark tasks to spawn. 
          Note these are Tokio tasks spawned into the tokio default runtime's threadpool (thread-per-core and work-stealing).
          
          - Going beyond ~2x physical core count will harm performance 
          - For each num_thread, a new connection is made to the backend 
          - Within each "iteration" running on a "thread" additional tasks are spawned; 
          - A task to call get_capabilities 
          - A task to call bs_write, then N tasks to call bs_read up to read_amplification 
          - A task to call ac_write, then ac_read; 
            note this task also has a configurable sleep on it to work around a race condition present in some cache backends
          
          [env: NUM_THREADS=]
          [default: 20]

      --write_only
          Only generate and write data with Bytestream.Write() RPC
          
          [env: WRITE_ONLY=]

      --read_amplification <READ_AMPLIFICATION>
          For each iteration of requests, how many additional read requests to send; allows for simulation of a more realistic read-heavy workload with a single client
          
          [env: READ_AMPLIFICATION=]
          [default: 20]

      --chunk_size <CHUNK_SIZE>
          The size in which chunks should be created and sent up to the backend. Bigger generally is better for speed on a good network, but bazel defaults this to quite small at 16k, so that is the default here
          
          [env: CHUNK_SIZE=]
          [default: 16384]

      --zero_pad_blob_pct <ZERO_PAD_BLOB_PCT>
          A mechanism by which to increase write performance (less RNG) and also test data deduplication, by replacing the specified percentage of each blob by 0s
          
          [env: ZERO_PAD_BLOB_PCT=]
          [default: 50]

      --ac_read_sleep_ms <AC_READ_SLEEP_MS>
          Some caches will return not-found to requests coming too soon after an AC entry is written. This delay offsets that, but in a single threaded mode it will significantly affect RPS. Set as close to 0 as possible while minimizing ac_read error rates in the Grafana dashboard
          
          [env: AC_READ_SLEEP_MS=]
          [default: 20]

      --digest_function <DIGEST_FUNCTION>
          The reAPI digest function to use to generate hashes; blake3 is preferred but not supported in bazel-remote, so the default is sha256. If the cache under test supports blake3, be sure to use this to remove the CPU-bound nature of large write benchmarks caused by sha256 hashing
          
          [env: DIGEST_FUNCTION=]
          [default: sha256]
          [possible values: sha256, blake3]

      --label <LABEL>
          The label to associate with metrics reported into prometheus, so that separate lines can be shown for each cache backend under test; comes in as a value on the "cache_backend" label
          
          [env: LABEL=]
          [default: default]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

```