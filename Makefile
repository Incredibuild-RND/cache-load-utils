#!make

# set up env from env file, similar to rust's dotenv
ifneq ("$(wildcard .env)","")
    include .env
    export $(shell sed 's/=.*//' .env)
endif

# Check if CUDA_HOME is set or nvcc is in PATH
CUDA_INSTALLED := $(shell (test -n "$$CUDA_HOME" || which nvcc > /dev/null) && echo 1 || echo 0)

# choose the appropriate base command for building and running the benchmark with or without the cuda feature
ifeq ($(CUDA_INSTALLED),1)
    CARGO_RUN_CMD=@cargo run --release --bin bazelbench-rs --features cuda --
else
    CARGO_RUN_CMD=@cargo run --release --bin bazelbench-rs --
endif

help:
	$(CARGO_RUN_CMD) --help

flamegraph: grafana bazel_remote
	CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --bin bazelbench-rs -- --read_amplification 1 --flamegraph --num_threads 1

bench_garnet: grafana
	$(CARGO_RUN_CMD) \
		--target_endpoint http://localhost:1337 \
		--ac_read_sleep_ms 0 \
		--digest_function blake3 \
		--label garnet \
		--num_threads 100 --read_amplification 100

bench_garnet_write_only: grafana
	$(CARGO_RUN_CMD) \
		--target_endpoint http://localhost:1337 \
		--write_only \
		--num_threads 100 \
		--digest_function blake3 \
		--label garnet

# bazel-remote benchmarks
bench_bazelremote: grafana bazel_remote
	$(CARGO_RUN_CMD) --label bazelremote --ac_read_sleep_ms 100

bench_bazelremote_write_only: grafana bazel_remote
	$(CARGO_RUN_CMD) \
		--write_only \
		--num_threads 100 \
		--label bazelremote

bench_bazelremote_write_only_big: grafana bazel_remote
	$(CARGO_RUN_CMD) \
		--write_only \
		--chunk_size 1048576 \
		--blob_size_bytes 10485760 \
		--num_threads 40 \
		--label bazelremote

# nativelink benchmarks
bench_nativelink: grafana nativelink
	$(CARGO_RUN_CMD) \
		--target_endpoint http://localhost:50051 \
		--ac_read_sleep_ms 0 \
		--digest_function blake3 \
		--label nativelink \
		--num_threads 100 --read_amplification 100

bench_nativelink_write_only: grafana nativelink
	$(CARGO_RUN_CMD) \
		--write_only \
		--num_threads 100 \
		--target_endpoint http://localhost:50051 \
		--digest_function blake3 \
		--label nativelink

bench_nativelink_write_only_big: grafana nativelink
	$(CARGO_RUN_CMD) \
		--write_only \
		--chunk_size 1048576 \
		--blob_size_bytes 10485760 \
		--num_threads 40 \
		--target_endpoint http://localhost:50051 \
		--digest_function blake3 \
		--label nativelink

bench_nativelink_write_only_big_cpu: grafana nativelink
	$(CARGO_RUN_CMD) \
		--write_only \
		--chunk_size 1048576 \
		--blob_size_bytes 10485760 \
		--num_threads 40 \
		--target_endpoint http://localhost:50051 \
		--digest_function blake3 \
		--label nativelink \
		--allow_gpu false


grafana: prometheus
	@docker kill grafana >/dev/null 2>&1 || true
	@docker rm grafana >/dev/null 2>&1 || true
	@docker run -d --name grafana \
		--network="host" \
		-v $(PWD)/datasources:/etc/grafana/provisioning/datasources \
		-v $(PWD)/dashboards:/etc/grafana/provisioning/dashboards \
		-e "GF_PROMETHEUS_URL=http://localhost:9090" \
		-e "GF_AUTH_ANONYMOUS_ENABLED=true" \
		-e "GF_AUTH_ANONYMOUS_ORG_ROLE=Admin" \
		grafana/grafana:latest >/dev/null
	@echo "\nbench dash available at http://localhost:3000/d/bdj4arf1qn0g0c/benchmark-metrics?orgId=1"

prometheus:
#	@docker kill prometheus >/dev/null 2>&1 || true
#	@docker rm prometheus >/dev/null 2>&1 || true
	@docker run -d --name prometheus \
        --rm \
		--network="host" \
        -v $(PWD)/prometheus.yml:/etc/prometheus/prometheus.yml \
        prom/prometheus >/dev/null 2>&1 || true

bazel_remote: stop_bazel_remote
	@mkdir /tmp/br || true
	@bazel-remote --dir "/tmp/br" --max_size 10 --experimental_remote_asset_api > /tmp/bazel_remote.log 2>&1 &
	@echo "bazel-remote running, tail logs with tail -f /tmp/bazel_remote.log\n"

stop_bazel_remote:
	@pkill -f -x bazel-remote || true
	@sleep 1
	@rm -rf "/tmp/br" || true

install_nativelink:
	cargo install --git https://github.com/TraceMachina/nativelink --rev ea508561d8faf1de3a7188867c70b7ef36069572

stop_nativelink:
	@pkill -f -x 'nativelink $(PWD)/nativelink/' || true
	@sleep 1
	@rm -rf "/tmp/nativelink" || true

nativelink: stop_nativelink install_nativelink
	@mkdir /tmp/nativelink || true
	@nativelink $(PWD)/nativelink/memory_and_disk.json > /tmp/nativelink.log 2>&1 &
	@echo "nativelink running, tail logs with tail -f /tmp/nativelink.log\n"

stop: stop_bazel_remote stop_nativelink
	@docker kill prometheus >/dev/null 2>&1 || true
	@docker kill grafana >/dev/null 2>&1 || true

cargo_bench:
ifeq ($(CUDA_INSTALLED),1)
	cargo bench --features cuda
else
	cargo bench
endif
