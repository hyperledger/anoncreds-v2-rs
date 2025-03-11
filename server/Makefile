.PHONY: build
build:
	cargo build

.PHONY: run
run:
	cargo run

# export TEST_THREADS=--test-threads=1
.PHONY: test
test:
	cargo test -- \
                   $(TEST_THREADS)

.PHONY: clean
clean:
	cargo clean

