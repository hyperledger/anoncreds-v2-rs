.PHONY: build
build:
	cargo build

# To ensure tests run in consistent order:
# TEST_THREADS=--test-threads=1 make-test
#
# OR
#
# export TEST_THREADS=--test-threads=1
# make-test

SKIP_TESTS_THAT_OVERWRITE_SRC = \
        --skip test_to_w3c \
        --skip test_create_presentation \
        --skip test_to_w3c_presentation \
        --skip test_map_to_w3c_presentation

SKIP_TESTS_THAT_ARE_OVERRIDDEN = \
        --skip overridden_to_fail

.PHONY: test
test:
	cargo test -- \
                   $(TEST_THREADS) \
                   $(SKIP_TESTS_THAT_OVERWRITE_SRC) \
                   $(SKIP_TESTS_THAT_ARE_OVERRIDDEN)

.PHONY: test-skip-slow
test-skip-slow:
	cargo test --features=ignore_slow \
                   -- \
                   $(TEST_THREADS) \
                   $(SKIP_TESTS_THAT_OVERWRITE_SRC) \
                   $(SKIP_TESTS_THAT_ARE_OVERRIDDEN)

.PHONY: test-skip-slow-slow
test-skip-slow-slow:
	cargo test --features=ignore_slow_slow \
                   -- \
                   $(TEST_THREADS) \
                   $(SKIP_TESTS_THAT_OVERWRITE_SRC) \
                   $(SKIP_TESTS_THAT_ARE_OVERRIDDEN)

.PHONY: clean
clean:
	cargo clean

README_MD = ./src/vcp/README.md
.PHONY: fix-readme-markdown
fix-readme-markdown:
	sed -i -e 's/<sub>/_/g'  $(README_MD)
	sed -i -e 's/<\/sub>//g' $(README_MD)
	sed -i '1i<!--- DO NOT EDIT.  GENERATED FROM README.org --->' $(README_MD)


