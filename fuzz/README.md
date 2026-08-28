# ROHCCXX fuzzing

Configure only with Clang. Fuzzers are disabled in normal builds:

```sh
cmake -S . -B build-fuzz -G Ninja -DCMAKE_CXX_COMPILER=clang++ \
  -DROHCCXX_BUILD_FUZZERS=ON -DROHCCXX_BUILD_TESTS=OFF
cmake --build build-fuzz
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
  build-fuzz/fuzz/fuzz_stateless_decompress fuzz/corpus/stateless \
  -max_len=65535 -timeout=10 -rss_limit_mb=2048 -max_total_time=300
```

All targets bound input sizes, operation counts, output capacity and parser work.
Failures must be minimized and reproduced outside libFuzzer before correction.

The pull-request workflow runs every target serially for a bounded smoke period.
The weekly scheduled job runs each target for at least five minutes. A skip or
nonzero target exit fails the job; only failure reproducers and logs are uploaded.
