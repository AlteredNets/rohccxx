#!/usr/bin/env bash
set -euo pipefail
umask 022

root=$PWD/benchmark-run
src=$root/source
archive=$root/incoming/rohccxx-0.4.1-source-with-submodules.tar.gz
buildinfo=$root/incoming/rohccxx-0.4.1-buildinfo.txt
flags='-O3 -DNDEBUG -march=x86-64 -mtune=generic'
mkdir -p "$root"/{incoming,harness-src,harness-build,calibration,final,artifacts}
cp benchmarks/{scientific_runner.cpp,scientific_comparator.cpp,fo_rtp_uncompressed_collision_regression.cpp,experiment-v0.4.1.json,METHODOLOGY-v0.4.1.md} "$root/harness-src/"
curl --fail --location --retry 3 --output "$archive" 'https://github.com/AlteredNets/rohccxx/releases/download/v0.4.1/rohccxx-0.4.1-source-with-submodules.tar.gz'
curl --fail --location --retry 3 --output "$buildinfo" 'https://github.com/AlteredNets/rohccxx/releases/download/v0.4.1/rohccxx-0.4.1-buildinfo.txt'
echo '018298423c6b9231f42a9d5f53cd55b63e53af65d7c664c8ed7879c48688787a  '"$archive" | sha256sum --check --strict
echo 'fb4553f3a8325afeea948a152066565c17074b85d4228573ea478fdc25f02172  '"$buildinfo" | sha256sum --check --strict
mkdir "$src"
tar -xzf "$archive" -C "$src" --strip-components=1
test "$(tr -d '\r\n' < "$src/VERSION")" = 0.4.1
grep -Fxq 'Main commit: 62e0c39dd3505162c14f30f31ba3d9cf4e10bff8' "$buildinfo"
grep -Fxq 'rohc-lib commit: 70589cc2b8650f82453815c84ba41b0ab80a52a0' "$buildinfo"
grep -Fxq 'VERSION: 0.4.1' "$buildinfo"

export CC=gcc-13 CXX=g++-13 CFLAGS="$flags" CXXFLAGS="$flags"
cmake -S "$src" -B "$root/build-release" -DCMAKE_BUILD_TYPE=Release -DROHCCXX_BUILD_TESTS=OFF -DCMAKE_C_FLAGS_RELEASE="$flags" -DCMAKE_CXX_FLAGS_RELEASE="$flags"
cmake --build "$root/build-release" --parallel

rohc_src=$src/tests/third_party/rohc-lib
test -f "$rohc_src/configure.ac"
mkdir "$root/rohclib-build-normalized"
pushd "$rohc_src"
autoreconf -fi
popd
pushd "$root/rohclib-build-normalized"
"$rohc_src/configure" --disable-doc --disable-examples --disable-rohc-tests --disable-python-rohc
make -j"$(nproc)"
popd

printf '%s\n' "$flags" > "$root/harness-build/effective-flags.txt"
g++-13 $flags -std=c++17 "$root/harness-src/scientific_runner.cpp" -o "$root/harness-build/scientific_runner" \
  -I"$rohc_src/src/common" -I"$rohc_src/src/comp" -I"$rohc_src/src/decomp" -I"$root/rohclib-build-normalized" \
  -L"$root/rohclib-build-normalized/src/.libs" -Wl,-rpath,"$root/rohclib-build-normalized/src/.libs" -lrohc -ldl
g++-13 $flags -std=c++17 "$root/harness-src/scientific_comparator.cpp" -o "$root/harness-build/scientific_comparator" \
  -I"$rohc_src/src/common" -I"$rohc_src/src/comp" -I"$rohc_src/src/decomp" -I"$root/rohclib-build-normalized" \
  -L"$root/rohclib-build-normalized/src/.libs" -Wl,-rpath,"$root/rohclib-build-normalized/src/.libs" -lrohc -ldl
g++-13 $flags -std=c++17 "$root/harness-src/fo_rtp_uncompressed_collision_regression.cpp" -o "$root/harness-build/collision_regression" \
  -I"$src/include" -I"$root/build-release/generated/include" -L"$root/build-release/src" -Wl,-rpath,"$root/build-release/src" -lrohccxx

resolved=$root/harness-build/experiment-resolved-v0.4.1.txt
: > "$resolved"
for f in "$root/harness-src/experiment-v0.4.1.json" "$root/harness-build/scientific_runner" "$root/harness-src/scientific_runner.cpp" "$root/harness-build/effective-flags.txt" "$archive" "$buildinfo" "$root/build-release/src/librohccxx.so.0.4.1" "$root/rohclib-build-normalized/src/.libs/librohc.so.3.0.0"; do sha256sum "$f" >> "$resolved"; done

first_line() { awk 'NR == 1 { line = $0 } END { print line }'; }
{
  echo "runner_image=${ImageOS:-unknown}-${ImageVersion:-unknown}"
  echo "kernel=$(uname -a)"
  echo "clock=$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource)"
  echo "compiler=$(g++-13 --version | first_line)"
  echo "linker=$(ld --version | first_line)"
  echo "cmake=$(cmake --version | first_line)"
  echo "glibc=$(ldd --version | first_line)"
  echo "topology=$(lscpu -p=CPU,CORE,SOCKET,NODE | tr '\n' ';')"
  echo "cpu_model=$(lscpu | awk -F: '/Model name/ && !seen {sub(/^ +/,"",$2);print $2;seen=1}')"
  echo "load_before=$(cat /proc/loadavg)"
  echo "swap_before=$(free -b | awk '/Swap:/{print $2","$3","$4}')"
  echo "steal_before=$(awk '/^cpu /{print $9}' /proc/stat)"
} > "$root/artifacts/environment.txt"

export LD_LIBRARY_PATH="$root/build-release/src:$root/rohclib-build-normalized/src/.libs"
export ROHCCXX_SO="$root/build-release/src/librohccxx.so.0.4.1"
"$root/harness-build/collision_regression" > "$root/artifacts/correctness.txt"
"$root/harness-build/scientific_comparator" validate >> "$root/artifacts/correctness.txt"
"$root/harness-build/scientific_runner" --mode correctness --manifest "$root/harness-src/experiment-v0.4.1.json" --root "$root" >> "$root/artifacts/correctness.txt"

shards=8
pids=()
for ((s=0;s<shards;s++)); do "$root/harness-build/scientific_runner" --mode calibration --shard "$s" "$shards" --manifest "$root/harness-src/experiment-v0.4.1.json" --root "$root" > "$root/artifacts/calibration-$s.log" 2>&1 & pids+=("$!"); done
for p in "${pids[@]}"; do wait "$p"; done
for plan in "$root"/calibration/calibration-plan-v0.4.1-shard-*.csv; do sha256sum "$plan" >> "$resolved"; done
pids=()
for ((s=0;s<shards;s++)); do "$root/harness-build/scientific_runner" --mode final --authorize-final --shard "$s" "$shards" --manifest "$root/harness-src/experiment-v0.4.1.json" --root "$root" > "$root/artifacts/final-$s.log" 2>&1 & pids+=("$!"); done
for p in "${pids[@]}"; do wait "$p"; done

head -1 "$root/calibration/raw-calibration-v0.4.1-shard-0.csv" > "$root/artifacts/raw-calibration.csv"
head -1 "$root/calibration/calibration-plan-v0.4.1-shard-0.csv" > "$root/artifacts/calibration-plan.csv"
head -1 "$root/final/raw-final-v0.4.1-shard-0.csv" > "$root/artifacts/raw-final.csv"
for f in "$root"/calibration/raw-calibration-v0.4.1-shard-*.csv; do tail -n +2 "$f" >> "$root/artifacts/raw-calibration.csv"; done
for f in "$root"/calibration/calibration-plan-v0.4.1-shard-*.csv; do tail -n +2 "$f" >> "$root/artifacts/calibration-plan.csv"; done
for f in "$root"/final/raw-final-v0.4.1-shard-*.csv; do tail -n +2 "$f" >> "$root/artifacts/raw-final.csv"; done
cp "$resolved" "$root/artifacts/resolved-identity.txt"
cp "$root/harness-build/effective-flags.txt" "$root/artifacts/effective-flags.txt"
{
  echo "load_after=$(cat /proc/loadavg)"
  echo "swap_after=$(free -b | awk '/Swap:/{print $2","$3","$4}')"
  echo "steal_after=$(awk '/^cpu /{print $9}' /proc/stat)"
} >> "$root/artifacts/environment.txt"
python3 benchmarks/analyze.py "$root/artifacts/raw-calibration.csv" "$root/artifacts/raw-final.csv" "$root/artifacts/statistical-summary.json"
(cd "$root/artifacts" && sha256sum raw-calibration.csv calibration-plan.csv raw-final.csv resolved-identity.txt effective-flags.txt correctness.txt environment.txt statistical-summary.json > SHA256SUMS)
