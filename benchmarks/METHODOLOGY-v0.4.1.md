# v0.4.1 benchmark methodology

Protocol revision: `v0.4.1-protocol-r2`.

This experiment compares rohccxx v0.4.1 with the pinned rohc-lib and an
uncompressed memory-copy control. It is not a cross-version comparison;
v0.4.0 and its historical workspace are explicitly excluded.

All treatments consume identical immutable packet vectors. Contexts are fresh for context-establishment measurements and advanced to the same ordinal before steady-state measurements. Allocation, corpus generation, setup, validation, logging, and file I/O are outside timed regions. The memory-copy control quantifies harness overhead only.

The IPv4 ID is stable per flow (`0x1234 + flow`). This deliberately keeps the
fixed calibration workload separate from 16-bit sequential-ID wrap stress;
wrap behavior belongs in correctness regression coverage, not timing samples.

The unavoidable API difference is context selection: rohccxx requires `rohc_comp_set_cid`, while rohc-lib derives context from flow keys. Each required selection operation stays inside its implementation's compression boundary. rohc-lib uses `rohc_buf` descriptors; rohccxx uses pointer/length arguments. Both libraries and the harness use GCC 13.3.0 with `-O3 -DNDEBUG -march=x86-64 -mtune=generic` and identical input, operation counts, context ordinals, and output capacities.

RTP, UDP, ESP, and IP-only results remain separate. Every workload must pass byte-exact and canary validation immediately before and after measurement. A gate or correctness failure suppresses that sample. Raw samples are immutable; no outlier is deleted. Summaries use median, MAD, and a fixed-seed bootstrap 95% confidence interval.

Every calibration treatment performs exactly 10,000 untimed operations before
its first discarded timing probe. The probe selects a repetition count meeting
both 1,000,000 operations and four seconds. Calibration rows are permanently
labeled `CALIBRATION_NON_REPORTABLE`; neither their durations nor their rows
become final observations. Final mode performs 21 new observations and requires
both `--mode final` and `--authorize-final`, plus the pinned manifest, resolved
build identity, and calibration-plan hash. Allocation, setup, context
establishment, validation, logging, and file I/O surround rather than enter the
timed API loop.

Three independent GitHub-hosted `ubuntu-24.04` jobs execute the same experiment.
Each job records its runner image, CPU model and topology, kernel, compiler,
linker, CMake, glibc, clocksource, load, swap, and CPU-steal counters. Workloads
are deterministically sharded within a replica to fit the six-hour job limit;
each shard has its own calibration plan, and every plan hash is added to that
replica's resolved identity before final mode. The cross-replica gate flags a
series when its median relative spread exceeds 15 percent and suppresses a
claim when any series is unstable. Results support relative comparisons only,
not absolute hardware-performance or marketing claims. The v0.4.1-only scope,
implementations, workloads, corpus, seed, payloads, flow counts, balanced
ordering, warm-up count, calibration minima, final observation count, timing
boundaries, correctness and guard requirements, statistics, confidence
intervals, no-outlier-deletion rule, calibration labeling, and final
authorization controls are unchanged.
