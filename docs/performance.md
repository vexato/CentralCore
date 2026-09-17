# Performance notes

The stabilization suite contains deterministic synthetic coverage for a
10,000-file provider manifest and a 10,000-component dependency chain. The
component resolver is iterative and linear in vertices plus dependency edges;
it does not recurse or risk stack overflow. Verification and update planning
use bounded concurrency and maps/sets keyed by validated paths.

For release reporting, run the large tests with `--nocapture` and record the
machine, profile, OS and storage type. Measure quick verification, full hashing
and update diff on an approximately 4,000-file instance. Results are indicative
only and are not performance guarantees across disks, antivirus products or
CPUs. Measure peak working set externally during idle, manifest resolution,
install and verify; investigate unexplained hundreds-of-megabytes growth.

Criterion was intentionally not added for 1.0: the useful paths are async and
filesystem-heavy, and deterministic scenario timings are more representative
than isolated microbenchmarks. Benchmarks are advisory and do not gate release.

## Phase 10 reference run

One Windows debug-profile run on the development machine measured:

| Scenario | Result |
|---|---:|
| parse 10,000-file instance JSON | 34.9 ms |
| validate the 10,000-file manifest | 88.3 ms |
| quick verify 4,000 real files | 65 ms |
| full hash verify 4,000 small real files | 483 ms |
| diff a 4,000-file UpdatePlan (2,000 changed) | 149.2 ms |

The verify fixture uses tiny files and therefore measures traversal/metadata
overhead more than game-sized hashing. Antivirus, storage and release builds
can change the result substantially. A representative peak-memory/install
measurement still requires the optional real-game harness; the deterministic
suite did not fabricate a number from a tiny fixture.
