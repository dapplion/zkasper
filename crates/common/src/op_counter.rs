//! Operation counters for benchmarking circuit cost.
//!
//! When the `count-ops` feature is enabled, every call to `sha256_pair`,
//! `poseidon_pair`, and `poseidon_leaf` increments a global atomic counter.
//! Use `reset()` before a guest verification run and `snapshot()` after to
//! get the operation counts.

use core::sync::atomic::{AtomicU64, Ordering};

static SHA256: AtomicU64 = AtomicU64::new(0);
static POSEIDON_T3: AtomicU64 = AtomicU64::new(0);
static POSEIDON_T4: AtomicU64 = AtomicU64::new(0);

/// Approximate constraints per operation (Plonkish / Groth16 ballpark).
const SHA256_CONSTRAINTS: u64 = 29_000;
const POSEIDON_T3_CONSTRAINTS: u64 = 250;
const POSEIDON_T4_CONSTRAINTS: u64 = 330;

#[inline]
pub fn inc_sha256() {
    SHA256.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn inc_poseidon_t3() {
    POSEIDON_T3.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn inc_poseidon_t4() {
    POSEIDON_T4.fetch_add(1, Ordering::Relaxed);
}

/// Reset all counters to zero.
pub fn reset() {
    SHA256.store(0, Ordering::Relaxed);
    POSEIDON_T3.store(0, Ordering::Relaxed);
    POSEIDON_T4.store(0, Ordering::Relaxed);
}

/// Snapshot of operation counts with constraint estimates.
#[derive(Debug, Clone)]
pub struct OpSnapshot {
    pub sha256: u64,
    pub poseidon_t3: u64,
    pub poseidon_t4: u64,
}

impl OpSnapshot {
    pub fn sha256_constraints(&self) -> u64 {
        self.sha256 * SHA256_CONSTRAINTS
    }

    pub fn poseidon_constraints(&self) -> u64 {
        self.poseidon_t3 * POSEIDON_T3_CONSTRAINTS + self.poseidon_t4 * POSEIDON_T4_CONSTRAINTS
    }

    pub fn total_constraints(&self) -> u64 {
        self.sha256_constraints() + self.poseidon_constraints()
    }

    /// Difference: self - other (for measuring a specific section).
    pub fn delta(&self, before: &OpSnapshot) -> OpSnapshot {
        OpSnapshot {
            sha256: self.sha256 - before.sha256,
            poseidon_t3: self.poseidon_t3 - before.poseidon_t3,
            poseidon_t4: self.poseidon_t4 - before.poseidon_t4,
        }
    }
}

impl core::fmt::Display for OpSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let total = self.total_constraints();
        write!(
            f,
            "sha256: {} (~{}M constraints), poseidon_t3: {} (~{}k), poseidon_t4: {} (~{}k) => total ~{}M constraints",
            self.sha256,
            self.sha256_constraints() / 1_000_000,
            self.poseidon_t3,
            self.poseidon_t3 * POSEIDON_T3_CONSTRAINTS / 1_000,
            self.poseidon_t4,
            self.poseidon_t4 * POSEIDON_T4_CONSTRAINTS / 1_000,
            total / 1_000_000,
        )
    }
}

/// Take a snapshot of the current counters.
pub fn snapshot() -> OpSnapshot {
    OpSnapshot {
        sha256: SHA256.load(Ordering::Relaxed),
        poseidon_t3: POSEIDON_T3.load(Ordering::Relaxed),
        poseidon_t4: POSEIDON_T4.load(Ordering::Relaxed),
    }
}
