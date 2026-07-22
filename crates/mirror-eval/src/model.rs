//! The population model and the two trace generators.
//!
//! Each participant has a stable *behavioral fingerprint*: the two signals real
//! Solana clustering tools exploit —
//!
//! - **timing habit** (`timing_offset`): how long after an intent surfaces this
//!   participant typically acts. The co-buy-timing attack keys on exactly this
//!   ("wallets acting within seconds of each other are linked"); an individual's
//!   habitual offset is what separates them from the crowd.
//! - **sizing habit** (`position_size`): the participant's typical position size.
//!   Round-number and consistent-size transfers are a documented fingerprint.
//!
//! The *unprotected* trace lets each participant act on their own fingerprint,
//! so actions carry identity-correlated timing and size. The *protected* trace
//! is what `mirror-pool` produces: the coordinator fires all `k` actions inside
//! one tight window with identical size, and the acting key is unlinked from the
//! member — so no action carries any per-identity signal.

use crate::rng::SplitMix64;

/// Seconds a real-world intent stays "hot" — the co-buy window an attacker
/// watches in the unprotected world. Participants' habitual offsets are spread
/// across it.
const INTENT_WINDOW_SECS: f64 = 60.0;

/// The tight window the pool coordinator fires within. Jitter here is
/// identity-independent (the coordinator schedules it, not the participant).
const POOL_WINDOW_SECS: f64 = 4.0;

/// Range of habitual position sizes across the population (arbitrary units).
const SIZE_MIN: f64 = 100.0;
const SIZE_MAX: f64 = 1000.0;

/// The fixed size every participant emits inside a protected round. Identical
/// across participants by construction — that is what collapses the sizing
/// fingerprint.
const ROUND_SIZE: f64 = 500.0;

/// A single participant's stable behavioral fingerprint.
#[derive(Clone, Copy, Debug)]
pub struct Fingerprint {
    pub id: usize,
    /// Habitual delay (seconds) after an intent before this participant acts.
    pub timing_offset: f64,
    /// Habitual position size.
    pub position_size: f64,
    /// Per-participant timing steadiness (std-dev of their own jitter). Some
    /// people are more punctual than others; the attacker benefits from steady
    /// habits, so modeling this keeps the unprotected attacker strong.
    pub timing_jitter: f64,
    /// Per-participant sizing steadiness (as a fraction of position_size).
    pub size_jitter_frac: f64,
}

/// One observed on-chain action. `(time, size)` is what the attacker sees;
/// `true_id` is ground truth, hidden from the attacker and used only to score.
#[derive(Clone, Copy, Debug)]
pub struct Action {
    pub time: f64,
    pub size: f64,
    pub true_id: usize,
}

/// A shared intent all participants respond to in a round (e.g. "buy token X").
/// `t0` is when it surfaced; sizes scale around the population baseline.
#[derive(Clone, Copy, Debug)]
pub struct RoundIntent {
    pub t0: f64,
}

impl RoundIntent {
    pub fn sample(rng: &mut SplitMix64) -> Self {
        // Intent can surface any time; absolute offset does not matter to the
        // attacker (it profiles *relative* timing), but varying it avoids any
        // accidental alignment.
        Self {
            t0: rng.range(0.0, 1_000_000.0),
        }
    }
}

/// The full population and its trace generators.
pub struct Population {
    pub members: Vec<Fingerprint>,
}

impl Population {
    /// Sample `k` participants with distinct, randomly-placed fingerprints.
    ///
    /// Placement is random (not monotonic in `id`) so the attacker gains no free
    /// information from index ordering — it must rely on the behavioral signals.
    pub fn sample(k: usize, rng: &mut SplitMix64) -> Self {
        let members = (0..k)
            .map(|id| Fingerprint {
                id,
                timing_offset: rng.range(0.0, INTENT_WINDOW_SECS),
                position_size: rng.range(SIZE_MIN, SIZE_MAX),
                // Habits are fairly steady: sub-second timing, a few percent sizing.
                timing_jitter: rng.range(0.3, 1.2),
                size_jitter_frac: rng.range(0.01, 0.05),
            })
            .collect();
        Self { members }
    }

    pub fn k(&self) -> usize {
        self.members.len()
    }

    /// Unprotected trace: each participant acts on their own habit. Timing and
    /// size are identity-correlated, so the trace is attributable.
    pub fn unprotected_trace(&self, intent: &RoundIntent, rng: &mut SplitMix64) -> Vec<Action> {
        self.members
            .iter()
            .map(|m| {
                let time = intent.t0 + m.timing_offset + m.timing_jitter * rng.next_normal();
                let size = m.position_size * (1.0 + m.size_jitter_frac * rng.next_normal());
                Action {
                    time,
                    size,
                    true_id: m.id,
                }
            })
            .collect()
    }

    /// Protected trace: `mirror-pool`. Every action has the identical round size
    /// and a coordinator-scheduled time drawn from one tight, identity-independent
    /// window. Nothing about `(time, size)` correlates with the participant.
    ///
    /// `true_id` is still recorded so the harness can score the attacker — but by
    /// construction the observable `(time, size)` is independent of it.
    pub fn protected_trace(&self, intent: &RoundIntent, rng: &mut SplitMix64) -> Vec<Action> {
        self.members
            .iter()
            .map(|m| {
                // Identity-independent jitter: the coordinator picks it, uniform
                // across the pool window, with no reference to the member.
                let time = intent.t0 + rng.range(0.0, POOL_WINDOW_SECS);
                Action {
                    time,
                    size: ROUND_SIZE,
                    true_id: m.id,
                }
            })
            .collect()
    }
}
