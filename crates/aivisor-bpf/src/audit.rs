//! Userspace consumer for the BPF audit ring buffer.
//!
//! The kernel side (`emit_event` in `common.h`) writes fixed-size records
//! into the `events` `BPF_MAP_TYPE_RINGBUF` and, if the ring is full,
//! **drops the record and carries on**. It never blocks and never fails the
//! syscall it was auditing — a full audit ring must not become a denial of
//! service against the sandboxed workload, and an LSM hook cannot wait for a
//! userspace reader anyway.
//!
//! That design only holds up if the userspace side is equally unwilling to
//! block. This module is the piece that makes it true:
//!
//! ```text
//!   BPF ringbuf ──▶ consumer thread ──▶ bounded channel ──▶ sinks
//!                        (poll)          (try_send only)    (aivisord)
//! ```
//!
//! The consumer thread's only job is to drain the ring as fast as the kernel
//! fills it and hand records off. It pushes into a **bounded** channel with
//! `try_send`, so a slow or stalled sink (a blocked OTLP endpoint, a full
//! disk) costs bounded memory and a rising drop count rather than
//! back-pressure that propagates into the ring and then into every audited
//! syscall. Roadmap Phase 3 failure mode #5 is exactly this bug: "blocking
//! ring-buffer consumer on slow sink".
//!
//! Loss is therefore possible by construction, at two distinct points, and
//! both are counted rather than hidden:
//!
//! * **Kernel-side loss** — `bpf_ringbuf_reserve` returned NULL. Userspace
//!   cannot see these individually; what it can see is the gap in [`AuditEvent::seq`]
//!   … except it cannot, because `seq` is assigned on *this* side. Kernel-side
//!   loss is instead inferred from ring occupancy, which is why the ring is
//!   sized at 8 MB (≈262k records) in `common.h`.
//! * **Userspace-side loss** — the bounded channel was full. Counted exactly,
//!   in [`AuditStream::dropped_count`], and stamped onto the next event that
//!   *does* get through as [`AuditEvent::dropped_count`] so a downstream sink
//!   reports loss in-band instead of silently under-reporting (blueprint §12:
//!   `StreamEvents` must drop with an explicit count).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use aivisor_core::Error;

/// How long the consumer thread waits in one `poll` call before re-checking
/// the shutdown flag. Also the worst-case delay on [`AuditStream`] drop.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Default depth of the bounded hand-off channel.
///
/// Sized so a sink can stall for a beat without immediate loss, while
/// capping the consumer's memory at roughly `DEFAULT_CHANNEL_DEPTH *
/// size_of::<AuditEvent>()` (~2 MB) no matter how long the stall lasts.
pub const DEFAULT_CHANNEL_DEPTH: usize = 65536;

/// Event categories, mirroring `EVT_KIND_*` in `common.h` and `EventKind` in
/// `proto/aivisor/v1/aivisor.proto`. The three encodings share integer
/// values on purpose so no translation table is needed anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    FileOpen,
    Exec,
    Connect,
    Mount,
    PolicyDeny,
    ResourcePressure,
    Lifecycle,
    BrokerCall,
    /// A value the kernel emitted that this build does not know about.
    /// Retained rather than discarded: an unknown kind is still evidence,
    /// and dropping it would make a version-skewed daemon silently lose
    /// audit records.
    Unknown(u32),
}

impl EventKind {
    fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::FileOpen,
            1 => Self::Exec,
            2 => Self::Connect,
            3 => Self::Mount,
            4 => Self::PolicyDeny,
            5 => Self::ResourcePressure,
            6 => Self::Lifecycle,
            7 => Self::BrokerCall,
            other => Self::Unknown(other),
        }
    }
}

/// What the hook decided, mirroring `EVT_DECISION_*` in `common.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventDecision {
    Allow,
    Deny,
    Notify,
    Kill,
    /// See [`EventKind::Unknown`] — an unrecognised decision is preserved,
    /// and [`EventDecision::is_kill`] treats it as *not* a kill so an
    /// unknown value can never cause a spurious sandbox teardown.
    Unknown(u32),
}

impl EventDecision {
    fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::Allow,
            1 => Self::Deny,
            2 => Self::Notify,
            3 => Self::Kill,
            other => Self::Unknown(other),
        }
    }

    /// Whether this decision obliges userspace to tear the sandbox down.
    ///
    /// An LSM hook cannot call `cgroup.kill` on its own cgroup — that is a
    /// write to a cgroupfs control file, unreachable from BPF context — so
    /// the kernel side blocks the operation, sets `FLAG_KILL_PENDING`, and
    /// emits this decision. Actually killing is a debt userspace owes the
    /// kernel side; see `aivisord::audit` for the responder that pays it.
    pub fn is_kill(self) -> bool {
        matches!(self, Self::Kill)
    }
}

/// One decoded audit record.
///
/// `MUST` match `struct aivisor_event` in `common.h` for the byte-decoding
/// in [`AuditEvent::from_bytes`] to be correct — this crosses the
/// kernel/userspace boundary as raw bytes with no serialization layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct AuditEvent {
    /// cgroup id, which is how an event is attributed to a sandbox. The
    /// mapping back to a `SandboxId` lives in the daemon, not here.
    pub cgid: u64,
    /// `bpf_ktime_get_ns()` — CLOCK_MONOTONIC nanoseconds, **not** a wall
    /// clock. Sinks that need a timestamp convert using the monotonic/real
    /// offset sampled once at start; see `aivisord::audit`.
    pub ts_ns: u64,
    pub pid: u32,
    pub kind: EventKind,
    pub decision: EventDecision,
    /// The errno the hook returned, 0 for an allow.
    pub errno: u32,
    /// Monotonic per-stream sequence number, assigned by the consumer as it
    /// drains the ring. Gaps are impossible; it exists so a sink can order
    /// records and detect its own loss downstream of this module.
    pub seq: u64,
    /// Cumulative count of events dropped by the bounded channel *before*
    /// this one was enqueued. A sink that sees this jump knows exactly how
    /// many records it is missing rather than under-reporting silently.
    pub dropped_count: u64,
}

impl AuditEvent {
    /// Wire size of `struct aivisor_event`: 8 + 8 + 4 + 4 + 4 + 4, no
    /// padding (8-byte alignment, 32-byte size).
    pub const WIRE_SIZE: usize = 32;

    /// Decode one ring record. Returns `None` for a short read rather than
    /// panicking: a truncated record means a C/Rust struct disagreement,
    /// and the consumer counts and skips it instead of taking the process
    /// down over one malformed audit event.
    pub fn from_bytes(b: &[u8], seq: u64, dropped_count: u64) -> Option<Self> {
        if b.len() < Self::WIRE_SIZE {
            return None;
        }
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_ne_bytes([
                b[o],
                b[o + 1],
                b[o + 2],
                b[o + 3],
                b[o + 4],
                b[o + 5],
                b[o + 6],
                b[o + 7],
            ])
        };
        Some(Self {
            cgid: u64_at(0),
            ts_ns: u64_at(8),
            pid: u32_at(16),
            kind: EventKind::from_raw(u32_at(20)),
            decision: EventDecision::from_raw(u32_at(24)),
            errno: u32_at(28),
            seq,
            dropped_count,
        })
    }
}

/// The non-blocking hand-off from ring to channel.
///
/// Split out from the polling loop so the drop-accounting can be tested
/// without a kernel: it is the part where a mistake is invisible in
/// production (a `send` instead of a `try_send` compiles fine and only
/// misbehaves under load, at which point it stalls the audited workload).
struct EventSender {
    tx: SyncSender<AuditEvent>,
    seq: u64,
    dropped: Arc<AtomicU64>,
    malformed: Arc<AtomicU64>,
}

impl EventSender {
    /// Decode and enqueue one raw ring record. Never blocks, never fails.
    fn offer(&mut self, raw: &[u8]) {
        // Read the running drop total *before* enqueuing so the event
        // carries the loss that preceded it.
        let dropped_before = self.dropped.load(Ordering::Relaxed);
        let Some(event) = AuditEvent::from_bytes(raw, self.seq, dropped_before) else {
            self.malformed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.seq += 1;

        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // The sink is behind. Drop this record and count it — the
                // alternative, blocking here, would push back into the ring
                // and from there into every syscall the LSM hooks audit.
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                // The stream was dropped; the poll loop's shutdown flag will
                // stop us on the next tick. Count it so the final tally is
                // still honest.
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// A live audit stream: the receiving end of the bounded channel, plus the
/// counters describing what did not make it through.
///
/// Dropping this stops the consumer thread (within [`POLL_INTERVAL`]) and
/// detaches from the ring buffer.
pub struct AuditStream {
    rx: Receiver<AuditEvent>,
    dropped: Arc<AtomicU64>,
    malformed: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl AuditStream {
    /// Block until the next event, or return `None` once the consumer
    /// thread has stopped and the channel is drained.
    pub fn recv(&self) -> Option<AuditEvent> {
        self.rx.recv().ok()
    }

    /// Next event, waiting at most `timeout`. `None` distinguishes nothing
    /// available from stream-ended only via [`Self::is_running`].
    pub fn recv_timeout(&self, timeout: Duration) -> Option<AuditEvent> {
        self.rx.recv_timeout(timeout).ok()
    }

    /// Take whatever is queued right now without waiting.
    pub fn drain(&self) -> Vec<AuditEvent> {
        self.rx.try_iter().collect()
    }

    /// Events discarded because the bounded channel was full — i.e. because
    /// the sink could not keep up. This is the number Phase 3's
    /// "audit < 1 % loss at 100k events/s" gate is measured against.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Ring records too short to decode. Non-zero here means the Rust and C
    /// definitions of `struct aivisor_event` have diverged; it is reported
    /// separately from `dropped_count` because the remedy is a rebuild, not
    /// a faster sink.
    pub fn malformed_count(&self) -> u64 {
        self.malformed.load(Ordering::Relaxed)
    }

    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::Relaxed)
    }

    /// Stop the consumer thread and wait for it to finish.
    ///
    /// Called by `Drop` too; explicit here so a caller that wants to know
    /// the final counters can stop the thread first and then read them
    /// without racing it.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            // A panicked consumer thread is not worth propagating from a
            // teardown path: the counters above are still readable and the
            // caller is shutting down regardless.
            let _ = handle.join();
        }
    }
}

impl Drop for AuditStream {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start draining the pinned `events` ring buffer into a bounded channel.
///
/// `channel_depth` bounds the consumer's memory and, with it, how long a
/// stalled sink can be tolerated before loss begins. It must be non-zero: a
/// zero-capacity `sync_channel` is a rendezvous channel, on which `try_send`
/// only ever succeeds if a receiver is *already parked* in `recv` — every
/// other event would be counted as dropped, which is a silently useless
/// audit pipeline rather than a loud misconfiguration.
///
/// Fails if the programs are not loaded (nothing has pinned `events` yet).
/// There is no degraded mode: a daemon that believes it is auditing but is
/// not is worse than one that refuses to start.
#[cfg(target_os = "linux")]
pub fn start_consumer(channel_depth: usize) -> Result<AuditStream, Error> {
    use libbpf_rs::{MapHandle, RingBufferBuilder};

    if channel_depth == 0 {
        return Err(Error::PolicyInvalid(
            "audit channel depth must be non-zero — a rendezvous channel would drop \
             every event whose receiver was not already parked in recv()"
                .into(),
        ));
    }

    let (tx, rx) = std::sync::mpsc::sync_channel(channel_depth);
    let dropped = Arc::new(AtomicU64::new(0));
    let malformed = Arc::new(AtomicU64::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));

    // Open the map on this thread so a missing pin surfaces as an error
    // from `start_consumer` rather than as a thread that quietly dies.
    let events_pin = std::path::PathBuf::from(crate::loader::PIN_DIR).join("events");
    let events = MapHandle::from_pinned_path(&events_pin).map_err(|e| {
        Error::LaunchFailed(format!(
            "open pinned audit ring buffer {}: {e} — are the BPF programs loaded? \
             (BpfLoader::load_and_attach pins them)",
            events_pin.display()
        ))
    })?;

    let (thread_dropped, thread_malformed, thread_shutdown) = (
        Arc::clone(&dropped),
        Arc::clone(&malformed),
        Arc::clone(&shutdown),
    );

    // The `RingBuffer` itself is built inside the thread: it borrows the map
    // and is not `Send`, so it cannot be constructed here and moved.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();

    let handle = std::thread::Builder::new()
        .name("aivisor-audit".into())
        .spawn(move || {
            let mut sender = EventSender {
                tx,
                seq: 0,
                dropped: Arc::clone(&thread_dropped),
                malformed: Arc::clone(&thread_malformed),
            };

            let mut builder = RingBufferBuilder::new();
            // The callback's return value is a libbpf convention: 0 keeps
            // consuming, negative aborts the current `poll`. Always 0 here —
            // one bad record must not stop the drain.
            if let Err(e) = builder.add(&events, |raw: &[u8]| {
                sender.offer(raw);
                0
            }) {
                let _ = ready_tx.send(Err(format!("attach to audit ring buffer: {e}")));
                thread_shutdown.store(true, Ordering::Relaxed);
                return;
            }

            let ring = match builder.build() {
                Ok(r) => r,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("build audit ring buffer: {e}")));
                    thread_shutdown.store(true, Ordering::Relaxed);
                    return;
                }
            };

            if ready_tx.send(Ok(())).is_err() {
                // Caller gave up waiting; nothing to drain for.
                thread_shutdown.store(true, Ordering::Relaxed);
                return;
            }

            while !thread_shutdown.load(Ordering::Relaxed) {
                // A poll error is logged and retried rather than fatal: the
                // common cause is EINTR from a signal, and tearing down the
                // audit pipeline because a signal arrived would lose every
                // subsequent event.
                if let Err(e) = ring.poll(POLL_INTERVAL) {
                    tracing::warn!("audit ring poll: {e}");
                }
            }

            // Final non-blocking sweep so events already in the ring at
            // shutdown are not lost to the stop flag.
            let _ = ring.consume();
            thread_shutdown.store(true, Ordering::Relaxed);
        })
        .map_err(|e| Error::LaunchFailed(format!("spawn audit consumer thread: {e}")))?;

    // Surface setup failures (bad map type, ENOMEM on the epoll fd) as an
    // error from this function instead of as an audit pipeline that looks
    // started and delivers nothing.
    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => {
            let _ = handle.join();
            return Err(Error::LaunchFailed(msg));
        }
        Err(_) => {
            let _ = handle.join();
            return Err(Error::LaunchFailed(
                "audit consumer thread exited before signalling readiness".into(),
            ));
        }
    }

    Ok(AuditStream {
        rx,
        dropped,
        malformed,
        shutdown,
        handle: Some(handle),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_event(cgid: u64, kind: u32, decision: u32, errno: u32) -> [u8; AuditEvent::WIRE_SIZE] {
        let mut b = [0u8; AuditEvent::WIRE_SIZE];
        b[0..8].copy_from_slice(&cgid.to_ne_bytes());
        b[8..16].copy_from_slice(&123u64.to_ne_bytes());
        b[16..20].copy_from_slice(&42u32.to_ne_bytes());
        b[20..24].copy_from_slice(&kind.to_ne_bytes());
        b[24..28].copy_from_slice(&decision.to_ne_bytes());
        b[28..32].copy_from_slice(&errno.to_ne_bytes());
        b
    }

    #[test]
    fn decodes_a_kernel_record() {
        let raw = raw_event(7, 1, 1, 1);
        let e = AuditEvent::from_bytes(&raw, 5, 0).unwrap();
        assert_eq!(e.cgid, 7);
        assert_eq!(e.ts_ns, 123);
        assert_eq!(e.pid, 42);
        assert_eq!(e.kind, EventKind::Exec);
        assert_eq!(e.decision, EventDecision::Deny);
        assert_eq!(e.errno, 1);
        assert_eq!(e.seq, 5);
    }

    #[test]
    fn short_records_are_rejected_not_panicked_on() {
        assert!(AuditEvent::from_bytes(&[0u8; 8], 0, 0).is_none());
    }

    #[test]
    fn unknown_kinds_and_decisions_are_preserved() {
        let raw = raw_event(1, 99, 98, 0);
        let e = AuditEvent::from_bytes(&raw, 0, 0).unwrap();
        assert_eq!(e.kind, EventKind::Unknown(99));
        assert_eq!(e.decision, EventDecision::Unknown(98));
        // An unrecognised decision must never be actioned as a kill.
        assert!(!e.decision.is_kill());
    }

    #[test]
    fn only_the_kill_decision_is_a_kill() {
        assert!(EventDecision::Kill.is_kill());
        for d in [
            EventDecision::Allow,
            EventDecision::Deny,
            EventDecision::Notify,
        ] {
            assert!(!d.is_kill());
        }
    }

    /// The property the whole module exists for: when the sink cannot keep
    /// up, the producer must lose events rather than block.
    #[test]
    fn a_full_channel_drops_instead_of_blocking() {
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        let dropped = Arc::new(AtomicU64::new(0));
        let mut sender = EventSender {
            tx,
            seq: 0,
            dropped: Arc::clone(&dropped),
            malformed: Arc::new(AtomicU64::new(0)),
        };

        // Nobody is reading. If `offer` blocked, this test would hang —
        // which is precisely the production failure it guards against.
        for _ in 0..100 {
            sender.offer(&raw_event(1, 0, 0, 0));
        }

        assert_eq!(dropped.load(Ordering::Relaxed), 96);
        assert_eq!(rx.try_iter().count(), 4);
    }

    #[test]
    fn drop_count_is_stamped_onto_the_next_delivered_event() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let dropped = Arc::new(AtomicU64::new(0));
        let mut sender = EventSender {
            tx,
            seq: 0,
            dropped: Arc::clone(&dropped),
            malformed: Arc::new(AtomicU64::new(0)),
        };

        sender.offer(&raw_event(1, 0, 0, 0)); // fills the channel
        sender.offer(&raw_event(2, 0, 0, 0)); // dropped
        sender.offer(&raw_event(3, 0, 0, 0)); // dropped

        let first = rx.recv().unwrap();
        assert_eq!(first.dropped_count, 0);

        sender.offer(&raw_event(4, 0, 0, 0)); // fits again
        let next = rx.recv().unwrap();
        // The sink learns, in band, that two records are missing between
        // these two events.
        assert_eq!(next.dropped_count, 2);
        assert_eq!(next.cgid, 4);
    }

    #[test]
    fn sequence_numbers_are_assigned_to_decoded_events_only() {
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        let malformed = Arc::new(AtomicU64::new(0));
        let mut sender = EventSender {
            tx,
            seq: 0,
            dropped: Arc::new(AtomicU64::new(0)),
            malformed: Arc::clone(&malformed),
        };

        sender.offer(&raw_event(1, 0, 0, 0));
        sender.offer(&[0u8; 4]); // malformed: must not consume a seq
        sender.offer(&raw_event(2, 0, 0, 0));

        let got: Vec<_> = rx.try_iter().collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].seq, 0);
        assert_eq!(got[1].seq, 1);
        assert_eq!(malformed.load(Ordering::Relaxed), 1);
    }
}
