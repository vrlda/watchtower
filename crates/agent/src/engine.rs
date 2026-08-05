use std::collections::{HashMap, VecDeque};

use wt_common::{AgentEvent, Config, EventKind, Evidence, Severity};

/// Rolling median baseline spike detector. A value is a spike when it exceeds
/// the median of the last `window` samples by `ratio`x.
pub struct SpikeDetector {
    samples: VecDeque<f64>,
    window: usize,
    ratio: f64,
}

impl SpikeDetector {
    pub fn new(window: usize, ratio: f64) -> Self {
        SpikeDetector {
            samples: VecDeque::with_capacity(window),
            window,
            ratio,
        }
    }

    pub fn push(&mut self, v: f64) {
        if self.samples.len() >= self.window {
            self.samples.pop_front();
        }
        self.samples.push_back(v);
    }

    fn median(&self) -> f64 {
        let mut v: Vec<f64> = self.samples.iter().copied().collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = v.len();
        if n == 0 {
            return 0.0;
        }
        if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2.0
        }
    }

    /// Needs at least 2 samples to establish a baseline.
    pub fn is_spike(&self, v: f64) -> bool {
        let m = self.median();
        self.samples.len() >= 2 && m > 0.0 && v >= m * self.ratio
    }
}

/// Suppress re-emission of the same (kind, key) within `window_secs`.
pub struct Deduper {
    window_secs: i64,
    last_emitted: HashMap<(EventKind, String), i64>,
}

impl Deduper {
    pub fn new(window_secs: i64) -> Self {
        Deduper {
            window_secs,
            last_emitted: HashMap::new(),
        }
    }

    pub fn should_emit(&mut self, kind: EventKind, key: &str, ts: i64) -> bool {
        let entry = self
            .last_emitted
            .entry((kind, key.to_string()))
            .or_insert(i64::MIN);
        if ts.saturating_sub(*entry) >= self.window_secs {
            *entry = ts;
            true
        } else {
            false
        }
    }
}

/// CPU usage state across polls: rolling baseline + spike event emission.
pub struct CpuState {
    host: String,
    total: u64,
    busy: u64,
    detector: SpikeDetector,
}

impl CpuState {
    pub fn new(window: usize, ratio: f64, host: &str) -> Self {
        CpuState {
            host: host.into(),
            total: 0,
            busy: 0,
            detector: SpikeDetector::new(window, ratio),
        }
    }

    /// Feed a fresh cpu usage percentage; emits a CpuSpike event when the
    /// current value deviates from the rolling median by the configured ratio.
    /// The poll `ts` (from run_once) is the single time source for the batch —
    /// all events in a batch share it. Note: id uniqueness relies on the
    /// Deduper suppressing a second CpuSpike for "cpu:usage" within its window,
    /// since two emits at the same ts would otherwise collide on `{host}-cpu-{ts}`.
    pub fn observe(&mut self, pct: f64, ts: i64) -> Vec<AgentEvent> {
        let mut evs = Vec::new();
        self.detector.push(pct);
        if self.detector.is_spike(pct) {
            evs.push(AgentEvent {
                id: format!("{}-cpu-{}", self.host, ts),
                ts,
                host_id: self.host.clone(),
                key: "cpu:usage".into(),
                kind: EventKind::CpuSpike,
                severity: Severity::Warning,
                summary: format!("CPU usage spiked to {:.0}%", pct),
                evidence: vec![Evidence {
                    ts,
                    source: "engine".into(),
                    detail: format!("CpuUsagePct={:.1}", pct),
                }],
            });
        }
        evs
    }
}

/// One detection pass: run all sensors against current state, apply dedup,
/// return events to ship. Called every poll interval and by `check`.
// arg grouping refactor deferred; 8 args accepted for now
#[allow(clippy::too_many_arguments)]
pub fn run_once(
    cfg: &Config,
    deduper: &mut Deduper,
    host_id: &str,
    ts: i64,
    procfs: &crate::procfs::ProcFs,
    sys: &dyn crate::cmd::CommandRunner,
    crash: &mut crate::sensors::systemd::CrashTracker,
    cpu: &mut CpuState,
) -> Vec<AgentEvent> {
    let mut evs = Vec::new();

    if let Ok(mem) = procfs.meminfo() {
        evs.extend(crate::sensors::resource::mem_events(mem, cfg, host_id, ts));
        evs.extend(crate::sensors::resource::swap_events(mem, cfg, host_id, ts));
    } else {
        eprintln!("sensor procfs.meminfo failed");
    }
    if let Ok(load) = procfs.load_one_min() {
        let ncpu = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        evs.extend(crate::sensors::resource::load_events(
            load, ncpu, cfg, host_id, ts,
        ));
    } else {
        eprintln!("sensor procfs.load_one_min failed");
    }
    if let Ok(errs) = procfs.netdev_errors() {
        evs.extend(crate::sensors::resource::netdev_events(&errs, host_id, ts));
    } else {
        eprintln!("sensor procfs.netdev_errors failed");
    }

    let (total, busy, pct) = crate::sensors::resource::cpu_usage_now(procfs, cpu.total, cpu.busy);
    cpu.total = total;
    cpu.busy = busy;
    evs.extend(cpu.observe(pct, ts));

    if let Ok(states) = crate::sensors::systemd::systemctl_list_units(sys) {
        for (unit, state) in states {
            crash.observe(&unit, state, (ts / 1000) as u64, host_id, &mut evs);
        }
    } else {
        eprintln!("sensor systemctl_list_units failed");
    }

    evs.retain(|e| deduper.should_emit(e.kind, &e.key, e.ts));
    evs
}

#[cfg(test)]
mod tests {
    use super::*;
    use wt_common::EventKind;

    #[test]
    fn spike_detector_flags_deviation_above_ratio() {
        let mut d = SpikeDetector::new(8, 2.0);
        for _ in 0..8 {
            d.push(100.0);
        }
        assert!(d.is_spike(300.0));
    }

    #[test]
    fn spike_detector_ignores_gradual_ramp() {
        let mut d = SpikeDetector::new(8, 2.0);
        let mut v = 100.0;
        for _ in 0..8 {
            d.push(v);
            v += 2.0;
        }
        assert!(!d.is_spike(v));
    }

    #[test]
    fn spike_detector_needs_baseline() {
        let mut d = SpikeDetector::new(8, 2.0);
        assert!(!d.is_spike(1000.0));
        d.push(1.0);
        assert!(!d.is_spike(1000.0));
    }

    #[test]
    fn deduper_suppresses_within_window() {
        let mut d = Deduper::new(300);
        assert!(d.should_emit(EventKind::LoadHigh, "load:1m", 1000));
        assert!(!d.should_emit(EventKind::LoadHigh, "load:1m", 1100));
        assert!(d.should_emit(EventKind::LoadHigh, "load:5m", 1100));
    }

    #[test]
    fn deduper_allows_after_window_expires() {
        let mut d = Deduper::new(300);
        assert!(d.should_emit(EventKind::DiskHigh, "mount:/", 1000));
        assert!(d.should_emit(EventKind::DiskHigh, "mount:/", 1301));
    }

    #[test]
    fn cpu_spike_state_machine_emits_event_after_sudden_rise() {
        let mut s = CpuState::new(8, 2.0, "h-1");
        let mut evs = Vec::new();
        for _ in 0..8 {
            evs.extend(s.observe(5.0, 1000));
        }
        assert!(evs.is_empty());
        let out = s.observe(90.0, 1000);
        assert_eq!(out[0].kind, EventKind::CpuSpike);
        assert_eq!(
            out[0].ts, 1000,
            "event must use the poll ts, not wall clock"
        );
        assert_eq!(out[0].id, "h-1-cpu-1000");
    }

    #[test]
    fn cpu_spike_ignores_gradual_increase() {
        let mut s = CpuState::new(8, 2.0, "h-1");
        let mut v = 5.0;
        let mut evs = Vec::new();
        for _ in 0..40 {
            v += 0.5;
            evs.extend(s.observe(v, 1000));
        }
        assert!(evs.is_empty());
    }

    #[test]
    fn run_once_wires_sensors_and_emits_events() {
        let cfg = Config::default();
        let mut deduper = Deduper::new(300);
        let mut cpu = CpuState::new(20, 2.5, "h-1");
        let mut crash = crate::sensors::systemd::CrashTracker::new(120);
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let runner = FakeSys;
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1000,
            &p,
            &runner,
            &mut crash,
            &mut cpu,
        );
        assert!(evs.iter().any(|e| e.kind == EventKind::SwapHigh));
        assert_eq!(
            evs.iter()
                .filter(|e| e.kind == EventKind::NetDevErrors)
                .count(),
            2
        );
        assert!(evs.iter().all(|e| e.host_id == "h-1"));
    }

    struct FakeSys;

    impl crate::cmd::CommandRunner for FakeSys {
        fn run(&self, _args: &[&str]) -> Result<String, String> {
            Ok("".to_string())
        }
    }
}
