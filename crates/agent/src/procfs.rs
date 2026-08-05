use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub struct ProcFs {
    base: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct MemInfo {
    pub mem_used_pct: f64,
    pub swap_used_pct: f64,
}

pub struct NetDevErrors {
    pub rx: u64,
    pub tx: u64,
}

impl ProcFs {
    pub fn new(base: PathBuf) -> Self {
        ProcFs { base }
    }

    fn read(&self, rel: &str) -> Result<String, String> {
        fs::read_to_string(self.base.join(rel)).map_err(|e| e.to_string())
    }

    pub fn cpu_ticks(&self) -> Result<(u64, u64), String> {
        let text = self.read("stat")?;
        let line = text.lines().next().ok_or("empty stat")?;
        let mut fields = line.split_whitespace();
        fields.next(); // "cpu"
        let nums: Vec<u64> = fields.filter_map(|f| f.parse::<u64>().ok()).collect();
        let total: u64 = nums.iter().sum();
        let idle = nums.get(3).copied().unwrap_or(0);
        Ok((total, idle))
    }

    pub fn meminfo(&self) -> Result<MemInfo, String> {
        let text = self.read("meminfo")?;
        let mut kv = HashMap::new();
        for line in text.lines() {
            let mut it = line.split_whitespace();
            if let (Some(k), Some(v)) = (it.next(), it.next()) {
                if let Ok(num) = v.parse::<u64>() {
                    kv.insert(k.trim_end_matches(':').to_string(), num);
                }
            }
        }
        let total = *kv.get("MemTotal").unwrap_or(&0) as f64;
        let avail = *kv.get("MemAvailable").unwrap_or(&0) as f64;
        let swap_total = *kv.get("SwapTotal").unwrap_or(&0) as f64;
        let swap_free = *kv.get("SwapFree").unwrap_or(&0) as f64;
        Ok(MemInfo {
            mem_used_pct: if total > 0.0 {
                (total - avail) / total * 100.0
            } else {
                0.0
            },
            swap_used_pct: if swap_total > 0.0 {
                (swap_total - swap_free) / swap_total * 100.0
            } else {
                0.0
            },
        })
    }

    pub fn load_one_min(&self) -> Result<f64, String> {
        let text = self.read("loadavg")?;
        let field = text.split_whitespace().next().ok_or("empty loadavg")?;
        field.parse::<f64>().map_err(|e| e.to_string())
    }

    pub fn uptime_secs(&self) -> Result<f64, String> {
        let text = self.read("uptime")?;
        let field = text.split_whitespace().next().ok_or("empty uptime")?;
        field.parse::<f64>().map_err(|e| e.to_string())
    }

    pub fn netdev_errors(&self) -> Result<HashMap<String, NetDevErrors>, String> {
        let text = self.read("net/dev")?;
        let mut out = HashMap::new();
        for line in text.lines().skip(2) {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            let name = parts[0].trim().to_string();
            let vals: Vec<u64> = parts[1]
                .split_whitespace()
                .filter_map(|f| f.parse::<u64>().ok())
                .collect();
            if vals.len() >= 16 {
                out.insert(
                    name,
                    NetDevErrors {
                        rx: vals[2],
                        tx: vals[10],
                    },
                );
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_base() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn parses_meminfo_percentages() {
        let p = ProcFs::new(test_base());
        let m = p.meminfo().unwrap();
        assert_eq!(m.mem_used_pct.round(), 75.0);
        assert_eq!(m.swap_used_pct.round(), 50.0);
    }

    #[test]
    fn parses_loadavg_first_field() {
        let p = ProcFs::new(test_base());
        assert_eq!(p.load_one_min().unwrap(), 2.5);
    }

    #[test]
    fn parses_uptime_seconds() {
        let p = ProcFs::new(test_base());
        assert_eq!(p.uptime_secs().unwrap(), 3600.0);
    }

    #[test]
    fn parses_netdev_errors() {
        let p = ProcFs::new(test_base());
        let errs = p.netdev_errors().unwrap();
        assert_eq!(errs[&"eth0".to_string()].tx, 3);
        assert_eq!(errs[&"eth1".to_string()].rx, 7);
        assert_eq!(errs[&"lo".to_string()].tx, 0);
    }
}
