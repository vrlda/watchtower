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

#[derive(Debug, Clone, PartialEq)]
pub struct TcpEntry {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
}

/// One mount entry from /proc/mounts (device, mount point, fstype).
#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub device: String,
    pub mount_point: String,
    pub fstype: String,
}

/// Parse /proc/mounts; keep only real (non-pseudo) filesystems.
pub fn parse_mounts(text: &str) -> Vec<Mount> {
    const PSEUDO: &[&str] = &[
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "cgroup",
        "cgroup2",
        "pstore",
        "securityfs",
        "debugfs",
        "tracefs",
        "bpf",
        "autofs",
        "mqueue",
        "hugetlbfs",
        "configfs",
        "fusectl",
        "binfmt_misc",
        "rpc_pipefs",
        "nsfs",
        "overlay",
    ];
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        if PSEUDO.contains(&parts[2]) {
            continue;
        }
        out.push(Mount {
            device: parts[0].to_string(),
            mount_point: parts[1].replace("\\040", " "),
            fstype: parts[2].to_string(),
        });
    }
    out
}

/// Decode the little-endian hex IPv4 from /proc/net/tcp.
/// "0100007F" → bytes [01 00 00 7F] → reversed → 127.0.0.1
pub fn decode_ipv4(hex: &str) -> String {
    let mut bytes = [0u8; 4];
    for (i, b) in bytes.iter_mut().enumerate() {
        if let Ok(v) = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
            *b = v;
        }
    }
    bytes.reverse();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Decode the 4 little-endian 32-bit words of the hex IPv6 from
/// /proc/net/tcp6. The kernel prints each network-order word as a LE u32,
/// so bytes within each 8-hex-char group are reversed. Rendered canonically
/// via std::net::Ipv6Addr (RFC 5952 compression, ::ffff:a.b.c.d form).
pub fn decode_ipv6(hex: &str) -> String {
    let mut bytes = [0u8; 16];
    for g in 0..4 {
        let chunk = &hex[g * 8..g * 8 + 8];
        for (i, c) in chunk.as_bytes().chunks(2).enumerate() {
            let byte = u8::from_str_radix(std::str::from_utf8(c).unwrap_or("00"), 16).unwrap_or(0);
            bytes[g * 4 + 3 - i] = byte;
        }
    }
    std::net::Ipv6Addr::from(bytes).to_string()
}

/// Parse a /proc/net/tcp or tcp6 file body into entries.
/// State hex: 0A = LISTEN, 01 = ESTABLISHED (the two we track).
pub fn parse_tcp_table(text: &str, v6: bool) -> Vec<TcpEntry> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (local_ip, local_port) = split_addr_port(fields[1]);
        let (remote_ip, remote_port) = split_addr_port(fields[2]);
        let state = match fields[3] {
            "0A" => "LISTEN",
            "01" => "ESTABLISHED",
            _ => continue,
        };
        out.push(TcpEntry {
            local_ip: if v6 {
                decode_ipv6(local_ip)
            } else {
                decode_ipv4(local_ip)
            },
            local_port,
            remote_ip: if v6 {
                decode_ipv6(remote_ip)
            } else {
                decode_ipv4(remote_ip)
            },
            remote_port,
            state: state.into(),
        });
    }
    out
}

/// "0100007F:1F90" → ("0100007F", 8080)
fn split_addr_port(s: &str) -> (&str, u16) {
    match s.rsplit_once(':') {
        Some((ip, port)) => (ip, u16::from_str_radix(port, 16).unwrap_or(0)),
        None => (s, 0),
    }
}

/// Parse a /proc/net/udp or udp6 file body. UDP has no listen/established
/// states — every row is kept as a (local ip, port) pair.
pub fn parse_udp_table(text: &str, v6: bool) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let (local_ip, local_port) = split_addr_port(fields[1]);
        let ip = if v6 {
            decode_ipv6(local_ip)
        } else {
            decode_ipv4(local_ip)
        };
        out.push((ip, local_port));
    }
    out
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

    /// /proc/sys/kernel/random/boot_id — changes on every boot.
    pub fn boot_id(&self) -> Result<String, String> {
        let text = self.read("sys/kernel/random/boot_id")?;
        Ok(text.trim().to_string())
    }

    /// Linux ephemeral port range start from /proc/sys/net/ipv4/ip_local_port_range
    /// (32768 on stock kernels). Sockets bound at/above this are source/backend
    /// sockets, not listeners worth flagging. Falls back to 32768.
    pub fn udp_ephemeral_min(&self) -> u16 {
        self.read("sys/net/ipv4/ip_local_port_range")
            .ok()
            .and_then(|s| s.split_whitespace().next().map(|v| v.to_string()))
            .and_then(|v| v.parse().ok())
            .unwrap_or(32768)
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

    pub fn tcp_entries(&self) -> Result<Vec<TcpEntry>, String> {
        let text = self.read("net/tcp")?;
        Ok(parse_tcp_table(&text, false))
    }

    pub fn tcp6_entries(&self) -> Result<Vec<TcpEntry>, String> {
        let text = self.read("net/tcp6")?;
        Ok(parse_tcp_table(&text, true))
    }

    pub fn udp_entries(&self) -> Result<Vec<(String, u16)>, String> {
        let text = self.read("net/udp")?;
        Ok(parse_udp_table(&text, false))
    }

    pub fn udp6_entries(&self) -> Result<Vec<(String, u16)>, String> {
        let text = self.read("net/udp6")?;
        Ok(parse_udp_table(&text, true))
    }

    pub fn mounts(&self) -> Result<Vec<Mount>, String> {
        let text = self.read("mounts")?;
        Ok(parse_mounts(&text))
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

    #[test]
    fn parses_tcp_listen_and_established() {
        let p = ProcFs::new(test_base());
        let entries = p.tcp_entries().unwrap();
        assert!(entries
            .iter()
            .any(|e| e.local_ip == "127.0.0.1" && e.local_port == 8080 && e.state == "LISTEN"));
        assert!(entries.iter().any(|e| e.remote_ip == "127.0.0.1"
            && e.remote_port == 8080
            && e.state == "ESTABLISHED"));
        assert!(entries
            .iter()
            .any(|e| e.remote_ip == "93.184.216.47" && e.remote_port == 443));
    }

    #[test]
    fn parses_tcp6_listen() {
        let p = ProcFs::new(test_base());
        let entries = p.tcp6_entries().unwrap();
        assert!(entries
            .iter()
            .any(|e| e.local_ip == "::" && e.local_port == 8080 && e.state == "LISTEN"));
        assert!(entries
            .iter()
            .any(|e| e.local_ip == "::" && e.local_port == 9000 && e.state == "ESTABLISHED"));
    }

    #[test]
    fn parses_udp_listens() {
        let p = ProcFs::new(test_base());
        let udp = p.udp_entries().unwrap();
        assert!(udp
            .iter()
            .any(|(ip, port)| ip == "0.0.0.0" && *port == 5353));
        assert!(udp
            .iter()
            .any(|(ip, port)| ip == "127.0.0.1" && *port == 53));
        let udp6 = p.udp6_entries().unwrap();
        assert!(udp6.iter().any(|(ip, port)| ip == "::" && *port == 5353));
    }

    #[test]
    fn parses_mounts_filtering_pseudo_fs() {
        let p = ProcFs::new(test_base());
        let mounts = p.mounts().unwrap();
        assert!(mounts.iter().any(|m| m.mount_point == "/"));
        assert!(mounts.iter().any(|m| m.mount_point == "/run"));
        assert!(!mounts.iter().any(|m| m.mount_point == "/sys"));
        assert!(!mounts.iter().any(|m| m.mount_point == "/proc"));
    }

    #[test]
    fn reads_boot_id() {
        let p = ProcFs::new(test_base());
        let id = p.boot_id().unwrap();
        assert!(id.contains('-'), "uuid-shaped: {}", id);
    }

    #[test]
    fn ephemeral_min_reads_kernel_range() {
        let p = ProcFs::new(test_base());
        assert_eq!(p.udp_ephemeral_min(), 32768);
    }

    #[test]
    fn ephemeral_min_falls_back_when_range_unreadable() {
        let p = ProcFs::new(PathBuf::from("/nonexistent"));
        assert_eq!(p.udp_ephemeral_min(), 32768);
    }

    #[test]
    fn decodes_ipv4_hex_little_endian() {
        assert_eq!(decode_ipv4("0100007F"), "127.0.0.1");
        assert_eq!(decode_ipv4("8F2D5A5D"), "93.90.45.143");
    }

    #[test]
    fn decodes_ipv6_groups_little_endian() {
        assert_eq!(decode_ipv6("00000000000000000000000000000000"), "::");
        assert_eq!(
            decode_ipv6("0000000000000000FFFF00000100007F"),
            "::ffff:127.0.0.1"
        );
    }

    #[test]
    fn decodes_ipv6_real_world_addresses() {
        // 2001:db8::1 (kernel LE-word format)
        assert_eq!(
            decode_ipv6("b80d0120000000000000000001000000"),
            "2001:db8::1"
        );
        // 2001:4860:4860::8888 (Google DNS)
        assert_eq!(
            decode_ipv6("60480120000060480000000088880000"),
            "2001:4860:4860::8888"
        );
        // fe80::1 (link-local); kernel word "000080FE" = LE u32 of bytes [FE 80 00 00]
        assert_eq!(decode_ipv6("000080fe000000000000000001000000"), "fe80::1");
    }
}
