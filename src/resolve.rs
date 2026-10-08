//! ホスト名解決モジュール
//!
//! 2つの方法でホスト名を取得する:
//!
//! 1. 逆引きDNS (PTR レコード)
//!    - ルーターが DNS を管理している環境で有効
//!    - 例: 192.168.1.1 → router.local
//!
//! 2. mDNS (Multicast DNS / Bonjour)
//!    - Apple製品、Linux (avahi)、スマートスピーカーなどが対応
//!    - .local ドメインで名前を叫ぶプロトコル
//!    - 例: MacBookPro.local, raspberrypi.local

use dns_lookup::lookup_addr;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::Duration;

/// IP アドレスのリストに対してホスト名を解決して返す
pub fn resolve_all(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
    let mut result: HashMap<Ipv4Addr, String> = HashMap::new();

    // 1. 逆引きDNS（全IPに対して並列実行）
    let ptr_results = resolve_ptr_parallel(ips);
    result.extend(ptr_results);

    // 2. mDNS（同一セグメントのデバイスを拾う）
    let mdns_results = resolve_mdns(ips, Duration::from_secs(2));
    // mDNSの結果でPTRを上書き（より信頼性が高い場合が多い）
    for (ip, name) in mdns_results {
        result.insert(ip, name);
    }

    result
}

/// PTR レコードによる逆引きDNS（並列）
fn resolve_ptr_parallel(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
    const WORKERS: usize = 16;
    let next = AtomicUsize::new(0);
    let results = Mutex::new(HashMap::new());
    let workers = ips.len().min(WORKERS);

    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&ip) = ips.get(index) else { break };
                    if let Ok(name) = lookup_addr(&IpAddr::V4(ip))
                        && name != ip.to_string()
                    {
                        results.lock().unwrap().insert(ip, name);
                    }
                }
            });
        }
    });

    results.into_inner().unwrap()
}

/// mDNS によるホスト名解決
///
/// "_services._dns-sd._udp.local." をブラウズして
/// 各サービスのホスト名（xxx.local）を集める
fn resolve_mdns(target_ips: &[Ipv4Addr], timeout: Duration) -> HashMap<Ipv4Addr, String> {
    let mut result = HashMap::new();

    let mdns = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  mDNS初期化失敗: {} (スキップ)", e);
            return result;
        }
    };

    // サービス種別を先に列挙し、その後各種別をbrowseしてアドレスを解決する。
    let enumeration = match mdns.browse("_services._dns-sd._udp.local.") {
        Ok(r) => r,
        Err(_) => return result,
    };
    let start = std::time::Instant::now();
    let enumeration_timeout = timeout / 2;
    let mut service_types = std::collections::BTreeSet::new();
    while start.elapsed() < enumeration_timeout {
        if let Ok(ServiceEvent::ServiceFound(service_type, _)) =
            enumeration.recv_timeout(Duration::from_millis(100))
        {
            service_types.insert(if service_type.ends_with('.') {
                service_type
            } else {
                format!("{service_type}.")
            });
        }
    }
    let _ = mdns.stop_browse("_services._dns-sd._udp.local.");
    let receivers: Vec<_> = service_types
        .iter()
        .filter_map(|service_type| mdns.browse(service_type).ok())
        .collect();
    let target_set: std::collections::HashSet<Ipv4Addr> = target_ips.iter().copied().collect();
    let resolve_timeout = timeout.saturating_sub(start.elapsed());
    let resolve_start = std::time::Instant::now();

    while resolve_start.elapsed() < resolve_timeout {
        for receiver in &receivers {
            if let Ok(ServiceEvent::ServiceResolved(info)) = receiver.try_recv() {
                for addr in info.get_addresses_v4() {
                    if target_set.contains(&addr) {
                        let hostname = info.get_hostname().trim_end_matches('.').to_string();
                        result.insert(addr, hostname);
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    mdns.shutdown().ok();
    result
}
