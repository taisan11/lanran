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
use std::sync::{Arc, Mutex};
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
    let results = Arc::new(Mutex::new(HashMap::new()));
    let mut handles = Vec::new();

    for &ip in ips {
        let results = Arc::clone(&results);
        let handle = thread::spawn(move || {
            if let Ok(name) = lookup_addr(&IpAddr::V4(ip)) {
                // IPそのものが返ってきた場合は無視
                if name != ip.to_string() {
                    let mut map = results.lock().unwrap();
                    map.insert(ip, name);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().ok();
    }

    Arc::try_unwrap(results).unwrap().into_inner().unwrap()
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

    // mDNSは "_services._dns-sd._udp.local." をブラウズするのが標準的だが、
    // IPを直接知りたいので "_http._tcp.local." や全サービスを見てみる。
    // mdns-sd では browse でホスト情報（アドレスを含む）が得られる。
    let receiver = match mdns.browse("_services._dns-sd._udp.local.") {
        Ok(r) => r,
        Err(_) => return result,
    };

    let target_set: std::collections::HashSet<Ipv4Addr> = target_ips.iter().copied().collect();
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() >= timeout { break; }

        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                for addr in info.get_addresses_v4() {
                    if target_set.contains(&addr) {
                        // ホスト名から末尾のドットを除去
                        let hostname = info.get_hostname().trim_end_matches('.').to_string();
                        result.insert(addr, hostname);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    mdns.shutdown().ok();
    result
}
