//! mDNS / DNS-SD discovery commands.

use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

const DNS_SD_ENUMERATION: &str = "_services._dns-sd._udp.local.";

/// Discover `.local` hostnames exposed by DNS-SD services on the local network.
pub fn mdns_cli(args: &mut noargs::RawArgs) -> noargs::Result<bool> {
    if !noargs::cmd("mdns")
        .doc("mDNSでDNS-SDサービスを探索し、応答した.localホスト名とIPアドレスを表示します")
        .take(args)
        .is_present()
    {
        return Ok(false);
    }

    let timeout = noargs::opt("timeout")
        .doc("探索時間を秒で指定します (1以上、デフォルト: 5)")
        .default("5")
        .take(args);
    if args.metadata().help_mode {
        return Ok(true);
    }

    let seconds = parse_timeout(timeout.value())
        .ok_or_else(|| noargs::Error::other(args, "--timeoutには1以上の秒数を指定してください"))?;
    let timeout_label = format!("{seconds}秒");
    println!("mDNSの.localホストを探索中 ({timeout_label})...");
    let daemon = ServiceDaemon::new()
        .map_err(|e| noargs::Error::other(args, format!("mDNS初期化失敗: {e}")))?;
    let enumeration = daemon
        .browse(DNS_SD_ENUMERATION)
        .map_err(|e| noargs::Error::other(args, format!("mDNS探索開始失敗: {e}")))?;

    let mut receivers = Vec::new();
    let mut hosts = std::collections::BTreeMap::<String, BTreeSet<String>>::new();
    let mut service_types = BTreeSet::new();
    let start = Instant::now();
    while should_continue(start, seconds) {
        if let Ok(ServiceEvent::ServiceFound(service_type, _)) = enumeration.try_recv() {
            let service_type = normalize_service_type(&service_type);
            if service_types.insert(service_type.clone()) {
                match daemon.browse(&service_type) {
                    Ok(receiver) => receivers.push(receiver),
                    Err(e) => eprintln!("探索開始失敗 ({service_type}): {e}"),
                }
            }
        }
        for receiver in &receivers {
            if let Ok(ServiceEvent::ServiceResolved(info)) = receiver.try_recv() {
                add_host(&info, &mut hosts);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = daemon.shutdown();

    if hosts.is_empty() {
        println!(".localホストは見つかりませんでした");
    } else {
        println!("{:<32} Addresses", "Hostname");
        println!("{}", "─".repeat(80));
        for (hostname, addresses) in &hosts {
            println!(
                "{hostname:<32} {}",
                addresses.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        println!("\n{} host(s) found", hosts.len());
    }
    Ok(true)
}

/// Browse and resolve instances of a DNS-SD service type.
pub fn dnssd_cli(args: &mut noargs::RawArgs) -> noargs::Result<bool> {
    if !noargs::cmd("dnssd")
        .doc("指定したDNS-SDサービス種別のインスタンスを探索します")
        .take(args)
        .is_present()
    {
        return Ok(false);
    }

    let service_type = noargs::arg("[service-type]")
        .doc("探索するサービス種別 (例: _http._tcp.local.、全種別は all)")
        .default("_http._tcp.local.")
        .take(args);
    let timeout = noargs::opt("timeout")
        .doc("探索時間を秒で指定します (1以上、デフォルト: 5)")
        .default("5")
        .take(args);
    if args.metadata().help_mode {
        return Ok(true);
    }

    let seconds = parse_timeout(timeout.value())
        .ok_or_else(|| noargs::Error::other(args, "--timeoutには1以上の秒数を指定してください"))?;
    let requested_type = service_type.value().to_string();
    let daemon = ServiceDaemon::new()
        .map_err(|e| noargs::Error::other(args, format!("mDNS初期化失敗: {e}")))?;
    if requested_type.eq_ignore_ascii_case("all") {
        println!("サービス種別を列挙しながら探索中 ({seconds}秒)...");
        let enumeration = daemon
            .browse(DNS_SD_ENUMERATION)
            .map_err(|e| noargs::Error::other(args, format!("mDNS探索開始失敗: {e}")))?;
        let start = Instant::now();
        let mut found_types = BTreeSet::new();
        let mut receivers = Vec::new();
        let mut instances = std::collections::BTreeMap::new();
        while should_continue(start, seconds) {
            if let Ok(ServiceEvent::ServiceFound(service_type, _)) = enumeration.try_recv() {
                let service_type = normalize_service_type(&service_type);
                if found_types.insert(service_type.clone()) {
                    match daemon.browse(&service_type) {
                        Ok(receiver) => receivers.push(receiver),
                        Err(e) => eprintln!("DNS-SD探索開始失敗 ({service_type}): {e}"),
                    }
                }
            }
            for receiver in &receivers {
                if let Ok(event) = receiver.try_recv() {
                    update_instances(event, &mut instances);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = daemon.shutdown();
        if instances.is_empty() {
            println!("サービスインスタンスは見つかりませんでした");
        } else {
            println!("{:<42} {:<28} {:<7} Addresses", "Instance", "Host", "Port");
            println!("{}", "─".repeat(110));
            for (name, (host, port, addresses)) in &instances {
                println!("{name:<42} {host:<28} {port:<7} {addresses}");
            }
            println!("\n{} instance(s) found", instances.len());
        }
        return Ok(true);
    }

    let service_types = BTreeSet::from([normalize_service_type(&requested_type)]);
    println!(
        "DNS-SD探索中: {} ({}秒)...",
        service_types.first().unwrap(),
        seconds
    );
    let mut receivers = Vec::new();
    for service_type in &service_types {
        let receiver = daemon.browse(service_type).map_err(|e| {
            noargs::Error::other(args, format!("DNS-SD探索開始失敗 ({service_type}): {e}"))
        })?;
        receivers.push(receiver);
    }

    let start = Instant::now();
    let mut instances = std::collections::BTreeMap::new();
    while should_continue(start, seconds) {
        let mut received = false;
        for receiver in &receivers {
            if let Ok(event) = receiver.try_recv() {
                received = true;
                update_instances(event, &mut instances);
            }
        }
        if !received {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let _ = daemon.shutdown();

    if instances.is_empty() {
        println!("サービスインスタンスは見つかりませんでした");
    } else {
        println!("{:<42} {:<28} {:<7} Addresses", "Instance", "Host", "Port");
        println!("{}", "─".repeat(110));
        for (name, (host, port, addresses)) in &instances {
            println!("{name:<42} {host:<28} {port:<7} {addresses}");
        }
        println!("\n{} instance(s) found", instances.len());
    }
    Ok(true)
}

fn update_instances(
    event: ServiceEvent,
    instances: &mut std::collections::BTreeMap<String, (String, u16, String)>,
) {
    match event {
        ServiceEvent::ServiceResolved(info) => {
            let name = info.get_fullname().to_string();
            let hostname = info.get_hostname().trim_end_matches('.').to_string();
            let port = info.get_port();
            let addresses = info
                .get_addresses()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            instances.insert(name, (hostname, port, addresses));
        }
        ServiceEvent::ServiceRemoved(_, fullname) => {
            instances.remove(&fullname);
        }
        _ => {}
    }
}

fn add_host(
    info: &mdns_sd::ResolvedService,
    hosts: &mut std::collections::BTreeMap<String, BTreeSet<String>>,
) -> Vec<(String, String)> {
    let hostname = info.get_hostname().trim_end_matches('.').to_string();
    let addresses = hosts.entry(hostname.clone()).or_default();
    info.get_addresses()
        .iter()
        .map(ToString::to_string)
        .filter_map(|address| {
            if addresses.insert(address.clone()) {
                Some((hostname.clone(), address))
            } else {
                None
            }
        })
        .collect()
}

fn should_continue(start: Instant, seconds: u64) -> bool {
    start.elapsed() < Duration::from_secs(seconds)
}

fn parse_timeout(value: &str) -> Option<u64> {
    value.parse::<u64>().ok().filter(|seconds| *seconds > 0)
}

fn normalize_service_type(service_type: &str) -> String {
    if service_type.ends_with('.') {
        service_type.to_string()
    } else {
        format!("{service_type}.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_accepts_only_unsigned_seconds() {
        assert_eq!(parse_timeout("0"), None);
        assert_eq!(parse_timeout("15"), Some(15));
        assert_eq!(parse_timeout("-1"), None);
        assert_eq!(parse_timeout("abc"), None);
    }

    #[test]
    fn service_type_has_exactly_one_trailing_dot() {
        assert_eq!(
            normalize_service_type("_http._tcp.local"),
            "_http._tcp.local."
        );
        assert_eq!(
            normalize_service_type("_http._tcp.local."),
            "_http._tcp.local."
        );
    }
}
