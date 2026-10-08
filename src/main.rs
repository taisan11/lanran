mod discovery;
mod ndp;
mod oui;
mod resolve;
mod ssdp;

use indicatif::ProgressBar;
use ipnetwork::IpNetwork;
use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> noargs::Result<()> {
    let mut args = noargs::raw_args();
    args.metadata_mut().app_name = env!("CARGO_PKG_NAME");
    args.metadata_mut().app_description = env!("CARGO_PKG_DESCRIPTION");

    if noargs::VERSION_FLAG.take(&mut args).is_present() {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    noargs::HELP_FLAG.take_help(&mut args);

    let _ = scan_cli(&mut args)?
        || list_interfaces_cli(&mut args)?
        || discovery::mdns_cli(&mut args)?
        || discovery::dnssd_cli(&mut args)?
        || ssdp::ssdp_cli(&mut args)?
        || ssdp::upnp_cli(&mut args)?
        || ndp::ndp_cli(&mut args)?;
    if let Some(help) = args.finish()? {
        print!("{help}");
    }

    Ok(())
}

fn list_interfaces_cli(args: &mut noargs::RawArgs) -> noargs::Result<bool> {
    if !noargs::cmd("interfaces")
        .doc("利用可能なネットワークインターフェースを一覧表示します")
        .take(args)
        .is_present()
    {
        return Ok(false);
    }

    let interfaces = datalink::interfaces();
    println!("利用可能なネットワークインターフェース:");
    for iface in interfaces {
        println!("  {} - {:?}", iface.name, iface.ips);
    }
    Ok(true)
}

fn scan_cli(args: &mut noargs::RawArgs) -> noargs::Result<bool> {
    if !noargs::cmd("scan")
        .doc("LAN内のホストをスキャンし、IPアドレス、MACアドレス、ベンダー情報、ホスト名を表示します")
        .take(args)
        .is_present()
    {
        return Ok(false);
    }

    let cidr_str = noargs::arg("<CIDR>")
        .doc("スキャン対象のIPレンジをCIDR形式で指定します (例: 192.168.1.0/24)")
        .example("192.168.1.0/24")
        .take(args);
    let iface_name = noargs::opt("interface")
        .ty("NAME")
        .doc("スキャンに使用するネットワークインターフェースを指定します (例: en0)")
        .take(args);
    let output_file = noargs::opt("out")
        .ty("FILE")
        .doc("結果をCSVファイルに出力します")
        .take(args);

    if args.metadata().help_mode {
        return Ok(true);
    }

    let network: IpNetwork = cidr_str.value().parse().unwrap_or_else(|_| {
        eprintln!("エラー: '{}' は有効なCIDRではありません", cidr_str.value());
        std::process::exit(1);
    });
    let ipv4_network = match network {
        IpNetwork::V4(n) => n,
        _ => {
            eprintln!("エラー: IPv4のCIDRを指定してください");
            std::process::exit(1);
        }
    };
    const MAX_SCAN_HOSTS: u32 = 65_536;
    if ipv4_network.size() > MAX_SCAN_HOSTS {
        eprintln!("エラー: スキャン範囲が大きすぎます (上限: {MAX_SCAN_HOSTS}アドレス)");
        std::process::exit(1);
    }

    let interfaces = datalink::interfaces();
    let iface_name_opt = iface_name.present().map(|arg| arg.value().to_string());
    let iface = find_interface(&interfaces, &iface_name_opt, &ipv4_network).unwrap_or_else(|| {
        eprintln!("エラー: 適切なインターフェースが見つかりません");
        eprintln!("指定CIDR全体が、稼働中の非loopbackインターフェースのIPv4ネットワーク内にある必要があります。");
        for i in &interfaces {
            eprintln!("  {} - {:?}", i.name, i.ips);
        }
        std::process::exit(1);
    });

    let src_mac = iface.mac.unwrap_or_else(|| {
        eprintln!("エラー: MACアドレスが取得できません");
        std::process::exit(1);
    });
    let src_ip = iface
        .ips
        .iter()
        .find_map(|ip| {
            if let IpNetwork::V4(n) = ip {
                (n.contains(ipv4_network.network()) && n.contains(ipv4_network.broadcast()))
                    .then_some(n.ip())
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            eprintln!("エラー: 指定ネットワークに対応するIPv4アドレスがありません");
            std::process::exit(1);
        });

    // OUIデータベースをロード（キャッシュから or ダウンロード）
    println!("OUIデータベースを準備中...");
    let oui_db = oui::OuiDb::load();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  ARP Scanner with Vendor & Hostname Resolution");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "  インターフェース : {}  |  IP: {}  |  MAC: {}",
        iface.name, src_ip, src_mac
    );
    println!(
        "  スキャン対象    : {}  ({} ホスト)",
        ipv4_network,
        ipv4_network.size()
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // ARPスキャン実行
    let results: Arc<Mutex<HashMap<Ipv4Addr, MacAddr>>> = Arc::new(Mutex::new(HashMap::new()));

    let config = Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(iface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("エラー: Ethernetチャンネルが開けません");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("エラー: {}", e);
            eprintln!("ヒント: sudo で実行してください");
            std::process::exit(1);
        }
    };

    // 受信スレッド
    let results_rx = Arc::clone(&results);
    let stop_rx = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop_rx);
    let recv_thread = thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match rx.next() {
                Ok(frame) => {
                    if let Some(eth) = EthernetPacket::new(frame)
                        && eth.get_ethertype() == EtherTypes::Arp
                        && let Some(arp) = ArpPacket::new(eth.payload())
                        && arp.get_operation() == ArpOperations::Reply
                        && ipv4_network.contains(arp.get_sender_proto_addr())
                    {
                        let mut map = results_rx.lock().unwrap();
                        map.insert(arp.get_sender_proto_addr(), arp.get_sender_hw_addr());
                    }
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    });

    // 送信と受信のプログレス
    println!("ARPスキャン中...");
    let total = ipv4_network.size() as u64 + 50; // 送信 + 受信待機（50単位）
    let pb = ProgressBar::new(total);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );

    let mut frame_buf = [0u8; 42];
    for target_ip in ipv4_network.iter() {
        build_arp_request(&mut frame_buf, src_mac, src_ip, target_ip);
        match tx.send_to(&frame_buf, None) {
            Some(Err(error)) => {
                eprintln!("ARP要求を {} に送信できません: {error}", target_ip);
            }
            None => eprintln!("ARP要求を {} に送信できませんでした", target_ip),
            Some(Ok(())) => {}
        }
        pb.inc(1);
        thread::sleep(Duration::from_micros(100));
    }

    // 受信待機中のプログレス表示
    for _ in 0..50 {
        thread::sleep(Duration::from_millis(100));
        pb.inc(1);
    }
    pb.finish_and_clear();
    stop_rx.store(true, Ordering::Relaxed);
    recv_thread.join().unwrap();

    let map = results.lock().unwrap();
    if map.is_empty() {
        println!("応答なし: ホストが見つかりませんでした");
        return Ok(true);
    }

    let mut entries: Vec<(Ipv4Addr, MacAddr)> = map.iter().map(|(k, v)| (*k, *v)).collect();
    entries.sort_by_key(|(ip, _)| *ip);

    // mDNSスキャン（別途）
    println!("ホスト名を解決中（mDNS / PTR）...\n");
    let ips: Vec<Ipv4Addr> = entries.iter().map(|(ip, _)| *ip).collect();
    let hostnames = resolve::resolve_all(&ips);

    // 結果表示
    println!(
        "{:<17} {:<19} {:<28} Hostname",
        "IP Address", "MAC Address", "Vendor"
    );
    println!("{}", "─".repeat(90));

    let mut output_records = Vec::new();
    for (ip, mac) in &entries {
        let vendor = oui_db.lookup(mac).unwrap_or_else(|| "Unknown".to_string());
        let hostname = hostnames
            .get(ip)
            .cloned()
            .unwrap_or_else(|| "-".to_string());
        // vendorが長い場合は切り詰め
        let vendor_short = if vendor.len() > 26 {
            format!("{}…", &vendor[..25])
        } else {
            vendor.clone()
        };
        println!("{:<17} {:<19} {:<28} {}", ip, mac, vendor_short, hostname);

        output_records.push((ip.to_string(), mac.to_string(), vendor, hostname));
    }

    println!("{}", "─".repeat(90));
    println!("{} ホスト発見\n", entries.len());

    // CSV出力（--outオプションが指定された場合）
    if let Some(out) = output_file.present() {
        let out_path = out.value();
        match write_csv(out_path, &output_records) {
            Ok(_) => println!("CSV出力: {}", out_path),
            Err(e) => eprintln!("CSV出力エラー: {}", e),
        }
    }

    Ok(true)
}

fn write_csv(path: &str, records: &[(String, String, String, String)]) -> csv::Result<()> {
    let mut writer = csv::Writer::from_path(path)?;
    writer.write_record(["IP Address", "MAC Address", "Vendor", "Hostname"])?;
    for (ip, mac, vendor, hostname) in records {
        writer.write_record([ip, mac, vendor, hostname])?;
    }
    writer.flush()?;
    Ok(())
}

fn build_arp_request(buf: &mut [u8; 42], src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buf[14..]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }
}

fn find_interface<'a>(
    interfaces: &'a [NetworkInterface],
    name: &Option<String>,
    network: &ipnetwork::Ipv4Network,
) -> Option<&'a NetworkInterface> {
    interfaces.iter().find(|iface| {
        name.as_ref().is_none_or(|name| iface.name == *name)
            && iface.is_up()
            && !iface.is_loopback()
            && iface.mac.is_some()
            && iface.ips.iter().any(|ip| match ip {
                IpNetwork::V4(interface_network) => {
                    network_fits_interface(network, interface_network)
                }
                IpNetwork::V6(_) => false,
            })
    })
}

fn network_fits_interface(
    requested: &ipnetwork::Ipv4Network,
    interface: &ipnetwork::Ipv4Network,
) -> bool {
    interface.contains(requested.network()) && interface.contains(requested.broadcast())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_writer_escapes_delimiters_and_quotes() {
        let path = std::env::temp_dir().join(format!("lanran-{}.csv", std::process::id()));
        let rows = vec![(
            "192.0.2.1".into(),
            "00:11:22:33:44:55".into(),
            "Vendor, Inc.".into(),
            "host\"name".into(),
        )];
        write_csv(path.to_str().unwrap(), &rows).unwrap();
        let mut reader = csv::Reader::from_path(&path).unwrap();
        let record = reader.records().next().unwrap().unwrap();
        assert_eq!(&record[2], "Vendor, Inc.");
        assert_eq!(&record[3], "host\"name");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn requested_network_must_fit_inside_interface_network() {
        let interface: ipnetwork::Ipv4Network = "192.168.1.10/24".parse().unwrap();
        let subnet: ipnetwork::Ipv4Network = "192.168.1.128/25".parse().unwrap();
        let outside: ipnetwork::Ipv4Network = "192.168.2.0/24".parse().unwrap();
        assert!(network_fits_interface(&subnet, &interface));
        assert!(!network_fits_interface(&outside, &interface));
    }
}
