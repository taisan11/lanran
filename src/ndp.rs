//! Passive IPv6 Neighbor Advertisement (NDP) collection.

use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::ndp::{NdpOptionTypes, NeighborAdvertPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::util::MacAddr;
use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

pub fn ndp_cli(args: &mut noargs::RawArgs) -> noargs::Result<bool> {
    if !noargs::cmd("ndp")
        .doc("IPv6 Neighbor Advertisementを受信専用で収集します")
        .take(args)
        .is_present()
    {
        return Ok(false);
    }

    let interface_name = noargs::arg("[interface]")
        .doc("待ち受けるネットワークインターフェース")
        .take(args);
    let timeout = noargs::opt("timeout")
        .doc("待ち受け時間を秒で指定します (1以上、デフォルト: 5)")
        .default("5")
        .take(args);
    if args.metadata().help_mode {
        return Ok(true);
    }

    let seconds = timeout
        .value()
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| noargs::Error::other(args, "--timeoutには1以上の秒数を指定してください"))?;
    let interfaces = datalink::interfaces();
    let requested_name = interface_name.present().map(|arg| arg.value().to_string());
    let interface = select_interface(&interfaces, requested_name.as_deref()).ok_or_else(|| {
        let name = requested_name.as_deref().unwrap_or("(自動選択)");
        noargs::Error::other(
            args,
            format!("IPv6対応のインターフェースが見つかりません: {name}"),
        )
    })?;

    // Periodically wake so a finite timeout can be honored.
    let config = Config {
        read_timeout: Some(Duration::from_millis(200)),
        ..Default::default()
    };
    let (_tx, mut rx) = match datalink::channel(interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(noargs::Error::other(args, "Ethernetチャンネルを開けません"));
        }
        Err(e) => {
            return Err(noargs::Error::other(
                args,
                format!(
                    "インターフェースを開けません: {e} (権限が必要な場合はsudoで実行してください)"
                ),
            ));
        }
    };

    let timeout_label = format!("{seconds}秒");
    println!(
        "{} でIPv6 Neighbor Advertisementを受信中 ({timeout_label})。送信は行いません。Ctrl-Cで終了。",
        interface.name
    );
    println!("{:<40} {:<19} Interface", "IPv6 Address", "MAC Address");
    println!("{}", "─".repeat(80));

    let start = Instant::now();
    let mut found = BTreeMap::<Ipv6Addr, MacAddr>::new();
    while start.elapsed() < Duration::from_secs(seconds) {
        if let Ok(frame) = rx.next()
            && let Some((address, mac)) = parse_neighbor_advertisement(frame)
            && found.insert(address, mac).is_none()
        {
            println!("{address:<40} {mac:<19} {}", interface.name);
        }
    }

    println!("\n{} IPv6 address(es) collected", found.len());
    Ok(true)
}

fn select_interface<'a>(
    interfaces: &'a [NetworkInterface],
    requested_name: Option<&str>,
) -> Option<&'a NetworkInterface> {
    if let Some(name) = requested_name {
        return interfaces.iter().find(|interface| {
            interface.name == name
                && interface.is_up()
                && interface.ips.iter().any(|ip| ip.ip().is_ipv6())
        });
    }

    interfaces.iter().find(|interface| {
        interface.is_up()
            && !interface.is_loopback()
            && interface.ips.iter().any(|ip| ip.ip().is_ipv6())
    })
}

fn parse_neighbor_advertisement(frame: &[u8]) -> Option<(Ipv6Addr, MacAddr)> {
    let ethernet = EthernetPacket::new(frame)?;
    if ethernet.get_ethertype() != EtherTypes::Ipv6 {
        return None;
    }

    let ipv6 = Ipv6Packet::new(ethernet.payload())?;
    if ipv6.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
        return None;
    }

    let advertisement = NeighborAdvertPacket::new(ipv6.payload())?;
    if advertisement.get_icmpv6_type() != Icmpv6Types::NeighborAdvert {
        return None;
    }

    let target_mac = advertisement
        .get_options()
        .into_iter()
        .find(|option| option.option_type == NdpOptionTypes::TargetLLAddr)
        .and_then(|option| {
            let data = option.data;
            (data.len() >= 6)
                .then(|| MacAddr::new(data[0], data[1], data[2], data[3], data[4], data[5]))
        })
        .unwrap_or_else(|| ethernet.get_source());

    Some((advertisement.get_target_addr(), target_mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_selection_respects_requested_interface() {
        let interfaces = datalink::interfaces();
        if let Some(interface) = interfaces.first() {
            assert_eq!(
                select_interface(&interfaces, Some(&interface.name))
                    .map(|selected| selected.name.as_str()),
                if interface.is_up() && interface.ips.iter().any(|ip| ip.ip().is_ipv6()) {
                    Some(interface.name.as_str())
                } else {
                    None
                }
            );
        }
    }
}
