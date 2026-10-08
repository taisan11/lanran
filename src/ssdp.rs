//! SSDP and UPnP device discovery.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const SSDP_ADDRESS: &str = "239.255.255.250:1900";
const MAX_DESCRIPTION_SIZE: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
struct SsdpDevice {
    address: Ipv4Addr,
    st: String,
    usn: String,
    server: String,
    location: String,
}

pub fn ssdp_cli(args: &mut noargs::RawArgs) -> noargs::Result<bool> {
    if !noargs::cmd("ssdp")
        .doc("SSDPでローカルネットワーク上のデバイスを探索します")
        .take(args)
        .is_present()
    {
        return Ok(false);
    }

    let search_target = noargs::arg("[search-target]")
        .doc("SSDP検索対象 (デフォルト: ssdp:all)")
        .default("ssdp:all")
        .take(args);
    let timeout = noargs::opt("timeout")
        .doc("応答の待ち時間を秒で指定します (1以上、デフォルト: 3)")
        .default("3")
        .take(args);
    if args.metadata().help_mode {
        return Ok(true);
    }

    let timeout = parse_timeout(timeout.value(), args)?;
    let devices = discover(search_target.value(), timeout, args)?;
    print_devices(&devices);
    Ok(true)
}

pub fn upnp_cli(args: &mut noargs::RawArgs) -> noargs::Result<bool> {
    if !noargs::cmd("upnp")
        .doc("UPnP root deviceを探索し、デバイス記述を表示します")
        .take(args)
        .is_present()
    {
        return Ok(false);
    }

    let timeout = noargs::opt("timeout")
        .doc("応答の待ち時間を秒で指定します (1以上、デフォルト: 3)")
        .default("3")
        .take(args);
    if args.metadata().help_mode {
        return Ok(true);
    }

    let timeout = parse_timeout(timeout.value(), args)?;
    let devices = discover("upnp:rootdevice", timeout, args)?;
    if devices.is_empty() {
        println!("UPnPデバイスは見つかりませんでした");
        return Ok(true);
    }

    println!(
        "{:<16} {:<28} {:<24} {:<24} LOCATION",
        "Address", "Friendly Name", "Manufacturer", "Model"
    );
    println!("{}", "─".repeat(130));
    for device in &devices {
        let description = fetch_description(
            &device.location,
            device.address,
            Duration::from_secs(timeout),
        );
        let friendly_name = description
            .as_deref()
            .and_then(|xml| xml_tag(xml, "friendlyName"))
            .unwrap_or_else(|| "-".to_string());
        let manufacturer = description
            .as_deref()
            .and_then(|xml| xml_tag(xml, "manufacturer"))
            .unwrap_or_else(|| "-".to_string());
        let model = description
            .as_deref()
            .and_then(|xml| xml_tag(xml, "modelName"))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<16} {:<28} {:<24} {:<24} {}",
            device.address, friendly_name, manufacturer, model, device.location
        );
        if description.is_none() {
            eprintln!("  デバイス記述を取得できませんでした: {}", device.location);
        }
    }
    println!("\n{} UPnP device(s) found", devices.len());
    Ok(true)
}

fn parse_timeout(value: &str, args: &noargs::RawArgs) -> noargs::Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| noargs::Error::other(args, "--timeoutには1以上の秒数を指定してください"))
}

fn discover(
    search_target: &str,
    timeout: u64,
    args: &noargs::RawArgs,
) -> noargs::Result<Vec<SsdpDevice>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| noargs::Error::other(args, format!("SSDPソケットを開けません: {e}")))?;
    socket
        .set_multicast_ttl_v4(2)
        .map_err(|e| noargs::Error::other(args, format!("マルチキャスト設定に失敗: {e}")))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| noargs::Error::other(args, format!("受信タイムアウト設定に失敗: {e}")))?;

    let request = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADDRESS}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {search_target}\r\n\r\n"
    );
    socket
        .send_to(request.as_bytes(), SSDP_ADDRESS)
        .map_err(|e| noargs::Error::other(args, format!("SSDP検索を送信できません: {e}")))?;

    println!("SSDP探索中: {search_target} ({timeout}秒)...");
    let start = Instant::now();
    let mut buffer = [0u8; 8192];
    let mut devices = BTreeMap::new();
    while start.elapsed() < Duration::from_secs(timeout) {
        match socket.recv_from(&mut buffer) {
            Ok((length, peer)) => {
                if let Some(device) = parse_response(&buffer[..length], peer) {
                    let key = if device.usn.is_empty() {
                        format!("{}:{}", device.address, device.location)
                    } else {
                        device.usn.clone()
                    };
                    devices.insert(key, device);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => {
                eprintln!("SSDP受信エラー: {e}");
                break;
            }
        }
    }
    Ok(devices.into_values().collect())
}

fn parse_response(packet: &[u8], peer: SocketAddr) -> Option<SsdpDevice> {
    let text = String::from_utf8_lossy(packet);
    let status = text.lines().next()?;
    if !status.starts_with("HTTP/1.") || !status.contains(" 200 ") {
        return None;
    }
    let mut headers = BTreeMap::new();
    for line in text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let address = match peer {
        SocketAddr::V4(peer) => *peer.ip(),
        SocketAddr::V6(_) => return None,
    };
    Some(SsdpDevice {
        address,
        st: headers.get("st").cloned().unwrap_or_default(),
        usn: headers.get("usn").cloned().unwrap_or_default(),
        server: headers.get("server").cloned().unwrap_or_default(),
        location: headers.get("location").cloned().unwrap_or_default(),
    })
}

fn print_devices(devices: &[SsdpDevice]) {
    if devices.is_empty() {
        println!("SSDPデバイスは見つかりませんでした");
        return;
    }
    println!("{:<16} {:<28} {:<45} LOCATION", "Address", "ST", "USN");
    println!("{}", "─".repeat(120));
    for device in devices {
        println!(
            "{:<16} {:<28} {:<45} {}",
            device.address, device.st, device.usn, device.location
        );
        if !device.server.is_empty() {
            println!("  Server: {}", device.server);
        }
    }
    println!("\n{} SSDP response(s) found", devices.len());
}

fn fetch_description(url: &str, expected_ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    if url.contains(['\r', '\n']) {
        return None;
    }
    let rest = url.strip_prefix("http://")?;
    let boundary = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..boundary];
    let suffix = &rest[boundary..];
    if authority.is_empty() || authority.contains('@') || suffix.starts_with('#') {
        return None;
    }
    let path = if suffix.starts_with('?') {
        format!("/{suffix}")
    } else {
        suffix.to_string()
    };
    if path.contains('#') {
        return None;
    }
    let host_port = authority;
    let (host, port) = if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let host = &host_port[1..end];
        let port = host_port[end + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .unwrap_or(80);
        (host, port)
    } else if let Some((host, port)) = host_port.rsplit_once(':') {
        (host, port.parse().ok()?)
    } else {
        (host_port, 80)
    };
    if host.is_empty() {
        return None;
    }
    // LOCATION is supplied by a network device. Only connect to the responding
    // device's address, even if the URL contains a hostname resolving elsewhere.
    if !(host, port)
        .to_socket_addrs()
        .ok()?
        .any(|address| address.is_ipv4() && address.ip() == expected_ip)
    {
        return None;
    }
    let address = SocketAddr::from((expected_ip, port));
    let mut stream = TcpStream::connect_timeout(&address, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let request_path = if path.is_empty() {
        "/".to_string()
    } else {
        format!("/{path}")
    };
    write!(
        stream,
        "GET {request_path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: text/xml, application/xml\r\n\r\n"
    )
    .ok()?;
    let mut response = Vec::new();
    stream
        .take(MAX_DESCRIPTION_SIZE)
        .read_to_end(&mut response)
        .ok()?;
    let response = String::from_utf8_lossy(&response);
    let (headers, body) = response.split_once("\r\n\r\n")?;
    if !headers.lines().next()?.contains(" 200 ") {
        return None;
    }
    if headers.lines().any(|line| {
        line.to_ascii_lowercase().starts_with("transfer-encoding:")
            && line.to_ascii_lowercase().contains("chunked")
    }) {
        return decode_chunked(body);
    }
    Some(body.to_string())
}

fn decode_chunked(body: &str) -> Option<String> {
    let mut decoded = Vec::new();
    let mut rest = body.as_bytes();
    loop {
        let line_end = rest.windows(2).position(|window| window == b"\r\n")?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&rest[..line_end])
                .ok()?
                .split(';')
                .next()?
                .trim(),
            16,
        )
        .ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size + 2 || &rest[size..size + 2] != b"\r\n" {
            return None;
        }
        decoded.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    Some(String::from_utf8_lossy(&decoded).into_owned())
}

fn xml_tag(document: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let value = document.split_once(&open)?.1.split_once(&close)?.0.trim();
    if value.is_empty() {
        return None;
    }
    Some(
        value
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssdp_headers_case_insensitively() {
        let packet = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:test\r\nLOCATION: http://192.0.2.4/device.xml\r\n\r\n";
        let device = parse_response(packet, "192.0.2.4:1900".parse().unwrap()).unwrap();
        assert_eq!(device.address, Ipv4Addr::new(192, 0, 2, 4));
        assert_eq!(device.st, "upnp:rootdevice");
        assert_eq!(device.usn, "uuid:test");
    }

    #[test]
    fn refuses_description_urls_that_resolve_to_another_host() {
        assert!(
            fetch_description(
                "http://192.0.2.5/device.xml",
                Ipv4Addr::new(192, 0, 2, 4),
                Duration::from_millis(1),
            )
            .is_none()
        );
    }

    #[test]
    fn extracts_and_unescapes_xml_text() {
        assert_eq!(
            xml_tag("<root><name>A &amp; B</name></root>", "name"),
            Some("A & B".into())
        );
    }
}
