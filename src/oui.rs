//! OUI (Organizationally Unique Identifier) データベース
//!
//! IEEE が公開している oui.csv をダウンロードしてキャッシュする。
//! MAC アドレスの上位3バイト（OUI）からベンダー名を引く。
//!
//! キャッシュ場所: ~/.cache/arp-scan/oui.csv
//! IEEE CSV URL : https://standards-oui.ieee.org/oui/oui.csv

use pnet::util::MacAddr;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

pub struct OuiDb {
    /// OUI (u32 上位24bit) -> ベンダー名
    map: HashMap<u32, String>,
}

impl OuiDb {
    /// DBをロード（キャッシュがあればそこから、なければダウンロード）
    pub fn load() -> Self {
        let path = cache_path();

        if !path.exists() {
            println!("  IEEE OUI DBをダウンロード中... (~3MB)");
            if let Err(e) = download(&path) {
                eprintln!(
                    "  警告: OUIダウンロード失敗: {} → ベンダー名は表示されません",
                    e
                );
                return Self {
                    map: HashMap::new(),
                };
            }
            println!("  ダウンロード完了: {}", path.display());
        } else {
            println!("  OUIキャッシュ使用: {}", path.display());
        }

        Self {
            map: parse_csv(&path),
        }
    }

    /// MAC アドレスからベンダー名を引く
    pub fn lookup(&self, mac: &MacAddr) -> Option<String> {
        // 上位3バイトをu32に変換
        let oui = (mac.0 as u32) << 16 | (mac.1 as u32) << 8 | mac.2 as u32;
        self.map.get(&oui).cloned()
    }
}

fn cache_path() -> PathBuf {
    let base = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let dir = base.join("arp-scan");
    fs::create_dir_all(&dir).ok();
    dir.join("oui.csv")
}

fn download(path: &Path) -> io::Result<()> {
    // curl でダウンロード（pnetのみで完結させるため外部コマンドを使用）
    let status = std::process::Command::new("curl")
        .args([
            "-sL",
            "https://standards-oui.ieee.org/oui/oui.csv",
            "-o",
            path.to_str().unwrap(),
        ])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("curl failed"))
    }
}

/// IEEEのCSVをパース
/// フォーマット: Registry,Assignment,Organization Name,Organization Address
/// 例: MA-L,FCECDA,"Apple, Inc.",Apple Inc.  ...
fn parse_csv(path: &PathBuf) -> HashMap<u32, String> {
    let mut map = HashMap::new();

    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return map,
    };

    let reader = io::BufReader::new(file);
    for (i, line) in reader.lines().enumerate() {
        if i == 0 {
            continue;
        } // ヘッダースキップ
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // CSVを簡易パース（カンマ区切り、ダブルクォート考慮）
        let parts = simple_csv_split(&line);
        if parts.len() < 3 {
            continue;
        }

        // Assignment 列（例: "FCECDA"）を OUI として使う
        let hex = parts[1].trim().replace(['-', ':'], "");
        if hex.len() != 6 {
            continue;
        }

        if let Ok(oui) = u32::from_str_radix(&hex, 16) {
            let vendor = parts[2].trim().trim_matches('"').to_string();
            map.insert(oui, vendor);
        }
    }

    map
}

/// ダブルクォートを考慮したシンプルなCSVスプリッタ
fn simple_csv_split(line: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                result.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    result.push(current);
    result
}
