#![doc = include_str!("../README.md")]
use base64::prelude::*;
use chrono::Timelike;
use reqwest::Upgraded;
use sha1::{Digest, digest::Output};
use std::{
    hash::{BuildHasher, Hasher},
    process::ExitCode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FRAME_MINUS: [u8; 7] = [1 << 7 | 1, 1 << 7 | 1, 0, 0, 0, 0, b'-'];
const FRAME_PLUS: [u8; 7] = [1 << 7 | 1, 1 << 7 | 1, 0, 0, 0, 0, b'+'];

const PACKET_MINUS_800: [u8; 800 * 7] = const {
    let mut out = [0; 5600 / 7 * 7];
    let mut i = 0;
    while i < out.len() {
        out[i] = FRAME_MINUS[i % FRAME_MINUS.len()];
        i += 1;
    }
    out
};

const PACKET_PLUS_800: [u8; 800 * 7] = const {
    let mut out = [0; 5600 / 7 * 7];
    let mut i = 0;
    while i < out.len() {
        out[i] = FRAME_PLUS[i % FRAME_PLUS.len()];
        i += 1;
    }
    out
};

fn find_target() -> i64 {
    // my network latency is a little bad so let's put the target one second into the future
    let now = chrono::Utc::now() + std::time::Duration::from_secs(1);
    let (hour, minute, second) = (now.hour(), now.minute(), now.second());

    let target = hour as i64 * 1_000_000 + minute as i64 * 10_000 + second as i64 * 100;
    target
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let client = reqwest::Client::new();

    let mut failed_reconnects = 0u32;

    let mut hasher = std::hash::RandomState::new().build_hasher();

    let mut ws_key: [u8; 24] = *b"AAAAAAAAAAAAAAAAAAAAAA==";

    while failed_reconnects <= 5 {
        if failed_reconnects > 0 {
            // reconnect after 10 seconds
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }

        hasher.write_u64(1);

        let mut key = hasher.finish();
        for i in 0..16 {
            ws_key[i] = b'A' + (key % 16) as u8;
            key /= 16;
        }

        // a compliant enough websocket negotiation
        let req = match client
            .get("http://the-number.site/ws")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", std::str::from_utf8(&ws_key).unwrap())
            .header("Sec-WebSocket-Version", "13")
            .send()
            .await
        {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Error sending request: {}", e);
                failed_reconnects += 1;
                continue;
            }
        };

        if req.status().as_u16() != 101 {
            eprintln!("Expected 101 status, got {}", req.status());
            failed_reconnects += 1;
            continue;
        }

        let mut check_hasher = sha1::Sha1::default();
        check_hasher.update(ws_key);
        check_hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let check_key = check_hasher.finalize();

        let Some(expected_key) = req
            .headers()
            .get("sec-websocket-accept")
            .and_then(|h| h.to_str().ok())
        else {
            eprintln!("Expected sec-websocket-accept header, got none");
            failed_reconnects += 1;
            continue;
        };

        let mut expected_key_dec = Output::<sha1::Sha1>::default();

        BASE64_STANDARD
            .decode_slice(expected_key.as_bytes(), expected_key_dec.as_mut_slice())
            .unwrap();

        if expected_key_dec != check_key {
            eprintln!(
                "Expected sec-websocket-accept, got {}",
                req.headers()
                    .get("sec-websocket-accept")
                    .unwrap()
                    .to_str()
                    .unwrap()
            );
            failed_reconnects += 1;
            continue;
        }

        let io = match req.upgrade().await {
            Ok(io) => io,
            Err(e) => {
                eprintln!("Error upgrading connection: {}", e);
                failed_reconnects += 1;
                continue;
            }
        };

        eprintln!("handle_connection: {:?}", handle_connection(io).await);

        failed_reconnects = 1;
    }

    ExitCode::from(1)
}

async fn handle_connection(io: Upgraded) -> Result<(), Box<dyn std::error::Error>> {
    static CONNECTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

    CONNECTED.store(true, std::sync::atomic::Ordering::Relaxed);

    let (mut reader, mut writer) = tokio::io::split(io);

    let number = tokio::sync::watch::Sender::new(0);

    let mut number_rx = number.subscribe();

    tokio::spawn(async move {
        struct Disconnected;

        impl Drop for Disconnected {
            fn drop(&mut self) {
                CONNECTED.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let _disconnected = Disconnected;

        let mut read = 0;
        let mut ptr = 0;
        let mut buf = [0; 8192];
        loop {
            let n = reader.read(&mut buf[ptr..]).await?;
            if n == 0 {
                eprintln!("reader: EOF");
                return Ok::<(), tokio::io::Error>(());
            }
            ptr += n;

            let mut read_ptr = 0;
            while read_ptr + 2 <= ptr {
                let op = buf[read_ptr];
                assert!(op & (1 << 7) != 0);
                assert_eq!(op & !(1 << 7), 1);
                assert!(buf[read_ptr + 1] < 127);
                let len = buf[read_ptr + 1] as usize;

                if read_ptr + len + 2 <= ptr {
                    let data = &buf[read_ptr + 2..read_ptr + len + 2];

                    read = std::str::from_utf8(data).unwrap().parse::<i64>().unwrap();

                    read_ptr += len + 2;
                } else {
                    break;
                }
            }

            buf.copy_within(read_ptr..ptr, 0);
            ptr -= read_ptr;

            number.send(read).unwrap();
        }
    });

    let Ok(()) = number_rx.changed().await else {
        return Err("Remote hang up".into());
    };

    while CONNECTED.load(std::sync::atomic::Ordering::Relaxed) {
        let sp = find_target();
        let pv = *number_rx.borrow();

        let packet = if pv < sp - 1600 {
            &PACKET_PLUS_800
        } else if pv > sp + 1600 {
            &PACKET_MINUS_800
        } else if pv < sp - 400 {
            &PACKET_PLUS_800[..7 * 200]
        } else if pv > sp + 400 {
            &PACKET_MINUS_800[..7 * 200]
        } else if pv < sp - 10 {
            &PACKET_PLUS_800[..7 * 10]
        } else if pv > sp + 10 {
            &PACKET_MINUS_800[..7 * 10]
        } else {
            &[]
        };
        eprintln!("SetP: {}, PV: {}, CO: {}", sp, pv, packet.len() / 7);

        if !packet.is_empty() {
            writer.write_all(packet).await.unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
        } else {
        }

        // 1 RTT or 500ms is polite enough for a pure Rust backend
        tokio::select! {
            _ = number_rx.changed() => {
                continue;
            }
            // we should read our own write, but if there is nothing, try again after 500ms
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                continue;
            }
        }
    }

    Ok(())
}
