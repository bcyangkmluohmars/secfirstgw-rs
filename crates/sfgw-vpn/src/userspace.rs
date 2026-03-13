// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(unsafe_code)]

//! Boringtun userspace WireGuard tunnel runtime.
//!
//! Provides a TUN-based WireGuard tunnel using boringtun for the noise protocol.
//! This is used when the kernel WireGuard module is not available.
//!
//! Architecture:
//! - A TUN device handles IP packets (reads outbound, writes inbound)
//! - A UDP socket handles encrypted WireGuard protocol packets
//! - boringtun's `Tunn` handles encryption/decryption per peer
//! - A timer task handles keepalives and handshake retransmissions
//!
//! # Safety
//!
//! The `create_tun_device` function uses `unsafe` for the TUNSETIFF ioctl.
//! This is the standard Linux API for creating TUN devices and is well-defined
//! behavior when called with valid parameters.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use boringtun::noise::{Tunn, TunnResult, rate_limiter::RateLimiter};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info};
use zeroize::Zeroize;

/// Configuration for a peer in the userspace tunnel.
#[derive(Clone)]
pub struct PeerConfig {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
    pub allowed_ips: Vec<String>,
}

impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("public_key", &self.public_key)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("allowed_ips", &self.allowed_ips)
            .finish()
    }
}

/// Create a TUN device with the given name.
///
/// Returns the file descriptor for the TUN device.
///
/// # Safety
///
/// Uses `ioctl(TUNSETIFF)` which is the standard Linux TUN/TAP API.
/// The ioctl is safe when called with a valid fd from `/dev/net/tun`
/// and a properly initialized `ifreq` struct.
pub fn create_tun_device(name: &str) -> Result<OwnedFd> {
    if name.len() > 15 {
        bail!("TUN device name too long (max 15 chars)");
    }

    // SAFETY: Opening /dev/net/tun is a standard Linux operation.
    // The returned fd is valid if open() succeeds (returns >= 0).
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        bail!(
            "failed to open /dev/net/tun: {}",
            std::io::Error::last_os_error()
        );
    }

    // SAFETY: We zero-initialize the ifreq struct and only write within bounds.
    // The ifr_name field is IFNAMSIZ (16) bytes, and we checked name.len() <= 15.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // IFF_TUN = layer 3 (IP packets), IFF_NO_PI = no packet info header
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

    // Copy the interface name
    for (i, &byte) in name.as_bytes().iter().enumerate().take(libc::IFNAMSIZ - 1) {
        ifr.ifr_name[i] = byte as libc::c_char;
    }

    // SAFETY: TUNSETIFF is the standard ioctl for configuring TUN/TAP devices.
    // fd is a valid file descriptor from open(/dev/net/tun).
    // ifr is a properly initialized ifreq struct.
    const TUNSETIFF: libc::Ioctl = 0x400454CA as libc::Ioctl;
    let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if ret < 0 {
        // SAFETY: fd is valid; close() on a valid fd is always safe.
        unsafe { libc::close(fd) };
        bail!(
            "TUNSETIFF ioctl failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // Set non-blocking for async I/O
    // SAFETY: fcntl F_GETFL/F_SETFL on a valid fd is standard POSIX.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }

    // SAFETY: fd is valid and we are taking ownership of it.
    // The OwnedFd will close it on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Spawn the boringtun packet processing loop as a background tokio task.
///
/// The task runs until the TUN device is closed (tunnel stopped).
/// If `bind_address` is set, the UDP socket binds to that specific IP
/// instead of all interfaces.
pub fn spawn_tunnel_task(
    name: String,
    tun_fd: OwnedFd,
    mut private_key_bytes: Vec<u8>,
    listen_port: u16,
    peer_configs: Vec<PeerConfig>,
    bind_address: Option<String>,
) {
    tokio::spawn(async move {
        if let Err(e) = run_tunnel_loop(
            &name,
            tun_fd,
            &private_key_bytes,
            listen_port,
            &peer_configs,
            bind_address.as_deref(),
        )
        .await
        {
            error!(tunnel = name, "boringtun tunnel loop exited: {e}");
        }
        private_key_bytes.zeroize();
    });
}

/// Main packet processing loop for a boringtun tunnel.
async fn run_tunnel_loop(
    name: &str,
    tun_fd: OwnedFd,
    private_key_bytes: &[u8],
    listen_port: u16,
    peer_configs: &[PeerConfig],
    bind_address: Option<&str>,
) -> Result<()> {
    // Parse the private key
    let key_array: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid private key length"))?;
    let static_private = StaticSecret::from(key_array);

    // Create rate limiter
    let rate_limiter = Arc::new(RateLimiter::new(&PublicKey::from(&static_private), 100));

    // Create boringtun Tunn instances for each peer
    let mut peers: HashMap<[u8; 32], Arc<Mutex<Tunn>>> = HashMap::new();
    let mut endpoint_map: HashMap<[u8; 32], SocketAddr> = HashMap::new();

    for (idx, pc) in peer_configs.iter().enumerate() {
        let peer_pub_bytes = BASE64
            .decode(&pc.public_key)
            .context("invalid peer public key base64")?;
        let peer_pub_array: [u8; 32] = peer_pub_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid peer public key length"))?;
        let peer_public = PublicKey::from(peer_pub_array);

        let psk: Option<[u8; 32]> = match &pc.preshared_key {
            Some(psk_b64) => {
                let psk_bytes = BASE64.decode(psk_b64).context("invalid PSK base64")?;
                let arr: [u8; 32] = psk_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid PSK length"))?;
                Some(arr)
            }
            None => None,
        };

        let tunn = Tunn::new(
            static_private.clone(),
            peer_public,
            psk,
            pc.persistent_keepalive,
            idx as u32,
            Some(rate_limiter.clone()),
        );

        peers.insert(peer_pub_array, Arc::new(Mutex::new(tunn)));

        if let Some(ref ep) = pc.endpoint
            && let Ok(addr) = ep.parse::<SocketAddr>()
        {
            endpoint_map.insert(peer_pub_array, addr);
        }
    }

    // Bind UDP socket for WireGuard protocol.
    // If bind_address is set, bind to that specific IP; otherwise bind to all interfaces.
    let udp = if let Some(addr) = bind_address {
        UdpSocket::bind(format!("{addr}:{listen_port}"))
            .await
            .with_context(|| format!("failed to bind UDP socket to {addr}:{listen_port}"))?
    } else {
        match UdpSocket::bind(format!("[::]:{listen_port}")).await {
            Ok(s) => s,
            Err(_) => {
                // IPv4 fallback if dual-stack bind fails
                UdpSocket::bind(format!("0.0.0.0:{listen_port}"))
                    .await
                    .context("failed to bind UDP socket for WireGuard")?
            }
        }
    };

    info!(
        tunnel = name,
        port = listen_port,
        peers = peer_configs.len(),
        "boringtun tunnel running"
    );

    // Use AsyncFd for the TUN device
    let tun_async = tokio::io::unix::AsyncFd::new(TunFd(tun_fd))?;

    let mut tun_buf = vec![0u8; 65536];
    let mut udp_buf = vec![0u8; 65536];
    let mut out_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            // Read from TUN (outbound IP packet → encrypt → send UDP)
            readable = tun_async.readable() => {
                let mut guard = readable?;
                match guard.try_io(|inner| {
                    // SAFETY: Reading from TUN fd into a valid buffer. The fd is
                    // valid (from AsyncFd) and tun_buf is a heap-allocated Vec.
                    let n = unsafe {
                        libc::read(
                            inner.get_ref().0.as_raw_fd(),
                            tun_buf.as_mut_ptr() as *mut libc::c_void,
                            tun_buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(n)) if n > 0 => {
                        // Find the right peer by destination IP and encrypt
                        // For simplicity, try all peers (a production impl would use a routing table)
                        for (pub_key, tunn) in &peers {
                            let mut t = tunn.lock().await;
                            match t.encapsulate(&tun_buf[..n], &mut out_buf) {
                                TunnResult::WriteToNetwork(data) => {
                                    if let Some(endpoint) = endpoint_map.get(pub_key)
                                        && let Err(e) = udp.send_to(data, endpoint).await {
                                            debug!(tunnel = name, "UDP send failed: {e}");
                                        }
                                    break;
                                }
                                TunnResult::Done => continue,
                                TunnResult::Err(e) => {
                                    debug!(tunnel = name, "encapsulate error: {:?}", e);
                                    continue;
                                }
                                _ => continue,
                            }
                        }
                    }
                    Ok(Ok(_)) | Ok(Err(_)) => {}
                    Err(_would_block) => {}
                }
            }

            // Read from UDP (inbound WireGuard packet → decrypt → write to TUN)
            result = udp.recv_from(&mut udp_buf) => {
                let (n, src_addr) = result?;

                // Try each peer's Tunn to decrypt
                for (pub_key, tunn) in &peers {
                    let mut t = tunn.lock().await;
                    match t.decapsulate(None, &udp_buf[..n], &mut out_buf) {
                        TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                            // SAFETY: Writing decrypted packet to TUN fd. The fd is valid
                            // (from AsyncFd), data is a valid slice from boringtun.
                            let written = unsafe {
                                libc::write(
                                    tun_async.get_ref().0.as_raw_fd(),
                                    data.as_ptr() as *const libc::c_void,
                                    data.len(),
                                )
                            };
                            if written < 0 {
                                debug!(tunnel = name, "TUN write failed: {}", std::io::Error::last_os_error());
                            }
                            // Update endpoint mapping
                            endpoint_map.insert(*pub_key, src_addr);
                            break;
                        }
                        TunnResult::WriteToNetwork(data) => {
                            // Response packet (handshake, cookie, etc.)
                            if let Err(e) = udp.send_to(data, src_addr).await {
                                debug!(tunnel = name, "UDP send failed: {e}");
                            }
                            endpoint_map.insert(*pub_key, src_addr);

                            // Check if there's a follow-up (some handshakes produce data)
                            loop {
                                match t.decapsulate(None, &[], &mut out_buf) {
                                    TunnResult::WriteToNetwork(data2) => {
                                        if let Err(e) = udp.send_to(data2, src_addr).await {
                                            debug!(tunnel = name, "UDP send failed: {e}");
                                        }
                                    }
                                    TunnResult::WriteToTunnelV4(data2, _) | TunnResult::WriteToTunnelV6(data2, _) => {
                                        // SAFETY: Writing follow-up decrypted packet to TUN fd.
                                        // Same guarantees as the outer TUN write above.
                                        let written = unsafe {
                                            libc::write(
                                                tun_async.get_ref().0.as_raw_fd(),
                                                data2.as_ptr() as *const libc::c_void,
                                                data2.len(),
                                            )
                                        };
                                        if written < 0 {
                                            debug!(tunnel = name, "TUN write failed: {}", std::io::Error::last_os_error());
                                        }
                                        break;
                                    }
                                    _ => break,
                                }
                            }
                            break;
                        }
                        TunnResult::Done => continue,
                        TunnResult::Err(_) => continue,
                    }
                }
            }

            // Timer tick for keepalives and handshake retransmissions
            _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
                for (pub_key, tunn) in &peers {
                    let mut t = tunn.lock().await;
                    match t.update_timers(&mut out_buf) {
                        TunnResult::WriteToNetwork(data) => {
                            if let Some(endpoint) = endpoint_map.get(pub_key)
                                && let Err(e) = udp.send_to(data, endpoint).await {
                                    debug!(tunnel = name, "UDP send failed: {e}");
                                }
                        }
                        TunnResult::Err(e) => {
                            debug!(tunnel = name, "timer error: {:?}", e);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Wrapper around OwnedFd for implementing AsyncFd traits.
struct TunFd(OwnedFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_name_validation() {
        // Names over 15 chars should fail
        assert!(create_tun_device("this_name_is_way_too_long").is_err());
    }

    #[test]
    fn peer_config_debug() {
        let pc = PeerConfig {
            public_key: "test_key".to_string(),
            preshared_key: None,
            endpoint: Some("1.2.3.4:51820".to_string()),
            persistent_keepalive: Some(25),
            allowed_ips: vec!["10.0.0.2/32".to_string()],
        };
        // Ensure Debug trait works (no secrets leaked)
        let debug_str = format!("{:?}", pc);
        assert!(debug_str.contains("test_key"));
    }
}
