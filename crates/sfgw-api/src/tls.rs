// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 configuration for the API server.
//!
//! Generates a self-signed certificate on first run and stores it on disk.
//! Subsequent runs load the existing certificate. Only TLS 1.3 cipher suites
//! are allowed: AES-256-GCM-SHA384 and CHACHA20-POLY1305-SHA256.

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Default directory for TLS certificate and key storage.
const TLS_DIR: &str = "/data/sfgw-tls";

/// Load an existing TLS config or generate a self-signed certificate.
///
/// Certificates are stored in `{tls_dir}/cert.pem` and `{tls_dir}/key.pem`.
/// The `tls_dir` defaults to [`TLS_DIR`] but can be overridden via `SFGW_TLS_DIR`.
pub fn load_or_create_tls_config() -> Result<ServerConfig> {
    let tls_dir =
        PathBuf::from(std::env::var("SFGW_TLS_DIR").unwrap_or_else(|_| TLS_DIR.to_string()));

    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    let (cert_chain, key) = if cert_path.exists() && key_path.exists() {
        tracing::info!("loading TLS certificate from {}", cert_path.display());
        load_cert_and_key(&cert_path, &key_path)?
    } else {
        tracing::info!(
            "generating self-signed TLS certificate in {}",
            tls_dir.display()
        );
        generate_and_store(&tls_dir, &cert_path, &key_path)?
    };

    build_server_config(cert_chain, key)
}

/// Build a [`ServerConfig`] restricted to TLS 1.3 only.
fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("failed to build TLS ServerConfig")?;

    Ok(config)
}

/// Load PEM-encoded certificate chain and private key from disk.
fn load_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("failed to read {}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM")?;

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("failed to parse private key PEM")?
        .context("no private key found in PEM file")?;

    Ok((certs, key))
}

/// Generate a self-signed certificate, write it to disk, and return the
/// certificate chain + private key for immediate use.
fn generate_and_store(
    tls_dir: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    std::fs::create_dir_all(tls_dir)
        .with_context(|| format!("failed to create TLS directory {}", tls_dir.display()))?;

    // Restrict directory permissions (owner-only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tls_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set permissions on {}", tls_dir.display()))?;
    }

    let mut params = rcgen::CertificateParams::new(vec![
        "secfirstgw.local".to_string(),
        "localhost".to_string(),
    ])
    .context("failed to create certificate params")?;

    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("Security First Gateway".to_string()),
    );
    params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        rcgen::DnValue::Utf8String("secfirstgw".to_string()),
    );

    // Add IP SANs for local access
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V6(
            std::net::Ipv6Addr::LOCALHOST,
        )));

    // Valid for 365 days
    let now = rcgen::date_time_ymd(2026, 1, 1);
    let expiry = rcgen::date_time_ymd(2027, 1, 1);
    params.not_before = now;
    params.not_after = expiry;

    let key_pair = rcgen::KeyPair::generate().context("failed to generate key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate self-signed certificate")?;

    // Write cert PEM
    let cert_pem = cert.pem();
    std::fs::write(cert_path, cert_pem.as_bytes())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;

    // Write key PEM
    let key_pem = key_pair.serialize_pem();
    std::fs::write(key_path, key_pem.as_bytes())
        .with_context(|| format!("failed to write {}", key_path.display()))?;

    // Restrict key file permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", key_path.display()))?;
    }

    tracing::info!(
        "self-signed TLS certificate generated at {}",
        cert_path.display()
    );

    // Parse back for rustls
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((vec![cert_der], key_der))
}

/// Convert a [`ServerConfig`] into an [`axum_server::tls_rustls::RustlsConfig`].
pub async fn into_axum_rustls_config(
    config: ServerConfig,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    let config = Arc::new(config);
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(config))
}
