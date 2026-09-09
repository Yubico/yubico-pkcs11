// Copyright 2026 Yubico AB
// Licensed under the Apache License, Version 2.0

//! Configuration parsing matching the C module's yubihsm_pkcs11.conf format.

use std::env;
use std::fs;

#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub connectors: Vec<ConnectorConfig>, // List of connectors to use
    pub debug: bool, // Enable pkcs11 debugging
    pub dinout: bool, // Enable pkcs11 function tracing
    pub libdebug: bool, // Enable libyubihsm debugging
    pub debug_file: Option<String>, // Output file for debugging
    pub cacert: Option<String>, // Cacert to use for HTTPS validation
    pub cert: Option<String>, // HTTPS client certificate to authenticate with
    pub key: Option<String>, // HTTPS client certificate key
    pub proxy: Option<String>, // Proxy server to use for connector
    pub noproxy: Option<String>, // Comma separated list of hosts ignore proxy for
    pub timeout: Option<u64>, // Timeout to use for initial connection to connector
    pub device_pubkey: Option<String>, // List of device public keys allowed for asymmetric authentication
}

impl Default for Config {
    fn default() -> Self {
        Self {
            connectors: Vec::new(),
            debug: false,
            dinout: false,
            libdebug: false,
            debug_file: None,
            cacert: None,
            cert: None,
            key: None,
            proxy: None,
            noproxy: None,
            timeout: None,
            device_pubkey: None,
        }
    }
}

/// Parse config from the pReserved string passed to C_Initialize.
/// Format: "connector=url connector=url2 debug dinout"
pub fn parse_config(config_string: &str) -> Config {
    let mut config = Config::default();

    for token in config_string.split_whitespace() {
        if let Some(url) = token.strip_prefix("connector=") {
            config.connectors.push(ConnectorConfig {
                url: url.to_string(),
            });
        } else if token == "debug" {
            config.debug = true;
        } else if token == "dinout" {
            config.dinout = true;
        } else if token == "libdebug" {
            config.libdebug = true;
        } else if let Some(file) = token.strip_prefix("debug-file=") {
            config.debug_file = Some(file.to_string());
        }
    }

    config
}

/// Load config from file.
pub fn load_from_file(path: &str) -> Config {
    let mut config = Config::default();

    if let Ok(contents) = fs::read_to_string(path) {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(url) = line.strip_prefix("connector=") {
                config.connectors.push(ConnectorConfig {
                    url: url.trim().to_string(),
                });
            } else if line == "debug" {
                config.debug = true;
            } else if line == "dinout" {
                config.dinout = true;
            } else if line == "libdebug" {
                config.libdebug = true;
            } else if let Some(file) = line.strip_prefix("debug-file=") {
                config.debug_file = Some(file.trim().to_string());
            } else if let Some(cert) = line.strip_prefix("cacert=") {
                config.cacert = Some(cert.trim().to_string());
            } else if let Some(proxy) = line.strip_prefix("proxy=") {
                config.proxy = Some(proxy.trim().to_string());
            } else if let Some(t) = line.strip_prefix("timeout=") {
                config.timeout = t.trim().parse().ok();
            }
        }
    }

    config
}

/// Resolve config: pReserved > YUBIHSM_PKCS11_CONF env > ./yubihsm_pkcs11.conf
pub fn resolve(reserved: Option<&str>) -> Config {
    // If pReserved contains connector= directly, use it
    if let Some(r) = reserved {
        let config = parse_config(r);
        if !config.connectors.is_empty() {
            return config;
        }
        // pReserved might be a file path
        let file_config = load_from_file(r);
        if !file_config.connectors.is_empty() {
            return file_config;
        }
    }

    // Try YUBIHSM_PKCS11_CONF env
    if let Ok(path) = env::var("YUBIHSM_PKCS11_CONF") {
        let config = load_from_file(&path);
        if !config.connectors.is_empty() {
            return config;
        }
    }

    // Try ./yubihsm_pkcs11.conf
    let config = load_from_file("yubihsm_pkcs11.conf");
    if !config.connectors.is_empty() {
        return config;
    }

    // Default: single connector at localhost
    Config {
        connectors: vec![ConnectorConfig {
            url: "http://127.0.0.1:12345".to_string(),
        }],
        ..Config::default()
    }
}