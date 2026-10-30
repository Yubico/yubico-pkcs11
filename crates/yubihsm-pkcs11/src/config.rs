/*
 * Copyright 2026 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Parsing of the configurations file format (yubihsm_pkcs11.conf)

use std::env;
use std::fs;

#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub connectors: Vec<ConnectorConfig>, // List of connectors to use
    pub debug: bool,                      // Enable pkcs11 debugging
    pub dinout: bool,                     // Enable pkcs11 function tracing
    pub libdebug: bool,                   // Enable libyubihsm debugging
    pub debug_file: Option<String>,       // Output file for debugging
    pub cacert: Option<String>,           // Cacert to use for HTTPS validation
    pub cert: Option<String>,             // HTTPS client certificate to authenticate with
    pub key: Option<String>,              // HTTPS client certificate key
    pub proxy: Option<String>,            // Proxy server to use for connector
    pub noproxy: Option<String>,          // Comma separated list of hosts ignore proxy for
    pub timeout: Option<u64>,             // Timeout to use for initial connection to connector
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

/// Load configurations from file.
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

/// Fold `other` into `config`
fn merge(config: &mut Config, other: Config) {
    config.connectors.extend(other.connectors);
    config.debug |= other.debug;
    config.dinout |= other.dinout;
    config.libdebug |= other.libdebug;
    config.debug_file = config.debug_file.take().or(other.debug_file);
    config.cacert = config.cacert.take().or(other.cacert);
    config.cert = config.cert.take().or(other.cert);
    config.key = config.key.take().or(other.key);
    config.proxy = config.proxy.take().or(other.proxy);
    config.noproxy = config.noproxy.take().or(other.noproxy);
    config.timeout = config.timeout.take().or(other.timeout);
    config.device_pubkey = config.device_pubkey.take().or(other.device_pubkey);
}

/// Parse configurations. pReserved is
/// parsed first (`cmdline_parser_string_ext`), then a config file is parsed
/// on top of it (`cmdline_parser_config_file`, `override = 0`)
///
/// No default connector is substituted if none was found, causing a
/// hard `CKR_ARGUMENTS_BAD` failure
pub fn resolve(reserved: Option<&str>) -> Config {
    let mut config = Config::default();

    if let Some(r) = reserved {
        merge(&mut config, parse_config(r));
    }

    let file_path =
        env::var("YUBIHSM_PKCS11_CONF").unwrap_or_else(|_| "yubihsm_pkcs11.conf".to_string());
    merge(&mut config, load_from_file(&file_path));

    config
}
