//! The network this run is on: testnet-10 (the default) or mainnet, chosen
//! once by `--network` before anything else runs ([`select`]). Every network
//! value (node network name, address prefix, params and artifacts, ports,
//! seeders, ticker) comes from here.

use std::sync::OnceLock;

use anyhow::{Result, bail};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    config::params::{MAINNET_PARAMS, Params, TESTNET_PARAMS},
    tx::ScriptPublicKey,
};

pub struct Net {
    /// Network name the node must report (and `--network` takes).
    pub name: &'static str,
    /// `params/<file>.json`, `artifacts/<file>/` and `.secrets/<file>-deployer.key`.
    pub params_file: &'static str,
    /// Address prefix: every address this run prints or accepts has it.
    pub prefix: Prefix,
    /// Ticker printed for amounts.
    pub ticker: &'static str,
    pub grpc_port: u16,
    /// DNS seeders for node discovery.
    pub seeders: &'static [&'static str],
    pub mainnet: bool,
}

/// testnet-10 DNS seeders: rusty-kaspa's TESTNET_PARAMS list at a41a333 plus
/// the two kaspad.net names (which may not resolve).
pub const TN10_DNS_SEEDERS: &[&str] = &[
    "seeder1-testnet.kaspad.net",
    "seeder2-testnet.kaspad.net",
    "seeder1-tn.kaspad.net",
    "dnsseeder-kaspa-testnet.x-con.at",
    "n-testnet-10.kaspa.ws",
];

pub const TESTNET10: Net = Net {
    name: "testnet-10",
    params_file: "testnet10",
    prefix: Prefix::Testnet,
    ticker: "TKAS",
    grpc_port: 16210,
    seeders: TN10_DNS_SEEDERS,
    mainnet: false,
};

pub const MAINNET: Net = Net {
    name: "mainnet",
    params_file: "mainnet",
    prefix: Prefix::Mainnet,
    ticker: "KAS",
    grpc_port: 16110,
    seeders: MAINNET_PARAMS.dns_seeders,
    mainnet: true,
};

static SELECTED: OnceLock<&'static Net> = OnceLock::new();

/// Choose the network for this process (`testnet-10` or `mainnet`). Once only,
/// before the first [`net`] call.
pub fn select(name: &str) -> Result<()> {
    let n: &'static Net = match name {
        "testnet-10" | "testnet10" => &TESTNET10,
        "mainnet" => &MAINNET,
        _ => bail!("unknown network {name:?} (testnet-10 or mainnet)"),
    };
    if SELECTED.set(n).is_err() && net().name != n.name {
        bail!("the network is already {}", net().name);
    }
    Ok(())
}

/// The selected network (testnet-10 unless [`select`]ed otherwise).
pub fn net() -> &'static Net {
    SELECTED.get_or_init(|| &TESTNET10)
}

/// Consensus params the local validator runs with (Toccata is active on both
/// networks: testnet-10 since DAA 467,579,632, mainnet since DAA 474,165,565).
pub fn consensus_params() -> Params {
    let p = if net().mainnet { MAINNET_PARAMS } else { TESTNET_PARAMS };
    assert_eq!(p.net.to_string(), net().name);
    p
}

/// The network's Schnorr (P2PK, x-only) address.
pub fn p2pk_address(x_only: &[u8; 32]) -> Address {
    Address::new(net().prefix, Version::PubKey, x_only)
}

/// The network's P2SH address of a script public key (registry and offer UTXOs).
pub fn spk_address(spk: &ScriptPublicKey) -> Result<Address> {
    Ok(kaspa_txscript::extract_script_pub_key_address(spk, net().prefix)?)
}

/// Parse a Schnorr address of this network into its x-only key. Anything else
/// (the other network, ECDSA, P2SH) is refused.
pub fn parse_owner_address(s: &str) -> Result<[u8; 32]> {
    let a = Address::try_from(s).map_err(|e| anyhow::anyhow!("{s}: {e}"))?;
    if a.prefix != net().prefix {
        bail!("{s}: not a {}: address (this run is on {})", net().prefix, net().name);
    }
    if a.version != Version::PubKey {
        bail!("{s}: a name owner must be a Schnorr P2PK address (version PubKey), got {}", a.version);
    }
    let key: [u8; 32] = a.payload.as_slice().try_into().map_err(|_| anyhow::anyhow!("{s}: bad payload length"))?;
    if key == [0u8; 32] {
        bail!("{s}: zero key");
    }
    // the contracts cannot check that a key is on the curve (README open issue 5)
    secp256k1::XOnlyPublicKey::from_slice(&key).map_err(|_| anyhow::anyhow!("{s}: not a valid secp256k1 x-only key"))?;
    Ok(key)
}
