//! The one network this tool knows. There is no mainnet mode.

use anyhow::{Result, bail};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{config::params::{Params, TESTNET_PARAMS}, tx::ScriptPublicKey};

/// Network name the node must report.
pub const NETWORK: &str = "testnet-10";
/// `params/<file>.json` and `artifacts/<file>/`.
pub const PARAMS_FILE: &str = "testnet10";
/// Address prefix: every address this tool prints or accepts is `kaspatest:`.
pub const PREFIX: Prefix = Prefix::Testnet;
/// Ticker printed for amounts.
pub const TICKER: &str = "TKAS";
pub const GRPC_PORT: u16 = 16210;

/// testnet-10 DNS seeders: rusty-kaspa's TESTNET_PARAMS list at a41a333 plus
/// the two kaspad.net names (which may not resolve).
pub const TN10_DNS_SEEDERS: &[&str] = &[
    "seeder1-testnet.kaspad.net",
    "seeder2-testnet.kaspad.net",
    "seeder1-tn.kaspad.net",
    "dnsseeder-kaspa-testnet.x-con.at",
    "n-testnet-10.kaspa.ws",
];

/// Consensus params the local validator runs with (testnet-10; Toccata is
/// active there since DAA 467,579,632, the kit validates with it always on).
pub fn consensus_params() -> Params {
    let p = TESTNET_PARAMS;
    assert_eq!(p.net.to_string(), NETWORK);
    p
}

/// A `kaspatest:` Schnorr (P2PK, x-only) address.
pub fn p2pk_address(x_only: &[u8; 32]) -> Address {
    Address::new(PREFIX, Version::PubKey, x_only)
}

/// The `kaspatest:` P2SH address of a script public key (registry and offer UTXOs).
pub fn spk_address(spk: &ScriptPublicKey) -> Result<Address> {
    Ok(kaspa_txscript::extract_script_pub_key_address(spk, PREFIX)?)
}

/// Parse a `kaspatest:` Schnorr address into its x-only key. Anything else
/// (mainnet, ECDSA, P2SH) is refused.
pub fn parse_owner_address(s: &str) -> Result<[u8; 32]> {
    let a = Address::try_from(s).map_err(|e| anyhow::anyhow!("{s}: {e}"))?;
    if a.prefix != PREFIX {
        bail!("{s}: not a kaspatest: address (this tool runs on {NETWORK} only)");
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
