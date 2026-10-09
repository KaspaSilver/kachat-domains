//! The deployer key: one fresh secp256k1 Schnorr key, created by `keygen` at
//! `.secrets/<network>-deployer.key` (mode 600: `testnet10-` or `mainnet-`). It is the only key this
//! tool ever reads; the key itself is never printed, only its address.

use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
};

use anyhow::{Context, Result, bail};
use secp256k1::{Keypair, Secp256k1, SecretKey};

use crate::{net::p2pk_address, paths::Paths};

/// `.secrets/` must be ignored by git before any secret is written.
pub fn ensure_gitignored(paths: &Paths) -> Result<()> {
    let gi = fs::read_to_string(paths.gitignore()).unwrap_or_default();
    if !gi.lines().any(|l| matches!(l.trim(), ".secrets/" | ".secrets" | "/.secrets/" | "/.secrets")) {
        bail!(".secrets/ is not in {}; add it before creating keys", paths.rel(&paths.gitignore()));
    }
    Ok(())
}

fn ensure_secrets_dir(paths: &Paths) -> Result<()> {
    ensure_gitignored(paths)?;
    let dir = paths.secrets_dir();
    if !dir.exists() {
        fs::DirBuilder::new().mode(0o700).create(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    Ok(())
}

/// Create the deployer key. Refuses to overwrite an existing one.
pub fn keygen(paths: &Paths) -> Result<Keypair> {
    ensure_secrets_dir(paths)?;
    let path = paths.deployer_key();
    if path.exists() {
        bail!("{} already exists; refusing to overwrite it", paths.rel(&path));
    }
    let secp = Secp256k1::new();
    let (sk, _) = secp.generate_keypair(&mut secp256k1::rand::rngs::OsRng);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    writeln!(f, "{}", faster_hex::hex_string(&sk.secret_bytes()))?;
    f.sync_all()?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(Keypair::from_secret_key(&secp, &sk))
}

/// Load the deployer key (and only that key). The file must be mode 600.
pub fn load(paths: &Paths) -> Result<Keypair> {
    let path = paths.deployer_key();
    let meta = fs::metadata(&path).with_context(|| format!("{} not found; run `keygen` first", paths.rel(&path)))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!("{} has mode {mode:o}; chmod 600 it", paths.rel(&path));
    }
    let text = fs::read_to_string(&path)?;
    let mut raw = [0u8; 32];
    faster_hex::hex_decode(text.trim().as_bytes(), &mut raw).with_context(|| format!("{} is not 32 hex bytes", paths.rel(&path)))?;
    let sk = SecretKey::from_slice(&raw).with_context(|| format!("{} is not a valid secp256k1 secret", paths.rel(&path)))?;
    Ok(Keypair::from_secret_key(&Secp256k1::new(), &sk))
}

pub fn address_of(kp: &Keypair) -> String {
    p2pk_address(&kp.x_only_public_key().0.serialize()).to_string()
}

/// Write a JSON file under `.secrets/` with mode 600.
pub fn write_secret_json(paths: &Paths, path: &std::path::Path, value: &serde_json::Value) -> Result<()> {
    ensure_secrets_dir(paths)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(serde_json::to_string_pretty(value)?.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
