//! Repository-relative paths. Nothing here is absolute: the root is found at
//! run time (`--repo`, `KACHAT_DOMAINS_ROOT`, or the nearest ancestor of the
//! current directory holding `params/<network>.json` and `contracts/`),
//! falling back to the checkout this binary was built from.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::net::net;

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
}

fn is_root(p: &Path) -> bool {
    p.join("params").join(format!("{}.json", net().params_file)).is_file() && p.join("contracts").join("KachatGap.sil").is_file()
}

impl Paths {
    pub fn find(explicit: Option<&Path>) -> Result<Paths> {
        if let Some(p) = explicit {
            if !is_root(p) {
                bail!("{} is not a kachat-domains checkout (no params/{}.json)", p.display(), net().params_file);
            }
            return Ok(Paths { root: p.canonicalize()? });
        }
        if let Ok(env) = std::env::var("KACHAT_DOMAINS_ROOT") {
            return Self::find(Some(Path::new(&env)));
        }
        let mut dir = std::env::current_dir()?;
        loop {
            if is_root(&dir) {
                return Ok(Paths { root: dir });
            }
            if !dir.pop() {
                break;
            }
        }
        // the checkout this binary was built in (tools/kachat-names-cli/../..)
        let built = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
        if is_root(&built) {
            return Ok(Paths { root: built.canonicalize()? });
        }
        bail!("cannot find the kachat-domains checkout; run inside it or pass --repo")
    }

    pub fn at(root: impl Into<PathBuf>) -> Paths {
        Paths { root: root.into() }
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.root.join(".secrets")
    }
    pub fn deployer_key(&self) -> PathBuf {
        self.secrets_dir().join(format!("{}-deployer.key", net().params_file))
    }
    /// Salted commits: `commits.json` on testnet-10 (as before mainnet mode), `commits-<network>.json` elsewhere.
    pub fn commits(&self) -> PathBuf {
        if net().mainnet { self.secrets_dir().join(format!("commits-{}.json", net().name)) } else { self.secrets_dir().join("commits.json") }
    }
    pub fn state(&self) -> PathBuf {
        self.root.join("state").join(format!("registry-{}.json", net().name))
    }
    pub fn manifest(&self) -> PathBuf {
        self.root.join("manifests").join(format!("kachat-names-{}.json", net().name))
    }
    pub fn dryrun_dir(&self) -> PathBuf {
        self.root.join("manifests").join("dryrun")
    }
    pub fn dryrun_manifest(&self) -> PathBuf {
        self.dryrun_dir().join(format!("kachat-names-{}.json", net().name))
    }
    pub fn params(&self) -> PathBuf {
        self.root.join("params").join(format!("{}.json", net().params_file))
    }
    pub fn artifacts(&self) -> PathBuf {
        self.root.join("artifacts").join(net().params_file)
    }
    pub fn gitignore(&self) -> PathBuf {
        self.root.join(".gitignore")
    }

    /// Path relative to the root, for printing and manifests.
    pub fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root).unwrap_or(p).display().to_string()
    }
}
