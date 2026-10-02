//! keygen / key loading guards, in a scratch directory.

use std::os::unix::fs::PermissionsExt;

use kachat_names_cli::{keys, paths::Paths};

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kachat-names-keys-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn keygen_needs_secrets_gitignored_first() {
    let d = scratch("nogi");
    let p = Paths::at(&d);
    assert!(keys::keygen(&p).unwrap_err().to_string().contains(".gitignore"));
    assert!(!p.deployer_key().exists());
    std::fs::write(d.join(".gitignore"), "target/\n").unwrap();
    assert!(keys::keygen(&p).is_err());
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn keygen_writes_mode_600_once_and_load_checks_the_mode() {
    let d = scratch("ok");
    std::fs::write(d.join(".gitignore"), "target/\n.secrets/\n").unwrap();
    let p = Paths::at(&d);
    let kp = keys::keygen(&p).unwrap();
    let meta = std::fs::metadata(p.deployer_key()).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(p.secrets_dir()).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(keys::address_of(&kp).starts_with("kaspatest:q"));
    // never overwritten
    assert!(keys::keygen(&p).is_err());
    assert_eq!(keys::load(&p).unwrap().secret_bytes(), kp.secret_bytes());
    std::fs::set_permissions(p.deployer_key(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(keys::load(&p).unwrap_err().to_string().contains("chmod 600"));
    std::fs::remove_dir_all(d).unwrap();
}
