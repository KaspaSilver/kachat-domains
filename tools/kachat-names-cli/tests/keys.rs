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

/// DOM-033: a commit is stored before its broadcast and dropped again only when the
/// node refuses it; other commits are left alone.
#[test]
fn commits_are_added_and_removed_one_by_one() {
    use kachat_names_cli::commits::{self, CommitRec};
    let d = scratch("commits");
    std::fs::write(d.join(".gitignore"), ".secrets/\n").unwrap();
    let p = Paths::at(&d);
    let rec = |n: &str, salt: u8| CommitRec { name: n.into(), owner: [1; 32], salt: [salt; 32], value: 20_000_000, outpoint: None, used_by: None, created_ms: 1 };
    let (a, b) = (rec("alpha", 1), rec("bravo", 2));
    commits::add(&p, &a).unwrap();
    commits::add(&p, &b).unwrap();
    assert_eq!(commits::load(&p).unwrap(), vec![a.clone(), b.clone()]);
    assert_eq!(std::fs::metadata(p.commits()).unwrap().permissions().mode() & 0o777, 0o600);
    commits::remove(&p, &a).unwrap();
    assert_eq!(commits::load(&p).unwrap(), vec![b]);
    std::fs::remove_dir_all(d).unwrap();
}
