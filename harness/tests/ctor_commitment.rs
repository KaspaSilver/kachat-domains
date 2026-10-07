//! Guard for silverscript#258: the compiler silently drops a constructor
//! parameter that no code reads, so the template (and every address built
//! from it) would not commit to that value.
//!
//! For each contract, change one constructor argument at a time and recompile:
//! - a baked parameter must change the template hash;
//! - an `init*` parameter is the starting runtime state, so it must change the
//!   state span and leave the template hash alone.
//!
//! A new parameter is covered automatically: the names come from the source,
//! and the argument lists are the ones the build and the CLI compile with.

use kachat_names_harness::*;

/// The constructor parameter names of `contracts/<contract>.sil`, in order.
fn ctor_params(src: &str, contract: &str) -> Vec<String> {
    let head = format!("contract {contract}(");
    let start = src.find(&head).expect("contract header") + head.len();
    let end = start + src[start..].find(')').expect("constructor close");
    src[start..end]
        .split(',')
        .map(|p| p.split_whitespace().last().expect("parameter name").to_string())
        .collect()
}

fn perturb(v: &ArtifactValue) -> ArtifactValue {
    match v {
        ArtifactValue::Int(i) => ArtifactValue::Int(i + 1),
        ArtifactValue::Bytes(b) => {
            let mut b = b.clone();
            b[0] ^= 0x01;
            ArtifactValue::Bytes(b)
        }
        other => panic!("unexpected constructor argument {other:?}"),
    }
}

fn check(contract: &str, args: &[ArtifactValue]) {
    let src = std::fs::read_to_string(repo_root().join(format!("contracts/{contract}.sil"))).unwrap();
    let names = ctor_params(&src, contract);
    assert_eq!(names.len(), args.len(), "{contract}: argument list out of step with the source");
    let base = compile_source(&src, args);
    let state_fields = base.abi.contracts[&base.contract].runtime_state.fields.len();
    assert_eq!(names.iter().filter(|n| n.starts_with("init")).count(), state_fields, "{contract}: init* params != state fields");

    let mut dropped = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let mut changed = args.to_vec();
        changed[i] = perturb(&args[i]);
        let t = compile_source(&src, &changed);
        if name.starts_with("init") {
            assert_eq!(t.template_hash, base.template_hash, "{contract}.{name}: state moved the template");
            assert_ne!(t.bytecode, base.bytecode, "{contract}.{name}: not in the state span");
        } else if t.template_hash == base.template_hash {
            dropped.push(name.clone());
        }
    }
    assert!(dropped.is_empty(), "{contract}: the template does not commit to {dropped:?} (silverscript#258)");
}

#[test]
fn every_constructor_parameter_is_committed() {
    for net in ["testnet10", "mainnet"] {
        let p = NetParams::load(net);
        let root = repo_root();
        let name = compile_name_in(&root, &p);
        check("KachatName", &name_args(&p));
        check("KachatGap", &gap_args(&p, &name));
        check("KachatOffer", &offer_args(&p, &name, Hash::from_bytes([7; 32])));
    }
}
