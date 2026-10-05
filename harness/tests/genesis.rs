//! Genesis, artifact integrity and the state codecs the app will use.

use std::collections::BTreeMap;

use kachat_names_harness::{scenarios::*, *};
use silverscript_abi::{decode_runtime_state_script, encode_runtime_state_script};

#[test]
fn genesis_mints_the_lone_gap_under_the_registry_id() {
    let kit = Kit::new();
    let g = &kit.genesis_tx;
    kit.validate(g, Block { daa: 2_000, time_ms: NOW_MS as u64 }).expect("genesis is valid");
    let out = &g.tx.outputs[0];
    assert_eq!(out.covenant.unwrap().covenant_id, kit.registry_id);
    assert_eq!(out.script_public_key, kit.gap.spk(&gap_state(&ZERO32, &FF32)));
    assert_eq!(g.tx.outputs.iter().filter(|o| o.covenant.is_some()).count(), 1);
}

#[test]
fn price_genesis_mints_every_shard_under_the_price_id() {
    let kit = Kit::new();
    let g = &kit.price_genesis_tx;
    kit.validate(g, Block { daa: 2_000, time_ms: NOW_MS as u64 }).expect("price genesis is valid");
    let k = kit.params.price_shards as usize;
    let bound: Vec<_> = g.tx.outputs.iter().filter(|o| o.covenant.is_some()).collect();
    assert_eq!(bound.len(), k);
    for (i, out) in g.tx.outputs[..k].iter().enumerate() {
        assert_eq!(out.covenant.unwrap().covenant_id, kit.price_id);
        assert_eq!(out.value, kit.params.price_value);
        assert_eq!(out.script_public_key, kit.price.spk(&price_state(i as i64, &xonly(&kit.authority), &kit.params.prices)));
    }
    assert_ne!(kit.price_id, kit.registry_id);
}

#[test]
fn testnet_runs_the_short_clock() {
    // params/testnet10.json: 10-minute periods, renewal and grace of one period each
    let p = NetParams::load("testnet10");
    assert_eq!((p.period_ms, p.renew_window_ms, p.grace_ms, p.max_years), (PERIOD, PERIOD, PERIOD, 2));
    let m = NetParams::load("mainnet");
    assert_eq!((m.period_ms, m.renew_window_ms, m.grace_ms), (YEAR_MS, 864_000_000, 864_000_000));
    // testnet prices are mainnet's / 100
    for i in 0..5 {
        assert_eq!(p.prices[i] * 100, m.prices[i]);
    }
}

#[test]
fn nobody_can_mint_the_price_id_later() {
    let kit = Kit::new();
    let thief = keypair(9);
    let spec = TxSpec {
        inputs: vec![Input::new(kit.p2pk_utxo(&thief, kas(5), 90), Unlock::P2pk(thief))],
        outputs: vec![kit.price_output(0, &xonly(&thief), &[0; 5], 0)],
        lock_time: 0,
    };
    let err = rejected(&kit, &spec, active_block());
    assert!(err.contains("genesis") || err.to_lowercase().contains("covenant"), "{err}");
}

#[test]
fn nobody_can_mint_the_registry_id_later() {
    // An ordinary input binding a fresh output to the registry id is a
    // genesis claim, and the id is keyed by the original genesis outpoint.
    let kit = Kit::new();
    let thief = keypair(9);
    let spec = TxSpec {
        inputs: vec![Input::new(kit.p2pk_utxo(&thief, kas(5), 90), Unlock::P2pk(thief))],
        outputs: vec![kit.gap_output(&ZERO32, &FF32, 0)],
        lock_time: 0,
    };
    let err = rejected(&kit, &spec, active_block());
    assert!(err.contains("genesis") || err.to_lowercase().contains("covenant"), "{err}");
}

#[test]
fn a_spent_name_output_cannot_be_rebound_by_a_non_registry_input() {
    // An output authorized by an input that does not carry the id is not a
    // continuation; with the registry id it is a (wrong) genesis claim.
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let mut spec = transfer(&kit, &n, &xonly(&keypair(7)));
    spec.outputs[0].covenant.as_mut().unwrap().authorizing_input = 1; // the P2PK funding
    assert!(rejected(&kit, &spec, active_block()).len() > 0);
}

#[test]
fn artifacts_match_a_fresh_compile_of_the_sources() {
    // scripts/build.sh output == the pinned compiler library on contracts/*.sil. Until the
    // price genesis exists only KachatPrice is built; the kit compiles the name and gap the
    // way build.py does once priceCovenantId is set (compile_name_in / compile_gap_in).
    for net in ["testnet10", "mainnet"] {
        let p = NetParams::load(net);
        let price = Template::load(net, "KachatPrice");
        let src = std::fs::read_to_string(repo_root().join("contracts/KachatPrice.sil")).unwrap();
        let i = |v: i64| ArtifactValue::Int(v);
        let fresh = compile_source(
            &src,
            &[i(0), ArtifactValue::Bytes(ZERO32.to_vec()), i(0), i(0), i(0), i(0), i(0), i(p.price_shards), i(p.price_value as i64)],
        );
        assert_eq!(fresh.bytecode, price.bytecode, "{net} KachatPrice");
        assert_eq!(silverscript_abi::template_hash(&price.prefix, &price.suffix), price.template_hash);
    }
    let kit = Kit::new();
    for t in [&kit.name, &kit.gap, &kit.offer] {
        assert_eq!(silverscript_abi::template_hash(&t.prefix, &t.suffix), t.template_hash, "{}", t.contract);
    }
}

#[test]
fn testnet_and_mainnet_share_the_price_template() {
    // same shard count and value: the price template is identical; the name and gap differ
    // only in what they bake (periodMs, windows, the price covenant id)
    let t = Template::load("testnet10", "KachatPrice");
    let m = Template::load("mainnet", "KachatPrice");
    assert_eq!(t.bytecode, m.bytecode);
}

#[test]
fn template_state_does_not_change_the_template_hash() {
    // a state change only moves bytes inside the span: prefix and suffix stay
    let kit = Kit::new();
    let s1 = NameFields::new(b"alice", &[7; 32], 0, 1, 2).encode();
    let s2 = NameFields::new(b"bobby", &[8; 32], 5, 3, 4).encode();
    let r1 = kit.name.redeem(&s1);
    let r2 = kit.name.redeem(&s2);
    let pre = kit.name.prefix.len();
    let suf = kit.name.suffix.len();
    assert_eq!(r1[..pre], r2[..pre]);
    assert_eq!(r1[r1.len() - suf..], r2[r2.len() - suf..]);
}

fn abi_encode(t: &Template, values: BTreeMap<String, ArtifactValue>) -> Vec<u8> {
    let c = &t.abi.contracts[&t.contract];
    encode_runtime_state_script(&t.abi, &c.runtime_state, &values).unwrap()
}

#[test]
fn hand_written_state_codecs_match_the_abi() {
    let kit = Kit::new();
    let b = |v: &[u8]| ArtifactValue::Bytes(v.to_vec());
    let i = ArtifactValue::Int;

    let gap = abi_encode(&kit.gap, BTreeMap::from([("lo".into(), b(&[1; 32])), ("hi".into(), b(&[2; 32]))]));
    assert_eq!(gap, gap_state(&[1; 32], &[2; 32]));
    assert_eq!(gap.len(), 66);

    for (price, start, exp) in [
        (0i64, NOW_MS - PERIOD, NOW_MS),
        (123_456_789_000, NOW_MS + 3 * PERIOD, NOW_MS + 5 * PERIOD),
        (2_900_000_000_000_000_000, 0, 1),
    ] {
        let f = NameFields::new(b"alice", &[3; 32], price, start, exp);
        let name = abi_encode(
            &kit.name,
            BTreeMap::from([
                ("key".into(), b(&f.key)),
                ("name".into(), b(&f.name)),
                ("owner".into(), b(&f.owner)),
                ("price".into(), i(price)),
                ("periodStart".into(), i(start)),
                ("expiresAt".into(), i(exp)),
            ]),
        );
        assert_eq!(name, f.encode());
        assert_eq!(name.len(), 126);
        assert_eq!(name.len(), NAME_STATE_LEN);
        let c = &kit.name.abi.contracts[&kit.name.contract];
        let back = decode_runtime_state_script(&kit.name.abi, &c.runtime_state, &name).unwrap();
        assert_eq!(back["price"], i(price));
        assert_eq!(back["periodStart"], i(start));
        assert_eq!(back["expiresAt"], i(exp));
        // periodStart sits between price and expiresAt: 0x08 price @99, 0x08 periodStart @108, 0x08 expiresAt @117
        assert_eq!((name[99], name[108], name[117]), (0x08, 0x08, 0x08));
        assert_eq!(name[109..117], num8(start));
        assert_eq!(name[118..126], num8(exp));
    }

    let offer = abi_encode(
        &kit.offer,
        BTreeMap::from([
            ("key".into(), b(&[4; 32])),
            ("buyer".into(), b(&[5; 32])),
            ("seller".into(), b(&[6; 32])),
            ("refundAfter".into(), i(600_000_000)),
        ]),
    );
    assert_eq!(offer, offer_state(&[4; 32], &[5; 32], &[6; 32], 600_000_000));
    assert_eq!(offer.len(), 108);

    for prices in [[0u64; 5], [4_000_000_000, 2_000_000_000, 1_000_000_000, 250_000_000, 35_000_000], [100_000_000_000_000_000; 5]] {
        let price = abi_encode(
            &kit.price,
            BTreeMap::from([
                ("shard".into(), i(7)),
                ("authority".into(), b(&[9; 32])),
                ("p1".into(), i(prices[0] as i64)),
                ("p2".into(), i(prices[1] as i64)),
                ("p3".into(), i(prices[2] as i64)),
                ("p4".into(), i(prices[3] as i64)),
                ("p5".into(), i(prices[4] as i64)),
            ]),
        );
        assert_eq!(price, price_state(7, &[9; 32], &prices));
        assert_eq!(price.len(), PRICE_STATE_LEN);
    }
}

#[test]
fn state_spans_are_where_the_app_splices() {
    let kit = Kit::new();
    for (t, len) in [(&kit.name, 126), (&kit.gap, 66), (&kit.offer, 108), (&kit.price, 87)] {
        let span = t.abi.contracts[&t.contract].compiled.state_span;
        assert_eq!(span.offset, 1, "{}", t.contract);
        assert_eq!(span.len, len, "{}", t.contract);
        assert_eq!(t.prefix, vec![0x6b], "{}", t.contract); // OP_TOALTSTACK
    }
}

#[test]
fn commit_script_is_a_plain_owner_spend() {
    // The commit UTXO is spendable by the owner alone, through the ordinary
    // P2SH path, whether or not it is ever used to register.
    let kit = Kit::new();
    let owner = keypair(1);
    let ox = xonly(&owner);
    let redeem = commit_redeem(&commitment(b"alice", &ox, &[1; 32]), &ox);
    assert_eq!(redeem.len(), 68);
    let utxo = Utxo::new(
        TransactionOutpoint::new(TransactionId::from_bytes([91; 32]), 0),
        UtxoEntry::new(COMMIT_VALUE, kaspa_txscript::pay_to_script_hash_script(&redeem), COMMIT_DAA, false, None),
    );
    let spec = TxSpec {
        inputs: vec![Input::new(utxo.clone(), Unlock::Commit { redeem: redeem.clone(), key: owner })],
        outputs: vec![TransactionOutput::new(COMMIT_VALUE - NET_FEE, p2pk_spk(&ox))],
        lock_time: 0,
    };
    ok(&kit, &spec, active_block());
    let spec = TxSpec {
        inputs: vec![Input::new(utxo, Unlock::Commit { redeem, key: keypair(9) })],
        outputs: vec![TransactionOutput::new(COMMIT_VALUE - NET_FEE, p2pk_spk(&ox))],
        lock_time: 0,
    };
    rejected(&kit, &spec, active_block());
}

#[test]
fn dispatch_tags_are_stable() {
    // A rename or a parameter type change orphans deployed UTXOs; pin the tags.
    let kit = Kit::new();
    let tags: Vec<(String, String)> = [
        (&kit.gap, "register"),
        (&kit.gap, "merge"),
        (&kit.gap, "absorbed"),
        (&kit.name, "transfer"),
        (&kit.name, "list"),
        (&kit.name, "buy"),
        (&kit.name, "extend"),
        (&kit.name, "renew"),
        (&kit.name, "release"),
        (&kit.name, "reclaim"),
        (&kit.offer, "accept"),
        (&kit.offer, "withdraw"),
        (&kit.offer, "refund"),
        (&kit.offer, "decline"),
        (&kit.price, "use"),
        (&kit.price, "update"),
        (&kit.price, "follow"),
    ]
    .iter()
    .map(|(t, e)| (format!("{}.{}", t.contract, e), t.dispatch_tag(e)))
    .collect();
    for (e, tag) in &tags {
        let sig = match e.as_str() {
            "KachatGap.register" => "register(byte[],byte[32],byte[32],int,int,byte[],byte[],int)",
            "KachatGap.merge" => "merge()",
            "KachatGap.absorbed" => "absorbed()",
            "KachatName.transfer" => "transfer(byte[32],sig)",
            "KachatName.list" => "list(int,sig)",
            "KachatName.buy" => "buy(byte[32])",
            "KachatName.extend" => "extend(int,int)",
            "KachatName.renew" => "renew(int,int)",
            "KachatName.release" => "release(sig)",
            "KachatName.reclaim" => "reclaim()",
            "KachatOffer.accept" => "accept(int,sig)",
            "KachatOffer.withdraw" => "withdraw(sig)",
            "KachatOffer.refund" => "refund()",
            "KachatOffer.decline" => "decline(sig)",
            "KachatPrice.use" => "use()",
            "KachatPrice.update" => "update(byte[32],int,int,int,int,int,sig)",
            "KachatPrice.follow" => "follow()",
            _ => unreachable!(),
        };
        let expect = faster_hex::hex_string(&blake3::hash(sig.as_bytes()).as_bytes()[..4]);
        assert_eq!(tag, &expect, "{e}");
    }
}
