//! The dry-run summary printed for every transaction.

use std::fmt::Write;

use kaspa_consensus_core::constants::LOCK_TIME_THRESHOLD;

use crate::{
    net::spk_address,
    ops::{MIN_FEERATE, Plan},
    util::{fmt_kas, fmt_ms, fmt_outpoint},
};

pub fn render(plan: &Plan, submit: bool) -> String {
    let tx = &plan.built.tx;
    let c = &plan.costs;
    let mut s = String::new();
    let mode = if submit { "SUBMIT" } else { "dry run" };
    let _ = writeln!(s, "== {} ({mode}) ==", plan.op);
    let _ = writeln!(s, "tx id      {}", tx.id());
    let lock = if tx.lock_time == 0 {
        "0 (none)".to_string()
    } else if tx.lock_time < LOCK_TIME_THRESHOLD {
        format!("{} (DAA score)", tx.lock_time)
    } else {
        format!("{} (unix ms, {})", tx.lock_time, fmt_ms(tx.lock_time as i64))
    };
    let _ = writeln!(s, "version    {}   lock time {lock}   payload {} B", tx.version, tx.payload.len());
    let _ = writeln!(s, "inputs ({}):", tx.inputs.len());
    for (i, input) in tx.inputs.iter().enumerate() {
        let e = &plan.built.entries[i];
        let budget = input.compute_commit.compute_budget().unwrap_or(0);
        let used = plan.built.used_units[i].map(|u| format!("{u} units")).unwrap_or_else(|| "FAILS".into());
        let _ = writeln!(
            s,
            "  #{i} {:<44} {}  {:>22}  seq {:<4} budget {budget:>2} ({used})  utxo DAA {}{}",
            plan.input_labels.get(i).map(String::as_str).unwrap_or(""),
            fmt_outpoint(&input.previous_outpoint),
            fmt_kas(e.amount),
            input.sequence,
            e.block_daa_score,
            if e.covenant_id.is_some() { "  [registry]" } else { "" }
        );
    }
    let _ = writeln!(s, "outputs ({}):", tx.outputs.len());
    for (i, o) in tx.outputs.iter().enumerate() {
        let cov = o
            .covenant
            .map(|b| format!("  covenant {}.. authorized by input {}", &b.covenant_id.to_string()[..16], b.authorizing_input))
            .unwrap_or_default();
        let addr = spk_address(&o.script_public_key).map(|a| a.to_string()).unwrap_or_else(|_| "non-standard".into());
        let _ = writeln!(s, "  #{i} {:<44} {:>22}  {addr}{cov}", plan.output_labels.get(i).map(String::as_str).unwrap_or(""), fmt_kas(o.value));
    }
    let total_in: u64 = plan.built.entries.iter().map(|e| e.amount).sum();
    let total_out: u64 = tx.outputs.iter().map(|o| o.value).sum();
    let fee_mass = c.compute_mass.max(c.normalized_transient);
    let _ = writeln!(
        s,
        "fee        {} = price {} + network {}   (in {} - out {})",
        fmt_kas(total_in - total_out),
        fmt_kas(plan.price_fee),
        fmt_kas(plan.network_fee),
        fmt_kas(total_in),
        fmt_kas(total_out)
    );
    let _ = writeln!(
        s,
        "mass       size {} B, compute {} g, transient {} g (normalized {}), storage {} g; relay floor {} ({} sompi/g x {fee_mass} g)",
        c.size,
        c.compute_mass,
        c.transient_mass,
        c.normalized_transient,
        c.storage_mass,
        fmt_kas((fee_mass as f64 * MIN_FEERATE) as u64),
        MIN_FEERATE
    );
    let _ = writeln!(s, "budgets    {:?} (compute budget units per input; 1 unit = 10,000 script units)", c.budgets);
    let _ = writeln!(
        s,
        "validated  at DAA {} / median time {}: {}",
        plan.block.daa,
        fmt_ms(plan.block.time_ms as i64),
        match &plan.validation {
            Ok(_) => "OK (rusty-kaspa TransactionValidator: isolation + header finality + UTXO context, Full flags)".to_string(),
            Err(e) => format!("REJECTED: {e}"),
        }
    );
    let _ = writeln!(
        s,
        "standard   {}",
        match &plan.standard {
            Ok(()) => "OK (P2SH sig-op scan <= 15, standard outputs)".to_string(),
            Err(e) => format!("NON-STANDARD: {e}"),
        }
    );
    for n in &plan.notes {
        let _ = writeln!(s, "note       {n}");
    }
    s
}
