//! Amounts, hex, outpoints and a push-only script parser.

use anyhow::{Result, anyhow, bail};
use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint};

use crate::net::net;

pub const SOMPI: u64 = 100_000_000;

/// "12.5" (TKAS) -> sompi. At most 8 decimals.
pub fn parse_kas(s: &str) -> Result<u64> {
    let s = s.trim().trim_end_matches(net().ticker).trim_end_matches("KAS").trim();
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    if int.is_empty() && frac.is_empty() || frac.len() > 8 || !int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()) {
        bail!("bad amount {s:?} (use e.g. 12.5)");
    }
    let i: u64 = if int.is_empty() { 0 } else { int.parse()? };
    let f: u64 = if frac.is_empty() { 0 } else { format!("{frac:0<8}").parse()? };
    i.checked_mul(SOMPI).and_then(|v| v.checked_add(f)).ok_or_else(|| anyhow!("amount overflow"))
}

pub fn fmt_kas(sompi: u64) -> String {
    format!("{}.{:08} {}", sompi / SOMPI, sompi % SOMPI, net().ticker)
}

pub fn fmt_kas_signed(v: i64) -> String {
    if v < 0 { format!("-{}", fmt_kas(v.unsigned_abs())) } else { fmt_kas(v as u64) }
}

pub fn hex(b: &[u8]) -> String {
    faster_hex::hex_string(b)
}

pub fn unhex32(s: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    if s.len() != 64 {
        bail!("expected 32 hex bytes, got {s:?}");
    }
    faster_hex::hex_decode(s.as_bytes(), &mut out).map_err(|e| anyhow!("{s}: {e}"))?;
    Ok(out)
}

pub fn fmt_outpoint(o: &TransactionOutpoint) -> String {
    format!("{}:{}", o.transaction_id, o.index)
}

pub fn parse_outpoint(s: &str) -> Result<TransactionOutpoint> {
    let (id, idx) = s.split_once(':').ok_or_else(|| anyhow!("outpoint must be <txid>:<index>"))?;
    Ok(TransactionOutpoint::new(TransactionId::from_bytes(unhex32(id)?), idx.parse()?))
}

/// Unix ms -> "2026-10-01 12:34:56 UTC".
pub fn fmt_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", tod / 3600, (tod % 3600) / 60, tod % 60)
}

/// A duration for humans: "10 min", "2.0 h", "10.0 days", "1.0 years".
pub fn fmt_dur(ms: i64) -> String {
    let m = ms.unsigned_abs() as f64;
    let sign = if ms < 0 { "-" } else { "" };
    if m < 3_600_000.0 {
        format!("{sign}{:.0} min", m / 60_000.0)
    } else if m < 86_400_000.0 {
        format!("{sign}{:.1} h", m / 3_600_000.0)
    } else if m < 31_536_000_000.0 {
        format!("{sign}{:.1} days", m / 86_400_000.0)
    } else {
        format!("{sign}{:.1} years", m / 31_536_000_000.0)
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

// ---------------------------------------------------------------------------
// push-only scripts (signature scripts of P2SH spends)
// ---------------------------------------------------------------------------

/// Every push of a push-only script, as bytes: OP_0 -> [], OP_1..OP_16 -> [n],
/// OP_1NEGATE -> [0x81], data pushes -> data. (ScriptBuilder::add_data and
/// add_i64 both emit the small-number opcodes, so this matches either.)
pub fn parse_pushes(script: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let take = |i: &mut usize, n: usize| -> Result<Vec<u8>> {
        if *i + n > script.len() {
            bail!("truncated push");
        }
        let v = script[*i..*i + n].to_vec();
        *i += n;
        Ok(v)
    };
    while i < script.len() {
        let op = script[i];
        i += 1;
        let item = match op {
            0x00 => vec![],
            0x01..=0x4b => take(&mut i, op as usize)?,
            0x4c => {
                let n = take(&mut i, 1)?[0] as usize;
                take(&mut i, n)?
            }
            0x4d => {
                let b = take(&mut i, 2)?;
                take(&mut i, u16::from_le_bytes([b[0], b[1]]) as usize)?
            }
            0x4e => {
                let b = take(&mut i, 4)?;
                take(&mut i, u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)?
            }
            0x4f => vec![0x81],
            0x51..=0x60 => vec![op - 0x50],
            _ => bail!("not a push-only script (opcode 0x{op:02x})"),
        };
        out.push(item);
    }
    Ok(out)
}

/// Minimal script number (little-endian sign-magnitude) -> i64.
pub fn script_num(b: &[u8]) -> Result<i64> {
    if b.is_empty() {
        return Ok(0);
    }
    if b.len() > 8 {
        bail!("script number longer than 8 bytes");
    }
    let mut v: u64 = 0;
    for (k, byte) in b.iter().enumerate() {
        let byte = if k == b.len() - 1 { byte & 0x7f } else { *byte };
        v |= (byte as u64) << (8 * k);
    }
    let neg = b[b.len() - 1] & 0x80 != 0;
    let v = v as i64;
    Ok(if neg { -v } else { v })
}

/// Decode an 8-byte state int (`num8` in the harness).
pub fn num8_decode(b: &[u8]) -> Result<i64> {
    if b.len() != 8 {
        bail!("state int must be 8 bytes");
    }
    script_num(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(parse_kas("35").unwrap(), 35 * SOMPI);
        assert_eq!(parse_kas("0.2").unwrap(), 20_000_000);
        assert_eq!(parse_kas("1.00000001").unwrap(), SOMPI + 1);
        assert!(parse_kas("1.000000001").is_err());
        assert!(parse_kas("-1").is_err());
        assert_eq!(fmt_kas(123_456_789), "1.23456789 TKAS");
    }

    #[test]
    fn script_numbers_round_trip() {
        use kachat_names_harness::num8;
        for v in [0i64, 1, 16, 17, 255, 256, -1, -255, 1_790_000_000_000, 31_536_000_000 * 2] {
            assert_eq!(num8_decode(&num8(v)).unwrap(), v);
        }
    }

    #[test]
    fn dates() {
        assert_eq!(fmt_ms(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_ms(1_790_000_000_000), "2026-09-21 14:13:20 UTC");
    }
}
