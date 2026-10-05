#!/usr/bin/env bash
# Mutation check: delete (or weaken) one security check at a time, rebuild the
# artifacts, run the engine-backed suite, and report which tests catch it.
# A mutation nobody catches is either redundant (defense in depth, labelled
# "redundant" below, with what covers it) or a hole in the tests. Restores contracts/ and artifacts/ after
# each mutation. Usage: scripts/mutation-check.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ -n "$(git status --porcelain contracts artifacts)" ]]; then
  echo "contracts/ or artifacts/ have uncommitted changes; commit first" >&2; exit 1
fi

mutate() { # file old new label
  python3 - "$1" "$2" "$3" <<'PY'
import sys
f, old, new = sys.argv[1:4]
s = open(f).read()
assert old in s, f"not found in {f}: {old}"
open(f, 'w').write(s.replace(old, new, 1))
PY
  ./scripts/build.sh >/dev/null 2>&1 || { echo "  $4: BUILD FAILED"; git checkout -q -- contracts artifacts; return; }
  local out killed
  out="$(cd harness && cargo test --release --offline --no-fail-fast 2>/dev/null)"
  killed="$(grep -E '^test .* FAILED$' <<<"$out" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/' | tr '\n' ' ')"
  if [[ -z "$killed" ]]; then echo "SURVIVED  $4"; else echo "killed    $4  <- $killed"; fi
  git checkout -q -- contracts artifacts
}

G=contracts/KachatGap.sil; N=contracts/KachatName.sil; O=contracts/KachatOffer.sil; P=contracts/KachatPrice.sil
mutate $G 'require(relativeLock >= tCommit, "commit matured");' '' "gap: commit maturity"
mutate $G 'require(unsigned(seq[7]) < 128, "commit sequence lock enabled");' '' "gap: sequence-lock disable bit"
mutate $G 'require(tx.inputs[1].scriptPubKey == byte[](commitLock), "commit script");' '' "gap: commit script"
mutate $G 'require(tx.time >= temporal(now));' '' "gap: now <= lock time"
mutate $G 'require(years <= maxYears, "years <= maxYears");' '' "gap: max years"
mutate $G 'require(minerFee() >= priceFor(priceIdx, len) * years, "price paid as miner fee");' 'require(minerFee() >= priceFor(priceIdx, len), "price paid as miner fee");' "gap: price x years"
mutate $G 'require(minerFee() >= priceFor(priceIdx, len) * years, "price paid as miner fee");' '' "gap: price paid at all"
mutate $G 'require(OpInputCovenantId(priceIdx) == priceCovId, "price record");' '' "gap: the price shard is a real shard (price covenant id)"
mutate $G 'require(priceIdx >= 0, "price index");' '' "gap: price index >= 0 (redundant: introspection of a negative index fails)"
mutate $G 'require(priceIdx < tx.inputs.length, "price index");' '' "gap: price index in range (redundant: introspection out of range fails)"
mutate $G 'int p = ps.p5;
        if (len == 1) {
            p = ps.p1;' 'int p = ps.p5;
        if (len == 1) {
            p = ps.p5;' "gap: 1-char tier"
mutate $G 'require(lessThan(lo, newKey), "lo < key");' '' "gap: lo < key"
mutate $G 'require(lessThan(newKey, hi), "key < hi");' '' "gap: key < hi"
mutate $G 'require(charset[unsigned(n[i])] == 0x01, "name charset");' '' "gap: charset"
mutate $G 'require(n[0] != 0x2d, "no leading hyphen");' '' "gap: leading hyphen"
mutate $G 'require(n[n.length - 1] != 0x2d, "no trailing hyphen");' '' "gap: trailing hyphen"
mutate $G 'require(OpCovOutputCount(covId) == 3, "three registry outputs");' '' "gap: register output count (redundant with AuthOutputCount(0) == 3 + one registry input)"
mutate $G 'require(tx.outputs[2].value == bond, "name bond");' '' "gap: name bond value"
mutate $G 'require(tx.inputs.length <= MAX_INPUTS, "at most 8 inputs");' '' "gap: input bound (redundant with the compiler loop guard, which TUTORIAL.md says not to rely on)"
mutate $G 'price: 0, periodStart: now, expiresAt: expiry' 'price: 0, periodStart: now - 1, expiresAt: expiry' "gap: register periodStart = now"
mutate $G 'require(seated.key == hi, "name at hi");' '' "gap: merge name adjacency"
mutate $G 'require(succ.lo == hi, "successor starts at hi");' '' "gap: merge successor adjacency"
mutate $G 'require(tx.outputs[0].value == gapValue, "merged gap value");' '' "gap: merged gap value"
mutate $N 'return raw[64] == 0x01 && checkSig' 'return checkSig' "name: SIGHASH_ALL only"
mutate $N 'require(OpCovInputCount(covId) == 1, "one registry input");' '' "name: one registry input (redundant with one registry output; the pair is tested below)"
mutate $N 'require(OpCovOutputCount(covId) == 1, "one registry output");' '' "name: one registry output (redundant with one registry input + one continuation)"
mutate $N 'require(OpCovInputCount(covId) == 1, "one registry input");
        require(OpCovOutputCount(covId) == 1, "one registry output");' '' "name: one registry input AND one registry output (both removed)"
mutate $N 'require(tx.outputs[out].value == bond, "continuation keeps the bond");' '' "name: continuation value"
mutate $N 'require(tx.outputs[payout].value >= price, "payout covers the price");' '' "name: buy payout value"
mutate $N 'require(tx.outputs[payout].scriptPubKey == byte[](sellerLock), "payout to the seller");' '' "name: buy payout script"
# extend (its checks come first in the file, so a first-occurrence match is extend's)
mutate $N 'require(years >= 1, "years >= 1");' '' "name: extend years >= 1"
mutate $N 'require(years <= maxYears, "years <= maxYears");' '' "name: extend max years"
mutate $N 'require(expiresAt <= MAX_EXPIRES_AT, "expiry cap");' '' "name: extend expiry cap"
mutate $N 'require(newExpiry <= periodStart + maxYears * periodMs, "at most maxYears past periodStart");' '' "name: extend period cap"
mutate $N 'require(newExpiry <= periodStart + maxYears * periodMs, "at most maxYears past periodStart");' 'require(newExpiry <= periodStart + maxYears * periodMs + 1, "at most maxYears past periodStart");' "name: extend period cap off by one ms"
mutate $N 'require(minerFee() >= renewPrice(priceIdx) * years, "extension paid as miner fee");' 'require(minerFee() >= renewPrice(priceIdx), "extension paid as miner fee");' "name: extend price x years"
mutate $N 'require(minerFee() >= renewPrice(priceIdx) * years, "extension paid as miner fee");' '' "name: extend paid at all"
mutate $N 'periodStart: periodStart, expiresAt: newExpiry' 'periodStart: expiresAt, expiresAt: newExpiry' "name: extend keeps periodStart"
# renew (multi-line context: the lines right before its time lock)
mutate $N 'require(years >= 1, "years >= 1");
        require(years <= maxYears, "years <= maxYears");
        require(expiresAt <= MAX_EXPIRES_AT, "expiry cap");
        require(tx.time' 'require(years <= maxYears, "years <= maxYears");
        require(expiresAt <= MAX_EXPIRES_AT, "expiry cap");
        require(tx.time' "name: renew years >= 1"
mutate $N 'require(years <= maxYears, "years <= maxYears");
        require(expiresAt <= MAX_EXPIRES_AT, "expiry cap");
        require(tx.time' 'require(expiresAt <= MAX_EXPIRES_AT, "expiry cap");
        require(tx.time' "name: renew max years"
mutate $N 'require(expiresAt <= MAX_EXPIRES_AT, "expiry cap");
        require(tx.time' 'require(tx.time' "name: renew expiry cap"
mutate $N 'require(tx.time >= temporal(expiresAt - renewWindowMs));' '' "name: renew window (time lock)"
mutate $N 'require(tx.time >= temporal(expiresAt - renewWindowMs));' 'require(tx.time >= temporal(expiresAt - renewWindowMs - 1));' "name: renew window off by one ms"
mutate $N 'require(minerFee() >= renewPrice(priceIdx) * years, "renewal paid as miner fee");' 'require(minerFee() >= renewPrice(priceIdx), "renewal paid as miner fee");' "name: renew price x years"
mutate $N 'require(minerFee() >= renewPrice(priceIdx) * years, "renewal paid as miner fee");' '' "name: renew paid at all"
mutate $N 'periodStart: expiresAt, expiresAt: expiresAt + years * periodMs' 'periodStart: periodStart, expiresAt: expiresAt + years * periodMs' "name: renew starts the period at the old expiry"
# the period travels unchanged through transfer, list, buy
mutate $N 'owner: newOwner, price: 0, periodStart: periodStart' 'owner: newOwner, price: 0, periodStart: expiresAt' "name: transfer keeps periodStart"
mutate $N 'price: newPrice, periodStart: periodStart' 'price: newPrice, periodStart: expiresAt' "name: list keeps periodStart"
mutate $N 'require(tx.outputs[payout].value >= price, "payout covers the price");
        validateOutputState(out, State { key: key, name: name, owner: newOwner, price: 0, periodStart: periodStart' 'require(tx.outputs[payout].value >= price, "payout covers the price");
        validateOutputState(out, State { key: key, name: name, owner: newOwner, price: 0, periodStart: expiresAt' "name: buy keeps periodStart"
mutate $N 'require(tx.time >= temporal(expiresAt + graceMs));' '' "name: reclaim after grace"
mutate $N 'require(tx.outputs[1].scriptPubKey == byte[](ownerLock), "bond to the last owner");' '' "name: reclaim bond script"
mutate $N 'require(tx.outputs[1].value >= bond, "bond returned");' '' "name: reclaim bond value"
mutate $N 'require(this.activeInputIndex == 1, "seat 1");' '' "name: exit seat"
mutate $N 'require(OpInputCovenantId(priceIdx) == priceCovId, "price record");' '' "name: the price shard is a real shard (price covenant id)"
mutate $O 'require(this.activeInputIndex == nameIdx + 1, "offer right after its name");' '' "offer: adjacency"
mutate $O 'require(OpInputCovenantId(nameIdx) == registryCovId, "registry name");' '' "offer: registry id"
mutate $O 'require(cur.key == key, "the wanted name");' '' "offer: wanted key (redundant: the continuation is validated with key = the offer key)"
mutate $O 'require(tx.outputs[payout].value >= tx.inputs[this.activeInputIndex].value - maxFee, "payout covers the offer");' '' "offer: accept payout value"
mutate $O 'periodStart: cur.periodStart' 'periodStart: cur.expiresAt' "offer: accept keeps periodStart"
mutate $O 'require(tx.daa >= refundAfter);' '' "offer: refund after"
mutate $O 'require(tx.inputs.length == 1, "refund alone");' '' "offer: refund alone"
mutate $O 'require(tx.outputs[0].scriptPubKey == byte[](buyerLock), "refund to the buyer");' '' "offer: refund script"
# registry v3: offers are bound to the seller
mutate $O 'return raw[64] == 0x01 && checkSig(s, pubkey(seller));' 'return checkSig(s, pubkey(seller));' "offer: seller SIGHASH_ALL only"
mutate $O 'entry accept(int nameIdx, sig sellerSig) {
        require(sellerSigned(sellerSig), "seller signature");' 'entry accept(int nameIdx, sig sellerSig) {' "offer: accept needs the seller"
mutate $O 'require(cur.owner == seller, "still the seller'"'"'s");' '' "offer: accept only while the seller owns the name"
mutate $O 'entry decline(sig sellerSig) {
        require(sellerSigned(sellerSig), "seller signature");' 'entry decline(sig sellerSig) {' "offer: decline needs the seller"
mutate $O 'require(tx.inputs.length == 1, "decline alone");' '' "offer: decline alone"
mutate $O 'require(tx.outputs.length == 1, "one return output");' '' "offer: decline one output"
mutate $O 'require(tx.outputs[0].scriptPubKey == byte[](buyerLock), "back to the buyer");' '' "offer: decline to the buyer"
mutate $O 'require(tx.outputs[0].value >= tx.inputs[0].value - maxFee, "return covers the offer");' '' "offer: decline value"
# registry v3: the price record
mutate $P 'return raw[64] == 0x01 && checkSig' 'return checkSig' "price: SIGHASH_ALL only"
mutate $P 'require(authoritySigned(authoritySig), "authority signature");' '' "price: authority signs a change"
mutate $P 'require(shard == 0, "shard 0 leads");' '' "price: shard 0 leads"
mutate $P 'require(shard != 0, "shard 0 leads");' '' "price: followers are not shard 0"
mutate $P 'require(p >= 0, "price >= 0");' '' "price: price >= 0"
mutate $P 'require(p <= MAX_PRICE, "price cap");' '' "price: price cap"
mutate $P 'validPrice(n3);' '' "price: tier 3 validated"
mutate $P 'require(newAuthority != byte[32](0x0000000000000000000000000000000000000000000000000000000000000000), "authority key");' '' "price: authority not zero"
mutate $P 'require(OpCovInputCount(covId) == shards, "every shard");' '' "price: every shard is an input"
mutate $P 'require(OpCovOutputCount(covId) == shards, "every shard continues");' '' "price: every shard continues"
mutate $P 'require(OpCovInputIdx(covId, shard) == this.activeInputIndex, "shards in order");' '' "price: shards in order"
mutate $P 'require(OpAuthOutputCount(this.activeInputIndex) == 1, "one continuation");
        require(OpAuthOutputIdx' 'require(OpAuthOutputIdx' "price: a change continues each shard once"
mutate $P 'require(OpAuthOutputIdx(this.activeInputIndex, 0) == OpCovOutputIdx(covId, shard), "continuations in order");' '' "price: continuations in order"
mutate $P 'require(OpCovInputCount(covId) == 1, "one price input");' '' "price: use reads one shard"
mutate $P 'require(OpCovOutputCount(covId) == 1, "one price output");' '' "price: use mints no extra shard"
mutate $P 'require(OpAuthOutputCount(this.activeInputIndex) == 1, "one continuation");
        int out' 'int out' "price: use has one continuation (redundant with one price output)"
mutate $P 'require(tx.outputs[out].value == priceValue, "shard value");
        validateOutputState(out, State { shard: shard' 'validateOutputState(out, State { shard: shard' "price: use keeps the shard value"
mutate $P 'require(tx.outputs[out].value == priceValue, "shard value");
            validateOutputState(out, State { shard: j' 'validateOutputState(out, State { shard: j' "price: a change keeps every shard value"
mutate $P 'State { shard: j, authority: newAuthority' 'State { shard: shard, authority: newAuthority' "price: a change keeps each shard number"
