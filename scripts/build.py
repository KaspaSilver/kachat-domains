#!/usr/bin/env python3
"""Compile the .kachat contracts (registry v4) for one network with the pinned silverc.

usage: build.py <silverc> <params.json> <out_dir>

Order (no template-hash cycles):
  1. KachatName   (bakes: bond, maxYears, graceMs, renewWindowMs, periodMs, the renew table)
  2. KachatGap    (bakes: name template, bond, gapValue, tCommit, maxYears, periodMs,
                   the register and renew tables)
     -- the registry genesis mints the registry covenant -> params.registryCovenantId
  3. KachatOffer  (bakes: registry covenant id, name template, offerMaxFee)

Writes <out_dir>/KachatName.json, KachatGap.json, [KachatOffer.json], build-info.json.
"""
import hashlib, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ZERO32 = [0] * 32


def I(v):
    return {"kind": "int", "value": v}


def B(v):
    return {"kind": "bytes", "value": list(v)}


def compile_contract(silverc, source, ctor, out_path):
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(ctor, f)
        ctor_path = f.name
    try:
        subprocess.run([silverc, source, '--constructor-args', ctor_path, '-o', out_path], check=True)
    finally:
        os.unlink(ctor_path)
    art = json.load(open(out_path))
    (name, contract), = art['contracts'].items()
    return contract


def layout(contract):
    bc = contract['compiled']['bytecode']
    span = contract['compiled']['state_span']
    prefix_len = span['offset']
    suffix_len = len(bc) - span['offset'] - span['len']
    return {
        'bytecodeLen': len(bc),
        'stateSpan': span,
        'prefixLen': prefix_len,
        'suffixLen': suffix_len,
        'templateHash': bytes(contract['compiled']['template_hash']).hex(),
        'dispatchTags': {k: v['dispatch_tag'] for k, v in contract['entries'].items()},
        'bytecodeSha256': hashlib.sha256(bytes(bc)).hexdigest(),
    }


def cov_id(p, key):
    cov = p.get(key)
    if not cov:
        return None
    b = bytes.fromhex(cov)
    if len(b) != 32 or b == bytes(32):
        sys.exit(f'{key} must be 32 non-zero bytes')
    return b


def main():
    silverc, params_path, out_dir = sys.argv[1:4]
    p = json.load(open(params_path))
    os.makedirs(out_dir, exist_ok=True)
    src = lambda n: os.path.join(ROOT, 'contracts', n + '.sil')
    version = p.get('registryVersion')
    if version not in (4, 5):
        sys.exit('params are not registry v4 or v5 (registryVersion)')
    # registry v5: the gap with `import` (contracts/v5/KachatGap.sil) bakes the migration
    mig = p.get('migration') if version == 5 else None
    if version == 5:
        if not mig:
            sys.exit('registry v5 params need a migration block (use root 00..00 and deadlineMs 0 for none)')
        for k in ('root', 'sponsor'):
            if len(bytes.fromhex(mig[k])) != 32:
                sys.exit(f'migration.{k} must be 32 bytes')
        if not 0 <= mig['deadlineMs'] < 1_000_000_000_000_000:
            sys.exit('migration.deadlineMs out of range')
    if not 1 <= p['maxYears'] <= 31:
        sys.exit('maxYears must be 1..31')
    if not 60_000 <= p['periodMs'] <= 31_536_000_000:
        sys.exit('periodMs must be between a minute and a year')
    if p['maxYears'] * p['periodMs'] >= 1_000_000_000_000:
        sys.exit('maxYears * periodMs must stay under 1e12 ms (the reclaim range check)')
    # A window longer than a period would let renew run again right after itself and prepay
    # past maxYears periods; equal is safe (the next window opens at the old expiry).
    if not 0 < p['renewWindowMs'] <= p['periodMs']:
        sys.exit('renewWindowMs must be more than 0 and at most periodMs')
    if not 0 < p['graceMs'] < 1_000_000_000_000:
        sys.exit('graceMs out of range')
    tiers = ('len1', 'len2', 'len3', 'len4', 'len5plus')
    for table in ('register', 'renew'):
        for k in tiers:
            v = p['prices'][table][k]
            # 32 periods of the largest price stay far inside a script integer (register sums
            # reg + renew * (years - 1)).
            if not 0 <= v <= 100_000_000_000_000_000:
                sys.exit(f'prices.{table}.{k} out of range (0..1e17 sompi)')
    reg = [I(p['prices']['register'][k]) for k in tiers]
    ren = [I(p['prices']['renew'][k]) for k in tiers]

    info = {
        'network': p['network'],
        'registryVersion': version,
        'compiler': p['compiler'],
        'params': {k: p[k] for k in ('bond', 'gapValue', 'tCommit', 'maxYears', 'periodMs', 'graceMs', 'renewWindowMs',
                                     'prices', 'offerMaxFee', 'genesisGap')},
        'registryCovenantId': p.get('registryCovenantId'),
        'contracts': {},
    }
    if mig:
        info['migration'] = mig

    name = compile_contract(silverc, src('KachatName'), [
        B(ZERO32), B(ZERO32), B(ZERO32), I(0), I(0), I(0),
        I(p['bond']), I(p['maxYears']), I(p['graceMs']), I(p['renewWindowMs']), I(p['periodMs']),
    ] + ren, os.path.join(out_dir, 'KachatName.json'))
    nl = layout(name)
    gap_source = os.path.join(ROOT, 'contracts', 'v5', 'KachatGap.sil') if version == 5 else src('KachatGap')
    migration_args = [B(bytes.fromhex(mig['root'])), I(mig['deadlineMs']), B(bytes.fromhex(mig['sponsor']))] if version == 5 else []
    gap = compile_contract(silverc, gap_source, [
        B(bytes.fromhex(p['genesisGap']['lo'])), B(bytes.fromhex(p['genesisGap']['hi'])),
        B(bytes.fromhex(nl['templateHash'])), I(nl['prefixLen']), I(nl['suffixLen']),
        I(p['bond']), I(p['gapValue']), I(p['tCommit']), I(p['maxYears']), I(p['periodMs']),
    ] + reg + ren + migration_args, os.path.join(out_dir, 'KachatGap.json'))
    gl = layout(gap)
    info['contracts'].update({'KachatName': nl, 'KachatGap': gl})
    summary = [f"name {nl['bytecodeLen']} B", f"gap {gl['bytecodeLen']} B"]

    reg_cov = cov_id(p, 'registryCovenantId')
    if reg_cov:
        offer = compile_contract(silverc, src('KachatOffer'), [
            B(ZERO32), B(ZERO32), B(ZERO32), I(0), B(reg_cov),
            B(bytes.fromhex(nl['templateHash'])), I(nl['prefixLen']), I(nl['suffixLen']),
            I(p['offerMaxFee']),
        ], os.path.join(out_dir, 'KachatOffer.json'))
        info['contracts']['KachatOffer'] = layout(offer)
        summary.append(f"offer {info['contracts']['KachatOffer']['bytecodeLen']} B")
    else:
        path = os.path.join(out_dir, 'KachatOffer.json')
        if os.path.exists(path):
            os.unlink(path)
        info['contracts']['KachatOffer'] = 'not built: set registryCovenantId after the registry genesis'
        summary.append('offer pending the registry genesis')
    # registry v4 has no price record
    stale = os.path.join(out_dir, 'KachatPrice.json')
    if os.path.exists(stale):
        os.unlink(stale)

    with open(os.path.join(out_dir, 'build-info.json'), 'w') as f:
        json.dump(info, f, indent=2)
        f.write('\n')
    print(f"{p['network']}: " + ', '.join(summary))


if __name__ == '__main__':
    main()
