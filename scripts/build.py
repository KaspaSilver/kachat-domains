#!/usr/bin/env python3
"""Compile the .kachat contracts (registry v3) for one network with the pinned silverc.

usage: build.py <silverc> <params.json> <out_dir>

Order (no template-hash cycles), each stage only once its covenant id exists:
  1. KachatPrice  (bakes: priceShards, priceValue) - always
     -- the price genesis mints the price covenant -> params.priceCovenantId
  2. KachatName   (bakes: bond, maxYears, graceMs, renewWindowMs, periodMs, price covenant)
  3. KachatGap    (bakes: name template, bond, gapValue, tCommit, maxYears, periodMs, price covenant)
     -- the registry genesis mints the registry covenant -> params.registryCovenantId
  4. KachatOffer  (bakes: registry covenant id, name template, offerMaxFee)

Writes <out_dir>/KachatPrice.json, [KachatName.json, KachatGap.json, [KachatOffer.json]], build-info.json.
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
    if p.get('registryVersion') != 3:
        sys.exit('params are not registry v3 (registryVersion: 3)')
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
    if not 1 <= p['priceShards'] <= 8:
        sys.exit('priceShards must be 1..8 (KachatPrice MAX_SHARDS)')
    if p['priceValue'] < 20_000_000:
        sys.exit('priceValue below 0.2 KAS: KIP-9 storage mass grows as an output shrinks')
    for k, v in p['prices'].items():
        if not 0 <= v <= 100_000_000_000_000_000:
            sys.exit(f'prices.{k} out of range (KachatPrice MAX_PRICE)')

    stage = lambda name, why: (os.path.exists(os.path.join(out_dir, name + '.json'))
                               and os.unlink(os.path.join(out_dir, name + '.json'))) or why

    price = compile_contract(silverc, src('KachatPrice'), [
        I(0), B(ZERO32), I(0), I(0), I(0), I(0), I(0),
        I(p['priceShards']), I(p['priceValue']),
    ], os.path.join(out_dir, 'KachatPrice.json'))
    pl = layout(price)
    info = {
        'network': p['network'],
        'registryVersion': 3,
        'compiler': p['compiler'],
        'params': {k: p[k] for k in ('bond', 'gapValue', 'tCommit', 'maxYears', 'periodMs', 'graceMs', 'renewWindowMs',
                                     'prices', 'priceShards', 'priceValue', 'offerMaxFee', 'genesisGap')},
        'priceCovenantId': p.get('priceCovenantId'),
        'registryCovenantId': p.get('registryCovenantId'),
        'contracts': {'KachatPrice': pl},
    }
    summary = [f"price {pl['bytecodeLen']} B"]

    price_cov = cov_id(p, 'priceCovenantId')
    reg_cov = cov_id(p, 'registryCovenantId')
    if price_cov:
        price_ref = [B(price_cov), B(bytes.fromhex(pl['templateHash'])), I(pl['prefixLen']), I(pl['suffixLen'])]
        name = compile_contract(silverc, src('KachatName'), [
            B(ZERO32), B(ZERO32), B(ZERO32), I(0), I(0), I(0),
            I(p['bond']), I(p['maxYears']), I(p['graceMs']), I(p['renewWindowMs']), I(p['periodMs']),
        ] + price_ref, os.path.join(out_dir, 'KachatName.json'))
        nl = layout(name)
        gap = compile_contract(silverc, src('KachatGap'), [
            B(bytes.fromhex(p['genesisGap']['lo'])), B(bytes.fromhex(p['genesisGap']['hi'])),
            B(bytes.fromhex(nl['templateHash'])), I(nl['prefixLen']), I(nl['suffixLen']),
            I(p['bond']), I(p['gapValue']), I(p['tCommit']), I(p['maxYears']), I(p['periodMs']),
        ] + price_ref, os.path.join(out_dir, 'KachatGap.json'))
        gl = layout(gap)
        info['contracts'].update({'KachatName': nl, 'KachatGap': gl})
        summary += [f"name {nl['bytecodeLen']} B", f"gap {gl['bytecodeLen']} B"]
        if reg_cov:
            offer = compile_contract(silverc, src('KachatOffer'), [
                B(ZERO32), B(ZERO32), B(ZERO32), I(0), B(reg_cov),
                B(bytes.fromhex(nl['templateHash'])), I(nl['prefixLen']), I(nl['suffixLen']),
                I(p['offerMaxFee']),
            ], os.path.join(out_dir, 'KachatOffer.json'))
            info['contracts']['KachatOffer'] = layout(offer)
            summary.append(f"offer {info['contracts']['KachatOffer']['bytecodeLen']} B")
        else:
            info['contracts']['KachatOffer'] = stage('KachatOffer', 'not built: set registryCovenantId after the registry genesis')
            summary.append('offer pending the registry genesis')
    else:
        if reg_cov:
            sys.exit('registryCovenantId is set but priceCovenantId is not: the registry bakes the price covenant')
        for n in ('KachatName', 'KachatGap', 'KachatOffer'):
            info['contracts'][n] = stage(n, 'not built: set priceCovenantId after the price genesis')
        summary.append('name/gap/offer pending the price genesis')

    with open(os.path.join(out_dir, 'build-info.json'), 'w') as f:
        json.dump(info, f, indent=2)
        f.write('\n')
    print(f"{p['network']}: " + ', '.join(summary))


if __name__ == '__main__':
    main()
