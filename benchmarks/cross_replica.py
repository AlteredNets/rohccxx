#!/usr/bin/env python3
import glob, hashlib, json, os, statistics, sys
roots=sorted(glob.glob(sys.argv[1]+'/replica-*'))
if len(roots)!=3: raise SystemExit(f'expected three replicas, got {len(roots)}')
docs=[]
for root in roots:
    sums=os.path.join(root,'SHA256SUMS')
    expected={line.split()[1]:line.split()[0] for line in open(sums)}
    for name,digest in expected.items():
        actual=hashlib.sha256(open(os.path.join(root,name),'rb').read()).hexdigest()
        if actual!=digest: raise SystemExit(f'hash mismatch {root}/{name}')
    if 'FAIL' in open(os.path.join(root,'correctness.txt')).read(): raise SystemExit(f'correctness failure {root}')
    docs.append(json.load(open(os.path.join(root,'statistical-summary.json'))))
identities=[]
for r in roots:
    lines=open(os.path.join(r,'resolved-identity.txt')).read().splitlines()
    plans=[line for line in lines if 'calibration-plan-' in line]
    if len(plans)!=8: raise SystemExit(f'missing plan identities {r}')
    identities.append('\n'.join(line for line in lines if 'calibration-plan-' not in line))
if len(set(identities))!=1: raise SystemExit('replica static identity mismatch')
keys=[]
for d in docs: keys.append({(x['profile'],x['payload'],x['flows'],x['implementation'],x['operation']):x['median_ops_s'] for x in d['throughput']})
if not all(k.keys()==keys[0].keys() for k in keys): raise SystemExit('summary workload mismatch')
comparisons=[]; unstable=0
for k in sorted(keys[0]):
    vals=[x[k] for x in keys]; spread=(max(vals)-min(vals))/statistics.median(vals); bad=spread>0.15;unstable+=bad
    comparisons.append({'key':k,'replica_medians_ops_s':vals,'relative_spread':spread,'unstable':bad})
out={'schema':1,'replicas':3,'claim_allowed':unstable==0,'unstable_series':unstable,'stability_threshold':0.15,'comparisons':comparisons}
json.dump(out,open(sys.argv[2],'w'),indent=2,sort_keys=True)
if unstable: print(f'FLAGGED: {unstable} unstable series; performance claim suppressed')
