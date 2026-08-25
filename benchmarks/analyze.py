#!/usr/bin/env python3
import csv, hashlib, json, random, statistics, sys
calibration, final, output = sys.argv[1:]
with open(calibration, newline='') as f: cal = list(csv.DictReader(f))
with open(final, newline='') as f: rows = list(csv.DictReader(f))
if len(cal) != 48 * 7 or len(rows) != 48 * 7 * 5:
    raise SystemExit(f"observation count mismatch calibration={len(cal)} final={len(rows)}")
for r in cal:
    if r['gate_status'] != 'CALIBRATION_NON_REPORTABLE' or int(r['operations']) < 100000 or int(r['elapsed_ns']) < 1000000000 or int(r['guards']) or int(r['incorrect']): raise SystemExit('invalid calibration row')
for r in rows:
    if r['gate_status'] != 'FINAL_VALID' or int(r['guards']) or int(r['incorrect']): raise SystemExit('invalid final row')
groups = {}
for r in rows:
    key = tuple(r[k] for k in ('profile','payload','flows','implementation','operation'))
    groups.setdefault(key, []).append(1e9 * int(r['operations']) / int(r['elapsed_ns']))
rng = random.Random(0x524f484343585832)
summary = []
for key, values in sorted(groups.items()):
    if len(values) != 5: raise SystemExit(f'missing observation {key}')
    med = statistics.median(values); mad = statistics.median(abs(v-med) for v in values)
    boots = sorted(statistics.median(rng.choices(values, k=len(values))) for _ in range(10000))
    summary.append(dict(zip(('profile','payload','flows','implementation','operation'),key), median_ops_s=med, median_ns_op=1e9/med, mad_ops_s=mad, bootstrap95=[boots[249],boots[9749]]))
compression = []
for key in sorted({(r['profile'],r['payload'],r['flows'],r['implementation']) for r in rows if r['operation'] in ('steady_compress','control')}):
    selected=[r for r in rows if (r['profile'],r['payload'],r['flows'],r['implementation'])==key and r['operation'] in ('steady_compress','control')]
    ratios=[int(r['output_bytes'])/int(r['input_bytes']) for r in selected]
    compression.append(dict(zip(('profile','payload','flows','implementation'),key), compressed_bytes_median=statistics.median(int(r['output_bytes']) for r in selected), bytes_saved_median=statistics.median(int(r['input_bytes'])-int(r['output_bytes']) for r in selected), compression_ratio=statistics.median(ratios)))
doc={'schema':1,'calibration_rows':len(cal),'final_rows':len(rows),'outliers_deleted':0,'throughput':summary,'compression':compression,'raw_sha256':hashlib.sha256(open(final,'rb').read()).hexdigest()}
with open(output,'w') as f: json.dump(doc,f,indent=2,sort_keys=True)
