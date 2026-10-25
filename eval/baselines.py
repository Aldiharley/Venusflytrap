import json, ctypes, re, sys, time
from urllib.parse import parse_qsl

JSONL=sys.argv[1]; OUT=sys.argv[2]
lib=ctypes.CDLL(sys.argv[3])
lib.libinjection_sqli.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.c_char_p]
lib.libinjection_sqli.restype=ctypes.c_int
lib.libinjection_xss.argtypes=[ctypes.c_char_p,ctypes.c_size_t]
lib.libinjection_xss.restype=ctypes.c_int

def li_attack(fields):
    fp=ctypes.create_string_buffer(16)
    for s in fields:
        b=s.encode("latin-1","replace")
        if not b: continue
        if lib.libinjection_sqli(b,len(b),fp)==1: return 1
        if lib.libinjection_xss(b,len(b))==1: return 1
    return 0

RX=[re.compile(p,re.I) for p in [
 r"union\s+select", r"\bor\s+1\s*=\s*1\b", r"<script", r"onerror\s*=",
 r"onload\s*=", r"/etc/passwd", r";\s*(cat|ls|id|whoami|wget|curl)\b",
 r"information_schema", r"\.\./\.\./", r"\$\(", r"javascript:",
 r"(select|insert|update|delete)\s+.*\bfrom\b", r"<img[^>]+src", r"etc/shadow"]]
def rx_attack(blob):
    return 1 if any(r.search(blob) for r in RX) else 0

def fields_of(r):
    fs=[r["path"]]
    fs+=[v for _,v in r["query"]]
    fs+=[v for _,v in r["cookies"]]
    body=r["body"]
    fs.append(body)
    if "=" in body and "{" not in body[:2]:
        try: fs+=[v for _,v in parse_qsl(body, keep_blank_values=True)]
        except Exception: pass
    for k,v in r["headers"]:
        if k.lower() in ("referer","user-agent","x-forwarded-for","cookie"): fs.append(v)
    return [f for f in fs if f]

def blob_of(r):
    return r["path"]+" "+r["body"]+" "+" ".join(v for _,v in r["query"])+" "+" ".join(v for _,v in r["cookies"])

def metrics(name,preds,labels,lat):
    tp=fp=tn=fn=0
    for p,l in zip(preds,labels):
        if p and l: tp+=1
        elif p and not l: fp+=1
        elif not p and not l: tn+=1
        else: fn+=1
    rec=tp/max(tp+fn,1); prec=tp/max(tp+fp,1)
    f1=2*prec*rec/(prec+rec) if prec+rec else 0; fpr=fp/max(fp+tn,1)
    lat.sort(); pct=lambda q: lat[round((len(lat)-1)*q)] if lat else 0
    return dict(engine=name,tp=tp,fp=fp,tn=tn,fn=fn,recall=round(rec,4),
                precision=round(prec,4),f1=round(f1,4),fp_rate=round(fpr,4),
                p50_us=pct(.5),p95_us=pct(.95),p99_us=pct(.99))

labels=[]; li_p=[]; rx_p=[]; li_lat=[]; rx_lat=[]
for line in open(JSONL):
    line=line.strip()
    if not line: continue
    r=json.loads(line); labels.append(r["label"])
    fs=fields_of(r); blob=blob_of(r)
    t=time.perf_counter(); li_p.append(li_attack(fs)); li_lat.append(int((time.perf_counter()-t)*1e6))
    t=time.perf_counter(); rx_p.append(rx_attack(blob)); rx_lat.append(int((time.perf_counter()-t)*1e6))

res=[metrics("libinjection",li_p,labels,li_lat), metrics("regex-signature",rx_p,labels,rx_lat)]
json.dump(res,open(OUT,"w"),indent=2)
for r in res: print(r)
