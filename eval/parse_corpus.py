import os, json, sys
from urllib.parse import urlsplit, parse_qsl

root = sys.argv[1]
out = sys.argv[2]
n=0; bad=0
with open(out,"w") as w:
    for dirpath,_,files in os.walk(root):
        for fn in files:
            if fn.endswith(".white"): label=0
            elif fn.endswith(".black"): label=1
            else: continue
            p=os.path.join(dirpath,fn)
            try:
                raw=open(p,"rb").read()
            except Exception:
                bad+=1; continue
            sep=b"\r\n\r\n"
            idx=raw.find(sep)
            if idx<0:
                sep=b"\n\n"; idx=raw.find(sep)
            head = raw[:idx] if idx>=0 else raw
            body = raw[idx+len(sep):] if idx>=0 else b""
            try:
                lines=head.split(b"\n")
                reqline=lines[0].decode("latin-1").strip()
                parts=reqline.split(" ")
                method=parts[0] if parts else "GET"
                target=parts[1] if len(parts)>1 else "/"
            except Exception:
                bad+=1; continue
            sp=urlsplit(target)
            path=sp.path or "/"
            query=[[k,v] for k,v in parse_qsl(sp.query, keep_blank_values=True)]
            headers=[]; cookies=[]
            for ln in lines[1:]:
                try: s=ln.decode("latin-1")
                except Exception: continue
                if ":" not in s: continue
                k,v=s.split(":",1); k=k.strip(); v=v.strip()
                if not k: continue
                if k.lower()=="cookie":
                    for kv in v.split(";"):
                        if "=" in kv:
                            ck,cv=kv.split("=",1); cookies.append([ck.strip(),cv.strip()])
                else:
                    headers.append([k,v])
            rec={"label":label,"method":method,"path":path,"query":query,
                 "headers":headers,"cookies":cookies,
                 "body":body.decode("latin-1","replace")}
            w.write(json.dumps(rec,ensure_ascii=False)+"\n"); n+=1
print(f"parsed={n} skipped={bad}")
