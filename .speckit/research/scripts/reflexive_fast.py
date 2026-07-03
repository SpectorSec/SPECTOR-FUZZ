#!/usr/bin/env python3
"""Fast (bisect) reflexive target matrix — vocabulary split, incident counts."""
import duckdb, re, bisect
from collections import defaultdict, Counter
from itertools import groupby
from Crypto.Hash import keccak

def sel(sig):
    k=keccak.new(digest_bits=256); k.update(sig.encode()); return "0x"+k.hexdigest()[:8]

PRIMS={
  "add_liquidity":(["add_liquidity(uint256[2],uint256)","add_liquidity(uint256[3],uint256)","add_liquidity(uint256[4],uint256)"],"KNOB"),
  "remove_liquidity_imbalance":(["remove_liquidity_imbalance(uint256[2],uint256)","remove_liquidity_imbalance(uint256[3],uint256)","remove_liquidity_imbalance(uint256[4],uint256)"],"KNOB"),
  "remove_liquidity_one_coin":(["remove_liquidity_one_coin(uint256,int128,uint256)"],"KNOB"),
  "exchange":(["exchange(int128,int128,uint256,uint256)"],"KNOB"),
  "exchange_underlying":(["exchange_underlying(int128,int128,uint256,uint256)"],"KNOB"),
  "borrow":(["borrow(uint256)","borrow(uint256,uint256,uint256,uint16,address)"],"KNOB"),
  "repayBorrow":(["repayBorrow(uint256)"],"KNOB"),
  "repay":(["repay(uint256)","repay(address,uint256,uint256,address)"],"KNOB"),
  "redeem":(["redeem(uint256)"],"KNOB"),
  "redeemUnderlying":(["redeemUnderlying(uint256)"],"KNOB"),
  "liquidateBorrow":(["liquidateBorrow(address,uint256,address)"],"KNOB"),
  "enterMarkets":(["enterMarkets(address[])"],"KNOB"),
  "mint":(["mint(uint256)"],"KNOB"),
  "accrueInterest":(["accrueInterest()"],"MECH"),
  "seize":(["seize(address,address,uint256)"],"MECH"),
  "updateStateOnRepay":([],"MECH"),
  "transferToReserve":([],"MECH"),
  "mintAllowed":(["mintAllowed(address,address,uint256)"],"HOOK"),
  "redeemAllowed":(["redeemAllowed(address,address,uint256)"],"HOOK"),
  "borrowAllowed":(["borrowAllowed(address,address,uint256)"],"HOOK"),
  "repayBorrowAllowed":(["repayBorrowAllowed(address,address,address,uint256)"],"HOOK"),
  "redeemVerify":(["redeemVerify(address,address,uint256,uint256)"],"HOOK"),
}
READ_RE=re.compile(r"virtual_price|priceperfullshare|pricepershare|latestround|getreserves|exchangerate|converttoassets|totalassets|get_dy|getamountsout|getprice|getpriceoracle|getunderlyingprice",re.I)
VAULT_RE=re.compile(r"virtual_price|priceperfullshare|pricepershare|converttoassets|totalassets|exchangerate|getunderlyingprice",re.I)
INFRA={"transfer","transferfrom","approve","balanceof","allowance","decimals","symbol","name","totalsupply","identity","burn","burnfrom","deposit","withdraw","fallback",""}

con=duckdb.connect("/workspace/_global/calls.db",read_only=True)
con.execute("SET threads TO 2")
allrows=con.execute("""SELECT file_name,function_name,call_type,raw_contract
   FROM calls WHERE is_noise=false ORDER BY file_name,call_id""").fetchall()

reflex=set(); prim_inc=defaultdict(set)
for fname,grp in groupby(allrows,key=lambda r:r[0]):
    seq=[(fn or "",ct or "",rc or "") for _f,fn,ct,rc in grp]
    n=len(seq)
    # precompute read positions (any value read) and vault-read positions
    read_pos=[i for i,(fn,ct,_r) in enumerate(seq) if ct=="STATICCALL" and READ_RE.search(fn)]
    vault_pos=[i for i,(fn,ct,_r) in enumerate(seq) if ct=="STATICCALL" and VAULT_RE.search(fn)]
    if not read_pos: continue
    hit=False; local=[]
    for i,(fn,ct,rc) in enumerate(seq):
        if ct!="CALL" or fn.lower() in INFRA or READ_RE.search(fn): continue
        # nearest read strictly after i
        k=bisect.bisect_right(read_pos,i)
        if k>=len(read_pos): continue
        g=read_pos[k]-i
        if g<5: continue
        # any vault read within (i, i+g+3]
        vk=bisect.bisect_right(vault_pos,i)
        if vk>=len(vault_pos) or vault_pos[vk] > i+g+3: continue
        hit=True
        if fn in PRIMS: local.append((fn,rc))
    if hit:
        reflex.add(fname)
        for fn,_rc in local: prim_inc[fn].add(fname)

print(f"Cross-step reflexive incidents: {len(reflex)}")
covered={f for fn in prim_inc for f in prim_inc[fn]}
print(f"...resolving a recognized protocol-primitive lever: {len(covered)}\n")

order={"KNOB":0,"MECH":1,"HOOK":2}
print(f"{'role':5s} {'#inc':>4s}  {'fn':26s} selector(s)")
print("-"*74)
knob_rows=[]
for fn in sorted(prim_inc,key=lambda k:(order[PRIMS[k][1]],-len(prim_inc[k]))):
    sigs,role=PRIMS[fn]; sels=[sel(s) for s in sigs]
    print(f"{role:5s} {len(prim_inc[fn]):>4d}  {fn:26s} {' '.join(sels) if sels else '(no ABI sig)'}")
    if role=="KNOB":
        for s,sg in zip(sels,sigs): knob_rows.append((fn,sg,s,len(prim_inc[fn])))

print("\n"+"="*74)
print("DEPLOYABLE: REFLEXIVE_LEVER_SELECTORS (KNOB primitives)")
print("="*74)
seen=set()
print("pub const REFLEXIVE_LEVER_SELECTORS: &[[u8; 4]] = &[")
for fn,sg,s,ninc in knob_rows:
    if s in seen: continue
    seen.add(s)
    b=", ".join(f"0x{s[2+k*2:4+k*2]}" for k in range(4))
    print(f"    [{b}],  // {fn}: {sg}")
print("];")
print(f"// {len(seen)} selectors, Curve-vault + lending-fork reflexive families")
