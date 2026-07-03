#!/usr/bin/env python3
"""
Reflexive-lever corpus extractor.

Predicate (name-AGNOSTIC for the lever, name-GENERIC for the read):
  A call L is a LEVER-candidate iff, within a small forward window, a
  VALUE-GATING READ (STATICCALL to a generic DeFi valuation function) is
  consumed shortly after L executes. L must be a mutating CALL (not a read,
  not plumbing). We never look for add_liquidity by name — whatever mutation
  precedes a valuation read nominates itself.

Runs across every file in calls.db and reports which incidents surface a lever.
"""
import duckdb, re
from collections import defaultdict, Counter

WINDOW = 5   # a read must appear within this many non-noise calls after the lever

# Generic DeFi VALUATION reads — protocol-agnostic, NOT yDAI-specific.
READ_PATTERNS = [
    r"virtual_price", r"priceperfullshare", r"pricepershare",
    r"latestanswer", r"latestround", r"getrounddata",
    r"getreserves", r"exchangerate",
    r"converttoassets", r"converttoshares", r"preview(redeem|withdraw|mint|deposit)",
    r"totalassets",
    r"get_dy", r"calc_withdraw_one_coin", r"calc_token_amount",
    r"getamountsout", r"getamountout", r"^quote$", r"consult", r"^peek$",
    r"^getprice", r"^price$", r"pricepertoken", r"getunderlyingprice",
]
READ_RE = re.compile("|".join(READ_PATTERNS), re.I)

# Plumbing / infra — present in nearly every trace; NOT levers even though mutating.
INFRA = {
    "transfer","transferfrom","approve","increaseallowance","decreaseallowance",
    "balanceof","allowance","decimals","symbol","name","totalsupply","identity",
    "mint","burn","burnfrom","deposit","withdraw","fallback","",
    # harness
    "testexploit","setup","testpoc","testattack","testattack1","run","attack",
}

def is_read(fn):
    return bool(READ_RE.search(fn or ""))

def is_infra(fn):
    return (fn or "").lower() in INFRA

con = duckdb.connect("calls.db", read_only=True)

# label lookup: one file -> its category set (dirty labels, but useful for grouping)
cat = defaultdict(set)
for f,c in con.execute("SELECT file_name, category FROM exploits").fetchall():
    if c: cat[f].add(c)

files = [r[0] for r in con.execute(
    "SELECT DISTINCT file_name FROM calls ORDER BY 1").fetchall()]

lever_files = Counter()          # lever_fn -> # distinct files it appears in as a lever
file_levers = defaultdict(set)   # file -> set(lever_fn)
pair_counts = Counter()          # (lever_fn, read_fn) -> occurrences
cat_hits    = Counter()          # category -> # files with a lever

for f in files:
    rows = con.execute("""
        SELECT call_id, depth, function_name, call_type
        FROM calls WHERE file_name=? AND is_noise=false
        ORDER BY call_id""", [f]).fetchall()
    # ordered list of (fn, ctype); index = position in non-noise stream
    seq = [(fn or "", ct or "") for (_cid,_d,fn,ct) in rows]
    n = len(seq)
    for i,(fn,ct) in enumerate(seq):
        if ct != "CALL":       # lever must be a mutating CALL
            continue
        if is_infra(fn):       # skip plumbing
            continue
        if is_read(fn):        # a read is not a lever
            continue
        # look forward within window for a value-gating read
        for j in range(i+1, min(i+1+WINDOW, n)):
            rfn, rct = seq[j]
            if rct == "STATICCALL" and is_read(rfn):
                file_levers[f].add(fn)
                pair_counts[(fn, rfn)] += 1
                break

for f,levs in file_levers.items():
    for L in levs:
        lever_files[L] += 1
    for c in (cat[f] or {"(unlabeled)"}):
        cat_hits[c] += 1

total_files = len(files)
hit_files   = len(file_levers)

print(f"Corpus: {total_files} files with traces")
print(f"Files exhibiting a LEVER→value-read pattern: {hit_files} "
      f"({100*hit_files/total_files:.0f}%)\n")

print("=== TOP LEVER FUNCTIONS (by # distinct incidents) ===")
for fn,c in lever_files.most_common(30):
    print(f"  {c:4d} files   {fn}")

print("\n=== LEVER→READ pairs (top 25 by occurrence) ===")
for (lf,rf),c in pair_counts.most_common(25):
    print(f"  {c:5d}   {lf:28s} -> {rf}")

print("\n=== incident CATEGORIES that surface a lever (top 20) ===")
for c,n in cat_hits.most_common(20):
    print(f"  {n:4d}   {c}")

# Spotlight: is yDAI in there, and what did it surface?
print("\n=== yDAI spotlight ===")
for f in ["Yearn_ydai_exp.sol","YearnFinance_exp.sol"]:
    print(f"  {f}: {sorted(file_levers.get(f, []))}")
