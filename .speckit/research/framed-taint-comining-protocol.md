# The Frame Co-Mining Protocol — how to build the delivery-frame template

**Date:** 2026-06-30
**Status:** PLAN (process, not code). Awaiting pilot-mechanism selection.
**Object being built:** the four-phase **delivery frame** (Borrow → Prime → Lever → Exploit)
as a *per-mechanism template*, which then becomes **the config file for taint** (seed / mask /
checkpoint / sink) so taint runs **framed, not blind**.
**Sources joined:** the machine half — `calls.db` (DuckDB, 910k calls / 706 exploit files) +
`clean_labels.json` (mechanism-keyed, source-derived, §14 of v3 doc). The human half — the
user's `DeFi-Security-Incident` postmortems (one .md per incident).
**Builds on:** `v3-exploit-grammar-integration.md` (§9–17: differential method, clean relabel,
the Class 1/2/3 resolution floor). **This doc does not re-derive that — it welds it to Meta's frame.**

---

## 0. The one-paragraph thesis

We are not building detectors ("did something bad happen?"). We are building the **delivery
frame** — how attacker authority is **Borrowed**, **Primed** to look normal, **Levered** at a
mechanical point, and realized as an **Exploit** payout. The frame is mined **co-operatively**:
the machine drafts the mechanical skeleton from call traces; the human writes the intent/story
and supplies what the trace is blind to. The finished frame is then loaded as taint config —
**seed only at the mined Borrow authority, mask by the mined Prime context, checkpoint at the
mined Lever DIM, sink at the mined Exploit extraction.** Framed taint is *cheaper* than blind
taint (far fewer seeds/checkpoints) — and that cost drop is the lever that justifies turning the
currently-compiled-out taint spine ON in the production build.

---

## 1. The division-of-labor law (WHO fills WHAT, and WHY that boundary)

The boundary is not "phases split between people." It is the **resolution floor** of the
function-level call tree (v3 §17). The machine sees **value movement + protocol vocabulary**; it
is blind to **arithmetic** (Class 2), **absence** (Class 3 missing-check), **off-chain** (Class 3
keys), **calldata args**, **economic dimension**, and **value magnitude**.

| Frame phase | Field | Filled by | Exact data source | Blind-spot caveat |
|---|---|---|---|---|
| **BORROW** | Authority Source / Mechanism / Target | **Machine (draft)** | `calls`: FIRST top-level call fn (`approve`/`flashLoan`/`swap`) + `call_type` + `raw_contract`. The depth-1 "hacker archetype" (Flash-Loan-Capitalist / Approval-First, v3 §7c). | Machine sees the *entry function*, not *why that authority / what gap*. |
| BORROW | **Belly Gap (intent)** | **Human** | postmortem: what trust/assumption was borrowed. | Pure story — no trace signal. |
| **PRIME** | Context Shape / nesting | **Machine (evidence)** | `calls`: `parent_id`/`depth` tree + `call_type` mix (DELEGATECALL = proxy/trusted-context, v3 §7c). | Machine sees *structure*, not *deception intent*. |
| PRIME | **Deception / Desensitization / Semantic Mangling / State Precondition** | **Human** | postmortem: the "story" of why it looked normal. | The primary human contribution. Trace can *corroborate* but never *state* intent. |
| **LEVER** | **Mechanical Point** | **Machine (draft) — Class 1 ONLY** | `calls`: differential-signature fn on `clean_labels.json` single-label files, `is_noise=false` (v3 §14: `stake`/`skim`/`deliver`/`latestRoundData`/`flashLoan`). | **Class 2/3 → NULL** (arithmetic/absence invisible). Then human writes the Lever. |
| LEVER | Execution Context | **Machine** | `calls.raw_contract` at the signature call; gate depth 4–8 (v3 §7d). | — |
| LEVER | **Mutated Parameters** | **Human or running engine** | NOT in db (no calldata/args column). | Hard blind spot. Engine's secant can supply at runtime; human supplies from postmortem. |
| LEVER | **Economic DIM** | **Human confirms machine GUESS** | Machine heuristic from fn name (`getReserves`/`latestAnswer`→Price; `transfer`/`balanceOf`→Balance; `getReserveNormalizedIncome`/`scaledTotalSupply`→Accumulator). Human confirms/corrects. | DIM is not stored; the fn-name map is a *candidate*, not truth. |
| **EXPLOIT** | Payout Target / Exit Path | **Machine (draft)** | `calls`: LAST non-noise call overall + DEEPEST call (v3 §8: `transfer` 353/34232) = the 6 leak primitives. | Machine sees the *extraction fn*, not the *magnitude*. |
| EXPLOIT | **Success Condition** | **Machine** | `exploits.success` bool. | — |
| EXPLOIT | **Materiality Measurement / Payout Threshold** | **Human or running engine** | NOT in db (no value column; `result` = return data only). | Hard blind spot → human from postmortem, or engine's a-posteriori inflow attribution (already built, feedbacks.rs:396). |

**The law in one line:** *Machine drafts the mechanical skeleton of all four phases at
function/call-type/depth granularity; human writes intent + the three things the trace cannot
hold (DIM semantics, param values, materiality magnitude); and for Class 2/3 mechanisms the
machine yields the Lever entirely to the human.*

---

## 2. The join key (how the two halves meet on the same incident)

Both halves key on the **incident**, resolvable three ways (already proven wired in v3 §14's
`relabel_from_source.py`):

```
DeFiHackLabs PoC file  ──(protocol+date)──►  source incident .md  ──(category/vuln_type)──►  mechanism
   calls.file_name              (human side: DeFi-Security-Incident/vulns/*.md)      clean_labels.json
```

- Machine card is emitted **per `file_name`** (e.g. `AccrualSelfPrimed_exp.sol`).
- Human card is written **per source incident .md** (same protocol).
- `clean_labels.json` already carries the file→mechanism map at **91% single-label** — so a
  mechanism's file-set is the co-mining batch. **Use single-label files only** (v3 §12 discipline:
  multi-label dilutes and lies).

---

## 3. The frame card (the artifact each incident produces)

One YAML/JSON card per incident. **Machine pre-fills the left column; human fills the right.**
Fields the machine cannot see are left as `null` with a `blind:` tag so the human knows it's theirs.

```yaml
incident: AccrualSelfPrimed          # join key (protocol)
poc_file: AccrualSelfPrimed_exp.sol  # calls.file_name
mechanism: staking-reward            # clean_labels.json (NOT the dirty category)
resolution_class: 1                  # v3 §17 — tells human how much machine could see

borrow:
  entry_fn:        approve           # MACHINE: first top-level call
  entry_archetype: approval-first    # MACHINE: depth-1 fingerprint
  call_type:       CALL              # MACHINE
  authority_target: <contract>       # MACHINE: raw_contract
  belly_gap:       null  # HUMAN: what assumption was borrowed  [blind]

prime:
  context_shape:   "DELEGATECALL into trusted proxy at depth 3"  # MACHINE evidence
  call_tree_depth: 4                 # MACHINE: parent_id/depth
  deception:       null  # HUMAN: why it read as normal          [blind]
  precondition:    null  # HUMAN: required prior state           [blind]

lever:
  mechanical_point: stake            # MACHINE (Class 1): differential signature fn
  exec_context:     <pool contract>  # MACHINE: raw_contract
  gate_depth:       6                # MACHINE: depth 4-8
  dim_guess:        Accumulator      # MACHINE heuristic from fn name
  dim_confirmed:    null  # HUMAN: confirm/correct DIM
  mutated_params:   null  # HUMAN or ENGINE: no calldata in db    [blind]

exploit:
  payout_fn:        transfer         # MACHINE: last non-noise call
  deepest_fn:       transfer         # MACHINE: deepest call
  success:          true             # MACHINE: exploits.success
  materiality:      null  # HUMAN or ENGINE: no value in db       [blind]
  threshold:        null  # HUMAN: the gated comparison           [blind]
```

For a **Class 3** mechanism (access-control, arbitrary-call, private-key) the machine card comes
back with `lever.mechanical_point: null  [blind: structure-less]` and a route hint
`→ control-leak / missing-check / earned>owed oracle` — i.e. it declares *"this one is not a frame
template; it's a structural-oracle job."* That NULL is a **result**, not a failure (v3 §17).

---

## 4. The PROCESS (Meta's 7 steps, re-cast as a human+machine pipeline)

**Step 1 — Pick the mechanism (not the human category).** v3 §15 proved similarity lives at the
*mechanism* level. Choose one clean, high-n, Class-1 mechanism from `clean_labels.json`.

**Step 2 — MACHINE pre-fill pass (I run).** One DuckDB query set over the mechanism's single-label
files emits the left column of every frame card: entry fn, call-type/tree, differential signature
fn, raw_contract, gate depth, DIM guess, last/deepest non-noise call, `success`. Output = N
half-filled cards + a `resolution_class` stamp. *Deliverable: `frames/<mechanism>/*.machine.yaml`.*

**Step 3 — HUMAN story pass (user).** For each card, read the matching postmortem and fill the
`[blind]` fields: belly_gap, deception, precondition, dim_confirmed, mutated_params, materiality,
threshold. For Class 2/3 cards, the human also writes the whole Lever.

**Step 4 — WELD CHECK (machine-assisted, Meta step 6).** Automated consistency assertions between
the two halves — *this is where co-mining earns its keep*:
- Does the human's stated **Borrow authority** appear as the machine's **entry_fn**? (mismatch →
  wrong card or wrong label — apply v3 §13 labeling-integrity discipline)
- Does **dim_confirmed** match the **dim_guess** family? (mismatch → refine the fn→DIM map)
- Does the human's described **extraction** match the machine's **payout_fn**?
- Is **materiality** consistent with **success=true**?
Contradictions are surfaced, not silently merged.

**Step 5 — ROLE abstraction (template synthesis).** Once ≥N welded cards for a mechanism agree,
abstract to the **role level, not the function level** (v3 §9: role conservation ~55–86% is the
real skeleton; function vocabulary is protocol-shuffle). Output one **frame template** per
mechanism: `{Borrow role, Prime role, Lever role+DIM, Exploit role}` with the concrete function
sets bound per protocol via topology.

**Step 6 — Emit the taint config.** Translate the template into the four taint hooks:
| Frame role | Taint hook | Existing code anchor |
|---|---|---|
| Borrow authority | **SEED** — taint only calldata at the mined entry authority, not all input | `INJECTION_TAINTED_CALLDATA` cmp_linearity.rs:94 (currently seeds broadly) |
| Prime context | **MASK** — allow propagation only if call context matches template | *new mechanism — most speculative; validate before building* |
| Lever DIM | **CHECKPOINT** — read DIM tag at the mined mechanical point, emit PromotionCandidate | `host.tainted_storage` DIM + weld 021 (already built) |
| Exploit extraction | **SINK + materiality** | a-posteriori inflow attribution feedbacks.rs:396 (already built) |

**Step 7 — Validate on fork.** Run the framed config against the pilot mechanism's live fork
(Lane A) and confirm it reaches the same lever the human documented, *cheaper* than blind taint.

---

## 5. Honest map of Meta's 4 integration points to code reality (what's new vs config)

| Meta point | Reality | Verdict |
|---|---|---|
| Borrow → seed at mined authority | Bus exists; **seed-scoping (authority-only vs all-calldata) is NEW policy** | small new logic |
| Prime → propagation mask | **Wholly new mechanism** — no current analog | speculative — validate first, may defer |
| Lever → checkpoint + DIM | **Mostly BUILT** (TAINTED_CALLS + DIM + weld 021) | config, not code |
| Exploit → sink + materiality | **BUILT** (a-posteriori inflow); dimension-specific metric is the gap | config, minor code |

**Grounding fact (unchanged, still the crux):** the taint spine is **compiled OUT of the default
binary** — `concolic_secant_dispatch` is not in Cargo.toml default features, so
`injection_causal_link_confirmed()` fail-opens in production and the weld's phantom-suppression is
unreachable. **Framed taint being cheaper (fewer seeds/checkpoints from the template) is exactly
the cost argument that could justify turning the spine ON.** The frame is not just a taint config —
it's the *economic justification* for enabling taint at all.

---

## 6. First action (on pilot selection)

I run **Step 2** on the chosen mechanism: emit `frames/<mechanism>/*.machine.yaml` (N half-filled
cards) + the resolution-class stamp, and hand you the exact `[blind]` fields to fill from the
postmortems. Nothing gets built into the fuzzer until a mechanism's frame is welded and validated.
```
```
