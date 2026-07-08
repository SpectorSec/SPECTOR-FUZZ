# The Population Procedure — data, purpose, order

**Date:** 2026-07-04
**Status:** PROCEDURE (process, not code). Front half of the 019-dependent archetype spec.
**Governing principle (the whole reason this doc exists):**
> Getting code to behave is rational. The hard part is determining **what data** the code
> uses, **for what purpose**, and **in what order** — i.e. getting chaotic incident data into
> a deterministic / controllable-enough space to derive a useful outcome.

This document does exactly that for the four-phase frame: it assigns **a data source, a purpose,
and a fill-order** to every slot, and shows how the ordering **reduces entropy** at each pass so
the space handed to the next filler is smaller and more controlled than the one before.

---

## 0. The asymmetry this procedure resolves

- **Lever + Exploit populate THEMSELVES** — a-posteriori, by the running fuzzer (mutator secant
  tunes the lever param; the feedback ledger measures the payout). No authoring. Already built.
- **Borrow + Prime must be AUTHORED** — a-priori, before the first transaction. Today that
  authoring is a human hand-writing `ydai_only.json`. **"Not parameterized" = no process turns a
  target into filled Borrow/Prime slots.** This procedure IS that process.

---

## 1. Current schema vs parameterized schema (the honest gap)

**Today (`presets/mod.rs:39`):**
```rust
pub struct ExploitTemplate {
    pub exploit_name: String,
    pub function_sigs: Vec<FunctionSig>,   // ABI to register
    pub calls: Vec<FunctionSig>,           // FLAT ordered selector list — no phase typing
}
```
The `ExploitTemplate.calls` list is an undifferentiated *preset* sequence — nothing marks which
call is Borrow vs Prime vs Lever. The frame lives only in the author's head at this layer.

**But the sequence-level substrate already exists one layer down — we TYPE it, we don't BUILD it.**
`CampaignSequence` (input.rs:50) is already a rich, first-class multi-step object:
```rust
pub struct CampaignSequence {
    pub steps:    Vec<ConciseEVMInput>,   // the ordered multi-step sequence
    pub linkages: Vec<StepLinkage>,       // EXPLICIT inter-step data-flow (what carries between phases)
    pub warps:    Vec<(usize, u64)>,      // per-step time advances
    pub promoted: Vec<usize>,             // step indices = promoted reflexive LEVERS (proto-Lever tag)
    pub aposteriori: bool,
}
// StepLinkage (input.rs:39): from_step --(from_registry_key)--> to_step.to_param_index
```
`StepLinkage` is *literally* the "taint thread between phases" — a value captured at one step is
routed into a later step's parameter. So Layer 2 is **present but UNTYPED**. What it lacks is only
three things: **phase labels**, **taint tags**, and **preset-level authoring**.

**Parameterized (what the procedure fills):** `FrameStep` maps **1:1 onto `CampaignSequence.steps[i]`**
(plus its `StepLinkage` edges) — we layer a **phase label + taint tag + fill-source** onto the
existing step, **no new struct, no new stroke**. The inter-phase carry is the existing
`StepLinkage`; `promoted` is already the proto-Lever marker.
```
// conceptual overlay on CampaignSequence.steps[i] (NOT a replacement type):
FrameStep {
  phase:  Borrow | Prime | Lever | Exploit,   // NEW label (only `promoted`≈Lever exists today)
  // selector / params / linkage ALREADY EXIST: steps[i] + linkages
  taint_tag:   Seed | Mask | Checkpoint | Sink,       // NEW tag on the slot
  fill_source: Topology | CorpusPrior | Human | Fuzzer, // NEW: determinism provenance
}
```
The taint tag on the slot is the one thing that turns a preset into a *frame*
("taint tags attach to typed slots" — the load-bearing sentence).

**Two ownership corrections (from the 2026-07-04 challenge, verified against source):**
1. **Layer 2 already exists as `CampaignSequence`; the frame TYPES it** (phase labels + taint tags)
   and lifts authoring to Preset. It is not a new grammar engine, and `StepLinkage` already
   supplies "what carries between phases." (Same class of error as the earlier "no sequence
   grammar exists" — the label was missing, not the thing.)
2. **The mutator does NOT generate Layer 2.** Ownership is: **Preset** authors the phase skeleton →
   **planner (`plan_campaign_sampled`)** instantiates it into a `CampaignSequence` → **mutator**
   stays a **Layer-1 (BoxedABI argument) engine, now SCOPED to a phase window** (mutate only inside
   Lever args, freeze all but the amount param, etc.). The mutator consumes the frame; it does not
   emit it. This a-priori-structure / within-slot-search separation is the point — do not collapse it.

---

## 2. The slot table — DATA · PURPOSE · TAINT, per phase

| Phase | Slot | Fill source | **Exact data** | **Purpose** | Taint tag |
|---|---|---|---|---|---|
| **BORROW** | `authority_mechanism` | Topology | ABI selector classified `FlashLoan`/`ERC20`(approve)/`ERC4626`(deposit) — topology.rs:266 | which call grants attacker capital/permission | **Seed** |
| BORROW | `authority_source` | Topology | `raw_contract` holding that selector | where authority comes from | Seed |
| BORROW | `authority_amount` | CorpusPrior → Fuzzer | gas-aware entry order (priors.json); magnitude tuned at runtime | how much to borrow | Seed |
| **PRIME** | `context` | Topology | co-occurring family (AMM/vault/pair) + `call_type` (DELEGATECALL=proxy) | the trusted surface the lever will read | **Mask** |
| PRIME | `precondition_calls` | CorpusPrior | typical setup nesting/depth per archetype (calls.db `parent_id`/`depth`) | the state that must be true before the lever | Mask |
| PRIME | `deception` / `belly_gap` | **Human** | postmortem: why it reads as normal | intent the trace cannot hold | Mask |
| **LEVER** | `lever_catalog` | Topology → CorpusPrior | reflexive-skew selectors present; differential-signature fn per archetype | candidate mechanical points | **Checkpoint** |
| LEVER | `mutated_param` + `DIM` | Fuzzer (secant) | apply_ledger_secant tunes; DIM read at runtime | the tuned lever + its economic dimension | Checkpoint |
| **EXPLOIT** | `payout` + `materiality` | Fuzzer (ledger) | feedback.rs:396 net inflow attribution | the measured payout | **Sink** |

**The blind slots (no machine column → forced human/fuzzer):** `deception`/`belly_gap` (intent),
`mutated_param`/`materiality` (value — no calldata/value column in calls.db). These are exactly
the blind axes from `machine-taxonomy-callsdb.md`. The procedure never asks a machine to fill them.

---

## 3. The FILL ORDER is an entropy-reduction pipeline (this is the core)

The order is not arbitrary — **each pass hands the next a smaller, more controlled space.**
This is the "chaotic → deterministic" collapse made literal.

```
  ALL POSSIBLE Borrow/Prime fills  (chaos: any selector, any order, any context)
            │
   ① TOPOLOGY  ──  DETERMINISTIC, from the TARGET's own ABI, pre-flight, zero search
            │        collapses "which authority mechanism?" from all-possible
            │        → the selectors ACTUALLY PRESENT on this target
            ▼
   a small set of present, typed candidate slots
            │
   ② CORPUS PRIOR  ──  RANKED-PROBABILISTIC, from calls.db per archetype class
            │        among the present candidates, orders by empirical frequency
            │        (gas-aware: approve-first) + supplies default precondition depth
            │        → a ranked shortlist, ambiguity reduced to a few options
            ▼
   a ranked, mostly-filled Borrow/Prime template
            │
   ③ HUMAN  ──  IRREDUCIBLE INTENT, from the postmortem
            │        fills ONLY the residue the two machine passes provably cannot see
            │        (belly_gap, deception, DIM confirmation)
            ▼
   a fully-authored, taint-tagged a-priori frame  ►  seeds CampaignSequence
            │
   ④ FUZZER  ──  MEASURED, a-posteriori
                 populates Lever mutated_param + Exploit payout by running
```

**Why this order and no other:**
- Topology **first** because it is the only *deterministic* source — it reads the target itself,
  so it collapses the biggest chunk of chaos for free before any probabilistic guess is made.
- Corpus prior **second** because it only makes sense to *rank* candidates that topology proved
  are *present*. Ranking all-possible selectors would be ranking noise.
- Human **third** because their scarce attention should touch only what survives two machine
  passes — never a slot a machine could have filled deterministically.
- Fuzzer **last** because Lever/Exploit are measured, not authored — they need the a-priori frame
  to exist first, then they resolve empirically.

---

**Status of the CorpusPrior pass (2026-07-06 — now a real artifact, not a plan).** The `②` source
is built: `exploit_analytics.duckdb` (345 canonical exploits, 12 clean product tables, cross-family
contamination hand-removed). Each incident carries a corrected attacker-flow `phase_frame` (ordered
Borrow→Prime→Lever→Exploit) + `phase_sig` (B/P/L/E presence), rebuilt in execution order with
oscillation preserved (`/workspace/_global/build_role_sequences.py`; see [[project_exploit_grammar_db]]).
**Key result: `phase_sig` degeneracy tracks the 3-class resolution floor for free** — flashloan/
price-manip/reentrancy → full `BPLE`; access-control/arbitrary-call → lone `P` (Class-3, no lever).
So `phase_sig` is a **free archetype pre-filter for this pass**: `BPLE` incidents are the training set
for full frames; `P`/`E` incidents tell topology "expect no lever here." (Weight by
`role_source='reparsed'`; `P`-only is inflated by shallow concrete-fallback trees. Inheritance_lineage
in the same DB is sparse/incomplete — ignore it.)

## 4. The determinism ledger (chaotic → controllable, classified)

| Source | Determinism class | What it controls | Residual chaos it leaves |
|---|---|---|---|
| Topology | **Deterministic** (function of the ABI) | which mechanisms/contexts exist on THIS target | ordering & magnitude |
| Corpus prior | **Bounded-probabilistic** (ranked frequencies) | most-likely entry order + precondition shape | intent, exact values |
| Human | **Irreducible** (judgment) | intent: belly gap, deception, DIM | nothing downstream — it's the floor |
| Fuzzer | **Measured** (empirical) | lever param + payout magnitude | none — this is the answer |

The procedure's whole value: it moves each slot **down** this ledger — from chaotic, to
deterministic-where-possible, to human-only-where-necessary, to measured-at-the-end. Nothing is
guessed that could be derived; nothing is asked of a human that a machine could see.

---

## 5. The closed-loop check (does the fill need its own oracle? No.)

You do **not** need a separate detector for "was the Borrow/Prime authoring correct."
**The fuzzer reaching the lever IS the signal:**
- a-priori frame seeds the run → mutator fires the a-posteriori Lever+Exploit → **fill was correct.**
- run never reaches the lever → the Borrow/Prime slots were wrong → correct source ①/②/③ and re-run.

This is the weld from `framed-taint-comining-protocol.md`, now with a concrete pass/fail:
**did the frame reach its own lever.** The determinism of the fill is *validated by execution*,
not asserted.

---

## 6. Dependencies & sequencing

- The `class` tag + `lever_catalog` on `ExploitTemplate`, and the mutator reading the catalog,
  are the **safe, unblocked** pieces.
- The **per-class inline-middleware gate** (Prime/Exploit tags → which inline mw attaches) is
  **blocked on 019 Phase A** (function_auth.rs must exist to gate onto).
- Chain: `019 Phase A → archetype class tag + lever_catalog → topology→class selection →
  per-class middleware gate`.

This procedure is the front half of that spec: it defines **what data fills each slot, for what
purpose, in what order.** The code that reads the filled schema is the rational, easy part.

---

## 7. Where `topology.rs` feeds the substrate (the instantiation wiring)

The population procedure above is intact. This section only locates **the exact seam** where
topology's output enters the `CampaignSequence` — so we know which call site the procedure
re-points, not just conceptually but by line.

### 7a. The four phases ALREADY EXIST as planner construction stages (just unlabeled)

`plan_campaign_sampled(cache, topology_report, …) -> Option<CampaignSequence>`
(`campaign_planner.rs:284`) builds the steps in **phase order** today — the frame is latent in
the construction sequence, it just has no phase field:

| Phase | Construction call | Line | Fill source TODAY |
|---|---|---|---|
| Borrow | `build_borrow_step(*token_addr)` | 298 | `cache.borrowable_tokens.first()` — **NOT topology** |
| Prime | `pick_prime_and_exploit(...)` → `build_abi_step` | 302–304 | corpus sampling + **one topology bit** |
| Lever | `maybe_promote_lever(cache)` → `promoted.push(...)` | 312–316 | reflexive vocabulary in `cache` — **NOT topology** |
| Exploit | `build_abi_step(...)` | 324–325 | corpus sampling |
| *(carry)* | `linkages: Vec::new()` | 352 | **instantiated EMPTY** |

This is the strongest confirmation of the REFINE: `FrameStep` doesn't need a new struct because
the steps are already assembled in Borrow→Prime→Lever→Exploit order. The procedure adds the
**label** to a stage that already runs, and populates the **`linkages`** that today start empty.

### 7b. Topology's ACTUAL influence today is ONE bit (measured, not assumed)

Topology contributes exactly **one boolean** to step construction — `prefer_same_contract` in
`pick_prime_and_exploit` (`campaign_planner.rs:370–381`):
```rust
let prefer_same_contract = topology_report
    .and_then(|r| r.ranked.first())
    .map(|(cls, _)| matches!(cls,
        PriceGatedVault | FlashDepositDrain | RewardAccumulator | ReflexiveSkew))
    .unwrap_or(false);
// comment: "topology INFORMS a same-contract preference, nothing FORCES an aim."
```
That is the whole of it. Topology does **not** fill the Borrow `authority_mechanism`, does **not**
supply the Prime `context`, does **not** choose the Lever. The rich per-family selector data that
topology already extracts flows to a **different destination** — the mutator bias.

### 7c. The key finding — topology already EXTRACTS the substrate; it just DELIVERS it to the wrong place

`TopologyHints::from_report_and_abi` (`topology.rs:434`) already walks the report and, for every
class with confidence ≥ 70, collects the **real ABI selectors per family** into `HintSet.selectors`.
That map — `ProtocolFamily → Vec<[u8;4]>` — **is the substrate the population procedure wants.**
Today it becomes a scheduler gamma-ray boost + a mutator weight (a bias knob). It never touches a
`CampaignSequence` step.

So the answer to "how does topology populate the substrate" is honest and precise:

- **What it extracts:** `classify_selector` → `ProtocolFamily` per ABI entry; `analyze` → ranked
  `Vec<(ExploitClass, confidence)>`; `TopologyHints` → the per-family real-selector map.
- **How it builds the substrate today:** it *doesn't* build the step substrate — it distills the
  selector map, then routes it to **mutator bias**. The `CampaignSequence` steps are built from
  `cache`, and topology only tips the prime/exploit sampling toward same-contract via one bit.
- **How it flows into each step at instantiation:** Borrow ← `cache.borrowable_tokens`; Prime ←
  corpus sampling nudged by `prefer_same_contract`; Lever ← `maybe_promote_lever` vocabulary;
  Exploit ← corpus sampling; `linkages` ← empty. Topology's real selector map is **absent** from
  every one of these slots.

### 7d. The feed-in point the procedure defines (re-point, don't rebuild)

The population procedure does not add a new extractor — topology already extracts everything. It
**re-points the same `family_selectors` map** from `TopologyHints` (bias) into the step slots at
instantiation:

- **Borrow.`authority_mechanism`** ← `family_selectors[FlashLoan | ERC20-approve | ERC4626-deposit]`
  at the `build_borrow_step` site (298), replacing the blind `borrowable_tokens.first()`.
- **Prime.`context`** ← the co-occurring family topology detected, at the `pick_prime_and_exploit`
  site (304), replacing the `prefer_same_contract` boolean with an actual filled slot.
- **`linkages`** ← populated (no longer `Vec::new()`) so the Seed→Mask→Checkpoint→Sink taint
  thread is instantiated, not left for the mutator to rediscover blind.

**The invariant:** the substrate topology produces is the `ProtocolFamily → selectors` map. Its
determinism (ledger §4, "function of the ABI") is **real at the source** — `classify_selector` is
deterministic — but today it is **not wired to the Borrow/Prime slots**, only to bias. The
procedure's contribution is exactly this rewire: same extraction, correct destination.

### 7e. Inheritance — the missing join key that would sharpen the substrate itself

**Origin:** DeepSeek data-analytics session (2026-07-05). The observation: without inheritance,
topology is forced to *guess a selector's purpose from its name*. Inheritance (the contract's
static type lineage) makes the purpose *readable* instead of guessed.

#### The disease (source-confirmed)

Two independent context-losses in the current topology pass, both verified:

1. **`classify_selector` is name-only** (`topology.rs:266`): its whole input is `(&[u8;4], &str)` —
   selector bytes + lowercased fn name. A `swap` is a `swap` regardless of *which contract* it's on.
   The `deposit(address) → ERC4626` disambiguation arm is a *symptom* — a name heuristic standing
   in for the type read `is IERC4626`.
2. **The pipeline flattens away contract identity** (`corpus_initializer.rs:617–626`): families are
   collected with `for (_, abis) in &address_to_abi` — the **address key is discarded** — into ONE
   flat `HashSet`. So `analyze`'s co-occurrence ("AMM + Chainlink → OraclePriceManip 85") fires even
   when the AMM and the oracle are **different, unrelated contracts.** `TopologyHints::from_report_and_abi`
   (`topology.rs:442`) flattens identically. → **archetype hallucination from a lossy join.**

**Verdict: REFINES (strongest topology enrichment proposed).** Inheritance is the join key that was
dropped. It repairs both losses: type-first selector meaning, and per-contract co-occurrence.

#### The critical split (do NOT collapse — same discipline as "mutator ≠ Layer-2 generator")

- **Inheritance-as-TYPE** (lineage `is ERC4626, Ownable, ReentrancyGuard`) → disambiguates *what a
  selector is*. This is Layer-1 typing / topology. **It does NOT author sequence order.**
- **Inheritance-as-ORDER** — a false equation. The call sequence is control-flow/state-dependent and
  stays owned by `CampaignSequence` + priors + frame. Inheritance sharpens LABELS, not ORDER.
- **The true kernel of the ordering intuition:** inherited *modifiers* (`Initializable`/`Pausable`/
  `Ownable`/`ReentrancyGuard`) are a **precondition/guard inventory** → they PRUNE the reachability
  space (paused/uninitialized/unauthorized states are dead) without authoring the sequence. This is
  *why generic fuzzers need "guiding"*: the guards live in inherited base contracts the fuzzer never
  modeled. So inheritance feeds **two different slots**: type lineage → topology; inherited modifiers
  → Prime `precondition_calls` / the Mask taint.

#### Where the lineage actually comes from (traced end-to-end)

Not Etherscan text, not regex over source — the **compiler AST**. Trace:

- Source enters via **blaz = an ingestion client, NOT a live compile service** (my "server-side" was
  wrong). `offchain_artifacts.rs:53 from_json_url` does `client.get(url).send()` — it *fetches a
  pre-built artifact*; the build happened earlier (separate blaz repo / `forge build`).
- **Run-mode determines AST availability:**
  - `ContractLoader::from_address` (pure onchain fork-by-address, `contract_utils.rs:576`) →
    `build_artifact = None` (594); ABI from **evmole bytecode decompilation** → **no source, no AST.**
  - `ContractLoader::from_config` (fork **+ local artifacts**, the audit-contest+fork hybrid,
    `contract_utils.rs:646`) → matches **fork bytecode → local artifact** via `find_contract_artifact`
    (704). Fork supplies **state/balances/addresses**; local repo supplies **ABI/source/source-map**.
    THIS is the user's actual workflow.
- **The AST is generated then dropped** (the decisive finding — extraction site CORRECTED after
  reading all three parsers, see 7e-note):
  - THREE ingestion parsers exist, and only two carry an AST:
    | Parser | Format | AST? | AST key |
    |---|---|---|---|
    | `from_json:64` | blaz-server (`success/bytecode/abi/sourcemap/sources`) | **No** — payload has no AST | — |
    | `from_solc_json:309` → `_from_solc_json:346` | forge build-info / standard-JSON | **Yes** | `output.sources.<file>.ast` (lowercase, compact) |
    | `from_command:246` solc → `_from_solc_json` | solc `--combined-json=…,ast,…` (requested at :205) | **Yes** | `output.sources.<file>.AST` (capital, legacy) |
  - `OffChainArtifact`/`ContractArtifact` have **no `ast` field**, and none of the parsers read it →
    **AST discarded at parse.** Downstream, `from_config` builds `BuildJobResult::new(…, Vec::new())`
    with `// TODO: offchain ast` (`contract_utils.rs:995`) — the *symptom* of the upstream drop.
  - (Contrast: `builder.rs::BuildJobResult::from_json:79` DOES parse+keep `json["ast"]` — a different
    format again. Multiple `from_json`s exist; the user's build-command path routes through
    `_from_solc_json`, which drops it.)

#### The AST gives the caveats — locked, per run-mode

`ContractDefinition` AST nodes carry `contractKind`, `baseContracts`, and **`linearizedBaseContracts`**
(the C3 MRO, precomputed by solc). Reading it = zero linearization work on our side.

| Caveat | `from_config` (fork + local repo — user's mode) | `from_address` (pure onchain fork) |
|---|---|---|
| #1 source→AST | **Recoverable** — source already local; AST dropped at one parse | Open — evmole bytecode only, no source |
| #2 proxy | 1967 slots (`snapshot_delta.rs:60`) resolve impl addr → its local artifact | Half — resolves address, impl still bytecode |
| #3 C3 linearization | **Locked** — `linearizedBaseContracts` in the AST | Open — no AST |

#### Recovery — bounded, one module (NOT a source-acquisition sidecar)

1. Add `asts: Vec<(String, Value)>` to `OffChainArtifact` (beside `sources`, parallel-ordered).
2. **[SITE CORRECTED]** Extract in **`_from_solc_json`** (`offchain_artifacts.rs:346`), inside the
   per-file source-`id` loop (lines 378–401) that already reads `output.sources.<file>.id`. Read the
   sibling key: `output["sources"][name].get("ast").or_else(|| get("AST"))` → clone `Value` if present,
   `None` otherwise (degrade, don't panic — some files lack an AST). Populate `asts` in the SAME
   `id`-ordering loop so it parallels `result.sources` (per-file, NOT the per-contract loop below).
   The blaz-server `from_json:64` path stays AST-less (payload never had one).
3. Thread it at `contract_utils.rs:995` — replace `Vec::new()` with the matched artifact's `asts`.
4. Lineage reader consumes `BuildJobResult.asts` → `(contract, lineage, family)` key → feeds
   `classify_selector` (type-first) + `analyze` (per-contract co-occurrence) + Prime preconditions.

#### The one genuine residual (precisely located)

**AST schema skew, pinned to one read site.** `solc --combined-json` emits `AST` (capital, legacy
node shape → `linearizedBaseContracts` under `attributes`); forge/standard-JSON emits `ast`
(lowercase, compact → `linearizedBaseContracts` top-level). Both land in `_from_solc_json`'s `output`
map, so the *extraction* is one `.get("ast").or_else(get("AST"))`. The *reader* must then be
defensive about node shape: try top-level `linearizedBaseContracts`, else `attributes.…`, else
degrade to name-first. Two capitalizations at the parse; two node shapes at the reader.

#### The recurring shape (why this whole thread stayed cheap)

Every layer ended at the same pattern — **capability present, discarded/idle at exactly one wiring
point**: `family_selectors` → mutator-bias only (7c); EIP-1967 slots → ownership-oracle only;
`ast` → parsed-past at `OffChainArtifact::from_json`. The inheritance feature is the sum of
*un-dropping* these, not building anything new — **as long as the run is Config mode (fork + local
repo).** For pure `from_address` runs the data genuinely isn't there and a source sidecar *would* be
new work; that mode is out of scope for the contest/bounty workflow this targets.

**Bonus — the economic-fork model clarified (closes a standing conceptual gap):** a fork is
*lazily-loaded real state* (balances/reserves fetched per-slot from RPC at the pinned block, cached),
with execution local in revm. "Moving money" = **net balance delta measured against real forked
balances**; the flashloan is local capital synthesis against real reserves. No real funds move, no
mocking needed — the fork's lazy-load *is* the "preload live balances" step. State always comes from
the fork (local ABIs can't reduce that RPC); only ABI/source is replaceable by the local repo.

#### Why NOT aggressive state mutation (the Harvey shortcut) — and why that mandates inheritance

Harvey (Wüstholz/Christakis, ConsenSys) uses two techniques: **input prediction** (secant on
*branch distance* → coverage — SPECTOR runs the same secant but on the *profit ledger* → economic
magnitude; `mutator.rs:656`) and **demand-driven fuzzing** with **aggressive fuzzing = mutating
persistent state directly** to cheaply test if a longer sequence pays off. Harvey's own frame matches
ours: *last txn = the checked path, previous txns = state setup* ≡ **Lever/Exploit vs Borrow/Prime**;
his *~60% of bugs need multiple txns* validates `CampaignSequence`.

**But the aggressive-state-mutation technique is FORBIDDEN for an economic fuzzer on a fork.** If you
poke forked state directly (force a slot/balance), the net-delta profit becomes **fictional** — you'd
"prove" a drain that only exists because you hand-wrote its precondition. That breaks the
real-state→real-impact invariant. An attacker on mainnet **cannot** set a storage slot; they must call
the right functions, in the right order, with the right permissions. So anything SPECTOR finds under
real-flow-only constraints is **attacker-realizable with real txns and real gas** — that realizability
is *what makes the profit measurement valid*. Harvey needn't respect it because he models *coverage*,
not *execution economics*.

**Consequence:** Harvey answers "is this deep state worth reaching?" **stochastically** (poke it and
see). SPECTOR can't poke → must answer **structurally** — read the guard/precondition inventory
(inherited `Pausable`/`Ownable`/`Initializable`/`ReentrancyGuard` modifiers → which deep states are
legitimately reachable). **§7e's inheritance work is the economic-fuzzer replacement for the one
Harvey technique the real-flow invariant forbids.** Not a nicety — the structural route is mandatory
*because* the stochastic shortcut fabricates profit.
