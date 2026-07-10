# System Inventory & Thesis-to-Code Alignment Matrix

**Method:** static, code-verified only (grep/read against HEAD `c53eb7c`, no test execution). Every
row below is backed by a file:line citation, not a spec claim taken on faith. This document exists
to answer one question across the whole codebase, not per-feature: **for a given oracle/leak class,
does the closed loop (Oracle → Objective → Intent → Primitive → Campaign → Scheduler → New
Observation) actually complete, or does it silently dead-end?**

Consolidates three prior review passes (self + two independent Codex passes) into one artifact so
future feature work has a single source of ground truth instead of re-deriving it per-PR.

---

## 1. Oracle capability map

20 oracle files exist in `src/evm/oracles/`. `OracleType` (`src/evm/mod.rs:526-545`) has 18
variants. `LeakClass::oracles()` (`src/evm/leak_class.rs:61-71`) claims to be the SSOT binding every
oracle to a primitive.

| Oracle file | OracleType variant | LeakClass home | Emits `PromotionCandidate`? | Loop status |
|---|---|---|---|---|
| `erc20.rs` | ERC20 | Value | No | Detect-only; feeds ledger indirectly (see §2 note) |
| `fee_on_transfer.rs` | FeeOnTransfer | Value | No | Detect-only |
| `rebasing.rs` | Rebasing | Value | No | Detect-only |
| `erc4626.rs` | ERC4626 | Value | No | Detect-only; **also bypasses `-d` entirely (§5.3)** |
| `function.rs` | Function | Permission | **Yes** (`function.rs:265`) | **Only fully-wired producer besides Value ledger** |
| `snapshot_delta.rs` | Ownership | Ownership | **No** — only `push_to_output()` (`:164-193`) | **Producer gap** — routing in 031 is dead code |
| `invariant.rs` | Invariant | Invariant | No | Producer gap (033 scoped to fix) |
| `state_comp.rs` | StateComparison | Invariant | No | Producer gap (033 scoped to fix) |
| `echidna.rs` | Echidna | Invariant | No | Producer gap (033 scoped to fix) |
| `reentrancy.rs` (oracle) | Reentrancy | ControlFlow | No | Producer gap — no feature currently scoped to fix it |
| `arb_call.rs` | ArbitraryCall | Message | No | Deferred by design (019-B gate) |
| `v2_pair.rs` | Pair | **none** | No | **Orphan** — no `LeakClass` arm maps to `Pair` at all |
| `arb_transfer.rs` | MathCalculate | **none** | No | **Orphan** — no `LeakClass` arm maps to `MathCalculate` |
| `typed_bug.rs` | TypedBug | **none** | No | **Orphan** |
| `selfdestruct.rs` | SelfDestruct | **none** | No | **Orphan** (note: `LeakClass::from_str` aliases the string `"selfdestruct"` to `Ownership` — a naming collision, see §5.1) |
| `approval.rs` | Approval | **none** | No | **Orphan** |
| `crosschain.rs` | CrossChain | **none** | No | **Orphan** |
| `nft.rs` | NFT | Ownership (added 028-orphan bind) | No | Detect-only |
| `freshness.rs` | **not in `OracleType` at all** | **none** | No | **Fully outside the taxonomy** — auto-activated by ABI fingerprint (`evm_fuzzer.rs:622-628`), invisible to `-d`, invisible to `LeakClass` |
| `temporal_skim.rs` | **not in `OracleType` at all** | **none** | No | **Fully outside the taxonomy** — gated only by `--temporal-skimming` (`evm_fuzzer.rs:592-597`) |

**Headline number:** of 20 oracle files, **18 never touch `PromotionCandidate`** — they detect,
call `EVMBugResult::push_to_output()`, and stop. Only `function.rs` (Permission) and the ledger
feedback path described in §2 (Value) ever feed the optimization loop. That is not "Value is
closest to complete, others partial" — it is "2 of 20 oracle surfaces participate in the loop at
all; the rest are pre-020 terminal-event fuzzing, unchanged."

**Orphans (6 `OracleType` variants with zero `LeakClass` mapping):** `Pair`, `MathCalculate`,
`TypedBug`, `SelfDestruct`, `Approval`, `CrossChain`. Feature 020's stated success criterion #1 was
"one source of truth... no second selection path remains" — these six oracles are real, wired,
`-d`-selectable detectors that the SSOT does not know exist. They cannot silently regress (they're
still detect-only, same as before 020), but the SSOT's claim to completeness is false as written.

---

## 2. LeakClass lifecycle map

For each of the 6 declared primitives, tracing producer → objective encoding → planner routing →
secant amplification → scheduler feedback:

| LeakClass | Producer exists? | Objective encoding | Planner routing | Secant amplification | Scheduler feedback |
|---|---|---|---|---|---|
| **Value** | Yes — but not any oracle in `.oracles()`. The actual producer is `record_aposteriori_candidate` (`feedbacks.rs:465-485`), a ledger-feedback mechanism gated by `--reflexive-lever`, independent of whether ERC20/FeeOnTransfer/Rebasing/ERC4626 oracles are even enabled. | `best_inflow: u128` (unsigned magnitude) — fits Value natively | `value_lever_pin`, unconditional (`mutator.rs:1193-1197`, `campaign_planner.rs:352-362`) | `secant_promotable(Value, _) = true` always (`mutator.rs:311`) | Generic `promote_boost` on `(contract,selector)` match, kind-agnostic (`scheduler.rs:515-533`) |
| **Permission** | Yes — `function.rs:265` | Reuses `best_inflow` (usually 0 — a call that moves no value; the field is semantically wrong here, see §5.2) | `structural_pin`, gated on `matches!(kind, Permission\|Ownership)` (`mutator.rs:1179-1189`) | `secant_promotable(Permission, n_args) = n_args >= 1` (`mutator.rs:312`) | Same generic `promote_boost`, kind-agnostic — **fires today**, contrary to THESIS.md's "no scheduler feedback on outcomes" claim (see §6) |
| **Ownership** | **No.** `snapshot_delta.rs` never constructs a `PromotionCandidate` (§1). | N/A — no candidate ever exists | Dead code: `structural_pin` filter includes `Ownership`, but no candidate with that kind is ever produced | `secant_promotable(Ownership, _) = false` (explicit, tested `mutator.rs:2246`) — correctly excluded, but moot since it never reaches here | N/A — never reaches the scheduler check |
| **Invariant** | **No.** `invariant.rs`/`state_comp.rs`/`echidna.rs` report and stop. | N/A | **Would still fail even with a producer**: `value_lever_pin` filter is `c.kind == LeakClass::Value` — strict equality, not `matches!(.., Value\|Invariant)` (`mutator.rs:1196`). 033's claim that "031's routing handles Invariant automatically" is false. | `secant_promotable(Invariant, _) = false` (explicit, tested `mutator.rs:2247`) — would need updating alongside the filter | N/A |
| **ControlFlow** | **No.** `reentrancy.rs` (oracle) reports and stops. Not scoped by any existing feature (031 named it as a gap; no feature owns the fix). | N/A | Would land in `structural_pin` IF the filter is extended to include `ControlFlow` (031 spec's own suggestion, not yet done) | Not in `secant_promotable` match at all — falls to `_ => false` | N/A |
| **Message** | **No** — by design, gated on 019-B (cross-contract provenance, not built). `LeakClass::Message.middleware()` correctly returns `None`. | N/A | N/A | N/A | N/A |

**The one line that matters:** only Value has a producer AND correct routing AND amplification AND
scheduler feedback. Permission has producer + routing + amplification + (previously undocumented)
scheduler feedback — it is closer to closed-loop than any spec currently credits. Ownership has
routing with no producer (silent dead code). Invariant has neither producer nor correct routing
(the routing bug is independent of and additional to the missing producer). ControlFlow has
neither, and no feature currently owns the gap. Message is correctly deferred.

---

## 3. Action-space inventory (the primitives, decoupled from who chooses them)

Cheat-code surface actually implemented in `src/evm/middlewares/cheatcode/mod.rs` (grepped
`VmCalls::` match arms): `prank_0/1`, `startPrank_0/1`, `stopPrank`, `warp`, `roll`, `deal`, `store`,
`load`, `etch`, `computeCreateAddress`, `computeCreate2Address_0/1`, `getNonce_0`, `chainId`,
`coinbase`, `difficulty`, `prevrandao_0/1`, `fee`, `txGasPrice`, `label`, `getLabel`,
`readCallers`, `record`, `recordLogs`, `getRecordedLogs`, `accesses`, `createSelectFork_0/1/2`,
`expectRevert_0/1/2`, `expectEmit_0/1/2/3`, `expectCall_*`, `expectCallMinGas_*`, plus the full
`assertEq`/`assertGt`/`assertApprox*` family (Foundry-test-compat, not exploit primitives). This
confirms the README's "full cheat-code suite" claim — the action space genuinely is that broad.

Campaign-level primitives (`campaign_planner.rs`): `Borrow` step (flashloan), `Prime`/`Exploit` ABI
steps (`build_abi_step`), `Structural` step (`build_structural_step`), `warps: Vec<(usize, u64)>`
(block advance before a step), `promoted: Vec<usize>` (secant-tunable step indices),
`divergence_value` pin (pre-seeded `txn_value`).

**None of this is in dispute** — the action space is real and matches 032's characterization. The
gap is entirely on the controller side (§2, §5), not the primitive side.

---

## 4. Planner / campaign-shape inventory — assembly order (as-built)

`plan_campaign_sampled` (`campaign_planner.rs:308-434`) assembles steps in this literal order:

1. Borrow (`:339-341`)
2. Prime + Exploit picks computed, Prime pushed (`:344-347`) — Exploit is held and pushed **last**, after step 6 below
3. Dynamic Value lever, if `value_lever_pin` set (`:348-362`)
4. Static reflexive-list cold-start lever, if no dynamic fire AND `effective_reflexive` (`:363-373`)
5. `aposteriori` arm flag set (`:379`, no step pushed)
6. **Structural pin appended here** (`:381-396`) — i.e., *after* steps 3-4
7. Divergence-value pin applied to first non-Borrow step (`:398-405`)
8. Exploit step pushed (`:407-409`)
9. Warp computed and inserted before the Exploit index (`:420-433`)

**Confirmed ordering defect:** step 6 runs after steps 3-4. `value_lever_pin` and `structural_pin`
can't both be non-`None` simultaneously (both read the same `PromotionCandidate` singleton, filtered
on mutually exclusive `kind`s) — but the **static** cold-start lever (step 4) is gated only on the
`--reflexive-lever` flag, independent of the candidate. So: flag on, and the live singleton candidate
happens to be `Permission`/`Ownership` → the static lever (Lever slot) lands *before* the structural
pin (Prime slot) in the assembled sequence. That inverts the BPLE contract every one of 031/032/033
states explicitly ("must precede the Lever"). Confirmed independently by two review passes; not
disputed by either.

Temporal warp activation (`:420-433`) has two independent triggers, not one as THESIS.md / 032
describe: `temporal_skimming` (human flag) **or** `ts_located` (`dimension_warp` flag AND
`TIMESTAMP_DIM_LOCATED` static, set by taint analysis in Feature 017 Wire B,
`feedbacks.rs:441-445`). The second path is oracle/taint-evidence-driven. THESIS.md's "Temporal
(warp injected, no oracle-driven activation)" undercounts this — it should read "partially
oracle-driven, same tier as Identity," matching the pattern the Value lever already documents
(dynamic evidence path + flag-gated static fallback).

---

## 5. Silent-failure audit

### 5.1 Naming collision in `LeakClass::from_str`
`leak_class.rs:110`: `"selfdestruct" => LeakClass::Ownership`. But `OracleType::SelfDestruct`
(`selfdestruct.rs`) is an orphan with no `LeakClass` mapping in `.oracles()` (§1). The alias implies
`selfdestruct` the detector is part of Ownership; `.oracles()` says otherwise
(`LeakClass::Ownership.oracles() == [Ownership, NFT]`, no `SelfDestruct`). Two authoritative-looking
methods on the same "SSOT" enum disagree with each other.

### 5.2 `best_inflow: u128` cannot hold what 033 proposes to put in it
033's own fix snippet writes `best_inflow: violation_distance // signed distance from invariant
boundary` into a field typed `u128` (unsigned) at `campaign_planner.rs:104`. This is a type error
in the spec's own example, not a hypothetical — 033 is not implementable as written without either
widening the field or losing the sign (which defeats "larger distance = deeper violation" if
direction matters). Independently, Permission promotions already store `best_inflow = 0` today
(a call that moves no value) — the field is being reused across two semantically different
concepts (value magnitude vs. presence flag) even before Invariant adds a third (signed distance).
This is the concrete evidence behind Codex's Issue 3 (generic objective score) — it's not a future
nice-to-have, current code already strains the field's single `u128` meaning.

### 5.3 ERC4626 bypasses the `-d` flag system entirely
`evm_fuzzer.rs:600-609`: `ERC4626Oracle` activates whenever `artifacts.erc4626_vaults` is
non-empty — **no check against `oracle_types` / `args.detectors` at all**. It fires even if the user
never passed `-d value_leak` or `-d erc4626`, and — separately — `OracleType::from_strs("all")`
(`mod.rs:604-623`) **does not include `OracleType::ERC4626` in its hardcoded list at all** (17 of 18
variants are listed; ERC4626 is missing). So `-d all` does not select ERC4626 through the normal
path, and no `-d` value can *deselect* it either. `LeakClass::Value.oracles()` lists `ERC4626`
as if `-d value_leak` controls it; in reality activation is a third, independent mechanism (ABI
fingerprint auto-detect) that ignores `-d` in both directions. The 020 spec's stated regression
guard — "a golden test asserts `-d all` and each `-d <oracle>` yield an identical oracle set
pre/post migration" — cannot catch this, because ERC4626's activation was never part of the set
`from_strs` produces.

### 5.4 Two oracles live entirely outside `OracleType`/`LeakClass`
`freshness.rs` and `temporal_skim.rs` (§1) are real detectors, wired into `evm_fuzzer.rs`, but have
no `OracleType` variant and no `LeakClass` — `-d` cannot select or deselect them, and 020's "one
source of truth" claim doesn't cover them at all. Not a regression (they predate/sit beside 020 by
design), but worth registering as known taxonomy gaps rather than leaving them undiscoverable.

### 5.5 Scheduler feedback is less absent than the specs claim
Both THESIS.md and 032 describe Identity/Permission as having "no scheduler feedback on outcomes."
`scheduler.rs:515-533`'s `promote_boost` is gated only on `cand.set` + `(contract, selector)` match
— **no `kind` filter**. Permission promotions get the identical corpus-power boost Value gets today.
The real gap is narrower than stated: there is no *objective-magnitude-aware* feedback (weighting
the boost by how much privilege depth or violation distance improved), but presence-based feedback
already exists uniformly across kinds. Docs should say "kind-agnostic but not objective-aware," not
"absent."

---

## 6. Thesis-to-code alignment matrix

| Thesis claim | Code reality | Status |
|---|---|---|
| "Value objective is the only fully-realized loop end-to-end" | True, and Permission is closer than credited (producer + routing + amplification + generic scheduler feedback all exist) | **Understates Permission** |
| "Ownership: structural_pin expanded in 031, no scheduler feedback" | No producer exists at all — the 031 routing is dead code, not a partial loop | **Overstates — should move to "producer gap," same tier as ControlFlow/Invariant** |
| "Temporal: warp injected, no oracle-driven activation" | A taint-driven path (`ts_located`) already exists, flag-gated like the Value dynamic/static split | **Overstates the gap — should be "partially oracle-driven"** |
| "031's routing handles Invariant automatically via `value_lever_pin`" (033) | False — filter is `== Value`, strict equality; `secant_promotable` hard-excludes Invariant | **False as written** |
| "The secant optimizes whatever objective the oracle defines" (033) | `best_inflow: u128` is the only field; already overloaded across Value/Permission semantics; cannot hold 033's own proposed signed distance | **Aspirational, not yet true — type-level blocker identified** |
| "`-d all` continues to select the full registry" (020 risk mitigation) | False for ERC4626 — auto-activated independent of `-d`, and absent from the `all` literal list | **False as written** |
| "One source of truth... no second selection path remains" (020 success criterion) | 6 `OracleType` orphans (Pair, MathCalculate, TypedBug, SelfDestruct, Approval, CrossChain) have zero `LeakClass` mapping; 2 oracles (freshness, temporal_skim) sit fully outside `OracleType` | **False as written — SSOT covers 12/18 registered types and 0 of 2 out-of-band oracles** |
| "Cheat-code suite is the action space, fully implemented" (032) | Confirmed — full `VmCalls` inventory matches the README claim | **True** |
| "BPLE: Permission/Ownership → Prime, must precede the Lever" (031) | Violated when `--reflexive-lever` + a live Permission/Ownership candidate coexist — static lever lands before the structural pin | **False under a specific, reachable condition** |

---

## 7. Recommended remediation order

Ordered by "what unblocks the most downstream correctness with the least new surface area":

1. **Fix the assembly-order bug (§4)** — move structural-pin insertion before the lever block.
   Self-contained, no new producers needed, closes a real correctness gap right now.
2. **Fix `-d all` / ERC4626 activation split (§5.3)** — either add `ERC4626` to the `all` list and
   gate auto-activation behind `oracle_types.contains`, or explicitly document ERC4626 as
   always-on-independent-of-`-d` and remove it from `LeakClass::Value.oracles()` so the SSOT
   doesn't claim control it doesn't have.
3. **Ownership + Invariant producers (§2)** — emit `PromotionCandidate` from `snapshot_delta.rs`,
   `invariant.rs`/`state_comp.rs`/`echidna.rs`. Do this together with #4, not before — a producer
   with no consumer is exactly the silent-failure pattern this document exists to prevent.
4. **Extend routing + `secant_promotable` for Invariant (§2)** — without this, #3 produces
   candidates the mutator still can't route or amplify.
5. **Resolve the `best_inflow` type/semantics problem (§5.2)** before or alongside #3/#4 — adding
   Invariant's signed distance into a `u128` field needs a decision now, not after the producer
   ships.
6. **Register the 6 orphaned `OracleType` variants + 2 out-of-band oracles into `LeakClass`
   (§1, §5.4)** — lowest urgency (no active regression), but required before any claim that the SSOT
   is complete.
7. **Doc pass last** — once 1-6 land or are consciously deferred, update THESIS.md / 031 / 032 / 033
   "built vs. future" sections to match reality, including the corrections in §6 (Permission's
   existing scheduler feedback, Temporal's existing taint-driven path, Ownership's true producer-gap
   status).

Doing the doc pass before the code fixes would re-create the exact problem this review was
commissioned to catch: specs that read as coherent architecture while individual code paths
silently diverge from them.
