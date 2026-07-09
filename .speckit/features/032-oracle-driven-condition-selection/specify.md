# Feature 032 — Oracle-Driven Execution Condition Selection

## The novelty (one sentence)

Traditional fuzzers primarily optimize over transaction inputs. SPECTOR-FUZZ introduces execution
conditions as a first-class search dimension. Oracle evidence is used not only to mutate calldata,
but to determine which execution conditions — identity, temporal progression, liquidity, storage
configuration, or callback context — should be modified to maximize the probability of reaching
economically significant states.

That sentence is why this isn't "just another mutator."

## Idea (not yet specced)

Auditors ask "what if the caller changes?", "what if time advances?", "what if balances shift?"
Cheat codes let the fuzzer enact those same what-ifs programmatically. The architectural leap is
having the CONTROLLER choose which condition to vary based on oracle EVIDENCE — not a human flag.

The search space difference:
- Traditional fuzzer: `f(calldata)` — one mutation dimension
- SPECTOR-FUZZ: `f(calldata, caller, balance, timestamp, storage, topology)` — multi-dimensional
  execution condition space

Currently only the Value condition (txn_value / secant) is fully evidence-driven end-to-end.
The others are human-flagged or not wired at all:

| Condition | Primitive | Status |
|---|---|---|
| Capital | flash loan Borrow step | Partially oracle-driven (topology lender pick) |
| Value magnitude | `txn_value` / secant | FULL — taint dim → probe_delta → secant → scheduler |
| Identity | `EVMInput.caller` | Partial — Permission oracle → structural_pin, no magnitude gradient |
| Time | `vm.warp` | Human-flagged (`--temporal-skimming`) — oracle doesn't drive warp injection |
| Storage/state | `vm.store` / `set_code` | Human-flagged (preset setup only, not adaptive) |

## The gap

For temporal: ERC4626 oracle detects price-per-share diverges with time (temporal evidence exists
via Feature 029 divergence optimizer) but the planner still requires `--temporal-skimming` to
inject the warp. The evidence doesn't automatically activate the condition.

Goal: when oracle evidence indicates a condition matters → system automatically enables and tunes
that condition without human flagging. Same loop that Value already has, applied to Time, Identity,
and Storage.

## Why it matters

Traditional fuzzers explore INPUT space only (calldata, txn_value, caller) within fixed execution
conditions. Adding evidence-driven condition selection explores a second layer — EXECUTION
CONDITION space — at the same oracle-guided depth. Many DeFi vulnerabilities are conjunctions:
caller must be X AND time must be after Y AND balance must exceed Z. Input mutation alone never
finds those. Evidence-driven condition selection can.

## README clarification

The README lists a "full suite" of cheat codes (vm.prank, vm.deal, vm.warp, vm.roll, vm.store,
vm.etch, computeCreateAddress, getNonce, expectRevert, expectEmit, etc.). These ARE implemented
— in the cheat code middleware (`src/evm/middlewares/cheatcode/`). That means the execution engine
correctly handles these calls when a contract under test invokes them.

That is the ACTION SPACE. Feature 032 is the CONTROLLER that chooses which action to apply based
on oracle evidence. Having a full action space and having an evidence-driven controller are
different properties. The README accurately describes the former; it does not claim the latter.

## Proposed architecture: Execution Intent Layer

The controller should not think in terms of cheat codes. It should think in terms of INTENT.
The intent layer resolves intent to the correct primitive — decoupling the planner from implementation.

```
PromotionCandidate
        ↓
Execution Intent        ← the research contribution
        ↓
Primitive Selection
        ↓
Cheat Code / EVMInput field
```

Intent → Primitive mapping:

| Intent | Primitive |
|---|---|
| Identity transition needed | `vm.prank` / `startPrank` / `EVMInput.caller` |
| Temporal progression needed | `vm.warp` / `vm.roll` / `CampaignSequence.warps` |
| Liquidity precondition needed | `vm.deal` / flash loan Borrow step |
| Storage hypothesis | `vm.store` / `vm.load` / `set_code` |
| Callback injection | nested prank + attacker bytecode |
| Deployment prediction | `computeCreateAddress` / `computeCreate2Address` |

This abstraction is stronger because: when a new execution primitive appears, you don't rewrite
the planner — you teach the intent layer how to realize that intent. The planner emits
"need temporal precondition"; the intent layer selects `vm.warp` vs `vm.roll` based on what
the target requires.

A human auditor thinks: "maybe this requires a different caller." The intent layer arrives at
the same conclusion from oracle evidence and realizes it with `startPrank`. That's the same
reasoning process, systematized.

## The core reframe: BPLE is a compiled execution plan, not a campaign template

Before Feature 032, BPLE looks like a fixed sequence of steps:
  Borrow → Prime → Lever → Exploit

After Feature 032, it is correctly read as a sequence of goals:
  Capital Intent → Identity/State Intent → Value/Temporal Intent → Extraction Intent

**BPLE is not a campaign template. It is a compiled execution plan.**
Each stage exists because the planner is trying to satisfy an execution condition:
- Need capital           → Borrow
- Need trusted identity  → Prime
- Need state transition  → Lever
- Need economic outcome  → Exploit

BPLE was already executing intents. Those intents were encoded structurally rather than
explicitly. Feature 032 does not introduce a new intent layer — it exposes the intent layer
that BPLE has implicitly contained from the beginning. That is a more accurate description
than "032 adds a new subsystem."

## N-stage generalization

If BPLE is an execution plan over intents, it no longer has to be four stages. The planner
can synthesize a campaign from whatever execution conditions the evidence requires:

  Need Capital + Need Identity + Need Time + Need Callback + Need Storage Hypothesis
        ↓
  Compose Execution Plan
        ↓
  Realize with primitives
        ↓
  Execute

The planner is no longer selecting from predefined campaign shapes. It is synthesizing a
campaign from the execution conditions required by the oracle evidence. That is the N-stage
generalization of BPLE.

## The defensible claim (what this enables)

NOT: "The engine reasons exactly like a human auditor." (too broad, anthropomorphizing)

YES: "The engine represents and composes execution intents that correspond to common classes
of reasoning performed by experienced smart contract auditors, and uses oracle-derived evidence
to instantiate those intents into executable campaign plans."

That is a systems claim. Observable in the architecture. Testable. Avoids overclaiming.

The barrier-to-entry answer this implies: not "more features" — but "the engine automatically
constructs the execution conditions that experienced auditors normally compose mentally."

## Compound intents — the real exploit model

Real exploits are conjunctions of execution conditions, not single what-ifs:
  "become the router → wait three blocks → borrow capital → call harvest"

That's four intents composed into one execution plan. The planner shouldn't produce a SINGLE
intent — it should produce an EXECUTION PLAN composed of multiple intents:

```
Identity Intent
      +
Temporal Intent
      +
Capital Intent
      ↓
Execution Plan
      ↓
Primitive Selection
      ↓
Campaign
```

This aligns directly with BPLE, which is already a compound execution plan:
- Borrow → Capital Intent (liquidity precondition)
- Prime  → Identity/State Intent (access setup)
- Lever  → Temporal/Value Intent (condition amplification)
- Exploit → Extraction

BPLE is the current implementation of compound intents, built before the intent abstraction was
named. Feature 032 is making that abstraction explicit and evidence-driven rather than
structure-hardcoded.

## Honest current state (what's implemented vs. what's future)

**Implemented**: execution primitives (full cheat-code suite in middleware). Action space exists.

**Implemented controller logic**: Value condition is oracle-driven end-to-end (taint → secant →
scheduler). Identity condition is partially oracle-driven (Permission oracle → structural_pin).

**Future controller logic**: temporal, storage, and callback conditions are human-flagged. The
intent layer does not exist yet — kind maps directly to primitive with no intermediate abstraction.

This distinction matters for credibility: the primitives exist, one dimension of the controller
is built, the general intent layer is the research contribution still to build.

## Not yet specced

Needs code investigation before a plan can be written. Open questions:
- How does oracle evidence map to a specific intent? (temporal divergence → temporal intent)
- Where does the intent layer live — planner, new module between planner and mutator?
- How does the scheduler learn from primitive OUTCOMES vs. corpus insertion dim-flow?
- How are compound intents ordered? (capital before temporal, or evidence-driven ordering?)
