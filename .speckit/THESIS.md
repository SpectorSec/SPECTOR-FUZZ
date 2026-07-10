# SPECTOR-FUZZ — Architectural Thesis

## Plain-language description

Oracles provide the signal. The planner turns signal into intent. The execution engine realizes
that intent through primitives. The system keeps observing, deciding, acting, and re-observing.
That is the closed loop.

## One-sentence description (formal)

A closed-loop autonomous exploration system in which oracles produce optimization objectives,
the planner composes execution intents, and the execution engine realizes those intents through
execution primitives to iteratively characterize economically significant program states.

## The control loop

```
New Observation
      │
      ▼
Oracle
      │
      ▼
Optimization Objective   ← What are we trying to optimize? (Feature 033)
      │
      ▼
Execution Intent         ← How should we perturb the system? (Feature 032)
      │
      ▼
Primitive Selection
      │
      ▼
Campaign Execution
      │
      ▼
New Observation          ← loop
```

Features 031, 032, and 033 are not separate features. They are three stages of one control loop.

## The optimization objective table

The secant is not a value optimizer. It is a generic optimization engine whose objective
function is supplied by the oracle. That is why the same infrastructure works across every
leak class.

| Leak Class   | Optimization Objective                              |
|---|---|
| Value        | maximize extracted value (best_inflow)              |
| Permission   | maximize privilege escalation depth                 |
| Ownership    | maximize unauthorized ownership transition          |
| Invariant    | maximize deviation from invariant boundary          |
| ControlFlow  | maximize unsafe state reach / recursive depth       |
| Message      | maximize attacker-controlled dispatch reach         |

## The action space vs. the controller

The cheat-code suite (vm.prank, vm.warp, vm.deal, vm.store, vm.roll, computeCreate2Address,
nested pranks, etc.) is the ACTION SPACE. It determines what the engine can do.

The controller — oracle → objective → intent → primitive — is the DECISION SYSTEM. It
determines what the engine chooses to do based on evidence.

A system with a full action space and no controller is an API.
A system with a controller that selects from the action space based on oracle evidence is an
autonomous exploration architecture.

## BPLE as compiled execution plan

BPLE (Borrow → Prime → Lever → Exploit) is not a campaign template. It is a compiled
execution plan. Each stage satisfies an execution condition:

- Need capital           → Borrow  (Capital Intent)
- Need trusted identity  → Prime   (Identity/State Intent)
- Need state transition  → Lever   (Value/Temporal Intent)
- Need economic outcome  → Exploit (Extraction Intent)

BPLE was already executing intents. Those intents were encoded structurally rather than
explicitly. Feature 032 exposes the intent layer that BPLE has implicitly contained from
the beginning.

The N-stage generalization: the planner composes whatever intents the evidence requires.
Not four fixed stages — a synthesized execution plan from oracle-derived conditions.

## Terminal events vs. optimization objectives

Traditional fuzzers treat oracle findings as terminal:
  Execute → Find bug → Report → Stop

SPECTOR-FUZZ treats oracle findings as intermediate control signals:
  Execute → Oracle fires → PromotionCandidate → Planner → Optimize → Execute again

This applies to every leak class. An invariant violation is not a result — it is evidence
that the preceding execution step is highly informative. Promote it. Optimize around it.
Characterize the failure region.

## The defensible claim

NOT: "The engine reasons exactly like a human auditor."

YES: "The engine represents and composes execution intents that correspond to common classes
of reasoning performed by experienced smart contract auditors, and uses oracle-derived evidence
to instantiate those intents into executable campaign plans."

The barrier-to-entry answer: the engine automatically constructs the execution conditions
that experienced auditors normally compose mentally. Not because it has more features —
because it systematizes the intent-composition process.

## What is built vs. what is future

**Built and closed-loop**: Value condition (taint → secant → scheduler). The Value objective
is the most fully-realized loop end-to-end.

**Built, near-complete loop**: Permission (oracle → structural_pin → Prime → presence-based
scheduler boost via promote_boost in scheduler.rs — kind-agnostic but not
objective-magnitude-aware; closer to complete than previously documented). Invariant (producers
in invariant.rs/echidna.rs/state_comp.rs now emit PromotionCandidate; routes to value_lever_pin
+ secant; 031-C/033-A). Temporal (warp injected; ALSO has a taint-driven oracle path via
ts_located / TIMESTAMP_DIM_LOCATED from Feature 017 Wire B — partially oracle-driven, same tier
as the Value dynamic/static split; "no oracle-driven activation" understated this).

**Built, producer gap closed**: Ownership (producer added to snapshot_delta.rs in 031-C;
structural_pin Ownership branch now live, not dead code).

**Specced, not built**: Execution Intent Layer (032). ControlFlow producer. N-stage planner.

**Not yet specced**: Message condition (019-B gated). Compound intent ordering. Scheduler
objective-magnitude weighting (promote_boost is presence-only; no kind-aware magnitude
scaling yet).
