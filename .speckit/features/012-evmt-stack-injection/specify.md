# Feature 012 — EVM Stack Taint Injection Detection

**Status:** Research (Complete)
**Owner:** DeepSeek + user
**Last updated:** 2026-06-30

---

## Summary

This was an investigation phase. Key discoveries and their destinations:

| Discovery | Consumed By |
|---|---|
| TAINT 1 sv_flows → storage provenance mapping | 013 Phase 1 |
| DELEGATECALL push_ctx bugs (calldata indices + storage clear) | 013 Phase 0 |
| LibAFL injection hook pattern (byte match at CALL boundary, no taint prop) | 013 Phase 1 |
| Four-link exploitation chain (TAINT→GUARD→SINK→SELECTOR) | 013 Phase 2 |
| TAINT 2 guard translation (BLOCKED + prank = bypass) | 013 Phase 2 |
| Persistent cross-execution taint on FuzzHost | 013 Phase 3 |
| Value-confirmed provenance (TaintProvenance struct) | 013 Phase 4 |
| Router classifier + selector filter for calldata-timing FP | 013 Phase 2 |
| Feedback → scheduler mutation weighting | 013 Phase 5 |
| Static kill chain grammar bridge (TAINT 1-3 → fuzzer init) | 013 Phase 6 |

All analysis, edge cases, TAINT model mappings, and architectural insights remain here as reference. The build plan is now at **Feature 013**.
