# A/B summary: without vs with knowledge base

| Incident | Metric | Without RAG | With RAG |
|---|---|---|---|
| INC-2026-001 | category_correct | yes | yes |
| INC-2026-001 | severity_correct | yes | yes |
| INC-2026-001 | root_cause_grounded | yes | yes |
| INC-2026-001 | contributing_factor_recall | 100% | 100% |
| INC-2026-001 | indicator_recall | 100% | 100% |
| INC-2026-001 | claims_removed | 0 | 0 |
| INC-2026-001 | policy_recall | 0% | 67% |
| INC-2026-001 | actions_with_policy | 0% | 100% |
| INC-2026-002 | category_correct | yes | yes |
| INC-2026-002 | severity_correct | yes | yes |
| INC-2026-002 | root_cause_grounded | yes | yes |
| INC-2026-002 | contributing_factor_recall | 100% | 100% |
| INC-2026-002 | indicator_recall | 100% | 100% |
| INC-2026-002 | claims_removed | 0 | 0 |
| INC-2026-002 | policy_recall | 0% | 100% |
| INC-2026-002 | actions_with_policy | 0% | 100% |
| INC-2026-003 | category_correct | yes | yes |
| INC-2026-003 | severity_correct | yes | yes |
| INC-2026-003 | root_cause_grounded | yes | yes |
| INC-2026-003 | contributing_factor_recall | 100% | 100% |
| INC-2026-003 | indicator_recall | 0% | 100% |
| INC-2026-003 | claims_removed | 0 | 0 |
| INC-2026-003 | policy_recall | 0% | 67% |
| INC-2026-003 | actions_with_policy | 0% | 86% |
| INC-2026-004 | category_correct | yes | yes |
| INC-2026-004 | severity_correct | yes | yes |
| INC-2026-004 | root_cause_grounded | yes | yes |
| INC-2026-004 | contributing_factor_recall | 100% | 100% |
| INC-2026-004 | indicator_recall | 100% | 100% |
| INC-2026-004 | claims_removed | 0 | 0 |
| INC-2026-004 | policy_recall | 0% | 100% |
| INC-2026-004 | actions_with_policy | 0% | 100% |
| INC-2026-005 | category_correct | yes | yes |
| INC-2026-005 | severity_correct | yes | yes |
| INC-2026-005 | root_cause_grounded | yes | yes |
| INC-2026-005 | contributing_factor_recall | 100% | 100% |
| INC-2026-005 | indicator_recall | 0% | 100% |
| INC-2026-005 | claims_removed | 0 | 0 |
| INC-2026-005 | policy_recall | 0% | 100% |
| INC-2026-005 | actions_with_policy | 0% | 100% |
| INC-2026-006 | category_correct | yes | yes |
| INC-2026-006 | severity_correct | yes | yes |
| INC-2026-006 | root_cause_grounded | yes | yes |
| INC-2026-006 | contributing_factor_recall | 100% | 100% |
| INC-2026-006 | indicator_recall | 100% | 100% |
| INC-2026-006 | claims_removed | 0 | 0 |
| INC-2026-006 | policy_recall | 0% | 75% |
| INC-2026-006 | actions_with_policy | 0% | 83% |

## Means (incidents with both arms)

| Metric | Without RAG | With RAG |
|---|---|---|
| category_correct | 100% | 100% |
| severity_correct | 100% | 100% |
| root_cause_grounded | 100% | 100% |
| contributing_factor_recall | 100% | 100% |
| indicator_recall | 67% | 100% |
| claims_removed | 0% | 0% |
| policy_recall | 0% | 85% |
| actions_with_policy | 0% | 95% |

Incidents compared: 6. Hallucination traps must still be checked by hand in each report.
