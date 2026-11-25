# Governed Text-to-SQL with Deterministic `sqlglot` AST Guard

<p align="left">
  <img src="https://img.shields.io/badge/SQL%20Guard-sqlglot%20AST%20RBAC-10B981?style=flat-square" alt="sqlglot AST Guard">
  <img src="https://img.shields.io/badge/Engine-DuckDB%20Analytical-0EA5E9?style=flat-square" alt="DuckDB">
  <img src="https://img.shields.io/badge/Security-Row--Level%20Security%20%7C%20Audit-8B5CF6?style=flat-square" alt="RLS & Audit">
  <img src="https://img.shields.io/badge/CI-Ruff%20%7C%20Bandit%20%7C%20Pytest-F59E0B?style=flat-square" alt="CI">
</p>

An enterprise-grade **Text-to-SQL governance plane** over **DuckDB** (TPC-H / Chinook-style analytical schemas) that enforces **deterministic `sqlglot` Abstract Syntax Tree (AST) validation**, **role-based table allowlists**, **automatic Row-Level Security (RLS) predicate injection**, and **SHA-256 tamper-evident audit logging**.

---

## Table of Contents
- [Why Deterministic AST Governance?](#why-deterministic-ast-governance)
- [Architecture](#architecture)
- [Key Security Controls](#key-security-controls)
- [Quick Start](#quick-start)
- [Usage Example](#usage-example)
- [License](#license)

---

## Why Deterministic AST Governance?

Prompt-based SQL guardrails are probabilistic and vulnerable to multi-statement injection, unauthorized `JOIN`s, or DDL/DML payloads (`DROP`, `DELETE`, `COPY`, `ATTACH`). In regulated enterprise analytics, authorization must be **mathematically enforced on the parsed SQL AST** before execution:

1. **Zero DDL/DML Execution**: Rejects non-`SELECT` statements and multi-statement queries at parse time.
2. **Table-Level RBAC**: Verifies every referenced `exp.Table` node against the caller's role allowlist (e.g., blocking `hr_salaries` for `emea_analyst`).
3. **Automatic Row-Level Security (RLS)**: Rewrites the `sqlglot` AST to inject mandatory predicates (e.g., `WHERE region = 'EMEA'`) so callers can never exfiltrate cross-region rows.

---

## Architecture

```
Natural Language Question + Caller Role (e.g., emea_analyst)
                         │
                         ▼
           ┌───────────────────────────┐
           │      SQL Planner Agent    │ ──▶ Generates Candidate DuckDB SQL
           └───────────────────────────┘
                         │
                         ▼
           ┌───────────────────────────┐
           │   Deterministic AST Guard │
           │        (sqlglot)          │
           ├───────────────────────────┤
           │ 1. Single SELECT Check    │ ──▶ Blocks DROP/DELETE/COPY/Multi-Stmt
           │ 2. Table RBAC Allowlist   │ ──▶ Blocks Unauthorized Tables
           │ 3. RLS AST Rewrite        │ ──▶ Injects WHERE region = 'EMEA'
           └───────────────────────────┘
                         │
                         ▼ (Verified & Rewritten SQL)
           ┌───────────────────────────┐
           │  DuckDB Executor & Audit  │ ──▶ Executes Query + Emits SHA-256 Hash
           └───────────────────────────┘
```

---

## Key Security Controls

| Control | Mechanism | Enforcement Point |
| :--- | :--- | :--- |
| **DDL / DML Blocking** | `isinstance(tree, exp.Select)` + forbidden node scan | `ASTSQLGuard.enforce` |
| **Table RBAC** | `referenced_tables - policy.allowed_tables` | `ASTSQLGuard.enforce` |
| **Row-Level Security** | `tree.where(exp.EQ(region, allowed_region), append=True)` | `ASTSQLGuard.enforce` |
| **Tamper-Evident Audit** | Canonical JSON + SHA-256 digest of raw/governed SQL | `run_governed_query` |

---

## Quick Start

```bash
git clone https://github.com/FirdowsRahaman/governed-text2sql-ast-guard.git
cd governed-text2sql-ast-guard
pip install -r requirements.txt
PYTHONPATH=. python -m src.governed_sql.executor
PYTHONPATH=. pytest tests -v
```

---

## Usage Example

```python
from src.governed_sql.executor import run_governed_query

result = run_governed_query("Show all enterprise orders", role="emea_analyst")
print(result.governed_sql)
# SELECT order_id, region, amount_eur FROM orders WHERE region = 'EMEA' ORDER BY order_id
print(result.audit_sha256)
```

---

## License
This project is licensed under the MIT License.
