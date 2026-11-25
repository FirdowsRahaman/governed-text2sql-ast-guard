# Governed Text-to-SQL with Deterministic `sqlglot` AST Guard

Multi-agent **Text-to-SQL** architecture over **DuckDB** (public TPC-H / Chinook-style analytical schema) with **deterministic `sqlglot` AST enforcement** for table-level RBAC, row-level security (RLS) predicate injection, DDL/DML blocking, and immutable audit logging.

## Architecture

1. **SQL Planner**: Translates natural-language analytical questions into DuckDB SQL.
2. **Deterministic AST Guard (`sqlglot`)**:
   - Rejects non-`SELECT` statements (`DROP`, `DELETE`, `INSERT`, `UPDATE`, `ALTER`, `COPY`, `ATTACH`).
   - Enforces per-role table allowlists (e.g., `emea_analyst` cannot query `hr_salaries`).
   - Rewrites the AST to inject mandatory row-level security filters (e.g., `WHERE region = 'EMEA'`).
3. **DuckDB Executor & Audit Trail**: Executes only AST-verified SQL and emits SHA-256 tamper-evident audit records.

## Quickstart

```bash
pip install -r requirements.txt
PYTHONPATH=. python -m src.governed_sql.executor
PYTHONPATH=. pytest tests -v
```
