"""Multi-agent Text-to-SQL pipeline over DuckDB with AST guard and audit logging."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import duckdb

from src.governed_sql.ast_guard import ASTSQLGuard


@dataclass(frozen=True)
class QueryExecutionResult:
    """Result of planning, AST-guarding, and executing a governed SQL query."""

    role: str
    raw_sql: str
    governed_sql: str
    rows: list[dict[str, Any]]
    audit_sha256: str


def create_demo_connection() -> duckdb.DuckDBPyConnection:
    """Create an in-memory DuckDB instance with TPC-H-style enterprise tables."""
    conn = duckdb.connect(":memory:")
    conn.execute("""
        CREATE TABLE customers (customer_id INTEGER, name VARCHAR, segment VARCHAR);
        INSERT INTO customers VALUES
            (1, 'Nordic Manufacturing GmbH', 'Enterprise'),
            (2, 'Tokyo Robotics KK', 'Enterprise'),
            (3, 'Paris FinTech SAS', 'Mid-Market');

        CREATE TABLE orders (order_id INTEGER, customer_id INTEGER, region VARCHAR, amount_eur DOUBLE);
        INSERT INTO orders VALUES
            (101, 1, 'EMEA', 120000.0),
            (102, 2, 'APAC', 95000.0),
            (103, 3, 'EMEA', 45000.0);

        CREATE TABLE hr_salaries (employee_id INTEGER, salary_eur DOUBLE);
        INSERT INTO hr_salaries VALUES (1, 185000.0);
    """)
    return conn


def plan_sql_from_question(question: str) -> str:
    """Deterministic SQL planner for offline/CI execution (replace with LLM in prod)."""
    q = question.lower()
    if "salary" in q or "salaries" in q:
        return "SELECT employee_id, salary_eur FROM hr_salaries"
    if "drop" in q:
        return "DROP TABLE orders"
    return "SELECT order_id, region, amount_eur FROM orders ORDER BY order_id"


def run_governed_query(
    question: str,
    role: str,
    conn: duckdb.DuckDBPyConnection | None = None,
) -> QueryExecutionResult:
    """Plan SQL, enforce AST RBAC/RLS, execute in DuckDB, and emit audit hash."""
    owns_conn = conn is None
    db = conn if conn is not None else create_demo_connection()
    try:
        raw_sql = plan_sql_from_question(question)
        governed_sql = ASTSQLGuard.enforce(raw_sql, role=role)
        cursor = db.execute(governed_sql)
        columns = [desc[0] for desc in cursor.description]
        rows = [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]

        audit_payload = json.dumps(
            {"role": role, "raw_sql": raw_sql, "governed_sql": governed_sql, "row_count": len(rows)},
            sort_keys=True,
        )
        audit_hash = hashlib.sha256(audit_payload.encode("utf-8")).hexdigest()
        return QueryExecutionResult(
            role=role,
            raw_sql=raw_sql,
            governed_sql=governed_sql,
            rows=rows,
            audit_sha256=audit_hash,
        )
    finally:
        if owns_conn:
            db.close()


if __name__ == "__main__":
    res = run_governed_query("Show all enterprise orders", role="emea_analyst")
    print(f"Governed SQL: {res.governed_sql}")
    print(f"Rows ({len(res.rows)}): {res.rows}")
    print(f"Audit SHA-256: {res.audit_sha256}")
