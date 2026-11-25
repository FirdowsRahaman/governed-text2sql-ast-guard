"""Tests for sqlglot AST guard and DuckDB governed execution."""

import pytest

from src.governed_sql.ast_guard import ASTSQLGuard, SQLGovernanceError
from src.governed_sql.executor import run_governed_query


def test_injects_row_level_security_for_emea_analyst():
    res = run_governed_query("Show all enterprise orders", role="emea_analyst")
    assert "region = 'EMEA'" in res.governed_sql
    assert len(res.rows) == 2
    assert all(row["region"] == "EMEA" for row in res.rows)


def test_blocks_unauthorized_table_access():
    with pytest.raises(SQLGovernanceError, match="not authorized"):
        run_governed_query("Show employee salaries", role="emea_analyst")


def test_blocks_ddl_injection():
    with pytest.raises(SQLGovernanceError, match="Only SELECT queries"):
        ASTSQLGuard.enforce("DROP TABLE orders", role="global_auditor")


def test_blocks_multi_statement_sql():
    with pytest.raises(SQLGovernanceError, match="Exactly one SQL statement"):
        ASTSQLGuard.enforce("SELECT * FROM orders; DROP TABLE orders;", role="global_auditor")
