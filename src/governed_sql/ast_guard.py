"""Deterministic sqlglot AST Guard for Text-to-SQL RBAC & Row-Level Security."""

from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import exp


@dataclass(frozen=True)
class RolePolicy:
    """RBAC and row-level security policy for a caller role."""

    role_name: str
    allowed_tables: frozenset[str]
    allowed_region: str | None = None


ROLE_POLICIES: dict[str, RolePolicy] = {
    "emea_analyst": RolePolicy(
        role_name="emea_analyst",
        allowed_tables=frozenset({"orders", "customers"}),
        allowed_region="EMEA",
    ),
    "apac_analyst": RolePolicy(
        role_name="apac_analyst",
        allowed_tables=frozenset({"orders", "customers"}),
        allowed_region="APAC",
    ),
    "global_auditor": RolePolicy(
        role_name="global_auditor",
        allowed_tables=frozenset({"orders", "customers", "audit_events"}),
        allowed_region=None,
    ),
}


class SQLGovernanceError(ValueError):
    """Raised when a generated SQL query violates AST security or RBAC rules."""


class ASTSQLGuard:
    """Validates and rewrites SQL queries using deterministic sqlglot AST inspection."""

    FORBIDDEN_EXPRESSIONS = (
        exp.Drop,
        exp.Delete,
        exp.Insert,
        exp.Update,
        exp.Alter,
        exp.Create,
        exp.Command,
        exp.Copy,
    )

    @classmethod
    def enforce(cls, sql: str, role: str) -> str:
        """Validate SQL against role RBAC and inject row-level security predicates."""
        if role not in ROLE_POLICIES:
            raise SQLGovernanceError(f"Unknown RBAC role: '{role}'.")
        policy = ROLE_POLICIES[role]

        try:
            statements = sqlglot.parse(sql, read="duckdb")
        except sqlglot.errors.ParseError as exc:
            raise SQLGovernanceError(f"SQL parse error: {exc}") from exc

        if len(statements) != 1 or statements[0] is None:
            raise SQLGovernanceError("Exactly one SQL statement is permitted per query.")

        tree = statements[0]
        if not isinstance(tree, exp.Select):
            raise SQLGovernanceError(f"Only SELECT queries are permitted; got {type(tree).__name__}.")

        for forbidden_cls in cls.FORBIDDEN_EXPRESSIONS:
            if tree.find(forbidden_cls) is not None:
                raise SQLGovernanceError(f"Forbidden SQL operation detected: {forbidden_cls.__name__}.")

        referenced_tables = {t.name.lower() for t in tree.find_all(exp.Table) if t.name}
        if not referenced_tables:
            raise SQLGovernanceError("Query must reference at least one governed table.")

        unauthorized = referenced_tables - policy.allowed_tables
        if unauthorized:
            raise SQLGovernanceError(
                f"Role '{role}' is not authorized to access table(s): {sorted(unauthorized)}."
            )

        if policy.allowed_region is not None and "orders" in referenced_tables:
            rls_filter = exp.EQ(
                this=exp.Column(this=exp.to_identifier("region")),
                expression=exp.Literal.string(policy.allowed_region),
            )
            tree = tree.where(rls_filter, append=True)

        return tree.sql(dialect="duckdb")
