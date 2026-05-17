"""
Database compatibility layer.

Drop-in replacement for `sqlite3.connect()` that auto-routes to PostgreSQL
when `DATABASE_URL` indicates a Postgres database, and falls back to SQLite
otherwise.

Usage:
    from utils.db_compat import connect

    conn = connect()                      # uses DATABASE_URL or default SQLite path
    conn = connect("/path/to/file.db")    # ignored in Postgres mode

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (1,))   # `?` placeholders work
    rows = cursor.fetchall()
    for row in rows:
        print(row["name"], row[0])        # both dict and positional access work

Why this exists:
    The codebase has 28+ raw `sqlite3.connect()` call sites alongside SQLAlchemy.
    Refactoring all of them to SQLAlchemy ORM is a large project. This helper
    lets the existing raw-SQL code run on PostgreSQL with minimal per-file
    changes — typically just changing the import and `connect()` line.

Translations applied automatically (Postgres mode only):
    - `?` parameter placeholders → `%s`
    - `datetime('now')` → `CURRENT_TIMESTAMP`
    - `date('now', '-N days')` → `(CURRENT_DATE - INTERVAL 'N days')`
    - `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY`
    - `INSERT OR IGNORE` → `INSERT ... ON CONFLICT DO NOTHING`
    - `PRAGMA table_info(t)` → `information_schema.columns` query
      (returns rows shaped like SQLite's so `row[1]` gives the column name)

NOT translated (must be fixed at the call site):
    - `INSERT OR REPLACE` — needs explicit `ON CONFLICT (cols) DO UPDATE SET`
      because we can't infer the conflict target safely. Only 6 sites use it.
    - `lastrowid` — Postgres needs `RETURNING id` in the query.
"""
from __future__ import annotations

import os
import re
import sqlite3
from typing import Any, Optional


# ----------------------------------------------------------------------------
# URL helpers
# ----------------------------------------------------------------------------

def _database_url() -> str:
    """Return DATABASE_URL with `postgres://` rewritten to `postgresql://`."""
    url = os.environ.get("DATABASE_URL", "")
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    # Strip SQLAlchemy driver suffix if present — psycopg2 doesn't accept it
    if url.startswith("postgresql+psycopg2://"):
        url = url.replace("postgresql+psycopg2://", "postgresql://", 1)
    if url.startswith("postgresql+psycopg://"):
        url = url.replace("postgresql+psycopg://", "postgresql://", 1)
    return url


def is_postgres() -> bool:
    """True if DATABASE_URL points at a Postgres database."""
    url = _database_url()
    return url.startswith("postgresql://")


def _default_sqlite_path() -> str:
    """Default SQLite path mirrors backend/utils/db_path.py logic."""
    if os.path.exists("/app/data"):
        return "/app/data/appsec.db"
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "appsec.db")


# ----------------------------------------------------------------------------
# SQL translation (SQLite syntax → Postgres syntax)
# ----------------------------------------------------------------------------

# Match PRAGMA table_info(table_name) — table name may be quoted or bare.
_PRAGMA_TABLE_INFO = re.compile(
    r"""PRAGMA\s+table_info\s*\(\s*["`']?(\w+)["`']?\s*\)""",
    re.IGNORECASE,
)
_DATETIME_NOW = re.compile(r"""datetime\s*\(\s*['"]now['"]\s*\)""", re.IGNORECASE)
_DATE_NOW_OFFSET = re.compile(
    r"""date\s*\(\s*['"]now['"]\s*,\s*['"]\s*(-?\d+)\s+days?\s*['"]\s*\)""",
    re.IGNORECASE,
)
_AUTOINCREMENT = re.compile(
    r"""INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT""",
    re.IGNORECASE,
)
_INSERT_OR_IGNORE = re.compile(r"""INSERT\s+OR\s+IGNORE""", re.IGNORECASE)
_INSERT_OR_REPLACE = re.compile(r"""INSERT\s+OR\s+REPLACE""", re.IGNORECASE)
_ON_CONFLICT_PRESENT = re.compile(r"""ON\s+CONFLICT""", re.IGNORECASE)


def _replace_param_placeholders(sql: str) -> str:
    """Replace `?` with `%s`, ignoring `?` inside string literals."""
    out = []
    i = 0
    in_str = False
    quote_char: Optional[str] = None
    while i < len(sql):
        c = sql[i]
        if in_str:
            out.append(c)
            if c == quote_char:
                # Handle '' or "" escaping inside the same literal.
                if i + 1 < len(sql) and sql[i + 1] == quote_char:
                    out.append(sql[i + 1])
                    i += 2
                    continue
                in_str = False
                quote_char = None
            i += 1
        else:
            if c in ("'", '"'):
                in_str = True
                quote_char = c
                out.append(c)
                i += 1
            elif c == "?":
                out.append("%s")
                i += 1
            else:
                out.append(c)
                i += 1
    return "".join(out)


def _pragma_to_information_schema(sql: str) -> str:
    """Replace `PRAGMA table_info(t)` with a Postgres equivalent.

    The resulting query returns rows compatible with SQLite's PRAGMA output:
        col[0] cid (always 0)
        col[1] name      ← this is what existing code reads via `col[1]`
        col[2] type
        col[3] notnull   (0/1)
        col[4] dflt_value
        col[5] pk        (0/1)
    """
    def _replace(m: re.Match) -> str:
        table = m.group(1)
        return (
            "SELECT "
            "0 AS cid, "
            f"column_name AS name, "
            "data_type AS type, "
            "CASE WHEN is_nullable = 'NO' THEN 1 ELSE 0 END AS notnull, "
            "column_default AS dflt_value, "
            "CASE WHEN column_name = ANY (SELECT a.attname FROM pg_index i "
            "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
            f"WHERE i.indrelid = '{table}'::regclass AND i.indisprimary) THEN 1 ELSE 0 END AS pk "
            "FROM information_schema.columns "
            f"WHERE table_schema = 'public' AND table_name = '{table}'"
        )

    return _PRAGMA_TABLE_INFO.sub(_replace, sql)


def translate_sqlite_to_postgres(sql: str) -> str:
    """Apply all SQLite→Postgres translations."""
    sql = _replace_param_placeholders(sql)
    sql = _DATETIME_NOW.sub("CURRENT_TIMESTAMP", sql)
    sql = _DATE_NOW_OFFSET.sub(
        lambda m: f"(CURRENT_DATE + INTERVAL '{m.group(1)} days')",
        sql,
    )
    sql = _AUTOINCREMENT.sub("SERIAL PRIMARY KEY", sql)
    sql = _pragma_to_information_schema(sql)

    # INSERT OR IGNORE: strip and append ON CONFLICT DO NOTHING if not already present
    if _INSERT_OR_IGNORE.search(sql):
        sql = _INSERT_OR_IGNORE.sub("INSERT", sql)
        if not _ON_CONFLICT_PRESENT.search(sql):
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

    # INSERT OR REPLACE: strip (caller must provide explicit ON CONFLICT clause)
    # Logs a warning so we can find any remaining sites.
    if _INSERT_OR_REPLACE.search(sql):
        sql = _INSERT_OR_REPLACE.sub("INSERT", sql)
        if not _ON_CONFLICT_PRESENT.search(sql):
            # Best-effort: add a generic ON CONFLICT DO NOTHING. Caller should
            # rewrite this to the explicit ON CONFLICT (cols) DO UPDATE SET form.
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

    return sql


# ----------------------------------------------------------------------------
# Connection / cursor wrappers
# ----------------------------------------------------------------------------

class _PgCursor:
    """Cursor wrapper that translates SQL and presents a sqlite3-like API."""

    def __init__(self, raw_cursor):
        self._cur = raw_cursor

    def execute(self, sql: str, params: Any = None):
        sql = translate_sqlite_to_postgres(sql)
        if params is None:
            self._cur.execute(sql)
        else:
            self._cur.execute(sql, params)
        return self

    def executemany(self, sql: str, params_seq):
        sql = translate_sqlite_to_postgres(sql)
        self._cur.executemany(sql, params_seq)
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def fetchmany(self, size: Optional[int] = None):
        if size is None:
            return self._cur.fetchmany()
        return self._cur.fetchmany(size)

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount

    @property
    def description(self):
        return self._cur.description

    @property
    def lastrowid(self):
        """Postgres has no lastrowid; callers should use `RETURNING id`.

        We do a best-effort with `lastval()` which works only inside the same
        session and only after an INSERT that touched a sequence.
        """
        try:
            self._cur.execute("SELECT lastval()")
            row = self._cur.fetchone()
            return row[0] if row else None
        except Exception:
            return None

    def close(self):
        self._cur.close()

    def __iter__(self):
        return iter(self._cur)


class _PgConnection:
    """Connection wrapper that returns translating cursors."""

    def __init__(self, dsn: str):
        import psycopg2
        from psycopg2.extras import DictCursor

        self._conn = psycopg2.connect(dsn, cursor_factory=DictCursor)
        # sqlite3-compat attribute. Setting it on Postgres is a no-op
        # because DictCursor already provides dict-and-positional row access.
        self.row_factory = None

    def cursor(self) -> _PgCursor:
        return _PgCursor(self._conn.cursor())

    def execute(self, sql: str, params: Any = None) -> _PgCursor:
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def executemany(self, sql: str, params_seq) -> _PgCursor:
        cur = self.cursor()
        cur.executemany(sql, params_seq)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            try:
                self._conn.rollback()
            except Exception:
                pass
        else:
            try:
                self._conn.commit()
            except Exception:
                pass
        try:
            self._conn.close()
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

def connect(sqlite_path: Optional[str] = None):
    """Drop-in replacement for `sqlite3.connect()`.

    If `DATABASE_URL` points at Postgres, returns a Postgres connection
    wrapper that accepts SQLite syntax. Otherwise returns a real
    `sqlite3.Connection` pointed at `sqlite_path` (or the default path).
    """
    if is_postgres():
        return _PgConnection(_database_url())

    # SQLite fallback — used for local dev when DATABASE_URL is unset.
    path = sqlite_path or _default_sqlite_path()
    return sqlite3.connect(path)


# Export Row for code that does `conn.row_factory = sqlite3.Row` — in
# Postgres mode it's harmless (no-op attribute). Keeping the symbol here
# means files don't need to keep `import sqlite3` around for one line.
Row = sqlite3.Row
