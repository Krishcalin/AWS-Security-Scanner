#!/usr/bin/env python3
"""A psycopg3-SHAPED fake connection for offline PostgresBackend tests (no live
server). Records every (sql, params) for assertions and threads canned rows
through the REAL aws_state_dialect.hybrid_row_factory / _Row so positional
``fetchone()[0]`` AND by-name ``row['col']`` / ``dict(row)`` are exercised for real.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collections import namedtuple

from aws_state_dialect import hybrid_row_factory

Col = namedtuple("Col", "name")   # cur.description[i].name (what hybrid_row_factory reads)


class FakeCursor:
    def __init__(self, conn, row_factory=None):
        self._conn = conn
        self._row_factory = row_factory or hybrid_row_factory
        self.description = None
        self._rows = []
        self._i = 0
        self.lastrowid = None
        self.rowcount = -1

    def execute(self, sql, params=()):
        self._conn.execute_log.append((sql, tuple(params) if params else ()))
        cols, rows = self._conn._resolve(sql)
        if cols is None:                      # DDL / write: no result set
            self.description = None
            self._rows = []
        else:
            self.description = [Col(c) for c in cols]
            maker = self._row_factory(self)   # REAL hybrid_row_factory -> _Row maker
            self._rows = [maker(r) for r in rows]
        self._i = 0
        return self

    def executemany(self, sql, seq):
        for p in seq:
            self._conn.execute_log.append((sql, tuple(p)))
        self.description = None
        self._rows = []

    def fetchone(self):
        if self._i >= len(self._rows):
            return None
        r = self._rows[self._i]
        self._i += 1
        return r

    def fetchall(self):
        r = self._rows[self._i:]
        self._i = len(self._rows)
        return r

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeConn:
    """psycopg3 Connection shape used by PostgresBackend: .execute(), .cursor(),
    .commit(), .rollback(), .close(). Records SQL for assertions."""

    def __init__(self):
        self.execute_log = []     # [(sql, params)] — primary assertion surface
        self.commits = 0
        self.rollbacks = 0
        self.transactions = 0     # count of transaction() blocks opened
        self.row_factory = None
        self._stubs = []          # [(needle, cols, rows)] FIFO; first match wins

    def stub(self, needle, cols, rows):
        """Register a canned result. ``needle`` is a substring (or compiled regex)
        matched against the executed SQL."""
        self._stubs.append((needle, cols, list(rows)))

    def _resolve(self, sql):
        for needle, cols, rows in self._stubs:
            hit = needle.search(sql) if hasattr(needle, "search") else needle in sql
            if hit:
                return cols, rows
        return None, []           # DDL / write: no description, no rows

    def execute(self, sql, params=()):
        return FakeCursor(self).execute(sql, params)

    def cursor(self, row_factory=None):
        return FakeCursor(self, row_factory)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        pass

    def transaction(self):
        """Mimic psycopg3 conn.transaction(): BEGIN on enter, COMMIT on a clean
        exit, ROLLBACK on an exception (never suppresses)."""
        conn = self

        class _Tx:
            def __enter__(self_):
                conn.transactions += 1
                return self_

            def __exit__(self_, et, ev, tb):
                conn.commit() if et is None else conn.rollback()
                return False
        return _Tx()

    @property
    def sql_log(self):
        return [s for s, _ in self.execute_log]
