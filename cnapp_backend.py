#!/usr/bin/env python3
"""
cnapp_backend.py — dual-dialect DB backend behind StateStore + AccountRegistry
(CNAPP Phase 9: live PostgresBackend wiring).

Both `aws_state.StateStore` and `cnapp_registry.AccountRegistry` used to hold a
raw ``sqlite3.Connection`` and issue qmark SQL + explicit ``.commit()`` directly.
They now route every read/write through a `Backend`, so a `postgresql://` URL runs
the same code on Postgres.

* **`SqliteBackend`** keeps today's sqlite path BYTE-IDENTICAL — identity dialect
  (qmark ``?``), the same PRAGMAs + ``sqlite3.Row`` row factory, ``BEGIN IMMEDIATE``
  transactions, and the ``PRAGMA user_version`` migration gate.
* **`PostgresBackend`** is additive — real psycopg3 + the already-tested
  ``aws_state_dialect`` (``?`` → ``%s`` conversion, ``ON CONFLICT`` upserts,
  ``RETURNING`` ids, a ``schema_migrations`` table + ``hybrid_row_factory`` so a
  row supports positional ``[0]`` AND by-name ``['col']`` / ``dict(row)``).

A missing psycopg driver OR an unreachable server raises `StateBackendUnavailable`
— NEVER a silent sqlite fallback (a shared team Postgres must not split into a
local file). psycopg and aws_state are imported LAZILY inside methods, so importing
this module never needs the driver and never cycles with aws_state.

Placeholder discipline (subtle, load-bearing): inline qmark SQL written in the
callers is normalized once via ``dialect.convert`` in ``execute``/``query_*``.
Upsert SQL from ``dialect.upsert`` is ALREADY rendered in the dialect's native
placeholder (``?`` on sqlite, ``%s`` on Postgres), so `upsert`/`upsert_many`
execute it WITHOUT a second convert — re-converting would double the ``%`` in a
Postgres ``%s`` and corrupt the statement.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, List, Optional, Sequence

from aws_state_dialect import (PostgresDialect, SqliteDialect,
                               StateBackendUnavailable, build_upsert,
                               hybrid_row_factory, parse_state_url)


@dataclass
class ExecResult:
    lastrowid: Optional[int]
    rowcount: int


class Backend(ABC):
    """Owns the dialect + a connection strategy.

    * **Single-connection path** (sqlite, or an injected test connection): every
      operation serializes on one reentrant lock over one connection — today's exact
      behavior, byte-identical.
    * **Pooled path** (production Postgres): each operation BORROWS a connection from a
      ``psycopg_pool.ConnectionPool`` (no global lock, real concurrency), and a
      ``transaction()`` checks out ONE connection for its whole duration via a
      thread-local so nested ops reuse it and different threads run in parallel.

    ``execute``/``executemany``/``upsert`` commit iff NOT inside a ``transaction()``."""

    dialect: Any
    raw: Any
    pool: Any
    OperationalError: type

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._local = threading.local()   # .conn = the txn's checked-out connection (per thread)
        self.pool = None                  # set by a pooled PostgresBackend; else single-connection

    # ── connection strategy ─────────────────────────────────────────────────
    @contextmanager
    def _conn(self):
        """Yield the connection an operation should use. Inside a transaction the
        thread-local checked-out conn is reused; pooled ⇒ borrow+return; else ⇒ the
        single connection under the reentrant lock (sqlite / injected test conn)."""
        active = getattr(self._local, "conn", None)
        if active is not None:            # inside transaction() on this thread
            yield active
        elif self.pool is not None:       # pooled: borrow one, return on exit
            with self.pool.connection() as c:
                yield c
        else:                             # single connection, serialized on the lock
            with self.lock:
                yield self.raw

    def _in_txn(self) -> bool:
        return getattr(self._local, "conn", None) is not None

    # ── subclass primitives (operate on the passed-in connection) ───────────
    @abstractmethod
    def _exec(self, conn, sql: str, params: Sequence): ...      # -> DBAPI cursor
    @abstractmethod
    def _execmany(self, conn, sql: str, seq: List[Sequence]) -> None: ...
    @abstractmethod
    def _txn_cm(self, conn):                                    # -> a context manager
        """Return a context manager that BEGINs on enter, COMMITs on a clean exit,
        and ROLLBACKs on an exception, on the GIVEN connection (sqlite: BEGIN
        IMMEDIATE/COMMIT/ROLLBACK; Postgres: ``conn.transaction()``)."""
    @abstractmethod
    def migrate(self) -> None: ...
    @abstractmethod
    def insert_returning_id(self, sql: str, params: Sequence, id_col: str = "id") -> int: ...

    # ── shared surface (identical behavior on both engines) ─────────────────
    def execute(self, sql: str, params: Sequence = ()) -> ExecResult:
        with self._conn() as c:
            cur = self._exec(c, self.dialect.convert(sql), params)
            if not self._in_txn():
                c.commit()
            return ExecResult(getattr(cur, "lastrowid", None),
                              getattr(cur, "rowcount", -1))

    def executemany(self, sql: str, seq: Iterable[Sequence]) -> None:
        with self._conn() as c:
            self._execmany(c, self.dialect.convert(sql), list(seq))
            if not self._in_txn():
                c.commit()

    def query_one(self, sql: str, params: Sequence = ()):
        with self._conn() as c:
            return self._exec(c, self.dialect.convert(sql), params).fetchone()

    def query_all(self, sql: str, params: Sequence = ()) -> list:
        with self._conn() as c:
            return self._exec(c, self.dialect.convert(sql), params).fetchall()

    def scalar(self, sql: str, params: Sequence = ()) -> Any:
        row = self.query_one(sql, params)
        return None if row is None else row[0]

    @property
    def _ph(self) -> str:
        return "%s" if self.dialect.paramstyle == "pyformat" else "?"

    def upsert(self, table, cols, conflict_cols, update_cols, params, *,
               reset_cols=None, returning=None):
        # ON CONFLICT DO UPDATE on BOTH engines (SQLite >= 3.24) — the ONLY form
        # that PRESERVES omitted columns (partial re-onboard) while still resetting
        # the explicit reset_cols. Rendered with the dialect's native placeholder,
        # so it is executed WITHOUT a second convert.
        sql = build_upsert(table, cols, conflict_cols, update_cols, reset_cols,
                           returning, ph=self._ph)
        with self._conn() as c:
            cur = self._exec(c, sql, params)
            row = cur.fetchone() if returning else None
            if not self._in_txn():
                c.commit()
            return row

    def upsert_many(self, table, cols, conflict_cols, update_cols, seq, *,
                    reset_cols=None) -> None:
        sql = build_upsert(table, cols, conflict_cols, update_cols, reset_cols,
                           ph=self._ph)
        with self._conn() as c:
            self._execmany(c, sql, list(seq))
            if not self._in_txn():
                c.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        if self._in_txn():                # nested on this thread → reuse, no new BEGIN
            yield
            return
        if self.pool is not None:         # pooled: ONE connection for the whole block
            with self.pool.connection() as c:
                self._local.conn = c
                try:
                    with self._txn_cm(c):
                        yield
                finally:
                    self._local.conn = None
        else:                             # single connection under the lock (sqlite / test conn)
            with self.lock:
                self._local.conn = self.raw
                try:
                    with self._txn_cm(self.raw):
                        yield
                finally:
                    self._local.conn = None

    @contextmanager
    def serialized(self) -> Iterator[None]:
        """Serialize a cross-connection read-modify-write across the WHOLE pool. A
        transaction() on the pooled path checks out one connection and gives per-row
        atomicity, but NOT mutual exclusion — two threads on two connections each
        SELECT-then-UPDATE would lose an increment (e.g. record_health's
        consecutive_failures). Wrap such an RMW in ``serialized()``: on the pooled path
        this reentrant lock is the only cross-connection mutex; on the single-connection
        path it is the same lock the ops already take (a reentrant no-op). Use only for
        the RARE RMW ops, never the scan/findings hot path."""
        with self.lock:
            yield

    def close(self) -> None:
        try:
            if self.pool is not None:
                self.pool.close()
            elif getattr(self, "raw", None) is not None:
                self.raw.close()
        except Exception:
            pass


class SqliteBackend(Backend):
    def __init__(self, conn: sqlite3.Connection) -> None:
        super().__init__()
        conn.row_factory = sqlite3.Row      # honor the wrapped-raw-connection contract
        self.raw = conn
        self.dialect = SqliteDialect()
        self.OperationalError = sqlite3.OperationalError

    @classmethod
    def connect(cls, path: str, *, check_same_thread: bool = True) -> "SqliteBackend":
        conn = sqlite3.connect(path, check_same_thread=check_same_thread)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return cls(conn)

    def _exec(self, conn, sql, params):
        return conn.execute(sql, params)

    def _execmany(self, conn, sql, seq):
        conn.executemany(sql, seq)

    @contextmanager
    def _txn_cm(self, conn):
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    def insert_returning_id(self, sql, params, id_col="id") -> int:
        with self._conn() as c:
            cur = self._exec(c, self.dialect.convert(sql), params)
            if not self._in_txn():
                c.commit()
            return cur.lastrowid

    def migrate(self) -> None:
        import aws_state
        # single-threaded at startup — use the one connection directly.
        ver = self.raw.execute("PRAGMA user_version").fetchone()[0]
        if ver < aws_state.SCHEMA_VERSION:
            self.raw.executescript(aws_state._DDL)
            self.raw.execute(f"PRAGMA user_version={aws_state.SCHEMA_VERSION}")
            self.raw.commit()


class PostgresBackend(Backend):
    """Pooled psycopg3 in production (a ``psycopg_pool.ConnectionPool`` built by
    ``connect()``), or a single injected connection in tests. A ``transaction()``
    checks out ONE pooled connection for its whole duration; every other operation
    borrows a connection and returns it — real concurrency, no process-wide lock."""

    def __init__(self, conn=None, *, pool=None) -> None:
        super().__init__()
        self.raw = conn                          # single injected conn (tests); None when pooled
        self.pool = pool                         # psycopg_pool.ConnectionPool in production
        self.dialect = PostgresDialect()
        import psycopg
        self.OperationalError = psycopg.errors.OperationalError

    @classmethod
    def connect(cls, dsn: str, *, connect_timeout: int = 3) -> "PostgresBackend":
        try:
            import psycopg        # noqa: F401  (also proves the driver is importable)
            import psycopg_pool
        except Exception as e:          # driver absent -> fail loud, never sqlite
            raise StateBackendUnavailable(
                f"postgresql:// backend needs psycopg + psycopg-pool: {e}")

        def _configure(conn):
            # per-connection setup the single-conn path did inline. CRITICAL: psycopg_pool
            # builds connections autocommit=FALSE by default; forcing True keeps a depth-0
            # statement (every read + each non-txn write) from leaving the connection "idle
            # in transaction", and lets conn.transaction() do explicit BEGINs for atomic blocks.
            conn.autocommit = True
            conn.row_factory = hybrid_row_factory

        try:
            min_size = int(os.getenv("CNAPP_DB_POOL_MIN", "2"))
            max_size = max(min_size, int(os.getenv("CNAPP_DB_POOL_MAX", "10")))
            pool = psycopg_pool.ConnectionPool(
                conninfo=dsn, min_size=min_size, max_size=max_size,
                timeout=connect_timeout, open=False, configure=_configure)
            pool.open(wait=True, timeout=connect_timeout)   # fail loud at startup if unreachable
        except StateBackendUnavailable:
            raise
        except Exception as e:          # unreachable / auth / pool timeout -> fail loud, never sqlite
            raise StateBackendUnavailable(f"postgres backend unavailable: {e}")
        return cls(pool=pool)

    def _exec(self, conn, sql, params):
        return conn.execute(sql, params)         # psycopg3 Connection.execute -> cursor

    def _execmany(self, conn, sql, seq):
        cur = conn.cursor()                      # psycopg3 has no conn.executemany
        cur.executemany(sql, list(seq))

    def _txn_cm(self, conn):
        return conn.transaction()                # psycopg's own BEGIN/COMMIT/ROLLBACK

    def insert_returning_id(self, sql, params, id_col="id") -> int:
        rsql = self.dialect.convert(sql) + f" RETURNING {id_col}"
        with self._conn() as c:
            row = c.execute(rsql, params).fetchone()
            if not self._in_txn():
                c.commit()
            return row[0]

    def migrate(self) -> None:
        import aws_state
        with self._conn() as c:                  # one connection for the whole migration
            for stmt in self.dialect.ddl():      # POSTGRES_DDL, all IF NOT EXISTS
                c.execute(stmt)
            row = c.execute(
                "SELECT COALESCE(MAX(version),0) FROM schema_migrations").fetchone()
            if row[0] < aws_state.SCHEMA_VERSION:
                c.execute(
                    "INSERT INTO schema_migrations(version,applied_epoch) "
                    "VALUES(%s,%s) ON CONFLICT (version) DO NOTHING",
                    (aws_state.SCHEMA_VERSION, 0))
            c.commit()


def _seed_default_workspace(be: Backend) -> None:
    """Idempotently ensure the ``ws-default`` workspace exists and every pre-existing
    account is bound to it — the v6->v7 backfill. This is DML (not DDL), so it lives
    here at the single connect chokepoint rather than in ``migrate()`` (which only runs
    DDL + a version stamp). Runs on every open (cheap; ``ON CONFLICT DO NOTHING``),
    independent of the version gate, on both engines. Seeding must NEVER make
    ``backend_for`` fail to open, so it fails open."""
    try:
        with be.transaction():
            be.execute(
                "INSERT INTO workspaces(workspace_id,name,slug,status,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT (workspace_id) DO NOTHING",
                ("ws-default", "Default", "ws-default", "active", 0, 0))
            be.execute(
                # WHERE 1=1 disambiguates the ON CONFLICT upsert clause from a join ON
                # clause for the sqlite parser on an INSERT..SELECT (valid on PG too).
                "INSERT INTO workspace_accounts(account_id, workspace_id, created_at) "
                "SELECT account_id, 'ws-default', 0 FROM accounts WHERE 1=1 "
                "ON CONFLICT (account_id) DO NOTHING")
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        pass


def backend_for(url: str, *, check_same_thread: bool = True) -> Backend:
    """Connect + migrate the right backend for a state URL. Postgres failures
    (driver or server) surface as `StateBackendUnavailable`; sqlite keeps the
    0700-dir / 0600-file tightening around connect."""
    scheme, dsn = parse_state_url(url)
    if scheme == "postgres":
        be = PostgresBackend.connect(url)
        be.migrate()
        _seed_default_workspace(be)
        return be
    # ON CONFLICT upserts (record_scan/coverage/usage + the whole registry) need
    # SQLite >= 3.24 (2018). Fail LOUD + pre-flight here rather than with an opaque
    # "near ON: syntax error" on the first write mid-scan.
    if sqlite3.sqlite_version_info < (3, 24, 0):
        raise StateBackendUnavailable(
            f"sqlite backend needs SQLite >= 3.24 for ON CONFLICT upserts; found "
            f"{sqlite3.sqlite_version}")
    if dsn != ":memory:":
        try:
            os.makedirs(os.path.dirname(os.path.abspath(dsn)), mode=0o700, exist_ok=True)
        except Exception:
            pass
    be = SqliteBackend.connect(dsn, check_same_thread=check_same_thread)
    be.migrate()
    if dsn != ":memory:":
        try:
            os.chmod(dsn, 0o600)
        except Exception:
            pass
    _seed_default_workspace(be)
    return be
