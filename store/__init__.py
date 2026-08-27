"""Persistence. The backend, the schema/DDL and the dialect split.

Imported by BOTH engine/ and hub/; imports NEITHER. That is the whole reason
this package exists as its own layer rather than living in one of them.

These three modules are mutually recursive -- aws_state imports cnapp_backend,
cnapp_backend imports aws_state and aws_state_dialect, aws_state_dialect imports
aws_state -- so they are one unit and cannot be split. aws_state already defers
its cnapp_backend imports into function bodies, which is the fingerprint of that
cycle being worked around once before. Splitting the trio across engine/ and
hub/ would have put a circular dependency across a package boundary.

Names still carry their old aws_/cnapp_ prefixes: placement here is by
dependency, not by filename.
"""
