"""The scanning engine: collection, checks, correlation, scoring, reporting.

Depends on store/. MUST NOT depend on hub/ -- enforced by
tests/test_layering.py, not merely asserted here.

Includes compliance_crosswalk (a leaf framework-crosswalk loader) which has no
aws_/cnapp_ prefix and belongs to no vendor layer.
"""
