"""The hosted platform: HTTP API, auth, workspaces, connectors, onboarding.

Depends on engine/ and store/. Nothing depends on hub/.

Includes aws_registry_connectors despite its aws_ prefix: it imports
cnapp_onboarding for secret-ref resolution and is consumed only by
cnapp_service, so leaving it in engine/ would have been the single remaining
engine->hub back-edge. Placement follows the dependency, not the filename.
"""
