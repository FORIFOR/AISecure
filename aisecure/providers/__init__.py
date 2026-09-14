"""Provider-specific collectors and response adapters.

Provider credentials stay in the process environment or an external secret
manager. They are never included in snapshots, proposals, or audit payloads.
"""
