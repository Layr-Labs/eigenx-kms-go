# Requirements

We need to add persistence to nodes so that when they restart, they can pick up where they left off and restore their state (specifically their shares).

## Goals

1. Create a persistence interface that can be implemented by different storage backends (e.g., local file system, database, cloud storage).
2. Implement an in-memory persistence layer for testing purposes.
3. Implement an on-disk persistence layer using badger
4. Implement an in-memory persistence layer using redis
5. Update the node logic to use the persistence layer for saving and loading state.
6. Update the `kmsServer` cli to be able to configure the persistence backend via flags.
    - This should include a `backend-type` flag (e.g., "in-memory", "badger", "redis") and any necessary configuration options for the selected backend.
    - Backend-specific configuration options should be prefixed with the backend type (e.g., `badger-path`, `redis-address`).

# Execution
