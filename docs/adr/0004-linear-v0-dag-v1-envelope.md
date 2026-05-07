# Linear operation log for v0; DAG-ready envelope from day one

The relay serialises writes to an Object's operation log with a monotonic sequence number (linear order) for v0. DAG causality (concurrent branches, multi-parent merge) is explicitly planned for v1.

To avoid a breaking wire format change, the blob envelope includes a `parents` field (list of parent blob hashes) from day one. In v0 this list always has exactly one entry (or zero for the root blob). In v1 the relay uses the `parents` field to build a DAG and deliver concurrent branches to clients for application-layer merge. Old clients producing single-parent envelopes remain valid in v1 — the format is additive.

Designing for linear-only would require a breaking envelope change when DAG is introduced. One extra field now prevents that.
