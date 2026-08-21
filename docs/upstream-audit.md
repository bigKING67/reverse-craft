# Upstream audit workflow

1. Run `reverse_craft.py references audit --remote --json` to compare pinned commits with remote `main`.
2. If a head moved, inspect only commits since the pin and map changed mechanisms to Reverse Craft paths.
3. Reconfirm the license at the changed path; repository-level MIT does not override separately licensed subprojects.
4. Classify each accepted path as `direct_copy`, `adapted`, `reimplemented`, `reference_only`, or `runtime_dependency`.
5. Update the pin and direct-copy SHA only after reviewing the diff and running all related gates.
6. For browser67, never copy runtime/session code. Validate the external runtime separately and keep its commit evidence.

An upstream head change is `review_needed`, not an automatic sync request. A reference can improve while Reverse Craft
correctly retains its current implementation.

