# Security Specification (Phase 0)

## Data Invariants
1. Every document under `/users/{userId}` and its subcollections (`/saves/{saveId}`, `/rankState/{docId}`) is strictly owned by `request.auth != null && request.auth.uid == userId`, and `ownerId`/`uid` is immutable after creation.
2. Subcollection documents under `/users/{userId}/saves/{saveId}` and `/users/{userId}/rankState/{docId}` require the parent `/users/{userId}` profile document to exist (Master Gate) on `get`, `create`, `update`, and `delete`, while `list` enforces `resource.data.ownerId == request.auth.uid`.
3. Public collections `/lb/{userId}` and `/rank/{userId}` contain zero PII and allow public reads (`get`, `list`) while restricting writes strictly to the authenticated owner (`request.auth.uid == userId`).
4. `/admins/{userId}` cannot be created, updated, or deleted from any client SDK (`allow write: if false`) and can only be read (`get`) by the owning UID.
5. All timestamps (`createdAt`, `updatedAt`) must match `request.time`, and all strings, integers, maps, and arrays have strict type and size bounds.

## Dirty Dozen Adversarial Payloads
1. **Identity Spoofing on Profile Create**: Create `/users/userA` as `userB` with `uid: "userA"` -> `PERMISSION_DENIED`.
2. **Unauthenticated Write**: Create `/users/userA` with `request.auth == null` -> `PERMISSION_DENIED`.
3. **Ghost Field / Shadow Update**: Update `/users/userA` adding `isAdmin: true` -> `PERMISSION_DENIED` (blocked by `hasOnly` and `affectedKeys().hasOnly`).
4. **Immutable UID Tampering**: Update `/users/userA` changing `uid` or `createdAt` -> `PERMISSION_DENIED`.
5. **Cross-User Save Read/List**: Read or list `/users/userA/saves` as `userB` -> `PERMISSION_DENIED`.
6. **Orphaned Subcollection Write**: Create `/users/userA/saves/slot1` before `/users/userA` exists -> `PERMISSION_DENIED` (Master Gate `exists()`).
7. **ID Poisoning**: Write `/users/userA/saves/../../etc` or a 200-char `saveId` -> `PERMISSION_DENIED` (`isValidId()`).
8. **Type Poisoning on Leaderboard**: Write `/lb/userA` with `wave: "9999"` (string instead of int) or `wave: 999999` -> `PERMISSION_DENIED`.
9. **Array Overflow on Rank Defense**: Write `/rank/userA` with `def` having 10 items -> `PERMISSION_DENIED` (`def.size() <= 5`).
10. **Forged Timestamp**: Create `/lb/userA` with `updatedAt: 0` instead of server timestamp -> `PERMISSION_DENIED` (`updatedAt == request.time`).
11. **Public Leaderboard Cross-Overwrite**: Update `/lb/userA` as `userB` -> `PERMISSION_DENIED`.
12. **Privilege Self-Promotion**: Create or update `/admins/userA` as `userA` -> `PERMISSION_DENIED` (`allow write: if false`).
