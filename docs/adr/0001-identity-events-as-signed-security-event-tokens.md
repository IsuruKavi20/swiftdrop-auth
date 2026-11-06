# ADR 0001: Identity events are signed Security Event Tokens, not an HMAC webhook

- **Status:** Accepted
- **Date:** 2026-11-06 (decided), 2026-11-07 (built: identity step 6)
- **Decider:** Isuru (auth owner)

## Context
SwiftDrop keeps a read-only copy of people (`app_users`). It must learn within seconds when a person is blocked,
deleted, renamed, changes email, password or roles. The auth service runs on Oracle Cloud, SwiftDrop elsewhere, so
there is no shared message broker. The messages carry personal data and drive security decisions ("this courier
is disabled"), so a receiver must be able to prove each message came from the auth service.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. JSON webhook signed with an HMAC shared secret** | simple, common | the same secret lives in two places and can leak from either; rotation must be coordinated across both clouds; custom format |
| **B. Signed Security Event Tokens (RFC 8417), push (RFC 8935) + poll (RFC 8936)** | signed with the keys we already rotate; receivers verify with our public JWKS (no secret to leak); IETF/OpenID standard; standard event names (CAEP/RISC); poll gives catch-up after downtime | a little more work (a JWT per event) |
| **C. Shared RabbitMQ/Kafka between the two systems** | familiar | a cross-cloud broker to secure and run; still needs message authenticity |

## Decision
**Option B.** Each identity event is a JWT with `typ: secevent+jwt`, signed RS256 with the active signing key,
`sub_id` (RFC 9493) for the person, no `exp`, plus a per-person `swiftdrop_version`. Pushed to configured receivers
(https only) and pollable by the receiver's own service client (`events:read`).

## Consequences
- Receivers verify with the JWKS they already use for access tokens; key rotation needs no coordination.
- A SET can never be used as an access or ID token (`typ`, no `exp`, no `sub`); tested.
- Events are recorded in the same transaction as the change (no lost or invented events) and carry a per-person
  version, so receivers must ignore older versions and repeated `jti`s.
- Delivery bookkeeping (`event_deliveries`) and the diary (`identity_events`) grow; a retention/cleanup job is
  needed (see identity plan, step 6 review).
- SwiftDrop can republish the events internally on its own broker; that is its choice and not coupled to us.

## References
RFC 8417, RFC 8935, RFC 8936, RFC 9493, OpenID Shared Signals Framework (CAEP, RISC). Design:
`plan/STEP6-IDENTITY-EVENTS.md`. Lesson: `learning/course/25-identity-events.md`.
