# Claustral

Revocable, attribute-scoped access control for AI data at rest.

Documents, RAG chunks, agent memory and model outputs are stored encrypted, and each object carries its own access policy. An agent or user can only open what its attributes allow. Revoking an object makes every copy of its ciphertext stop opening, including copies already sitting in caches, vector stores and agent memory. Every protect, open, deny and revoke is written to a tamper-evident audit log.

Claustral has two backends behind one small Go API:

- **local**: AES-256-GCM, per-object data keys wrapped by a local master key, policy evaluation in-process, revocation by destroying the wrapped key. Zero infrastructure.
- **opentdf**: seals objects as ZTDF through the official [OpenTDF](https://opentdf.io) Go SDK, so policy decisions and key release happen at an OpenTDF platform (KAS) using attribute FQNs.

There is no "development mode" and no plaintext fallback. If a backend cannot encrypt, the call fails.

## Why the name

A claustral founding is how many ant colonies begin: a new queen seals herself in a chamber with everything precious and opens it only on her own terms. Claustral does the same for data an AI system touches.

## Quickstart (local backend)

Requires Go 1.27+.

```bash
go install github.com/davidparkercodes/claustral/cmd/claustral@latest

claustral keygen
# wrote master key ~/.local/share/claustral/master.key (id ...). Back it up.

echo "user prefers tea, allergic to nuts" \
  | claustral protect -attr user/alice -attr scope/memory -id mem-alice-0001 > mem.sealed

claustral open -entity assistant -attr user/alice -attr scope/memory < mem.sealed
# user prefers tea, allergic to nuts

claustral open -entity other-agent -attr user/bob -attr scope/memory < mem.sealed
# error: claustral: access denied: missing attributes user/alice   (exit code 3)

claustral revoke -id mem-alice-0001 -reason "user asked to forget"
claustral open -entity assistant -attr user/alice -attr scope/memory < mem.sealed
# error: claustral: object revoked   (exit code 3)

claustral audit -object mem-alice-0001
claustral audit -verify
```

### Library

```go
db, _ := sqlite.Open(path)
key, _ := local.LoadMasterKeyFile(keyPath)
backend, _ := local.New(db, key)
log, _ := audit.New(db)
c, _ := claustral.New(backend, log)

p, _ := claustral.NewPolicy("user/alice", "scope/memory")
sealed, _ := c.Protect(ctx, []byte("..."), p, claustral.WithActor("ingest"))

data, err := c.Open(ctx, sealed.Blob, claustral.Entity{ID: "assistant", Attributes: []string{"user/alice", "scope/memory"}})
if errors.Is(err, claustral.ErrDenied) || errors.Is(err, claustral.ErrRevoked) { ... }

_ = c.Revoke(ctx, sealed.ID, "admin", "retention expired")
```

`pkg/sqlite` opens the database with sensible pragmas (WAL, busy timeout, secure_delete); any `database/sql` SQLite connection works. The `Backend` and `AuditLog` interfaces in `pkg/claustral` are the extension points.

### HTTP API

```bash
export CLAUSTRAL_API_TOKEN=$(openssl rand -hex 32)
claustral serve -addr 127.0.0.1:8484
```

`serve` refuses to start without a token of at least 32 characters. Every `/v1` route requires `Authorization: Bearer <token>`. `/healthz` is open.

| Method | Path | Body / query | Result |
|---|---|---|---|
| POST | `/v1/protect` | `{"data": b64, "attributes": [...], "id"?, "actor"?}` | `201 {"id", "sealed": b64}` |
| POST | `/v1/open` | `{"sealed": b64, "entity": {"id", "attributes"}}` | `200 {"data": b64}`, `403 denied/revoked` |
| POST | `/v1/inspect` | `{"sealed": b64}` | object id, backend, policy |
| POST | `/v1/revoke` | `{"id", "reason"?, "actor"?}` | `200`, `404` unknown |
| GET | `/v1/audit` | `object_id, entity_id, action, outcome, after, limit` | `{"events": [...]}` |
| GET | `/v1/audit/verify` | | hash chain result and head hash |

**Entity registry.** By default `/v1/open` trusts the entity attributes in the request body, so anyone holding the API token can claim any attributes. That is fine when a single trusted gateway holds the token and does its own authentication. For anything else, run `serve -entities entities.json`; `/v1/open` then ignores body entities and resolves the entity from the `X-Claustral-Entity-Token` header:

```json
{"entities": [
  {"id": "support-agent", "token_sha256": "<sha256 hex of the agent's token>", "attributes": ["team/support", "region/eu"]}
]}
```

## OpenTDF backend

Build with the tag (the SDK pulls in gRPC and friends, so it is opt-in):

```bash
go install -tags opentdf github.com/davidparkercodes/claustral/cmd/claustral@latest
```

Configure:

| Variable | Meaning |
|---|---|
| `CLAUSTRAL_BACKEND=opentdf` | select the backend |
| `CLAUSTRAL_OPENTDF_ENDPOINT` | platform URL, e.g. `https://platform.example.com` |
| `CLAUSTRAL_OPENTDF_CLIENT_ID` / `_CLIENT_SECRET` | OAuth client credentials for the service identity (required, no defaults) |
| `CLAUSTRAL_OPENTDF_TOKEN_ENDPOINT` | optional explicit token endpoint |
| `CLAUSTRAL_OPENTDF_KAS_URL` | KAS URL (default `<endpoint>/kas`); also the only KAS allowed at decrypt |
| `CLAUSTRAL_OPENTDF_INSECURE=1` | allow `http://` (local platform only) |

Policy attributes must be OpenTDF attribute value FQNs that exist on the platform, for example `https://example.com/attr/classification/value/secret`. Using FQNs for the local backend too keeps policies portable between backends.

How decisions work with this backend:

- `Protect` creates a ZTDF with `WithDataAttributes(<policy>)` and wraps it in a small Claustral envelope (object id + policy for audit and inspect). The object id is also sealed into the TDF's encrypted metadata and checked on open.
- `Open` asks KAS to rewrap the key. Pass the end user's or agent's access token as `Entity.Token` (`open -entity-token`) so the platform evaluates that entity's entitlements. Without a token the service's own client identity is the entity. `Entity.Attributes` are ignored here: the platform is the authority.
- `Revoke` returns `ErrUnsupported`. OpenTDF does not revoke individual objects; access is withdrawn by changing subject mappings or deactivating attribute values, and KAS then refuses rewrap for every existing copy. Claustral does not pretend otherwise.

Tested against SDK `github.com/opentdf/platform/sdk` v0.36.0. The repository's tests cover the envelope only; end-to-end tests against a live platform are a follow-up.

## Threat model

What Claustral protects against:

- **Copied ciphertext.** Blobs in caches, vector stores, logs, backups of application data, or another agent's memory are useless without the key store and master key (local) or KAS approval (opentdf).
- **Over-broad access.** Policies are all-of: the entity must hold every attribute. An empty policy is rejected rather than meaning "anyone". There is no wildcard attribute.
- **Revocation after copying (local).** Revoke deletes the wrapped data key (SQLite `secure_delete` plus a WAL checkpoint). Clearing the revoked flag or restoring the row metadata does not bring it back.
- **Tampering with objects.** The header (id, policy, master key id) is authenticated data for the payload, and the wrapped data key is bound to the object id and policy digest. Editing the policy in a blob, in the key store, or swapping ids fails closed.
- **Unaudited access.** Opening fails, and plaintext is withheld, if the audit event cannot be written. Protect rolls back (revokes) the object if its audit event cannot be written.
- **Silent audit edits.** The audit table rejects UPDATE and DELETE via triggers, and every event is SHA-256 hash-chained to the previous one. `audit -verify` finds modified, inserted or deleted rows.

Honest limits:

- **Anyone with the master key and the database can open everything** that is not revoked (local). Keep the key out of the database's backups, in a secret manager or a 0600 file (Claustral refuses group/world readable key files). There is no HSM/KMS integration yet.
- **Revocation is not retroactive to plaintext.** If an agent already opened an object and kept the plaintext, revocation cannot claw it back. Claustral narrows exposure to what was actually opened, and the audit log tells you exactly who opened it.
- **Old backups of the key store still hold wrapped keys** for objects revoked after the backup was taken. Treat key store backups like key material, or rotate the master key after sensitive revocations.
- **Truncation of the newest audit events is not detectable from the chain alone.** Export the head hash (`audit -verify` prints it) to somewhere the writer cannot modify if you need that guarantee.
- **The API token is all-powerful.** In trusted-caller mode the caller asserts entity attributes. Use the entity registry, or put Claustral behind something that authenticates entities.
- **Metadata is visible.** Object ids and policies are in plaintext in the blob header so they can be audited and inspected without a key. Do not put secrets in attribute names or ids.
- **Not a classifier.** Claustral does not decide what is sensitive. The caller chooses the policy.
- **Single node.** The local backend uses SQLite. It is safe for concurrent use by one host's processes, not a distributed key store.

## Status

Early (v0.1.0). The format may change before 1.0; every blob carries a version byte.

## License

Apache-2.0. See [LICENSE](LICENSE).
