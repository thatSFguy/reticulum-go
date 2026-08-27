# CLAUDE.md — guidance for AI agents and contributors

This project is a pure-Go [Reticulum](https://reticulum.network/) (RNS) + LXMF implementation. The byte-level protocol it implements is specified in **[reticulum-specifications](https://github.com/thatSFguy/reticulum-specifications)** — that is the authoritative reference for every wire format, framing rule, and signature input touched by this codebase.

---

## 0. Standing rule — always reference the specification repo

**Before writing, changing, reviewing, or validating any code that touches the wire — packet headers, announces, token crypto, link handshake, resources, transport, LXMF payloads, stamps — open the relevant `SPEC.md` section and cite it.** This is not optional and it is not "when in doubt". Two minutes of spec reading saves hours of code archaeology, and every wire-format bug this project has had was a case of coding from memory instead of from the spec.

The spec repo is checked out locally at **`../reticulum-specifications/`** (`/home/robw/projects/reticulum-specifications`). Prefer the local copy — it is the same content as GitHub and grep-able:

| File | Use it for |
|---|---|
| `../reticulum-specifications/SPEC.md` | The byte-level spec, section-numbered. Cite as "SPEC §6.4.3" in code comments and commit messages. |
| `../reticulum-specifications/playbook.md` | Interop troubleshooting, test design, incident registry of past wire-format bugs. Read §7 before designing a debugging plan from scratch. |
| `../reticulum-specifications/agent.md` | Verification discipline (§0 prime directive, `[verified]` / ⚠️ UNVERIFIED / 🔮 SPECULATION markers) — relevant whenever you find something the spec doesn't yet cover. |
| `../reticulum-specifications/flows/` | Chronological end-to-end narratives ("send a propagated LXMF message"), cross-referencing SPEC sections. |
| `../reticulum-specifications/tools/` | Runnable Python verifiers against upstream `rns`/`lxmf`. The only admissible way to prove a byte format. |
| `../reticulum-specifications/test-vectors/` | Known-good byte sequences to round-trip. |

If the local checkout is missing or stale, `git -C ../reticulum-specifications pull` (or read from GitHub). Do not proceed on memory.

**When this code and the spec disagree, the spec wins until proven otherwise** — and "proven otherwise" means a `tools/` verifier run against upstream Python, not an argument. Per `agent.md` §0, third-party clients (MeshChat, Sideband forks, our own apps) are never evidence.

### Spec version pinning

`SPEC_VERSION` at the repo root holds the `reticulum-specifications` commit SHA this code was last synced against. The nightly `.github/workflows/spec-watch.yml` compares it to upstream `master` and maintains a single open `spec-sync` issue listing what has landed since. When you bring the code up to date with a spec change (or confirm no change was needed), **bump `SPEC_VERSION` in the same PR and close the issue.**

---

## 1. Cardinal rules

From `playbook.md`; short form:

1. **Spec before code.** Identify the SPEC section governing the failing byte path and read it before reading Go.
2. **Rebuild sibling-impl binaries before assuming your code is wrong.** A pre-built artifact in a sibling repo's `build/` may lag its source by months (`playbook.md` §2.2).
3. **Self-round-trip tests are insufficient for wire formats.** They pass when both sides agree on the wrong thing. Anything producing or consuming wire bytes needs at least one byte-equality test against upstream Python RNS — that's what the `*_interop_test.go` files and `testdata/` fixtures are for.
4. **Silent drops are not random.** Multi-hop drops → SPEC §2.3 HEADER_2 conversion; link establishes then drops DATA → §6.4.2/§6.4.3; signature invalid → §4.2/§5.6.1/§6.2/§6.6; large message truncated → §10 Resource.
5. **Write up what you learn.** A wire detail the spec doesn't cover goes back to `reticulum-specifications` as an issue or PR with an upstream source citation, marked ⚠️ UNVERIFIED if no verifier exists yet.

---

## 2. This project

Pure-Go RNS + LXMF library — no third-party RNS library, no cgo. Two packages, `lxmf` depending only on `rns`. Interoperates with canonical Python `RNS`/`LXMF` and the wider client ecosystem (Sideband, NomadNet, MeshChat).

It is the canonical extraction of the RNS/LXMF core previously duplicated in `reticulum-group-chat` and `reticulum-relay-chat`; those repos plus `semaphore` now consume this module. **Changes here ripple into all three** — treat public signatures as API.

### 2.1 Build and test

```
go build ./...
go vet ./...
go test ./... -count=1
```

Go 1.26.1+ (`go-version-file: go.mod` in CI). Deps: `golang.org/x/crypto`, `github.com/vmihailenco/msgpack/v5`.

CI is three workflows: `test.yml` gates every push to `main` and every PR on build + vet + test + `-race`; `fuzz.yml` and `spec-watch.yml` run nightly. `test.yml` is deliberately not gated on `gofmt -l` — the tree is not gofmt-clean under the pinned toolchain, and the offenders predate this work, so **run `gofmt -l` on the files you touch rather than trusting CI to catch formatting.** Fuzz search is nightly, but seed corpora (including regression seeds from past crashers) run as ordinary tests. Fuzz locally with:

```
go test ./rns/ -run=XXX -fuzz=FuzzValidateMsgpackBounds -fuzztime=1m
```

### 2.2 Architecture

| Concern | Where |
|---|---|
| Identity, destination hashes, signing | `rns/identity.go` |
| Packet header encode/decode (SPEC §2) | `rns/packet.go` |
| Token crypto — modified Fernet (§3) | `rns/token.go`, `rns/link_token.go` |
| Ratchets — rotation, ring, decrypt (§7.3, §7.4) | `rns/ratchet.go` |
| Announce wire format + LXMF app_data (§4) | `rns/announce.go` |
| Link handshake / state machine / data (§6) | `rns/link.go`, `rns/link_state.go`, `rns/link_data.go` |
| Proofs (§6.6) | `rns/proof.go` |
| Transport, path finding, relayed-packet handling (§7, §12) | `rns/transport.go`, `rns/path.go` |
| Resource fragmentation (§10) | `rns/resource*.go` |
| REQUEST/RESPONSE RPC (§11) | `rns/request.go`, `rns/request_dispatch.go` |
| Propagation retrieval — client `/get` (§5.8.3) | `lxmf/retrieve.go` |
| HDLC framing + TCP interfaces (§8) | `rns/hdlc.go`, `rns/tcp.go` (client), `rns/tcp_server.go` (server), `rns/tcp_reconnect.go` |
| Hostile-msgpack guard | `rns/msgpack_guard.go` (+ fuzz target) |
| LXMF message pack/unpack, signature (§5.3–§5.6) | `lxmf/message.go` |
| Opportunistic + link delivery, propagation submit (§5.1, §5.2, §5.8) | `lxmf/delivery.go` |
| Propagation-node app_data parsing (§5.8.5) | `lxmf/propagation.go` |
| Stamps — outbound PoW, both flavors (§5.7) | `lxmf/stamp.go` |

Interop fixtures live in `rns/testdata/` and `lxmf/testdata/`; `*_interop_test.go` files are the byte-equality tests against upstream. `lxmf/testdata/stamp_upstream.json` was generated by running upstream `LXStamper` at the pinned `rns==1.4.2` / `lxmf==1.1.1`; regenerate it in a throwaway venv if the pin moves.

### 2.3 Scope — what is deliberately NOT implemented

Read this before "fixing" a perceived gap; these are decisions, not oversights.

- **Stamps are outbound-only.** `lxmf/stamp.go` generates both §5.7.2 flavors: delivery stamps at `WORKBLOCK_EXPAND_ROUNDS = 3000` over the `message_id`, spliced in as payload element [4] for recipients whose announce declares a `stamp_cost`; and propagation stamps at `WORKBLOCK_EXPAND_ROUNDS_PN = 1000` over the `transient_id`, appended raw for nodes that declare one. `Delivery` applies both automatically from the peer's announce, with `DisableOutboundStamps` / `MaxStampCost` as the escape hatches. Inbound stamps are validated and scored too (§5.7.2 step 3): set `Delivery.InboundStampCost` to the cost you announce and every inbound stamp is checked, with the achieved `Message.StampValue` exposed for prioritisation. `Delivery.EnforceStamps` drops what does not clear it; off by default, matching upstream's `_enforce_stamps`.
- **Tickets (§5.7.3) are implemented** — `lxmf/ticket.go`. `Delivery.IssueTicket` grants one via `FIELD_TICKET` (`0x0C`); a held ticket replaces the grind on outbound; inbound stamps are validated against tickets we issued before falling through to proof-of-work. Note a ticket stamp is **16 bytes**, not `StampSize` — upstream derives it with `truncated_hash`, and §5.7.3's `[:32]` is wrong.
- **Propagation-node *server* role (§5.8) is out of scope** — this is a client that submits to and retrieves from nodes, not a node. No peering keys (`WORKBLOCK_EXPAND_ROUNDS_PEERING = 25`). The client half of both directions IS implemented: `SendPropagated` submits, `RetrievePropagated` collects (§5.8.3).
- **IFAC-sealed packets are rejected**, not decoded (`rns/packet.go`).
- **The transport-node (relay) role is out of scope.** This is a leaf that talks *through* relays — it originates the §2.3 HEADER_2 conversion and consumes relayed packets, but never forwards anyone else's traffic. So the §12 relay rules, §7.2.2 path-request dedup, and the §12.3.2 / §16.1 transport-node tables (`reverse_table`, `link_table`, random blobs) have no implementation here, and upstream changes to them are no-ops for us.

`MaxPropagationStampCost` / `MaxDeliveryStampCost` (both 20) in `lxmf/stamp.go` cap grind work because `stamp_cost` comes from a stranger's announce; see the comments there before changing either.

### 2.4 Where this project deviates from the spec

Nothing knowingly. Deviations discovered must be recorded here with the SPEC section, the reason, and the date — agents look here to resolve "the spec says X but this code does Y".

### 2.5 Conventions

- **Cite the spec in comments and commit messages.** Existing code is dense with `SPEC §N.N` references (see `rns/transport.go`); match that. Commit subjects are `scope: imperative summary` (`rns:`, `lxmf:`, `ci:`).
- **Comments explain *why*, especially the non-obvious wire rules and the security rationale** (see `lxmf/stamp.go`'s cost-cap comment, `lxmf/message.go`'s msgpack alloc-limit note). Don't strip these.
- Every receive-path msgpack decode goes through the guarded helpers — the pinned `msgpack/v5` alloc limit is broken; see `lxmf/message.go` `safeUnmarshal` and `rns/msgpack_guard.go`.
- New wire behavior needs an interop test with upstream-derived bytes, not just a Go round-trip (cardinal rule 3).

---

## 3. Contributing findings back upstream

If you find a wire-format detail not in `SPEC.md`:

1. Cite the SPEC section in the commit message here (or note "not yet in SPEC").
2. Open an issue/PR against `reticulum-specifications` with an upstream `RNS`/`LXMF` file+line citation, marked ⚠️ UNVERIFIED if no `tools/verify_*.py` exists yet.
3. Append an incident-registry entry to `playbook.md` §7 if the fix corresponds to a non-obvious trap — symptom, spec section, fix, one-sentence lesson.

---

## 4. Attribution

Structure adapted from [`reticulum-specifications/templates/AGENTS.md`](https://github.com/thatSFguy/reticulum-specifications/blob/main/templates/AGENTS.md), licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The wire-format knowledge that makes this project possible lives at <https://github.com/thatSFguy/reticulum-specifications>.

Reticulum the protocol is by [Mark Qvist](https://github.com/markqvist) (`RNS` and `LXMF`).
