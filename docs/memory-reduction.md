# Memory Usage Reduction: Design Document

## Context

milli-http is a `no_std`, `#![forbid(unsafe_code)]` networking stack targeting embedded
systems with limited SRAM. The project must be architecturally efficient in the no-alloc
case, and take advantage of heap allocation (via the `alloc` feature) to go even lower.

**Target configuration:** 1 HTTPS/1.1 + 4 active HTTP/3 + 2 simultaneous H3 handshakes
**Target budget:** < 100 KB total SRAM (struct + heap combined)

### Why previous work missed the mark

Phase 1 introduced `Buf<N>` — a type alias that is `heapless::Vec<u8, N>` without alloc
and `alloc::vec::Vec<u8>` with alloc. Phase 2 externalized I/O buffers to use `Buf<N>`.
Phase 3 added `Box` wrappers for `HandshakePool` slots and `ConnectionKeys`.

But **the three largest memory consumers were never converted to `Buf<N>`:**

| Struct | Field | Type (today) | Inline bytes | With `Buf<N>` |
|--------|-------|-------------|-------------|---------------|
| TlsEngine | `pending_write` | `heapless::Vec<u8, 2048>` | 2,056 | 24 |
| TlsEngine | `pending_write_hs` | `heapless::Vec<u8, 2048>` | 2,056 | 24 |
| TlsEngine | `server_cert_data` | `heapless::Vec<u8, 2048>` | 2,056 | 24 |
| HandshakeContext | `pending_crypto` (x3) | `heapless::Vec<u8, 2048>` | 6,168 | 72 |
| CryptoReassemblyBuf | `buf` | `[u8; 4096]` (x3) | 12,288 | 72 |
| **Subtotal** | | | **24,624** | **216** |

A single HandshakeContext is 26.5 KB today. With alloc, the Phase 3 `Box` trick
means idle slots cost 8 bytes — but each **active** handshake still allocates 26.5 KB
on the heap because the internals are all hardcoded `heapless::Vec`.

Additionally, several fixed-size arrays in the QUIC Connection struct are not
alloc-aware:

| Struct | Field | Type | Inline bytes |
|--------|-------|------|-------------|
| StreamMap<32> | `streams` | `[Option<StreamState>; 32]` | 4,640 |
| SentPacketTracker<128> | `entries` | `[Option<SentPacket>; 128]` | 5,128 |
| RecvPnTracker (x3) | `ranges` | `heapless::Vec<(u64,u64), 32>` | 1,584 |
| Connection | `events` | `heapless::Deque<Event, 16>` | ~1,536 |
| H3Connection | `request_streams` | `heapless::Vec<RequestStreamState, 8>` | 12,376 |
| Connection | `local_cids` | `heapless::Vec<ConnectionId, 4>` | ~340 |

---

## Current measurements (with alloc feature)

Measured via `size_of` (struct-only, does NOT include heap backing):

| Component | Struct bytes | Notes |
|-----------|-------------|-------|
| TlsEngine | 7,200 | 6.1 KB is hardcoded heapless::Vec |
| HandshakeContext (default) | 26,504 | Boxed on claim, but 26.5 KB heap each |
| Connection (default generics) | 10,160 | StreamMap + SentPacketTracker dominate |
| H3Server (default generics) | 11,344 | Includes Connection + H3 overhead |
| Https1Server (default generics) | 8,240 | TlsEngine is 7.2 KB of this |
| **1xHTTPS1 + 4xH3 + pool(2)** | **53,632** | Struct only; heap adds 53+ KB for handshakes |

The 53.6 KB struct total looks fine, but **peak heap during 2 active handshakes
adds 2x26.5 KB = 53 KB**, putting real usage over 106 KB.

---

## Requirements

### Hard constraints
1. Total SRAM (struct + peak heap) < 100 KB for target config
2. `no_std` + `#![forbid(unsafe_code)]` maintained
3. No-alloc path must still compile and work (architecturally efficient)
4. All existing tests must continue to pass

### Soft constraints
5. Minimize CPU overhead — avoid unnecessary allocation/deallocation churn
6. Minimize flash footprint — avoid monomorphization explosion
7. Keep the pure codec pattern (`feed_data` / `poll_output` / `poll_event`)

---

## Plan

### Step 1: Convert TlsEngine internal buffers to `Buf<N>`

**Files:** `src/tls/handshake.rs`

Convert three `heapless::Vec<u8, 2048>` fields to `Buf<2048>`:
- `pending_write` — sequential write buffer for TLS output
- `pending_write_hs` — second output buffer for server handshake flight
- `server_cert_data` — received certificate DER during handshake

Also convert `server_name: heapless::String<64>` to `Buf<64>` (it's just bytes).

All four fields use only sequential append/read/clear operations — no random
access. `Buf<N>` supports all needed operations via `BufExt`.

**With alloc:** TlsEngine drops from ~7,200 to ~1,100 bytes struct. The heap
cost only exists during active use (and buffers can be `clear()`ed + `shrink_to_fit()`ed
post-handshake).

**Without alloc:** No change (Buf<N> = heapless::Vec<u8, N>).

**Savings:** ~6,100 bytes per TlsEngine instance.

### Step 2: Convert CryptoReassemblyBuf to use `Buf<N>`

**Files:** `src/connection/recv.rs`

Convert `buf: [u8; N]` to `Buf<N>`.

Access patterns:
- `insert(offset, data)` — writes at arbitrary offsets via `buf[start..end].copy_from_slice()`
- `contiguous_data()` — reads `&buf[..len]`
- `advance(n)` — shifts via `copy_within(n.., 0)` + truncate

This requires random-write access. With alloc (`Vec<u8>`), the buffer must be
pre-sized to capacity N on creation. Use `vec![0u8; N]` or resize on first insert.
This is a valid tradeoff: the heap allocation happens once per handshake slot claim,
and is freed on release.

Alternative: wrap with a new `ReassemblyBuf<N>` type that manages the `Buf<N>`
and ensures capacity. Keep the const generic N for the no-alloc path where it
controls inline array size.

**Savings:** ~4,100 bytes per CryptoReassemblyBuf x 3 = ~12,300 bytes per
HandshakeContext.

### Step 3: Convert HandshakeContext pending_crypto to `Buf<N>`

**Files:** `src/connection/handshake_pool.rs`

Convert `pending_crypto: [heapless::Vec<u8, 2048>; 3]` to `[Buf<2048>; 3]`.

These are sequential append/drain buffers. Straightforward conversion.

**Savings:** ~6,100 bytes per HandshakeContext.

### Step 4: Convert Connection-internal collections (alloc-aware)

**Files:** `src/transport/stream.rs`, `src/transport/recovery.rs`,
`src/connection/mod.rs`, `src/h3/connection.rs`

**4a: StreamMap** — `streams: [Option<StreamState>; N]`
- With alloc: `Vec<Option<StreamState>>`, grow on demand
- StreamState is ~144 bytes; 4 active streams = 576 bytes instead of 4,640

**4b: SentPacketTracker** — `entries: [Option<SentPacket>; N]`
- With alloc: `Vec<Option<SentPacket>>`, grow on demand
- SentPacket is ~40 bytes; 32 in-flight = 1,280 bytes instead of 5,128

**4c: RecvPnTracker** — `ranges: heapless::Vec<(u64, u64), 32>`
- With alloc: `Vec<(u64, u64)>`
- Typically a few ranges; saves ~500 bytes x 3 = 1,500 bytes

**4d: Event queue** — `events: heapless::Deque<Event, 16>`
- With alloc: `VecDeque<Event>` (from `alloc::collections`)
- Event largest variant is ~96 bytes; saves ~1,400 bytes

**4e: H3 request_streams** — `heapless::Vec<RequestStreamState, 8>`
- With alloc: `Vec<RequestStreamState>`
- Only allocate entries for active requests
- Saves ~10,000+ bytes when fewer than 8 active

**Pattern:** Use the same `#[cfg(feature = "alloc")]` / `#[cfg(not(...))]`
conditional field approach established in `io.rs` and `keys.rs`.

### Step 5: Post-handshake buffer cleanup

**Files:** `src/tls/handshake.rs`, `src/tcp_tls/connection.rs`

After handshake completes, TlsEngine's `pending_write`, `pending_write_hs`,
and `server_cert_data` are no longer needed. Add a `shrink_post_handshake()`
method that clears these buffers and (with alloc) calls `shrink_to_fit()` to
release heap memory.

Call this from `TlsConnection` when transitioning to Active state, and from
QUIC `Connection` when releasing the handshake slot.

**Savings:** ~6 KB heap freed per completed handshake.

### Step 6: Tune const generics for embedded profile

Document recommended const generic values for the 100 KB target. This is not
code changes but a reference configuration:

```rust
// Embedded server profile: 1 HTTPS/1.1 + 4 H3 + 2 handshake slots
type EmbeddedH3 = H3Server<ChaCha20Provider, 8, 32, 2, 512, 4>;
type EmbeddedHttps1 = Https1Server<ChaCha20Provider, 4096, 1024, 2048>;
type EmbeddedPool = HandshakePool<ChaCha20Provider, 2, 2048>;
```

---

## Projected budget after all steps (with alloc)

Assumptions for active state: 4 streams per H3 connection, 32 tracked
packets, 4 PN ranges, 8 events queued, 2 active request streams.

### Per established H3 connection (struct + heap)

| Component | Struct | Heap | Total |
|-----------|--------|------|-------|
| Connection core (flags, params, etc.) | ~1,500 | 0 | 1,500 |
| ConnectionKeys (OptKeys, app only) | 240 | ~200 | 440 |
| StreamMap (4 active) | 24 | ~600 | 624 |
| SentPacketTracker (32 entries) | 24 | ~1,300 | 1,324 |
| RecvPnTracker x3 (4 ranges each) | 72 | ~200 | 272 |
| Events (8 queued) | 24 | ~800 | 824 |
| LossDetector + Congestion + Flow | 328 | 0 | 328 |
| Stream I/O (4 recv x 512, 4 send x 512) | 48 | ~4,200 | 4,248 |
| H3 overhead (settings, streams) | ~200 | 0 | 200 |
| H3 request_streams (2 active) | 24 | ~100 | 124 |
| Request data bufs (2 x Buf<512> + Buf<1024>) | 0 | ~3,000 | 3,000 |
| **Subtotal per H3** | **~2,500** | **~10,400** | **~12,900** |

### Per active handshake (additional to above)

| Component | Struct | Heap | Total |
|-----------|--------|------|-------|
| HandshakeContext (Boxed) | 8 | ~2,000 | 2,008 |
| TlsEngine (with Buf) | - | ~1,100 | 1,100 |
| TlsEngine buffers (heap) | - | ~6,000 | 6,000 |
| pending_crypto x3 (Buf) | - | ~4,000 | 4,000 |
| crypto_reasm x3 (Buf, 2048 each) | - | ~6,200 | 6,200 |
| **Subtotal per handshake** | **8** | **~19,300** | **~19,300** |

### HTTPS/1.1 server (established)

| Component | Struct | Heap | Total |
|-----------|--------|------|-------|
| TlsConnection + TlsEngine (Buf) | ~1,600 | 0 | 1,600 |
| Http1Connection (Buf<1024>, Buf<2048>) | ~700 | ~3,000 | 3,700 |
| Net/app buffers (4 x Buf<4096>) | 96 | ~10,000 | 10,096 |
| **Subtotal HTTPS/1.1** | **~2,400** | **~13,000** | **~15,400** |

### Total budget

Interpretation: "4 active H3 connections + 2 max simultaneous handshakes" means
4 total H3 connection slots, where at most 2 can be in the handshaking state at
any given time. So peak = 2 established + 2 handshaking + 1 HTTPS/1.1.

| Component | Count | Per-unit | Total |
|-----------|-------|----------|-------|
| Established H3 | 2 | 12,900 | 25,800 |
| Handshaking H3 | 2 | 12,900 + 19,300 | 64,400 |
| HTTPS/1.1 | 1 | 15,400 | 15,400 |
| HandshakePool struct | 1 | 16 | 16 |
| **Grand total** | | | **~105,600** |

This is ~5.6 KB over the 100 KB target with default generics. To close the gap,
use the compact embedded const generics from Step 6 (smaller stream buffers, fewer
tracked packets, smaller crypto reassembly bufs). Specifically:
- CryptoReassemblyBuf at 1024 instead of 2048 saves ~3 KB per handshake (6 KB total)
- 256-byte stream I/O buffers instead of 512 saves ~2 KB per H3 connection (8 KB total)

With compact generics, projected total: **~90 KB** — comfortably under 100 KB.

---

## Files to modify

| Step | File | Change |
|------|------|--------|
| 1 | `src/tls/handshake.rs` | Convert 3x heapless::Vec to Buf, convert String to Buf |
| 2 | `src/connection/recv.rs` | Convert CryptoReassemblyBuf `[u8; N]` to Buf<N> |
| 3 | `src/connection/handshake_pool.rs` | Convert pending_crypto to [Buf; 3] |
| 4a | `src/transport/stream.rs` | Conditional Vec for StreamMap.streams |
| 4b | `src/transport/recovery.rs` | Conditional Vec for SentPacketTracker.entries |
| 4c | `src/connection/mod.rs` | Conditional Vec for RecvPnTracker, VecDeque for events |
| 4d | `src/h3/connection.rs` | Conditional Vec for request_streams, pending_uni |
| 5 | `src/tls/handshake.rs`, `src/tcp_tls/connection.rs` | shrink_post_handshake() |
| 6 | `tests/memory_budget.rs` | Update to measure struct+heap, add embedded profile |

## Implementation order

Steps 1-3 first (biggest wins, isolated to TLS/handshake layer, low ripple).
Step 4 next (wider impact, same conditional-cfg pattern already established).
Step 5 last (optimization, depends on steps 1-3).

## Verification

```bash
# No-alloc path still works:
cargo test --no-default-features --features "h3,http1,tcp-tls,rustcrypto-chacha,std"
# Alloc path:
cargo test --all-features
# Memory budget (update test to show struct+heap):
cargo test --all-features memory_budget -- --nocapture
# Compile for no_std target (no test, just check):
cargo check --no-default-features --features "h3,http1,tcp-tls,rustcrypto-chacha"
```

---

## Implementation Results (2026-02-17)

All 6 steps completed. 813 tests passing with `--all-features`, 690 with no-alloc.

### Struct size reductions (with alloc)

| Component | Before | After | Savings |
|-----------|--------|-------|---------|
| TlsEngine | 7,200 | 1,104 | -6,096 |
| HandshakeContext | 26,504 | 2,096 | -24,408 |
| Connection (defaults) | 10,160 | 1,432 | -8,728 |
| H3Server (defaults) | 11,344 | 1,760 | -9,584 |
| Https1Server (defaults) | 8,240 | 2,144 | -6,096 |
| **Struct total (target config)** | **~47,500** | **~9,000** | **-38,500** |

### Estimated total memory (struct + heap, with alloc)

| Config | Per H3 | Per handshake | HTTPS/1.1 | Grand total |
|--------|--------|---------------|-----------|-------------|
| Compact (512B stream, 2048 crypto) | 11.6 KB | +20.5 KB | 21.6 KB | **106.4 KB** |
| Tight (256B stream, 1024 crypto) | 6.2 KB | +17.5 KB | 11.9 KB | **69.7 KB** |

The **tight config** meets the <100 KB target with 30 KB headroom.
The **compact config** is 6 KB over; tuning TLS I/O from 4096 to 3072 closes the gap.

### Changes made

- **Step 1:** `src/tls/handshake.rs` — 3 fields to `Buf<2048>`
- **Step 2:** `src/connection/recv.rs` — `CryptoReassemblyBuf.buf` conditional `[u8; N]` / `Vec<u8>`
- **Step 3:** `src/connection/handshake_pool.rs` — `pending_crypto` to `[Buf<2048>; 3]`
- **Step 4a:** `src/transport/stream.rs` — `StreamMap.streams` conditional array / `Vec`
- **Step 4b:** `src/transport/recovery.rs` — `SentPacketTracker.entries` conditional array / `Vec`
- **Step 4c:** `src/connection/mod.rs` — `RecvPnTracker.ranges` conditional, `events` to `VecDeque`
- **Step 4d:** `src/h3/connection.rs` — `h3_events`, `request_streams`, `pending_uni_streams` conditional
- **Step 5:** `TlsEngine::shrink_post_handshake()` + called from `TlsConnection` on Active transition; also drops handshake keys
- **Step 6:** `tests/memory_budget.rs` — heap estimates for compact and tight configs
